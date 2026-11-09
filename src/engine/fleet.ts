// Fleet drift, config diffs and snapshot comparison.

import { find, flatten, has, type Config } from './parse.ts'
import type { DeviceAudit, Finding } from './audit.ts'

// ---------- Drift: the same setting differing across devices ----------

export interface DriftRow { setting: string; values: Record<string, string>; distinct: number; majority: string }

const list = (c: Config, re: RegExp, pick: (t: string) => string) => find(c, re).map(l => pick(l.text)).sort().join(', ') || '(none)'

export const DRIFT_KEYS: [string, (c: Config) => string][] = [
  ['NTP servers', c => list(c, /^ntp server /, t => t.split(/\s+/).find(x => /^\d+\.\d+\.\d+\.\d+$|[a-z]\.[a-z]/i.test(x) && x !== 'server') ?? t)],
  ['Syslog hosts', c => list(c, /^logging (host |server |\d)/, t => t.split(/\s+/).find(x => /^\d+\.\d+\.\d+\.\d+$/.test(x)) ?? t.split(/\s+/).pop()!)],
  ['Logging trap level', c => find(c, /^logging trap /)[0]?.text.split(/\s+/)[2] ?? '(default)'],
  ['Time zone', c => find(c, /^clock timezone /)[0]?.text.slice(15) ?? '(UTC default)'],
  ['Domain name', c => find(c, /^(ip domain[- ]name|domain-name) /)[0]?.text.split(/\s+/).pop() ?? '(none)'],
  ['Name servers', c => list(c, /^(ip name-server|name-server|dns server-group)/, t => t.split(/\s+/).slice(-1)[0])],
  ['SSH version', c => has(c, /^(ip )?ssh version 2$/) ? '2' : c.platform === 'nxos' ? '2 (NX-OS)' : 'not forced'],
  ['VTY transport', c => [...new Set(find(c, /^line vty /).map(l => l.children.find(x => /^transport input /.test(x.text))?.text.slice(16) ?? 'default'))].join(' / ') || '(no vty)'],
  ['VTY exec-timeout', c => [...new Set(find(c, /^line vty /).map(l => l.children.find(x => /^exec-timeout /.test(x.text))?.text.slice(13) ?? 'default'))].join(' / ') || '(no vty)'],
  ['AAA', c => has(c, /^aaa new-model$/) ? (find(c, /^aaa authentication login default /)[0]?.text.slice(32) ?? 'new-model, no login list') : c.platform === 'asa' || c.platform === 'nxos' ? 'platform default' : 'off'],
  ['Enable secret type', c => { const l = find(c, /^enable (secret|password) /)[0]; return l ? l.text.startsWith('enable password') ? 'enable password' : `type ${l.text.match(/ (\d) /)?.[1] ?? '?'}` : '(none)' }],
  ['Password encryption', c => has(c, /^service password-encryption$/) ? 'on' : 'off'],
  ['SNMP versions', c => [has(c, /^snmp-server community /) && 'v2c', has(c, /^snmp-server group \S+ v3 /) && 'v3'].filter(Boolean).join(' + ') || '(none)'],
  ['HTTP server', c => [has(c, /^ip http server$/) && 'http', has(c, /^ip http secure-server$/) && 'https'].filter(Boolean).join(' + ') || 'off'],
  ['Banner', c => has(c, /^banner (login|motd)/) ? 'present' : 'missing'],
  ['Source route', c => has(c, /^no ip source-route$/) ? 'disabled' : 'enabled'],
]

export function drift(configs: Config[]): DriftRow[] {
  if (configs.length < 2) return []
  const rows: DriftRow[] = []
  for (const [setting, f] of DRIFT_KEYS) {
    const values: Record<string, string> = {}
    for (const c of configs) values[c.hostname || 'unnamed'] = f(c)
    const counts = new Map<string, number>()
    for (const v of Object.values(values)) counts.set(v, (counts.get(v) ?? 0) + 1)
    if (counts.size < 2) continue
    const majority = [...counts].sort((a, b) => b[1] - a[1])[0][0]
    rows.push({ setting, values, distinct: counts.size, majority })
  }
  return rows
}

// ---------- Config diff (order-independent, by full parent path) ----------

export interface DiffGroup { parent: string; added: string[]; removed: string[] }

export function configDiff(a: Config, b: Config): DiffGroup[] {
  const fa = flatten(a), fb = flatten(b)
  const ca = new Map<string, number>(), cb = new Map<string, number>()
  for (const x of fa) ca.set(x, (ca.get(x) ?? 0) + 1)
  for (const x of fb) cb.set(x, (cb.get(x) ?? 0) + 1)
  const groups = new Map<string, DiffGroup>()
  const grp = (full: string) => {
    const parts = full.split(' > ')
    const leaf = parts.pop()!
    const parent = parts.join(' > ')
    let g = groups.get(parent)
    if (!g) { g = { parent, added: [], removed: [] }; groups.set(parent, g) }
    return { g, leaf }
  }
  for (const [k, n] of ca) { const m = cb.get(k) ?? 0; for (let i = m; i < n; i++) { const { g, leaf } = grp(k); g.removed.push(leaf) } }
  for (const [k, n] of cb) { const m = ca.get(k) ?? 0; for (let i = m; i < n; i++) { const { g, leaf } = grp(k); g.added.push(leaf) } }
  // A parent line that was itself added/removed already implies its children; keep them, they show what moved.
  return [...groups.values()].sort((x, y) => x.parent.localeCompare(y.parent))
}

/** Line-based unified diff (LCS) for the side-by-side view of a single device. */
export function lineDiff(a: string[], b: string[]): { op: ' ' | '+' | '-'; text: string; na?: number; nb?: number }[] {
  const n = a.length, m = b.length
  if (n * m > 4_000_000) {
    // Too large for a full LCS table; fall back to set difference.
    const sb = new Set(b), sa = new Set(a)
    return [...a.filter(x => !sb.has(x)).map(text => ({ op: '-' as const, text })), ...b.filter(x => !sa.has(x)).map(text => ({ op: '+' as const, text }))]
  }
  const dp = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1))
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1])
  const out: { op: ' ' | '+' | '-'; text: string; na?: number; nb?: number }[] = []
  let i = 0, j = 0
  while (i < n && j < m) {
    if (a[i] === b[j]) { out.push({ op: ' ', text: a[i], na: i + 1, nb: j + 1 }); i++; j++ }
    else if (dp[i + 1][j] >= dp[i][j + 1]) { out.push({ op: '-', text: a[i], na: i + 1 }); i++ }
    else { out.push({ op: '+', text: b[j], nb: j + 1 }); j++ }
  }
  while (i < n) { out.push({ op: '-', text: a[i], na: i + 1 }); i++ }
  while (j < m) { out.push({ op: '+', text: b[j], nb: j + 1 }); j++ }
  return out
}

// ---------- Snapshots ----------

export interface SnapDevice { host: string; platform: string; score: number; findings: { key: string; rule: string; severity: string; title: string; target: string }[] }
export interface Snapshot { id: string; label: string; at: number; score: number; devices: SnapDevice[]; /** masked configs by host; may be dropped for cloud sync when large */ configs?: Record<string, string> }

export function makeSnapshot(id: string, label: string, devices: DeviceAudit[], configs?: Record<string, string>, at = Date.now()): Snapshot {
  return {
    id, label, at,
    score: devices.length ? Math.round(devices.reduce((s, d) => s + d.score, 0) / devices.length) : 0,
    devices: devices.map(d => ({ host: d.host, platform: d.platform, score: d.score, findings: d.findings.filter(f => !f.waived).map(f => ({ key: f.key, rule: f.rule, severity: f.severity, title: f.title, target: f.target })) })),
    configs,
  }
}

export interface Comparison {
  fixed: SnapDevice['findings']
  added: SnapDevice['findings']
  regressed: SnapDevice['findings']
  unchanged: number
  devices: { host: string; before?: number; after?: number }[]
}

/**
 * Compares `current` to `previous`. A finding absent from `previous` is "regressed" if any older
 * snapshot had it (it was fixed once and came back), otherwise "new".
 */
export function compareSnapshots(previous: Snapshot, current: Snapshot, older: Snapshot[] = []): Comparison {
  const keys = (s: Snapshot) => new Map(s.devices.flatMap(d => d.findings.map(f => [f.key, f] as const)))
  const p = keys(previous), c = keys(current)
  const history = new Set(older.flatMap(s => s.devices.flatMap(d => d.findings.map(f => f.key))))
  const fixed = [...p.values()].filter(f => !c.has(f.key))
  const appeared = [...c.values()].filter(f => !p.has(f.key))
  const hosts = [...new Set([...previous.devices.map(d => d.host), ...current.devices.map(d => d.host)])]
  return {
    fixed,
    added: appeared.filter(f => !history.has(f.key)),
    regressed: appeared.filter(f => history.has(f.key)),
    unchanged: [...c.keys()].filter(k => p.has(k)).length,
    devices: hosts.map(host => ({ host, before: previous.devices.find(d => d.host === host)?.score, after: current.devices.find(d => d.host === host)?.score })),
  }
}

export const findingKeys = (fs: Finding[]) => new Set(fs.map(f => f.key))
