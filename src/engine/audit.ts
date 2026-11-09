import { child, find, has, parse, type Config, type Platform } from './parse.ts'
import { context, DEFAULT_SETTINGS, RULES, SEV_ORDER, SEV_WEIGHT, type Block, type Ctx, type Fix, type Rule, type Settings, type Severity } from './rules.ts'
import type { AceIssue, Acl } from './acl.ts'

export interface Waiver { key: string; reason: string; /** ISO date (YYYY-MM-DD); the waiver lapses after this day */ expires: string; by?: string; at: number }

export interface Finding {
  /** Stable across re-imports: host|rule|target */
  key: string
  host: string
  rule: string
  title: string
  severity: Severity
  category: string
  ref: string
  target: string
  line?: number
  detail: string
  fix?: Fix
  waived?: Waiver
}

export interface DeviceAudit {
  host: string
  platform: Platform
  score: number
  grade: string
  findings: Finding[]
  /** Rule ids evaluated for this platform */
  evaluated: number
  passed: number
  ctx: Ctx
  inventory: Inventory
}

export const waiverActive = (w: Waiver | undefined, today = new Date().toISOString().slice(0, 10)) => !!w && w.expires >= today

export function auditConfig(c: Config, settings: Settings = DEFAULT_SETTINGS, waivers: Record<string, Waiver> = {}, today?: string): DeviceAudit {
  const ctx = context(c, settings)
  const host = c.hostname || 'unnamed'
  const findings: Finding[] = []
  let total = 0, lost = 0, evaluated = 0, passed = 0
  for (const r of RULES) {
    if (!r.platforms.includes(c.platform)) continue
    evaluated++
    const hits = safeCheck(r, ctx)
    const w = SEV_WEIGHT[r.severity]
    total += w
    const live = hits.map(h => {
      const key = `${host}|${r.id}|${h.target}`
      const wv = waivers[key]
      return { key, host, rule: r.id, title: r.title, severity: r.severity, category: r.category, ref: r.ref, target: h.target, line: h.line, detail: h.detail, fix: h.fix, waived: waiverActive(wv, today) ? wv : undefined } as Finding
    })
    findings.push(...live)
    if (live.some(f => !f.waived)) lost += w
    else passed++
  }
  findings.sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) || (a.line ?? 0) - (b.line ?? 0))
  const score = total ? Math.round(100 * (total - lost) / total) : 100
  return { host, platform: c.platform, score, grade: grade(score), findings, evaluated, passed, ctx, inventory: inventory(c) }
}

function safeCheck(r: Rule, ctx: Ctx) {
  try { return r.check(ctx) } catch { return [] }
}

export const grade = (s: number) => s >= 90 ? 'A' : s >= 80 ? 'B' : s >= 70 ? 'C' : s >= 55 ? 'D' : 'F'

export function auditText(text: string, settings?: Settings, waivers?: Record<string, Waiver>, platform?: Platform) {
  return auditConfig(parse(text, platform), settings, waivers)
}

// ---------- Inventory ----------

export interface Inventory {
  hostname: string
  platform: Platform
  version: string
  domain: string
  interfaces: { name: string; description: string; ip: string; mode: string; vlan: string; shutdown: boolean; line: number }[]
  vlans: { id: string; name: string }[]
  routing: { protocol: string; id: string; detail: string; line: number }[]
  staticRoutes: number
  snmp: string[]
  aaaServers: number
  users: number
}

export function inventory(c: Config): Inventory {
  const ver = find(c, /^(version|ASA Version|: ASA Version) /)[0]?.text.split(/\s+/).pop() ?? ''
  const interfaces = find(c, /^interface \S/).map(l => {
    const ipl = l.children.find(x => /^(ip(v4)? address|ip address) \S/.test(x.text) && !/ secondary$/.test(x.text))
    const mode = child(l, /^switchport mode /)?.text.split(' ')[2] ?? (child(l, /^switchport$/) || child(l, /^switchport access vlan/) ? 'access' : ipl ? 'routed' : '')
    const vlan = child(l, /^switchport access vlan /)?.text.split(' ')[3] ?? child(l, /^switchport trunk allowed vlan /)?.text.split(' ').slice(4).join(' ') ?? (/^Vlan/i.test(l.text.slice(10)) ? l.text.slice(14) : '')
    const ip = ipl ? ipl.text.replace(/^ip(v4)? address /, '').split(' ').slice(0, 2).join(' ') : ''
    return { name: l.text.slice(10).trim(), description: child(l, /^description /)?.text.slice(12) ?? child(l, /^nameif /)?.text.slice(7) ?? '', ip, mode, vlan, shutdown: !!child(l, /^shutdown$/), line: l.n }
  })
  const vlans = find(c, /^vlan \d+$/).map(l => ({ id: l.text.slice(5), name: child(l, /^name /)?.text.slice(5) ?? '' }))
  for (const l of find(c, /^vlan \d+[,-]/)) for (const part of l.text.slice(5).split(',')) {
    const [a, b] = part.split('-').map(Number)
    for (let v = a; v <= (b || a) && v - a < 200; v++) if (!vlans.some(x => x.id === String(v))) vlans.push({ id: String(v), name: '' })
  }
  const routing = find(c, /^router (ospf|ospfv3|bgp|eigrp|rip|isis)\b/).map(l => {
    const [, protocol, id = ''] = l.text.split(/\s+/)
    let detail = ''
    if (protocol === 'bgp') detail = `${l.children.filter(x => /^neighbor \S+ remote-as/.test(x.text)).length} neighbors`
    else if (protocol === 'rip') detail = child(l, /^version 2$/) ? 'version 2' : 'version 1 (default)'
    else if (protocol === 'ospf') detail = `${new Set(l.children.map(x => x.text.match(/ area (\S+)/)?.[1]).filter(Boolean)).size || 0} areas`
    else if (protocol === 'eigrp') detail = /^\d+$/.test(id) ? 'classic mode' : 'named mode'
    return { protocol: protocol.toUpperCase(), id, detail, line: l.n }
  })
  const snmp = [
    has(c, /^snmp-server community /) && 'v2c',
    has(c, /^snmp-server host \S+ .*version 1\b/) && 'v1',
    has(c, /^snmp-server group \S+ v3 /) && 'v3',
  ].filter(Boolean) as string[]
  return {
    hostname: c.hostname, platform: c.platform, version: ver,
    domain: find(c, /^(ip domain[- ]name|domain-name|ip domain-name) /)[0]?.text.split(/\s+/).pop() ?? '',
    interfaces, vlans: vlans.sort((a, b) => Number(a.id) - Number(b.id)), routing,
    staticRoutes: find(c, /^(ip route|route) \S/).length, snmp,
    aaaServers: find(c, /^(tacacs server|radius server|tacacs-server host|radius-server host|aaa-server \S+ \(\S+\) host)/).length,
    users: find(c, /^username /).length,
  }
}

// ---------- Remediation script ----------

export interface Script { apply: string; rollback: string; notes: string[]; count: number }

/** Merges fixes into one config-mode script. Commands sharing a parent context are grouped under it, in a safe order. */
export function remediationScript(host: string, platform: Platform, findings: Finding[]): Script {
  const live = findings.filter(f => f.fix && !f.waived)
  const ordered = [...live].sort((a, b) => (a.fix!.order ?? 1) - (b.fix!.order ?? 1))
  const merge = (blocks: Block[]) => {
    const groups: { key: string; parents: string[]; cmds: string[] }[] = []
    const seen = new Set<string>()
    for (const b of blocks) {
      const sig = JSON.stringify(b)
      if (seen.has(sig)) continue
      seen.add(sig)
      const key = b.parents.join('\n')
      // Global commands always start a new group so their order is kept; sub-contexts merge.
      const last = groups[groups.length - 1]
      const existing = key ? groups.find(g => g.key === key) : last && !last.key ? last : undefined
      const g = existing ?? (groups.push({ key, parents: b.parents, cmds: [] }), groups[groups.length - 1])
      for (const c of b.cmds) if (!g.cmds.includes(c) || c.startsWith(' ')) g.cmds.push(c)
    }
    const out: string[] = []
    for (const g of groups) {
      if (!g.cmds.length) continue
      g.parents.forEach((p, i) => out.push(' '.repeat(i) + p))
      for (const c of g.cmds) out.push(' '.repeat(g.parents.length) + c)
      if (g.parents.length) out.push(...g.parents.map((_, i) => ' '.repeat(g.parents.length - 1 - i) + 'exit'))
    }
    return out
  }
  const stamp = new Date().toISOString().slice(0, 10)
  const head = (what: string) => [`! ${what} for ${host} (${platform.toUpperCase()}), ${live.length} finding${live.length === 1 ? '' : 's'}, generated ${stamp}`]
  const safety = platform === 'asa' || platform === 'nxos' ? [] : ['! Safety net: schedule a reload so a lockout undoes itself. Run "reload cancel" when done.', '! reload in 15']
  const end = platform === 'asa' ? ['write memory'] : platform === 'nxos' ? ['end', 'copy running-config startup-config'] : ['end', '! reload cancel', 'write memory']
  const applyLines = merge(ordered.flatMap(f => f.fix!.apply))
  const rollLines = merge([...ordered].reverse().flatMap(f => f.fix!.rollback))
  const notes = [...new Set(live.map(f => f.fix!.note).filter(Boolean) as string[])]
  return {
    apply: [...head('Remediation'), ...safety, 'configure terminal', ...applyLines, ...end].join('\n'),
    rollback: [...head('Rollback'), 'configure terminal', ...rollLines, ...end.filter(l => !l.includes('reload'))].join('\n'),
    notes,
    count: live.length,
  }
}

// ---------- ACL summary ----------

export interface AclSummary { acl: Acl; issues: AceIssue[]; referenced: boolean }
export const aclSummary = (a: DeviceAudit): AclSummary[] => a.ctx.acls.map(acl => ({ acl, issues: a.ctx.aclIssues.filter(i => i.acl === acl.name), referenced: a.ctx.refs.has(acl.name) }))

// ---------- Fleet ----------

export function fleetScore(devices: DeviceAudit[]) {
  if (!devices.length) return { score: 0, grade: 'F', critical: 0, high: 0, medium: 0, low: 0, waived: 0, total: 0 }
  const score = Math.round(devices.reduce((s, d) => s + d.score, 0) / devices.length)
  const live = devices.flatMap(d => d.findings.filter(f => !f.waived))
  const n = (s: Severity) => live.filter(f => f.severity === s).length
  return { score, grade: grade(score), critical: n('critical'), high: n('high'), medium: n('medium'), low: n('low'), waived: devices.flatMap(d => d.findings).filter(f => f.waived).length, total: live.length }
}

// ---------- CSV ----------

const csvCell = (v: unknown) => { const s = v === undefined || v === null ? '' : String(v); return /[",\n\r]/.test(s) || /^[=+\-@]/.test(s) ? `"${(/^[=+\-@]/.test(s) ? "'" : '') + s.replace(/"/g, '""')}"` : s }
export function findingsCsv(devices: DeviceAudit[]): string {
  const rows = [['host', 'platform', 'rule', 'severity', 'category', 'title', 'target', 'line', 'detail', 'benchmark', 'status', 'waiver_reason', 'waiver_expires', 'fix']]
  for (const d of devices) for (const f of d.findings) rows.push([d.host, d.platform, f.rule, f.severity, f.category, f.title, f.target, String(f.line ?? ''), f.detail, f.ref, f.waived ? 'waived' : 'open', f.waived?.reason ?? '', f.waived?.expires ?? '', f.fix ? f.fix.apply.flatMap(b => [...b.parents, ...b.cmds]).join(' / ') : ''])
  return rows.map(r => r.map(csvCell).join(',')).join('\r\n') + '\r\n'
}
