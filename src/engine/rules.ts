// Hardening rule pack. Grouped like the CIS Cisco IOS Benchmark (management, control and data plane)
// with DISA STIG network-device themes. Each rule: id, severity, rationale, a test over the parsed
// config, and a fix with rollback, expressed in the right parent context.

import { aclReferences, analyzeAcl, extractAcls, objectGroupUsage, type Acl, type AceIssue } from './acl.ts'
import { child, children, find, has, isPhysical, type Config, type Line, type Platform } from './parse.ts'

export type Severity = 'critical' | 'high' | 'medium' | 'low'
export interface Block { parents: string[]; cmds: string[] }
export interface Fix {
  /** Commands to apply, in order; parents = the config-mode context (e.g. ["line vty 0 4"]) */
  apply: Block[]
  rollback: Block[]
  /** Shown next to the script, e.g. "Configure SSH before removing telnet" */
  note?: string
  /** 0 = definitions that others depend on (ACLs, keys), 1 = global, 2 = sub-contexts */
  order?: number
}
export interface Hit { target: string; line?: number; detail: string; fix?: Fix }
export interface Rule {
  id: string
  title: string
  severity: Severity
  category: string
  /** Benchmark area this check corresponds to */
  ref: string
  rationale: string
  platforms: Platform[]
  check(ctx: Ctx): Hit[]
}

export interface Settings {
  mgmtNets: string[]
  ntpServers: string[]
  syslogHosts: string[]
  execTimeout: number
  aaaMethod: 'local' | 'group tacacs+ local' | 'group radius local'
  banner: string
  edgePattern: string
  vtyAcl: string
  snmpAcl: string
}

export const DEFAULT_SETTINGS: Settings = {
  mgmtNets: ['192.0.2.0/24'],
  ntpServers: ['192.0.2.123', '198.51.100.123'],
  syslogHosts: ['192.0.2.50'],
  execTimeout: 10,
  aaaMethod: 'local',
  banner: 'Authorized access only. Activity on this device is logged and monitored.',
  edgePattern: 'internet|isp|wan|outside|upstream|transit|peering|uplink-to-carrier|dmz-edge',
  vtyAcl: 'MGMT-VTY',
  snmpAcl: 'MGMT-SNMP',
}

export interface Ctx {
  c: Config
  s: Settings
  acls: Acl[]
  aclIssues: AceIssue[]
  refs: Map<string, number[]>
  ifaces: Iface[]
}

export interface Iface { line: Line; name: string; ip: boolean; shutdown: boolean; edge: boolean; physical: boolean; description: string; switchport: boolean; sub: boolean }

export function interfaces(c: Config, s: Settings): Iface[] {
  const edgeRe = new RegExp(s.edgePattern || '(?!)', 'i')
  return find(c, /^interface \S/).map(l => {
    const name = l.text.slice(10).trim()
    const description = child(l, /^description /)?.text.slice(12) ?? ''
    const nameif = child(l, /^nameif /)?.text.slice(7) ?? ''
    const sec0 = !!child(l, /^security-level 0$/)
    const ip = !!child(l, /^ip(v4)? address (?!.*\bnegotiated\b)\S+/) || !!child(l, /^ip address (dhcp|negotiated)/) || !!child(l, /^ip address \S+\/\d+/)
    const shutdown = !!child(l, /^shutdown$/)
    const switchport = !!child(l, /^switchport/) && !child(l, /^no switchport$/)
    return {
      line: l, name, ip, shutdown, description, switchport,
      physical: isPhysical(name) && !name.includes('.'),
      sub: name.includes('.'),
      edge: edgeRe.test(description) || edgeRe.test(nameif) || sec0 || !!child(l, /^ip nat outside$/),
    }
  })
}

const isIos = (c: Config) => c.platform === 'ios' || c.platform === 'iosxe'
const vtys = (c: Config) => find(c, /^line vty /)
const cons = (c: Config) => find(c, /^line (con|console)\b/)
const neg = (cmd: string) => cmd.startsWith('no ') ? cmd.slice(3) : `no ${cmd}`
const g = (cmds: string[], order = 1): Fix => ({ apply: [{ parents: [], cmds }], rollback: [{ parents: [], cmds: cmds.map(neg).reverse() }], order })
const inCtx = (parent: string, cmds: string[], rollback: string[]): Fix => ({ apply: [{ parents: [parent], cmds }], rollback: [{ parents: [parent], cmds: rollback }], order: 2 })

/** "192.0.2.0/24" -> "192.0.2.0 0.0.0.255" (wildcard) or "192.0.2.0 255.255.255.0" (mask) */
export function netParts(cidr: string, kind: 'wildcard' | 'mask') {
  const [ip, lenS] = cidr.split('/')
  const len = Math.max(0, Math.min(32, Number(lenS ?? 32)))
  const mask = len === 0 ? 0 : (0xffffffff << (32 - len)) >>> 0
  const v = kind === 'mask' ? mask : (~mask) >>> 0
  return `${ip} ${[v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].join('.')}`
}
const mgmtAcl = (name: string, nets: string[]) => [`ip access-list standard ${name}`, ...nets.map(n => ` permit ${netParts(n, 'wildcard')}`), ' deny any log']
const aclBlock = (name: string, nets: string[]): Block => ({ parents: [], cmds: mgmtAcl(name, nets) })

/** One fix per community line, shared by SNMP-01/02/03 so the script never fights itself. */
function snmpFix(c: Config, s: Settings, l: Line): Fix {
  const define = !c.lines.some(x => x.text === `ip access-list standard ${s.snmpAcl}`)
  const t = l.text.split(/\s+/)
  const weak = /<masked:weak>/.test(l.text)
  const rw = /\b(RW|rw)\b|group network-admin/.test(l.text)
  const value = weak ? '<NEW-LONG-RANDOM-COMMUNITY>' : t[2]
  const cmds = c.platform === 'nxos'
    ? [...(weak || rw ? [`no ${l.text}`] : []), `snmp-server community ${value} group network-operator`, `snmp-server community ${value} use-ipv4acl ${s.snmpAcl}`]
    : [...(weak || rw ? [`no ${l.text}`] : []), `snmp-server community ${value} RO ${s.snmpAcl}`]
  return {
    apply: [...(define && c.platform !== 'nxos' ? [aclBlock(s.snmpAcl, s.mgmtNets)] : []), { parents: [], cmds }],
    rollback: [{ parents: [], cmds: [`no snmp-server community ${value}`, weak ? '! re-enter the old community manually' : l.text] }],
    note: weak ? 'Replace <NEW-LONG-RANDOM-COMMUNITY> with a long random string, or better, move to SNMPv3 authPriv and remove v2c.' : 'The community value is masked here. Type the real community in place of <masked> when applying.',
    order: 1,
  }
}

const timeoutOk = (l: Line, max: number) => {
  const t = child(l, /^exec-timeout /)
  if (!t) return false
  const [, m, sec] = t.text.split(/\s+/).map(Number)
  const total = (m || 0) + (sec || 0) / 60
  return total > 0 && total <= max
}

export const RULES: Rule[] = [
  // ---------------- AAA ----------------
  {
    id: 'AAA-01', title: 'AAA new-model is enabled', severity: 'high', category: 'AAA', ref: 'CIS 1.1 Local AAA rules', platforms: ['ios', 'iosxe'],
    rationale: 'Without aaa new-model the device falls back to line passwords with no per-user accountability and no lockout control.',
    check: ({ c, s }) => has(c, /^aaa new-model$/) ? [] : [{ target: 'global', detail: 'aaa new-model is missing.', fix: { ...g(['aaa new-model', `aaa authentication login default ${s.aaaMethod}`, `aaa authentication enable default ${s.aaaMethod === 'local' ? 'enable' : s.aaaMethod.replace(/ local$/, ' enable')}`, `aaa authorization exec default ${s.aaaMethod === 'local' ? 'local' : s.aaaMethod} if-authenticated`]), note: 'Make sure a local user with a type 8/9 secret exists before enabling AAA, or you can lock yourself out.' } }],
  },
  {
    id: 'AAA-02', title: 'Login authentication uses an AAA method list', severity: 'high', category: 'AAA', ref: 'CIS 1.1 Local AAA rules', platforms: ['ios', 'iosxe'],
    rationale: 'A default login method list makes every line authenticate through AAA instead of shared line passwords.',
    check: ({ c, s }) => !has(c, /^aaa new-model$/) || has(c, /^aaa authentication login default /) ? [] : [{ target: 'global', detail: 'No "aaa authentication login default" method list.', fix: g([`aaa authentication login default ${s.aaaMethod}`]) }],
  },
  {
    id: 'AAA-03', title: 'Enable authentication uses AAA', severity: 'medium', category: 'AAA', ref: 'CIS 1.1 Local AAA rules', platforms: ['ios', 'iosxe'],
    rationale: 'Privileged mode should be authenticated through the same method list so access is attributable.',
    check: ({ c, s }) => !has(c, /^aaa new-model$/) || has(c, /^aaa authentication enable default /) ? [] : [{ target: 'global', detail: 'No "aaa authentication enable default" method list.', fix: g([`aaa authentication enable default ${s.aaaMethod === 'local' ? 'enable' : s.aaaMethod.replace(/ local$/, ' enable')}`]) }],
  },
  {
    id: 'AAA-04', title: 'Command and exec accounting is configured', severity: 'medium', category: 'AAA', ref: 'CIS 1.1 Local AAA rules / STIG accounting', platforms: ['ios', 'iosxe'],
    rationale: 'Accounting records who ran which privileged command, which audits and incident reviews depend on.',
    check: ({ c }) => {
      if (!has(c, /^aaa new-model$/) || !has(c, /^aaa group server|^tacacs server|^tacacs-server host|^radius server/)) return []
      const ok = has(c, /^aaa accounting commands 15 /) && has(c, /^aaa accounting exec /)
      return ok ? [] : [{ target: 'global', detail: 'An AAA server is configured but command or exec accounting is not.', fix: g(['aaa accounting exec default start-stop group tacacs+', 'aaa accounting commands 15 default start-stop group tacacs+']) }]
    },
  },
  {
    id: 'AAA-05', title: 'Remote AAA has a local fallback', severity: 'low', category: 'AAA', ref: 'CIS 1.1 Local AAA rules', platforms: ['ios', 'iosxe'],
    rationale: 'If every AAA server is unreachable and there is no local method, nobody can log in to fix it.',
    check: ({ c }) => find(c, /^aaa authentication login \S+ group \S+$/).map(l => ({ target: l.text, line: l.n, detail: `"${l.text}" has no local fallback.`, fix: { apply: [{ parents: [], cmds: [`${l.text} local`] }], rollback: [{ parents: [], cmds: [l.text] }], order: 1 } })),
  },
  {
    id: 'AAA-06', title: 'ASA management sessions authenticate with AAA', severity: 'high', category: 'AAA', ref: 'STIG NDM authentication', platforms: ['asa'],
    rationale: 'Without "aaa authentication ssh console" the ASA accepts the shared login password for SSH.',
    check: ({ c }) => has(c, /^aaa authentication ssh console /) ? [] : [{ target: 'global', detail: 'No "aaa authentication ssh console".', fix: g(['aaa authentication ssh console LOCAL', 'aaa authentication enable console LOCAL']) }],
  },

  // ---------------- Device access ----------------
  {
    id: 'ACC-01', title: 'VTY lines accept SSH only (no telnet)', severity: 'critical', category: 'Device access', ref: 'CIS 1.2 Access rules / STIG encrypted management', platforms: ['ios', 'iosxe'],
    rationale: 'Telnet sends credentials and every command in clear text. VTYs should accept SSH only.',
    check: ({ c }) => vtys(c).flatMap(l => {
      const t = child(l, /^transport input /)
      const bad = !t ? c.platform === 'ios' : /\b(telnet|all)\b/.test(t.text)
      if (!bad) return []
      return [{ target: l.text, line: (t ?? l).n, detail: t ? `"${t.text}" allows telnet.` : 'No "transport input", so classic IOS accepts every protocol, including telnet.', fix: inCtx(l.text, ['transport input ssh'], [t ? t.text : 'transport input all']) }]
    }),
  },
  {
    id: 'ACC-02', title: 'SSH version 2 only', severity: 'high', category: 'Device access', ref: 'CIS 1.2 Access rules / STIG SSHv2', platforms: ['ios', 'iosxe', 'asa'],
    rationale: 'SSHv1 has known cryptographic weaknesses; version 2 must be forced.',
    check: ({ c }) => {
      if (c.platform === 'asa') return has(c, /^ssh version 2$/) ? [] : [{ target: 'global', detail: '"ssh version 2" is missing.', fix: g(['ssh version 2']) }]
      return has(c, /^ip ssh version 2$/) ? [] : [{ target: 'global', detail: '"ip ssh version 2" is missing, so SSHv1 may be negotiated.', fix: g(['ip ssh version 2']), }]
    },
  },
  {
    id: 'ACC-03', title: 'VTY access-class restricts management sources', severity: 'high', category: 'Device access', ref: 'CIS 1.2 Access rules', platforms: ['ios', 'iosxe', 'nxos'],
    rationale: 'Without an access-class any host that can route to the device can reach the login prompt and brute-force it.',
    check: ({ c, s }) => {
      const hits = vtys(c).filter(l => !child(l, /^(ip )?access-class \S+ in\b/) && !child(l, /^transport input none$/))
      if (!hits.length) return []
      const define = !c.lines.some(l => l.text === `ip access-list standard ${s.vtyAcl}`)
      return hits.map((l, i) => ({
        target: l.text, line: l.n, detail: 'No inbound access-class on this VTY range.',
        fix: {
          apply: [...(i === 0 && define ? [aclBlock(s.vtyAcl, s.mgmtNets)] : []), { parents: [l.text], cmds: [c.platform === 'nxos' ? `access-class ${s.vtyAcl} in` : `access-class ${s.vtyAcl} in`] }],
          rollback: [{ parents: [l.text], cmds: [`no access-class ${s.vtyAcl} in`] }, ...(i === 0 && define ? [{ parents: [], cmds: [`no ip access-list standard ${s.vtyAcl}`] }] : [])],
          note: `Check that ${s.mgmtNets.join(', ')} covers your jump hosts before applying.`, order: 2,
        },
      }))
    },
  },
  {
    id: 'ACC-04', title: 'Exec timeout on VTY lines', severity: 'medium', category: 'Device access', ref: 'CIS 1.2 Access rules / STIG session timeout', platforms: ['ios', 'iosxe', 'nxos'],
    rationale: 'Idle sessions left open are a hijack risk. The usual baseline is 10 minutes or less; "exec-timeout 0 0" disables it.',
    check: ({ c, s }) => vtys(c).filter(l => !timeoutOk(l, s.execTimeout) && (!!child(l, /^exec-timeout /) || c.platform === 'nxos')).map(l => {
      const t = child(l, /^exec-timeout /)
      return { target: l.text, line: (t ?? l).n, detail: t ? `"${t.text}" is ${/ 0( 0)?$/.test(t.text) ? 'disabled' : `over ${s.execTimeout} minutes`}.` : 'No exec-timeout; NX-OS VTY sessions never time out by default.', fix: inCtx(l.text, [c.platform === 'nxos' ? `exec-timeout ${s.execTimeout}` : `exec-timeout ${s.execTimeout} 0`], [t ? t.text : 'no exec-timeout']) }
    }),
  },
  {
    id: 'ACC-05', title: 'Exec timeout on the console', severity: 'medium', category: 'Device access', ref: 'CIS 1.2 Access rules', platforms: ['ios', 'iosxe', 'nxos'],
    rationale: 'A console left logged in is an open door for anyone in the room.',
    check: ({ c, s }) => cons(c).filter(l => { const t = child(l, /^exec-timeout /); return !!t && !timeoutOk(l, s.execTimeout) }).map(l => {
      const t = child(l, /^exec-timeout /)!
      return { target: l.text, line: t.n, detail: `"${t.text}" on the console.`, fix: inCtx(l.text, [c.platform === 'nxos' ? `exec-timeout ${s.execTimeout}` : `exec-timeout ${s.execTimeout} 0`], [t.text]) }
    }),
  },
  {
    id: 'ACC-06', title: 'AUX port disabled', severity: 'low', category: 'Device access', ref: 'CIS 1.2 Access rules', platforms: ['ios', 'iosxe'],
    rationale: 'An AUX port with exec enabled is an out-of-band entry point usually left unmonitored.',
    check: ({ c }) => find(c, /^line aux /).filter(l => !child(l, /^no exec$/)).map(l => ({ target: l.text, line: l.n, detail: 'AUX line still runs an exec.', fix: inCtx(l.text, ['no exec', 'transport input none'], ['exec', 'no transport input']) })),
  },
  {
    id: 'ACC-07', title: 'SSH timeout and retry limits', severity: 'low', category: 'Device access', ref: 'CIS 1.2 Access rules', platforms: ['ios', 'iosxe'],
    rationale: 'Short negotiation timeouts and few retries slow down brute-force attempts.',
    check: ({ c }) => {
      const cmds = [!has(c, /^ip ssh time-out /) && 'ip ssh time-out 60', !has(c, /^ip ssh authentication-retries /) && 'ip ssh authentication-retries 3'].filter(Boolean) as string[]
      return cmds.length ? [{ target: 'global', detail: `Missing: ${cmds.join(', ')}.`, fix: g(cmds) }] : []
    },
  },
  {
    id: 'ACC-08', title: 'Login block-for (brute-force protection)', severity: 'low', category: 'Device access', ref: 'CIS 1.2 Access rules / STIG lockout', platforms: ['ios', 'iosxe'],
    rationale: '"login block-for" stops logins for a while after repeated failures.',
    check: ({ c }) => has(c, /^login block-for /) ? [] : [{ target: 'global', detail: 'No login block-for.', fix: g(['login block-for 120 attempts 5 within 60', 'login on-failure log']) }],
  },
  {
    id: 'ACC-09', title: 'HTTP server disabled', severity: 'high', category: 'Device access', ref: 'CIS 1.2 Access rules / Cisco advisories (Web UI)', platforms: ['ios', 'iosxe'],
    rationale: 'The HTTP web UI has been the entry point for several critical IOS XE advisories. Disable it unless you need it, and never expose plain HTTP.',
    check: ({ c }) => find(c, /^ip http server$/).map(l => ({ target: 'ip http server', line: l.n, detail: 'Plain-text HTTP web UI is enabled.', fix: g(['no ip http server']) })),
  },
  {
    id: 'ACC-10', title: 'HTTPS server restricted by an access-class', severity: 'medium', category: 'Device access', ref: 'CIS 1.2 Access rules', platforms: ['ios', 'iosxe'],
    rationale: 'If the web UI is needed, restrict it to management subnets.',
    check: ({ c, s }) => has(c, /^ip http secure-server$/) && !has(c, /^ip http access-class /) ? [{ target: 'ip http secure-server', line: find(c, /^ip http secure-server$/)[0].n, detail: 'HTTPS web UI is reachable from any source.', fix: { apply: [aclBlock(s.vtyAcl, s.mgmtNets), { parents: [], cmds: [`ip http access-class ipv4 ${s.vtyAcl}`] }], rollback: [{ parents: [], cmds: [`no ip http access-class ipv4 ${s.vtyAcl}`] }], order: 1 } }] : [],
  },
  {
    id: 'ACC-11', title: 'Telnet feature disabled', severity: 'critical', category: 'Device access', ref: 'STIG encrypted management', platforms: ['nxos'],
    rationale: 'NX-OS "feature telnet" opens a clear-text management service.',
    check: ({ c }) => find(c, /^feature telnet$/).map(l => ({ target: 'feature telnet', line: l.n, detail: 'Telnet is enabled.', fix: g(['no feature telnet']) })),
  },
  {
    id: 'ACC-12', title: 'No telnet management access on the ASA', severity: 'critical', category: 'Device access', ref: 'STIG encrypted management', platforms: ['asa'],
    rationale: 'ASA "telnet <net> <mask> <ifc>" allows clear-text management.',
    check: ({ c }) => find(c, /^telnet \d+\.\d+\.\d+\.\d+ /).map(l => ({ target: l.text, line: l.n, detail: `"${l.text}" allows telnet management.`, fix: { apply: [{ parents: [], cmds: [`no ${l.text}`] }], rollback: [{ parents: [], cmds: [l.text] }], order: 1 } })),
  },
  {
    id: 'ACC-13', title: 'ASA management not open to any source', severity: 'high', category: 'Device access', ref: 'STIG management access', platforms: ['asa'],
    rationale: '"ssh 0.0.0.0 0.0.0.0 outside" or "http 0.0.0.0 0.0.0.0 <ifc>" exposes the login to the internet.',
    check: ({ c, s }) => find(c, /^(ssh|http) 0\.0\.0\.0 0\.0\.0\.0 \S+$/).map(l => {
      const [proto, , , ifc] = l.text.split(' ')
      return { target: l.text, line: l.n, detail: `${proto.toUpperCase()} management accepted from any address on ${ifc}.`, fix: { apply: [{ parents: [], cmds: [`no ${l.text}`, ...s.mgmtNets.map(n => `${proto} ${netParts(n, 'mask')} ${ifc}`)] }], rollback: [{ parents: [], cmds: [...s.mgmtNets.map(n => `no ${proto} ${netParts(n, 'mask')} ${ifc}`), l.text] }], order: 1 } }
    }),
  },
  {
    id: 'ACC-14', title: 'ASA SSH and console idle timeouts', severity: 'medium', category: 'Device access', ref: 'STIG session timeout', platforms: ['asa'],
    rationale: 'ASA defaults to a 5 minute SSH timeout but it is often raised to 60; console timeout defaults to never.',
    check: ({ c, s }) => {
      const out: Hit[] = []
      const st = find(c, /^ssh timeout \d+$/)[0]
      if (st && Number(st.text.split(' ')[2]) > s.execTimeout) out.push({ target: 'ssh timeout', line: st.n, detail: `"${st.text}" is over ${s.execTimeout} minutes.`, fix: { apply: [{ parents: [], cmds: [`ssh timeout ${s.execTimeout}`] }], rollback: [{ parents: [], cmds: [st.text] }] } })
      const ct = find(c, /^console timeout \d+$/)[0]
      if (!ct || ct.text === 'console timeout 0') out.push({ target: 'console timeout', line: ct?.n, detail: 'Console never times out.', fix: { apply: [{ parents: [], cmds: [`console timeout ${s.execTimeout}`] }], rollback: [{ parents: [], cmds: ['console timeout 0'] }] } })
      return out
    },
  },

  // ---------------- Passwords and secrets ----------------
  {
    id: 'PWD-01', title: 'enable secret instead of enable password', severity: 'critical', category: 'Passwords', ref: 'CIS 1.3 Password rules / STIG password storage', platforms: ['ios', 'iosxe'],
    rationale: '"enable password" is stored in clear text or reversible type 7. "enable secret" with type 8/9 is a real hash.',
    check: ({ c }) => find(c, /^enable password /).map(l => ({ target: 'enable password', line: l.n, detail: 'enable password is set (clear text or type 7).', fix: { apply: [{ parents: [], cmds: ['enable algorithm-type scrypt secret <NEW-ENABLE-SECRET>', 'no enable password'] }], rollback: [{ parents: [], cmds: ['! re-enter the previous enable password manually'] }], note: 'Replace <NEW-ENABLE-SECRET> before pasting.', order: 1 } })),
  },
  {
    id: 'PWD-02', title: 'enable secret uses type 8 or 9', severity: 'medium', category: 'Passwords', ref: 'CIS 1.3 Password rules', platforms: ['ios', 'iosxe'],
    rationale: 'Type 5 (MD5) hashes crack quickly on GPUs. Type 9 (scrypt) or 8 (PBKDF2) are the current recommendation.',
    check: ({ c }) => find(c, /^enable secret (?:level \d+ )?[45] /).map(l => ({ target: 'enable secret', line: l.n, detail: `enable secret is type ${l.text.match(/ ([45]) /)![1]}.`, fix: { apply: [{ parents: [], cmds: ['enable algorithm-type scrypt secret <NEW-ENABLE-SECRET>'] }], rollback: [{ parents: [], cmds: ['! the old hash cannot be restored; keep the new secret'] }], note: 'Replace <NEW-ENABLE-SECRET> before pasting.', order: 1 } })),
  },
  {
    id: 'PWD-03', title: 'An enable secret is set', severity: 'high', category: 'Passwords', ref: 'CIS 1.3 Password rules', platforms: ['ios', 'iosxe'],
    rationale: 'Without an enable secret, privileged mode is protected only by whatever AAA or line config happens to exist.',
    check: ({ c }) => has(c, /^enable (secret|password) /) ? [] : [{ target: 'global', detail: 'No enable secret.', fix: { apply: [{ parents: [], cmds: ['enable algorithm-type scrypt secret <NEW-ENABLE-SECRET>'] }], rollback: [{ parents: [], cmds: ['no enable secret'] }], note: 'Replace <NEW-ENABLE-SECRET> before pasting.', order: 1 } }],
  },
  {
    id: 'PWD-04', title: 'Local users use hashed secrets', severity: 'high', category: 'Passwords', ref: 'CIS 1.3 Password rules / STIG password storage', platforms: ['ios', 'iosxe', 'asa', 'nxos'],
    rationale: '"username X password" stores a reversible type 7 or clear text password; use "secret" with type 8/9 (pbkdf2 on ASA).',
    check: ({ c }) => find(c, /^username \S+ .*\b(password|secret) /).filter(l => /<masked:weak>/.test(l.text)).map(l => {
      const user = l.text.split(/\s+/)[1]
      const priv = l.text.match(/privilege \d+/)?.[0]
      const cmd = c.platform === 'asa' ? `username ${user} password <NEW-PASSWORD>${priv ? ' ' + priv : ''}` : c.platform === 'nxos' ? `username ${user} password <NEW-PASSWORD>` : `username ${user}${priv ? ' ' + priv : ''} algorithm-type scrypt secret <NEW-PASSWORD>`
      return { target: `username ${user}`, line: l.n, detail: `User ${user} has a weak password (${/ password 7 /.test(l.text) ? 'type 7' : / (secret|password) 5 /.test(l.text) ? 'type 5 MD5' : 'clear text or legacy'}).`, fix: { apply: [{ parents: [], cmds: [cmd] }], rollback: [{ parents: [], cmds: ['! the old password was masked on import; keep the new one'] }], note: 'Replace <NEW-PASSWORD>. The old value was masked on import and is not stored.', order: 1 } }
    }),
  },
  {
    id: 'PWD-05', title: 'Line passwords are not type 7 or clear text', severity: 'high', category: 'Passwords', ref: 'CIS 1.3 Password rules', platforms: ['ios', 'iosxe'],
    rationale: 'Type 7 line passwords decode in one step with public tools. Use AAA login instead of line passwords.',
    check: ({ c, s }) => c.lines.filter(l => l.parent && /^line /.test(l.parent.text) && /^password /.test(l.text)).map(l => ({
      target: l.parent!.text, line: l.n, detail: `${l.parent!.text} has a ${/^password 7 /.test(l.text) ? 'type 7' : 'clear-text'} password.`,
      fix: { apply: [{ parents: [l.parent!.text], cmds: [has(c, /^aaa new-model$/) ? 'login authentication default' : 'login local', 'no password'] }], rollback: [{ parents: [l.parent!.text], cmds: ['! re-enter the old line password manually (it was masked on import)'] }], note: s.aaaMethod === 'local' ? 'Requires at least one local user with a secret.' : undefined, order: 2 },
    })),
  },
  {
    id: 'PWD-06', title: 'service password-encryption', severity: 'medium', category: 'Passwords', ref: 'CIS 1.3 Password rules', platforms: ['ios', 'iosxe'],
    rationale: 'It only applies type 7 (easily reversed), but it keeps passwords from showing over a shoulder or in pasted configs. Benchmarks still require it.',
    check: ({ c }) => has(c, /^service password-encryption$/) ? [] : [{ target: 'global', detail: 'service password-encryption is off.', fix: g(['service password-encryption']) }],
  },
  {
    id: 'PWD-07', title: 'Password strength check enabled', severity: 'low', category: 'Passwords', ref: 'STIG password complexity', platforms: ['nxos'],
    rationale: 'NX-OS enforces password complexity unless "no password strength-check" is configured.',
    check: ({ c }) => find(c, /^no password strength-check$/).map(l => ({ target: 'password strength-check', line: l.n, detail: 'Password strength checking is disabled.', fix: g(['password strength-check']) })),
  },
  {
    id: 'PWD-08', title: 'ASA enable password is PBKDF2', severity: 'high', category: 'Passwords', ref: 'STIG password storage', platforms: ['asa'],
    rationale: 'Legacy "encrypted" ASA hashes are MD5-based. Re-entering the password on 9.7+ stores PBKDF2.',
    check: ({ c }) => find(c, /^(enable password|passwd) /).filter(l => /<masked:weak>/.test(l.text)).map(l => ({ target: l.text.split(' ')[0], line: l.n, detail: `${l.text.split(' ')[0]} uses a legacy hash.`, fix: { apply: [{ parents: [], cmds: [`${l.text.startsWith('passwd') ? 'passwd' : 'enable password'} <NEW-PASSWORD>`] }], rollback: [{ parents: [], cmds: ['! keep the new password'] }], note: 'Replace <NEW-PASSWORD>.', order: 1 } })),
  },
  {
    id: 'PWD-09', title: 'Routing and AAA keys are not weak', severity: 'medium', category: 'Passwords', ref: 'CIS 3.3 Routing rules / STIG key storage', platforms: ['ios', 'iosxe', 'nxos', 'asa'],
    rationale: 'TACACS/RADIUS keys, OSPF/BGP passwords and key chains stored as type 7 or clear text are recoverable from any config backup.',
    check: ({ c }) => c.lines.filter(l => /^(key 7|key-string|key \S|tacacs-server key|radius-server key|ip ospf (message-digest|authentication)-key|neighbor \S+ password|ntp authentication-key)/.test(l.text) && /<masked:weak>/.test(l.text) && !/^(username|enable|password|snmp)/.test(l.text)).slice(0, 20).map(l => ({ target: `${l.parent ? l.parent.text + ' > ' : ''}${l.text.replace(/<masked:weak>.*$/, '').trim()}`, line: l.n, detail: `Weak key at line ${l.n}: ${l.text.replace(/<masked:weak>.*/, '<masked>')}`, fix: { apply: [{ parents: l.parent ? [l.parent.text] : [], cmds: ['! enable "password encryption aes" (key config-key password-encrypt) so keys are stored as type 6, then re-enter this key'] }], rollback: [{ parents: [], cmds: ['! no change'] }] } })),
  },

  // ---------------- SNMP ----------------
  {
    id: 'SNMP-01', title: 'SNMP communities are restricted by an ACL', severity: 'high', category: 'SNMP', ref: 'CIS 1.5 SNMP rules', platforms: ['ios', 'iosxe', 'nxos'],
    rationale: 'An SNMP community without an ACL answers any host, and v1/v2c communities travel in clear text.',
    check: ({ c, s }) => {
      const hits = find(c, /^snmp-server community /).filter(l => {
        const t = l.text.split(/\s+/)
        if (c.platform === 'nxos') return !/\b(use-ipv4acl|use-acl)\b/.test(l.text) && !find(c, new RegExp(`^snmp-server community ${t[2].replace(/[<>:]/g, '.')} use-`)).length
        const last = t[t.length - 1]
        return /^(RO|RW|ro|rw)$/.test(last) || t.length <= 3 || /^view$/.test(t[t.length - 2])
      })
      if (!hits.length) return []
      return hits.map(l => ({ target: l.text, line: l.n, detail: `"${l.text}" has no ACL.`, fix: snmpFix(c, s, l) }))
    },
  },
  {
    id: 'SNMP-02', title: 'No read-write SNMP communities', severity: 'high', category: 'SNMP', ref: 'CIS 1.5 SNMP rules', platforms: ['ios', 'iosxe', 'nxos'],
    rationale: 'An RW community lets anyone who learns it rewrite configuration or reload the device.',
    check: ({ c, s }) => find(c, /^snmp-server community \S+ .*\b(RW|rw)\b|^snmp-server community \S+ group network-admin/).map(l => ({ target: l.text, line: l.n, detail: 'Read-write SNMP community. Use SNMPv3 authPriv for any write access.', fix: snmpFix(c, s, l) })),
  },
  {
    id: 'SNMP-03', title: 'No default or guessable communities', severity: 'critical', category: 'SNMP', ref: 'CIS 1.5 SNMP rules', platforms: ['ios', 'iosxe', 'nxos', 'asa'],
    rationale: '"public", "private" and short dictionary words are the first strings every scanner tries.',
    check: ({ c, s }) => find(c, /^snmp-server (community|host) .*<masked:weak>/).map(l => ({ target: l.text, line: l.n, detail: 'Default, short or dictionary community string (value masked on import).', fix: l.text.startsWith('snmp-server community') ? snmpFix(c, s, l) : { apply: [{ parents: [], cmds: [`no ${l.text}`, l.text.replace('<masked:weak>', '<NEW-LONG-RANDOM-COMMUNITY>')] }], rollback: [{ parents: [], cmds: ['! re-enter the old trap community manually'] }], order: 1 } })),
  },
  {
    id: 'SNMP-04', title: 'SNMPv3 with authentication and privacy', severity: 'medium', category: 'SNMP', ref: 'CIS 1.5 SNMP rules / STIG SNMPv3', platforms: ['ios', 'iosxe', 'asa'],
    rationale: 'v1/v2c have no encryption. SNMPv3 groups should use "priv" (authPriv).',
    check: ({ c, s }) => {
      const v2 = find(c, /^snmp-server community /).length > 0 || find(c, /^snmp-server host \S+ .*version (1|2c)/).length > 0
      const weakGroups = find(c, /^snmp-server group \S+ v3 (noauth|auth)\b/)
      const out: Hit[] = weakGroups.map(l => ({ target: l.text, line: l.n, detail: `"${l.text}" is not authPriv.`, fix: { apply: [{ parents: [], cmds: [l.text.replace(/ v3 (noauth|auth)\b/, ' v3 priv')] }], rollback: [{ parents: [], cmds: [l.text] }] } }))
      if (v2 && !has(c, /^snmp-server group \S+ v3 priv/)) out.push({ target: 'global', detail: 'Only SNMP v1/v2c is configured.', fix: g([`snmp-server group SNMPV3-RO v3 priv access ${s.snmpAcl}`, '! snmp-server user <USER> SNMPV3-RO v3 auth sha <AUTH> priv aes 128 <PRIV>']) })
      return out
    },
  },

  // ---------------- Logging ----------------
  {
    id: 'LOG-01', title: 'Remote syslog server', severity: 'medium', category: 'Logging', ref: 'CIS 2.2 Logging rules / STIG log offload', platforms: ['ios', 'iosxe', 'nxos', 'asa'],
    rationale: 'Logs that only live on the device are lost on reload and can be wiped by an attacker.',
    check: ({ c, s }) => has(c, /^logging (host |server |\d+\.\d+\.\d+\.\d+)/) || c.platform === 'asa' && has(c, /^logging host /) ? [] : [{ target: 'global', detail: 'No remote syslog host.', fix: g(s.syslogHosts.map(h => c.platform === 'nxos' ? `logging server ${h} 6` : c.platform === 'asa' ? `logging host mgmt ${h}` : `logging host ${h}`)) }],
  },
  {
    id: 'LOG-02', title: 'Local log buffer', severity: 'low', category: 'Logging', ref: 'CIS 2.2 Logging rules', platforms: ['ios', 'iosxe', 'asa'],
    rationale: 'A buffered log helps troubleshoot even when the syslog server is unreachable.',
    check: ({ c }) => has(c, /^logging buffered\b/) ? [] : [{ target: 'global', detail: 'logging buffered is not set.', fix: g([c.platform === 'asa' ? 'logging buffered informational' : 'logging buffered 64000 informational']) }],
  },
  {
    id: 'LOG-03', title: 'Log timestamps with milliseconds and time zone', severity: 'low', category: 'Logging', ref: 'CIS 2.2 Logging rules', platforms: ['ios', 'iosxe'],
    rationale: 'Correlating events across devices needs precise, zoned timestamps.',
    check: ({ c }) => has(c, /^service timestamps log datetime .*msec/) ? [] : [{ target: 'global', detail: 'Log timestamps lack datetime msec.', fix: { apply: [{ parents: [], cmds: ['service timestamps debug datetime msec localtime show-timezone', 'service timestamps log datetime msec localtime show-timezone'] }], rollback: [{ parents: [], cmds: ['service timestamps log uptime'] }] } }],
  },
  {
    id: 'LOG-04', title: 'Syslog trap level set', severity: 'low', category: 'Logging', ref: 'CIS 2.2 Logging rules', platforms: ['ios', 'iosxe', 'asa'],
    rationale: 'Without an explicit trap level, informational events may never reach the collector.',
    check: ({ c }) => has(c, /^logging (trap|host) /) && !has(c, /^logging trap /) ? [{ target: 'global', detail: 'logging trap is not set.', fix: g(['logging trap informational']) }] : [],
  },
  {
    id: 'LOG-05', title: 'Configuration change logging (archive log config)', severity: 'low', category: 'Logging', ref: 'CIS 2.2 Logging rules / STIG change audit', platforms: ['ios', 'iosxe'],
    rationale: '"archive / log config" records each config command with the user who entered it.',
    check: ({ c }) => { const a = find(c, /^archive$/)[0]; return a && child(a, /^log config$/) ? [] : [{ target: 'archive', detail: 'Config change logging is off.', fix: { apply: [{ parents: ['archive'], cmds: ['log config', ' logging enable', ' notify syslog contenttype plaintext', ' hidekeys'] }], rollback: [{ parents: ['archive'], cmds: ['no log config'] }], order: 2 } }] },
  },
  {
    id: 'LOG-06', title: 'Logging enabled on the ASA', severity: 'medium', category: 'Logging', ref: 'STIG logging', platforms: ['asa'],
    rationale: 'ASA logging is off until "logging enable" is configured.',
    check: ({ c }) => has(c, /^logging enable$/) ? [] : [{ target: 'global', detail: '"logging enable" is missing.', fix: g(['logging enable', 'logging timestamp']) }],
  },

  // ---------------- NTP ----------------
  {
    id: 'NTP-01', title: 'NTP servers configured', severity: 'medium', category: 'NTP', ref: 'CIS 2.3 NTP rules', platforms: ['ios', 'iosxe', 'nxos', 'asa'],
    rationale: 'Without synchronized time, logs from different devices cannot be correlated and certificates may fail.',
    check: ({ c, s }) => has(c, /^ntp server /) ? [] : [{ target: 'global', detail: 'No NTP server.', fix: g(s.ntpServers.map(h => `ntp server ${h}`)) }],
  },
  {
    id: 'NTP-02', title: 'NTP authentication', severity: 'medium', category: 'NTP', ref: 'CIS 2.3 NTP rules / STIG NTP auth', platforms: ['ios', 'iosxe', 'nxos', 'asa'],
    rationale: 'Unauthenticated NTP lets an on-path attacker shift the clock and break log timelines and certificate checks.',
    check: ({ c }) => {
      if (!has(c, /^ntp server /)) return []
      const auth = has(c, /^ntp authenticate$/) && has(c, /^ntp trusted-key /) && has(c, /^ntp authentication-key /)
      const keyless = find(c, /^ntp server /).filter(l => !/\bkey \d+/.test(l.text))
      if (auth && !keyless.length) return []
      return [{ target: 'global', detail: auth ? `${keyless.length} NTP server${keyless.length > 1 ? 's do' : ' does'} not reference a key.` : 'NTP authentication is not enabled.', fix: { apply: [{ parents: [], cmds: ['ntp authentication-key 1 md5 <NTP-KEY>', 'ntp authenticate', 'ntp trusted-key 1', ...keyless.map(l => `${l.text.replace(/ prefer$/, '')} key 1${/ prefer$/.test(l.text) ? ' prefer' : ''}`)] }], rollback: [{ parents: [], cmds: ['no ntp authenticate', 'no ntp trusted-key 1', ...keyless.map(l => l.text)] }], note: 'Replace <NTP-KEY> with the key your NTP servers use. Prefer SHA keys where the platform supports them.', order: 1 } }]
    },
  },
  {
    id: 'NTP-03', title: 'NTP access restricted', severity: 'low', category: 'NTP', ref: 'CIS 2.3 NTP rules', platforms: ['ios', 'iosxe'],
    rationale: 'Without "ntp access-group" the device can serve time (and mode 6/7 queries) to anyone.',
    check: ({ c }) => has(c, /^ntp server /) && !has(c, /^ntp access-group /) ? [{ target: 'global', detail: 'No ntp access-group.', fix: { apply: [{ parents: [], cmds: ['ip access-list standard NTP-PEERS', ...find(c, /^ntp server /).map(l => ` permit host ${l.text.split(/\s+/).find(x => /^\d+\.\d+\.\d+\.\d+$/.test(x)) ?? '<SERVER>'}`), ' deny any'] }, { parents: [], cmds: ['ntp access-group peer NTP-PEERS'] }], rollback: [{ parents: [], cmds: ['no ntp access-group peer NTP-PEERS', 'no ip access-list standard NTP-PEERS'] }], order: 1 } }] : [],
  },

  // ---------------- Services ----------------
  {
    id: 'SVC-01', title: 'IP source routing disabled', severity: 'medium', category: 'Services', ref: 'CIS 3.1 Routing rules', platforms: ['ios', 'iosxe'],
    rationale: 'Source routing lets a sender choose the path through your network, bypassing controls. IOS enables it by default.',
    check: ({ c }) => has(c, /^no ip source-route$/) ? [] : [{ target: 'global', detail: '"no ip source-route" is missing (enabled by default).', fix: g(['no ip source-route']) }],
  },
  {
    id: 'SVC-02', title: 'CDP off on internet-facing interfaces', severity: 'medium', category: 'Services', ref: 'CIS 2.1 Global services', platforms: ['ios', 'iosxe', 'nxos'],
    rationale: 'CDP announces the model, software version and addresses to the neighbor; on an ISP-facing link that neighbor is not yours.',
    check: ({ c, ifaces }) => {
      if (has(c, /^no cdp run$|^no cdp enable$/)) return []
      return ifaces.filter(i => i.edge && !i.shutdown && !child(i.line, /^no cdp enable$/)).map(i => ({ target: i.line.text, line: i.line.n, detail: `${i.name} looks internet-facing (${i.description || 'NAT outside'}) and still runs CDP.`, fix: inCtx(i.line.text, ['no cdp enable'], ['cdp enable']) }))
    },
  },
  {
    id: 'SVC-03', title: 'Proxy ARP disabled on routed interfaces', severity: 'medium', category: 'Services', ref: 'CIS 3.1 Routing rules', platforms: ['ios', 'iosxe'],
    rationale: 'Proxy ARP answers for hosts on other networks, which hides misconfiguration and helps spoofing.',
    check: ({ ifaces }) => ifaces.filter(i => i.ip && !i.shutdown && !child(i.line, /^no ip proxy-arp$/) && !/^(Loopback|Tunnel|Null|NVI)/i.test(i.name)).map(i => ({ target: i.line.text, line: i.line.n, detail: `Proxy ARP is on (default) on ${i.name}.`, fix: inCtx(i.line.text, ['no ip proxy-arp'], ['ip proxy-arp']) })),
  },
  {
    id: 'SVC-04', title: 'No directed broadcasts', severity: 'medium', category: 'Services', ref: 'CIS 3.1 Routing rules', platforms: ['ios', 'iosxe'],
    rationale: 'Directed broadcasts are the amplifier in smurf attacks.',
    check: ({ ifaces }) => ifaces.flatMap(i => children(i.line, /^ip directed-broadcast/).map(l => ({ target: i.line.text, line: l.n, detail: `${i.name} forwards directed broadcasts.`, fix: inCtx(i.line.text, ['no ip directed-broadcast'], [l.text]) }))),
  },
  {
    id: 'SVC-05', title: 'ICMP redirects and unreachables off at the edge', severity: 'low', category: 'Services', ref: 'CIS 3.1 Routing rules', platforms: ['ios', 'iosxe'],
    rationale: 'Redirects and unreachables leak topology and can be abused for reconnaissance on untrusted links.',
    check: ({ ifaces }) => ifaces.filter(i => i.edge && i.ip && !i.shutdown).flatMap(i => {
      const cmds = [!child(i.line, /^no ip redirects$/) && 'no ip redirects', !child(i.line, /^no ip unreachables$/) && 'no ip unreachables'].filter(Boolean) as string[]
      return cmds.length ? [{ target: i.line.text, line: i.line.n, detail: `${i.name}: ${cmds.join(', ')} missing.`, fix: inCtx(i.line.text, cmds, cmds.map(neg)) }] : []
    }),
  },
  {
    id: 'SVC-06', title: 'TCP and UDP small servers disabled', severity: 'medium', category: 'Services', ref: 'CIS 2.1 Global services', platforms: ['ios', 'iosxe'],
    rationale: 'echo, chargen and discard are classic denial-of-service amplifiers with no legitimate use today.',
    check: ({ c }) => find(c, /^service (tcp|udp)-small-servers/).map(l => ({ target: l.text, line: l.n, detail: `${l.text} is enabled.`, fix: { apply: [{ parents: [], cmds: [`no ${l.text}`] }], rollback: [{ parents: [], cmds: [l.text] }], order: 1 } })),
  },
  {
    id: 'SVC-07', title: 'Finger, PAD and BOOTP servers disabled', severity: 'low', category: 'Services', ref: 'CIS 2.1 Global services', platforms: ['ios', 'iosxe'],
    rationale: 'Legacy services expand the attack surface for no benefit.',
    check: ({ c }) => {
      const cmds = [
        has(c, /^(ip finger|service finger)$/) && 'no ip finger',
        !has(c, /^no service pad$/) && 'no service pad',
        !has(c, /^no ip bootp server$/) && 'no ip bootp server',
      ].filter(Boolean) as string[]
      return cmds.length ? [{ target: 'global', detail: `Missing: ${cmds.join(', ')}.`, fix: g(cmds) }] : []
    },
  },
  {
    id: 'SVC-08', title: 'TCP keepalives for inbound sessions', severity: 'low', category: 'Services', ref: 'CIS 2.1 Global services', platforms: ['ios', 'iosxe'],
    rationale: 'Keepalives clean up orphaned VTY sessions that would otherwise hold a line.',
    check: ({ c }) => has(c, /^service tcp-keepalives-in$/) ? [] : [{ target: 'global', detail: 'service tcp-keepalives-in is off.', fix: g(['service tcp-keepalives-in', 'service tcp-keepalives-out']) }],
  },
  {
    id: 'SVC-09', title: 'DNS lookup has a server or is disabled', severity: 'low', category: 'Services', ref: 'CIS 2.1 Global services', platforms: ['ios', 'iosxe'],
    rationale: 'With lookup on and no name server, every mistyped command broadcasts a DNS query and hangs the session.',
    check: ({ c }) => has(c, /^no ip domain[- ]lookup$/) || has(c, /^ip name-server /) ? [] : [{ target: 'global', detail: 'DNS lookup is on with no name server.', fix: g(['no ip domain lookup']) }],
  },
  {
    id: 'SVC-10', title: 'Network config loading disabled', severity: 'low', category: 'Services', ref: 'CIS 2.1 Global services', platforms: ['ios', 'iosxe'],
    rationale: '"service config" and "boot network" fetch configuration over TFTP at boot, which an attacker on the segment can supply.',
    check: ({ c }) => find(c, /^(service config|boot network )/).map(l => ({ target: l.text, line: l.n, detail: `${l.text} loads config from the network.`, fix: { apply: [{ parents: [], cmds: [`no ${l.text}`] }], rollback: [{ parents: [], cmds: [l.text] }], order: 1 } })),
  },
  {
    id: 'SVC-11', title: 'ASA does not answer ICMP from any source on the outside', severity: 'low', category: 'Services', ref: 'STIG ICMP filtering', platforms: ['asa'],
    rationale: '"icmp permit any outside" makes the firewall itself pingable and fingerprintable from the internet.',
    check: ({ c }) => find(c, /^icmp permit any (?:\S+ )?outside$/).map(l => ({ target: l.text, line: l.n, detail: `${l.text}.`, fix: { apply: [{ parents: [], cmds: [`no ${l.text}`, 'icmp permit any unreachable outside', 'icmp deny any outside'] }], rollback: [{ parents: [], cmds: ['no icmp deny any outside', 'no icmp permit any unreachable outside', l.text] }], order: 1 } })),
  },

  // ---------------- Banners ----------------
  {
    id: 'BAN-01', title: 'Login or MOTD banner present', severity: 'low', category: 'Banners', ref: 'CIS 1.6 Banner rules / STIG DoD notice', platforms: ['ios', 'iosxe', 'nxos', 'asa'],
    rationale: 'A legal notice is required by most policies and supports prosecution of unauthorized access.',
    check: ({ c, s }) => has(c, /^banner (login|motd)\b/) ? [] : [{ target: 'global', detail: 'No login or MOTD banner.', fix: { apply: [{ parents: [], cmds: c.platform === 'asa' ? [`banner login ${s.banner}`] : c.platform === 'nxos' ? [`banner motd #${s.banner}#`] : [`banner login ^C${s.banner}^C`] }], rollback: [{ parents: [], cmds: [c.platform === 'nxos' ? 'no banner motd' : 'no banner login'] }], note: c.platform === 'asa' || c.platform === 'nxos' ? undefined : 'Type ^C as Ctrl+V Ctrl+C, or use another delimiter such as #.', order: 1 } }],
  },

  // ---------------- Interfaces ----------------
  {
    id: 'INT-01', title: 'Unused interfaces are shut down', severity: 'medium', category: 'Interfaces', ref: 'CIS 3.x / STIG unused ports', platforms: ['ios', 'iosxe', 'nxos'],
    rationale: 'An unused port left up lets anyone with physical access plug in, often straight into VLAN 1.',
    check: ({ ifaces }) => {
      const unused = ifaces.filter(i => i.physical && !i.shutdown && !i.ip && !i.description && !/^(mgmt|Management)/i.test(i.name) && !i.line.children.some(ch => /^(switchport (access vlan|mode trunk|trunk)|channel-group|ip address|service-policy|encapsulation|vrf|nameif|pppoe|dialer)/.test(ch.text)))
      return unused.map(i => ({ target: i.line.text, line: i.line.n, detail: `${i.name} has no address, VLAN or description and is not shut down.`, fix: inCtx(i.line.text, ['description UNUSED', 'shutdown'], ['no shutdown', 'no description']) }))
    },
  },
  {
    id: 'INT-02', title: 'Access ports are not in VLAN 1', severity: 'low', category: 'Interfaces', ref: 'STIG VLAN 1 usage', platforms: ['ios', 'iosxe', 'nxos'],
    rationale: 'VLAN 1 carries control traffic and is the default for every port; user ports belong in a dedicated VLAN.',
    check: ({ ifaces }) => ifaces.filter(i => !i.shutdown && child(i.line, /^switchport mode access$/) && (!child(i.line, /^switchport access vlan /) || child(i.line, /^switchport access vlan 1$/))).map(i => ({ target: i.line.text, line: i.line.n, detail: `${i.name} is an access port in VLAN 1.`, fix: inCtx(i.line.text, ['switchport access vlan <USER-VLAN>'], ['switchport access vlan 1']) })),
  },
  {
    id: 'INT-03', title: 'Unicast RPF on internet-facing interfaces', severity: 'low', category: 'Interfaces', ref: 'CIS 3.2 Border router filtering', platforms: ['ios', 'iosxe', 'asa'],
    rationale: 'uRPF drops spoofed source addresses at the edge (BCP 38).',
    check: ({ c, ifaces }) => {
      if (c.platform === 'asa') return find(c, /^nameif outside$/).length && !has(c, /^ip verify reverse-path interface outside$/) ? [{ target: 'outside', detail: 'Reverse-path verification is off on outside.', fix: g(['ip verify reverse-path interface outside']) }] : []
      return ifaces.filter(i => i.edge && i.ip && !i.shutdown && !child(i.line, /^ip verify unicast/)).map(i => ({ target: i.line.text, line: i.line.n, detail: `${i.name} has no uRPF check.`, fix: inCtx(i.line.text, ['ip verify unicast source reachable-via rx'], ['no ip verify unicast source reachable-via rx']) }))
    },
  },
  {
    id: 'INT-04', title: 'Inbound ACL on internet-facing interfaces', severity: 'high', category: 'Interfaces', ref: 'CIS 3.2 Border router filtering / STIG ingress filtering', platforms: ['ios', 'iosxe'],
    rationale: 'An ISP-facing interface without an inbound ACL accepts bogons and direct attacks on the router and the inside network.',
    check: ({ ifaces }) => ifaces.filter(i => i.edge && i.ip && !i.shutdown && !child(i.line, /^ip access-group \S+ in$/) && !child(i.line, /^zone-member security /)).map(i => ({ target: i.line.text, line: i.line.n, detail: `${i.name} has no inbound ACL or zone membership.`, fix: { apply: [{ parents: [], cmds: ['ip access-list extended EDGE-IN', ' deny ip 10.0.0.0 0.255.255.255 any', ' deny ip 172.16.0.0 0.15.255.255 any', ' deny ip 192.168.0.0 0.0.255.255 any', ' deny ip 127.0.0.0 0.255.255.255 any', ' deny ip 224.0.0.0 31.255.255.255 any', ' ! permit what this edge needs here, e.g. return traffic and BGP from the peer', ' permit ip any any'] }, { parents: [i.line.text], cmds: ['ip access-group EDGE-IN in'] }], rollback: [{ parents: [i.line.text], cmds: ['no ip access-group EDGE-IN in'] }, { parents: [], cmds: ['no ip access-list extended EDGE-IN'] }], note: 'Starting point only: anti-spoofing entries, then tighten the final permit to the services this edge really needs.', order: 2 } })),
  },

  // ---------------- Routing ----------------
  {
    id: 'RTE-01', title: 'OSPF authentication', severity: 'medium', category: 'Routing', ref: 'CIS 3.3 Routing rules', platforms: ['ios', 'iosxe', 'nxos'],
    rationale: 'Unauthenticated OSPF lets any host on a segment inject routes.',
    check: ({ c, ifaces }) => find(c, /^router ospf \S+/).filter(r => !child(r, /^area \S+ authentication/) && !ifaces.some(i => child(i.line, /^ip ospf (authentication|message-digest-key)/))).map(r => ({ target: r.text, line: r.n, detail: `${r.text} has no area or interface authentication.`, fix: inCtx(r.text, ['area 0 authentication message-digest', '! then on each OSPF interface: ip ospf message-digest-key 1 md5 <KEY>'], ['no area 0 authentication message-digest']) })),
  },
  {
    id: 'RTE-02', title: 'BGP neighbors use a password', severity: 'medium', category: 'Routing', ref: 'CIS 3.3 Routing rules', platforms: ['ios', 'iosxe', 'nxos'],
    rationale: 'TCP MD5 (or TCP-AO) on eBGP sessions blocks spoofed resets and session hijacks.',
    check: ({ c }) => find(c, /^router bgp \d+/).flatMap(r => {
      const peers = new Set<string>()
      for (const l of r.children) { const m = l.text.match(/^neighbor (\d+\.\d+\.\d+\.\d+) remote-as/); if (m) peers.add(m[1]) }
      for (const l of r.children) for (const ch of [l, ...l.children]) { const m = ch.text.match(/^(?:neighbor (\S+) )?password /); if (m?.[1]) peers.delete(m[1]); else if (m && l.text.startsWith('neighbor ')) peers.delete(l.text.split(' ')[1]) }
      return [...peers].map(p => ({ target: `${r.text} neighbor ${p}`, line: r.n, detail: `BGP neighbor ${p} has no password.`, fix: inCtx(r.text, [`neighbor ${p} password <BGP-KEY>`], [`no neighbor ${p} password`]) }))
    }),
  },
  {
    id: 'RTE-03', title: 'EIGRP authentication', severity: 'medium', category: 'Routing', ref: 'CIS 3.3 Routing rules', platforms: ['ios', 'iosxe'],
    rationale: 'Unauthenticated EIGRP neighbors can inject routes.',
    check: ({ c, ifaces }) => find(c, /^router eigrp \S+/).filter(r => !ifaces.some(i => child(i.line, /^ip authentication mode eigrp/)) && !r.children.some(ch => ch.children.some(x => /authentication mode/.test(x.text) || x.children.some(y => /authentication mode/.test(y.text))))).map(r => ({ target: r.text, line: r.n, detail: `${r.text} has no authentication.`, fix: { apply: [{ parents: [], cmds: ['key chain EIGRP-KEYS', ' key 1', '  key-string <EIGRP-KEY>'] }], rollback: [{ parents: [], cmds: ['no key chain EIGRP-KEYS'] }], note: 'Then add "ip authentication mode eigrp <AS> md5" and "ip authentication key-chain eigrp <AS> EIGRP-KEYS" on each EIGRP interface.', order: 0 } })),
  },

  // ---------------- ACLs ----------------
  {
    id: 'ACL-01', title: 'No permit any any', severity: 'high', category: 'ACLs', ref: 'CIS 3.2 Border router filtering', platforms: ['ios', 'iosxe', 'nxos', 'asa'],
    rationale: 'A "permit ip any any" entry makes everything after it dead and usually defeats the ACL\'s purpose.',
    check: ({ aclIssues, c }) => aclIssues.filter(x => x.kind === 'any-any').map(x => ({ target: `${x.acl}: ${x.text}`, line: x.line, detail: `${x.acl}: ${x.detail}`, fix: aclRemove(c, x) })),
  },
  {
    id: 'ACL-02', title: 'No shadowed ACEs', severity: 'medium', category: 'ACLs', ref: 'ACL hygiene', platforms: ['ios', 'iosxe', 'nxos', 'asa'],
    rationale: 'A shadowed entry never matches because earlier entries with the opposite action already decide its traffic. The intent of that entry is not being enforced.',
    check: ({ aclIssues, c }) => aclIssues.filter(x => x.kind === 'shadowed').map(x => ({ target: `${x.acl}: ${x.text}`, line: x.line, detail: `${x.acl}: "${x.text}". ${x.detail}`, fix: { ...aclRemove(c, x), note: 'Decide the intent: if this entry should win, move it above the covering entries instead of deleting it.' } })),
  },
  {
    id: 'ACL-03', title: 'No redundant ACEs', severity: 'low', category: 'ACLs', ref: 'ACL hygiene', platforms: ['ios', 'iosxe', 'nxos', 'asa'],
    rationale: 'Redundant entries add TCAM usage and review noise without changing behavior.',
    check: ({ aclIssues, c }) => aclIssues.filter(x => x.kind === 'redundant').map(x => ({ target: `${x.acl}: ${x.text}`, line: x.line, detail: `${x.acl}: "${x.text}". ${x.detail}`, fix: aclRemove(c, x) })),
  },
  {
    id: 'ACL-04', title: 'Applied ACLs exist', severity: 'high', category: 'ACLs', ref: 'ACL hygiene', platforms: ['ios', 'iosxe', 'nxos', 'asa'],
    rationale: 'On IOS an access-group pointing at a missing ACL permits everything, so the filter you think is there is not.',
    check: ({ acls, refs, c }) => {
      const names = new Set(acls.map(a => a.name))
      const out: Hit[] = []
      for (const [name, lines] of refs) {
        if (names.has(name) || /^(prefix|prefix-list|route-map|gateway)$/.test(name)) continue
        const ln = c.lines.find(l => l.n === lines[0])
        if (!ln) continue
        out.push({ target: `ACL ${name}`, line: lines[0], detail: `"${ln.text}" references ACL ${name}, which is not defined.`, fix: { apply: [{ parents: [], cmds: [`! define ACL ${name} or remove the reference at line ${lines[0]}`] }], rollback: [{ parents: [], cmds: ['! no change'] }] } })
      }
      return out
    },
  },
  {
    id: 'ACL-05', title: 'No unused ACLs', severity: 'low', category: 'ACLs', ref: 'ACL hygiene', platforms: ['ios', 'iosxe', 'nxos', 'asa'],
    rationale: 'ACLs referenced nowhere are dead config that misleads reviewers and drifts out of date.',
    check: ({ acls, refs }) => acls.filter(a => !refs.has(a.name)).map(a => ({ target: `ACL ${a.name}`, line: a.line, detail: `ACL ${a.name} (${a.aces.length} entries) is not referenced anywhere.`, fix: { apply: [{ parents: [], cmds: [a.family === 'asa' ? `clear configure access-list ${a.name}` : /^\d+$/.test(a.name) ? `no access-list ${a.name}` : `no ip access-list ${a.kind === 'standard' && a.family === 'ios' ? 'standard ' : a.family === 'ios' ? 'extended ' : ''}${a.name}`] }], rollback: [{ parents: [], cmds: [`! restore ACL ${a.name} from the snapshot config (line ${a.line})`] }], order: 1 } })),
  },
  {
    id: 'ACL-06', title: 'No unused object-groups', severity: 'low', category: 'ACLs', ref: 'ACL hygiene', platforms: ['ios', 'iosxe', 'nxos', 'asa'],
    rationale: 'Orphaned object-groups make firewall reviews slower and hide stale addresses.',
    check: ({ c }) => objectGroupUsage(c).filter(o => !o.used).map(o => {
      const def = c.lines.find(l => l.n === o.line)!
      return { target: `object-group ${o.name}`, line: o.line, detail: `${def.text} is not referenced.`, fix: { apply: [{ parents: [], cmds: [`no ${def.text}`] }], rollback: [{ parents: [], cmds: [`! restore ${def.text} from the snapshot config`] }], order: 1 } }
    }),
  },
]

function aclRemove(c: Config, x: AceIssue): Fix {
  const ln = c.lines.find(l => l.n === x.line)
  if (!ln) return { apply: [], rollback: [] }
  if (ln.parent) {
    const seq = ln.text.match(/^(\d+) /)?.[1]
    return { apply: [{ parents: [ln.parent.text], cmds: [seq ? `no ${seq}` : `no ${ln.text}`] }], rollback: [{ parents: [ln.parent.text], cmds: [seq ? ln.text : `! re-add "${ln.text}" in its original position`] }], order: 2 }
  }
  return { apply: [{ parents: [], cmds: [`no ${ln.text}`] }], rollback: [{ parents: [], cmds: [`! numbered ACLs append at the end; restore order from the snapshot if needed`, ln.text] }], order: 1 }
}

export function context(c: Config, s: Settings): Ctx {
  const acls = extractAcls(c)
  return { c, s, acls, aclIssues: acls.flatMap(analyzeAcl), refs: aclReferences(c), ifaces: interfaces(c, s) }
}

export const SEV_WEIGHT: Record<Severity, number> = { critical: 10, high: 6, medium: 3, low: 1 }
export const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low']
