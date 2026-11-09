// IPv4 ACL model and reasoning. Each ACE becomes a union of 6-dimensional boxes
// (protocol, source, destination, source port, destination port, TCP established flag).
// Shadowing is decided by box subtraction, so an ACE hidden by the combination of several
// earlier ACEs is found too, not only one-to-one overlaps.

import { children, type Config, type Line } from './parse.ts'

export type Range = [number, number]
/** proto, src, dst, sport (or ICMP type), dport (or ICMP code), established (0 = any packet, 1 = established only) */
export type Box = [Range, Range, Range, Range, Range, Range]

export interface Ace {
  acl: string
  line: number
  text: string
  seq?: number
  action: 'permit' | 'deny'
  boxes: Box[]
  /** False when part of the ACE could not be modelled (unknown keyword, unresolved object-group) */
  exact: boolean
  remark?: boolean
  anyAny: boolean
  objectGroups: string[]
}

export interface Acl {
  name: string
  kind: 'standard' | 'extended'
  line: number
  aces: Ace[]
  /** Platform syntax family */
  family: 'ios' | 'nxos' | 'asa'
}

export interface AceIssue {
  acl: string
  line: number
  text: string
  kind: 'shadowed' | 'redundant' | 'any-any'
  /** Lines of the ACEs that cover this one */
  by: number[]
  detail: string
}

const FULL_IP: Range = [0, 0xffffffff]
const FULL_PORT: Range = [0, 65535]
const FULL8: Range = [0, 255]
const ANY_EST: Range = [0, 1]

export const PROTOCOLS: Record<string, number> = { icmp: 1, igmp: 2, ipinip: 4, tcp: 6, udp: 17, gre: 47, esp: 50, ahp: 51, ah: 51, eigrp: 88, ospf: 89, pim: 103, vrrp: 112, sctp: 132 }
export const PORTS: Record<string, number> = {
  echo: 7, discard: 9, daytime: 13, chargen: 19, 'ftp-data': 20, ftp: 21, ssh: 22, telnet: 23, smtp: 25, time: 37, nameserver: 42, whois: 43, tacacs: 49, domain: 53, bootps: 67, bootpc: 68, tftp: 69, gopher: 70, finger: 79, www: 80, http: 80, hostname: 101, pop2: 109, pop3: 110, sunrpc: 111, ident: 113, nntp: 119, ntp: 123, 'netbios-ns': 137, 'netbios-dgm': 138, 'netbios-ss': 139, imap4: 143, snmp: 161, snmptrap: 162, bgp: 179, irc: 194, ldap: 389, https: 443, 'pim-auto-rp': 496, isakmp: 500, biff: 512, exec: 512, login: 513, who: 513, cmd: 514, syslog: 514, lpd: 515, talk: 517, rip: 520, uucp: 540, klogin: 543, kshell: 544, ldaps: 636, kerberos: 750, 'non500-isakmp': 4500, 'sip': 5060, 'lotusnotes': 1352, 'citrix-ica': 1494, 'sqlnet': 1521, 'radius': 1645, 'radius-acct': 1646, 'h323': 1720, 'pptp': 1723, 'rtsp': 554, 'aol': 5190, 'ctiqbe': 2748, 'cifs': 3020, 'rdp': 3389, 'netbios-ssn': 139, 'mobile-ip': 434,
}
const ICMP_TYPES: Record<string, number> = { 'echo-reply': 0, unreachable: 3, 'source-quench': 4, redirect: 5, 'alternate-address': 6, echo: 8, 'router-advertisement': 9, 'router-solicitation': 10, 'time-exceeded': 11, 'parameter-problem': 12, 'timestamp-request': 13, 'timestamp-reply': 14, 'information-request': 15, 'information-reply': 16, 'mask-request': 17, 'mask-reply': 18, traceroute: 30, 'packet-too-big': 3, 'ttl-exceeded': 11 }

export const ipToInt = (s: string): number | null => {
  const m = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (!m) return null
  const o = m.slice(1).map(Number)
  if (o.some(x => x > 255)) return null
  return ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3]
}
export const intToIp = (n: number) => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.')

/** Wildcard (inverse mask) to ranges. Contiguous wildcards give one range; non-contiguous ones are expanded up to a limit. */
export function wildcardRanges(addr: number, wild: number): Range[] | null {
  const base = (addr & ~wild) >>> 0
  // contiguous if wild+1 is a power of two
  if (((wild + 1) & wild) >>> 0 === 0) return [[base, (base | wild) >>> 0]]
  // Expand on the non-contiguous high bits; the trailing contiguous low bits form each range.
  let low = 0
  while (low < 32 && ((wild >>> low) & 1)) low++
  const highBits: number[] = []
  for (let b = low; b < 32; b++) if ((wild >>> b) & 1) highBits.push(b)
  if (highBits.length > 10) return null
  const out: Range[] = []
  const lowMask = low === 32 ? 0xffffffff : (2 ** low) - 1
  for (let k = 0; k < 1 << highBits.length; k++) {
    let v = base
    highBits.forEach((b, i) => { if ((k >> i) & 1) v = (v | (2 ** b)) >>> 0 })
    out.push([v, (v + lowMask) >>> 0])
  }
  return out.sort((a, b) => a[0] - b[0])
}

export const maskToWildcard = (mask: number) => (~mask) >>> 0
export const prefixRange = (addr: number, len: number): Range => {
  const size = 2 ** (32 - len)
  const base = Math.floor(addr / size) * size
  return [base, base + size - 1]
}

export interface Groups { network: Map<string, Range[] | null>; service: Map<string, { proto?: Range; ports: Range[] } | null>; protocol: Map<string, Range[]> }

/** Resolves IOS / ASA / NX-OS object-groups (network, service, protocol) into ranges. */
export function objectGroups(c: Config): Groups {
  const g: Groups = { network: new Map(), service: new Map(), protocol: new Map() }
  const nets = new Map<string, Line>()
  for (const l of c.top) {
    let m = l.text.match(/^object-group (?:ip address|network) (\S+)/)
    if (m) { nets.set(m[1], l); continue }
    m = l.text.match(/^object network (\S+)/)
    if (m) { nets.set(m[1], l); continue }
    m = l.text.match(/^object-group (?:service|ip port) (\S+)(?: (tcp|udp|tcp-udp))?/)
    if (m) {
      const proto: Range | undefined = m[2] === 'tcp' ? [6, 6] : m[2] === 'udp' ? [17, 17] : undefined
      const ports: Range[] = []
      let ok = true
      for (const ch of l.children) {
        const t = ch.text.replace(/^\d+\s+/, '')
        const pm = t.match(/^(?:port-object|service-object (?:tcp|udp|tcp-udp)(?: destination)?|tcp|udp|tcp-udp)\s+(eq|range|gt|lt|neq)\s+(\S+)(?:\s+(\S+))?/)
        if (pm) { const r = portSpec(pm[1], [pm[2], pm[3]].filter(Boolean) as string[]); if (r) ports.push(...r.ranges); else ok = false }
        else if (/^(description|group-object)/.test(t)) { if (t.startsWith('group-object')) ok = false }
        else ok = false
      }
      g.service.set(m[1], ok ? { proto, ports } : null)
      continue
    }
    m = l.text.match(/^object-group protocol (\S+)/)
    if (m) g.protocol.set(m[1], l.children.map(ch => { const p = ch.text.replace(/^protocol-object\s+/, ''); const v = PROTOCOLS[p] ?? (p === 'ip' ? -1 : Number(p)); return (v === -1 ? FULL8 : [v, v]) as Range }))
  }
  const resolve = (name: string, seen: Set<string>): Range[] | null => {
    if (g.network.has(name)) return g.network.get(name)!
    const l = nets.get(name)
    if (!l || seen.has(name)) return null
    seen.add(name)
    const out: Range[] = []
    for (const ch of l.children) {
      const t = ch.text.replace(/^\d+\s+/, '').split(/\s+/)
      if (t[0] === 'description') continue
      if (t[0] === 'network-object') t.shift()
      if (t[0] === 'subnet') t.shift()
      if (t[0] === 'host') { const ip = ipToInt(t[1] ?? ''); if (ip === null) return null; out.push([ip, ip]); continue }
      if (t[0] === 'object' || t[0] === 'group-object') { const r = resolve(t[1] ?? '', seen); if (!r) return null; out.push(...r); continue }
      if (t[0] === 'range') { const a = ipToInt(t[1] ?? ''), b = ipToInt(t[2] ?? ''); if (a === null || b === null) return null; out.push([a, b]); continue }
      if (t[0]?.includes('/')) { const [ip, len] = t[0].split('/'); const n = ipToInt(ip); if (n === null) return null; out.push(prefixRange(n, Number(len))); continue }
      const addr = ipToInt(t[0] ?? ''), m = ipToInt(t[1] ?? '')
      if (addr === null || m === null) return null
      // A subnet mask has its top bit set (or is 0.0.0.0 for "any"); otherwise it is a wildcard.
      const r = wildcardRanges(addr, m >= 0x80000000 || m === 0 && t[0] === '0.0.0.0' ? maskToWildcard(m) : m)
      if (!r) return null
      out.push(...r)
    }
    g.network.set(name, out)
    return out
  }
  for (const name of nets.keys()) g.network.set(name, resolve(name, new Set()))
  return g
}

function portSpec(op: string, args: string[]): { ranges: Range[]; used: number } | null {
  const p = (s: string | undefined) => s === undefined ? null : /^\d+$/.test(s) ? Number(s) : PORTS[s] ?? null
  if (op === 'range') { const a = p(args[0]), b = p(args[1]); return a === null || b === null ? null : { ranges: [[Math.min(a, b), Math.max(a, b)]], used: 2 } }
  const v = p(args[0])
  if (v === null) return null
  if (op === 'gt') return { ranges: [[v + 1, 65535]], used: 1 }
  if (op === 'lt') return { ranges: [[0, v - 1]], used: 1 }
  if (op === 'neq') return { ranges: [[0, v - 1], [v + 1, 65535]].filter(r => r[0] <= r[1]) as Range[], used: 1 }
  return { ranges: [[v, v]], used: 1 }
}

/** Parses one ACE body: "permit tcp 10.0.0.0 0.0.0.255 any eq 22 log". `family` decides mask vs wildcard. */
export function parseAce(body: string, family: 'ios' | 'nxos' | 'asa', groups?: Groups, standard = false): Omit<Ace, 'acl' | 'line' | 'text'> | null {
  const t = body.trim().split(/\s+/)
  let i = 0
  let seq: number | undefined
  if (/^\d+$/.test(t[0])) { seq = Number(t[0]); i++ }
  const action = t[i++]
  if (action !== 'permit' && action !== 'deny') return null
  let exact = true
  const og: string[] = []
  const proto: Range[] = []
  if (standard) proto.push(FULL8)
  else {
    const p = t[i++]
    if (p === 'ip' || p === 'ipv4' || p === 'any') proto.push(FULL8)
    else if (p === 'object-group') {
      const name = t[i++]
      og.push(name)
      const pr = groups?.protocol.get(name)
      const sv = groups?.service.get(name)
      if (pr) proto.push(...pr)
      else if (sv?.proto) proto.push(sv.proto)
      else { proto.push(FULL8); exact = false }
    } else if (p === 'object') { i++; proto.push(FULL8); exact = false }
    else if (PROTOCOLS[p] !== undefined) proto.push([PROTOCOLS[p], PROTOCOLS[p]])
    else if (/^\d+$/.test(p)) proto.push([Number(p), Number(p)])
    else return null
  }
  const isPorty = proto.length === 1 && (proto[0][0] === 6 && proto[0][1] === 6 || proto[0][0] === 17 && proto[0][1] === 17)
  const isIcmp = proto.length === 1 && proto[0][0] === 1 && proto[0][1] === 1

  const addr = (): Range[] | null => {
    const a = t[i]
    if (a === undefined) return null
    if (a === 'any' || a === 'any4') { i++; return [FULL_IP] }
    if (a === 'host') { const n = ipToInt(t[i + 1]); i += 2; return n === null ? null : [[n, n]] }
    if (a === 'object-group' || a === 'addrgroup' || a === 'object') {
      const name = t[i + 1]; i += 2
      og.push(name)
      const r = groups?.network.get(name)
      if (!r) { exact = false; return [FULL_IP] }
      return r
    }
    if (a.includes('/')) { const [ip, len] = a.split('/'); const n = ipToInt(ip); i++; return n === null ? null : [prefixRange(n, Number(len))] }
    const n = ipToInt(a)
    if (n === null) return null
    const m = ipToInt(t[i + 1] ?? '')
    if (m === null) { i++; return [[n, n]] } // standard ACL bare host
    i += 2
    const wild = family === 'asa' ? maskToWildcard(m) : m
    const r = wildcardRanges(n, wild)
    if (!r) { exact = false; return [FULL_IP] }
    return r
  }
  const ports = (): Range[] => {
    const op = t[i]
    if (op && /^(eq|gt|lt|neq|range)$/.test(op)) {
      if (op === 'eq' && family !== 'asa') {
        // IOS allows "eq 80 443 8080"
        const out: Range[] = []
        i++
        while (t[i] !== undefined && (/^\d+$/.test(t[i]) || PORTS[t[i]] !== undefined) && !(isIcmp)) { const r = portSpec('eq', [t[i]]); if (!r) break; out.push(...r.ranges); i++ }
        return out.length ? out : [FULL_PORT]
      }
      const r = portSpec(op, [t[i + 1], t[i + 2]])
      if (!r) { exact = false; i += 2; return [FULL_PORT] }
      i += 1 + r.used
      return r.ranges
    }
    if (op === 'object-group' && groups?.service.has(t[i + 1] ?? '')) {
      const s = groups.service.get(t[i + 1])
      og.push(t[i + 1]); i += 2
      if (!s) { exact = false; return [FULL_PORT] }
      return s.ports.length ? s.ports : [FULL_PORT]
    }
    return [FULL_PORT]
  }

  let dst: Range[] = [FULL_IP]
  let dp: Range[] = [FULL_PORT]
  let icmpType: Range[] = [FULL_PORT]
  let est: Range = ANY_EST
  const src = addr()
  if (!src) return null
  const sp = isPorty ? ports() : [FULL_PORT]
  if (standard) return finish()
  const d = addr()
  if (!d) return null
  dst = d
  if (isPorty) dp = ports()
  if (isIcmp && t[i] && !/^(log|log-input|time-range)$/.test(t[i])) {
    const ty = /^\d+$/.test(t[i]) ? Number(t[i]) : ICMP_TYPES[t[i]]
    if (ty !== undefined) { icmpType = [[ty, ty]]; i++ } else exact = false
    if (t[i] && /^\d+$/.test(t[i])) { dp = [[Number(t[i]), Number(t[i])]]; i++ }
  }
  while (i < t.length) {
    const k = t[i++]
    if (k === 'established') est = [1, 1]
    else if (k === 'log' || k === 'log-input' || k === 'log-disable' || k === 'inactive') { if (k === 'inactive') exact = false }
    else if (k === 'interval' || k === 'level') i++
    else if (k === 'time-range') { i++; exact = false }
    else if (/^(dscp|precedence|tos|ttl|fragments|option|ack|fin|psh|rst|syn|urg|match-any|match-all|reflect|packet-length)$/.test(k)) exact = false
    else if (/^\d+$/.test(k)) continue
    else exact = false
  }
  return finish()

  function finish() {
    const s = isIcmp ? icmpType : sp
    const boxes: Box[] = []
    for (const pr of proto) for (const a of src!) for (const b of dst) for (const x of s) for (const y of dp) boxes.push([pr, a, b, x, y, est])
    const full = (r: Range[], f: Range) => r.length === 1 && r[0][0] === f[0] && r[0][1] === f[1]
    const anyAny = action === 'permit' && full(proto, FULL8) && full(src!, FULL_IP) && full(dst, FULL_IP) && exact
    return { seq, action: action as 'permit' | 'deny', boxes, exact, anyAny, objectGroups: og }
  }
}

// ---------- ACL extraction per platform ----------

export function extractAcls(c: Config): Acl[] {
  const groups = objectGroups(c)
  const fam: Acl['family'] = c.platform === 'asa' ? 'asa' : c.platform === 'nxos' ? 'nxos' : 'ios'
  const acls = new Map<string, Acl>()
  const get = (name: string, kind: Acl['kind'], line: number) => {
    let a = acls.get(name)
    if (!a) { a = { name, kind, line, aces: [], family: fam }; acls.set(name, a) }
    return a
  }
  for (const l of c.top) {
    // Named: "ip access-list extended NAME" (IOS) or "ip access-list NAME" (NX-OS)
    let m = l.text.match(/^ip access-list (?:(standard|extended) )?(\S+)$/)
    if (m) {
      const kind = m[1] === 'standard' ? 'standard' : 'extended'
      const acl = get(m[2], kind, l.n)
      for (const ch of children(l, /./)) {
        if (/^(\d+ )?remark\b/.test(ch.text) || /^statistics /.test(ch.text)) continue
        const ace = parseAce(ch.text, fam, groups, kind === 'standard')
        if (ace) acl.aces.push({ ...ace, acl: acl.name, line: ch.n, text: ch.text })
      }
      continue
    }
    // Numbered IOS: "access-list 101 permit ..." ; 1-99 and 1300-1999 are standard
    m = l.text.match(/^access-list (\d+) (permit|deny|remark)\b(.*)$/)
    if (m && fam !== 'asa') {
      const num = Number(m[1])
      const kind = num < 100 || (num >= 1300 && num < 2000) ? 'standard' : 'extended'
      const acl = get(m[1], kind, l.n)
      if (m[2] === 'remark') continue
      const ace = parseAce(`${m[2]}${m[3]}`, fam, groups, kind === 'standard')
      if (ace) acl.aces.push({ ...ace, acl: acl.name, line: l.n, text: l.text })
      continue
    }
    // ASA: "access-list NAME extended permit ..." / "access-list NAME standard permit ..."
    m = l.text.match(/^access-list (\S+) (?:line \d+ )?(extended|standard|remark) ?(.*)$/)
    if (m && fam === 'asa') {
      const acl = get(m[1], m[2] === 'standard' ? 'standard' : 'extended', l.n)
      if (m[2] === 'remark') continue
      const ace = parseAce(m[3], 'asa', groups, m[2] === 'standard')
      if (ace) acl.aces.push({ ...ace, acl: acl.name, line: l.n, text: l.text })
    }
  }
  return [...acls.values()]
}

// ---------- Box algebra ----------

const inter = (a: Range, b: Range): Range | null => { const lo = Math.max(a[0], b[0]), hi = Math.min(a[1], b[1]); return lo <= hi ? [lo, hi] : null }

/** a minus b, as a list of disjoint boxes */
export function subtract(a: Box, b: Box): Box[] {
  const ix = a.map((r, d) => inter(r, b[d]))
  if (ix.some(x => !x)) return [a]
  const out: Box[] = []
  const cur = a.map(r => [...r]) as Box
  for (let d = 0; d < 6; d++) {
    const [lo, hi] = ix[d]!
    if (cur[d][0] < lo) { const piece = cur.map(r => [...r]) as Box; piece[d] = [cur[d][0], lo - 1]; out.push(piece) }
    if (cur[d][1] > hi) { const piece = cur.map(r => [...r]) as Box; piece[d] = [hi + 1, cur[d][1]]; out.push(piece) }
    cur[d] = [lo, hi]
  }
  return out
}

const LIMIT = 4000
/** Returns the part of `target` not covered by `covers`, or null if the computation got too large (treated as "not covered"). */
export function remainder(target: Box[], covers: Box[]): Box[] | null {
  let rest = target
  for (const c of covers) {
    const next: Box[] = []
    for (const r of rest) next.push(...subtract(r, c))
    rest = next
    if (rest.length > LIMIT) return null
    if (!rest.length) break
  }
  return rest
}

export const boxesIntersect = (a: Box[], b: Box[]) => a.some(x => b.some(y => x.every((r, d) => inter(r, y[d]))))

/** Finds shadowed (never matches, earlier ACEs with another action catch its traffic first), redundant (same action already applied) and any/any ACEs. */
export function analyzeAcl(acl: Acl): AceIssue[] {
  const out: AceIssue[] = []
  acl.aces.forEach((ace, idx) => {
    if (ace.anyAny && idx < acl.aces.length - 1) out.push({ acl: acl.name, line: ace.line, text: ace.text, kind: 'any-any', by: [], detail: `Permits all traffic; the ${acl.aces.length - 1 - idx} ACE${acl.aces.length - 1 - idx === 1 ? '' : 's'} after it can never match.` })
    else if (ace.anyAny) out.push({ acl: acl.name, line: ace.line, text: ace.text, kind: 'any-any', by: [], detail: 'Permits all traffic.' })
    if (idx === 0) return
    const earlier = acl.aces.slice(0, idx).filter(e => e.exact)
    const overlapping = earlier.filter(e => boxesIntersect(e.boxes, ace.boxes))
    if (!overlapping.length) return
    const rest = remainder(ace.boxes, overlapping.flatMap(e => e.boxes))
    if (!rest || rest.length) return
    // Fully covered. Decide shadowed vs redundant by what action the covering traffic actually gets.
    const differing = overlapping.filter(e => e.action !== ace.action)
    const single = overlapping.find(e => remainder(ace.boxes, e.boxes)?.length === 0)
    const by = single ? [single.line] : overlapping.map(e => e.line)
    if (differing.length) out.push({ acl: acl.name, line: ace.line, text: ace.text, kind: 'shadowed', by, detail: `Never matches: ${single ? `line ${single.line}` : `lines ${by.join(', ')} together`} already ${differing.length === overlapping.length ? (ace.action === 'permit' ? 'deny' : 'permit') : 'decide'} all of its traffic${differing.length === overlapping.length ? '' : ' (with mixed actions)'}.` })
    else out.push({ acl: acl.name, line: ace.line, text: ace.text, kind: 'redundant', by, detail: `Redundant: ${single ? `line ${single.line}` : `lines ${by.join(', ')} together`} already ${ace.action} all of its traffic. Safe to remove.` })
  })
  return out
}

/** Where ACL names are referenced, mapped to the lines that reference them. */
export function aclReferences(c: Config): Map<string, number[]> {
  const refs = new Map<string, number[]>()
  const add = (name: string, n: number) => { const l = refs.get(name) ?? []; l.push(n); refs.set(name, l) }
  const pats: RegExp[] = [
    /^ip access-group (\S+) (?:in|out)/, /^ipv4 access-group (\S+)/, /^access-class (\S+)/, /^ip access-class (\S+)/,
    /^access-group (\S+) (?:in|out|global)/, /^match (?:ip )?address (?!prefix-list)(.+)$/, /^match access-group name (\S+)/, /^match access-group (\S+)/,
    /^ntp access-group (?:peer|serve|serve-only|query-only) (\S+)/, /^ip http access-class (?:ipv4 )?(\S+)/, /^distribute-list (\S+)/,
    /^ip nat (?:inside|outside) source list (\S+)/, /^(?:ssh|http|telnet) access-list (\S+)/, /^nat \(.*\) .*access-list (\S+)/, /^vpn-filter value (\S+)/,
    /^split-tunnel-network-list value (\S+)/, /^ip igmp access-group (\S+)/, /^snmp-server (?:tftp-server-list|file-transfer access-group) (\S+)/,
    /^ip directed-broadcast (\S+)/, /^ip ssh access-group (\S+)/, /^access-list (\S+) in$/, /^ip port-map .* list (\S+)/,
    /^ip dhcp .* access-list (\S+)/, /^ip pim .* (?:list|group-list) (\S+)/, /^capture \S+ access-list (\S+)/, /^class-map .* access-group (\S+)/, /^vlan filter (\S+)/,
  ]
  for (const l of c.lines) {
    if (l.banner) continue
    const t = l.text
    for (const re of pats) {
      const m = t.match(re)
      if (m) { for (const name of m[1].split(/\s+/)) if (name && !/^(in|out|vrf|ipv6)$/.test(name)) add(name, l.n) }
    }
    // SNMP community or group ACLs: "snmp-server community X RO 10" / "... RO SNMP-ACL" / "use-ipv4-acl NAME"
    const s = t.match(/^snmp-server community \S+(?: view \S+)?(?: (?:RO|RW|ro|rw))?(?: ipv6 \S+)? (\S+)$/)
    if (s && !/^(RO|RW|ro|rw)$/.test(s[1])) add(s[1], l.n)
    const s2 = t.match(/(?:use-ipv4-acl|use-acl|access) (\S+)/)
    if (s2 && t.startsWith('snmp-server')) add(s2[1], l.n)
    const g = t.match(/^snmp-server group \S+ v\d \S+(?: .*)? access (\S+)/)
    if (g) add(g[1], l.n)
  }
  return refs
}

/** Object-group names referenced anywhere other than their own definition. */
export function objectGroupUsage(c: Config): { name: string; line: number; used: boolean }[] {
  const defs = c.top.filter(l => /^(object-group (?:network|service|ip address|ip port|protocol|icmp-type) \S+|object (?:network|service) \S+)/.test(l.text))
  return defs.map(d => {
    const name = d.text.split(/\s+/)[d.text.startsWith('object-group ip') ? 3 : 2]
    const re = new RegExp(`(^|\\s)(object-group|object|addrgroup|portgroup|group-object|network-object object|service-object object)\\s+${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(\\s|$)`)
    const used = c.lines.some(l => !l.banner && l !== d && !l.text.startsWith('object-group ') && !l.text.startsWith('object ') && re.test(l.text)
      || l.parent && l.parent !== d && re.test(l.text) && /^(group-object|network-object object)/.test(l.text))
    return { name, line: d.n, used }
  })
}
