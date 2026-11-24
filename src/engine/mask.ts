// Secret masking on import. Every secret value is replaced before anything is stored or synced.
// The type digit stays (so rules can still see "type 7" or "type 9"), and the value becomes
// <masked> or <masked:weak>, so weakness checks keep working on the masked text.

export interface MaskedSecret {
  line: number
  kind: string
  /** Encoding as shown in the config: 0 (plain), 5 (MD5), 7 (Vigenere, reversible), 8 (PBKDF2), 9 (scrypt), 6 (AES), pbkdf2, encrypted */
  type: string
  weak: boolean
  reason: string
}

export const MASK = '<masked>'
export const MASK_WEAK = '<masked:weak>'

const WEAK_COMMUNITIES = new Set(['public', 'private', 'cisco', 'community', 'snmp', 'admin', 'secret', 'test', 'read', 'write', 'manager', 'monitor', 'default', 'password'])
const VAL = String.raw`(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\S+)`
const BANNER_OPEN = /^banner\s+(?:motd|login|exec|incoming|slip-ppp|prompt-timeout|config-save|asdm)\b\s*(.*)$/i

const isAsaConfig = (text: string) => /^\s*(: )?ASA Version \d/m.test(text) || /^\s*nameif\s+\S+/m.test(text)
const unquote = (v: string) => /^(['"])([\s\S]*)\1$/.test(v) ? v.slice(1, -1) : v

const typeInfo = (t: string): { weak: boolean; reason: string } => {
  switch (t) {
    case '0': case 'clear': return { weak: true, reason: 'Plain text' }
    case '7': return { weak: true, reason: 'Type 7 is reversible obfuscation, not encryption' }
    case '5': return { weak: true, reason: 'Type 5 is salted MD5; use type 8 or 9' }
    case '4': return { weak: true, reason: 'Type 4 is a broken SHA-256 scheme' }
    case '8': return { weak: false, reason: 'Type 8 (PBKDF2-SHA256)' }
    case '9': return { weak: false, reason: 'Type 9 (scrypt)' }
    case '6': return { weak: false, reason: 'Type 6 (AES, reversible with the master key)' }
    case '3': return { weak: true, reason: 'NX-OS type 3 is reversible with a fixed key' }
    case 'sha-crypt': return { weak: false, reason: 'SHA-256/512 crypt hash' }
    case 'localized': return { weak: false, reason: 'Localized SNMPv3 key (hashed per device)' }
    case 'pbkdf2': return { weak: false, reason: 'PBKDF2 hash' }
    case 'hidden': return { weak: false, reason: 'VTPv3 hidden/secret key' }
    case 'encrypted': return { weak: true, reason: 'Legacy ASA MD5-based hash' }
    default: return { weak: true, reason: 'Unknown encoding' }
  }
}

interface Pattern { re: RegExp; kind: string; /** group index of the type digit, 0 = none */ t: number; v: number; defaultType?: string }

// Order matters: specific patterns first. Each regex is anchored to a trimmed logical line and allows flexible whitespace.
const PATTERNS: Pattern[] = [
  { re: new RegExp(`^(enable\\s+(?:secret|password)(?:\\s+level\\s+\\d+)?(?:\\s+algorithm-type\\s+\\S+)?\\s+)([0-9])\\s+(${VAL})(.*)$`), kind: 'enable', t: 2, v: 3 },
  { re: new RegExp(`^(enable\\s+(?:secret|password)(?:\\s+level\\s+\\d+)?(?:\\s+algorithm-type\\s+\\S+)?\\s+)(${VAL})(\\s+(?:pbkdf2|encrypted))?(.*)$`), kind: 'enable', t: 0, v: 2, defaultType: '0' },
  { re: new RegExp(`^(enable\\s+algorithm-type\\s+\\S+\\s+(?:secret|password)\\s+)([0-9])\\s+(${VAL})(.*)$`), kind: 'enable', t: 2, v: 3 },
  { re: new RegExp(`^(enable\\s+algorithm-type\\s+\\S+\\s+(?:secret|password)\\s+)(${VAL})(.*)$`), kind: 'enable', t: 0, v: 2, defaultType: '0' },
  { re: new RegExp(`^(username\\s+\\S+(?:\\s+(?:privilege\\s+\\d+|algorithm-type\\s+\\S+|view\\s+\\S+|access-class\\s+\\S+|role\\s+\\S+))*\\s+(?:secret|password)\\s+)([0-9])\\s+(${VAL})(.*)$`), kind: 'user', t: 2, v: 3 },
  { re: new RegExp(`^(username\\s+\\S+(?:\\s+(?:privilege\\s+\\d+|algorithm-type\\s+\\S+|view\\s+\\S+|access-class\\s+\\S+|role\\s+\\S+))*\\s+(?:secret|password)\\s+)(${VAL})(.*)$`), kind: 'user', t: 0, v: 2, defaultType: '0' },
  // VTP password: "vtp password [0|6|7] <secret> [hidden | secret]"
  { re: new RegExp(`^(vtp\\s+password\\s+)([0-9])\\s+(?!hidden\\b|secret\\b)(${VAL})(.*)$`), kind: 'vtp', t: 2, v: 3 },
  { re: new RegExp(`^(vtp\\s+password\\s+)(${VAL})(\\s+(?:hidden|secret))?(.*)$`), kind: 'vtp', t: 0, v: 2, defaultType: '0' },
  // IS-IS interface and router passwords: "isis password [0|6|7] <secret> [level-1|level-2]", "area-password", "domain-password"
  { re: new RegExp(`^(isis\\s+password\\s+)([0-9])\\s+(?!level-[12]\\b)(${VAL})(.*)$`), kind: 'isis', t: 2, v: 3 },
  { re: new RegExp(`^(isis\\s+password\\s+)(${VAL})(.*)$`), kind: 'isis', t: 0, v: 2, defaultType: '0' },
  { re: new RegExp(`^((?:area-password|domain-password)\\s+)([0-9])\\s+(?!authenticate\\b)(${VAL})(.*)$`), kind: 'isis', t: 2, v: 3 },
  { re: new RegExp(`^((?:area-password|domain-password)\\s+)(${VAL})(.*)$`), kind: 'isis', t: 0, v: 2, defaultType: '0' },
  // NHRP / RSVP / MPLS LDP authentication
  { re: new RegExp(`^(ip\\s+nhrp\\s+authentication\\s+)(${VAL})(.*)$`), kind: 'nhrp', t: 0, v: 2, defaultType: '0' },
  { re: new RegExp(`^(ip\\s+rsvp\\s+authentication\\s+key\\s+)([0-9])\\s+(${VAL})(.*)$`), kind: 'rsvp', t: 2, v: 3 },
  { re: /^(ip\s+rsvp\s+authentication\s+key\s+)(.+?)\s*$/, kind: 'rsvp', t: 0, v: 2, defaultType: '0' },
  { re: new RegExp(`^(mpls\\s+ldp\\s+neighbor\\s+(?:vrf\\s+\\S+\\s+)?\\S+\\s+password\\s+)([0-9])\\s+(${VAL})(.*)$`), kind: 'ldp', t: 2, v: 3 },
  { re: new RegExp(`^(mpls\\s+ldp\\s+neighbor\\s+(?:vrf\\s+\\S+\\s+)?\\S+\\s+password\\s+)(clear|encrypted)\\s+(${VAL})(.*)$`), kind: 'ldp', t: 2, v: 3 },
  { re: new RegExp(`^(mpls\\s+ldp\\s+neighbor\\s+(?:vrf\\s+\\S+\\s+)?\\S+\\s+password\\s+)(${VAL})(.*)$`), kind: 'ldp', t: 0, v: 2, defaultType: '0' },
  { re: new RegExp(`^(password\\s+)([0-9])\\s+(${VAL})(.*)$`), kind: 'line', t: 2, v: 3 },
  { re: new RegExp(`^(password\\s+)(${VAL})(.*)$`), kind: 'line', t: 0, v: 2, defaultType: '0' },
  { re: new RegExp(`^(snmp-server\\s+community\\s+)(${VAL})(.*)$`), kind: 'snmp', t: 0, v: 2, defaultType: 'community' },
  // ASA: "snmp-server host <ifc> <host> [poll|trap] community [0|8] <string> [version 2c]"
  { re: new RegExp(`^(snmp-server\\s+host\\s+.*?\\bcommunity\\s+(?:[08]\\s+)?)(${VAL})(.*)$`), kind: 'snmp', t: 0, v: 2, defaultType: 'community' },
  { re: new RegExp(`^(snmp-server\\s+host\\s+\\S+(?:\\s+vrf\\s+\\S+)?(?:\\s+(?:traps|informs))?(?:\\s+version\\s+(?:1|2c))?\\s+)(${VAL})(.*)$`), kind: 'snmp', t: 0, v: 2, defaultType: 'community' },
  // AAA servers: "tacacs-server ... key", "radius-server ... key", "server-private <host> ... key", ASA "ldap-login-password" / "radius-common-pw"
  { re: new RegExp(`^(server-private\\s+\\S+(?:\\s+.*?)?\\s+key\\s+)([0-9])\\s+(${VAL})(.*)$`), kind: 'aaa-key', t: 2, v: 3 },
  { re: new RegExp(`^(server-private\\s+\\S+(?:\\s+.*?)?\\s+key\\s+)(${VAL})(.*)$`), kind: 'aaa-key', t: 0, v: 2, defaultType: '0' },
  { re: new RegExp(`^((?:tacacs-server|radius-server)\\s+(?:host\\s+.*?\\s+)?key\\s+)([0-9])\\s+(${VAL})(.*)$`), kind: 'aaa-key', t: 2, v: 3 },
  { re: new RegExp(`^((?:tacacs-server|radius-server)\\s+(?:host\\s+.*?\\s+)?key\\s+)(${VAL})(.*)$`), kind: 'aaa-key', t: 0, v: 2, defaultType: '0' },
  { re: new RegExp(`^((?:ldap-login-password|radius-common-pw)\\s+)([0-9])\\s+(${VAL})(.*)$`), kind: 'aaa-key', t: 2, v: 3 },
  { re: new RegExp(`^((?:ldap-login-password|radius-common-pw)\\s+)(${VAL})(.*)$`), kind: 'aaa-key', t: 0, v: 2, defaultType: '0' },
  // "ip ftp password 7 ...", "ppp chap password 7 ...", "ppp pap sent-username u password 7 ..."
  { re: new RegExp(`^((?:ip\\s+(?:ftp|http\\s+client)\\s+password|ppp\\s+chap\\s+password|ppp\\s+pap\\s+sent-username\\s+\\S+\\s+password)\\s+)([0-9])\\s+(${VAL})(.*)$`), kind: 'line', t: 2, v: 3 },
  { re: new RegExp(`^((?:ip\\s+(?:ftp|http\\s+client)\\s+password|ppp\\s+chap\\s+password|ppp\\s+pap\\s+sent-username\\s+\\S+\\s+password)\\s+)(${VAL})(.*)$`), kind: 'line', t: 0, v: 2, defaultType: '0' },
  // HSRP / VRRP / GLBP: "standby 1 authentication md5 key-string 7 ...", "standby 1 authentication cisco", "vrrp 1 authentication text X"
  { re: new RegExp(`^((?:standby|vrrp|glbp)\\s+(?:\\d+\\s+)?authentication\\s+(?:md5\\s+key-string\\s+|text\\s+)?)([0-9])\\s+(${VAL})(.*)$`), kind: 'fhrp', t: 2, v: 3 },
  { re: new RegExp(`^((?:standby|vrrp|glbp)\\s+(?:\\d+\\s+)?authentication\\s+(?:md5\\s+key-string\\s+|text\\s+)?)(?!md5\\b|text\\b|key-chain\\b)(${VAL})(.*)$`), kind: 'fhrp', t: 0, v: 2, defaultType: '0' },
  // IOS keyring: "pre-shared-key address 192.0.2.1 key MYKEY" (the address is not the secret)
  { re: new RegExp(`^(pre-shared-key\\s+(?:address\\s+\\S+(?:\\s+\\S+)?|hostname\\s+\\S+)\\s+key\\s+)([0-9])\\s+(${VAL})(.*)$`), kind: 'psk', t: 2, v: 3 },
  { re: new RegExp(`^(pre-shared-key\\s+(?:address\\s+\\S+(?:\\s+\\S+)?|hostname\\s+\\S+)\\s+key\\s+)(${VAL})(.*)$`), kind: 'psk', t: 0, v: 2, defaultType: '0' },
  { re: new RegExp(`^(key\\s+)([0-9])\\s+(${VAL})(.*)$`), kind: 'server-key', t: 2, v: 3 },
  { re: new RegExp(`^(key\\s+)(${VAL})(.*)$`), kind: 'server-key', t: 0, v: 2, defaultType: '0' },
  { re: new RegExp(`^(key-string\\s+)([0-9])\\s+(${VAL})(.*)$`), kind: 'key-chain', t: 2, v: 3 },
  { re: new RegExp(`^(key-string\\s+)(${VAL})(.*)$`), kind: 'key-chain', t: 0, v: 2, defaultType: '0' },
  { re: new RegExp(`^(ntp\\s+authentication-key\\s+\\d+\\s+(?:md5|sha1|sha256|hmac-sha1|hmac-sha256)\\s+)([0-9])\\s+(${VAL})(.*)$`), kind: 'ntp', t: 2, v: 3 },
  { re: new RegExp(`^(ntp\\s+authentication-key\\s+\\d+\\s+(?:md5|sha1|sha256|hmac-sha1|hmac-sha256)\\s+)(${VAL})(?:\\s+([0-9]))?(.*)$`), kind: 'ntp', t: 3, v: 2, defaultType: '0' },
  { re: new RegExp(`^(ip\\s+ospf\\s+(?:message-digest-key\\s+\\d+\\s+(?:md5|sha-1|hmac-sha-\\d+)|authentication-key)\\s+)([0-9])\\s+(${VAL})(.*)$`), kind: 'ospf', t: 2, v: 3 },
  { re: new RegExp(`^(ip\\s+ospf\\s+(?:message-digest-key\\s+\\d+\\s+(?:md5|sha-1|hmac-sha-\\d+)|authentication-key)\\s+)(${VAL})(.*)$`), kind: 'ospf', t: 0, v: 2, defaultType: '0' },
  { re: new RegExp(`^(neighbor\\s+\\S+\\s+password\\s+)([0-9])\\s+(${VAL})(.*)$`), kind: 'bgp', t: 2, v: 3 },
  { re: new RegExp(`^(neighbor\\s+\\S+\\s+password\\s+)(clear|encrypted)\\s+(${VAL})(.*)$`), kind: 'bgp', t: 2, v: 3 },
  { re: new RegExp(`^(neighbor\\s+\\S+\\s+password\\s+)(${VAL})(.*)$`), kind: 'bgp', t: 0, v: 2, defaultType: '0' },
  { re: new RegExp(`^(crypto\\s+isakmp\\s+key\\s+)([0-9])\\s+(${VAL})(.*)$`), kind: 'psk', t: 2, v: 3 },
  { re: new RegExp(`^(crypto\\s+isakmp\\s+key\\s+)(${VAL})(.*)$`), kind: 'psk', t: 0, v: 2, defaultType: '0' },
  { re: new RegExp(`^((?:ikev1\\s+|ikev2\\s+(?:local|remote)-authentication\\s+)?pre-shared-key(?:\\s+(?:local|remote))?\\s+)([0-9])\\s+(${VAL})(.*)$`), kind: 'psk', t: 2, v: 3 },
  { re: new RegExp(`^((?:ikev1\\s+|ikev2\\s+(?:local|remote)-authentication\\s+)?pre-shared-key(?:\\s+(?:local|remote))?\\s+)(${VAL})(.*)$`), kind: 'psk', t: 0, v: 2, defaultType: '0' },
  { re: new RegExp(`^(failover\\s+key\\s+(?:hex\\s+)?)([0-9])\\s+(${VAL})(.*)$`), kind: 'psk', t: 2, v: 3 },
  { re: new RegExp(`^(failover\\s+key\\s+(?:hex\\s+)?)(${VAL})(.*)$`), kind: 'psk', t: 0, v: 2, defaultType: '0' },
  { re: new RegExp(`^(passwd\\s+)(${VAL})(\\s+(?:pbkdf2|encrypted))?(.*)$`), kind: 'enable', t: 0, v: 2, defaultType: '0' },
  { re: new RegExp(`^(wpa-psk\\s+ascii\\s+)([0-9])\\s+(${VAL})(.*)$`), kind: 'psk', t: 2, v: 3 },
  { re: new RegExp(`^(wpa-psk\\s+ascii\\s+)(${VAL})(.*)$`), kind: 'psk', t: 0, v: 2, defaultType: '0' },
]

const isMasked = (v: string) => {
  const raw = unquote(v)
  return raw === MASK || raw === MASK_WEAK
}

function weakCommunity(v: string) {
  const raw = unquote(v)
  return WEAK_COMMUNITIES.has(raw.toLowerCase()) || raw.length < 10 || !/[^a-z]/i.test(raw)
}

// SNMPv3 users carry two secrets: "auth sha X priv aes 128 Y" (IOS), "auth md5 X priv Y localizedkey" (NX-OS),
// "v3 encrypted auth sha X priv aes 256 Y" (ASA). Mask both values.
function maskSnmpUser(body: string, line: number, secrets: MaskedSecret[]) {
  const type = /\b(localizedkey|localized-key|encrypted)\b/.test(body) ? 'localized' : '0'
  const info = typeInfo(type)
  const re = new RegExp(`\\b(auth\\s+(?:md5|sha\\S*)\\s+|priv\\s+(?:(?:aes(?:-\\d+)?|3des|des)(?:\\s+\\d{3})?\\s+)?)(${VAL})`, 'g')
  return body.replace(re, (all, kw: string, v: string) => {
    const rawVal = unquote(v)
    if (isMasked(v) || /^(access|localizedkey|localized-key|engineID)$/.test(rawVal)) return all
    secrets.push({ line, kind: 'snmpv3', type, weak: info.weak, reason: info.reason })
    return kw + (info.weak ? MASK_WEAK : MASK)
  })
}

interface Segment { lineIdx: number; physOffset: number; len: number; joinedStart: number; joinedEnd: number }

function buildLogicalLine(lines: string[], startIdx: number): { endIdx: number; lead: string; body: string; segs: Segment[] } {
  const firstLead = lines[startIdx].match(/^\s*/)![0]
  if (!/\\\s*$/.test(lines[startIdx]) || startIdx + 1 >= lines.length || !lines[startIdx + 1].trim() || /^\s*(!|end\s*$)/i.test(lines[startIdx + 1])) {
    const body = lines[startIdx].slice(firstLead.length)
    return {
      endIdx: startIdx,
      lead: firstLead,
      body,
      segs: [{ lineIdx: startIdx, physOffset: firstLead.length, len: body.length, joinedStart: 0, joinedEnd: body.length }],
    }
  }
  const segs: Segment[] = []
  let joined = ''
  let j = startIdx
  while (j < lines.length) {
    const raw = lines[j]
    const segLead = raw.match(/^\s*/)![0]
    const hasCont = j + 1 < lines.length && /\\\s*$/.test(raw) && lines[j + 1].trim() && !/^\s*(!|end\s*$)/i.test(lines[j + 1])
    const endPos = hasCont ? raw.lastIndexOf('\\') : raw.length
    const part = raw.slice(segLead.length, endPos)
    if (segs.length > 0 && joined && !/\s$/.test(joined) && segLead.length > 0) joined += ' '
    const joinedStart = joined.length
    joined += part
    segs.push({ lineIdx: j, physOffset: segLead.length, len: part.length, joinedStart, joinedEnd: joined.length })
    if (!hasCont) break
    j++
  }
  return { endIdx: j, lead: firstLead, body: joined, segs }
}

function replaceSpan(lines: string[], segs: Segment[], a: number, b: number, token: string): number {
  let firstLine = segs[0].lineIdx
  let replaced = false
  for (const seg of segs) {
    if (b <= seg.joinedStart || a >= seg.joinedEnd) continue
    const localA = Math.max(a, seg.joinedStart) - seg.joinedStart + seg.physOffset
    const localB = Math.min(b, seg.joinedEnd) - seg.joinedStart + seg.physOffset
    const rep = replaced ? '' : token
    if (!replaced) { firstLine = seg.lineIdx; replaced = true }
    lines[seg.lineIdx] = lines[seg.lineIdx].slice(0, localA) + rep + lines[seg.lineIdx].slice(localB)
  }
  return firstLine
}

const indentOf = (s: string) => {
  let i = 0
  while (i < s.length && (s[i] === ' ' || s[i] === '\t')) i += s[i] === '\t' ? 8 : 1
  return i
}

/** Masks secrets in a config. Returns the masked text plus a list of what was masked (never the values). */
export function maskSecrets(text: string): { text: string; secrets: MaskedSecret[] } {
  const secrets: MaskedSecret[] = []
  const normalized = text.replace(/\r\n?/g, '\n')
  const asa = isAsaConfig(normalized)
  const lines = normalized.split('\n')
  const stack: { indent: number; text: string }[] = []
  let bannerEnd: string | null = null

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]
    if (bannerEnd !== null) {
      if (raw.includes(bannerEnd)) bannerEnd = null
      continue
    }
    const lead = raw.match(/^\s*/)![0]
    const body = raw.slice(lead.length)
    const indent = indentOf(raw)
    if (!body.trim()) continue
    if (body.startsWith('!') || (indent === 0 && body.startsWith(':'))) {
      if (indent === 0) stack.length = 0
      continue
    }
    while (stack.length && stack[stack.length - 1].indent >= indent) stack.pop()
    const inKeyChain = stack.some(b => /^key\s+chain\b/i.test(b.text))
    const inServerBlock = stack.some(b => /^(?:tacacs|radius|ldap)\s+server\b|^aaa-server\b|^crypto\s+keyring\b/i.test(b.text))
    stack.push({ indent, text: body })

    if (!lead) {
      const bm = body.match(BANNER_OPEN)
      if (bm) {
        if (!asa) {
          const rest = bm[1]
          const delim = rest.startsWith('^C') ? '^C' : rest[0] ?? ''
          if (delim && !rest.slice(delim.length).includes(delim) && lines.slice(i + 1).some(l => l.includes(delim))) {
            bannerEnd = delim
          }
        }
        continue
      }
    }

    const { endIdx, body: logical, segs } = buildLogicalLine(lines, i)
    if (/^snmp-server\s+user\s+/.test(logical)) {
      if (segs.length === 1) {
        lines[i] = lead + maskSnmpUser(logical, i + 1, secrets)
      } else {
        // Mask segment by segment if a multi-line SNMPv3 user command uses backslash continuations.
        let lineText = logical
        const re = new RegExp(`\\b(auth\\s+(?:md5|sha\\S*)\\s+|priv\\s+(?:(?:aes(?:-\\d+)?|3des|des)(?:\\s+\\d{3})?\\s+)?)(${VAL})`, 'gd')
        let match: RegExpExecArray | null
        const edits: { a: number; b: number; token: string }[] = []
        const type = /\b(localizedkey|localized-key|encrypted)\b/.test(logical) ? 'localized' : '0'
        const info = typeInfo(type)
        while ((match = re.exec(lineText)) !== null) {
          const v = match[2]
          const rawVal = unquote(v)
          if (isMasked(v) || /^(access|localizedkey|localized-key|engineID)$/.test(rawVal)) continue
          edits.push({ a: match.indices![2]![0], b: match.indices![2]![1], token: info.weak ? MASK_WEAK : MASK })
        }
        for (let e = edits.length - 1; e >= 0; e--) {
          const lineIdx = replaceSpan(lines, segs, edits[e].a, edits[e].b, edits[e].token)
          secrets.push({ line: lineIdx + 1, kind: 'snmpv3', type, weak: info.weak, reason: info.reason })
        }
      }
      i = endIdx
      continue
    }

    for (const p of PATTERNS) {
      const m = new RegExp(p.re.source, 'd').exec(logical)
      if (!m) continue
      const value = m[p.v]
      if (!value || isMasked(value)) break
      const rawVal = unquote(value)
      // Keywords that look like values (e.g. "snmp-server host 10.0.0.1 version 3 priv USER") are not secrets.
      if (p.kind === 'snmp' && /^snmp-server\s+host\b/.test(logical) && /\bversion\s+3\b/.test(logical)) break
      if (p.kind === 'snmp' && /^(view|context|host)$/.test(rawVal)) break
      if (p.kind === 'line' && /^(encryption|policy|aaa|strength-check|min-length|aging|history|lockout)$/.test(rawVal)) break
      if (p.kind === 'server-key') {
        const nextLine = lines[endIdx + 1]?.trim() ?? ''
        const nextDeeperKeyString = /^key-string\s+/i.test(nextLine) && indentOf(lines[endIdx + 1] ?? '') > indent
        if (!lead || /^(chain|config-key)$/.test(rawVal) || (inKeyChain && /^key\s+\d+$/.test(logical)) || (/^key\s+\d+$/.test(logical) && !inServerBlock && nextDeeperKeyString)) break
      }
      if (p.kind === 'snmp' && /^(use-vrf|filter-vrf|source-interface)$/.test(rawVal)) break
      let type = p.t ? m[p.t] ?? p.defaultType ?? '0' : p.defaultType ?? '0'
      // Infer encoded type when type digit is omitted or normalized
      if (type === 'clear') type = '0'
      if (type === 'encrypted' && /^\$[56]\$/.test(rawVal)) type = 'sha-crypt'
      if (type === '5' && /^\$[56]\$/.test(rawVal)) type = 'sha-crypt'
      if (type === '0') {
        if (/^\$8\$/.test(rawVal)) type = '8'
        else if (/^\$(?:9|14)\$/.test(rawVal)) type = '9'
        else if (/^\$[56]\$/.test(rawVal)) type = 'sha-crypt'
        else if (/^\$1\$/.test(rawVal)) type = '5'
      }
      const tail = logical.slice(m.indices![p.v]![1])
      if (p.kind === 'vtp' && /^\s+(?:hidden|secret)\b/.test(tail)) type = 'hidden'
      // ASA: "enable password <hash> pbkdf2|encrypted", "username x password <hash> [privilege 15] pbkdf2|encrypted".
      const asaTail = type === '0' && tail.match(/\b(pbkdf2|encrypted)\b/)
      if (asaTail) type = asaTail[1]
      let info = typeInfo(type)
      if (type === 'community') info = weakCommunity(value) ? { weak: true, reason: 'Default, short or dictionary-like community string' } : { weak: false, reason: 'Community string' }
      if (p.kind === 'enable' && /^enable\s+password\b/.test(logical) && type !== 'pbkdf2') info = { weak: true, reason: type === '7' ? 'enable password with type 7 is reversible; use enable secret' : 'enable password is not hashed; use enable secret' }
      const token = info.weak ? MASK_WEAK : MASK
      const [a, b] = m.indices![p.v]!
      const maskedLine = replaceSpan(lines, segs, a, b, token)
      secrets.push({ line: maskedLine + 1, kind: p.kind, type: type === 'community' ? 'community' : type, weak: info.weak, reason: info.reason })
      break
    }
    i = endIdx
  }
  return { text: lines.join('\n'), secrets }
}

/** Fallback masker for any line still flagged by looksSecret after maskSecrets(). */
export function maskUnrecognisedLine(line: string): string {
  const lead = line.match(/^\s*/)![0]
  const body = line.slice(lead.length)
  const kwRe = new RegExp(
    `(\\b(?:password|secret|community|key-string|pre-shared-key|passwd|wpa-psk|shared-secret|auth-key|authentication-key|ldap-login-password|radius-common-pw|nhrp\\s+authentication|area-password|domain-password|passphrase|psk|key)\\b(?:\\s+(?:[0-9]|clear|encrypted|md5|sha1|sha256|text))?\\s+)(${VAL})(.*)$`,
    'i'
  )
  const m = body.match(kwRe)
  if (!m) return line.replace(/\S+$/, MASK)
  const rest = m[3]
  const safeTail = rest && !/^\s+(?:level-[12]|hidden|secret|ro|rw|pbkdf2|encrypted|prefer|privilege\s+\d+|version\s+\S+)\s*$/i.test(rest)
    ? rest.replace(/\S+/g, MASK)
    : rest
  return lead + body.slice(0, m.index!) + m[1] + MASK + safeTail
}

/** Heuristic check used by the import report: does a line still look like it carries a clear-text secret? */
export function looksSecret(line: string) {
  const t = line.trim()
  if (!t || /^(!|:(\s|$))/.test(t)) return false
  if (/<masked/.test(t)) {
    if (/^snmp-server\s+user\b/.test(t)) {
      const stripped = t.replace(new RegExp(`<masked(?::weak)?>`, 'g'), '')
      return /\b(?:auth\s+(?:md5|sha\S*)|priv\s+(?:(?:aes(?:-\d+)?|3des|des)(?:\s+\d{3})?))\s+(?!access\b|localizedkey\b|localized-key\b|engineID\b)\S+/.test(stripped)
    }
    return false
  }
  if (/^(no\s+|service\s+password|aaa\s+|ip\s+ssh\b|crypto\s+key\b|ntp\s+(?:trusted-key|authenticate)\b|key\s+chain\b|key\s+\d+$|security\s+passwords\b|password-policy\b|password\s+encryption\b|password\s+strength\b|(?:set|match)\s+community\b|ip\s+(?:community-list|bgp-community)\b|description\s+|remark\s+|.*\bremark\s+|banner\s+|ip\s+rsvp\s+authentication\s+key-chain\b|ip\s+ospf\s+authentication(?:\s+message-digest)?$|ip\s+ospf\s+message-digest$|isis\s+authentication-type\b)/.test(t)) return false
  if (/^ntp\s+(?:server|peer)\s+\S+(?:\s+(?:vrf\s+\S+|version\s+\d+|prefer|burst|iburst|minpoll\s+\d+|maxpoll\s+\d+|source\s+\S+))*\s+key\s+\d+(?:\s+(?:prefer|burst|iburst|version\s+\d+|minpoll\s+\d+|maxpoll\s+\d+|source\s+\S+))*\s*$/i.test(t)) return false
  return /(^|\s)(password|secret|community|key|key-string|pre-shared-key|passwd|psk|wpa-psk|passphrase|shared-secret|auth-key|authentication-key|ldap-login-password|radius-common-pw|nhrp\s+authentication|area-password|domain-password)\s+\S+/i.test(t)
    && !/(^|\s)(key|password|secret)\s+(chain|config-key|change|exchange|encryption|policy|strength-check|mode|type|list)\b/i.test(t)
}

/** Idempotent defense-in-depth sanitizer: applies maskSecrets and masks any unrecognised secret-like lines outside closed banners. */
export function sanitizeConfigText(text: string): string {
  const { text: masked } = maskSecrets(text)
  const asa = isAsaConfig(masked)
  const raw = masked.split('\n')
  let bannerEnd: string | null = null
  let changed = false
  for (let i = 0; i < raw.length; i++) {
    const line = raw[i]
    if (bannerEnd !== null) {
      if (line.includes(bannerEnd)) bannerEnd = null
      continue
    }
    const trimmed = line.trim()
    if (!asa && /^banner\s+/.test(trimmed) && line.match(/^\s*/)?.[0] === '') {
      const m = trimmed.match(BANNER_OPEN)
      if (m) {
        const rest = m[1]
        const delim = rest.startsWith('^C') ? '^C' : rest[0] ?? ''
        if (delim && !rest.slice(delim.length).includes(delim) && raw.slice(i + 1).some(l => l.includes(delim))) {
          bannerEnd = delim
        }
        continue
      }
    }
    if (looksSecret(line)) {
      raw[i] = maskUnrecognisedLine(line)
      changed = true
    }
  }
  return changed ? raw.join('\n') : masked
}
