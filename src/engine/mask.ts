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

const typeInfo = (t: string): { weak: boolean; reason: string } => {
  switch (t) {
    case '0': return { weak: true, reason: 'Plain text' }
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
    case 'encrypted': return { weak: true, reason: 'Legacy ASA MD5-based hash' }
    default: return { weak: true, reason: 'Unknown encoding' }
  }
}

interface Pattern { re: RegExp; kind: string; /** group index of the type digit, 0 = none */ t: number; v: number; defaultType?: string }

// Order matters: specific patterns first. Each regex is anchored to a trimmed line.
const PATTERNS: Pattern[] = [
  { re: /^(enable (?:secret|password)(?: level \d+)? )([0-9]) (\S+)(.*)$/, kind: 'enable', t: 2, v: 3 },
  { re: /^(enable (?:secret|password)(?: level \d+)? )(\S+)( (pbkdf2|encrypted))?(.*)$/, kind: 'enable', t: 0, v: 2, defaultType: '0' },
  { re: /^(username \S+(?: privilege \d+)?(?: algorithm-type \S+)? (?:secret|password) )([0-9]) (\S+)(.*)$/, kind: 'user', t: 2, v: 3 },
  { re: /^(username \S+(?: privilege \d+)? (?:secret|password) )(\S+)(.*)$/, kind: 'user', t: 0, v: 2, defaultType: '0' },
  { re: /^(password )([0-9]) (\S+)(.*)$/, kind: 'line', t: 2, v: 3 },
  { re: /^(password )(\S+)(.*)$/, kind: 'line', t: 0, v: 2, defaultType: '0' },
  { re: /^(snmp-server community )(\S+)(.*)$/, kind: 'snmp', t: 0, v: 2, defaultType: 'community' },
  // ASA: "snmp-server host <ifc> <host> [poll|trap] community [0|8] <string> [version 2c]"
  { re: /^(snmp-server host .*?\bcommunity (?:[08] )?)(\S+)(.*)$/, kind: 'snmp', t: 0, v: 2, defaultType: 'community' },
  { re: /^(snmp-server host \S+(?: vrf \S+)?(?: (?:traps|informs))?(?: version (?:1|2c))? )(\S+)(.*)$/, kind: 'snmp', t: 0, v: 2, defaultType: 'community' },
  // "radius-server host 10.1.1.1 auth-port 1812 acct-port 1813 key 7 ..." has options before the key.
  { re: /^((?:tacacs-server|radius-server) (?:host .*? )?key )([0-9]) (\S+)(.*)$/, kind: 'aaa-key', t: 2, v: 3 },
  { re: /^((?:tacacs-server|radius-server) (?:host .*? )?key )(\S+)(.*)$/, kind: 'aaa-key', t: 0, v: 2, defaultType: '0' },
  // "ip ftp password 7 ...", "ppp chap password 7 ...", "ppp pap sent-username u password 7 ..."
  { re: /^((?:ip (?:ftp|http client) password|ppp chap password|ppp pap sent-username \S+ password) )([0-9]) (\S+)(.*)$/, kind: 'line', t: 2, v: 3 },
  { re: /^((?:ip (?:ftp|http client) password|ppp chap password|ppp pap sent-username \S+ password) )(\S+)(.*)$/, kind: 'line', t: 0, v: 2, defaultType: '0' },
  // HSRP / VRRP / GLBP: "standby 1 authentication md5 key-string 7 ...", "standby 1 authentication cisco", "vrrp 1 authentication text X"
  { re: /^((?:standby|vrrp|glbp) (?:\d+ )?authentication (?:md5 key-string |text )?)([0-9]) (\S+)(.*)$/, kind: 'fhrp', t: 2, v: 3 },
  { re: /^((?:standby|vrrp|glbp) (?:\d+ )?authentication (?:md5 key-string |text )?)(?!md5\b|text\b)(\S+)(.*)$/, kind: 'fhrp', t: 0, v: 2, defaultType: '0' },
  // IOS keyring: "pre-shared-key address 192.0.2.1 key MYKEY" (the address is not the secret)
  { re: /^(pre-shared-key (?:address \S+(?: \S+)?|hostname \S+) key )([0-9]) (\S+)(.*)$/, kind: 'psk', t: 2, v: 3 },
  { re: /^(pre-shared-key (?:address \S+(?: \S+)?|hostname \S+) key )(\S+)(.*)$/, kind: 'psk', t: 0, v: 2, defaultType: '0' },
  { re: /^(key )([0-9]) (\S+)(.*)$/, kind: 'server-key', t: 2, v: 3 },
  { re: /^(key )(\S+)(.*)$/, kind: 'server-key', t: 0, v: 2, defaultType: '0' },
  { re: /^(key-string )([0-9]) (\S+)(.*)$/, kind: 'key-chain', t: 2, v: 3 },
  { re: /^(key-string )(\S+)(.*)$/, kind: 'key-chain', t: 0, v: 2, defaultType: '0' },
  { re: /^(ntp authentication-key \d+ md5 )(\S+)(?: ([0-9]))?(.*)$/, kind: 'ntp', t: 3, v: 2, defaultType: '0' },
  { re: /^(ip ospf (?:message-digest-key \d+ md5|authentication-key) )([0-9]) (\S+)(.*)$/, kind: 'ospf', t: 2, v: 3 },
  { re: /^(ip ospf (?:message-digest-key \d+ md5|authentication-key) )(\S+)(.*)$/, kind: 'ospf', t: 0, v: 2, defaultType: '0' },
  { re: /^(neighbor \S+ password )([0-9]) (\S+)(.*)$/, kind: 'bgp', t: 2, v: 3 },
  { re: /^(neighbor \S+ password )(\S+)(.*)$/, kind: 'bgp', t: 0, v: 2, defaultType: '0' },
  { re: /^(crypto isakmp key )([0-9]) (\S+)(.*)$/, kind: 'psk', t: 2, v: 3 },
  { re: /^(crypto isakmp key )(\S+)(.*)$/, kind: 'psk', t: 0, v: 2, defaultType: '0' },
  { re: /^((?:ikev1 |ikev2 (?:local|remote)-authentication )?pre-shared-key(?: local| remote)? )([0-9]) (\S+)(.*)$/, kind: 'psk', t: 2, v: 3 },
  { re: /^((?:ikev1 |ikev2 (?:local|remote)-authentication )?pre-shared-key(?: local| remote)? )(\S+)(.*)$/, kind: 'psk', t: 0, v: 2, defaultType: '0' },
  { re: /^(passwd )(\S+)( encrypted)?(.*)$/, kind: 'enable', t: 0, v: 2 },
  { re: /^(wpa-psk ascii )([0-9]) (\S+)(.*)$/, kind: 'psk', t: 2, v: 3 },
]

const isMasked = (v: string) => v === MASK || v === MASK_WEAK

function weakCommunity(v: string) {
  return WEAK_COMMUNITIES.has(v.toLowerCase()) || v.length < 10 || !/[^a-z]/i.test(v)
}

// SNMPv3 users carry two secrets: "auth sha X priv aes 128 Y" (IOS), "auth md5 X priv Y localizedkey" (NX-OS),
// "v3 encrypted auth sha X priv aes 256 Y" (ASA). Mask both values.
function maskSnmpUser(body: string, line: number, secrets: MaskedSecret[]) {
  const type = /\b(localizedkey|localized-key|encrypted)\b/.test(body) ? 'localized' : '0'
  const info = typeInfo(type)
  return body.replace(/\b(auth (?:md5|sha\S*) |priv (?:(?:aes(?:-\d+)?|3des|des)(?: \d{3})? )?)(\S+)/g, (all, kw: string, v: string) => {
    if (isMasked(v) || /^(access|localizedkey|localized-key|engineID)$/.test(v)) return all
    secrets.push({ line, kind: 'snmpv3', type, weak: info.weak, reason: info.reason })
    return kw + (info.weak ? MASK_WEAK : MASK)
  })
}

/** Masks secrets in a config. Returns the masked text plus a list of what was masked (never the values). */
export function maskSecrets(text: string): { text: string; secrets: MaskedSecret[] } {
  const secrets: MaskedSecret[] = []
  const lines = text.replace(/\r\n?/g, '\n').split('\n')
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]
    const lead = raw.match(/^\s*/)![0]
    const body = raw.slice(lead.length)
    if (/^snmp-server user /.test(body)) { lines[i] = lead + maskSnmpUser(body, i + 1, secrets); continue }
    // NX-OS "username admin password 5 $5$..." and ASA "username x password y privilege 15" fit the user patterns.
    for (const p of PATTERNS) {
      const m = new RegExp(p.re.source, 'd').exec(body)
      if (!m) continue
      const value = m[p.v]
      if (!value || isMasked(value)) break
      // Keywords that look like values (e.g. "snmp-server host 10.0.0.1 version 3 priv USER") are not secrets.
      if (p.kind === 'snmp' && body.startsWith('snmp-server host') && /\bversion 3\b/.test(body)) break
      if (p.kind === 'snmp' && /^(view|context|host)$/.test(value)) break
      if (p.kind === 'line' && /^(encryption|policy|aaa)$/.test(value)) break
      if (p.kind === 'server-key' && (/^key \d+$/.test(body) || !lead || /^(chain|config-key)$/.test(value))) break
      if (p.kind === 'snmp' && /^(use-vrf|filter-vrf|source-interface)$/.test(value)) break
      let type = p.t ? m[p.t] ?? p.defaultType ?? '0' : p.defaultType ?? '0'
      // NX-OS / IOS XE "type 5" with a $5$ or $6$ prefix is SHA-256/512 crypt, not MD5.
      if (type === '5' && /^\$[56]\$/.test(value)) type = 'sha-crypt'
      // ASA: "enable password <hash> pbkdf2|encrypted", "username x password <hash> pbkdf2".
      const asaTail = type === '0' && body.slice(m.indices![p.v]![1]).match(/^ (pbkdf2|encrypted)\b/)
      if (asaTail) type = asaTail[1]
      let info = typeInfo(type)
      if (type === 'community') info = weakCommunity(value) ? { weak: true, reason: 'Default, short or dictionary-like community string' } : { weak: false, reason: 'Community string' }
      if (p.kind === 'enable' && /^enable password/.test(body) && type !== 'pbkdf2') info = { weak: true, reason: type === '7' ? 'enable password with type 7 is reversible; use enable secret' : 'enable password is not hashed; use enable secret' }
      const token = info.weak ? MASK_WEAK : MASK
      const [a, b] = m.indices![p.v]!
      const out = body.slice(0, a) + token + body.slice(b)
      lines[i] = lead + out
      secrets.push({ line: i + 1, kind: p.kind, type: type === 'community' ? 'community' : type, weak: info.weak, reason: info.reason })
      break
    }
  }
  return { text: lines.join('\n'), secrets }
}

/** Heuristic check used by the import report: does a line still look like it carries a clear-text secret? */
export function looksSecret(line: string) {
  const t = line.trim()
  if (/<masked/.test(t)) return false
  if (/^(no |service password|aaa |ip ssh|crypto key|ntp trusted-key|ntp authenticate|key chain|key \d+$|security passwords|password-policy|password encryption|password strength|(set|match) community|ip (community-list|bgp-community)|description |remark |.* remark )/.test(t)) return false
  return /(^|\s)(password|secret|community|key|key-string|pre-shared-key)\s+\S+/.test(t) && !/(^|\s)(key|password|secret) (chain|config-key|change|exchange|encryption|policy|strength-check)\b/.test(t)
}
