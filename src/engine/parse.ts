// Hierarchical Cisco config parser. Children are lines indented deeper than their parent,
// the same model ciscoconfparse uses, with special handling for multi-line banners and
// certificate blobs that would otherwise break regex-on-lines approaches.

export type Platform = 'ios' | 'iosxe' | 'nxos' | 'asa'

export interface Line {
  /** 1-based line number in the source text */
  n: number
  text: string
  indent: number
  parent: Line | null
  children: Line[]
  /** True for lines inside a banner body (not configuration commands) */
  banner?: boolean
}

export interface Config {
  lines: Line[]
  /** Top-level commands in order */
  top: Line[]
  platform: Platform
  hostname: string
  source: string
}

const BANNER = /^banner\s+(motd|login|exec|incoming|slip-ppp|prompt-timeout|config-save|asdm)\b\s*(.*)$/i

export function detectPlatform(text: string): Platform {
  if (/^\s*(: )?ASA Version \d/m.test(text) || /^\s*nameif\s+\S+/m.test(text)) return 'asa'
  if (/^!Command: show running-config/m.test(text) || /^\s*feature\s+(ssh|telnet|interface-vlan|lacp|vpc|bgp|ospf|nxapi)\b/m.test(text) || /^version \d+\.\d+\(\d+\)[A-Z]\d/m.test(text) && /^\s*vdc /m.test(text)) return 'nxos'
  if (/^version (1[6-9]|[2-9]\d)\.\d+/m.test(text) || /Cisco IOS XE/i.test(text) || /^\s*platform (punt-keepalive|qfp|hardware throughput)/m.test(text)) return 'iosxe'
  return 'ios'
}

const indentOf = (s: string) => {
  let i = 0
  while (i < s.length && (s[i] === ' ' || s[i] === '\t')) i += s[i] === '\t' ? 8 : 1
  return i
}

export function parse(source: string, platform?: Platform): Config {
  const raw = source.replace(/\r\n?/g, '\n').split('\n')
  const lines: Line[] = []
  const top: Line[] = []
  const stack: Line[] = []
  let bannerEnd: string | null = null
  let bannerParent: Line | null = null

  for (let i = 0; i < raw.length; i++) {
    const text = raw[i].replace(/\s+$/, '')
    const n = i + 1
    if (bannerEnd !== null) {
      const body: Line = { n, text, indent: indentOf(text), parent: bannerParent, children: [], banner: true }
      bannerParent!.children.push(body)
      lines.push(body)
      if (text.includes(bannerEnd)) bannerEnd = null
      continue
    }
    if (!text.trim()) continue
    const indent = indentOf(text)
    const trimmed = text.trim()
    // "!" and ":" (ASA) lines are comments; at column 0 they also close any open block.
    if (trimmed.startsWith('!') || (trimmed.startsWith(':') && indent === 0)) {
      if (indent === 0) stack.length = 0
      continue
    }
    while (stack.length && stack[stack.length - 1].indent >= indent) stack.pop()
    const parent = stack.length ? stack[stack.length - 1] : null
    const line: Line = { n, text: trimmed, indent, parent, children: [] }
    if (parent) parent.children.push(line)
    else top.push(line)
    lines.push(line)
    stack.push(line)

    const b = !parent && trimmed.match(BANNER)
    if (b) {
      // IOS banners use a delimiter (^C, #, %, etc.). Body runs until the delimiter repeats.
      const rest = b[2]
      const delim = rest.startsWith('^C') ? '^C' : rest[0]
      if (delim) {
        const after = rest.slice(delim.length)
        if (!after.includes(delim)) { bannerEnd = delim; bannerParent = line }
      }
    }
  }
  const hostLine = top.find(l => /^(hostname|switchname)\s+\S+/.test(l.text))
  return { lines, top, platform: platform ?? detectPlatform(source), hostname: hostLine ? hostLine.text.split(/\s+/)[1].replace(/^"|"$/g, '') : '', source }
}

// ---------- Query helpers (ciscoconfparse-style) ----------

export const find = (c: Config, re: RegExp) => c.top.filter(l => re.test(l.text))
export const findAll = (c: Config, re: RegExp) => c.lines.filter(l => !l.banner && re.test(l.text))
export const child = (l: Line, re: RegExp) => l.children.find(x => !x.banner && re.test(x.text))
export const children = (l: Line, re: RegExp) => l.children.filter(x => !x.banner && re.test(x.text))
export const has = (c: Config, re: RegExp) => c.top.some(l => re.test(l.text))
/** Parent chain from the top down, e.g. ["interface Gi0/1"] for an interface sub-command */
export const path = (l: Line) => { const p: string[] = []; for (let x = l.parent; x; x = x.parent) p.unshift(x.text); return p }
/** Lines of a block (parent plus descendants) as source text */
export function blockText(l: Line): string[] {
  const out = [' '.repeat(l.indent) + l.text]
  for (const c of l.children) out.push(...blockText(c))
  return out
}

/** All config lines as full-path strings, used for order-independent diffs */
export function flatten(c: Config): string[] {
  const out: string[] = []
  for (const l of c.lines) if (!l.banner) out.push([...path(l), l.text].join(' > '))
  return out
}

export const isPhysical = (name: string) => /^(GigabitEthernet|FastEthernet|TenGigabitEthernet|TwentyFiveGigE|FortyGigabitEthernet|HundredGigE|Ethernet|TwoGigabitEthernet|FiveGigabitEthernet|AppGigabitEthernet|Management|mgmt|Serial)\d/i.test(name)
