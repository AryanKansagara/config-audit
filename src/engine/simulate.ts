// Applies remediation blocks to a config text the way the device would show it afterwards,
// so the app can preview the post-fix score before anything touches a real device.

import type { Block } from './rules.ts'

// Commands where a new value replaces the old one (same leading words) instead of adding a line.
const SINGLETON = /^(transport input|exec-timeout|ip ssh version|ip ssh time-out|ip ssh authentication-retries|logging buffered|logging trap|access-class|ip access-class|switchport access vlan|console timeout|ssh timeout|ssh version|service timestamps log|service timestamps debug|enable secret|login block-for|ip http access-class|aaa authentication login default|aaa authentication enable default)\b/

const keyOf = (cmd: string) => cmd.match(SINGLETON)?.[0]

/** What a typed command looks like in "show running-config" afterwards (hashes and placeholders masked). */
export function asShown(cmd: string): string {
  return cmd
    .replace(/^enable algorithm-type scrypt secret \S+$/, 'enable secret 9 <masked>')
    .replace(/^username (\S+)( privilege \d+)? algorithm-type scrypt secret \S+$/, 'username $1$2 secret 9 <masked>')
    .replace(/<(NEW-[A-Z-]+|[A-Z]+-KEY|NTP-KEY|BGP-KEY|EIGRP-KEY)>/g, '<masked>')
    .replace(/^banner (login|motd) \^C(.*)\^C$/, 'banner $1 ^C$2^C')
}

interface Node { text: string; children: Node[] }

function toTree(text: string): Node[] {
  const root: Node[] = []
  const stack: { indent: number; node: Node }[] = []
  let inBanner: string | null = null
  for (const raw of text.split('\n')) {
    const indent = raw.length - raw.trimStart().length
    const t = raw.trim()
    if (inBanner !== null) { stack[0].node.children.push({ text: raw, children: [] }); if (raw.includes(inBanner)) inBanner = null; continue }
    if (!t) continue
    while (stack.length && stack[stack.length - 1].indent >= indent) stack.pop()
    const node: Node = { text: t, children: [] }
    if (t.startsWith('!') && indent === 0) { stack.length = 0; root.push(node); continue }
    ;(stack.length ? stack[stack.length - 1].node.children : root).push(node)
    stack.push({ indent, node })
    const b = indent === 0 && t.match(/^banner \S+ (\^C|.)(.*)$/)
    if (b && !b[2].includes(b[1])) { inBanner = b[1]; stack.length = 0; stack.push({ indent: 0, node }) }
  }
  return root
}

function fromTree(nodes: Node[], depth = 0, inBanner = false): string[] {
  const out: string[] = []
  for (const n of nodes) {
    out.push(inBanner ? n.text : ' '.repeat(depth) + n.text)
    out.push(...fromTree(n.children, depth + 1, /^banner \S+ /.test(n.text)))
  }
  return out
}

/** Applies config-mode blocks to a config. `!` comment commands are ignored. */
export function applyBlocks(text: string, blocks: Block[]): string {
  const root = toTree(text.replace(/\r\n?/g, '\n'))
  const endIdx = () => { const i = root.findIndex(n => n.text === 'end'); return i < 0 ? root.length : i }
  for (const b of blocks) {
    let level = root
    for (const p of b.parents) {
      let n = level.find(x => x.text === p)
      if (!n) { n = { text: p, children: [] }; if (level === root) root.splice(endIdx(), 0, n); else level.push(n) }
      level = n.children
    }
    // Commands with leading spaces are children of the previous command in this block (e.g. ACL entries).
    let lastTop: Node | null = null
    for (const rawCmd of b.cmds) {
      const nested = /^\s+/.test(rawCmd)
      const cmd = asShown(rawCmd.trim())
      if (!cmd || cmd.startsWith('!')) continue
      const target = nested && lastTop ? lastTop.children : level
      const insert = (n: Node) => { if (target === root) root.splice(endIdx(), 0, n); else target.push(n) }
      if (cmd.startsWith('no ') && !nested) {
        const what = cmd.slice(3)
        const idx = target.findIndex(x => x.text === what || x.text.startsWith(what + ' ') && !/^(ip access-list|access-list \S+ \S+ .*|interface)/.test(what))
        if (idx >= 0) { target.splice(idx, 1); lastTop = null; continue }
        if (!target.some(x => x.text === cmd)) insert({ text: cmd, children: [] })
        continue
      }
      // A positive command replaces its "no" form, and singletons replace their previous value.
      const noIdx = target.findIndex(x => x.text === `no ${cmd}`)
      if (noIdx >= 0) target.splice(noIdx, 1)
      const k = keyOf(cmd)
      const existing = target.find(x => x.text === cmd) ?? (k ? target.find(x => keyOf(x.text) === k) : undefined)
      if (existing) { existing.text = cmd; lastTop = existing; continue }
      const n: Node = { text: cmd, children: [] }
      insert(n)
      lastTop = n
    }
  }
  return fromTree(root).join('\n')
}
