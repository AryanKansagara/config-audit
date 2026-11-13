// Import: split pasted text or files into device configs, detect platform, mask secrets, and
// produce a validation report with line numbers.

import { looksSecret, maskSecrets, type MaskedSecret } from './mask.ts'
import { detectPlatform, parse, type Platform } from './parse.ts'

export interface RawFile { name: string; text: string }
export interface Issue { line?: number; level: 'error' | 'warn' | 'info'; message: string }
export interface Ingested {
  source: string
  hostname: string
  platform: Platform
  /** Masked config text, the only form ever stored */
  text: string
  lines: number
  secrets: MaskedSecret[]
  issues: Issue[]
  ok: boolean
}

const START = /^(Building configuration\.\.\.|Current configuration : \d+ bytes|!Command: show running-config|: Saved|ASA Version \d|!RANCID-CONTENT-TYPE)/m

/** Splits one blob into device configs. Handles Ansible ios_facts JSON, RANCID/Oxidized files and several configs pasted back to back. */
export function splitConfigs(f: RawFile): RawFile[] {
  const text = f.text.replace(/^﻿/, '').replace(/\r\n?/g, '\n')
  const trimmed = text.trim()
  // Ansible ad-hoc output: "R1 | SUCCESS => { ...facts... }", one block per host.
  if (/^\S+ \| (SUCCESS|CHANGED) => \{/m.test(trimmed)) {
    const out: RawFile[] = []
    for (const part of trimmed.split(/^(?=\S+ \| (?:SUCCESS|CHANGED|FAILED!|UNREACHABLE!) => )/m)) {
      const m = part.match(/^(\S+) \| (SUCCESS|CHANGED) => (\{[\s\S]*\})\s*$/)
      if (m) try { out.push(...fromAnsible(JSON.parse(m[3]), m[1])) } catch { /* that host had no config facts */ }
    }
    if (out.length) return out
  }
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try { return fromAnsible(JSON.parse(trimmed), f.name) } catch { /* not JSON, fall through */ }
  }
  // Several configs back to back: split before each "Building configuration" / "Current configuration" header
  // that follows an "end" line, or before a repeated "hostname" at column 0 after an "end".
  const lines = text.split('\n')
  const cuts: number[] = [0]
  let seenEnd = false
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]
    if (/^end\s*$/.test(l) || /^: end$/.test(l)) { seenEnd = true; continue }
    if (seenEnd && l.trim() && !/^(!|\s*$)/.test(l)) {
      // Back up over any comment header lines that belong to the next config.
      let j = i
      while (j > 0 && /^(!|Building configuration|Current configuration|\s*$)/.test(lines[j - 1]) && !/^end\s*$/.test(lines[j - 1])) j--
      cuts.push(j)
      seenEnd = false
    }
  }
  if (cuts.length === 1) return [{ name: f.name, text }]
  return cuts.map((c, k) => ({ name: `${f.name} #${k + 1}`, text: lines.slice(c, cuts[k + 1]).join('\n') })).filter(x => x.text.trim())
}

function fromAnsible(j: unknown, name: string): RawFile[] {
  const out: RawFile[] = []
  const visit = (v: unknown, label: string) => {
    if (!v || typeof v !== 'object') return
    const o = v as Record<string, unknown>
    const facts = (o.ansible_facts ?? o) as Record<string, unknown>
    // Module output uses "ansible_net_config"; the "ansible_facts" variable (e.g. "{{ ansible_facts | to_nice_json }}") drops the prefix.
    const cfg = facts.ansible_net_config ?? facts.net_config ?? (o.config as unknown)
    if (typeof cfg === 'string') { out.push({ name: String(facts.ansible_net_hostname ?? facts.net_hostname ?? label), text: cfg }); return }
    if (Array.isArray(v)) v.forEach((x, i) => visit(x, `${label}[${i}]`))
    else for (const [k, x] of Object.entries(o)) if (x && typeof x === 'object') visit(x, k)
  }
  visit(j, name)
  if (!out.length) throw new Error('no ansible_net_config / net_config found')
  return out
}

export function looksLikeCisco(text: string) {
  return /^(hostname|switchname|interface|line vty|version \d|ASA Version|ip route|router |access-list|ip access-list|vlan \d|feature |snmp-server|logging |aaa )/m.test(text)
}

export function ingest(f: RawFile): Ingested {
  const issues: Issue[] = []
  const platform = detectPlatform(f.text)
  const { text, secrets } = maskSecrets(f.text)
  const c = parse(text, platform)
  const lines = text.split('\n').length
  if (!looksLikeCisco(f.text)) issues.push({ level: 'error', message: 'This does not look like a Cisco running-config (no hostname, interface or line commands found).' })
  if (!c.hostname) issues.push({ level: 'warn', message: 'No "hostname" line; the device will be named from the file name.' })
  if (!/^\s*(: )?end\s*$/m.test(f.text) && platform !== 'nxos') issues.push({ level: 'warn', message: 'No final "end" line. The config may be truncated (common with terminal-length paging).' })
  // Paging artefacts and console noise
  f.text.split(/\r?\n/).forEach((l, i) => {
    if (/--More--|<--- More --->/.test(l)) issues.push({ line: i + 1, level: 'warn', message: 'Pager prompt in the output. Run "terminal length 0" before "show running-config".' })
    else if (/^\S+[#>]\s*(show|sh) (run|running-config)/.test(l)) issues.push({ line: i + 1, level: 'info', message: 'Prompt and command echo found; ignored.' })
    else if (/^% (Invalid|Incomplete|Ambiguous)/.test(l)) issues.push({ line: i + 1, level: 'warn', message: `CLI error in the capture: ${l.trim()}` })
    else if (/\t/.test(l)) issues.push({ line: i + 1, level: 'info', message: 'Tab indentation; treated as 8 spaces.' })
  })
  const bannerOpen = c.top.find(l => /^banner /.test(l.text) && l.children.length && !l.children[l.children.length - 1].text.includes(l.text.match(/^banner \S+ (\^C|.)/)?.[1] ?? '\u0000'))
  if (bannerOpen) issues.push({ line: bannerOpen.n, level: 'warn', message: 'Banner delimiter never closes; the rest of the file was read as banner text.' })
  // Safety net: anything that still looks like a secret after masking is flagged so it can be checked before sharing.
  text.split('\n').forEach((l, i) => { if (!c.lines.some(x => x.n === i + 1 && x.banner) && looksSecret(l)) issues.push({ line: i + 1, level: 'warn', message: `Possible secret the masker did not recognise: "${l.trim().split(/\s+/).slice(0, 3).join(' ')} ...". Check before sharing.` }) })
  if (secrets.length) issues.push({ level: 'info', message: `Masked ${secrets.length} secret${secrets.length > 1 ? 's' : ''} (${summarizeSecrets(secrets)}). Only the type and whether it is weak are kept.` })
  const hostname = c.hostname || f.name.replace(/\.(txt|cfg|conf|config|log)$/i, '').replace(/[^\w.-]+/g, '-')
  return { source: f.name, hostname, platform, text, lines, secrets, issues: issues.slice(0, 60), ok: !issues.some(i => i.level === 'error') }
}

export function summarizeSecrets(s: MaskedSecret[]) {
  const counts = new Map<string, number>()
  for (const x of s) { const k = x.type === 'community' ? 'SNMP community' : x.type === '0' ? 'plain text' : /^\d$/.test(x.type) ? `type ${x.type}` : x.type; counts.set(k, (counts.get(k) ?? 0) + 1) }
  return [...counts].map(([k, n]) => `${n} ${k}`).join(', ')
}

export const PLATFORM_LABEL: Record<Platform, string> = { ios: 'IOS', iosxe: 'IOS XE', nxos: 'NX-OS', asa: 'ASA' }
