import { useEffect, useMemo, useRef, useState } from 'react'
import type { Finding } from './engine/audit.ts'
import { PLATFORM_LABEL } from './engine/ingest.ts'
import type { Platform } from './engine/parse.ts'
import { SEV_ORDER, type Severity } from './engine/rules.ts'

export const SEV_LABEL: Record<Severity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' }

export const Sev = ({ s }: { s: Severity }) => <span className={`sev sev-${s}`}>{SEV_LABEL[s]}</span>
export const PlatformTag = ({ p }: { p: Platform }) => <span className="tag">{PLATFORM_LABEL[p]}</span>

/** Animated score ring; the number counts toward the new value when it changes. */
export function ScoreRing({ score, size = 132, label = 'Hardening score', grade }: { score: number; size?: number; label?: string; grade?: string }) {
  const [shown, setShown] = useState(score)
  const from = useRef(score)
  useEffect(() => {
    const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches
    if (reduce) { setShown(score); from.current = score; return }
    const start = performance.now(), a = from.current, b = score
    let raf = 0
    const step = (t: number) => {
      const k = Math.min(1, (t - start) / 900)
      const e = 1 - Math.pow(1 - k, 3)
      setShown(Math.round(a + (b - a) * e))
      if (k < 1) raf = requestAnimationFrame(step)
      else from.current = b
    }
    raf = requestAnimationFrame(step)
    return () => { cancelAnimationFrame(raf); from.current = b }
  }, [score])
  const r = 52, c = 2 * Math.PI * r
  const tone = shown >= 90 ? 'good' : shown >= 70 ? 'ok' : shown >= 55 ? 'warn' : 'bad'
  return (
    <div className={`ring ring-${tone}`} style={{ width: size, height: size }} role="img" aria-label={`${label}: ${score} out of 100${grade ? `, grade ${grade}` : ''}`}>
      <svg viewBox="0 0 120 120" width={size} height={size} aria-hidden="true">
        <circle cx="60" cy="60" r={r} className="ring-track" />
        <circle cx="60" cy="60" r={r} className="ring-fill" strokeDasharray={c} strokeDashoffset={c * (1 - shown / 100)} transform="rotate(-90 60 60)" />
      </svg>
      <div className="ring-num"><strong>{shown}</strong>{grade && <span>{grade}</span>}</div>
    </div>
  )
}

export function SevBar({ counts }: { counts: Record<Severity, number> }) {
  const total = SEV_ORDER.reduce((s, k) => s + counts[k], 0)
  if (!total) return <div className="sevbar empty-bar" aria-label="No open findings" />
  return (
    <div className="sevbar" role="img" aria-label={SEV_ORDER.map(k => `${counts[k]} ${k}`).join(', ')}>
      {SEV_ORDER.map(k => counts[k] ? <i key={k} className={`sevbar-${k}`} style={{ flexGrow: counts[k] }} title={`${counts[k]} ${k}`} /> : null)}
    </div>
  )
}

export const sevCounts = (fs: Finding[]) => Object.fromEntries(SEV_ORDER.map(s => [s, fs.filter(f => f.severity === s && !f.waived).length])) as Record<Severity, number>

interface ViewLine { n: number; text: string; indent: number; top: number; hasKids: boolean }

/**
 * Config tree viewer. Lines with findings light up (worst severity wins); their top-level parent
 * gets a marker too, so collapsed blocks still show where the problems are.
 */
export function ConfigView({ text, findings, selected, onSelect, added, maxHeight, foldable = true }: {
  text: string
  findings: Finding[]
  selected?: string | null
  onSelect?(f: Finding): void
  /** New line numbers to flash as just-added */
  added?: Set<number>
  maxHeight?: number | string
  foldable?: boolean
}) {
  const lines = useMemo<ViewLine[]>(() => {
    const raw = text.split('\n')
    let top = 0
    const out = raw.map((t, i) => {
      const indent = t.length - t.trimStart().length
      if (indent === 0 && t.trim() && !t.startsWith('!')) top = i + 1
      return { n: i + 1, text: t, indent, top: indent === 0 ? i + 1 : top, hasKids: false }
    })
    for (let i = 0; i < out.length - 1; i++) if (out[i].indent === 0 && out[i + 1].indent > 0 && out[i + 1].text.trim()) out[i].hasKids = true
    return out
  }, [text])
  const byLine = useMemo(() => {
    const m = new Map<number, Finding[]>()
    for (const f of findings) if (f.line && !f.waived) m.set(f.line, [...(m.get(f.line) ?? []), f])
    return m
  }, [findings])
  const byTop = useMemo(() => {
    const m = new Map<number, Severity>()
    for (const [n, fs] of byLine) {
      const top = lines[n - 1]?.top
      if (!top) continue
      const worst = fs.map(f => f.severity).sort((a, b) => SEV_ORDER.indexOf(a) - SEV_ORDER.indexOf(b))[0]
      const cur = m.get(top)
      if (!cur || SEV_ORDER.indexOf(worst) < SEV_ORDER.indexOf(cur)) m.set(top, worst)
    }
    return m
  }, [byLine, lines])
  const [folded, setFolded] = useState<Set<number>>(new Set())
  const box = useRef<HTMLDivElement>(null)
  const selLine = findings.find(f => f.key === selected)?.line
  useEffect(() => {
    if (!selLine || !box.current) return
    const el = box.current.querySelector<HTMLElement>(`[data-n="${selLine}"]`)
    if (el) box.current.scrollTo({ top: el.offsetTop - box.current.clientHeight / 3, behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' })
  }, [selLine])

  return (
    <div className="cfg" ref={box} style={{ maxHeight }} role="region" aria-label="Configuration">
      <ol className="cfg-lines">
        {lines.map(l => {
          if (foldable && l.indent > 0 && folded.has(l.top)) return null
          const fs = byLine.get(l.n)
          const worst = fs?.map(f => f.severity).sort((a, b) => SEV_ORDER.indexOf(a) - SEV_ORDER.indexOf(b))[0]
          const topSev = l.hasKids ? byTop.get(l.n) : undefined
          const isSel = !!fs?.some(f => f.key === selected)
          const comment = l.text.trimStart().startsWith('!')
          return (
            <li key={l.n} data-n={l.n} className={[worst && `hit hit-${worst}`, isSel && 'sel', added?.has(l.n) && 'added', comment && 'cmt'].filter(Boolean).join(' ')}>
              <span className="ln">{l.n}</span>
              {foldable && l.hasKids
                ? <button type="button" className={`fold${folded.has(l.n) ? ' closed' : ''}`} aria-label={folded.has(l.n) ? `Expand ${l.text}` : `Collapse ${l.text}`} aria-expanded={!folded.has(l.n)} onClick={() => setFolded(s => { const n = new Set(s); if (n.has(l.n)) n.delete(l.n); else n.add(l.n); return n })}>
                    <svg viewBox="0 0 10 10" width="9" height="9" aria-hidden="true"><path d="M2 3.5 5 6.5 8 3.5" fill="none" stroke="currentColor" strokeWidth="1.6" /></svg>
                  </button>
                : <span className="fold-sp" />}
              <code className="tx">{highlight(l.text)}</code>
              {topSev && folded.has(l.n) && <span className={`dot dot-${topSev}`} aria-label={`${topSev} finding inside`} />}
              {fs && onSelect && (
                <button type="button" className={`pin pin-${worst}`} onClick={() => onSelect(fs[0])} aria-label={`${fs.length} finding${fs.length > 1 ? 's' : ''} on line ${l.n}: ${fs[0].title}`}>{fs[0].rule}{fs.length > 1 ? ` +${fs.length - 1}` : ''}</button>
              )}
            </li>
          )
        })}
      </ol>
    </div>
  )
}

const KW = /^(\s*)(no\s+)?(\S+)(.*)$/
/** Light syntax colouring: leading keyword, "no", masked secrets, addresses. */
function highlight(t: string) {
  if (t.trimStart().startsWith('!')) return t
  const m = t.match(KW)
  if (!m) return t
  const [, sp, no, kw, rest] = m
  const parts: (string | React.JSX.Element)[] = []
  let k = 0
  for (const seg of rest.split(/(<masked(?::weak)?>|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d+)?\b)/)) {
    if (!seg) continue
    if (seg.startsWith('<masked')) parts.push(<span key={k++} className={`tk-mask${seg.includes('weak') ? ' weak' : ''}`}>{seg}</span>)
    else if (/^\d/.test(seg)) parts.push(<span key={k++} className="tk-ip">{seg}</span>)
    else parts.push(seg)
  }
  return <>{sp}{no && <span className="tk-no">{no}</span>}<span className="tk-kw">{kw}</span>{parts}</>
}

export function ScriptBlock({ title, code, file }: { title: string; code: string; file?: string }) {
  return (
    <div className="code">
      <div className="code-head">
        <span>{title}</span>
        <span className="row gap-sm">
          <CopyBtn text={code} />
          {file && <button type="button" className="btn ghost sm" onClick={() => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([code], { type: 'text/plain' })); a.download = file; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000) }}>Download</button>}
        </span>
      </div>
      <pre><code>{code}</code></pre>
    </div>
  )
}

function CopyBtn({ text }: { text: string }) {
  const [done, setDone] = useState(false)
  return <button type="button" className="btn ghost sm" onClick={async () => { try { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 1400) } catch { /* clipboard blocked */ } }}>{done ? 'Copied' : 'Copy'}</button>
}
