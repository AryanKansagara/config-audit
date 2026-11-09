import { useEffect, useMemo, useState } from 'react'
import { auditConfig, remediationScript } from './engine/audit.ts'
import { PLATFORM_LABEL } from './engine/ingest.ts'
import { parse } from './engine/parse.ts'
import { applyBlocks } from './engine/simulate.ts'
import { ConfigView, ScoreRing, ScriptBlock, SevBar, sevCounts } from './components.tsx'
import type { TabProps } from './Project.tsx'
import { FindingRow } from './Tabs.tsx'
import { Empty, isTyping, Link } from './ui.tsx'

export default function DeviceView({ project, ds, audits, update, arg }: TabProps) {
  const a = audits.find(x => x.host === arg)
  const dev = project.devices.find(d => d.hostname === arg)
  const q = new URLSearchParams(location.search)
  const [sel, setSel] = useState<string | null>(q.get('f'))
  const [view, setView] = useState<'findings' | 'script'>('findings')
  const text = dev ? ds[dev.id] ?? '' : ''
  const lineFocus = Number(q.get('line')) || undefined

  const script = useMemo(() => a ? remediationScript(a.host, a.platform, a.findings) : null, [a])
  const after = useMemo(() => {
    if (!a || !dev) return null
    const fixed = applyBlocks(text, a.findings.filter(f => !f.waived).flatMap(f => f.fix?.apply ?? []))
    const c = parse(fixed, dev.platform)
    if (!c.hostname) c.hostname = dev.hostname
    return auditConfig(c, project.settings, project.waivers)
  }, [a, text])

  const open = a?.findings.filter(f => !f.waived) ?? []
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (isTyping(e) || e.metaKey || e.ctrlKey || !open.length) return
      if (e.key !== 'j' && e.key !== 'k') return
      const i = open.findIndex(f => f.key === sel)
      const j = e.key === 'j' ? Math.min(open.length - 1, i + 1) : Math.max(0, i - 1)
      setSel(open[j].key)
      setView('findings')
    }
    addEventListener('keydown', onKey)
    return () => removeEventListener('keydown', onKey)
  })

  if (!a || !dev) return <Empty title="Device not found"><p className="muted">It may have been removed from this audit.</p><Link className="btn primary" href={`/app/p/${project.id}`}>Back to overview</Link></Empty>
  const withLine = a.findings.filter(f => f.line)
  const focus = sel ?? (lineFocus ? withLine.find(f => f.line === lineFocus)?.key ?? null : null)
  const missing = a.findings.filter(f => !f.line)

  return (
    <div className="stack">
      <div className="device-head">
        <ScoreRing score={a.score} grade={a.grade} size={88} label={`${a.host} score`} />
        <div>
          <h2 className="mono">{a.host}</h2>
          <p className="muted small">{PLATFORM_LABEL[a.platform]}{a.inventory.version ? ` ${a.inventory.version}` : ''} · {dev.lines} lines · imported {new Date(dev.importedAt).toLocaleDateString()} from {dev.source} · {dev.secrets.length} secrets masked ({dev.secrets.filter(s => s.weak).length} weak)</p>
          <SevBar counts={sevCounts(a.findings)} />
        </div>
        {after && after.score > a.score && <div className="after"><span className="muted small">After the script</span><ScoreRing score={after.score} grade={after.grade} size={64} label="Projected score after remediation" /></div>}
      </div>
      <div className="device-grid">
        <ConfigView text={text} findings={a.findings} selected={focus} onSelect={f => { setSel(f.key); setView('findings') }} maxHeight="72vh" />
        <div className="device-side">
          <div className="seg-control" role="tablist" aria-label="Device panel">
            <button type="button" role="tab" aria-selected={view === 'findings'} className={view === 'findings' ? 'on' : ''} onClick={() => setView('findings')}>Findings <span className="count">{open.length}</span></button>
            <button type="button" role="tab" aria-selected={view === 'script'} className={view === 'script' ? 'on' : ''} onClick={() => setView('script')}>Remediation script</button>
          </div>
          {view === 'findings' ? (
            <>
              {missing.length > 0 && <p className="muted small">{missing.length} finding{missing.length > 1 ? 's are' : ' is'} about something missing from the config, so {missing.length > 1 ? 'they have' : 'it has'} no line to highlight.</p>}
              <ul className="findings compact">
                {a.findings.map(f => <FindingRow key={f.key} f={f} open={focus === f.key} onToggle={() => setSel(focus === f.key ? null : f.key)} project={project} update={update} showHost={false} />)}
              </ul>
              {!a.findings.length && <Empty title="Clean">Every check for this platform passes.</Empty>}
            </>
          ) : script && (
            <div className="stack-sm">
              {script.count === 0 ? <p className="muted">Nothing to remediate: every open finding is fixed or waived.</p> : <>
                <p className="small">{script.count} open findings, in a safe order: definitions (ACLs, keys) first, then global commands, then interface and line blocks. Waived findings are left out.{after && ` Projected score after applying: ${after.score} (${after.grade}).`}</p>
                {script.notes.length > 0 && <ul className="notes">{script.notes.map(n => <li key={n}>{n}</li>)}</ul>}
                <ScriptBlock title="Apply" code={script.apply} file={`${a.host}-remediation.txt`} />
                <ScriptBlock title="Rollback" code={script.rollback} file={`${a.host}-rollback.txt`} />
              </>}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
