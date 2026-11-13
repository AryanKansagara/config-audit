import { useEffect, useMemo } from 'react'
import { fleetScore, findingsCsv } from './engine/audit.ts'
import { compareSnapshots, drift } from './engine/fleet.ts'
import { PLATFORM_LABEL } from './engine/ingest.ts'
import { SEV_ORDER } from './engine/rules.ts'
import { useProject } from './projectData.ts'
import { ScoreRing, Sev, SevBar, sevCounts } from './components.tsx'
import { download, fmtDate, Link, SyntheticBadge } from './ui.tsx'

export default function Report({ id }: { id: string }) {
  const { loading, project, audits, configs } = useProject(id)
  useEffect(() => { if (project) document.title = `Configuration audit report · ${project.name}` }, [project?.name])
  const dr = useMemo(() => drift(configs), [configs])

  if (loading) return <div className="boot"><span className="spinner" /> Building the report</div>
  if (!project) return <section className="page narrow center"><h1>Audit not found</h1><Link href="/app" className="btn primary">All audits</Link></section>
  if (!audits.length) return <section className="page narrow center"><h1>No devices yet</h1><Link href={`/app/p/${id}/configs`} className="btn primary">Import configs</Link></section>
  const fleet = fleetScore(audits)
  const all = audits.flatMap(a => a.findings)
  const waived = all.filter(f => f.waived)
  const snaps = [...project.snapshots].sort((a, b) => a.at - b.at)
  const last = snaps.at(-1)
  const cmp = last ? compareSnapshots(last, { id: 'now', label: 'now', at: Date.now(), score: fleet.score, devices: audits.map(a => ({ host: a.host, platform: a.platform, score: a.score, findings: a.findings.filter(f => !f.waived).map(f => ({ key: f.key, rule: f.rule, severity: f.severity, title: f.title, target: f.target })) })) }, snaps.slice(0, -1)) : null

  return (
    <article className="report">
      <div className="report-actions">
        <Link href={`/app/p/${id}`} className="btn ghost sm">Back to the audit</Link>
        <div className="row gap-sm">
          <button type="button" className="btn outline sm" onClick={() => download(`${project.name.replace(/\W+/g, '-')}-findings.csv`, findingsCsv(audits))}>CSV</button>
          <button type="button" className="btn primary sm" onClick={() => print()}>Print or save as PDF</button>
        </div>
      </div>
      <header className="report-head">
        <div>
          <div className="eyebrow">Configuration hardening audit</div>
          <h1>{project.name} {project.sampleId && <SyntheticBadge id={project.sampleId} />}</h1>
          <p className="muted">{audits.length} devices · generated {fmtDate(Date.now())} · checks modelled on CIS Cisco IOS Benchmark and DISA STIG network device themes</p>
        </div>
        <ScoreRing score={fleet.score} grade={fleet.grade} size={110} label="Fleet score" />
      </header>

      <section>
        <h2>Summary</h2>
        <ul className="report-points">
          <li>{fleet.total} open findings: {fleet.critical} critical, {fleet.high} high, {fleet.medium} medium, {fleet.low} low. {fleet.waived} waived with a reason and an expiry date.</li>
          <li>Lowest score: {[...audits].sort((a, b) => a.score - b.score)[0].host} ({[...audits].sort((a, b) => a.score - b.score)[0].score}/100).</li>
          {cmp && <li>Since "{last!.label}" ({fmtDate(last!.at)}): {cmp.fixed.length} fixed, {cmp.added.length} new, {cmp.regressed.length} regressed; fleet score {last!.score} → {fleet.score}.</li>}
          {dr.length > 0 && <li>{dr.length} settings drift across devices: {dr.map(r => r.setting).join(', ')}.</li>}
        </ul>
      </section>

      <section>
        <h2>Fleet scorecard</h2>
        <table className="tbl">
          <thead><tr><th>Device</th><th>Platform</th><th>Score</th><th>Grade</th><th>Checks passed</th><th>Open by severity</th></tr></thead>
          <tbody>
            {audits.map(a => {
              const c = sevCounts(a.findings)
              return <tr key={a.host}><td className="mono">{a.host}</td><td>{PLATFORM_LABEL[a.platform]} {a.inventory.version}</td><td><b>{a.score}</b></td><td>{a.grade}</td><td>{a.passed}/{a.evaluated}</td><td><SevBar counts={c} /><span className="small">{SEV_ORDER.map(s => `${c[s]} ${s}`).join(' · ')}</span></td></tr>
            })}
          </tbody>
        </table>
      </section>

      {audits.map(a => (
        <section key={a.host} className="report-device">
          <h2 className="mono">{a.host} <span className="muted small">{a.score}/100</span></h2>
          {a.findings.filter(f => !f.waived).length === 0 ? <p className="muted">No open findings.</p> : (
            <table className="tbl">
              <thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Where</th></tr></thead>
              <tbody>{a.findings.filter(f => !f.waived).map(f => <tr key={f.key}><td><Sev s={f.severity} /></td><td className="mono small">{f.rule}</td><td><b>{f.title}</b><div className="small muted">{f.detail}</div></td><td className="small">{f.line ? `line ${f.line}` : 'global'}</td></tr>)}</tbody>
            </table>
          )}
        </section>
      ))}

      <section>
        <h2>Accepted risks (waivers)</h2>
        {waived.length === 0 ? <p className="muted">None.</p> : (
          <table className="tbl">
            <thead><tr><th>Device</th><th>Finding</th><th>Reason</th><th>Approved by</th><th>Expires</th></tr></thead>
            <tbody>{waived.map(f => <tr key={f.key}><td className="mono small">{f.host}</td><td>{f.title}</td><td className="small">{f.waived!.reason}</td><td className="small">{f.waived!.by ?? '—'}</td><td>{f.waived!.expires}</td></tr>)}</tbody>
          </table>
        )}
      </section>
      <footer className="small muted report-foot">Secrets were masked on import; no password, key or community value appears in this report. Generated with Config Audit, an independent project not affiliated with Cisco.</footer>
    </article>
  )
}
