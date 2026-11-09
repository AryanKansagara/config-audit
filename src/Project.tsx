import { lazy, Suspense, useEffect, useState } from 'react'
import { fleetScore, findingsCsv, type DeviceAudit } from './engine/audit.ts'
import { makeSnapshot } from './engine/fleet.ts'
import type { Config } from './engine/parse.ts'
import { useProject } from './projectData.ts'
import { uuid, type Dataset, type Project } from './store.ts'
import { ScoreRing } from './components.tsx'
import { download, Empty, go, isTyping, Link, Modal, SyntheticBadge, toast } from './ui.tsx'

const Tabs = lazy(() => import('./Tabs.tsx'))
const DeviceView = lazy(() => import('./Device.tsx'))
const History = lazy(() => import('./History.tsx'))
const Import = lazy(() => import('./Import.tsx'))

export const TABS = [['overview', 'Overview'], ['findings', 'Findings'], ['acls', 'ACLs'], ['drift', 'Drift'], ['inventory', 'Inventory'], ['history', 'History'], ['configs', 'Configs']] as const
export type Tab = (typeof TABS)[number][0] | 'device'

export interface TabProps {
  project: Project
  ds: Dataset
  audits: DeviceAudit[]
  configs: Config[]
  update(p: Partial<Project>): void
  arg?: string
}

export function snapshotNow(project: Project, ds: Dataset, audits: DeviceAudit[], update: (p: Partial<Project>) => void, label?: string) {
  if (!audits.length) { toast('Import at least one config first', { tone: 'error' }); return }
  const configs = Object.fromEntries(project.devices.filter(d => ds[d.id] !== undefined).map(d => [d.hostname, ds[d.id]]))
  const name = label ?? `Audit ${new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}`
  const snap = makeSnapshot(uuid(), name, audits, configs)
  const before = project.snapshots
  update({ snapshots: [...before, snap] })
  toast(`Saved snapshot "${name}"`, { tone: 'ok', undo: () => update({ snapshots: before }) })
}

export default function ProjectView({ id, tab: rawTab, arg }: { id: string; tab: string; arg?: string }) {
  const { loading, project, ds, update, audits, configs } = useProject(id)
  const tab = (rawTab === 'device' || TABS.some(t => t[0] === rawTab) ? rawTab : 'overview') as Tab
  const [help, setHelp] = useState(false)

  useEffect(() => { if (project) document.title = `${project.name} · Config Audit` }, [project?.name])

  const setTab = (t: Tab) => go(`/app/p/${id}${t === 'overview' ? '' : '/' + t}`, { keepScroll: true })
  const csv = () => download(`${project!.name.replace(/\W+/g, '-')}-findings-${new Date().toISOString().slice(0, 10)}.csv`, findingsCsv(audits))

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (isTyping(e) || e.metaKey || e.ctrlKey || e.altKey || !project || !ds) return
      const n = Number(e.key)
      if (n >= 1 && n <= TABS.length) { e.preventDefault(); setTab(TABS[n - 1][0]) }
      else if (e.key === '?') setHelp(true)
      else if (e.key === 's') snapshotNow(project, ds, audits, update)
      else if (e.key === 'p') go(`/app/p/${id}/report`)
      else if (e.key === 'e') csv()
    }
    addEventListener('keydown', onKey)
    return () => removeEventListener('keydown', onKey)
  })

  if (loading) return <div className="boot" role="status"><span className="spinner" /> Parsing configs</div>
  if (!project || !ds) return (
    <section className="page narrow center">
      <Empty title="Audit not found"><p className="muted">It may have been deleted, or it lives on another device.</p><Link href="/app" className="btn primary">All audits</Link></Empty>
    </section>
  )
  const empty = !audits.length
  const fleet = fleetScore(audits)
  const props: TabProps = { project, ds, audits, configs, update, arg }

  return (
    <section className="page">
      <div className="proj-head">
        <div className="row gap">
          {!empty && <ScoreRing score={fleet.score} grade={fleet.grade} size={76} label="Fleet score" />}
          <div>
            <div className="eyebrow"><Link href="/app">Audits</Link></div>
            <h1 className="row gap-sm wrap">{project.name} {project.sampleId && <SyntheticBadge />}</h1>
            {!empty && <p className="muted small" style={{ margin: 0 }}>{audits.length} device{audits.length > 1 ? 's' : ''} · {fleet.total} open findings · {fleet.critical} critical · {fleet.waived} waived</p>}
          </div>
        </div>
        {!empty && (
          <div className="toolbar">
            <button type="button" className="btn outline sm" onClick={csv} title="Export findings as CSV (E)">CSV</button>
            <button type="button" className="btn outline sm" onClick={() => snapshotNow(project, ds, audits, update)} title="Save a snapshot (S)">Save snapshot</button>
            <Link href={`/app/p/${id}/report`} className="btn primary sm" title="Printable audit report (P)">Report</Link>
          </div>
        )}
      </div>
      {project.dataMissing && <div className="banner-warn">This audit was synced from another device, but its configs were too large to sync. Findings and snapshots are here; re-import the configs on the Configs tab to re-run the audit.</div>}
      <nav className="tabs" aria-label="Audit sections">
        {TABS.map(([t, l], i) => <Link key={t} href={`/app/p/${id}${t === 'overview' ? '' : '/' + t}`} aria-current={t === tab || (tab === 'device' && t === 'overview') ? 'page' : undefined} title={`${l} (${i + 1})`}>{l}{t === 'findings' && !empty ? <span className="count">{fleet.total}</span> : null}</Link>)}
      </nav>
      <Suspense fallback={<div className="boot"><span className="spinner" /></div>}>
        {tab === 'configs' || (empty && tab !== 'history')
          ? <Import {...props} />
          : tab === 'device' ? <DeviceView {...props} />
          : tab === 'history' ? <History {...props} />
          : <Tabs tab={tab} {...props} />}
      </Suspense>
      <Modal open={help} onClose={() => setHelp(false)} title="Keyboard shortcuts">
        <dl className="shortcuts">
          <div><dt><kbd>1</kbd>&ndash;<kbd>7</kbd></dt><dd>Switch sections</dd></div>
          <div><dt><kbd>S</kbd></dt><dd>Save a snapshot</dd></div>
          <div><dt><kbd>P</kbd></dt><dd>Printable report</dd></div>
          <div><dt><kbd>E</kbd></dt><dd>Export findings CSV</dd></div>
          <div><dt><kbd>J</kbd> <kbd>K</kbd></dt><dd>Next / previous finding on a device</dd></div>
          <div><dt><kbd>&#8984;</kbd>/<kbd>Ctrl</kbd> <kbd>Z</kbd></dt><dd>Undo the last delete or waiver</dd></div>
        </dl>
      </Modal>
    </section>
  )
}
