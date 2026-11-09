import { useEffect, useState } from 'react'
import { SAMPLES } from './engine/samples.ts'
import { createBlankProject, createSampleProject } from './projectData.ts'
import { deleteProject, saveProject, useProjects, type Project } from './store.ts'
import { useSync } from './sync.ts'
import { ScoreRing } from './components.tsx'
import { ask, fmtDate, go, Link, SyntheticBadge, toast } from './ui.tsx'

export default function Workspace() {
  const list = useProjects()
  const sync = useSync()
  const [busy, setBusy] = useState(false)

  // /app?sample=fleet opens (or creates) the sample straight away.
  useEffect(() => {
    const q = new URLSearchParams(location.search)
    const s = q.get('sample')
    const tab = q.get('tab')?.replace(/[^a-z]/g, '')
    if (!s || list === null || busy || !SAMPLES.some(x => x.id === s)) return
    setBusy(true)
    void createSampleProject(s).then(p => go(`/app/p/${p.id}${tab ? '/' + tab : ''}`, { replace: true }))
  }, [list, busy])

  const openSample = async () => { setBusy(true); const p = await createSampleProject('fleet'); go(`/app/p/${p.id}`) }
  const newProject = async () => {
    const p = await createBlankProject(`Audit ${new Date().toLocaleDateString('en-US', { month: 'short', year: 'numeric' })}`)
    go(`/app/p/${p.id}/configs`)
  }

  if (list === null || busy) return <div className="boot" role="status"><span className="spinner" /> {busy ? 'Parsing the synthetic fleet' : 'Opening your audits'}</div>

  return (
    <section className="page">
      <div className="page-head">
        <div>
          <div className="eyebrow">Workspace</div>
          <h1>Audits</h1>
          <p className="muted">One project per site, fleet or change window. Each keeps its devices, waivers, remediation settings and snapshots. {sync.user ? 'Synced to your account.' : 'Stored in this browser.'}</p>
        </div>
        {list.length > 0 && <button type="button" className="btn primary" onClick={newProject}>New audit</button>}
      </div>

      {list.length === 0 ? (
        <div className="onboard">
          <article className="onboard-card feature-card">
            <div className="eyebrow light">Two minutes</div>
            <h2>Try the sample</h2>
            <p>Three synthetic devices with real problems, plus an older snapshot to compare against:</p>
            <ul className="sample-list">
              {SAMPLES[0].files.map(f => <li key={f.name}><code>{f.name.replace('.cfg', '')}</code> {f.name.startsWith('BR') ? 'branch router with telnet and type 7 passwords' : f.name.startsWith('CORE') ? 'core switch with a shadowed ACL' : 'edge router, mostly hardened'}</li>)}
            </ul>
            <button type="button" className="btn primary" onClick={() => void openSample()}>Open the sample fleet</button>
          </article>
          <article className="onboard-card">
            <div className="eyebrow">Your network</div>
            <h2>Import your configs</h2>
            <p>Paste <code>show running-config</code> output, drop one or many files, or a zip from Oxidized, RANCID or an archive folder. The platform is detected, secrets are masked, and every problem in the capture is reported with its line number.</p>
            <div className="row gap wrap">
              <button type="button" className="btn primary" onClick={newProject}>Import configs</button>
              <Link href="/docs" className="btn outline">How to collect them</Link>
            </div>
            <p className="muted small">Parsed in your browser. Only masked text is stored, on this device unless you sign in.</p>
          </article>
        </div>
      ) : (
        <>
          <div className="project-grid">
            {list.map(p => <ProjectCard key={p.id} p={p} />)}
          </div>
          {!list.some(p => p.sampleId) && <p className="muted small samples-row">Want to see a full example? <button type="button" className="linkish" onClick={() => void openSample()}>Open the sample fleet</button></p>}
        </>
      )}
    </section>
  )
}

function ProjectCard({ p }: { p: Project }) {
  const [renaming, setRenaming] = useState(false)
  const last = [...p.snapshots].sort((a, b) => a.at - b.at).at(-1)
  return (
    <article className="project-card">
      <div className="row between">
        {renaming ? (
          <form onSubmit={e => { e.preventDefault(); const v = String(new FormData(e.currentTarget).get('n')).trim(); if (v) void saveProject({ ...p, name: v }); setRenaming(false) }}>
            <input name="n" defaultValue={p.name} autoFocus aria-label="Audit name" onBlur={e => e.currentTarget.form?.requestSubmit()} />
          </form>
        ) : <h3><Link href={`/app/p/${p.id}`}>{p.name}</Link></h3>}
        {p.sampleId && <SyntheticBadge />}
      </div>
      <div className="row gap">
        {last ? <ScoreRing score={last.score} size={64} label="Last snapshot score" /> : <div className="ring-empty" aria-hidden="true">—</div>}
        <dl className="mini-stats">
          <div><dt>Devices</dt><dd>{p.devices.length}</dd></div>
          <div><dt>Snapshots</dt><dd>{p.snapshots.length}</dd></div>
          <div><dt>Waivers</dt><dd>{Object.keys(p.waivers).length}</dd></div>
        </dl>
      </div>
      {p.dataMissing && <p className="warn-text small">The configs live on another device. Re-import here to re-run the audit.</p>}
      <div className="row between">
        <span className="muted small">Updated {fmtDate(p.updatedAt)}</span>
        <div className="row gap-sm">
          <button type="button" className="btn ghost sm" onClick={() => setRenaming(true)}>Rename</button>
          <button type="button" className="btn danger-ghost sm" onClick={async () => {
            if (!(await ask(`Delete “${p.name}”?`, 'Removes the audit, its configs and snapshots from this browser (and the cloud, if you are signed in). You can undo for a few seconds.', 'Delete audit'))) return
            const undo = await deleteProject(p.id)
            toast(`Deleted ${p.name}`, { undo: () => void undo() })
          }}>Delete</button>
        </div>
      </div>
    </article>
  )
}
