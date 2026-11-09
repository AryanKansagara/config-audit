import { useMemo, useState } from 'react'
import { compareSnapshots, configDiff, makeSnapshot, type Snapshot } from './engine/fleet.ts'
import { parse } from './engine/parse.ts'
import type { Severity } from './engine/rules.ts'
import { Sev } from './components.tsx'
import { snapshotNow, type TabProps } from './Project.tsx'
import { deleteSnapshotCloud } from './sync.ts'
import { Empty, fmtDate, toast } from './ui.tsx'

const CURRENT = 'current'

export default function History({ project, ds, audits, update }: TabProps) {
  const snaps = [...project.snapshots].sort((a, b) => a.at - b.at)
  const current = useMemo<Snapshot | null>(() => audits.length ? makeSnapshot(CURRENT, 'Current configs', audits, Object.fromEntries(project.devices.filter(d => ds[d.id] !== undefined).map(d => [d.hostname, ds[d.id]]))) : null, [audits, ds])
  const options = [...snaps, ...(current ? [current] : [])]
  const [aId, setA] = useState(snaps.at(-1)?.id ?? '')
  const [bId, setB] = useState(current ? CURRENT : snaps.at(-1)?.id ?? '')
  const A = options.find(s => s.id === aId) ?? snaps.at(-2) ?? snaps.at(-1)
  const B = options.find(s => s.id === bId) ?? current ?? snaps.at(-1)
  const cmp = useMemo(() => A && B && A !== B ? compareSnapshots(A, B, snaps.filter(s => s.at < A.at)) : null, [A, B])
  const hosts = [...new Set([...(A?.configs ? Object.keys(A.configs) : []), ...(B?.configs ? Object.keys(B.configs) : [])])]
  const [host, setHost] = useState<string>('')
  const h = hosts.includes(host) ? host : hosts[0]
  const diff = useMemo(() => {
    const ta = A?.configs?.[h], tb = B?.configs?.[h]
    if (ta === undefined || tb === undefined) return null
    return configDiff(parse(ta), parse(tb)).filter(g => g.added.length || g.removed.length)
  }, [A, B, h])

  const remove = (s: Snapshot) => {
    const before = project.snapshots
    update({ snapshots: before.filter(x => x.id !== s.id) })
    void deleteSnapshotCloud(s.id)
    toast(`Deleted snapshot "${s.label}"`, { undo: () => update({ snapshots: before }) })
  }

  return (
    <div className="stack">
      <div className="panel">
        <div className="row between wrap">
          <h2>Snapshots</h2>
          <button type="button" className="btn primary sm" onClick={() => snapshotNow(project, ds, audits, update)} disabled={!audits.length}>Save snapshot of current configs</button>
        </div>
        {snaps.length === 0 ? <p className="muted">No snapshots yet. Save one after each audit; next time you can see what was fixed, what is new and what came back.</p> : (
          <div className="snap-strip">
            {snaps.map(s => (
              <div key={s.id} className="snap">
                <strong>{s.label}</strong>
                <span className="muted small">{fmtDate(s.at)} · {s.devices.length} devices</span>
                <span className="snap-score">{s.score}</span>
                <button type="button" className="linkish small danger" onClick={() => remove(s)} aria-label={`Delete snapshot ${s.label}`}>Delete</button>
              </div>
            ))}
          </div>
        )}
      </div>

      {options.length >= 2 && (
        <div className="panel">
          <div className="filters">
            <label className="field"><span>Compare</span><select value={A?.id} onChange={e => setA(e.target.value)}>{options.map(s => <option key={s.id} value={s.id}>{s.label}{s.id !== CURRENT ? ` (${fmtDate(s.at)})` : ''}</option>)}</select></label>
            <label className="field"><span>With</span><select value={B?.id} onChange={e => setB(e.target.value)}>{options.map(s => <option key={s.id} value={s.id}>{s.label}{s.id !== CURRENT ? ` (${fmtDate(s.at)})` : ''}</option>)}</select></label>
          </div>
          {!cmp ? <p className="muted">Pick two different snapshots.</p> : (
            <>
              <div className="cmp-stats">
                <div className="good"><strong>{cmp.fixed.length}</strong><span>fixed</span></div>
                <div className="bad"><strong>{cmp.added.length}</strong><span>new</span></div>
                <div className="warn"><strong>{cmp.regressed.length}</strong><span>regressed</span></div>
                <div><strong>{cmp.unchanged}</strong><span>unchanged</span></div>
                <div><strong>{A!.score} → {B!.score}</strong><span>fleet score</span></div>
              </div>
              <div className="table-wrap">
                <table className="tbl">
                  <thead><tr><th>Device</th><th>Before</th><th>After</th><th>Change</th></tr></thead>
                  <tbody>{cmp.devices.map(d => <tr key={d.host}><td className="mono small">{d.host}</td><td>{d.before ?? '—'}</td><td>{d.after ?? '—'}</td><td className={d.before !== undefined && d.after !== undefined ? d.after > d.before ? 'pos' : d.after < d.before ? 'neg' : '' : ''}>{d.before !== undefined && d.after !== undefined ? (d.after - d.before > 0 ? '+' : '') + (d.after - d.before) : d.before === undefined ? 'added' : 'removed'}</td></tr>)}</tbody>
                </table>
              </div>
              <div className="grid-3">
                <CmpList title="Fixed" items={cmp.fixed} tone="good" />
                <CmpList title="New" items={cmp.added} tone="bad" />
                <CmpList title="Regressed (fixed once, back again)" items={cmp.regressed} tone="warn" />
              </div>
            </>
          )}
        </div>
      )}

      {options.length >= 2 && cmp && (
        <div className="panel">
          <div className="row between wrap">
            <h2>Config diff</h2>
            {hosts.length > 0 && <label className="field inline"><span>Device</span><select value={h} onChange={e => setHost(e.target.value)}>{hosts.map(x => <option key={x}>{x}</option>)}</select></label>}
          </div>
          {!diff ? <p className="muted small">One of these snapshots has no stored config for {h ?? 'this device'} (configs of large fleets are kept on the device that imported them).</p>
            : diff.length === 0 ? <p className="muted">No configuration changes for {h}.</p> : (
              <div className="diff">
                {diff.map(g => (
                  <div key={g.parent} className="diff-group">
                    <div className="diff-parent mono">{g.parent || '(global)'}</div>
                    {g.removed.map((l, i) => <div key={'r' + i} className="diff-line del mono"><span aria-hidden="true">-</span> {l}</div>)}
                    {g.added.map((l, i) => <div key={'a' + i} className="diff-line add mono"><span aria-hidden="true">+</span> {l}</div>)}
                  </div>
                ))}
              </div>
            )}
        </div>
      )}
      {options.length < 2 && snaps.length > 0 && <Empty title="One snapshot so far">Import updated configs or save another snapshot to compare.</Empty>}
    </div>
  )
}

function CmpList({ title, items, tone }: { title: string; items: { key: string; rule: string; severity: string; title: string; target: string }[]; tone: string }) {
  return (
    <div className={`cmp-list ${tone}`}>
      <h3>{title} <span className="count">{items.length}</span></h3>
      {items.length === 0 ? <p className="muted small">None.</p> : (
        <ul>{items.slice(0, 40).map(f => <li key={f.key}><Sev s={f.severity as Severity} /> <span><b>{f.title}</b><small className="muted">{f.key.split('|')[0]} · {f.target}</small></span></li>)}</ul>
      )}
    </div>
  )
}
