import { useMemo, useState } from 'react'
import { aclSummary, type Finding, type Waiver } from './engine/audit.ts'
import { intToIp, objectGroupUsage, type Range } from './engine/acl.ts'
import { drift } from './engine/fleet.ts'
import { RULES, SEV_ORDER, type Severity } from './engine/rules.ts'
import { PlatformTag, ScoreRing, Sev, SevBar, sevCounts } from './components.tsx'
import type { Tab, TabProps } from './Project.tsx'
import { Empty, fmtDate, Link, toast } from './ui.tsx'

export default function Tabs({ tab, ...p }: TabProps & { tab: Tab }) {
  if (tab === 'findings') return <Findings {...p} />
  if (tab === 'acls') return <Acls {...p} />
  if (tab === 'drift') return <Drift {...p} />
  if (tab === 'inventory') return <Inventory {...p} />
  return <Overview {...p} />
}

const devHref = (pid: string, host: string, q = '') => `/app/p/${pid}/device/${encodeURIComponent(host)}${q}`

// ---------- Overview ----------

function Overview({ project, audits, configs }: TabProps) {
  const all = audits.flatMap(a => a.findings)
  const byRule = useMemo(() => {
    const m = new Map<string, { f: Finding; hosts: Set<string> }>()
    for (const f of all) if (!f.waived) { const e = m.get(f.rule) ?? { f, hosts: new Set() }; e.hosts.add(f.host); m.set(f.rule, e) }
    return [...m.values()].sort((a, b) => SEV_ORDER.indexOf(a.f.severity) - SEV_ORDER.indexOf(b.f.severity) || b.hosts.size - a.hosts.size)
  }, [audits])
  const dr = useMemo(() => drift(configs), [configs])
  const cats = useMemo(() => {
    const m = new Map<string, number>()
    for (const f of all) if (!f.waived) m.set(f.category, (m.get(f.category) ?? 0) + 1)
    return [...m].sort((a, b) => b[1] - a[1])
  }, [audits])
  const maxCat = Math.max(1, ...cats.map(c => c[1]))
  return (
    <div className="stack">
      <div className="scorecards">
        {[...audits].sort((a, b) => a.score - b.score).map(a => (
          <Link key={a.host} href={devHref(project.id, a.host)} className="scorecard">
            <ScoreRing score={a.score} grade={a.grade} size={72} label={`${a.host} score`} />
            <div className="scorecard-body">
              <strong>{a.host}</strong>
              <span className="row gap-sm"><PlatformTag p={a.platform} /><span className="muted small">{a.inventory.version && `v${a.inventory.version}`}</span></span>
              <SevBar counts={sevCounts(a.findings)} />
              <span className="muted small">{a.findings.filter(f => !f.waived).length} open · {a.passed}/{a.evaluated} checks pass</span>
            </div>
          </Link>
        ))}
      </div>
      <div className="grid-2">
        <div className="panel">
          <div className="row between"><h2>Top issues across the fleet</h2><Link href={`/app/p/${project.id}/findings`} className="linkish small">All findings</Link></div>
          {byRule.length === 0 ? <p className="muted">Nothing open. Every check passes or is waived.</p> : (
            <ul className="rule-list">
              {byRule.slice(0, 10).map(({ f, hosts }) => (
                <li key={f.rule}>
                  <Sev s={f.severity} />
                  <span><strong>{f.title}</strong><small className="muted">{f.rule} · {[...hosts].join(', ')}</small></span>
                  <span className="mono small">{hosts.size}/{audits.length}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="stack">
          <div className="panel">
            <h2>Open findings by area</h2>
            <div className="bars">
              {cats.map(([c, n]) => <div key={c} className="bar-row"><span>{c}</span><div className="bar"><i style={{ width: `${(n / maxCat) * 100}%` }} /></div><b>{n}</b></div>)}
            </div>
          </div>
          <div className="panel">
            <div className="row between"><h2>Fleet drift</h2><Link href={`/app/p/${project.id}/drift`} className="linkish small">Details</Link></div>
            <p className="muted small">{audits.length < 2 ? 'Import two or more devices to compare settings.' : dr.length ? `${dr.length} settings differ across devices: ${dr.slice(0, 4).map(r => r.setting).join(', ')}${dr.length > 4 ? '…' : ''}.` : 'All tracked settings match across devices.'}</p>
          </div>
        </div>
      </div>
    </div>
  )
}

// ---------- Findings ----------

export function WaiverForm({ f, onSave, onCancel }: { f: Finding; onSave(w: Waiver): void; onCancel(): void }) {
  const def = new Date(Date.now() + 90 * 86400000).toISOString().slice(0, 10)
  return (
    <form className="waiver-form" onSubmit={e => {
      e.preventDefault()
      const d = new FormData(e.currentTarget)
      onSave({ key: f.key, reason: String(d.get('reason')).trim(), expires: String(d.get('expires')), by: String(d.get('by') || '').trim() || undefined, at: Date.now() })
    }}>
      <label className="field grow"><span>Reason (shown in the report)</span><input name="reason" required minLength={4} placeholder="e.g. Web UI needed for DNA Center onboarding; isolated by mgmt VRF" autoFocus /></label>
      <label className="field"><span>Expires</span><input name="expires" type="date" required defaultValue={def} min={new Date().toISOString().slice(0, 10)} /></label>
      <label className="field"><span>Approved by</span><input name="by" placeholder="optional" /></label>
      <div className="row gap-sm end"><button type="button" className="btn ghost sm" onClick={onCancel}>Cancel</button><button className="btn primary sm">Waive</button></div>
    </form>
  )
}

export function useWaivers({ project, update }: Pick<TabProps, 'project' | 'update'>) {
  return {
    waive: (w: Waiver) => { const before = project.waivers; update({ waivers: { ...before, [w.key]: w } }); toast('Waived until ' + w.expires, { tone: 'ok', undo: () => update({ waivers: before }) }) },
    unwaive: (key: string) => { const before = project.waivers; const { [key]: _, ...rest } = before; update({ waivers: rest }); toast('Waiver removed', { undo: () => update({ waivers: before }) }) },
  }
}

export function FindingRow({ f, open, onToggle, project, update, showHost = true }: { f: Finding; open: boolean; onToggle(): void; showHost?: boolean } & Pick<TabProps, 'project' | 'update'>) {
  const [waiving, setWaiving] = useState(false)
  const { waive, unwaive } = useWaivers({ project, update })
  const rule = RULES.find(r => r.id === f.rule)
  const lapsed = !f.waived && project.waivers[f.key]
  return (
    <li className={`finding${open ? ' open' : ''}${f.waived ? ' waived' : ''}`}>
      <button type="button" className="finding-head" aria-expanded={open} onClick={onToggle}>
        <Sev s={f.severity} />
        <span className="finding-title"><strong>{f.title}</strong><small>{showHost && <>{f.host} · </>}{f.target === 'global' ? 'global config' : f.target}{f.line && !/ line \d+$/.test(f.target) ? ` · line ${f.line}` : ''}</small></span>
        {f.waived && <span className="badge">Waived to {f.waived.expires}</span>}
        {lapsed && <span className="badge warn">Waiver expired {lapsed.expires}</span>}
        <span className="mono small muted">{f.rule}</span>
      </button>
      {open && (
        <div className="finding-body">
          <p>{f.detail}</p>
          {rule && <p className="muted small"><b>Why it matters:</b> {rule.rationale} <span className="ref">{rule.ref}</span></p>}
          {f.fix && (
            <pre className="fix"><code>{f.fix.apply.flatMap(b => [...b.parents.map((p, i) => ' '.repeat(i) + p), ...b.cmds.map(c => ' '.repeat(b.parents.length) + c), ...(b.parents.length ? ['exit'] : [])]).join('\n')}</code></pre>
          )}
          {f.fix?.note && <p className="small note">{f.fix.note}</p>}
          {f.waived && <p className="small"><b>Waiver:</b> {f.waived.reason}{f.waived.by ? ` (approved by ${f.waived.by})` : ''}, recorded {fmtDate(f.waived.at)}, expires {f.waived.expires}.</p>}
          <div className="row gap-sm wrap">
            {showHost && <Link href={devHref(project.id, f.host, `?f=${encodeURIComponent(f.key)}`)} className="btn outline sm">Show in config</Link>}
            {f.waived ? <button type="button" className="btn ghost sm" onClick={() => unwaive(f.key)}>Remove waiver</button>
              : !waiving && <button type="button" className="btn ghost sm" onClick={() => setWaiving(true)}>Waive…</button>}
          </div>
          {waiving && <WaiverForm f={f} onCancel={() => setWaiving(false)} onSave={w => { waive(w); setWaiving(false) }} />}
        </div>
      )}
    </li>
  )
}

function Findings({ project, audits, update }: TabProps) {
  const [sev, setSev] = useState<Severity | 'all'>('all')
  const [host, setHost] = useState('all')
  const [cat, setCat] = useState('all')
  const [status, setStatus] = useState<'open' | 'waived' | 'all'>('open')
  const [q, setQ] = useState('')
  const [open, setOpen] = useState<string | null>(null)
  const all = audits.flatMap(a => a.findings)
  const cats = [...new Set(all.map(f => f.category))].sort()
  const list = all.filter(f => (sev === 'all' || f.severity === sev) && (host === 'all' || f.host === host) && (cat === 'all' || f.category === cat) && (status === 'all' || (status === 'waived') === !!f.waived) && (!q || `${f.title} ${f.detail} ${f.rule} ${f.target}`.toLowerCase().includes(q.toLowerCase())))
    .sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) || a.host.localeCompare(b.host))
  const expired = Object.values(project.waivers).filter(w => w.expires < new Date().toISOString().slice(0, 10))
  return (
    <div className="stack">
      <div className="filters">
        <label className="field"><span>Severity</span><select value={sev} onChange={e => setSev(e.target.value as Severity | 'all')}><option value="all">All</option>{SEV_ORDER.map(s => <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</option>)}</select></label>
        <label className="field"><span>Device</span><select value={host} onChange={e => setHost(e.target.value)}><option value="all">All devices</option>{audits.map(a => <option key={a.host}>{a.host}</option>)}</select></label>
        <label className="field"><span>Area</span><select value={cat} onChange={e => setCat(e.target.value)}><option value="all">All areas</option>{cats.map(c => <option key={c}>{c}</option>)}</select></label>
        <label className="field"><span>Status</span><select value={status} onChange={e => setStatus(e.target.value as 'open')}><option value="open">Open</option><option value="waived">Waived</option><option value="all">All</option></select></label>
        <label className="field grow"><span>Search</span><input type="search" value={q} onChange={e => setQ(e.target.value)} placeholder="telnet, SNMP, line 42…" /></label>
      </div>
      {expired.length > 0 && <p className="banner-warn small">{expired.length} waiver{expired.length > 1 ? 's have' : ' has'} expired; those findings count again.</p>}
      <p className="muted small">{list.length} finding{list.length === 1 ? '' : 's'}</p>
      {list.length === 0 ? <Empty title={status === 'waived' ? 'No waivers yet' : 'No findings match'}><p className="muted">{status === 'waived' ? 'Waive a finding to accept a risk with a reason and an expiry date.' : 'Try clearing a filter.'}</p></Empty> : (
        <ul className="findings">
          {list.map(f => <FindingRow key={f.key} f={f} open={open === f.key} onToggle={() => setOpen(open === f.key ? null : f.key)} project={project} update={update} />)}
        </ul>
      )}
    </div>
  )
}

// ---------- ACLs ----------

const rangeText = (r: Range) => r[0] === 0 && r[1] === 0xffffffff ? 'any' : r[0] === r[1] ? intToIp(r[0]) : `${intToIp(r[0])}–${intToIp(r[1])}`

function Acls({ project, audits }: TabProps) {
  const [host, setHost] = useState(audits.find(a => a.ctx.aclIssues.some(i => i.kind !== 'any-any'))?.host ?? audits[0]?.host)
  const a = audits.find(x => x.host === host) ?? audits[0]
  const sums = useMemo(() => a ? aclSummary(a) : [], [a])
  const groups = useMemo(() => a ? objectGroupUsage(a.ctx.c) : [], [a])
  const totals = audits.map(x => ({ host: x.host, acls: x.ctx.acls.length, issues: x.ctx.aclIssues.length, unused: x.ctx.acls.filter(l => !x.ctx.refs.has(l.name)).length }))
  return (
    <div className="stack">
      <div className="seg-control wrap" role="tablist" aria-label="Device">
        {totals.map(t => <button key={t.host} type="button" role="tab" aria-selected={t.host === a?.host} className={t.host === a?.host ? 'on' : ''} onClick={() => setHost(t.host)}>{t.host} <span className="count">{t.issues + t.unused}</span></button>)}
      </div>
      {!sums.length ? <Empty title="No IPv4 ACLs on this device" /> : sums.map(({ acl, issues, referenced }) => (
        <div key={acl.name} className="panel acl">
          <div className="row between wrap">
            <h2 className="mono">{acl.name} <span className="tag">{acl.kind}</span> {!referenced && <span className="badge warn">not applied anywhere</span>}</h2>
            <span className="muted small">{acl.aces.length} entries · {issues.filter(i => i.kind !== 'any-any').length} shadowed or redundant</span>
          </div>
          <div className="table-wrap">
            <table className="tbl">
              <thead><tr><th>Line</th><th>Entry</th><th>Source</th><th>Destination</th><th>Status</th></tr></thead>
              <tbody>
                {acl.aces.map(ace => {
                  const iss = issues.filter(i => i.line === ace.line)
                  const src = [...new Set(ace.boxes.map(b => rangeText(b[1])))]
                  const dst = [...new Set(ace.boxes.map(b => rangeText(b[2])))]
                  return (
                    <tr key={ace.line} className={iss.length ? `row-${iss[0].kind}` : ''}>
                      <td className="mono small"><Link href={devHref(project.id, a.host, `?line=${ace.line}`)}>{ace.line}</Link></td>
                      <td className="mono small">{ace.text}</td>
                      <td className="mono small">{src.slice(0, 3).join(', ')}{src.length > 3 ? ` +${src.length - 3}` : ''}</td>
                      <td className="mono small">{dst.slice(0, 3).join(', ')}{dst.length > 3 ? ` +${dst.length - 3}` : ''}</td>
                      <td className="small">{iss.length ? iss.map(i => <div key={i.kind}><b className={`acl-${i.kind}`}>{i.kind === 'any-any' ? 'any/any' : i.kind}</b> {i.detail}</div>) : ace.exact ? <span className="muted">ok</span> : <span className="muted" title="Uses a keyword or object the engine does not model, so it is never reported as covered">partly modelled</span>}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      ))}
      {groups.length > 0 && (
        <div className="panel">
          <h2>Object-groups</h2>
          <ul className="chips">{groups.map(g => <li key={g.name} className={g.used ? '' : 'warn'}><code>{g.name}</code> {g.used ? 'in use' : 'unused'}</li>)}</ul>
        </div>
      )}
    </div>
  )
}

// ---------- Drift ----------

function Drift({ configs }: TabProps) {
  const rows = useMemo(() => drift(configs), [configs])
  const hosts = configs.map(c => c.hostname || 'unnamed')
  if (configs.length < 2) return <Empty title="Drift needs two or more devices"><p className="muted">Import more configs on the Configs tab to compare settings across the fleet.</p></Empty>
  if (!rows.length) return <Empty title="No drift"><p className="muted">Every tracked setting is identical across {configs.length} devices.</p></Empty>
  return (
    <div className="panel">
      <h2>Settings that differ across devices</h2>
      <p className="muted small">Majority value in plain text; outliers highlighted. A device can be the outlier and still be right (the edge router often is): read this as "decide on one standard".</p>
      <div className="table-wrap">
        <table className="tbl drift">
          <thead><tr><th>Setting</th>{hosts.map(h => <th key={h}>{h}</th>)}</tr></thead>
          <tbody>
            {rows.map(r => (
              <tr key={r.setting}>
                <th scope="row">{r.setting}</th>
                {hosts.map(h => <td key={h} className={r.values[h] === r.majority ? '' : 'outlier'}><span className="mono small">{r.values[h]}</span></td>)}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ---------- Inventory ----------

function Inventory({ audits, project }: TabProps) {
  const [host, setHost] = useState(audits[0]?.host)
  const a = audits.find(x => x.host === host) ?? audits[0]
  const inv = a.inventory
  return (
    <div className="stack">
      <div className="table-wrap panel">
        <table className="tbl">
          <thead><tr><th>Device</th><th>Platform</th><th>Version</th><th>Interfaces (up)</th><th>VLANs</th><th>Routing</th><th>Static routes</th><th>SNMP</th><th>AAA servers</th><th>Local users</th></tr></thead>
          <tbody>
            {audits.map(x => (
              <tr key={x.host} className={x.host === a.host ? 'row-sel' : ''} onClick={() => setHost(x.host)}>
                <td><button type="button" className="linkish" onClick={() => setHost(x.host)}>{x.host}</button></td>
                <td><PlatformTag p={x.platform} /></td>
                <td className="mono small">{x.inventory.version || '—'}</td>
                <td>{x.inventory.interfaces.length} ({x.inventory.interfaces.filter(i => !i.shutdown).length})</td>
                <td>{x.inventory.vlans.length}</td>
                <td className="small">{x.inventory.routing.map(r => `${r.protocol} ${r.id}`).join(', ') || '—'}</td>
                <td>{x.inventory.staticRoutes}</td>
                <td className="small">{x.inventory.snmp.join(', ') || '—'}</td>
                <td>{x.inventory.aaaServers}</td>
                <td>{x.inventory.users}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="grid-2">
        <div className="panel">
          <h2>{inv.hostname} interfaces</h2>
          <div className="table-wrap">
            <table className="tbl">
              <thead><tr><th>Interface</th><th>Description</th><th>Mode</th><th>Address / VLAN</th><th>State</th></tr></thead>
              <tbody>
                {inv.interfaces.map(i => (
                  <tr key={i.name}>
                    <td className="mono small"><Link href={devHref(project.id, a.host, `?line=${i.line}`)}>{i.name}</Link></td>
                    <td className="small">{i.description || <span className="muted">—</span>}</td>
                    <td className="small">{i.mode || '—'}</td>
                    <td className="mono small">{i.ip || i.vlan || '—'}</td>
                    <td><span className={`state ${i.shutdown ? 'down' : 'up'}`}>{i.shutdown ? 'shutdown' : 'enabled'}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        <div className="stack">
          <div className="panel">
            <h2>VLANs</h2>
            {inv.vlans.length ? <ul className="chips">{inv.vlans.map(v => <li key={v.id}><b>{v.id}</b> {v.name}</li>)}</ul> : <p className="muted small">No VLAN database in this config.</p>}
          </div>
          <div className="panel">
            <h2>Routing protocols</h2>
            {inv.routing.length ? <ul className="plain">{inv.routing.map(r => <li key={r.protocol + r.id}><b>{r.protocol}</b> {r.id} <span className="muted small">{r.detail}</span></li>)}</ul> : <p className="muted small">Static routing only ({inv.staticRoutes} routes).</p>}
            {inv.domain && <p className="small muted">Domain: {inv.domain}</p>}
          </div>
        </div>
      </div>
    </div>
  )
}
