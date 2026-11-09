import { useState } from 'react'
import { DEFAULT_SETTINGS, type Settings as S } from './engine/rules.ts'
import { deleteProject, getDefaults, getProjects, saveProject, setDefaults } from './store.ts'
import { exportAll, RAW_SYNC_LIMIT, useSync } from './sync.ts'
import { ask, download, setTheme, toast, useDark } from './ui.tsx'

const list = (s: string) => s.split(/[\s,]+/).map(x => x.trim()).filter(Boolean)
const validCidr = (s: string) => /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(s)

export default function Settings() {
  const [d, setD] = useState<S>(getDefaults)
  const dark = useDark()
  const sync = useSync()
  const save = (p: Partial<S>) => { const next = { ...d, ...p }; setD(next); setDefaults(next); toast('Saved', { tone: 'ok', ttl: 1500 }) }
  const projects = getProjects()

  return (
    <section className="page narrow settings">
      <div className="eyebrow">Settings</div>
      <h1>Settings</h1>

      <div className="panel">
        <h2>Remediation defaults</h2>
        <p className="muted small">Used when writing fix commands (management ACLs, NTP, syslog, timeouts). New audits copy these; use "Apply to all audits" to update existing ones.</p>
        <div className="inline-fields">
          <label className="field"><span>Management subnets (CIDR)</span><input defaultValue={d.mgmtNets.join(', ')} onBlur={e => { const v = list(e.target.value); if (v.length && v.every(validCidr)) save({ mgmtNets: v }); else toast('Use CIDR like 192.0.2.0/24', { tone: 'error' }) }} /></label>
          <label className="field"><span>NTP servers</span><input defaultValue={d.ntpServers.join(', ')} onBlur={e => save({ ntpServers: list(e.target.value) })} /></label>
          <label className="field"><span>Syslog hosts</span><input defaultValue={d.syslogHosts.join(', ')} onBlur={e => save({ syslogHosts: list(e.target.value) })} /></label>
          <label className="field"><span>Max exec-timeout (minutes)</span><input type="number" min="1" max="60" value={d.execTimeout} onChange={e => save({ execTimeout: Math.max(1, Math.min(60, Number(e.target.value) || 10)) })} /></label>
          <label className="field"><span>AAA login method</span><select value={d.aaaMethod} onChange={e => save({ aaaMethod: e.target.value as S['aaaMethod'] })}><option value="local">local</option><option value="group tacacs+ local">group tacacs+ local</option><option value="group radius local">group radius local</option></select></label>
          <label className="field"><span>VTY ACL name</span><input defaultValue={d.vtyAcl} onBlur={e => e.target.value.trim() && save({ vtyAcl: e.target.value.trim() })} /></label>
          <label className="field"><span>SNMP ACL name</span><input defaultValue={d.snmpAcl} onBlur={e => e.target.value.trim() && save({ snmpAcl: e.target.value.trim() })} /></label>
          <label className="field wide"><span>Internet-facing interface pattern (regex on description / nameif)</span><input className="mono" defaultValue={d.edgePattern} onBlur={e => { try { new RegExp(e.target.value); save({ edgePattern: e.target.value }) } catch { toast('Not a valid regular expression', { tone: 'error' }) } }} /></label>
          <label className="field wide"><span>Banner text</span><input defaultValue={d.banner} onBlur={e => save({ banner: e.target.value })} /></label>
        </div>
        <div className="row gap-sm wrap">
          <button type="button" className="btn outline sm" disabled={!projects.length} onClick={async () => { for (const p of projects) await saveProject({ ...p, settings: d }); toast(`Applied to ${projects.length} audits`, { tone: 'ok' }) }}>Apply to all audits</button>
          <button type="button" className="btn ghost sm" onClick={() => { setDefaults(DEFAULT_SETTINGS); setD(DEFAULT_SETTINGS); location.reload() }}>Reset to defaults</button>
        </div>
      </div>

      <div className="panel">
        <h2>Appearance</h2>
        <div className="seg-control" role="radiogroup" aria-label="Theme">
          <button type="button" role="radio" aria-checked={!dark} className={!dark ? 'on' : ''} onClick={() => setTheme('light')}>Light</button>
          <button type="button" role="radio" aria-checked={dark} className={dark ? 'on' : ''} onClick={() => setTheme('dark')}>Dark</button>
        </div>
      </div>

      <div className="panel">
        <h2>Your data</h2>
        <p>Audits live in this browser (IndexedDB), with secrets already masked. {sync.user ? <>Signed in as <b>{sync.user.email}</b>: devices, findings, waivers, settings and snapshots sync; masked config text syncs when an audit's configs are under {(RAW_SYNC_LIMIT / 1e6).toFixed(1)} MB, otherwise it stays on this device.</> : 'Sign in from the account menu (top right) to sync across machines. It is optional.'}</p>
        <div className="row gap wrap">
          <button type="button" className="btn outline" onClick={async () => download(`config-audit-export-${new Date().toISOString().slice(0, 10)}.json`, await exportAll())}>Export all my data (JSON)</button>
          <button type="button" className="btn danger-ghost" onClick={async () => {
            const all = getProjects()
            if (!all.length) { toast('Nothing to delete'); return }
            if (!(await ask('Delete all local audits?', `Removes ${all.length} audit${all.length > 1 ? 's' : ''} from this browser${sync.user ? ' and from your cloud account' : ''}. You can undo for a few seconds.`, 'Delete everything'))) return
            const undos = await Promise.all(all.map(p => deleteProject(p.id)))
            toast(`Deleted ${all.length} audits`, { undo: () => { for (const u of undos) void u() } })
          }}>Delete all audits</button>
        </div>
      </div>

      <div className="panel">
        <h2>Keyboard shortcuts</h2>
        <dl className="shortcuts">
          <div><dt><kbd>1</kbd>&ndash;<kbd>7</kbd></dt><dd>Switch audit sections</dd></div>
          <div><dt><kbd>J</kbd> <kbd>K</kbd></dt><dd>Next / previous finding on a device</dd></div>
          <div><dt><kbd>S</kbd></dt><dd>Save a snapshot</dd></div>
          <div><dt><kbd>P</kbd></dt><dd>Printable report</dd></div>
          <div><dt><kbd>E</kbd></dt><dd>Export findings CSV</dd></div>
          <div><dt><kbd>&#8984;</kbd>/<kbd>Ctrl</kbd> <kbd>Z</kbd></dt><dd>Undo the last delete or waiver</dd></div>
          <div><dt><kbd>?</kbd></dt><dd>Show shortcuts on an audit page</dd></div>
        </dl>
      </div>
    </section>
  )
}
