import { useRef, useState } from 'react'
import { ingest, PLATFORM_LABEL, splitConfigs, summarizeSecrets, type Ingested, type RawFile } from './engine/ingest.ts'
import { addDevices, removeDevice } from './projectData.ts'
import { PlatformTag } from './components.tsx'
import type { TabProps } from './Project.tsx'
import { fmtDate, go, Link, toast } from './ui.tsx'

const MAX_FILE = 20 * 1024 * 1024
const isText = (name: string) => !/\.(png|jpe?g|gif|pdf|exe|bin|gz|tar|ico|svg|woff2?|db|sqlite|DS_Store)$/i.test(name) && !/(^|\/)\.(git|svn)\//.test(name)

async function readFiles(files: FileList | File[]): Promise<{ raw: RawFile[]; skipped: string[] }> {
  const raw: RawFile[] = [], skipped: string[] = []
  for (const f of Array.from(files)) {
    if (f.size > MAX_FILE) { skipped.push(`${f.name} (over 20 MB)`); continue }
    if (/\.zip$/i.test(f.name)) {
      const { unzipSync, strFromU8 } = await import('fflate')
      try {
        const entries = unzipSync(new Uint8Array(await f.arrayBuffer()))
        for (const [name, data] of Object.entries(entries)) {
          if (name.endsWith('/') || !data.length) continue
          if (!isText(name)) { skipped.push(name); continue }
          raw.push({ name: name.split('/').pop()!, text: strFromU8(data) })
        }
      } catch { skipped.push(`${f.name} (could not unzip)`) }
      continue
    }
    raw.push({ name: f.name, text: await f.text() })
  }
  return { raw, skipped }
}

export default function Import({ project }: TabProps) {
  const [paste, setPaste] = useState('')
  const [preview, setPreview] = useState<Ingested[] | null>(null)
  const [skipped, setSkipped] = useState<string[]>([])
  const [drag, setDrag] = useState(false)
  const [busy, setBusy] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)

  const stage = (raw: RawFile[], skip: string[] = []) => {
    const items = raw.flatMap(splitConfigs).map(ingest).filter(i => i.text.trim())
    // Files that are clearly not configs (READMEs, .gitignore in an Oxidized repo) are listed but not imported.
    setPreview(items)
    setSkipped(skip)
    if (!items.length) toast('Nothing that looks like a config was found', { tone: 'error' })
  }
  const onFiles = async (files: FileList | File[]) => {
    setBusy(true)
    try { const { raw, skipped: s } = await readFiles(files); stage(raw, s) } finally { setBusy(false) }
  }
  const commit = async () => {
    const good = preview!.filter(i => i.ok)
    if (!good.length) return
    const r = await addDevices(project, good)
    setPreview(null); setPaste('')
    toast(`${r.added ? `Added ${r.added}` : ''}${r.added && r.replaced ? ', ' : ''}${r.replaced ? `replaced ${r.replaced}` : ''} device${good.length > 1 ? 's' : ''}`, { tone: 'ok' })
    go(`/app/p/${project.id}`)
  }

  return (
    <div className="stack">
      <div className="grid-2 import">
        <div className="panel">
          <h2>Paste running-config</h2>
          <p className="muted small">One or several <code>show running-config</code> outputs back to back, or Ansible <code>ios_facts</code> JSON.</p>
          <label className="sr-only" htmlFor="paste">Configuration text</label>
          <textarea id="paste" className="mono" rows={12} value={paste} onChange={e => setPaste(e.target.value)} placeholder={'Building configuration...\n!\nhostname BR-RTR-02\n!\ninterface GigabitEthernet0/0\n ip address 192.0.2.1 255.255.255.0\n…\nend'} spellCheck={false} />
          <div className="row gap-sm"><button type="button" className="btn primary" disabled={!paste.trim()} onClick={() => stage([{ name: 'pasted text', text: paste }])}>Check</button>{paste && <button type="button" className="btn ghost" onClick={() => setPaste('')}>Clear</button>}</div>
        </div>
        <div className={`panel drop${drag ? ' over' : ''}`}
          onDragOver={e => { e.preventDefault(); setDrag(true) }} onDragLeave={() => setDrag(false)}
          onDrop={e => { e.preventDefault(); setDrag(false); void onFiles(e.dataTransfer.files) }}>
          <h2>Upload files</h2>
          <p className="muted small">Any number of config files (.cfg, .txt, no extension), or a .zip of an Oxidized, RANCID or archive folder. Read locally; nothing is uploaded.</p>
          <div className="drop-zone">
            <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true"><path d="M12 16V4m0 0-4 4m4-4 4 4M4 16v3a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-3" /></svg>
            <span>{busy ? 'Reading…' : 'Drop files or a zip here'}</span>
            <button type="button" className="btn outline sm" onClick={() => fileRef.current?.click()}>Choose files</button>
            <input ref={fileRef} type="file" multiple hidden accept=".cfg,.txt,.conf,.config,.log,.zip,.json,text/plain,application/zip,application/json" onChange={e => { if (e.target.files?.length) void onFiles(e.target.files); e.target.value = '' }} />
          </div>
          <p className="small"><Link href="/docs">How to collect configs</Link> from the CLI, archive, Oxidized, RANCID or Ansible.</p>
        </div>
      </div>

      {preview && (
        <div className="panel">
          <div className="row between wrap">
            <h2>Validation report</h2>
            <div className="row gap-sm"><button type="button" className="btn ghost sm" onClick={() => setPreview(null)}>Discard</button><button type="button" className="btn primary sm" disabled={!preview.some(i => i.ok)} onClick={() => void commit()}>Import {preview.filter(i => i.ok).length} device{preview.filter(i => i.ok).length === 1 ? '' : 's'}</button></div>
          </div>
          <p className="small muted">Secrets were masked before this report was built: type 7, enable and user passwords, SNMP communities, AAA, routing, NTP and VPN keys are replaced with <code>&lt;masked&gt;</code> or <code>&lt;masked:weak&gt;</code>. Only the type and whether it is weak are kept. The original text is never stored.</p>
          <ul className="validate">
            {preview.map((i, k) => {
              const replaces = project.devices.some(d => d.hostname.toLowerCase() === i.hostname.toLowerCase())
              return (
                <li key={k} className={i.ok ? '' : 'bad'}>
                  <div className="row between wrap">
                    <span className="row gap-sm"><strong className="mono">{i.hostname}</strong><PlatformTag p={i.platform} /><span className="muted small">{i.source} · {i.lines} lines</span></span>
                    <span className="small">{!i.ok ? <b className="error">Skipped</b> : replaces ? 'Replaces existing device' : 'New device'}</span>
                  </div>
                  {i.secrets.length > 0 && <p className="small muted">Masked: {summarizeSecrets(i.secrets)}; {i.secrets.filter(s => s.weak).length} weak.</p>}
                  {i.issues.filter(x => !/^Masked/.test(x.message)).length > 0 && (
                    <ul className="issues">
                      {i.issues.filter(x => !/^Masked/.test(x.message)).slice(0, 12).map((x, j) => <li key={j} className={x.level}><span className="mono small">{x.line ? `line ${x.line}` : '—'}</span> {x.message}</li>)}
                    </ul>
                  )}
                </li>
              )
            })}
          </ul>
          {skipped.length > 0 && <p className="small muted">Skipped {skipped.length} non-text file{skipped.length > 1 ? 's' : ''}: {skipped.slice(0, 8).join(', ')}{skipped.length > 8 ? '…' : ''}</p>}
        </div>
      )}

      <div className="panel">
        <h2>Devices in this audit</h2>
        {project.devices.length === 0 ? <p className="muted">None yet. Paste or upload a config above{project.sampleId ? '' : ', or '}{!project.sampleId && <Link href="/app?sample=fleet">open the sample fleet</Link>}.</p> : (
          <div className="table-wrap">
            <table className="tbl">
              <thead><tr><th>Hostname</th><th>Platform</th><th>Source</th><th>Lines</th><th>Secrets masked</th><th>Imported</th><th /></tr></thead>
              <tbody>
                {project.devices.map(d => (
                  <tr key={d.id}>
                    <td className="mono small"><Link href={`/app/p/${project.id}/device/${encodeURIComponent(d.hostname)}`}>{d.hostname}</Link></td>
                    <td>{PLATFORM_LABEL[d.platform]}</td>
                    <td className="small">{d.source}</td>
                    <td>{d.lines}</td>
                    <td className="small">{d.secrets.length} ({d.secrets.filter(s => s.weak).length} weak)</td>
                    <td className="small">{fmtDate(d.importedAt)}</td>
                    <td><button type="button" className="btn danger-ghost sm" onClick={async () => { const undo = await removeDevice(project, d.id); toast(`Removed ${d.hostname}`, { undo: () => void undo() }) }}>Remove</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="muted small">Re-importing a device with the same hostname replaces it. Save a snapshot first if you want to compare before and after.</p>
      </div>
    </div>
  )
}
