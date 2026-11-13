import { useEffect, useMemo, useState } from 'react'
import { auditConfig, type DeviceAudit } from './engine/audit.ts'
import { makeSnapshot } from './engine/fleet.ts'
import { ingest, type Ingested } from './engine/ingest.ts'
import { parse, type Config } from './engine/parse.ts'
import { SAMPLES } from './engine/samples.ts'
import { getData, getDefaults, getProjects, putData, saveProject, useProjects, uuid, type Dataset, type Device, type Project } from './store.ts'

const toDevice = (i: Ingested): Device => ({ id: uuid(), hostname: i.hostname, platform: i.platform, source: i.source, importedAt: Date.now(), lines: i.lines, secrets: i.secrets, issues: i.issues })

export function parseDevice(d: Device, text: string): Config {
  const c = parse(text, d.platform)
  if (!c.hostname) c.hostname = d.hostname
  return c
}

export function runAudits(p: Project, ds: Dataset): { audits: DeviceAudit[]; configs: Config[] } {
  const configs = p.devices.filter(d => ds[d.id] !== undefined).map(d => parseDevice(d, ds[d.id]))
  return { configs, audits: configs.map(c => auditConfig(c, p.settings, p.waivers)) }
}

// One in-flight creation per sample, so a double click (or a re-run effect) never makes two copies.
const creating = new Map<string, Promise<Project>>()
export function createSampleProject(sampleId = 'fleet'): Promise<Project> {
  const p = creating.get(sampleId) ?? buildSample(sampleId).finally(() => creating.delete(sampleId))
  creating.set(sampleId, p)
  return p
}

async function buildSample(sampleId: string): Promise<Project> {
  const existing = getProjects().find(p => p.sampleId === sampleId)
  if (existing) return existing
  const def = SAMPLES.find(s => s.id === sampleId)!
  const settings = getDefaults()
  const now = Date.now()
  const id = uuid()
  // An older audit of the same fleet, so History has a real compare from day one.
  const prev = (def.previous ?? []).map(f => ingest(f))
  const prevAudits = prev.map(i => auditConfig(parse(i.text, i.platform), settings, {}))
  const snapshots = prev.length ? [makeSnapshot(uuid(), 'Previous audit (synthetic)', prevAudits, Object.fromEntries(prev.map(i => [i.hostname, i.text])), now - 35 * 86400000)] : []
  const cur = def.files.map(f => ingest(f))
  const devices = cur.map(toDevice)
  await putData(id, Object.fromEntries(devices.map((d, k) => [d.id, cur[k].text])))
  return saveProject({ id, name: def.name, createdAt: now, updatedAt: now, devices, settings, waivers: {}, snapshots, sampleId })
}

export async function createBlankProject(name: string): Promise<Project> {
  const now = Date.now()
  return saveProject({ id: uuid(), name, createdAt: now, updatedAt: now, devices: [], settings: getDefaults(), waivers: {}, snapshots: [] })
}

/** Adds devices; a device with the same hostname is replaced (that is a re-import of the same box). */
export async function addDevices(p: Project, items: Ingested[]): Promise<{ added: number; replaced: number }> {
  const ds = { ...(await getData(p.id) ?? {}) }
  let devices = [...p.devices]
  let added = 0, replaced = 0
  for (const it of items) {
    const old = devices.find(d => d.hostname.toLowerCase() === it.hostname.toLowerCase())
    const dev = toDevice(it)
    if (old) { delete ds[old.id]; devices = devices.map(d => d === old ? dev : d); replaced++ }
    else { devices.push(dev); added++ }
    ds[dev.id] = it.text
  }
  await putData(p.id, ds)
  await saveProject({ ...p, devices, dataMissing: false })
  return { added, replaced }
}

export async function removeDevice(p: Project, id: string): Promise<() => Promise<void>> {
  const ds = { ...(await getData(p.id) ?? {}) }
  const text = ds[id]
  const dev = p.devices.find(d => d.id === id)
  delete ds[id]
  await putData(p.id, ds)
  await saveProject({ ...p, devices: p.devices.filter(d => d.id !== id) })
  return async () => {
    const cur = getProjects().find(x => x.id === p.id)
    if (!cur || !dev) return
    const d2 = { ...(await getData(p.id) ?? {}), [id]: text }
    await putData(p.id, d2)
    await saveProject({ ...cur, devices: [...cur.devices, dev] })
  }
}

export function useProject(id: string) {
  const list = useProjects()
  const project = list?.find(p => p.id === id) ?? null
  const [ds, setDs] = useState<Dataset | null>(null)
  const devKey = project ? project.devices.map(d => d.id).join(',') : ''
  useEffect(() => {
    if (!project) return
    let live = true
    void getData(project.id).then(d => { if (live) setDs(d ?? {}) })
    return () => { live = false }
  }, [project?.id, devKey])
  const update = (patch: Partial<Project>) => project && saveProject({ ...project, ...patch })
  const run = useMemo(() => project && ds ? runAudits(project, ds) : null, [project?.devices, project?.settings, project?.waivers, ds])
  return { loading: list === null || (project !== null && ds === null), project, ds, update, audits: run?.audits ?? [], configs: run?.configs ?? [] }
}
