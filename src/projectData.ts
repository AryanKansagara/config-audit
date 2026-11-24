import { useEffect, useMemo, useState } from 'react'
import { auditConfig, type DeviceAudit } from './engine/audit.ts'
import { makeSnapshot } from './engine/fleet.ts'
import { ingest, type Ingested } from './engine/ingest.ts'
import { looksSecret, maskSecrets, maskUnrecognisedLine, sanitizeConfigText } from './engine/mask.ts'
import { parse, type Config } from './engine/parse.ts'
import { SAMPLES } from './engine/samples.ts'
import { getData, getDefaults, getProjects, putData, saveProject, useProjects, uuid, type Dataset, type Device, type Project } from './store.ts'

const toDevice = (i: Ingested): Device => ({ id: uuid(), hostname: i.hostname, platform: i.platform, source: i.source, importedAt: Date.now(), lines: i.lines, secrets: i.secrets, issues: i.issues })

export function parseDevice(d: Device, text: string): Config {
  const c = parse(sanitizeConfigText(text), d.platform)
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
  const safeDs = useMemo(() => ds ? Object.fromEntries(Object.entries(ds).map(([k, v]) => [k, sanitizeConfigText(v)])) : null, [ds])
  const legacyUnmasked = useMemo(() => !!(project && ds && hasUnmaskedSecrets(project, ds)), [project, ds])
  const maskStoredCopy = async () => {
    if (!project || !ds) return
    const nextDs = await maskStoredProject(project, ds)
    setDs(nextDs)
  }
  const run = useMemo(() => project && safeDs ? runAudits(project, safeDs) : null, [project?.devices, project?.settings, project?.waivers, safeDs])
  return { loading: list === null || (project !== null && ds === null), project, ds: safeDs, legacyUnmasked, maskStoredCopy, update, audits: run?.audits ?? [], configs: run?.configs ?? [] }
}

const scrubIssues = (issues: Device['issues']) => issues.map(iss => {
  if (!/Possible secret the masker did not recognise/.test(iss.message)) return iss
  const m = iss.message.match(/"([^"]+)"/)
  if (!m) return iss
  const inner = m[1].replace(/\s+\.\.\.$/, '')
  const masked = maskUnrecognisedLine(sanitizeConfigText(inner))
  return masked === inner ? iss : { ...iss, message: iss.message.replace(m[1], `${masked} ...`) }
})

export function hasUnmaskedSecrets(p: Project, ds: Dataset): boolean {
  for (const d of p.devices) {
    const raw = ds[d.id]
    if (raw && sanitizeConfigText(raw) !== raw.replace(/\r\n?/g, '\n')) return true
    if (d.issues.some((iss, i) => scrubIssues(d.issues)[i].message !== iss.message)) return true
  }
  for (const s of p.snapshots) {
    if (s.configs && Object.values(s.configs).some(v => sanitizeConfigText(v) !== v.replace(/\r\n?/g, '\n'))) return true
    if (s.devices.some(d => d.findings.some(f => sanitizeConfigText(f.target) !== f.target))) return true
  }
  return false
}

export async function maskStoredProject(p: Project, ds: Dataset): Promise<Dataset> {
  const nextDs: Dataset = Object.fromEntries(Object.entries(ds).map(([k, v]) => [k, sanitizeConfigText(v)]))
  await putData(p.id, nextDs)
  const devices = p.devices.map(d => {
    const raw = ds[d.id]
    if (!raw) return { ...d, issues: scrubIssues(d.issues) }
    const { secrets } = maskSecrets(raw)
    const extra = raw.split('\n').some(l => looksSecret(l))
    return {
      ...d,
      secrets: secrets.length && secrets.length >= d.secrets.length ? secrets : d.secrets,
      issues: extra ? scrubIssues(d.issues) : d.issues,
    }
  })
  const snapshots = p.snapshots.map(s => ({
    ...s,
    devices: s.devices.map(d => ({ ...d, findings: d.findings.map(f => ({ ...f, target: sanitizeConfigText(f.target) })) })),
    configs: s.configs ? Object.fromEntries(Object.entries(s.configs).map(([k, v]) => [k, sanitizeConfigText(v)])) : undefined,
  }))
  await saveProject({ ...p, devices, snapshots })
  return nextDs
}
