import { test } from 'node:test'
import assert from 'node:assert/strict'
import { child, detectPlatform, find, parse, path } from './parse.ts'
import { maskSecrets } from './mask.ts'
import { analyzeAcl, extractAcls, parseAce, remainder, wildcardRanges, ipToInt, objectGroupUsage, aclReferences, type Box } from './acl.ts'
import { auditText, findingsCsv, remediationScript, inventory } from './audit.ts'
import { RULES, DEFAULT_SETTINGS } from './rules.ts'
import { compareSnapshots, configDiff, drift, lineDiff, makeSnapshot } from './fleet.ts'
import { ingest, splitConfigs } from './ingest.ts'
import { applyBlocks } from './simulate.ts'
import { BRANCH, CORE, EDGE, SAMPLES } from './samples.ts'

const audit = (t: string) => auditText(maskSecrets(t).text)
const ruleIds = (t: string) => new Set(audit(t).findings.map(f => f.rule))

// ---------- Parser ----------

test('parser builds parent/child blocks from indentation', () => {
  const c = parse('hostname R1\n!\ninterface Gi0/1\n description up\n ip address 10.0.0.1 255.255.255.0\n!\nrouter bgp 65001\n address-family ipv4\n  neighbor 10.0.0.2 activate\n exit-address-family\n!\nend\n')
  const ifc = find(c, /^interface /)[0]
  assert.equal(ifc.children.length, 2)
  assert.equal(child(ifc, /^description/)!.text, 'description up')
  const nb = c.lines.find(l => l.text.startsWith('neighbor'))!
  assert.deepEqual(path(nb), ['router bgp 65001', 'address-family ipv4'])
  assert.equal(c.hostname, 'R1')
})

test('multi-line banners do not leak into the config tree', () => {
  const c = parse('hostname R1\nbanner motd ^C\nline vty 0 4\n transport input telnet\n^C\nline vty 0 4\n transport input ssh\nend\n')
  const vty = find(c, /^line vty/)
  assert.equal(vty.length, 1, 'the "line vty" inside the banner is banner text, not config')
  assert.equal(child(vty[0], /^transport/)!.text, 'transport input ssh')
})

test('platform detection: IOS, IOS XE, NX-OS, ASA', () => {
  assert.equal(detectPlatform('version 15.7\nhostname R'), 'ios')
  assert.equal(detectPlatform('version 17.9\nhostname R'), 'iosxe')
  assert.equal(detectPlatform('!Command: show running-config\nfeature ssh\nhostname N'), 'nxos')
  assert.equal(detectPlatform(': Saved\nASA Version 9.18(3)\nhostname FW'), 'asa')
})

// ---------- Masking ----------

test('secrets are masked and keep only type and weakness', () => {
  const { text, secrets } = maskSecrets('enable secret 9 $9$abc$def\nusername bob privilege 15 password 7 0822455D0A16\nsnmp-server community public RO 10\nsnmp-server community Xk82-pq7Zr-llw9 RO MGMT\ntacacs-server key S3cr3t!\n line vty 0 4\n password 7 104D000A0618\n')
  assert.ok(!/0822455D0A16|public|Xk82|S3cr3t|\$9\$abc/.test(text), 'no secret value survives')
  assert.match(text, /^enable secret 9 <masked>$/m)
  assert.match(text, /^username bob privilege 15 password 7 <masked:weak>$/m)
  assert.match(text, /^snmp-server community <masked:weak> RO 10$/m)
  assert.match(text, /^snmp-server community <masked> RO MGMT$/m)
  assert.equal(secrets.length, 6)
  assert.deepEqual(secrets.map(s => s.weak), [false, true, true, false, true, true])
})

test('masking leaves non-secret lines alone', () => {
  const src = 'service password-encryption\nkey chain K\n key 1\n  key-string 7 0822455D0A16\npassword encryption aes\nip ssh version 2\n'
  const { text, secrets } = maskSecrets(src)
  assert.match(text, /^ key 1$/m)
  assert.match(text, /^password encryption aes$/m)
  assert.equal(secrets.length, 1)
})

// ---------- ACL engine ----------

test('wildcards: contiguous and non-contiguous', () => {
  assert.deepEqual(wildcardRanges(ipToInt('10.1.0.0')!, ipToInt('0.0.255.255')!), [[ipToInt('10.1.0.0'), ipToInt('10.1.255.255')]])
  const odd = wildcardRanges(ipToInt('10.0.0.1')!, ipToInt('0.0.1.0')!)!
  assert.deepEqual(odd, [[ipToInt('10.0.0.1'), ipToInt('10.0.0.1')], [ipToInt('10.0.1.1'), ipToInt('10.0.1.1')]])
})

test('ACE parsing: ports, named ports, ranges, established', () => {
  const a = parseAce('permit tcp 10.0.0.0 0.0.0.255 host 192.0.2.10 range 8000 8099 established', 'ios')!
  assert.equal(a.boxes.length, 1)
  const [proto, , dst, , dp, est] = a.boxes[0]
  assert.deepEqual(proto, [6, 6])
  assert.deepEqual(dst, [ipToInt('192.0.2.10'), ipToInt('192.0.2.10')])
  assert.deepEqual(dp, [8000, 8099])
  assert.deepEqual(est, [1, 1])
  const b = parseAce('permit tcp any any eq www 443 22', 'ios')!
  assert.deepEqual(b.boxes.map(x => x[4]), [[80, 80], [443, 443], [22, 22]])
  assert.equal(parseAce('permit ip any any', 'ios')!.anyAny, true)
})

test('ASA uses subnet masks, IOS uses wildcards', () => {
  const asa = parseAce('permit tcp 10.1.1.0 255.255.255.0 any eq ssh', 'asa')!
  assert.deepEqual(asa.boxes[0][1], [ipToInt('10.1.1.0'), ipToInt('10.1.1.255')])
  const ios = parseAce('permit tcp 10.1.1.0 0.0.0.255 any eq 22', 'ios')!
  assert.deepEqual(ios.boxes[0][1], asa.boxes[0][1])
})

test('box subtraction finds coverage by several ACEs together', () => {
  const half1 = parseAce('permit tcp 10.20.0.0 0.0.127.255 any eq 22', 'ios')!.boxes
  const half2 = parseAce('permit tcp 10.20.128.0 0.0.127.255 any eq 22', 'ios')!.boxes
  const whole = parseAce('deny tcp 10.20.0.0 0.0.255.255 any eq 22', 'ios')!.boxes
  assert.equal(remainder(whole, half1)!.length > 0, true, 'one half alone does not cover it')
  assert.deepEqual(remainder(whole, [...half1, ...half2] as Box[]), [])
})

test('shadowed vs redundant vs any-any on the core switch ACL', () => {
  const c = parse(maskSecrets(CORE).text)
  const acls = extractAcls(c)
  const servers = acls.find(a => a.name === 'SERVERS-IN')!
  assert.equal(servers.aces.length, 10)
  const issues = analyzeAcl(servers)
  const kinds = issues.map(i => `${i.text.split(' ')[0]}:${i.kind}`)
  assert.deepEqual(kinds, ['20:shadowed', '50:shadowed', '70:redundant'])
  assert.equal(issues[1].by.length, 2, 'line 50 is covered by 30 and 40 together')
  assert.deepEqual(analyzeAcl(acls.find(a => a.name === 'TEMP-MIGRATION')!).map(i => i.kind), ['any-any'])
})

test('a narrower port range after a broader one is shadowed; a broader one is not', () => {
  const c = parse('hostname X\nip access-list extended T\n permit tcp any any range 1 1024\n deny tcp any any eq 443\n deny tcp any any range 1000 2000\nend\n')
  const issues = analyzeAcl(extractAcls(c)[0])
  assert.equal(issues.length, 1)
  assert.match(issues[0].text, /eq 443/)
})

test('established-only ACE is covered by a full TCP permit but not the other way round', () => {
  const a = parse('hostname X\nip access-list extended T\n permit tcp any any\n permit tcp any any established\nend\n')
  assert.equal(analyzeAcl(extractAcls(a)[0])[0]?.kind, 'redundant')
  const b = parse('hostname X\nip access-list extended T\n permit tcp any any established\n deny tcp any any\nend\n')
  assert.equal(analyzeAcl(extractAcls(b)[0]).length, 0)
})

test('object-groups resolve into ranges, and unused ones are reported', () => {
  const c = parse(maskSecrets(CORE).text)
  const ace = extractAcls(c).find(a => a.name === 'SERVERS-IN')!.aces.find(a => a.text.includes('APP-SERVERS'))!
  assert.equal(ace.exact, true)
  assert.equal(ace.boxes.length, 2)
  const usage = objectGroupUsage(c)
  assert.deepEqual(usage.map(u => `${u.name}:${u.used}`), ['APP-SERVERS:true', 'LEGACY-NMS:false'])
})

test('ACL references cover interfaces, VTYs, SNMP, NAT and HTTP', () => {
  const refs = aclReferences(parse(maskSecrets(CORE).text))
  assert.ok(refs.has('SERVERS-IN') && refs.has('MGMT-VTY') && refs.has('SNMP-RO'))
  assert.ok(!refs.has('TEMP-MIGRATION'))
  assert.ok(aclReferences(parse(BRANCH)).has('NAT-USERS'))
})

test('NX-OS and ASA numbered and named ACL syntax', () => {
  const nx = parse('!Command: show running-config\nfeature ssh\nhostname N1\nip access-list WEB\n  10 permit tcp 10.0.0.0/8 any eq 443\n  20 permit tcp 10.1.0.0/16 any eq 443\n')
  assert.equal(nx.platform, 'nxos')
  assert.deepEqual(analyzeAcl(extractAcls(nx)[0]).map(i => i.kind), ['redundant'])
  const asa = parse('ASA Version 9.16(4)\nhostname FW\nobject-group network WEB\n network-object host 192.0.2.10\naccess-list OUT extended permit tcp any object-group WEB eq https\naccess-list OUT extended deny tcp any host 192.0.2.10 eq 443\naccess-group OUT in interface outside\n')
  assert.deepEqual(analyzeAcl(extractAcls(asa)[0]).map(i => i.kind), ['shadowed'])
})

// ---------- Rule pack ----------

test('rule pack has 40+ checks with unique ids and complete metadata', () => {
  assert.ok(RULES.length >= 40, `got ${RULES.length}`)
  assert.equal(new Set(RULES.map(r => r.id)).size, RULES.length)
  for (const r of RULES) assert.ok(r.title && r.rationale && r.ref && r.platforms.length, r.id)
})

test('branch router: telnet, type 7, enable password, public community, http server', () => {
  const ids = ruleIds(BRANCH)
  for (const id of ['ACC-01', 'PWD-01', 'PWD-04', 'PWD-05', 'SNMP-01', 'SNMP-02', 'SNMP-03', 'ACC-09', 'NTP-01', 'LOG-01', 'SVC-01', 'SVC-02', 'SVC-03', 'INT-01', 'INT-04']) assert.ok(ids.has(id), id)
  assert.ok(!ids.has('ACL-02'))
})

test('hardened edge router scores an A and passes the access checks', () => {
  const a = audit(EDGE)
  assert.equal(a.grade, 'A')
  const ids = new Set(a.findings.map(f => f.rule))
  for (const id of ['ACC-01', 'ACC-02', 'ACC-03', 'AAA-01', 'NTP-02', 'SVC-02', 'INT-04', 'LOG-01']) assert.ok(!ids.has(id), id)
  assert.ok(ids.has('RTE-02'), 'second BGP neighbor has no password')
})

test('scores rank the fleet: branch < core < edge', () => {
  const [b, c, e] = [BRANCH, CORE, EDGE].map(t => audit(t).score)
  assert.ok(b < c && c < e, `${b} ${c} ${e}`)
  assert.ok(b < 50)
})

test('waivers suppress a finding until they expire', () => {
  const host = 'BR-RTR-01'
  const key = `${host}|ACC-09|ip http server`
  const masked = maskSecrets(BRANCH).text
  const base = auditText(masked)
  const w = auditText(masked, DEFAULT_SETTINGS, { [key]: { key, reason: 'Needed for DNA onboarding', expires: '2999-01-01', at: 0 } })
  assert.ok(w.findings.find(f => f.key === key)!.waived)
  assert.ok(w.score > base.score)
  const lapsed = auditText(masked, DEFAULT_SETTINGS, { [key]: { key, reason: 'old', expires: '2000-01-01', at: 0 } })
  assert.equal(lapsed.findings.find(f => f.key === key)!.waived, undefined)
})

test('NX-OS telnet, ASA telnet and open management are caught', () => {
  assert.ok(ruleIds('!Command: show running-config\nfeature telnet\nfeature ssh\nhostname N1\n').has('ACC-11'))
  const asa = ruleIds('ASA Version 9.12(4)\nhostname FW\ntelnet 10.0.0.0 255.0.0.0 inside\nssh 0.0.0.0 0.0.0.0 outside\nhttp server enable\nhttp 0.0.0.0 0.0.0.0 outside\n: end\n')
  for (const id of ['ACC-12', 'ACC-13', 'ACC-02', 'LOG-06']) assert.ok(asa.has(id), id)
})

// ---------- Remediation ----------

test('remediation script puts commands in the right parent context with rollback', () => {
  const a = audit(BRANCH)
  const s = remediationScript(a.host, a.platform, a.findings)
  assert.match(s.apply, /line vty 0 4\n transport input ssh\n/)
  assert.match(s.apply, /interface GigabitEthernet0\/2\n description UNUSED\n shutdown\nexit/)
  assert.ok(s.apply.indexOf('ip access-list standard MGMT-VTY') < s.apply.indexOf('access-class MGMT-VTY in'), 'ACL is defined before it is applied')
  assert.equal((s.apply.match(/^ip access-list standard MGMT-VTY$/gm) ?? []).length, 1, 'shared ACL defined once')
  assert.match(s.rollback, /line vty 0 4\n.*transport input telnet ssh/s)
  assert.match(s.rollback, /no access-class MGMT-VTY in/)
})

test('applying every fix raises the branch score to A, and the result re-parses cleanly', () => {
  const masked = maskSecrets(BRANCH).text
  const before = auditText(masked)
  const after = auditText(applyBlocks(masked, before.findings.flatMap(f => f.fix?.apply ?? [])))
  assert.ok(after.score >= 90, `after ${after.score}`)
  assert.ok(after.score > before.score + 40)
  assert.ok(!after.findings.some(f => f.rule === 'ACC-01' || f.rule === 'PWD-01'))
})

test('simulate: "no" removes the line, singletons replace their value', () => {
  const out = applyBlocks('hostname R\nip http server\nline vty 0 4\n transport input telnet\n exec-timeout 0 0\nend', [{ parents: [], cmds: ['no ip http server', 'no ip source-route'] }, { parents: ['line vty 0 4'], cmds: ['transport input ssh', 'exec-timeout 10 0'] }])
  assert.equal(out, 'hostname R\nline vty 0 4\n transport input ssh\n exec-timeout 10 0\nno ip source-route\nend')
})

// ---------- Fleet ----------

test('drift lists settings that differ across devices with the majority value', () => {
  const rows = drift([BRANCH, CORE, EDGE].map(t => parse(maskSecrets(t).text)))
  const ntp = rows.find(r => r.setting === 'NTP servers')!
  assert.equal(ntp.values['BR-RTR-01'], '(none)')
  assert.equal(ntp.majority, '10.0.50.123, 10.0.50.124')
  assert.ok(rows.some(r => r.setting === 'VTY transport'))
  assert.ok(!rows.some(r => r.setting === 'Time zone'), 'all three share EST')
})

test('config diff is order-independent and grouped by parent', () => {
  const a = parse('hostname R\ninterface Gi1\n shutdown\n description x\nntp server 192.0.2.1\nend')
  const b = parse('hostname R\nntp server 192.0.2.2\ninterface Gi1\n description x\nend')
  const d = configDiff(a, b)
  assert.deepEqual(d.find(g => g.parent === 'interface Gi1'), { parent: 'interface Gi1', added: [], removed: ['shutdown'] })
  assert.deepEqual(d.find(g => g.parent === ''), { parent: '', added: ['ntp server 192.0.2.2'], removed: ['ntp server 192.0.2.1'] })
  assert.deepEqual(lineDiff(['a', 'b', 'c'], ['a', 'c', 'd']).map(x => x.op + x.text), [' a', '-b', ' c', '+d'])
})

test('snapshot compare: fixed, new and regressed', () => {
  const mk = (id: string, t: string) => makeSnapshot(id, id, [audit(t)])
  const s1 = mk('s1', BRANCH)
  const s2 = mk('s2', BRANCH.replace(' transport input telnet ssh\n', ' transport input ssh\n'))
  const s3 = mk('s3', BRANCH.replace('ip http server\n', 'ip http secure-server\n').replace('version 15.7\n', 'version 15.7\nservice tcp-small-servers\n'))
  const c12 = compareSnapshots(s1, s2)
  assert.deepEqual(c12.fixed.map(f => f.rule), ['ACC-01'])
  const c23 = compareSnapshots(s2, s3, [s1])
  assert.deepEqual(c23.regressed.map(f => f.rule), ['ACC-01'], 'telnet came back')
  assert.ok(c23.added.some(f => f.rule === 'SVC-06'))
  assert.ok(c23.fixed.some(f => f.rule === 'ACC-09'))
})

// ---------- Import ----------

test('import splits concatenated configs and Ansible ios_facts JSON', () => {
  const two = splitConfigs({ name: 'paste', text: BRANCH + '\n' + CORE })
  assert.equal(two.length, 2)
  assert.deepEqual(two.map(f => ingest(f).hostname), ['BR-RTR-01', 'CORE-SW-01'])
  const json = JSON.stringify({ r1: { ansible_facts: { ansible_net_hostname: 'r1', ansible_net_config: 'hostname r1\nline vty 0 4\n transport input telnet\nend' } } })
  const files = splitConfigs({ name: 'facts.json', text: json })
  assert.equal(files.length, 1)
  assert.ok(ruleIds(files[0].text).has('ACC-01'))
})

test('validation report flags paging, truncation and non-configs with line numbers', () => {
  const r = ingest({ name: 'r.txt', text: 'R1#show run\nhostname R1\ninterface Gi0/1\n --More-- \n ip address 10.0.0.1 255.255.255.0\n' })
  assert.ok(r.issues.some(i => i.line === 4 && /terminal length 0/.test(i.message)))
  assert.ok(r.issues.some(i => /truncated/.test(i.message)))
  assert.equal(ingest({ name: 'notes.txt', text: 'groceries\nmilk\n' }).ok, false)
})

test('inventory and CSV export', () => {
  const inv = inventory(parse(maskSecrets(CORE).text))
  assert.deepEqual(inv.vlans.map(v => v.id), ['10', '20', '30', '99'])
  assert.deepEqual(inv.routing.map(r => r.protocol), ['OSPF'])
  assert.equal(inv.interfaces.find(i => i.name === 'GigabitEthernet1/0/1')!.vlan, '30')
  const csv = findingsCsv([audit(BRANCH)])
  assert.match(csv.split('\r\n')[0], /^host,platform,rule,severity/)
  assert.ok(!/0822455D0A16|public/.test(csv), 'no secrets in exports')
  assert.equal(SAMPLES[0].files.length, 3)
})

test('sample configs use only RFC 1918 / RFC 5737 / loopback addresses', () => {
  const ok = (ip: string) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|0\.0\.0\.0$|255\.|127\.|224\.|0\.|31\.255)/.test(ip)
  for (const f of [...SAMPLES[0].files, ...(SAMPLES[0].previous ?? [])]) {
    for (const ip of f.text.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g) ?? []) assert.ok(ok(ip), `${f.name}: ${ip}`)
  }
})
