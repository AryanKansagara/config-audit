// Regression tests from real-world config layouts. The fixtures are short excerpts written to match
// public configs: the Batfish example network (Apache-2.0, github.com/batfish/batfish, networks/example)
// and the ciscoconfparse test fixtures (layout only; values and addresses rewritten).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parse } from './parse.ts'
import { maskSecrets, looksSecret } from './mask.ts'
import { aclReferences, analyzeAcl, extractAcls, objectGroupUsage } from './acl.ts'
import { auditText } from './audit.ts'
import { ingest, splitConfigs } from './ingest.ts'

const audit = (t: string) => auditText(maskSecrets(t).text)
const hits = (t: string, rule: string) => audit(t).findings.filter(f => f.rule === rule)

test('SNMPv3 users: both auth and priv values are masked (IOS and NX-OS layouts)', () => {
  const { text, secrets } = maskSecrets([
    'snmp-server user admin network-admin auth md5 0x8a1b2c3d4e5f60718293a4b5c6d7e8f9 priv 0x8a1b2c3d4e5f60718293a4b5c6d7e8f9 localizedkey',
    'snmp-server user NMS NETOPS v3 auth sha AuthPass123 priv aes 128 PrivPass456 access MGMT',
  ].join('\n'))
  assert.ok(!/0x8a1b|AuthPass123|PrivPass456/.test(text), 'no SNMPv3 key survives')
  assert.match(text, /auth md5 <masked> priv <masked> localizedkey/)
  assert.match(text, /auth sha <masked:weak> priv aes 128 <masked:weak> access MGMT$/m)
  assert.equal(secrets.length, 4)
})

test('ASA "snmp-server host ... community X" masks the community, not the host name', () => {
  const { text } = maskSecrets('snmp-server host INSIDE Machine01 poll community public\nsnmp-server host OUTSIDE 192.0.2.9 community 0 Tr4p-C0mmunity-77 version 2c\n')
  assert.match(text, /^snmp-server host INSIDE Machine01 poll community <masked:weak>$/m)
  assert.match(text, /^snmp-server host OUTSIDE 192\.0\.2\.9 community 0 <masked> version 2c$/m)
  assert.ok(!/public|Tr4p/.test(text))
})

test('keys after options, PPP/FTP passwords, HSRP auth and keyring PSKs are masked', () => {
  const src = [
    'radius-server host 192.0.2.10 auth-port 1812 acct-port 1813 key 7 12115605111E005739',
    'ip ftp password 7 107D3D232342041E3A',
    'interface Dialer1',
    ' ppp chap password 7 107D3D232342041E3A',
    ' ppp pap sent-username auser password 7 023530612D5319347A',
    'interface Vlan10',
    ' standby 1 authentication md5 key-string 7 0822455D0A16',
    ' standby 2 authentication cisco',
    'crypto keyring KR',
    ' pre-shared-key address 198.51.100.7 key S1te2S1teKey',
  ].join('\n')
  const { text, secrets } = maskSecrets(src)
  assert.ok(!/12115605|107D3D|0235306|0822455D|\bcisco\b|S1te2S1te/.test(text), text)
  assert.match(text, /auth-port 1812 acct-port 1813 key 7 <masked:weak>/)
  assert.match(text, /pre-shared-key address 198\.51\.100\.7 key <masked:weak>/)
  assert.equal(secrets.length, 7)
  assert.ok(text.split('\n').every(l => !looksSecret(l)), 'nothing left that looks like a secret')
})

test('hash types: NX-OS type 5 with $5$ is SHA-crypt (strong), $1$ is MD5, type 3 is reversible', () => {
  const { secrets } = maskSecrets('username a password 5 $5$Kx9$abcdefabcdef role network-admin\nusername b password 5 $1$.vTq$m3rHbbqITE role network-operator\nrouter bgp 65001\n  neighbor 192.0.2.1 remote-as 65001\n    password 3 a667d47acc18ea6b\n')
  assert.deepEqual(secrets.map(s => [s.type, s.weak]), [['sha-crypt', false], ['5', true], ['3', true]])
})

test('import warns about lines that still look like secrets, but not BGP communities', () => {
  assert.equal(looksSecret('set community 65001:2 additive'), false)
  assert.equal(looksSecret('match community as2_community'), false)
  assert.equal(looksSecret('ip bgp-community new-format'), false)
  assert.equal(looksSecret(' isis password Sup3rS3cret'), true)
  const g = ingest({ name: 'r1.cfg', text: 'hostname R1\nrouter isis\n isis password Sup3rS3cret\nroute-map RM permit 10\n set community 1:2 additive\nend\n' })
  const warns = g.issues.filter(i => /Possible secret/.test(i.message))
  assert.deepEqual(warns.map(w => w.line), [3])
})

test('exec-timeout 15 0 is reported as too long, not as disabled', () => {
  const f = hits('hostname R1\nline vty 0 4\n exec-timeout 15 0\n transport input ssh\nend\n', 'ACC-04')
  assert.equal(f.length, 1)
  assert.match(f[0].detail, /over 10 minutes/)
  assert.match(hits('hostname R1\nline vty 0 4\n exec-timeout 0 0\nend\n', 'ACC-04')[0].detail, /disabled/)
})

test('"match access-group name X" references X only', () => {
  const refs = aclReferences(parse('class-map match-all C\n match access-group name NOT_INTERNAL\n'))
  assert.deepEqual([...refs.keys()], ['NOT_INTERNAL'])
})

// Excerpt of networks/example/live/configs/as1border1.cfg from Batfish (Apache-2.0).
const BATFISH_BGP = `hostname as1border1
router bgp 1
 bgp router-id 1.1.1.1
 neighbor as1 peer-group
 neighbor as1 remote-as 1
 neighbor as2 peer-group
 neighbor as2 remote-as 2
 neighbor as2 password 7 0822455D0A16
 neighbor 1.10.1.1 peer-group as1
 neighbor 1.10.1.1 update-source Loopback0
 neighbor 10.12.11.2 peer-group as2
 neighbor 5.6.7.8 remote-as 555
 neighbor 5.6.7.8 shutdown
end
`

test('BGP: peer-group members are checked, a peer-group password covers them, shut neighbors are skipped', () => {
  const f = hits(BATFISH_BGP, 'RTE-02')
  assert.deepEqual(f.map(x => x.target), ['router bgp 1 neighbor 1.10.1.1'])
})

test('ASA object NAT: an object used by its own nat statement is not "unused", and is listed once', () => {
  const c = parse('ASA Version 9.8(2)\nhostname fw\nobject network obj_any\n subnet 0.0.0.0 0.0.0.0\nobject network spare\n host 192.0.2.5\nobject network obj_any\n nat (INSIDE,OUTSIDE) dynamic interface\n: end\n', 'asa')
  const u = objectGroupUsage(c)
  assert.deepEqual(u.map(x => [x.name, x.used]), [['obj_any', true], ['spare', false]])
})

test('ACL wording: "line N already denies", "lines A, B together already deny"', () => {
  const acl = extractAcls(parse('ip access-list extended A\n deny ip any any\n deny tcp any any\nip access-list extended B\n permit tcp any any\n permit udp any any\n deny tcp host 192.0.2.1 any\n'))
  assert.match(analyzeAcl(acl[0])[0].detail, /line 2 already denies all/)
  const b = analyzeAcl(acl[1]).find(i => i.line === 7)!
  assert.match(b.detail, /line 5 already permits all/)
})

test('Ansible: "ansible_facts | to_nice_json" (net_config) and ad-hoc "| SUCCESS =>" output are both read', () => {
  const facts = splitConfigs({ name: 'r1.json', text: JSON.stringify({ net_hostname: 'r1', net_config: 'hostname r1\nend\n', net_version: '17.09.04a' }) })
  assert.deepEqual(facts.map(f => f.name), ['r1'])
  const adhoc = `r1 | SUCCESS => {
    "ansible_facts": { "ansible_net_config": "hostname r1\\nend\\n", "ansible_net_hostname": "r1" },
    "changed": false
}
r2 | UNREACHABLE! => {
    "changed": false,
    "msg": "timed out"
}
r3 | SUCCESS => {
    "ansible_facts": { "ansible_net_config": "hostname r3\\nend\\n", "ansible_net_hostname": "r3" },
    "changed": false
}`
  const out = splitConfigs({ name: 'adhoc.txt', text: adhoc })
  assert.deepEqual(out.map(f => f.name), ['r1', 'r3'])
  assert.match(out[1].text, /^hostname r3/)
})

test('ACL-only snippets are accepted as Cisco config', () => {
  assert.ok(ingest({ name: 'acl.txt', text: 'ip access-list extended ACL_00\n permit udp any host 192.0.2.10\n' }).ok)
})

test('bundled Batfish sample: six IOS routers parse cleanly with BGP, OSPF and ACLs found', async () => {
  const { SAMPLES } = await import('./samples.ts')
  const s = SAMPLES.find(x => x.id === 'batfish')!
  assert.equal(s.files.length, 6)
  for (const f of s.files) {
    const g = ingest(f)
    assert.ok(g.ok && g.platform === 'ios' && g.hostname === f.name.replace('.cfg', ''), f.name)
    assert.ok(!g.issues.some(i => i.level !== 'info'), `${f.name}: ${JSON.stringify(g.issues)}`)
    const a = auditText(g.text)
    assert.ok(a.score > 40 && a.score < 90, `${f.name} score ${a.score}`)
    if (/^router ospf/m.test(f.text)) assert.ok(a.findings.some(x => x.rule === 'RTE-01'), `${f.name}: OSPF without authentication is found`)
  }
})

test('ACL first-match attribution: only entries that actually catch traffic are blamed (Batfish as2dept1)', () => {
  const [a] = extractAcls(parse('ip access-list extended RESTRICT_HOST_TRAFFIC_IN\n permit ip 2.128.0.0 0.0.255.255 any\n deny   ip any any\n permit icmp any any\n'))
  const i = analyzeAcl(a)
  assert.equal(i.length, 1)
  assert.equal(i[0].kind, 'shadowed')
  assert.deepEqual(i[0].by, [2, 3])
  assert.match(i[0].detail, /line 2 \(permit\), line 3 \(deny\) catch all of its traffic first/)
  // An overlapping deny whose overlap was already permitted earlier does not make the entry "shadowed".
  const [b] = extractAcls(parse('ip access-list extended B\n permit tcp any any\n deny tcp host 192.0.2.1 any\n permit tcp host 192.0.2.1 any eq 22\n'))
  const j = analyzeAcl(b).filter(x => x.line === 4)
  assert.equal(j[0].kind, 'redundant')
  assert.deepEqual(j[0].by, [2])
})
