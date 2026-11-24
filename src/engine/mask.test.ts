import { test } from 'node:test'
import assert from 'node:assert/strict'
import { maskSecrets, looksSecret, sanitizeConfigText } from './mask.ts'
import { ingest, splitConfigs } from './ingest.ts'
import { auditText } from './audit.ts'
import { makeSnapshot } from './fleet.ts'
import { BRANCH, CORE, EDGE, SAMPLES } from './samples.ts'

test('masks vtp, server-private, isis, nhrp, rsvp and mpls ldp across variants', () => {
  const cfg = [
    'Building configuration...',
    'hostname R1',
    'vtp password LEAKvtp1',
    'vtp password 0 LEAKvtp2',
    'vtp password LEAKvtp3hidden hidden',
    'aaa group server tacacs+ TAC',
    ' server-private 192.0.2.4 key LEAKpriv1',
    ' server-private 192.0.2.5 port 49 timeout 5 single-connection key 7 LEAKpriv7',
    'interface GigabitEthernet0/0',
    ' isis password LEAKisis1',
    ' isis password 0 LEAKisis2 level-2',
    ' ip nhrp authentication LEAKnhrp',
    ' ip rsvp authentication key LEAKrsvp',
    ' ip rsvp authentication key-chain SAFE_RSVP_CHAIN',
    'router isis',
    ' area-password LEAKarea',
    ' domain-password 7 LEAKdom authenticate snp send-only',
    'mpls ldp neighbor 192.0.2.9 password LEAKldp1',
    'mpls ldp neighbor vrf CUST1 192.0.2.10 password 7 LEAKldp7',
    'end',
  ].join('\n')

  const { text, secrets } = maskSecrets(cfg)
  assert.ok(!/LEAK/.test(text), text)
  assert.match(text, /^vtp password <masked:weak>$/m)
  assert.match(text, /^vtp password 0 <masked:weak>$/m)
  assert.match(text, /^vtp password <masked> hidden$/m)
  assert.match(text, /server-private 192\.0\.2\.4 key <masked:weak>/)
  assert.match(text, /server-private 192\.0\.2\.5 port 49 timeout 5 single-connection key 7 <masked:weak>/)
  assert.match(text, /^ isis password <masked:weak>$/m)
  assert.match(text, /^ isis password 0 <masked:weak> level-2$/m)
  assert.match(text, /^ ip nhrp authentication <masked:weak>$/m)
  assert.match(text, /^ ip rsvp authentication key <masked:weak>$/m)
  assert.match(text, /^ ip rsvp authentication key-chain SAFE_RSVP_CHAIN$/m)
  assert.match(text, /^ area-password <masked:weak>$/m)
  assert.match(text, /^ domain-password 7 <masked:weak> authenticate snp send-only$/m)
  assert.match(text, /^mpls ldp neighbor 192\.0\.2\.9 password <masked:weak>$/m)
  assert.match(text, /^mpls ldp neighbor vrf CUST1 192\.0\.2\.10 password 7 <masked:weak>$/m)
  assert.equal(secrets.length, 13)
  assert.equal(ingest({ name: 'r1.cfg', text: cfg }).ok, true)
})

test('handles flexible whitespace, quoted values, algorithm-type, and multi-line continuations', () => {
  const cfg = [
    'hostname   WS-RTR',
    'enable   algorithm-type   scrypt   secret   LEAKen',
    'username   bob   algorithm-type   scrypt   secret   LEAKuser',
    'username   alice   \\',
    '  privilege 15   secret   LEAKcont',
    'tacacs server ISE-1',
    ' key   123456',
    'key chain KC1',
    ' key 1',
    '  key-string   "LEAK quoted key"',
    'end',
  ].join('\n')
  const { text, secrets } = maskSecrets(cfg)
  assert.ok(!/LEAK|123456/.test(text), text)
  assert.match(text, /^enable\s+algorithm-type\s+scrypt\s+secret\s+<masked:weak>$/m)
  assert.match(text, /^username\s+bob\s+algorithm-type\s+scrypt\s+secret\s+<masked:weak>$/m)
  assert.match(text, /privilege 15\s+secret\s+<masked:weak>/)
  assert.match(text, /^ key\s+<masked:weak>$/m)
  assert.match(text, /^ key 1$/m, 'key ID inside key chain is preserved')
  assert.match(text, /^  key-string\s+<masked:weak>$/m)
  assert.equal(secrets.length, 5)
  assert.equal(secrets.find(s => s.line === 5)?.line, 5)
})

test('handles NX-OS and ASA platform variants including quoted type 7, PBKDF2, LDAP, failover, and single-line banners', () => {
  const nxos = [
    '!Command: show running-config',
    'feature ssh',
    'switchname NX1',
    'username admin password 5 $5$salt$LEAKsha role network-admin',
    'tacacs-server key 7 "LEAKnx7"',
    'snmp-server user ops network-admin auth sha "LEAKauth" priv aes-128 "LEAKpriv"',
  ].join('\n')
  const mNx = maskSecrets(nxos)
  assert.ok(!/LEAK/.test(mNx.text), mNx.text)
  assert.equal(mNx.secrets.length, 4)
  assert.equal(mNx.secrets[0].weak, false)

  const asa = [
    ': Saved',
    'ASA Version 9.18(3)',
    'hostname FW1',
    'banner login Authorized access only',
    'passwd LEAKasa1 pbkdf2',
    'enable password LEAKenpbk pbkdf2',
    'username fwadmin password LEAKfwadmin encrypted privilege 15',
    'aaa-server CORP protocol ldap',
    ' ldap-login-password LEAKldap',
    ' radius-common-pw LEAKrad',
    'failover key LEAKfail',
    ': end',
  ].join('\n')
  const gAsa = ingest({ name: 'fw1.cfg', text: asa })
  assert.equal(gAsa.platform, 'asa')
  assert.equal(gAsa.ok, true)
  assert.ok(!/LEAK/.test(gAsa.text), gAsa.text)
  assert.equal(gAsa.secrets.length, 6)
  assert.equal(gAsa.secrets[0].type, 'pbkdf2')
  assert.equal(gAsa.secrets[0].weak, false)
})

test('closed banners preserve banner prose, while unclosed banners and unrecognised secrets fail closed', () => {
  const closed = [
    'hostname B1',
    'banner motd ^C',
    'Never share your password or community here',
    '^C',
    'vtp password LEAKreal',
    'end',
  ].join('\n')
  const gClosed = ingest({ name: 'b1.cfg', text: closed })
  assert.equal(gClosed.ok, true)
  assert.match(gClosed.text, /Never share your password or community here/)
  assert.ok(!/LEAKreal/.test(gClosed.text))

  const unclosed = [
    'hostname B2',
    'banner motd ^C',
    'vtp password LEAKinside',
    'custom-daemon secret LEAKunrec',
  ].join('\n')
  const gUnclosed = ingest({ name: 'b2.cfg', text: unclosed })
  assert.equal(gUnclosed.ok, false)
  assert.ok(!/LEAK/.test(gUnclosed.text))
  assert.ok(!gUnclosed.issues.some(i => /LEAK/.test(i.message)))

  const unrec = [
    'hostname R-UNREC',
    'vendor-tool auth-key LEAKraw123',
    'end',
  ].join('\n')
  const gUnrec = ingest({ name: 'u.cfg', text: unrec })
  assert.equal(gUnrec.ok, false)
  assert.ok(!gUnrec.text.includes('LEAKraw123'))
  assert.match(gUnrec.text, /vendor-tool auth-key <masked>/)
  assert.ok(gUnrec.issues.some(i => i.level === 'error' && /Possible secret/.test(i.message) && !i.message.includes('LEAKraw123')))
})

test('Ansible JSON imports, snapshots, and existing fixtures mask cleanly with zero regressions', () => {
  const ansible = JSON.stringify({
    r1: {
      ansible_facts: {
        ansible_net_hostname: 'ANS-R1',
        ansible_net_config: 'hostname ANS-R1\nvtp password LEAKans\nend\n',
      },
    },
    r2: {
      ansible_facts: {
        ansible_net_hostname: 'ANS-R2',
        ansible_net_config: 'hostname ANS-R2\ncustom-app shared-secret LEAKblock\nend\n',
      },
    },
  })
  const parts = splitConfigs({ name: 'facts.json', text: ansible }).map(ingest)
  assert.equal(parts.length, 2)
  assert.equal(parts[0].ok, true)
  assert.ok(!/LEAK/.test(parts[0].text))
  assert.equal(parts[1].ok, false)
  assert.ok(!/LEAK/.test(parts[1].text))

  // Defense-in-depth snapshot sanitization strips legacy unmasked values if any reached makeSnapshot.
  const a = auditText(maskSecrets(BRANCH).text)
  const snap = makeSnapshot('s1', 'test', [a], { 'BR-RTR-01': 'hostname BR-RTR-01\nvtp password LEAKsnap\nend' })
  assert.ok(!/LEAKsnap/.test(snap.configs!['BR-RTR-01']))
  assert.equal(sanitizeConfigText(maskSecrets(BRANCH).text), maskSecrets(BRANCH).text)

  // All bundled fixtures stay ok with exact expected grades/scores and zero unmasked issues.
  assert.equal(auditText(ingest({ name: 'branch', text: BRANCH }).text).score, 34)
  assert.equal(auditText(ingest({ name: 'core', text: CORE }).text).score, 80)
  assert.equal(auditText(ingest({ name: 'edge', text: EDGE }).text).score, 96)
  for (const f of SAMPLES[1].files) assert.equal(ingest(f).ok, true, f.name)
  assert.equal(looksSecret('ntp server 10.0.50.123 key 1 prefer'), false)
})

test('second pass: further secrets on a line, URLs, comments and less common keys are masked, and it is idempotent', () => {
  const lines = [
    'username bob privilege 15 password 0 LEAKa secret 5 LEAKb', 'key config-key password-encrypt LEAK', ' authentication mode hmac-sha-256 0 LEAK',
    ' area 1 virtual-link 192.0.2.1 message-digest-key 1 md5 7 LEAK', ' ospfv3 authentication ipsec spi 500 sha1 LEAK',
    ' ipv6 ospf encryption ipsec spi 500 esp aes-cbc 128 LEAK sha1 LEAK', ' authentication text LEAK', ' path ftp://user:LEAK@192.0.2.1/cfg',
    ' pre-shared-key hex LEAK', ' key-octet-string 7 LEAK cryptographic-algorithm AES_128_CMAC', 'snmp-server community 7 LEAK RO',
    'snmp mib community-map LEAK engineid 1', 'license smart register idtoken LEAK', 'event manager environment _pw LEAK two', ' management-interface key=LEAK',
    'aaa-server X (inside) host 192.0.2.1 LEAK', ' description old password LEAK', ' remark secret: LEAK', '! enable secret LEAK', 'no username bob password 0 LEAK',
  ]
  for (const l of lines) {
    const once = maskSecrets(`hostname R1\n${l}\nend\n`).text
    assert.doesNotMatch(once, /LEAK/, l)
    assert.equal(maskSecrets(once).text, once, l)
  }
  const keep = 'hostname R1\nno service password-encryption\nservice password-encryption\nno enable password\nno ip http server\nip ospf authentication message-digest\naaa-server X protocol radius\naaa-server X (inside) host 192.0.2.1\nsecurity passwords min-length 10\nip ssh version 2\nend\n'
  assert.equal(maskSecrets(keep).text, keep)
})

test('bare NX-OS hsrp keys and keys written in remarks are masked; ordinary authentication lines are not', () => {
  const t = 'hostname R1\ninterface Vlan1\n  hsrp 1\n    authentication LEAK\n    priority 110\n  ip address 192.0.2.1/24\nip access-list extended A\n remark key LEAK\nrouter ospf 1\n area 0 authentication message-digest\ncrypto isakmp policy 1\n authentication pre-share\nkey chain K\nend\n'
  const once = maskSecrets(t).text
  assert.doesNotMatch(once, /LEAK/)
  for (const keep of [' area 0 authentication message-digest', ' authentication pre-share', 'key chain K', '    priority 110']) assert.ok(once.includes(keep), keep)
  assert.equal(maskSecrets(once).text, once)
})
