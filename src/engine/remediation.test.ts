import { test } from 'node:test'
import assert from 'node:assert/strict'
import { auditText, findingsCsv, remediationScript, type Finding } from './audit.ts'
import { maskSecrets } from './mask.ts'
import { sanitizeFix } from './rules.ts'
import { applyBlocks } from './simulate.ts'
import { BRANCH, CORE, EDGE } from './samples.ts'
import { BATFISH_FILES } from './samples-public.ts'

function runnableLines(script: string): string[] {
  return script.split('\n').filter(line => {
    const trimmed = line.trim()
    return trimmed.length > 0 && !trimmed.startsWith('!')
  })
}

function assertCleanScript(scriptText: string, label: string) {
  for (const line of runnableLines(scriptText)) {
    assert.ok(!/<masked/i.test(line), `${label} runnable line still has <masked>: ${line}`)
  }
}

test('no fixture remediation script (Apply, Rollback, finding fixes, CSV) emits <masked> in runnable commands', () => {
  for (const [name, raw] of [['BRANCH', BRANCH], ['CORE', CORE], ['EDGE', EDGE], ...BATFISH_FILES.map(f => [f.name, f.text] as const)]) {
    const a = auditText(maskSecrets(raw).text)
    const s = remediationScript(a.host, a.platform, a.findings)
    assertCleanScript(s.apply, `${name} apply`)
    assertCleanScript(s.rollback, `${name} rollback`)
    for (const f of a.findings) {
      if (!f.fix) continue
      for (const b of [...f.fix.apply, ...f.fix.rollback]) {
        for (const cmd of b.cmds) {
          if (!cmd.trim().startsWith('!')) {
            assert.ok(!/<masked/i.test(cmd), `${name} ${f.rule} fix still has <masked>: ${cmd}`)
          }
        }
      }
    }
    const csv = findingsCsv([a])
    for (const line of csv.split(/\r?\n/).slice(1)) {
      if (!line) continue
      const fixCol = line.slice(line.lastIndexOf(',') + 1)
      assert.ok(!/<masked/i.test(fixCol), `${name} CSV fix column has <masked>: ${fixCol}`)
    }
  }
})

test('BR-RTR-01 disambiguates RO and RW community placeholders and explains them in notes', () => {
  const masked = maskSecrets(BRANCH).text
  const a = auditText(masked)
  const s = remediationScript(a.host, a.platform, a.findings)
  assert.match(s.apply, /^no snmp-server community <OLD-COMMUNITY-RO> RO$/m)
  assert.match(s.apply, /^no snmp-server community <OLD-COMMUNITY-RW> RW$/m)
  assert.match(s.apply, /^snmp-server community <NEW-LONG-RANDOM-COMMUNITY> RO MGMT-SNMP$/m)
  assert.ok(s.notes.some(n => n.includes('<OLD-COMMUNITY-RO>')))
  assert.ok(s.notes.some(n => n.includes('<OLD-COMMUNITY-RW>')))
  assert.ok(s.notes.some(n => n.includes('<NEW-LONG-RANDOM-COMMUNITY>')))
  assert.ok(!s.apply.includes('<masked'))
  assert.ok(!s.rollback.includes('<masked'))

  const after = auditText(applyBlocks(masked, a.findings.flatMap(f => f.fix?.apply ?? [])))
  assert.ok(after.score >= 90, `expected simulated score >= 90, got ${after.score}`)
  assert.ok(!after.findings.some(f => f.rule === 'SNMP-01' || f.rule === 'SNMP-02' || f.rule === 'SNMP-03'))
})

test('multiple communities with the same role get unique line-numbered tokens and are all removed', () => {
  const cfg = [
    'hostname DUP-SNMP',
    'snmp-server community public RO',
    'snmp-server community monitor RO',
    'end',
  ].join('\n')
  const masked = maskSecrets(cfg).text
  const a = auditText(masked)
  const s = remediationScript(a.host, a.platform, a.findings)
  assertCleanScript(s.apply, 'dup apply')
  assertCleanScript(s.rollback, 'dup rollback')
  assert.match(s.apply, /^no snmp-server community <OLD-COMMUNITY-RO-L2> RO$/m)
  assert.match(s.apply, /^no snmp-server community <OLD-COMMUNITY-RO-L3> RO$/m)

  const after = auditText(applyBlocks(masked, a.findings.flatMap(f => f.fix?.apply ?? [])))
  assert.ok(!after.findings.some(f => f.rule === 'SNMP-01' || f.rule === 'SNMP-03'))
})

test('strong masked communities (SNMP-01 / SNMP-02) never emit <masked> on IOS or NX-OS', () => {
  const ios = [
    'hostname STRONG-IOS',
    'snmp-server community Str0ng!Comm-RO RO',
    'snmp-server community Str0ng!Comm-RW RW MGMT-ACL',
    'ip access-list standard MGMT-ACL',
    ' permit 10.0.0.0 0.0.0.255',
    'end',
  ].join('\n')
  const iosMasked = maskSecrets(ios).text
  const iosAudit = auditText(iosMasked)
  const iosScript = remediationScript(iosAudit.host, iosAudit.platform, iosAudit.findings)
  assertCleanScript(iosScript.apply, 'strong ios apply')
  assertCleanScript(iosScript.rollback, 'strong ios rollback')
  assert.match(iosScript.apply, /^snmp-server community <EXISTING-COMMUNITY-RO> RO MGMT-SNMP$/m)
  assert.match(iosScript.apply, /^no snmp-server community <EXISTING-COMMUNITY-RW> RW MGMT-ACL$/m)
  assert.match(iosScript.apply, /^snmp-server community <EXISTING-COMMUNITY-RW> RO MGMT-SNMP$/m)
  assert.match(iosScript.rollback, /^no snmp-server community <EXISTING-COMMUNITY-RO>$/m)
  assert.match(iosScript.rollback, /^snmp-server community <EXISTING-COMMUNITY-RO> RO$/m)
  assert.match(iosScript.rollback, /^snmp-server community <EXISTING-COMMUNITY-RW> RW MGMT-ACL$/m)
  assert.ok(!iosScript.notes.some(n => /<masked/.test(n)))
  assert.ok(iosScript.notes.some(n => n.includes('<EXISTING-COMMUNITY-RO>')))
  assert.ok(iosScript.notes.some(n => n.includes('<EXISTING-COMMUNITY-RW>')))

  const iosAfter = auditText(applyBlocks(iosMasked, iosAudit.findings.flatMap(f => f.fix?.apply ?? [])))
  assert.ok(!iosAfter.findings.some(f => f.rule === 'SNMP-01' || f.rule === 'SNMP-02'))

  const nxos = [
    '!Command: show running-config',
    'feature ssh',
    'hostname STRONG-NX',
    'snmp-server community Str0ng!NX-RO group network-operator',
    'snmp-server community Str0ng!NX-RW group network-admin',
  ].join('\n')
  const nxMasked = maskSecrets(nxos).text
  const nxAudit = auditText(nxMasked)
  const nxScript = remediationScript(nxAudit.host, nxAudit.platform, nxAudit.findings)
  assertCleanScript(nxScript.apply, 'strong nxos apply')
  assertCleanScript(nxScript.rollback, 'strong nxos rollback')
  assert.match(nxScript.apply, /^snmp-server community <EXISTING-COMMUNITY-RO> use-ipv4acl MGMT-SNMP$/m)
  assert.match(nxScript.apply, /^no snmp-server community <EXISTING-COMMUNITY-RW> group network-admin$/m)

  const nxAfter = auditText(applyBlocks(nxMasked, nxAudit.findings.flatMap(f => f.fix?.apply ?? [])))
  assert.ok(!nxAfter.findings.some(f => f.rule === 'SNMP-01' || f.rule === 'SNMP-02'))
})

test('weak snmp-server host lines on IOS and ASA use clear fill-in tokens in apply and rollback', () => {
  const ios = [
    'hostname TRAP-IOS',
    'snmp-server host 192.0.2.50 version 2c public',
    'snmp-server host 192.0.2.51 version 2c private',
    'end',
  ].join('\n')
  const iosMasked = maskSecrets(ios).text
  const iosAudit = auditText(iosMasked)
  const iosScript = remediationScript(iosAudit.host, iosAudit.platform, iosAudit.findings)
  assertCleanScript(iosScript.apply, 'trap ios apply')
  assertCleanScript(iosScript.rollback, 'trap ios rollback')
  assert.match(iosScript.apply, /^no snmp-server host 192\.0\.2\.50 version 2c <OLD-TRAP-COMMUNITY-L2>$/m)
  assert.match(iosScript.apply, /^no snmp-server host 192\.0\.2\.51 version 2c <OLD-TRAP-COMMUNITY-L3>$/m)
  assert.match(iosScript.apply, /^snmp-server host 192\.0\.2\.50 version 2c <NEW-LONG-RANDOM-COMMUNITY>$/m)
  assert.match(iosScript.rollback, /^no snmp-server host 192\.0\.2\.50 version 2c <NEW-LONG-RANDOM-COMMUNITY>$/m)
  assert.ok(iosScript.notes.some(n => n.includes('<OLD-TRAP-COMMUNITY-L2>')))

  const iosAfter = auditText(applyBlocks(iosMasked, iosAudit.findings.flatMap(f => f.fix?.apply ?? [])))
  assert.ok(!iosAfter.findings.some(f => f.rule === 'SNMP-03'))

  const asa = [
    'ASA Version 9.18(3)',
    'hostname TRAP-ASA',
    'snmp-server host INSIDE Machine01 poll community public',
  ].join('\n')
  const asaAudit = auditText(maskSecrets(asa).text)
  const asaScript = remediationScript(asaAudit.host, asaAudit.platform, asaAudit.findings)
  assertCleanScript(asaScript.apply, 'trap asa apply')
  assertCleanScript(asaScript.rollback, 'trap asa rollback')
  assert.match(asaScript.apply, /^no snmp-server host INSIDE Machine01 poll community <OLD-TRAP-COMMUNITY>$/m)
  assert.match(asaScript.apply, /^snmp-server host INSIDE Machine01 poll community <NEW-LONG-RANDOM-COMMUNITY>$/m)
})

test('all masked secret categories and fallback sanitizer never emit <masked> in runnable apply or rollback commands', () => {
  const allSecrets = [
    'hostname SECRET-ALL',
    'enable password 7 0822455D0A16',
    'enable secret 5 $1$Xq7e$Wb2HnY1mJz2rQk3pA6vLs1',
    'username netadmin privilege 15 password 7 13061E010803',
    'tacacs-server key 7 0822455D0A16',
    'radius-server key 7 0822455D0A16',
    'ntp authentication-key 1 md5 104D000A0618 7',
    'key chain KC',
    ' key 1',
    '  key-string 7 0822455D0A16',
    'router bgp 65001',
    ' neighbor 192.0.2.10 remote-as 65002',
    ' neighbor 192.0.2.10 password 7 0822455D0A16',
    'line vty 0 4',
    ' password 7 104D000A0618',
    ' login',
    'end',
  ].join('\n')
  const a = auditText(maskSecrets(allSecrets).text)
  const s = remediationScript(a.host, a.platform, a.findings)
  assertCleanScript(s.apply, 'all-secrets apply')
  assertCleanScript(s.rollback, 'all-secrets rollback')

  // Direct defense-in-depth test for non-SNMP masked findings via sanitizeFix & remediationScript
  const fixed = sanitizeFix({
    apply: [{ parents: [], cmds: ['no tacacs-server key 7 <masked:weak>', '! leave comment <masked> untouched'] }],
    rollback: [{ parents: [], cmds: ['tacacs-server key <masked>'] }],
  })
  assert.deepEqual(fixed.apply[0].cmds, ['no tacacs-server key 7 <FILL-IN-SECRET>', '! leave comment <masked> untouched'])
  assert.deepEqual(fixed.rollback[0].cmds, ['tacacs-server key <FILL-IN-SECRET>'])
  assert.match(fixed.note ?? '', /<FILL-IN-SECRET>/)

  const syntheticFinding: Finding = {
    key: 'R1|TEST|psk',
    host: 'R1',
    rule: 'TEST-01',
    title: 'Test masked command',
    severity: 'high',
    category: 'Passwords',
    ref: 'test',
    target: 'crypto isakmp key',
    detail: 'weak key',
    fix: {
      apply: [{ parents: [], cmds: ['no crypto isakmp key <masked:weak> address 192.0.2.5'] }],
      rollback: [{ parents: [], cmds: ['crypto isakmp key <masked:weak> address 192.0.2.5'] }],
    },
  }
  const scrubbed = remediationScript('R1', 'ios', [syntheticFinding])
  assertCleanScript(scrubbed.apply, 'synthetic apply')
  assertCleanScript(scrubbed.rollback, 'synthetic rollback')
  assert.match(scrubbed.apply, /no crypto isakmp key <FILL-IN-SECRET> address 192\.0\.2\.5/)
  assert.match(scrubbed.rollback, /crypto isakmp key <FILL-IN-SECRET> address 192\.0\.2\.5/)
  assert.ok(scrubbed.notes.some(n => n.includes('<FILL-IN-SECRET>')))
})
