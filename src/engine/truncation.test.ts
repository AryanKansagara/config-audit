import { test } from 'node:test'
import assert from 'node:assert/strict'
import { auditConfig, fleetScore } from './audit.ts'
import { makeSnapshot } from './fleet.ts'
import { ingest } from './ingest.ts'
import { maskSecrets } from './mask.ts'
import { parse } from './parse.ts'
import { DEFAULT_SETTINGS } from './rules.ts'
import { BRANCH, CORE, EDGE } from './samples.ts'

test('truncated IOS configs are marked incomplete, get no grade, and are excluded from fleet score', () => {
  const truncated = [
    '!',
    'hostname CORE-SW-01',
    'service password-encryption',
    'no service pad',
    'aaa new-model',
    'ip domain name core.example.net',
    'no ip source-route',
  ].join('\n')
  const g = ingest({ name: 'core-cut.cfg', text: truncated })
  assert.equal(g.ok, true)
  assert.equal(g.incomplete, true)
  assert.ok(g.issues.some(i => /may be truncated/.test(i.message)))

  const c = parse(g.text, g.platform)
  const incAudit = auditConfig(c, DEFAULT_SETTINGS, {}, undefined, { incomplete: g.incomplete })
  assert.equal(incAudit.incomplete, true)
  assert.equal(incAudit.score, null)
  assert.equal(incAudit.grade, null)

  // Fleet of only incomplete devices has no fleet score or grade.
  const onlyInc = fleetScore([incAudit])
  assert.equal(onlyInc.score, null)
  assert.equal(onlyInc.grade, null)
  assert.equal(onlyInc.incompleteCount, 1)

  // Mixed fleet excludes the incomplete device from the fleet average and snapshot score.
  const branchAudit = auditConfig(parse(maskSecrets(BRANCH).text, 'ios'), DEFAULT_SETTINGS, {})
  const mixed = fleetScore([branchAudit, incAudit])
  assert.equal(mixed.score, branchAudit.score)
  assert.equal(mixed.scoredCount, 1)
  assert.equal(mixed.incompleteCount, 1)

  const snap = makeSnapshot('s1', 'mixed', [branchAudit, incAudit])
  assert.equal(snap.score, branchAudit.score)
  assert.equal(snap.incompleteCount, 1)
  assert.equal(snap.devices.find(d => d.host === 'CORE-SW-01')?.score, null)
})

test('explicitly confirming completeness grades the device and includes it in the fleet score', () => {
  const truncated = 'hostname PARTIAL-1\nservice password-encryption\naaa new-model\n'
  const g = ingest({ name: 'partial.cfg', text: truncated })
  assert.equal(g.incomplete, true)
  const a = auditConfig(parse(g.text, g.platform), DEFAULT_SETTINGS, {}, undefined, { incomplete: true, confirmedComplete: true })
  assert.equal(a.incomplete, undefined)
  assert.equal(a.confirmedComplete, true)
  assert.ok(typeof a.score === 'number' && a.grade !== null)
  const f = fleetScore([a])
  assert.equal(f.score, a.score)
  assert.equal(f.incompleteCount, 0)
})

test('NX-OS, ASA without ": end", and supported snippets are not misflagged as incomplete', () => {
  const nxos = ingest({
    name: 'nx1.cfg',
    text: '!Command: show running-config\nfeature ssh\nhostname NX1\nline vty\n exec-timeout 10\n',
  })
  assert.equal(nxos.platform, 'nxos')
  assert.equal(nxos.incomplete, undefined)
  assert.ok(!nxos.issues.some(i => /truncated/.test(i.message)))

  const asa = ingest({
    name: 'fw1.cfg',
    text: ': Saved\nASA Version 9.18(3)\nhostname FW1\nnameif outside\nssh 10.0.0.0 255.255.255.0 inside\n',
  })
  assert.equal(asa.platform, 'asa')
  assert.equal(asa.incomplete, undefined)
  assert.ok(!asa.issues.some(i => /truncated/.test(i.message)))

  const aclFrag = ingest({
    name: 'acl.txt',
    text: 'ip access-list extended ACL_00\n permit udp any host 192.0.2.10\n',
  })
  assert.equal(aclFrag.ok, true)
  assert.equal(aclFrag.incomplete, undefined)

  const ifaceFrag = ingest({
    name: 'ifc.txt',
    text: 'interface GigabitEthernet0/1\n ip address 10.0.0.1 255.255.255.0\n no shutdown\n',
  })
  assert.equal(ifaceFrag.ok, true)
  assert.equal(ifaceFrag.incomplete, undefined)

  // Complete full IOS samples remain non-incomplete.
  for (const [name, txt] of [['branch', BRANCH], ['core', CORE], ['edge', EDGE]]) {
    assert.equal(ingest({ name, text: txt }).incomplete, undefined, name)
  }
})

test('pager prompts and unclosed banners still mark captures truncated even on NX-OS/ASA', () => {
  const nxPaged = ingest({
    name: 'nx-cut.cfg',
    text: '!Command: show running-config\nhostname NX-CUT\ninterface Ethernet1/1\n --More-- \n',
  })
  assert.equal(nxPaged.incomplete, true)

  const asaPaged = ingest({
    name: 'asa-cut.cfg',
    text: 'ASA Version 9.16(4)\nhostname FW-CUT\n<--- More --->\n',
  })
  assert.equal(asaPaged.incomplete, true)

  const bannerCut = ingest({
    name: 'banner-cut.cfg',
    text: 'hostname BAN-CUT\nbanner motd ^C\nAuthorized users only\n',
  })
  assert.equal(bannerCut.incomplete, true)
})
