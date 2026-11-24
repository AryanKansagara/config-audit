import { strToU8, zipSync } from 'fflate'
import { pasted, secretsOf } from './configs'
import { downloadText, dumpStorage, expect, fleetScore, newBlankAudit, openSampleFleet, test } from './fixtures'

// Scores of the synthetic sample fleet. They come straight from the rule engine, so a change to a rule,
// weight or the sample itself changes them: update these numbers together with that change.
const SAMPLE = { fleet: 70, open: 65, critical: 5, devices: { 'BR-RTR-01': 34, 'CORE-SW-01': 80, 'EDGE-RTR-01': 96 } }

const deviceScore = (page: import('@playwright/test').Page, host: string) =>
  page.getByRole('img', { name: new RegExp(`^${host} score: \\d+ out of 100`) })

test.describe('sample fleet', () => {
  test('shows scores and an ACL shadowing finding', async ({ page }) => {
    await page.goto('/')
    await page.getByRole('link', { name: 'Try the sample fleet' }).click()
    await expect(page.getByRole('heading', { level: 1, name: /Three-device fleet/ })).toBeVisible()
    await expect(page).toHaveURL(/\/app\/p\/[\w-]+$/)

    expect(await fleetScore(page)).toBe(SAMPLE.fleet)
    await expect(page.getByText(`3 devices · ${SAMPLE.open} open findings · ${SAMPLE.critical} critical · 0 waived`)).toBeVisible()
    for (const [host, score] of Object.entries(SAMPLE.devices)) {
      await expect(deviceScore(page, host)).toHaveAttribute('aria-label', new RegExp(`: ${score} out of 100`))
    }

    // ACL reasoning: lines 110 and 111 together cover line 112, so the deny never matches.
    await page.getByRole('navigation', { name: 'Audit sections' }).getByRole('link', { name: 'ACLs' }).click()
    await page.getByRole('tab', { name: /CORE-SW-01/ }).click()
    const shadowed = page.getByRole('row', { name: /deny tcp 10\.20\.0\.0 0\.0\.255\.255 host 10\.30\.1\.20 eq 22/ })
    await expect(shadowed).toContainText('shadowed')
    await expect(shadowed).toContainText('Never matches: lines 110, 111 together already permit all of its traffic.')
    await expect(page.getByRole('row', { name: /deny tcp 10\.20\.5\.0 0\.0\.0\.255 host 10\.30\.1\.10 eq 443/ })).toContainText('Never matches: line 108 already permits all of its traffic.')
    // A redundant entry is reported differently from a shadowed one.
    await expect(page.getByRole('row', { name: /permit udp 10\.0\.0\.0 0\.255\.255\.255 host 10\.30\.1\.53 eq 53/ })).toContainText('Redundant: line 113 already permits all of its traffic.')
  })

  test('opens a device with its remediation and rollback scripts, and downloads them', async ({ page }) => {
    const id = await openSampleFleet(page)
    await page.getByRole('link', { name: /BR-RTR-01/ }).first().click()
    await expect(page).toHaveURL(new RegExp(`/app/p/${id}/device/BR-RTR-01$`))
    await expect(page.getByRole('heading', { level: 2, name: 'BR-RTR-01' })).toBeVisible()
    await expect(page.getByText('After the script')).toBeVisible()

    await page.getByRole('tab', { name: 'Remediation script' }).click()
    const apply = page.locator('.code', { has: page.getByText('Apply', { exact: true }) })
    const rollback = page.locator('.code', { has: page.getByText('Rollback', { exact: true }) })
    await expect(apply).toContainText('! Remediation for BR-RTR-01 (IOS)')
    await expect(apply).toContainText('! reload in 15')
    await expect(apply).toContainText('configure terminal')
    await expect(apply).toContainText('aaa new-model')
    await expect(apply).toContainText('username netadmin privilege 15 algorithm-type scrypt secret <NEW-PASSWORD>')
    await expect(rollback).toContainText('! Rollback for BR-RTR-01 (IOS)')
    await expect(rollback).toContainText('no ip access-list standard MGMT-VTY')

    const a = await downloadText(page, () => apply.getByRole('button', { name: 'Download' }).click())
    const r = await downloadText(page, () => rollback.getByRole('button', { name: 'Download' }).click())
    expect(a.name).toBe('BR-RTR-01-remediation.txt')
    expect(r.name).toBe('BR-RTR-01-rollback.txt')
    expect(a.text).toContain('configure terminal')
    expect(a.text).toContain('ip ssh version 2')
    expect(r.text).toContain('! Rollback for BR-RTR-01 (IOS)')
    expect(a.text.trimEnd()).toBe((await apply.locator('pre').innerText()).trimEnd())
    expect(r.text.trimEnd()).toBe((await rollback.locator('pre').innerText()).trimEnd())
    // The sample's own secrets were masked on load, so they are not in the scripts either.
    for (const s of ['Branch123', 'br4nchRW', '13061E010803', '0822455D0A16']) {
      expect(a.text + r.text).not.toContain(s)
    }
  })

  test('a waiver changes the score, survives a reload, and can be removed', async ({ page }) => {
    const id = await openSampleFleet(page)
    const before = await fleetScore(page)
    expect(before).toBe(SAMPLE.fleet)

    await page.goto(`/app/p/${id}/findings`)
    await expect(page.getByText(`${SAMPLE.open} findings`, { exact: true })).toBeVisible()
    const row = page.locator('li.finding').filter({ hasText: 'HTTP server disabled' }).filter({ hasText: 'BR-RTR-01' })
    await row.locator('.finding-head').click()
    await row.getByRole('button', { name: 'Waive…' }).click()
    await row.getByLabel(/Reason/).fill('E2E: accepted risk, isolated management VRF')
    await row.getByLabel('Approved by').fill('E2E Tester')
    await row.getByRole('button', { name: 'Waive', exact: true }).click()
    await expect(page.getByText(/^Waived until \d{4}-\d{2}-\d{2}$/)).toBeVisible()

    await expect(page.getByText(`${SAMPLE.open - 1} findings`, { exact: true })).toBeVisible()
    await page.getByRole('link', { name: 'Overview' }).click()
    await expect(page.getByText(`${SAMPLE.open - 1} open findings · ${SAMPLE.critical} critical · 1 waived`)).toBeVisible()
    const after = await fleetScore(page)
    expect(after).toBeGreaterThan(before)

    // Persisted: a reload keeps the waiver, its reason and the new score.
    await page.reload()
    await expect(page.getByText(`${SAMPLE.open - 1} open findings`)).toBeVisible()
    expect(await fleetScore(page)).toBe(after)
    await page.goto(`/app/p/${id}/findings`)
    await page.getByLabel('Status').selectOption('waived')
    const waived = page.locator('li.finding.waived')
    await expect(waived).toHaveCount(1)
    await waived.locator('.finding-head').click()
    await expect(waived).toContainText('E2E: accepted risk, isolated management VRF (approved by E2E Tester)')

    await waived.getByRole('button', { name: 'Remove waiver' }).click()
    await page.getByRole('link', { name: 'Overview' }).click()
    await expect(page.getByText(`${SAMPLE.open} open findings · ${SAMPLE.critical} critical · 0 waived`)).toBeVisible()
    expect(await fleetScore(page)).toBe(before)
  })

  test('the audit is still there after a reload and from the workspace list', async ({ page }) => {
    const id = await openSampleFleet(page)
    await page.reload()
    await expect(page.getByRole('heading', { level: 1, name: /Three-device fleet/ })).toBeVisible()
    expect(await fleetScore(page)).toBe(SAMPLE.fleet)

    await page.goto('/app')
    await expect(page.getByText('Stored in this browser.')).toBeVisible()
    const card = page.locator('article.project-card')
    await expect(card).toHaveCount(1)
    await expect(card).toContainText('Three-device fleet')
    await expect(card.getByRole('link', { name: 'Three-device fleet' })).toHaveAttribute('href', `/app/p/${id}`)
    // Opening the sample again reuses the stored audit instead of making a second copy.
    await page.goto('/app?sample=fleet')
    await expect(page).toHaveURL(new RegExp(`/app/p/${id}$`))
    await page.goto('/app')
    await expect(card).toHaveCount(1)
  })
})

const everywhere = async (page: import('@playwright/test').Page, id: string, hosts: string[]) => {
  // All text a user can reach for this audit, plus every file the app can download.
  const seen: string[] = []
  const text = async () => seen.push(await page.locator('body').innerText())
  for (const tab of ['', '/findings', '/acls', '/drift', '/inventory', '/history', '/configs', '/report']) {
    await page.goto(`/app/p/${id}${tab}`)
    await expect(page.locator('h1').first()).toBeVisible()
    await expect(page.locator('.boot')).toHaveCount(0)
    await text()
  }
  for (const h of hosts) {
    await page.goto(`/app/p/${id}/device/${h}`)
    await expect(page.getByRole('heading', { level: 2, name: h })).toBeVisible()
    await text()
    await page.getByRole('tab', { name: 'Remediation script' }).click()
    await text()
    for (const title of ['Apply', 'Rollback']) {
      const block = page.locator('.code', { has: page.getByText(title, { exact: true }) })
      seen.push((await downloadText(page, () => block.getByRole('button', { name: 'Download' }).click())).text)
    }
  }
  await page.goto(`/app/p/${id}`)
  seen.push((await downloadText(page, () => page.getByRole('button', { name: 'CSV' }).click())).text)
  await page.goto('/settings')
  seen.push((await downloadText(page, () => page.getByRole('button', { name: /Export all my data/ }).click())).text)
  seen.push(await dumpStorage(page))
  return seen.join('\n=====\n')
}

test.describe('import and secret masking', () => {
  test('a pasted config is audited and its secrets are masked everywhere', async ({ page }) => {
    const id = await newBlankAudit(page)
    await page.locator('#paste').fill(pasted('E2E-PASTE-01', 'P'))
    await page.getByRole('button', { name: 'Check', exact: true }).click()

    const report = page.locator('.panel', { has: page.getByRole('heading', { name: 'Validation report' }) })
    await expect(report).toContainText('E2E-PASTE-01')
    await expect(report).toContainText('Masked: 1 type 5, 3 plain text, 1 type 7, 1 SNMP community; 6 weak.')
    await expect(report).toContainText('New device')
    // Not even the validation report may show a value.
    for (const s of secretsOf('P')) expect(await report.innerText()).not.toContain(s)

    await report.getByRole('button', { name: 'Import 1 device' }).click()
    await expect(page.getByText('Added 1 device')).toBeVisible()
    await expect(page.getByText('1 device · ')).toBeVisible()
    await expect(page.getByRole('link', { name: 'E2E-PASTE-01' })).toBeVisible()
    await expect(deviceScore(page, 'E2E-PASTE-01')).toBeVisible()

    // The masked config is what the device page shows, and the masked markers are in place.
    await page.goto(`/app/p/${id}/device/E2E-PASTE-01`)
    await expect(page.locator('body')).toContainText('enable secret 5 <masked:weak>')
    await expect(page.locator('body')).toContainText('snmp-server community <masked:weak> RO')

    const all = await everywhere(page, id, ['E2E-PASTE-01'])
    for (const s of secretsOf('P')) expect(all, `secret ${s} leaked`).not.toContain(s)
    expect(all).toContain('<masked')
  })

  test('a zip is unpacked, non-config entries are skipped, and secrets are masked everywhere', async ({ page }) => {
    const id = await newBlankAudit(page)
    const zip = zipSync({
      'archive/Z1.cfg': strToU8(pasted('E2E-ZIP-01', 'Z')),
      'archive/Z2.cfg': strToU8(pasted('E2E-ZIP-02', 'Y')),
      'archive/logo.png': new Uint8Array([137, 80, 78, 71, 1, 2, 3]),
    })
    await page.locator('input[type=file]').setInputFiles({ name: 'configs.zip', mimeType: 'application/zip', buffer: Buffer.from(zip) })

    const report = page.locator('.panel', { has: page.getByRole('heading', { name: 'Validation report' }) })
    await expect(report).toContainText('E2E-ZIP-01')
    await expect(report).toContainText('E2E-ZIP-02')
    await expect(report).toContainText('Skipped 1 non-text file: archive/logo.png')
    for (const s of [...secretsOf('Z'), ...secretsOf('Y')]) expect(await report.innerText()).not.toContain(s)

    await report.getByRole('button', { name: 'Import 2 devices' }).click()
    await expect(page.getByText('Added 2 devices')).toBeVisible()
    await expect(page.getByText('2 devices · ')).toBeVisible()
    // Same secret-bearing lines in two devices: drift compares them, so the tab has data.
    const all = await everywhere(page, id, ['E2E-ZIP-01', 'E2E-ZIP-02'])
    for (const s of [...secretsOf('Z'), ...secretsOf('Y')]) expect(all, `secret ${s} leaked`).not.toContain(s)
  })

  test('re-importing a device with the same hostname replaces it', async ({ page }) => {
    const id = await newBlankAudit(page)
    for (const [i, tag] of ['One', 'Two'].entries()) {
      await page.goto(`/app/p/${id}/configs`)
      await page.locator('#paste').fill(pasted('E2E-SAME', tag))
      await page.getByRole('button', { name: 'Check', exact: true }).click()
      await expect(page.getByText(i === 0 ? 'New device' : 'Replaces existing device')).toBeVisible()
      await page.getByRole('button', { name: 'Import 1 device' }).click()
      await expect(page.getByText(i === 0 ? 'Added 1 device' : 'replaced 1 device')).toBeVisible()
    }
    await page.goto(`/app/p/${id}/configs`)
    await expect(page.locator('table.tbl tbody tr')).toHaveCount(1)
  })

  test('a pasted config survives a reload with its secrets still masked', async ({ page }) => {
    await newBlankAudit(page)
    await page.locator('#paste').fill(pasted('E2E-KEEP', 'K'))
    await page.getByRole('button', { name: 'Check', exact: true }).click()
    await page.getByRole('button', { name: 'Import 1 device' }).click()
    await expect(deviceScore(page, 'E2E-KEEP')).toBeVisible()
    const score = await deviceScore(page, 'E2E-KEEP').getAttribute('aria-label')
    await page.reload()
    await expect(deviceScore(page, 'E2E-KEEP')).toHaveAttribute('aria-label', score!)
    await page.goto('/app')
    await expect(page.locator('article.project-card')).toContainText('Devices1')
    expect(await dumpStorage(page)).not.toContain('SentinelK')
  })
})

test.describe('bad input never produces a score', () => {
  type Case = { name: string; file: { name: string; mimeType: string; buffer: Buffer }; message: RegExp; toast?: boolean }
  const configText = pasted('E2E-CUT', 'C')
  const cases: Case[] = [
    { name: 'wrong format (plain prose)', file: { name: 'notes.txt', mimeType: 'text/plain', buffer: Buffer.from('hello world\nthis is not a router config\n') }, message: /This does not look like a Cisco running-config/ },
    { name: 'wrong format (JSON without config)', file: { name: 'facts.json', mimeType: 'application/json', buffer: Buffer.from('{"a": 1, "b": [1, 2, 3]}') }, message: /This does not look like a Cisco running-config/ },
    { name: 'binary data', file: { name: 'blob.cfg', mimeType: 'text/plain', buffer: Buffer.from([0, 1, 2, 3, 255, 254, 0, 9, 10, 200]) }, message: /This does not look like a Cisco running-config/ },
    { name: 'empty file', file: { name: 'empty.cfg', mimeType: 'text/plain', buffer: Buffer.alloc(0) }, message: /Nothing that looks like a config was found/, toast: true },
    { name: 'whitespace-only file', file: { name: 'blank.cfg', mimeType: 'text/plain', buffer: Buffer.from('\n  \n\t\n') }, message: /Nothing that looks like a config was found/, toast: true },
    { name: 'corrupt zip', file: { name: 'broken.zip', mimeType: 'application/zip', buffer: Buffer.from('PK\x03\x04 this is not really a zip archive') }, message: /broken\.zip \(could not unzip\)/ },
    { name: 'truncated zip', file: { name: 'cut.zip', mimeType: 'application/zip', buffer: Buffer.from(zipSync({ 'a.cfg': strToU8(configText) })).subarray(0, 60) }, message: /cut\.zip \(could not unzip\)/ },
    { name: 'empty zip', file: { name: 'empty.zip', mimeType: 'application/zip', buffer: Buffer.from(zipSync({})) }, message: /Nothing that looks like a config was found/, toast: true },
  ]
  for (const c of cases) {
    test(c.name, async ({ page }) => {
      const id = await newBlankAudit(page)
      await page.locator('input[type=file]').setInputFiles(c.file)
      await expect(page.getByText(c.message).first()).toBeVisible()
      const report = page.locator('.panel', { has: page.getByRole('heading', { name: 'Validation report' }) })
      await expect(report.getByRole('button', { name: 'Import 0 devices' })).toBeDisabled()
      // Nothing was imported and nothing shows a score.
      await expect(report.getByRole('img')).toHaveCount(0)
      await expect(page.getByText('None yet. Paste or upload a config above')).toBeVisible()
      await page.goto(`/app/p/${id}`)
      await expect(page.getByRole('img', { name: /score/i })).toHaveCount(0)
      await expect(page.getByRole('heading', { name: 'Paste running-config' })).toBeVisible()
    })
  }

  test('the same bad input pasted instead of uploaded is rejected too', async ({ page }) => {
    await newBlankAudit(page)
    await page.locator('#paste').fill('hello world\nthis is not a router config\n')
    await page.getByRole('button', { name: 'Check', exact: true }).click()
    await expect(page.getByText(/This does not look like a Cisco running-config/)).toBeVisible()
    await expect(page.getByText('Skipped', { exact: true })).toBeVisible()
    await expect(page.getByRole('button', { name: 'Import 0 devices' })).toBeDisabled()
  })

  test('a truncated config is flagged before import and nothing is stored until confirmed', async ({ page }) => {
    const id = await newBlankAudit(page)
    const cut = pasted('E2E-CUT', 'C').split('\n').slice(0, 14).join('\n')
    await page.locator('#paste').fill(cut)
    await page.getByRole('button', { name: 'Check', exact: true }).click()
    const report = page.locator('.panel', { has: page.getByRole('heading', { name: 'Validation report' }) })
    await expect(report).toContainText('No final "end" line. The config may be truncated')
    // The validation report itself never shows a score.
    await expect(report.getByRole('img')).toHaveCount(0)
    await page.goto(`/app/p/${id}`)
    await expect(page.getByRole('img', { name: /score/i })).toHaveCount(0)
  })

  test('a CLI pager prompt is reported with its line number', async ({ page }) => {
    await newBlankAudit(page)
    const text = pasted('E2E-MORE', 'M').replace('interface GigabitEthernet0/0', ' --More-- \ninterface GigabitEthernet0/0')
    await page.locator('#paste').fill(text)
    await page.getByRole('button', { name: 'Check', exact: true }).click()
    await expect(page.getByText(/line \d+\s+Pager prompt in the output/)).toBeVisible()
  })
})

test.describe('whole app', () => {
  test('every page renders without page errors or outside requests', async ({ page, blocked, pageErrors }) => {
    const id = await openSampleFleet(page)
    const paths = ['/', '/docs', '/settings', '/app', `/app/p/${id}`, ...['findings', 'acls', 'drift', 'inventory', 'history', 'configs', 'report'].map(t => `/app/p/${id}/${t}`),
      `/app/p/${id}/device/CORE-SW-01`, `/app/p/${id}/device/EDGE-RTR-01`]
    for (const p of paths) {
      await page.goto(p)
      await expect(page.locator('h1').first(), p).toBeVisible()
      await expect(page.locator('.boot'), p).toHaveCount(0)
    }
    // An unknown audit id and an unknown path get their own pages, not a blank screen.
    await page.goto('/app/p/00000000-0000-0000-0000-000000000000')
    await expect(page.getByText('Audit not found')).toBeVisible()
    await page.goto('/no/such/page')
    await expect(page.getByRole('heading', { name: /Invalid input detected/ })).toBeVisible()
    expect(pageErrors).toEqual([])
    // Signed out and without build-time Supabase settings: nothing leaves the page.
    expect(blocked).toEqual([])
  })

  test('the landing demo fixes critical findings live', async ({ page }) => {
    await page.goto('/')
    const demo = page.getByLabel('Live demo on a synthetic branch router')
    const score = () => demo.getByRole('img', { name: /^Hardening score: \d+ out of 100/ }).getAttribute('aria-label')
    const before = await score()
    await demo.getByRole('button', { name: /^Fix \d+ critical$/ }).click()
    await expect(demo.getByText(/^Applied: \d+ critical findings$/)).toBeVisible()
    expect(Number((await score())!.match(/: (\d+) out/)![1])).toBeGreaterThan(Number(before!.match(/: (\d+) out/)![1]))
  })
})
