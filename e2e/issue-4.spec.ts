import { dumpStorage, expect, newBlankAudit, test } from './fixtures'

test('unrecognised secret-like command is masked in report, blocked from import, and absent from storage', async ({ page }) => {
  await newBlankAudit(page)
  await page.locator('#paste').fill([
    'Building configuration...',
    'hostname BLOCK-RTR',
    'custom-daemon auth-key LEAKunrec123',
    'end',
  ].join('\n'))
  await page.getByRole('button', { name: 'Check', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Validation report' })).toBeVisible()
  await expect(page.getByText(/Possible secret the masker did not recognise/)).toBeVisible()
  await expect(page.getByText('Skipped')).toBeVisible()
  await expect(page.getByRole('button', { name: /^Import 0 devices$/ })).toBeDisabled()
  const body = await page.locator('body').innerText()
  expect(body).not.toContain('LEAKunrec123')
  expect(await dumpStorage(page)).not.toContain('LEAKunrec123')
})

test('Ansible JSON, flexible whitespace, quoted NX-OS keys and continuations mask before storage', async ({ page }) => {
  const id = await newBlankAudit(page)
  const payload = JSON.stringify({
    ansible_facts: {
      ansible_net_hostname: 'ANS-GW',
      ansible_net_config: [
        'hostname ANS-GW',
        'username   bob   algorithm-type   scrypt   secret   LEAKws',
        'tacacs-server host 192.0.2.4 key 7 "LEAKquote"',
        'username cont \\',
        '  secret LEAKcont',
        'end',
      ].join('\n'),
    },
  })
  await page.locator('#paste').fill(payload)
  await page.getByRole('button', { name: 'Check', exact: true }).click()
  await page.getByRole('button', { name: 'Import 1 device' }).click()
  await expect(page).toHaveURL(new RegExp(`/app/p/${id}$`))
  const stored = await dumpStorage(page)
  expect(stored).not.toContain('LEAK')
})

test('legacy stored project with unmasked config is not deleted, masks on view/export, and offers in-place cleanup', async ({ page }) => {
  const id = '00000000-0000-4000-8000-000000000044'
  await page.goto('/app')
  await page.evaluate(async pid => {
    const project = {
      id: pid,
      name: 'Legacy unmasked audit',
      createdAt: 1700000000000,
      updatedAt: 1700000000000,
      devices: [{
        id: 'dev-1',
        hostname: 'OLD-RTR',
        platform: 'ios',
        source: 'old.cfg',
        importedAt: 1700000000000,
        lines: 4,
        secrets: [],
        issues: [{ line: 2, level: 'warn', message: 'Possible secret the masker did not recognise: "vtp password LEAKlegacy ...". Check before sharing.' }],
      }],
      settings: { execTimeout: 10, vtyAcl: 'MGMT-VTY', snmpAcl: 'MGMT-SNMP', mgmtNets: ['10.0.0.0/24'], banner: 'Authorized access only', ntpServers: [], syslogHosts: [], aaaMethod: 'local' },
      waivers: {},
      snapshots: [{
        id: 'snap-1',
        label: 'Old snap',
        at: 1700000000000,
        score: 70,
        devices: [{ host: 'OLD-RTR', platform: 'ios', score: 70, findings: [{ key: 'k1', rule: 'SNMP-01', severity: 'high', title: 't', target: 'snmp-server community LEAKsnap RO' }] }],
        configs: { 'OLD-RTR': 'hostname OLD-RTR\nvtp password LEAKlegacy\nend\n' },
      }],
    }
    await new Promise<void>((resolve, reject) => {
      const req = indexedDB.open('config-audit', 1)
      req.onupgradeneeded = () => {
        if (!req.result.objectStoreNames.contains('projects')) req.result.createObjectStore('projects', { keyPath: 'id' })
        if (!req.result.objectStoreNames.contains('data')) req.result.createObjectStore('data')
      }
      req.onsuccess = () => {
        const tx = req.result.transaction(['projects', 'data'], 'readwrite')
        tx.objectStore('projects').put(project)
        tx.objectStore('data').put({ 'dev-1': 'hostname OLD-RTR\nvtp password LEAKlegacy\nend\n' }, pid)
        tx.oncomplete = () => resolve()
        tx.onerror = () => reject(tx.error)
      }
      req.onerror = () => reject(req.error)
    })
  }, id)
  await page.reload()

  await page.goto(`/app/p/${id}`)
  await expect(page.getByRole('heading', { name: 'Legacy unmasked audit' })).toBeVisible()
  await expect(page.getByText(/contains unmasked values from an earlier import/i)).toBeVisible()
  await expect(page.locator('body')).not.toContainText('LEAKlegacy')

  // Mask stored copy updates IndexedDB cleanly without deleting the project or device.
  await page.getByRole('button', { name: 'Mask stored copy' }).click()
  await expect(page.getByText('Masked stored configs and snapshots')).toBeVisible()
  await expect(page.getByText(/contains unmasked values from an earlier import/i)).toHaveCount(0)
  expect(await dumpStorage(page)).not.toContain('LEAKlegacy')
  await page.getByRole('link', { name: 'OLD-RTR' }).click()
  await expect(page.getByText('vtp password <masked:weak>')).toBeVisible()
})
