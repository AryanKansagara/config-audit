import { expect, newBlankAudit, openSampleFleet, test } from './fixtures'

test('BR-RTR-01 remediation uses distinct SNMP placeholders, clear notes, and simulates cleanly', async ({ page }) => {
  const id = await openSampleFleet(page)
  await page.goto(`/app/p/${id}/device/BR-RTR-01`)
  await expect(page.getByText('After the script')).toBeVisible()
  await page.getByRole('tab', { name: 'Remediation script' }).click()

  const apply = page.locator('.code', { has: page.getByText('Apply', { exact: true }) })
  const rollback = page.locator('.code', { has: page.getByText('Rollback', { exact: true }) })
  const applyText = await apply.innerText()
  const rollbackText = await rollback.innerText()

  expect(applyText).not.toContain('<masked')
  expect(rollbackText).not.toContain('<masked')
  expect(applyText).toContain('no snmp-server community <OLD-COMMUNITY-RO> RO')
  expect(applyText).toContain('no snmp-server community <OLD-COMMUNITY-RW> RW')
  expect(applyText).toContain('snmp-server community <NEW-LONG-RANDOM-COMMUNITY> RO MGMT-SNMP')

  const notes = page.locator('.notes')
  await expect(notes).toContainText('<OLD-COMMUNITY-RO>')
  await expect(notes).toContainText('<OLD-COMMUNITY-RW>')
  await expect(notes).toContainText('<NEW-LONG-RANDOM-COMMUNITY>')
  await expect(page.getByText(/Projected score after applying: 94 \(A\)/)).toBeVisible()
})

test('strong masked SNMP communities and duplicate roles emit fill-in tokens without <masked>', async ({ page }) => {
  const id = await newBlankAudit(page)
  await page.locator('#paste').fill(`hostname SNMP-CHECK
!
snmp-server community StrongRO#123456 RO
snmp-server community StrongRW#123456 RW MGMT
snmp-server host 192.0.2.50 version 2c public
!
ip access-list standard MGMT
 permit 192.0.2.0 0.0.0.255
!
end
`)
  await page.getByRole('button', { name: 'Check', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Validation report' })).toBeVisible()
  await page.getByRole('button', { name: 'Import 1 device' }).click()
  await page.goto(`/app/p/${id}/device/SNMP-CHECK`)
  await page.getByRole('tab', { name: 'Remediation script' }).click()

  const apply = page.locator('.code', { has: page.getByText('Apply', { exact: true }) })
  const rollback = page.locator('.code', { has: page.getByText('Rollback', { exact: true }) })
  const applyText = await apply.innerText()
  const rollbackText = await rollback.innerText()

  expect(applyText).not.toContain('<masked')
  expect(rollbackText).not.toContain('<masked')
  expect(applyText).toContain('snmp-server community <EXISTING-COMMUNITY-RO> RO MGMT-SNMP')
  expect(applyText).toContain('no snmp-server community <EXISTING-COMMUNITY-RW> RW MGMT')
  expect(applyText).toContain('no snmp-server host 192.0.2.50 version 2c <OLD-TRAP-COMMUNITY>')
  await expect(page.locator('.notes')).toContainText('<EXISTING-COMMUNITY-RO>')
  await expect(page.locator('.notes')).toContainText('<OLD-TRAP-COMMUNITY>')
})
