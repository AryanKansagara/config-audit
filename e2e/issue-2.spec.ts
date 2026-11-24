import { expect, newBlankAudit, test } from './fixtures'

const TRUNCATED = `!
hostname CORE-SW-01
service password-encryption
no service pad
logging buffered 64000 informational
logging host 10.0.50.20
aaa new-model
aaa authentication login default group tacacs+ local
ip domain name core.example.net
no ip source-route
!`

const COMPLETE = `Building configuration...
!
hostname COMPLETE-RTR
!
enable algorithm-type scrypt secret $9$abcdefghijklmn$opqrstuvwxyz
username netadmin privilege 15 algorithm-type scrypt secret $9$1234567890abcd$efghijklmnopqr
service password-encryption
no ip source-route
ip ssh version 2
line vty 0 4
 transport input ssh
 exec-timeout 10 0
 login local
!
end
`

test('incomplete device is excluded from fleet score, shows Incomplete badge, and can be confirmed persistently', async ({ page }) => {
  const id = await newBlankAudit(page)
  await page.locator('#paste').fill(`${COMPLETE}\n${TRUNCATED}`)
  await page.getByRole('button', { name: 'Check', exact: true }).click()
  await expect(page.getByText('Incomplete', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Import 2 devices' }).click()
  await expect(page).toHaveURL(new RegExp(`/app/p/${id}$`))

  // Overview: 1 score ring for COMPLETE-RTR + 1 for Fleet score (= COMPLETE-RTR's score), CORE-SW-01 marked Incomplete.
  await expect(page.getByText(/1 incomplete excluded from score/)).toBeVisible()
  await expect(page.getByText('Not graded · excluded from fleet score')).toBeVisible()
  const ringsBefore = await page.getByRole('img', { name: /score/i }).count()
  expect(ringsBefore).toBe(2)

  const fleetLabelBefore = await page.getByRole('img', { name: /Fleet score:/ }).getAttribute('aria-label')
  const completeLabel = await page.getByRole('img', { name: /COMPLETE-RTR score:/ }).getAttribute('aria-label')
  expect(fleetLabelBefore?.match(/\d+ out of 100/)?.[0]).toBe(completeLabel?.match(/\d+ out of 100/)?.[0])

  // Confirm completeness on the Device page and verify it persists across reload.
  await page.getByRole('link', { name: /CORE-SW-01/ }).first().click()
  await expect(page.getByRole('img', { name: /CORE-SW-01 score/i })).toHaveCount(0)
  await expect(page.getByRole('img', { name: /Projected score/i })).toHaveCount(0)
  await expect(page.getByRole('img', { name: /Fleet score:/ })).toHaveCount(1)
  await page.getByRole('button', { name: 'Confirm config is complete' }).click()
  await expect(page.getByText('Confirmed complete')).toBeVisible()
  await expect(page.getByRole('img', { name: /CORE-SW-01 score:/ })).toBeVisible()

  await page.reload()
  await expect(page.getByText('Confirmed complete')).toBeVisible()
  await page.goto(`/app/p/${id}`)
  await expect(page.getByRole('img', { name: /score/i })).toHaveCount(3)
  await expect(page.getByText('Confirmed complete')).toBeVisible()
  await page.goto(`/app/p/${id}/report`)
  await expect(page.getByText('Confirmed complete').first()).toBeVisible()
})

test('confirming completeness during import stores the choice and grades immediately', async ({ page }) => {
  const id = await newBlankAudit(page)
  await page.locator('#paste').fill(TRUNCATED)
  await page.getByRole('button', { name: 'Check', exact: true }).click()
  await page.getByLabel(/Confirm this config is complete/).check()
  await expect(page.getByText('Confirmed complete')).toBeVisible()
  await page.getByRole('button', { name: 'Import 1 device' }).click()
  await expect(page).toHaveURL(new RegExp(`/app/p/${id}$`))
  await expect(page.getByRole('img', { name: /Fleet score:/ })).toBeVisible()
  await expect(page.getByText('Confirmed complete')).toBeVisible()
})

test('NX-OS and ASA configs without end are graded normally and not flagged incomplete', async ({ page }) => {
  const id = await newBlankAudit(page)
  const nxos = `!Command: show running-config
feature ssh
hostname NX-EDGE
line vty
 exec-timeout 10
`
  await page.locator('#paste').fill(nxos)
  await page.getByRole('button', { name: 'Check', exact: true }).click()
  const report = page.locator('.panel', { has: page.getByRole('heading', { name: 'Validation report' }) })
  await expect(report).not.toContainText('may be truncated')
  await page.getByRole('button', { name: 'Import 1 device' }).click()
  await expect(page).toHaveURL(new RegExp(`/app/p/${id}$`))
  await expect(page.getByRole('img', { name: /NX-EDGE score:/ })).toBeVisible()
  await expect(page.getByText('Incomplete')).toHaveCount(0)
})
