import { dumpStorage, expect, newBlankAudit, openSampleFleet, test } from './fixtures'

// Each test states the behaviour that is wanted. While the bug exists it is marked as an expected failure
// (test.fail, set only after all setup steps worked, so a broken selector is still a real failure). Once the
// bug is fixed the marker switches itself off and the test is an ordinary regression test.
const knownBug = (broken: boolean, issue: number) => test.fail(broken, `https://github.com/AryanKansagara/config-audit/issues/${issue}`)

const importIfPossible = async (page: import('@playwright/test').Page) => {
  const button = page.getByRole('button', { name: /^Import \d+ devices?$/ })
  if (!(await button.isEnabled())) return
  await button.click()
  await expect(page.getByText(/^(Added|replaced) \d+ devices?/)).toBeVisible()
}

test('a truncated config is not imported with a grade', async ({ page }) => {
  const id = await newBlankAudit(page)
  // First 30 lines of the synthetic CORE-SW-01 sample: no interfaces, ACLs, SNMP or lines, and no final "end".
  const fragment = `!
hostname CORE-SW-01
service password-encryption
no service pad
logging buffered 64000 informational
logging host 10.0.50.20
aaa new-model
aaa authentication login default group tacacs+ local
aaa authentication enable default group tacacs+ enable
aaa authorization exec default group tacacs+ local if-authenticated
ip domain name core.example.net
no ip source-route
login block-for 120 attempts 5 within 60
!
`
  await page.locator('#paste').fill(fragment)
  await page.getByRole('button', { name: 'Check', exact: true }).click()
  await expect(page.getByText(/may be truncated/)).toBeVisible()
  await importIfPossible(page)
  await page.goto(`/app/p/${id}`)
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
  const graded = await page.getByRole('img', { name: /score/i }).count()
  knownBug(graded > 0, 2)
  expect(graded, 'a truncated config was imported and given a score').toBe(0)
  await expect(page.getByText('Incomplete', { exact: true }).first()).toBeVisible()
})

test('secrets from vtp, server-private, isis, nhrp, rsvp and ldp commands are not stored', async ({ page }) => {
  await newBlankAudit(page)
  await page.locator('#paste').fill(`Building configuration...
!
hostname E2E-LEAK
!
vtp password LEAKvtp
!
aaa group server tacacs+ TAC
 server-private 192.0.2.4 key LEAKprivate
!
interface GigabitEthernet0/0
 ip address 192.0.2.2 255.255.255.0
 isis password LEAKisis
 ip nhrp authentication LEAKnhrp
 ip rsvp authentication key LEAKrsvp
!
mpls ldp neighbor 192.0.2.9 password LEAKldp
!
end
`)
  await page.getByRole('button', { name: 'Check', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Validation report' })).toBeVisible()
  await importIfPossible(page)
  const secrets = ['LEAKvtp', 'LEAKprivate', 'LEAKisis', 'LEAKnhrp', 'LEAKrsvp', 'LEAKldp']
  const stored = await dumpStorage(page)
  const body = await page.locator('body').innerText()
  const leaked = secrets.some(s => stored.includes(s) || body.includes(s))
  knownBug(leaked, 4)
  for (const s of secrets) {
    expect(stored).not.toContain(s)
    expect(body).not.toContain(s)
  }
})

test('the remediation script never contains a masked placeholder where a real value is needed', async ({ page }) => {
  const id = await openSampleFleet(page)
  await page.goto(`/app/p/${id}/device/BR-RTR-01`)
  await page.getByRole('tab', { name: 'Remediation script' }).click()
  const apply = page.locator('.code', { has: page.getByText('Apply', { exact: true }) })
  const rollback = page.locator('.code', { has: page.getByText('Rollback', { exact: true }) })
  await expect(apply).toContainText('configure terminal')
  await expect(rollback).toContainText('configure terminal')
  const placeholder = (await apply.innerText()).includes('<masked') || (await rollback.innerText()).includes('<masked')
  knownBug(placeholder, 3)
  expect(placeholder, 'the Apply or Rollback script contains <masked...> as a command argument').toBe(false)
})
