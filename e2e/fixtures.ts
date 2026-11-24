import { expect, test as base, type Page } from '@playwright/test'

/**
 * Every test gets a fresh browser context (empty IndexedDB and localStorage), signed out.
 * Requests to anything but the preview server are blocked (aborted) and recorded; the Google Fonts
 * stylesheet the page links to is stubbed with an empty one. Page errors are recorded.
 * Both lists must be empty when the test ends.
 */
export const test = base.extend<{ blocked: string[]; pageErrors: string[] }>({
  blocked: [async ({ context, baseURL }, use) => {
    const blocked: string[] = []
    const origin = new URL(baseURL!).origin
    await context.route('**/*', route => {
      const url = route.request().url()
      if (url.startsWith(origin) || url.startsWith('data:') || url.startsWith('blob:')) return route.continue()
      if (/^https:\/\/fonts\.googleapis\.com\//.test(url)) return route.fulfill({ status: 200, contentType: 'text/css', body: '' })
      blocked.push(url)
      return route.abort('blockedbyclient')
    })
    await use(blocked)
    expect(blocked, 'external requests were attempted').toEqual([])
  }, { auto: true }],
  pageErrors: [async ({ page }, use) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(String(e)))
    await use(errors)
    expect(errors, 'uncaught page errors').toEqual([])
  }, { auto: true }],
})

export { expect }

/** Opens the synthetic three-device fleet from the workspace and returns the project id. */
export async function openSampleFleet(page: Page): Promise<string> {
  await page.goto('/app')
  await page.getByRole('button', { name: 'Open the sample fleet' }).click()
  await expect(page.getByRole('heading', { level: 1, name: /Three-device fleet/ })).toBeVisible()
  const id = page.url().match(/\/app\/p\/([\w-]+)/)?.[1]
  expect(id).toBeTruthy()
  return id!
}

export async function fleetScore(page: Page): Promise<number> {
  const label = await page.getByRole('img', { name: /^Fleet score: \d+ out of 100/ }).getAttribute('aria-label')
  return Number(label!.match(/Fleet score: (\d+)/)![1])
}

/** Everything the app stored in this browser: IndexedDB stores and localStorage, as one string. */
export async function dumpStorage(page: Page): Promise<string> {
  return page.evaluate(async () => {
    const db = await new Promise<IDBDatabase>((res, rej) => { const r = indexedDB.open('config-audit'); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error) })
    const out: unknown[] = []
    for (const name of Array.from(db.objectStoreNames)) {
      const rows = await new Promise<unknown[]>((res, rej) => { const r = db.transaction(name).objectStore(name).getAll(); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error) })
      out.push({ [name]: rows })
    }
    db.close()
    return JSON.stringify({ idb: out, local: { ...localStorage }, session: { ...sessionStorage } })
  })
}

/** Reads a Playwright download as text. */
export async function downloadText(page: Page, click: () => Promise<void>): Promise<{ name: string; text: string }> {
  const [dl] = await Promise.all([page.waitForEvent('download'), click()])
  const path = await dl.path()
  const { readFileSync } = await import('node:fs')
  return { name: dl.suggestedFilename(), text: readFileSync(path, 'utf8') }
}

/** Starts an empty audit from the workspace and returns its id; the page is left on its Configs tab. */
export async function newBlankAudit(page: Page): Promise<string> {
  await page.goto('/app')
  await page.getByRole('button', { name: 'Import configs' }).click()
  await expect(page.getByRole('heading', { name: 'Paste running-config' })).toBeVisible()
  return page.url().match(/\/app\/p\/([\w-]+)/)![1]
}
