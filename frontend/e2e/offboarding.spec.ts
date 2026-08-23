import { expect, test } from '@playwright/test'

test('synthetic Alex Morgan offboarding reaches observed VERIFIED evidence', async ({ page }) => {
  await page.goto('/')
  await page.getByLabel('Email').fill('admin@example.test')
  await page.getByLabel('Password').fill('identitymesh-demo-password')
  await page.getByRole('button', { name: /Sign in/ }).click()
  await expect(page.getByRole('heading', { name: 'Identity Assurance Overview' })).toBeVisible()

  await page.getByRole('link', { name: 'Identities' }).click()
  await expect(page.getByRole('heading', { name: 'Identities' })).toBeVisible()
  await expect(page.getByText('legacy.contractor', { exact: true })).toBeVisible()
  await expect(page.getByText('taylor.other', { exact: true }).first()).toBeVisible()

  await page.getByRole('link', { name: 'Connectors' }).click()
  await expect(page.getByRole('heading', { name: 'Connectors' })).toBeVisible()
  await expect(page.getByText('Corporate LDAP')).toBeVisible()

  await page.getByRole('link', { name: 'People' }).click()
  await page.getByRole('link', { name: 'Alex Morgan' }).click()
  await expect(page.getByText('3 known identities')).toBeVisible()

	const created = page.waitForResponse(
		(response) => response.url().endsWith('/api/v1/lifecycle-cases') && response.request().method() === 'POST',
	)
	await page.getByRole('button', { name: 'Create offboarding' }).click()
	const createResponse = await created
	const createBody = await createResponse.text()
	await expect(createResponse.status(), `${createBody}; request headers: ${JSON.stringify(createResponse.request().headers())}`).toBe(201)
	await expect(page).toHaveURL(/\/lifecycle\/[0-9a-f-]+$/)
  await page.getByRole('button', { name: 'Generate plan' }).click()
  await expect(page.getByText('AWAITING APPROVAL')).toBeVisible()
  await page.getByRole('button', { name: 'Approve plan' }).click()
  await page.getByRole('button', { name: 'Execute controlled actions' }).click()

  await expect(page.getByText('VERIFIED')).toBeVisible({ timeout: 30_000 })

  await page.getByRole('link', { name: 'Reports' }).click()
  await expect(page.getByRole('heading', { name: 'Reports', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Generate PDF' }).click()
  const reportLink = page.getByRole('link', { name: 'Download PDF' })
  await expect(reportLink).toBeVisible()
  const reportHref = await reportLink.getAttribute('href')
  expect(reportHref).toBeTruthy()
  const reportResponse = await page.request.get(reportHref!)
  expect(reportResponse.status(), await reportResponse.text()).toBe(200)
  expect(reportResponse.headers()['content-type']).toContain('application/pdf')
  expect(reportResponse.headers()['content-disposition']).toContain('identitymesh-offboarding-')
  expect((await reportResponse.body()).subarray(0, 8).toString()).toBe('%PDF-1.4')

  await page.getByRole('link', { name: 'Evidence' }).click()
  await expect(page.getByRole('heading', { name: 'Evidence' })).toBeVisible()
})
