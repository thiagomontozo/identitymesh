import { expect, test } from '@playwright/test'

test('synthetic Alex Morgan offboarding reaches observed VERIFIED evidence', async ({ page }) => {
  await page.goto('/')
  await page.getByLabel('Email').fill('admin@example.test')
  await page.getByLabel('Password').fill('identitymesh-demo-password')
  await page.getByRole('button', { name: /Sign in/ }).click()
  await expect(page.getByRole('heading', { name: 'Identity Assurance Overview' })).toBeVisible()

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
  await page.getByRole('link', { name: 'Evidence' }).click()
  await expect(page.getByRole('heading', { name: 'Evidence' })).toBeVisible()
})
