$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$env:IDENTITYMESH_BOOTSTRAP_ADMIN_PASSWORD = 'identitymesh-demo-password'
docker compose --profile demo up -d --build --wait
try {
  Get-Content test/fixtures/demo.sql | docker compose exec -T postgres psql -U identitymesh -d identitymesh
  Push-Location frontend
  try {
    npm ci
    npx playwright install chromium
    npm exec playwright test -- --config=playwright.config.ts
  } finally { Pop-Location }
} finally { docker compose --profile demo down -v --remove-orphans }
