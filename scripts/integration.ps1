$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
docker compose -f compose.test.yml up -d --build --wait
try {
  $env:IDENTITYMESH_TEST_DATABASE_URL='postgres://identitymesh:identitymesh-test-only@localhost:55432/identitymesh_test?sslmode=disable'
  $env:IDENTITYMESH_TEST_SCIM_URL='http://localhost:18090/scim/v2'
  $env:IDENTITYMESH_TEST_SCIM_B_URL='http://localhost:18091/scim/v2'
  $env:IDENTITYMESH_TEST_LDAP_URL='ldap://localhost:1389'
  go test -tags=integration -count=1 -p=1 ./backend/...
} finally { docker compose -f compose.test.yml down -v --remove-orphans }
