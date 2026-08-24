$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    docker compose -f compose.load.yml up --build --abort-on-container-exit --exit-code-from load-test
}
finally {
    docker compose -f compose.load.yml down -v --remove-orphans
    Pop-Location
}
