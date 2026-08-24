#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
trap 'docker compose -f compose.load.yml down -v --remove-orphans' EXIT
docker compose -f compose.load.yml up --build --abort-on-container-exit --exit-code-from load-test
