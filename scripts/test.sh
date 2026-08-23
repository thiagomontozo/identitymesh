#!/usr/bin/env sh
set -eu
go test ./backend/...
(cd frontend && npm ci && npm test && npm run build)
