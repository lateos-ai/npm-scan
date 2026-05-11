#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/.."

COMPOSE="docker compose -f docker/docker-compose.yml"

echo "=== Docker Compose Validation ==="

echo "[1] Config syntax check..."
$COMPOSE config --quiet
echo "    PASS: config valid"

echo "[2] Build CLI image..."
docker build -f docker/Dockerfile.cli -t npm-scan:local .
echo "    PASS: CLI image built"

echo "[3] Smoke-test CLI container (--help)..."
docker run --rm --entrypoint node npm-scan:local cli/cli.js --help | grep -q "npm-scan"
echo "    PASS: --help works"

echo "[4] Smoke-test scan with a clean package..."
RESULT=$(docker run --rm --entrypoint node npm-scan:local cli/cli.js scan lodash 2>/dev/null || true)
echo "$RESULT" | grep -q "scanId"
echo "    PASS: scan lodash works"

echo "[5] Validate compose config..."
$COMPOSE config --quiet
echo "    PASS: compose config valid"

echo ""
echo "=== All docker tests passed ==="
