# AGENTS.md

## Project
ESM Node.js CLI monorepo for @lateos/npm-scan supply chain scanner.

## Repos
- **GitHub (oss):** `origin` → `https://github.com/lateos-ai/npm-scan.git` — public npm package `@lateos/npm-scan`
- **Premium:** `/Users/leochong/Projects/npm-scan-premium` — private premium feature repo (license-gated features: SIEM, PDF, SSO, etc.)

## Verification
Run `npm test` (222 tests), `npm run test:coverage` (85%+), `npm run lint`, `npm run build`.

## Architecture
- `cli/`: Commander.js entrypoints
- `backend/`: Core logic, detectors (ATK-001 to ATK-011), db/schema.sql
- `backend/detectors/`: 11 ATK detectors + index.js routing
- `backend/siem/`: SIEM exporters (CEF, ECS, Sentinel, QRadar)
- `backend/license.js`: HMAC-signed license key generation/validation
- `backend/db.js`: SQLite via sql.js (WASM, no native deps)
- `backend/fetch.js`: npm registry fetch + tarball extraction
- `backend/report.js`: HTML + text report generation
- `backend/cra.js`: EU CRA compliance report
- `backend/sbom.js`: CycloneDX + SPDX SBOM
- `backend/pdf.js`: PDF report generation (premium)
- `backend/policy.js`: YAML/JSON policy-as-code engine
- `test/`: 222 tests across 8 files (db, detectors-edge-cases, detectors-corpus, report, policy, cli, fetch)
- `test/fixtures/`: Shared mock data for test suites
- `tests/corpus/`: 33 malicious + 50 clean tarballs for integration testing
- `deploy/helm/`: Kubernetes Helm chart (enterprise)
- `docker/`: Multi-arch Docker images (cli, pipeline)

## Publishing
- Bump version: `npm version patch && git push origin main --tags`
- GitHub Actions auto-publishes via `.github/workflows/publish.yml` with Sigstore provenance attestation (on tag push `v*.*.*`)
- Requires `NPM_TOKEN` secret in GitHub repo (granular access token with read-and-publish scope for `@lateos/npm-scan`)
- Manual fallback: `npm publish --access public` (no provenance when publishing locally)
- Remote: `backup` → `/Volumes/Untitled/npm-scan.git` (FAT32 thumb drive)

## Conventions
- ESM modules, Node.js native test runner
- No native deps (sql.js WASM instead of better-sqlite3)
- Node >= 18 required
- License-gated premium: all code public, HMAC-signed `license.js` gates premium features
- Follow project-plan.md phases/ATK taxonomy
- Security vulns reported via GitHub Private Vulnerability Reporting (see `SECURITY.md`)
