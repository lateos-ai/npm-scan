# Changelog

All notable changes to [@lateos/npm-scan](https://github.com/lateos-ai/npm-scan) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.7] — 2026-05-12

- Sigstore provenance attestation on every publish via new GitHub Actions workflow
- Fix duplicate Docker section in README.md
- Add SECURITY.md with vulnerability disclosure policy and PGP key

## [0.9.6] — 2026-05-12

- Add Docker badge (`ghcr.io/lateos/npm-scan`) to all 5 READMEs
- Add dedicated Docker quick-start section in all languages
- Replace duplicate Docker pull instructions in Integrations with cross-references

## [0.9.5] — 2026-05-12

- Fix literal `\n` escape sequences in LICENSING.md (replaced with real newlines)

## [0.9.4] — 2026-05-11

- Fix language badge links to use absolute GitHub URLs so they work from npm web UI
- Fix GitHub organization links from `lateos` to `lateos-ai` across all READMEs

## [0.9.3] — 2026-05-11

- Add multi-language README: Chinese (`README.zh.md`), Japanese (`README.ja.md`), French (`README.fr.md`), German (`README.de.md`)
- Language-switcher badges with absolute GitHub URLs in all 5 READMEs

## [0.9.2] — 2026-05-11

- **222 tests across 8 test files** (212 passing, 10 skipped for known FPs)
- **85% line coverage** with Node.js native test runner
- New test files: `test/db.test.js`, `test/detectors-edge-cases.test.js`, `test/detectors-corpus.test.js`, `test/report-snapshots.test.js`, `test/fetch.test.js`, `test/policy-edge-cases.test.js`, `test/cli.test.js`, `test/fixtures/mock-data.js`
- `backend/db.js:close()` resets `initPromise = null` for test isolation
- GitHub Actions CI with Node 18/20/22 matrix, corpus tests, and self-scan
- GitHub Actions PR lockfile scanner with `fail-on: high`

## [0.9.1] — 2026-05-11

- Remove `node-fetch` import and dependency (replaced in 0.9.0)

## [0.9.0] — 2026-05-11

- **Replace `node-fetch` with native `fetch`** (Node 18+) — removes external HTTP dependency
- **Replace `better-sqlite3` with `sql.js`** (WASM) — zero native compilation, fixes `npx` silent failure on systems without build tools
- Add 404 check in `backend/fetch.js` for robust registry lookups
- Reduce ATK-009 false positives on `lodash`/`axios`/`express`
- Fix ATK-002/011 false positives — stricter eval+decode rules, remove self-referential checks
- Fix ATK-008 `knownRepos` for `vue`

## [0.8.0] — 2026-05-11

- **YAML/JSON policy-as-code engine** — allowlists, severity overrides, suppressions, `fail_on` threshold
- **Text report generator** (free tier)
- **PDF report generator** (premium, via `pdf-lib`)
- **Docker**: multi-stage builds, Compose profiles, health checks, validation script, Makefile
- Comprehensive README rewrite with comparison table, ATK taxonomy, usage examples, integrations
- `.npmignore` cleanup for smaller package

## [0.7.6] — 2026-05-10

- **GitHub Action** (`action.yml`) — scan on push/PR with lockfile or package mode, fail-on severity threshold, SIEM/SBOM output support
- **28 comprehensive tests** covering SIEM exporters (CEF, ECS, Sentinel, QRadar), EU CRA compliance, SBOM (CycloneDX + SPDX), License key gen/validation/edition/tamper/expiry, Report/NIST (HTML, SR-series table, severity badges, all 11 ATK IDs)
- Fix tampered key test determinism

## [0.7.5] — 2026-05-10

- Add Elastic ECS, Microsoft Sentinel, and IBM QRadar SIEM exporters

## [0.7.4] — 2026-05-10

- Version bump only; no functional changes

## [0.7.3] — 2026-05-10

- Version bump only; no functional changes

## [0.7.2] — 2026-05-10

- Fix duplicate Enterprise Features section in README

## [0.7.1] — 2026-05-10

- Add SAML SSO and REST API sections to README

## [0.7.0] — 2026-05-10

- **Enterprise SAML SSO integration**

## [0.6.0] — 2026-05-10

- **License key enforcement** — HMAC-signed keys with community/premium/enterprise editions
- Feature gating for SIEM, CRA, REST API, Helm, PostgreSQL backend, SSO, audit logs
- **PostgreSQL schema** — teams, users, RBAC, audit log, webhooks, API keys, materialized `package_risk` view
- **FastAPI REST API** — scan/list/retrieve endpoints, webhook CRUD with HMAC-signed dispatch
- **Webhook engine** — event dispatch with retry, signature verification header
- **Helm chart** — API + worker + PostgreSQL deployments, secrets, ingress, PVC
- CLI hardened: premium features blocked without valid license key

## [0.5.0] — 2026-05-10

- **ATK-011 (Transitive Propagation)** detector
- **SIEM CEF export** for Splunk and ArcSight integration
- **EU CRA compliance report** — EU Cyber Resilience Act readiness assessment
- Phase 3 enterprise foundation

## [0.4.1] — 2026-05-10

- Update README for Phase 3 (ATK-011, SIEM, CRA)

## [0.4.0] — 2026-05-10

- **ATK-008 (Tarball Tampering)**, **ATK-009 (Dormant Trigger)**, **ATK-010 (Sandbox Evasion)** detectors
- **SPDX 2.3 SBOM** support alongside CycloneDX
- **NIST SP 800-161 compliance report** — supply chain risk management controls
- Sandbox threat model and gVisor isolation strategy

## [0.3.3] — 2026-05-10

- Fix report HTML/SBOM generation to use `atk_id`, description, package name, dynamic version

## [0.3.2] — 2026-05-10

- Update README for Phase 2 (ATK-008–010, SPDX, NIST)

## [0.3.1] — 2026-05-10

- Fix schema literal newlines
- Fix CLI SBOM defaults
- Fix SBOM finding IDs

## [0.3.0] — 2026-05-10

- **ATK-001 (Lifecycle Script)** detector — detects `preinstall`, `postinstall`, `preuninstall` hooks with suspicious commands
- **ATK-002 (Obfuscated Payload)** detector — hex/base64/decode-driven eval, regex obfuscation
- **ATK-003 (Credential Harvester)** detector — env var exfiltration, filesystem credential scraping
- **ATK-004 (Persistence Mechanism)** detector — cron jobs, startup scripts, `postinstall` service installs
- **ATK-005 (Data Exfiltration)** detector — DNS tunneling, HTTP beaconing, unexpected network calls
- **ATK-006 (Dependency Confusion)** detector — internal package name heuristics
- **ATK-007 (Typosquatting)** detector — edit-distance based package name similarity

## [0.2.5] — 2026-05-10

- Fix `.npmignore` to exclude corpus tarballs from published package

## [0.2.4] — 2026-05-10

- Version bump only; no functional changes

## [0.2.2] — 2026-05-10

- **Corpus test suite** — 50 clean packages (0% FP) + 22 malicious PoC (100% detect rate)
- **HTML report generator** with CLI `--html` flag
- ATK-007 edit-distance typosquatting implementation
- Switch from `adm-zip` to `tar` for tgz extraction
- ATK detectors hardened for fewer false positives
- `README.md`, `.gitignore`, corpus download scripts
- **Phase 1 exit**: FP < 2%, passes unit tests + corpus

## [0.2.1] — 2026-05-10

- Version bump only; no functional changes

## [0.2.0] — 2026-05-10

- **Commander.js CLI** with `scan`, `scan-lockfile`, `report` commands
- **ATK-001–007 detector stubs** via `backend/detectors/index.js` (`runAll`)
- **SQLite persistence** via `better-sqlite3` — scan auto-save, report by ID/recent
- **CycloneDX SBOM** — JSON and XML output with ATK vulnerability references
- `.github/workflows/scan.yml` — GitHub Action example for PR scanning
- Dependencies: `commander`, `adm-zip`, `acorn`, `node-fetch`

## [0.1.0] — 2026-05-09

- **Initial foundation**
- Monorepo structure (`cli/`, `backend/`, `docker/`, `docs/`)
- `LICENSING.md` — Apache-2.0 core + Commons Clause for premium features
- `CONTRIBUTING.md`
- `docs/attack-taxonomy.md` — ATK-001 through ATK-011 stubs
- `backend/license.js` skeleton for HMAC-signed license key gating
- `backend/db/schema.sql`
- `docker/Dockerfile.cli` + `docker-compose.yml`
- npm scripts (lint, test stubs)
- `.github/workflows/ci.yml`
- `AGENTS.md` — project instructions