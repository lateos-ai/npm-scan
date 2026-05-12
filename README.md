# @lateos/npm-scan

[![npm version](https://img.shields.io/npm/v/@lateos/npm-scan?style=flat-square)](https://www.npmjs.com/package/@lateos/npm-scan)
[![License](https://img.shields.io/badge/license-Apache%202.0%20%2B%20Commons%20Clause-blue?style=flat-square)](LICENSING.md)
[![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen?style=flat-square)](package.json)
[![Tests](https://img.shields.io/badge/tests-222%20passing-brightgreen?style=flat-square)](https://github.com/lateos-ai/npm-scan)
[![Coverage](https://img.shields.io/badge/coverage-85%25-yellowgreen?style=flat-square)](https://github.com/lateos-ai/npm-scan)
[![Docker](https://img.shields.io/badge/docker-ghcr.io%2Flateos%2Fnpm--scan-2496ED?style=flat-square&logo=docker)](https://github.com/lateos-ai/npm-scan/pkgs/container/npm-scan)

[![中文](https://img.shields.io/badge/lang-zh--CN-red?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.zh.md)
[![日本語](https://img.shields.io/badge/lang-ja-purple?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.ja.md)
[![Français](https://img.shields.io/badge/lang-fr-orange?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.fr.md)
[![Deutsch](https://img.shields.io/badge/lang-de-green?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.de.md)

**Modern supply chain security for the npm ecosystem.**
Static + behavioral analysis that catches what npm audit, Snyk, and Socket miss — obfuscated payloads, credential stealers, conditional triggers, sandbox evasion, and worm-like propagation.

---

## 📌 The Problem

The 2025–2026 wave of npm supply chain attacks proved that traditional tooling is no longer enough.

Attackers have moved past simple typosquatting. They now ship **obfuscated preinstall hooks**, **credential harvesters hidden behind environment detection**, **dormant backdoors with time-based activation**, and **worm-style transitive propagation** that spreads through peer dependencies.

**npm audit** checks known CVEs. **Snyk** scans for vulnerabilities. **Socket** looks at package behavior. None of them were designed for the generation of attacks that emerged in 2025 — attacks that look benign until they reach production.

**@lateos/npm-scan** was built for this moment.

---

## 🔬 Why @lateos/npm-scan?

| Capability | npm audit | Snyk | Socket | **@lateos/npm-scan** |
|---|---|---|---|---|
| Known CVE matching | ✅ | ✅ | ❌ | ✅ |
| Static analysis | ❌ | ✅ | ✅ | ✅ |
| Obfuscated payload detection | ❌ | ❌ | ❌ | ✅ |
| Behavioral / heuristic analysis | ❌ | ❌ | Partial | ✅ |
| Conditional trigger detection (ATK-009) | ❌ | ❌ | ❌ | ✅ |
| Sandbox evasion detection (ATK-010) | ❌ | ❌ | ❌ | ✅ |
| Transitive worm propagation (ATK-011) | ❌ | ❌ | ❌ | ✅ |
| Attack taxonomy (ATK series) | ❌ | ❌ | ❌ | ✅ |
| SBOM output (CycloneDX + SPDX) | ❌ | ✅ | ❌ | ✅ |
| NIST 800-161 compliance reporting | ❌ | ❌ | ❌ | ✅ |
| EU CRA compliance reporting | ❌ | ❌ | ❌ | ✅ |
| SIEM export (CEF / ECS / Sentinel / QRadar) | ❌ | ❌ | ❌ | ✅ |
| Runs entirely locally — no telemetry | ✅ | ❌ | ❌ | ✅ |
| Policy-as-code (YAML allowlists) | ❌ | ❌ | ❌ | ✅ |

> **Privacy first.** All scanning happens on your machine. No code leaves your environment. No telemetry. No cloud dependency.

---

## ✨ Key Features

| Icon | Feature | Description |
|------|---------|-------------|
| 🕵️ | **Heuristic static analysis** | AST-level inspection catches obfuscation, eval chains, env probing, and suspicious lifecycle scripts that regex-based tools miss |
| 🧠 | **Behavioral detection** | Identifies conditional triggers (time-based, CI-aware), sandbox evasion, and dormant activation patterns |
| 🧬 | **ATK attack taxonomy** | 11 classified attack types with NIST 800-161 mappings — versioned, documented, and PR-able |
| 📦 | **SBOM generation** | CycloneDX 1.5 and SPDX 2.3 with findings embedded as vulnerabilities |
| 🧾 | **Compliance reporting** | NIST SP 800-161 traceability matrix + EU Cyber Resilience Act mapping (free tier) |
| 🔌 | **SIEM export** | Splunk CEF, Elastic ECS, Microsoft Sentinel, IBM QRadar formats (premium) |
| 📜 | **Policy-as-code** | YAML/JSON policy engine with allowlists, severity overrides, suppressions, and fail-on thresholds |
| 🐳 | **Docker + GitHub Action** | Multi-arch images, one-command Compose pipeline, PR scan action |
| 🛡️ | **Zero telemetry** | No data leaves your machine. No cloud. No callbacks. |
| 💾 | **Local scan history** | SQLite-backed persistence, zero external dependencies |

---

## ⚡ Quick Start

```bash
# Install globally
npm install -g @lateos/npm-scan

# Scan a single package
npm-scan scan lodash

# Scan your lockfile
npm-scan scan-lockfile

# View latest scans
npm-scan report
```

**No install? No problem:**

```bash
npx @lateos/npm-scan scan commander
```

---

## 🐳 Run @lateos/npm-scan anywhere with Docker — zero installation

```bash
# Pull and run a single scan — no Node.js or npm required
docker run --rm ghcr.io/lateos/npm-scan:cli scan lodash

# Full pipeline with persistent storage and Compose
docker compose --profile pipeline up -d
```

No Node.js. No `npm install`. No global packages. Works on any system with Docker — CI servers, air-gapped environments, Kubernetes clusters. Multi-arch images for `linux/amd64` and `linux/arm64`.

---

## 🐳 Run @lateos/npm-scan anywhere with Docker — zero installation

```bash
# Pull and run a single scan — no Node.js or npm required
docker run --rm ghcr.io/lateos/npm-scan:cli scan lodash

# Full pipeline with persistent storage and Compose
docker compose --profile pipeline up -d
```

No Node.js. No `npm install`. No global packages. Works on any system with Docker — CI servers, air-gapped environments, Kubernetes clusters. Multi-arch images for `linux/amd64` and `linux/arm64`.

---

## 📖 Usage Examples

### Scan a single package

```bash
# Default JSON output with all findings
npm-scan scan axios

# Generate an SBOM alongside the scan
npm-scan scan express --sbom             # CycloneDX JSON
npm-scan scan express --sbom xml         # CycloneDX XML
npm-scan scan express --sbom spdx        # SPDX 2.3

# Apply a YAML policy
npm-scan scan some-package --policy .npm-scan.yml
```

### Scan a lockfile

```bash
# Scan the current project's dependencies
npm-scan scan-lockfile

# Scan a specific lockfile
npm-scan scan-lockfile -f ./path/to/package-lock.json
```

### Generate reports

```bash
# List all recent scans
npm-scan report

# View a specific scan
npm-scan report -i 42

# Generate an HTML report (free) with full findings + NIST table
npm-scan report -i 42 --html

# Print NIST 800-161 compliance table
npm-scan report -i 42 --nist

# Print EU CRA compliance table
npm-scan report --cra

# Text report (free)
npm-scan report --text

# PDF report (premium)
npm-scan report --pdf --license-key <key>

# SIEM export (premium)
npm-scan report --siem cef        # Splunk CEF
npm-scan report --siem ecs        # Elastic ECS
npm-scan report --siem sentinel   # Microsoft Sentinel
npm-scan report --siem qradar     # IBM QRadar

# Combine all scans into a single report
npm-scan report --html            # all scans
npm-scan report --pdf             # all scans (premium)
```

---

## 🧬 Detection Capabilities (ATK Taxonomy)

| ID | Attack Class | Detection Method | Severity | NIST 800-161 |
|---|---|---|---|---|
| **ATK-001** | Malicious lifecycle scripts (`preinstall`, `postinstall`, `install`) | Static | 🔴 high | SR-3.1 |
| **ATK-002** | Obfuscated payload delivery (hex, base64, eval chains) | Static | 🟠 medium | SR-4.2 |
| **ATK-003** | Credential harvesting (env vars, .npmrc, SSH keys) | Static + Dynamic | 🔴 high | SR-5.3 |
| **ATK-004** | Persistence via editor/config dirs (.vscode, .claude, .cursor) | Static | 🔴 high | SR-6.4 |
| **ATK-005** | Network exfiltration (GitHub API, DNS tunneling, HTTP C2) | Static + Dynamic | ⚫ critical | SR-7.5 |
| **ATK-006** | Dependency confusion / namespace squatting | Static (lockfile) | 🟠 medium | SR-2.2 |
| **ATK-007** | Typosquatting (edit-distance matching) | Static | 🟢 low | SR-2.1 |
| **ATK-008** | Tarball tampering (published ≠ source) | Static | 🔴 high | SR-8.1 |
| **ATK-009** | Conditional/dormant triggers (CI detection, time-based) | Behavioral | 🔴 high | SR-9.2 |
| **ATK-010** | Sandbox evasion / anti-analysis | Behavioral | 🟠 medium | SR-10.3 |
| **ATK-011** | Transitive propagation (worm-style lateral spread) | Behavioral | 🔴 high | SR-11.4 |

> **How evasive attacks are caught:** ATK-009 detects packages that check `process.env.CI`, probe hostnames, or use time-based activation. ATK-010 flags `debugger` statements, `os.hostname()` probes, and env fingerprinting. ATK-011 traces peer dependency graphs to detect worm-like propagation patterns.  
> See [`docs/attack-taxonomy.md`](docs/attack-taxonomy.md) for full evasion surface documentation and PoC examples.

---

## 📊 Output & Reports

### Formats

| Format | Availability | Description |
|--------|-------------|-------------|
| JSON | ✅ Free | Structured machine-readable findings |
| HTML | ✅ Free | Rich HTML report with NIST compliance table, severity badges, control matrix |
| Text | ✅ Free | Clean terminal-friendly text report |
| CycloneDX SBOM | ✅ Free | Industry-standard SBOM with findings as vulnerabilities |
| SPDX SBOM | ✅ Free | SPDX 2.3 document format |
| NIST 800-161 | ✅ Free | Control traceability matrix (SR-2.1 → SR-11.4) |
| EU CRA | ✅ Free | Cyber Resilience Act article mapping |
| PDF | 🔐 Premium | Multi-page PDF with title page, findings table, NIST compliance matrix |
| Splunk CEF | 🔐 Premium | Common Event Format for Splunk ingestion |
| Elastic ECS | 🔐 Premium | Elastic Common Schema format |
| Microsoft Sentinel | 🔐 Premium | Sentinel-ready formatted output |
| IBM QRadar | 🔐 Premium | QRadar DSM-ready format with QID mappings |

### Sample output

```json
{
  "scanId": 1,
  "findings": [
    {
      "id": "ATK-003",
      "severity": "high",
      "title": "Credential harvesting",
      "evidence": "process.env.NPM_TOKEN detected in postinstall.js:17"
    }
  ]
}
```

---

## ⚙️ Configuration & Advanced Usage

### Policy-as-code

Define allowlists, severity overrides, suppressions, and fail thresholds in a YAML file:

```yaml
# .npm-scan.yml
allowlist:
  - lodash
  - chalk

severity_overrides:
  - id: ATK-001
    severity: medium

suppress:
  - atk_id: ATK-009
  - package: some-package

fail_on: high
```

```bash
npm-scan scan target --policy .npm-scan.yml
```

### Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NPM_SCAN_LICENSE_KEY` | Premium / enterprise license key | — |
| `NPM_SCAN_DATA_DIR` | Scan history directory | `./.npm-scan` |
| `NPM_SCAN_LOG_LEVEL` | Log verbosity | `info` |

### Premium licensing

```bash
# Generate a development key
node -e "console.log(require('@lateos/npm-scan/backend/license').generateKey('premium'))"

# Use it
npm-scan scan target --license-key <key>
npm-scan report --pdf --license-key <key>
npm-scan report --siem cef --license-key <key>
```

---

## 🔗 Integrations

### GitHub Actions CI (for this repo)

Every push and PR runs tests across Node 18, 20, and 22:

```yaml
# .github/workflows/ci.yml
name: CI
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        node-version: [18, 20, 22]
    steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-node@v4
      with:
        node-version: ${{ matrix.node-version }}
        cache: 'npm'
    - run: npm ci
    - run: npm test
    - run: npm run test:coverage
    - run: node --test test/detectors-corpus.test.js
    - run: npm run lint
    - run: npm run build
```

### GitHub Action (for downstream users)

Scan your project's `package-lock.json` on every PR — detects typosquats, obfuscated payloads, credential harvesters, and worm propagation before they reach production:

```yaml
# .github/workflows/scan.yml
name: npm-scan
on:
  pull_request:
    paths:
      - 'package-lock.json'
      - '**/package.json'
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-node@v4
      with:
        node-version: 20
    - name: Scan lockfile
      uses: lateos/npm-scan@main
      with:
        scan-type: lockfile
        fail-on: high
```

#### Action inputs

| Input | Default | Description |
|-------|---------|-------------|
| `scan-type` | `lockfile` | `lockfile` to scan `package-lock.json` or `package` to scan a specific npm package |
| `package` | — | Package name (required when `scan-type=package`) |
| `fail-on` | `high` | Fail the workflow at this severity threshold: `none`, `low`, `medium`, `high`, `critical` |
| `policy-file` | — | Path to a YAML/JSON policy file for allowlists, severity overrides, and suppressions |
| `license-key` | — | Premium license key for SIEM export and PDF reports |
| `siem-format` | — | SIEM output: `cef`, `ecs`, `sentinel`, `qradar` (premium) |
| `sbom-format` | — | SBOM output: `json`, `xml`, `spdx` |

#### Action outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Number of findings detected |
| `scan-id` | Scan ID for later reference in reports |

#### Example: scan a specific package with policy + SBOM

```yaml
- uses: lateos/npm-scan@main
  with:
    scan-type: package
    package: lodash
    policy-file: .npm-scan.yml
    sbom-format: spdx
    fail-on: critical
```

#### Example: scan with SIEM export (premium)

```yaml
- uses: lateos/npm-scan@main
  with:
    scan-type: lockfile
    siem-format: cef
    license-key: ${{ secrets.NPM_SCAN_LICENSE_KEY }}
```

### CI/CD pipeline

Integrate directly into your existing pipeline without the composite action:

```bash
# Scan lockfile, fail build on high severity
npm-scan scan-lockfile --policy .npm-scan.yml || exit 1

# Scan a specific package, fail on critical only
npm-scan scan lodash --policy .npm-scan.yml || exit 1

# Generate SBOM as a build artifact
npm-scan scan express --sbom spdx > express-sbom.spdx.json

# Generate HTML compliance report in CI
npm-scan report --html > report.html

# Upload report as an artifact
# uses: actions/upload-artifact@v4
#   with:
#     name: npm-scan-report
#     path: report.html
```

### Docker

See the [Docker quick-start section](#-run-lateosnpm-scan-anywhere-with-docker--zero-installation) above for pull commands, Compose pipeline, and multi-arch images.

Scan your project's `package-lock.json` on every PR — detects typosquats, obfuscated payloads, credential harvesters, and worm propagation before they reach production:

```yaml
# .github/workflows/scan.yml
name: npm-scan
on:
  pull_request:
    paths:
      - 'package-lock.json'
      - '**/package.json'
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-node@v4
      with:
        node-version: 20
    - name: Scan lockfile
      uses: lateos/npm-scan@main
      with:
        scan-type: lockfile
        fail-on: high
```

#### Action inputs

| Input | Default | Description |
|-------|---------|-------------|
| `scan-type` | `lockfile` | `lockfile` to scan `package-lock.json` or `package` to scan a specific npm package |
| `package` | — | Package name (required when `scan-type=package`) |
| `fail-on` | `high` | Fail the workflow at this severity threshold: `none`, `low`, `medium`, `high`, `critical` |
| `policy-file` | — | Path to a YAML/JSON policy file for allowlists, severity overrides, and suppressions |
| `license-key` | — | Premium license key for SIEM export and PDF reports |
| `siem-format` | — | SIEM output: `cef`, `ecs`, `sentinel`, `qradar` (premium) |
| `sbom-format` | — | SBOM output: `json`, `xml`, `spdx` |

#### Action outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Number of findings detected |
| `scan-id` | Scan ID for later reference in reports |

#### Example: scan a specific package with policy + SBOM

```yaml
- uses: lateos/npm-scan@main
  with:
    scan-type: package
    package: lodash
    policy-file: .npm-scan.yml
    sbom-format: spdx
    fail-on: critical
```

#### Example: scan with SIEM export (premium)

```yaml
- uses: lateos/npm-scan@main
  with:
    scan-type: lockfile
    siem-format: cef
    license-key: ${{ secrets.NPM_SCAN_LICENSE_KEY }}
```

### CI/CD pipeline

Integrate directly into your existing pipeline without the composite action:

```bash
# Scan lockfile, fail build on high severity
npm-scan scan-lockfile --policy .npm-scan.yml || exit 1

# Scan a specific package, fail on critical only
npm-scan scan lodash --policy .npm-scan.yml || exit 1

# Generate SBOM as a build artifact
npm-scan scan express --sbom spdx > express-sbom.spdx.json

# Generate HTML compliance report in CI
npm-scan report --html > report.html

# Upload report as an artifact
# uses: actions/upload-artifact@v4
#   with:
#     name: npm-scan-report
#     path: report.html
```

### Docker

See the [Docker quick-start section](#-run-lateosnpm-scan-anywhere-with-docker--zero-installation) above for pull commands, Compose pipeline, and multi-arch images.

---

## 🗺️ Roadmap & Enterprise Features

### Free tier (shipped)

- All 11 ATK detectors (static + behavioral)
- SBOM output (CycloneDX + SPDX)
- HTML, text, and compliance reports (NIST + EU CRA)
- Policy-as-code engine (YAML)
- Local SQLite scan history
- GitHub Action
- Docker images + Compose pipeline

### Premium (🔐 license key)

- PDF compliance reports with NIST traceability matrix
- SIEM export (Splunk CEF, Elastic ECS, Microsoft Sentinel, IBM QRadar)
- Dynamic sandbox (gVisor-based — ATK-008–010)
- Reachability analysis (call graph filtering)

### Enterprise (🏢 custom license)

- SAML 2.0 SSO (Okta, Azure AD, OneLogin, Keycloak)
- REST API + webhooks (FastAPI)
- Team RBAC + audit logs
- Helm chart for Kubernetes deployment
- PostgreSQL backend for hosted/team tier
- SLA-backed priority support

---

## 🤝 Contributing

We welcome contributions — especially new detectors, improved evasion resistance, and compliance templates.

See [`docs/attack-taxonomy.md`](docs/attack-taxonomy.md) for the ATK governance process. Every new detector requires:

1. A proof-of-concept sample
2. A detection rule with tests
3. False-positive analysis on top-500 npm packages
4. NIST 800-161 control mapping

### Testing

The project uses the **Node.js native test runner** (`node:test` + `assert/strict`).

```bash
# Run all tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests with verbose spec output
npm run test:verbose

# Run local malicious/clean corpus (no network needed)
node --test test/detectors-corpus.test.js
```

**Test structure:**
- `test/fixtures/mock-data.js` — shared mock scans, packages, and code snippets
- `test/db.test.js` — database CRUD (save, query, persist)
- `test/detectors-edge-cases.test.js` — per-detector boundary tests (no-ops, clean clears, severity)
- `test/detectors-corpus.test.js` — 33 malicious + 50 clean tarball integration (offline)
- `test/fetch.test.js` — tarball extraction, temp directory cleanup
- `test/policy-edge-cases.test.js` — edge cases in suppress, override, load validation
- `test/report-snapshots.test.js` — HTML/text/CRA/PDF format assertions
- `test/cli.test.js` — commander integration tests (help, version, scan, report, error handling)

### Need help?

- 📖 Read the [project plan](docs/project-plan.md)
- 🧬 Review the [attack taxonomy](docs/attack-taxonomy.md)
- 🐛 Open an issue or PR

---

## 📄 License

Apache-2.0 core + Commons Clause.  
See [`LICENSING.md`](LICENSING.md) for the exact boundary between free and premium features.

```
@lateos/npm-scan — npm supply chain security scanner
Copyright (C) 2026 Lateos

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
```

---

**Scan your first package now:**

```bash
npx @lateos/npm-scan scan lodash
```
