# npm-scan

Powerful npm supply chain security scanner. Detects malicious packages, supply chain attacks, and generates SBOM + compliance reports.

## Quick Start

```bash
npm install -g @lateos/npm-scan
npm-scan scan lodash
```

Or run without install:

```bash
npx @lateos/npm-scan scan lodash
```

## Features

- **Static Analysis** — detects malicious lifecycle scripts, obfuscated payloads, credential harvesting, persistence, network exfiltration, dependency confusion, typosquatting, tarball tampering, conditional triggers, sandbox evasion, and transitive propagation (ATK-001–011)
- **SBOM Output** — CycloneDX 1.5 and SPDX 2.3 with findings mapped as vulnerabilities
- **NIST 800-161 Compliance** — HTML report includes control traceability matrix (SR-2.1 → SR-11.4)
- **EU CRA Compliance** — report maps findings to Cyber Resilience Act articles and Annex I requirements
- **SIEM Export** — CEF format for Splunk and other SIEM ingestion (premium)
- **EU CRA Compliance** — report maps findings to Cyber Resilience Act articles (premium)
- **License Key Gating** — premium features locked behind signed license keys
- **REST API** — FastAPI-based API with webhooks, auth, scan management (premium)
- **Kubernetes / Helm** — Helm chart for deploying the full pipeline on K8s (premium)
- **SQLite Storage** — local scan history, zero external dependencies
- **CLI** — `scan`, `scan-lockfile`, `report --sbom --html --nist --cra --siem`
- **Dynamic Sandbox** — gVisor-based isolation (premium, documented in `docs/sandbox-threat-model.md`)
- **GitHub Action** — scans lockfile on PRs
- **Docker** — multi-arch images via GHCR

## Commands

```
npm-scan scan <package>              Scan a package from the npm registry
npm-scan scan <package> --sbom       Scan + output CycloneDX SBOM
npm-scan scan <package> --sbom spdx  Scan + output SPDX SBOM
npm-scan scan-lockfile               Scan a local package-lock.json
npm-scan report                      List recent scans
npm-scan report -i <id>              Show findings for a scan
npm-scan report -i <id> --sbom       Generate CycloneDX SBOM
npm-scan report -i <id> --sbom spdx  Generate SPDX SBOM
npm-scan report -i <id> --html       Generate HTML report (with NIST table)
npm-scan report -i <id> --nist       Print NIST 800-161 compliance table
npm-scan report -i <id> --cra        Print EU CRA compliance table
npm-scan report -i <id> --siem cef   Generate SIEM CEF output (premium)
npm-scan report --html               Generate HTML report for all scans
npm-scan report --nist               Print NIST compliance for all scans
npm-scan report --cra                Print EU CRA compliance for all scans (premium)
npm-scan report --siem cef           Generate SIEM for all scans (premium)
```

## Architecture

```
cli/          Commander.js CLI entrypoint
backend/      Detectors, fetch, SQLite db, SBOM, report, license, SIEM, CRA
api/          FastAPI REST API + webhooks (premium)
docker/       Multi-arch Docker images + compose
deploy/       Kubernetes Helm chart (premium)
docs/         Project plan, attack taxonomy (ATK), sandbox threat model
tests/        Corpus: 5 clean + 33 malicious packages
```

## Detectors (ATK Taxonomy)

| ID      | Class                                      | Severity |
|---------|--------------------------------------------|----------|
| ATK-001 | Malicious lifecycle scripts                 | high     |
| ATK-002 | Obfuscated payloads                         | medium   |
| ATK-003 | Credential harvesting                       | high     |
| ATK-004 | Persistence via editor configs              | high     |
| ATK-005 | Network exfiltration                        | critical |
| ATK-006 | Dependency confusion                        | medium   |
| ATK-007 | Typosquatting                               | low      |
| ATK-008 | Tarball tampering (published ≠ source)      | high     |
| ATK-009 | Conditional/dormant triggers (CI, time)     | high     |
| ATK-010 | Sandbox evasion / anti-analysis             | medium   |
| ATK-011 | Transitive propagation (worm)               | high     |
| ATK-011 | Transitive propagation (worm)               | high     |

See `docs/attack-taxonomy.md` for full NIST 800-161 mappings, evasion surfaces, and PoC examples.

## Development

```bash
npm install
npm run dev          # CLI stub
npm run test         # Unit tests (14)
npm run corpus       # False-positive corpus test (33 malicious, 5 clean)
```

## License

Apache-2.0 core + Commons Clause premium. See `LICENSING.md`.
