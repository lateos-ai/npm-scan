# npm-scan

Powerful npm supply chain security scanner. Detects malicious packages, supply chain attacks, and generates SBOM reports.

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

- **Static Analysis** — detects malicious lifecycle scripts, obfuscated payloads, credential harvesting, persistence, network exfiltration, dependency confusion, and typosquatting (ATK-001–007)
- **SBOM Output** — CycloneDX 1.5 JSON/XML with findings mapped as vulnerabilities
- **SQLite Storage** — local scan history, zero external dependencies
- **CLI** — `scan`, `scan-lockfile`, `report --sbom`
- **GitHub Action** — scans lockfile on PRs
- **Docker** — multi-arch images via GHCR

## Commands

```
npm-scan scan <package>            Scan a package from the npm registry
npm-scan scan-lockfile             Scan a local package-lock.json
npm-scan report                    List recent scans
npm-scan report -i <id>            Show findings for a scan
npm-scan report -i <id> --sbom     Generate CycloneDX SBOM (json/xml)
```

## Architecture

```
cli/          Commander.js CLI entrypoint
backend/      Detectors, fetch, SQLite db, SBOM, license
docker/       Multi-arch Docker images + compose
docs/         Project plan, attack taxonomy (ATK)
tests/        Corpus: clean + malicious packages
```

## Development

```bash
npm install
npm run dev          # CLI stub
npm run test         # Unit tests
npm run corpus       # False-positive corpus test
```

## Detectors (ATK Taxonomy)

| ID | Class | Severity |
|----|-------|----------|
| ATK-001 | Malicious lifecycle scripts | high |
| ATK-002 | Obfuscated payloads | medium |
| ATK-003 | Credential harvesting | high |
| ATK-004 | Persistence via editor configs | high |
| ATK-005 | Network exfiltration | critical |
| ATK-006 | Dependency confusion | medium |
| ATK-007 | Typosquatting | low |

See `docs/attack-taxonomy.md` for full NIST 800-161 mappings.

## License

Apache-2.0 core + Commons Clause premium. See `LICENSING.md`.