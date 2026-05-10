# Project Plan: npm-scan
## Enhanced Open-Core npm Supply Chain Security Scanner
### (Successor to / Evolution of Package-Inferno)

**Date:** May 2026
**Version:** 1.1
**Author:** Lateos (lateos.ai)

---

## 1. Project Vision & Objectives

Build a best-in-class, developer-friendly npm supply chain security tool that detects sophisticated attacks like Mini Shai-Hulud (and future variants) through behavioral, static, and hybrid analysis.

### Core Goals

- Detect malicious patterns: preinstall hooks, obfuscation, credential harvesting, persistence via `.claude`/`.vscode`, GitHub exfiltration, and emerging variants
- Provide enterprise-grade compliance reporting and SIEM integrations
- Follow open-core model: generous free tier + gated premium features
- Distribute as both npm CLI and Docker images
- Be easy to run locally, in CI, and at scale

### Differentiation

Hybrid analysis + a formal, versioned attack taxonomy + a strong compliance/SIEM story + excellent UX.

---

## 2. Attack Taxonomy (ATK Series) — The Moat

Before writing detection code, publish and maintain a versioned **npm Attack Taxonomy (ATK)**. This is modeled on the IPI taxonomy pattern and serves as the anchor for all detector development, contributor PRs, and marketing claims.

Each entry defines: attack class, detection surface (static/dynamic/both), evasion surface, and mapping to NIST 800-161 controls.

| ID | Class | Detection Surface | Status |
|----|-------|-------------------|--------|
| ATK-001 | Malicious lifecycle scripts (`preinstall`, `postinstall`, `install`) | Static | Phase 1 |
| ATK-002 | Obfuscated payload delivery (hex encoding, base64, `eval`) | Static | Phase 1 |
| ATK-003 | Credential harvesting (env var scraping, `.npmrc`, SSH key access) | Static + Dynamic | Phase 1 |
| ATK-004 | Persistence via editor/tool config dirs (`.vscode`, `.claude`, `.cursor`) | Static | Phase 1 |
| ATK-005 | Network exfiltration (GitHub API, DNS tunneling, HTTP POST to C2) | Static + Dynamic | Phase 1 |
| ATK-006 | Dependency confusion / namespace squatting | Static (lockfile) | Phase 1 |
| ATK-007 | Typosquatting (edit-distance matching against top-N packages) | Static | Phase 1 |
| ATK-008 | Tarball tampering (published tarball ≠ source repo) | Static (diff) | Phase 2 |
| ATK-009 | Conditional/dormant triggers (CI env detection, time-based activation) | Dynamic | Phase 2 |
| ATK-010 | Sandbox evasion detection (anti-analysis behaviors) | Dynamic | Phase 2 |
| ATK-011 | Transitive supply chain propagation (worm-style lateral spread) | Dynamic | Phase 3 |

> **Governance:** ATK entries are versioned. New entries require a PR with: proof-of-concept sample, detection rule, false positive analysis, and NIST 800-161 control mapping. The taxonomy is published at `docs/attack-taxonomy.md` and referenced in all scan reports.

---

## 3. Licensing — Decided Before the First PR

Licensing boundaries must be defined in `LICENSING.md` before accepting any external contributions.

### Model: Apache-2.0 core + Commons Clause premium

- **Core (Apache-2.0):** Static analysis engine, ATK-001–007 detectors, CLI, lockfile scanner, SBOM output (CycloneDX), GitHub Action, Docker images, JSON output, SQLite-backed local storage, basic HTML report.
- **Premium (Apache-2.0 + Commons Clause):** Dynamic sandbox (ATK-008+), advanced compliance reports (PDF, regulatory templates), SIEM connectors, reachability analysis, team dashboard, SSO, audit logs, API/webhooks, on-prem/air-gapped licenses, priority support.

> **Why Commons Clause over BSL:** Commons Clause is lighter-weight, avoids the community friction HashiCorp and Elasticsearch created with BSL transitions, and the boundary ("you may not sell this software as a service") is unambiguous. BSL is a fallback only if legal counsel recommends it.

### Feature Flags

Premium features are gated by a license key validated at runtime. The key system skeleton ships in Phase 0. Keys are issued per-seat for CLI, per-org for hosted.

---

## 4. Core Requirements

### Free / Open-Source Tier

- Static analysis (ATK-001–007): obfuscation, credential patterns, lifecycle scripts, YARA
- CLI: `scan`, `scan-lockfile`, `report` commands
- Docker-based full pipeline (Enumerator → Fetcher → Analyzer → Dashboard)
- SBOM output: CycloneDX (Phase 1), SPDX (Phase 2)
- Basic HTML report (Phase 1); PDF report is premium (Phase 2)
- GitHub Action
- Policy-as-code engine (YAML config, free)
- SQLite for local/CLI mode — zero external dependencies

### Premium Features (license key or hosted SaaS)

- Dynamic sandbox / hybrid analysis (ATK-008–011, safe hook execution with syscall monitoring)
- Advanced compliance reports (PDF/HTML, regulatory mapping: NIST 800-161, EU CRA, SOC 2, ISO 27001, DORA)
- Reachability analysis (parse call graphs, surface only reachable findings)
- Full SIEM connectors (Splunk TA, Microsoft Sentinel Solution, Elastic integration, QRadar)
- Team dashboard, SSO, audit logs, high-scale orchestration
- Priority support and on-prem/air-gapped licenses
- OPA/Rego policy engine (YAML for free tier)
- PostgreSQL backend (team/hosted tier)

> **Note on ML-assisted false-positive reduction:** Explicitly deferred until real scan telemetry exists. Will not appear in roadmap until Phase 4+ with data to justify it.

---

## 5. Tech Stack

| Layer | Technology | Notes |
|-------|------------|-------|
| CLI | Node.js + Commander.js | Global `npm install -g npm-scan` |
| Enumerator / Fetcher | Node.js | Extends Package-Inferno structure |
| Analyzer (static) | Node.js + Python 3.12+ | YARA via `yara-python` |
| Dynamic Sandbox | gVisor (runsc) | See §6.1 — not vm2/isolated-vm |
| Local storage (free) | SQLite | Zero-setup, file-based |
| Team/hosted storage | PostgreSQL | SaaS and enterprise tier only |
| Dashboard | Streamlit (MVP stub) | FastAPI + React when first enterprise customer requires it |
| SBOM | cyclonedx-node + cyclonedx-python | CycloneDX 1.5 |
| Reports (free) | Jinja2 → HTML | PDF is premium |
| Reports (premium) | Jinja2 → WeasyPrint → PDF | With NIST 800-161 templates |
| Policy Engine (free) | YAML | Shipped in core |
| Policy Engine (premium) | OPA/Rego | Full enterprise policy-as-code |
| Containerization | Docker + Docker Compose + GHCR | Multi-arch images |
| Observability | OpenTelemetry + structured JSON logging | Opt-in telemetry only |
| Licensing | Feature flags via license key validation | Skeleton in Phase 0 |

---

## 6. Architecture

```
CLI Layer (npm-scan command)
    ↓ lightweight mode (static-only, SQLite, no Docker required)
    ↓ full mode (delegates to Docker Compose pipeline)

Docker Compose Pipeline:
  [enumerator] → [Redis queue] → [fetcher] → [analyzer-static]
                                                    ↓
                                          [analyzer-sandbox]  ← premium, gVisor
                                                    ↓
                                          [report-generator]
                                                    ↓
                                    [api-service (FastAPI)] + [streamlit-dashboard]

Storage:
  SQLite (local / free tier)
  PostgreSQL (team / hosted tier)
  S3-compatible (tarball cache, optional)

Output Formats:
  JSON (structured findings, machine-readable)
  CycloneDX SBOM (Phase 1) + SPDX (Phase 2)
  HTML report (free)
  PDF report with regulatory mappings (premium)
  SIEM formats: OCSF, CEF, ECS (premium, Phase 3)
```

### 6.1 Dynamic Sandbox Architecture — Security-First

> The sandbox executes malicious code by design. One escape on a user's machine destroys the tool's reputation. This section is non-negotiable.

**Selected isolation stack: gVisor (runsc)**

- Kernel-level syscall interception without a full VM — Docker-compatible, production-hardened
- Firecracker microVMs as an optional upgrade for highest-assurance environments
- **Explicitly not used:** vm2 (repeated escapes), isolated-vm (Node-based, insufficient for hostile payloads)

**Sandbox threat model (required before Phase 2 ships):**

| Threat | Mitigation |
|--------|------------|
| Syscall escape | gVisor intercepts all syscalls at the gVisor kernel boundary |
| Network exfiltration during analysis | Network namespace isolation; egress blocked except to monitored sink |
| Filesystem escape | Read-only bind mounts; package extracted to ephemeral tmpfs |
| Resource exhaustion (CPU/memory bomb) | cgroup limits: 1 CPU, 512MB RAM, 30s timeout |
| Sandbox detection by malware | Randomized env vars, realistic process tree, no obvious sandbox markers |
| Tarball extraction bomb | Size limits enforced before extraction (uncompressed cap: 500MB) |

**Anti-sandbox-evasion (ATK-010):** The analyzer checks for behaviors that indicate the package probes its environment before acting (hostname checks, `CI` env var detection, timing attacks). Detection of evasion attempts is itself a high-severity finding.

---

## 7. Adversarial Posture

npm-scan is a security tool that will be actively studied by the people it's designed to catch. The plan explicitly addresses this.

### Evasion Resistance

- YARA rules and behavioral signatures are versioned and updated on a defined cadence
- ATK taxonomy includes known evasion techniques per detector (documented in `docs/attack-taxonomy.md`)
- Obfuscation detection uses AST-level analysis, not regex — resistant to trivial reformatting
- Conditional trigger detection (ATK-009) specifically targets code that behaves differently in sandbox vs. production

### Supply Chain Integrity of npm-scan Itself

> npm-scan must not be a supply chain attack vector.

- All releases signed with `npm provenance` (Sigstore) from day one
- npm-scan's own `package.json` is scanned by npm-scan in CI (self-attestation)
- Lockfile committed and integrity-checked in CI
- SBOM generated and published with every release
- Dependency update PRs gated on passing scan results

### Known Evasion Vectors (documented, not hidden)

The `docs/evasion-known.md` file catalogues known evasion techniques so contributors know what to harden against. Transparency about limitations builds trust; hiding them does not.

---

## 8. Compliance Strategy — NIST 800-161 First

> Attempting to map five frameworks simultaneously produces five shallow implementations. One framework done properly is worth more than five done poorly.

### Phase 2: NIST SP 800-161r1 (Cybersecurity Supply Chain Risk Management)

**Why NIST 800-161 first:**
- Supply-chain-specific (directly relevant to the tool's purpose)
- Maps to CMMC Level 2 — existing domain expertise from SecureStack/DockerShield work
- US government and defense contractor buyers have budget and mandate
- NIST → FedRAMP → CMMC creates a coherent enterprise sales story

**Phase 2 deliverable:** A compliance report template that maps each npm-scan finding to the relevant NIST 800-161 practice (SR-series controls). PDF output with finding → control traceability matrix.

### Phase 3+: Additional Frameworks (in order)

1. EU Cyber Resilience Act (CRA) — EU enterprise buyers
2. SOC 2 Type II (CC6.x supply chain controls) — SaaS buyers
3. ISO 27001:2022 (A.15 supplier relationships) — global enterprise
4. DORA — financial sector EU buyers

Each framework addition is a versioned template, not a rewrite of the report engine.

---

## 9. Phased Roadmap

### Phase 0: Foundation (Week 1)

**Exit criteria:** npm name claimed, repo structured, licensing documented, license key skeleton wired, Docker images published.

- [ ] Claim `npm-scan` on npm (publish stub immediately)
- [ ] Fork/rename Package-Inferno repo → monorepo structure (`/cli`, `/backend`, `/docker`, `/docs`)
- [ ] Write `LICENSING.md` — define Apache-2.0 + Commons Clause boundary explicitly
- [ ] Write `docs/attack-taxonomy.md` — ATK-001–007 initial entries with NIST 800-161 mappings
- [ ] License key feature-flag skeleton (runtime validation, graceful degradation)
- [ ] SQLite schema for local mode (replaces PostgreSQL for free tier)
- [ ] `CONTRIBUTING.md` referencing ATK taxonomy governance process
- [ ] Initial Docker images published to GHCR (multi-arch)
- [ ] Basic CI/CD pipeline (GitHub Actions): lint, test, image build

### Phase 1: MVP — Production Ready Scanner (Weeks 2–4)

**Exit criteria:** Static scanner runs on any package in <30s; false positive rate <2% on top-500 npm packages; GitHub Action published; SBOM output validated.

**Priority sequence:**

1. **GitHub Action first** — highest-leverage distribution channel
2. **ATK-001–007 static detectors** hardened against Shai-Hulud patterns
3. **CLI:** `npm-scan scan <package>`, `npm-scan scan-lockfile`, `npm-scan report`
4. **SQLite-backed scan history** for local users (no external dependencies)
5. **CycloneDX SBOM output** with findings embedded as vulnerabilities
6. **Basic HTML report** (Jinja2 template; PDF deferred to Phase 2)
7. **YAML policy engine** (allowlists, severity overrides, block-on-severity)
8. **Docker Compose improvements** — one-command start, health checks
9. **Test corpus:** 50+ clean packages + 20+ malicious samples including Shai-Hulud variants

**Not in Phase 1:** PDF reports, PostgreSQL, sandbox, ML.

### Phase 2: Hybrid Analysis & Compliance (Weeks 5–7)

**Exit criteria:** Sandbox threat model documented and reviewed; NIST 800-161 report template covers SR-series controls; dynamic analysis catches ATK-008/009 patterns.

- Dynamic sandbox service (gVisor-based) — full threat model shipped before first user
- ATK-008–010 behavioral detectors
- NIST 800-161r1 compliance report template (PDF via WeasyPrint)
- SPDX SBOM output (complement to CycloneDX)
- Reachability analysis (lockfile call graph parsing — surfaces only reachable findings)
- Dashboard: "Compliance" tab with NIST control mapping
- ATK taxonomy updated with sandbox-derived evasion findings
- Self-scan of npm-scan in CI using sandbox tier

### Phase 3: Enterprise & Integrations (Weeks 8–11)

**Exit criteria:** At least one Splunkbase listing live; one paying customer.

- SIEM exporters: Splunk TA, Microsoft Sentinel Solution, Elastic integration, QRadar
- FastAPI-based REST API + webhooks
- Team features: multi-user, RBAC, audit logs
- Feature-flag enforcement (license key hard gating)
- EU CRA compliance report template
- PostgreSQL backend for hosted/team tier
- Kubernetes / Helm chart
- Publish to Splunkbase + Azure Marketplace (content packs)
- ATK-011 transitive propagation detector

### Phase 4: Polish & Scale (Ongoing)

- VS Code extension (surfaces findings inline)
- SOC 2 + ISO 27001 compliance templates
- DORA template (financial sector)
- Hosted SaaS option with usage-based billing
- Opt-in telemetry (aggregate false positive rates feed detector improvement)
- Marketing site + pricing page
- ML-assisted scoring — **only after telemetry data justifies it**

---

## 10. Distribution & Packaging

| Channel | Details |
|---------|---------|
| npm (`npm-scan`) | Global CLI + lightweight static-only mode |
| Docker images (GHCR) | Focused images per service + all-in-one + Compose file |
| GitHub Releases | Binaries via `pkg` for offline/air-gapped use |
| GitHub Action | `lateos/npm-scan-action` — Phase 1 priority |
| Splunkbase | Splunk TA for SIEM integration — Phase 3 |
| Azure Marketplace | Sentinel Solution content pack — Phase 3 |

---

## 11. Success Metrics — Operational, Not Vanity

Lagging indicators (stars, press) are tracked but not used for go/no-go decisions. Leading indicators drive phase gates:

| Metric | Target | Phase Gate |
|--------|--------|------------|
| False positive rate on top-500 npm packages | < 2% | Phase 1 exit |
| Static scan time (average package) | < 30 seconds | Phase 1 exit |
| Dynamic scan time (average package) | < 5 minutes | Phase 2 exit |
| ATK taxonomy entries with passing detector tests | 100% | Every phase |
| NIST 800-161 control coverage in compliance report | SR-series complete | Phase 2 exit |
| Paying customers | ≥ 1 | Phase 3 exit |
| Splunkbase listing live | Yes/No | Phase 3 exit |
| npm-scan self-scan passing in CI | Always green | Ongoing |

---

## 12. Risks & Mitigations

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| Sandbox escape damages user environment | Low but catastrophic | gVisor isolation; full threat model before Phase 2 ships; security advisory process |
| False positives erode trust | Medium | Strict test corpus; allowlist support; reachability analysis reduces noise |
| Maintenance burden | High (solo) | Modular design; ATK taxonomy governance keeps contributions structured |
| Legal / license friction | Low | Commons Clause is cleaner than BSL; `LICENSING.md` published Day 1 |
| npm registry rate limiting | Medium | Exponential backoff + S3 tarball cache |
| Adversarial evasion of detectors | High (over time) | ATK taxonomy documents evasion surface; AST-level analysis over regex; evasion findings = high severity |
| npm-scan itself becomes a target | Medium | Sigstore provenance; self-scan in CI; SBOM published with every release |
| Feature scope creep (ML, etc.) | High | ML explicitly gated behind telemetry prerequisite; roadmap is sequential not parallel |

---

## 13. Deliverables Per Phase

Each phase ships:

- Working code + Docker Compose (validated one-command start)
- Comprehensive README with real examples
- Test corpus additions (clean + malicious packages)
- Updated `docs/attack-taxonomy.md`
- CI/CD pipeline passing (including self-scan for Phase 2+)
- `CHANGELOG.md` entry referencing ATK IDs addressed

---

## 14. Immediate Next Steps (Phase 0, Day 1)

Ordered by dependency and leverage:

1. `npm publish npm-scan` — claim the name before someone else does
2. Write `LICENSING.md` — unblocks external contributions
3. Write `docs/attack-taxonomy.md` — ATK-001–007, NIST mappings — unblocks detector PRs
4. Wire license key skeleton — unblocks premium feature development
5. SQLite schema for local mode — removes PostgreSQL dependency from free tier
6. Monorepo structure (`/cli`, `/backend`, `/docker`, `/docs`)
7. Initial Docker images to GHCR
8. GitHub Action stub — distribution channel, even before full detection logic

---

*This document is the canonical project plan for npm-scan v1.x. Changes require updating both this document and the affected ATK taxonomy entries.*
