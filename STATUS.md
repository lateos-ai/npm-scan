# STATUS.md

Snapshot of where the project stands. Update this when starting/finishing significant work — don't let it go stale.

_Last updated: 2026-10-15_

## Current state
- **Version:** 1.5.2 (published)
- **Branch:** `800-package-AI-SLOP-campaign`, branched off `fix/slsa-provenance-verification`
- **Tests:** `npm test` (Node native test runner), coverage target 85%+ (`npm run test:coverage`)

## Recent work (most recent first)
- **Coverage expansion for Aug–Oct 2026 campaigns (2026-10-15)** — see [docs/security/coverage-expansion-plan-2026-10.md](docs/security/coverage-expansion-plan-2026-10.md). Three new detectors + four extensions + lockfile validation, derived from keyv/cacheable, GhostAction, MemTensor, PolinRider:
  - **D32-HOST-PERSISTENCE** — user-level LaunchAgent/`systemd --user`/`loginctl enable-linger` + AST-gated dead-man's switch.
  - **D33-INSTALL-CONFIG-ABUSE** — `.pnpmfile.cjs`/`.yarnrc`/`bunfig.toml`/`overrides` (closes gap §5).
  - **TIER1-MANIFEST-CONFUSION** — registry manifest vs tarball `package.json` (closes gap §7).
  - **D30 GhostAction extension** — `shipped_workflow_secret_exfil` with a registry-host allowlist.
  - **infostealer/D22** — new token literals + secret-file recon targets; **c2-deaddrop** — on-chain (EtherHiding/NullReceiver) dead-drop.
  - **Lockfile `resolved`-host + integrity validation** (closes gap §3), allowlist extended via `allow.registries` policy + `scan-lockfile --policy`.
  - **Fixed `lib/prompt-injection.js`** — was dead code (call-signature mismatch) + an infinite-loop hazard (non-global regexes in `while(exec())`); both fixed together, now live.
  - ~65 new tests. Full `test/` suite 789 pass / 0 fail. D32–D34 weights pre-telemetry (Linux corpus re-run pending).
- **Gap-assessment remediation (2026-08-19)** — three new detectors plus the shared libraries they required, closing the runtime-evasion, provenance-desync and workspace-persistence gaps:
  - **D29-RUNTIME-EVASION** (`tier1-runtime-evasion.js`) — Bun/Deno/QuickJS coverage. Headline fix: a Deno-idiom credential stealer that previously scored **zero findings** across the whole pipeline (the byte-identical Node version scored HIGH) now reports critical.
  - **D30-WORKSPACE-PERSISTENCE** (`tier1-workspace-persistence.js`) — `.claude/*`, `.cursor/rules/*`, `.vscode/*`, `.github/workflows/*`, with constant-folded path reconstruction so dynamically assembled paths resolve to the same target as literals. Replaces ATK-004's single `mkdir` regex.
  - **ERR_TARBALL_GIT_DESYNC** (`tier1-tarball-git-desync.js` + `backend/validators/git-diff.js`) — tarball-to-Git differential. **Opt-in, network-bound, off by default.**
  - New shared libs: `lib/ast-parse.js`, `lib/runtime-primitives.js`, `lib/path-resolver.js`, `lib/agent-surfaces.js`.
  - Also fixed a pre-existing SARIF conformance bug affecting **every** tier-1 detector (`message: {}` and an array in `artifactLocation.uri`, neither schema-valid).
  - 111 new tests; 0 findings across 123 real `node_modules` packages; 0.72% pipeline overhead.
- Added **D28-AI-SLOP-DROPPER** (`tier1-ai-slop-dropper.js`) for the "AI Slop"/WEL1DROPPER 800-package campaign: README-directed `require()` entry with no lifecycle hooks, hex/base64 string-array obfuscation, `process.platform`/`arch` fingerprinting scope-coupled to network calls, and DNS TXT out-of-band stage-2 resolution. 24 tests, 0 FPs on the clean corpus, 3.8% worst-case perf cost. See the D28 calibration notes in [AGENTS.md](AGENTS.md).
- Restricted worm-propagation patterns to lifecycle-hook scripts only, to stop false positives on `axios`/`nodemailer` (`6cb62c2`)
- Overrode `brace-expansion` to `5.0.9` to resolve GHSA-mh99-v99m-4gvg (`f4feb21`)
- Supply chain detection gap analysis & implementation — added TIER1-HOOK-FOLLOWTHROUGH, TIER1-VERSION-BACKFILL, TIER1-CRYPTO-TAMPER detectors, extended TIER1-INFOSTEALER and TIER1-MAINTAINER-COMPROMISE, added serverless PaaS domain watchlist (`7063b67` + follow-up lint/formatting fixes)
- Added VINCE (CISA) vulnerability coordination module and `submit-vince` CLI command (v1.5.0)

See [CHANGELOG.md](CHANGELOG.md) for full detail and the `[Unreleased]` section for what hasn't shipped in a version bump yet.

## In progress / open threads
- **D29/D30 weights are pre-telemetry.** Verified against the gap-analysis PoCs and 123 real `node_modules` packages, but *not* against the 50-package clean corpus, because `test/detectors-corpus.test.js` cannot run on Windows (`execSync` hands GNU tar a `C:\…` path it reads as a remote host — 108 failures, 0 assertion failures, pre-existing). **Re-run the corpus suite on Linux before trusting the FP numbers.**
- **D31 needs a real-registry trial.** All tests use an injected `sourceProvider`; the GitHub codeload path has not been exercised against live repositories. Expect calibration work on the generated-file skip list before it can be enabled by default.
- **D28 still parses independently** with its own `acorn.parse` rather than the shared cached `parseSource`. Migrating it would remove one parse per file and inherit the hashbang/modern-syntax fix — D28 remains evadable by an `#!/usr/bin/env bun` line and by a `.ts` rename.
- **`lib/prompt-injection.js` fixed** (was dead code + infinite-loop hazard): signature now matches the `runTier1` call convention so the detector actually runs, and the non-global-regex `while(exec())` loop was replaced with a flag-agnostic `matchAll` generator. Covered by `test/prompt-injection.test.js`.
- **SLSA provenance — shape bug fixed, cryptographic verification still deferred.** `lib/slsa-verifier.js` now reads `dist.attestations` as the object-shaped pointer it is and does structural verification only (attestation exists, binds the served tarball digest, self-consistent build claims); `verified` is deliberately always `false` and grants no trust discount. Remaining: real Sigstore bundle-signature + Fulcio chain + Rekor inclusion verification. Note the keyv/cacheable worm *mints its own valid provenance*, so provenance must never suppress findings — D31 remains the only tarball-to-source trust anchor.
- **Install-time surfaces + lockfile validation — closed (2026-10).** D33 covers `.pnpmfile.cjs`/`.yarnrc.yml`/`bunfig.toml`/`overrides` (gap §5); D30 covers MCP/agent hook configs (gap §6); `analyzeResolutionIntegrity` covers lockfile `resolved` hosts + missing `integrity` (gap §3).
- D6a (version-anomaly) heuristic is a known FP-risk area pending production scan telemetry
- D24/D25 (Bun runtime swap / split payload) pattern weights need tuning once broader scan telemetry is available

## Where to look for more context
- [AGENTS.md](AGENTS.md) — architecture, detector registry, conventions
- [docs/project-plan.md](docs/project-plan.md) — phases, licensing model, ATK taxonomy roadmap
- [DECISION.md](DECISION.md) — standing architectural/product decisions
