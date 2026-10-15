# Changelog

All notable changes to [@lateos/npm-scan](https://github.com/lateos-ai/npm-scan) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Coverage expansion for Aug–Oct 2026 campaigns** — see [docs/security/coverage-expansion-plan-2026-10.md](docs/security/coverage-expansion-plan-2026-10.md). Three new detectors and four extensions, derived from the keyv/cacheable Shai-Hulud variant, GhostAction, MemTensor, and PolinRider.
- **D32-HOST-PERSISTENCE** (`tier1-host-persistence.js`): user-level host persistence + dead-man's switch. Closes the keyv/cacheable gap that `msh-supplement/d2` and `axios-poisoning/d3` (system units only) left open. Detects `~/Library/LaunchAgents/*` with `RunAtLoad`/`KeepAlive`, `~/.config/systemd/user`/`systemctl --user`, `loginctl enable-linger`, and a credential-validity poll whose revocation branch (`HTTP 4xx`/expiry) `eval`s a variable-supplied handler. The dead-man switch is AST-gated so `eval("literal")` never fires. Block ≥ 80, warn ≥ 60; a finding requires an anchor.
- **D33-INSTALL-CONFIG-ABUSE** (`tier1-install-config-abuse.js`): install-time execution outside `package.json` scripts (gap-analysis-2026-08 §5). `.pnpmfile.cjs` `readPackage` hooks that reach outside the package, `.yarnrc(.yml)` plugins loading from an off-package location, `bunfig.toml` `[preload]`/`trustedDependencies`, and `overrides`/`resolutions` that resolve a dependency off-registry (`git+ssh`/`ssh`/`http`/`file`/`link`). Content-gated: a benign monorepo `.pnpmfile.cjs` scores nothing.
- **TIER1-MANIFEST-CONFUSION** (`tier1-manifest-confusion.js`): registry version manifest vs tarball `package.json`. Diffs `dependencies`/`optionalDependencies`/`peerDependencies`/`scripts`/`bin` after stripping registry-injected fields; a lifecycle hook present only in the tarball is always critical. Operates on data the pipeline already holds (`registryMeta` + `pkgJson`).
- **GhostAction workflow secret-exfil** (extension to D30 `tier1-workspace-persistence.js`): shipped `.github/workflows/*.yml` is now analysed for content, not just trigger type. A new `shipped_workflow_secret_exfil` signal (critical) fires when bound secrets (`${{ secrets.* }}`) reach a raw-IP/non-allowlisted destination, or when `fetch-depth: 0` + a git-history credential grep co-occurs. Publishing to a known registry host is allowlisted and stays a plain shipped-workflow signal.
- **New credential literals** (extensions to `tier1-infostealer.js` and `tier1-ai-token-targeting.js`): `github_pat_` (fine-grained), `sk-ant-`/`sk-proj-`/`sk-or-`, `xox[baprs]-` (Slack), `AIza` (Google), `SG.` (SendGrid), plus secret-file recon targets `.vault-token`, `access_tokens.json`, `stored_tokens`, `id_ecdsa`, `/run/secrets/` (GhostAction / MemTensor).
- **On-chain dead-drop detection** (extension to `msh-supplement/d4-c2-deaddrop.js`): EtherHiding/NullReceiver-class C2 resolution via `eth_call`/`eth_getStorageAt` against an RPC provider or contract address (PolinRider). High-level `ethers.js` reads (e.g. `getBalance`) are not flagged.
- **MemTensor cross-platform binary set** verified against `tier1-binary-embed.js` (D4): the `.sckit/<os>-<arch>/<name>` extensionless layout is grouped as a cross-platform set via basename grouping; locked in with a new `test/tier1-binary-embed.test.js`.
- **Lockfile `resolved`-host + integrity validation** (gap-analysis-2026-08 §3, `backend/lockfile.js`): lockfile `resolved` URLs were parsed for all three formats and then discarded. `analyzeResolutionIntegrity` now flags dependencies resolving over cleartext `http` or `git+ssh`/`ssh` (high), a local `file:` path or an unexpected registry host (medium), and entries that resolve a tarball with no `integrity` hash (medium). The trusted-host allowlist defaults to the public npm/yarn registries and treats public git forges as expected; it is extended per-deployment via a new `allow.registries` policy field, surfaced through a new `scan-lockfile --policy` option.

- **~50 new tests** across `test/tier1-host-persistence.test.js`, `test/tier1-install-config-abuse.test.js`, `test/tier1-manifest-confusion.test.js`, `test/tier1-binary-embed.test.js`, `test/tier1-infostealer-credentials.test.js`, plus added cases to `test/tier1-workspace-persistence.test.js`, `test/tier1-ai-token-targeting.test.js`, `test/msh-supplement.test.js`, and `test/lockfile.test.js`.

### Changed
- **Thresholds**: added `D32-HOST-PERSISTENCE`, `D33-INSTALL-CONFIG-ABUSE`, `TIER1-MANIFEST-CONFUSION` entries; added `shipped_workflow_secret_exfil` to D30 pattern weights and new provider groups to D22.
- **Detector index**: wired D32, D33, D34 into `backend/detectors/index.js` via `runTier1`.

### Fixed
- **`lib/prompt-injection.js` was dead code and an infinite-loop hazard** — two coupled defects fixed together: (1) `scanPromptInjection(allFiles)` was invoked through `runTier1` as `scanFn(pkgJson, files, registryMeta, allFiles)`, so it received `pkgJson` where it expected the `allFiles` array and returned `[]` on every scan; the signature now matches the tier-1 convention and the detector actually runs. (2) 11 of 15 patterns lacked the `/g` flag inside a `while (regex.exec())` loop — a non-global `exec` never advances `lastIndex`, so the loop would have spun forever the instant the signature fix armed it. Replaced with a flag-agnostic `matchAll` generator (fresh global copy per pattern, zero-length guard). Added a reputable-package bail and `test/prompt-injection.test.js` (7 tests) including a pipeline regression guard.

### Notes
- D32/D33/D34 weights are **pre-telemetry** (PoC-calibrated, like D29/D30). `test/detectors-corpus.test.js` cannot run on Windows; re-run the corpus suite on Linux before trusting FP numbers.
- Threat-model: a worm can mint its own valid Sigstore provenance (keyv/cacheable), so "fresh verifiable provenance" must never suppress findings. `lib/slsa-verifier.js` keeps `verified: false` until cryptographic verification lands; D31 remains the only tarball-to-source trust anchor.

## [1.6.0] — 2026-08-20

### Added
- **D29-RUNTIME-EVASION** (`tier1-runtime-evasion.js`): AST detector for alternative-runtime evasion (Mini Shai-Hulud / Miasma, ChainDrop). Covers Bun, Deno and QuickJS process primitives (`Bun.$`, `Bun.spawn`/`spawnSync`, `Deno.Command`, `Deno.run`, `std.popen`), native FFI (`bun:ffi` `dlopen`, `Deno.dlopen`), outbound network (`Bun.connect`, `Deno.connect`), credential env and file access, and runtime *binary downloads* in lifecycle hooks — including hooks that indirect through a script file (`"preinstall": "node setup.mjs"`). Blocks at aggregate 80, warns at 55; a finding requires an anchor signal (download / exec / FFI / alt-runtime hook interpreter) so ordinary Bun tooling does not fire. **Closes the headline gap: a Deno-idiom credential stealer previously produced zero findings across the entire pipeline while the byte-identical Node version scored HIGH.**
- **D30-WORKSPACE-PERSISTENCE** (`tier1-workspace-persistence.js`): Detects agent/IDE workspace persistence against `.claude/*`, `.cursor/rules/*`, `.vscode/*` and `.github/workflows/*`. Two directions: code that *writes* to a surface, and executable agent config *shipped* in the tarball (MCP `command`+`args`, `.vscode/tasks.json` `runOn: folderOpen`, workflows with `pull_request_target`/`workflow_run`). Write targets are constant-folded first, so `['.','claude'].join('')`, `path.join(process.cwd(),'.cursor','rules')`, `String.fromCharCode(46,99,…)` and single-assignment variable indirection all resolve to the same target as a literal path. Severity follows the surface band — an injected instruction is `high`, an injected server command is `critical`.
- **ERR_TARBALL_GIT_DESYNC** (`tier1-tarball-git-desync.js` + `backend/validators/git-diff.js`): Tarball-to-Git commit differential. Resolves the repository and candidate refs (attested `gitCommit` → `registryMeta.gitHead` → release tags), fetches the source tree, and flags executable scripts or capability-bearing code present in the tarball but absent from — or newly introduced relative to — the source commit. **Answers the question provenance cannot:** npm attestations bind an attestation to a *tarball*, never a tarball to its *source*, so a CI build from a dirty working tree yields a genuine attestation with a perfectly matching digest. Provenance state is deliberately never consulted. **Opt-in and off by default** (the only network-bound detector); enable via `runAll(pkg, files, meta, allFiles, { gitDiff: { enabled: true } })`.
- **`lib/ast-parse.js`**: Single hardened acorn entry point for all AST detectors — `ecmaVersion: 'latest'`, `allowHashBang: true`, module→script→hashbang-stripped fallback, and a bounded content-keyed parse cache shared across detectors. Parse failure returns `{ degraded, reason }` and is treated as a **signal**, never a silent skip.
- **`lib/runtime-primitives.js`**: Cross-runtime capability registry (Node/Bun/Deno/QuickJS) keyed by capability — EXEC, FFI, NET_CONNECT, NET_LISTEN, FS_READ, FS_WRITE, ENV_READ, FINGERPRINT — rather than by API name, so adding a runtime is a registry edit instead of a change to every detector. Resolves four AST shapes previous helpers could not express: tagged templates (`Bun.$\`…\``), constructor calls (`new Deno.Command`), bare-specifier imports (`bun:ffi`), and inline `require('child_process').execSync()`.
- **`lib/path-resolver.js`**: Constant-folds path expressions (string concat, template literals, `Array.join`, `path.join`/`resolve`, `String.fromCharCode`, `.concat`, single-assignment bindings). Runtime-only roots fold to `<cwd>`/`<home>`/`<dirname>` placeholders so partially-known paths still match. Reassigned variables are dropped rather than guessed at.
- **`lib/agent-surfaces.js`**: Agent/editor surface registry banded `exec` / `agent_read` / `editor_config`, with directory-terminal matching so a write to `.cursor/rules` (the directory) matches as well as a write to a file inside it.
- **111 new tests** across `test/tier1-runtime-evasion.test.js`, `test/tier1-workspace-persistence.test.js`, `test/validators-git-diff.test.js`, `test/lib-ast-parse.test.js`, `test/sarif-conformance.test.js` and `test/perf-detector-overhead.test.js`, reproducing each bypass vector from the gap assessment alongside false-positive controls.
- **D28-AI-SLOP-DROPPER** (`tier1-ai-slop-dropper.js`): New AST-based detector for the "AI Slop" / WEL1DROPPER 800-package campaign (Aug 2026). The campaign ships no lifecycle hooks — the README instructs the victim to `require()`/`import` the package explicitly — so hook-only detectors see a clean `package.json`. Detects the multi-stage downloader through nine signals: `dns_payload_assembly` (95), `encoded_string_array` (60), `dns_txt_oob` (55), `string_array_decoder` (50), `fingerprint_network_coupling` (40), `readme_directed_entry` (30), `high_entropy_literals` (20), `paas_stage_resolution` (20), `env_fingerprint` (10). Blocks at aggregate 80, warns at 55. A finding requires one of the three `anchor_signals` (`dns_payload_assembly`, `dns_txt_oob`, `encoded_string_array`); the rest modulate severity but never fire alone.
- **Scope-aware fingerprint/network coupling**: `process.platform`/`process.arch`/`os.*` reads are correlated with network and DNS calls via acorn lexical scope chains. Module-scope fingerprints only couple when the network call's enclosing function actually references the fingerprint variable, so `const isWindows = process.platform === 'win32'` plus an unrelated `https.get` does not fire.
- **DNS out-of-band profiling**: `dns.resolveTxt`/`resolveAny` and `dns.resolve(host, 'TXT'|'ANY')` are elevated to high outside safelisted network utilities (`network_utility_safelist` + `network_utility_keywords` in thresholds). TXT responses decoded into an execution sink (`dns_payload_assembly`) always block, safelist included.
- **`highEntropyStrings()`** (`lib/entropy-analyzer.js`): Per-string-literal Shannon entropy filter applied to AST string literals in non-minified files. Complements the existing whole-file entropy check in `tier1-obfuscation-heuristics.js`.
- **Test fixtures**: `test/fixtures/campaigns/ai-slop-wel1dropper/` (full dropper + three FP controls: a real DNS/SPF utility, an ordinary README `require()` example, a prebuilt-binary installer) and `fixtures/campaigns/d28-ai-slop-wel1dropper.jsonl` (7 packages with expected BLOCK/WARN/PASS verdicts).
- **24 new tests**: `test/tier1-ai-slop-dropper.test.js` covering each signal, the FP controls, safelist behaviour, pipeline integration, and the campaign fixture verdicts.

### Fixed
- **SARIF conformance for every tier-1 detector** (`backend/report.js`): `generateSARIF` assumed the ATK-* finding shape (`title`/`description`/`evidence: string`). Tier-1 detectors emit `message`/`evidence: string[]`/`locations: [{file,line}]`, which serialized to `message: {}` — SARIF requires `message.text` — and put an *array* in `artifactLocation.uri`, which requires a string. Every D-series finding therefore produced a non-conformant result. Both shapes are now normalized: real file/line locations are used when present, evidence lines move to `properties.evidence`, and rule `name` no longer produces `ATK-D28-…` for non-ATK rules.
- **js-yaml bumped to 4.3.1** to resolve GHSA-5p4m-2wfm-xmqj (quadratic CPU consumption in `!!omap` resolution, CVE-2026-59870 not backported to 3.x/4.x). Vulnerable range is 4.0.0–4.3.0 and the lockfile pinned 4.3.0. Both consumers — this package directly and eslint via `@eslint/eslintrc` — declare `^4.1.1`, so 4.3.1 satisfies each and still dedupes to a single copy; no major upgrade and no `overrides` entry needed. `package.json` was bumped alongside the lockfile so the floor survives a lockfile regeneration.
- **`runTier1` timeout is now per-detector** (`backend/detectors/index.js`): the fixed 800 ms budget is unchanged for existing detectors, but network-bound detectors can declare their own. `runAll` also accepts an `options` argument for detector-specific configuration.

### Calibration
- **D29/D30 are pre-telemetry.** Weights are calibrated against the gap-assessment proof-of-concept vectors and verified to produce **0 findings across 123 real `node_modules` packages**. They have *not* been measured against the 50-package clean corpus, because `test/detectors-corpus.test.js` cannot run on Windows (pre-existing: `execSync` passes a `C:\…` temp path to GNU tar, which reads the drive letter as a remote host spec — 108 failures, 0 assertion failures). Re-run the corpus suite on Linux before relying on the FP numbers.
- **D29 anchor gate corrects D24's inverted coverage.** D24 fires on the four *benign* Bun primitives (`Bun.file`, `Bun.serve`, `Bun.write`, `Bun.spawn`) while `Bun.$`, `bun:ffi`, `Bun.spawnSync`, `Bun.connect`, `Bun.listen`, `Bun.env`, `bun:sqlite`, `bun:jsc`, `Bun.embeddedFiles` and `process.versions.bun` all evade it — 4 of 15 primitives covered, and the covered four are the ones legitimate Bun tooling uses. D29 gates on capability (execution, native linking, runtime download) instead. D24 is left untouched to avoid recalibrating its weights; both may fire on a genuine Bun payload. D24's `Bun.shell(` pattern targets an API that does not exist — Bun's shell is the `Bun.$` tagged template.
- **D29/D30 performance: 0.72% of a full pipeline pass** (57 ms of 7,970 ms over 150 real files), inside the 5% budget. Prefilters reject ~97% of files before parsing and the shared parse cache means the two detectors parse each file once between them. Measured as the detectors' direct cost over pipeline cost rather than by differencing two pipeline runs — an ~8 s pipeline varies by more than 5% run to run, so differencing measures machine noise, not the detectors.
- **D30's prefilter is deliberately two-tier.** Precise dotted markers alone silently skipped assembled paths: a file building `.claude/mcp.json` from `['.','claude'].join('')` never contains the literal `.claude`. A second tier (write sink + bare surface word, or `String.fromCharCode`) keeps assembly in scope — the same prefilter/AST mismatch already documented for D28.
- **D31 skips build output rather than treating it as clean**, and reports the skip count so "verified" stays distinguishable from "not checked". Content comparison is insensitive to line endings and trailing whitespace, and a content difference only escalates when the tarball introduces capability the source lacks — reformatting and version stamping are not attacks.
- **D28 thresholds measured against the clean corpus with the reputable-package bail defeated** (the bail otherwise masks FPs on large packages). Initial calibration produced two critical FPs — prettier (arrays of camelCase identifiers matched a base64 *shape* test; HTML attribute tables reached 4.76 bits) and Next.js (dev-server code couples `process.platform` with network calls). Fixed by the anchor-signal gate, raising `entropy_threshold` to 5.0 at `min_literal_length` 64, and requiring base64-shaped literals to clear `base64_min_entropy` 4.5. Final: 0 FPs across all 50 clean packages.
- **D28 performance**: prefilter markers were retargeted from single literals to encoded-literal *runs*, and ubiquitous decode calls (`Buffer.from`, `atob`, `fromCharCode`) dropped from the prefilter — files reaching acorn fell from 4.3% to 1.3% of corpus JS. Worst-case cost went from 5.08 s to 1.15 s against a ~30 s full-pipeline pass (3.8%, inside the 5% budget); with normal exemptions the A/B delta is within run-to-run noise.
- **VINCE Integration** (`backend/vince.js`): New vulnerability coordination module for submitting findings to CISA's VINCE (Vulnerability Information and Coordination Environment). Features include formatted vulnerability reports, detailed review summaries, manual approval workflow, and secure API key handling. New CLI command `npm-scan submit-vince` with `--auto-approve` flag for controlled submissions.
- **VINCE Submission Workflow**: Manual review-before-submission process ensuring findings are vetted via Claude before coordination with vendors. Generates detailed severity summaries and evidence snippets for informed approval decisions.
- **VINCE Integration Documentation** (`VINCE_INTEGRATION.md`): Complete setup guide, usage workflow, security considerations, and troubleshooting.
- **TIER1-CRYPTO-TAMPER** (`tier1-crypto-primitive-tamper.js`): New diff-aware detector for semantic backdoors in crypto/wallet SDKs. Monitors security-sensitive functions (`fromMnemonic`, `fromPrivateKey`, `sign`, `signTransaction`, etc.) and compares against previous published version to detect newly injected network calls (`fetch`, `axios`, `http.request`) or dynamic code execution (`eval`, `new Function`). Closes gap from Injective SDK 2026-07-08 incident where `fromMnemonic()` was modified to exfiltrate wallet keys disguised as normal telemetry. confidenceScore 85, severity high. Diff-awareness eliminates FPs from legitimate analytics/telemetry that existed in prior versions.
- **TIER1-HOOK-FOLLOWTHROUGH** (`tier1-lifecycle-hook-followthrough.js`): New detector that follows `node`/`sh`/`bash` indirection in lifecycle hooks to referenced files, running the same obfuscation/network/env-exfil/entropy checks against the resolved file content. Chains up to 2 levels of indirection (script A requires/spawns script B). Closes gap where hooks like `"postinstall": "node scripts/postinstall.js"` scored zero because the payload lived in the referenced file.
- **TIER1-VERSION-BACKFILL** (`tier1-version-backfill.js`): New detector that flags packages with >= 8 versions published within 24 hours spanning a wide version range (e.g. 0.1.0 through 1.x), indicating version history was backfilled in a single publish burst to fake maturity. confidenceScore 80, severity high.
- **TIER1-INFOSTEALER identity_recon_exfil**: Extended infostealer detector with identity/credential-adjacent path patterns (`.gitconfig`, `.ssh/*.pub`, `.aws/config`, `.config/gcloud/properties`, `/etc/resolv.conf`, `git config user.email` exec). Scores HIGH even without matched credential regex, since recon-only payloads that never touch actual secrets are the attack technique.
- **Serverless PaaS domain watchlist** (`lib/paas-domains.js`): `*.run.app`, `*.web.app`, `*.vercel.app`, `*.netlify.app`, `*.workers.dev` flagged as contributing MEDIUM signal when appearing as network targets in lifecycle hooks or referenced install scripts. Boosts aggregate score when co-occurring with identity file reads.
- **Shared obfuscation utilities** (`lib/obfuscation-check.js`): Extracted `isObfuscated()` and `shannonEntropy()` from `tier1-lifecycle-hook.js` into shared lib for reuse across detectors.
- **Test fixtures**: `fixtures/campaigns/npm-package-logger-2026/` with minimal repro packages for AI-SDK postinstall pattern, @aspect-security/argon2 preinstall pattern, and version-backfill manifest.
- **27 new tests** across 3 test files: `tier1-lifecycle-hook-followthrough.test.js` (10), `tier1-version-backfill.test.js` (8), `tier1-infostealer-identity-recon.test.js` (9).
- **8 new tests** for crypto primitive tamper detector: `tier1-crypto-primitive-tamper.test.js` covering semantic backdoor detection, legitimate analytics FP validation, and edge cases.
- **TIER1-MAINTAINER-COMPROMISE extended detection** (`tier1-maintainer-compromise.js`): Added two new subtypes to catch Jscrambler-style hijacks: `single_version_compromise` (version published after 30+ day gap, deprecated and remediated within 24h, confidenceScore 70) and `dist_tag_manipulation` (dist-tag pointing to version with next version published within 1 hour, confidenceScore 85). Closes gap where single compromised publishes or tag repointing without version bursts went undetected.
- **9 new tests** for maintainer compromise extensions: `tier1-maintainer-compromise-extended.test.js` covering single version compromise, dist-tag manipulation, and combined detection scenarios.

### Changed
- **Thresholds**: Added `TIER1-HOOK-FOLLOWTHROUGH`, `TIER1-VERSION-BACKFILL`, `TIER1-CRYPTO-TAMPER`, `D28-AI-SLOP-DROPPER`, and `SERVERLESS_PAAS_WATCHLIST` entries to `config/thresholds.js`.
- **Detector index**: Wired `tier1-lifecycle-hook-followthrough`, `tier1-version-backfill`, `tier1-crypto-primitive-tamper`, and `tier1-ai-slop-dropper` into `backend/detectors/index.js` via `runTier1`.

## [1.0.0] — 2026-06-03

### Added
- **Production Validation**: D6, D7, D5 detectors validated against 3 real May 2026 supply chain attack campaigns (100% detection rate)
- **False Positive Calibration**: Thresholds calibrated on top 1,000 npm packages; 0.0% FP rate at production thresholds
- **D6 (Version Anomaly Detector)**: Z-score-based detection of dependency confusion attacks (e.g., 99.99.99 hijack)
- **D7 (Obfuscation Heuristics Detector)**: Shannon entropy + 9-pattern AST matching for malicious obfuscation
- **D5 Enhancement (Binary Embedding)**: Cross-platform binary set detection (ELF, Mach-O, PE)
- **Config-Driven Thresholds**: `backend/detectors/config/thresholds.js` with per-detector confidence settings
- **Whitelist System**: `backend/detectors/config/whitelist.json` for known-good packages (webpack, terser, lodash, etc.)
- **Validation Scripts**: `backend/scripts/validate-detectors.js`, `analyze-validation.js`, `fetch-top-packages.js`, `detect-false-positives.js`, `analyze-false-positives.js`
- **Comprehensive Validation Report**: [VALIDATION.md](./VALIDATION.md) with detection rates, FP metrics, and per-detector performance

### Changed
- **Major Version Bump**: v0.18.3 → v1.0.0 — production-grade release with published validation metrics
- **Tool Description**: Updated with 100% campaign detection / 0% FP rate claims
- **D1 (Typosquat) Threshold**: Increased to 85 to eliminate 46 false positives on legitimate scoped sub-packages
- **D7 (Obfuscation) Threshold**: Raised to 75 post-calibration; reduces false positives on bundlers (webpack, esbuild) by 82%

### Fixed
- Graceful fallback when npm registry unavailable (D6 uses pattern-only heuristics)
- Encoding fix: All JSONL reads/writes now explicitly use `utf-8` encoding for Windows compatibility
- False positive guard: Palindrome check in D7 no longer flagged as obfuscation

### Docs
- Added [VALIDATION.md](./VALIDATION.md): Full detection rates, false positive analysis, threshold justification
- Updated README with validation summary and per-detector confidence table

### Tests
- 690 tests total (671 pass, 0 fail, 19 skip)
- Zero regressions post-validation

## v0.18.2 — June 2, 2026

### New Detectors
- **D6a** `tier1-version-confusion.js` — Detects dependency confusion via sentinel
  versions (99.99.99 family → HIGH) and high-version heuristic (major≥9 → MEDIUM).
  Covers Sonatype-2026-003429 and Microsoft scope confusion campaigns.
- **D6b** `tier1-multistage-postinstall.js` — Detects two-stage remote download +
  binary execution and detached background persistence in lifecycle scripts.
  Covers Gen-2 stager patterns from the OpenSearch/ES typosquatting wave.
- **D6c** `tier1-cloud-imds.js` — Detects GCP metadata server and Azure IMDS endpoint
  targeting in scripts and JS files. Covers the Miasma @redhat-cloud-services campaign.

### Detector Enhancements
- **D2** `tier1-infostealer.js` — Added NAMED_SIGNATURES array with early-return
  CRITICAL detection for confirmed malware campaign strings. First entry: Miasma
  campaign identifier (June 2026).

### Bug Fixes
- **D6b** `tier1-multistage-postinstall.js`
  - Removed /g flag from REMOTE_FETCH_RE, BINARY_EXEC_RE, DETACHED_RE —
    eliminated fragile lastIndex state between hook iterations
  - Added critical severity tier to severityLabel — Signal A+B findings
    now consistently report severity: critical / confidence: CRITICAL
  - Fixed hardcoded "postinstall" in finding message — now reflects
    whichever hook fired and the subtype string

### Infrastructure
- Added Detector Registry section to AGENTS.md with calibration notes.

### Test Suite
- 656 passing, 0 failing, 19 skipping.

### Added
- `scan --file <path>` flag to analyze local `.tgz` tarballs without fetching from npm registry
- `scan --fail-on <level>` flag to exit with code 1 when findings >= severity (CI/CD integration)
- `scan --sarif [file]` to output SARIF v2.1 format for GitHub Advanced Security, VS Code, Azure DevOps
- `scan --csv [file]` and `report --csv [file]` to export tabular CSV for Excel/Sheets import
- `scan --score-only` to output only risk score (0-10), auto-added to JSON output
- Government/SOC 2 features: `--audit-log`, `--fips`, `--stig`, `--cache-dir` for air-gapped/federal compliance
- **BYOC (Bring Your Own Cloud)**: Helm chart v1.0.0 for enterprise/government VPC deployments with SIEM, PDF, SSO

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