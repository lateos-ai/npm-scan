# AGENTS.md

## Project
ESM Node.js CLI monorepo for @lateos/npm-scan supply chain scanner.

## Repos
- **GitHub (oss):** `origin` → `https://github.com/lateos-ai/npm-scan.git` — public npm package `@lateos/npm-scan`
- **Premium:** `/Users/leochong/Projects/npm-scan-premium` — private premium feature repo (license-gated features: SIEM, PDF, SSO, etc.)

## Verification
Run `npm test` (243 tests), `npm run test:coverage` (85%+), `npm run lint`, `npm run build`.

## Architecture
- `cli/`: Commander.js entrypoints
- `backend/`: Core logic, detectors (ATK-001 to ATK-011), db/schema.sql
- `backend/detectors/`: 11 ATK detectors + tier-1 suite (D1–D6c, D24–D25) + campaign detectors + index.js routing
- `backend/siem/`: SIEM exporters (CEF, ECS, Sentinel, QRadar)
- `backend/license.js`: HMAC-signed license key generation/validation
- `backend/db.js`: SQLite via sql.js (WASM, no native deps)
- `backend/fetch.js`: npm registry fetch + tarball extraction
- `backend/report.js`: HTML + text report generation
- `backend/cra.js`: EU CRA compliance report
- `backend/sbom.js`: CycloneDX + SPDX SBOM
- `backend/pdf.js`: PDF report generation (premium)
- `backend/policy.js`: YAML/JSON policy-as-code engine
- `backend/validators/`: opt-in verification engines that reach outside the tarball (`git-diff.js` — tarball-to-Git differential; injectable `sourceProvider` keeps tests hermetic)
- `test/`: detector, lib, report and policy suites (db, detectors-edge-cases, detectors-corpus, report, policy, cli, fetch, per-detector tier1 suites, lib-ast-parse, sarif-conformance, perf-detector-overhead, validators-git-diff)
- `test/fixtures/`: Shared mock data for test suites
- `tests/corpus/`: 33 malicious + 50 clean tarballs for integration testing
- `deploy/helm/`: Kubernetes Helm chart (enterprise)
- `docker/`: Multi-arch Docker images (cli, pipeline)

## Detector Registry

### Tier 1 Detectors

| ID | File | Finding ID | Campaign Coverage |
|---|---|---|---|
| D1 | `tier1-typosquat.js` | `TIER1-TYPOSQUAT` | Typosquatting, edit-distance spoofing |
| D2 | `tier1-infostealer.js` | `TIER1-INFOSTEALER` | AI-generated infostealers, GitHub PAT harvesting, named malware signatures, identity/credential-adjacent path recon |
| D3 | `tier1-lifecycle-hook.js` | `TIER1-LIFECYCLE-HOOK` | Obfuscated install scripts, env exfiltration |
| D3b | `tier1-lifecycle-hook-followthrough.js` | `TIER1-HOOK-FOLLOWTHROUGH` | Hook indirection to referenced files (node/sh/bash), 2-level chain followthrough |
| D4 | `tier1-binary-embed.js` | `TIER1-BINARY-EMBED` | Bun runtime abuse, IMDSv2/ECS credential targeting |
| D5 | `tier1-metadata-spoof.js` | `TIER1-METADATA-SPOOF` | Namespace spoofing, cloned repo URLs, Yandex alias pattern |
| D6a | `tier1-version-confusion.js` | `TIER1-VERSION-CONFUSION` | Sentinel versions (99.99.99 family), high-version heuristic (major≥9) |
| D6b | `tier1-multistage-postinstall.js` | `TIER1-MULTISTAGE-POSTINSTALL` | Two-stage download+exec, detached background persistence |
| D6c | `tier1-cloud-imds.js` | `TIER1-CLOUD-IMDS` | GCP metadata server, Azure IMDS endpoint targeting |
| D6d | `tier1-version-backfill.js` | `TIER1-VERSION-BACKFILL` | Version history backfill in single publish burst to fake maturity |
| D24 | `tier1-bun-runtime-swap.js` | `D24-BUN-RUNTIME-SWAP` | Bun runtime swap (spawn, API usage, process.argv), bun downloader, credential combo, node-to-bun evasion (Miasma/Hades campaign) |
| D25 | `tier1-split-dynamic-payload.js` | `D25-SPLIT-DYNAMIC-PAYLOAD` | Split/dynamic payload assembly, sys.path manipulation, eval+fetch chains, buffer assembly, multifile traversal (Miasma/Hades campaign) |
| D28 | `tier1-ai-slop-dropper.js` | `D28-AI-SLOP-DROPPER` | README-directed `require()`/`import` entry with no lifecycle hooks, hex/base64 string-array obfuscation + decoder, per-literal entropy, `process.platform`/`arch` fingerprinting scope-coupled to network calls, DNS TXT out-of-band stage-2 resolution ("AI Slop"/WEL1DROPPER 800-package campaign) |
| D29 | `tier1-runtime-evasion.js` | `D29-RUNTIME-EVASION` | Alternative-runtime evasion: Bun/Deno/QuickJS process primitives (`Bun.$`, `Bun.spawnSync`, `Deno.Command`), native FFI (`bun:ffi`, `Deno.dlopen`), runtime binary downloads in lifecycle hooks incl. `setup.mjs` indirection, credential env/file access (Mini Shai-Hulud / Miasma) |
| D30 | `tier1-workspace-persistence.js` | `D30-WORKSPACE-PERSISTENCE` | Agent/IDE workspace persistence: writes to `.claude/*`, `.cursor/rules/*`, `.vscode/*`, `.github/workflows/*` with constant-folded path reconstruction; shipped executable agent config (MCP `command`+`args`, `runOn: folderOpen`, privileged workflow triggers) |
| D31 | `tier1-tarball-git-desync.js` | `ERR_TARBALL_GIT_DESYNC` | Tarball-to-Git differential via `backend/validators/git-diff.js`. **Opt-in / network-bound.** Executable scripts or capability-bearing code present in the tarball but absent from the attested commit. Deliberately ignores provenance state |
| D32 | `tier1-host-persistence.js` | `D32-HOST-PERSISTENCE` | User-level host persistence (LaunchAgent `~/Library`, `~/.config/systemd/user`, `loginctl enable-linger`) + dead-man's-switch (eval remote handler on credential revocation) — keyv/cacheable 2026-08 |
| D33 | `tier1-install-config-abuse.js` | `D33-INSTALL-CONFIG-ABUSE` | Install-time execution outside `package.json`: `.pnpmfile.cjs` readPackage, `.yarnrc(.yml)` plugins, `bunfig.toml` preload/trustedDependencies, `overrides`/`resolutions` off-registry (gap-analysis §5) |
| D34 | `tier1-manifest-confusion.js` | `TIER1-MANIFEST-CONFUSION` | Registry version manifest ≠ tarball `package.json` (deps/scripts/bin divergence). Registry-injected fields stripped before diff |

### Shared Detector Libraries

| Module | Purpose |
|---|---|
| `lib/ast-parse.js` | Single hardened acorn entry point (`ecmaVersion: 'latest'`, `allowHashBang`, module→script→hashbang-stripped fallback). Returns `{ ast, degraded, reason }` — parse failure is a **signal**, never a silent skip. Bounded content-keyed cache shared across detectors. |
| `lib/runtime-primitives.js` | Cross-runtime capability registry (Node/Bun/Deno/QuickJS) keyed by capability (EXEC, FFI, NET_*, FS_*, ENV_READ, FINGERPRINT) rather than API name. Resolves tagged templates, `new` expressions, bare-specifier imports, namespace bindings, and inline `require('x').y()`. |
| `lib/path-resolver.js` | Constant-folds path expressions (concat, template literals, `Array.join`, `path.join/resolve`, `String.fromCharCode`, single-assignment bindings). Runtime roots fold to `<cwd>`/`<home>`/`<dirname>` placeholders. |
| `lib/agent-surfaces.js` | Agent/editor surface registry, banded `exec` (critical) / `agent_read` (high) / `editor_config` (medium). |

### Calibration Notes

- **D6a heuristic** (`major >= 9 && minor >= 5 && patch >= 5`, `major !== 1`): known FP risk area. Tune confidence thresholds once production scan telemetry is available.
- **D2 named signatures**: zero-FP string literals for confirmed malware campaigns. Safe to add new entries without score recalibration.
- **D24/D25 pattern weights**: calibrated against Miasma/Hades campaign artifacts. Tune `bun_api_usage` and `buffer_assembly` weights once broader scan telemetry is available, as these patterns may appear in legitimate Bun-based tooling.
- **D3b hook followthrough**: Only fires on `node <path>` / `sh <path>` / `bash <path>` hooks with no inline eval/URL/exec. Chains up to 2 levels. Reuses `lib/obfuscation-check.js` for entropy/obfuscation scoring.
- **D6d version backfill**: Requires >= 8 versions, < 24h spread, wide version range (major span >= 1 or >= 4 unique minors). Calibrated against npm-package-logger-2026 campaign.
- **Serverless PaaS watchlist** (`*.run.app`, `*.web.app`, `*.vercel.app`, `*.netlify.app`, `*.workers.dev`): MEDIUM contributing signal (+15 confidence boost), not standalone critical. Hooks into D2 infostealer and D3b hook-followthrough.
- **D28 anchor signals**: a finding requires one of `dns_payload_assembly`, `dns_txt_oob`, or `encoded_string_array`. Everything else (fingerprint/network coupling, entropy, README lure, PaaS host, bare fingerprint) only modulates severity. This gate is load-bearing: without it Next.js flags critical (its dev server couples `process.platform` with network code) and prettier flags critical (HTML attribute tables at 4.76 bits + arrays of camelCase identifiers). Both are clean at the current calibration.
- **D28 entropy calibration** (measured on the clean corpus, reputable bail defeated): the campaign write-up's suggested 4.5-bit threshold is too low — 1,050 clean literals of >= 64 chars exceed it. `entropy_threshold` is 5.0 at `min_literal_length` 64; random base64 payloads score 5.0–5.4. Separately, a base64 *shape* test matches ordinary identifiers (`doExpressions`, `RegExpLiteral`), so encoded literals must also clear `base64_min_entropy` (4.5) — of 12,708 base64-shaped clean literals only 43 do.
- **D28 DNS safelist**: `dns_txt_oob` is suppressed for packages matching `network_utility_safelist`/`network_utility_keywords` (DNS, SPF, DKIM, ACME, mail tooling). `dns_payload_assembly` is never suppressed — decoding TXT records into an execution sink is not legitimate even for a mail utility.
- **D28 performance**: a regex prefilter runs before any parsing, so only ~1.3% of corpus JS files reach acorn. Worst case (reputable bail defeated across the whole corpus) is ~1.15 s against a ~30 s full-pipeline pass, i.e. 3.8%; with normal exemptions the delta is inside run-to-run noise. Files over `max_file_bytes` (512 KB) are skipped, as are non-`.js`/`.mjs`/`.cjs` files (TypeScript sources fail to parse and are dropped silently). Slowest single package in the corpus is Next.js at ~484 ms (3,721 files) against `runTier1`'s 800 ms timeout — headroom is real but not large, so re-measure before adding another AST walk. If new signals are added, keep the prefilter markers in sync with the AST thresholds — a mismatch silently disables the signal.
- **D29 anchor signals**: a finding requires a runtime download, an exec primitive, FFI, or an alternative-runtime hook interpreter. Supporting signals (`alt_runtime_fs_read`, `alt_runtime_listen`, `runtime_fingerprint`, `alt_runtime_network`) only modulate severity. This gate is load-bearing and corrects D24's **inverted coverage**: D24 fires on the four *benign* Bun primitives (`Bun.file`, `Bun.serve`, `Bun.write`, `Bun.spawn`) while `Bun.$`, `bun:ffi`, `Bun.spawnSync`, `Bun.connect` and `Bun.env` all evade it. Without the anchor gate an honest `Bun.serve` + `Bun.file` HTTP server flags. D24 is left as-is (regex, campaign-specific); D29 supersedes it for capability coverage, and the two may both fire on a genuine Bun payload.
- **D29 known gap**: `Bun.shell(` in D24's pattern list is a phantom API — Bun's shell is the `Bun.$` tagged template. D29 covers `Bun.$` correctly; D24's dead pattern was left untouched to avoid recalibrating its weights.
- **D29/D30 weights are pre-telemetry.** Calibrated against the gap-analysis PoCs and verified 0 findings across 123 real `node_modules` packages, *not* against the 50-package clean corpus (the corpus harness does not run on Windows — see below). Re-verify on Linux before relying on the FP numbers.
- **D30 severity follows the surface band, not the syntax.** An injected instruction is `high` (an agent must comply); an injected server command is `critical` (it executes unconditionally on next agent/editor start). Packages that legitimately declare themselves MCP servers (`keywords: ['mcp']`) are suppressed *unless* the shipped config launches a shell, passes an inline `-c` payload, fetches from the network, or runs an absolute path outside the package.
- **D30 prefilter has two tiers**, and this is deliberate: precise dotted markers (`.claude`, `.cursor`) plus a write-sink-and-bare-surface-word pass. A file assembling `.claude/mcp.json` from `['.','claude'].join('')` never contains the literal `.claude`, so the precise tier alone silently skipped it — the same prefilter/AST mismatch called out in the D28 note above.
- **D31 is off by default and network-bound.** It fetches the repository tree for the attested commit or a release tag, so the pipeline short-circuits before any I/O unless enabled via `runAll(..., { gitDiff: { enabled: true } })` or the thresholds flag. Build-output directories are *skipped*, not treated as clean, and the skip count is reported so "verified" is distinguishable from "unchecked"; an unreachable source yields `unverifiable`, never `clean`. Provenance state is deliberately never consulted — a valid attestation over a dirty build is precisely the attack.
- **D29/D30 performance**: 0.72% of a full pipeline pass (57 ms of 7,970 ms over 150 real files). Prefilters reject ~97% of files before parsing, and `lib/ast-parse.js` caches by content so the two detectors parse each file once between them. Note that D28 still parses independently with its own acorn call — migrating it to `parseSource` would remove one parse per file and is the obvious next optimisation.
- **D32 dead-man's-switch anchor**: a finding requires an anchor (an autostart install — LaunchAgent/`systemctl --user`/`loginctl enable-linger`/`launchctl`+plist — or the dead-man switch); `token_monitor_poll` and `self_destruct_threshold` only modulate. The switch is AST-gated so `eval("literal")` never fires — only `eval`/exec of a *variable* handler correlated with a credential-revocation status check, which is why a legitimate `new Function(...)` code generator (no revocation poll) does not fire. Complements msh D2 / axios D3, which cover only *system* units. Weights pre-telemetry.
- **D33 content-gated**: presence of a `.pnpmfile.cjs` is not suspicious (legitimate monorepo use is common); only hooks that reach outside the package (exec/network) or rewrite a dependency fire. `overrides`/`resolutions` flag only off-registry protocols (`git+ssh`/`ssh`/`http`/`file`/`link`); `github:`/`git+https:`/`npm:` aliasing is too common to flag and is deliberately ignored. `bunfig.toml` `trustedDependencies` alone (weight 55) stays under the warn threshold.
- **D34 registry-vs-tarball**: the two manifests come from the same publish, so any divergence in a capability-bearing field is high-confidence malicious. Registry-injected fields (`_id`, `dist`, `_npmUser`, `gitHead`, `time`, `maintainers`, …) are stripped before diffing or every package fires. Returns `[]` when `registryMeta` is absent (local `--file` scans). `devDependencies` is intentionally not compared (publish-time pruning is a benign source of divergence).
- **D30 GhostAction extension**: shipped-workflow analysis now escalates a `shipped_workflow_secret_exfil` signal when bound secrets (`${{ secrets.* }}`) reach a non-allowlisted/raw-IP destination, or when `fetch-depth: 0` + a git-history credential grep co-occurs. Publishing to a known registry host (`registry.npmjs.org`, `pypi.org`, `api.github.com`, …) is allowlisted and stays a plain `shipped_exec_config`. Note: *any* shipped `.github/workflows/*.yml` still fires `shipped_exec_config` (pre-existing behaviour, EXEC band).

### Known environment issue

`test/detectors-corpus.test.js` fails on Windows (108 failures): `execSync` passes a `C:\…` temp path to GNU tar, which reads the drive letter as a remote host spec. Pre-existing and unrelated to detector logic — there are no assertion failures. The corpus suite must be run on Linux/macOS.

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
