# Coverage Expansion Plan — October 2026

> **Date:** 2026-10-15
> **Scope:** New detector coverage for the npm supply chain attack classes that post-date the August 2026 audit ([gap-analysis-2026-08.md](gap-analysis-2026-08.md)), derived from four real campaigns observed Aug–Oct 2026.
> **Method:** External threat-intel review (Socket.dev research), diffed against `backend/detectors/` and grep-verified for actual coverage.
> **Decision:** Track A (new attack coverage) first. Track B (correctness/trust debt) deferred to a later pass.

---

## 0. Reconciliation with prior audits

Two items from the August audit are **already resolved** and are not re-planned here:

- **§1 SLSA attestation shape bug** — `lib/slsa-verifier.js` now reads `dist.attestations` as the object-shaped pointer it actually is and fetches the attestation document. Fixed.
- **§6 MCP / agent hook config execution** — now covered by **D30-WORKSPACE-PERSISTENCE** (`.mcp.json`, `.claude/settings.json` hooks, `.vscode/tasks.json` `folderOpen`, shipped workflows). Fixed.

MemTensor-class native-binary drops are **mostly already caught** by D4 (`tier1-binary-embed.js` detects the ELF/PE/Mach-O magic + `child_process` invocation); the only miss is cross-platform *set* scoring for the `.<dir>/<os>-<arch>/<name>` layout, handled as a minor fix below.

What is genuinely new is enumerated next.

---

## 1. Campaign → technique → coverage map

| # | Campaign (date) | Technique | Existing coverage | Action |
|---|---|---|---|---|
| 1 | keyv/cacheable (2026-08-04) | User-level host persistence: `~/Library/LaunchAgents`, `~/.config/systemd/user`, `loginctl enable-linger` | msh D2 / axios D3 cover **system** units only | **New D32** |
| 2 | keyv/cacheable | Dead-man's switch: poll credential validity, `eval` remote handler on HTTP 4xx / TTL expiry | none | **New D32 anchor** |
| 3 | keyv/cacheable | Worm mints its own fresh Sigstore provenance (DSSE + Fulcio + Rekor) | D31 ignores provenance (correct) | Threat-model note; do not let provenance suppress |
| 4 | all four | Install-time execution outside `package.json`: `.pnpmfile.cjs`, `.yarnrc.yml` plugins, `bunfig.toml`/`trustedDependencies`, `overrides`/`resolutions` | none | **New D33** |
| 5 | (general) | Registry version manifest ≠ tarball `package.json` (manifest confusion) | none | **New D34** |
| 6 | GhostAction (2026-10-08) | Shipped workflow: `on: push` + `${{ secrets.* }}` + `curl` to IP + `fetch-depth: 0` history grep | D30 flags only `pull_request_target`/`workflow_run` | **Extend D30** |
| 7 | GhostAction / MemTensor | New token literals: `github_pat_`, `sk-ant-/sk-proj-/sk-or-`, `xox[baprs]-`, `AIza`, `SG.`; files `access_tokens.json`, `stored_tokens`, `id_ecdsa`, `.vault-token` | only `glpat-` present | **Extend infostealer + D22** |
| 8 | PolinRider (2026-09-17) | Blockchain dead-drop C2 (EtherHiding / NullReceiver) | DNS + GitHub-commit dead-drop only | **Extend c2-deaddrop** |
| 9 | MemTensor | Cross-platform binary set in `.<dir>/<os>-<arch>/<name>` layout | D4 `CROSS_PLATFORM_RE` matches `name-<os>-<arch>` only | **Minor D4 fix** |
| 10 | keyv/cacheable | basE91 polymorphic string encoding (non-base64 alphabet) | entropy caught; decoder/shape not modeled | Note only (low priority) |

---

## 2. New detectors

### D32 — `tier1-host-persistence.js` (finding ID `D32-HOST-PERSISTENCE`)

Regex-driven (mirrors `msh-supplement/d2-persistence.js`), scoped to the **user-level** persistence + dead-man's-switch class that system-level checks miss.

Anchor signal (load-bearing): `deadman_switch` — a credential-validity poll whose *failure branch* (HTTP 4xx / expiry) feeds `eval`/`exec` of a non-literal (remote/variable) handler. Everything else only modulates severity.

Pattern weights (calibration: pre-telemetry, PoC-derived):
```
launch_agent_user        85   ~/Library/LaunchAgents/ OR /Library/LaunchAgents/*.plist w/ RunAtLoad|KeepAlive
systemd_user_unit        80   ~/.config/systemd/user/ OR systemctl --user
loginctl_linger          85   loginctl enable-linger
launchctl_plist_write    75   launchctl load|bootout + plist write
token_monitor_poll       60   periodic poll of whoami | /-/v1/tokens | /user/repos
deadman_switch           95   ANCHOR: invalidation branch -> eval/exec of variable handler
self_destruct_threshold  65   TTL/expiry self-delete after failure
```
Block ≥ 80, warn ≥ 60. Reputable-package bail at top.

### D33 — `tier1-install-config-abuse.js` (finding ID `D33-INSTALL-CONFIG-ABUSE`)

Closes the long-open August §5 gap. Four install-time surfaces, all already present in `allFiles`:

```
pnpmfile_mutates_and_dispatches   85   .pnpmfile.cjs readPackage + (scripts/deps mutation) + (exec|fetch|curl)
yarnrc_external_plugin            80   .yarnrc.yml plugins: resolving outside package (http/git URL)
bunfig_blocks_lifecycle           55   bunfig.toml trustedDependencies re-enable (moderate alone)
bunfig_lifecycle_to_external      85   bunfig.toml [install.lifecycle] -> external script
override_resolved_off_registry    90   overrides/resolutions resolved: http:// | git+ssh:// | non-registry host
```
`.pnpmfile.cjs` presence alone is **not** suspicious (legitimate monorepo use) — score on content. `bunfig` closes the D24 asymmetry (D24 sees the Bun runtime, not the config that authorizes it).

### D34 — `tier1-manifest-confusion.js` (finding ID `TIER1-MANIFEST-CONFUSION`)

Diff the registry version manifest against the tarball `package.json`. Both are in scope at `cli/cli.js:101` (`runAll(pkgJson, jsFiles, meta, allFiles)`), where `meta` is the `/{name}/{version}` response.

```
dependency_divergence   90   dependencies/devDependencies differ
script_divergence      100   lifecycle scripts differ (install hook in tarball only)
bin_divergence         90   bin targets differ
```
Exclude registry-injected fields (`_id`, `dist`, `_npmUser`, `gitHead`, `_integrity`, `time`, `maintainers`, …) and version-normalization differences before diffing, or every package fires. Return `[]` when `registryMeta` is null (local `--file` scans).

---

## 3. Extensions to existing detectors

### D30 — GhostAction workflow secret-exfil (`tier1-workspace-persistence.js`)
In `analyzeShippedConfig`, the `.ya?ml` branch currently only checks `pull_request_target|workflow_run`. Add a content scan for:
- bound-secret reference + network sink: `${{ secrets.` … `}}` co-occurring with `curl|wget|Invoke-WebRequest|https?://`
- git-history credential sweep: `fetch-depth: 0` or `git log -p --all` + a regex sweep (`grep -[rEi]`/`AKIA`/`sk-`/`ghp_`)

New subtype `shipped_workflow_secret_exfil` (weight 90, always critical), distinct from `shipped_workflow_privileged_trigger` (70).

### TIER1-INFOSTEALER — token literals + secret-file targets (`tier1-infostealer.js`)
Add literal regexes alongside the existing `AWS_KEY_RE`/`GH_TOKEN_RE`/`_GITLAB_TOKEN_RE`, loop them into `extractCredentials` so the existing `anyCredPattern → critical` scaling applies:
`github_pat_[A-Za-z0-9_]{22,}`, `sk-ant-[A-Za-z0-9_-]{20,}`, `sk-proj-[A-Za-z0-9_-]{20,}`, `sk-or-(v1-)?[A-Za-z0-9_-]{20,}`, `xox[baprs]-[A-Za-z0-9-]{10,}`, `AIza[A-Za-z0-9_-]{35}`, `SG\.[A-Za-z0-9_-]{16,}`.
Extend `IDENTITY_PATH_RE` with `access_tokens.json`, `stored_tokens`, `id_ecdsa`, `.vault-token`, `/run/secrets/`.

### D22-AI-TOKEN-TARGETING — literal formats + new providers (`tier1-ai-token-targeting.js`)
Add literal-format regexes (not just env-var names) and new `slack_token`/`sendgrid_token`/`google_api_key` groups in pattern weights.

### c2-deaddrop — blockchain dead-drop (`msh-supplement/d4-c2-deaddrop.js`)
Add a contributing signal for EtherHiding/NullReceiver-class resolution: `ethers`/`web3` provider call (`eth_call`/`getStorageAt`) whose return is decoded into a URL/host, or `eth_`/`web3` + JSON-RPC + `fetch(decoded)`. Keep it a contributing signal, not standalone (low npm prevalence).

### D4 — cross-platform set naming (`tier1-binary-embed.js`)
`detectCrossPlatformSets` currently matches `name-<os>-<arch>` file suffixes. Add a second grouping that strips a `<dir>/<os>-<arch>/<base>` path layout so the MemTensor `.sckit/<os>-<arch>/sckit` set counts as cross-platform.

---

## 4. Threat-model note (keyv/cacheable)

A worm can mint its own **valid** Sigstore provenance (DSSE envelope + Fulcio cert + Rekor entry) for a trojanized build. Consequence: "fresh verifiable provenance" must **never** suppress findings. D31 (tarball-git-desync) remains the only signal that binds a tarball to its *source*; the SLSA verifier's `verified: false` invariant must be preserved until cryptographic verification lands. Recorded in `lib/slsa-verifier.js` header.

---

## 5. Wiring & registration

- `backend/detectors/index.js`: add `import` + `runTier1(...)` blocks for D32, D33, D34 (D30/infostealer/D22/c2-deaddrop/D4 are edited in place).
- `backend/detectors/config/thresholds.js`: add `D32-HOST-PERSISTENCE`, `D33-INSTALL-CONFIG-ABUSE`, `TIER1-MANIFEST-CONFUSION` entries; add `shipped_workflow_secret_exfil` to D30 weights; add new D22 groups.
- `AGENTS.md` detector registry: add D32/D33/D34 rows + calibration notes.
- `CHANGELOG.md` `[Unreleased]`: document the three detectors, the four extensions, and the campaigns they close.

---

## 6. Tests

Node native test runner (`node --test`). Per new detector a `test/<name>.test.js` with: PoC reproduction, FP controls, pipeline integration via `runAll`, and standard tier-1 finding-shape assertions. Extensions add cases to the existing test files.

- `test/tier1-host-persistence.test.js` — LaunchAgent + dead-man's switch PoC; FP: legit macOS menu-bar app installing a real LaunchAgent; `gh` token-refresh helper that never evals remote code.
- `test/tier1-install-config-abuse.test.js` — malicious `.pnpmfile.cjs`, hostile `bunfig.toml`, `overrides` off-registry redirect; FP: benign monorepo `.pnpmfile.cjs`, legit `bunfig.toml` trusted dep, normal `resolutions` to a sha.
- `test/tier1-manifest-confusion.test.js` — tarball `package.json` adds `postinstall` absent from registry manifest; FP: byte-identical manifest.
- `test/tier1-workspace-persistence.test.js` — add GhostAction `security-audit.yml` fixture + FP (normal release workflow publishing with `${{ secrets.NPM_TOKEN }}`).
- `test/tier1-infostealer.test.js` / ai-token test — add GhostAction/MemTensor key patterns + FP (SDK documenting `sk-proj-…` placeholder).
- `test/tier1-binary-embed.test.js` — `.sckit/<os>-<arch>/sckit` cross-platform fixture.

---

## 7. Verification

- `npm test`, `npm run lint`, `npm run build`.
- **Corpus caveat (blocking for calibration):** `test/detectors-corpus.test.js` cannot run on Windows (pre-existing `execSync`→GNU tar drive-letter bug). D32–D34 are **pre-telemetry**; re-run the corpus suite on Linux before trusting FP numbers, exactly as D29/D30 are flagged.

---

## 8. Suggested order & effort

1. D34 manifest-confusion (~0.5d) — near-free, data in scope, high-confidence.
2. Ext B token literals (~0.5d) — pure regex additions, zero-FP literal classes.
3. D33 install-config-abuse (~2d) — new surface, reuse D30/obfuscation libs.
4. Ext A workflow exfil (~1d).
5. D32 host-persistence + dead-man switch (~2–3d) — novel signal, most calibration risk.
6. Ext C blockchain dead-drop + D4 naming fix (~1d).

**Deferred (Track B):** cryptographic Sigstore verification; ATK-006 stub rework.

**Completed after the initial Track A commit:** `lib/prompt-injection.js` dead-code + non-global-regex infinite-loop fix (call-signature mismatch in `index.js`); lockfile `resolved`-host + missing-`integrity` validation with a policy-configurable `allow.registries` allowlist.
