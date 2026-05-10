# npm Attack Taxonomy (ATK)

Versioned anchor for detectors, PRs, reports. Each entry: attack class, detection surface, evasion surface, NIST 800-161 mapping.

## ATK Table

| ID      | Class                                      | Detection Surface | Evasion Surface          | NIST 800-161     | Status |
|---------|--------------------------------------------|-------------------|--------------------------|------------------|--------|
| ATK-001 | Malicious lifecycle scripts (pre/postinstall) | Static          | Obfuscation              | SR-3.1           | Phase 1 |
| ATK-002 | Obfuscated payload (hex/base64/eval)       | Static          | Polyglots               | SR-4.2           | Phase 1 |
| ATK-003 | Credential harvesting (.npmrc/SSH/env)      | Static+Dynamic  | Conditional triggers     | SR-5.3           | Phase 1 |
| ATK-004 | Persistence (.vscode/.claude/.cursor)      | Static          | Hidden files             | SR-6.4           | Phase 1 |
| ATK-005 | Network exfiltration (GitHub/DNS/HTTP C2)  | Static+Dynamic  | Encrypted payloads       | SR-7.5           | Phase 1 |
| ATK-006 | Dependency confusion/namespace squatting   | Static (lock)   | Typosquatting            | SR-2.2           | Phase 1 |
| ATK-007 | Typosquatting (edit-distance top-N)        | Static          | Homoglyphs               | SR-2.1           | Phase 1 |
| ATK-008 | Tarball tampering (tarball ≠ repo)         | Static (diff)   | Mirror repos             | SR-8.1           | Phase 2 |
| ATK-009 | Conditional triggers (CI/time)             | Static+Dynamic  | Env probes               | SR-9.2           | Phase 2 |
| ATK-010 | Sandbox evasion                            | Static+Dynamic  | Anti-analysis            | SR-10.3          | Phase 2 |
| ATK-011 | Transitive propagation (worm)              | Static+Dynamic  | Peer deps                | SR-11.4          | Phase 3 |

## Detailed Entries

### ATK-008 — Tarball Tampering
- **Description:** The published npm tarball contains code that does not match the source repository. This can happen when a maintainer's npm token is compromised or CI is abused.
- **Detection surface:** Static (diff). Compare `package.json` `repository` field against known good mappings. Check embedded `// Source:` comments against declared repo URL. Full automated diff against `git clone` requires sandbox tier.
- **Evasion surface:** Mirror repos, monorepo confusion, repository field omitted or generic (`github.com/user`).
- **NIST mapping:** SR-8.1 (Integrity Verification)
- **Example:** A package named `lodash` with `repository` pointing to `github.com/attacker/lodash-mirror`.

### ATK-009 — Conditional Triggers
- **Description:** The package behaves differently based on environment detection. May appear benign during scan but activates malicious behavior in production. Common triggers: CI env detection, date/time checks, hostname checks.
- **Detection surface:** Static+Dynamic. Static analysis looks for `process.env.CI`, `process.env.NODE_ENV`, date comparisons, `setTimeout`/`setInterval`. Dynamic sandbox runs with randomized env and observes behavior difference.
- **Evasion surface:** Obfuscated env probes, time-based triggers with external NTP, trigger after multi-hour delay.
- **NIST mapping:** SR-9.2 (Conditional Behavior Analysis)
- **Example:** `if (process.env.NODE_ENV === 'production') { eval(atob(payload)) }`

### ATK-010 — Sandbox Evasion / Anti-Analysis
- **Description:** The package actively probes its execution environment to detect analysis tools. If sandbox is detected, the package suppresses malicious behavior. Common probes: `debugger` statement, `os.hostname()`, `process.argv` inspection for `--inspect`, stack trace capture.
- **Detection surface:** Static+Dynamic. Static analysis checks for debugger statements, hostname checks, process tree inspection, `navigator`/`document` usage (browser env confusion). Dynamic sandbox uses randomized env and monitors syscalls for sandbox-detection patterns.
- **Evasion surface:** Indirect probing (measure timing without `performance.now()`), environment fingerprinting through error messages, incremental evasion.
- **NIST mapping:** SR-10.3 (Anti-Evasion Detection)
- **Example:** `if (os.hostname().includes('docker')) { process.exit(0) }`

### ATK-011 — Transitive Propagation (Worm)
- **Description:** The package acts as a self-propagating worm by spreading itself through the dependency tree. Instead of (or in addition to) executing a standalone payload, it modifies peer/sibling packages' code or `package.json` to inject its own lifecycle hooks or entry points. This propagates the attack when the infected sibling is required by other packages upstream. Also covers "worm-drop" patterns where the package installs itself into other packages' `node_modules` via programmatic `npm install`/`npm link`.
- **Detection surface:** Static+Dynamic. Static analysis checks for `child_process.exec`/`execSync` with `npm install`/`npm link` of local packages, `fs.writeFile` targeting sibling `node_modules` directories, `package.json` script injection in other packages, `fs.symlink` for binary propagation, and self-name references used to locate and copy own code into peer packages. Dynamic sandbox monitors filesystem writes outside the package's own directory tree.
- **Evasion surface:** Peer dep confusion (installing a popular peer package with the same name as a benign transitive dep), delayed propagation (worm activates only after N runs or N days), piggybacking on legitimate `postinstall` chains, writing to `node_modules/.cache` or `node_modules/.bin` where detection is less likely.
- **NIST mapping:** SR-11.4 (Supply Chain Propagation Monitoring)
- **Example:** A package reads `process.env.npm_package_name`, locates its own directory in `node_modules`, then writes a malicious `postinstall` script to the `package.json` of a sibling package, ensuring the worm runs when any project dependency is installed.

## Governance

New ATK requires PR with: PoC sample, detection rule, FP analysis, NIST map. Published at `docs/attack-taxonomy.md`. Referenced in all scan reports.