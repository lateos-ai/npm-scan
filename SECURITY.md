# Security Policy

## Supported Versions

Only the **latest published minor version** on npm receives security patches. Keep `@lateos/npm-scan` up to date:

```bash
npm update -g @lateos/npm-scan
```

| Version | Supported |
|---------|-----------|
| 0.9.x   | ✅ Active |
| < 0.9   | ❌       |

## Reporting a Vulnerability

Use **GitHub Private Vulnerability Reporting**:

1. Go to [github.com/lateos-ai/npm-scan/security/advisories/new](https://github.com/lateos-ai/npm-scan/security/advisories/new)
2. Describe the vulnerability in detail (ideally with a proof of concept)
3. Allow **72 hours** for an initial acknowledgment

For encrypted follow-up outside of GitHub, use our PGP key:

```
Fingerprint: 1BC6 998B 879B BDE0 D778  629E D9CF F5EF 1F7C 557B
Key ID:      1F7C557B
Email:       leo@lateos.ai
```

## Scope

**In scope:**
- Detector logic (ATK-001 through ATK-011)
- Code execution in the scanner engine (`backend/fetch.js`, `cli/cli.js`)
- CI/CD pipeline and publish process (provenance bypass, supply chain)
- Configuration injection via `policy.yaml` or command-line flags

**Out of scope:**
- CVEs in third-party dependencies — report upstream
- Vulnerabilities in the npm registry itself — report to npm
- Malicious packages detected by the scanner (that's working as designed)

## Security Practices

`@lateos/npm-scan` follows these practices to protect its own supply chain:

- **Sigstore provenance** on every npm publish — verifiable via `npm view @lateos/npm-scan provenance`
- **Self-scanning in CI** — every commit scans the project's own `package-lock.json` for the full ATK taxonomy
- **SBOM per release** — CycloneDX and SPDX 2.3 Bill of Materials published with every version
- **2FA** enforced on the npm publisher account
- **Docker multi-arch images** signed and pushed via CI, not manually
- **All code public** — no security-by-obscurity

## Self-Scanning

As a supply chain security scanner, `@lateos/npm-scan` dogfoods its own detectors. Every CI run executes:

```bash
npx @lateos/npm-scan scan-lockfile --fail-on medium
```

If a future update to a dependency triggers one of our detectors (e.g., typosquat, obfuscated lifecycle script), the build **fails** before the change reaches npm.

## Safe Harbor

We consider security research conducted under this policy as authorized and will not pursue legal action against researchers who:

- Report vulnerabilities through GitHub Private Vulnerability Reporting
- Do not access or modify user data beyond what's necessary to demonstrate the vulnerability
- Do not exploit the vulnerability beyond demonstrating it
- Act in good faith to improve the security of the project