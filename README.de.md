# @lateos/npm-scan

[![English](https://img.shields.io/badge/lang-en-blue?style=flat-square)](README.md)
[![中文](https://img.shields.io/badge/lang-zh--CN-red?style=flat-square)](README.zh.md)
[![日本語](https://img.shields.io/badge/lang-ja-purple?style=flat-square)](README.ja.md)
[![Français](https://img.shields.io/badge/lang-fr-orange?style=flat-square)](README.fr.md)
[![Deutsch](https://img.shields.io/badge/lang-de-green?style=flat-square)](README.de.md)

[![npm version](https://img.shields.io/npm/v/@lateos/npm-scan?style=flat-square)](https://www.npmjs.com/package/@lateos/npm-scan)
[![License](https://img.shields.io/badge/license-Apache%202.0%20%2B%20Commons%20Clause-blue?style=flat-square)](LICENSING.md)
[![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen?style=flat-square)](package.json)
[![Tests](https://img.shields.io/badge/tests-222%20passing-brightgreen?style=flat-square)](https://github.com/lateos/npm-scan)
[![Coverage](https://img.shields.io/badge/coverage-85%25-yellowgreen?style=flat-square)](https://github.com/lateos/npm-scan)

**Moderne Lieferkettensicherheit für das npm-Ökosystem.**  
Statische + verhaltensbasierte Analyse, die erkennt, was npm audit, Snyk und Socket übersehen — obfuskierte Payloads, Credential-Stealer, bedingte Auslöser, Sandbox-Evasion und wurmartige Verbreitung.

---

## 📌 Das Problem

Die Welle von npm-Lieferkettenangriffen 2025–2026 hat bewiesen, dass herkömmliche Werkzeuge nicht mehr ausreichen.

Angreifer haben sich längst über einfaches Typosquatting hinausentwickelt. Sie liefern nun **obfuskierte Preinstall-Hooks**, **hinter Umgebungserkennung versteckte Credential-Stealer**, **schlafende Hintertüren mit zeitbasierter Aktivierung** und **wurmartige transitive Verbreitung**, die sich über Peer-Abhängigkeiten ausbreitet.

**npm audit** prüft bekannte CVEs. **Snyk** scannt nach Schwachstellen. **Socket** untersucht das Paketverhalten. Keines dieser Tools wurde für die Angriffsgeneration entwickelt, die 2025 auftrat — Angriffe, die harmlos aussehen, bis sie die Produktion erreichen.

**@lateos/npm-scan** wurde für diesen Moment entwickelt.

---

## 🔬 Warum @lateos/npm-scan?

| Fähigkeit | npm audit | Snyk | Socket | **@lateos/npm-scan** |
|---|---|---|---|---|
| Bekannte CVE-Übereinstimmung | ✅ | ✅ | ❌ | ✅ |
| Statische Analyse | ❌ | ✅ | ✅ | ✅ |
| Erkennung obfuskierter Payloads | ❌ | ❌ | ❌ | ✅ |
| Verhaltens-/heuristische Analyse | ❌ | ❌ | Teilweise | ✅ |
| Erkennung bedingter Auslöser (ATK-009) | ❌ | ❌ | ❌ | ✅ |
| Sandbox-Evasion-Erkennung (ATK-010) | ❌ | ❌ | ❌ | ✅ |
| Transitive Wurmverbreitung (ATK-011) | ❌ | ❌ | ❌ | ✅ |
| Angriffstaxonomie (ATK-Serie) | ❌ | ❌ | ❌ | ✅ |
| SBOM-Ausgabe (CycloneDX + SPDX) | ❌ | ✅ | ❌ | ✅ |
| NIST 800-161-Compliance-Bericht | ❌ | ❌ | ❌ | ✅ |
| EU-CRA-Compliance-Bericht | ❌ | ❌ | ❌ | ✅ |
| SIEM-Export (CEF / ECS / Sentinel / QRadar) | ❌ | ❌ | ❌ | ✅ |
| Vollständig lokale Ausführung — keine Telemetrie | ✅ | ❌ | ❌ | ✅ |
| Policy-as-Code (YAML-Whitelists) | ❌ | ❌ | ❌ | ✅ |

> **Datenschutz an erster Stelle.** Alle Scans erfolgen auf Ihrem Rechner. Kein Code verlässt Ihre Umgebung. Keine Telemetrie. Keine Cloud-Abhängigkeit.

---

## ✨ Hauptfunktionen

| Symbol | Funktion | Beschreibung |
|------|---------|-------------|
| 🕵️ | **Heuristische statische Analyse** | AST-Level-Inspektion erkennt Obfuskation, eval-Ketten, Umgebungsabfragen und verdächtige Lebenszyklus-Skripte, die regex-basierten Tools entgehen |
| 🧠 | **Verhaltenserkennung** | Identifiziert bedingte Auslöser (zeitbasiert, CI-bewusst), Sandbox-Evasion und schlafende Aktivierungsmuster |
| 🧬 | **ATK-Angriffstaxonomie** | 11 klassifizierte Angriffstypen mit NIST 800-161-Zuordnungen — versioniert, dokumentiert und PR-fähig |
| 📦 | **SBOM-Generierung** | CycloneDX 1.5 und SPDX 2.3 mit eingebetteten Ergebnissen als Schwachstellen |
| 🧾 | **Compliance-Berichte** | NIST SP 800-161-Rückverfolgbarkeitsmatrix + EU Cyber Resilience Act-Zuordnung (kostenlos) |
| 🔌 | **SIEM-Export** | Splunk CEF, Elastic ECS, Microsoft Sentinel, IBM QRadar-Formate (Premium) |
| 📜 | **Policy-as-Code** | YAML/JSON-Policy-Engine mit Whitelists, Schweregrad-Überschreibungen, Unterdrückungen und Fehlerschwellen |
| 🐳 | **Docker + GitHub Action** | Multi-Arch-Images, Ein-Befehl-Compose-Pipeline, PR-Scan-Action |
| 🛡️ | **Null Telemetrie** | Keine Daten verlassen Ihren Rechner. Keine Cloud. Keine Rückrufe. |
| 💾 | **Lokaler Scan-Verlauf** | SQLite-basierte Persistenz, keine externen Abhängigkeiten |

---

## ⚡ Schnellstart

```bash
# Global installieren
npm install -g @lateos/npm-scan

# Ein einzelnes Paket scannen
npm-scan scan lodash

# Ihre Lock-Datei scannen
npm-scan scan-lockfile

# Letzte Scans anzeigen
npm-scan report
```

**Keine Installation? Kein Problem:**

```bash
npx @lateos/npm-scan scan commander
```

---

## 📖 Verwendungsbeispiele

### Ein einzelnes Paket scannen

```bash
# Standard-JSON-Ausgabe mit allen Ergebnissen
npm-scan scan axios

# SBOM zusammen mit dem Scan generieren
npm-scan scan express --sbom             # CycloneDX JSON
npm-scan scan express --sbom xml         # CycloneDX XML
npm-scan scan express --sbom spdx        # SPDX 2.3

# Eine YAML-Policy anwenden
npm-scan scan some-package --policy .npm-scan.yml
```

### Eine Lock-Datei scannen

```bash
# Die Abhängigkeiten des aktuellen Projekts scannen
npm-scan scan-lockfile

# Eine bestimmte Lock-Datei scannen
npm-scan scan-lockfile -f ./path/to/package-lock.json
```

### Berichte generieren

```bash
# Alle letzten Scans auflisten
npm-scan report

# Einen bestimmten Scan anzeigen
npm-scan report -i 42

# HTML-Bericht (kostenlos) mit vollständigen Ergebnissen + NIST-Tabelle
npm-scan report -i 42 --html

# NIST 800-161-Compliance-Tabelle ausgeben
npm-scan report -i 42 --nist

# EU-CRA-Compliance-Tabelle ausgeben
npm-scan report --cra

# Textbericht (kostenlos)
npm-scan report --text

# PDF-Bericht (Premium)
npm-scan report --pdf --license-key <key>

# SIEM-Export (Premium)
npm-scan report --siem cef        # Splunk CEF
npm-scan report --siem ecs        # Elastic ECS
npm-scan report --siem sentinel   # Microsoft Sentinel
npm-scan report --siem qradar     # IBM QRadar

# Alle Scans in einem einzigen Bericht zusammenfassen
npm-scan report --html            # alle Scans
npm-scan report --pdf             # alle Scans (Premium)
```

---

## 🧬 Erkennungsfähigkeiten (ATK-Taxonomie)

| ID | Angriffsklasse | Erkennungsmethode | Schweregrad | NIST 800-161 |
|---|---|---|---|---|
| **ATK-001** | Böswillige Lebenszyklus-Skripte (`preinstall`, `postinstall`, `install`) | Statisch | 🔴 hoch | SR-3.1 |
| **ATK-002** | Obfuskierte Payload-Zustellung (hex, base64, eval-Ketten) | Statisch | 🟠 mittel | SR-4.2 |
| **ATK-003** | Credential-Diebstahl (Umgebungsvariablen, .npmrc, SSH-Schlüssel) | Statisch + Dynamisch | 🔴 hoch | SR-5.3 |
| **ATK-004** | Persistenz über Editor-/Konfigurationsverzeichnisse (.vscode, .claude, .cursor) | Statisch | 🔴 hoch | SR-6.4 |
| **ATK-005** | Netzwerk-Exfiltration (GitHub-API, DNS-Tunneling, HTTP C2) | Statisch + Dynamisch | ⚫ kritisch | SR-7.5 |
| **ATK-006** | Abhängigkeitsverwirrung / Namespace-Squatting | Statisch (Lock-Datei) | 🟠 mittel | SR-2.2 |
| **ATK-007** | Typosquatting (Edit-Distanz-Matching) | Statisch | 🟢 niedrig | SR-2.1 |
| **ATK-008** | Tarball-Manipulation (veröffentlicht ≠ Quelle) | Statisch | 🔴 hoch | SR-8.1 |
| **ATK-009** | Bedingte/schlafende Auslöser (CI-Erkennung, zeitbasiert) | Verhaltensbasiert | 🔴 hoch | SR-9.2 |
| **ATK-010** | Sandbox-Evasion / Anti-Analyse | Verhaltensbasiert | 🟠 mittel | SR-10.3 |
| **ATK-011** | Transitive Verbreitung (wurmartige laterale Ausbreitung) | Verhaltensbasiert | 🔴 hoch | SR-11.4 |

> **Wie ausweichende Angriffe erkannt werden:** ATK-009 erkennt Pakete, die `process.env.CI` prüfen, Hostnamen sondieren oder zeitbasierte Aktivierung verwenden. ATK-010 markiert `debugger`-Anweisungen, `os.hostname()`-Sonden und Umgebungs-Fingerprinting. ATK-011 verfolgt Peer-Abhängigkeitsgraphen, um wurmartige Verbreitungsmuster zu erkennen.  
> Vollständige Dokumentation der Ausweichfläche und PoC-Beispiele finden Sie in [`docs/attack-taxonomy.md`](docs/attack-taxonomy.md).

---

## 📊 Ausgaben und Berichte

### Formate

| Format | Verfügbarkeit | Beschreibung |
|--------|-------------|-------------|
| JSON | ✅ Kostenlos | Strukturierte maschinenlesbare Ergebnisse |
| HTML | ✅ Kostenlos | Reichhaltiger HTML-Bericht mit NIST-Compliance-Tabelle, Schweregrad-Abzeichen, Kontrollmatrix |
| Text | ✅ Kostenlos | Sauberer, terminalfreundlicher Textbericht |
| CycloneDX SBOM | ✅ Kostenlos | Branchenstandard-SBOM mit Ergebnissen als Schwachstellen eingebettet |
| SPDX SBOM | ✅ Kostenlos | SPDX 2.3-Dokumentformat |
| NIST 800-161 | ✅ Kostenlos | Kontroll-Rückverfolgbarkeitsmatrix (SR-2.1 → SR-11.4) |
| EU CRA | ✅ Kostenlos | Zuordnung der Cyber Resilience Act-Artikel |
| PDF | 🔐 Premium | Mehrseitiges PDF mit Titelseite, Ergebnistabelle, NIST-Compliance-Matrix |
| Splunk CEF | 🔐 Premium | Common Event Format für Splunk-Erfassung |
| Elastic ECS | 🔐 Premium | Elastic Common Schema-Format |
| Microsoft Sentinel | 🔐 Premium | Sentinel-ready formatierte Ausgabe |
| IBM QRadar | 🔐 Premium | QRadar-DSM-ready-Format mit QID-Zuordnungen |

### Beispielausgabe

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

## ⚙️ Konfiguration und erweiterte Nutzung

### Policy-as-Code

Definieren Sie Whitelists, Schweregrad-Überschreibungen, Unterdrückungen und Fehlerschwellen in einer YAML-Datei:

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

### Umgebungsvariablen

| Variable | Beschreibung | Standard |
|----------|-------------|---------|
| `NPM_SCAN_LICENSE_KEY` | Premium-/Enterprise-Lizenzschlüssel | — |
| `NPM_SCAN_DATA_DIR` | Scan-Verlaufsverzeichnis | `./.npm-scan` |
| `NPM_SCAN_LOG_LEVEL` | Ausführlichkeitsgrad der Protokollierung | `info` |

### Premium-Lizenzierung

```bash
# Einen Entwicklerschlüssel generieren
node -e "console.log(require('@lateos/npm-scan/backend/license').generateKey('premium'))"

# Verwenden
npm-scan scan target --license-key <key>
npm-scan report --pdf --license-key <key>
npm-scan report --siem cef --license-key <key>
```

---

## 🔗 Integrationen

### GitHub Actions CI (für dieses Repository)

Jeder Push und PR führt Tests auf Node 18, 20 und 22 aus:

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

### GitHub Action (für nachgelagerte Benutzer)

Scannen Sie die `package-lock.json` Ihres Projekts bei jedem PR — erkennt Typosquatting, obfuskierte Payloads, Credential-Stealer und Wurmverbreitung, bevor sie die Produktion erreichen:

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

#### Action-Eingaben

| Eingabe | Standard | Beschreibung |
|-------|---------|-------------|
| `scan-type` | `lockfile` | `lockfile` zum Scannen von `package-lock.json` oder `package` zum Scannen eines bestimmten npm-Pakets |
| `package` | — | Paketname (erforderlich bei `scan-type=package`) |
| `fail-on` | `high` | Workflow bei diesem Schweregrad-Schwellwert fehlschlagen lassen: `none`, `low`, `medium`, `high`, `critical` |
| `policy-file` | — | Pfad zu einer YAML/JSON-Policy-Datei für Whitelists, Schweregrad-Überschreibungen und Unterdrückungen |
| `license-key` | — | Premium-Lizenzschlüssel für SIEM-Export und PDF-Berichte |
| `siem-format` | — | SIEM-Ausgabe: `cef`, `ecs`, `sentinel`, `qradar` (Premium) |
| `sbom-format` | — | SBOM-Ausgabe: `json`, `xml`, `spdx` |

#### Action-Ausgaben

| Ausgabe | Beschreibung |
|--------|-------------|
| `findings-count` | Anzahl der erkannten Ergebnisse |
| `scan-id` | Scan-ID für spätere Referenz in Berichten |

#### Beispiel: Bestimmtes Paket mit Policy + SBOM scannen

```yaml
- uses: lateos/npm-scan@main
  with:
    scan-type: package
    package: lodash
    policy-file: .npm-scan.yml
    sbom-format: spdx
    fail-on: critical
```

#### Beispiel: Mit SIEM-Export scannen (Premium)

```yaml
- uses: lateos/npm-scan@main
  with:
    scan-type: lockfile
    siem-format: cef
    license-key: ${{ secrets.NPM_SCAN_LICENSE_KEY }}
```

### CI/CD-Pipeline

Direkte Integration in Ihre bestehende Pipeline ohne die Composite-Action:

```bash
# Lock-Datei scannen, Build bei hohem Schweregrad fehlschlagen lassen
npm-scan scan-lockfile --policy .npm-scan.yml || exit 1

# Bestimmtes Paket scannen, nur bei kritisch fehlschlagen
npm-scan scan lodash --policy .npm-scan.yml || exit 1

# SBOM als Build-Artefakt generieren
npm-scan scan express --sbom spdx > express-sbom.spdx.json

# HTML-Compliance-Bericht in CI generieren
npm-scan report --html > report.html

# Bericht als Artefakt hochladen
# uses: actions/upload-artifact@v4
#   with:
#     name: npm-scan-report
#     path: report.html
```

### Docker

```bash
# Pull and run
docker pull ghcr.io/lateos/npm-scan:cli
docker run --rm ghcr.io/lateos/npm-scan:cli scan lodash

# Vollständige Pipeline mit Compose (Redis-basierte Warteschlange)
docker compose --profile pipeline up -d

# CLI mit persistentem Speicher
docker compose --profile cli up -d
```

Multi-Arch-Images für `linux/amd64` und `linux/arm64` verfügbar.

### GitHub Action (für nachgelagerte Benutzer)

Scannen Sie die `package-lock.json` Ihres Projekts bei jedem PR — erkennt Typosquatting, obfuskierte Payloads, Credential-Stealer und Wurmverbreitung, bevor sie die Produktion erreichen:

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

#### Action-Eingaben

| Eingabe | Standard | Beschreibung |
|-------|---------|-------------|
| `scan-type` | `lockfile` | `lockfile` zum Scannen von `package-lock.json` oder `package` zum Scannen eines bestimmten npm-Pakets |
| `package` | — | Paketname (erforderlich bei `scan-type=package`) |
| `fail-on` | `high` | Workflow bei diesem Schweregrad-Schwellwert fehlschlagen lassen: `none`, `low`, `medium`, `high`, `critical` |
| `policy-file` | — | Pfad zu einer YAML/JSON-Policy-Datei für Whitelists, Schweregrad-Überschreibungen und Unterdrückungen |
| `license-key` | — | Premium-Lizenzschlüssel für SIEM-Export und PDF-Berichte |
| `siem-format` | — | SIEM-Ausgabe: `cef`, `ecs`, `sentinel`, `qradar` (Premium) |
| `sbom-format` | — | SBOM-Ausgabe: `json`, `xml`, `spdx` |

#### Action-Ausgaben

| Ausgabe | Beschreibung |
|--------|-------------|
| `findings-count` | Anzahl der erkannten Ergebnisse |
| `scan-id` | Scan-ID für spätere Referenz in Berichten |

#### Beispiel: Bestimmtes Paket mit Policy + SBOM scannen

```yaml
- uses: lateos/npm-scan@main
  with:
    scan-type: package
    package: lodash
    policy-file: .npm-scan.yml
    sbom-format: spdx
    fail-on: critical
```

#### Beispiel: Mit SIEM-Export scannen (Premium)

```yaml
- uses: lateos/npm-scan@main
  with:
    scan-type: lockfile
    siem-format: cef
    license-key: ${{ secrets.NPM_SCAN_LICENSE_KEY }}
```

### CI/CD-Pipeline

Direkte Integration in Ihre bestehende Pipeline ohne die Composite-Action:

```bash
# Lock-Datei scannen, Build bei hohem Schweregrad fehlschlagen lassen
npm-scan scan-lockfile --policy .npm-scan.yml || exit 1

# Bestimmtes Paket scannen, nur bei kritisch fehlschlagen
npm-scan scan lodash --policy .npm-scan.yml || exit 1

# SBOM als Build-Artefakt generieren
npm-scan scan express --sbom spdx > express-sbom.spdx.json

# HTML-Compliance-Bericht in CI generieren
npm-scan report --html > report.html

# Bericht als Artefakt hochladen
# uses: actions/upload-artifact@v4
#   with:
#     name: npm-scan-report
#     path: report.html
```

### Docker

```bash
# Pull and run
docker pull ghcr.io/lateos/npm-scan:cli
docker run --rm ghcr.io/lateos/npm-scan:cli scan lodash

# Vollständige Pipeline mit Compose (Redis-basierte Warteschlange)
docker compose --profile pipeline up -d

# CLI mit persistentem Speicher
docker compose --profile cli up -d
```

Multi-Arch-Images für `linux/amd64` und `linux/arm64` verfügbar.

---

## 🗺️ Roadmap und Enterprise-Funktionen

### Kostenlose Stufe (ausgeliefert)

- Alle 11 ATK-Detektoren (statisch + verhaltensbasiert)
- SBOM-Ausgabe (CycloneDX + SPDX)
- HTML-, Text- und Compliance-Berichte (NIST + EU CRA)
- Policy-as-Code-Engine (YAML)
- Lokaler SQLite-Scan-Verlauf
- GitHub Action
- Docker-Images + Compose-Pipeline

### Premium (🔐 Lizenzschlüssel)

- PDF-Compliance-Berichte mit NIST-Rückverfolgbarkeitsmatrix
- SIEM-Export (Splunk CEF, Elastic ECS, Microsoft Sentinel, IBM QRadar)
- Dynamische Sandbox (gVisor-basiert — ATK-008–010)
- Erreichbarkeitsanalyse (Call-Graph-Filterung)

### Enterprise (🏢 benutzerdefinierte Lizenz)

- SAML 2.0 SSO (Okta, Azure AD, OneLogin, Keycloak)
- REST-API + Webhooks (FastAPI)
- Team-RBAC + Audit-Logs
- Helm-Chart für Kubernetes-Bereitstellung
- PostgreSQL-Backend für gehostete/Team-Stufe
- SLA-gestützter Prioritätssupport

---

## 🤝 Beitragen

Wir begrüßen Beiträge — insbesondere neue Detektoren, verbesserte Ausweichresistenz und Compliance-Vorlagen.

Siehe [`docs/attack-taxonomy.md`](docs/attack-taxonomy.md) für den ATK-Governance-Prozess. Jeder neue Detektor erfordert:

1. Ein Proof-of-Concept-Beispiel
2. Eine Erkennungsregel mit Tests
3. False-Positive-Analyse auf den Top-500-npm-Paketen
4. NIST 800-161-Control-Zuordnung

### Tests

Das Projekt verwendet den **nativen Node.js-Test-Runner** (`node:test` + `assert/strict`).

```bash
# Alle Tests ausführen
npm test

# Tests mit Codeabdeckung ausführen
npm run test:coverage

# Tests mit ausführlicher Ausgabe ausführen
npm run test:verbose

# Lokales bösartiges/sauberes Korpus ausführen (kein Netzwerk erforderlich)
node --test test/detectors-corpus.test.js
```

**Teststruktur:**
- `test/fixtures/mock-data.js` — gemeinsam genutzte Mock-Scans, Pakete und Code-Snippets
- `test/db.test.js` — Datenbank-CRUD (Speichern, Abfragen, Persistieren)
- `test/detectors-edge-cases.test.js` — detektorspezifische Grenztests (No-Ops, saubere Bereinigung, Schweregrad)
- `test/detectors-corpus.test.js` — 33 bösartige + 50 saubere Tarball-Integrationstests (offline)
- `test/fetch.test.js` — Tarball-Extraktion, Bereinigung temporärer Verzeichnisse
- `test/policy-edge-cases.test.js` — Grenzfälle bei Unterdrückung, Überschreibung, Ladevalidierung
- `test/report-snapshots.test.js` — HTML/Text/CRA/PDF-Format-Assertions
- `test/cli.test.js` — Commander-Integrationstests (Hilfe, Version, Scan, Bericht, Fehlerbehandlung)

### Hilfe benötigt?

- 📖 Lesen Sie den [Projektplan](docs/project-plan.md)
- 🧬 Überprüfen Sie die [Angriffstaxonomie](docs/attack-taxonomy.md)
- 🐛 Öffnen Sie ein Issue oder PR

---

## 📄 Lizenz

Apache-2.0 Core + Commons Clause.  
Siehe [`LICENSING.md`](LICENSING.md) für die genaue Grenze zwischen kostenlosen und Premium-Funktionen.

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

**Scannen Sie Ihr erstes Paket jetzt:**

```bash
npx @lateos/npm-scan scan lodash
```