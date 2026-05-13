# @lateos/npm-scan

[![English](https://img.shields.io/badge/lang-en-blue?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.md)
[![中文](https://img.shields.io/badge/lang-zh--CN-red?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.zh.md)
[![日本語](https://img.shields.io/badge/lang-ja-purple?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.ja.md)
[![Français](https://img.shields.io/badge/lang-fr-orange?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.fr.md)
[![Deutsch](https://img.shields.io/badge/lang-de-green?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.de.md)

[![npm version](https://img.shields.io/npm/v/@lateos/npm-scan?style=flat-square)](https://www.npmjs.com/package/@lateos/npm-scan)
[![License](https://img.shields.io/badge/license-Apache%202.0%20%2B%20Commons%20Clause-blue?style=flat-square)](LICENSING.md)
[![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen?style=flat-square)](package.json)
[![Tests](https://img.shields.io/badge/tests-222%20passing-brightgreen?style=flat-square)](https://github.com/lateos-ai/npm-scan)
[![Coverage](https://img.shields.io/badge/coverage-85%25-yellowgreen?style=flat-square)](https://github.com/lateos-ai/npm-scan)
[![Docker](https://img.shields.io/badge/docker-ghcr.io%2Flateos%2Fnpm--scan-2496ED?style=flat-square&logo=docker)](https://github.com/lateos-ai/npm-scan/pkgs/container/npm-scan)
[![Sigstore](https://img.shields.io/static/v1?label=Sigstore&message=Provenance&color=green&style=flat-square&logo=sigstore)](https://github.com/lateos-ai/npm-scan/actions/workflows/publish.yml)

**npmエコシステムのためのモダンなサプライチェーンセキュリティ。**  
静的解析＋行動分析で、npm audit、Snyk、Socketが見逃す脅威——難読化ペイロード、認証情報窃取、条件付きトリガー、サンドボックス回避、ワーム型伝播——を検出します。

---

## 📌 問題

2025～2026年のnpmサプライチェーン攻撃の波は、従来のツールがもはや十分ではないことを証明しました。

攻撃者は単純なタイポスクワッティングを超えています。今や彼らは**難読化されたプリインストールフック**、**環境検出の背後に隠れた認証情報窃取ツール**、**時間ベースのアクティベーションによる潜伏バックドア**、そしてピア依存関係を通じて拡散する**ワーム型の推移的伝播**を仕掛けています。

**npm audit**は既知のCVEをチェックします。**Snyk**は脆弱性をスキャンします。**Socket**はパッケージの動作を分析します。しかし、これらは2025年に出現した攻撃——本番環境に到達するまで無害に見える攻撃——のために設計されたものではありません。

**@lateos/npm-scan**はこの瞬間のために作られました。

---

## 🔬 なぜ@lateos/npm-scanなのか？

| 機能 | npm audit | Snyk | Socket | **@lateos/npm-scan** |
|---|---|---|---|---|
| 既知CVEマッチング | ✅ | ✅ | ❌ | ✅ |
| 静的解析 | ❌ | ✅ | ✅ | ✅ |
| 難読化ペイロード検出 | ❌ | ❌ | ❌ | ✅ |
| 行動/ヒューリスティック分析 | ❌ | ❌ | 部分的 | ✅ |
| 条件付きトリガー検出 (ATK-009) | ❌ | ❌ | ❌ | ✅ |
| サンドボックス回避検出 (ATK-010) | ❌ | ❌ | ❌ | ✅ |
| 推移的ワーム伝播 (ATK-011) | ❌ | ❌ | ❌ | ✅ |
| 攻撃分類 (ATKシリーズ) | ❌ | ❌ | ❌ | ✅ |
| SBOM出力 (CycloneDX + SPDX) | ❌ | ✅ | ❌ | ✅ |
| NIST 800-161コンプライアンス報告 | ❌ | ❌ | ❌ | ✅ |
| EU CRAコンプライアンス報告 | ❌ | ❌ | ❌ | ✅ |
| SIEMエクスポート (CEF / ECS / Sentinel / QRadar) | ❌ | ❌ | ❌ | ✅ |
| 完全ローカル実行——テレメトリなし | ✅ | ❌ | ❌ | ✅ |
| ポリシー・アズ・コード (YAML許可リスト) | ❌ | ❌ | ❌ | ✅ |

> **プライバシー第一。** すべてのスキャンはお使いのマシン上で実行されます。コードが環境外に送信されることはありません。テレメトリはありません。クラウド依存もありません。

---

## ✨ 主要機能

| アイコン | 機能 | 説明 |
|------|---------|-------------|
| 🕵️ | **ヒューリスティック静的解析** | ASTレベルの検査で、正規表現ベースのツールでは見逃す難読化、evalチェーン、環境プロービング、疑わしいライフサイクルスクリプトを捕捉 |
| 🧠 | **行動検出** | 条件付きトリガー（時間ベース、CI認識）、サンドボックス回避、潜伏アクティベーションパターンを識別 |
| 🧬 | **ATK攻撃分類** | NIST 800-161マッピング付き11の分類攻撃タイプ——バージョン管理、文書化、PR対応 |
| 📦 | **SBOM生成** | CycloneDX 1.5およびSPDX 2.3、発見項目は脆弱性として埋め込み |
| 🧾 | **コンプライアンス報告** | NIST SP 800-161トレーサビリティマトリックス＋EUサイバーレジリエンス法マッピング（無料） |
| 🔌 | **SIEMエクスポート** | Splunk CEF、Elastic ECS、Microsoft Sentinel、IBM QRadar形式（プレミアム） |
| 📜 | **ポリシー・アズ・コード** | YAML/JSONポリシーエンジン、許可リスト、重要度上書き、抑制、失敗しきい値をサポート |
| 🐳 | **Docker + GitHub Action** | マルチアーキテクチャイメージ、ワンコマンドComposeパイプライン、PRスキャンアクション |
| 🛡️ | **ゼロテレメトリ** | データはあなたのマシンから離れません。クラウドなし。コールバックなし。 |
| 💾 | **ローカルスキャン履歴** | SQLite駆動の永続化、外部依存関係ゼロ |

---

## ⚡ クイックスタート

```bash
# グローバルインストール
npm install -g @lateos/npm-scan

# 単一パッケージをスキャン
npm-scan scan lodash

# ロックファイルをスキャン
npm-scan scan-lockfile

# 最新のスキャンを表示
npm-scan report
```

**インストール不要？問題ありません：**

```bash
npx @lateos/npm-scan scan commander
```

---

## 🐳 Dockerで@lateos/npm-scanをどこでも実行 — インストール不要

```bash
# 単一スキャンをプルして実行 — Node.jsやnpmは不要
docker run --rm ghcr.io/lateos/npm-scan:cli scan lodash

# 永続ストレージとComposeを使用した完全パイプライン
docker compose --profile pipeline up -d
```

Node.js不要。`npm install`不要。グローバルパッケージ不要。Dockerがあればどんなシステムでも動作——CIサーバー、エアギャップ環境、Kubernetesクラスター。`linux/amd64`および`linux/arm64`向けマルチアーキテクチャイメージ。

---

## 🛡️ 政府機関・SOC 2 対応

| 機能 | SOC 2 コントロール | NIST 800-161 | STIG/FedRAMP アライメント |
|------|-------|--------------|--------------|
| 監査ログ (--audit-log) | CC6.8 | AU-2 | ✓ |
| FIPS暗号化 (--fips) | CC6.1 | SC-13 | ✓ |
| STIGレポート (--stig) | CC7.3 | RA-5 | ✓ |
| オフラインキャッシュ (--cache-dir) | A1.2 | SC-8 | ✓ |
| Sigstoreプロvenes | CC6.2 | SI-7 | ✓ |
| SBOM (SPDX/CycloneDX) | CC7.4 | SA-10 | ✓ |

```bash
# エアギャップ環境での完全なコンプライアンススキャンを実行
npm-scan scan-lockfile --cache-dir /offline/cache --audit-log /var/log/npm-scan.audit --fips
npm-scan report --stig
```

---

## 📖 使用例

### 単一パッケージのスキャン

```bash
# デフォルトのJSON出力ですべての発見項目を表示
npm-scan scan axios

# スキャンと同時にSBOMを生成
npm-scan scan express --sbom             # CycloneDX JSON
npm-scan scan express --sbom xml         # CycloneDX XML
npm-scan scan express --sbom spdx        # SPDX 2.3

# YAMLポリシーを適用
npm-scan scan some-package --policy .npm-scan.yml

# ローカルtarballをスキャン（レジストリからの取得不要）
npm-scan scan --file path/to/malicious-package.tgz
```

### ロックファイルのスキャン

```bash
# 現在のプロジェクトの依存関係をスキャン
npm-scan scan-lockfile

# 特定のロックファイルをスキャン
npm-scan scan-lockfile -f ./path/to/package-lock.json

# 高重大または致命的な問題でCI/CDを失敗させる（終了コード1）
npm-scan scan-lockfile --fail-on high

# 任何の発見項目でビルドを失敗させる（low以上）
npm-scan scan-lockfile --fail-on low

# SARIF v2.1出力を生成（GitHub Advanced Security / VS Code向け）
npm-scan scan-lockfile --sarif results.sarif

# リスクスコアのみを出力（0-10）（ダッシュボード/閾値向け）
npm-scan scan-lockfile --score-only
```

### レポートの生成

```bash
# 最近のスキャンをすべて一覧表示
npm-scan report

# 特定のスキャンを表示
npm-scan report -i 42

# HTMLレポートを生成（無料）、完全な発見項目＋NIST表付き
npm-scan report -i 42 --html

# NIST 800-161コンプライアンス表を印刷
npm-scan report -i 42 --nist

# EU CRAコンプライアンス表を印刷
npm-scan report --cra

# テキストレポート（無料）
npm-scan report --text

# PDFレポート（プレミアム）
npm-scan report --pdf --license-key <key>

# SIEMエクスポート（プレミアム）
npm-scan report --siem cef        # Splunk CEF
npm-scan report --siem ecs        # Elastic ECS
npm-scan report --siem sentinel   # Microsoft Sentinel
npm-scan report --siem qradar     # IBM QRadar

# すべてのスキャンを1つのレポートに統合
npm-scan report --html            # すべてのスキャン
npm-scan report --pdf             # すべてのスキャン（プレミアム）
```

---

## 🧬 検出機能（ATK分類）

| ID | 攻撃クラス | 検出方法 | 重要度 | NIST 800-161 |
|---|---|---|---|---|
| **ATK-001** | 悪意のあるライフサイクルスクリプト（`preinstall`、`postinstall`、`install`） | 静的 | 🔴 高 | SR-3.1 |
| **ATK-002** | 難読化ペイロード配信（hex、base64、evalチェーン） | 静的 | 🟠 中 | SR-4.2 |
| **ATK-003** | 認証情報収集（環境変数、.npmrc、SSH鍵） | 静的＋動的 | 🔴 高 | SR-5.3 |
| **ATK-004** | エディター/設定ディレクトリを介した永続化（.vscode、.claude、.cursor） | 静的 | 🔴 高 | SR-6.4 |
| **ATK-005** | ネットワーク外部漏洩（GitHub API、DNSトンネリング、HTTP C2） | 静的＋動的 | ⚫ クリティカル | SR-7.5 |
| **ATK-006** | 依存関係混乱／名前空間スクワッティング | 静的（ロックファイル） | 🟠 中 | SR-2.2 |
| **ATK-007** | タイポスクワッティング（編集距離マッチング） | 静的 | 🟢 低 | SR-2.1 |
| **ATK-008** | tarball改ざん（公開版≠ソース） | 静的 | 🔴 高 | SR-8.1 |
| **ATK-009** | 条件付き／潜伏トリガー（CI検出、時間ベース） | 行動 | 🔴 高 | SR-9.2 |
| **ATK-010** | サンドボックス回避／アンチ解析 | 行動 | 🟠 中 | SR-10.3 |
| **ATK-011** | 推移的伝播（ワーム型横方向拡散） | 行動 | 🔴 高 | SR-11.4 |

> **回避型攻撃の捕捉方法：** ATK-009は`process.env.CI`をチェックする、ホスト名をプローブする、または時間ベースのアクティベーションを使用するパッケージを検出します。ATK-010は`debugger`文、`os.hostname()`プローブ、環境フィンガープリンティングをフラグ付けします。ATK-011はピア依存関係グラフをトレースしてワーム型伝播パターンを検出します。  
> 完全な回避面のドキュメントとPoC例については、[`docs/attack-taxonomy.md`](docs/attack-taxonomy.md)を参照してください。

---

## 📊 出力とレポート

### 形式

| 形式 | 利用可能性 | 説明 |
|--------|-------------|-------------|
| JSON | ✅ 無料 | 構造化された機械可読な発見項目 |
| HTML | ✅ 無料 | NISTコンプライアンス表、重要度バッジ、コントロールマトリックス付きリッチHTMLレポート |
| テキスト | ✅ 無料 | クリーンな端末向けテキストレポート |
| CycloneDX SBOM | ✅ 無料 | 発見項目を脆弱性として埋め込んだ業界標準SBOM |
| SPDX SBOM | ✅ 無料 | SPDX 2.3文書形式 |
| NIST 800-161 | ✅ 無料 | コントロールトレーサビリティマトリックス（SR-2.1 → SR-11.4） |
| EU CRA | ✅ 無料 | サイバーレジリエンス法の条項マッピング |
| PDF | 🔐 プレミアム | タイトルページ、発見項目表、NISTコンプライアンスマトリックス付きマルチページPDF |
| Splunk CEF | 🔐 プレミアム | Splunk取り込み用共通イベント形式 |
| Elastic ECS | 🔐 プレミアム | Elastic Common Schema形式 |
| Microsoft Sentinel | 🔐 プレミアム | Sentinel対応のフォーマット済み出力 |
| IBM QRadar | 🔐 プレミアム | QIDマッピング付きQRadar DSM対応形式 |

### 出力サンプル

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

## ⚙️ 設定と高度な使い方

### ポリシー・アズ・コード

YAMLファイルで許可リスト、重要度上書き、抑制、失敗しきい値を定義：

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

### 環境変数

| 変数 | 説明 | デフォルト |
|----------|-------------|---------|
| `NPM_SCAN_LICENSE_KEY` | プレミアム／エンタープライズライセンスキー | — |
| `NPM_SCAN_DATA_DIR` | スキャン履歴ディレクトリ | `./.npm-scan` |
| `NPM_SCAN_LOG_LEVEL` | ログの詳細レベル | `info` |

### プレミアムライセンス

leo@lateos.ai までお問い合わせいただき、高级版/エンタープライズ版ライセンスキーを取得してください。

```bash
# それを使用
npm-scan scan target --license-key <key>
npm-scan report --pdf --license-key <key>
npm-scan report --siem cef --license-key <key>
```

---

## 🔗 インテグレーション

### GitHub Actions CI（このリポジトリ用）

プッシュとPRごとにNode 18、20、22でテストを実行：

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

### GitHub Action（ダウンストリームユーザー向け）

すべてのPRでプロジェクトの`package-lock.json`をスキャン——タイポスクワッティング、難読化ペイロード、認証情報窃取ツール、ワーム伝播を本番環境に到達する前に検出：

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

#### Action入力

| 入力 | デフォルト | 説明 |
|-------|---------|-------------|
| `scan-type` | `lockfile` | `lockfile`は`package-lock.json`をスキャン、`package`は特定のnpmパッケージをスキャン |
| `package` | — | パッケージ名（`scan-type=package`時に必須） |
| `fail-on` | `high` | この重要度しきい値でワークフローを失敗させる：`none`、`low`、`medium`、`high`、`critical` |
| `policy-file` | — | 許可リスト、重要度上書き、抑制用のYAML/JSONポリシーファイルへのパス |
| `license-key` | — | SIEMエクスポートとPDFレポート用のプレミアムライセンスキー |
| `siem-format` | — | SIEM出力：`cef`、`ecs`、`sentinel`、`qradar`（プレミアム） |
| `sbom-format` | — | SBOM出力：`json`、`xml`、`spdx` |

#### Action出力

| 出力 | 説明 |
|--------|-------------|
| `findings-count` | 検出された発見項目の数 |
| `scan-id` | 後でレポートで参照するためのスキャンID |

#### 例：ポリシー＋SBOMで特定パッケージをスキャン

```yaml
- uses: lateos/npm-scan@main
  with:
    scan-type: package
    package: lodash
    policy-file: .npm-scan.yml
    sbom-format: spdx
    fail-on: critical
```

#### 例：SIEMエクスポートでスキャン（プレミアム）

```yaml
- uses: lateos/npm-scan@main
  with:
    scan-type: lockfile
    siem-format: cef
    license-key: ${{ secrets.NPM_SCAN_LICENSE_KEY }}
```

### CI/CDパイプライン

複合アクションを使わずに既存のパイプラインに直接統合：

```bash
# ロックファイルをスキャン、高重要度でビルドを失敗
npm-scan scan-lockfile --policy .npm-scan.yml || exit 1

# 特定のパッケージをスキャン、クリティカルのみで失敗
npm-scan scan lodash --policy .npm-scan.yml || exit 1

# SBOMをビルドアーティファクトとして生成
npm-scan scan express --sbom spdx > express-sbom.spdx.json

# CIでHTMLコンプライアンスレポートを生成
npm-scan report --html > report.html

# レポートをアーティファクトとしてアップロード
# uses: actions/upload-artifact@v4
#   with:
#     name: npm-scan-report
#     path: report.html
```

### Docker

上記の[Dockerクイックスタート](#-dockerでlateosnpm-scanをどこでも実行--インストール不要)セクションを参照してください。プルコマンド、Composeパイプライン、マルチアーキテクチャイメージについて説明しています。

すべてのPRでプロジェクトの`package-lock.json`をスキャン——タイポスクワッティング、難読化ペイロード、認証情報窃取ツール、ワーム伝播を本番環境に到達する前に検出：

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

#### Action入力

| 入力 | デフォルト | 説明 |
|-------|---------|-------------|
| `scan-type` | `lockfile` | `lockfile`は`package-lock.json`をスキャン、`package`は特定のnpmパッケージをスキャン |
| `package` | — | パッケージ名（`scan-type=package`時に必須） |
| `fail-on` | `high` | この重要度しきい値でワークフローを失敗させる：`none`、`low`、`medium`、`high`、`critical` |
| `policy-file` | — | 許可リスト、重要度上書き、抑制用のYAML/JSONポリシーファイルへのパス |
| `license-key` | — | SIEMエクスポートとPDFレポート用のプレミアムライセンスキー |
| `siem-format` | — | SIEM出力：`cef`、`ecs`、`sentinel`、`qradar`（プレミアム） |
| `sbom-format` | — | SBOM出力：`json`、`xml`、`spdx` |

#### Action出力

| 出力 | 説明 |
|--------|-------------|
| `findings-count` | 検出された発見項目の数 |
| `scan-id` | 後でレポートで参照するためのスキャンID |

#### 例：ポリシー＋SBOMで特定パッケージをスキャン

```yaml
- uses: lateos/npm-scan@main
  with:
    scan-type: package
    package: lodash
    policy-file: .npm-scan.yml
    sbom-format: spdx
    fail-on: critical
```

#### 例：SIEMエクスポートでスキャン（プレミアム）

```yaml
- uses: lateos/npm-scan@main
  with:
    scan-type: lockfile
    siem-format: cef
    license-key: ${{ secrets.NPM_SCAN_LICENSE_KEY }}
```

### CI/CDパイプライン

複合アクションを使わずに既存のパイプラインに直接統合：

```bash
# ロックファイルをスキャン、高重要度でビルドを失敗
npm-scan scan-lockfile --policy .npm-scan.yml || exit 1

# 特定のパッケージをスキャン、クリティカルのみで失敗
npm-scan scan lodash --policy .npm-scan.yml || exit 1

# SBOMをビルドアーティファクトとして生成
npm-scan scan express --sbom spdx > express-sbom.spdx.json

# CIでHTMLコンプライアンスレポートを生成
npm-scan report --html > report.html

# レポートをアーティファクトとしてアップロード
# uses: actions/upload-artifact@v4
#   with:
#     name: npm-scan-report
#     path: report.html
```

### Docker

上記の[Dockerクイックスタート](#-dockerでlateosnpm-scanをどこでも実行--インストール不要)セクションを参照してください。プルコマンド、Composeパイプライン、マルチアーキテクチャイメージについて説明しています。

---

## 🗺️ ロードマップとエンタープライズ機能

### 無料版（出荷済み）

- 全11ATK検出器（静的＋行動）
- SBOM出力（CycloneDX + SPDX）
- HTML、テキスト、コンプライアンスレポート（NIST + EU CRA）
- ポリシー・アズ・コードエンジン（YAML）
- ローカルSQLiteスキャン履歴
- GitHub Action
- Dockerイメージ＋Composeパイプライン

### プレミアム（🔐 ライセンスキー）

- NISTトレーサビリティマトリックス付きPDFコンプライアンスレポート
- SIEMエクスポート（Splunk CEF、Elastic ECS、Microsoft Sentinel、IBM QRadar）
- 動的サンドボックス（gVisorベース — ATK-008–010）
- 到達可能性分析（コールグラフフィルタリング）

### エンタープライズ（🏢 カスタムライセンス）

- SAML 2.0 SSO（Okta、Azure AD、OneLogin、Keycloak）
- REST API + webhooks（FastAPI）
- チームRBAC＋監査ログ
- Kubernetes展開用Helmチャート
- ホスティング/チーム階層向けPostgreSQLバックエンド
- SLA保証付き優先サポート

---

## 🤝 コントリビューション

コントリビューションを歓迎します——特に新しい検出器、回避耐性の向上、コンプライアンステンプレートを募集しています。

ATKガバナンスプロセスについては[`docs/attack-taxonomy.md`](docs/attack-taxonomy.md)を参照してください。新しい検出器には以下が必要です：

1. 概念実証サンプル
2. テスト付き検出ルール
3. トップ500 npmパッケージに対する誤検出分析
4. NIST 800-161コントロールマッピング

### テスト

このプロジェクトは**Node.jsネイティブテストランナー**（`node:test` + `assert/strict`）を使用しています。

```bash
# すべてのテストを実行
npm test

# カバレッジ付きでテストを実行
npm run test:coverage

# 詳細な出力付きでテストを実行
npm run test:verbose

# ローカルの悪意／クリーンコーパスを実行（ネットワーク不要）
node --test test/detectors-corpus.test.js
```

**テスト構造：**
- `test/fixtures/mock-data.js` — 共有モックスキャン、パッケージ、コードスニペット
- `test/db.test.js` — データベースCRUD（保存、クエリ、永続化）
- `test/detectors-edge-cases.test.js` — 検出器ごとの境界テスト（no-op、クリーンクリア、重要度）
- `test/detectors-corpus.test.js` — 33悪意＋50クリーンtarball統合テスト（オフライン）
- `test/fetch.test.js` — tarball抽出、一時ディレクトリクリーンアップ
- `test/policy-edge-cases.test.js` — 抑制、上書き、ロード検証のエッジケース
- `test/report-snapshots.test.js` — HTML/テキスト/CRA/PDF形式のアサーション
- `test/cli.test.js` — commander統合テスト（ヘルプ、バージョン、スキャン、レポート、エラーハンドリング）

### ヘルプが必要ですか？

- 🔒 [セキュリティポリシー](SECURITY.md)で脆弱性の開示方法を確認
- 📖 [プロジェクト計画](docs/project-plan.md)を読む
- 🧬 [攻撃分類](docs/attack-taxonomy.md)を確認
- 🐛 IssueまたはPRを開く

---

## 📄 ライセンス

Apache-2.0コア＋Commons Clause。  
無料版とプレミアム版機能の正確な境界については[`LICENSING.md`](LICENSING.md)を参照してください。

---

## 👤 メンテナーについて

**Roongrunchai Chongolnee** — `@lateos/npm-scan` の作成者兼メンテナー。CISSP、CEH、Cisco Security、AWS Cloud Practitioner の認定を持つセキュリティ専門家で、Philips で10年間のインフラおよびアプリケーションセキュリティの経験があります。このツールは、オープンソースコミュニティに実用的で検出器駆動型のサプライチェーン型マルウェア防御を提供するために構築しました。透明性、コミュニティ所有、継続的改善に取り組んでいます。

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/roongrunchai-chong-c-ab9742108/)
[![GitHub](https://img.shields.io/badge/GitHub-lateos--ai-181717?style=flat-square&logo=github)](https://github.com/lateos-ai/npm-scan)

Issue、アイデア、PRはいつでも歓迎します——セキュリティは協力によって最も強力になります。

---

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

**最初のパッケージを今すぐスキャン：**

```bash
npx @lateos/npm-scan scan lodash
```