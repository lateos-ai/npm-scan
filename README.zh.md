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

**适用于 npm 生态系统的现代供应链安全工具。**  
静态 + 行为分析，捕获 npm audit、Snyk 和 Socket 遗漏的威胁——混淆载荷、凭证窃取器、条件触发器、沙箱逃逸以及蠕虫式传播。

---

## 📌 问题

2025–2026 年 npm 供应链攻击浪潮证明，传统工具已无法应对。

攻击者早已超越简单的域名抢注。他们现在投放的是**混淆的预安装钩子**、**隐藏在环境检测背后的凭证窃取器**、**基于时间激活的潜伏后门**，以及通过同级依赖传播的**蠕虫式传递传播**。

**npm audit** 检查已知 CVE。**Snyk** 扫描漏洞。**Socket** 分析包行为。但它们都不是为了应对 2025 年涌现的攻击而设计的——那些在进入生产环境之前看似无害的攻击。

**@lateos/npm-scan** 为此而生。

---

## 🔬 为什么选择 @lateos/npm-scan？

| 能力 | npm audit | Snyk | Socket | **@lateos/npm-scan** |
|---|---|---|---|---|
| 已知 CVE 匹配 | ✅ | ✅ | ❌ | ✅ |
| 静态分析 | ❌ | ✅ | ✅ | ✅ |
| 混淆载荷检测 | ❌ | ❌ | ❌ | ✅ |
| 行为/启发式分析 | ❌ | ❌ | 部分 | ✅ |
| 条件触发器检测 (ATK-009) | ❌ | ❌ | ❌ | ✅ |
| 沙箱逃逸检测 (ATK-010) | ❌ | ❌ | ❌ | ✅ |
| 传递性蠕虫传播 (ATK-011) | ❌ | ❌ | ❌ | ✅ |
| 攻击分类 (ATK 系列) | ❌ | ❌ | ❌ | ✅ |
| SBOM 输出 (CycloneDX + SPDX) | ❌ | ✅ | ❌ | ✅ |
| NIST 800-161 合规报告 | ❌ | ❌ | ❌ | ✅ |
| EU CRA 合规报告 | ❌ | ❌ | ❌ | ✅ |
| SIEM 导出 (CEF / ECS / Sentinel / QRadar) | ❌ | ❌ | ❌ | ✅ |
| 完全本地运行——无遥测 | ✅ | ❌ | ❌ | ✅ |
| 策略即代码 (YAML 白名单) | ❌ | ❌ | ❌ | ✅ |

> **隐私优先。** 所有扫描在您的机器上完成。没有代码离开您的环境。没有遥测。没有云依赖。

---

## ✨ 核心功能

| 图标 | 功能 | 描述 |
|------|---------|-------------|
| 🕵️ | **启发式静态分析** | AST 级别检查捕获混淆、eval 链、环境探测以及基于正则的工具遗漏的可疑生命周期脚本 |
| 🧠 | **行为检测** | 识别条件触发器（基于时间、CI 感知）、沙箱逃逸和潜伏激活模式 |
| 🧬 | **ATK 攻击分类** | 11 种分类攻击类型，附带 NIST 800-161 映射——可版本控制、可文档化、可 PR |
| 📦 | **SBOM 生成** | CycloneDX 1.5 和 SPDX 2.3，发现项嵌入为漏洞 |
| 🧾 | **合规报告** | NIST SP 800-161 可追溯性矩阵 + EU 网络弹性法案映射（免费） |
| 🔌 | **SIEM 导出** | Splunk CEF、Elastic ECS、Microsoft Sentinel、IBM QRadar 格式（高级版） |
| 📜 | **策略即代码** | YAML/JSON 策略引擎，支持白名单、严重性覆盖、抑制和失败阈值 |
| 🐳 | **Docker + GitHub Action** | 多架构镜像，一键 Compose 流水线，PR 扫描操作 |
| 🛡️ | **零遥测** | 没有数据离开您的机器。没有云。没有回调。 |
| 💾 | **本地扫描历史** | SQLite 驱动的持久化，零外部依赖 |

---

## ⚡ 快速开始

```bash
# 全局安装
npm install -g @lateos/npm-scan

# 扫描单个包
npm-scan scan lodash

# 扫描你的锁定文件
npm-scan scan-lockfile

# 查看最新扫描
npm-scan report
```

**无需安装？没问题：**

```bash
npx @lateos/npm-scan scan commander
```

---

## 🐳 在任何地方通过 Docker 运行 @lateos/npm-scan — 零安装

```bash
# 拉取并运行单次扫描 — 无需 Node.js 或 npm
docker run --rm ghcr.io/lateos/npm-scan:cli scan lodash

# 使用持久化存储和 Compose 的完整流水线
docker compose --profile pipeline up -d
```

无需 Node.js。无需 `npm install`。无需全局包。适用于任何拥有 Docker 的系统——CI 服务器、气隙环境、Kubernetes 集群。支持 `linux/amd64` 和 `linux/arm64` 的多架构镜像。

---

## 📖 使用示例

### 扫描单个包

```bash
# 默认 JSON 输出，包含所有发现
npm-scan scan axios

# 扫描时同时生成 SBOM
npm-scan scan express --sbom             # CycloneDX JSON
npm-scan scan express --sbom xml         # CycloneDX XML
npm-scan scan express --sbom spdx        # SPDX 2.3

# 应用 YAML 策略
npm-scan scan some-package --policy .npm-scan.yml

# 扫描本地 tarball（无需从注册表获取）
npm-scan scan --file path/to/malicious-package.tgz
```

### 扫描锁定文件

```bash
# 扫描当前项目的依赖
npm-scan scan-lockfile

# 扫描特定锁定文件
npm-scan scan-lockfile -f ./path/to/package-lock.json

# 在高危或严重问题时使 CI/CD 失败（退出码 1）
npm-scan scan-lockfile --fail-on high

# 任何发现项都使构建失败（low 及以上）
npm-scan scan-lockfile --fail-on low

# 生成 SARIF v2.1 输出，用于 GitHub Advanced Security / VS Code
npm-scan scan-lockfile --sarif results.sarif

# 仅输出风险分数（0-10）用于仪表板/阈值
npm-scan scan-lockfile --score-only
```

### 生成报告

```bash
# 列出所有最近的扫描
npm-scan report

# 查看特定扫描
npm-scan report -i 42

# 生成 HTML 报告（免费），包含完整的发现项 + NIST 表格
npm-scan report -i 42 --html

# 打印 NIST 800-161 合规表格
npm-scan report -i 42 --nist

# 打印 EU CRA 合规表格
npm-scan report --cra

# CSV 导出用于 Excel / Sheets（审计就绪）
npm-scan report --csv risks.csv
npm-scan scan lodash --csv          # CSV 输出到标准输出

# 文本报告（免费）
npm-scan report --text

# PDF 报告（高级版）
npm-scan report --pdf --license-key <key>

# SIEM 导出（高级版）
npm-scan report --siem cef        # Splunk CEF
npm-scan report --siem ecs        # Elastic ECS
npm-scan report --siem sentinel   # Microsoft Sentinel
npm-scan report --siem qradar     # IBM QRadar

# 合并所有扫描到单个报告
npm-scan report --html            # 所有扫描
npm-scan report --pdf             # 所有扫描（高级版）
```

---

## 🧬 检测能力（ATK 分类）

| ID | 攻击类型 | 检测方法 | 严重性 | NIST 800-161 |
|---|---|---|---|---|
| **ATK-001** | 恶意生命周期脚本（`preinstall`, `postinstall`, `install`） | 静态 | 🔴 高 | SR-3.1 |
| **ATK-002** | 混淆载荷投递（hex、base64、eval 链） | 静态 | 🟠 中 | SR-4.2 |
| **ATK-003** | 凭证窃取（环境变量、.npmrc、SSH 密钥） | 静态 + 动态 | 🔴 高 | SR-5.3 |
| **ATK-004** | 通过编辑器/配置目录持久化（.vscode、.claude、.cursor） | 静态 | 🔴 高 | SR-6.4 |
| **ATK-005** | 网络外泄（GitHub API、DNS 隧道、HTTP C2） | 静态 + 动态 | ⚫ 严重 | SR-7.5 |
| **ATK-006** | 依赖混淆 / 命名空间抢占 | 静态（锁定文件） | 🟠 中 | SR-2.2 |
| **ATK-007** | 域名抢注（编辑距离匹配） | 静态 | 🟢 低 | SR-2.1 |
| **ATK-008** | tarball 篡改（发布版 ≠ 源代码） | 静态 | 🔴 高 | SR-8.1 |
| **ATK-009** | 条件/潜伏触发器（CI 检测、基于时间） | 行为 | 🔴 高 | SR-9.2 |
| **ATK-010** | 沙箱逃逸 / 反分析 | 行为 | 🟠 中 | SR-10.3 |
| **ATK-011** | 传递性传播（蠕虫式横向扩散） | 行为 | 🔴 高 | SR-11.4 |

> **如何捕获逃避式攻击：** ATK-009 检测检查 `process.env.CI`、探测主机名或使用时间激活的包。ATK-010 标记 `debugger` 语句、`os.hostname()` 探测和环境指纹采集。ATK-011 追踪同级依赖图以检测蠕虫式传播模式。  
> 完整逃避面文档和 PoC 示例请参阅 [`docs/attack-taxonomy.md`](docs/attack-taxonomy.md)。

---

## 📊 输出与报告

### 格式

| 格式 | 可用性 | 描述 |
|--------|-------------|-------------|
| JSON | ✅ 免费 | 结构化机器可读的发现项 |
| HTML | ✅ 免费 | 丰富 HTML 报告，含 NIST 合规表、严重性徽章、控制矩阵 |
| 文本 | ✅ 免费 | 简洁的终端友好文本报告 |
| CycloneDX SBOM | ✅ 免费 | 行业标准 SBOM，发现项嵌入为漏洞 |
| SPDX SBOM | ✅ 免费 | SPDX 2.3 文档格式 |
| NIST 800-161 | ✅ 免费 | 控制可追溯性矩阵（SR-2.1 → SR-11.4） |
| EU CRA | ✅ 免费 | 网络弹性法案条款映射 |
| PDF | 🔐 高级版 | 多页 PDF，含标题页、发现项表格、NIST 合规矩阵 |
| Splunk CEF | 🔐 高级版 | 用于 Splunk 导入的通用事件格式 |
| Elastic ECS | 🔐 高级版 | Elastic 通用模式格式 |
| Microsoft Sentinel | 🔐 高级版 | Sentinel 就绪格式化输出 |
| IBM QRadar | 🔐 高级版 | QRadar DSM 就绪格式，含 QID 映射 |

### 示例输出

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

## ⚙️ 配置与高级用法

### 策略即代码

在 YAML 文件中定义白名单、严重性覆盖、抑制和失败阈值：

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

### 环境变量

| 变量 | 描述 | 默认值 |
|----------|-------------|---------|
| `NPM_SCAN_LICENSE_KEY` | 高级版/企业版许可证密钥 | — |
| `NPM_SCAN_DATA_DIR` | 扫描历史目录 | `./.npm-scan` |
| `NPM_SCAN_LOG_LEVEL` | 日志详细级别 | `info` |

### 高级版许可

```bash
# 生成开发密钥
node -e "console.log(require('@lateos/npm-scan/backend/license').generateKey('premium'))"

# 使用它
npm-scan scan target --license-key <key>
npm-scan report --pdf --license-key <key>
npm-scan report --siem cef --license-key <key>
```

---

## 🔗 集成

### GitHub Actions CI（针对本仓库）

每次推送和 PR 在 Node 18、20 和 22 上运行测试：

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

### GitHub Action（面向下游用户）

在每个 PR 上扫描您项目的 `package-lock.json`——在它们进入生产环境之前检测域名抢注、混淆载荷、凭证窃取器和蠕虫传播：

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

#### Action 输入

| 输入 | 默认值 | 描述 |
|-------|---------|-------------|
| `scan-type` | `lockfile` | `lockfile` 扫描 `package-lock.json` 或 `package` 扫描特定 npm 包 |
| `package` | — | 包名（`scan-type=package` 时需要） |
| `fail-on` | `high` | 在此严重性阈值处使工作流失败：`none`、`low`、`medium`、`high`、`critical` |
| `policy-file` | — | YAML/JSON 策略文件路径，用于白名单、严重性覆盖和抑制 |
| `license-key` | — | 用于 SIEM 导出和 PDF 报告的高级版许可证密钥 |
| `siem-format` | — | SIEM 输出：`cef`、`ecs`、`sentinel`、`qradar`（高级版） |
| `sbom-format` | — | SBOM 输出：`json`、`xml`、`spdx` |

#### Action 输出

| 输出 | 描述 |
|--------|-------------|
| `findings-count` | 检测到的发现项数量 |
| `scan-id` | 扫描 ID，用于后续报告引用 |

#### 示例：使用策略 + SBOM 扫描特定包

```yaml
- uses: lateos/npm-scan@main
  with:
    scan-type: package
    package: lodash
    policy-file: .npm-scan.yml
    sbom-format: spdx
    fail-on: critical
```

#### 示例：使用 SIEM 导出扫描（高级版）

```yaml
- uses: lateos/npm-scan@main
  with:
    scan-type: lockfile
    siem-format: cef
    license-key: ${{ secrets.NPM_SCAN_LICENSE_KEY }}
```

### CI/CD 流水线

直接集成到您现有的流水线中，无需复合操作：

```bash
# 扫描锁定文件，在高严重性时使构建失败
npm-scan scan-lockfile --policy .npm-scan.yml || exit 1

# 扫描特定包，仅在严重时失败
npm-scan scan lodash --policy .npm-scan.yml || exit 1

# 生成 SBOM 作为构建产物
npm-scan scan express --sbom spdx > express-sbom.spdx.json

# 在 CI 中生成 HTML 合规报告
npm-scan report --html > report.html

# 上传报告作为产物
# uses: actions/upload-artifact@v4
#   with:
#     name: npm-scan-report
#     path: report.html
```

### Docker

请参见上方的 [Docker 快速入门部分](#-在任何地方通过-docker-运行-lateosnpm-scan--零安装)，了解拉取命令、Compose 流水线和多架构镜像。

在每个 PR 上扫描您项目的 `package-lock.json`——在它们进入生产环境之前检测域名抢注、混淆载荷、凭证窃取器和蠕虫传播：

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

#### Action 输入

| 输入 | 默认值 | 描述 |
|-------|---------|-------------|
| `scan-type` | `lockfile` | `lockfile` 扫描 `package-lock.json` 或 `package` 扫描特定 npm 包 |
| `package` | — | 包名（`scan-type=package` 时需要） |
| `fail-on` | `high` | 在此严重性阈值处使工作流失败：`none`、`low`、`medium`、`high`、`critical` |
| `policy-file` | — | YAML/JSON 策略文件路径，用于白名单、严重性覆盖和抑制 |
| `license-key` | — | 用于 SIEM 导出和 PDF 报告的高级版许可证密钥 |
| `siem-format` | — | SIEM 输出：`cef`、`ecs`、`sentinel`、`qradar`（高级版） |
| `sbom-format` | — | SBOM 输出：`json`、`xml`、`spdx` |

#### Action 输出

| 输出 | 描述 |
|--------|-------------|
| `findings-count` | 检测到的发现项数量 |
| `scan-id` | 扫描 ID，用于后续报告引用 |

#### 示例：使用策略 + SBOM 扫描特定包

```yaml
- uses: lateos/npm-scan@main
  with:
    scan-type: package
    package: lodash
    policy-file: .npm-scan.yml
    sbom-format: spdx
    fail-on: critical
```

#### 示例：使用 SIEM 导出扫描（高级版）

```yaml
- uses: lateos/npm-scan@main
  with:
    scan-type: lockfile
    siem-format: cef
    license-key: ${{ secrets.NPM_SCAN_LICENSE_KEY }}
```

### CI/CD 流水线

直接集成到您现有的流水线中，无需复合操作：

```bash
# 扫描锁定文件，在高严重性时使构建失败
npm-scan scan-lockfile --policy .npm-scan.yml || exit 1

# 扫描特定包，仅在严重时失败
npm-scan scan lodash --policy .npm-scan.yml || exit 1

# 生成 SBOM 作为构建产物
npm-scan scan express --sbom spdx > express-sbom.spdx.json

# 在 CI 中生成 HTML 合规报告
npm-scan report --html > report.html

# 上传报告作为产物
# uses: actions/upload-artifact@v4
#   with:
#     name: npm-scan-report
#     path: report.html
```

### Docker

请参见上方的 [Docker 快速入门部分](#-在任何地方通过-docker-运行-lateosnpm-scan--零安装)，了解拉取命令、Compose 流水线和多架构镜像。

---

## 🗺️ 路线图与企业功能

### 免费版（已发布）

- 全部 11 个 ATK 检测器（静态 + 行为）
- SBOM 输出（CycloneDX + SPDX）
- HTML、文本和合规报告（NIST + EU CRA）
- 策略即代码引擎（YAML）
- 本地 SQLite 扫描历史
- GitHub Action
- Docker 镜像 + Compose 流水线

### 高级版（🔐 许可证密钥）

- PDF 合规报告，含 NIST 可追溯性矩阵
- SIEM 导出（Splunk CEF、Elastic ECS、Microsoft Sentinel、IBM QRadar）
- 动态沙箱（基于 gVisor — ATK-008–010）
- 可达性分析（调用图过滤）

### 企业版（🏢 自定义许可证）

- SAML 2.0 SSO（Okta、Azure AD、OneLogin、Keycloak）
- REST API + webhooks（FastAPI）
- 团队 RBAC + 审计日志
- 用于 Kubernetes 部署的 Helm Chart
- 用于托管/团队版的 PostgreSQL 后端
- SLA 保障的优先支持

---

## 🤝 贡献

我们欢迎贡献——特别是新的检测器、改进的逃避抵抗能力和合规模板。

请参阅 [`docs/attack-taxonomy.md`](docs/attack-taxonomy.md) 了解 ATK 治理流程。每个新的检测器需要：

1. 概念验证样本
2. 附带测试的检测规则
3. 对前 500 个 npm 包的误报分析
4. NIST 800-161 控制映射

### 测试

该项目使用 **Node.js 原生测试运行器**（`node:test` + `assert/strict`）。

```bash
# 运行所有测试
npm test

# 运行测试并带覆盖率
npm run test:coverage

# 运行测试并带详细输出
npm run test:verbose

# 运行本地恶意/清洁语料库（无需网络）
node --test test/detectors-corpus.test.js
```

**测试结构：**
- `test/fixtures/mock-data.js` — 共享的模拟扫描、包和代码片段
- `test/db.test.js` — 数据库 CRUD（保存、查询、持久化）
- `test/detectors-edge-cases.test.js` — 每个检测器的边界测试（无操作、清洁清除、严重性）
- `test/detectors-corpus.test.js` — 33 个恶意 + 50 个清洁 tarball 集成测试（离线）
- `test/fetch.test.js` — tarball 提取、临时目录清理
- `test/policy-edge-cases.test.js` — 抑制、覆盖、加载验证的边缘情况
- `test/report-snapshots.test.js` — HTML/文本/CRA/PDF 格式断言
- `test/cli.test.js` — commander 集成测试（帮助、版本、扫描、报告、错误处理）

### 需要帮助？

- 🔒 查看[安全策略](SECURITY.md)了解漏洞披露流程
- 📖 阅读[项目计划](docs/project-plan.md)
- 🧬 查看[攻击分类](docs/attack-taxonomy.md)
- 🐛 提交 issue 或 PR

---

## 📄 许可证

Apache-2.0 核心 + Commons Clause。  
请参阅 [`LICENSING.md`](LICENSING.md) 了解免费版和高级版功能之间的确切界限。

---

## 👤 关于维护者

**Roongrunchai Chongolnee** — `@lateos/npm-scan` 的创建者和维护者。持有 CISSP、CEH、思科安全、AWS 云从业者认证的安全专业人士，在飞利浦拥有十年的基础设施和应用安全经验。我构建这个工具是为了让开源社区拥有一个实用、检测器驱动的供应链恶意软件防御方案——我致力于保持其透明、社区拥有和持续改进。

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/roongrunchai-chong-c-ab9742108/)
[![GitHub](https://img.shields.io/badge/GitHub-lateos--ai-181717?style=flat-square&logo=github)](https://github.com/lateos-ai/npm-scan)

欢迎提交 issue、想法和 PR——安全在协作中最强大。

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

**立即扫描您的第一个包：**

```bash
npx @lateos/npm-scan scan lodash
```