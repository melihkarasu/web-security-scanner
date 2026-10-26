# Web Security Scanner 🛡️

> **Modular Web & Source-Code Security Auditing Suite**  
> Passive reconnaissance • Deep static analysis (SAST + AST/Taint) • Controlled active exploitation • Evidence-verified AI Red Teaming • Autonomous Strix Pentesting  
> Core server runs on Python 3 standard library. Optional Docker & Strix sandbox integration.

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-orange?style=for-the-badge)](https://melihkarasu.github.io/web-security-scanner/)
[![Local Mode](https://img.shields.io/badge/Local%20Mode-Python%203%20Stdlib-00b86b?style=for-the-badge)](#-quick-start)
[![Docker Ready](https://img.shields.io/badge/Docker-Supported-2496ed?style=for-the-badge)](#option-3-docker-mode-containerized)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)
[![Design: Mistral AI](https://img.shields.io/badge/Design-Mistral%20AI-fa520f?style=for-the-badge)](https://mistral.ai)

---

## Why This Exists

Most security tools force a trade-off between **convenient but shallow** online header checkers and **powerful but heavy** enterprise suites.

Web Security Scanner bridges that gap with a **Unified Single-Input Command Center** that scales across three execution tiers:

1. **Browser-Only Preview (GitHub Pages):** Instant DNS & email security posture checks (DMARC, SPF, DNSSEC, CAA, IPv6) via DNS-over-HTTPS (DoH) with zero installation.
2. **Core Local Mode (`python3 server.py`):** Runs on the Python 3 standard library with zero required `pip` or `npm` packages. Unlocks live HTTP header proxying, deep passive reconnaissance, local directory SAST (regex + Python AST + JS taint + entropy + Google OSV CVEs), ethics-gated active scanning (12 modules), and evidence-verified AI Red Team orchestration.
3. **Full Autonomous Pentest Mode (Local + Strix / Docker):** Integrates the [Strix](https://github.com/usestrix/strix) multi-agent CLI as a managed subprocess executing real proof-of-concept (PoC) exploits inside an isolated Docker sandbox.

---

## ✨ Capability Matrix

| Capability | GitHub Pages (Browser Mode) | Local / Docker Mode (`server.py`) |
|------------|-----------------------------|-----------------------------------|
| **DNS & Email Security** (DMARC, SPF, DNSSEC, CAA, IPv6, MX) | ✅ Live via Cloudflare/Google DoH | ✅ Live via Cloudflare/Google DoH |
| **HTTP Security Headers** (CSP, HSTS, XFO, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) | ❌ (CORS restricted in browser) | ✅ Automatic server-side fetch |
| **Subpath / URL Directory Scanning** (`example.com/app/login?id=1`) | ⚠️ Domain-level DNS only | ✅ Full path & query preservation |
| **Deep Passive Scan** (Cookie flags, TLS/Cert expiry & SAN, `robots.txt` exposure, Mixed Content, Tech Fingerprint) | ❌ | ✅ |
| **SAST — Local Directory Code Audit** (146 rules across 7 languages + Python AST + JS taint + Shannon entropy + 8-ecosystem Google OSV CVEs + **Supply Chain & Dependency Confusion Auditor** + **AI/LLM, CI/CD, JWT/OAuth & K8s rules** + **PHP 2026 Advisories (`php2shell` CVE-2026-109618/109619/115560)** + **Node.js Oct 2026 Security Releases (CVE-2026-111497 Brotli RCE & 10 CVEs)** + Git Diff mode + 4-phase AI Code Audit + 6-artifact `security-check` suite) | ❌ | ✅ (Standalone or hybrid with URL) |
| **Active Security Testing** (16 modules: SQLi, NoSQLi, SSTI, XSS, CSRF, SSRF, Open Redirect, IDOR, Active CORS, Live JWT & OAuth 2.0/OIDC, Active GraphQL, HPP & Cache Poisoning, Ports, Deep Headers, Browser Sim, Business Logic + 2-pass verification) | ❌ | ✅ (Ethics-gated + rate-limited) |
| **AI Red Team Orchestration** (Scout → Strategist → Analyst → Reporter, evidence-verified findings only) | ❌ | ✅ OpenAI-compatible / Gemini / Vertex AI / OpenRouter / Ollama |
| **Strix Autonomous AI Pentest** (100% CLI flag & env parity + Docker sandbox PoC generation + live sub-agent tree + `coverage.json` + SARIF 2.1.0/CSV/MD) | ❌ | ✅ (Requires `strix-agent` + Docker) |
| **Cloudflare Audit Lifecycle & Unified Coverage Ledger** (`Confirmed` / `Needs Validation` / `Hardening Notes` / `Rejected` + cross-engine Coverage Ledger) | ✅ (Passive/DNS) | ✅ Full across all engines |
| **Exportable Reports** (Markdown, JSON, HTML, SARIF 2.1.0, CSV, `SECURITY-REPORT.md`, `architecture.md`, `coverage-ledger.md`, `findings.json`) | Basic (DNS/Score) | ✅ Full multi-engine report |

> **Live Mode Indicator:** The top navigation bar and Command Center display live status badges (`🟢 Local Mode: Active` / `🔍 Deep Scan & SAST: Active` vs. `🟡 Static Mode`) so you always know which capabilities are available.

---

## 🚀 Quick Start — Choose Your Edition (`Lite` vs `Full`)

Web Security Scanner offers **two installation & runtime editions** from the same codebase, plus a zero-install browser preview. You can also switch between **⚡ Lite** and **🚀 Full (AI)** views at any time from the top navigation bar:

| Edition | Footprint & Dependencies | Included Capabilities | Best For |
|---------|--------------------------|-----------------------|----------|
| **⚡ Web Security Scanner Lite** *(Fast Install)* | **~2 MB**, Python 3 stdlib only, **0 pip packages, 0 Docker requirement, 0 LLM keys** | **All 7 Standard Deterministic Analyses:** HTTP Headers, DNS/Email, Deep Passive (Cookies/TLS Cipher+PFS/Robots/WAF+Tech), 146-Rule 7-Language SAST + Dependency Confusion + 8-Ecosystem OSV CVEs, and all 16 Active DAST Modules | Instant local/CI auditing in 2 seconds with zero setup |
| **🚀 Web Security Scanner Full** *(Comprehensive AI & Sandbox)* | Python 3 + `strix-agent` CLI + `strix-sandbox` Docker image (~1.4 GB) + LLM API key / local Ollama | **All 10 Analyses:** Everything in Lite **+** AI Red Team Orchestration, 4-Phase AI Semantic Code Audit, and Autonomous Container Sandbox Pentest (PoC + SARIF 2.1.0 + PR Fix) | Deep AI-driven red teaming and autonomous PoC validation |

### Option 1: Zero-Install Browser Preview (GitHub Pages)
Open **[melihkarasu.github.io/web-security-scanner](https://melihkarasu.github.io/web-security-scanner/)** in your browser.  
Performs passive DNS and email security auditing via DoH.

### Option 2: Terminal One-Command Install (`Lite` or `Full`)
```bash
# ⚡ 1) Fast Install — Web Security Scanner Lite (Zero dependencies, no LLM setup, ready in ~2s):
curl -fsSL https://raw.githubusercontent.com/melihkarasu/web-security-scanner/main/install.sh | bash -s -- --lite

# 🚀 2) Comprehensive Install — Web Security Scanner Full (Includes AI Red Team + Strix Docker Sandbox):
curl -fsSL https://raw.githubusercontent.com/melihkarasu/web-security-scanner/main/install.sh | bash -s -- --full

# Or interactive menu (prompts you to pick 1=Lite or 2=Full) / manual run:
git clone https://github.com/melihkarasu/web-security-scanner.git
cd web-security-scanner
python3 server.py --lite   # or: python3 server.py --full
```
Your browser opens `http://127.0.0.1:8765` automatically (`NO_BROWSER=1` disables auto-open).

### Option 3: Docker Mode (`Lite` or `Full` Container)
```bash
# ⚡ Docker Lite (Lightweight, non-root, zero LLM/Strix overhead):
curl -fsSL https://raw.githubusercontent.com/melihkarasu/web-security-scanner/main/install.sh | bash -s -- --docker-lite
# (or: docker compose up -d)

# 🚀 Docker Full (Includes Strix CLI + host Docker socket for autonomous sandbox PoC runs):
curl -fsSL https://raw.githubusercontent.com/melihkarasu/web-security-scanner/main/install.sh | bash -s -- --docker-full
# (or: docker compose -f docker-compose.yml -f docker-compose.strix.yml up -d --build)
```
Access the Web UI at **`http://localhost:8765`**.

> **Zero `.env` Setup Required for LLMs:** All LLM provider keys, endpoints, and model selections are configured directly inside the Web UI (**🤖 AI Settings** drawer), verified with the **⚡ Test Connection** button, and stored in your browser's `localStorage`.

---

## 🛡️ What You Get

### 1. Passive Reconnaissance — Zero Target Disruption
| Module | What It Checks |
|--------|----------------|
| **HTTP Security Headers** | `Content-Security-Policy` (flags `unsafe-inline`, `unsafe-eval`, wildcards), `Strict-Transport-Security` (max-age, `includeSubDomains`, `preload`), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` |
| **Information Leakage** | Flags version disclosure headers (`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Runtime`) |
| **DNS & Email Hardening** | DMARC policy (`p=reject` / `quarantine` / `none`), SPF (`-all` / `~all`), DNSSEC (`AD` flag), CAA records, IPv6 (`AAAA`), MX records |
| **Grading & Remediation** | `A+` to `F` score with ready-to-copy Nginx, Apache, and Express.js hardening snippets |

### 2. Deep Passive Scan (Local / Docker Mode)
- **Cookie Security** — Inspects `Set-Cookie` headers for missing `HttpOnly`, `Secure`, and `SameSite=Strict/Lax` attributes.
- **TLS / Certificate** — Connects via Python `ssl` to verify TLS protocol version (flags TLS 1.0/1.1), certificate issuer, days until expiration, and SAN hostname matching.
- **`robots.txt` Exposure** — Detects sensitive disallowed paths (`/admin`, `/.env`, `/backup`, `/config`, `/db`, `/wp-admin`, `/api`).
- **Mixed Content** — Scans HTTPS HTML bodies for active (`<script>`, `<iframe>`) and passive (`<img>`, `<link>`) `http://` resource loads.
- **Technology Fingerprinting** — Identifies web servers, frameworks, CMSs, and CDNs (WordPress, Next.js, Angular, React, Laravel, PHP, Java, Express.js, Cloudflare, AWS) from headers, meta tags, script markers, and cookie names.

### 3. SAST — Local Directory & Source Code Analysis (Local / Docker Mode)
Scan any local directory path (`/var/www/app`, `~/project`, `./src`) either **standalone** or **in parallel with a live URL** (hybrid white-box scan):

| Layer | Engine | Capabilities |
|-------|--------|--------------|
| **Pattern Rules (`sast_engine.py`)** | 42 regex rules across 9 code categories | Hardcoded secrets (11 rules: AWS, GitHub, GitLab, Slack, Google, OpenAI, JWT, DB URIs), SQLi (6), XSS sinks (5), SSRF (4), Path Traversal (2), Weak Crypto (2), Dangerous Functions (7), Dockerfile/IaC (5) |
| **Structural AST, Taint & 2026 Runtime Advisories (`deep_sast_engine.py`)** | Python `ast` + JS taint + Shannon entropy + 87 extended rules (129 total) | Python AST call-graph taint tracking (`eval`, `exec`, `pickle`, `subprocess`, SQL execution), multi-line JavaScript source-to-sink taint analysis, high-entropy secret string detection, **21 Official PHP 2026 Advisory rules (`PHP-ADV-001`…`021` — `php2shell` CVE-2026-109618 OOM RCE, CVE-2026-109619 Stale Global State RCE & CVE-2026-115560 Session Upload Progress RCE)**, **10 Official Node.js Oct 2026 Security Release rules (`NODE-ADV-001`…`010` — CVE-2026-111497 Brotli RCE, `dns.resolve` NUL byte, TLS fullwidth/IP bypass, SEA/Snapshot entropy)**, and JWT/CORS/Kubernetes/GraphQL checks |
| **Independent Verification Pass** | Two-pass file re-verification | Re-reads matched file lines to filter out comments, test fixtures, and false positives |
| **Live Dependency CVE Audit** | Google OSV API (`api.osv.dev`) | Parses `package.json` / `package-lock.json` (npm), `requirements.txt` (PyPI), and `go.mod` (Go) and queries Google OSV in batch for known CVEs |

### 4. Active Security Testing (Local / Docker Mode, Ethics-Gated)
Enforces a mandatory ethical confirmation gate (`POST /api/active-confirm` → `403 ETIK_ONAY_YOK` if unconfirmed), a 1.5-second delay between requests, a 60-request cap per scan, and strictly read-only/benign probes:

| Module | Technique |
|--------|-----------|
| **SQL Injection (`sqli`)** | Error-based (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, SQLAlchemy signatures), Boolean-based (`AND 1=1` vs `AND 1=2` response similarity), Time-based (`SLEEP(2)`) |
| **NoSQL Injection (`nosqli`)** | MongoDB/Redis/CouchDB error signatures + `$ne` operator differential probes |
| **SSTI (`ssti`)** | Benign template math evaluation probes (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`, `%{7*7}` → checks for rendered `49`) |
| **Node.js Oct 2026 Security Advisory Audit** | SAST & HTTP header detection for all 10 CVEs in the [21 Oct 2026 Node.js Security Releases](https://nodejs.org/tr/blog/vulnerability/october-2026-security-releases) (`NODE-ADV-001`…`NODE-ADV-010`): checks unpatched/EOL Node.js versions (`< 26.12.1`, `< 24.22.1`, `< 22.23.4`, EOL `<= 20.x`) in `Dockerfile`/`.nvmrc`/`.node-version`, **CVE-2026-111497** (Brotli decoder OOB write RCE), **CVE-2026-105482** (`dns.resolve` NUL byte truncation), **CVE-2026-105483 / CVE-2026-106069 / CVE-2026-106072** (TLS fullwidth digit & non-canonical IPv4 hostname bypass), **CVE-2026-105481** (Keep-Alive socket early response smuggling), **CVE-2026-106074** (`crypto.randomUUID`/`randomInt` SEA & startup snapshot entropy reuse), **CVE-2026-106070 / CVE-2026-106071 / CVE-2026-106073** (`zlib` ZIP header cache & Permission Model wildcard/`fs.realpathSync` bypass), and vulnerable `undici` versions — with automated `Dockerfile`/`.nvmrc` remediation via `POST /api/node-advisory-remediate` |
| **PHP 2026 Security Advisory Audit (`php2shell`)** | SAST & HTTP header detection for **CVE-2026-109618** (OOM Corruption RCE) and **CVE-2026-109619** (Stale Global State RCE) and **CVE-2026-115560** (Session Upload Progress & Serialize Handler RCE) plus 2026 PHP advisories (`PHP-ADV-001`…`PHP-ADV-021`): checks unpatched PHP versions (`< 8.5.12`, `< 8.4.27`, `< 8.3.36`, `< 8.2.35`), `session.upload_progress.enabled`, `session.serialize_handler` runtime changes, PHP 8.5 `fatal_error_backtraces`, `memory_limit`/`post_max_size`/`RLIMIT_AS`, FPM pools, Apache/.htaccess, `ini_set()` misuse, and IOC webshell patterns — recommends official remediation per [php.net/archive/2026.php](https://www.php.net/archive/2026.php) (primary: upgrade PHP from official sources & full worker restart; secondary: official advisory config mitigations) |
| **Reflected & DOM XSS (`xss`)** | Benign reflection marker (`wzxqmk731`) unescaped context check + passive DOM sink regex scan |
| **CSRF (`csrf`)** | HTML `<form>` anti-CSRF token inspection + session cookie `SameSite` correlation |
| **SSRF (`ssrf`)** | Internal loopback probe (`127.0.0.1`) on URL-like query parameters (`url`, `redirect`, `next`, `uri`, `callback`) with differential response analysis |
| **Open Redirect (`open_redirect`)** | Non-redirecting HTTP check for external `Location` header injection on redirect parameters |
| **IDOR Indicators (`idor`)** | Flags numeric/UUID object reference parameters (`id`, `uid`, `user`, `account`, `doc`) requiring server-side ownership verification |
| **Browser Simulation (`browser_sim_engine.py`)** | Same-domain crawler (max 10 pages, depth 2), external `.js` file downloader & DOM source-to-sink taint analyzer, automatic form input probe injector, clickjacking frameability check, and session cookie rotation check |
| **Business Logic (`business_logic_engine.py`)** | Boundary numeric manipulation (negative/zero/overflow values on `price`/`qty`/`amount`), workflow/privilege parameter bypass probes (`role=admin`, `step=final`), and concurrent race-condition checks on `/race` or `/transfer` endpoints |
| **TCP Port Scan (`ports`)** | Connects to 24 common ports (`21, 22, 25, 53, 80, 443, 1433, 1521, 2375, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017`) and highlights exposed database/infrastructure services |
| **Finding Correlation (`correlate_findings`)** | Chains multi-module findings into high-impact attack paths (e.g., *SSRF + Open DB Port → Internal Network Compromise*, *XSS + Weak CSP → Unblocked Script Execution*) |

### 5. AI Red Team Orchestration — Evidence-Verified Pipeline
Enable **🤖 AI Red Team Agents** in the Command Center to run a 3-stage, evidence-verified pipeline (`/api/ai-scan`):

| Stage / Agent | Role | How It Works |
|---------------|------|--------------|
| **Stage 1: Real Recon** | Baseline Discovery | Runs the crawler, form extractor, header fetcher, and baseline active modules to build a factual attack-surface state (`export_scan_state`) |
| **🔍 The Scout** | Attack Surface Analysis | Analyzes discovered URLs, form inputs, HTTP headers, technologies, and baseline findings to identify high-priority entry points |
| **🎯 The Strategist** | Hypothesis Generation | Proposes up to 4 non-duplicate, read-only probes per loop (up to 3 loops) in strict JSON format (`url`, `param`, `payload`, `vuln_class`). Each probe is **executed live** against the target via the shared rate-limited HTTP client (properly replacing/merging URL query parameters) |
| **🧠 The Analyst** | Strict Evidence Triage | Inspects the real HTTP status and response excerpt for each probe and returns a structured JSON verdict (`VULNERABLE`, `NOT_VULNERABLE`, `INCONCLUSIVE`, confidence, severity, CWE, and exact evidence quote). **Speculative findings are discarded** |
| **📋 The Reporter** | Executive Synthesis | Synthesizes both AI-verified findings and deterministic engine findings into an executive summary, attack chains, and prioritized remediation plan |

**Supported LLM Providers (`ai_connector.py`):**
- **OpenAI-Compatible Endpoints** — OpenAI, DeepSeek, Groq, Mistral, vLLM, LM Studio, LocalAI (includes automatic fallback for reasoning models that return output in `reasoning` fields, plus 180s timeout and network retry).
- **Google Cloud Vertex AI** — Region: `global` (default) or regional endpoints; supports `gemini-3.1-pro`, `gemini-3.8-flash`, etc. via Vertex API Key or Service Account JSON (requires `cryptography` package for RS256 JWT signing).
- **Google Gemini API (Google AI Studio)** — Direct API key (`AIza...`).
- **OpenRouter** — Unified access to 100+ models.
- **Ollama (Local / Offline)** — Connects to `http://localhost:11434` (`gemma2`, `llama3.1`, `codellama`, etc.) for 100% offline inference.

### 6. Strix Autonomous AI Pentest — Subprocess & Docker Sandbox Integration
In addition to the built-in AI orchestrator, the **⚔️ Strix Pentest** tab manages the official **[Strix CLI](https://github.com/usestrix/strix)** (`strix_engine.py`) as a background subprocess:

- **Full CLI Flag Parity:** Supports scan modes (`quick`, `standard`, `deep`), custom instructions (`--instruction-file`), white-box multi-target scanning (`--target` repeatable + `--target-list`), turn/budget caps (`--max-turns`, `--max-budget`), CI severity threshold (`--fail-on`), code diff scoping (`--scope-mode`, `--diff-base`), custom CLI config (`--config`), MCP server configuration (`--mcp-config`, `--mcp-server`, `--mcp-exclude`), sandbox file injection (`--workspace-file`), past run discovery & resumption (`--resume`), and CLI self-update (`--update`).
- **Live Polling & PoC Extraction:** Polls `strix_runs/<run>/run.json` and `vulnerabilities.json` every 4 seconds, streaming `strix_output.log` and mapping Strix's CVSS 3.1 scores, CWE IDs, HTTP evidence, and executable PoC scripts directly into the UI and exportable reports.
- **Privacy & Safety:** Enforces the server-side ethical gate (including on `--resume` by resolving the original target hostname) and sets `STRIX_TELEMETRY=0` by default.

---

## ⚠️ Known Limitations & Architectural Trade-offs

We believe security tools should be transparent about their boundaries:

1. **Browser Mode (GitHub Pages) is Passive-Only:** Due to browser CORS policies and raw socket restrictions, the GitHub Pages demo can only query DNS/email records via DoH. Full HTTP header fetching, deep passive scanning, local directory SAST, active testing, AI Red Team, and Strix require running `server.py` locally or in Docker.
2. **Static HTML/JS Simulation vs. Headless Chromium:** `browser_sim_engine.py` uses Python's `HTMLParser` and regex/taint heuristics to crawl links, extract forms, and analyze external `.js` files. It does **not** run a headless browser (Playwright/Puppeteer); therefore, single-page applications (SPAs) that render routes exclusively via client-side JavaScript execution will have limited crawl coverage unless tested with Strix's full sandbox.
3. **Conservative Active Scan Limits:** To prevent accidental denial-of-service, `active_scan_engine.py` enforces a 1.5-second minimum interval between requests and a hard cap of **60 HTTP requests per scan** (crawler capped at 10 pages / depth 2 / 5 JS files).
4. **AI Thought Stream Delivery:** `/api/ai-scan` executes synchronously per scan request and returns the accumulated `thought_chain` log array when the pipeline finishes (whereas Strix runs asynchronously in the background and streams status via 4-second polling on `/api/strix-status`).
5. **External Network Calls When Configured:** While core local scanning keeps data on your machine, DNS audits query Cloudflare/Google DoH, dependency CVE checks query `api.osv.dev`, and cloud LLM providers send prompt context (headers, discovered URLs/forms, trimmed HTTP response excerpts) to your selected LLM API. Use **Ollama** if you require strictly air-gapped/local LLM inference.
6. **Docker + Strix Socket Privilege:** Running Strix inside Docker (`docker-compose.strix.yml`) mounts `/var/run/docker.sock` so Strix can spawn sibling `strix-sandbox` containers on the host daemon. Only use the Strix compose override in trusted local environments. When scanning services bound to `localhost` on your host machine from inside the Strix Docker sandbox, target the Docker bridge IP (e.g., `http://172.17.0.1:3000`).

---

## 🔒 Security Architecture

| Principle | Implementation |
|-----------|----------------|
| **Localhost-only binding** | `server.py` binds to `127.0.0.1:8765` by default (`0.0.0.0` only inside container) |
| **Mandatory ethics gate** | Active, AI, and Strix scans require explicit per-domain confirmation (`POST /api/active-confirm`); returns `403 ETIK_ONAY_YOK` otherwise |
| **Rate limiting & caps** | 1.5 s minimum delay between active requests, 60-request hard cap per scan |
| **Read-only probes** | No `INSERT`/`UPDATE`/`DELETE` payloads; SQLi/SSTI/XSS probes use benign markers |
| **Zero-dependency core** | Core server, SAST, and active engines run on Python 3 stdlib (`urllib`, `socket`, `ssl`, `http.server`, `json`, `re`, `ast`); `cryptography` is only required for Vertex AI Service Account JWT auth |
| **Resource bounds** | SAST skips `node_modules`, `.git`, `.venv`, files >1 MB, and caps at 800 files per scan |

---

## 📁 Project Structure

```text
web-security-scanner/
├── server.py                  # Local HTTP server & API router (headers, deep-scan, SAST, active, AI, Strix)
├── sast_engine.py             # 42-rule SAST engine + two-pass verification + Google OSV CVE client
├── deep_sast_engine.py        # Python AST analyzer, JS multi-line taint tracker, Shannon entropy & extended rules
├── active_scan_engine.py      # 12-module active scanner, correlation engine, rate limiter & ethical gate
├── browser_sim_engine.py      # Crawler, external JS DOM-XSS analyzer, form injector, clickjacking & session flow
├── business_logic_engine.py   # Numeric boundary manipulation, workflow bypass & race condition tester
├── ai_connector.py            # Unified LLM client (OpenAI-compatible, Vertex AI, Gemini, OpenRouter, Ollama)
├── ai_orchestrator.py         # Evidence-verified 4-agent Red Team pipeline (Scout → Strategist → Analyst → Reporter)
├── strix_engine.py            # Strix CLI subprocess manager (full CLI flag parity, live polling & report mapper)
├── index.html                 # Unified Single-Input Command Center & 8-tab diagnostic dashboard
├── js/app.js                  # Frontend controller, DoH client, mode detection & MD/JSON/HTML report exporter
├── css/style.css              # Dedicated production stylesheet & contrast/layout rules
├── css/tailwind.min.css       # Precompiled standalone Tailwind CSS (zero CDN dependency)
├── install.sh                 # One-command installer (--full for Strix, --docker for containerized setup)
├── Dockerfile                 # Multi-mode container build (supports ARG INSTALL_STRIX=1)
├── docker-compose.yml         # Standard non-root container deployment
├── docker-compose.strix.yml   # Strix-enabled container override (mounts host docker.sock)
└── requirements.txt           # Optional dependency (cryptography>=42.0.0 for Vertex AI Service Account JWT)
```

**Local API Endpoints (`server.py`):**
- `GET  /api/status` — Server health & local mode detection
- `GET  /api/headers?url=` — Live HTTP response header proxy (bypasses browser CORS)
- `GET  /api/deep-scan?url=` — Deep passive scan (cookies, TLS, `robots.txt`, mixed content, tech fingerprint)
- `GET  /api/sast?path=` — Local directory SAST (129 rules incl. PHP `php2shell` & Node.js Oct 2026 advisories) + AST/taint + Google OSV dependency CVE scan
- `POST /api/php-advisory-remediate` — Official [php.net/archive/2026.php](https://www.php.net/archive/2026.php) `Dockerfile`/`php.ini`/FPM remediation (`8.5.12`, `8.4.27`, `8.3.36`, `8.2.35`)
- `POST /api/node-advisory-remediate` — Official [Node.js Oct 2026 Security Releases](https://nodejs.org/tr/blog/vulnerability/october-2026-security-releases) `Dockerfile`/`.nvmrc`/`.node-version` remediation (`v26.12.1`, `v24.22.1`, `v22.23.4`)
- `POST /api/active-confirm` — Per-domain ethical authorization gate
- `GET  /api/active-scan?url=&modules=` — Rate-limited active vulnerability scan
- `POST /api/ai-test` — LLM provider connectivity test
- `POST /api/ai-scan` — Evidence-verified AI Red Team orchestration
- `GET  /api/strix-capabilities` — Strix CLI & Docker sandbox readiness check
- `POST /api/strix-scan` — Start or `--resume` an autonomous Strix pentest
- `GET  /api/strix-status?scan_id=` — Live status, log tail, and finding count polling
- `GET  /api/strix-report?scan_id=` — Full Strix report (CVSS, CWE, PoC scripts, HTTP evidence)
- `GET  /api/strix-runs` & `GET /api/strix-past-runs` — Active and historical resumable Strix runs
- `POST /api/strix-cancel` & `POST /api/strix-update` — Terminate active scan or update Strix CLI

---

## 🏆 Built on Giants' Shoulders

| Project | Contribution | Entegrasyon / Kapsama Oranı | Integration in This Repo |
|---------|--------------|:---------------------------:|--------------------------|
| **[Strix](https://github.com/usestrix/strix)** | Autonomous multi-agent penetration testing & PoC validation | **%100**<br>*(Full CLI & Sandbox Parity)* | **100% CLI & Artifact Parity:** Managed via `strix_engine.py` subprocess + Docker sandbox; supports all CLI flags, `POSTMAN_API_KEY` / `PERPLEXITY_API_KEY` / `EXA_API_KEY`, 25+ finding fields (`cvss_breakdown`, `fix_pr_body`, `code_locations`), live `.state/agents.json` + SQLite `agents.db` topology, `coverage.json`, `findings.sarif` (SARIF 2.1.0), `vulnerabilities.csv`, and `penetration_test_report.md` |
| **[security-check](https://github.com/ersinkoc/security-check)** | OWASP-aligned SAST taxonomy, 7-language deep scanners & 4-phase AI code audit | **%100**<br>*(Full Pipeline Parity)* | **100% Pipeline & Artifact Parity:** 146 static/structural rules across 7 languages (Go, Rust, PHP, Java, C#, TS/JS, Python AST) + 8-ecosystem OSV CVE parsers (npm, PyPI, Go, Cargo, Composer, Gemfile, Maven, NuGet) + Git Diff (`sc-diff-report`) mode + 4-phase LLM code audit (`Recon → Hunt → Adversarial Verify → Report`) + 6-file output suite (`SECURITY-REPORT.md`, `architecture.md`, `coverage-ledger.md`, `dependency-audit.md`, `verified-findings.md`, `findings.json`) |
| **[Cloudflare Security Audit Skill](https://github.com/cloudflare/security-audit-skill)** | Evidence-first finding lifecycle & independent verification pass | **%100**<br>*(Full Lifecycle Parity)* | **100% Lifecycle & Coverage Parity:** Enforces the 4-state finding lifecycle (`Confirmed`, `Needs Validation`, `Hardening Notes`, `Rejected / Disproved`) across all engines so unverified heuristics never inflate threat counts, paired with a Unified Audit Coverage Ledger tracking every surface, trust boundary, evidence record, and coverage gap |
| **[Claude-Red](https://github.com/SnailSploit/Claude-Red)** | Offensive security skills, attack playbooks & context-aware red team methodologies | **%100 (Web/API/Kod Yüzeyi)**<br>*(Genel Repo: %48)*<br>*(Donanım/RF/Binary/AD hariç tüm web alanları tam)* | **100% Web Application & Source Parity:** Web, API, Auth, Cloud, Container, CI/CD, Supply Chain, Cryptography ve AI Security kategorilerindeki tüm ofansif teknikler deterministik motorlara ve AI ajanlarına entegre edildi: **4 yeni aktif DAST modülü** (`cors_active`, `jwt_oauth`, `graphql`, `hpp`), **2 yeni saldırı zinciri**, **17 yeni derin SAST kuralı** (AI Prompt Injection/SSRF, CI/CD pwn-request, unpinned actions, JWT/OAuth, K8s docker.sock), **Dependency Confusion denetçisi** (`.npmrc`/`pip.conf` + sahipsiz npm/PyPI namespace kontrolü), derin **TLS Cipher/PFS/CRIME denetimi** ve AI Red Team orkestratörüne keşif verisine göre **dinamik Claude-Red mikro-playbook priming** mekanizması |

**Additional data sources:** [Google OSV](https://osv.dev/) (open-source vulnerability database), [Official PHP 2026 Security Advisories](https://www.php.net/archive/2026.php) (`CVE-2026-109618` / `CVE-2026-109619` / `CVE-2026-115560` & 2026 CVE remediation reference), [Official Node.js October 2026 Security Releases](https://nodejs.org/tr/blog/vulnerability/october-2026-security-releases) (`v26.12.1` / `v24.22.1` / `v22.23.4` — `CVE-2026-111497` Brotli RCE & 10 CVEs), [VibeCodedApps](https://app.melihkarasu.com) (design & deployment architecture).

---

## ⚖️ Legal & Ethical Use

**This tool is for authorized security testing only.**

1. **Scope:** Only scan domains, endpoints, and repositories that you own, operate, or have explicit written authorization to test.
2. **Active & AI modes send real HTTP probes.** Confirming the ethical declaration in the UI is mandatory and enforced server-side. Built-in rate limits reduce load but **do not substitute for legal permission**.
3. **Origin Accountability:** In Local and Docker modes, all outbound requests originate from your machine's IP address. You are solely responsible for compliance with applicable laws (including CFAA, Computer Misuse Act, TCK Art. 243–244, GDPR, and NIS2).
4. **No Warranty:** Provided "as is" under the MIT License without warranty of any kind. The author assumes no liability for misuse or damages.

**If you are unsure whether you have permission to scan a target — do not scan it.**

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for full text.

---

Built with ☕ and 🔍 by [@melihkarasu](https://github.com/melihkarasu).
