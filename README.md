# Web Security Scanner 🛡️

> **Production-grade web security auditing in a single file.**  
> Passive reconnaissance • Deep static analysis • Active exploitation • AI-orchestrated Red Teaming  
> Zero dependencies. Runs locally. No data leaves your machine.

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-orange?style=for-the-badge)](https://melihkarasu.github.io/web-security-scanner/)
[![Local Mode](https://img.shields.io/badge/Local%20Mode-Python%203%20Stdlib-00b86b?style=for-the-badge)](#-quick-start)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)
[![Design: Mistral AI](https://img.shields.io/badge/Design-Mistral%20AI-fa520f?style=for-the-badge)](https://mistral.ai)

---

## Why This Exists

Most security tools force a choice: **convenient but shallow** (online scanners) or **powerful but complex** (Burp, custom scripts, CI pipelines).  

Web Security Scanner removes that trade-off.

- **For developers:** Catch vulnerabilities before they ship — run a full audit on `localhost:3000` in seconds.
- **For pentesters:** A lightweight, scriptable companion for reconnaissance and validation.
- **For teams:** CI-ready JSON/HTML reports with CVSS scores, CWE mappings, and evidence — no SaaS subscription required.
- **For learners:** Transparent, readable Python code. Every check is inspectable; every finding is explained.

**One binary decision:** Run it in your browser (passive only) or on your machine (full capability). No Docker, no `npm install`, no account creation.

---

## ✨ Capability Matrix

| Capability | GitHub Pages (Browser) | Local Mode (`server.py`) |
|------------|------------------------|--------------------------|
| **DNS & Email Security** (DMARC, SPF, DNSSEC, CAA, IPv6) | ✅ Live via DoH | ✅ Live via DoH |
| **HTTP Security Headers** (CSP, HSTS, XFO, Permissions-Policy…) | ⚠️ Paste `curl -I` output | ✅ Fully automatic |
| **Deep Passive Scan** (Cookies, TLS, robots.txt, Mixed Content, Tech Fingerprint) | ❌ | ✅ |
| **SAST — Source Code Analysis** (42 rules, 10 categories, OSV CVE check) | ❌ | ✅ |
| **Active Security Testing** (SQLi, XSS, CSRF, SSRF, IDOR, Ports) | ❌ | ✅ (Ethics gate + rate limit) |
| **AI Red Team Orchestration** (Scout → Strategist → Analyst) | ❌ | ✅ Vertex AI / OpenRouter / Ollama |
| **Reports** (Markdown, JSON, HTML — CVSS + CWE + Evidence) | Basic only | ✅ Full |
| **Localhost / Internal Network Testing** | ❌ | ✅ |
| **Request Origin** | Your browser (DoH APIs) | Your machine IP |

> **Rule of thumb:** Start with the live demo. If you need depth, run locally — it takes 3 seconds.

---

## 🚀 Quick Start

### Option 1: Zero-Install Live Demo
Open **[melihkarasu.github.io/web-security-scanner](https://melihkarasu.github.io/web-security-scanner/)** in your browser.  
Passive DNS + header analysis works instantly. For deep header audits, paste `curl -I https://target.com` output into the "cURL" tab.

### Option 2: Full Power — Local Mode (Terminal)
```bash
# Linux / macOS
git clone https://github.com/melihkarasu/web-security-scanner.git
cd web-security-scanner
python3 server.py

# Windows (PowerShell)
git clone https://github.com/melihkarasu/web-security-scanner.git
cd web-security-scanner
python server.py
```
Your browser opens `http://127.0.0.1:8765` automatically. Green **"🟢 Local Mode"** badge confirms full capability.

### Option 3: Full Power — Docker Mode (Containerized)
Zero environment setup on host machine. Runs isolated with non-root security:
```bash
# Docker Compose ile tek komutla başlatın:
docker compose up -d

# Veya standart Docker CLI ile:
docker build -t web-security-scanner .
docker run -d -p 8765:8765 --name web-security-scanner web-security-scanner
```
Arayüze tarayıcınızdan **`http://localhost:8765`** adresinden erişebilirsiniz.

> **LLM / API Ayarları:** Kurulum anında `.env` veya komut satırı ile uğraşmanız gerekmez. Kurulum bittikten sonra arayüzdeki **🤖 AI Red Team Paneli** üzerinden OpenAI Compatible, Google Gemini veya Vertex AI ayarlarınızı doğrudan yapabilir ve test edebilirsiniz.

**Stop anytime:** `Ctrl + C` in terminal.

---

## 🛡️ What You Get

### 1. Passive Reconnaissance — Zero Risk, High Signal
| Module | What It Finds |
|--------|---------------|
| **HTTP Security Headers** | CSP (with `unsafe-inline/eval` detection), HSTS (max-age, preload, subdomains), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **Information Leakage** | `Server`, `X-Powered-By`, `X-AspNet-Version` — flagged and penalized |
| **DNS & Email Hardening** | DMARC policy (`reject`/`quarantine`/`none`), SPF (`-all`/`~all`), DNSSEC validation, CAA records, IPv6 readiness |
| **Scoring** | A+ → F letter grade with nginx/Apache/Express remediation snippets |

### 2. Deep Passive Scan (Local Only)
- **Cookie Security** — HttpOnly, Secure, SameSite analysis per cookie
- **TLS / Certificate** — Protocol version (detects TLS 1.0/1.1), issuer, expiry countdown, SAN matching
- **robots.txt Exposure** — Detects `/admin`, `/.env`, `/backup`, `/config` and similar sensitive paths
- **Mixed Content** — Active (scripts/iframes) and passive (images/CSS) HTTP loads on HTTPS pages
- **Technology Fingerprinting** — Framework detection (WordPress, Next.js, Angular, React, Laravel, Django…) via headers, meta tags, cookies, and JS patterns

### 3. SAST — Static Application Security Testing (Local Only)
**42 rules across 10 categories**, zero false-positive tolerance:

| Category | Rules | Highlights |
|----------|-------|------------|
| **Secrets Management** | 11 | AWS, GitHub, GitLab, Slack, Google, OpenAI keys; JWT secrets; DB connection strings; fallback patterns |
| **SQL Injection** | 6 | Template literals, concatenation, f-strings, `.format()`, PHP interpolation, `%` formatting |
| **XSS Sinks** | 5 | `innerHTML`, `document.write`, `dangerouslySetInnerHTML`, `v-html`, `insertAdjacentHTML` |
| **SSRF** | 4 | User-controlled `fetch`, `axios`, `urlopen`, `URL` constructor calls |
| **Path Traversal** | 2 | User input in `open()`, `readFile()` |
| **Weak Crypto** | 2 | MD5, SHA-1 usage |
| **Dangerous Functions** | 7 | `eval`, `exec`, `child_process`, `os.system`, `pickle.loads`, unsafe `yaml.load`, disabled TLS verify |
| **Dockerfile / IaC** | 5 | `:latest` tags, `USER root`, `COPY . .`, embedded secrets, `0.0.0.0/0` exposure |
| **Dependency CVE** | Live | npm (lockfile-aware), PyPI, Go modules — queried against **Google OSV** |

**Verification pass:** Every finding is re-checked in a second pass (file re-read) to eliminate false positives — Cloudflare audit methodology.

### 4. Active Security Testing (Local Only, Ethics-Gated)
Rate-limited (1.5 s/req, max 60 req/scan), read-only payloads, mandatory ethical confirmation:

| Test | Technique |
|------|-----------|
| **SQL Injection** | Error-based (DB fingerprints), Boolean-based (1=1 vs 1=2 + similarity), Time-based (`SLEEP`) |
| **XSS** | Reflected (unique harmless markers) + DOM sink detection |
| **CSRF** | Form token pattern analysis + SameSite cookie audit |
| **SSRF** | Internal IP probes on URL-like params + differential response analysis |
| **IDOR** | Identifier parameter enumeration (advisory) |
| **Port Scan** | 24 common TCP ports; DB/infra ports highlighted |
| **Deep Headers** | CSP directive breakdown, CORS wildcard+credentials risk, Cache-Control gaps |

### 5. AI Red Team Orchestration — **New in v6**
Click **"🤖 AI Orchestration"** to deploy a virtual three-agent Red Team:

| Agent | Role | Output |
|-------|------|--------|
| **🔍 The Scout** | Reconnaissance | Maps attack surface, discovers forms/parameters, identifies entry points |
| **🎯 The Strategist** | Attack Planning | Selects optimal modules, payloads, and execution order based on Scout intel |
| **🧠 The Analyst** | Correlation & Triage | Chains findings into exploit paths (e.g., XSS + IDOR → Account Takeover), prioritizes remediation |

**Live "Thought Chain" terminal** streams each agent's reasoning in real time.

**Supported LLM Providers (Configurable from Web UI):**
- **OpenAI Compatible (Any Endpoint)** — Base URL (`https://api.openai.com/v1`, DeepSeek, Groq, Mistral, vLLM, LM Studio, LocalAI vb.), API Key, Model (`gpt-4o`, `deepseek-chat` vb.).
- **Google Cloud Vertex AI** — **Bölge (Region): `global` (us-central1 DEĞİL!)**, Güncel Modeller: **`gemini-3.1-pro`**, **`gemini-3.8-flash`**, Kimlik Doğrulama: Service Account JSON içeriği veya Vertex API Key.
- **Google Gemini API (Google AI Studio)** — Doğrudan Gemini API anahtarı (`AIza...`), Güncel Modeller: **`gemini-3.1-pro`**, **`gemini-3.8-flash`**.
- **OpenRouter** — 100+ model (`google/gemini-3.1-pro`, `google/gemini-3.8-flash`, `claude-3.5-sonnet`, `gpt-4o` vb.), API Key.
- **Ollama (Yerel / Host)** — `gemma2`, `llama3.1`, `codellama` — **tamamen çevrimdışı, sıfır maliyet**.

> **Kurulum Sonrası Arayüzden Kolay Yönetim:** Tüm API anahtarları, Base URL ve model tercihleri web arayüzündeki **AI Red Team Orkestrasyon Paneli** üzerinden girilir, **"⚡ Bağlantıyı Test Et"** butonu ile anında doğrulanır ve tarayıcının `LocalStorage` alanında saklanır. Diske veya konteyner ortamına hassas veri yazılmaz.

### 6. Professional Reporting
- **Markdown** — Human-readable, version-control friendly
- **JSON** — Machine-parseable, SIEM/CI integration ready
- **HTML** — Compliance-ready, styled, standalone

Every finding includes: **Evidence** (HTTP response / code line), **Severity**, **CWE**, **CVSS estimate**, **Remediation code snippet**.

---

## 🔒 Security Architecture — Built In, Not Bolted On

| Principle | Implementation |
|-----------|----------------|
| **Localhost-only binding** | `server.py` binds `127.0.0.1:8765` — no public interface, no proxy |
| **Ethics gate** | Active tests require explicit UI confirmation + server-side domain allowlist; `403 ETIK_ONAY_YOK` otherwise |
| **Rate limiting** | 1.5 s minimum between requests, 60 request hard cap per scan |
| **Read-only payloads** | No `INSERT`/`UPDATE`/`DELETE`; SQLi uses benign `SELECT` probes |
| **Zero dependencies** | Python 3 stdlib only (`urllib`, `socket`, `ssl`, `http.server`, `json`, `re`, `ast`, `hashlib`…) |
| **Supply-chain safe** | No `pip install`, no `npm`, no binary blobs — audit the source in minutes |
| **Resource limits** | SAST skips `node_modules`, `.git`, files >1 MB, >800 files total |

---

## 📁 Project Structure

```
web-security-scanner/
├── server.py                 # HTTP server + API endpoints (headers, deep-scan, SAST, active, AI)
├── sast_engine.py            # 42-rule SAST engine + OSV dependency check
├── active_scan_engine.py     # Active test modules + rate limiter + ethics gate
├── browser_sim_engine.py     # Headless crawler, JS analyzer, form injector, clickjacking, session flow
├── business_logic_engine.py  # Numeric manipulation, workflow bypass, race condition tests
├── ai_connector.py           # Vertex AI / OpenRouter / Ollama unified client
├── ai_orchestrator.py        # 3-agent loop (Scout → Strategist → Analyst) + cost controls
├── index.html                # 5-tab UI (Audit, cURL, SAST, Active, Checklist)
├── js/app.js                 # Client logic, SSE log streaming, report generation
├── css/mistral-theme.css     # Mistral AI design system
└── README.md
```

**Local API Endpoints:**
- `GET  /api/headers?url=` — Header proxy (bypasses CORS)
- `GET  /api/deep-scan?url=` — Deep passive scan
- `GET  /api/sast?path=` — Source code scan
- `POST /api/active-confirm` — Ethics confirmation
- `GET  /api/active-scan?url=&modules=` — Active scan (post-confirmation)
- `POST /api/ai-scan` — AI Red Team orchestration

---

## 🏆 Built on Giants' Shoulders

This tool synthesizes battle-tested methodologies from three outstanding open-source projects:

| Project | Contribution | Adaptation |
|---------|--------------|------------|
| **[Strix](https://github.com/usestrix/strix)** | Active exploitation methodology: SQLi (error/boolean/time), XSS, CSRF, SSRF, evidence generation | Reimplemented in stdlib Python; deterministic, rate-limited, ethics-gated |
| **[security-check](https://github.com/ersinkoc/security-check)** | SAST rule design: secrets, crypto, injection sinks, Dockerfile/IaC, OWASP-aligned categories | 42 rules ported + verification pass + CVSS/CWE enrichment + OSV integration |
| **[Cloudflare Security Audit Skill](https://github.com/cloudflare/security-audit-skill)** | Finding lifecycle: evidence-based findings, independent verification pass, coverage tracking | Applied to both SAST and active findings; Markdown/JSON/HTML report pipeline |

**Additional data sources:** [Google OSV](https://osv.dev/) (vulnerability database), [VibeCodedApps](https://app.melihkarasu.com) (deployment architecture).

---

## ⚖️ Legal & Ethical Use

**This tool is for authorized testing only.**

1. **Scope:** Only scan systems you own, manage, or have explicit written permission to test.
2. **Active mode sends real HTTP requests.** The UI ethics declaration is mandatory; the server enforces it. Rate limits protect targets but **do not replace authorization**.
3. **Local mode = your IP.** All outbound requests originate from your machine. You are responsible for compliance with:
   - Turkish Penal Code (TCK Art. 243–244)
   - Computer Fraud and Abuse Act (US)
   - GDPR, NIS2, and applicable local regulations
4. **No warranty.** Provided "as is." The author accepts no liability for misuse, damage, or legal consequences arising from your use of this software.

**If you're unsure whether you have permission — you don't. Don't scan.**

---

## 🤝 Contributing

Issues and PRs welcome. Areas of interest:
- New SAST rules (follow existing pattern in `sast_engine.py`)
- Additional active test modules
- AI agent prompt improvements
- UI/UX refinements
- Documentation translations

Please read the code first — it's intentionally readable.

---

## 📄 License

**MIT License** — Use freely, modify, distribute. Attribution appreciated.

```
MIT License

Copyright (c) 2024 Melih Karasu

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🙏 Acknowledgements

- **Mistral AI** — Design system inspiration
- **Google OSV** — Open vulnerability data
- **Open source security community** — For building the tools we all stand on

---

**Star the repo** if this saves you time. **Open an issue** if it doesn't.  
Built with ☕ and 🔍 by [@melihkarasu](https://github.com/melihkarasu).