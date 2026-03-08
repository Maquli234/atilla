<div align="center">

```
 █████╗ ████████╗██╗██╗     ██╗      █████╗
██╔══██╗╚══██╔══╝██║██║     ██║     ██╔══██╗
███████║   ██║   ██║██║     ██║     ███████║
██╔══██║   ██║   ██║██║     ██║     ██╔══██║
██║  ██║   ██║   ██║███████╗███████╗██║  ██║
╚═╝  ╚═╝   ╚═╝   ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝
```

**Professional XSS Testing Framework**

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![Version](https://img.shields.io/badge/Version-3.0-cyan?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)

> ⚠️ **For authorized security testing ONLY. Unauthorized use is illegal.**

</div>

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [GUI Mode](#gui-mode)
- [WAF Bypass Module](#waf-bypass-module)
- [Plugin System](#plugin-system)
- [API Integration](#api-integration)
- [Configuration](#configuration)
- [Reporting](#reporting)
- [Contributing](#contributing)
- [Legal Notice](#legal-notice)

---

## Overview

ATILLA is a professional-grade Cross-Site Scripting (XSS) testing framework designed for security researchers, penetration testers, and bug bounty hunters. It combines intelligent context-aware payload selection, WAF fingerprinting, headless browser crawling, and comprehensive reporting into a single unified tool.

**Key differentiators:**
- Context-aware payload selection (HTML, JS, CSS, JSON injection points detected automatically)
- WAF fingerprinting with 10+ bypass mutation strategies
- Playwright headless browser support for JS-rendered SPAs
- Blind/OOB XSS detection with callback payloads
- CVSS v3.1 severity scoring
- Rich GUI and CLI interfaces
- Plugin architecture for extensibility

---

## Features

| Category | Feature | Details |
|----------|---------|---------|
| **Detection** | Context Analysis | Auto-detects HTML/JS/CSS/JSON injection contexts |
| **Detection** | Confidence Scoring | 0–100 scale with VULNERABLE/REFLECTED/ENCODED/PARTIAL categories |
| **Detection** | DOM Sink Detection | 18+ dangerous sink patterns |
| **Detection** | Blind XSS | OOB callback payloads for stored XSS |
| **Payloads** | Library Size | 87+ base payloads, 140+ with mutations |
| **Payloads** | WAF Bypass | 10 mutation strategies per payload |
| **Payloads** | Sets | basic, owasp, advanced, dom, blind, all |
| **Crawling** | Static Crawl | BFS link discovery, form extraction |
| **Crawling** | Headless Browser | Playwright-based JS-rendered page support |
| **Crawling** | AJAX Discovery | XHR/fetch endpoint interception |
| **WAF** | Fingerprinting | 10 WAF signatures (Cloudflare, AWS, Akamai, etc.) |
| **WAF** | CSP Analysis | Bypass-feasibility scoring |
| **Reporting** | Formats | JSON + interactive dark-theme HTML |
| **Reporting** | CVSS | v3.1 base score computation |
| **GUI** | Interface | Full Tkinter GUI mirroring all CLI flags |
| **API** | REST API | FastAPI-based programmatic access |
| **Plugins** | Architecture | Drop-in plugin system for custom modules |

---

## Architecture

```
atilla_v3/
├── main.py                    # CLI entry point
├── core/
│   ├── config.py              # ScanConfig — all parameters
│   ├── engine.py              # Scan orchestrator
│   └── models.py              # Data models (Vulnerability, Severity, etc.)
├── payloads/
│   ├── library.py             # 87+ payloads in 10 context-keyed buckets
│   └── mutator.py             # WAF-evasion mutation engine (10 strategies)
├── detection/
│   ├── analyzer.py            # Response analysis + confidence scoring
│   ├── blind.py               # OOB/blind XSS payloads
│   ├── context.py             # Injection context classifier
│   ├── csp.py                 # CSP header parser + bypass analysis
│   ├── dom.py                 # DOM sink detector (18+ patterns)
│   └── waf.py                 # WAF fingerprinting
├── crawling/
│   └── crawler.py             # BFS crawler + Playwright headless mode
├── modules/
│   ├── waf_bypass.py          # Advanced WAF bypass module
│   ├── encoder.py             # Context-aware encoding engine
│   └── browser_payloads.py    # Browser-specific payload variants
├── gui/
│   └── app.py                 # Full Tkinter GUI
├── api/
│   └── server.py              # FastAPI REST API server
├── plugins/
│   └── base.py                # Plugin base class
├── reporting/
│   └── report.py              # JSON + HTML report generation
├── tests/
│   ├── test_analyzer.py       # Analyzer unit tests
│   ├── test_context.py        # Context detector tests
│   ├── test_mutator.py        # Mutator unit tests
│   └── test_payloads.py       # Payload library tests
├── utils/
│   └── cvss.py                # CVSS v3.1 scoring
└── ml/
    └── scorer.py              # Heuristic false-positive scorer
```

---

## Installation

### Option 1 — pip (recommended)

```bash
# Clone the repository
git clone https://github.com/Maquli234/atilla.git
cd atilla

# Install core dependencies
pip install httpx colorama pyfiglet

# Optional: headless browser support
pip install playwright
playwright install chromium

# Optional: API server
pip install fastapi uvicorn

# Optional: GUI (usually built-in with Python)
# Tkinter is included with standard Python installations
```

### Option 2 — Docker

```bash
# Build the image
docker build -t atilla .

# Run a scan
docker run --rm atilla python3 main.py -u "http://target/search?q=test"

# Interactive shell
docker run --rm -it atilla bash
```

### Option 3 — Manual / Virtual Environment

```bash
git clone https://github.com/Maquli234/atilla.git
cd atilla
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python3 main.py --help
```

### Requirements

| Package | Version | Purpose |
|---------|---------|---------|
| `httpx` | ≥0.27.0 | Async HTTP client |
| `colorama` | ≥0.4.6 | Terminal colors |
| `pyfiglet` | ≥1.0.2 | ASCII banner |
| `playwright` | ≥1.40 | Headless browser (optional) |
| `fastapi` | ≥0.100 | REST API server (optional) |
| `uvicorn` | ≥0.23 | ASGI server (optional) |

---

## Usage

### Quick Start

```bash
# Scan a single URL
python3 main.py -u "http://localhost/search?q=test"

# Verbose with all payloads + save reports
python3 main.py -u "http://localhost/search?q=test" --set all -v \
    -o results.json --html-report report.html

# Authenticated scan
python3 main.py -u "http://localhost/dashboard?q=x" \
    --auth-cookie "session=abc123" --set owasp

# Crawl + scan entire site
python3 main.py -u "http://localhost/" --crawl --crawl-depth 4 --set owasp

# WAF-targeted scan with mutations
python3 main.py -u "http://protected.local/search?q=x" --set advanced

# Blind XSS (stored/no-reflection)
python3 main.py -u "http://localhost/contact?msg=x" \
    --blind-xss --oob-host yourburp.oastify.com

# Full JS-rendered SPA
python3 main.py -u "http://localhost/" \
    --crawl --playwright --set all -v -o results.json

# With CVSS scoring
python3 main.py -u "http://localhost/search?q=x" --cvss --html-report report.html
```

### All CLI Flags

```
-u, --url               Target URL (required)
--auth-cookie           Cookie value: "session=abc"
--set                   Payload set: basic|owasp|advanced|dom|blind|all
--timeout               Request timeout in seconds (default: 15)
--concurrency           Parallel connections (default: 5)
--delay                 Min delay between requests (default: 0.2s)
--retries               Retry attempts per request (default: 3)
--crawl                 Enable domain crawling
--crawl-depth           Max crawl depth (default: 3)
--playwright            Use headless browser for JS pages
--no-smart-context      Disable automatic context detection
--no-mutations          Disable WAF-bypass mutations
--blind-xss             Inject OOB blind XSS payloads
--oob-host              OOB callback host
-o, --output            JSON report path
--html-report           HTML report path
--cvss                  Include CVSS v3.1 scores
-v, --verbose           Per-payload detail output
--gui                   Launch GUI mode
--api                   Start REST API server
--api-port              API port (default: 8080)
```

### Payload Sets Explained

| Set | Payloads | Description |
|-----|----------|-------------|
| `basic` | 13 | Common vectors, fastest scan |
| `owasp` | 38 | OWASP Top 10 aligned (default) |
| `advanced` | 38 | WAF bypass + JS string exploits |
| `dom` | 22 | DOM sinks, template literals, SPA |
| `blind` | dynamic | OOB callback payloads |
| `all` | 87+ | Everything, with mutations = 140+ |

---

## GUI Mode

```bash
python3 main.py --gui
```

The GUI provides:
- All CLI flags as interactive form fields
- Real-time scan output in scrollable terminal pane
- Saved configuration profiles
- Results dashboard with severity breakdown
- One-click HTML report generation

---

## WAF Bypass Module

```bash
# Auto-enabled when WAF is detected
python3 main.py -u "http://cloudflare-protected.local/search?q=x" --set advanced
```

Mutation strategies applied when a WAF is fingerprinted:
1. Mixed case (`<ScRiPt>`)
2. HTML entity encoding (`&#97;&#108;&#101;&#114;&#116;`)
3. Unicode escape (`\u0061lert`)
4. Null byte injection
5. Comment insertion (`on<!---->load`)
6. Whitespace variants (`\t`, `\n`, `%0a`)
7. Double URL encoding (`%253C`)
8. String concatenation (`'al'+'ert'`)
9. Function constructor (`Function('alert(1)')()`)
10. Full-width Unicode characters

---

## Plugin System

Drop a Python file into `plugins/` implementing the `AtillaPlugin` base class:

```python
from plugins.base import AtillaPlugin

class MyPlugin(AtillaPlugin):
    name        = "my_plugin"
    description = "Custom XSS variant detector"

    def on_response(self, param, payload, response_text, headers):
        if "my_custom_indicator" in response_text:
            return self.finding(param, payload, confidence=85, detail="Custom match")
        return None
```

---

## API Integration

```bash
# Start the API server
python3 main.py --api --api-port 8080

# Trigger a scan via HTTP
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "http://localhost/search?q=test", "payload_set": "owasp"}'

# Get results
curl http://localhost:8080/results/{scan_id}
```

---

## Configuration

Save reusable scan profiles in `config.json`:

```json
{
  "profiles": {
    "quick": {
      "payload_set": "basic",
      "concurrency": 10,
      "timeout": 10
    },
    "thorough": {
      "payload_set": "all",
      "crawl": true,
      "crawl_depth": 5,
      "use_mutations": true,
      "cvss": true
    },
    "stealth": {
      "payload_set": "owasp",
      "delay": 2.0,
      "concurrency": 1
    }
  }
}
```

---

## Reporting

ATILLA generates two report formats:

**JSON** — machine-readable, CI/CD friendly:
```json
{
  "tool": "ATILLA v3.0",
  "scan_time": "2024-01-15T10:30:00",
  "total_findings": 3,
  "severity_summary": {"HIGH": 2, "MEDIUM": 1},
  "findings": [...]
}
```

**HTML** — dark-themed interactive report with:
- Severity breakdown cards
- Per-finding evidence snippets
- DOM sink listings
- CVSS scores and vectors
- WAF detection status

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Write tests in `tests/`
4. Run tests: `python3 -m pytest tests/ -v`
5. Submit a pull request

### Adding Payloads

Add to the appropriate bucket in `payloads/library.py`:
```python
_WAF = [
    # Your new payload
    "<your-payload>",
]
```

### Adding WAF Signatures

Add to `detection/waf.py`:
```python
WAF_SIGNATURES["YourWAF"] = ["signature1", "header-indicator"]
```

---

## Legal Notice

> **IMPORTANT — READ BEFORE USING**
>
> ATILLA is provided for **educational purposes and authorized security testing only**.
>
> - ✅ Use only on systems you **own** or have **explicit written permission** to test
> - ✅ Bug bounty programs within defined scope
> - ✅ Penetration testing engagements with signed authorization
> - ❌ Unauthorized testing of any system is **illegal** under computer fraud laws worldwide
> - ❌ The authors accept **no liability** for misuse
>
> By using this tool you agree to use it responsibly and legally.

---

<div align="center">

Made with ⚔️ for the security community

[Report a Bug](https://github.com/Maquli234/atilla/issues) · [Request a Feature](https://github.com/Maquli234/atilla/issues)

</div>
