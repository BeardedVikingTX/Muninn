# Muninn

> *"Odin's raven of Thought flies over Midgard each day, sees all, and returns to whisper what he saw."*

**Muninn** is a deep-analysis post-processor for Burp Suite history. Point it at your captured traffic, and it hunts for potential vulnerabilities — then hands back a prioritized, human-readable audit report with manual test commands, expected behavior, CVE/CWE context, and bug-bounty payout estimates.

No auto-submissions. No noise. Just **signal** for the hunter to confirm.

---

## Why Muninn?

Manual review of Burp history is slow and error-prone. Existing scanners fire off thousands of requests, flag dozens of false positives, and drown you in reports you have to re-triage from scratch.

Muninn takes a different approach:

- **Offline-first.** Analyzes what *you* already captured — no extra load on the target.
- **Human-in-the-loop.** Every finding is a *lead*, not a claim. You confirm, then submit.
- **Context-rich.** Each lead ships with the exact `curl`/Repeater command to test it, the expected response pattern, and matching CVE/CWE history.
- **Scope-aware.** Correlates findings against `scope.yaml` for in-scope host matching and per-finding payout estimation.

---

## Features

- **Burp XML ingestion** — works with Burp Community and Pro exports
- **Endpoint inventory** — normalized map of every URL, method, status, and parameter
- **Heuristic detection**
  - Reflection-based **XSS** candidates
  - **SSRF / IDOR / open-redirect** parameter heuristics
  - **GraphQL** operations
  - Sensitive keyword leakage (tokens, keys, sessions, auth headers)
- **CVE/CWE correlation** — cross-references local datasets for severity, impact, and known PoC references
- **Scope & payout scoring** — parses `scope.yaml` for in-scope hosts, program platform, payout ranges, and response SLAs
- **Manual test runbook** — every lead comes with a ready-to-run command and expected result
- **Professional Markdown reports** — clean, deterministic, submission-ready
- **Optional enrichment** — pluggable API keys for Shodan, Censys, VirusTotal, GreyNoise, NVD, LLM triage (Groq / Mistral / Gemini), and more

---

## Quick Start

```bash
git clone https://github.com/beardedvikingtx/muninn.git
cd muninn
pip install -r requirements.txt

# In Burp: Target → Site map → select items → right-click → Save items
# Save as: burp_history.xml

# Optional enrichment
cp keys.txt.example keys.txt
# … fill in the keys you have

python muninn.py \
    --burp  burp_history.xml \
    --scope scope.yaml \
    --cves  CVE_Lists/ \
    --out   audit_reports/
```
Reports land in `audit_reports/huginn_audit_<timestamp>.md`.

* * * * *

# How It Works
------------
```
  ┌──────────────┐    ┌────────────────┐    ┌──────────────────┐
  │ Burp Suite   │    │                │    │  Muninn Parser   │
  │ (browse,     │───▶│ burp_history   │───▶│  (normalize,     │
  │  form fill,  │    │     .xml       │    │   decode, index) │
  │  click)      │    │                │    └────────┬─────────┘
  └──────────────┘    └────────────────┘             │
                                                     ▼
                        ┌────────────────────────────┼────────────────────────────┐
                        ▼                            ▼                            ▼
                ┌──────────────┐            ┌──────────────┐            ┌──────────────┐
                │  Heuristics  │            │  CVE / CWE   │            │  Scope Match │
                │  XSS · SSRF  │            │  Correlation │            │  + Payout    │
                │  IDOR · leak │            │              │            │    Ranges    │
                └──────┬───────┘            └──────┬───────┘            └──────┬───────┘
                       │                           │                           │
                       └─────────────┬─────────────┴───────────────────────────┘
                                     ▼
                            ┌──────────────────┐
                            │  Audit Report    │
                            │  + Manual Tests  │
                            │  + Payout Est.   │
                            └──────────────────┘
```
1.  **Capture** --- browse the target in Burp (fill forms, click buttons, upload images, hit every endpoint)

2.  **Export** --- save your history as `burp_history.xml`

3.  **Analyze** --- Muninn parses, enriches, correlates, and scores

4.  **Review** --- open the generated Markdown report

5.  **Confirm** --- run the provided manual test commands

6.  **Submit** --- only after you've verified a real issue

* * * * *

## Configuration
-------------

### `scope.yaml`

Defines the target program. Used for in-scope matching and payout estimation.
```
program: "Example Program"
platform: hackerone
in_scope:
  - "*.example.com"
  - "api.example.com"
out_of_scope:
  - "blog.example.com"
payouts:
  critical: [5000, 15000]
  high:     [1500, 5000]
  medium:   [500, 1500]
  low:      [50, 500]
response_sla_days: 30
```
### `keys.txt`

Copy `keys.txt.example` → `keys.txt` and fill in the APIs you have. Muninn degrades gracefully --- features with a missing key are silently skipped.

Supported integrations:

-   **Recon**: Shodan, Censys, VirusTotal, GreyNoise, AlienVault, AbuseIPDB, IPInfo, HackerTarget, BeVigil, ReconEer, CyberAtlas

-   **Intelligence**: NVD, MITRE, OpenSource, [Abuse.ch](https://abuse.ch/)

-   **LLM triage**: Groq, OpenRouter, Mistral, Cohere, Cerebras, DeepSeek, Gemini

-   **Quantum**: IBM Quantum Platform

### `CVE_Lists/`

Drop CVE datasets here (JSON/CSV from NVD, GitHub Advisory, or your own curated set). Muninn indexes them locally for offline correlation.

* * * * *

# Report Contents
---------------

Each `muninn_audit_*.md` report contains:

| Section | What you get |
| --- | --- |
| Endpoint Inventory | Full URL/method/param/status map |
| GraphQL Operations | Detected queries/mutations |
| High-Risk Parameters | SSRF, IDOR, open-redirect candidates |
| Reflected Parameters | XSS candidates with reflection context |
| Sensitive Keywords | Leaked tokens, keys, sessions |
| CVE Correlations | Matching CVEs with severity + references |
| Scope & Payout Estimate | Per-finding range and total ceiling |
| Manual Test Runbook | Copy-paste `curl` commands + expected results |

* * * * *

# Roadmap
-------

-   □

    Parallel enrichment (Shodan, Censys, VirusTotal)

-   □

    LLM-assisted triage with confidence scoring

-   □

    HTTP/2 and WebSocket ingestion

-   □

    Headless re-test mode with auth replay

-   □

    SARIF export for CI/IDE integration

-   □

    Auto-generated PoC scaffolding for common CWEs

-   □

    Quantum-assisted fuzzing research (IBM Quantum)

* * * * *

# Philosophy
----------

-   **Human in the loop.** Muninn never submits anything. **You** do.

-   **Signal over noise.** Every finding is a *lead* --- you validate before submitting.

-   **No false-positive submissions.** Heuristics flag; **you** confirm.

-   **Respect scope.** Only run against authorized targets.

* * * * *

# Legal
-----

Muninn is intended for **authorized security testing and bug bounty work only**. Running it against systems without explicit written permission is illegal and unethical. The author assumes no liability for misuse.

* * * * *

# Credits
-------

Built by [@beardedvikingtx](https://github.com/beardedvikingtx) --- for hunters who like their ravens sharp.

Named after **Muninn**, one of Odin's ravens --- *Memory* --- who flew over Midgard each day and returned to whisper what he saw.

* * * * *

# License
-------

MIT
