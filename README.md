<p align="center">
  <i>To every security analyst who has ever copied a URL from an email, pasted it into VirusTotal,<br>
  waited, repeated for five more tools, and then tried to explain to their boss why this takes<br>
  fifteen minutes per email.</i>
</p>

<h1 align="center">Phishing Guardian</h1>
<p align="center"><b>One click. 4+ intelligence sources. Under five seconds.</b></p>
<p align="center">Free. Open source. Built for the people who keep us safe.</p>

---

## The Problem

Walk through any Security Operations Center and you'll see the same routine at every desk.

An analyst opens a forwarded email, copies the first URL into VirusTotal, waits, copies the
sender's IP into AbuseIPDB, waits, runs a WHOIS lookup on the domain, checks PhishTank, checks
URLScan, then writes up findings by hand before moving to the next email.

For a team triaging 20–30 suspicious emails a day, that's a significant chunk of analyst time
spent on repetitive lookups rather than judgment calls — and the process varies from analyst to
analyst, which makes outcomes inconsistent. Phishing Guardian automates the lookups so the
analyst's time goes to the decision, not the data-gathering.

---

## What It Does

One interface. Every check automated. Results in seconds.

```
  Raw Email  ──────►  6 Sources Checked  ──────►  Risk Report
 (Headers +           in Parallel                 (Score + Actions)
   Body)
```

| Layer | What Gets Checked | Source |
|---|---|---|
| Authentication | SPF, DKIM, DMARC validation | Header parser |
| Sender identity | Display-name spoofing, Reply-To mismatch | Heuristic engine |
| URLs | Reputation, domain age, typosquatting | VirusTotal · PhishTank · OpenPhish · URLScan |
| Domains | Registration date, registrar, country | WHOIS |
| IP addresses | Abuse confidence, report history | AbuseIPDB |
| Attachments | SHA256 hash, file type, PDF JavaScript detection | VirusTotal · PDF parser |
| Content | Urgency keywords, generic greetings, threats | NLP heuristics |

All checked in parallel, typically returning a full result in under five seconds.

---

## Example Output

A phishing email lands in your inbox. You paste it into Phishing Guardian. Seconds later:

```
ANALYSIS RESULTS
─────────────────────────────────────────────
Risk Score        76 / 100 — HIGH
Confidence         MEDIUM
Sources Checked    PhishTank · OpenPhish · WHOIS · URLScan
Analysis Time      3.2 seconds

DETECTED INDICATORS
  • Lookalike domain: paypa1.com impersonates paypal.com
  • No SPF, DKIM, or DMARC authentication present
  • Urgency language detected: "URGENT", "immediately"
  • Generic greeting: "Dear Customer" instead of recipient's name

RECOMMENDED ACTIONS
  1. Block sender domain at email gateway
  2. Forward to SOC for investigation
  3. Delete from all user inboxes
  4. Notify team of active phishing campaign

  Full PDF report available for download
```

No manual lookups. The decision gets made in seconds, and the report is generated automatically.

---

## Why It's Worth Using

| | Manual triage | Phishing Guardian |
|---|---|---|
| Time per email | ~10–15 minutes | Under 5 seconds |
| Sources checked | Manually, inconsistently | 6 automatically, every time |
| Reports | Typed by hand | One-click PDF export |
| Analysis history | Scattered or nonexistent | Searchable database |
| Consistency across analysts | Varies | Identical process every time |

As a rough estimate: a team handling 20 suspicious emails a day at ~12 minutes each spends
roughly 4 hours daily on manual triage alone. Cutting that to seconds per email frees up a
meaningful chunk of analyst capacity — the exact savings will depend on your team's current
process and email volume.

---

## Running Cost

Every component runs on free infrastructure:

| Component | Technology | Cost |
|---|---|---|
| Backend | Python 3.12 + FastAPI | $0 |
| Database | SQLite (zero configuration) | $0 |
| URL reputation | VirusTotal free API | 500 req/day, $0 |
| URL reputation | PhishTank (no key required) | Unlimited, $0 |
| URL reputation | OpenPhish (no key required) | Unlimited, $0 |
| URL behavior | URLScan.io (no key required) | Unlimited, $0 |
| IP reputation | AbuseIPDB free API | 1,000 checks/day, $0 |
| Domain lookup | WHOIS library (built into Python) | Unlimited, $0 |
| Frontend | Vanilla HTML, CSS, JavaScript | $0 |
| PDF generation | ReportLab (open source) | $0 |
| Deployment | PythonAnywhere / Oracle Cloud free tier | $0 |

**The tool itself is free and always will be** — MIT licensed, no premium tier, no paid version.
The optional costs below are entirely for *upgraded third-party API quotas* (VirusTotal/AbuseIPDB
paid tiers) if you outgrow the free rate limits — Phishing Guardian works fully on the free tiers.

---

## Scaling With Your Team

The same codebase works at every stage — only your `.env` configuration changes.

**Solo analyst**
Local install, all free API tiers.
```bash
pip install -r requirements.txt
```
Cost: $0

**Small team (5–10 analysts)**
Deploy on PythonAnywhere or Render's free tier, share the URL, add free VirusTotal/AbuseIPDB keys.
Setup time: ~20 minutes. Cost: $0

**Larger SOC (50+ analysts)**
Dedicated cloud VM, VirusTotal Premium (~$50/mo), AbuseIPDB Premium (~$15/mo), Slack/Teams
alert integration. Setup time: ~1 hour. Cost: ~$90/month in optional API upgrades — the tool
itself remains free.

---

## What Phishing Guardian Is Not

Honest scope, no marketing fluff:

- **Not a replacement for EDR.** It analyzes phishing emails and files; it doesn't replace
  endpoint detection and response.
- **Not a SIEM.** It doesn't ingest logs or correlate events across your network.
- **Not AI-powered.** The current scoring engine is heuristic and rules-based. ML-based scoring
  is on the roadmap, not yet implemented.
- **Not a silver bullet.** No single tool catches everything — this is one layer in a
  defense-in-depth strategy.

**What it is:** a way to remove the repetitive, manual part of phishing triage so analyst time
goes toward judgment calls instead of copy-pasting into six different tools.

---

## Quick Start

No Docker, no database setup, no API keys required to get started.

```bash
# Clone the repository
git clone https://github.com/TurlaFSB/Phishing-Gaurdian.git
cd Phishing-Gaurdian

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate        # macOS / Linux
# .\venv\Scripts\activate       # Windows

# Install dependencies
pip install -r requirements.txt

# Start the application
python run.py
```

Open `http://localhost:8000`, paste an email, click Analyze.

Or use the hosted version: **https://phishing-gaurdian.onrender.com/**

Optional: add free API keys to `.env` for stronger detection coverage (VirusTotal, AbuseIPDB).
Takes about 30 seconds — see the documentation for details.

> **Note:** double-check whether "Phishing-Gaurdian" above is the intended repository name —
> if it's a typo for "Guardian," fix it in the actual GitHub repo/URL before publishing, since a
> broken clone link is the one thing in this README that would directly block a new user.

---

## Threat Intelligence Sources

| Source | Type | API Key Required? | Free Limit |
|---|---|---|---|
| [VirusTotal](https://virustotal.com) | URL & file hash vs. 70+ engines | Yes | 500/day |
| [AbuseIPDB](https://abuseipdb.com) | IP reputation & abuse history | Yes | 1,000/day |
| PhishTank | Community-verified phishing database | No | Unlimited |
| OpenPhish | AI-detected phishing URLs | No | Unlimited |
| URLScan.io | URL behavioral scanning | No | Unlimited |
| WHOIS | Domain registration & age | No | Unlimited |

These tools already existed individually — Phishing Guardian's contribution is wiring them
together into one automated workflow, so going from "I received a suspicious email" to "here's
a complete risk assessment with a downloadable PDF" takes one paste instead of six.

---

<p align="center">
  <b>Phishing Guardian</b><br>
  <sub>Free · Open Source · No Telemetry · No Tracking</sub><br><br>
  <sub>MIT License · Python 3.12+ · Built for the security community</sub>
</p>
