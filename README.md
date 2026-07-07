
<p align="center">
  <i>To every security analyst who has ever copied a URL from an email, pasted it into VirusTotal, waited, repeated for five more tools, and then tried to explain to their boss why this takes 15 minutes per email.</i>
</p>

<br>

# Phishing Guardian

**One click. Six intelligence sources. Five seconds.**

That's the difference between the tool you're using now and the one you're about to deploy.

<br>

---

## The Problem Nobody Talks About

Walk through any Security Operations Center and you'll see the same scene playing out at every desk:

An analyst squints at a forwarded email. Opens VirusTotal. Copies the first URL. Pastes. Waits. Opens AbuseIPDB. Copies the sender's IP. Pastes. Waits. Opens WHOIS. Types the domain. Reads. Opens PhishTank. Searches. Opens URLScan. Pastes again. Opens Notepad. Writes down the findings. Moves to the next email.

**Fifteen minutes. One email.**

Now multiply that by thirty emails a day. That's seven and a half hours—an entire workday—spent on manual triage. Not hunting threats. Not improving defenses. Not training junior analysts. Just copying and pasting between browser tabs.

This isn't a skills problem. It's a tooling problem. And nobody was solving it for teams without a six-figure budget.

**So we built it ourselves.**

<br>

---

## What This Tool Actually Does

Phishing Guardian consolidates your entire phishing triage workflow into a single interface:
┌─────────────────────────────────────────────────────────┐
│ │
│ PASTE EMAIL → CLICK ANALYZE → GET REPORT │
│ │
│ ┌─────────────┐ ┌─────────────┐ ┌────────────┐ │
│ │ Raw email │ │ 6 sources │ │ Risk │ │
│ │ with │───▶│ checked │───▶│ score │ │
│ │ headers │ │ in parallel│ │ Report │ │
│ └─────────────┘ └─────────────┘ └────────────┘ │
│ │
│ Time: < 5 seconds │
│ │
└─────────────────────────────────────────────────────────┘

text

But that undersells it. Here's everything it analyzes, automatically, without you touching a single external website:

| Layer | What Gets Checked | Source |
|-------|-------------------|--------|
| **Authentication** | SPF, DKIM, DMARC validation | Header parser |
| **Sender Identity** | Display name spoofing, Reply-To mismatch | Heuristic engine |
| **URLs** | Reputation, domain age, typosquatting | VirusTotal, PhishTank, OpenPhish, URLScan |
| **Domains** | Registration date, registrar, country | WHOIS |
| **IP Addresses** | Abuse confidence, report history | AbuseIPDB |
| **Attachments** | SHA256 hash, file type, PDF JavaScript | VirusTotal, PDF parser |
| **Language** | Urgency keywords, generic greetings, threats | NLP heuristics |

**All in parallel. All in under five seconds.**

<br>

---

## The Numbers That Matter

| Metric | Before | After |
|--------|--------|-------|
| Time per email | 10–15 minutes | < 5 seconds |
| Sources checked | Manually, inconsistently | 6 automatically, every time |
| Reports generated | Manually typed | One-click PDF download |
| History | None (or scattered) | Searchable database |
| Cost | Free tools, massive time sink | Free tools, zero time sink |
| Consistency | Depends on the analyst | Identical process every time |

If your team handles 20 suspicious emails a day, this tool saves **5 hours of analyst time daily.** That's 1,300 hours a year. That's a full-time salary recovered.

<br>

---

## How We Built It (And Why It Costs Nothing)

Phishing Guardian runs on entirely free infrastructure:

| Component | Technology | Cost |
|-----------|-----------|------|
| **Backend** | Python 3.12 + FastAPI | $0 |
| **Database** | SQLite (no server needed) | $0 |
| **URL Analysis** | VirusTotal free API | 500 req/day — $0 |
| **URL Analysis** | PhishTank (no key needed) | Unlimited — $0 |
| **URL Analysis** | OpenPhish (no key needed) | Unlimited — $0 |
| **URL Analysis** | URLScan.io (no key needed) | Unlimited — $0 |
| **IP Reputation** | AbuseIPDB free API | 1,000 checks/day — $0 |
| **Domain Lookup** | WHOIS (built into Python) | Unlimited — $0 |
| **Frontend** | Vanilla HTML/CSS/JS | $0 |
| **PDF Reports** | ReportLab (open source) | $0 |

**Total operating cost: $0 per month.**

When your team grows and you need higher API limits, upgrading is a single-line change in a config file. No code changes. No downtime.

<br>

---

## A Real Example

Here's what happens when a phishing email hits your inbox and you run it through Phishing Guardian:

**Input:**
From: "PayPal Security" security@paypa1.com
Subject: URGENT: Your Account Has Been Suspended

Dear Customer,

Unusual activity has been detected on your account.
Please verify immediately: https://paypa1.com/verify

Regards,
PayPal Security Team

text

**Output (3.2 seconds later):**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🛡️ ANALYSIS RESULTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Risk Score: 76/100 — HIGH
Confidence: MEDIUM
Sources checked: PhishTank, OpenPhish, WHOIS, URLScan

🔴 DETECTED INDICATORS:
• Lookalike domain: paypa1.com impersonates paypal.com
• No SPF/DKIM/DMARC authentication present
• Urgency language: "URGENT", "immediately"
• Generic greeting: "Dear Customer"
• Sender domain registered < 1 year ago

📋 RECOMMENDED ACTIONS:

Block sender domain at email gateway

Forward to SOC for investigation

Delete from all user inboxes

Warn team about this campaign

📥 Full PDF report: Download
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

text

The analyst who reviewed this spent zero minutes on manual lookups. The decision was made in seconds. The report was generated automatically. The threat was contained.

<br>

---

## Scaling With Your Organization

Phishing Guardian is designed to grow with you, not hold you back:

**Solo Analyst (You, Today)**
- Local installation on your laptop
- All free APIs
- Zero cost. Zero setup time beyond `pip install`

**Small Team (5–10 Analysts)**
- Deploy on PythonAnywhere or Render (free tiers)
- Share the URL with your team
- Add VirusTotal and AbuseIPDB free keys for better detection
- Still zero cost

**Enterprise SOC (50+ Analysts)**
- Deploy on dedicated cloud VM
- Upgrade to VirusTotal Premium ($50/mo)
- Add AbuseIPDB Premium ($15/mo)
- Integrate with Slack/Teams for real-time alerts
- Total: ~$90/month for an enterprise-grade phishing triage platform

**Every stage uses the same codebase.** The only difference is a few lines in your `.env` file.

<br>

---

## What This Is Not

Let's be honest about scope, because technical accuracy matters:

- **Not a replacement for EDR.** This analyzes phishing emails and files. It doesn't replace endpoint detection.
- **Not a SIEM.** It doesn't ingest logs or correlate events across your network.
- **Not AI-powered (yet).** The current scoring is heuristic and rules-based. ML integration is on the roadmap.
- **Not a silver bullet.** No tool catches everything. Phishing Guardian is one layer in a defense-in-depth strategy.

**What it IS:** A massive time-saver for the most repetitive, soul-crushing part of security operations. A force multiplier for small teams. A way to standardize phishing triage across your organization.

<br>

---

## Getting Started (No, Really — 5 Minutes)

```bash
git clone https://github.com/TurlaFSB/Phishing-Gaurdian.git
cd Phishing-Gaurdian
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python run.py
Open http://localhost:8000. Paste an email. Click Analyze.

That's it. No database setup. No API key configuration. No Docker. The tool works out of the box using completely free threat intelligence sources.

Adding API keys takes 30 seconds and makes the analysis stronger. But it's optional.


Why We Built This Instead of Buying Something
Because the cheapest commercial phishing analysis platform we could find started at $5,000 a year. For a small team, that's a significant investment. For a student or independent analyst, it's impossible.

The free tools exist—VirusTotal, AbuseIPDB, PhishTank, URLScan—but nobody had connected them into a single workflow. Nobody had automated the tedious parts. Nobody had made it dead simple to go from "I received a suspicious email" to "here's the risk assessment."

So we did.

And because we benefit from the open-source community's free tools, we're giving our work back to that community. MIT licensed. Free forever. No premium tier. No "contact sales." No catch.


The Roadmap
What we're building next, in order of priority:

Priority	Feature	Impact
🔴 Highest	Email forwarding for auto-analysis	Eliminates copy-paste entirely
🔴 Highest	Slack/Teams webhook integration	Real-time SOC alerts
🟡 Medium	Multi-user support with RBAC	Team deployment
🟡 Medium	Browser extension	One-click from Gmail/Outlook
🟢 Lower	ML-based detection model	Better heuristic scoring
🟢 Lower	REST API with key auth	Programmatic access

Contributing
This is a security tool built by practitioners, for practitioners. If you see something that could be better:

Open an issue — tell us what's broken or what's missing

Submit a PR — we review quickly and merge what works

Share it — the more people who use it, the better it gets

No CLA. No contributor agreement. No corporate ownership. MIT means MIT.


Acknowledgments
Threat Intelligence Providers:

VirusTotal, for making their API free for low-volume use

AbuseIPDB, for community-driven IP reputation

PhishTank and OpenPhish, for maintaining free phishing databases

URLScan.io, for free behavioral URL scanning

Open Source Projects:

FastAPI, for making Python APIs a joy to build

SQLAlchemy, for the best ORM in any language

ReportLab, for PDF generation without licensing fees

The entire Python ecosystem, for making this possible

Personal:

My mentor, who taught me that knowledge shared is knowledge multiplied

Every security analyst who's ever pasted a URL into VirusTotal at 11 PM on a Friday


<p align="center"> <b>Phishing Guardian</b><br> Free. Open source. Built for the people who keep us safe.<br><br> <sub>MIT License · Python 3.12+ · No telemetry · No tracking · No cost</sub> </p> ```