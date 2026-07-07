<p align="center">
  <i>To every security analyst who has ever copied a URL from an email, pasted it into VirusTotal, waited, repeated for five more tools, and then tried to explain to their boss why this takes 15 minutes per email.</i>
</p>

<br>

# Phishing Guardian

**One click. Six intelligence sources. Under five seconds.**

That's the difference between the tool you're using now and the one you're about to deploy. Free. Open source. Built for the people who keep us safe.

<br>

---

## The Problem Nobody Talks About

Walk through any Security Operations Center and you'll see the same scene playing out at every desk.

An analyst squints at a forwarded email. Opens VirusTotal. Copies the first URL. Pastes. Waits. Opens AbuseIPDB. Copies the sender's IP. Pastes. Waits. Opens WHOIS. Types the domain. Reads. Opens PhishTank. Searches. Opens URLScan. Pastes again. Opens Notepad. Writes down findings. Moves to the next email.

**Fifteen minutes. One email. Thirty emails a day. That's an entire workday lost to manual triage.**

This isn't a skills problem. It's a tooling problem. And nobody was solving it for teams without a six-figure budget. So we built it ourselves.

<br>

---

## What Phishing Guardian Does

One interface. Every check automated. Results in seconds.

<div align="center">

<table>
<tr>
<td align="center" width="200" style="padding:20px;background:#111;border:1px solid #222;border-radius:8px;">
<b style="color:#f5f5f7;font-size:1.1em;">📧 Raw Email</b><br>
<span style="color:#86868b;font-size:0.85em;">Headers + Body</span>
</td>
<td align="center" width="60" style="font-size:2em;color:#3b82f6;">→</td>
<td align="center" width="200" style="padding:20px;background:#111;border:1px solid #222;border-radius:8px;">
<b style="color:#f5f5f7;font-size:1.1em;">🔍 6 Sources</b><br>
<span style="color:#86868b;font-size:0.85em;">Checked in Parallel</span>
</td>
<td align="center" width="60" style="font-size:2em;color:#3b82f6;">→</td>
<td align="center" width="200" style="padding:20px;background:#111;border:1px solid #222;border-radius:8px;">
<b style="color:#f5f5f7;font-size:1.1em;">📊 Risk Report</b><br>
<span style="color:#86868b;font-size:0.85em;">Score + Actions</span>
</td>
</tr>
</table>

<p style="color:#3b82f6;font-weight:600;margin-top:16px;font-size:1.1em;">⏱ Time: Under 5 Seconds</p>

</div>

Every layer of the email is analyzed automatically:

| Layer | What Gets Checked | Source |
|-------|-------------------|--------|
| **Authentication** | SPF, DKIM, DMARC validation | Header parser |
| **Sender Identity** | Display name spoofing, Reply-To mismatch | Heuristic engine |
| **URLs** | Reputation, domain age, typosquatting | VirusTotal · PhishTank · OpenPhish · URLScan |
| **Domains** | Registration date, registrar, country | WHOIS |
| **IP Addresses** | Abuse confidence, report history | AbuseIPDB |
| **Attachments** | SHA256 hash, file type, PDF JavaScript | VirusTotal · PDF parser |
| **Content** | Urgency keywords, generic greetings, threats | NLP heuristics |

All in parallel. All in under five seconds.

<br>

---

## Real-World Example

A phishing email lands in your inbox. You paste it into Phishing Guardian. Three seconds later:

<div style="background:#111;border:1px solid #222;border-radius:8px;padding:24px;font-family:system-ui,-apple-system,sans-serif;color:#f5f5f7;max-width:620px;margin:16px auto;text-align:left;">

<div style="color:#3b82f6;font-size:1.2em;margin-bottom:16px;font-weight:700;">🛡️ ANALYSIS RESULTS</div>

<table style="width:100%;border-collapse:collapse;">
<tr>
  <td style="color:#86868b;padding:6px 0;">Risk Score</td>
  <td style="color:#f59e0b;font-weight:700;">76 / 100 — HIGH</td>
</tr>
<tr>
  <td style="color:#86868b;padding:6px 0;">Confidence</td>
  <td style="color:#f5f5f7;">MEDIUM</td>
</tr>
<tr>
  <td style="color:#86868b;padding:6px 0;">Sources Checked</td>
  <td style="color:#34c759;">PhishTank · OpenPhish · WHOIS · URLScan</td>
</tr>
<tr>
  <td style="color:#86868b;padding:6px 0;">Analysis Time</td>
  <td style="color:#f5f5f7;">3.2 seconds</td>
</tr>
</table>

<div style="margin-top:20px;color:#ef4444;font-weight:700;">🔴 DETECTED INDICATORS</div>
<ul style="color:#f5f5f7;margin-top:6px;padding-left:20px;">
  <li>Lookalike domain: <code style="color:#f59e0b;background:#1a1a1a;padding:2px 6px;border-radius:4px;">paypa1.com</code> impersonates <code style="color:#3b82f6;background:#1a1a1a;padding:2px 6px;border-radius:4px;">paypal.com</code></li>
  <li>No SPF, DKIM, or DMARC authentication present</li>
  <li>Urgency language detected: "URGENT", "immediately"</li>
  <li>Generic greeting: "Dear Customer" instead of recipient's name</li>
</ul>

<div style="margin-top:20px;color:#3b82f6;font-weight:700;">📋 RECOMMENDED ACTIONS</div>
<ol style="color:#f5f5f7;margin-top:6px;padding-left:20px;">
  <li>Block sender domain at email gateway</li>
  <li>Forward to SOC for investigation</li>
  <li>Delete from all user inboxes</li>
  <li>Notify team of active phishing campaign</li>
</ol>

<div style="margin-top:20px;text-align:center;padding:10px;background:#1a1a1a;border-radius:6px;">
  <span style="color:#86868b;">📥</span> <span style="color:#3b82f6;">Full PDF report available for download</span>
</div>

</div>

The analyst who reviewed this spent zero minutes on manual lookups. The decision was made in seconds. The report was generated automatically. The threat was contained.

<br>

---

## The Numbers That Matter

| Metric | Before | After |
|--------|--------|-------|
| Time per email | 10–15 minutes | Under 5 seconds |
| Sources checked per email | Manually, inconsistently | 6 automatically, every time |
| Reports generated | Manually typed in Notepad | One-click PDF download |
| Analysis history | None or scattered | Searchable database |
| Monthly cost | Free tools, massive time sink | Free tools, zero time sink |
| Consistency between analysts | Varies wildly | Identical process every time |

**If your team handles 20 suspicious emails a day, Phishing Guardian saves 5 hours of analyst time daily. That's 1,300 hours per year. That's a full-time salary recovered. The tool pays for itself on day one.**

<br>

---

## How It Costs Nothing to Run

Every component of Phishing Guardian runs on free infrastructure:

| Component | Technology | Cost |
|-----------|-----------|:---:|
| **Backend server** | Python 3.12 + FastAPI | $0 |
| **Database** | SQLite (zero configuration) | $0 |
| **URL reputation** | VirusTotal free API | 500 req/day · $0 |
| **URL reputation** | PhishTank — no key required | Unlimited · $0 |
| **URL reputation** | OpenPhish — no key required | Unlimited · $0 |
| **URL behavior** | URLScan.io — no key required | Unlimited · $0 |
| **IP reputation** | AbuseIPDB free API | 1,000 checks/day · $0 |
| **Domain lookup** | WHOIS library (built into Python) | Unlimited · $0 |
| **Frontend** | Vanilla HTML, CSS, JavaScript | $0 |
| **PDF generation** | ReportLab (open source) | $0 |
| **Deployment** | PythonAnywhere / Oracle Cloud free tier | $0 |

**Total operating cost: $0 per month. Forever.**

<br>

---

## Scaling With Your Organization

Phishing Guardian grows with you. The same codebase works at every stage:

<br>

**Solo Analyst — You, Today**
One laptop. Local installation. All free APIs.
Setup: pip install -r requirements.txt
Cost: $0

text

**Small Team — 5–10 Analysts**
Deploy on PythonAnywhere or Render free tier.
Share URL with team. Add VirusTotal and AbuseIPDB free keys.
Setup: 20 minutes
Cost: $0

text

**Enterprise SOC — 50+ Analysts**
Deploy on dedicated cloud VM. VirusTotal Premium ($50/mo).
AbuseIPDB Premium ($15/mo). Slack/Teams integration for real-time alerts.
Setup: 1 hour
Cost: ~$90/month

text

<br>

Every stage uses identical code. The only difference is a few lines in your `.env` file. No migrations. No downtime. No vendor lock-in.

<br>

---

## What Phishing Guardian Is Not

Honest scope. No marketing fluff.

- **Not a replacement for EDR.** This analyzes phishing emails and files. It does not replace endpoint detection and response.
- **Not a SIEM.** It does not ingest logs or correlate events across your network.
- **Not AI-powered.** The current scoring engine is heuristic and rules-based. Machine learning integration is on the roadmap.
- **Not a silver bullet.** No single tool catches everything. Phishing Guardian is one layer in a defense-in-depth strategy.

**What it is:** A force multiplier for the most repetitive, time-consuming part of security operations. A way to standardize phishing triage. A tool that gives analysts their time back.

<br>

---

## Quick Start

No Docker. No database setup. No API keys required. Just Python and five minutes.

```bash
# Clone the repository
git clone https://github.com/TurlaFSB/Phishing-Gaurdian.git
cd Phishing-Gaurdian

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate        # macOS / Linux
# .\venv\Scripts\activate       # Windows

# Install dependencies
pip install -r requirements.txt

# Start the application
python run.py
Open http://localhost:8000 in any browser. Paste an email. Click Analyze.

That's it.

Optional: Add free API keys to .env for stronger detection. Takes 30 seconds. Details in the documentation.


Available Threat Intelligence Sources
Source	Type	Needs Key?	Free Limit	Sign Up
VirusTotal	URL & file hash against 70+ engines	Yes	500/day	virustotal.com
AbuseIPDB	IP reputation & abuse history	Yes	1,000/day	abuseipdb.com
PhishTank	Community-verified phishing database	No	Unlimited	Built-in
OpenPhish	AI-detected phishing URLs	No	Unlimited	Built-in
URLScan.io	URL behavioral scanning	No	Unlimited	Built-in
WHOIS	Domain registration & age	No	Unlimited	Built-in



The free tools exist—VirusTotal, AbuseIPDB, PhishTank, URLScan—but nobody had connected them into a single automated workflow. Nobody had made it dead simple to go from "I received a suspicious email" to "here is the complete risk assessment with a downloadable PDF report."

MIT licensed. Free forever. No premium tier. No "contact sales." No catch.


Acknowledgments
Threat Intelligence Providers:
VirusTotal · AbuseIPDB · PhishTank · OpenPhish · URLScan.io · WHOIS

<p align="center"> <b>Phishing Guardian</b><br> <sub>Free · Open Source · No Telemetry · No Tracking · No Cost</sub><br><br> <sub>MIT License · Python 3.12+ · Built for the security community</sub> </p> ```