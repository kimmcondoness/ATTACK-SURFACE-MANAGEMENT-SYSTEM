# Attack Surface Management (ASM) System

## Project Overview

This project is an undergraduate Final Year Project (FYP) developed for **Bluesify Solutions Sdn. Bhd.**, a cybersecurity service provider.

The objective is to develop a **web-based Attack Surface Management (ASM) system** that allows an organization to discover, monitor, and assess its own **internet-facing digital assets**.

This is **NOT** an offensive security platform.

The system only scans assets that are **owned or explicitly authorized** by the organization.

---

# Project Objectives

1. Discover internet-facing digital assets.
2. Detect vulnerabilities and security misconfigurations.
3. Provide centralized monitoring, risk prioritization, and reporting.

## How each objective is met

| Objective | What delivers it |
|---|---|
| Automatically discover **and continuously monitor** internet-facing assets | Subfinder and Nmap discover assets and services on one click. **Continuous monitoring** re-scans each target daily, weekly or monthly on its own (background scheduler), tracks every asset (new / missing / back), and records what changed between scans in **Changes detected**. The owner is emailed about the important changes. |
| Detect vulnerabilities and security misconfigurations | Built-in **configuration checks** (HTTPS and TLS certificate, security headers, information disclosure, cookies, CORS) run on every scan and need no extra tool. Also: NVD CVE matching on detected service banners, 40 direct **exposure checks** for what Google dorks look for (exposed `.env`, `.git`, backups, debug pages, admin tools, public buckets), and Nuclei's template scan when Nuclei is installed. Findings are enriched with CVSS, CISA KEV and EPSS. A finding that a later scan no longer detects is marked resolved automatically. |
| Centralized dashboard, risk prioritization and reporting | One dashboard: live radar, charts, changes, targets, dorking and scan history; inventory pages; Findings & CVE Report with triage; risk score per finding and per target; PDF/CSV reports with mitigation steps; a Threat Intelligence page for analysts; an IT Administrator user directory. |

---

# What is Attack Surface Management?

Attack Surface Management (ASM) is the continuous process of identifying every digital asset exposed to the Internet, evaluating its security posture, detecting vulnerabilities, and helping security teams reduce cyber risk before attackers exploit exposed systems.

The project focuses only on the **external attack surface**.

Examples:

- Domains
- Subdomains
- IP Addresses
- Web Applications
- APIs
- Open Ports
- Public Services

---

# Intended Users

The system supports three roles. Each owns a different question, and none can do another's job.

## Cybersecurity Analyst

Responsible for

- monitoring assets
- performing scans
- triaging findings (open, in progress, resolved, false positive)
- generating technical scan reports (PDF/CSV)

Operational: owns targets, triggers Subfinder/Nmap/Nuclei scans, works from
the Dashboard and inventory scoped to their own authorized targets. Asks
"what is exposed, and what did the scanners find?" and is the only role that
changes finding status (besides the IT Administrator).

---

## Threat Intelligence Analyst

Responsible for

- reviewing findings for real-world exploitation risk, not just severity
- cross-referencing CVEs against CVSS score, the CISA Known Exploited
  Vulnerabilities (KEV) catalog, and public exploit availability
- triaging/prioritizing findings org-wide (across every authorized target,
  not only ones they personally scanned)
- tracking general threat landscape awareness (recent CISA KEV additions)
  independent of the organization's own current findings

Analytical, read-only: does not create targets, trigger scans, change finding
status or generate scan reports. Has no access to the Dashboard or inventory --
works only from the Threat Intelligence page and exports a Threat Briefing CSV
(org-wide, prioritized). Asks "which findings are actually being exploited?".
See `services/risk_service.py` (`vulnerability_priority`), `services/kev_service.py`,
and `services/cve_lookup.py` for the scoring methodology.

---

## IT Administrator

Responsible for

- managing assets
- maintaining users
- configuring scans
- monitoring dashboard

---

# Technology Stack

## Backend

- Flask
- Python

## Database

- MySQL

## Local Environment

- Laragon (local Windows dev)

## Production Deployment

Supported on both Linux and Windows/IIS -- see [DEPLOYMENT.md](DEPLOYMENT.md)
for systemd/Nginx and IIS/Waitress setup, prerequisites, and the
single-process constraint the live scan controls depend on.

## Frontend

- HTML
- CSS
- Bootstrap 5
- JavaScript
- Chart.js

---

# Security Tools

The backend integrates with:

## Subfinder

Purpose

- discover subdomains

---

## Nmap

Purpose

- identify open ports
- detect exposed services

---

## Nuclei

Purpose

- template-based vulnerability scanning
- security misconfiguration detection

Optional: when Nuclei is installed its findings are added to every vulnerability scan.
When it is not installed the scan says so and carries on with the built-in configuration
checks below. The app never invents findings.

---

## Built-in configuration checks

Run on every vulnerability scan (`scanner/config_scanner.py`), with nothing to install.
They are ordinary requests to the target's own hosts (a few GETs, one TRACE, one TLS
handshake); nothing is exploited.

- HTTPS: not offered at all, or plain HTTP that does not redirect to it
- TLS certificate: expired, wrong hostname, not trusted, expiring within 14 days; TLS 1.0 / 1.1 accepted
- Security headers: Strict-Transport-Security, Content-Security-Policy, clickjacking protection,
  X-Content-Type-Options, Referrer-Policy
- Information disclosure: version numbers in `Server`, `X-Powered-By`, `X-AspNet-Version`
- Cookies missing `Secure` / `HttpOnly`; CORS that lets any website read responses; HTTP TRACE enabled

Only a real page (a 2xx response) is judged, so an error, a block page or a redirect to
another site is never reported as "missing headers". Findings are titled `[Config] ...`
and carry their own step-by-step mitigation.

---

## Continuous monitoring

Turn it on per target (Your targets, Monitoring column): **Daily, Weekly or Monthly**.

- A background scheduler (checks every minute) starts the same full scan a person would,
  for every authorized target that is due. A target is claimed with one atomic database
  update, so it can never be scanned twice for the same period.
- **Changes detected** on the dashboard lists what differs from the previous scan:
  new asset, asset missing (not returned by two discovery runs in a row) and asset back;
  new finding, fixed (a deterministic check no longer detects it: the finding is marked
  resolved) and reopened. The first scan of a target only sets the baseline.
- Assets are de-duplicated across scans, and a host discovery says is gone is no longer scanned.
- The owner is emailed once per scan when something important changed (a new or missing
  asset, or a new or reopened critical/high finding). Without `MAIL_SERVER` the message is
  only logged.
- Settings (`config.py`): `MONITOR_SCHEDULER_ENABLED`, `MONITOR_POLL_SECONDS`,
  `MONITOR_MAX_CONCURRENT_SCANS`, `MONITOR_ALERT_EMAILS`.
- Existing databases are upgraded in place at start-up (new columns and the new tables
  are added, nothing is lost): see `database/upgrade.py`.

### Monitoring keeps running when nobody is signed in, and you can prove it

The scheduler lives in the server process, not in a browser session, so signing out (or a
session timing out) never pauses it. Three things make that visible:

- **Monitoring log** (`monitor_runs` table, *Continuous monitoring* panel on the Dashboard):
  every scan the scheduler starts, and every manual scan of a monitored target, with when it
  started, who started it (Scheduler / You), how it ended (Completed, Failed, Stopped,
  Interrupted), how long it took, what it found ("2 new assets, 1 new finding") and whether the
  owner was emailed.
- **Engine heartbeat** (`monitor_heartbeat` table): the scheduler writes its pulse after every
  check, so the status line ("Monitoring engine active, last check 22s ago") comes from the
  database and is true whoever is looking. It turns amber/red when the scheduler goes quiet.
  `GET /workspace/monitoring/status` returns the same as JSON, and `GET /api/health/monitoring`
  (no sign-in) returns 200 while the engine is alive and 503 when it is not, for an uptime checker.
- **While you were away**: `users.last_seen_at` remembers when each user was last here. When they
  sign back in, the Overview and Dashboard say, for example, "Monitoring kept running while you
  were away. Since you were last here (2026-10-03 23:35 UTC), 3 scheduled scans ran and 2 changes
  were detected."

A restart does not lose monitoring either: schedules and timestamps live in the database, the
scheduler checks straight away when the server starts (catching up on anything that came due while
it was down), and any scan the previous process left half-done is closed as *Interrupted*. If that
was a scheduled scan, it is started again at the next check, so a monthly target does not wait a
month because of a restart.

Only authorized targets are ever scanned, on a schedule or otherwise.

---

---

## Google Dorking

Purpose

- OSINT discovery
- identify publicly indexed assets
- confirm which exposures are real

The dashboard lists 76 curated dork queries per target (links that open in Google).
Each scan also runs a **dork exposure check** (`scanner/exposure_scanner.py`): it
requests the matching paths on the host itself (`/.env`, `/.git/config`, backups, SQL
dumps, debug pages, admin tools, public buckets and more) and only records a finding
when the response *content* matches, so catch-all pages and login redirects are not
counted. Confirmed exposures appear as `[Dork]` findings with a risk score and
mitigation steps, in the Findings page and both report formats. Exposed secrets are
never copied out; evidence is a status, a size and variable names only.

Google Dorking is only used on **authorized organization assets**.

---

# System Workflow

```text
Login
    ↓
Dashboard
    ↓
Create Authorized Target
    ↓
Asset Discovery
(Subfinder)
    ↓
Store Assets
(MySQL)
    ↓
Port Discovery
(Nmap)
    ↓
Store Services
    ↓
Vulnerability Scan
(built-in configuration checks
 + NVD CVE matching
 + Nuclei when installed)
    ↓
Dork Exposure Check
(direct requests)
    ↓
Change Detection
(new / missing assets, new / fixed findings)
    ↓
Risk Analysis
    ↓
Dashboard + Alert Email
    ↓
Generate Report

Continuous monitoring: the scheduler repeats the whole scan chain
for every monitored target when it is due.
```

---

# Backend Architecture

The backend follows a modular architecture.

```text
Flask

├── Authentication
├── User Management
├── Target Management
├── Asset Discovery
├── Scanner Integration
├── Vulnerability Module
├── Continuous Monitoring
├── Risk Analysis
├── Dashboard API
├── Reporting
└── Audit Logs
```

Each module should remain independent.

---

# Database Design

Main tables

- users
- authorized_targets
- assets
- ports_services
- vulnerabilities
- scans
- reports
- monitor_events (changes noticed by continuous monitoring)
- monitor_runs (the monitoring log: every scan that counts as monitoring, and how it ended)
- monitor_heartbeat (the scheduler's pulse: one row, rewritten on every check)
- report_shares (reports an analyst has shared with Threat Intelligence)

Continuous monitoring adds `monitor_interval_days` and `monitor_last_run_at` to
`authorized_targets`, `last_seen_at`, `status` and `missed_runs` to `assets`, and `last_seen_at`
to `users`.

Relationships

```
User
    ↓
Authorized Target
    ↓
Assets
    ↓
Ports
    ↓
Vulnerabilities
    ↓
Reports
```

---

# Frontend Pages

## Login

Functions

- Login
- Remember Session
- Logout

---

## Dashboard

Display

- Total Assets
- Vulnerabilities
- Critical Risks
- High Risks
- Scan Status
- Recent Findings
- Charts
- Asset Summary
- Google Dorking (curated queries per target, with confirmed exposures flagged)
- Long tables (Your targets, Scan history) are paged 10 rows at a time with page numbers
- Changes detected: what changed between scans (new / missing assets, new / fixed /
  reopened findings), following the selected target
- Monitoring column in Your targets: Off / Daily / Weekly / Monthly, with the next scan time
- Live attack surface radar: assets ringed by their worst live finding (riskiest in the
  centre), with callouts for the top findings. The radar sits still until a scan starts;
  then the sweep runs and the picture updates live, and it stops when the scan ends.
  The scan-activity and finding-trend charts wait too: they show their result only after
  the scan has finished

---

## Asset Management

Functions

- Add Target
- Edit Target
- Delete Target
- View Assets
- Search
- Filter

---

## Asset Details

Display

- Domain
- IP
- URL
- Ports
- Services
- Technologies
- Discovery Date

---

## Scan Management

Functions

- Start Asset Discovery
- Start Port Discovery
- Start Vulnerability Scan
- Start Dork Exposure Check (confirms Google dork exposures directly on the host)
- Set a monitoring schedule per target (automatic re-scans; see Continuous monitoring)
- Pause / Resume / Stop a running scan
- View Scan Progress (live elapsed timer that excludes paused time, and a progress
  bar based on the scan phases actually finished; survives a page reload)
- Scan History

---

## Vulnerabilities

Also called Findings & CVE Report -- one page combining the findings list,
exports and PDF/CSV report generation.

Display

- Severity
- CVE
- CVSS Score
- Risk Score (CVSS, or a severity weight when there is no CVE, boosted for a
  CISA KEV match or a known public exploit)
- Description
- Affected Asset
- Recommendation / Mitigation Steps
- Status

Functions

- Set Triage status: Open, In Progress, Resolved, False Positive
  (Cybersecurity Analyst and IT Administrator only)
- Select and delete findings (e.g. ones with no confirmed CVE)
- Export findings as JSON, CSV or Markdown

Filters

- Critical
- High
- Medium
- Low

---

## Reports

Generate

- PDF
- CSV

Report contains

- Assets
- Vulnerabilities, with CVSS and risk score
- Mitigation steps and a suggested timeframe per finding
- Risk Summary
- Statistics

Report history shows each report's Read / Unread state, per user.

Share with Threat Intelligence

- Each report in the history has a **Share** button (with an optional note). The report appears in
  the Threat Intelligence inbox and they download the very same file the analyst exported.
- The history shows whether it is shared and whether Threat Intelligence has downloaded it, and the
  analyst can **Withdraw** it at any time. A report is shared at most once; only its owner can share
  or withdraw it.

---

## Threat Intelligence

Only Threat Intelligence Analyst and IT Administrator

Display

- Live findings across every authorized target, org-wide (not limited to
  targets the viewer personally scanned)
- CISA KEV matches
- Prioritized findings, ranked by real CVSS score, CISA KEV status and
  public exploit availability, with each CVE's EPSS score (FIRST.org's estimated chance
  of exploitation in the next 30 days), a colour-coded status (open in red, in progress
  in amber), CVE links to the NIST NVD, and a keyword / severity filter
- Recent CISA KEV catalog additions
- **Reports shared by analysts**: the inbox of reports Cybersecurity Analysts have shared (target,
  format, who shared it, when, their note, New / Downloaded). Download gives the identical PDF or
  CSV the analyst exported. "New" is tracked per Threat Intelligence analyst.

Functions

- Export a Threat Briefing (CSV)
- Download reports shared by analysts

Read-only: cannot create targets, run scans, or change finding status.

---

## User Management

Only IT Administrator

Functions

- Create User
- Edit User
- Delete User
- Assign Roles

User directory (Active Directory style): the admin dashboard lists every user with
a search box, and **Manage** opens that user's page with a left menu:

- Profile: identity and account details; change name, username and email
  (validated, and must stay unique)
- Access: change role, and see what that role can do
- Targets: the user's authorized targets with asset and live-finding counts
- Authentication: reset password (same password rules), lock / unlock account,
  reset MFA (makes every trusted device ask for the email code again)
- Activity: what the user did and what administrators changed on the account

Users cannot edit their own username or email; only an IT Administrator can. An
administrator cannot change their own role or lock their own account. A locked
account is signed out immediately.

---

# Security Requirements

This project is cybersecurity focused.

Follow secure coding practices.

## SQL Injection

Never use raw SQL.

Always use SQLAlchemy ORM.

---

## Password Security

Use

```
bcrypt
```

Never store plaintext passwords.

Password requirements (enforced on sign up, password reset and admin-created
accounts; a password that misses any rule is rejected)

- more than 8 characters
- at least one uppercase letter
- at least one number
- at least one special character

---

## Authentication

Use

- Flask Session

or

- JWT

Session timeout

30 minutes.

Email verification code (MFA)

Asked once every 7 days per browser, not at every sign-in. After a correct code the
browser is trusted for 7 days, counted from that moment; signing in again does not
extend it, and signing out does not cancel it. The code is asked again after 7 days,
on a new browser or after cookies are cleared, or after an IT Administrator resets
the user's MFA or password. IT Administrators are not asked for a code.

---

## Authorization

Role-Based Access Control

Roles

- IT Administrator
- Cybersecurity Analyst
- Threat Intelligence Analyst

---

## Input Validation

Validate

- domains
- URLs
- IP addresses

Reject

- invalid formats
- shell characters
- dangerous input

---

## Command Injection

Never execute

```
subprocess(..., shell=True)
```

Always use

```
shell=False
```

Validate every target before execution.

---

## CSRF

Protect every POST request.

---

## XSS

Escape output.

Sanitize user input.

---

## Secure Headers

Use

- CSP
- X-Frame-Options
- X-Content-Type-Options
- Referrer Policy

---

## Logging

Log

- Login
- Logout
- Scan
- Report Generation
- Errors

Do not log passwords.

---

# Authorization Rule

Only scan assets that belong to the organization.

Reject scanning of

- random domains
- public websites
- unauthorized targets

Each target must be marked as

```
Authorized = True
```

before scanning.

---

# Folder Structure

```text
asm-system/

app.py

config.py

models.py

routes/

services/

scanner/

templates/

static/

reports/

database/

utils/
```

---

# Coding Standard

Follow

- PEP8
- Modular Architecture
- REST API Design
- Separation of Concerns
- Reusable Services

Avoid

- duplicated code
- business logic inside routes
- SQL inside HTML
- scanner code inside controllers

---

# UI Style

Theme

Modern Cybersecurity Dashboard

Colors

- Dark
- Blue
- White

Responsive

Desktop first

Use Bootstrap 5.

---

# Project Goal

Build a realistic Attack Surface Management prototype suitable for an undergraduate cybersecurity FYP.

Prioritize:

- clean architecture
- secure coding
- maintainability
- readability
- modular design

Do not build an offensive hacking tool.

The final system should demonstrate the complete workflow:

Authorized Target

↓

Asset Discovery

↓

Port Discovery

↓

Vulnerability Detection

↓

Risk Analysis

↓

Dashboard

↓

Reporting

All scanning must remain restricted to **authorized organizational assets only**.