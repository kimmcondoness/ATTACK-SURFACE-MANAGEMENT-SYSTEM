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

- vulnerability scanning
- security misconfiguration detection

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
(Nuclei)
    ↓
Dork Exposure Check
(direct requests)
    ↓
Risk Analysis
    ↓
Dashboard
    ↓
Generate Report
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
- Pause / Resume / Stop a running scan
- View Scan Progress
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

---

## Threat Intelligence

Only Threat Intelligence Analyst and IT Administrator

Display

- Live findings across every authorized target, org-wide (not limited to
  targets the viewer personally scanned)
- CISA KEV matches
- Prioritized findings, ranked by real CVSS score, CISA KEV status and
  public exploit availability
- Recent CISA KEV catalog additions

Functions

- Export a Threat Briefing (CSV)

Read-only: cannot create targets, run scans, or change finding status.

---

## User Management

Only IT Administrator

Functions

- Create User
- Edit User
- Delete User
- Assign Roles

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

---

## Authentication

Use

- Flask Session

or

- JWT

Session timeout

30 minutes.

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