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

The system supports four roles.

## Cybersecurity Analyst

Responsible for

- monitoring assets
- performing scans
- analyzing vulnerabilities
- reviewing reports

Operational: owns targets, triggers Subfinder/Nmap/Nuclei scans, works from
the Dashboard scoped to their own authorized targets.

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

Analytical, not operational: does not create targets or trigger scans --
works from the dedicated Threat Intelligence page instead of the Dashboard.
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

## Security Team

Responsible for

- reviewing risks
- monitoring attack surface
- responding to findings
- reviewing reports

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
- Start Vulnerability Scan
- View Scan Progress
- Scan History

---

## Vulnerabilities

Display

- Severity
- CVE
- Description
- Affected Asset
- Recommendation
- Status

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
- Vulnerabilities
- Risk Summary
- Statistics

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
- Security Team

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