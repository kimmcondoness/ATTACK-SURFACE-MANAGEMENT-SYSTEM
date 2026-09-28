# Design Direction — Attack Surface Management (ASM)

> Transcribed from the actual decisions made while building this project (not invented).
> Edit anything below directly — you're the author here.

## Identity

An internal cybersecurity operations tool for Bluesify Solutions Sdn. Bhd. — used by IT
Administrators, Cybersecurity Analysts, and Threat Intelligence Analysts to discover, monitor and
assess their own authorized internet-facing assets. This is a working analyst tool, not a
public-facing marketing site or SaaS landing page. It should read like a SOC console: dense,
factual, and quick to scan under pressure — not like a product pitch.

## Personality

- Utilitarian and professional over decorative. A tool you trust with real vulnerability
  data, not a tool that's trying to impress you.
- Direct, plain language. No marketing voice: "Scan a target," "Findings & CVE report,"
  "Open ports & public services" — describe what a panel does, not what it promises.
- Terminal/ops-console inspired, but never at the cost of legibility. Monospace is used
  for data (counts, IDs, domains, ports), not as a "hacker aesthetic" gimmick.
- Honest about limitations: mock vs. real scan data is always labeled, not hidden; an
  NVD keyword match says "possible," not "confirmed."

## Palette

Two coexisting surfaces, used deliberately (not mixed within one component):

**Light surface** (page background, admin dashboard, login/signup forms)
- Paper background: `#f4f1e9`
- Paper hairline / borders: `#d9d3c1`
- Card white: `#ffffff`
- Body text: `#1c1f1a`
- Muted text: `#6b6a5f`

**Dark surface** ("widget" cards floating on the light page — Dashboard/Overview panels,
and the sidebar itself)
- Ink (sidebar, brand dark): `#0c1210`
- Panel background: `#101c16`
- Panel background (raised/hover): `#14241d`
- Panel border: `#1e3a2f`
- Panel text: `#eef4ef`
- Panel muted text: `#93a89c`

**Shared accent + severity scale** (used on both surfaces, with tinted/opacity variants
for the dark surface so contrast holds)
- Accent green: `#3fae6a` / dark `#2c8752` — the one brand color, used for primary
  actions, active nav state, and "healthy/completed" status
- Critical: `#b3261e` (light) / `#f0a29e` on dark tint
- High: `#b5651d` (light) / `#f2c393` on dark tint
- Medium: `#a68b12` (light) / `#e8dc9c` on dark tint
- Low: `#4c6b8a` (light) / `#a9cdec` on dark tint

Palette rule: 1 accent (green) + the 4-step severity scale, on a light/dark surface pair.
Severity colors are functional, not decorative — they always mean the same thing (critical
→ high → medium → low) everywhere they appear.

## Typography

- Sans: Segoe UI (system stack) for all prose, labels, and UI chrome.
- Mono: Consolas (system stack) for anything data-shaped: counts, IDs, domains, CVEs,
  ports, timestamps, dork queries. The reason: this is a tool where analysts need to
  distinguish "a value" from "a description" at a glance, and monospace does that job
  without extra styling.
- No large display/hero typography anywhere — there is no hero section in this product.

## Composition

- Server-rendered pages with a persistent sidebar (dark) and a light main content area.
- Content is organized as stacked panels (cards), each answering one question: targets,
  assets, open ports, scan history, findings, reports. Panels exist because the data model
  has that many distinct entities — not because a template expects N sections.
- Stat tiles carry a thin proportional progress bar under the number (relative to the
  largest of the group) rather than a decorative sparkline.
- Two donut charts (scan status, finding severity) plus a shared 1M/3M/6M/12M range
  filter and a target-scope filter — both are real, working controls, not display-only.
- A dashboard is filtered by ownership always (users on their own targets, or "All"), so
  a freshly scanned site never gets visually mixed into unrelated historical data.

## Motion

Minimal and functional only: panels lift slightly with a soft shadow on hover, table rows
highlight on hover, buttons/inputs transition border-color on focus/hover. No scroll-reveal,
no parallax, no entrance animations — an analyst re-visiting this dashboard hourly should
never wait on a page to "finish animating in."

## Dial

`ENERGY 1 / RHYTHM 2 / MOTION 1`

- **ENERGY 1**: calm, GOV.UK/ops-console register — the opposite of a startup landing page.
- **RHYTHM 2**: panels are consistently structured (head + content), but vary in shape
  by necessity — a donut chart panel looks different from a data table panel, which looks
  different from the scan-control panel. That variation comes from content, not decoration.
- **MOTION 1**: hover/focus feedback only, as described above.

Design Read: *"Reading this as: an internal SOC/ASM console for cybersecurity analysts and
IT admins, in a utilitarian ops-console style, dial ENERGY 1 / RHYTHM 2 / MOTION 1."*
