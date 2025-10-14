# HTB — Holmes CTF 2025 — Personal Writeups

**Author:** `Preetha`  
**Event:** Hack The Box — Holmes CTF 2025 (team participation)  
**Personal focus:** I worked hands‑on on **two** challenges: **The Card** and **The Enduring Echo**.  

---

## Table of contents
- [Overview](#overview)
- [Repository structure](#repository-structure)
- [The Enduring Echo](#the-enduring-echo)
- [The Card](#the-card)
- [Artifacts & evidence](#artifacts--evidence)
- [How to reproduce / run locally](#how-to-reproduce--run-locally)
- [Contact](#contact)

---

## Overview
I participated as a team in the HTB Holmes CTF (2025). The two challenges I personally completed and documented here are:

- **The Card** — forensic triage & log correlation (summary in `The_Card/README.md`)  
- **The Enduring Echo** — disk forensics, Windows event log parsing, persistence analysis, and pivot detection (detailed in `The_Enduring_Echo/README.md`)

All artifacts are sanitized and exported from lab images. I can demonstrate any step live or provide additional sanitized exports on request.

---

## Repository structure
```
HTB-Holmes-CTF/
├── README.md
├── The_Card.md
│ ├── artifacts/
│ │ ├── linked_campaigns.png
└── The_Enduring_Echo.md
├── README.md
├── artifacts/
│ ├── evtx-parsed.csv
│ ├── timeline.csv
│ ├── JM.ps1
│ ├── screenshot-timeline.png
│ └── psreadline-history-excerpt.txt
└── notes.txt
```
---
## [The Card](/HTB-Holmes-CTF/The_Card.md)

This challenge involved analyzing web server logs from a honeypot to trace an attacker’s activity.  
Key tasks included identifying the attacker’s user-agent, detecting web shell deployment, tracking data exfiltration, and mapping threat intelligence indicators using the CogWork platforms.

## The Enduring Echo
---
## Artifacts & evidence
Key artifacts included:
- Parsed EVTX CSV exports (`evtx-parsed.csv`) filtered for Security events of interest (e.g., 4688, 4720).  
- Timeline exports (`timeline.csv`) used in Timeline Explorer.  
- Extracted persistence script (`JM.ps1`) and scheduled task XML screenshot.  
- Screenshots of timeline and relevant event filters.

---

## How to reproduce / run locally
1. Clone the repo.  
2. Open challenge folder and view `README.md`.  
3. Open artifacts in a text editor (CSV, PS1) or image viewer for screenshots.  
4. If you want a live demo, contact me and I’ll provide sanitized logs or run a short walkthrough.

---

## Contact
- Email: `preethudoss@gmail.com`  
- LinkedIn: `https://www.linkedin.com/in/preetha-pr/`

---