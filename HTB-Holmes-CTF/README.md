# HTB — Holmes CTF 2025 — Personal Writeups

**Author:** `Preetha`  
**Event:** Hack The Box — Holmes CTF 2025 (team participation)  
**Personal focus:** I worked hands‑on on **two** challenges: **The Card** and **The Enduring Echo**.  

---

## Table of contents
- [Overview](#overview)
- [The Enduring Echo](#the-enduring-echo)
- [The Card](#the-card)
- [Artifacts & evidence](#artifacts--evidence)
- [Contact](#contact)

---

## Overview
I participated as a team in the HTB Holmes CTF (2025). The two challenges I personally completed and documented here are:

- **The Card** — forensic triage & log correlation (summary in `The_Card/README.md`)  
- **The Enduring Echo** — disk forensics, Windows event log parsing, persistence analysis, and pivot detection (detailed in `The_Enduring_Echo/README.md`)

All artifacts are sanitized and exported from lab images. I can demonstrate any step live or provide additional sanitized exports on request.

---
## [The Card](/HTB-Holmes-CTF/The_Card.md)

This challenge involved analyzing web server logs from a honeypot to trace an attacker’s activity.  
Key tasks included identifying the attacker’s user-agent, detecting web shell deployment, tracking data exfiltration, and mapping threat intelligence indicators using the CogWork platforms.

## [The Enduring Echo](/HTB-Holmes-CTF/The_Enduring_Echo.md)

This challenge focused on forensic investigation of a compromised Windows system.  
Key objectives included analyzing event logs, detecting remote execution via `wmiexec.py`, identifying persistence mechanisms, user account creation, and attacker pivoting using port proxy techniques.

---
## Artifacts & evidence
Key artifacts included:
- Parsed EVTX CSV exports (`evtx-parsed.csv`) filtered for Security events of interest (e.g., 4688, 4720).  
- Timeline exports (`timeline.csv`) used in Timeline Explorer.  
- Extracted persistence script (`JM.ps1`) and scheduled task XML screenshot.  
- Screenshots of timeline and relevant event filters.

---

## Contact
- Email: `preethudoss@gmail.com`  
- LinkedIn: `https://www.linkedin.com/in/preetha-pr/`

---