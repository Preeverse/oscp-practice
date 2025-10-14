# HTB — Holmes CTF 2025 — Personal Writeups

**Author:** `Preetha`  
**Event:** Hack The Box — Holmes CTF 2025 (team participation)  
**Personal focus:** I worked hands‑on on **two** challenges: **The Card** and **The Enduring Echo**.  

---

## Table of contents
- [Overview](#overview)
- [The Card](#the-card)
- [The Enduring Echo](#the-enduring-echo)
- [Artifacts & evidence](#artifacts--evidence)
- [Contact](#contact)

---

## Overview

I participated as part of a team in the **HTB Holmes CTF (2025)**, a Capture the Flag event focused on real-world cyber investigation and threat analysis.  
I personally completed two challenges — **The Card** and **The Enduring Echo** — which are documented in this repository.

These scenarios gave me strong hands-on experience with:

- Log analysis and event correlation  
- Web and disk forensics  
- Connecting intelligence across platforms like **honeypots**, **SIEM**, and **forensic tools**

Each challenge sharpened my understanding of how to trace attacks, extract indicators, and link attacker behavior across multiple stages.

All artifacts have been sanitized and exported from lab environments. I'm happy to walk through any part of the investigation upon request.

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