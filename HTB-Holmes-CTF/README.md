# HTB — Holmes CTF 2025 — Writeups

**Author:** `Preetha`  
**Event:** Hack The Box — Holmes CTF 2025 (team participation)  
**Personal focus:** I worked hands‑on on **two** challenges: **The Card** and **The Enduring Echo**.  

---

## Table of contents
- [Overview](#overview)
- [HTB Holmes CTF Challenges](#htb-holmes-ctf-challenges)
- [Artifacts & evidence](#artifacts--evidence)

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
## HTB Holmes CTF Challenges

| Name               | Learning             |                                                                                                                                     | 
|--------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| 🔗[The Card](/HTB-Holmes-CTF/The_Card.md)            | Web server log analysis, Honeypot investigation, User-Agent fingerprinting, Web shell detection, Data exfiltration tracking, Threat intelligence mapping, Campaign attribution, CogWork platform usage|
| 🔗[The Enduring Echo](/HTB-Holmes-CTF/The_Enduring_Echo.md) | Windows forensics, Event log analysis, Remote execution detection (wmiexec.py), Persistence mechanism identification, Malicious user account creation, Port proxy pivoting, Registry analysis, MITRE ATT&CK mapping|
---

## Artifacts & evidence
Key artifacts included:
- Parsed EVTX CSV exports (`evtx-parsed.csv`) filtered for Security events of interest (e.g., 4688, 4720).  
- Timeline exports (`timeline.csv`) used in Timeline Explorer.  
- Extracted persistence script (`JM.ps1`) and scheduled task XML screenshot.  
- Screenshots of timeline and relevant event filters.
---