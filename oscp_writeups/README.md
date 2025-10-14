# OSCP / Hack The Box Practice Writeups

Welcome to my personal repository where I document my progress and learning while preparing for the **Offensive Security Certified Professional (OSCP)** certification.

This repo contains writeups of retired Hack The Box (HTB) machines, focusing on:
- Realistic penetration testing methodology
- Privilege escalation techniques
- Enumeration workflows
- Hands-on use of tools like `nmap`, `pspy`, `linpeas`, and more

> **Note**: All machines documented here are retired HTB boxes. No live targets were harmed. Flags and IPs are redacted in compliance with HTB's Terms of Service.

---

## Index of Machines

| Machine Name | Difficulty | Writeup Link | Key Techniques |
|--------------|------------|--------------|----------------|
| Bashed       | Easy       | [bashed.md](/oscp_writeups/bashed.md) | Cronjob abuse, SUID, `pspy`, Webshell |
| *Coming soon*| *-*        | *TBD*        | *TBD*          |

---

## Tools Used

- `nmap` – network scanning
- `gobuster` – directory brute-forcing
- `pspy` – cronjob enumeration
- `python3` / `bash` – reverse shells
- `GTFOBins` – privilege escalation techniques
- `linpeas.sh`, `sudo -l`, `find / -perm` – local enumeration

---

## What I'm Learning

- OSCP-style post-exploitation methodology
- Manual enumeration over automation
- Exploiting misconfigurations (cron, file perms, SUID/SGID)
- Documenting findings in clean, reusable format

---

## Disclaimer

> This repository is for educational purposes only. All machines targeted are from Hack The Box's retired list. Any resemblance to real systems is purely coincidental.

---

## More Coming Soon

I'll continue adding new boxes as I complete them.

Follow the repo or connect with me on GitHub to stay updated!
