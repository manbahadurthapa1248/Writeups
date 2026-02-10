# **Chain - ThunderCipher**

*Target Ip. Address: 192.168.5.149*

Let's begin with a basic nmap scan.

```bash
kali@kali:nmap -sV -sC 192.168.5.149
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-10 20:48 +0545
Nmap scan report for 192.168.5.149
Host is up (0.088s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 5c:8e:2c:cc:c1:b0:3e:7c:0e:22:34:d8:60:31:4e:62 (RSA)
|   256 81:fd:c6:4c:5a:50:0a:27:ea:83:38:64:b9:8b:bd:c1 (ECDSA)
|_  256 c1:8f:87:c1:52:09:27:60:5f:2e:2d:e0:08:03:72:c8 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Momentum | Index
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.62 seconds
```

So, we have 2 open ports. Port 22 (ssh) and Port 80 (http).

While viewing the website, I noticed this is a same challenge as ReconCipher.

I have already done it. You can check it out on: *https://github.com/manbahadurthapa1248/Writeups/blob/main/ThunderCipher/ReconCipher%20-%20ThunderCipher.md*





















