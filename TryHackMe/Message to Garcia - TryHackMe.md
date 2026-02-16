# **Message to Garcia - TryHackMe**

*Targert Ip. Address: 10.48.154.142*

Let's start with nmap scan.

```bash
kali@kali:nmap -sV -sC 10.48.154.142
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-16 19:48 +0545
Nmap scan report for 10.48.154.142
Host is up (0.043s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e3:4c:e4:3a:b2:0f:64:be:20:88:2b:37:66:28:d8:77 (ECDSA)
|_  256 9b:a6:6d:51:ba:d9:37:86:44:ce:ed:b9:a2:6d:42:eb (ED25519)
80/tcp   open  http    nginx 1.24.0 (Ubuntu)
|_http-title: SFTP | Home
|_http-server-header: nginx/1.24.0 (Ubuntu)
5000/tcp open  http    Werkzeug httpd 3.1.3 (Python 3.12.3)
|_http-server-header: Werkzeug/3.1.3 Python/3.12.3
|_http-title: SFTP | Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.07 seconds
```

So, we have 3 open ports. Port 5000 is the one we need as it is hosting SFTP. 

<img width="1244" height="954" alt="image" src="https://github.com/user-attachments/assets/bfafa838-af45-4cd3-b0fe-584775b3e245" />

So, we have file upload system, backup system, resource fetcher. Resource fetcher seems interesting.

<img width="986" height="688" alt="image" src="https://github.com/user-attachments/assets/f8342b50-f3c6-49a6-a5e3-4ae365bd266c" />

With just file://../../../etc/passwd, we have LFI now.

There is a placeholder telling file://README.md, let's see what it has.

```
.
├── app.py                  # Main Flask application
├── functions.py            # Core encryption and validation logic
├── sftp_server.py          # SFTP server implementation
├── create_message.py       # Utility to generate encrypted messages
├── requirements.txt        # Python dependencies
├── templates/              # HTML templates
├── static/                 # CSS, JavaScript, fonts
└── uploads/                # File upload directory
```

So, we get the file structure from the README, now we can read each one of them, to understand better.

From create_message.py, we get the Encryption key.

```create_message.py
#!/usr/bin/env python3
"""
Simple script to create the encrypted message for the challenge.
"""
from cryptography.fernet import Fernet

# The encryption key (same as in functions.py)
ENCRYPTION_KEY = b'TU.....SE='
cipher = Fernet(ENCRYPTION_KEY)

# The expected message
message = "Garcia, it seems I've cracked the code!! I need you to meet me at coordinates: 40.4168° N, 3.7038° W. The cipher is: TRACK"

print(f"[*] Message to encrypt: {message}")
print(f"[*] Encryption key: {ENCRYPTION_KEY.decode()}")

# Encrypt the message
encrypted = cipher.encrypt(message.encode('utf-8'))

# Save to file
with open("message.enc", "wb") as f:
    f.write(encrypted)

print(f"\n[+] Encrypted message saved to: message.enc")
print(f"[+] File size: {len(encrypted)} bytes")

# Test decryption
decrypted = cipher.decrypt(encrypted)
print(f"\n[*] Testing decryption...")
print(f"[+] Decrypted: {decrypted.decode('utf-8')}")
print(f"[+] Match: {decrypted.decode('utf-8').strip() == message}")

print(f"\n{'='*60}")
print(f"SUCCESS! Upload 'message.enc' to the application!")
print(f"{'='*60}")
```

So, we need to encrypt the message with the key we have, save it as message.enc and upload it.

Now, we create a python script using fernet module to encrypt the message.

```message.py
from cryptography.fernet import Fernet

key = b'TU.....SE='
cipher = Fernet(key)

expected_message = "Garcia, it seems I've cracked the code!! I need you to meet me at coordinates: 40.4168° N, 3.7038° W. The cipher is: TRACK"

token = cipher.encrypt(expected_message.encode())

with open("message.enc", "wb") as f:
    f.write(token)

print("[+] message.enc generated successfully!
```

Run the script.

```bash
kali@kali:python3 message.py 
[+] message.enc generated successfully!
```

Upload the message.enc on the upload section.

<img width="978" height="590" alt="image" src="https://github.com/user-attachments/assets/d838fc22-7e31-4458-a463-ed97bfe1a7f5" />

We got the flag.
