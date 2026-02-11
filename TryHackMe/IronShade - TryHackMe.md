# **IronShade - TryHackMe**

This is a Linux Forensics room.

**1. What is the Machine ID of the machine we are investigating?**

```bash
ubuntu@cybertees:~$ cat /etc/machine-id
dc7c8ac5c09a4bbfaf3d09d399f10d96
```
So, the machine id of the machine is dc7c8ac5c09a4bbfaf3d09d399f10d96.

**2. What backdoor user account was created on the server?**

```bash
ubuntu@cybertees:/home$ ls
mircoservice  ubuntu
```
So, microservice is the backdoor account.

**3. What is the cronjob that was set up by the attacker for persistence?**
So, attacker mainly set up cron jobs for root.

```bash
ubuntu@cybertees:~$ sudo crontab -l             
# Edit this file to introduce tasks to be run by cron.                  
#
# Each task to run has to be defined through a single line                  
# indicating with different fields when the task will be run                  
# and what command to run for the task                
#
# To define the time you can provide concrete values for                  
# minute (m), hour (h), day of month (dom), month (mon),                  
# and day of week (dow) or use '*' in these fields (for 'any').                  
#                  
# Notice that tasks will be started based on the cron's system                  
# daemon's notion of time and timezones.                  
#                  
# Output of the crontab jobs (including errors) is sent through                  
# email to the user the crontab file belongs to (unless redirected).                  
#                  
# For example, you can run a backup of all your user accounts                  
# at 5 a.m every week with:                  
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/                  
#
# For more information see the manual pages of crontab(5) and cron(8)
#
# m h  dom mon dow   command

@reboot /home/mircoservice/printer_app
```
So, the attacker set cron job "@reboot /home/mircoservice/printer_app" as root.

**4. Examine the running processes on the machine. Can you identify the suspicious-looking hidden process from the backdoor account?**

```bash
ubuntu@cybertees:~$ ps aux | grep mircoservice
root         599  0.0  0.0   2364   508 ?        Ss   12:54   0:00 /home/mircoservice/.tmp/.strokes
root         893  0.0  0.0   2496    72 ?        S    12:54   0:00 /home/mircoservice/printer_app
ubuntu      2531  0.0  0.0   8172  2384 pts/1    S+   13:13   0:00 grep --color=auto mircoservice
```
So, the hidden process is "/home/mircoservice/.tmp/.strokes".

**5. How many processes are found to be running from the backdoor account’s directory?**

From the above output only, we see 2 processes are running from the backdoor account'sdirectory.

**6.What is the name of the hidden file in memory from the root directory?**

```bash
root@cybertees:/# ls -la
total 100
drwxr-xr-x  19 root root  4096 Feb 11 12:54 .
drwxr-xr-x  19 root root  4096 Feb 11 12:54 ..
-rwxr-xr-x   1 root root 17088 Jul  2  2024 .systmd
lrwxrwxrwx   1 root root     7 Oct 26  2020 bin -> usr/bin
drwxr-xr-x   3 root root  4096 Aug 13  2024 boot
drwxr-xr-x  17 root root  3320 Feb 11 12:54 dev
drwxr-xr-x 156 root root 12288 Feb 11 12:54 etc
drwxr-xr-x   4 root root  4096 Aug  5  2024 home
lrwxrwxrwx   1 root root     7 Oct 26  2020 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Oct 26  2020 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Oct 26  2020 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Oct 26  2020 libx32 -> usr/libx32
drwx------   2 root root 16384 Oct 26  2020 lost+found
drwxr-xr-x   2 root root  4096 Jun 26  2024 media
drwxr-xr-x   2 root root  4096 Oct 26  2020 mnt
drwxr-xr-x   4 root root  4096 Jul  9  2024 opt
dr-xr-xr-x 258 root root     0 Feb 11 12:53 proc
drwx------   9 root root  4096 Jun 28  2024 root
drwxr-xr-x  37 root root  1140 Feb 11 13:09 run
lrwxrwxrwx   1 root root     8 Oct 26  2020 sbin -> usr/sbin
drwxr-xr-x   8 root root  4096 Feb 27  2022 snap
drwxr-xr-x   2 root root  4096 Oct 26  2020 srv
dr-xr-xr-x  13 root root     0 Feb 11 12:53 sys
drwxrwxrwt  15 root root  4096 Feb 11 13:09 tmp
drwxr-xr-x  14 root root  4096 Oct 26  2020 usr
drwxr-xr-x  15 root root  4096 Jun 24  2024 var
```
So, .systmd is the hidden file.

**7. What suspicious services were installed on the server? Format is service a, service b in alphabetical order.**

```bash
root@cybertees:/# ls /sys/fs/cgroup/systemd/system.slice/
 -.mount                                  'snap-amazon\x2dssm\x2dagent-7993.mount'
 ModemManager.service                      snap-core-16928.mount
 NetworkManager-wait-online.service        snap-core-17200.mount
 NetworkManager.service                    snap-core18-2823.mount
 accounts-daemon.service                   snap-core18-2829.mount
 acpid.service                             snap-core20-2105.mount
 acpid.socket                              snap-core20-2318.mount
 anacron.service                           snap-lxd-24061.mount
 apparmor.service                          snap-lxd-29619.mount
 apport.service                            snap.amazon-ssm-agent.amazon-ssm-agent.service
 apt-daily-upgrade.service                 snap.lxd.daemon.unix.socket
 atd.service                               snapd.apparmor.service
 avahi-daemon.service                      snapd.seeded.service
 avahi-daemon.socket                       snapd.service
 backup.service                            snapd.socket
 badr.service                              ssh.service
 blk-availability.service                  strokes.service
 cgroup.clone_children                     switcheroo-control.service
 cgroup.procs                              sys-fs-fuse-connections.mount
 cloud-config.service                      sys-kernel-config.mount
 cloud-final.service                       sys-kernel-debug.mount
 cloud-init-hotplugd.socket                sys-kernel-tracing.mount
 cloud-init-local.service                  syslog.socket
 cloud-init.service                        sysstat.service
 console-setup.service                     system-getty.slice
 cron.service                              system-modprobe.slice
 cups-browsed.service                     'system-serial\x2dgetty.slice'
 cups.service                              systemd-initctl.socket
 cups.socket                               systemd-journal-flush.service
 dbus.service                              systemd-journald-audit.socket
 dbus.socket                               systemd-journald-dev-log.socket
 dev-hugepages.mount                       systemd-journald.service
 dev-mqueue.mount                          systemd-journald.socket
 dm-event.socket                           systemd-logind.service
 finalrd.service                           systemd-modules-load.service
 fwupd.service                             systemd-networkd-wait-online.service
 hddtemp.service                           systemd-networkd.service
 ifupdown-pre.service                      systemd-networkd.socket
 irqbalance.service                        systemd-random-seed.service
 iscsid.socket                             systemd-remount-fs.service
 kerneloops.service                        systemd-resolved.service
 keyboard-setup.service                    systemd-rfkill.socket
 kmod-static-nodes.service                 systemd-sysctl.service
 lightdm.service                           systemd-sysusers.service
 lvm2-lvmpolld.socket                      systemd-timesyncd.service
 lvm2-monitor.service                      systemd-tmpfiles-setup-dev.service
 multipathd.service                        systemd-tmpfiles-setup.service
 multipathd.socket                         systemd-udev-settle.service
 networkd-dispatcher.service               systemd-udev-trigger.service
 networking.service                        systemd-udevd-control.socket
 notify_on_release                         systemd-udevd-kernel.socket
 openvpn.service                           systemd-udevd.service
 polkit.service                            systemd-update-utmp.service
 proc-sys-fs-binfmt_misc.mount             systemd-user-sessions.service
 proc_run.service                          tasks
 rsyslog.service                           udisks2.service
 rtkit-daemon.service                      ufw.service
 run-snapd-ns-lxd.mnt.mount                unattended-upgrades.service
 run-snapd-ns.mount                        upower.service
 run-user-1000.mount                       uuidd.socket
 setvtrgb.service                          whoopsie.service
'snap-amazon\x2dssm\x2dagent-7628.mount'   wpa_supplicant.service
```
From here: backup.service and strokes.service are suspicious.

**8. Examine the logs; when was the backdoor account created on this infected system?**

```bash
root@cybertees:/# grep -ia "useradd" /var/log/auth.log* | grep -i mircoservice
/var/log/auth.log:Aug  5 22:05:33 cybertees useradd[2067]: new user: name=mircoservice, UID=1001, GID=1001, home=/home/mircoservice, shell=/bin/bash, from=/dev/pts/0
```
So, the account was created on Aug 5 22:05:33.

**9. From which IP address were multiple SSH connections observed against the suspicious backdoor account?**

```bash
root@cybertees:/# grep -a ssh /var/log/auth.log* | grep -i mircoservice
/var/log/auth.log:Aug  5 22:10:40 cybertees sshd[2115]: Accepted password for mircoservice from 10.11.75.247 port 56660 ssh2
/var/log/auth.log:Aug  5 22:10:40 cybertees sshd[2115]: pam_unix(sshd:session): session opened for user mircoservice by (uid=0)
/var/log/auth.log:Aug  5 23:54:31 cybertees sshd[3117]: Accepted password for mircoservice from 10.11.75.247 port 62606 ssh2
/var/log/auth.log:Aug  5 23:54:31 cybertees sshd[3117]: pam_unix(sshd:session): session opened for user mircoservice by (uid=0)
/var/log/auth.log:Aug  6 00:27:27 cybertees sshd[2115]: pam_unix(sshd:session): session closed for user mircoservice
/var/log/auth.log:Aug  6 00:28:42 cybertees sshd[1380]: Accepted password for mircoservice from 10.11.75.247 port 51472 ssh2
/var/log/auth.log:Aug  6 00:28:42 cybertees sshd[1380]: pam_unix(sshd:session): session opened for user mircoservice by (uid=0)
/var/log/auth.log:Aug  6 00:28:55 cybertees sshd[1668]: Accepted password for mircoservice from 10.11.75.247 port 51482 ssh2
/var/log/auth.log:Aug  6 00:28:55 cybertees sshd[1668]: pam_unix(sshd:session): session opened for user mircoservice by (uid=0)
/var/log/auth.log:Aug  6 01:16:35 cybertees sshd[1738]: Disconnected from user mircoservice 10.11.75.247 port 51482
/var/log/auth.log:Aug  6 01:16:35 cybertees sshd[1668]: pam_unix(sshd:session): session closed for user mircoservice
/var/log/auth.log:Aug  6 01:16:41 cybertees sshd[2256]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.11.75.247  user=mircoservice
/var/log/auth.log:Aug  6 01:16:43 cybertees sshd[2256]: Failed password for mircoservice from 10.11.75.247 port 54649 ssh2
/var/log/auth.log:Aug  6 01:17:14 cybertees sshd[2256]: Failed password for mircoservice from 10.11.75.247 port 54649 ssh2
/var/log/auth.log:Aug  6 01:38:20 cybertees sshd[1380]: pam_unix(sshd:session): session closed for user mircoservice
/var/log/auth.log:Aug 13 22:15:06 cybertees sshd[2385]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.11.75.247  user=mircoservice
/var/log/auth.log:Aug 13 22:15:08 cybertees sshd[2385]: Failed password for mircoservice from 10.11.75.247 port 64855 ssh2
/var/log/auth.log:Aug 13 22:15:16 cybertees sshd[2385]: message repeated 2 times: [ Failed password for mircoservice from 10.11.75.247 port 64855 ssh2]
/var/log/auth.log:Aug 13 22:15:16 cybertees sshd[2385]: Connection reset by authenticating user mircoservice 10.11.75.247 port 64855 [preauth]
/var/log/auth.log:Aug 13 22:15:16 cybertees sshd[2385]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.11.75.247  user=mircoservice
/var/log/auth.log:Aug 13 22:15:41 cybertees sshd[2388]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.11.75.247  user=mircoservice
/var/log/auth.log:Aug 13 22:15:44 cybertees sshd[2388]: Failed password for mircoservice from 10.11.75.247 port 64871 ssh2
/var/log/auth.log:Aug 13 22:16:12 cybertees sshd[2388]: message repeated 2 times: [ Failed password for mircoservice from 10.11.75.247 port 64871 ssh2]
/var/log/auth.log:Aug 13 22:16:12 cybertees sshd[2388]: Connection reset by authenticating user mircoservice 10.11.75.247 port 64871 [preauth]
/var/log/auth.log:Aug 13 22:16:12 cybertees sshd[2388]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.11.75.247  user=mircoservice
```
So, the IP address with multiple SSH connections was 10.11.75.247.

**10. How many failed SSH login attempts were observed on the backdoor account?**

```bash
root@cybertees:/# grep -a "Failed" /var/log/auth.log* | grep -i mircoservice | wc -l
6
```
That was wrong. Let's see whole log.

```bash
root@cybertees:/# grep -a "Failed" /var/log/auth.log* | grep -i mircoservice
/var/log/auth.log:Aug  6 01:16:43 cybertees sshd[2256]: Failed password for mircoservice from 10.11.75.247 port 54649 ssh2
/var/log/auth.log:Aug  6 01:17:14 cybertees sshd[2256]: Failed password for mircoservice from 10.11.75.247 port 54649 ssh2
/var/log/auth.log:Aug 13 22:15:08 cybertees sshd[2385]: Failed password for mircoservice from 10.11.75.247 port 64855 ssh2
/var/log/auth.log:Aug 13 22:15:16 cybertees sshd[2385]: message repeated 2 times: [ Failed password for mircoservice from 10.11.75.247 port 64855 ssh2]
/var/log/auth.log:Aug 13 22:15:44 cybertees sshd[2388]: Failed password for mircoservice from 10.11.75.247 port 64871 ssh2
/var/log/auth.log:Aug 13 22:16:12 cybertees sshd[2388]: message repeated 2 times: [ Failed password for mircoservice from 10.11.75.247 port 64871 ssh2]
```
So, 2 of them were having 2 error message repeated. So, total is 8.

**11. Which malicious package was installed on the host?**

Since, account was created on 2024-08-05, I will get results from that date onwards.

```bash
root@cybertees:/# awk '$1 > "2024-08-05" && $3 == "install"' /var/log/dpkg.log
2024-08-06 01:10:20 install pscanner:amd64 <none> 1.5
2024-08-13 21:36:41 install gedit-common:all <none> 3.36.2-0ubuntu1
2024-08-13 21:36:42 install libgtksourceview-4-common:all <none> 4.6.0-1
2024-08-13 21:36:43 install libgtksourceview-4-0:amd64 <none> 4.6.0-1
2024-08-13 21:36:43 install gir1.2-gtksource-4:amd64 <none> 4.6.0-1
2024-08-13 21:36:43 install libamtk-5-common:all <none> 5.0.2-1build1
2024-08-13 21:36:43 install libamtk-5-0:amd64 <none> 5.0.2-1build1
2024-08-13 21:36:43 install libtepl-4-0:amd64 <none> 4.4.0-1
2024-08-13 21:36:44 install gedit:amd64 <none> 3.36.2-0ubuntu1
2024-08-13 22:23:14 install linux-modules-5.15.0-1066-aws:amd64 <none> 5.15.0-1066.72~20.04.1
2024-08-13 22:23:23 install linux-image-5.15.0-1066-aws:amd64 <none> 5.15.0-1066.72~20.04.1
2024-08-13 22:23:26 install linux-aws-5.15-headers-5.15.0-1066:all <none> 5.15.0-1066.72~20.04.1
2024-08-13 22:23:36 install linux-headers-5.15.0-1066-aws:amd64 <none> 5.15.0-1066.72~20.04.1
2026-02-11 13:18:25 install linux-modules-5.15.0-1067-aws:amd64 <none> 5.15.0-1067.73~20.04.1
2026-02-11 13:18:29 install linux-image-5.15.0-1067-aws:amd64 <none> 5.15.0-1067.73~20.04.1
2026-02-11 13:18:31 install linux-aws-5.15-headers-5.15.0-1067:all <none> 5.15.0-1067.73~20.04.1
2026-02-11 13:18:36 install linux-headers-5.15.0-1067-aws:amd64 <none> 5.15.0-1067.73~20.04.1
```
So, pscanner is the malicious package.

**12. What is the secret code found in the metadata of the suspicious package?**

```bash
root@cybertees:/# dpkg -s pscanner
Package: pscanner
Status: install ok installed
Priority: optional
Section: base
Maintainer: johnnyEng
Architecture: amd64
Version: 1.5
Description: Secret_code{_tRy_Hack_ME_}
```
We got the secret code: {_tRy_Hack_ME_}
