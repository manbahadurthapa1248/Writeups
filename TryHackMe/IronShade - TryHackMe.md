# **IronShade - TryHackMe**

This is a Linux Forensics room.

**1. What is the Machine ID of the machine we are investigating?**

```bash
ubuntu@cybertees:~$ cat /etc/machine-id
dc7c8.....10d96
```

**2. What backdoor user account was created on the server?**

```bash
ubuntu@cybertees:/home$ ls                                                                                         
mircoservice  ubuntu  
```
So, microservice is the backdoor account.

**3. What is the cronjob that was set up by the attacker for persistence?**














