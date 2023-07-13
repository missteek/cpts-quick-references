# USING WEB PROXIES & Assessment  

[REGEX Match and Replace Rules](https://academy.hackthebox.com/module/110/section/1050)  

>Match Regex : True  
```
^User-Agent.*$
```
>Replace
```
User-Agent: HackTheBox Agent 1.0
```  

[MetaSploit - auxiliary/scanner/http/](https://academy.hackthebox.com/module/110/section/1053)  

>Send MSFConsole request via Web Proxy to see traffic send and request made to remote target, as example this perform a put of file, `msf test file`.  

```
sudo msfconsole

use auxiliary/scanner/http/http_put

set PROXIES HTTP:127.0.0.1:8080
set RHOST 46.101.95.166
set RPORT 30118
```  

[Intruder payloads and Wordlists - Fuzzer](https://academy.hackthebox.com/module/110/section/1056)  

>Here are good quick short common wordlists from SecLists.  

```
/usr/share/seclists/Discovery/Web-Content/common.txt

/usr/share/seclists/Usernames/top-usernames-shortlist.txt

/usr/share/seclists/Fuzzing/alphanum-case.txt
```  

>Burp Intruder payload attacks with above payloads.  

[Burp Store + Extensions from BApp Store](https://academy.hackthebox.com/module/110/section/1104)  

## Skills Assessment - Using Web Proxies  

[Skills Assessment - Using Web Proxies - Burp Suite](https://academy.hackthebox.com/module/110/section/1055)  





