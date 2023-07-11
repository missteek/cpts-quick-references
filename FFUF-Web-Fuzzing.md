# Ffuf Web Application Attacks  

## Quick Reference Commands  

| **Command**   | **Description**   |
| --------------|-------------------|
| `ffuf -h` | ffuf help |
| `ffuf -ic -c -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ` | Directory Fuzzing |
| `ffuf -ic -c -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/indexFUZZ` | Extension Fuzzing |
| `ffuf -ic -c -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php` | Page Fuzzing |
| `ffuf -ic -c -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v` | Recursive Fuzzing |
| `ffuf -ic -c -w wordlist.txt:FUZZ -u https://FUZZ.hackthebox.eu/` | Sub-domain Fuzzing |
| `ffuf -ic -c -w wordlist.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs xxx` | VHost Fuzzing |
| `ffuf -ic -c -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx` | Parameter Fuzzing - GET |
| `ffuf -ic -c -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx` | Parameter Fuzzing - POST |
| `ffuf -c -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx` | Value Fuzzing |  

## Wordlists

>Custom Wordlist - [Value Fuzzing](https://academy.hackthebox.com/module/54/section/505)  

| **Command**   | **Description**   |
| --------------|-------------------|
| `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt` | Directory/Page Wordlist |
| `/usr/share/seclists/Discovery/Web-Content/web-extensions.txt` | Extensions Wordlist |
| `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` | Domain Wordlist |
| `/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt` | Parameters Wordlist |

## Misc

| **Command**   | **Description**   |
| --------------|-------------------|
| `sudo sh -c 'echo "SERVER_IP  academy.htb" >> /etc/hosts'` | Add DNS entry aid in virtual host routing vHost name resolution header different websites on same IP hosted. |
| `for i in $(seq 1 1000); do echo $i >> ids.txt; done` | Create Sequence Wordlist |
| `curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'` | curl w/ POST |

## FFUFING Detail  

[FFUF enumerate any files/folders hosted on the web server using ffuf.](https://codingo.io/tools/ffuf/bounty/2020/09/17/everything-you-need-to-know-about-ffuf.html#fuzzing-multiple-locations)  


### Samples  

1. Root directories `ffuf -c -w 9-big.txt -u http://easy.box/FUZZ`
2. root with extensions `ffuf -c -w 9-big.txt -u http://easy.box/FUZZ -e .git,.txt,.json,.php,.html,.bak,.old,.sql,.zip,.conf,.cfg,.asp,.aspx,.cs`
3. Sub web folders below folder `ffuf -c -w 9-big.txt -u http://eezy.box/secret/FUZZ`
4. Sub web folder with extensions `ffuf -c -w 9-big.txt -u http://eezy.box/secret/FUZZ -e .git,.txt,.json,.php,.html,.bak,.old,.sql,.zip,.conf,.cfg,.js`
5. vHost fuzz domain `ffuf -c -w 9-big.txt -H "Host: FUZZ.easy.box/" -u http://easy.box/`
6. subdomain root  ^^ repeat step 1 but for found subdomain ^^ `ffuf -c -w 9-big.txt -u http://sub.easy.box/FUZZ`
7. Reporting `ffuf -c -w common.txt -u http://oscp.sec:8080/FUZZ -o ffuf_report.html -of html`

### Root website  

```
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://vulnnet.htb/FUZZ
```
```
ffuf -c -c -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://spectra.htb/FUZZ
```
```
ffuf -c -w ~/Downloads/wordlists/big.txt -u http://lordoftheroot.box:1337/FUZZ
```

### ROOT website extensions  

```
ffuf -c -w typo3_custom.txt -u http://maintest.enterprize.htb/FUZZ -e .old -fc 301 | grep "\.old"
```
```
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://vulnnet.htb/FUZZ -e .txt,.json,.php,.html,.bak,.old,.sql,.zip,.zz -fc 403
```
```
ffuf -c -c -w ~/Downloads/wordlists/big.txt -u http://lordoftheroot.box:1337/FUZZ -e .git,.txt,.json,.php,.html,.bak,.old,.sql,.zip,.conf,.cfg,.go
```

### SUB-domains  

>[Sub-domain Fuzzing](https://academy.hackthebox.com/module/54/section/488)  

> -fw  Filter by amount of words in response. Comma separated list of word counts and ranges
> -H  Header `"Name: Value"`, separated by colon. Multiple -H flags are accepted
> -fc Wrong parameter value returning HTTP response code 400. filtering out response code 400 - Bad request
  
```
ffuf -c -ic -w subdomains-top1million-5000.txt -u http://FUZZ.academy.htb:12345/ -fc 403
```

### vHosts domains  

>vHost Fuzzing [HackTheBox Academy - vHost fuzz](https://academy.hackthebox.com/module/144/section/1257)  
>Wordlist - /usr/share/seclists/Discovery/DNS/namelist.txt  

```
ffuf -c -w ./vhosts -u http://192.168.10.10 -H "HOST: FUZZ.randomtarget.com" -fs 612
```
```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.academy.htb" -u http://academy.htb:54542/ -fs 85
```
```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.koikoi.oscp/" -u http://koikoi.oscp/
```
```
ffuf -u http://trick.htb -c -w 0-common-with-mylist.txt -H 'Host: preprod-FUZZ.trick.htb' -fw 1697
```  
```
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://broadcast.vulnnet.htb/FUZZ -fc 401
```
```
ffuf -u http://sneakycorp.htb -H 'Host: FUZZ.sneakycorp.htb' -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fw 6
```
```
ffuf -u http://horizontall.htb -H 'Host: FUZZ.forge.htb' -c -w ~/Downloads/wordlists/0-common-with-mylist.txt
```

### Extensions  

```
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://broadcast.vulnnet.htb/FUZZ -e .txt,.json,.php,.html,.bak,.old,.sql,.zip,.zz -fc 403
```

>Accepted Extension discovery scans.  
```
ffuf -c -ic -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://academy.htb:57089/indexFUZZ
```  

>Multiple subdomain scan using a `for` loop to scan through possible file names with three possible extensions listed, `.php,.phps,.php7`.  

```
for sub in archive test faculty; do ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt:FUZZ -u http://$sub.academy.htb:57089/FUZZ -recursion -recursion-depth 1 -e .php,.phps,.php7 -v -t 200 -fs 287 -ic; done
```

### Known file + Extension

```
ffuf -c -v -c -w ~/Downloads/htb/quick-extensions1.txt -u http://team.htb/scripts/script.FUZZ
```

### FFUF via Proxy

```
ffuf -c -c -w /root/Downloads/wordlists/webfuzz_less.txt -u http://pinkyspalace.box:8080/FUZZ -x http://pinkyspalace.box:31337
```
```
ffuf -c -c -w /root/Downloads/wordlists/webfuzz_less.txt -u http://pinkyspalace.box:8080/FUZZ -replay-proxy http://127.0.0.1:8080
```

### API endpoints

> ' single quote escape with slash in below command!
> -- comments out the rest of API query syntax for LUA or SQL etc.

```
ffuf -u http://target IP/weather/forecast?city=\'FUZZ-- -c -w /opt/SecLists/Fuzzing/special-chars.txt -mc 200,500 -fw 9
```

### Parameter values

>[Parameter Fuzzing - GET](https://academy.hackthebox.com/module/54/section/490)  
>[Parameter Fuzzing - POST](https://academy.hackthebox.com/module/54/section/508)

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:54542/admin/admin.php?FUZZ=key -fs xxx
```
```
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:PARAM -c -w values.txt:VAL -u http://flasky.offsec/add?PARAM=VAL -mr "VAL" -c
```
>POST
```
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```
```
ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:54542/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs 768
```
>Discovered the key value as `73`, and POST using `CURL`.  
```
curl http://admin.academy.htb:54542/admin/admin.php -X POST -d 'id=73' -H 'Content-Type: application/x-www-form-urlencoded'
```
>HTB{p4r4m373r_fuzz1n6_15_k3y!}  

### API file POST request

>[ippsec youtube API Enum](https://youtu.be/yM914q6zS-U) - IPPSEC - Hackthebox - Interface API enumeration

```
ffuf -u http://prd.m.rendering-api.interface.htb/FUZZ -c -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -mc all -fs 0
```
```
ffuf -u http://prd.m.rendering-api.interface.htb/api/FUZZ -c -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -mc all -fs 50 -d 'x=x'
```
```
ffuf -request api.txt -request-proto http -c -w /opt/SecLists/Discovery/Web-Content/api/api-seen-in-wild.txt -mc all -fs 36
```

### FFuF Web report

```
ffuf -c -c -w /root/Downloads/wordlists/0-common-with-mylist.txt -u http://oscp.sec:8080/FUZZ -o ffuf_report.html -of html
```
```
ffuf -c -c -w common.txt -u http://192.168.x.y:8080/FUZZ -o ffuf_report.html -of html && firefox ffuf_report.html
```

### Username enum info leak

>Login [FFUF Username Enumeration](https://tryhackme.com/room/authenticationbypass)  
>Logon Site reveal if user exist with message = An account with this username already exists

```
ffuf -c -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.139.148/customers/signup -mr "An account with this username already exists"
```

>Getting valid combination credentials

```
ffuf -c -w valid_usernames.txt:W1,/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.139.148/customers/login -fc 200
```

### Recursive

```
ffuf -recursion -recursion-depth 1 -u https://admin.academy.htb:54542/FUZZ -c -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt
```
```
ffuf -c -v -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://94.237.55.13:43548/FUZZ -e .php -recursion -recursion-depth 1
```
```
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php
```

## HELP

```
Fuzz Faster U Fool - v2.0.0-dev

HTTP OPTIONS:
  -H                  Header `"Name: Value"`, separated by colon. Multiple -H flags are accepted.
  -X                  HTTP method to use
  -b                  Cookie data `"NAME1=VALUE1; NAME2=VALUE2"` for copy as curl functionality.
  -d                  POST data
  -http2              Use HTTP2 protocol (default: false)
  -ignore-body        Do not fetch the response content. (default: false)
  -r                  Follow redirects (default: false)
  -recursion          Scan recursively. Only FUZZ keyword is supported, and URL (-u) has to end in it. (default: false)
  -recursion-depth    Maximum recursion depth. (default: 0)
  -recursion-strategy Recursion strategy: "default" for a redirect based, and "greedy" to recurse on all matches (default: default)
  -replay-proxy       Replay matched requests using this proxy.
  -sni                Target TLS SNI, does not support FUZZ keyword
  -timeout            HTTP request timeout in seconds. (default: 10)
  -u                  Target URL
  -x                  Proxy URL (SOCKS5 or HTTP). For example: http://127.0.0.1:8080 or socks5://127.0.0.1:8080

GENERAL OPTIONS:
  -V                  Show version information. (default: false)
  -ac                 Automatically calibrate filtering options (default: false)
  -acc                Custom auto-calibration string. Can be used multiple times. Implies -ac
  -ach                Per host autocalibration (default: false)
  -ack                Autocalibration keyword (default: FUZZ)
  -acs                Autocalibration strategy: "basic" or "advanced" (default: basic)
  -c                  Colorize output. (default: false)
  -config             Load configuration from a file
  -json               JSON output, printing newline-delimited JSON records (default: false)
  -maxtime            Maximum running time in seconds for entire process. (default: 0)
  -maxtime-job        Maximum running time in seconds per job. (default: 0)
  -noninteractive     Disable the interactive console functionality (default: false)
  -p                  Seconds of `delay` between requests, or a range of random delay. For example "0.1" or "0.1-2.0"
  -rate               Rate of requests per second (default: 0)
  -s                  Do not print additional information (silent mode) (default: false)
  -sa                 Stop on all error cases. Implies -sf and -se. (default: false)
  -scraperfile        Custom scraper file path
  -scrapers           Active scraper groups (default: all)
  -se                 Stop on spurious errors (default: false)
  -search             Search for a FFUFHASH payload from ffuf history
  -sf                 Stop when > 95% of responses return 403 Forbidden (default: false)
  -t                  Number of concurrent threads. (default: 40)
  -v                  Verbose output, printing full URL and redirect location (if any) with the results. (default: false)

MATCHER OPTIONS:
  -mc                 Match HTTP status codes, or "all" for everything. (default: 200,204,301,302,307,401,403,405,500)
  -ml                 Match amount of lines in response
  -mmode              Matcher set operator. Either of: and, or (default: or)
  -mr                 Match regexp
  -ms                 Match HTTP response size
  -mt                 Match how many milliseconds to the first response byte, either greater or less than. EG: >100 or <100
  -mw                 Match amount of words in response

FILTER OPTIONS:
  -fc                 Filter HTTP status codes from response. Comma separated list of codes and ranges
  -fl                 Filter by amount of lines in response. Comma separated list of line counts and ranges
  -fmode              Filter set operator. Either of: and, or (default: or)
  -fr                 Filter regexp
  -fs                 Filter HTTP response size. Comma separated list of sizes and ranges
  -ft                 Filter by number of milliseconds to the first response byte, either greater or less than. EG: >100 or <100
  -fw                 Filter by amount of words in response. Comma separated list of word counts and ranges

INPUT OPTIONS:
  -D                  DirSearch wordlist compatibility mode. Used in conjunction with -e flag. (default: false)
  -e                  Comma separated list of extensions. Extends FUZZ keyword.
  -ic                 Ignore wordlist comments (default: false)
  -input-cmd          Command producing the input. --input-num is required when using this input method. Overrides -w.
  -input-num          Number of inputs to test. Used in conjunction with --input-cmd. (default: 100)
  -input-shell        Shell to be used for running command
  -mode               Multi-wordlist operation mode. Available modes: clusterbomb, pitchfork, sniper (default: clusterbomb)
  -request            File containing the raw http request
  -request-proto      Protocol to use along with raw request (default: https)
  -w                  Wordlist file path and (optional) keyword separated by colon. eg. '/path/to/wordlist:KEYWORD'

OUTPUT OPTIONS:
  -debug-log          Write all of the internal logging to the specified file.
  -o                  Write output to file
  -od                 Directory path to store matched results to.
  -of                 Output file format. Available formats: json, ejson, html, md, csv, ecsv (or, 'all' for all formats) (default: json)
  -or                 Don't create the output file if we don't have results (default: false)

EXAMPLE USAGE:
  Fuzz file paths from wordlist.txt, match all responses but filter out those with content-size 42.
  Colored, verbose output.
    ffuf -w wordlist.txt -u https://example.org/FUZZ -mc all -fs 42 -c -v

  Fuzz Host-header, match HTTP 200 responses.
    ffuf -w hosts.txt -u https://example.org/ -H "Host: FUZZ" -mc 200

  Fuzz POST JSON data. Match all responses not containing text "error".
    ffuf -w entries.txt -u https://example.org/ -X POST -H "Content-Type: application/json" \
      -d '{"name": "FUZZ", "anotherkey": "anothervalue"}' -fr "error"

  Fuzz multiple locations. Match only responses reflecting the value of "VAL" keyword. Colored.
    ffuf -w params.txt:PARAM -w values.txt:VAL -u https://example.org/?PARAM=VAL -mr "VAL" -c
```  

# Skills Assessment - Web Fuzzing  

94.237.55.114:57089


>Run a sub-domain/vhost fuzzing scan on `*.academy.htb` for the IP shown above. What are all the sub-domains you can identify?

```
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.academy.htb:PORT/
```  

```
ffuf -c -ic -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:52269/ -H 'Host: FUZZ.academy.htb' -fs 985


https://academy.hackthebox.com/module/54/section/511 Question 5:
ffuf -w /opt/useful/SecLists/Usernames/top-usernames-shortlist.txt:FUZZ -u http://faculty.academy.htb:39234/courses/linux-security.php7 -X POST -d 'username=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded'
 
ffuf -w /opt/useful/SecLists/Usernames/top-usernames-shortlist.txt:FUZZ -u http://faculty.academy.htb:39234/courses/linux-security.php7 -X POST -d 'user=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded'

ffuf -w /opt/useful/SecLists/Usernames/top-usernames-shortlist.txt:FUZZ -u http://faculty.academy.htb:39234/courses/linux-security.php7?username=FUZZ -fs 774
 
ffuf -w /opt/useful/SecLists/Usernames/top-usernames-shortlist.txt:FUZZ -u http://faculty.academy.htb:39234/courses/linux-security.php7?user=FUZZ -fs 780
```


>94.237.55.114:57089

```
for sub in archive test faculty; do ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://:30862$sub.academy.htb/FUZZ -recursion -recursion-depth 1 -e .php,.phps,.php7 -v -t 200 -fs 287 -ic; done
```