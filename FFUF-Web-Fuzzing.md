# Ffuf

>Quick List of Commands

| **Command**   | **Description**   |
| --------------|-------------------|
| `ffuf -h` | ffuf help |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ` | Directory Fuzzing |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/indexFUZZ` | Extension Fuzzing |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php` | Page Fuzzing |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v` | Recursive Fuzzing |
| `ffuf -w wordlist.txt:FUZZ -u https://FUZZ.hackthebox.eu/` | Sub-domain Fuzzing |
| `ffuf -w wordlist.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs xxx` | VHost Fuzzing |
| `ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx` | Parameter Fuzzing - GET |
| `ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx` | Parameter Fuzzing - POST |
| `ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx` | Value Fuzzing |  

# Wordlists

| **Command**   | **Description**   |
| --------------|-------------------|
| `/opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt` | Directory/Page Wordlist |
| `/opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt` | Extensions Wordlist |
| `/opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt` | Domain Wordlist |
| `/opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt` | Parameters Wordlist |

# Misc

| **Command**   | **Description**   |
| --------------|-------------------|
| `sudo sh -c 'echo "SERVER_IP  academy.htb" >> /etc/hosts'` | Add DNS entry |
| `for i in $(seq 1 1000); do echo $i >> ids.txt; done` | Create Sequence Wordlist |
| `curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'` | curl w/ POST |

# FFUFF Detail  

FFUF
Let's enumerate any files/folders hosted on the web server using ffuf.
subdomains FUZZ
https://codingo.io/tools/ffuf/bounty/2020/09/17/everything-you-need-to-know-about-ffuf.html#fuzzing-multiple-locations


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
apt install ffuf

ffuf -u http://sneakycorp.htb/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Ffuf Web site method
1. root of website
2. root website with extensions
3. sub web folders from root  - REPEAT for every web folder ^^
4. sub web folder from root with extensions
5. subdomain fuzz of root domain 
6. subdomain root  ^^ repeat step 1 but for found subdomain ^^
7. subdomain root with extensions
8. given file name unknown extension
9. Through Proxy

^^ REPEAT for other HTTP ports 80, 443, 8080, 1337, etc.....


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
" 1. root of website"
ffuf -c -w ~/Downloads/wordlists/9-big.txt -u http://easy.box/FUZZ

" 2. root website with extensions"
ffuf -c -w ~/Downloads/wordlists/9-big.txt -u http://easy.box/FUZZ -e .git,.txt,.json,.php,.html,.bak,.old,.sql,.zip,.conf,.cfg,.asp,.aspx,.cs

" 3. sub web folders from root "
ffuf -c -w ~/Downloads/wordlists/9-big.txt -u http://eezy.box/secret/FUZZ
" 4. sub web folder from root with extensions "
ffuf -c -w ~/Downloads/wordlists/9-big.txt -u http://eezy.box/secret/FUZZ -e .git,.txt,.json,.php,.html,.bak,.old,.sql,.zip,.conf,.cfg,.js
" 5. subdomain fuzz of root domain "
ffuf -c -w ~/Downloads/wordlists/9-big.txt -H "Host: FUZZ.easy.box/" -u http://easy.box/
" 6. subdomain root  ^^ repeat step 1 but for found subdomain ^^ "
ffuf -c -w ~/Downloads/wordlists/9-big.txt -u http://sub.easy.box/FUZZ
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


FFUF Web Report

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ffuf -c -w /root/Downloads/wordlists/0-common-with-mylist.txt -u http://oscp.sec:8080/FUZZ -o ffuf_report.html -of html

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



#### ffuf root website
root of website

files and folders big ffuf


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://vulnnet.thm/FUZZ

ffuf -c -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://spectra.htb/FUZZ

ffuf -c -w ~/Downloads/wordlists/big.txt -u http://lordoftheroot.box:1337/FUZZ
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~





#### ffuf root website extensions
ffuf extensions


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ffuf -w typo3_custom.txt -u http://maintest.enterprize.thm/FUZZ -e .old -fc 301 | grep "\.old"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



Extensions
going down the rabbit holes - 


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://vulnnet.thm/FUZZ -e .txt,.json,.php,.html,.bak,.old,.sql,.zip,.zz -fc 403

ffuf -c -w ~/Downloads/wordlists/big.txt -u http://lordoftheroot.box:1337/FUZZ -e .git,.txt,.json,.php,.html,.bak,.old,.sql,.zip,.conf,.cfg,.go
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


#### ffuf subdomains below root website
ffuf subdomain enumeration

 -fw              Filter by amount of words in response. Comma separated list of word counts and ranges
  -H               Header `"Name: Value"`, separated by colon. Multiple -H flags are accepted
  
  -hc wrong parameter value returning HTTP response code 400. filtering out response code 400 - Bad request
  
  

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ffuf -u http://trick.htb -w 0-common-with-mylist.txt -H 'Host: preprod-FUZZ.trick.htb' -fw 1697


ffuf -u https://mango.htb -H 'Host: FUZZ.mango.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fw 6

ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.vulnnet.thm" -u http://vulnnet.thm/ -fs 85

ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.koikoi.oscp/" -u http://koikoi.oscp/
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


#### ffuf subdomain root
subdomain root 


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://broadcast.vulnnet.thm/FUZZ -fc 401


ffuf -u http://sneakycorp.htb -H 'Host: FUZZ.sneakycorp.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fw 6

ffuf -u http://horizontall.htb -H 'Host: FUZZ.forge.htb' -w ~/Downloads/wordlists/0-common-with-mylist.txt

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


#### ffuf subdomain root with extensions
subdomain root with extensions



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://broadcast.vulnnet.thm/FUZZ -e .txt,.json,.php,.html,.bak,.old,.sql,.zip,.zz -fc 403


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


#### ffuf known file + Extension
ffuf a known file name but need extension fuzzing

fuzzing only extension if file name is known
verbose print full url


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ffuf -c -v -w ~/Downloads/htb/quick-extensions1.txt -u http://team.thm/scripts/script.FUZZ
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~




#### ffuf thru Proxy
ffuf via Proxy


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ffuf -c -w /root/Downloads/wordlists/webfuzz_less.txt -u http://pinkyspalace.box:8080/FUZZ -x http://pinkyspalace.box:31337
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



ffuf fuzzer to Burp proxy
send found results to burp proxy
burp fuzzer spider scanner methods


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ffuf -c -w /root/Downloads/wordlists/webfuzz_less.txt -u http://pinkyspalace.box:8080/FUZZ -replay-proxy http://127.0.0.1:8080
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


#### ffuf API endpoints
ffuf API Gateway endpoints

special characters wordlist


' single quote escape with slash in below command!
-- comments out the rest of API query syntax for LUA or SQL etc.


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ffuf -u http://target IP/weather/forecast?city=\'FUZZ-- -w /opt/SecLists/Fuzzing/special-chars.txt -mc 200,500 -fw 9
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~




#### ffuf help
help ffuf

ffuf
Encountered error(s): 2 errors occurred.
	* -u flag or -request flag is required
	* Either -w or --input-cmd flag is required

Fuzz Faster U Fool - v1.1.0

HTTP OPTIONS:
  -H               Header `"Name: Value"`, separated by colon. Multiple -H flags are accepted.
  -X               HTTP method to use (default: GET)
  -b               Cookie data `"NAME1=VALUE1; NAME2=VALUE2"` for copy as curl functionality.
  -d               POST data
  -ignore-body     Do not fetch the response content. (default: false)
  -r               Follow redirects (default: false)
  -recursion       Scan recursively. Only FUZZ keyword is supported, and URL (-u) has to end in it. (default: false)
  -recursion-depth Maximum recursion depth. (default: 0)
  -replay-proxy    Replay matched requests using this proxy.
  -timeout         HTTP request timeout in seconds. (default: 10)
  -u               Target URL
  -x               HTTP Proxy URL

GENERAL OPTIONS:
  -V               Show version information. (default: false)
  -ac              Automatically calibrate filtering options (default: false)
  -acc             Custom auto-calibration string. Can be used multiple times. Implies -ac
  -c               Colorize output. (default: false)
  -maxtime         Maximum running time in seconds for entire process. (default: 0)
  -maxtime-job     Maximum running time in seconds per job. (default: 0)
  -p               Seconds of `delay` between requests, or a range of random delay. For example "0.1" or "0.1-2.0"
  -s               Do not print additional information (silent mode) (default: false)
  -sa              Stop on all error cases. Implies -sf and -se. (default: false)
  -se              Stop on spurious errors (default: false)
  -sf              Stop when > 95% of responses return 403 Forbidden (default: false)
  -t               Number of concurrent threads. (default: 40)
  -v               Verbose output, printing full URL and redirect location (if any) with the results. (default: false)

MATCHER OPTIONS:
  -mc              Match HTTP status codes, or "all" for everything. (default: 200,204,301,302,307,401,403)
  -ml              Match amount of lines in response
  -mr              Match regexp
  -ms              Match HTTP response size
  -mw              Match amount of words in response

FILTER OPTIONS:
  -fc              Filter HTTP status codes from response. Comma separated list of codes and ranges
  -fl              Filter by amount of lines in response. Comma separated list of line counts and ranges
  -fr              Filter regexp
  -fs              Filter HTTP response size. Comma separated list of sizes and ranges
  -fw              Filter by amount of words in response. Comma separated list of word counts and ranges

INPUT OPTIONS:
  -D               DirSearch wordlist compatibility mode. Used in conjunction with -e flag. (default: false)
  -e               Comma separated list of extensions. Extends FUZZ keyword.
  -ic              Ignore wordlist comments (default: false)
  -input-cmd       Command producing the input. --input-num is required when using this input method. Overrides -w.
  -input-num       Number of inputs to test. Used in conjunction with --input-cmd. (default: 100)
  -mode            Multi-wordlist operation mode. Available modes: clusterbomb, pitchfork (default: clusterbomb)
  -request         File containing the raw http request
  -request-proto   Protocol to use along with raw request (default: https)
  -w               Wordlist file path and (optional) keyword separated by colon. eg. '/path/to/wordlist:KEYWORD'

OUTPUT OPTIONS:
  -debug-log       Write all of the internal logging to the specified file.
  -o               Write output to file
  -od              Directory path to store matched results to.
  -of              Output file format. Available formats: json, ejson, html, md, csv, ecsv (or, 'all' for all formats) (default: json)

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

  More information and examples: https://github.com/ffuf/ffuf
  


#### ffuf web parameter values
WEb ffuf for parameters and values


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:PARAM -w values.txt:VAL -u http://flasky.offsec/add?PARAM=VAL -mr "VAL" -c


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


#### ffuf API file post request fuzz
FFUF with input file POST FUZZ

https://youtu.be/yM914q6zS-U -> IPPSEC - Hackthebox - Interface API enumeration


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ffuf -u http://prd.m.rendering-api.interface.htb/FUZZ -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -mc all -fs 0

ffuf -u http://prd.m.rendering-api.interface.htb/api/FUZZ -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -mc all -fs 50 -d 'x=x'


ffuf -request api.txt -request-proto http -w /opt/SecLists/Discovery/Web-Content/api/api-seen-in-wild.txt -mc all -fs 36


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


html2pdf

#### FFuF Web report

FFUF Web Report


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ffuf -c -w /root/Downloads/wordlists/0-common-with-mylist.txt -u http://oscp.sec:8080/FUZZ -o ffuf_report.html -of html

ffuf -c -w common.txt -u http://192.168.x.y:8080/FUZZ -o ffuf_report.html -of html && firefox ffuf_report.html

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



#### ffuf Username enum info leak
FFUF Username Enumeration
https://tryhackme.com/room/authenticationbypass

Site reveal if user exist with message = An account with this username already exists’



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ffuf -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.139.148/customers/signup -mr "An account with this username already exists"


" getting valid combination credentials"

ffuf -w valid_usernames.txt:W1,/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.139.148/customers/login -fc 200
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~






#### ffuf vHost Fuzzing
vHost fuzz
https://academy.hackthebox.com/module/144/section/1257


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ffuf -w ./vhosts -u http://192.168.10.10 -H "HOST: FUZZ.randomtarget.com" -fs 612
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.

/opt/useful/SecLists/Discovery/DNS/namelist.txt



#### ffuf recursive
 ffuf -recursion -recursion-depth 1


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ffuf -recursion -recursion-depth 1 -u http://192.168.10.10/FUZZ -w /opt/useful/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~




