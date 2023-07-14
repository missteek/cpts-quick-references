# Firewall and IDS/IPS Evasion - Hard Lab

>Now our client wants to know if it is possible to find out the version of the running services on unknown port behind Firewall IDS/IPS. 
>Identify the version of service our client was talking about and submit the flag as the answer. 

[Firewall and IDS/IPS Evasion - Hard Lab](https://academy.hackthebox.com/module/19/section/119)  

> Scanning Options and Description  

* 10.129.2.28	Scans the specified target.
* -p 21,22,25	Scans only the specified ports.
* -sS	Performs SYN scan on specified ports.
* -sA	Performs ACK scan on specified ports.
* -Pn	Disables ICMP Echo requests.
* -n	Disables DNS resolution.
* --disable-arp-ping	Disables ARP ping.
* --packet-trace	Shows all packets sent and received.

>Scan by Using Decoys  
  
```
sudo nmap 10.129.2.47 -p 22,80,50000 -sV -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53 -e tun0 -D RND:10
```  

>Connect To The Filtered Port `50000` discovered, from a different source port of `53` to evade detection.

```
ncat -nv --source-port 53 10.129.2.47 50000
```  

>Additional techniques by targeting [Firewall and IDS/IPS Evasion](https://academy.hackthebox.com/module/19/section/106)  

>Testing Firewall Rule  

```
sudo nmap 10.129.2.28 -n -Pn -p445 -O
```

>Scan by Using Different Source IP  

```
sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0
```  

>SYN-Scan From DNS Port  

```
sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53
```  