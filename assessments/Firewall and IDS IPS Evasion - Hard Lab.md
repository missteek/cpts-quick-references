# Firewall and IDS/IPS Evasion - Hard Lab

Firewall and IDS/IPS Evasion - Hard Lab
https://academy.hackthebox.com/module/19/section/119



sudo nmap 10.129.2.47 -p 22,80,50000 -sV -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53 -e tun0 -D RND:10



https://academy.hackthebox.com/module/19/section/106




ncat -nv --source-port 53 10.129.2.47 50000
