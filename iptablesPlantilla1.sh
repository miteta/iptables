#!/bin/bash 

##VARIABLES## 
PORTS_INTERNET_TCP="80,443,53" 
PORTS_INTERNET_UDP="53" 
INTERNET="enp0s3" 
DMZ="enp0s8" 
XARXA_INTERNA="enp0s9" 

##ESBORRAR REGLES ANTERIORS## 
iptables -t filter -X 
iptables -t filter -F 
iptables -t nat -X 
iptables -t nat -F 

##POLITICA PER DEFECTE LLISTES BLANQUES## 
iptables -P OUTPUT DROP 
iptables -P INPUT DROP 
iptables -P FORWARD DROP 

##REGLES GENERIQUES## 
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 
iptables -A INPUT -p icmp -j ACCEPT 
iptables -A OUTPUT -p icmp -j ACCEPT 
iptables -A FORWARD -p icmp -j ACCEPT 

echo 1 > /proc/system/net/ipv4/ip_forward #Bit de forwarding 
iptables -t nat -A POSTROUTING -o $INTERNET -j MASQUERADE 

##REGLES BASTIÓ## 
iptables -A OUTPUT -p tcp -m multiport --dport $PORTS_INTERNET_TCP -o $INTERNET -j ACCEPT iptables -A OUTPUT -p udp -m multiport --dport $PORTS_INTERNET_UDP -o $INTERNET -j ACCEPT iptables -A INPUT -i $XARXA_INTERNA -p tcp --dport 22 -j ACCEPT 

##ESTACIO DE TREBALL## 
iptables -A FORWARD -o $INTERNET -p tcp -m multiport --dport $PORTS_INTERNET_TCP -j ACCEPT iptables -A FORWARD -o $INTERNET -p udp -m multiport --dport $PORTS_INTERNET_UDP -j ACCEPT iptables -A FORWARD -i $XARXA_INTERNA -o $DMZ -p tcp --dport 80 -j ACCEPT 

##DMZ## 
#Esta implementat a les 2 primeres regles de l'estació de treball 

##INTERNET## 
iptables -t nat -A PREROUTING -i $INTERNET -p tcp --dport 80 -j DNAT --to-destination 192.168.1.2 iptables -A FORWARD -i $INTERNET -o $DMZ -p tcp --dport 80 -j ACCEPT
