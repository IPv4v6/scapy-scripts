#!/usr/bin/env python3

from scapy.all import *
from sys import argv

packetlist = rdpcap(argv[1])


for packet in packetlist:

	if packet.haslayer(Raw):
		print(str(datetime.fromtimestamp(packet.time)) + " " +
			str(packet[IP].src) + ":" + str(packet[TCP].sport) + " -> " +
			str(packet[IP].dst) + ":" + str(packet[TCP].dport))
		hexdump(packet[Raw])
		print("------------------------------------------------------------")
