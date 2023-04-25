#!/usr/bin/env python3

from scapy.all import *
import datetime
from scapy.layers.http import HTTPRequest
from ip2geotools.databases.noncommercial import DbIpCity    # To Convert IP address to locations
import os
import time

def sniff_b(iface=None):
	sniff(prn=process_packet, store=False)
	
def process_packet(packet):			
		
	if packet.haslayer(TCP):           # To capture TCP Packets
		if packet.haslayer(HTTPRequest):
			a= format(len(packet[TCP]))
			c= packet.src   
			b= packet.dst 
			response = DbIpCity.get(packet[IP].src, api_key='free')
			x= response.city
			i= packet.sport  
			h= packet.dport
			g= packet[IP].src     
			e= packet[IP].dst 
			f= packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
			time= datetime.datetime.now()	
			print(f"\n[+] Capture Time: {time}\n Destination MAC: {b}\n Source MAC: {c}\n Protocol: TCP, Transfer Control Protocol\n Destination Address: {e}\n Source Address: {g}\n Destination Port: {h}\n Source Port: {i}\n Size: {a} Bytes\n Url: {f}\n Location: {x}")
	
	if packet.haslayer(UDP):      # To capture UDP Packets

			a= format(len(packet[UDP]))
			c= packet.src   
			b= packet.dst 
			i= packet.sport
			response = DbIpCity.get(packet[IP].src, api_key='free')
			x= response.city  
			h= packet.dport
			g= packet[IP].src     
			e= packet[IP].dst  
			time= datetime.datetime.now()	
			print(f"\n[+] Capture Time: {time}\n Destination MAC: {b}\n Source MAC: {c}\n Protocol: UDP, User Datagram Protocol\n Destination Address: {e}\n Source Address: {g}\n Destination Port: {h}\n Source Port: {i}\n Size: {a} Bytes \n Location: {x}")

	if packet.haslayer(ICMP):  # To capture ICMP Packets
			a= format(len(packet[ICMP]))
			c= packet.src   
			b= packet.dst 
			response = DbIpCity.get(packet[IP].src, api_key='free')
			x= response.city  
			g= packet[IP].src     
			e= packet[IP].dst  
			time= datetime.datetime.now()	
			print(f"\n[+] Capture Time: {time}\n Destination MAC: {b}\n Source MAC: {c}\n Protocol: ICMP, Internet Control Message Protocol\n Destination Address: {e}\n Source Address: {g}\n Size: {a} Bytes\n Location: {x}")


if __name__ == "__main__":
	import argparse   # parse arguments
	parser = argparse.ArgumentParser(description="Personal Packet Sniffer, here to protect your home.")
	parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
	parser.add_argument("--show-raw", dest="show_raw", action="store_true", help="Check If all libraries are installed properly")
	args = parser.parse_args()
	iface = args.iface
	show_raw = args.show_raw
	sniff_b(iface)
