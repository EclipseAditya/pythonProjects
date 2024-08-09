#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] HTTP Request")
            print(packet)
        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] HTTP Response")
            print(packet)

    # packet.accept()
    print(packet)
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

