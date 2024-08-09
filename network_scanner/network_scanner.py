#!/usr/bin/env python

import scapy.all as scapy #scapy comes with python 2.7 for 3 or higher pip3 install scapy-python3
# import optparse #opt parser is older version, its hiher is arg parse
# def get_arguments():
#     parser = optparse.OptionParser()
#     parser.add_option("-t", "--target", dest = "target", help="Enter the target ip/ ip range")
#     (options, arguments) = parser.parse_args()
#     if not  options:
#         parser.error("[-] Please specify the target ip, use --help for more info.")
#     return options

import argparse #opt parser is older version, its hiher is argparse
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest = "target", help="Enter the target ip/ ip range")
    options = parser.parse_args()
    if not  options:
        parser.error("[-] Please specify the target ip, use --help for more info.")
    return options
def scan(ip):
    arp_request = scapy.ARP(pdst = ip)
    # arp_request.show()
    broadcast =scapy.Ether(dst  = "ff:ff:ff:ff:ff:ff")
    # broadcast.show()
    arp_request_broadcast = broadcast/arp_request
    # arp_request_broadcast.show()
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose = False)[0]
    # print(answered_list.summary())
    # print(answered_list.summary())
    # print("IP\t\t\tMAC ADDRESS\n-----------------------------------------")
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc,"mac": element[1].hwsrc }
        clients_list.append(client_dict)
        # print(element[1].psrc + "\t\t"+ element[1].hwsrc)
    return clients_list
        # print(arp_request_broadcast.summary())qq

def print_result(result_list):
    print("IP\t\t\tMAC ADDRESS\n-------------------------------------------------")
    for client in result_list:
        print(client["ip"]+"\t\t"+client["mac"])

options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)
