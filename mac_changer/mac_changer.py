#!/usr/bin/env python
import subprocess
import optparse
import re

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change its MAC address")
    parser.add_option("-m", "--mac", dest="new_mac", help="New Mac address")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] please specify a new interface, use --help for more info.")
    elif not options.new_mac:
        parser.error("[-] please specify a new mac, use --help for more info.")
    return options

def change_mac(interface, new_mac):
    print("changing mac address for " + interface + " with " + new_mac)

    # subprocess.call("sudo ifconfig " + interface + " down", shell=True)
    # subprocess.call("sudo ifconfig " + interface + " hw ether " + new_mac, shell=True)
    # subprocess.call("sudo ifconfig " + interface + " up", shell=True)

    subprocess.call(["sudo", "ifconfig", interface, "down"])
    subprocess.call(["sudo", "ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["sudo", "ifconfig", interface, "up"])

def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(["ifconfig", interface]).decode('utf-8')
    mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)
    if mac_address_search_result:
        return mac_address_search_result.group(0)
    else:
        print("Could not read mac address.")

options = get_arguments()
current_mac = get_current_mac(options.interface)
print("Current Mac = " + str(current_mac))
change_mac(options.interface, options.new_mac)
current_mac = get_current_mac(options.interface)
if current_mac == options.new_mac:
    print("[+] MAC address was succesfully changed")
else:
    print("[-] MAC address was did not change")
# 00:11:22:33:44:55
