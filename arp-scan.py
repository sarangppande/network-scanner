#! /usr/bin/env python

import sys, os
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import srp
from scapy.layers.inet import Ether, ARP

mac_vendor_map = {}
# Read ieee-oui.txt file which contain mac-address,Vendor mapping
# https://github.com/royhills/arp-scan/blob/master/ieee-oui.txt
with open("ieee-oui.txt") as file:
    content = file.read().splitlines()
for line in content:
    if not line.startswith("#"):
        mac, vendor = line.split("\t")
        mac_vendor_map[mac] = vendor

# Read the IP address or Subnet address   
try: 
    ip_address_range = sys.argv[1]
except:
        print "Please provide IP address or Subnet Address"
        exit()

# Send ARP packet to desination IP address
ans, unasn = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address_range), timeout=2, verbose=0)
ip_mac_vendor_list = []
if ans:
    print "\n"
    print "IP Address".center(17, " ") + "MAC Address".center(17, " ") + "Vendor".center(17, " ")
else:
    print "ARP scan result empty"
for send, recv in ans:
    mac_address = recv.getlayer(Ether).hwsrc
    ip_address_src = recv.getlayer(Ether).psrc
    try:
        vendor = mac_vendor_map[mac_address.replace(":", "")[0:6]]
    except:    
        vendor = "(Unknown)"
    ip_mac_vendor_list.append([ip_address_src, mac_address, vendor]) 
    print ip_address_src.ljust(17) + "  " + mac_address.ljust(17) + "  " + vendor.ljust(17)
