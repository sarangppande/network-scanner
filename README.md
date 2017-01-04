# network-scanner
A network scanning tool

# Getting Started
## Prerequisite 
1) Python 2.7

2) Scapy Library 

## Installation 
There are no explict installation step, just download the file and run them.
```
Note: Please make sure that ieee-oui.txt file is in the same directory as the arp-scan.py file.
```
# Usage

## synprobe.py

This application scans for open ports on given IP address or subnet. After finding all open port it probes those open port to collect more information using three-way handshake.

```
python synprobe.py -pStart-End ip_address/subnet_mask
```
Options:
-p: port range

## arp-scan.py

This application list the MAC address of given IP address or Subnet using ARP protocol. Application uses first 6 hexadecimal values of the MAC address to determine Ethernet card vendor.

```
python arp-scan.py ip_address/subnet_mask
```

## Acknowledgments
1) File (ieee-oui.txt) courtesy of : https://github.com/royhills/arp-scan/blob/master/ieee-oui.txt
