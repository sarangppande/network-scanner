#! /usr/bin/env python

import logging
import sys, os, re
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sr, sr1, send, hexdump, sniff
from scapy.layers.inet import IP, ICMP, TCP



# Need to create a new rule in IP table to not drop packets,
# because packets are created and user level and kernel is unaware of request, so drops any response and RST the connection 
os.system('iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP')

INVLAID_ARGUMENTS_ERROR = 'Invalid Arguments, please check and try again with correct arguments\n' + \
                           'Port number range should be defined as follows: -pStart-End\n' + \
                           'IP address or subnet should be defined as : xxx.xxx.xxx.xxx or xxx.xxx.xxx.xxx/xx'

# Helper Methods  required for finding all IP address in subnet
def find_position_of_seperator(ip_address_of_subnet, position_number):
    position_of_seperator = -1
    for j in range(0, position_number):
            position_of_seperator = ip_address_of_subnet.find(".", position_of_seperator + 1)
    return position_of_seperator

def increment_prev_octet(first_three_octet, octet_number):
    if octet_number != 0 :    
        position_of_seperator = find_position_of_seperator(first_three_octet, octet_number - 1)
        octet = int (first_three_octet [position_of_seperator + 1:])
        if octet == 255:
            return     increment_prev_octet(first_three_octet [:position_of_seperator - 2], octet_number - 1)    
        else:
            octet = octet + 1
            return first_three_octet [:position_of_seperator + 1] + str(octet)


def ERROR():
    print INVLAID_ARGUMENTS_ERROR
    exit()

# ++++++++++++++Start of Application: synprobe.py++++++++++++++++++++

# List of ip and ports
list_of_ip = []
list_of_open_port = []    
# Common ports : List same as the one used by nmap
list_of_port = [80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
    143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
    1025, 587, 8888, 199, 1720,
    113, 554, 256]
ip_address = ""

# Store Command Line arguments
# Check if port number are specified
try:
    if sys.argv[1].startswith('-p'):
            position_of_dash = sys.argv[1][1:].find("-")
    
            # if no dash was provided between port range, show error
            if position_of_dash == -1:
		exit()
            port_number_start_range = int(sys.argv[1][2:position_of_dash + 1])
            port_number_end_range = int(sys.argv[1][position_of_dash + 2:])
    
            # if start port number is greater than end port number
            if port_number_start_range > port_number_end_range:
		exit()
        
            # Save all port number in the range into a list
            list_of_port = []
            for i in range(port_number_start_range, port_number_end_range + 1):
                list_of_port.append(i)
        
    else:
            # if port range was not provided means the first argument is IP address
            ip_address = sys.argv[1]
        
    # Read the IP address or Subnet address
    if len(ip_address) == 0:    
            ip_address = sys.argv[2]
except:
    ERROR()
# Find position of slash in IP if subnet is given     
position_of_subnet_marker = ip_address.find("/")
# Find all IPs in Subnet
if position_of_subnet_marker != -1:
    ip_address_of_subnet, mask = ip_address.split("/")
    no_of_ip_address = (2 ** (32 - int(mask)))
    position_of_seperator = find_position_of_seperator(ip_address_of_subnet, 3)
    print "No of IP in subnet: " + str(no_of_ip_address)
    # Seperate the first 3 octet and last octet , Increment the last octet till it hit 255 then increment prev octect once and repeat with last octet
    first_three_octet = ip_address_of_subnet[0:position_of_seperator + 1]
    last_octet = int (ip_address_of_subnet[position_of_seperator + 1:])
    for i in range(1, no_of_ip_address - 1):
        last_octet = last_octet + 1
        if(last_octet > 255):
            last_octet = 0
            first_three_octet = increment_prev_octet(first_three_octet[:-1], 3) + "."
        list_of_ip.append(first_three_octet + str(last_octet))         
else:
    list_of_ip.append(ip_address)


# Send SYN request to identify open ports on victims
for ip in list_of_ip:
    # we will first check if machine with IP is online, so that we can avoid checking ports of offline machines 
    ping_packet = IP(dst=ip) / ICMP()
    reply = sr1(ping_packet, timeout=2, verbose=0)
    if reply:
        for port in list_of_port:
            # Send SYN flag to machine and check if it replies ACK+SYN
            ans = sr1(IP(dst=ip) / TCP(dport=port, flags="S"), verbose=0)
            if ans[0].getlayer(TCP).flags == 18:
                list_of_open_port.append([ans[0].getlayer(IP).src, ans[0].getlayer(TCP).sport])

print "Number of Open ports: " + str(len(list_of_open_port))
print "\n+++++++++++++++++++++++++++++++++++++\n"
# Probing 
for p in list_of_open_port:
    ip = p[0]
    port = p[1]
    IP_PACKET = IP(dst=ip)
    # 1) SEND SYN packet to Machine
    SYN = TCP(dport=port, flags='S')
    # 2) Wait for SYN ACK reply
    SYN_ACK = sr1(IP_PACKET / SYN, verbose=0)
    # 3) Send ACK . Three way handshake complete. Piggybacking HTTP request to see reply from service
    ACK = TCP(dport=port, flags='A', seq=SYN_ACK.ack, ack=SYN_ACK.seq + 1)
    http_request, error = sr(IP_PACKET / ACK / "GET / HTTP/1.0\r\n\r\n", verbose=0, multi=True, timeout=2)
    try:
        print "IP Address: " + ip + "  port no: " + str(port)
        load = http_request[1][1].getlayer(TCP).load             
        print "Service response: \n"
        # print 1024 bytes
        if len(load) > 1024:
            print hexdump(load[0:1024])
        else:
            print hexdump(load)
    except:
        print "Response was empty. Retrying to get response with another request having longer timeout\n"
        try:
            http_request, error = sr(IP_PACKET / ACK / "GET / HTTP/1.0\r\n\r\n", verbose=0, multi=True, timeout=10)
            load = http_request[1][1].getlayer(TCP).load             
            print "Service response: \n"
            if len(load) > 1024:
                print hexdump(load[0:1024])
            else:
                print hexdump(load)
        except:
            print "No Reply from service"
    finally:
        print "\n+++++++++++++++++++++++++++++++++++++\n"

    # kill the connection
    close_connection = send(IP_PACKET / TCP(dport=port, flags='RA', seq=http_request[0][1].getlayer(TCP).ack, ack=http_request[0][1].getlayer(TCP).seq + 1), verbose=0)

# Drop the IP rule table that we added
os.system('iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP')

