#!/usr/bin/env python
import argparse
from tabnanny import verbose
import scapy.all as scapy  # pip3 install scapy-python3


def parse_input():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--range", dest="range",
                        help="The target IP range => Format FirstIP\SubnetMask: e.g. 192.168.100.1/24")
    opts = parser.parse_args()
    if not opts.range:
        parser.error(
            "[-] You have to enter the IP range name => (Check `python3 network-scanner.py -h` for more info).")
    return opts


def scan_ip_range(range):
    # scapy.arping(range)
    # scapy.ls(scapy.ARP()) # Know the field names
    # ARP packet object that contains IPs that we need to know its own MACs
    arp_request = scapy.ARP(pdst=range)
    # print(arp_request.summary())

    # Send ARP fram to ask about all possibe IPs in the whole devices in the same networks because we sent the ARP Packet to the BC MAC
    # Use ethernet fram to set dst MAC
    broadcast_ethernet_fram = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    # scapy.ls(scapy.Ether()) # Know the field names

    # append APR req to BC frame.
    arp_request_broadcast_compination = broadcast_ethernet_fram/arp_request
    # print(arp_request_broadcast_compination.summary()) # to show a summary about working of this portion
    # arp_request_broadcast_compination.show() # show more details about the content of this packet

    # sr function to send and receive packets, but srp allow to send and recieve Packets with a custom Ether part
    # before sending a packet, you need to configure this packet to go to its dst (as we did in ether part above)
    # I need to omit the unanswered_packets
    answered_packets, _ = scapy.srp(
        arp_request_broadcast_compination, timeout=1, verbose=False)  # to wait for one second
    # print(answered_packets.show())
    recieved_ips_macs_list = []
    for _, received in answered_packets:
        recieved_ips_macs_map = {'ip': received.pdst, 'mac': received.hwdst}
        recieved_ips_macs_list.append(recieved_ips_macs_map)
        # print(received.pdst, received.hwdst, sep="\t\t")
    return recieved_ips_macs_list


def print_ips_and_macs(ips_macs_list_of_dict):
    print("_" * 50)
    print("IP\t\t\tMAC")
    print("-" * 50)
    for ips_macs_dict in ips_macs_list_of_dict:
        print(ips_macs_dict['ip'], ips_macs_dict['mac'], sep="\t\t")


opts = parse_input()
founded_info = scan_ip_range(opts.range)
print_ips_and_macs(founded_info)
