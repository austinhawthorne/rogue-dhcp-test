#!/usr/bin/env python3
"""
DHCP Server Emulator

This script listens on the specified interface for DHCP Discover messages and responds
with a DHCP Offer message. You can specify:
  - The DHCP range (e.g., "192.168.1.100-192.168.1.200")
  - The default gateway to include in the offer
  - The subnet mask (default is "255.255.255.0")
  - The DNS server IP (optional)

Usage:
  sudo ./dhcp_server.py -i <interface> -r <dhcp_range> -g <default_gateway> [-m <mask>] [-d <dns>]

Example:
  sudo ./dhcp_server.py -i eth0 -r 192.168.1.100-192.168.1.200 -g 192.168.1.1 -m 255.255.255.0 -d 8.8.8.8
"""

import argparse
import ipaddress
import socket
from scapy.all import (
    Ether,
    IP,
    UDP,
    BOOTP,
    DHCP,
    sendp,
    sniff,
    get_if_addr,
    get_if_hwaddr,
)

def choose_offered_ip_range(server_ip, dhcp_range):
    """
    Given the server's IP and a DHCP range string (e.g., "192.168.1.100-192.168.1.200"),
    choose an offered IP by selecting the first address in the range that is not the server IP.
    """
    try:
        start_str, end_str = dhcp_range.split("-")
        start_ip = ipaddress.IPv4Address(start_str)
        end_ip = ipaddress.IPv4Address(end_str)
        server_ip_addr = ipaddress.IPv4Address(server_ip)
    except Exception as e:
        print(f"[Server] Error parsing DHCP range: {e}")
        return None

    for ip_int in range(int(start_ip), int(end_ip) + 1):
        candidate = ipaddress.IPv4Address(ip_int)
        if candidate != server_ip_addr:
            return str(candidate)
    return None

def handle_dhcp_packet(packet, server_ip, server_mac, offered_ip, default_gateway, mask, dns, iface):
    """
    Process incoming DHCP Discover packets and respond with a DHCP Offer.
    """
    if packet.haslayer(DHCP):
        dhcp_options = packet[DHCP].options
        for opt in dhcp_options:
            # DHCP Discover message type is 1
            if isinstance(opt, tuple) and opt[0] == "message-type" and opt[1] == 1:
                client_mac = packet[Ether].src
                client_chaddr = packet[BOOTP].chaddr
                xid = packet[BOOTP].xid

                print(f"[Server] Received DHCP Discover from {client_mac}")
                # Build DHCP options list
                options = [
                    ("message-type", "offer"),
                    ("server_id", server_ip),
                    ("lease_time", 3600),
                    ("subnet_mask", mask),
                    ("router", default_gateway),
                ]
                if dns is not None:
                    # Option 6 for DNS servers; convert the IP to 4-byte binary representation.
                    options.append((6, socket.inet_aton(dns)))
                options.append("end")

                offer = (
                    Ether(src=server_mac, dst="ff:ff:ff:ff:ff:ff")
                    / IP(src=server_ip, dst="255.255.255.255")
                    / UDP(sport=67, dport=68)
                    / BOOTP(
                        op=2,
                        yiaddr=offered_ip,
                        siaddr=server_ip,
                        chaddr=client_chaddr,
                        xid=xid,
                    )
                    / DHCP(options=options)
                )
                sendp(offer, iface=iface, verbose=1)
                print(f"[Server] Sent DHCP Offer with IP {offered_ip} to {client_mac}")

def dhcp_server(iface, dhcp_range, default_gateway, mask, dns):
    server_ip = get_if_addr(iface)
    server_mac = get_if_hwaddr(iface)
    offered_ip = choose_offered_ip_range(server_ip, dhcp_range)
    if not offered_ip:
        print("[Server] Could not determine an offered IP from the specified DHCP range.")
        return

    print(f"[Server] Interface: {iface}")
    print(f"[Server] Server IP: {server_ip}")
    print(f"[Server] DHCP Range: {dhcp_range}")
    print(f"[Server] Default Gateway: {default_gateway}")
    print(f"[Server] Subnet Mask: {mask}")
    if dns:
        print(f"[Server] DNS Server: {dns}")
    print(f"[Server] Offering IP: {offered_ip}")
    print("[Server] Waiting for DHCP Discover messages...")

    sniff(
        iface=iface,
        filter="udp and (port 67 or port 68)",
        prn=lambda pkt: handle_dhcp_packet(pkt, server_ip, server_mac, offered_ip, default_gateway, mask, dns, iface),
    )

def main():
    parser = argparse.ArgumentParser(description="DHCP Server Emulator")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to use (e.g., eth0)")
    parser.add_argument("-r", "--range", required=True, help="DHCP range (e.g., 192.168.1.100-192.168.1.200)")
    parser.add_argument("-g", "--gateway", required=True, help="Default gateway to include in the DHCP Offer (e.g., 192.168.1.1)")
    parser.add_argument("-m", "--mask", required=False, default="255.255.255.0", help="Subnet mask for the DHCP Offer (default: 255.255.255.0)")
    parser.add_argument("-d", "--dns", required=False, default=None, help="DNS server IP to include in the DHCP Offer (optional)")
    args = parser.parse_args()

    dhcp_server(args.interface, args.range, args.gateway, args.mask, args.dns)

if __name__ == "__main__":
    main()
