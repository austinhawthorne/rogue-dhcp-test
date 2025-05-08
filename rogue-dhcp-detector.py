#!/usr/bin/env python3
"""
DHCP Client Scanner

This script sends a DHCP Discover message from the specified interface and listens
for DHCP Offer responses. It prints the details of any responses received, which can be
used to determine if multiple DHCP servers are present on the subnet.

Usage:
  sudo ./dhcp_client.py -i <interface> -t <timeout>

Example:
  sudo ./dhcp_client.py -i eth0 -t 10
"""

import argparse
import time
from scapy.all import (
    Ether,
    IP,
    UDP,
    BOOTP,
    DHCP,
    sendp,
    sniff,
    RandMAC,
)

def get_random_chaddr():
    """
    Generate a random MAC address (as a string), convert it to bytes,
    and pad it to 16 bytes for the BOOTP chaddr field.
    """
    mac_str = RandMAC()  # This returns a MAC string, e.g. "00:11:22:33:44:55"
    # Remove colons and convert to bytes
    mac_bytes = bytes.fromhex(mac_str.replace(":", ""))
    # Pad to 16 bytes as required by BOOTP
    return mac_bytes.ljust(16, b'\x00')

def send_dhcp_discover(iface):
    """
    Craft and send a DHCP Discover packet.
    """
    discover = (
        Ether(dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=get_random_chaddr())
        / DHCP(options=[("message-type", "discover"), "end"])
    )
    print("[Client] Sending DHCP Discover...")
    sendp(discover, iface=iface, verbose=1)

def handle_dhcp_response(packet):
    """
    Callback function for sniffing DHCP responses.
    If a packet contains a DHCP Offer or ACK, print its details.
    """
    if packet.haslayer(DHCP):
        options = packet[DHCP].options
        msg_type = None
        for opt in options:
            if isinstance(opt, tuple) and opt[0] == "message-type":
                msg_type = opt[1]
                break
        if msg_type == 2:
            response_type = "OFFER"
        elif msg_type == 5:
            response_type = "ACK"
        else:
            response_type = f"Type {msg_type}"
        server_ip = packet[IP].src
        offered_ip = packet[BOOTP].yiaddr
        print(f"[Client] Received DHCP {response_type} from {server_ip} offering IP {offered_ip}")

def dhcp_client(iface, timeout):
    send_dhcp_discover(iface)
    print(f"[Client] Waiting for DHCP responses (timeout: {timeout} seconds)...")
    sniff(
        iface=iface,
        filter="udp and (port 67 or port 68)",
        prn=handle_dhcp_response,
        timeout=timeout,
    )
    print("[Client] Scan complete.")

def main():
    parser = argparse.ArgumentParser(description="DHCP Client Scanner")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to use (e.g., eth0)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Time in seconds to wait for responses (default: 10)")
    args = parser.parse_args()

    dhcp_client(args.interface, args.timeout)

if __name__ == "__main__":
    main()
