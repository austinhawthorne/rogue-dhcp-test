#!/usr/bin/env python3
import argparse
import subprocess
from scapy.all import sniff, DHCP, BOOTP, IP

# Will be set to the user’s desired DHCP server IP (string), or None
TARGET_SERVER = None

seen = set()

def handle_dhcp_response(packet):
    if not packet.haslayer(DHCP):
        return

    # Get message-type option
    opts = packet[DHCP].options
    msg = next((v for (k, v) in opts if k == 'message-type'), None)
    if msg not in (2, 5):   # 2 = OFFER, 5 = ACK
        return

    resp = "OFFER" if msg == 2 else "ACK"
    server_ip = packet[IP].src
    offered_ip = packet[BOOTP].yiaddr

    # If the user supplied a target server, ignore others
    if TARGET_SERVER and server_ip != TARGET_SERVER:
        return

    key = (resp, server_ip, offered_ip)
    if key not in seen:
        seen.add(key)
        print(f"[Client] DHCP {resp} from {server_ip} → your IP {offered_ip}")

def send_request(iface):
    # Release existing lease, then fire off one-shot DISCOVER→REQUEST
    subprocess.run(['dhclient', '-r', iface],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.Popen(['dhclient', '-1', iface],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def main():
    global TARGET_SERVER

    parser = argparse.ArgumentParser(
        description="Listen for DHCP replies (optionally filtering to one server)"
    )
    parser.add_argument("-i", "--interface", required=True,
                        help="Network interface (e.g. eth0)")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                        help="Seconds to listen for replies (default: 10)")
    parser.add_argument("-s", "--server", dest="target_server", default=None,
                        help="Only accept replies from this DHCP server IP")
    args = parser.parse_args()

    TARGET_SERVER = args.target_server

    print(f"[Client] Triggering host DHCP client on {args.interface}…")
    send_request(args.interface)

    print(f"[Client] Sniffing for {args.timeout}s "
          f"{'from server '+TARGET_SERVER if TARGET_SERVER else 'from all servers'}…")
    sniff(
        iface=args.interface,
        filter="udp and (port 67 or port 68)",
        prn=handle_dhcp_response,
        timeout=args.timeout
    )

    print("[Client] Done scanning.")

if __name__ == "__main__":
    main()
