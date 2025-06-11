#!/usr/bin/env python3
import argparse
import subprocess
from scapy.all import (
    sniff, sendp,
    Ether, IP, UDP, BOOTP, DHCP,
    get_if_hwaddr
)

TARGET_SERVER = None       # IP of the DHCP server we want to accept, if any
_requested = False         # Have we already sent our custom REQUEST?
_offers = {}               # Map server_ip → (offered_ip, xid)

def handle_dhcp_response(pkt):
    global _requested

    if not pkt.haslayer(DHCP):
        return

    # Pull out message-type
    opts = pkt[DHCP].options
    msg = next((v for (k, v) in opts if k == 'message-type'), None)
    if msg not in (2, 5):   # 2=OFFER, 5=ACK
        return

    server_ip  = pkt[IP].src
    your_ip    = pkt[BOOTP].yiaddr
    xid        = pkt[BOOTP].xid
    resp_name  = "OFFER" if msg == 2 else "ACK"

    # 1) Display EVERY unique offer/ack
    key = (resp_name, server_ip, your_ip)
    if key not in _offers:
        _offers[key] = xid
        print(f"[Client] DHCP {resp_name} from {server_ip} → your IP {your_ip}")

    # 2) If this is an OFFER from our target server, send a custom REQUEST
    if msg == 2 and TARGET_SERVER == server_ip and not _requested:
        send_explicit_request(iface=args.interface,
                              server_ip=server_ip,
                              offered_ip=your_ip,
                              xid=xid)
        _requested = True

def send_explicit_request(iface, server_ip, offered_ip, xid):
    """
    Craft and send a DHCPREQUEST to accept the given OFFER.
    """
    client_mac = get_if_hwaddr(iface)
    # chaddr needs 16 bytes: MAC (6 bytes) + padding (10 bytes)
    mac_bytes = bytes.fromhex(client_mac.replace(":", "")) + b"\x00" * 10

    pkt = (
        Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(op=1, chaddr=mac_bytes, xid=xid) /
        DHCP(options=[
            ("message-type", "request"),
            ("server_id", server_ip),
            ("requested_addr", offered_ip),
            "end"
        ])
    )
    sendp(pkt, iface=iface, verbose=False)
    print(f"[Client] Sent custom DHCPREQUEST to accept OFFER from {server_ip}")

def kick_host_dhcp(iface):
    """
    Use the system dhclient just to fire off DISCOVER/REQUEST.
    We still capture all OFFERS and then send our own REQUEST if needed.
    """
    subprocess.run(['dhclient', '-r', iface],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # one-shot discover+request
    subprocess.Popen(['dhclient', '-1', iface],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Detect all DHCP servers, and optionally accept one"
    )
    parser.add_argument("-i", "--interface", required=True,
                        help="Network interface (e.g., eth0)")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                        help="Seconds to listen for replies")
    parser.add_argument("-s", "--server", dest="target", default=None,
                        help="Server IP whose OFFER we should accept")
    args = parser.parse_args()
    TARGET_SERVER = args.target

    print(f"[Client] Triggering host DHCP client on {args.interface}…")
    kick_host_dhcp(args.interface)

    mode = f"and accepting {TARGET_SERVER}" if TARGET_SERVER else "from all servers"
    print(f"[Client] Sniffing for {args.timeout}s {mode}…")
    sniff(
        iface=args.interface,
        filter="udp and (port 67 or port 68)",
        prn=handle_dhcp_response,
        timeout=args.timeout
    )

    print("[Client] Done scanning.")
