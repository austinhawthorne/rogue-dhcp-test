Quick way to test if you have any rogue DHCP servers on your network and if your network is allowing them.  Contains two scripts, one that runs a test rogue DHCP server and one that forces a client to initiate a DHCP request and logs which servers respond.  

To test, run on hosts that are mapped to the same VLAN/Subnet

On the host that you want to run the test server, run the 'rogue-dhcp.py' script with the below options (define the range, mask, gateway, dns, and interface):

```
client1:~/rogue-dhcp-test $ sudo python rogue-dhcp.py -r 10.0.3.10-10.0.3.20 -m 255.255.255.0 -g 10.0.3.100 -d 8.8.8.8 -i eth0
[Server] Interface: eth0
[Server] Server IP: 10.0.3.100
[Server] DHCP Range: 10.0.3.10-10.0.3.20
[Server] Default Gateway: 10.0.3.100
[Server] Subnet Mask: 255.255.255.0
[Server] DNS Server: 8.8.8.8
[Server] Offering IP: 10.0.3.10
[Server] Waiting for DHCP Discover messages...
```

On the host that you want to trigger a DHCP request and record the results, run the 'rogue-detect.py' script with the below options (define the interface and what the valid DHCP server is so the host accepts OFFERs from that server):

```
client2:~/rogue-dhcp-test $ sudo python rogue-detect.py -i eth0 -s 10.0.3.1
[Client] Triggering host DHCP client on eth0…
[Client] Sniffing for 10s from server 10.0.3.1…
[Client] DHCP OFFER from 10.0.3.1 → your IP 10.0.3.180
[Client] Done scanning.
```
