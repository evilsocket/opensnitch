"""Forge reconnaissance techniques that the nmap corpus does not contain.

Each writes one pcap into testdata-style form so the engine can replay it.
Sources: RFC 7707 (Network Reconnaissance in IPv6 Networks), nmap's
targets-ipv6-multicast-* NSE scripts, and the rate-limit side-channel papers.
"""
import sys
from scapy.all import (Ether, IP, IPv6, TCP, UDP, ICMP, wrpcap,
                       ICMPv6EchoRequest, ICMPv6MLQuery, ICMPv6ND_RS,
                       IPv6ExtHdrDestOpt, HBHOptUnknown, IPv6ExtHdrHopByHop,
                       DNS, DNSQR)

SCANNER_MAC = "aa:bb:cc:dd:ee:ff"
VICTIM_MAC  = "02:00:00:00:00:01"
V4_SCANNER, V4_VICTIM = "10.77.0.2", "10.77.0.1"
V6_SCANNER, V6_VICTIM = "fd00:77::2", "fd00:77::1"

def eth(dst=VICTIM_MAC):
    return Ether(src=SCANNER_MAC, dst=dst)

def mcast_mac(v6):
    # 33:33 + last four bytes of the group, per RFC 2464.
    import socket
    b = socket.inet_pton(socket.AF_INET6, v6)
    return "33:33:%02x:%02x:%02x:%02x" % (b[12], b[13], b[14], b[15])

cases = {}

# 1. MP6: ICMPv6 echo request to the all-nodes group. RFC 7707 s3.1.
cases["mp6-multicast-echo"] = [
    eth(mcast_mac("ff02::1"))/IPv6(src=V6_SCANNER, dst="ff02::1")/ICMPv6EchoRequest(id=1, seq=i)
    for i in range(12)
]

# 2. Unrecognised option 0x80 in a Destination Options header, to all-nodes.
#    This is nmap's targets-ipv6-multicast-invalid-dst, and RFC 7707 s3.2:
#    the "10" high bits force a Parameter Problem even from Windows, which
#    ignores multicast echo.
def invalid_dst(dst, i):
    opt = HBHOptUnknown(otype=0x80, optlen=4, optdata=b"\x00\x00\x00\x00")
    return (eth(mcast_mac(dst) if dst.startswith("ff") else VICTIM_MAC)
            / IPv6(src=V6_SCANNER, dst=dst)
            / IPv6ExtHdrDestOpt(options=[opt])
            / ICMPv6EchoRequest(id=2, seq=i))
cases["ieh-invalid-option-multicast"] = [invalid_dst("ff02::1", i) for i in range(12)]

# 3. The same probe sent to our UNICAST address, which is what a scanner does
#    once it has a candidate address from a hitlist.
cases["ieh-invalid-option-unicast"] = [invalid_dst(V6_VICTIM, i) for i in range(12)]

# 4. MLD general query, RFC 7707 s3.3: every listener answers and reveals itself.
cases["mld-query"] = [
    eth(mcast_mac("ff02::1"))/IPv6(src=V6_SCANNER, dst="ff02::1", hlim=1)/ICMPv6MLQuery()
    for _ in range(12)
]

# 5. LLMNR and mDNS name enumeration of this host.
cases["llmnr-enumeration"] = [
    eth(mcast_mac("ff02::1:3"))/IPv6(src=V6_SCANNER, dst="ff02::1:3")
    / UDP(sport=50000+i, dport=5355)/DNS(qd=DNSQR(qname="victim%d.local" % i))
    for i in range(12)
]
cases["mdns-enumeration"] = [
    eth("01:00:5e:00:00:fb")/IP(src=V4_SCANNER, dst="224.0.0.251")
    / UDP(sport=5353, dport=5353)/DNS(qd=DNSQR(qname="_services._dns-sd._udp.local"))
    for _ in range(12)
]

# 6. IPv4 broadcast discovery: ping the subnet and the limited broadcast.
cases["broadcast-ping"] = [
    eth("ff:ff:ff:ff:ff:ff")/IP(src=V4_SCANNER, dst=d)/ICMP(id=3, seq=i)
    for i, d in enumerate(["10.77.0.255", "255.255.255.255"] * 6)
]

# 7. RST rate-limit probing: our host used as an idle-scan reflector. Many
#    packets from one source to ONE port, to measure the global RST budget.
cases["rst-ratelimit-probe"] = [
    eth()/IP(src=V4_SCANNER, dst=V4_VICTIM)/TCP(sport=40000+i, dport=80, flags="S")
    for i in range(60)
]

# 8. ICMP rate-limit side channel (arXiv 2210.13088): a burst of echo requests
#    to our unicast address to measure the ICMPv6 error budget.
cases["icmpv6-ratelimit-probe"] = [
    eth()/IPv6(src=V6_SCANNER, dst=V6_VICTIM)/ICMPv6EchoRequest(id=4, seq=i)
    for i in range(60)
]

# 9. Router Solicitation flood: reveals routers and, by the RA that follows,
#    the prefix -- a topology probe rather than a port probe.
cases["router-solicitation"] = [
    eth(mcast_mac("ff02::2"))/IPv6(src=V6_SCANNER, dst="ff02::2")/ICMPv6ND_RS()
    for _ in range(12)
]

out = sys.argv[1]
for name, pkts in cases.items():
    path = "%s/%s.pcap" % (out, name)
    wrpcap(path, pkts)
    print("%-32s %3d packets" % (name, len(pkts)))
