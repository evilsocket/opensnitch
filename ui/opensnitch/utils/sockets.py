

# https://pkg.go.dev/syscall#pkg-constants
Family = {
    '0': 'AF_UNSPEC',
    '2': 'AF_INET',
    '10': 'AF_INET6',
    '17': 'AF_PACKET',
    '40': 'AF_VSOCK',
    '44': 'AF_XDP',
    '45': 'AF_MCTP',
}

Proto = {
    '0': 'IP',
    '1': 'ICMP',
    '2': 'IGMP',
    '6': 'TCP',
    '17': 'UDP',
    '33': 'DCCP',
    '41': 'IPv6',
    '58': 'ICMPv6',
    '132': 'SCTP',
    '136': 'UDPLITE',
    '255': 'RAW',
    '3':     'ETH_P_ALL',
    '2048':  'ETH_P_IP',
    '34525': 'ETH_P_IPV6',
    '2054':  'ETH_P_ARP',
    '32821': 'ETH_P_RARP',
    '33024': 'ETH_P_8021Q',
    '4':     'ETH_P_802_2',
    '34916': 'ETH_P_PPPOE',
    '34958': 'ETH_P_PAE',
    '35085': 'ETH_P_FCOE'
}

State = {
# special case for protos that don't report state (AF_PACKET)
    '0': 'LISTEN',
    '1': 'Established',
    '2': 'TCP_SYN_SENT',
    '3': 'TCP_SYN_RECV',
    '4': 'TCP_FIN_WAIT1',
    '5': 'TCP_FIN_WAIT2',
    '6': 'TCP_TIME_WAIT',
    '7': 'CLOSE',
    '8': 'TCP_CLOSE_WAIT',
    '9': 'TCP_LAST_ACK',
    '10': 'LISTEN',
    '11': 'TCP_CLOSING',
    '12': 'TCP_NEW_SYNC_RECV',
    '13': 'TCP_MAX_STATES'
}
