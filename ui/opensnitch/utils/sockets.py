

# https://pkg.go.dev/syscall#pkg-constants
Family = {
    '0': 'AF_UNSPEC',
    '2': 'AF_INET',
    '10': 'AF_INET6',
    '11': 'AF_PACKET',
    '40': 'AF_VSOCK',
    '44': 'AF_XDP',
    '45': 'AF_MCTP',
}

Proto = {
    '0': 'IP',
    '1': 'ICMP',
    '2': 'IGMP',
    '3': 'ETH_P_ALL',
    '6': 'TCP',
    '17': 'UDP',
    '33': 'DCCP',
    '41': 'IPv6',
    '58': 'ICMPv6',
    '132': 'SCTP',
    '136': 'UDPLITE',
    '255': 'RAW'
}

State = {
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
