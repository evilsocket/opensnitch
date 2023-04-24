#!/bin/sh
#
# OpenSnitch - 2023
# https://github.com/evilsocket/opensnitch
#
# Usage: bash debug-ebpf-maps.sh tcp (or tcpv6, udp, udpv6)
#

function print_map_proto
{
    case "$1" in
        12001)
            echo "------------------------------  TCP  ------------------------------"
            ;;
        12002)
            echo "------------------------------ TCPv6 ------------------------------"
            ;;
        12003)
            echo "------------------------------  UDP  ------------------------------"
            ;;
        12004)
            echo "------------------------------ UDPv6 ------------------------------"
            ;;
    esac
}

function dump_map
{
    echo
    print_map_proto $mid
    bpftool map dump id $1 |awk '
    BEGIN { total=0; }
    {
        split($0, line);
        if (line[1] == "key:"){
            is_key=1;
            total++;
        } else if (is_key == 1){
            sport=strtonum("0x" line[2] line[1]);
            dport=strtonum("0x" line[7] line[8]);
            printf("%d:%d.%d.%d.%d -> %d.%d.%d.%d:%d\n",
                sport,
                strtonum("0x" line[3]),
                strtonum("0x" line[4]),
                strtonum("0x" line[5]),
                strtonum("0x" line[6]),
                strtonum("0x" line[9]),
                strtonum("0x" line[10]),
                strtonum("0x" line[11]),
                strtonum("0x" line[12]),
                dport);
            is_key=0;
        }
    }
    END { printf("Total: %d\n", total); }'
    print_map_proto $mid
}

if [ -z $1 ]; then
    echo
    echo "   Usage: bash debug-ebpf-maps.sh <proto> (tcp, tcpv6, udp or udpv6)"
    echo
    exit
fi
if ! command -v bpftool; then
    echo
    echo "  [error] bpftool not found. Install it."
    echo
    exit
fi

mid=0
case "$1" in
    tcp)
        mid=$(bpftool map list | grep -B 1 12001 | grep hash | cut -d: -f1)
        ;;
    tcpv6)
        mid=$(bpftool map list | grep -B 1 12002 | grep hash | cut -d: -f1)
        ;;
    udp)
        mid=$(bpftool map list | grep -B 1 12003 | grep hash | cut -d: -f1)
        ;;
    udpv6)
        mid=$(bpftool map list | grep -B 1 12004 | grep hash | cut -d: -f1)
        ;;
esac
if [ $mid -eq 0 ]; then
    echo
    echo "  [error] Invalid protocol ($1)"
    echo
    exit
fi

dump_map $mid
