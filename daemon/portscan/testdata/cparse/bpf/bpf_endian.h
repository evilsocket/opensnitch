/*
 * A stand-in for libbpf's <bpf/bpf_endian.h>. See bpf_helpers.h in this
 * directory for why the shim exists at all.
 *
 * libbpf's version resolves at compile time against the TARGET's endianness,
 * which for a BPF object is the host's. Using the host byte order here is
 * therefore the faithful choice, not a shortcut: on the little-endian machines
 * this is built and run on, both expand to the same byte swap.
 */
#ifndef PORTSCAN_SHIM_BPF_ENDIAN_H
#define PORTSCAN_SHIM_BPF_ENDIAN_H

#include <linux/bpf.h>

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohl(x) __builtin_bswap32(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#else
#define bpf_ntohs(x) (x)
#define bpf_htons(x) (x)
#define bpf_ntohl(x) (x)
#define bpf_htonl(x) (x)
#endif

#endif /* PORTSCAN_SHIM_BPF_ENDIAN_H */
