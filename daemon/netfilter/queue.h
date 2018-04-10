#ifndef _NETFILTER_QUEUE_H
#define _NETFILTER_QUEUE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <math.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

typedef struct {
    uint verdict;
    uint mark;
    uint mark_set;
    uint length;
    unsigned char *data;
} verdictContainer;

extern void go_callback(int id, unsigned char* data, int len, uint mark, u_int32_t idx, verdictContainer *vc);

static int nf_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *arg){
    uint32_t id = -1, idx = 0, mark = 0;
    struct nfqnl_msg_packet_hdr *ph = NULL;
    unsigned char *buffer = NULL;
    int size = 0;
    verdictContainer vc = {0};

    mark = nfq_get_nfmark(nfa);
    ph   = nfq_get_msg_packet_hdr(nfa);
    id   = ntohl(ph->packet_id);
    size = nfq_get_payload(nfa, &buffer);
    idx  = (uint32_t)((uintptr_t)arg);

    go_callback(id, buffer, size, mark, idx, &vc);

    if( vc.mark_set == 1 ) {
      return nfq_set_verdict2(qh, id, vc.verdict, vc.mark, vc.length, vc.data);
    } else {
      return nfq_set_verdict(qh, id, vc.verdict, vc.length, vc.data);
    }
}

static inline struct nfq_q_handle* CreateQueue(struct nfq_handle *h, u_int16_t queue, u_int32_t idx) {
    return nfq_create_queue(h, queue, &nf_callback, (void*)((uintptr_t)idx));
}

static inline int Run(struct nfq_handle *h, int fd) {
    char buf[4096] __attribute__ ((aligned));
    int rcvd, opt = 1;

    setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &opt, sizeof(int));

    while ((rcvd = recv(fd, buf, sizeof(buf), 0)) && rcvd >= 0) {
        nfq_handle_packet(h, buf, rcvd);
    }

    return errno;
}

#endif
