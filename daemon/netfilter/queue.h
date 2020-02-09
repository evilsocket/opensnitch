#ifndef _NETFILTER_QUEUE_H
#define _NETFILTER_QUEUE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <math.h>
#include <unistd.h>
#include <dlfcn.h>
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

static void *get_uid = NULL;

extern void go_callback(int id, unsigned char* data, int len, uint mark, u_int32_t idx, verdictContainer *vc, uint32_t uid);

static int nf_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *arg){
    uint32_t id = -1, idx = 0, mark = 0;
    struct nfqnl_msg_packet_hdr *ph = NULL;
    unsigned char *buffer = NULL;
    int size = 0;
    verdictContainer vc = {0};
    uint32_t uid = -1;

    mark = nfq_get_nfmark(nfa);
    ph   = nfq_get_msg_packet_hdr(nfa);
    id   = ntohl(ph->packet_id);
    size = nfq_get_payload(nfa, &buffer);
    idx  = (uint32_t)((uintptr_t)arg);

#ifdef NFQA_CFG_F_UID_GID
    if (get_uid)
        nfq_get_uid(nfa, &uid);
#endif

    go_callback(id, buffer, size, mark, idx, &vc, uid);

    if( vc.mark_set == 1 ) {
      return nfq_set_verdict2(qh, id, vc.verdict, vc.mark, vc.length, vc.data);
    } else {
      return nfq_set_verdict(qh, id, vc.verdict, vc.length, vc.data);
    }
}

static inline struct nfq_q_handle* CreateQueue(struct nfq_handle *h, u_int16_t queue, u_int32_t idx) {
    struct nfq_q_handle* qh = nfq_create_queue(h, queue, &nf_callback, (void*)((uintptr_t)idx));
#ifdef NFQA_CFG_F_UID_GID
    if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)){
        printf("queue.Run() no UID allowed by this kernel\n");
    }
#endif
    return qh;
}

static inline int Run(struct nfq_handle *h, int fd) {
    char buf[4096] __attribute__ ((aligned));
    int rcvd, opt = 1;

    void *hndl = dlopen("libnetfilter_queue.so.1", RTLD_LAZY);
    if (!hndl) {
        hndl = dlopen("libnetfilter_queue.so", RTLD_LAZY);
    }
    if (hndl) {
        if ((get_uid = dlsym(hndl, "nfq_get_uid")) == NULL){
            printf("Warning: nfq_get_uid not available\n");
        }
    }

    setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &opt, sizeof(int));

    while ((rcvd = recv(fd, buf, sizeof(buf), 0)) && rcvd >= 0) {
        nfq_handle_packet(h, buf, rcvd);
    }

    return errno;
}

#endif
