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
    unsigned int verdict;
    unsigned int mark;
    unsigned int mark_set;
    unsigned int length;
    unsigned char *data;
} verdictContainer;

static void *get_uid = NULL;

extern void go_callback(int id, unsigned char* data, int len, unsigned int mark, uint32_t idx, verdictContainer *vc, uint32_t uid, uint32_t in_dev, uint32_t out_dev);

static uint8_t stop = 0;

static inline void configure_uid_if_available(struct nfq_q_handle *qh){
    void *hndl = dlopen("libnetfilter_queue.so.1", RTLD_LAZY);
    if (!hndl) {
        hndl = dlopen("libnetfilter_queue.so", RTLD_LAZY);
        if (!hndl){
            printf("WARNING: libnetfilter_queue not available\n");
            return;
        }
    }
    if ((get_uid = dlsym(hndl, "nfq_get_uid")) == NULL){
        printf("WARNING: nfq_get_uid not available\n");
        return;
    }
    printf("OK: libnetfiler_queue supports nfq_get_uid\n");
#ifdef NFQA_CFG_F_UID_GID
    if (qh != NULL && nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)){
        printf("WARNING: UID not available on this kernel/libnetfilter_queue\n");
    }
#endif
}

static int nf_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *arg){
    if (stop) {
        return -1;
    }

    uint32_t id = -1, idx = 0, mark = 0;
    struct nfqnl_msg_packet_hdr *ph = NULL;
    unsigned char *buffer = NULL;
    int size = 0;
    verdictContainer vc = {0};
    uint32_t uid = 0xffffffff;
    uint32_t in_dev=0, out_dev=0;

    in_dev = nfq_get_indev(nfa);
    out_dev = nfq_get_outdev(nfa);

    mark = nfq_get_nfmark(nfa);
    ph   = nfq_get_msg_packet_hdr(nfa);
    id   = ntohl(ph->packet_id);
    size = nfq_get_payload(nfa, &buffer);
    idx  = (uint32_t)((uintptr_t)arg);

#ifdef NFQA_CFG_F_UID_GID
    if (get_uid)
        nfq_get_uid(nfa, &uid);
#endif

    go_callback(id, buffer, size, mark, idx, &vc, uid, in_dev, out_dev);

    if( vc.mark_set == 1 ) {
      return nfq_set_verdict2(qh, id, vc.verdict, vc.mark, vc.length, vc.data);
    }
    return nfq_set_verdict2(qh, id, vc.verdict, vc.mark, vc.length, vc.data);
}

static inline struct nfq_q_handle* CreateQueue(struct nfq_handle *h, uint16_t queue, uint32_t idx) {
    struct nfq_q_handle* qh = nfq_create_queue(h, queue, &nf_callback, (void*)((uintptr_t)idx));
    if (qh == NULL){
        printf("ERROR: nfq_create_queue() queue not created\n");
    } else {
        configure_uid_if_available(qh);
    }
    return qh;
}

static inline void stop_reading_packets() {
    stop = 1;
}

static inline int Run(struct nfq_handle *h, int fd) {
    char buf[4096] __attribute__ ((aligned));
    int rcvd, opt = 1;

    setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &opt, sizeof(int));

    while ((rcvd = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        if (stop == 1) {
            return errno;
        }
        nfq_handle_packet(h, buf, rcvd);
    }

    return errno;
}

#endif
