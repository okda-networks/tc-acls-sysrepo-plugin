#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include "tcnl.h"

unsigned int djb2_hash(const char *str) {
    unsigned int hash = 5381; // Initial hash value
    int c;

    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }

    return hash;
}

int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
		fprintf(stderr,
			"addattr_l ERROR: message exceeded bound of %d\n",
			maxlen);
		return -1;
	}
	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	if (alen)
		memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
	return 0;
}

int addattr32(struct nlmsghdr *n, int maxlen, int type, __u32 data)
{
	return addattr_l(n, maxlen, type, &data, sizeof(__u32));
}

int tcnl_modify_ingress_qdisc_shared_block(int idx, uint32_t tca_block_id)
{
    // TODO free memory of req
    // TODO convert to sysrepo safe call
    
    struct nl_request req;
    int fd, retsize;
    struct sockaddr_nl sa;
    struct rtattr *rta;

    // Create netlink socket
    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Prepare netlink message
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    req.nlh.nlmsg_flags = NLM_F_CREATE | NLM_F_REPLACE | NLM_F_EXCL | NLM_F_REQUEST;
    req.nlh.nlmsg_type = RTM_NEWQDISC;

    req.tcm.tcm_family = AF_UNSPEC;
    req.tcm.tcm_handle = TC_H_MAKE(0xffff, 0);
    req.tcm.tcm_parent = TC_H_INGRESS;
    req.tcm.tcm_info = 0;
    req.tcm.tcm_ifindex = idx;

    addattr_l(&req.nlh,sizeof(req),TCA_KIND,"ingress",strlen("ingress"));
    addattr32(&req.nlh,sizeof(req),TCA_INGRESS_BLOCK,tca_block_id);

    // Send netlink message
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    retsize = sendto(fd, (void *)&req, req.nlh.nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa));
    printf("return size %d\n", retsize);

    if (retsize == -1) {
        perror("sendto");
        close(fd);
        exit(EXIT_FAILURE);
    }

    close(fd);
    return 0;
}