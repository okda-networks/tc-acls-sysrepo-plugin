#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include "tcnl.h"
#include <netlink/errno.h>
#include "plugin/context.h"
#include <netlink/route/rtnl.h>
#include <srpc.h>
#include "plugin/common.h"
#include "uthash.h"
#include "utlist.h"

unsigned int acl_name2id(const char *str) {
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

// add or update ingress qdisc block id for a given interface.
int tcnl_modify_ingress_qdisc_shared_block(onm_tc_nl_ctx_t* nl_ctx, int if_idx, uint32_t tca_block_id)
{
    struct nl_request req;
    int ret;

    // Prepare netlink message
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    req.nlh.nlmsg_flags = NLM_F_CREATE | NLM_F_REPLACE | NLM_F_EXCL | NLM_F_REQUEST;
    req.nlh.nlmsg_type = RTM_NEWQDISC;
    req.tcm.tcm_family = AF_UNSPEC;
    req.tcm.tcm_handle = TC_H_MAKE(0xffff, 0);
    req.tcm.tcm_parent = TC_H_INGRESS;
    req.tcm.tcm_info = 0;
    req.tcm.tcm_ifindex = if_idx;
    addattr_l(&req.nlh,sizeof(req),TCA_KIND,"ingress",strlen("ingress"));
    addattr32(&req.nlh,sizeof(req),TCA_INGRESS_BLOCK,tca_block_id);

    // Send netlink message
    SRPLG_LOG_INF(PLUGIN_NAME, "NETLINK: applying acl %d for interface ID %d",tca_block_id, if_idx);
    ret = nl_sendto(nl_ctx->socket, &req, req.nlh.nlmsg_len);
    if (ret == -1) {
        SRPLG_LOG_ERR(PLUGIN_NAME, "NETLINK: failed to apply acl %d for interface ID %d",tca_block_id, if_idx);
        return -1;
    }
    return 0;
}


// TODO experimential
int tcnl_tc_block_exists(onm_tc_nl_ctx_t* nl_ctx,unsigned int tca_block_id)
{
    int sockfd,ret;
    struct sockaddr_nl src_addr, dest_addr;

    struct nlmsghdr *nlh_recv;
    struct iovec iov_send, iov_recv;
    struct msghdr msg_send, msg_recv;

    // Create a socket
    sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sockfd == -1) {
        perror("Error creating socket");
    }

    // Fill in the source and destination addresses
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();  // Use the process ID as the source port

    // Bind the socket
    if (bind(sockfd, (struct sockaddr *)&src_addr, sizeof(src_addr)) == -1) {
        perror("Error binding socket");
    }


    struct nl_request req;
    // Prepare netlink message
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	req.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	req.nlh.nlmsg_type = RTM_GETTFILTER;
    req.tcm.tcm_parent = TC_H_UNSPEC;
	req.tcm.tcm_family = AF_UNSPEC;
    req.tcm.tcm_ifindex = TCM_IFINDEX_MAGIC_BLOCK;
	req.tcm.tcm_block_index = tca_block_id;

    // Prepare the iov and msg structures for sending
    int status;
    iov_send.iov_base = &req;
    iov_send.iov_len = req.nlh.nlmsg_len;

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;  // Send to kernel

    memset(&msg_send, 0, sizeof(msg_send));
    msg_send.msg_name = (void *)&dest_addr;
    msg_send.msg_namelen = sizeof(dest_addr);
    msg_send.msg_iov = &iov_send;
    msg_send.msg_iovlen = 1;

    // Send the Netlink message
    ret = sendmsg(sockfd, &msg_send, 0);
    //ret = nl_sendto(nl_ctx->socket, &req, req.nlh.nlmsg_len);
    if (ret == -1) {
        perror("Error sending Netlink message");
    }
    SRPLG_LOG_INF(PLUGIN_NAME, "NETLINK: request sent, get filter of tca block %d, return %d",tca_block_id,ret);

    // Receive the response
    memset(&msg_recv, 0, sizeof(msg_recv));
    iov_recv.iov_base = malloc(MAX_MSG);
    iov_recv.iov_len = MAX_MSG;
    msg_recv.msg_name = (void *)&src_addr;
    msg_recv.msg_namelen = sizeof(src_addr);
    msg_recv.msg_iov = &iov_recv;
    msg_recv.msg_iovlen = 1;

    
    status = recvmsg(sockfd, &msg_recv,0);
    if (status < 0) {
        perror("Error receiving Netlink message");
        //printf("rcv error %d\n", status);
    }

    // Process and print the response
    nlh_recv = (struct nlmsghdr *)iov_recv.iov_base;
    // Extract and process the response based on your application needs

    if (nlh_recv->nlmsg_type == RTM_NEWTFILTER) {
        // Block Exists
		ret = 1;
	}
    else if (nlh_recv->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh_recv);
        int error = err->error;
        //printf("error parsing shared block dump: %s\n", nl_geterror(error));      
        ret = -1; 
    }
    else {
        //printf("Response is not a tc filter %d\n", nlh_recv->nlmsg_type);
        ret = -1;
    }

    // Clean up
    free(iov_recv.iov_base);
    close(sockfd);

    return ret;
}


int tcnl_filter_flower_modify(unsigned int acl_id,onm_tc_acl_hash_element_t* acl_hash){
    int sockfd,ret;
    struct sockaddr_nl src_addr, dest_addr;

    struct nlmsghdr *nlh_recv;
    struct iovec iov_send, iov_recv;
    struct msghdr msg_send, msg_recv;
    __u32 protocol, prio, block_index;
    struct {
		struct nlmsghdr	nlh;
		struct tcmsg		tcm;
		char			buf[MAX_MSG];
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
		.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REQUEST,
		.nlh.nlmsg_type = RTM_NEWTFILTER,
		.tcm.tcm_family = AF_UNSPEC,
	};
    

    const onm_tc_acl_hash_element_t *iter = NULL, *tmp = NULL;
    onm_tc_ace_element_t* ace_iter = NULL;

    

    HASH_ITER(hh, acl_hash, iter, tmp)
    {   
        if (acl_name2id(iter->acl.name)==acl_id)
        {
            printf("ACL matched %s ID %d\n", iter->acl.name,acl_id);
            block_index = acl_id;

            LL_FOREACH(iter->acl.aces.ace, ace_iter)
            {
                printf("New ACE, ACE name %s: IPv4 %d IPv6 %d EHT %d\n",ace_iter->ace.name,sizeof(ace_iter->ace.matches.ipv4),sizeof(ace_iter->ace.matches.ipv6),sizeof(ace_iter->ace.matches.eth));
                
                if(ace_iter->ace.matches.eth.source_mac_address)
                {
                    SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |%s---- Source mac address = %s",ace_iter->ace.name, ace_iter->ace.matches.eth.source_mac_address);
                }
                if(ace_iter->ace.matches.eth.destination_mac_address)
                {
                    SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |%s---- Destination mac address = %s",ace_iter->ace.name, ace_iter->ace.matches.eth.destination_mac_address);
                }
                if(ace_iter->ace.matches.ipv4.source_ipv4_network)
                {
                    SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |%s---- Source IPv4 Network = %s",ace_iter->ace.name, ace_iter->ace.matches.ipv4.source_ipv4_network);
                }
                if(ace_iter->ace.matches.ipv4.destination_ipv4_network)
                {
                    SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |%s---- Destination IPv4 Network = %s",ace_iter->ace.name, ace_iter->ace.matches.ipv4.destination_ipv4_network);
                }
                
            }
        }
        /*
        SRPLG_LOG_INF(PLUGIN_NAME, "| \t+ ACL %s:", iter->acl.name);
        SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\tName = %s", iter->acl.name);
        if(iter->acl.type){
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\tType = %s", iter->acl.type);
        }
        
        SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\tACEs:");
        LL_FOREACH(iter->acl.aces.ace, ace_iter)
        {
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t+ ACE %s", ace_iter->ace.name);
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     ACE Name = %s", ace_iter->ace.name);
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     + Matches:");
            if(ace_iter->ace.matches.ipv4.source_ipv4_network){
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Source-Network = %s", ace_iter->ace.matches.ipv4.source_ipv4_network);
            }
            if(ace_iter->ace.matches.ipv4.destination_ipv4_network){
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Destination-Network = %s", ace_iter->ace.matches.ipv4.destination_ipv4_network);
            }
            if(ace_iter->ace.actions.logging||ace_iter->ace.actions.forwarding){
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     + Actions:");
                if(ace_iter->ace.actions.forwarding){
                    SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Action-Forwarding = %s", ace_iter->ace.actions.forwarding);
                }
                if(ace_iter->ace.actions.logging){
                    SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Action-Logging = %s", ace_iter->ace.actions.logging);
                }
            }
        }
        */
    }
}