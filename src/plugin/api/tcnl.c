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
#include "utils/memory.h"
#include <errno.h>
#include <linux/pkt_cls.h>
#include "plugin/types.h"

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
int addattr16(struct nlmsghdr *n, int maxlen, int type, __u16 data)
{
	return addattr_l(n, maxlen, type, &data, sizeof(__u16));
}

int addattr8(struct nlmsghdr *n, int maxlen, int type, __u8 data)
{
	return addattr_l(n, maxlen, type, &data, sizeof(__u8));
}

void print_netlink_message(struct nlmsghdr *nlmsg) {
    printf("Received Netlink Message:\n");
    printf("  Type: %u\n", nlmsg->nlmsg_type);
    printf("  Flags: %u\n", nlmsg->nlmsg_flags);
    printf("  Sequence Number: %u\n", nlmsg->nlmsg_seq);
    printf("  PID: %u\n", nlmsg->nlmsg_pid);
    printf("  Length: %d\n",nlmsg->nlmsg_len);


    // Add more attributes to print as needed...
    if (nlmsg->nlmsg_type != RTM_NEWTFILTER && //44
	    nlmsg->nlmsg_type != RTM_GETTFILTER &&
	    nlmsg->nlmsg_type != RTM_DELTFILTER &&
	    nlmsg->nlmsg_type != RTM_NEWCHAIN &&
	    nlmsg->nlmsg_type != RTM_GETCHAIN &&
	    nlmsg->nlmsg_type != RTM_DELCHAIN) {
		printf("Response is not a tc filter type %d\n", nlmsg->nlmsg_type);
	}
    else if (nlmsg->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlmsg);
				int error = err->error;
                printf("error %s\n", nl_geterror(error));
                
    }
    else {
        printf("Response is a tc filter %d\n", nlmsg->nlmsg_type);
    }


}

int get_u16(__u16 *val, const char *arg, int base)
{
	unsigned long res;
	char *ptr;

	if (!arg || !*arg)
		return -1;
	res = strtoul(arg, &ptr, base);

	/* empty string or trailing non-digits */
	if (!ptr || ptr == arg || *ptr)
		return -1;

	/* overflow */
	if (res == ULONG_MAX && errno == ERANGE)
		return -1;

	if (res > 0xFFFFUL)
		return -1;

	*val = res;
	return 0;
}

int get_be16(__be16 *val, const char *arg, int base)
{
	__u16 v;
	int ret = get_u16(&v, arg, base);

	if (!ret)
		*val = htons(v);

	return ret;
}

int get_u32(__u32 *val, const char *arg, int base)
{
	unsigned long res;
	char *ptr;

	if (!arg || !*arg)
		return -1;
	res = strtoul(arg, &ptr, base);

	/* empty string or trailing non-digits */
	if (!ptr || ptr == arg || *ptr)
		return -1;

	/* overflow */
	if (res == ULONG_MAX && errno == ERANGE)
		return -1;

	/* in case UL > 32 bits */
	if (res > 0xFFFFFFFFUL)
		return -1;

	*val = res;
	return 0;
}

int get_unsigned(unsigned int *val, const char *arg, int base)
{
	unsigned long res;
	char *ptr;

	if (!arg || !*arg)
		return -1;

	res = strtoul(arg, &ptr, base);

	/* empty string or trailing non-digits */
	if (!ptr || ptr == arg || *ptr)
		return -1;

	/* overflow */
	if (res == ULONG_MAX && errno == ERANGE)
		return -1;

	/* out side range of unsigned */
	if (res > UINT_MAX)
		return -1;

	*val = res;
	return 0;
}

int proto_a2n(unsigned short *id, const char *buf, const struct proto *proto_tb, size_t tb_len)
{
	int i;
	for (i = 0; i < tb_len; i++) {
		if (strcasecmp(proto_tb[i].name, buf) == 0) {
			*id = htons(proto_tb[i].id);
			return 0;
		}
	}
	if (get_be16(id, buf, 0))
		return -1;

	return 0;
}

int ll_proto_a2n(unsigned short *id, const char *buf)
{
	size_t len_tb = ARRAY_SIZE(llproto_names);
	return proto_a2n(id, buf, llproto_names, len_tb);
}

int ll_addr_a2n(char *lladdr, int len, const char *lladdr_str)
{
    int i;
    char *arg = strdup(lladdr_str);
    for (i = 0; i < len; i++) {
        int temp;
        char *cp = strchr(arg, ':');
        if (cp) {
            *cp = 0;
            cp++;
        }
        if (sscanf(arg, "%x", &temp) != 1) {
            fprintf(stderr, "\"%s\" is invalid lladdr.\n",
                arg);
            return -1;
        }
        if (temp < 0 || temp > 255) {
            fprintf(stderr, "\"%s\" is invalid lladdr.\n",
                arg);
            return -1;
        }
        lladdr[i] = temp;
        if (!cp)
            break;
        arg = cp;
    }
    return i + 1;
}

void ipv4_prefix_to_netmask(struct in_addr *netmask, int prefix_length) {
    // Check for valid prefix length, TODO error handling
    if (prefix_length > 32) {
        return;
        }
    netmask->s_addr = htonl(prefix_length ? (0xFFFFFFFF << (32 - prefix_length)) : 0);
}

void ipv6_prefix_to_netmask(struct in6_addr *netmask, uint8_t prefix_length) {
    // TODO error handling
    // Initialize netmask to zero
    memset(netmask, 0, sizeof(*netmask));

    for (int i = 0; i < 16; i++) {
        if (prefix_length >= 8) {
            netmask->s6_addr[i] = 0xFF;
            prefix_length -= 8;
        } 
        else
        {
            netmask->s6_addr[i] |= (0xFF >> (8 - prefix_length));
            break;
        }
    }
}

static int __flower_parse_ip_addr(char *str, int family,
				  int addr4_type, int mask4_type,
				  int addr6_type, int mask6_type,
				  struct nlmsghdr *nlh)
{
    int prefix_length;
    char ip_str[INET6_ADDRSTRLEN];

    if (sscanf(str, "%[^/]/%d", ip_str, &prefix_length) != 2) {
        SRPLG_LOG_ERR(PLUGIN_NAME, "Invalid ADDR/CIDR format: %s, failed to set network address",str);
        return EXIT_FAILURE;
    }

    // ipv4
    if (family == AF_INET)
    {
        struct in_addr addr,netmask;
        if (inet_pton(AF_INET, ip_str, &addr) <= 0) {
            SRPLG_LOG_ERR(PLUGIN_NAME, "Failed to parse IPv4 Network Address: %s",ip_str);
            return EXIT_FAILURE;
        }
        ipv4_prefix_to_netmask(&netmask,prefix_length);

        addattr_l(nlh, MAX_MSG, family == AF_INET ? addr4_type : addr6_type,
                &addr, sizeof(struct in_addr));
        addattr_l(nlh, MAX_MSG, family == AF_INET ? mask4_type : mask6_type,
                &netmask, sizeof(struct in_addr));
    }
    // ipv6
    else if (family == AF_INET6)
    {
        struct in6_addr addr6, netmask;
        
        if (inet_pton(AF_INET6, ip_str, &addr6) <= 0) {
            perror("inet_pton");
            SRPLG_LOG_ERR(PLUGIN_NAME, "Failed to parse IPv6 Network Address: %s",ip_str);
            return EXIT_FAILURE;
        }
        ipv6_prefix_to_netmask(&netmask,prefix_length);
        addattr_l(nlh, MAX_MSG, family == AF_INET ? addr4_type : addr6_type,
                    &addr6, sizeof(struct in6_addr));
        addattr_l(nlh, MAX_MSG, family == AF_INET ? mask4_type : mask6_type,
                    &netmask, sizeof(struct in6_addr));

    }
	return 0;
}


static int flower_parse_ip_addr(char *str, __be16 eth_type,
				int addr4_type, int mask4_type,
				int addr6_type, int mask6_type,
				struct nlmsghdr *n)
{
	int family;
	if (eth_type == htons(ETH_P_IP)) {
		family = AF_INET;
	} else if (eth_type == htons(ETH_P_IPV6)) {
		family = AF_INET6;
	} else if (!eth_type) {
		family = AF_UNSPEC;
	} else {
		return -1;
	}
	return __flower_parse_ip_addr(str, family, addr4_type, mask4_type,
				      addr6_type, mask6_type, n);
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
        printf("[FIX ME] Response is not a tc filter %d\n", nlh_recv->nlmsg_type);
        ret = -1;
    }

    // Clean up
    free(iov_recv.iov_base);
    close(sockfd);

    return ret;
}

// TODO delete this, its for debugging only
void print_lladdr(const char *lladdr, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02X", (unsigned char)lladdr[i]);  // Print each byte in hexadecimal format
        if (i < len - 1) {
            printf(":");  // Print colon between bytes (except for the last byte)
        }
    }
    printf("\n");
}

/// @brief this function adds nlattr to nlh in the request message, it will parse each parameter in the ace and add its corresponding TCA_OPTION
static int nl_put_flower_options(struct nlmsghdr *nlh,onm_tc_ace_element_t* ace)
{
    struct rtattr *tail;
    struct tcmsg *tcm = NLMSG_DATA(nlh);
    int ret;

    tail = (struct rtattr *) (((void *) nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
    addattr_l(nlh, MAX_MSG, TCA_OPTIONS, NULL, 0);

    //addattr32(nlh, MAX_MSG, TCA_FLOWER_FLAGS, TCA_CLS_FLAGS_SKIP_HW);

    __be16 eth_type = TC_H_MIN(tcm->tcm_info);
    if (eth_type == htons(ETH_P_8021Q))
    {

    }
    else if (eth_type != htons(ETH_P_ALL)) 
    {
        ret = addattr16(nlh, MAX_MSG, TCA_FLOWER_KEY_ETH_TYPE, eth_type);
        if (ret)
            SRPLG_LOG_ERR(PLUGIN_NAME, "ACE Name %s failed to set EtherType",ace->ace.name);
    }

    if(ace->ace.matches.eth.source_mac_address)
    {
        SRPLG_LOG_INF(PLUGIN_NAME, "ACE Name %s Match Source mac address = %s",ace->ace.name, ace->ace.matches.eth.source_mac_address);
        char addr[ETH_ALEN];
        ret = ll_addr_a2n(addr, sizeof(addr), ace->ace.matches.eth.source_mac_address);
        if (ret < 0)
           SRPLG_LOG_ERR(PLUGIN_NAME, "ACE Name %s Invalid MAC address format = %s",ace->ace.name, ace->ace.matches.eth.source_mac_address); 
        else{
            addattr_l(nlh,MAX_MSG,TCA_FLOWER_KEY_ETH_SRC,addr,sizeof(addr));
            if (ace->ace.matches.eth.source_mac_address_mask)
            {
                ret = ll_addr_a2n(addr,sizeof(addr),ace->ace.matches.eth.source_mac_address_mask);
                if( ret < 0){
                    SRPLG_LOG_ERR(PLUGIN_NAME, "ACE Name %s Invalid MAC Address Mask format = %s",ace->ace.name, ace->ace.matches.eth.source_mac_address_mask);
                }
                else
                    addattr_l(nlh,MAX_MSG,TCA_FLOWER_KEY_ETH_SRC_MASK,addr,sizeof(addr));
            }
        }
    }
    if(ace->ace.matches.eth.destination_mac_address)
    {
        SRPLG_LOG_INF(PLUGIN_NAME, "ACE Name %s Match Destination mac address = %s",ace->ace.name, ace->ace.matches.eth.destination_mac_address);
        char addr[ETH_ALEN];
        ret = ll_addr_a2n(addr, sizeof(addr), ace->ace.matches.eth.destination_mac_address);
        if (ret < 0)
           SRPLG_LOG_ERR(PLUGIN_NAME, "ACE Name %s Invalid MAC address format = %s",ace->ace.name, ace->ace.matches.eth.destination_mac_address); 
        else{
            addattr_l(nlh,MAX_MSG,TCA_FLOWER_KEY_ETH_DST,addr,sizeof(addr));
            if (ace->ace.matches.eth.destination_mac_address_mask)
            {
                ret = ll_addr_a2n(addr,sizeof(addr),ace->ace.matches.eth.destination_mac_address_mask);
                if( ret < 0){
                    SRPLG_LOG_ERR(PLUGIN_NAME, "ACE Name %s Invalid MAC Address Mask format = %s",ace->ace.name, ace->ace.matches.eth.destination_mac_address_mask);
                }
                else
                    addattr_l(nlh,MAX_MSG,TCA_FLOWER_KEY_ETH_DST_MASK,addr,sizeof(addr));
            }
        }
    }

    if(ace->ace.matches.ipv4.source_ipv4_network)
    {
        SRPLG_LOG_INF(PLUGIN_NAME, "ACE Name %s Match Source IPv4 Network = %s",ace->ace.name, ace->ace.matches.ipv4.source_ipv4_network);
        flower_parse_ip_addr(ace->ace.matches.ipv4.source_ipv4_network, eth_type,
						   TCA_FLOWER_KEY_IPV4_SRC,
						   TCA_FLOWER_KEY_IPV4_SRC_MASK,
						   TCA_FLOWER_KEY_IPV6_SRC,
						   TCA_FLOWER_KEY_IPV6_SRC_MASK,
						   nlh);
    }
    if(ace->ace.matches.ipv4.destination_ipv4_network)
    {
        SRPLG_LOG_INF(PLUGIN_NAME, "ACE Name %s Match Destination IPv4 Network = %s",ace->ace.name, ace->ace.matches.ipv4.destination_ipv4_network);
        //flower_parse_ipv4_addr(ace->ace.matches.ipv4.destination_ipv4_network,nlh);
        flower_parse_ip_addr(ace->ace.matches.ipv4.destination_ipv4_network, eth_type,
						   TCA_FLOWER_KEY_IPV4_DST,
						   TCA_FLOWER_KEY_IPV4_DST_MASK,
						   TCA_FLOWER_KEY_IPV6_DST,
						   TCA_FLOWER_KEY_IPV6_DST_MASK,
						   nlh);
    }
    if(ace->ace.matches.ipv6.source_ipv6_network)
    {
        SRPLG_LOG_INF(PLUGIN_NAME, "ACE Name %s Match Source IPv6 Network = %s",ace->ace.name, ace->ace.matches.ipv6.source_ipv6_network);
        flower_parse_ip_addr(ace->ace.matches.ipv6.source_ipv6_network, eth_type,
						   TCA_FLOWER_KEY_IPV4_SRC,
						   TCA_FLOWER_KEY_IPV4_SRC_MASK,
						   TCA_FLOWER_KEY_IPV6_SRC,
						   TCA_FLOWER_KEY_IPV6_SRC_MASK,
						   nlh);
    }
    if(ace->ace.matches.ipv6.destination_ipv6_network)
    {
        SRPLG_LOG_INF(PLUGIN_NAME, "ACE Name %s Match Destination IPv6 Network = %s",ace->ace.name, ace->ace.matches.ipv6.destination_ipv6_network);
        flower_parse_ip_addr(ace->ace.matches.ipv6.destination_ipv6_network, eth_type,
						   TCA_FLOWER_KEY_IPV4_DST,
						   TCA_FLOWER_KEY_IPV4_DST_MASK,
						   TCA_FLOWER_KEY_IPV6_DST,
						   TCA_FLOWER_KEY_IPV6_DST_MASK,
						   nlh);
    }
    if (ace->ace.matches.tcp.source_port.port != 0)
    {
        __u8 ip_proto = IPPROTO_TCP;
        __be16 port = htons(ace->ace.matches.tcp.source_port.port);

        addattr8(nlh, MAX_MSG, TCA_FLOWER_KEY_IP_PROTO, ip_proto);
        addattr16(nlh, MAX_MSG, TCA_FLOWER_KEY_TCP_SRC, port);
    }
    if (ace->ace.matches.tcp.destination_port.port != 0)
    {
        __u8 ip_proto = IPPROTO_TCP;
        __be16 port = htons(ace->ace.matches.tcp.destination_port.port);
        
        addattr8(nlh, MAX_MSG, TCA_FLOWER_KEY_IP_PROTO, ip_proto);
        addattr16(nlh, MAX_MSG, TCA_FLOWER_KEY_TCP_DST, port);
    }
    if (ace->ace.matches.udp.source_port.port != 0)
    {
        __u8 ip_proto = IPPROTO_UDP;
        __be16 port = htons(ace->ace.matches.udp.source_port.port);
        
        addattr8(nlh, MAX_MSG, TCA_FLOWER_KEY_IP_PROTO, ip_proto);
        addattr16(nlh, MAX_MSG, TCA_FLOWER_KEY_UDP_SRC, port);
    }
    if (ace->ace.matches.udp.destination_port.port != 0)
    {
        __u8 ip_proto = IPPROTO_UDP;
        __be16 port = htons(ace->ace.matches.udp.destination_port.port);
        
        addattr8(nlh, MAX_MSG, TCA_FLOWER_KEY_IP_PROTO, ip_proto);
        addattr16(nlh, MAX_MSG, TCA_FLOWER_KEY_UDP_DST, port);
    }

    tail->rta_len = (((void *)nlh)+nlh->nlmsg_len) - (void *)tail;
}

int tcnl_filter_flower_modify(unsigned int acl_id,onm_tc_acl_hash_element_t* acl_hash){
    int sockfd,ret;
    struct sockaddr_nl src_addr, dest_addr;

    struct nlmsghdr *nlh_recv;
    struct iovec iov_send, iov_recv;
    struct msghdr msg_send, msg_recv;
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
            __u32 prio, block_index,tcm_handle;
            __u16 proto_id;
            block_index = acl_id;
            prio = 0;
            tcm_handle = 1;

            // set priority and get the appropriate ip protocol version
            LL_FOREACH(iter->acl.aces.ace, ace_iter)
            {
                prio += 10;
                char *proto_buf = NULL;
                if(ace_iter->ace.matches.ipv6._is_set == 1)
                    proto_buf = "ipv6";
                else if (ace_iter->ace.matches.ipv4._is_set == 1)
                    proto_buf = "ipv4";
                else if (ace_iter->ace.matches.icmp._is_set == 1)
                {
                    //ipv4 or ipv6 ? TODO look at acl type
                    proto_buf = "ipv4";
                }
                else if (ace_iter->ace.matches.tcp._is_set == 1)
                {
                    //ipv4 or ipv6 ? TODO look at acl type
                    proto_buf = "ipv4";
                }
                else if (ace_iter->ace.matches.udp._is_set == 1)
                {
                    //ipv4 or ipv6 ? TODO look at acl type
                    proto_buf = "ipv4";
                }
                
                SRPLG_LOG_DBG(PLUGIN_NAME, "ACE Name %s Protocol Buffer = %s",ace_iter->ace.name,proto_buf);
                req.tcm.tcm_ifindex = TCM_IFINDEX_MAGIC_BLOCK;
	            req.tcm.tcm_block_index = block_index;
                req.tcm.tcm_handle = tcm_handle;
                // set ip protocol version
                if (proto_buf)
                {
                    if (ll_proto_a2n(&proto_id, proto_buf))
                    {
                        SRPLG_LOG_ERR(PLUGIN_NAME, "ACE Name %s failed to set specified EtherType, setting it to ALL",ace_iter->ace.name);
                        req.tcm.tcm_info = TC_H_MAKE(prio<<16, htons(ETH_P_ALL));
                    }
                    else {
                        SRPLG_LOG_DBG(PLUGIN_NAME, "ACE Name %s protocol is not specified, set EtherType to %d",ace_iter->ace.name,htons(proto_id));
                        req.tcm.tcm_info = TC_H_MAKE(prio<<16, proto_id);
                    }
                }
                else
                {
                    // ethertype is not specified in ACE config
                    // check if ethertype is specified in ethernet match.
                    if (ace_iter->ace.matches.eth.ethertype != 0)
                    {
                        SRPLG_LOG_DBG(PLUGIN_NAME, "ACE Name %s L2 match ethertype %d",ace_iter->ace.name,ace_iter->ace.matches.eth.ethertype);
                        req.tcm.tcm_info = TC_H_MAKE(prio<<16, ace_iter->ace.matches.eth.ethertype);
                    }
                    else
                    {
                        SRPLG_LOG_DBG(PLUGIN_NAME, "ACE Name %s protocol is not specified, set EtherType to ALL",ace_iter->ace.name);
                        req.tcm.tcm_info = TC_H_MAKE(prio<<16, htons(ETH_P_ALL));
                    } 
                }

                addattr_l(&req.nlh,sizeof(req),TCA_KIND,"flower",strlen("flower")+1);
                
                nl_put_flower_options(&req.nlh,ace_iter);

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
                if (ret == -1) {
                    perror("Error sending Netlink message");
                }
                //printf("return of send %d\n",ret);


                // Receive the response
                memset(&msg_recv, 0, sizeof(msg_recv));
                iov_recv.iov_base = malloc(MAX_MSG);
                iov_recv.iov_len = MAX_MSG;
                msg_recv.msg_name = (void *)&src_addr;
                msg_recv.msg_namelen = sizeof(src_addr);
                msg_recv.msg_iov = &iov_recv;
                msg_recv.msg_iovlen = 1;

                
                status = recvmsg(sockfd, &msg_recv, MSG_DONTWAIT);
                if (status < 0) {
                    perror("Error receiving Netlink message");
                    //printf("rcv error %d\n", status);
                }

                // Process and print the response
                nlh_recv = (struct nlmsghdr *)iov_recv.iov_base;
                // Extract and process the response based on your application needs
                //print_netlink_message(nlh_recv);

                // Clean up
                free(iov_recv.iov_base);
                close(sockfd);
                
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