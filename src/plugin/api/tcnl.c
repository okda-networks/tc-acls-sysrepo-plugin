/*
Many of the code is stolen from iproute2
https://github.com/iproute2/iproute2/blob/main/tc/tc_util.c

*/

#include "tcnl.h"

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

int ipv4_prefix_to_netmask(struct in_addr *netmask, int prefix_length) {
    if (netmask == NULL) {
        return -1;
    }
    if (prefix_length > 32) {
            SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL] bad ipv4 prefix length %d",prefix_length);
            return -2;
        }
    netmask->s_addr = htonl(prefix_length ? (0xFFFFFFFF << (32 - prefix_length)) : 0);
    return 0;
}

int ipv6_prefix_to_netmask(struct in6_addr *netmask, uint8_t prefix_length) {
    if (netmask == NULL) {
        return -1;
    }
    if (prefix_length > 128) {
        return -2;
    }
    // Initialize netmask to zero
    memset(netmask, 0, sizeof(*netmask));

    for (int i = 0; i < 16; i++) {
        if (prefix_length >= 8) {
            netmask->s6_addr[i] = 0xFF;
            prefix_length -= 8;
        } 
        else {
            netmask->s6_addr[i] |= (0xFF >> (8 - prefix_length));
            break;
        }
    }
    return 0;
}

static int __tcnl_flower_put_ip_addr(char *str, int family,int addr4_type, int mask4_type, int addr6_type, int mask6_type,struct nl_msg *msg)
{
    int prefix_length;
    int error = 0;
    char ip_str[INET6_ADDRSTRLEN];

    if (sscanf(str, "%[^/]/%d", ip_str, &prefix_length) != 2) {
        SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL] Invalid ADDR/CIDR format: %s, failed to set network address",str);
        return -1;
    }

    // ipv4
    if (family == AF_INET)
    {
        struct in_addr addr,netmask;
        if (inet_pton(AF_INET, ip_str, &addr) <= 0) {
            SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL] Failed to parse IPv4 Network Address: %s",ip_str);
            return -1;
        }
        error = ipv4_prefix_to_netmask(&netmask,prefix_length);
        if (error){
            SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL] Failed to parse IPv4 Network Prefix Length: %d",prefix_length);
            return error;
        }

        error = nla_put(msg,family == AF_INET ? addr4_type : addr6_type,sizeof(struct in_addr),&addr);
        if (error){
            SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL] Failed to set IPv4 Network Address Attributes");
            return error;
        }
        error = nla_put(msg,family == AF_INET ? mask4_type : mask6_type,sizeof(struct in_addr),&netmask);
        if (error){
            SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL] Failed to set IPv4 Network Address Mask Attributes");
            return error;
        }
    }
    // ipv6
    else if (family == AF_INET6)
    {
        struct in6_addr addr6, netmask;
        
        if (inet_pton(AF_INET6, ip_str, &addr6) <= 0) {
            SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL] Failed to parse IPv6 Network Address: %s",ip_str);
            return -1;
        }
        error = ipv6_prefix_to_netmask(&netmask,prefix_length);
        if (error){
            SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL] Failed to parse IPv6 Network Prefix Length: %d",prefix_length);
            return error;
        }
        error = nla_put(msg,family == AF_INET ? addr4_type : addr6_type,sizeof(struct in6_addr),&addr6);
        if (error){
            SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL] Failed to set IPv6 Network Address Attributes");
            return error;
        }        
        error = nla_put(msg,family == AF_INET ? mask4_type : mask6_type, sizeof(struct in6_addr),&netmask);
        if (error){
            SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL] Failed to set IPv6 Network Address Mask Attributes");
            return error;
        }

    }
	return 0;
}
static int tcnl_flower_parse_ip_addr(char *str, __be16 eth_type,int addr4_type, int mask4_type,int addr6_type, int mask6_type,struct nl_msg *msg)
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
	return __tcnl_flower_put_ip_addr(str, family, addr4_type, mask4_type,
				      addr6_type, mask6_type, msg);
}
//TODO this function is NOT correct
__be16 generate_neq_mask(__be16 port_be) {
    uint16_t port = ntohs(port_be);
    uint16_t mask = ~port;
    return htons(mask); 
}
static int tcnl_flower_put_port_range(struct nl_msg *msg, __u8 ip_proto, __be16 lower_port, __be16 upper_port, int port_min_key, int port_max_key) {
    int ret = 0;
    ret = nla_put_s8(msg,TCA_FLOWER_KEY_IP_PROTO,ip_proto);
    if (ret < 0){
        SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS] port 'range', failed to set port range ip protocol");
        return ret;
    }
    ret = nla_put_s16(msg,port_min_key,lower_port);
    if (ret < 0){
        SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS] port 'range', failed to set range lower port number");
        return ret;
    }
    ret = nla_put_s16(msg,port_max_key,upper_port);
    if (ret < 0){
        SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS] port 'range', failed to set range upper port number");
        return ret;
    }

    return ret;
}
static int tcnl_flower_put_port_and_operator(struct nl_msg *msg, __u8 ip_proto, __be16 port, int port_key, int port_mask_key, int range_min_key, int range_max_key, int operation) {
    int ret = 0;
    ret = nla_put_s8(msg,TCA_FLOWER_KEY_IP_PROTO,ip_proto);
    if (ret < 0){
        SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS] failed to set port ip protocol");
        return ret;
    }
    __be16 port_lower, port_upper,port_middle;
    __u16 port_mask = 0;
    switch (operation) {
        case PORT_GTE:
            port_lower = port;
            port_upper = htons(MAX_PORT_NUMBER);
            if (port_upper == port_lower)
            {
                ret = nla_put_s16(msg,port_key,port);
                if (ret < 0){
                    SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS] port 'gte', failed to set port number");
                    return ret;
                }
                break;
            }
            else if (port_lower < MIN_PORT_NUMBER){
                ret = tcnl_flower_put_port_range(msg,ip_proto,htons(MIN_PORT_NUMBER),htons(MAX_PORT_NUMBER),range_min_key, range_max_key);
                if (ret < 0){
                    return ret;
                }
                break;
            }
            else if (port_lower > MAX_PORT_NUMBER)
            {
                SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS] port 'gte', port number is higher than max allowed port");
                return -1;
                break;
            }
            else {
                ret = tcnl_flower_put_port_range(msg,ip_proto,port_lower,port_upper,range_min_key, range_max_key);
                if (ret < 0){
                    return ret;
                }
                break;
            }
            
        case PORT_LTE:
            port_lower = htons(MIN_PORT_NUMBER);
            port_upper = port;
            
            if (port_upper == port_lower)
            {
                ret = nla_put_s16(msg,port_key,port);
                if (ret < 0){
                    SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS] port 'lte', failed to set port number");
                    return ret;
                }
                break;
            }
            else if (port_upper < MIN_PORT_NUMBER){
                SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS] port 'lte', port number is less than minimum allowed port");
                return -1;
                break;   
            }
            else if (port_upper > MAX_PORT_NUMBER)
            {
                ret = tcnl_flower_put_port_range(msg,ip_proto,htons(MIN_PORT_NUMBER),htons(MAX_PORT_NUMBER),range_min_key, range_max_key);
                if (ret < 0){
                    return ret;
                }
                break;
            }
            else
            {
                ret = tcnl_flower_put_port_range(msg,ip_proto,port_lower,port_upper,range_min_key, range_max_key);
                if (ret < 0){
                    return ret;
                }
                break;
            }
            
        case PORT_NOT_EQUAL:
            port_lower = htons(MIN_PORT_NUMBER);
            port_middle = port;
            port_upper = htons(MAX_PORT_NUMBER);
            if (ntohs(port_middle) < MIN_PORT_NUMBER || ntohs(port_middle) > MAX_PORT_NUMBER){
                ret = tcnl_flower_put_port_range(msg,ip_proto,port_lower,port_upper,range_min_key, range_max_key);
                if (ret < 0){
                    return ret;
                }
                break;
            } else if (ntohs(port_middle) == ntohs(port_lower))
            {
                ret = tcnl_flower_put_port_range(msg,ip_proto,ntohs(ntohs(port_middle)+1),port_upper,range_min_key, range_max_key);
                if (ret < 0){
                    return ret;
                }
                break;
            } else if (ntohs(port_middle) == ntohs(port_upper))
            {
                ret = tcnl_flower_put_port_range(msg,ip_proto,port_lower,htons(ntohs(port_middle)-1),range_min_key, range_max_key);
                if (ret < 0){
                    return ret;
                }
                break;
            }
            __be16 mask = generate_neq_mask(port);
            ret = nla_put_s16(msg,port_key,port);
            if (ret < 0){
                SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS] port 'neq', failed to set port number");
                return ret;
            }
            ret = nla_put_s16(msg,port_mask_key, mask);
            if (ret < 0){
                SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS] port 'neq', failed to set port mask");
                return ret;
            }
            break;

        case PORT_EQUAL:
            ret = nla_put_s16(msg,port_key, port);
            if (ret < 0){
                SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS] port 'eq', failed to set port number");
                return ret;
            }
            break;
        default:
            // Handle unknown operation...
            break;
    }

    return 0;
}
static int tcnl_flower_parse_tcp_ports(struct nl_msg *msg, onm_tc_ace_element_t *ace) {
    int ret = 0;

    // Handle TCP source port
    if (ace->ace.matches.tcp.source_port.port_operator != PORT_NOOP) {
        __be16 port = htons(ace->ace.matches.tcp.source_port.port);
        SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS] ACE Name %s Match TCP Source Single Port (port %d, lower_port %d, upper_port %d, operator %d)", 
                    ace->ace.name,
                    ace->ace.matches.tcp.source_port.port,
                    ace->ace.matches.tcp.source_port.lower_port, 
                    ace->ace.matches.tcp.source_port.upper_port,
                    ace->ace.matches.tcp.source_port.port_operator);

        ret = tcnl_flower_put_port_and_operator (
            msg, IPPROTO_TCP, port, 
            TCA_FLOWER_KEY_TCP_SRC,
            TCA_FLOWER_KEY_TCP_SRC_MASK,
            TCA_FLOWER_KEY_PORT_SRC_MIN,
            TCA_FLOWER_KEY_PORT_SRC_MAX, 
            ace->ace.matches.tcp.source_port.port_operator);
        if (ret) return ret;
    }
    else if (ace->ace.matches.tcp.source_port.lower_port != 0 && ace->ace.matches.tcp.source_port.upper_port !=0){
        SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS] ACE Name %s Match TCP Source Port Range (port %d, lower_port %d, upper_port %d, operator %d)", 
                    ace->ace.name,
                    ace->ace.matches.tcp.source_port.port,
                    ace->ace.matches.tcp.source_port.lower_port, 
                    ace->ace.matches.tcp.source_port.upper_port,
                    ace->ace.matches.tcp.source_port.port_operator);
        __be16 lower_port = htons(ace->ace.matches.tcp.source_port.lower_port);
        __be16 upper_port = htons(ace->ace.matches.tcp.source_port.upper_port);
        ret = tcnl_flower_put_port_range(msg, IPPROTO_TCP, lower_port, upper_port, TCA_FLOWER_KEY_PORT_SRC_MIN, TCA_FLOWER_KEY_PORT_SRC_MAX);
        if (ret) return ret;
    }

    // Handle TCP destination port
    if (ace->ace.matches.tcp.destination_port.port_operator != PORT_NOOP) {
        SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS] ACE Name %s Match TCP Destination Single Port (port %d, lower_port %d, upper_port %d, operator %d)", 
            ace->ace.name,
            ace->ace.matches.tcp.destination_port.port,
            ace->ace.matches.tcp.destination_port.lower_port, 
            ace->ace.matches.tcp.destination_port.upper_port,
            ace->ace.matches.tcp.destination_port.port_operator);
        __be16 port = htons(ace->ace.matches.tcp.destination_port.port);

        ret = tcnl_flower_put_port_and_operator(msg, IPPROTO_TCP, port, TCA_FLOWER_KEY_TCP_DST, TCA_FLOWER_KEY_TCP_DST_MASK,TCA_FLOWER_KEY_PORT_DST_MIN,TCA_FLOWER_KEY_PORT_DST_MAX, ace->ace.matches.tcp.destination_port.port_operator);
        if (ret) return ret;
    } 
    else if (ace->ace.matches.tcp.destination_port.lower_port != 0 && ace->ace.matches.tcp.destination_port.upper_port != 0){
        SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS] ACE Name %s Match TCP Destination Port Range (port %d, lower_port %d, upper_port %d, operator %d)", 
            ace->ace.name,
            ace->ace.matches.tcp.destination_port.port,
            ace->ace.matches.tcp.destination_port.lower_port, 
            ace->ace.matches.tcp.destination_port.upper_port,
            ace->ace.matches.tcp.destination_port.port_operator);
        __be16 lower_port = htons(ace->ace.matches.tcp.destination_port.lower_port);
        __be16 upper_port = htons(ace->ace.matches.tcp.destination_port.upper_port);
        ret = tcnl_flower_put_port_range(msg, IPPROTO_TCP, lower_port, upper_port, TCA_FLOWER_KEY_PORT_DST_MIN, TCA_FLOWER_KEY_PORT_DST_MAX);
        if (ret) return ret;
    }

    return ret;
}
static int tcnl_flower_parse_udp_ports(struct nl_msg *msg, onm_tc_ace_element_t *ace) {
    int ret = 0;
    // Handle UDP source port
    if (ace->ace.matches.udp.source_port.port_operator != PORT_NOOP) {
        SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS] ACE Name %s Match UDP Source Port/Range (port %d, lower_port %d, upper_port %d, operator %d)", 
        ace->ace.name,
        ace->ace.matches.udp.source_port.port,
        ace->ace.matches.udp.source_port.lower_port, 
        ace->ace.matches.udp.source_port.upper_port,
        ace->ace.matches.udp.source_port.port_operator);
        __be16 port = htons(ace->ace.matches.udp.source_port.port);

        ret = tcnl_flower_put_port_and_operator(msg, IPPROTO_UDP, port, TCA_FLOWER_KEY_UDP_SRC, TCA_FLOWER_KEY_UDP_SRC_MASK,TCA_FLOWER_KEY_PORT_SRC_MIN,TCA_FLOWER_KEY_PORT_SRC_MAX, ace->ace.matches.udp.source_port.port_operator);
        if (ret) return ret;
    }
    else if (ace->ace.matches.udp.source_port.lower_port != 0 && ace->ace.matches.udp.source_port.upper_port !=0){
        SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS] ACE Name %s Match UDP Source Port/Range (port %d, lower_port %d, upper_port %d, operator %d)", 
        ace->ace.name,
        ace->ace.matches.udp.source_port.port,
        ace->ace.matches.udp.source_port.lower_port, 
        ace->ace.matches.udp.source_port.upper_port,
        ace->ace.matches.udp.source_port.port_operator);
        __be16 lower_port = htons(ace->ace.matches.udp.source_port.lower_port);
        __be16 upper_port = htons(ace->ace.matches.udp.source_port.upper_port);
        ret = tcnl_flower_put_port_range(msg, IPPROTO_UDP, lower_port, upper_port, TCA_FLOWER_KEY_PORT_SRC_MIN, TCA_FLOWER_KEY_PORT_SRC_MAX);
        if (ret) return ret;
    }

    // Handle UDP destination port
    if (ace->ace.matches.udp.destination_port.port_operator != PORT_NOOP) {
        SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS] ACE Name %s Match UDP Destination Port/Range (port %d, lower_port %d, upper_port %d, operator %d)", 
            ace->ace.name,
            ace->ace.matches.udp.destination_port.port,
            ace->ace.matches.udp.destination_port.lower_port, 
            ace->ace.matches.udp.destination_port.upper_port,
            ace->ace.matches.udp.destination_port.port_operator);
        __be16 port = htons(ace->ace.matches.udp.destination_port.port);

        ret = tcnl_flower_put_port_and_operator(msg, IPPROTO_UDP, port, TCA_FLOWER_KEY_UDP_DST, TCA_FLOWER_KEY_UDP_DST_MASK,TCA_FLOWER_KEY_PORT_DST_MIN,TCA_FLOWER_KEY_PORT_DST_MAX, ace->ace.matches.udp.destination_port.port_operator);
        if (ret) return ret;
    } else if (ace->ace.matches.udp.destination_port.lower_port != 0 && ace->ace.matches.udp.destination_port.upper_port != 0){
        SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS] ACE Name %s Match UDP Destination Port/Range (port %d, lower_port %d, upper_port %d, operator %d)", 
            ace->ace.name,
            ace->ace.matches.udp.destination_port.port,
            ace->ace.matches.udp.destination_port.lower_port, 
            ace->ace.matches.udp.destination_port.upper_port,
            ace->ace.matches.udp.destination_port.port_operator);
        __be16 lower_port = htons(ace->ace.matches.udp.destination_port.lower_port);
        __be16 upper_port = htons(ace->ace.matches.udp.destination_port.upper_port);
        ret = tcnl_flower_put_port_range(msg, IPPROTO_UDP, lower_port, upper_port, TCA_FLOWER_KEY_PORT_DST_MIN, TCA_FLOWER_KEY_PORT_DST_MAX);
        if (ret) return ret;
    }

    return ret;
}
int tcnl_flower_put_action(struct nl_msg *msg, onm_tc_ace_element_t* ace){
    const char *action_kind = "gact";
    struct tc_gact gact_params = { 0 };
    int ret = 0;
    if (!ace) {
        SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS] action, ace is NULL\n");
        return -1;
    }

    if (ace->ace.actions.forwarding == FORWARD_DROP)
    {
        gact_params.action = TC_ACT_SHOT;
    } else if (ace->ace.actions.forwarding == FORWARD_REJECT)
    {
        gact_params.action = TC_ACT_SHOT;
    } else if (ace->ace.actions.forwarding == FORWARD_ACCEPT)
    {
        gact_params.action = TC_ACT_OK;
    } else //FORWARD_NOOP
    {
        gact_params.action = TC_ACT_UNSPEC;
    }

    // Start a nested attribute for TCA_FLOWER_ACT
    struct nlattr *act_nest = nla_nest_start(msg, TCA_FLOWER_ACT);
    //struct rtattr *flower_act_nest = addattr_nest(nlh, MAX_MSG, TCA_FLOWER_ACT);

    // Start a nested attribute for each action
    struct nlattr *act_kind_nest = nla_nest_start(msg, TCA_ACT_KIND);
    //struct rtattr *act_nest = addattr_nest(nlh, MAX_MSG, TCA_ACT_KIND);

    // Set the action priority (index)
    int action_priority = 1; 
    //addattr32(nlh, MAX_MSG, TCA_ACT_INDEX, action_priority);
    ret = nla_put_s32(msg,TCA_ACT_INDEX,action_priority);
    if (ret < 0) {
        SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS] action, failed to set action priority\n");
        return ret;
    }
    // Add the TCA_ACT_KIND attribute
    //addattr_l(nlh, MAX_MSG, TCA_ACT_KIND, action_kind, strlen(action_kind) + 1);
    ret = nla_put(msg,TCA_ACT_KIND,strlen(action_kind) + 1,action_kind);
    if (ret < 0) {
        SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS] action, failed to set action kind\n");
        return ret;
    }

    // Start a nested attribute for TCA_ACT_OPTIONS
    struct nlattr *act_options_nest = nla_nest_start(msg, TCA_ACT_OPTIONS);
    //struct rtattr *options_nest = addattr_nest(nlh, MAX_MSG, TCA_ACT_OPTIONS);

    // Add the TCA_GACT_PARMS attribute with gact parameters
    //addattr_l(nlh, MAX_MSG, TCA_GACT_PARMS, &gact_params, sizeof(gact_params));
    ret = nla_put(msg,TCA_GACT_PARMS,sizeof(gact_params),&gact_params);
    if (ret < 0) {
        SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS] action, failed to set action kind\n");
        return ret;
    }
    nla_nest_end(msg, act_options_nest);
    // Close the TCA_ACT_OPTIONS nested attribute
    //addattr_nest_end(nlh, options_nest);

    // Close the nested attribute for the action
    //addattr_nest_end(nlh, act_nest);
    nla_nest_end(msg, act_kind_nest);

    // Close the TCA_FLOWER_ACT nested attribute
    nla_nest_end(msg, act_nest);
    //addattr_nest_end(nlh, flower_act_nest);
}

// Callback function for handling incoming messages
static int nl_msg_recv_cb(struct nl_msg *msg, void *arg) {
    struct nlmsghdr *nlh = nlmsg_hdr(msg);

    // Print the message type
    printf("Received message type: %d\n", nlh->nlmsg_type);

    return NL_OK;
}
bool filter_exists = false;
static int rcv_is_filter_cb(struct nl_msg *msg, void *arg) {
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    //SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][CHECK BLOCK] Received message type: %d",nlh->nlmsg_type);
    if (nlh->nlmsg_type==RTM_NEWTFILTER){
        filter_exists = true;
    }
    return NL_OK;
}

int tcnl_put_flower_options(struct nl_msg** msg, onm_tc_ace_element_t* ace){
    if (!ace){
        SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS] ace is NULL");
        return -1;
    }
    int ret = 0;
    SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS] ACE Name %s",ace->ace.name);
    struct nlmsghdr *nlhdr = nlmsg_hdr(*msg);
    
    if (!nlhdr) {
        SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS][%s] Failed to get netlink message header",ace->ace.name);
        return -1;
    }

    struct tcmsg *tcm = (struct tcmsg *)nlmsg_data(nlhdr);
    if (!tcm) {
        SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS][%s] Failed to get netlink tc message",ace->ace.name);
        return -1;
    }

    __be16 eth_type = TC_H_MIN(tcm->tcm_info);

    struct nlattr *opts = nla_nest_start(*msg, TCA_OPTIONS);
    // Start TCA_OPTIONS nested attribute
    if (!opts) {
        // Handle error
        nlmsg_free(*msg);
        return -1;
    }

    

    if (eth_type == htons(ETH_P_8021Q)){

    }
    else if (eth_type != htons(ETH_P_ALL)) {
        ret = nla_put_s16(*msg,TCA_FLOWER_KEY_ETH_TYPE,eth_type);
        if (ret < 0){
            SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS][%s] Failed to set EtherType",ace->ace.name);
            return ret;
        }
    }
    else {
        // TODO review this
        SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS][%s] EtherType is set to 'ALL'",ace->ace.name);
    }

    if(ace->ace.matches.eth.source_address){
        SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS][%s] Match source mac address '%s'",ace->ace.name, ace->ace.matches.eth.source_address);
        char addr[ETH_ALEN];
        ret = ll_addr_a2n(addr, sizeof(addr), ace->ace.matches.eth.source_address);
        if (ret < 0){
           SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS][%s] Invalid MAC address format '%s'",ace->ace.name, ace->ace.matches.eth.source_address);
           return ret;
        } 
        else{
            ret = nla_put(*msg,TCA_FLOWER_KEY_ETH_SRC,sizeof(addr),addr);
            if(ret < 0){
                SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS][%s] Failed to source eth mac address attributes '%s'",ace->ace.name, ace->ace.matches.eth.source_address);
                return ret;
            }
            if (ace->ace.matches.eth.source_address_mask){
                SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS][%s]Match Source mac address mask '%s'",ace->ace.name, ace->ace.matches.eth.source_address_mask);
                ret = ll_addr_a2n(addr,sizeof(addr),ace->ace.matches.eth.source_address_mask);
                if(ret < 0){
                    SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS][%s] Invalid MAC Address Mask format '%s'",ace->ace.name, ace->ace.matches.eth.source_address_mask);
                    return ret;
                }
                else {
                    ret = nla_put(*msg,TCA_FLOWER_KEY_ETH_SRC_MASK,sizeof(addr),addr);
                    if(ret < 0){
                        SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS][%s] Failed to source eth mask attributes '%s'",ace->ace.name, ace->ace.matches.eth.source_address_mask);
                        return ret;
                    }
                }
            }
        }
    }
    if(ace->ace.matches.eth.destination_address){
        SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS][%s] Match destination mac address '%s'",ace->ace.name, ace->ace.matches.eth.destination_address);
        char addr[ETH_ALEN];
        ret = ll_addr_a2n(addr, sizeof(addr), ace->ace.matches.eth.destination_address);
        if (ret < 0){
           SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS][%s]Invalid MAC address format '%s'",ace->ace.name, ace->ace.matches.eth.destination_address); 
           return ret;
        }
        else{
            ret = nla_put(*msg,TCA_FLOWER_KEY_ETH_DST,sizeof(addr),addr);
            if(ret < 0){
                SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][%s] Failed to destination eth mac address attributes '%s'",ace->ace.name, ace->ace.matches.eth.destination_address);
                return ret;
            }
            if (ace->ace.matches.eth.destination_address_mask){
                SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS][%s] Match destination mac address mask '%s'",ace->ace.name, ace->ace.matches.eth.destination_address_mask);
                ret = ll_addr_a2n(addr,sizeof(addr),ace->ace.matches.eth.destination_address_mask);
                if( ret < 0){
                    SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS][%s] Invalid MAC address mask format '%s'",ace->ace.name, ace->ace.matches.eth.destination_address_mask);
                    return ret;
                }
                else {
                    ret = nla_put(*msg,TCA_FLOWER_KEY_ETH_DST_MASK,sizeof(addr),addr);
                    if(ret < 0){
                        SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS][%s] Failed to destination eth mask attributes '%s'",ace->ace.name, ace->ace.matches.eth.destination_address_mask);
                        return ret;
                    }
                }
            }
        }
    }

    if(ace->ace.matches.ipv4.source_network){
        SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS][%s] Match source IPv4 network '%s'",ace->ace.name, ace->ace.matches.ipv4.source_network);
        ret = tcnl_flower_parse_ip_addr(ace->ace.matches.ipv4.source_network, eth_type,
						   TCA_FLOWER_KEY_IPV4_SRC,
						   TCA_FLOWER_KEY_IPV4_SRC_MASK,
						   TCA_FLOWER_KEY_IPV6_SRC,
						   TCA_FLOWER_KEY_IPV6_SRC_MASK,
						   *msg);
        if (ret){
            SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS][%s] Failed to set source IPv4 network '%s', ethertype '= '%d'.",
            ace->ace.name, ace->ace.matches.ipv4.source_network,eth_type);
            return ret;
        }
    }
    if(ace->ace.matches.ipv4.destination_network){
        SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS][%s] Match destination IPv4 network '%s'.",ace->ace.name, ace->ace.matches.ipv4.destination_network);
        ret = tcnl_flower_parse_ip_addr(ace->ace.matches.ipv4.destination_network, eth_type,
						   TCA_FLOWER_KEY_IPV4_DST,
						   TCA_FLOWER_KEY_IPV4_DST_MASK,
						   TCA_FLOWER_KEY_IPV6_DST,
						   TCA_FLOWER_KEY_IPV6_DST_MASK,
						   *msg);
        if (ret){
            SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS][%s] Failed to set destination IPv4 network '%s', ethertype '%d'.",
            ace->ace.name, ace->ace.matches.ipv4.destination_network,eth_type);
            return ret;
        }
    }

    if(ace->ace.matches.ipv6.source_network){
        SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS][%s] Match source IPv6 network '%s'.",ace->ace.name, ace->ace.matches.ipv6.source_network);
        ret = tcnl_flower_parse_ip_addr(ace->ace.matches.ipv6.source_network, eth_type,
						   TCA_FLOWER_KEY_IPV4_SRC,
						   TCA_FLOWER_KEY_IPV4_SRC_MASK,
						   TCA_FLOWER_KEY_IPV6_SRC,
						   TCA_FLOWER_KEY_IPV6_SRC_MASK,
						   *msg);
        if (ret){
            SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS][%s] Failed to set source IPv6 network '%s', ethertype '%d'.",
            ace->ace.name, ace->ace.matches.ipv6.source_network,eth_type);
            return ret;
        }
    }
    if(ace->ace.matches.ipv6.destination_network){
        SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS][%s] Match Destination IPv6 Network = %s",ace->ace.name, ace->ace.matches.ipv6.destination_network);
        ret = tcnl_flower_parse_ip_addr(ace->ace.matches.ipv6.destination_network, eth_type,
						   TCA_FLOWER_KEY_IPV4_DST,
						   TCA_FLOWER_KEY_IPV4_DST_MASK,
						   TCA_FLOWER_KEY_IPV6_DST,
						   TCA_FLOWER_KEY_IPV6_DST_MASK,
						   *msg);
        if (ret){
            SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS][%s] Failed to set destination IPv6 network '%s', ethertype '%d'.",
            ace->ace.name, ace->ace.matches.ipv6.destination_network,eth_type);
            return ret;
        }
    }

    ret = tcnl_flower_parse_tcp_ports(*msg, ace);
    if (ret) return ret;

    ret = tcnl_flower_parse_udp_ports(*msg, ace);
    if (ret) return ret;

    ret = tcnl_flower_put_action(*msg,ace);
    if (ret) return ret;

    nla_nest_end(*msg, opts);
    return ret;
}
int tcnl_set_filter_msg(struct nl_msg** msg, int request_type, unsigned int flags, unsigned int acl_id, onm_tc_ace_element_t * ace_element) {
    if(ace_element == NULL){
        SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL] Invalid ACE elemenent");
        return -1;
    }

    uint16_t tcm_handle = ace_element->ace.handle;
    uint16_t priority = ace_element->ace.priority;
    char *proto_buf = NULL;
    uint16_t proto_id;
    struct tcmsg tcm = {0};
    int ret;

    if (priority == 0){
        SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL] Bad ACE priority");
        return -2;
    }
    if (tcm_handle == 0){
        SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FILTER UPDATE] Bad ACE handle, setting it to default value");
        tcm_handle = DEFAULT_TCM_HANDLE;
    }
    
    // Allocate a new Netlink message
    *msg = nlmsg_alloc_simple(request_type, flags);
    if (!*msg) {
        SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FILTER UPDATE] failled to allocate nlmsg memory");
        return -1;
    }
    // Prepare tcmsg structure
    tcm.tcm_family = AF_UNSPEC;
    tcm.tcm_ifindex = TCM_IFINDEX_MAGIC_BLOCK;
    tcm.tcm_block_index = acl_id;
    tcm.tcm_handle = tcm_handle;
    SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FILTER UPDATE] ACE Name '%s'",ace_element->ace.name);
    if (request_type == RTM_NEWTFILTER)
    {
        if(ace_element->ace.matches.ipv6._is_set == 1){
            proto_buf = "ipv6";
        }
        else if (ace_element->ace.matches.ipv4._is_set == 1){
            proto_buf = "ipv4";
        }
        else if (ace_element->ace.matches.icmp._is_set == 1){
            //ipv4 or ipv6 ? TODO look at acl type
            proto_buf = "ipv4";
        }
        else if (ace_element->ace.matches.tcp._is_set == 1){
            //ipv4 or ipv6 ? TODO look at acl type
            proto_buf = "ipv4";
        }
        else if (ace_element->ace.matches.udp._is_set == 1){
            //ipv4 or ipv6 ? TODO look at acl type
            proto_buf = "ipv4";
        }
        SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FILTER UPDATE][%s] Protocol Buffer '%s'.",ace_element->ace.name,proto_buf);

        // set ip protocol version
        if (proto_buf){
            if (ll_proto_a2n(&proto_id, proto_buf)){
                SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FILTER UPDATE][%s] Failed to set specified protocol, setting EtherType to ALL.",ace_element->ace.name);
                tcm.tcm_info = TC_H_MAKE(priority<<16, htons(ETH_P_ALL));
            }
            else {
                SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FILTER UPDATE][%s] Set EtherType to %d.",ace_element->ace.name,htons(proto_id));
                tcm.tcm_info = TC_H_MAKE(priority<<16, proto_id);
            }
        }
        else{
            // ethertype is not specified in ACE config
            // check if ethertype is specified in ethernet match.
            if (ace_element->ace.matches.eth.ethertype != 0){
                SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FILTER UPDATE][%s] L2 match ethertype %d.",ace_element->ace.name,ace_element->ace.matches.eth.ethertype);
                tcm.tcm_info = TC_H_MAKE(priority<<16, ace_element->ace.matches.eth.ethertype);
            }
            else {
                SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FILTER UPDATE][%s] Protocol is not specified, set EtherType to ALL",ace_element->ace.name);
                tcm.tcm_info = TC_H_MAKE(priority<<16, htons(ETH_P_ALL));
            } 
        }
    }
    else {
        SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FILTER UPDATE][%s] Request type %d requres not setting a protocol",ace_element->ace.name,request_type);
        tcm.tcm_info = TC_H_MAKE(priority<<16, 0);
    }
    // Add tcmsg to the message
    ret = nlmsg_append(*msg, &tcm, sizeof(tcm), NLMSG_ALIGNTO);
    if (ret < 0){
        SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FILTER UPDATE][%s] Failed to set message header.",ace_element->ace.name);
        return ret;
    }

    // GET filter stops here.
    if (request_type == RTM_GETTFILTER){
        SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FILTER UPDATE] Building Get filter message is complete, filter priority %d, filter handle %d.",priority,tcm_handle);
        return ret;
    }

    ret = nla_put_string(*msg,TCA_KIND,"flower");
    if (ret < 0){
        SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FILTER UPDATE][%s] Failed add flower kind attribute.",ace_element->ace.name);
        return ret;
    }
    SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FILTER UPDATE][%s] Added filter kind 'flower'",ace_element->ace.name);

    // DELETED filter stops here.
    if (request_type == RTM_DELTFILTER){
        SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][FILTER UPDATE][%s] Building delete filter message is complete, filter priority %d, filter handle %d.",ace_element->ace.name, priority,tcm_handle);
        return ret;
    }


    // put flower options
    ret = tcnl_put_flower_options(msg,ace_element);
    if (ret < 0){
        SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FILTER UPDATE][%s] Failed to add flower options.",ace_element->ace.name);
        return ret;
    }

    return ret;
}
int tcnl_filter_modify(onm_tc_ctx_t * ctx, onm_tc_ace_element_t* ace, unsigned int acl_id, unsigned int request_type, unsigned int flags, bool override){
    struct nl_msg *msg;
    int ret = 0;
    if(override && request_type != RTM_DELTFILTER){
        ret = tcnl_set_filter_msg(&msg,RTM_DELTFILTER,0,acl_id,ace);
        if (ret < 0) return ret;
        // don't return error for this tcnl_talk instance.
        // it is expect to delete a filter that doesn't exist on tc (when override is used)
        // this will through an error of object not found
        ret = tcnl_talk(&msg,ctx,nl_msg_recv_cb,false);
    }
    ret = tcnl_set_filter_msg(&msg,request_type,flags,acl_id,ace);
    if (ret < 0){
        return ret;
    }
    ret = tcnl_talk(&msg,ctx,nl_msg_recv_cb,true);
    return ret;
}
int tcnl_block_modify(onm_tc_acl_hash_element_t * acls_hash, unsigned int acl_id, onm_tc_ctx_t * ctx, int request_type, unsigned int flags){
    const onm_tc_acl_hash_element_t *iter = NULL, *tmp = NULL;
    int ret = -11;
    HASH_ITER(hh, acls_hash, iter, tmp)
    {   
        if (iter->acl.acl_id == acl_id)
        {
            ret = 0;
            onm_tc_ace_element_t* ace_iter = NULL;
            // iterate over aces
            LL_FOREACH(iter->acl.aces.ace, ace_iter)
            {
                ret = tcnl_filter_modify(ctx,ace_iter,acl_id,request_type,flags,true);
                if (ret < 0){
                    return ret;
                }
            }
        } 
    }
    return ret;
}
bool tcnl_block_exists(onm_tc_ctx_t * ctx, unsigned int acl_id){
    struct nl_msg *msg;
    struct tcmsg tcm = {0};
    int ret = 0;
    filter_exists = false;
    int request_type = RTM_GETTFILTER;
    int flags = NLM_F_DUMP, protocol = 0, prio = 0;
    msg = nlmsg_alloc_simple(request_type, flags);
	tcm.tcm_parent = TC_H_UNSPEC;
	tcm.tcm_family = AF_UNSPEC;
    tcm.tcm_info = TC_H_MAKE(prio<<16, protocol);
    tcm.tcm_ifindex = TCM_IFINDEX_MAGIC_BLOCK;
	tcm.tcm_block_index = acl_id;
    SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][CHECK BLOCK] Checking if acl block ID %d exits on linux tc",acl_id);
    ret = nlmsg_append(msg, &tcm, sizeof(tcm), NLMSG_ALIGNTO);
    ret = tcnl_talk(&msg,ctx,rcv_is_filter_cb,true);
    SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][CHECK BLOCK %d] Block %s",acl_id, filter_exists ? "exists" : "does not exist");
    return filter_exists;
}

int tcnl_set_qdisc_msg(struct nl_msg** msg, int request_type, unsigned int flags, char * qdisc_kind, int if_idx, uint32_t ingress_block_id, uint32_t egress_block_id){
    // Allocate a new Netlink message
    int ret = 0;
    SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][QDISC UPDATE] Interface ID %d prepare netlink message",if_idx);
    *msg = nlmsg_alloc_simple(request_type, flags);
    if (!*msg) {
        SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][QDISC UPDATE] Interface ID %d failed to allocate nlmsg memory",if_idx);
        return -1;
    }
    struct tcmsg tcm = {0};
    // Prepare tcmsg structure
    tcm.tcm_family = AF_UNSPEC;
    tcm.tcm_ifindex = if_idx;
    tcm.tcm_info = 0;
    tcm.tcm_handle = TC_H_MAKE(0xffff, 0);
    tcm.tcm_parent = TC_H_CLSACT;
    if (strcmp(qdisc_kind,"ingress")){
        tcm.tcm_parent = TC_H_INGRESS;
    }
    ret = nlmsg_append(*msg, &tcm, sizeof(tcm), NLMSG_ALIGNTO);
    
    nla_put(*msg,TCA_KIND,strlen(qdisc_kind)+1,qdisc_kind);
    if (ingress_block_id != 0){
        SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][QDISC UPDATE][INTF ID %d] Set ingress block ID %d",if_idx,ingress_block_id);
        ret = nla_put_s32(*msg,TCA_INGRESS_BLOCK,ingress_block_id);
        if (ret < 0){
            SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][QDISC UPDATE][INTF ID %d] Failed to set ingress block ID %d",if_idx,ingress_block_id);
            return ret;
        }
    }
    if (egress_block_id != 0){
        SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][QDISC UPDATE][INTF ID %d] Set egress block ID %d",if_idx,egress_block_id);
        ret = nla_put_s32(*msg,TCA_EGRESS_BLOCK,egress_block_id);
        if (ret < 0){
            SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][FLOWER_OPTIONS][interface ID %d] Failed to set rgress block ID %d",if_idx,egress_block_id);
            return ret;
        }
    }
    return 0;
}
int tcnl_qdisc_modify(onm_tc_ctx_t * ctx, int request_type, char * qdisc_kind, int if_idx, uint32_t ingress_block_id, uint32_t egress_block_id, bool override){
    struct nl_msg *msg;
    int ret = 0;
    unsigned int flags = 0;
    if(request_type == RTM_NEWQDISC){
        flags = NLM_F_CREATE | NLM_F_REPLACE | NLM_F_EXCL;
    }
    if(!override && request_type == RTM_NEWQDISC){
        flags = NLM_F_CREATE;
    }
    ret = tcnl_set_qdisc_msg(&msg, request_type, flags, qdisc_kind, if_idx, ingress_block_id, egress_block_id);
    if (ret < 0) return ret;
    ret = tcnl_talk(&msg,ctx,nl_msg_recv_cb,true);
    return ret;
}

int tcnl_talk(struct nl_msg** msg, onm_tc_ctx_t * ctx, void * rcv_callback, bool msg_clear){
    int ret = 0;
    // Initialize and connect to Netlink
    struct nl_sock * sock = ctx->nl_ctx.socket;
    if (!sock) {
        SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][TALK] Failed to create netlink socket.");
        return -1;
    }
    ret = nl_send_auto(sock, *msg);
    if (ret < 0) {
        SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][TALK] Failed to send netlink message '%s'",nl_geterror(ret));
        return ret;
    }
    SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][TALK] Send netlink message success");
    
    // Receive message callabck
    nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, rcv_callback, NULL);
    // Receive messages
    ret = nl_recvmsgs_default(sock);
    if (ret < 0) {
        //if (ret != -12) // hide object not found error
            SRPLG_LOG_ERR(PLUGIN_NAME, "[TCNL][TALK] Error receiving netlink messages'%d %s'",ret,nl_geterror(ret));
        nlmsg_free(*msg);
        //nl_socket_free(sock);
        return ret;
    }
    SRPLG_LOG_INF(PLUGIN_NAME, "[TCNL][TALK] Send netlink message response is '%s'",nl_geterror(ret));
    // Clean up
    if (msg_clear){
        nlmsg_free(*msg);
    }
    
    //nl_socket_free(sock);

    return 0;
}