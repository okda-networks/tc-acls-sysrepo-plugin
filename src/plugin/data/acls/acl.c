/*
 * okda-networks / onm-tc-acls
 *
 * This program is made available under the terms of the
 * BSD 3-Clause license which is available at
 * https://opensource.org/licenses/BSD-3-Clause
 *
 * SPDX-FileCopyrightText: 2023 Okda Networks
 * SPDX-FileContributor: Sartura Ltd, Deutsche Telekom AG.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "libyang/log.h"
#include "libyang/tree_data.h"
#include "plugin/common.h"
#include "plugin/ly_tree.h"
#include "plugin/types.h"
#include "srpc/ly_tree.h"
#include "sysrepo.h"
#include "uthash.h"
#include "utils/memory.h"
#include "utlist.h"
#include "memory.h"
// other data API
#include "acl.h"
#include "acl/aces.h"
#include "acl/linked_list.h"

#include <assert.h>
#include <srpc.h>
#include <stdio.h>
#include <stdlib.h>

#include "plugin/api/tcnl.h"

/*
    Libyang, srpc and other data type conversion functions.
*/

onm_tc_acl_hash_element_t* onm_tc_acl_hash_new(void)
{
    return NULL;
}

onm_tc_acl_hash_element_t* onm_tc_acl_hash_element_new(void)
{
    onm_tc_acl_hash_element_t* new_element = NULL;

    new_element = xmalloc(sizeof(onm_tc_acl_hash_element_t));
    if (!new_element)
        return NULL;

    // NULL all fields
    new_element->acl = (onm_tc_acl_t) { 0 };
    return new_element;
}

unsigned int acl_name2id(const char *str) {
    unsigned int hash = 5381; // Initial hash value
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    return hash;
}

int onm_tc_acl_hash_element_set_name(onm_tc_acl_hash_element_t** el, const char* name, sr_change_oper_t change_operation)
{
    if ((*el)->acl.name) {
        FREE_SAFE((*el)->acl.name);
    }
    if (name) {
        (*el)->acl.name = xstrdup(name);
        (*el)->acl.acl_id = acl_name2id(name);
        (*el)->acl.name_change_op = change_operation;
        return (*el)->acl.name == NULL;
    }

    return 0;
}

int onm_tc_acl_hash_element_set_type(onm_tc_acl_hash_element_t** el, const char* type,sr_change_oper_t change_operation)
{
    // this is an identifity ref, don't use strcmp if you need to compare string, use strstr
    //TODO fix data type
    if ((*el)->acl.type) {
    //    FREE_SAFE((*el)->acl.type);
    }
    if (type) {
    //    (*el)->acl.type = xstrdup(type);
    //    return (*el)->acl.type == NULL;
    }
    return 0;
}

int onm_tc_acls_hash_add_acl_element(onm_tc_acl_hash_element_t** hash, onm_tc_acl_hash_element_t* new_element)
{
    onm_tc_acl_hash_element_t* found_element = NULL;

    if (new_element->acl.name)
        HASH_FIND_STR(*hash, new_element->acl.name, found_element);
    else
    {
        // element key is NULL
        return -2;
    }
    // element already exists
    if (found_element != NULL) {
        return -1;
    }

    // element not found - add new element to the hash
    HASH_ADD_KEYPTR(hh, *hash, new_element->acl.name, strlen(new_element->acl.name), new_element);

    return 0;
}

onm_tc_acl_hash_element_t* onm_tc_acl_hash_get_element(onm_tc_acl_hash_element_t** hash, const char* name)
{
    onm_tc_acl_hash_element_t* found_element = NULL;

    HASH_FIND_STR(*hash, name, found_element);

    return found_element;
}

//TODO compelete freeing elements
void onm_tc_acl_element_hash_free(onm_tc_acl_hash_element_t** el)
{
    if (*el) {
        // name
        if ((*el)->acl.name) {
            free((*el)->acl.name);
        }

        // type
        //TODO fix data type
        if ((*el)->acl.type) {
            //free((*el)->acl.type);
        }


        // ace list
        // TODO add all ACE entries
        if ((*el)->acl.aces.ace) {
            ONM_TC_ACL_LIST_FREE((*el)->acl.aces.ace);
        }
        // element data
        free(*el);
        *el = NULL;
    }
}

void onm_tc_acls_list_hash_free(onm_tc_acl_hash_element_t** hash)
{
    onm_tc_acl_hash_element_t *tmp = NULL, *element = NULL;
    HASH_ITER(hh, *hash, element, tmp)
    {   
        HASH_DEL(*hash, element);
        onm_tc_acl_element_hash_free(&element);
    }

    *hash = NULL;
}

int events_acl_init(void *priv)
{
	int error = 0;
	return error;
}

void events_acl_free(void *priv)
{
}

int onm_tc_events_acls_hash_add_acl_element(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx)
{
	const char *node_name = LYD_NAME(change_ctx->node);
	const char *parent_node_name = LYD_NAME(&change_ctx->node->parent->node);
	const char *node_value = lyd_get_value(change_ctx->node);
    onm_tc_ctx_t *ctx = (onm_tc_ctx_t *) priv;
	//printf("ADD ACL DATA:\n\tNode Name: %s\n\tNode Value: %s\n\tParent Node Name: %s\n\tOperation: %d\n",node_name,node_value,parent_node_name,change_ctx->operation);
	onm_tc_acl_hash_element_t* event_acl_hash = NULL;
    event_acl_hash = onm_tc_acl_hash_element_new();

	int error = 0;
	if (strcmp(node_name,"name")==0)
	{
		SRPLG_LOG_INF(PLUGIN_NAME, "Processing new ACL change, ACL Name: %s, Change operation: %d.",node_value,change_ctx->operation);
		SRPC_SAFE_CALL_ERR(error, onm_tc_acl_hash_element_set_name(&event_acl_hash, node_value,change_ctx->operation), error_out);

        //init aces list inside temp change acl hash element
        ONM_TC_ACL_LIST_NEW(event_acl_hash->acl.aces.ace);

        // add acl element to acls_list
        onm_tc_acls_hash_add_acl_element(&ctx->events_acls_list, event_acl_hash);
	}
	goto out;

error_out:
	return error;

out:
	return error;
}

int validate_and_update_events_acls_hash(onm_tc_ctx_t * ctx){
	onm_tc_acl_hash_element_t * events_acls = ctx->events_acls_list;
	onm_tc_acl_hash_element_t * running_acls = ctx->running_acls_list;

    if (events_acls == NULL){
        return -1;
    }
    onm_tc_acl_hash_element_t *iter = NULL, *tmp = NULL;
    onm_tc_ace_element_t* ace_iter = NULL;
	SRPLG_LOG_INF(PLUGIN_NAME, "Validating change event data");
    HASH_ITER(hh, events_acls, iter, tmp)
    {	
		if (!iter->acl.name){
			SRPLG_LOG_ERR(PLUGIN_NAME, "Bad ACL name");
			return -1;
		}
		SRPLG_LOG_INF(PLUGIN_NAME, "Validating ACL '%s' data, event change operation '%d'",
		iter->acl.name, iter->acl.name_change_op);
		// ACL name event operation can only be SR_OP_CREATED or SR_OP_DELETED, only newely created acls don't need validation against running acls hash
		if (iter->acl.name_change_op == SR_OP_CREATED){
			continue;
		}

        LL_FOREACH(iter->acl.aces.ace, ace_iter){
			if (!ace_iter->ace.name){
				SRPLG_LOG_ERR(PLUGIN_NAME, "[%s] Validation failed, bad ACE element",iter->acl.name);
				return -1;
			}
			SRPLG_LOG_INF(PLUGIN_NAME, "[%s] Validating ACE '%s' data, event change operation '%d'",iter->acl.name,
			ace_iter->ace.name, ace_iter->ace.name_change_op);
			// ACE name event operation can only be SR_OP_CREATED or SR_OP_DELETED, only newely created aces don't need validation against running acls hash
			if (ace_iter->ace.name_change_op == SR_OP_CREATED){
				continue;
			}
			onm_tc_ace_element_t * running_ace = onm_tc_get_ace_in_acl_list_by_name(ctx->running_acls_list,iter->acl.name,ace_iter->ace.name);
			
			// ace name not found in running acls list; should never meet this condition since skipping new aces validation
			if (!running_ace){
				SRPLG_LOG_ERR(PLUGIN_NAME, "[%s] Validation failed, modified ACE %s not found in ACL Name %s",iter->acl.name,ace_iter->ace.name, iter->acl.name);
                return -1;
			}
            // ensure to set ace priority to match the running ace priority (SR_OP_MOVED will be handeld in a different function)
            //onm_tc_ace_hash_element_set_ace_priority(&ace_iter,running_ace->ace.priority,DEFAULT_CHANGE_OPERATION);

			if(!ace_iter->ace.matches.eth.source_address && running_ace->ace.matches.eth.source_address){
                SRPLG_LOG_INF(PLUGIN_NAME, "[%s][VALIDATION] Update ACE '%s' source mac address",iter->acl.name, ace_iter->ace.name);
				char * node_value = running_ace->ace.matches.eth.source_address;
				onm_tc_ace_hash_element_set_match_src_mac_addr(&ace_iter,node_value,DEFAULT_CHANGE_OPERATION);
            }
            if(!ace_iter->ace.matches.eth.source_address_mask && running_ace->ace.matches.eth.source_address_mask){
                SRPLG_LOG_INF(PLUGIN_NAME, "[%s][VALIDATION] Update ACE '%s' source mac address mask",iter->acl.name, ace_iter->ace.name);
				char * node_value = running_ace->ace.matches.eth.source_address_mask;
				onm_tc_ace_hash_element_set_match_src_mac_addr_mask(&ace_iter,node_value,DEFAULT_CHANGE_OPERATION);
            }
			if(!ace_iter->ace.matches.eth.destination_address && running_ace->ace.matches.eth.destination_address){
                SRPLG_LOG_INF(PLUGIN_NAME, "[%s][VALIDATION]Update ACE '%s' destination mac address",iter->acl.name, ace_iter->ace.name);
				char * node_value = running_ace->ace.matches.eth.destination_address;
				onm_tc_ace_hash_element_set_match_dst_mac_addr(&ace_iter,node_value,DEFAULT_CHANGE_OPERATION);
            }
            if(!ace_iter->ace.matches.eth.destination_address_mask && running_ace->ace.matches.eth.destination_address_mask){
                SRPLG_LOG_INF(PLUGIN_NAME, "[%s][VALIDATION] Update ACE '%s' destination mac address mask",iter->acl.name, ace_iter->ace.name);
				char * node_value = running_ace->ace.matches.eth.destination_address_mask;
				onm_tc_ace_hash_element_set_match_dst_mac_addr_mask(&ace_iter,node_value,DEFAULT_CHANGE_OPERATION);
            }

			// TODO do more testing here
            if(ace_iter->ace.matches.eth.ethertype == 0 && running_ace->ace.matches.eth.ethertype !=0){
                SRPLG_LOG_INF(PLUGIN_NAME, "[%s][VALIDATION] Update ACE '%s' ethertype",iter->acl.name, ace_iter->ace.name);
				uint16_t node_value = running_ace->ace.matches.eth.ethertype;
				ace_iter->ace.matches.eth.ethertype = node_value;
				ace_iter->ace.matches.eth.ethertype_change_op = DEFAULT_CHANGE_OPERATION;
            }

			// IPv4
            if(!ace_iter->ace.matches.ipv4.source_network && running_ace->ace.matches.ipv4.source_network){
                SRPLG_LOG_INF(PLUGIN_NAME, "[%s][VALIDATION] Update ACE '%s' source ipv4 network",iter->acl.name, ace_iter->ace.name);
				char * node_value = running_ace->ace.matches.ipv4.source_network;
				onm_tc_ace_hash_element_set_match_ipv4_src_network(&ace_iter,node_value,DEFAULT_CHANGE_OPERATION);
            }
            if(!ace_iter->ace.matches.ipv4.destination_network && running_ace->ace.matches.ipv4.destination_network){
                SRPLG_LOG_INF(PLUGIN_NAME, "[%s][VALIDATION] Update ACE '%s' destination ipv4 network",iter->acl.name, ace_iter->ace.name);
				char * node_value = running_ace->ace.matches.ipv4.destination_network;
				onm_tc_ace_hash_element_set_match_ipv4_dst_network(&ace_iter,node_value,DEFAULT_CHANGE_OPERATION);
            }

			// IPv6
            if(!ace_iter->ace.matches.ipv6.source_network && running_ace->ace.matches.ipv6.source_network){
                SRPLG_LOG_INF(PLUGIN_NAME, "[%s][VALIDATION] Update ACE '%s' source ipv6 network",iter->acl.name, ace_iter->ace.name);
				char * node_value = running_ace->ace.matches.ipv6.source_network;
				onm_tc_ace_hash_element_set_match_ipv6_src_network(&ace_iter,node_value,DEFAULT_CHANGE_OPERATION);
            }
            if(!ace_iter->ace.matches.ipv6.destination_network && running_ace->ace.matches.ipv6.destination_network){
                SRPLG_LOG_INF(PLUGIN_NAME, "[%s][VALIDATION] Update ACE '%s' destination ipv6 network",iter->acl.name, ace_iter->ace.name);
				char * node_value = running_ace->ace.matches.ipv6.destination_network;
				onm_tc_ace_hash_element_set_match_ipv6_dst_network(&ace_iter,node_value,DEFAULT_CHANGE_OPERATION);
            }
            // TODO update logging and possible add if statement to only check if tcp or udp ports are set.
			// port single, operator and range
			VALIDATE_AND_UPDATE_EVENT_PORT_OR_RANGE(ace_iter, tcp, source_port, "Update ACE '%s' tcp source port info", PORT_ATTR_SRC, PORT_ATTR_PROTO_TCP);
			VALIDATE_AND_UPDATE_EVENT_PORT_OR_RANGE(ace_iter, tcp, destination_port, "Update ACE '%s' tcp destination port info", PORT_ATTR_DST, PORT_ATTR_PROTO_TCP);
			VALIDATE_AND_UPDATE_EVENT_PORT_OR_RANGE(ace_iter, udp, source_port, "Update ACE '%s' udp source port info", PORT_ATTR_SRC, PORT_ATTR_PROTO_UDP);
			VALIDATE_AND_UPDATE_EVENT_PORT_OR_RANGE(ace_iter, udp, destination_port, "Update ACE '%s' udp destination port info", PORT_ATTR_DST, PORT_ATTR_PROTO_UDP);

			// action forwarding
			if(ace_iter->ace.actions.forwarding == FORWARD_NOOP){
                SRPLG_LOG_INF(PLUGIN_NAME, "[%s][VALIDATION] Update ACE '%s' action forwarding",iter->acl.name, ace_iter->ace.name);
				forwarding_action_t node_value = running_ace->ace.actions.forwarding;
				ace_iter->ace.actions.forwarding = node_value;
				ace_iter->ace.actions.forwarding_change_op = DEFAULT_CHANGE_OPERATION;
            }

			// action logging
            if(ace_iter->ace.actions.logging == LOG_NOOP && running_ace->ace.actions.logging != LOG_NOOP){
                SRPLG_LOG_INF(PLUGIN_NAME, "[%s][]VALIDATION] Update ACE '%s' action logging",iter->acl.name, ace_iter->ace.name);
				logging_action_t node_value = running_ace->ace.actions.logging;
				ace_iter->ace.actions.logging = node_value;
				ace_iter->ace.actions.forwarding_change_op = DEFAULT_CHANGE_OPERATION;
            }
		}
    }
}


int onm_tc_acl_element_from_ly(onm_tc_acl_hash_element_t** acl_hash_element, const struct lyd_node* acl_element_node)
{
    int error = 0;

    // make sure the hash is empty at the start
    //assert(*acl_hash_element == NULL);

    // libyang
    struct lyd_node *acl_name_node = NULL, *acl_type_node = NULL;
    struct lyd_node *aces_container_node = NULL;
    struct lyd_node *ace_list_node = NULL;
    struct lyd_node *ace_name_node = NULL;
    struct lyd_node *matches_container_node = NULL, *actions_container_node = NULL;

    struct lyd_node *match_eth_container_node = NULL, *match_ipv4_container_node = NULL, *match_ipv6_container_node = NULL, *match_tcp_container_node = NULL, *match_udp_container_node = NULL, *match_icmp_container_node = NULL;
    struct lyd_node *eth_dst_mac_addr_node = NULL, *eth_dst_mac_addr_mask_node = NULL, *eth_src_mac_addr_node = NULL, *eth_src_mac_addr_mask_node = NULL, *eth_ethtype_node = NULL;
    struct lyd_node *ipv4_src_network_node = NULL, *ipv4_dst_network_node = NULL;
    struct lyd_node *ipv6_src_network_node = NULL, *ipv6_dst_network_node = NULL;
    //tcp
    struct lyd_node *tcp_src_port_container_node = NULL, *tcp_dst_port_container_node = NULL;
    struct lyd_node *tcp_src_port_node = NULL, *tcp_dst_port_node = NULL,*tcp_src_range_lower_port_node = NULL,*tcp_dst_range_lower_port_node = NULL, *tcp_src_range_upper_port_node = NULL, *tcp_dst_range_upper_port_node = NULL;
    //udp
    struct lyd_node *udp_src_port_container_node = NULL, *udp_dst_port_container_node = NULL;
    struct lyd_node *udp_src_port_node = NULL, *udp_dst_port_node = NULL,*udp_src_range_lower_port_node = NULL,*udp_dst_range_lower_port_node = NULL, *udp_src_range_upper_port_node = NULL, *udp_dst_range_upper_port_node = NULL;
    // tcp or udp
    struct lyd_node *src_port_operator_node = NULL, *dst_port_operator_node = NULL;
    struct lyd_node *icmp_code_node = NULL;
    struct lyd_node *action_forwarding_node = NULL, *action_logging_node = NULL;


    // internal DS
    onm_tc_ace_element_t* new_ace_element = NULL;

    // get existing nodes
    SRPC_SAFE_CALL_PTR(acl_name_node, srpc_ly_tree_get_child_leaf(acl_element_node, "name"), error_out);
    acl_type_node = srpc_ly_tree_get_child_leaf(acl_element_node, "type");
    aces_container_node = srpc_ly_tree_get_child_container(acl_element_node, "aces");

    //set data
    if (acl_name_node){
        SRPC_SAFE_CALL_ERR(error, onm_tc_acl_hash_element_set_name(acl_hash_element, lyd_get_value(acl_name_node),DEFAULT_CHANGE_OPERATION), error_out);  
    }
    if (acl_type_node){
        SRPC_SAFE_CALL_ERR(error, onm_tc_acl_hash_element_set_type(acl_hash_element, lyd_get_value(acl_type_node),DEFAULT_CHANGE_OPERATION), error_out);
    }

    if (aces_container_node){
        ace_list_node = srpc_ly_tree_get_child_list(aces_container_node, "ace");

        // init ace list
        ONM_TC_ACL_LIST_NEW((*acl_hash_element)->acl.aces.ace);
        unsigned int ace_prio_counter = 0;
        while(ace_list_node){
            // add new ace element
            new_ace_element = onm_tc_ace_hash_element_new();

            // fetch ace nodes
            SRPC_SAFE_CALL_PTR(ace_name_node, srpc_ly_tree_get_child_leaf(ace_list_node, "name"), error_out);
            matches_container_node = srpc_ly_tree_get_child_container(ace_list_node, "matches");
            actions_container_node = srpc_ly_tree_get_child_container(ace_list_node, "actions");

            //parse ace data
            if (ace_name_node){
                ace_prio_counter +=10;
                SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_ace_name(&new_ace_element, lyd_get_value(ace_name_node),DEFAULT_CHANGE_OPERATION), error_out);
                SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_ace_priority(&new_ace_element, ace_prio_counter , DEFAULT_CHANGE_OPERATION), error_out);
                SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_ace_handle(&new_ace_element, DEFAULT_TCM_HANDLE), error_out);
                ace_name_node = NULL;
            }

            if (matches_container_node){
                match_eth_container_node = srpc_ly_tree_get_child_container(matches_container_node, "eth");
                match_ipv4_container_node = srpc_ly_tree_get_child_container(matches_container_node, "ipv4");
                match_ipv6_container_node = srpc_ly_tree_get_child_container(matches_container_node, "ipv6");
                match_tcp_container_node = srpc_ly_tree_get_child_container(matches_container_node, "tcp");
                match_udp_container_node = srpc_ly_tree_get_child_container(matches_container_node, "udp");
                match_icmp_container_node = srpc_ly_tree_get_child_container(matches_container_node, "icmp");
                matches_container_node = NULL;
                if (match_eth_container_node){
                    eth_src_mac_addr_node = srpc_ly_tree_get_child_leaf(match_eth_container_node, "source-mac-address");
                    eth_src_mac_addr_mask_node = srpc_ly_tree_get_child_leaf(match_eth_container_node, "source-mac-address-mask");
                    eth_dst_mac_addr_node = srpc_ly_tree_get_child_leaf(match_eth_container_node, "destination-mac-address");
                    eth_dst_mac_addr_mask_node = srpc_ly_tree_get_child_leaf(match_eth_container_node, "destination-mac-address-mask");
                    eth_ethtype_node = srpc_ly_tree_get_child_leaf(match_eth_container_node, "ethertype");
                    match_eth_container_node = NULL;
                }

                if (match_ipv4_container_node){
                    ipv4_src_network_node = srpc_ly_tree_get_child_leaf(match_ipv4_container_node, "source-ipv4-network");
                    ipv4_dst_network_node = srpc_ly_tree_get_child_leaf(match_ipv4_container_node, "destination-ipv4-network");
                    match_ipv4_container_node = NULL;
                }

                if (match_ipv6_container_node){
                    ipv6_src_network_node = srpc_ly_tree_get_child_leaf(match_ipv6_container_node, "source-ipv6-network");
                    ipv6_dst_network_node = srpc_ly_tree_get_child_leaf(match_ipv6_container_node, "destination-ipv6-network");
                    match_ipv6_container_node = NULL;
                }

                if (match_tcp_container_node){
                    tcp_src_port_container_node = srpc_ly_tree_get_child_container(match_tcp_container_node, "source-port");
                    tcp_dst_port_container_node = srpc_ly_tree_get_child_container(match_tcp_container_node, "destination-port");
                    match_tcp_container_node = NULL;
                    if (tcp_src_port_container_node){
                        tcp_src_port_node = srpc_ly_tree_get_child_leaf(tcp_src_port_container_node, "port");
                        tcp_src_range_lower_port_node = srpc_ly_tree_get_child_leaf(tcp_src_port_container_node, "lower-port");
                        tcp_src_range_upper_port_node = srpc_ly_tree_get_child_leaf(tcp_src_port_container_node, "upper-port");
                        src_port_operator_node = srpc_ly_tree_get_child_leaf(tcp_src_port_container_node, "operator");
                        tcp_src_port_container_node = NULL;
                    }
                    if (tcp_dst_port_container_node){
                        tcp_dst_port_node = srpc_ly_tree_get_child_leaf(tcp_dst_port_container_node, "port");
                        tcp_dst_range_lower_port_node = srpc_ly_tree_get_child_leaf(tcp_dst_port_container_node, "lower-port");
                        tcp_dst_range_upper_port_node = srpc_ly_tree_get_child_leaf(tcp_dst_port_container_node, "upper-port");
                        dst_port_operator_node = srpc_ly_tree_get_child_leaf(tcp_dst_port_container_node, "operator");
                        tcp_dst_port_container_node = NULL;
                    }
                }

                if (match_udp_container_node){
                    udp_src_port_container_node = srpc_ly_tree_get_child_container(match_udp_container_node, "source-port");
                    udp_dst_port_container_node = srpc_ly_tree_get_child_container(match_udp_container_node, "destination-port");
                    match_udp_container_node = NULL;
                    if (udp_src_port_container_node){
                        udp_src_port_node = srpc_ly_tree_get_child_leaf(udp_src_port_container_node, "port");
                        udp_src_range_lower_port_node = srpc_ly_tree_get_child_leaf(udp_src_port_container_node, "lower-port");
                        udp_src_range_upper_port_node = srpc_ly_tree_get_child_leaf(udp_src_port_container_node, "upper-port");
                        src_port_operator_node = srpc_ly_tree_get_child_leaf(udp_src_port_container_node, "operator");
                        udp_src_port_container_node = NULL;
                    }
                    if (udp_dst_port_container_node){
                        udp_dst_port_node = srpc_ly_tree_get_child_leaf(udp_dst_port_container_node, "port");
                        udp_dst_range_lower_port_node = srpc_ly_tree_get_child_leaf(udp_dst_port_container_node, "lower-port");
                        udp_dst_range_upper_port_node = srpc_ly_tree_get_child_leaf(udp_dst_port_container_node, "upper-port");
                        dst_port_operator_node = srpc_ly_tree_get_child_leaf(udp_dst_port_container_node, "operator");
                        udp_dst_port_container_node = NULL;
                    }
                }

                if (match_icmp_container_node){
                    icmp_code_node = srpc_ly_tree_get_child_leaf(match_icmp_container_node, "code");
                    match_icmp_container_node = NULL;
                }
            }

            if (actions_container_node){
                SRPC_SAFE_CALL_PTR(action_forwarding_node, srpc_ly_tree_get_child_leaf(actions_container_node, "forwarding"), error_out);
                SRPC_SAFE_CALL_PTR(action_logging_node, srpc_ly_tree_get_child_leaf(actions_container_node, "logging"), error_out);
                actions_container_node = NULL;
            }

            // set match data
            if(eth_src_mac_addr_node){
                SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_src_mac_addr(&new_ace_element, lyd_get_value(eth_src_mac_addr_node),DEFAULT_CHANGE_OPERATION), error_out);
                eth_src_mac_addr_node = NULL;
            }
            if(eth_src_mac_addr_mask_node){
                SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_src_mac_addr_mask(&new_ace_element, lyd_get_value(eth_src_mac_addr_mask_node),DEFAULT_CHANGE_OPERATION), error_out);
                eth_src_mac_addr_mask_node = NULL;
            }
            if(eth_dst_mac_addr_node){
                SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_dst_mac_addr(&new_ace_element, lyd_get_value(eth_dst_mac_addr_node),DEFAULT_CHANGE_OPERATION), error_out);
                eth_dst_mac_addr_node = NULL;
            }
            if(eth_dst_mac_addr_mask_node){
                SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_dst_mac_addr_mask(&new_ace_element, lyd_get_value(eth_dst_mac_addr_mask_node),DEFAULT_CHANGE_OPERATION), error_out);
                eth_dst_mac_addr_mask_node = NULL;
            }
            if(eth_ethtype_node){
                const char* ethertype_str = NULL;
                SRPC_SAFE_CALL_PTR(ethertype_str, lyd_get_value(eth_ethtype_node), error_out);
                uint16_t ether_type;
                if (ll_proto_a2n(&ether_type, ethertype_str))
                {
                    // TODO revise: currently this failure will set ethertype to ALL
                    SRPLG_LOG_ERR(PLUGIN_NAME, "ACE %s Failed to set specified EtherType for L2 match",new_ace_element->ace.name);
                    error = -1;
                }
                else
                    SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_eth_ethertype(&new_ace_element, ether_type,DEFAULT_CHANGE_OPERATION), error_out);
                eth_ethtype_node = NULL;
            }
            if(ipv4_src_network_node){
                SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_ipv4_src_network(&new_ace_element, lyd_get_value(ipv4_src_network_node),DEFAULT_CHANGE_OPERATION), error_out);
                ipv4_src_network_node = NULL;
            }
            if(ipv4_dst_network_node){
                SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_ipv4_dst_network(&new_ace_element, lyd_get_value(ipv4_dst_network_node),DEFAULT_CHANGE_OPERATION), error_out);
                ipv4_dst_network_node = NULL;
            }
            if(ipv6_src_network_node){
                SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_ipv6_src_network(&new_ace_element, lyd_get_value(ipv6_src_network_node),DEFAULT_CHANGE_OPERATION), error_out);
                ipv6_src_network_node = NULL;
            }
            if(ipv6_dst_network_node){
                SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_ipv6_dst_network(&new_ace_element, lyd_get_value(ipv6_dst_network_node),DEFAULT_CHANGE_OPERATION), error_out);
                ipv6_dst_network_node = NULL;
            }

            if(tcp_src_port_node){
                onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                const char* port_oper_str, *port_str = NULL;
                SRPC_SAFE_CALL_PTR(port_oper_str, lyd_get_value(src_port_operator_node), error_out);
                SRPC_SAFE_CALL_PTR(port_str, lyd_get_value(tcp_src_port_node), error_out);
                port_operator_t port_opr = onm_tc_ace_port_oper_a2i(port_oper_str);
                error = port_str_to_port_attr(port_attr,NULL,NULL,port_str,port_opr,PORT_ATTR_SRC,PORT_ATTR_PROTO_TCP);
                SRPC_SAFE_CALL_ERR(error, set_ace_port_single(new_ace_element, port_attr,DEFAULT_CHANGE_OPERATION), error_out);
                SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_port_operator(&new_ace_element, port_attr,DEFAULT_CHANGE_OPERATION), error_out);

                tcp_src_port_node = NULL;
                free(port_attr);
            }
            if(tcp_dst_port_node){
                onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                const char* port_oper_str, *port_str = NULL;
                SRPC_SAFE_CALL_PTR(port_oper_str, lyd_get_value(dst_port_operator_node), error_out);
                SRPC_SAFE_CALL_PTR(port_str, lyd_get_value(tcp_dst_port_node), error_out);
                port_operator_t port_opr = onm_tc_ace_port_oper_a2i(port_oper_str);
                error = port_str_to_port_attr(port_attr,NULL,NULL,port_str,port_opr,PORT_ATTR_DST,PORT_ATTR_PROTO_TCP);
                SRPC_SAFE_CALL_ERR(error, set_ace_port_single(new_ace_element, port_attr,DEFAULT_CHANGE_OPERATION), error_out);
                SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_port_operator(&new_ace_element, port_attr,DEFAULT_CHANGE_OPERATION), error_out);
                tcp_dst_port_node = NULL;
                free(port_attr);
            }
            if(udp_src_port_node){
                onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                const char* port_oper_str, *port_str = NULL;
                SRPC_SAFE_CALL_PTR(port_oper_str, lyd_get_value(src_port_operator_node), error_out);
                SRPC_SAFE_CALL_PTR(port_str, lyd_get_value(udp_src_port_node), error_out);
                port_operator_t port_opr = onm_tc_ace_port_oper_a2i(port_oper_str);
                error = port_str_to_port_attr(port_attr,NULL,NULL,port_str,port_opr,PORT_ATTR_SRC,PORT_ATTR_PROTO_UDP);
                SRPC_SAFE_CALL_ERR(error, set_ace_port_single(new_ace_element, port_attr,DEFAULT_CHANGE_OPERATION), error_out);
                SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_port_operator(&new_ace_element, port_attr,DEFAULT_CHANGE_OPERATION), error_out);

                udp_src_port_node = NULL;
                free(port_attr);
            }
            if(udp_dst_port_node){
                onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                const char* port_oper_str, *port_str = NULL;
                SRPC_SAFE_CALL_PTR(port_oper_str, lyd_get_value(dst_port_operator_node), error_out);
                SRPC_SAFE_CALL_PTR(port_str, lyd_get_value(udp_dst_port_node), error_out);
                port_operator_t port_opr = onm_tc_ace_port_oper_a2i(port_oper_str);
                error = port_str_to_port_attr(port_attr,NULL,NULL,port_str,port_opr,PORT_ATTR_DST,PORT_ATTR_PROTO_UDP);
                SRPC_SAFE_CALL_ERR(error, set_ace_port_single(new_ace_element, port_attr,DEFAULT_CHANGE_OPERATION), error_out);
                SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_port_operator(&new_ace_element, port_attr,DEFAULT_CHANGE_OPERATION), error_out);

                udp_dst_port_node = NULL;
                free(port_attr);
            }
            if(tcp_src_range_lower_port_node){
                onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                const char* port_oper_str =NULL, * lower_str = NULL, *upper_str = NULL;
                SRPC_SAFE_CALL_PTR(lower_str, lyd_get_value(tcp_src_range_lower_port_node), error_out);
                SRPC_SAFE_CALL_PTR(upper_str, lyd_get_value(tcp_src_range_upper_port_node), error_out);

                port_str_to_port_attr(port_attr, lower_str, upper_str, NULL, PORT_NOOP, PORT_ATTR_SRC,PORT_ATTR_PROTO_TCP);
                SRPC_SAFE_CALL_ERR(error, set_ace_port_range(new_ace_element, port_attr,DEFAULT_CHANGE_OPERATION), error_out);

                tcp_src_range_lower_port_node = NULL;
                tcp_src_range_upper_port_node = NULL;
                free(port_attr);
            }
            if(tcp_dst_range_lower_port_node){
                onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                const char* port_oper_str =NULL, * lower_str = NULL, *upper_str = NULL;
                port_oper_str = "range";
                SRPC_SAFE_CALL_PTR(lower_str, lyd_get_value(tcp_dst_range_lower_port_node), error_out);
                SRPC_SAFE_CALL_PTR(upper_str, lyd_get_value(tcp_dst_range_upper_port_node), error_out);

                port_str_to_port_attr(port_attr, lower_str, upper_str, NULL, PORT_NOOP, PORT_ATTR_DST,PORT_ATTR_PROTO_TCP);
                SRPC_SAFE_CALL_ERR(error, set_ace_port_range(new_ace_element, port_attr,DEFAULT_CHANGE_OPERATION), error_out);
                //SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_port_operator(&new_ace_element, port_attr,DEFAULT_CHANGE_OPERATION), error_out);

                tcp_dst_range_lower_port_node = NULL;
                tcp_dst_range_upper_port_node = NULL;
                free(port_attr);
            }
            if(udp_src_range_lower_port_node){
                onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                const char* port_oper_str =NULL, * lower_str = NULL, *upper_str = NULL;
                SRPC_SAFE_CALL_PTR(lower_str, lyd_get_value(udp_src_range_lower_port_node), error_out);
                SRPC_SAFE_CALL_PTR(upper_str, lyd_get_value(udp_src_range_upper_port_node), error_out);

                port_str_to_port_attr(port_attr, lower_str, upper_str, NULL, PORT_NOOP, PORT_ATTR_SRC,PORT_ATTR_PROTO_UDP);
                SRPC_SAFE_CALL_ERR(error, set_ace_port_range(new_ace_element, port_attr,DEFAULT_CHANGE_OPERATION), error_out);
                //SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_port_operator(&new_ace_element, port_attr,DEFAULT_CHANGE_OPERATION), error_out);

                udp_src_range_lower_port_node = NULL;
                udp_src_range_upper_port_node = NULL;
                free(port_attr);
            }
            if(udp_dst_range_lower_port_node){
                onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                const char* port_oper_str =NULL, * lower_str = NULL, *upper_str = NULL;
                SRPC_SAFE_CALL_PTR(lower_str, lyd_get_value(udp_dst_range_lower_port_node), error_out);
                SRPC_SAFE_CALL_PTR(upper_str, lyd_get_value(udp_dst_range_upper_port_node), error_out);

                port_str_to_port_attr(port_attr, lower_str, upper_str, NULL, PORT_NOOP, PORT_ATTR_DST,PORT_ATTR_PROTO_UDP);
                SRPC_SAFE_CALL_ERR(error, set_ace_port_range(new_ace_element, port_attr,DEFAULT_CHANGE_OPERATION), error_out);
                //SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_port_operator(&new_ace_element, port_attr,DEFAULT_CHANGE_OPERATION), error_out);

                udp_dst_range_lower_port_node = NULL;
                udp_dst_range_upper_port_node = NULL;
                free(port_attr);
            }

            if(icmp_code_node){
                const char* icmp_code_str = NULL;
                SRPC_SAFE_CALL_PTR(icmp_code_str, lyd_get_value(icmp_code_node), error_out);
                const uint8_t icmp_code = (uint8_t)atoi(icmp_code_str);
                SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_icmp_code(&new_ace_element, icmp_code,DEFAULT_CHANGE_OPERATION), error_out);
                icmp_code_node = NULL;
            }
            // set actions data
            if(action_forwarding_node){
                SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_action_forwarding(&new_ace_element, lyd_get_value(action_forwarding_node),DEFAULT_CHANGE_OPERATION), error_out);
                action_forwarding_node = NULL;
            }
            if(action_logging_node){
                SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_action_logging(&new_ace_element, lyd_get_value(action_logging_node),DEFAULT_CHANGE_OPERATION), error_out);
                action_logging_node = NULL;
            }


            // add ace list to main acl list
            ONM_TC_ACL_LIST_ADD_ELEMENT((*acl_hash_element)->acl.aces.ace, new_ace_element);
            
            // null new ace element
            new_ace_element = NULL;

            //move to next ace
            ace_list_node = srpc_ly_tree_get_list_next(ace_list_node);
        }
    }
    goto out;
error_out:
    error = -1;

out:
    return error;
}


int onm_tc_acls_list_from_ly(onm_tc_acl_hash_element_t** acl_hash, const struct lyd_node* acl_list_node){
    int error = 0;

    // make sure the hash is empty at the start
    assert(*acl_hash == NULL);

    // libyang
    struct lyd_node *acl_iter = (struct lyd_node*)acl_list_node;
    struct lyd_node *acl_name_node = NULL, *acl_type_node = NULL;
    struct lyd_node *aces_container_node = NULL;
    struct lyd_node *ace_list_node = NULL;
    struct lyd_node *ace_name_node = NULL;
    struct lyd_node *matches_container_node = NULL, *actions_container_node = NULL;

    struct lyd_node *match_eth_container_node = NULL, *match_ipv4_container_node = NULL, *match_ipv6_container_node = NULL, *match_tcp_container_node = NULL, *match_udp_container_node = NULL, *match_icmp_container_node = NULL;
    struct lyd_node *eth_dst_mac_addr_node = NULL, *eth_dst_mac_addr_mask_node = NULL, *eth_src_mac_addr_node = NULL, *eth_src_mac_addr_mask_node = NULL, *eth_ethtype_node = NULL;
    struct lyd_node *ipv4_src_network_node = NULL, *ipv4_dst_network_node = NULL;
    struct lyd_node *ipv6_src_network_node = NULL, *ipv6_dst_network_node = NULL;
    //tcp
    struct lyd_node *tcp_src_port_container_node = NULL, *tcp_dst_port_container_node = NULL;
    struct lyd_node *tcp_src_port_node = NULL, *tcp_dst_port_node = NULL,*tcp_src_range_lower_port_node = NULL,*tcp_dst_range_lower_port_node = NULL, *tcp_src_range_upper_port_node = NULL, *tcp_dst_range_upper_port_node = NULL;
    //udp
    struct lyd_node *udp_src_port_container_node = NULL, *udp_dst_port_container_node = NULL;
    struct lyd_node *udp_src_port_node = NULL, *udp_dst_port_node = NULL,*udp_src_range_lower_port_node = NULL,*udp_dst_range_lower_port_node = NULL, *udp_src_range_upper_port_node = NULL, *udp_dst_range_upper_port_node = NULL;
    // tcp or udp
    struct lyd_node *src_port_operator_node = NULL, *dst_port_operator_node = NULL;
    struct lyd_node *icmp_code_node = NULL;
    struct lyd_node *action_forwarding_node = NULL, *action_logging_node = NULL;


    // internal DS
    onm_tc_acl_hash_element_t* new_element = NULL;
    onm_tc_ace_element_t* new_ace_element = NULL;

    while (acl_iter) {
        // create new element
        new_element = onm_tc_acl_hash_element_new();

        onm_tc_acl_element_from_ly(&new_element,acl_iter);
        // add acl element to acls list
        error = onm_tc_acls_hash_add_acl_element(acl_hash, new_element);

        // set to NULL
        new_element = NULL;

        // move to next acl entry
        acl_iter = srpc_ly_tree_get_list_next(acl_iter);
    }

    goto out;
error_out:
    error = -1;

out:
    if (new_element) {
        onm_tc_acl_element_hash_free(&new_element);
    }

    return error;
}

void onm_tc_acls_list_print_debug(const onm_tc_acl_hash_element_t* acl_hash)
{
    const onm_tc_acl_hash_element_t *iter = NULL, *tmp = NULL;
    onm_tc_ace_element_t* ace_iter = NULL;
    SRPLG_LOG_INF(PLUGIN_NAME, "+ ACLs: ");
    HASH_ITER(hh, acl_hash, iter, tmp)
    {
        SRPLG_LOG_INF(PLUGIN_NAME, "| \t+ ACL %s:", iter->acl.name);
        SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\tName = %s (change operation %d)", iter->acl.name,iter->acl.name_change_op);
        SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\tACL ID = %d", iter->acl.acl_id);
        if(iter->acl.type){
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\tType = %s (change operation %d)", iter->acl.type,iter->acl.type_change_op);
        }
        
        SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\tACEs:");
        LL_FOREACH(iter->acl.aces.ace, ace_iter)
        {
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t+ ACE %s", ace_iter->ace.name);
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     ACE Name = %s (change operation %d)", ace_iter->ace.name,ace_iter->ace.name_change_op);
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     ACE Priority = %d", ace_iter->ace.priority);
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     ACE Handle = %d", ace_iter->ace.handle);
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     + Matches:");
            if(ace_iter->ace.matches.eth.source_address){
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Source mac address = %s (change operation %d)",
                ace_iter->ace.matches.eth.source_address,
                ace_iter->ace.matches.eth.source_address_change_op);
            }
            if(ace_iter->ace.matches.eth.source_address_mask){
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Source mac address mask = %s (change operation %d)",
                ace_iter->ace.matches.eth.source_address_mask,
                ace_iter->ace.matches.eth.source_address_mask_change_op);
            }
            if(ace_iter->ace.matches.eth.destination_address){
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Destination mac address = %s (change operation %d)",
                ace_iter->ace.matches.eth.destination_address,
                ace_iter->ace.matches.eth.destination_address_change_op);
            }
            if(ace_iter->ace.matches.eth.destination_address_mask){
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Destination mac address mask = %s (change operation %d)",
                ace_iter->ace.matches.eth.destination_address_mask,
                ace_iter->ace.matches.eth.destination_address_mask_change_op);
            }
            if(ace_iter->ace.matches.eth.ethertype != 0){
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- EtherType = %d (change operation %d)",
                ace_iter->ace.matches.eth.ethertype,
                ace_iter->ace.matches.eth.ethertype_change_op);
            }
            if(ace_iter->ace.matches.ipv4.source_network){
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Source IPv4 Network = %s (change operation %d)",
                ace_iter->ace.matches.ipv4.source_network,
                ace_iter->ace.matches.ipv4.source_network_change_op);
            }
            if(ace_iter->ace.matches.ipv4.destination_network){
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Destination IPv4 Network = %s (change operation %d)",
                ace_iter->ace.matches.ipv4.destination_network,
                ace_iter->ace.matches.ipv4.destination_network_change_op);
            }
            if(ace_iter->ace.matches.ipv6.source_network){
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Source IPv6 Network = %s (change operation %d)",
                ace_iter->ace.matches.ipv6.source_network,
                ace_iter->ace.matches.ipv6.source_network_change_op);
            }
            if(ace_iter->ace.matches.ipv6.destination_network){
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Destination IPv6 Network = %s (change operation %d)",
                ace_iter->ace.matches.ipv6.destination_network, ace_iter->ace.matches.ipv6.destination_network_change_op);
            }
            // TCP Source Port
            if (ace_iter->ace.matches.tcp.source_port.port != 0 ||
                (ace_iter->ace.matches.tcp.source_port.port_operator != PORT_NOOP)){
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- TCP Source Port = %d Operator = %d (change operation %d)",
                ace_iter->ace.matches.tcp.source_port.port, 
                ace_iter->ace.matches.tcp.source_port.port_operator,
                ace_iter->ace.matches.tcp.source_port.single_port_change_op);
            }
            // TCP Source Port Range
            if(ace_iter->ace.matches.tcp.source_port.lower_port != 0  || ace_iter->ace.matches.tcp.source_port.upper_port != 0)
            {
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- TCP Source Port Range = [%d-%d] Operator = %d (change operation %d)",
                ace_iter->ace.matches.tcp.source_port.lower_port, 
                ace_iter->ace.matches.tcp.source_port.upper_port,
                ace_iter->ace.matches.tcp.source_port.port_operator,
                ace_iter->ace.matches.tcp.source_port.range_port_change_op
                );
            }
            // UDP Source Port
            if (ace_iter->ace.matches.udp.source_port.port != 0 ||
                (ace_iter->ace.matches.udp.source_port.port_operator != PORT_NOOP)) {
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- UDP Source Port = %d Operator = %d (change operation %d)",
                ace_iter->ace.matches.udp.source_port.port,
                ace_iter->ace.matches.udp.source_port.port_operator,
                ace_iter->ace.matches.udp.source_port.single_port_change_op);
            }
            // UDP Source Port Range
            if (ace_iter->ace.matches.udp.source_port.lower_port != 0 || ace_iter->ace.matches.udp.source_port.upper_port != 0) {
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- UDP Source Port Range = [%d-%d] Operator = %d (change operation %d)",
                ace_iter->ace.matches.udp.source_port.lower_port,
                ace_iter->ace.matches.udp.source_port.upper_port,
                ace_iter->ace.matches.udp.source_port.port_operator,
                ace_iter->ace.matches.udp.source_port.range_port_change_op);
            }
            // TCP Destination Port
            if (ace_iter->ace.matches.tcp.destination_port.port != 0 ||
            (ace_iter->ace.matches.tcp.destination_port.port_operator != PORT_NOOP)) {
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- TCP Destination Port = %d Operator = %d (change operation %d)",
                ace_iter->ace.matches.tcp.destination_port.port,
                ace_iter->ace.matches.tcp.destination_port.port_operator,
                ace_iter->ace.matches.tcp.destination_port.single_port_change_op);
            }
            // TCP Destination Port Range
            if (ace_iter->ace.matches.tcp.destination_port.lower_port != 0 || ace_iter->ace.matches.tcp.destination_port.upper_port != 0) {
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- TCP Destination Port Range = [%d-%d] Operator = %d (change operation %d)",
                ace_iter->ace.matches.tcp.destination_port.lower_port,
                ace_iter->ace.matches.tcp.destination_port.upper_port,
                ace_iter->ace.matches.tcp.destination_port.port_operator,
                ace_iter->ace.matches.tcp.destination_port.range_port_change_op);
            }

            // UDP Destination Port
            if (ace_iter->ace.matches.udp.destination_port.port != 0 ||
                (ace_iter->ace.matches.udp.destination_port.port_operator != PORT_NOOP)) {
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- UDP Destination Port = %d Operator = %d (change operation %d)",
                ace_iter->ace.matches.udp.destination_port.port,
                ace_iter->ace.matches.udp.destination_port.port_operator,
                ace_iter->ace.matches.udp.destination_port.single_port_change_op);
            }

            // UDP Destination Port Range
            if (ace_iter->ace.matches.udp.destination_port.lower_port != 0 || ace_iter->ace.matches.udp.destination_port.upper_port != 0) {
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- UDP Destination Port Range = [%d-%d] Operator = %d (change operation %d)", 
                ace_iter->ace.matches.udp.destination_port.lower_port,
                ace_iter->ace.matches.udp.destination_port.upper_port,
                ace_iter->ace.matches.udp.destination_port.port_operator,
                ace_iter->ace.matches.udp.destination_port.range_port_change_op);
            }
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     + Actions:");{
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Action-Forwarding = %d (change operation %d)",
                ace_iter->ace.actions.forwarding,
                ace_iter->ace.actions.forwarding_change_op);
            }
            if(ace_iter->ace.actions.logging != 0){
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Action-Logging = %d (change operation %d)", 
                ace_iter->ace.actions.logging,
                ace_iter->ace.actions.logging_change_op);
            }
        }
    }
}
