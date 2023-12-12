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
    Libyang conversion functions.
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


int onm_tc_acl_hash_element_set_name(onm_tc_acl_hash_element_t** el, const char* name)
{
    if ((*el)->acl.name) {
        FREE_SAFE((*el)->acl.name);
    }
    if (name) {
        (*el)->acl.name = xstrdup(name);
        return (*el)->acl.name == NULL;
    }

    return 0;
}

int onm_tc_acl_hash_element_set_type(onm_tc_acl_hash_element_t** el, const char* type)
{
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

void onm_tc_acl_hash_element_free(onm_tc_acl_hash_element_t** el)
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

        //attachment points TODO handeld on a seperate function

        // ace list
        // TODO add all ACE entries
        // TODO fix data type
        if ((*el)->acl.aces.ace) {
            ONM_TC_ACL_LIST_FREE((*el)->acl.aces.ace);
        }
        // element data
        free(*el);
        *el = NULL;
    }
}

int onm_tc_acl_hash_from_ly(onm_tc_acl_hash_element_t** acl_hash, const struct lyd_node* acl_list_node)
{
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
    struct lyd_node *tcp_src_port_container_node = NULL, *tcp_dst_port_container_node = NULL;
    struct lyd_node *tcp_src_port_node = NULL, *tcp_dst_port_node = NULL;
    struct lyd_node *udp_src_port_container_node = NULL, *udp_dst_port_container_node = NULL;
    struct lyd_node *udp_src_port_node = NULL, *udp_dst_port_node = NULL;
    struct lyd_node *icmp_code_node = NULL;
    struct lyd_node *action_forwarding_node = NULL, *action_logging_node = NULL;


    // internal DS
    onm_tc_acl_hash_element_t* new_element = NULL;
    onm_tc_ace_element_t* new_ace_element = NULL;

    while (acl_iter) {
        // create new element
        new_element = onm_tc_acl_hash_element_new();

        // get existing nodes
        SRPC_SAFE_CALL_PTR(acl_name_node, srpc_ly_tree_get_child_leaf(acl_iter, "name"), error_out);
        acl_type_node = srpc_ly_tree_get_child_leaf(acl_iter, "type");
        aces_container_node = srpc_ly_tree_get_child_container(acl_iter, "aces");

        //set data
        if (acl_name_node){
            SRPC_SAFE_CALL_ERR(error, onm_tc_acl_hash_element_set_name(&new_element, lyd_get_value(acl_name_node)), error_out);  
        }
        if (acl_type_node){
            SRPC_SAFE_CALL_ERR(error, onm_tc_acl_hash_element_set_type(&new_element, lyd_get_value(acl_type_node)), error_out);
        }

        if (aces_container_node){
            ace_list_node = srpc_ly_tree_get_child_list(aces_container_node, "ace");

            // init ace list
            ONM_TC_ACL_LIST_NEW(new_element->acl.aces.ace);

            while(ace_list_node){
                // add new ace element
                new_ace_element = onm_tc_ace_hash_element_new();

                // fetch ace nodes
                SRPC_SAFE_CALL_PTR(ace_name_node, srpc_ly_tree_get_child_leaf(ace_list_node, "name"), error_out);
                matches_container_node = srpc_ly_tree_get_child_container(ace_list_node, "matches");
                actions_container_node = srpc_ly_tree_get_child_container(ace_list_node, "actions");

                //parse ace data
                if (ace_name_node){
                    SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_ace_name(&new_ace_element, lyd_get_value(ace_name_node)), error_out);
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
                            //TODO add support for port range
                            tcp_src_port_node = srpc_ly_tree_get_child_leaf(tcp_src_port_container_node, "port");
                            tcp_src_port_container_node = NULL;
                        }
                        if (tcp_dst_port_container_node){
                            //TODO add support for port range
                            tcp_dst_port_node = srpc_ly_tree_get_child_leaf(tcp_dst_port_container_node, "port");
                            tcp_dst_port_container_node = NULL;
                        }
                    }

                    if (match_udp_container_node){
                        udp_src_port_container_node = srpc_ly_tree_get_child_container(match_udp_container_node, "source-port");
                        udp_dst_port_container_node = srpc_ly_tree_get_child_container(match_udp_container_node, "destination-port");
                        match_udp_container_node = NULL;
                        if (udp_src_port_container_node){
                            //TODO add support for port range
                            udp_src_port_node = srpc_ly_tree_get_child_leaf(udp_src_port_container_node, "port");
                            udp_src_port_container_node = NULL;
                        }
                        if (udp_dst_port_container_node){
                            //TODO add support for port range
                            udp_dst_port_node = srpc_ly_tree_get_child_leaf(udp_dst_port_container_node, "port");
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
                    SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_src_mac_addr(&new_ace_element, lyd_get_value(eth_src_mac_addr_node)), error_out);
                    eth_src_mac_addr_node = NULL;
                }
                if(eth_src_mac_addr_mask_node){
                    SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_src_mac_addr_mask(&new_ace_element, lyd_get_value(eth_src_mac_addr_mask_node)), error_out);
                    eth_src_mac_addr_mask_node = NULL;
                }
                if(eth_dst_mac_addr_node){
                    SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_dst_mac_addr(&new_ace_element, lyd_get_value(eth_dst_mac_addr_node)), error_out);
                    eth_dst_mac_addr_node = NULL;
                }
                if(eth_dst_mac_addr_mask_node){
                    SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_dst_mac_addr_mask(&new_ace_element, lyd_get_value(eth_dst_mac_addr_mask_node)), error_out);
                    eth_dst_mac_addr_mask_node = NULL;
                }
                if(eth_ethtype_node){
                    const char* ethertype_str = NULL;
                    SRPC_SAFE_CALL_PTR(ethertype_str, lyd_get_value(eth_ethtype_node), error_out);
                    uint16_t ether_type;
                    if (ll_proto_a2n(&ether_type, ethertype_str))
                    {
                        SRPLG_LOG_ERR(PLUGIN_NAME, "ACE %s Failed to set specified EtherType for L2 match",new_ace_element->ace.name);
                    }
                    SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_eth_ethertype(&new_ace_element, ether_type), error_out);
                    eth_ethtype_node = NULL;
                }
                if(ipv4_src_network_node){
                    SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_ipv4_src_network(&new_ace_element, lyd_get_value(ipv4_src_network_node)), error_out);
                    ipv4_src_network_node = NULL;
                }
                if(ipv4_dst_network_node){
                    SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_ipv4_dst_network(&new_ace_element, lyd_get_value(ipv4_dst_network_node)), error_out);
                    ipv4_dst_network_node = NULL;
                }
                if(ipv6_src_network_node){
                    SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_ipv6_src_network(&new_ace_element, lyd_get_value(ipv6_src_network_node)), error_out);
                    ipv6_src_network_node = NULL;
                }
                if(ipv6_dst_network_node){
                    SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_ipv6_dst_network(&new_ace_element, lyd_get_value(ipv6_dst_network_node)), error_out);
                    ipv6_dst_network_node = NULL;
                }
                if(tcp_src_port_node){
                    //TODO Add support for port range
                    const char* tcp_src_port_str = NULL;
                    SRPC_SAFE_CALL_PTR(tcp_src_port_str, lyd_get_value(tcp_src_port_node), error_out);
                    const uint16_t src_port = (uint16_t)atoi(tcp_src_port_str);
                    SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_tcp_src_port(&new_ace_element, src_port), error_out);
                    tcp_src_port_node = NULL;
                }
                if(tcp_dst_port_node){
                    //TODO Add support for port range
                    const char* tcp_dst_port_str = NULL;
                    SRPC_SAFE_CALL_PTR(tcp_dst_port_str, lyd_get_value(tcp_dst_port_node), error_out);

                    const uint16_t dst_port = (uint16_t)atoi(tcp_dst_port_str);
                    SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_tcp_dst_port(&new_ace_element, dst_port), error_out);
                    tcp_dst_port_node = NULL;
                }
                if(udp_src_port_node){
                    //TODO Add support for port range
                    const char* udp_src_port_str = NULL;
                    SRPC_SAFE_CALL_PTR(udp_src_port_str, lyd_get_value(udp_src_port_node), error_out);

                    const uint16_t src_port = (uint16_t)atoi(udp_src_port_str);
                    SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_udp_src_port(&new_ace_element, src_port), error_out);
                    udp_src_port_node = NULL;
                }
                if(udp_dst_port_node){
                    //TODO Add support for port range
                    const char* udp_dst_port_str = NULL;
                    SRPC_SAFE_CALL_PTR(udp_dst_port_str, lyd_get_value(udp_dst_port_node), error_out);
                    const uint16_t dst_port = (uint16_t)atoi(udp_dst_port_str);
                    SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_udp_dst_port(&new_ace_element, dst_port), error_out);
                    udp_dst_port_node = NULL;
                }
                if(icmp_code_node){
                    const char* icmp_code_str = NULL;
                    SRPC_SAFE_CALL_PTR(icmp_code_str, lyd_get_value(icmp_code_node), error_out);
                    const uint8_t icmp_code = (uint8_t)atoi(icmp_code_str);
                    SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_icmp_code(&new_ace_element, icmp_code), error_out);
                    icmp_code_node = NULL;
                }
                // set actions data
                if(action_forwarding_node){
                    SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_action_forwarding(&new_ace_element, lyd_get_value(action_forwarding_node)), error_out);
                    printf("set action to of %s to %s\n",new_ace_element->ace.name,lyd_get_value(action_forwarding_node));
                    action_forwarding_node = NULL;
                }
                if(action_logging_node){
                    SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_action_logging(&new_ace_element, lyd_get_value(action_logging_node)), error_out);
                    action_logging_node = NULL;
                }


                // add ace list to main acl list
                ONM_TC_ACL_LIST_ADD_ELEMENT(new_element->acl.aces.ace, new_ace_element);
                
                // null new ace element
                new_ace_element = NULL;

                //move to next ace
                ace_list_node = srpc_ly_tree_get_list_next(ace_list_node);
            }
        }

        // add element to the hash
        onm_tc_acl_hash_add_element(acl_hash, new_element);

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
        //TODO fix this function not cause a memeory leak, not all data are freed now
        onm_tc_acl_hash_element_free(&new_element);
    }

    return error;
}

void onm_tc_acl_hash_print_debug(const onm_tc_acl_hash_element_t* acl_hash)
{
    const onm_tc_acl_hash_element_t *iter = NULL, *tmp = NULL;
    onm_tc_ace_element_t* ace_iter = NULL;
    SRPLG_LOG_INF(PLUGIN_NAME, "+ ACLs: ");
    HASH_ITER(hh, acl_hash, iter, tmp)
    {
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
            if(ace_iter->ace.matches.eth.source_mac_address)
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Source mac address = %s", ace_iter->ace.matches.eth.source_mac_address);
            if(ace_iter->ace.matches.eth.source_mac_address_mask)
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Source mac address mask = %s", ace_iter->ace.matches.eth.source_mac_address_mask);
            if(ace_iter->ace.matches.eth.destination_mac_address)
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Destination mac address = %s", ace_iter->ace.matches.eth.destination_mac_address);
            if(ace_iter->ace.matches.eth.destination_mac_address_mask)
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Destination mac address mask = %s", ace_iter->ace.matches.eth.destination_mac_address_mask);
            if(ace_iter->ace.matches.eth.ethertype != 0)
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- EtherType = %d", ace_iter->ace.matches.eth.ethertype);
            if(ace_iter->ace.matches.ipv4.source_ipv4_network)
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Source IPv4 Network = %s", ace_iter->ace.matches.ipv4.source_ipv4_network);
            if(ace_iter->ace.matches.ipv4.destination_ipv4_network)
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Destination IPv4 Network = %s", ace_iter->ace.matches.ipv4.destination_ipv4_network);
            if(ace_iter->ace.matches.ipv6.source_ipv6_network)
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Source IPv6 Network = %s", ace_iter->ace.matches.ipv6.source_ipv6_network);
            if(ace_iter->ace.matches.ipv6.destination_ipv6_network)
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Destination IPv6 Network = %s", ace_iter->ace.matches.ipv6.destination_ipv6_network);
            if(ace_iter->ace.matches.tcp.source_port.port != 0)
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- TCP Source Port = %d", ace_iter->ace.matches.tcp.source_port.port);
            if(ace_iter->ace.matches.tcp.destination_port.port != 0)
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- TCP Destination Port = %d", ace_iter->ace.matches.tcp.destination_port.port);
            if(ace_iter->ace.matches.udp.source_port.port != 0)
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- UDP Source Port = %d", ace_iter->ace.matches.udp.source_port.port);
            if(ace_iter->ace.matches.udp.destination_port.port != 0)
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- UDP Destination Port = %d", ace_iter->ace.matches.udp.destination_port.port);
            
            //if(ace_iter->ace.actions.logging||ace_iter->ace.actions.forwarding){
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     + Actions:");
            //    if(ace_iter->ace.actions.forwarding)
                    SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Action-Forwarding = %d", ace_iter->ace.actions.forwarding);
                if(ace_iter->ace.actions.logging == 0)
                    SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Action-Logging = %d", ace_iter->ace.actions.logging);
            //}
        }
    }
}

int onm_tc_acl_hash_add_element(onm_tc_acl_hash_element_t** hash, onm_tc_acl_hash_element_t* new_element)
{
    onm_tc_acl_hash_element_t* found_element = NULL;

    HASH_FIND_STR(*hash, new_element->acl.name, found_element);

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

void onm_tc_acl_hash_free(onm_tc_acl_hash_element_t** hash)
{
    onm_tc_acl_hash_element_t *tmp = NULL, *element = NULL;

    HASH_ITER(hh, *hash, element, tmp)
    {
        HASH_DEL(*hash, element);
        onm_tc_acl_hash_element_free(&element);
    }

    *hash = NULL;
}

