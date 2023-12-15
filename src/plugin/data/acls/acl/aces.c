#include "plugin/types.h"
#include "../deps/uthash/utlist.h"
#include "aces.h"
#include "utils/memory.h"



//For testing
#include<stdio.h>

onm_tc_ace_element_t* onm_tc_ace_element_new(void)
{
    return NULL;
}

onm_tc_ace_element_t* onm_tc_ace_hash_element_new(void)
{
    onm_tc_ace_element_t* new_ace_element = NULL;

    new_ace_element = xmalloc(sizeof(onm_tc_ace_element_t));
    if (!new_ace_element)
        return NULL;

    // NULL all fields
    new_ace_element->ace = (onm_tc_ace_t) { 0 };

    return new_ace_element;
}

void onm_tc_ace_element_free(onm_tc_ace_element_t** el)
{
    //TODO fix this function to free all ACL and ACE elements
    if (*el) {
        // name
        if ((*el)->ace.name) {
            free((*el)->ace.name);
        }
        // TODO free ACE entries

        free(*el);
        *el = NULL;
    }
}

void onm_tc_ace_free (onm_tc_ace_element_t** ace)
{
    onm_tc_ace_element_t *iter = NULL, *tmp = NULL;

    LL_FOREACH_SAFE(*ace, iter, tmp)
    {
        // remove from list
        LL_DELETE(*ace, iter);

        // free element data
        onm_tc_ace_element_free(&iter);
    }
}

int onm_tc_ace_hash_element_set_ace_name(onm_tc_ace_element_t** el, const char* name)
{
    if ((*el)->ace.name) {
        FREE_SAFE((*el)->ace.name);
    }
    if (name) {
        (*el)->ace.name = xstrdup(name);
        return (*el)->ace.name == NULL;
    }

    return 0;
}

int onm_tc_ace_hash_element_set_match_src_mac_addr(onm_tc_ace_element_t** el, const char* mac_addr)
{
    if ((*el)->ace.matches.eth.source_mac_address) {
        FREE_SAFE((*el)->ace.matches.eth.source_mac_address);
    }
    if (mac_addr) {
        (*el)->ace.matches.eth.source_mac_address = xstrdup(mac_addr);
        (*el)->ace.matches.eth._is_set = 1;
        return (*el)->ace.matches.eth.source_mac_address == NULL;
    }

    return 0;
}

int onm_tc_ace_hash_element_set_match_src_mac_addr_mask(onm_tc_ace_element_t** el, const char* mask)
{
    if ((*el)->ace.matches.eth.source_mac_address_mask) {
        FREE_SAFE((*el)->ace.matches.eth.source_mac_address_mask);
    }
    if (mask) {
        (*el)->ace.matches.eth.source_mac_address_mask = xstrdup(mask);
        (*el)->ace.matches.eth._is_set = 1;
        return (*el)->ace.matches.eth.source_mac_address_mask == NULL;
    }

    return 0;
}

int onm_tc_ace_hash_element_set_match_dst_mac_addr(onm_tc_ace_element_t** el, const char* mac_addr)
{
    if ((*el)->ace.matches.eth.destination_mac_address) {
        FREE_SAFE((*el)->ace.matches.eth.destination_mac_address);
    }
    if (mac_addr) {
        (*el)->ace.matches.eth.destination_mac_address = xstrdup(mac_addr);
        (*el)->ace.matches.eth._is_set = 1;
        return (*el)->ace.matches.eth.destination_mac_address == NULL;
    }
    return 0;
}

int onm_tc_ace_hash_element_set_match_dst_mac_addr_mask(onm_tc_ace_element_t** el, const char* mask)
{
    if ((*el)->ace.matches.eth.destination_mac_address_mask) {
        FREE_SAFE((*el)->ace.matches.eth.destination_mac_address_mask);
    }
    if (mask) {
        (*el)->ace.matches.eth.destination_mac_address_mask = xstrdup(mask);
        (*el)->ace.matches.eth._is_set = 1;
        return (*el)->ace.matches.eth.destination_mac_address_mask == NULL;
    }
    return 0;
}

int onm_tc_ace_hash_element_set_match_eth_ethertype(onm_tc_ace_element_t** el, uint16_t ethertype)
{
    (*el)->ace.matches.eth.ethertype = ethertype;
    return 0;
}

int onm_tc_ace_hash_element_set_match_ipv4_src_network(onm_tc_ace_element_t** el, const char* network_addr)
{
    if ((*el)->ace.matches.ipv4.source_ipv4_network) {
        FREE_SAFE((*el)->ace.matches.ipv4.source_ipv4_network);
    }
    if (network_addr) {
        (*el)->ace.matches.ipv4.source_ipv4_network = xstrdup(network_addr);
        (*el)->ace.matches.ipv4._is_set = 1;
        return (*el)->ace.matches.ipv4.source_ipv4_network == NULL;
    }
    return 0;
}

int onm_tc_ace_hash_element_set_match_ipv4_dst_network(onm_tc_ace_element_t** el, const char* network_addr)
{
    if ((*el)->ace.matches.ipv4.destination_ipv4_network) {
        FREE_SAFE((*el)->ace.matches.ipv4.destination_ipv4_network);
    }
    if (network_addr) {
        (*el)->ace.matches.ipv4.destination_ipv4_network = xstrdup(network_addr);
        (*el)->ace.matches.ipv4._is_set = 1;
        return (*el)->ace.matches.ipv4.destination_ipv4_network == NULL;
    }
    return 0;
}

int onm_tc_ace_hash_element_set_match_ipv6_src_network(onm_tc_ace_element_t** el, const char* network_addr)
{
    if ((*el)->ace.matches.ipv6.source_ipv6_network) {
        FREE_SAFE((*el)->ace.matches.ipv6.source_ipv6_network);
    }
    if (network_addr) {
        (*el)->ace.matches.ipv6.source_ipv6_network = xstrdup(network_addr);
        (*el)->ace.matches.ipv6._is_set = 1;
        return (*el)->ace.matches.ipv6.source_ipv6_network == NULL;
    }
    return 0;
}

int onm_tc_ace_hash_element_set_match_ipv6_dst_network(onm_tc_ace_element_t** el, const char* network_addr)
{
    if ((*el)->ace.matches.ipv6.destination_ipv6_network) {
        FREE_SAFE((*el)->ace.matches.ipv6.destination_ipv6_network);
    }
    if (network_addr) {
        (*el)->ace.matches.ipv6.destination_ipv6_network = xstrdup(network_addr);
        (*el)->ace.matches.ipv6._is_set = 1;
        return (*el)->ace.matches.ipv6.destination_ipv6_network == NULL;
    }
    return 0;
}

int onm_tc_ace_hash_element_set_match_icmp_code(onm_tc_ace_element_t** el, uint8_t icmp_code)
{
    (*el)->ace.matches.icmp.code = icmp_code;
    (*el)->ace.matches.icmp._is_set = 1;
    return 0;
}

int onm_tc_ace_hash_element_set_action_forwarding(onm_tc_ace_element_t** el, const char* action)
{
    if (action) {
        if (strcmp(action,"accept") == 0)
        {
            (*el)->ace.actions.forwarding = FORWARD_ACCEPT;
        }
        else if (strcmp(action,"drop") == 0)
        {
            (*el)->ace.actions.forwarding = FORWARD_DROP;
        }
        else if (strcmp(action,"reject") == 0)
        {
            (*el)->ace.actions.forwarding = FORWARD_REJECT;
        }
    }
    
    return 0;
}

// TODO add action str to identity enum translation
int onm_tc_ace_hash_element_set_action_logging(onm_tc_ace_element_t** el, const char* action)
{
    //TODO: fix data type
    /*
    if ((*el)->ace.actions.logging) {
        FREE_SAFE((*el)->ace.actions.logging);
    }
    if (action) {
        (*el)->ace.actions.logging = xstrdup(action);
        return (*el)->ace.actions.logging == NULL;
    }
    */
    return 0;
}

port_operation_t onm_tc_ace_port_oper_a2i(char * oper_str)
{
    port_operation_t operation = PORT_NOOP;
    if (strcmp(oper_str,"eq") == 0)
    {
        operation = PORT_EQUAL;
    }
    else if (strcmp(oper_str,"lte") == 0)
    {
        operation = PORT_LTE;
    }
    else if (strcmp(oper_str,"gte") == 0)
    {
        operation = PORT_GTE;
    }
    else if (strcmp(oper_str,"neq") == 0)
    {
        operation = PORT_NOT_EQUAL;
    }
    else if (strcmp(oper_str,"range") == 0)
    {
        operation = PORT_RANGE;
    }
    return operation;
}

int set_ace_port_single(onm_tc_ace_element_t* el, port_operation_t operation, int direction, int proto, onm_tc_port_attributes_t* port_attr) {
    if (proto == PORT_ATTR_PROTO_TCP) {
        if (direction == PORT_ATTR_SRC) {
            el->ace.matches.tcp.source_port.port = port_attr->port;
            el->ace.matches.tcp.source_port.operation = operation;
            el->ace.matches.tcp._is_set = 1;
        } else {
            el->ace.matches.tcp.destination_port.port = port_attr->port;
            el->ace.matches.tcp.destination_port.operation = operation;
            el->ace.matches.tcp._is_set = 1;
        }
    } else if (proto == PORT_ATTR_PROTO_UDP) {
        if (direction == PORT_ATTR_SRC) {
            el->ace.matches.udp.source_port.port = port_attr->port;
            el->ace.matches.udp.source_port.operation = operation;
            el->ace.matches.udp._is_set = 1;
        } else {
            el->ace.matches.udp.destination_port.port = port_attr->port;
            el->ace.matches.udp.destination_port.operation = operation;
            el->ace.matches.udp._is_set = 1;
        }
    }
    return 0;
}

int set_ace_port_range(onm_tc_ace_element_t* el, port_operation_t operation, int direction, int proto, onm_tc_port_attributes_t* port_attr) {
    if (proto == PORT_ATTR_PROTO_TCP) {
        if (direction == PORT_ATTR_SRC) {
            el->ace.matches.tcp.source_port.lower_port = port_attr->lower_port;
            el->ace.matches.tcp.source_port.upper_port = port_attr->upper_port;
            el->ace.matches.tcp.source_port.operation = operation;
            el->ace.matches.tcp._is_set = 1;
        } else {
            el->ace.matches.tcp.destination_port.lower_port = port_attr->lower_port;
            el->ace.matches.tcp.destination_port.upper_port = port_attr->upper_port;
            el->ace.matches.tcp.destination_port.operation = operation;
            el->ace.matches.tcp._is_set = 1;
        }
    } else if (proto == PORT_ATTR_PROTO_UDP) {
        if (direction == PORT_ATTR_SRC) {
            el->ace.matches.udp.source_port.lower_port = port_attr->lower_port;
            el->ace.matches.udp.source_port.upper_port = port_attr->upper_port;
            el->ace.matches.udp.source_port.operation = operation;
            el->ace.matches.udp._is_set = 1;
        } else {
            el->ace.matches.udp.destination_port.lower_port = port_attr->lower_port;
            el->ace.matches.udp.destination_port.upper_port = port_attr->upper_port;
            el->ace.matches.udp.destination_port.operation = operation;
            el->ace.matches.udp._is_set = 1;
        }
    }
    return 0;
}

int onm_tc_ace_hash_element_set_match_port(onm_tc_ace_element_t** el, onm_tc_port_attributes_t* port_attr) {
    port_operation_t operation = onm_tc_ace_port_oper_a2i(port_attr->operation_str);

    if (operation != PORT_RANGE) {
        return set_ace_port_single(*el, operation, port_attr->direction, port_attr->proto, port_attr);
    } else {
        return set_ace_port_range(*el, operation, port_attr->direction, port_attr->proto, port_attr);
    }
}