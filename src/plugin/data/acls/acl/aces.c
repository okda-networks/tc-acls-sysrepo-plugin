#include "plugin/types.h"
#include "../deps/uthash/utlist.h"
#include "aces.h"
#include "utils/memory.h"

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
        return (*el)->ace.matches.eth.source_mac_address == NULL;
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
        return (*el)->ace.matches.eth.destination_mac_address == NULL;
    }
    return 0;
}

int onm_tc_ace_hash_element_set_match_ipv4_src_network(onm_tc_ace_element_t** el, const char* network_addr)
{
    if ((*el)->ace.matches.ipv4.source_ipv4_network) {
        FREE_SAFE((*el)->ace.matches.ipv4.source_ipv4_network);
    }
    if (network_addr) {
        (*el)->ace.matches.ipv4.source_ipv4_network = xstrdup(network_addr);
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
        return (*el)->ace.matches.ipv6.destination_ipv6_network == NULL;
    }
    return 0;
}

//TODO Add support for port range
int onm_tc_ace_hash_element_set_match_tcp_src_port(onm_tc_ace_element_t** el, uint16_t src_port)
{
    (*el)->ace.matches.tcp.source_port.port = src_port;
    return 0;
}

//TODO Add support for port range
int onm_tc_ace_hash_element_set_match_tcp_dst_port(onm_tc_ace_element_t** el, uint16_t dst_port)
{
    (*el)->ace.matches.tcp.destination_port.port= dst_port;
    return 0;
}

//TODO Add support for port range
int onm_tc_ace_hash_element_set_match_udp_src_port(onm_tc_ace_element_t** el, uint16_t src_port)
{
    (*el)->ace.matches.udp.source_port.port = src_port;
    return 0;
}

//TODO Add support for port range
int onm_tc_ace_hash_element_set_match_udp_dst_port(onm_tc_ace_element_t** el, uint16_t dst_port)
{
    (*el)->ace.matches.udp.destination_port.port = dst_port;
    return 0;
}

int onm_tc_ace_hash_element_set_match_icmp_code(onm_tc_ace_element_t** el, uint8_t icmp_code)
{
    (*el)->ace.matches.icmp.code = icmp_code;
    return 0;
}

// TODO add action str to identity enum translation
int onm_tc_ace_hash_element_set_action_forwarding(onm_tc_ace_element_t** el, const char* action)
{
    //TODO: fix data type
    /*
    if ((*el)->ace.actions.forwarding) {
        FREE_SAFE((*el)->ace.actions.forwarding);
    }
    if (action) {
        (*el)->ace.actions.forwarding = xstrdup(action);
        return (*el)->ace.actions.forwarding == NULL;
    }
    */
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