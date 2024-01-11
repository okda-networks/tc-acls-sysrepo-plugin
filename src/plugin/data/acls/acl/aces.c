#include "plugin/types.h"
#include "../deps/uthash/utlist.h"
#include "aces.h"
#include "utils/memory.h"
#include "plugin/context.h"
#include "plugin/common.h"
#include <linux/limits.h>

#include "plugin/data/acls/acl/linked_list.h"
#include "plugin/data/acls/acl.h"
#include "plugin/api/tcnl.h"

#include "plugin/data/acls/acl/linked_list.h"
#include <sysrepo/xpath.h>

//For testing
#include<stdio.h>

int onm_tc_ace_hash_element_set_ace_name(onm_tc_ace_element_t** el, const char* name, sr_change_oper_t change_operation)
{
    if ((*el)->ace.name) {
        FREE_SAFE((*el)->ace.name);
    }
    if (name) {
        (*el)->ace.name = xstrdup(name);
        (*el)->ace.name_change_op = change_operation;
        return (*el)->ace.name == NULL;
    }

    return 0;
}

int onm_tc_ace_hash_element_set_ace_priority(onm_tc_ace_element_t** el, const unsigned int priority, sr_change_oper_t change_operation)
{
    if (priority == 0){
        return -1;
    }
    (*el)->ace.priority = priority;
    (*el)->ace.prio_change_op = change_operation;

    return 0;
}

int onm_tc_ace_hash_element_set_ace_handle(onm_tc_ace_element_t** el, const unsigned int handle)
{
    if (handle == 0){
        return -1;
    }
    (*el)->ace.handle = handle;
    return 0;
}

int onm_tc_ace_hash_element_set_match_src_mac_addr(onm_tc_ace_element_t** el, const char* mac_addr,sr_change_oper_t change_operation)
{
    if ((*el)->ace.matches.eth.source_address) {
        FREE_SAFE((*el)->ace.matches.eth.source_address);
    }
    if (mac_addr) {
        (*el)->ace.matches.eth.source_address = xstrdup(mac_addr);
        (*el)->ace.matches.eth._is_set = 1;
        (*el)->ace.matches.eth.source_address_change_op = change_operation;
        return (*el)->ace.matches.eth.source_address == NULL;
    }

    return 0;
}

int onm_tc_ace_hash_element_set_match_src_mac_addr_mask(onm_tc_ace_element_t** el, const char* mask,sr_change_oper_t change_operation)
{
    if ((*el)->ace.matches.eth.source_address_mask) {
        FREE_SAFE((*el)->ace.matches.eth.source_address_mask);
    }
    if (mask) {
        (*el)->ace.matches.eth.source_address_mask = xstrdup(mask);
        (*el)->ace.matches.eth._is_set = 1;
        (*el)->ace.matches.eth.source_address_mask_change_op = change_operation;
        return (*el)->ace.matches.eth.source_address_mask == NULL;
    }

    return 0;
}

int onm_tc_ace_hash_element_set_match_dst_mac_addr(onm_tc_ace_element_t** el, const char* mac_addr,sr_change_oper_t change_operation)
{
    if ((*el)->ace.matches.eth.destination_address) {
        FREE_SAFE((*el)->ace.matches.eth.destination_address);
    }
    if (mac_addr) {
        (*el)->ace.matches.eth.destination_address = xstrdup(mac_addr);
        (*el)->ace.matches.eth._is_set = 1;
        (*el)->ace.matches.eth.destination_address_change_op = change_operation;
        return (*el)->ace.matches.eth.destination_address == NULL;
    }
    return 0;
}

int onm_tc_ace_hash_element_set_match_dst_mac_addr_mask(onm_tc_ace_element_t** el, const char* mask,sr_change_oper_t change_operation)
{
    if ((*el)->ace.matches.eth.destination_address_mask) {
        FREE_SAFE((*el)->ace.matches.eth.destination_address_mask);
    }
    if (mask) {
        (*el)->ace.matches.eth.destination_address_mask = xstrdup(mask);
        (*el)->ace.matches.eth._is_set = 1;
        (*el)->ace.matches.eth.destination_address_mask_change_op = change_operation;
        return (*el)->ace.matches.eth.destination_address_mask == NULL;
    }
    return 0;
}

int onm_tc_ace_hash_element_set_match_eth_ethertype(onm_tc_ace_element_t** el, uint16_t ethertype,sr_change_oper_t change_operation)
{
    (*el)->ace.matches.eth.ethertype = ethertype;
    (*el)->ace.matches.eth.ethertype_change_op = change_operation;
    return 0;
}

int onm_tc_ace_hash_element_set_match_ipv4_src_network(onm_tc_ace_element_t** el, const char* network_addr,sr_change_oper_t change_operation)
{
    if ((*el)->ace.matches.ipv4.source_network) {
        FREE_SAFE((*el)->ace.matches.ipv4.source_network);
    }
    if (network_addr) {
        (*el)->ace.matches.ipv4.source_network = xstrdup(network_addr);
        (*el)->ace.matches.ipv4._is_set = 1;
        (*el)->ace.matches.ipv4.source_network_change_op = change_operation;
        return (*el)->ace.matches.ipv4.source_network == NULL;
    }
    return 0;
}

int onm_tc_ace_hash_element_set_match_ipv4_dst_network(onm_tc_ace_element_t** el, const char* network_addr, sr_change_oper_t change_operation)
{
    if ((*el)->ace.matches.ipv4.destination_network) {
        FREE_SAFE((*el)->ace.matches.ipv4.destination_network);
    }
    if (network_addr) {
        (*el)->ace.matches.ipv4.destination_network = xstrdup(network_addr);
        (*el)->ace.matches.ipv4._is_set = 1;
        (*el)->ace.matches.ipv4.destination_network_change_op = change_operation;
        return (*el)->ace.matches.ipv4.destination_network == NULL;
    }
    return 0;
}

int onm_tc_ace_hash_element_set_match_ipv6_src_network(onm_tc_ace_element_t** el, const char* network_addr, sr_change_oper_t change_operation)
{
    if ((*el)->ace.matches.ipv6.source_network) {
        FREE_SAFE((*el)->ace.matches.ipv6.source_network);
    }
    if (network_addr) {
        (*el)->ace.matches.ipv6.source_network = xstrdup(network_addr);
        (*el)->ace.matches.ipv6._is_set = 1;
        (*el)->ace.matches.ipv6.source_network_change_op = change_operation;
        return (*el)->ace.matches.ipv6.source_network == NULL;
    }
    return 0;
}

int onm_tc_ace_hash_element_set_match_ipv6_dst_network(onm_tc_ace_element_t** el, const char* network_addr, sr_change_oper_t change_operation)
{
    if ((*el)->ace.matches.ipv6.destination_network) {
        FREE_SAFE((*el)->ace.matches.ipv6.destination_network);
    }
    if (network_addr) {
        (*el)->ace.matches.ipv6.destination_network = xstrdup(network_addr);
        (*el)->ace.matches.ipv6._is_set = 1;
         (*el)->ace.matches.ipv6.destination_network_change_op = change_operation;
        return (*el)->ace.matches.ipv6.destination_network == NULL;
    }
    return 0;
}

int onm_tc_ace_hash_element_set_match_icmp_code(onm_tc_ace_element_t** el, uint8_t icmp_code, sr_change_oper_t change_operation)
{
    (*el)->ace.matches.icmp.code = icmp_code;
    (*el)->ace.matches.icmp._is_set = 1;
    (*el)->ace.matches.icmp.code_change_op = change_operation;
    return 0;
}

int onm_tc_ace_hash_element_set_action_forwarding(onm_tc_ace_element_t** el, const char* action, sr_change_oper_t change_operation)
{
    if (!action) {
        return -1;
    }
    if (strstr(action,"accept") != NULL){
        (*el)->ace.actions.forwarding = FORWARD_ACCEPT;
    }
    else if (strstr(action,"drop") != NULL){
        (*el)->ace.actions.forwarding = FORWARD_DROP;
    }
    else if (strstr(action,"reject") != NULL){
        (*el)->ace.actions.forwarding = FORWARD_REJECT;
    }
    else {
        return -1;
    }

    (*el)->ace.actions.forwarding_change_op = change_operation;
    return 0;
}

// TODO add action str to identity enum translation
int onm_tc_ace_hash_element_set_action_logging(onm_tc_ace_element_t** el, const char* action, sr_change_oper_t change_operation)
{
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

port_operator_t onm_tc_ace_port_oper_a2i(const char * oper_str)
{
    if (!oper_str)
        return PORT_NOOP;

    port_operator_t operation = PORT_NOOP;
    if (strstr(oper_str,"neq") != NULL)
    {
        operation = PORT_NOT_EQUAL;
    }
    else if (strstr(oper_str,"eq") != NULL)
    {
        operation = PORT_EQUAL;
    }
    else if (strstr(oper_str,"lte") != NULL)
    {
        operation = PORT_LTE;
    }
    else if (strstr(oper_str,"gte") != NULL)
    {
        operation = PORT_GTE;
    }
    
    return operation;
}

// this function allows for empty values:
// if port value(s) not set in the input pointer, port_attr will have it set to DEFAULT_PORT_VALUE
// if port operator is not set, port_attr will get PORT_NOOP, unless uppor port is set, in that case it will be considered as a range operator
int port_str_to_port_attr (onm_tc_port_attributes_t *port_attr, const char * lower_str, const char * upper_str, const char * single_port_value_str, const port_operator_t single_port_opr,onm_tc_port_attr_direction_t direction, onm_tc_port_attr_proto_t proto)
{
    port_attr->single_port_operator = single_port_opr;
    port_attr->direction = direction;
    port_attr->proto = proto;


    if (single_port_value_str){
        const uint16_t port = (uint16_t)atoi(single_port_value_str);
        if (port == 0){
            return -1;
            // port 0 is not allowed to be set by user
        }

        port_attr->single_port_value = port;
        return 0;
    }
    if (single_port_opr != PORT_NOOP){
        port_attr->single_port_operator = single_port_opr;
    }
    if (lower_str){
        const uint16_t port = (uint16_t)atoi(lower_str);
        if (port == 0){
            return -1;
            // port 0 is not allowed to be set by user
        }
        port_attr->range_lower_port = port;
    }
    if (upper_str){ 
        const uint16_t port = (uint16_t)atoi(upper_str);
        if (port == 0){
            return -1;
            // port 0 not allowed to be set by user.
        }
        port_attr->range_upper_port = port;
    }
    return 0;
}

int set_ace_port_single(onm_tc_ace_element_t* el, onm_tc_port_attributes_t* port_attr, sr_change_oper_t change_operation) {
    if (port_attr->proto == PORT_ATTR_PROTO_TCP) {
        if (port_attr->direction == PORT_ATTR_SRC) {
            el->ace.matches.tcp.source_port.port = port_attr->single_port_value;
            el->ace.matches.tcp.source_port.single_port_change_op = change_operation;
            el->ace.matches.tcp._is_set = 1;
        } else {
            el->ace.matches.tcp.destination_port.port = port_attr->single_port_value;
            el->ace.matches.tcp.destination_port.single_port_change_op = change_operation;
            el->ace.matches.tcp._is_set = 1;
        }
    } else if (port_attr->proto == PORT_ATTR_PROTO_UDP) {
        if (port_attr->direction == PORT_ATTR_SRC) {
            el->ace.matches.udp.source_port.port = port_attr->single_port_value;
            el->ace.matches.udp.source_port.single_port_change_op = change_operation;
            el->ace.matches.udp._is_set = 1;
        } else {
            el->ace.matches.udp.destination_port.port = port_attr->single_port_value;
            el->ace.matches.udp.destination_port.single_port_change_op = change_operation;
            el->ace.matches.udp._is_set = 1;
        }
    }
    return 0;
}

int set_ace_port_range_lower_port(onm_tc_ace_element_t* el, onm_tc_port_attributes_t* port_attr, sr_change_oper_t change_operation) {
    if (port_attr->proto == PORT_ATTR_PROTO_TCP) {
        if (port_attr->direction == PORT_ATTR_SRC) {
            el->ace.matches.tcp.source_port.lower_port = port_attr->range_lower_port;
            el->ace.matches.tcp.source_port.range_port_change_op = change_operation;
            el->ace.matches.tcp._is_set = 1;
        } else {
            el->ace.matches.tcp.destination_port.lower_port = port_attr->range_lower_port;
            el->ace.matches.tcp.destination_port.range_port_change_op = change_operation;
            el->ace.matches.tcp._is_set = 1;
        }
    } else if (port_attr->proto == PORT_ATTR_PROTO_UDP) {
        if (port_attr->direction == PORT_ATTR_SRC) {
            el->ace.matches.udp.source_port.lower_port = port_attr->range_lower_port;
            el->ace.matches.udp.source_port.range_port_change_op = change_operation;
            el->ace.matches.udp._is_set = 1;
        } else {
            el->ace.matches.udp.destination_port.lower_port = port_attr->range_lower_port;
            el->ace.matches.udp.destination_port.range_port_change_op = change_operation;
            el->ace.matches.udp._is_set = 1;
        }
    }
    return 0;
}

int set_ace_port_range_upper_port(onm_tc_ace_element_t* el, onm_tc_port_attributes_t* port_attr, sr_change_oper_t change_operation) {
    if (port_attr->proto == PORT_ATTR_PROTO_TCP) {
        if (port_attr->direction == PORT_ATTR_SRC) {
            el->ace.matches.tcp.source_port.upper_port = port_attr->range_upper_port;
            el->ace.matches.tcp.source_port.range_port_change_op = change_operation;
            el->ace.matches.tcp._is_set = 1;
        } else {
            el->ace.matches.tcp.destination_port.upper_port = port_attr->range_upper_port;
            el->ace.matches.tcp.destination_port.range_port_change_op = change_operation;
            el->ace.matches.tcp._is_set = 1;
        }
    } else if (port_attr->proto == PORT_ATTR_PROTO_UDP) {
        if (port_attr->direction == PORT_ATTR_SRC) {
            el->ace.matches.udp.source_port.upper_port = port_attr->range_upper_port;
            el->ace.matches.udp.source_port.range_port_change_op = change_operation;
            el->ace.matches.udp._is_set = 1;
        } else {
            el->ace.matches.udp.destination_port.upper_port = port_attr->range_upper_port;
            el->ace.matches.udp.destination_port.range_port_change_op = change_operation;
            el->ace.matches.udp._is_set = 1;
        } 
    }
    return 0;
}

// TODO Fix error handling if needed
int set_ace_port_range(onm_tc_ace_element_t* el, onm_tc_port_attributes_t* port_attr, sr_change_oper_t change_operation) {
    set_ace_port_range_lower_port(el,port_attr,change_operation);
    set_ace_port_range_upper_port(el,port_attr,change_operation);
    return 0;
}


int onm_tc_ace_hash_element_set_match_port_operator(onm_tc_ace_element_t** el, onm_tc_port_attributes_t* port_attr, sr_change_oper_t change_operation) {
    if (port_attr->proto == PORT_ATTR_PROTO_TCP) {
        if (port_attr->direction == PORT_ATTR_SRC) {
            (*el)->ace.matches.tcp.source_port.port_operator = port_attr->single_port_operator;
            (*el)->ace.matches.tcp.source_port.single_port_change_op = change_operation;
        } else {
            (*el)->ace.matches.tcp.destination_port.port_operator = port_attr->single_port_operator;
            (*el)->ace.matches.tcp.destination_port.single_port_change_op = change_operation;
        }
        (*el)->ace.matches.tcp._is_set = 1;
    } else if (port_attr->proto == PORT_ATTR_PROTO_UDP) {
        if (port_attr->direction == PORT_ATTR_SRC) {
            (*el)->ace.matches.udp.source_port.port_operator = port_attr->single_port_operator;
            (*el)->ace.matches.udp.source_port.single_port_change_op = change_operation;
        } else {
            (*el)->ace.matches.udp.destination_port.port_operator = port_attr->single_port_operator;
            (*el)->ace.matches.udp.destination_port.single_port_change_op = change_operation;
        }
        (*el)->ace.matches.udp._is_set = 1;
    }
    return 0;
}

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

onm_tc_ace_element_t* onm_tc_get_ace_in_acl_list_by_priority(onm_tc_acl_hash_element_t* acl_hash, const char* acl_name, uint16_t ace_priority) 
{
    if (acl_name == NULL || ace_priority == 0 || acl_hash == NULL) {
        return NULL;
    }

    onm_tc_acl_hash_element_t* current_acl_element = onm_tc_acl_hash_get_element(&acl_hash,acl_name);
    if (current_acl_element)
    {
        // Search for the ACE in this ACL
        onm_tc_ace_element_t* current_ace_element;
        for (current_ace_element = current_acl_element->acl.aces.ace; current_ace_element != NULL; current_ace_element = current_ace_element->next) {
            if (current_ace_element->ace.priority == ace_priority) {
                return current_ace_element;
            }
        }
        return NULL; // ace not found
    }
    else {
        return NULL;// acl not found
    }   
}

onm_tc_ace_element_t* onm_tc_get_ace_in_acl_list_by_name(onm_tc_acl_hash_element_t* acl_hash, const char* acl_name, const char* ace_name) 
{
    if (acl_name == NULL || ace_name == NULL || acl_hash == NULL) {
        return NULL;
    }

    onm_tc_acl_hash_element_t* current_acl_element = onm_tc_acl_hash_get_element(&acl_hash,acl_name);
    if (current_acl_element)
    {
        // Search for the ACE in this ACL
        onm_tc_ace_element_t* current_ace_element;
        for (current_ace_element = current_acl_element->acl.aces.ace; current_ace_element != NULL; current_ace_element = current_ace_element->next) {
            if (strcmp(current_ace_element->ace.name, ace_name) == 0) {
                return current_ace_element;
            }
        }
        return NULL; // ace not found
    }
    else {
        return NULL;// acl not found
    }   
}

int acls_list_add_ace_element(onm_tc_acl_hash_element_t** acl_hash, const char* acl_name, onm_tc_ace_element_t* new_ace) 
{
    if (acl_hash == NULL || acl_name == NULL || new_ace == NULL) {
        printf("invalid input\n");
        return -1; // Invalid input
    }
    if ( *acl_hash == NULL)
    {
        printf("desired acl_hash doesn't exist\n");
    }

    // Find the specified ACL in the hash
    onm_tc_acl_hash_element_t* current_acl = onm_tc_acl_hash_get_element(acl_hash,acl_name);
    if(current_acl)
    {
        ONM_TC_ACL_LIST_ADD_ELEMENT(current_acl->acl.aces.ace, new_ace);
        return 0; // Success
    }
    else
    {
        return -1; // ACL not found
    }
}

char* extract_prev_list_name(const char *prev_list) {
    if (prev_list == NULL){
        return NULL;
    }
    char *value = NULL;
    if (strcmp(prev_list, "") == 0) {
        char *value = (char*)malloc(1);
        if (value != NULL) {
            value[0] = '\0';
        }
        return value;
    }
    
    char *start = strchr(prev_list, '\''); // Find the first single quote
    if (start != NULL) {
        start++; // Move past the quote to the start of the value
        const char *end = strchr(start, '\''); // Find the second single quote
        if (end != NULL) {
            int length = end - start;
            value = (char*)malloc(length + 1); 
            if (value != NULL) {
                strncpy(value, start, length);
                value[length] = '\0';
            }
        }
    }
    return value;
}

int ensure_ace_exists_in_acls_list(onm_tc_acl_hash_element_t** acl_hash, const char * acl_name, const char * ace_name){
    onm_tc_acl_hash_element_t* updated_acl = onm_tc_acl_hash_get_element(acl_hash,acl_name);
    onm_tc_ace_element_t* updated_ace = onm_tc_get_ace_in_acl_list_by_name((*acl_hash),acl_name,ace_name);
    int error = 0;
    // make sure acl exits in events acls list
    if (!updated_acl){
        // add new acl data
        SRPLG_LOG_INF(PLUGIN_NAME, "Change event ACL name %s is not present in events acl hash, creating new ACL element.",acl_name);
        updated_acl = onm_tc_acl_hash_element_new();
        error = onm_tc_acl_hash_element_set_name(&updated_acl, acl_name,DEFAULT_CHANGE_OPERATION);
        
        // add new updated_acl to change acls list
        error = onm_tc_acls_hash_add_acl_element(acl_hash,updated_acl);
    }

    // make sure ace exists
    if (!updated_ace){
        SRPLG_LOG_INF(PLUGIN_NAME, "[%s] Change event ACE name %s is not present in events acls hash, creating new ACE element.",acl_name, ace_name);
        updated_ace = onm_tc_ace_hash_element_new();
        SRPLG_LOG_INF(PLUGIN_NAME, "[%s] Change event didn't happen on ACE name %s, setting ACE name change operation to default.",acl_name, ace_name);
        error = onm_tc_ace_hash_element_set_ace_name(&updated_ace,ace_name,DEFAULT_CHANGE_OPERATION);
        error = acls_list_add_ace_element(acl_hash,acl_name,updated_ace);
    }
}

int reorder_events_acls_aces_from_change_ctx(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx){
    
    int error = 0;
    const struct lyd_node * node = change_ctx->node;
    const char *node_name = LYD_NAME(node);
	const char *node_value = lyd_get_value(node);
    char *prev_list_name = extract_prev_list_name(change_ctx->previous_list);
    onm_tc_ctx_t *ctx = (onm_tc_ctx_t *) priv;
    char change_path[PATH_MAX] = {0};
    char acl_name_buffer[100] = {0};
    char ace_name_buffer[100] = {0};
    onm_tc_acl_hash_element_t *iter = NULL, *tmp = NULL;
    onm_tc_ace_element_t* ace_iter = NULL;
    if (strcmp(node_name,"ace")==0){
        error = (lyd_path(change_ctx->node, LYD_PATH_STD, change_path, sizeof(change_path)) != NULL);
        srpc_extract_xpath_key_value(change_path, "acl", "name", acl_name_buffer, sizeof(acl_name_buffer));
        srpc_extract_xpath_key_value(change_path, "ace", "name", ace_name_buffer, sizeof(ace_name_buffer));
        SRPLG_LOG_INF(PLUGIN_NAME, "[%s][%s] Starting a new change event ACEs priority validation process", acl_name_buffer, ace_name_buffer);
        if (change_ctx->operation == SR_OP_CREATED || change_ctx->operation == SR_OP_MOVED || change_ctx->operation == SR_OP_DELETED){
            // copy all running acls list aces to events list.
            // iterate over running acls
            SRPLG_LOG_INF(PLUGIN_NAME, "[PRIO VALIDATION] Copying running acls list to events acls list");
            HASH_ITER(hh, ctx->running_acls_list, iter, tmp)
            {
                // if the running acl name matches change event acl name
                if (strcmp(iter->acl.name,acl_name_buffer)==0){
                    LL_FOREACH(iter->acl.aces.ace, ace_iter){
                        // check if ace name is already added to events list
                        onm_tc_ace_element_t* events_ace = onm_tc_get_ace_in_acl_list_by_name(ctx->events_acls_list,acl_name_buffer,ace_iter->ace.name);
                        if (!events_ace){
                            // add ace to events list.
                            ensure_ace_exists_in_acls_list(&ctx->events_acls_list, acl_name_buffer,ace_iter->ace.name);
                        }
                    }
                }
            }
            // done copy
            //onm_tc_acls_list_print_debug(ctx->running_acls_list);
            // iterate over events acls list to order them according to user order
            SRPLG_LOG_INF(PLUGIN_NAME, "[PRIO VALIDATION] Reording aces in events list");
            HASH_ITER(hh, ctx->events_acls_list, iter, tmp)
            {
                // if the events acl name matches with change event acl name and its not a new acl
                if (strcmp(iter->acl.name,acl_name_buffer)==0 && iter->acl.name_change_op != SR_OP_CREATED){
                    LL_FOREACH(iter->acl.aces.ace, ace_iter){
                        if (change_ctx->operation != SR_OP_DELETED){
                            if (strcmp(ace_iter->ace.name,prev_list_name)==0 || strcmp(prev_list_name,"")==0){                            
                                // get the reordered ace
                                onm_tc_ace_element_t * event_ace = onm_tc_get_ace_in_acl_list_by_name(ctx->events_acls_list,acl_name_buffer,ace_name_buffer);
                                // if ace is not not found (after copy of running aces to events list), it means that the ace is created SR_OP_CREATED not moved
                                if (!event_ace){
                                    // create the ace and get its pointer.
                                    ensure_ace_exists_in_acls_list(&ctx->events_acls_list,acl_name_buffer,ace_name_buffer);
                                    onm_tc_ace_element_t * event_ace = onm_tc_get_ace_in_acl_list_by_name(ctx->events_acls_list,acl_name_buffer,ace_name_buffer);
                                    // change the name change op to SR_OP_CREATED
                                    onm_tc_ace_hash_element_set_ace_name(&event_ace,ace_name_buffer,SR_OP_CREATED);
                                    // delete the ace from its current position and re-order it.
                                    LL_DELETE(ctx->events_acls_list->acl.aces.ace,event_ace);
                                    if (strcmp(prev_list_name,"")==0){
                                        // ace is ordered first in the list
                                        LL_PREPEND(ctx->events_acls_list->acl.aces.ace,event_ace);
                                    }
                                    else {
                                        if (ace_iter->next == event_ace){
                                            SRPLG_LOG_ERR(PLUGIN_NAME, "[PRIO VALIDATION] Bad ACE moved event, trying to set ace %s next element to itself", event_ace->ace.name);
                                            return -1;
                                        }
                                        // set ace user order
                                        event_ace->next = ace_iter->next;
                                        ace_iter->next = event_ace; 
                                    }  
                                }
                                // ace is found, this means it was moved
                                else {
                                    LL_DELETE(ctx->events_acls_list->acl.aces.ace,event_ace);
                                    if (strcmp(prev_list_name,"")==0){
                                        // ace is ordered first in the list
                                        LL_PREPEND(ctx->events_acls_list->acl.aces.ace,event_ace);
                                    }
                                    else {
                                        if (ace_iter->next == event_ace){
                                            SRPLG_LOG_ERR(PLUGIN_NAME, "[PRIO VALIDATION] Bad ACE moved event, trying to set ace %s next element to itself", event_ace->ace.name);
                                            return -1;
                                        }
                                        // set ace user order
                                        event_ace->next = ace_iter->next;
                                        ace_iter->next = event_ace;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            SRPLG_LOG_INF(PLUGIN_NAME, "[PRIO VALIDATION] Setting events list aces priority values");
            // iterate again over events acls list to set new order priority
            uint16_t ace_prio_counter = 0;
            HASH_ITER(hh, ctx->events_acls_list, iter, tmp)
            {
                if (strcmp(iter->acl.name,acl_name_buffer)==0){
                    LL_FOREACH(iter->acl.aces.ace, ace_iter){
                        // don't assign new priority order to deleted aces
                        if (ace_iter->ace.name_change_op!=SR_OP_DELETED){
                            ace_prio_counter +=10;
                            onm_tc_ace_hash_element_set_ace_priority(&ace_iter,ace_prio_counter,SR_OP_MOVED);
                            onm_tc_ace_hash_element_set_ace_handle(&ace_iter,DEFAULT_TCM_HANDLE);
                        }
                        
                    }
                }
            }
        }
        return 0;

    }
}

int remove_unchanged_priority_aces_from_events_list(void *priv){
    onm_tc_acl_hash_element_t *iter = NULL, *tmp = NULL;
    onm_tc_ace_element_t* ace_iter = NULL;
    onm_tc_ctx_t *ctx = (onm_tc_ctx_t *) priv;
    // iterate one last time to delete unchanged priority aces
    SRPLG_LOG_INF(PLUGIN_NAME, "[PRIO VALIDATION] Removing unchanged priority aces from events list");
    HASH_ITER(hh, ctx->events_acls_list, iter, tmp)
    {
        LL_FOREACH(iter->acl.aces.ace, ace_iter){
            onm_tc_ace_element_t* running_ace = onm_tc_get_ace_in_acl_list_by_name(ctx->running_acls_list,iter->acl.name,ace_iter->ace.name);
            if (running_ace){
                if (running_ace->ace.priority == ace_iter->ace.priority && ace_iter->ace.name_change_op == DEFAULT_CHANGE_OPERATION){
                    // ace order didn't change
                    // delete the ace from change list
                    // TODO free ace memory after delete
                    LL_DELETE(ctx->events_acls_list->acl.aces.ace,ace_iter);
                }
            }
        }
    }
}

int events_acls_hash_update_ace_element_from_change_ctx(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx)
{
    int error = 0;
    const struct lyd_node * node = change_ctx->node;
    const char *node_name = LYD_NAME(node);
	const char *node_value = lyd_get_value(node);
    onm_tc_ctx_t *ctx = (onm_tc_ctx_t *) priv;
    char change_path[PATH_MAX] = {0};
    char acl_name_buffer[100] = {0};
    char ace_name_buffer[100] = {0};

    if (node_value){
        error = (lyd_path(change_ctx->node, LYD_PATH_STD, change_path, sizeof(change_path)) != NULL);
        SRPC_SAFE_CALL_ERR(error, srpc_extract_xpath_key_value(change_path, "acl", "name", acl_name_buffer, sizeof(acl_name_buffer)), error_out);
        SRPC_SAFE_CALL_ERR(error, srpc_extract_xpath_key_value(change_path, "ace", "name", ace_name_buffer, sizeof(ace_name_buffer)), error_out);

        onm_tc_acl_hash_element_t* updated_acl = onm_tc_acl_hash_get_element(&ctx->events_acls_list,acl_name_buffer);
        onm_tc_ace_element_t* updated_ace = onm_tc_get_ace_in_acl_list_by_name(ctx->events_acls_list,acl_name_buffer,ace_name_buffer);
        onm_tc_ace_element_t* running_ace = onm_tc_get_ace_in_acl_list_by_name(ctx->running_acls_list,acl_name_buffer,ace_name_buffer);
        // make sure acl exits in events acls list
        if (!updated_acl)
        {
            // add new acl data
            SRPLG_LOG_INF(PLUGIN_NAME, "Change event ACL name %s is not present in events acl hash, creating new ACL element.",acl_name_buffer);
            updated_acl = onm_tc_acl_hash_element_new();
            SRPC_SAFE_CALL_ERR(error, onm_tc_acl_hash_element_set_name(&updated_acl, acl_name_buffer,DEFAULT_CHANGE_OPERATION), error_out);
            
            // add new updated_acl to change acls list
            onm_tc_acls_hash_add_acl_element(&ctx->events_acls_list,updated_acl);
        }

        // make sure ace exists
        if (!updated_ace)
        {
            SRPLG_LOG_INF(PLUGIN_NAME, "[%s] Change event ACE name %s is not present in events acls hash, creating new ACE element.",acl_name_buffer,ace_name_buffer);
            updated_ace = onm_tc_ace_hash_element_new();
            // if the change event happened on the ace name.
            if (strcmp(node_name,"name")==0){
                SRPLG_LOG_INF(PLUGIN_NAME, "[%s] Change event happned on ACE name %s, setting ACE name operation to %d.",acl_name_buffer,ace_name_buffer,change_ctx->operation);
                onm_tc_ace_hash_element_set_ace_name(&updated_ace,node_value,change_ctx->operation);
            }
            else {
                SRPLG_LOG_INF(PLUGIN_NAME, "[%s] Change event didn't happen on ACE name %s, setting ACE name change operation to default.",acl_name_buffer,ace_name_buffer);
                onm_tc_ace_hash_element_set_ace_name(&updated_ace,ace_name_buffer,DEFAULT_CHANGE_OPERATION);
            }
            // if the updated ace exists in the running_acls list, set the same ace priority
            if (running_ace){
                SRPLG_LOG_INF(PLUGIN_NAME, "[%s] Change event ACE name %s has a corresponding ACE in running acls list, setting ACE priority to %d.",acl_name_buffer,ace_name_buffer,running_ace->ace.priority);
                onm_tc_ace_hash_element_set_ace_priority(&updated_ace,running_ace->ace.priority,DEFAULT_CHANGE_OPERATION);
                onm_tc_ace_hash_element_set_ace_handle(&updated_ace,running_ace->ace.handle);
            }
            else {
                SRPLG_LOG_INF(PLUGIN_NAME, "[%s] Change event ACE name %s has no corresponding ACE in running acls list, setting ACE priority to 0.",acl_name_buffer,ace_name_buffer);
                onm_tc_ace_hash_element_set_ace_priority(&updated_ace,0,DEFAULT_CHANGE_OPERATION);
                onm_tc_ace_hash_element_set_ace_handle(&updated_ace,DEFAULT_TCM_HANDLE);
            }
            
            error = acls_list_add_ace_element(&ctx->events_acls_list,acl_name_buffer,updated_ace);
        }

        //update ace in events acls list
        SRPC_SAFE_CALL_ERR(error, ace_element_update_from_lyd_node(updated_ace,node,change_ctx->operation,acl_name_buffer),error_out);
        
        goto out;
    }

error_out:
	return error;

out:
	return error;
}

int ace_element_update_from_lyd_node(onm_tc_ace_element_t* updated_ace,const struct lyd_node * node, sr_change_oper_t change_operation, char * acl_name) {
    int error = 0;
    const char *node_name = LYD_NAME(node);
    const char *node_value = lyd_get_value(node);
	const char *parent_node_name = LYD_NAME(&node->parent->node);
    const char *grand_parent_node_name = LYD_NAME(&node->parent->node.parent->node);
	
    if (updated_ace == NULL || node_name == NULL || node_value == NULL) {
        SRPLG_LOG_ERR(PLUGIN_NAME, "Failed to update ACE %s element '%s' value '%s'.",updated_ace->ace.name,node_name,node_value);
        return -1;
    }
    if (strcmp(node_name,"name") != 0){
     SRPLG_LOG_INF(PLUGIN_NAME, "[%s] Update change ACE %s element '%s' value %s, change operation %d.",acl_name,updated_ace->ace.name,node_name,node_value,change_operation);
    }

    //L2 match
    if (strcmp(node_name,"source-mac-address")==0){
        onm_tc_ace_hash_element_set_match_src_mac_addr(&updated_ace, node_value,change_operation);
    }

    if (strcmp(node_name,"source-mac-address-mask")==0){
        onm_tc_ace_hash_element_set_match_src_mac_addr_mask(&updated_ace, node_value,change_operation);
    }

    if (strcmp(node_name,"destination-mac-address")==0){
        onm_tc_ace_hash_element_set_match_dst_mac_addr(&updated_ace, node_value,change_operation);
    }

    if (strcmp(node_name,"destination-mac-address-mask")==0){
        onm_tc_ace_hash_element_set_match_dst_mac_addr_mask(&updated_ace, node_value,change_operation);
    }

    if (strcmp(node_name,"ethertype")==0)
    {
        uint16_t ether_type;
        if (ll_proto_a2n(&ether_type, node_value))
        {
            // TODO revise: currently this failure will set ethertype to ALL
            SRPLG_LOG_ERR(PLUGIN_NAME, "[%s] Failed to update ACE %s element '%s' value '%s'",acl_name,updated_ace->ace.name,node_name,node_value);
            return -1;
        }
        else
        {
            onm_tc_ace_hash_element_set_match_eth_ethertype(&updated_ace, ether_type,change_operation);
        }
        
    }

    // L3
    if (strcmp(node_name,"source-ipv4-network")==0){
        onm_tc_ace_hash_element_set_match_ipv4_src_network(&updated_ace,node_value,change_operation);
    }

    if (strcmp(node_name,"destination-ipv4-network")==0){
        onm_tc_ace_hash_element_set_match_ipv4_dst_network(&updated_ace,node_value,change_operation);
    }

    if (strcmp(node_name,"source-ipv6-network")==0){
        onm_tc_ace_hash_element_set_match_ipv6_src_network(&updated_ace,node_value,change_operation);
    }

    if (strcmp(node_name,"destination-ipv6-network")==0){
        onm_tc_ace_hash_element_set_match_ipv6_dst_network(&updated_ace,node_value,change_operation);
    }

    //L4
    {
        if (strcmp(parent_node_name,"source-port")==0){
            if (strcmp(grand_parent_node_name,"tcp")==0){
                if (strcmp(node_name,"operator")==0){ // tcp source port, single Port Operator
                    onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                    uint16_t port = updated_ace->ace.matches.tcp.source_port.port;
                    port_operator_t port_opr = onm_tc_ace_port_oper_a2i(node_value);
                    SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr,NULL,NULL,NULL,port_opr,PORT_ATTR_SRC,PORT_ATTR_PROTO_TCP), port_attr_error_out);
                    error = onm_tc_ace_hash_element_set_match_port_operator(&updated_ace, port_attr,change_operation);
                    free(port_attr);
                }
                if (strcmp(node_name,"port")==0){ // tcp source port, single port value
                    onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                    SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr,NULL,NULL,node_value,PORT_NOOP,PORT_ATTR_SRC,PORT_ATTR_PROTO_TCP), port_attr_error_out);
                    error = set_ace_port_single(updated_ace, port_attr,change_operation);
                    free(port_attr);
                }
                if (strcmp(node_name,"lower-port")==0 ){ // tcp source port, port range
                    onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                    SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr,node_value,NULL,NULL,PORT_NOOP,PORT_ATTR_SRC,PORT_ATTR_PROTO_TCP), port_attr_error_out);
                    //error = onm_tc_ace_hash_element_set_match_port_operator(&updated_ace, port_attr,change_operation);
                    error = set_ace_port_range_lower_port(updated_ace, port_attr,change_operation);
                    free(port_attr);
                }
                
                if (strcmp(node_name,"upper-port")==0){ // tcp source port, port range
                    onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                    SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr,NULL,node_value,NULL,PORT_NOOP,PORT_ATTR_SRC,PORT_ATTR_PROTO_TCP), port_attr_error_out);
                    //error = onm_tc_ace_hash_element_set_match_port_operator(&updated_ace, port_attr,change_operation);
                    error = set_ace_port_range_upper_port(updated_ace, port_attr,change_operation);
                    free(port_attr); 
                }
            }
            else if (strcmp(grand_parent_node_name, "udp") == 0) {
                if (strcmp(node_name, "port") == 0) {
                    onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                    SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr,NULL,NULL,node_value,PORT_NOOP,PORT_ATTR_SRC, PORT_ATTR_PROTO_UDP), port_attr_error_out);
                    error = set_ace_port_single(updated_ace, port_attr, change_operation);
                    free(port_attr);
                }
                if (strcmp(node_name, "operator") == 0) {
                    onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                    port_operator_t port_opr = onm_tc_ace_port_oper_a2i(node_value);
                    SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr,NULL,NULL,NULL,port_opr,PORT_ATTR_SRC, PORT_ATTR_PROTO_UDP), port_attr_error_out);
                    error = onm_tc_ace_hash_element_set_match_port_operator(&updated_ace, port_attr, change_operation);
                    free(port_attr);
                }
                if (strcmp(node_name, "lower-port") == 0) {
                    onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                    SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr,node_value,NULL,NULL,PORT_NOOP,PORT_ATTR_SRC, PORT_ATTR_PROTO_UDP), port_attr_error_out);
                    //error = onm_tc_ace_hash_element_set_match_port_operator(&updated_ace, port_attr, change_operation);
                    error = set_ace_port_range_lower_port(updated_ace, port_attr, change_operation);
                    free(port_attr);
                }
                if (strcmp(node_name, "upper-port") == 0) {
                    onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                    SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr,NULL,node_value,NULL,PORT_NOOP, PORT_ATTR_SRC, PORT_ATTR_PROTO_UDP), port_attr_error_out);
                    //error = onm_tc_ace_hash_element_set_match_port_operator(&updated_ace, port_attr, change_operation);
                    error = set_ace_port_range_upper_port(updated_ace, port_attr, change_operation);
                    free(port_attr);
                }
            }
        }
        else if (strcmp(parent_node_name, "destination-port") == 0) {
        if (strcmp(grand_parent_node_name, "tcp") == 0) {
            if (strcmp(node_name, "operator") == 0) {
                onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                port_operator_t port_opr = onm_tc_ace_port_oper_a2i(node_value);
                SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr,NULL,NULL,NULL,port_opr,  PORT_ATTR_DST, PORT_ATTR_PROTO_TCP), port_attr_error_out);
                error = onm_tc_ace_hash_element_set_match_port_operator(&updated_ace, port_attr, change_operation);
                free(port_attr);
            }
            if (strcmp(node_name, "port") == 0) {
                onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr,NULL,NULL,node_value,PORT_NOOP, PORT_ATTR_DST, PORT_ATTR_PROTO_TCP), port_attr_error_out);
                error = set_ace_port_single(updated_ace, port_attr, change_operation);
                free(port_attr);
            }
            if (strcmp(node_name, "lower-port") == 0) {
                onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr,node_value,NULL,NULL,PORT_NOOP,  PORT_ATTR_DST, PORT_ATTR_PROTO_TCP), port_attr_error_out);
                //error = onm_tc_ace_hash_element_set_match_port_operator(&updated_ace, port_attr, change_operation);
                error = set_ace_port_range_lower_port(updated_ace, port_attr, change_operation);
                free(port_attr);
            }
            if (strcmp(node_name, "upper-port") == 0) {
                onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr,NULL,node_value,NULL,PORT_NOOP, PORT_ATTR_DST, PORT_ATTR_PROTO_TCP), port_attr_error_out);
                //error = onm_tc_ace_hash_element_set_match_port_operator(&updated_ace, port_attr, change_operation);
                error = set_ace_port_range_upper_port(updated_ace, port_attr, change_operation);
                free(port_attr);
            }
        }
        else if (strcmp(grand_parent_node_name, "udp") == 0) {
            if (strcmp(node_name, "port") == 0) {
                onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr,NULL,NULL,node_value,PORT_NOOP, PORT_ATTR_DST, PORT_ATTR_PROTO_UDP), port_attr_error_out);
                error = set_ace_port_single(updated_ace, port_attr, change_operation);
                free(port_attr);
            }
            if (strcmp(node_name, "operator") == 0) {
                onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                port_operator_t port_opr = onm_tc_ace_port_oper_a2i(node_value);
                error = port_str_to_port_attr(port_attr,NULL,NULL,NULL,port_opr, PORT_ATTR_DST, PORT_ATTR_PROTO_UDP);
                error = onm_tc_ace_hash_element_set_match_port_operator(&updated_ace, port_attr, change_operation);
                free(port_attr);
            }
            if (strcmp(node_name, "lower-port") == 0) {
                onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr,node_value,NULL,NULL,PORT_NOOP, PORT_ATTR_DST, PORT_ATTR_PROTO_UDP), port_attr_error_out);
                //error = onm_tc_ace_hash_element_set_match_port_operator(&updated_ace, port_attr, change_operation);
                error = set_ace_port_range_lower_port(updated_ace, port_attr, change_operation);
                free(port_attr);
            }
            if (strcmp(node_name, "upper-port") == 0) {
                onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr,NULL,node_value,NULL,PORT_NOOP, PORT_ATTR_DST, PORT_ATTR_PROTO_UDP), port_attr_error_out);
                //error = onm_tc_ace_hash_element_set_match_port_operator(&updated_ace, port_attr, change_operation);
                error = set_ace_port_range_upper_port(updated_ace, port_attr, change_operation);
                free(port_attr);
            }
        }
    }
    }

    // actions
    if (strcmp(node_name,"forwarding")==0){
        onm_tc_ace_hash_element_set_action_forwarding(&updated_ace,node_value,change_operation);
    }
    if (strcmp(node_name,"logging")==0){
        onm_tc_ace_hash_element_set_action_logging(&updated_ace,node_value,change_operation);
    }
    goto out;

port_attr_error_out:
    SRPLG_LOG_ERR(PLUGIN_NAME, "[%s] ACE '%s' Illegal port attributes (node name '%s', node value '%s')",acl_name,updated_ace->ace.name,node_name,node_value);
    
    return error;

error_out:
    return error;

out:
    return 0; // Update successful
}

void onm_tc_ace_hash_print_debug(const onm_tc_ace_element_t* ace_iter)
{
        SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t+ ACE %s", ace_iter->ace.name);
        SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     ACE Name = %s (change operation %d)", ace_iter->ace.name,ace_iter->ace.name_change_op);
        SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     ACE Priority = %d", ace_iter->ace.priority);
        SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     ACE Handle = %d", ace_iter->ace.handle);
        SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     + Matches:");
        if(ace_iter->ace.matches.eth.source_address){
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Source mac address = %s (change operation %d, set flag %d)",
            ace_iter->ace.matches.eth.source_address,
            ace_iter->ace.matches.eth.source_address_change_op,
            ace_iter->ace.matches.eth._is_set);
        }
        if(ace_iter->ace.matches.eth.source_address_mask){
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Source mac address mask = %s (change operation %d, set flag %d)",
            ace_iter->ace.matches.eth.source_address_mask,
            ace_iter->ace.matches.eth.source_address_mask_change_op,
            ace_iter->ace.matches.eth._is_set);
        }
        if(ace_iter->ace.matches.eth.destination_address){
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Destination mac address = %s (change operation %d, set flag %d)",
            ace_iter->ace.matches.eth.destination_address,
            ace_iter->ace.matches.eth.destination_address_change_op,
            ace_iter->ace.matches.eth._is_set);
        }
        if(ace_iter->ace.matches.eth.destination_address_mask){
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Destination mac address mask = %s (change operation %d, set flag %d)",
            ace_iter->ace.matches.eth.destination_address_mask,
            ace_iter->ace.matches.eth.destination_address_mask_change_op,
            ace_iter->ace.matches.eth._is_set);
        }
        if(ace_iter->ace.matches.eth.ethertype != 0){
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- EtherType = %d (change operation %d, set flag %d)",
            ace_iter->ace.matches.eth.ethertype,
            ace_iter->ace.matches.eth.ethertype_change_op,
            ace_iter->ace.matches.eth._is_set);
        }
        if(ace_iter->ace.matches.ipv4.source_network){
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Source IPv4 Network = %s (change operation %d, set flag %d)",
            ace_iter->ace.matches.ipv4.source_network,
            ace_iter->ace.matches.ipv4.source_network_change_op,
            ace_iter->ace.matches.ipv4._is_set);
        }
        if(ace_iter->ace.matches.ipv4.destination_network){
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Destination IPv4 Network = %s (change operation %d, set flag %d)",
            ace_iter->ace.matches.ipv4.destination_network,
            ace_iter->ace.matches.ipv4.destination_network_change_op,
            ace_iter->ace.matches.ipv4._is_set);
        }
        if(ace_iter->ace.matches.ipv6.source_network){
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Source IPv6 Network = %s (change operation %d, set flag %d)",
            ace_iter->ace.matches.ipv6.source_network,
            ace_iter->ace.matches.ipv6.source_network_change_op,
            ace_iter->ace.matches.ipv6._is_set);
        }
        if(ace_iter->ace.matches.ipv6.destination_network){
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- Destination IPv6 Network = %s (change operation %d, set flag %d)",
            ace_iter->ace.matches.ipv6.destination_network,
            ace_iter->ace.matches.ipv6.destination_network_change_op,
            ace_iter->ace.matches.ipv6._is_set);
        }
        // TCP Source Port
        if (ace_iter->ace.matches.tcp.source_port.port != 0 || ace_iter->ace.matches.tcp.source_port.port_operator != PORT_NOOP){
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- TCP Source Port = %d Operator = %d (change operation %d, set flag %d)",
            ace_iter->ace.matches.tcp.source_port.port, 
            ace_iter->ace.matches.tcp.source_port.port_operator,
            ace_iter->ace.matches.tcp.source_port.single_port_change_op,
            ace_iter->ace.matches.tcp._is_set);
        }
        // TCP Source Port Range
        if(ace_iter->ace.matches.tcp.source_port.lower_port != 0 || ace_iter->ace.matches.tcp.source_port.upper_port != 0)
        {
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- TCP Source Port Range = [%d-%d] Operator = %d (change operation %d, set flag %d)",
            ace_iter->ace.matches.tcp.source_port.lower_port, 
            ace_iter->ace.matches.tcp.source_port.upper_port,
            ace_iter->ace.matches.tcp.source_port.port_operator,
            ace_iter->ace.matches.tcp.source_port.range_port_change_op,
            ace_iter->ace.matches.tcp._is_set);
        }
        // UDP Source Port
        if (ace_iter->ace.matches.udp.source_port.port != 0 || ace_iter->ace.matches.udp.source_port.port_operator != PORT_NOOP) {
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- UDP Source Port = %d Operator = %d (change operation %d, set flag %d)",
            ace_iter->ace.matches.udp.source_port.port,
            ace_iter->ace.matches.udp.source_port.port_operator,
            ace_iter->ace.matches.udp.source_port.single_port_change_op,
            ace_iter->ace.matches.udp._is_set);
        }
        // UDP Source Port Range
        if (ace_iter->ace.matches.udp.source_port.lower_port != 0 || ace_iter->ace.matches.udp.source_port.upper_port != 0) {
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- UDP Source Port Range = [%d-%d] Operator = %d (change operation %d, set flag %d)",
            ace_iter->ace.matches.udp.source_port.lower_port,
            ace_iter->ace.matches.udp.source_port.upper_port,
            ace_iter->ace.matches.udp.source_port.port_operator,
            ace_iter->ace.matches.udp.source_port.range_port_change_op,
            ace_iter->ace.matches.udp._is_set);
        }
        // TCP Destination Port
        if (ace_iter->ace.matches.tcp.destination_port.port != 0 || ace_iter->ace.matches.tcp.destination_port.port_operator != PORT_NOOP) {
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- TCP Destination Port = %d Operator = %d (change operation %d, set flag %d)",
            ace_iter->ace.matches.tcp.destination_port.port,
            ace_iter->ace.matches.tcp.destination_port.port_operator,
            ace_iter->ace.matches.tcp.destination_port.single_port_change_op,
            ace_iter->ace.matches.tcp._is_set);
        }
        // TCP Destination Port Range
        if (ace_iter->ace.matches.tcp.destination_port.lower_port != 0 || ace_iter->ace.matches.tcp.destination_port.upper_port != 0) {
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- TCP Destination Port Range = [%d-%d] Operator = %d (change operation %d, set flag %d)",
            ace_iter->ace.matches.tcp.destination_port.lower_port,
            ace_iter->ace.matches.tcp.destination_port.upper_port,
            ace_iter->ace.matches.tcp.destination_port.port_operator,
            ace_iter->ace.matches.tcp.destination_port.range_port_change_op,
            ace_iter->ace.matches.tcp._is_set);
        }

        // UDP Destination Port
        if (ace_iter->ace.matches.udp.destination_port.port != 0 || ace_iter->ace.matches.udp.destination_port.port_operator != PORT_NOOP) {
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
