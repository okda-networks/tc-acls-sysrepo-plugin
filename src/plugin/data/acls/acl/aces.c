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
    if (strcmp(action,"accept") == 0){
        (*el)->ace.actions.forwarding = FORWARD_ACCEPT;
    }
    else if (strcmp(action,"drop") == 0){
        (*el)->ace.actions.forwarding = FORWARD_DROP;
    }
    else if (strcmp(action,"reject") == 0){
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

port_operator_t onm_tc_ace_port_oper_a2i(const char * oper_str)
{
    if (!oper_str)
        return PORT_NOOP;

    port_operator_t operation = PORT_NOOP;
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

// this function allows for empty values:
// if port value(s) not set in the input pointer, port_attr will have it set to DEFAULT_PORT_VALUE
// if port operator is not set, port_attr will get PORT_NOOP, unless uppor port is set, in that case it will be considered as a range operator
int port_str_to_port_attr (onm_tc_port_attributes_t *port_attr, const char * lower_str, const char * upper_str, const port_operator_t port_opr,onm_tc_port_attr_direction_t direction, onm_tc_port_attr_proto_t proto)
{
    port_attr->port_operator = port_opr;
    port_attr->direction = direction;
    port_attr->proto = proto;

    if (port_opr == PORT_EQUAL || port_opr == PORT_LTE || port_opr == PORT_GTE || port_opr == PORT_NOT_EQUAL)
    {
        if (lower_str){
            const uint16_t port = (uint16_t)atoi(lower_str);
            if (port == 0){
                return -1;
                // port 0 is not allowed to be set by user
            }

            port_attr->port = port;
        }
        else {
            port_attr->port = DEFAULT_PORT_VALUE;
        }
        return 0;
    }
    else if (port_opr == PORT_RANGE)
    {
        if (lower_str){
            const uint16_t lower_port = (uint16_t)atoi(lower_str);
            if (lower_port == 0){
                return -1;
                // port 0 not allowed to be set by user
            }
            port_attr->lower_port = lower_port;
        }
        else {
            port_attr->lower_port = DEFAULT_PORT_VALUE;
        }
        if (upper_str){
            const uint16_t upper_port = (uint16_t)atoi(upper_str);
            if (upper_port == 0){
                return -1;
                // port 0 not allowed to be set by user
            }
            port_attr->upper_port = upper_port;
        }
        else {
            port_attr->upper_port = DEFAULT_PORT_VALUE;
        }
        return 0;
    }
    else if (port_opr == PORT_NOOP) // handles both range and non-range
    {
        if (upper_str){ //upper_str will only be set in case of port range, handling this as a port range
            const uint16_t upper_port = (uint16_t)atoi(upper_str);
            if (upper_port == 0){
                return -1;
                // port 0 not allowed to be set by user
            }
            port_attr->upper_port = upper_port;
            port_attr->port_operator = PORT_RANGE;
            if (lower_str){ // lower port is set for port range
                const uint16_t lower_port = (uint16_t)atoi(lower_str);
                if (lower_port == 0){
                    return -1;
                    // port 0 not allowed to be set by user
                }
                port_attr->lower_port = lower_port;
            }
            else{ 
                port_attr->lower_port = DEFAULT_PORT_VALUE;
            }
        }
        else if (lower_str){ // lower_str is set, uppert_str is not set, in this case handle it as single port with NOOP operator
            const uint16_t port = (uint16_t)atoi(lower_str);
            if (port == 0){
                return -1;
                // port 0 not allowed to be set by user.
            }
            port_attr->port = port;
            port_attr->lower_port = DEFAULT_PORT_VALUE;
            port_attr->upper_port = DEFAULT_PORT_VALUE;
        }
        else { // no operator, no lower_str , no upper_str
            return -1;
        }
    }
    return 0;
}

int set_ace_port_operator(onm_tc_ace_element_t* el, onm_tc_port_attributes_t* port_attr, sr_change_oper_t change_operation){
if (port_attr->proto == PORT_ATTR_PROTO_TCP) {
        if (port_attr->direction == PORT_ATTR_SRC) {
            el->ace.matches.tcp.source_port.port_operator = port_attr->port_operator;
            el->ace.matches.tcp.source_port.port_change_op = change_operation;
        } else {
            el->ace.matches.tcp.destination_port.port_operator = port_attr->port_operator;
            el->ace.matches.tcp.destination_port.port_change_op = change_operation;
        }
    } else if (port_attr->proto == PORT_ATTR_PROTO_UDP) {
        if (port_attr->direction == PORT_ATTR_SRC) {
            el->ace.matches.udp.source_port.port_operator = port_attr->port_operator;
            el->ace.matches.udp.source_port.port_change_op = change_operation;
        } else {
            el->ace.matches.udp.destination_port.port_operator = port_attr->port_operator;
            el->ace.matches.udp.destination_port.port_change_op = change_operation;
        }
    }
    return 0;
}

int set_ace_port_single(onm_tc_ace_element_t* el, onm_tc_port_attributes_t* port_attr, sr_change_oper_t change_operation) {
    if (port_attr->proto == PORT_ATTR_PROTO_TCP) {
        if (port_attr->direction == PORT_ATTR_SRC) {
            el->ace.matches.tcp.source_port.port = port_attr->port;
            el->ace.matches.tcp.source_port.port_change_op = change_operation;
            el->ace.matches.tcp._is_set = 1;
        } else {
            el->ace.matches.tcp.destination_port.port = port_attr->port;
            el->ace.matches.tcp.destination_port.port_change_op = change_operation;
            el->ace.matches.tcp._is_set = 1;
        }
    } else if (port_attr->proto == PORT_ATTR_PROTO_UDP) {
        if (port_attr->direction == PORT_ATTR_SRC) {
            el->ace.matches.udp.source_port.port = port_attr->port;
            el->ace.matches.udp.source_port.port_change_op = change_operation;
            el->ace.matches.udp._is_set = 1;
        } else {
            el->ace.matches.udp.destination_port.port = port_attr->port;
            el->ace.matches.udp.destination_port.port_change_op = change_operation;
            el->ace.matches.udp._is_set = 1;
        }
    }
    return 0;
}

int set_ace_port_range_lower_port(onm_tc_ace_element_t* el, onm_tc_port_attributes_t* port_attr, sr_change_oper_t change_operation) {
    if (port_attr->proto == PORT_ATTR_PROTO_TCP) {
        if (port_attr->direction == PORT_ATTR_SRC) {
            el->ace.matches.tcp.source_port.lower_port = port_attr->lower_port;
            el->ace.matches.tcp.source_port.port_change_op = change_operation;
            el->ace.matches.tcp._is_set = 1;
        } else {
            el->ace.matches.tcp.destination_port.lower_port = port_attr->lower_port;
            el->ace.matches.tcp.destination_port.port_operator = port_attr->port_operator;
            el->ace.matches.tcp.destination_port.port_change_op = change_operation;
            el->ace.matches.tcp._is_set = 1;
        }
    } else if (port_attr->proto == PORT_ATTR_PROTO_UDP) {
        if (port_attr->direction == PORT_ATTR_SRC) {
            el->ace.matches.udp.source_port.lower_port = port_attr->lower_port;
            el->ace.matches.udp.source_port.port_change_op = change_operation;
            el->ace.matches.udp._is_set = 1;
        } else {
            el->ace.matches.udp.destination_port.lower_port = port_attr->lower_port;
            el->ace.matches.udp.destination_port.port_change_op = change_operation;
            el->ace.matches.udp._is_set = 1;
        }
    }
    return 0;
}

int set_ace_port_range_upper_port(onm_tc_ace_element_t* el, onm_tc_port_attributes_t* port_attr, sr_change_oper_t change_operation) {
    if (port_attr->proto == PORT_ATTR_PROTO_TCP) {
        if (port_attr->direction == PORT_ATTR_SRC) {
            el->ace.matches.tcp.source_port.upper_port = port_attr->upper_port;
            el->ace.matches.tcp.source_port.port_change_op = change_operation;
            el->ace.matches.tcp._is_set = 1;
        } else {
            el->ace.matches.tcp.destination_port.upper_port = port_attr->upper_port;
            el->ace.matches.tcp.destination_port.port_change_op = change_operation;
            el->ace.matches.tcp._is_set = 1;
        }
    } else if (port_attr->proto == PORT_ATTR_PROTO_UDP) {
        if (port_attr->direction == PORT_ATTR_SRC) {
            el->ace.matches.udp.source_port.upper_port = port_attr->upper_port;
            el->ace.matches.udp.source_port.port_change_op = change_operation;
            el->ace.matches.udp._is_set = 1;
        } else {
            el->ace.matches.udp.destination_port.upper_port = port_attr->upper_port;
            el->ace.matches.udp.destination_port.port_change_op = change_operation;
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

int onm_tc_ace_hash_element_set_match_port(onm_tc_ace_element_t** el, onm_tc_port_attributes_t* port_attr, sr_change_oper_t change_operation) 
{
    if (port_attr->port_operator != PORT_RANGE) {
        return set_ace_port_single(*el, port_attr, change_operation);
    } else {
        return set_ace_port_range(*el, port_attr, change_operation);
    }
}

int onm_tc_ace_hash_element_set_match_port_operator(onm_tc_ace_element_t** el, onm_tc_port_attributes_t* port_attr, sr_change_oper_t change_operation) 
{
    return set_ace_port_operator(*el, port_attr, change_operation);
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

onm_tc_ace_element_t* onm_tc_get_ace_in_acl_list(onm_tc_acl_hash_element_t* acl_hash, const char* acl_name, const char* ace_name) 
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

/*int events_acls_hash_add_ace_element(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx)
{
    int error = 0;
    const char *node_name = LYD_NAME(change_ctx->node);
	const char *parent_node_name = LYD_NAME(&change_ctx->node->parent->node);
	const char *node_value = lyd_get_value(change_ctx->node);
    onm_tc_ctx_t *ctx = (onm_tc_ctx_t *) priv;
    char change_path[PATH_MAX] = {0};
    char acl_name_buffer[100] = {0};
    if (node_value)
    {
        error = (lyd_path(change_ctx->node, LYD_PATH_STD, change_path, sizeof(change_path)) != NULL);
        SRPC_SAFE_CALL_ERR(error, srpc_extract_xpath_key_value(change_path, "acl", "name", acl_name_buffer, sizeof(acl_name_buffer)), error_out);

        printf("ADD ACL DATA:\n\tNode Name: %s\n\tNode Value: %s\n\tParent Node Name: %s\n\tOperation: %d\n",node_name,node_value,parent_node_name,change_ctx->operation);
        onm_tc_ace_element_t* new_ace = NULL;
        new_ace = onm_tc_ace_hash_element_new();
        // ace name
        if (strcmp(node_name,"name")==0)
        {
            SRPLG_LOG_INF(PLUGIN_NAME, "Adding new change ACE to Change ACLs list change, ACE Name: %s, Change operation: %d.",node_value,change_ctx->operation);
            SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_ace_name(&new_ace, node_value,change_ctx->operation), error_out);
            onm_tc_ace_element_t* running_ace = onm_tc_get_ace_in_acl_list(ctx->running_acls_list,acl_name_buffer,node_value);
            //same ace should exist in running_acls hash, set the same priority for the ace in events_acls hash
            if(running_ace){
                onm_tc_ace_hash_element_set_ace_priority(&new_ace, running_ace->ace.priority,change_ctx->operation);
            }
        }
        // make sure acl exits in acls list
        if (!(onm_tc_acl_hash_get_element(&ctx->events_acls_list,acl_name_buffer)))
        {
            onm_tc_acl_hash_element_t* temp_acl = onm_tc_acl_hash_element_new();
            SRPC_SAFE_CALL_ERR(error, onm_tc_acl_hash_element_set_name(&temp_acl, acl_name_buffer,DEFAULT_CHANGE_OPERATION), error_out);
            onm_tc_acls_hash_add_acl_element(&ctx->events_acls_list,temp_acl);
        }

        
        //add ace to acls list
        error = acls_list_add_ace_element(&ctx->events_acls_list,acl_name_buffer,new_ace);
        goto out;
    }

error_out:
	return error;

out:
	return error;
}*/

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

    if (node_value)
    {
        error = (lyd_path(change_ctx->node, LYD_PATH_STD, change_path, sizeof(change_path)) != NULL);
        SRPC_SAFE_CALL_ERR(error, srpc_extract_xpath_key_value(change_path, "acl", "name", acl_name_buffer, sizeof(acl_name_buffer)), error_out);
        SRPC_SAFE_CALL_ERR(error, srpc_extract_xpath_key_value(change_path, "ace", "name", ace_name_buffer, sizeof(ace_name_buffer)), error_out);

        onm_tc_acl_hash_element_t* updated_acl = onm_tc_acl_hash_get_element(&ctx->events_acls_list,acl_name_buffer);
        onm_tc_ace_element_t* updated_ace = onm_tc_get_ace_in_acl_list(ctx->events_acls_list,acl_name_buffer,ace_name_buffer);
        onm_tc_ace_element_t* running_ace = onm_tc_get_ace_in_acl_list(ctx->running_acls_list,acl_name_buffer,ace_name_buffer);
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
            SRPLG_LOG_INF(PLUGIN_NAME, "Change event ACE name %s is not present in events acls hash, creating new ACE element.",ace_name_buffer);
            updated_ace = onm_tc_ace_hash_element_new();
            // if the change event happened on the ace name.
            if (strcmp(node_name,"name")==0){
                SRPLG_LOG_INF(PLUGIN_NAME, "Change event happned on ACE name %s, setting ACE name operation to %d.",ace_name_buffer,change_ctx->operation);
                onm_tc_ace_hash_element_set_ace_name(&updated_ace,node_value,change_ctx->operation);
            }
            else {
                SRPLG_LOG_INF(PLUGIN_NAME, "Change event didn't happen on ACE name %s, setting ACE name change operation to default.",ace_name_buffer);
                onm_tc_ace_hash_element_set_ace_name(&updated_ace,ace_name_buffer,DEFAULT_CHANGE_OPERATION);
            }
            // if the updated ace exists in the running_acls list, set the same ace priority
            if (running_ace){
                SRPLG_LOG_INF(PLUGIN_NAME, "Change event ACE name %s has a corresponding ACE in running acls list, setting ACE priority to %d.",ace_name_buffer,running_ace->ace.priority);
                onm_tc_ace_hash_element_set_ace_priority(&updated_ace,running_ace->ace.priority,DEFAULT_CHANGE_OPERATION);
            }
            else {
                SRPLG_LOG_INF(PLUGIN_NAME, "Change event ACE name %s has no corresponding ACE in running acls list, setting ACE priority to 0.",ace_name_buffer);
                onm_tc_ace_hash_element_set_ace_priority(&updated_ace,0,DEFAULT_CHANGE_OPERATION);
            }
            
            error = acls_list_add_ace_element(&ctx->events_acls_list,acl_name_buffer,updated_ace);
        }

        //update ace in events acls list
        SRPC_SAFE_CALL_ERR(error, ace_element_update_from_lyd_node(updated_ace,node,change_ctx->operation),error_out);
        
        goto out;
    }

error_out:
	return error;

out:
	return error;
}

int ace_element_update_from_lyd_node(onm_tc_ace_element_t* updated_ace,const struct lyd_node * node, sr_change_oper_t change_operation) {
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
        //printf("ADD ACL DATA:\n\tNode Name: %s\n\tNode Value: %s\n\tParent Node Name: %s\n\tGrandParent Name: %s\n\tOperation: %d\n",node_name,node_value,parent_node_name,grand_parent_node_name,change_operation);
        SRPLG_LOG_INF(PLUGIN_NAME, "Update change ACE %s element '%s' value %s.",updated_ace->ace.name,node_name,node_value);
    }

    //L2 match
    if (strcmp(node_name,"source-mac-address")==0){
        onm_tc_ace_hash_element_set_match_src_mac_addr(&updated_ace, node_value,change_operation);
    }

    if (strcmp(node_name,"source-mac-address-mask")==0){
        onm_tc_ace_hash_element_set_match_src_mac_addr_mask(&updated_ace, node_value,change_operation);
    }

    if (strcmp(node_name,"destination-mac-address")==0){
        SRPLG_LOG_INF(PLUGIN_NAME, "Update change ACE %s, element '%s' value %s",updated_ace->ace.name,node_name,node_value);
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
            SRPLG_LOG_ERR(PLUGIN_NAME, "Failed to update ACE %s element '%s' value '%s'.",updated_ace->ace.name,node_name,node_value);
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
                    SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr,NULL,NULL,port_opr,PORT_ATTR_SRC,PORT_ATTR_PROTO_TCP), port_attr_error_out);
                    error = onm_tc_ace_hash_element_set_match_port_operator(&updated_ace, port_attr,change_operation);
                    free(port_attr);
                }
                if (strcmp(node_name,"port")==0){ // tcp source port, single port value
                    onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                    SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr,node_value,NULL,PORT_NOOP,PORT_ATTR_SRC,PORT_ATTR_PROTO_TCP), port_attr_error_out);
                    error = onm_tc_ace_hash_element_set_match_port(&updated_ace, port_attr,change_operation);
                    free(port_attr);
                }
                if (strcmp(node_name,"lower-port")==0 ){ // tcp source port, port range
                    onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                    SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr,node_value,NULL,PORT_RANGE,PORT_ATTR_SRC,PORT_ATTR_PROTO_TCP), port_attr_error_out);
                    error = onm_tc_ace_hash_element_set_match_port_operator(&updated_ace, port_attr,change_operation);
                    error = set_ace_port_operator(updated_ace, port_attr, change_operation);
                    error = set_ace_port_range_lower_port(updated_ace, port_attr,change_operation);
                    free(port_attr);
                }
                
                if (strcmp(node_name,"upper-port")==0){ // tcp source port, port range
                    onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                    SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr,NULL,node_value,PORT_RANGE,PORT_ATTR_SRC,PORT_ATTR_PROTO_TCP), port_attr_error_out);
                    error = onm_tc_ace_hash_element_set_match_port_operator(&updated_ace, port_attr,change_operation);
                    error = set_ace_port_operator(updated_ace, port_attr, change_operation);
                    error = set_ace_port_range_upper_port(updated_ace, port_attr,change_operation);
                    free(port_attr); 
                }
            }
            else if (strcmp(grand_parent_node_name, "udp") == 0) {
                if (strcmp(node_name, "port") == 0) {
                    onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                    SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr, node_value, NULL, PORT_NOOP, PORT_ATTR_SRC, PORT_ATTR_PROTO_UDP), port_attr_error_out);
                    error = set_ace_port_single(updated_ace, port_attr, change_operation);
                    free(port_attr);
                }
                if (strcmp(node_name, "operator") == 0) {
                    onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                    port_operator_t port_opr = onm_tc_ace_port_oper_a2i(node_value);
                    SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr, NULL, NULL, port_opr, PORT_ATTR_SRC, PORT_ATTR_PROTO_UDP), port_attr_error_out);
                    error = set_ace_port_operator(updated_ace, port_attr, change_operation);
                    free(port_attr);
                }
                if (strcmp(node_name, "lower-port") == 0) {
                    onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                    SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr, node_value, NULL, PORT_RANGE, PORT_ATTR_SRC, PORT_ATTR_PROTO_UDP), port_attr_error_out);
                    error = set_ace_port_operator(updated_ace, port_attr, change_operation);
                    error = set_ace_port_range_lower_port(updated_ace, port_attr, change_operation);
                    free(port_attr);
                }
                if (strcmp(node_name, "upper-port") == 0) {
                    onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                    SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr, NULL, node_value, PORT_RANGE, PORT_ATTR_SRC, PORT_ATTR_PROTO_UDP), port_attr_error_out);
                    error = set_ace_port_operator(updated_ace, port_attr, change_operation);
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
                SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr, NULL, NULL, port_opr, PORT_ATTR_DST, PORT_ATTR_PROTO_TCP), port_attr_error_out);
                error = set_ace_port_operator(updated_ace, port_attr, change_operation);
                free(port_attr);
            }
            if (strcmp(node_name, "port") == 0) {
                onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr, node_value, NULL, PORT_NOOP, PORT_ATTR_DST, PORT_ATTR_PROTO_TCP), port_attr_error_out);
                error = set_ace_port_single(updated_ace, port_attr, change_operation);
                free(port_attr);
            }
            if (strcmp(node_name, "lower-port") == 0) {
                onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr, node_value, NULL, PORT_RANGE, PORT_ATTR_DST, PORT_ATTR_PROTO_TCP), port_attr_error_out);
                error = set_ace_port_operator(updated_ace, port_attr, change_operation);
                error = set_ace_port_range_lower_port(updated_ace, port_attr, change_operation);
                free(port_attr);
            }
            if (strcmp(node_name, "upper-port") == 0) {
                onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr, NULL, node_value, PORT_RANGE, PORT_ATTR_DST, PORT_ATTR_PROTO_TCP), port_attr_error_out);
                error = set_ace_port_operator(updated_ace, port_attr, change_operation);
                error = set_ace_port_range_upper_port(updated_ace, port_attr, change_operation);
                free(port_attr);
            }
        }
        else if (strcmp(grand_parent_node_name, "udp") == 0) {
            if (strcmp(node_name, "port") == 0) {
                onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr, node_value, NULL, PORT_NOOP, PORT_ATTR_DST, PORT_ATTR_PROTO_UDP), port_attr_error_out);
                error = set_ace_port_single(updated_ace, port_attr, change_operation);
                free(port_attr);
            }
            if (strcmp(node_name, "operator") == 0) {
                onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                port_operator_t port_opr = onm_tc_ace_port_oper_a2i(node_value);
                error = port_str_to_port_attr(port_attr, NULL, NULL, port_opr, PORT_ATTR_DST, PORT_ATTR_PROTO_UDP);
                error = set_ace_port_operator(updated_ace, port_attr, change_operation);
                free(port_attr);
            }
            if (strcmp(node_name, "lower-port") == 0) {
                onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr, node_value, NULL, PORT_RANGE, PORT_ATTR_DST, PORT_ATTR_PROTO_UDP), port_attr_error_out);
                error = set_ace_port_operator(updated_ace, port_attr, change_operation);
                error = set_ace_port_range_lower_port(updated_ace, port_attr, change_operation);
                free(port_attr);
            }
            if (strcmp(node_name, "upper-port") == 0) {
                onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t));
                SRPC_SAFE_CALL_ERR(error, port_str_to_port_attr(port_attr, NULL, node_value, PORT_RANGE, PORT_ATTR_DST, PORT_ATTR_PROTO_UDP), port_attr_error_out);
                error = set_ace_port_operator(updated_ace, port_attr, change_operation);
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
    SRPLG_LOG_ERR(PLUGIN_NAME, "ACE '%s' Illegal port attributes (node name '%s', node value '%s')",updated_ace->ace.name,node_name,node_value);
    
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
            (ace_iter->ace.matches.tcp.source_port.port_operator != PORT_NOOP &&
            ace_iter->ace.matches.tcp.source_port.port_operator != PORT_RANGE)){
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- TCP Source Port = %d Operator = %d (change operation %d)",
            ace_iter->ace.matches.tcp.source_port.port, 
            ace_iter->ace.matches.tcp.source_port.port_operator,
            ace_iter->ace.matches.tcp.source_port.port_change_op);
        }
        // TCP Source Port Range
        if(ace_iter->ace.matches.tcp.source_port.lower_port != 0  || ace_iter->ace.matches.tcp.source_port.upper_port != 0)
        {
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- TCP Source Port Range = [%d-%d] Operator = %d (change operation %d)",
            ace_iter->ace.matches.tcp.source_port.lower_port, 
            ace_iter->ace.matches.tcp.source_port.upper_port,
            ace_iter->ace.matches.tcp.source_port.port_operator,
            ace_iter->ace.matches.tcp.source_port.port_change_op
            );
        }
        // UDP Source Port
        if (ace_iter->ace.matches.udp.source_port.port != 0 ||
            (ace_iter->ace.matches.udp.source_port.port_operator != PORT_NOOP &&
            ace_iter->ace.matches.udp.source_port.port_operator != PORT_RANGE)) {
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- UDP Source Port = %d Operator = %d (change operation %d)",
            ace_iter->ace.matches.udp.source_port.port,
            ace_iter->ace.matches.udp.source_port.port_operator,
            ace_iter->ace.matches.udp.source_port.port_change_op);
        }
        // UDP Source Port Range
        if (ace_iter->ace.matches.udp.source_port.lower_port != 0 || ace_iter->ace.matches.udp.source_port.upper_port != 0) {
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- UDP Source Port Range = [%d-%d] Operator = %d (change operation %d)",
            ace_iter->ace.matches.udp.source_port.lower_port,
            ace_iter->ace.matches.udp.source_port.upper_port,
            ace_iter->ace.matches.udp.source_port.port_operator,
            ace_iter->ace.matches.udp.source_port.port_change_op);
        }
        // TCP Destination Port
        if (ace_iter->ace.matches.tcp.destination_port.port != 0 ||
            (ace_iter->ace.matches.tcp.destination_port.port_operator != PORT_NOOP &&
            ace_iter->ace.matches.tcp.destination_port.port_operator != PORT_RANGE )) {
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- TCP Destination Port = %d Operator = %d (change operation %d)",
            ace_iter->ace.matches.tcp.destination_port.port,
            ace_iter->ace.matches.tcp.destination_port.port_operator,
            ace_iter->ace.matches.tcp.destination_port.port_change_op);
        }
        // TCP Destination Port Range
        if (ace_iter->ace.matches.tcp.destination_port.lower_port != 0 || ace_iter->ace.matches.tcp.destination_port.upper_port != 0) {
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- TCP Destination Port Range = [%d-%d] Operator = %d (change operation %d)",
            ace_iter->ace.matches.tcp.destination_port.lower_port,
            ace_iter->ace.matches.tcp.destination_port.upper_port,
            ace_iter->ace.matches.tcp.destination_port.port_operator,
            ace_iter->ace.matches.tcp.destination_port.port_change_op);
        }

        // UDP Destination Port
        if (ace_iter->ace.matches.udp.destination_port.port != 0 ||
            (ace_iter->ace.matches.udp.destination_port.port_operator != PORT_NOOP &&
            ace_iter->ace.matches.udp.destination_port.port_operator != PORT_RANGE)) {
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- UDP Destination Port = %d Operator = %d (change operation %d)",
            ace_iter->ace.matches.udp.destination_port.port,
            ace_iter->ace.matches.udp.destination_port.port_operator,
            ace_iter->ace.matches.udp.destination_port.port_change_op);
        }

        // UDP Destination Port Range
        if (ace_iter->ace.matches.udp.destination_port.lower_port != 0 || ace_iter->ace.matches.udp.destination_port.upper_port != 0) {
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|     |---- UDP Destination Port Range = [%d-%d] Operator = %d (change operation %d)", 
            ace_iter->ace.matches.udp.destination_port.lower_port,
            ace_iter->ace.matches.udp.destination_port.upper_port,
            ace_iter->ace.matches.udp.destination_port.port_operator,
            ace_iter->ace.matches.udp.destination_port.port_change_op);
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
