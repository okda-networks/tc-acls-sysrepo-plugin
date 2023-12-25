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

//For testing
#include<stdio.h>

int onm_tc_ace_hash_element_set_ace_name(onm_tc_ace_element_t** el, const char* name, sr_change_oper_t change_operation)
{
    if ((*el)->ace.name) {
        FREE_SAFE((*el)->ace.name);
    }
    if (name) {
        (*el)->ace.name = xstrdup(name);
        (*el)->ace.ace_name_change_op = change_operation;
        return (*el)->ace.name == NULL;
    }

    return 0;
}

int onm_tc_ace_hash_element_set_match_src_mac_addr(onm_tc_ace_element_t** el, const char* mac_addr,sr_change_oper_t change_operation)
{
    if ((*el)->ace.matches.eth.source_mac_address) {
        FREE_SAFE((*el)->ace.matches.eth.source_mac_address);
    }
    if (mac_addr) {
        (*el)->ace.matches.eth.source_mac_address = xstrdup(mac_addr);
        (*el)->ace.matches.eth._is_set = 1;
        (*el)->ace.matches.eth.src_mac_change_op = change_operation;
        return (*el)->ace.matches.eth.source_mac_address == NULL;
    }

    return 0;
}

int onm_tc_ace_hash_element_set_match_src_mac_addr_mask(onm_tc_ace_element_t** el, const char* mask,sr_change_oper_t change_operation)
{
    if ((*el)->ace.matches.eth.source_mac_address_mask) {
        FREE_SAFE((*el)->ace.matches.eth.source_mac_address_mask);
    }
    if (mask) {
        (*el)->ace.matches.eth.source_mac_address_mask = xstrdup(mask);
        (*el)->ace.matches.eth._is_set = 1;
        (*el)->ace.matches.eth.src_mac_mask_change_op = change_operation;
        return (*el)->ace.matches.eth.source_mac_address_mask == NULL;
    }

    return 0;
}

int onm_tc_ace_hash_element_set_match_dst_mac_addr(onm_tc_ace_element_t** el, const char* mac_addr,sr_change_oper_t change_operation)
{
    if ((*el)->ace.matches.eth.destination_mac_address) {
        FREE_SAFE((*el)->ace.matches.eth.destination_mac_address);
    }
    if (mac_addr) {
        (*el)->ace.matches.eth.destination_mac_address = xstrdup(mac_addr);
        (*el)->ace.matches.eth._is_set = 1;
        (*el)->ace.matches.eth.dst_mac_change_op = change_operation;
        return (*el)->ace.matches.eth.destination_mac_address == NULL;
    }
    return 0;
}

int onm_tc_ace_hash_element_set_match_dst_mac_addr_mask(onm_tc_ace_element_t** el, const char* mask,sr_change_oper_t change_operation)
{
    if ((*el)->ace.matches.eth.destination_mac_address_mask) {
        FREE_SAFE((*el)->ace.matches.eth.destination_mac_address_mask);
    }
    if (mask) {
        (*el)->ace.matches.eth.destination_mac_address_mask = xstrdup(mask);
        (*el)->ace.matches.eth._is_set = 1;
        (*el)->ace.matches.eth.dst_mac_mask_change_op = change_operation;
        return (*el)->ace.matches.eth.destination_mac_address_mask == NULL;
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
    if ((*el)->ace.matches.ipv4.source_ipv4_network) {
        FREE_SAFE((*el)->ace.matches.ipv4.source_ipv4_network);
    }
    if (network_addr) {
        (*el)->ace.matches.ipv4.source_ipv4_network = xstrdup(network_addr);
        (*el)->ace.matches.ipv4._is_set = 1;
        (*el)->ace.matches.ipv4.src_ipv4_change_op = change_operation;
        return (*el)->ace.matches.ipv4.source_ipv4_network == NULL;
    }
    return 0;
}

int onm_tc_ace_hash_element_set_match_ipv4_dst_network(onm_tc_ace_element_t** el, const char* network_addr, sr_change_oper_t change_operation)
{
    if ((*el)->ace.matches.ipv4.destination_ipv4_network) {
        FREE_SAFE((*el)->ace.matches.ipv4.destination_ipv4_network);
    }
    if (network_addr) {
        (*el)->ace.matches.ipv4.destination_ipv4_network = xstrdup(network_addr);
        (*el)->ace.matches.ipv4._is_set = 1;
        (*el)->ace.matches.ipv4.dst_ipv4_change_op = change_operation;
        return (*el)->ace.matches.ipv4.destination_ipv4_network == NULL;
    }
    return 0;
}

int onm_tc_ace_hash_element_set_match_ipv6_src_network(onm_tc_ace_element_t** el, const char* network_addr, sr_change_oper_t change_operation)
{
    if ((*el)->ace.matches.ipv6.source_ipv6_network) {
        FREE_SAFE((*el)->ace.matches.ipv6.source_ipv6_network);
    }
    if (network_addr) {
        (*el)->ace.matches.ipv6.source_ipv6_network = xstrdup(network_addr);
        (*el)->ace.matches.ipv6._is_set = 1;
        (*el)->ace.matches.ipv6.src_ipv6_change_op = change_operation;
        return (*el)->ace.matches.ipv6.source_ipv6_network == NULL;
    }
    return 0;
}

int onm_tc_ace_hash_element_set_match_ipv6_dst_network(onm_tc_ace_element_t** el, const char* network_addr, sr_change_oper_t change_operation)
{
    if ((*el)->ace.matches.ipv6.destination_ipv6_network) {
        FREE_SAFE((*el)->ace.matches.ipv6.destination_ipv6_network);
    }
    if (network_addr) {
        (*el)->ace.matches.ipv6.destination_ipv6_network = xstrdup(network_addr);
        (*el)->ace.matches.ipv6._is_set = 1;
         (*el)->ace.matches.ipv6.dst_ipv6_change_op = change_operation;
        return (*el)->ace.matches.ipv6.destination_ipv6_network == NULL;
    }
    return 0;
}

int onm_tc_ace_hash_element_set_match_icmp_code(onm_tc_ace_element_t** el, uint8_t icmp_code, sr_change_oper_t change_operation)
{
    (*el)->ace.matches.icmp.code = icmp_code;
    (*el)->ace.matches.icmp._is_set = 1;
    (*el)->ace.matches.icmp.icmp_code_change_op = change_operation;
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

port_operation_t onm_tc_ace_port_oper_a2i(const char * oper_str)
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

int port_str_to_port_attr (onm_tc_port_attributes_t *port_attr, const char * lower_str, const char * upper_str, const char * port_oper_str,onm_tc_port_attr_direction_t direction, onm_tc_port_attr_proto_t proto)
{
    port_operation_t port_opr = onm_tc_ace_port_oper_a2i(port_oper_str);
    port_attr->port_operation = port_opr;

    if (port_opr == PORT_EQUAL || port_opr == PORT_LTE || port_opr == PORT_GTE || port_opr == PORT_NOT_EQUAL)
    {
        const uint16_t port = (uint16_t)atoi(lower_str);     
        port_attr->direction = direction;
        port_attr->proto = proto;
        port_attr->port = port;
        return 0;
    }
    else if (port_opr == PORT_RANGE)
    {
        const uint16_t lower_port = (uint16_t)atoi(lower_str);
        const uint16_t upper_port = (uint16_t)atoi(upper_str);
        port_attr->direction = direction;
        port_attr->proto = proto;
        port_attr->lower_port = lower_port;
        port_attr->upper_port = upper_port;
        return 0;
    }
    else if (port_opr == PORT_NOOP)
    {
        return -1;
    }
}

int set_ace_port_single(onm_tc_ace_element_t* el, port_operation_t operation, int direction, int proto, onm_tc_port_attributes_t* port_attr, sr_change_oper_t change_operation) {
    if (proto == PORT_ATTR_PROTO_TCP) {
        if (direction == PORT_ATTR_SRC) {
            el->ace.matches.tcp.source_port.port = port_attr->port;
            el->ace.matches.tcp.source_port.port_operation = operation;
            el->ace.matches.tcp.source_port.src_port_value_change_op = change_operation;
            el->ace.matches.tcp._is_set = 1;
        } else {
            el->ace.matches.tcp.destination_port.port = port_attr->port;
            el->ace.matches.tcp.destination_port.port_operation = operation;
            el->ace.matches.tcp.destination_port.dst_port_value_change_op = change_operation;
            el->ace.matches.tcp._is_set = 1;
        }
    } else if (proto == PORT_ATTR_PROTO_UDP) {
        if (direction == PORT_ATTR_SRC) {
            el->ace.matches.udp.source_port.port = port_attr->port;
            el->ace.matches.udp.source_port.port_operation = operation;
            el->ace.matches.udp.source_port.src_port_value_change_op = change_operation;
            el->ace.matches.udp._is_set = 1;
        } else {
            el->ace.matches.udp.destination_port.port = port_attr->port;
            el->ace.matches.udp.destination_port.port_operation = operation;
            el->ace.matches.udp.destination_port.dst_port_value_change_op = change_operation;
            el->ace.matches.udp._is_set = 1;
        }
    }
    return 0;
}

int set_ace_port_range(onm_tc_ace_element_t* el, port_operation_t operation, int direction, int proto, onm_tc_port_attributes_t* port_attr, sr_change_oper_t change_operation) {
    if (proto == PORT_ATTR_PROTO_TCP) {
        if (direction == PORT_ATTR_SRC) {
            el->ace.matches.tcp.source_port.lower_port = port_attr->lower_port;
            el->ace.matches.tcp.source_port.upper_port = port_attr->upper_port;
            el->ace.matches.tcp.source_port.port_operation = operation;
            el->ace.matches.tcp.source_port.src_port_value_change_op = change_operation;
            el->ace.matches.tcp._is_set = 1;
        } else {
            el->ace.matches.tcp.destination_port.lower_port = port_attr->lower_port;
            el->ace.matches.tcp.destination_port.upper_port = port_attr->upper_port;
            el->ace.matches.tcp.destination_port.port_operation = operation;
            el->ace.matches.tcp.destination_port.dst_port_value_change_op = change_operation;
            el->ace.matches.tcp._is_set = 1;
        }
    } else if (proto == PORT_ATTR_PROTO_UDP) {
        if (direction == PORT_ATTR_SRC) {
            el->ace.matches.udp.source_port.lower_port = port_attr->lower_port;
            el->ace.matches.udp.source_port.upper_port = port_attr->upper_port;
            el->ace.matches.udp.source_port.port_operation = operation;
            el->ace.matches.udp.source_port.src_port_value_change_op = change_operation;
            el->ace.matches.udp._is_set = 1;
        } else {
            el->ace.matches.udp.destination_port.lower_port = port_attr->lower_port;
            el->ace.matches.udp.destination_port.upper_port = port_attr->upper_port;
            el->ace.matches.udp.destination_port.port_operation = operation;
            el->ace.matches.udp.destination_port.dst_port_value_change_op = change_operation;
            el->ace.matches.udp._is_set = 1;
        }
    }
    return 0;
}

int onm_tc_ace_hash_element_set_match_port(onm_tc_ace_element_t** el, onm_tc_port_attributes_t* port_attr, sr_change_oper_t change_operation) 
{
    if (port_attr->port_operation != PORT_RANGE) {
        return set_ace_port_single(*el, port_attr->port_operation, port_attr->direction, port_attr->proto, port_attr, change_operation);
    } else {
        return set_ace_port_range(*el, port_attr->port_operation, port_attr->direction, port_attr->proto, port_attr, change_operation);
    }
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

onm_tc_ace_element_t* get_ace_in_acl_list(const char* acl_name, const char* ace_name, onm_tc_acl_hash_element_t* acl_hash) 
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
        printf("success\n");
        return 0; // Success
    }
    else
    {
        return -1; // ACL not found
    }
}

int events_acls_hash_add_ace_element(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx)
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

        
        if (strcmp(node_name,"name")==0)
        {
            SRPLG_LOG_INF(PLUGIN_NAME, "Adding new change ACE to Change ACLs list change, ACE Name: %s, Change operation: %d.",node_value,change_ctx->operation);
            SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_ace_name(&new_ace, node_value,change_ctx->operation), error_out);
        }
        // make sure acl exits in acls list
        if (!(onm_tc_acl_hash_get_element(&ctx->events_acls_list,acl_name_buffer)))
        {
            onm_tc_acl_hash_element_t* temp_acl = onm_tc_acl_hash_element_new();
            SRPC_SAFE_CALL_ERR(error, onm_tc_acl_hash_element_set_name(&temp_acl, acl_name_buffer,change_ctx->operation), error_out);
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
}

int events_acls_hash_update_ace_element(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx)
{
    int error = 0;
    int default_change_operation = -1;
    const char *node_name = LYD_NAME(change_ctx->node);
	const char *parent_node_name = LYD_NAME(&change_ctx->node->parent->node);
    const char *grand_parent_node_name = LYD_NAME(&change_ctx->node->parent->node.parent->node);
	const char *node_value = lyd_get_value(change_ctx->node);
    onm_tc_ctx_t *ctx = (onm_tc_ctx_t *) priv;
    char change_path[PATH_MAX] = {0};
    char acl_name_buffer[100] = {0};
    char ace_name_buffer[100] = {0};

    if (node_value)
    {
        error = (lyd_path(change_ctx->node, LYD_PATH_STD, change_path, sizeof(change_path)) != NULL);
        SRPC_SAFE_CALL_ERR(error, srpc_extract_xpath_key_value(change_path, "acl", "name", acl_name_buffer, sizeof(acl_name_buffer)), error_out);
        SRPC_SAFE_CALL_ERR(error, srpc_extract_xpath_key_value(change_path, "ace", "name", ace_name_buffer, sizeof(ace_name_buffer)), error_out);
        printf("ADD ACL DATA:\n\tNode Name: %s\n\tNode Value: %s\n\tParent Node Name: %s\n\tGrand Parent Name: %s\n\tOperation: %d\n",node_name,node_value,parent_node_name,grand_parent_node_name,change_ctx->operation);
        onm_tc_ace_element_t* updated_ace = get_ace_in_acl_list(acl_name_buffer,ace_name_buffer,ctx->events_acls_list);
        
        // make sure acl exits in acls list
        onm_tc_acl_hash_element_t* updated_acl = onm_tc_acl_hash_get_element(&ctx->events_acls_list,acl_name_buffer);
        if (!updated_acl)
        {
            printf("update on ace of an acl that is not present in change acl\n");
            // add new acl data
            updated_acl = onm_tc_acl_hash_element_new();
            SRPC_SAFE_CALL_ERR(error, onm_tc_acl_hash_element_set_name(&updated_acl, acl_name_buffer,default_change_operation), error_out);
            ONM_TC_ACL_LIST_NEW(updated_acl->acl.aces.ace);

            // add new ace data to new acl
            updated_ace = onm_tc_ace_hash_element_new();
            onm_tc_ace_hash_element_set_ace_name(&updated_ace,ace_name_buffer,default_change_operation);

            ONM_TC_ACL_LIST_ADD_ELEMENT(updated_acl->acl.aces.ace, updated_ace);
            
            // add updated_acl to change acls list
            onm_tc_acls_hash_add_acl_element(&ctx->events_acls_list,updated_acl);
        }

        // acl exist, make sure ace exists
        else if (!updated_ace)
        {
            printf("update on ace that is not present in change acl\n");
            updated_ace = onm_tc_ace_hash_element_new();
            onm_tc_ace_hash_element_set_ace_name(&updated_ace,ace_name_buffer,default_change_operation);
            
            error = acls_list_add_ace_element(&ctx->events_acls_list,acl_name_buffer,updated_ace);
        }

        //update ace in change acls list
        ace_element_update_data(updated_ace,node_name, node_value,change_ctx->operation);
        
        goto out;
    }

error_out:
	return error;

out:
	return error;
}

int ace_element_update_data(onm_tc_ace_element_t* updated_ace, const char * node_name, const char * node_value,sr_change_oper_t change_operation) {
    int error = 0;

    if (updated_ace == NULL || node_name == NULL || node_value == NULL) {
        return -1;
    }
    //L2 match
    if (strcmp(node_name,"source-mac-address")==0)
    {
        onm_tc_ace_hash_element_set_match_src_mac_addr(&updated_ace, node_value,change_operation);
    }

    if (strcmp(node_name,"source-mac-address-mask")==0)
        onm_tc_ace_hash_element_set_match_src_mac_addr_mask(&updated_ace, node_value,change_operation);

    if (strcmp(node_name,"destination-mac-address")==0)
        onm_tc_ace_hash_element_set_match_dst_mac_addr(&updated_ace, node_value,change_operation);

    if (strcmp(node_name,"destination-mac-address-mask")==0)
        onm_tc_ace_hash_element_set_match_dst_mac_addr_mask(&updated_ace, node_value,change_operation);

    if (strcmp(node_name,"ethertype")==0)
    {
        uint16_t ether_type;
        if (ll_proto_a2n(&ether_type, node_value))
        {
            // TODO revise: currently this failure will set ethertype to ALL
            //SRPLG_LOG_ERR(PLUGIN_NAME, "ACE %s Failed to set specified EtherType for L2 match",);
            return -1;
        }
        else
        {
            onm_tc_ace_hash_element_set_match_eth_ethertype(&updated_ace, ether_type,change_operation);
        }
        
    }

    // L3
    if (strcmp(node_name,"source-ipv4-network")==0)
        onm_tc_ace_hash_element_set_match_ipv4_src_network(&updated_ace,node_value,change_operation);

    if (strcmp(node_name,"destination-ipv4-network")==0)
        onm_tc_ace_hash_element_set_match_ipv4_dst_network(&updated_ace,node_value,change_operation);

    if (strcmp(node_name,"source-ipv6-network")==0)
        onm_tc_ace_hash_element_set_match_ipv6_src_network(&updated_ace,node_value,change_operation);

    if (strcmp(node_name,"destination-ipv6-network")==0)
        onm_tc_ace_hash_element_set_match_ipv6_dst_network(&updated_ace,node_value,change_operation);

    // L4
    if (strcmp(node_name,"port")==0)
    {

    }

    return 0; // Update successful
}