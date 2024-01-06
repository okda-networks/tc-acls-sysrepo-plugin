#include "plugin/api/acls/acl/ace_change.h"
#include "plugin/api/tcnl.h"
#include "plugin/common.h"
#include "plugin/data/acls/acl/aces.h"


bool is_change_op_in_set(int change_op, const int change_op_set[], size_t set_size) {
	bool result = false;
    for (size_t i = 0; i < set_size; ++i) {
        if (change_op == change_op_set[i]) {
            result = true;
        }
    }
    return result;
}

onm_tc_ace_element_t* extract_ace_elements_with_change_ops(const onm_tc_ace_element_t* ace, const int change_op_set[], size_t set_size) {
    if (ace == NULL || set_size == 0) {
        return NULL;
    }

	bool is_updated = false;
	onm_tc_ace_element_t * ret_ace = onm_tc_ace_hash_element_new();
    if (ret_ace == NULL) {
        return NULL;
    }
	
    // eth
    if (is_change_op_in_set(ace->ace.matches.eth.source_address_change_op, change_op_set, set_size)) {
		onm_tc_ace_hash_element_set_match_src_mac_addr(&ret_ace,ace->ace.matches.eth.source_address,ace->ace.matches.eth.source_address_change_op);
		is_updated = true;
    }
    if (is_change_op_in_set(ace->ace.matches.eth.destination_address_change_op, change_op_set, set_size)) {
        onm_tc_ace_hash_element_set_match_dst_mac_addr(&ret_ace,ace->ace.matches.eth.destination_address,ace->ace.matches.eth.destination_address_change_op);
		is_updated = true;
    }
	if (is_change_op_in_set(ace->ace.matches.eth.source_address_mask_change_op, change_op_set, set_size)) {
		onm_tc_ace_hash_element_set_match_src_mac_addr_mask(&ret_ace,ace->ace.matches.eth.source_address_mask,ace->ace.matches.eth.source_address_mask_change_op);
		is_updated = true;
    }
    if (is_change_op_in_set(ace->ace.matches.eth.destination_address_mask_change_op, change_op_set, set_size)) {
        onm_tc_ace_hash_element_set_match_dst_mac_addr_mask(&ret_ace,ace->ace.matches.eth.destination_address_mask,ace->ace.matches.eth.destination_address_mask_change_op);
		is_updated = true;
    }
	if (is_change_op_in_set(ace->ace.matches.eth.ethertype_change_op, change_op_set, set_size)) {
        onm_tc_ace_hash_element_set_match_eth_ethertype(&ret_ace,ace->ace.matches.eth.ethertype,ace->ace.matches.eth.ethertype_change_op);
		is_updated = true;
    }
	
	// ipv4
	if (is_change_op_in_set(ace->ace.matches.ipv4.source_network_change_op, change_op_set, set_size)) {
        onm_tc_ace_hash_element_set_match_ipv4_src_network(&ret_ace,ace->ace.matches.ipv4.source_network,ace->ace.matches.ipv4.source_network_change_op);
		is_updated = true;
    }
	if (is_change_op_in_set(ace->ace.matches.ipv4.destination_network_change_op, change_op_set, set_size)) {
        onm_tc_ace_hash_element_set_match_ipv4_dst_network(&ret_ace,ace->ace.matches.ipv4.destination_network,ace->ace.matches.ipv4.destination_network_change_op);
		is_updated = true;
    }

	// ipv6
	if (is_change_op_in_set(ace->ace.matches.ipv6.source_network_change_op, change_op_set, set_size)) {
        onm_tc_ace_hash_element_set_match_ipv6_src_network(&ret_ace,ace->ace.matches.ipv6.source_network,ace->ace.matches.ipv6.source_network_change_op);
		is_updated = true;
    }
	if (is_change_op_in_set(ace->ace.matches.ipv6.destination_network_change_op, change_op_set, set_size)) {
        onm_tc_ace_hash_element_set_match_ipv6_dst_network(&ret_ace,ace->ace.matches.ipv6.destination_network,ace->ace.matches.ipv6.destination_network_change_op);
		is_updated = true;
    }

	// TCP source port 
    if (is_change_op_in_set(ace->ace.matches.tcp.source_port.single_port_change_op, change_op_set, set_size)) {
		ret_ace->ace.matches.tcp.source_port.port_operator = ace->ace.matches.tcp.source_port.port_operator;
        ret_ace->ace.matches.tcp.source_port.port = ace->ace.matches.tcp.source_port.port;
		ret_ace->ace.matches.tcp._is_set = ace->ace.matches.tcp._is_set;
        ret_ace->ace.matches.tcp.source_port.single_port_change_op = ace->ace.matches.tcp.source_port.single_port_change_op;
		is_updated = true;
    }
	// TCP destination port
	if (is_change_op_in_set(ace->ace.matches.tcp.destination_port.single_port_change_op, change_op_set, set_size)) {
        ret_ace->ace.matches.tcp.destination_port.port_operator = ace->ace.matches.tcp.destination_port.port_operator;
        ret_ace->ace.matches.tcp.destination_port.port = ace->ace.matches.tcp.destination_port.port;
		ret_ace->ace.matches.tcp._is_set = ace->ace.matches.tcp._is_set;
        ret_ace->ace.matches.tcp.destination_port.single_port_change_op = ace->ace.matches.tcp.destination_port.single_port_change_op;
		is_updated = true;
    }

    // UDP source port
    if (is_change_op_in_set(ace->ace.matches.udp.source_port.single_port_change_op, change_op_set, set_size)) {
        ret_ace->ace.matches.udp.source_port.port_operator = ace->ace.matches.udp.source_port.port_operator;
        ret_ace->ace.matches.udp.source_port.port = ace->ace.matches.udp.source_port.port;
		ret_ace->ace.matches.udp._is_set = ace->ace.matches.udp._is_set;
        ret_ace->ace.matches.udp.source_port.single_port_change_op = ace->ace.matches.udp.source_port.single_port_change_op;
		is_updated = true;
    }

    // UDP destination port
    if (is_change_op_in_set(ace->ace.matches.udp.destination_port.single_port_change_op, change_op_set, set_size)) {
        ret_ace->ace.matches.udp.destination_port.port_operator = ace->ace.matches.udp.destination_port.port_operator;
        ret_ace->ace.matches.udp.destination_port.port = ace->ace.matches.udp.destination_port.port;
		ret_ace->ace.matches.udp._is_set = ace->ace.matches.udp._is_set;
        ret_ace->ace.matches.udp.destination_port.single_port_change_op = ace->ace.matches.udp.destination_port.single_port_change_op;
		is_updated = true;
    }


	// TCP source range 
    if (is_change_op_in_set(ace->ace.matches.tcp.source_port.range_port_change_op, change_op_set, set_size)) {
		ret_ace->ace.matches.tcp.source_port.lower_port = ace->ace.matches.tcp.source_port.lower_port;
		ret_ace->ace.matches.tcp.source_port.upper_port = ace->ace.matches.tcp.source_port.upper_port;
		ret_ace->ace.matches.tcp._is_set = ace->ace.matches.tcp._is_set;
        ret_ace->ace.matches.tcp.source_port.range_port_change_op = ace->ace.matches.tcp.source_port.range_port_change_op;
		is_updated = true;
    }
	// TCP destination range
	if (is_change_op_in_set(ace->ace.matches.tcp.destination_port.range_port_change_op, change_op_set, set_size)) {
        ret_ace->ace.matches.tcp.destination_port.lower_port = ace->ace.matches.tcp.destination_port.lower_port;
        ret_ace->ace.matches.tcp.destination_port.upper_port = ace->ace.matches.tcp.destination_port.upper_port;
		ret_ace->ace.matches.tcp._is_set = ace->ace.matches.tcp._is_set;
        ret_ace->ace.matches.tcp.destination_port.range_port_change_op = ace->ace.matches.tcp.destination_port.range_port_change_op;
		is_updated = true;
    }

    // UDP source range
    if (is_change_op_in_set(ace->ace.matches.udp.source_port.range_port_change_op, change_op_set, set_size)) {
        ret_ace->ace.matches.udp.source_port.lower_port = ace->ace.matches.udp.source_port.lower_port;
        ret_ace->ace.matches.udp.source_port.upper_port = ace->ace.matches.udp.source_port.upper_port;
		ret_ace->ace.matches.udp._is_set = ace->ace.matches.udp._is_set;
        ret_ace->ace.matches.udp.source_port.range_port_change_op = ace->ace.matches.udp.source_port.range_port_change_op;
		is_updated = true;
    }

    // UDP destination range
    if (is_change_op_in_set(ace->ace.matches.udp.destination_port.range_port_change_op, change_op_set, set_size)) {
        ret_ace->ace.matches.udp.destination_port.lower_port = ace->ace.matches.udp.destination_port.lower_port;
        ret_ace->ace.matches.udp.destination_port.upper_port = ace->ace.matches.udp.destination_port.upper_port;
		ret_ace->ace.matches.udp._is_set = ace->ace.matches.udp._is_set;
        ret_ace->ace.matches.udp.destination_port.range_port_change_op = ace->ace.matches.udp.destination_port.range_port_change_op;
		is_updated = true;
    }


	// action forwarding
	if (is_change_op_in_set(ace->ace.actions.forwarding_change_op, change_op_set, set_size)){
		ret_ace->ace.actions.forwarding = ace->ace.actions.forwarding;
		ret_ace->ace.actions.forwarding_change_op = ace->ace.actions.forwarding_change_op;
		is_updated = true;
	}
	// action logging
	if (is_change_op_in_set(ace->ace.actions.logging_change_op, change_op_set, set_size)){
		ret_ace->ace.actions.logging = ace->ace.actions.logging;
		ret_ace->ace.actions.logging_change_op = ace->ace.actions.logging_change_op;
		is_updated = true;
	}

	if (is_updated){
		SRPLG_LOG_INF(PLUGIN_NAME, "Change event extract change operation set success, ACE name %s, Priority %d",ace->ace.name,ace->ace.priority);
		onm_tc_ace_hash_element_set_ace_name(&ret_ace,ace->ace.name, ace->ace.name_change_op);
		onm_tc_ace_hash_element_set_ace_priority(&ret_ace,ace->ace.priority, ace->ace.prio_change_op);
		onm_tc_ace_hash_element_set_ace_handle(&ret_ace,ace->ace.handle);
	}
	else {
		SRPLG_LOG_INF(PLUGIN_NAME, "Change event extract change operation set, found no matching operation element, ACE Name %s, Priority %d",ace->ace.name,ace->ace.priority);
		onm_tc_ace_free(&ret_ace);
		return NULL;
	}

    return ret_ace;
}

int apply_ace_created_operation(onm_tc_ctx_t * ctx, onm_tc_ace_element_t * ace, unsigned int acl_id){
	int ret = 0;
	int change_op_set[] = {SR_OP_CREATED};
	size_t set_size = sizeof(change_op_set) / sizeof(change_op_set[0]);
	onm_tc_ace_element_t* created_ace = extract_ace_elements_with_change_ops(ace,change_op_set,set_size);
	if (created_ace == NULL){
		SRPLG_LOG_ERR(PLUGIN_NAME, "Change operation 'ACE Created', ace element is NULL");
		return -1;
	}
	SRPLG_LOG_INF(PLUGIN_NAME, "Apply change operation 'ACE Created' ACE Name %s, Priority %d",ace->ace.name,ace->ace.priority);
	onm_tc_ace_hash_print_debug(ace);
	ret = tcnl_filter_modify(created_ace,acl_id,ctx, RTM_NEWTFILTER,NLM_F_CREATE,true);
	onm_tc_ace_element_free(&created_ace);
	return ret;
}

int apply_ace_deleted_operation(onm_tc_ctx_t * ctx, onm_tc_ace_element_t * ace, unsigned int acl_id){
	int ret = 0;
	if (ace == NULL) {
		SRPLG_LOG_ERR(PLUGIN_NAME, "Change operation 'ACE Deleted', ace element is NULL");
		return -1;
	}

	SRPLG_LOG_INF(PLUGIN_NAME, "Apply change operation 'ACE Deleted' ACE Name %s, Priority %d",ace->ace.name,ace->ace.priority);
	ret = tcnl_filter_modify(ace,acl_id,ctx,RTM_DELTFILTER,0,false);
	return ret;
}

int apply_ace_modified_operation(onm_tc_ctx_t * ctx, onm_tc_ace_element_t * ace, onm_tc_ace_element_t* running_ace, unsigned int acl_id){
	int ret = 0;
	// create modified ace
	int modified_op_set[] = {SR_OP_MODIFIED, DEFAULT_CHANGE_OPERATION, SR_OP_CREATED};
	int set_size = sizeof(modified_op_set) / sizeof(modified_op_set[0]);
	onm_tc_ace_element_t* modified_ace = extract_ace_elements_with_change_ops(ace,modified_op_set,set_size);
	if (modified_ace == NULL){
		SRPLG_LOG_ERR(PLUGIN_NAME, "Change operation 'ACE Modified', ace element is NULL");
		return -1;
	}
	if (running_ace){
		// delete operational ace if the priority is different
		if (running_ace->ace.priority > modified_ace->ace.priority){
			ret = apply_ace_deleted_operation(ctx,running_ace,acl_id);
		}
	}
	if (ret<0){
		SRPLG_LOG_ERR(PLUGIN_NAME, "Change operation 'ACE Deleted' failed, ACE Name %s, Priority %d",ace->ace.name,ace->ace.priority);
	}
	SRPLG_LOG_INF(PLUGIN_NAME, "Apply change operation 'ACE Modifed' ACE Name %s, Priority %d",ace->ace.name,ace->ace.priority);
	ret = tcnl_filter_modify(modified_ace,acl_id,ctx,RTM_NEWTFILTER,NLM_F_CREATE,true);
	onm_tc_ace_element_free(&modified_ace);
	return ret;
}


int apply_events_ace_changes(onm_tc_ctx_t * ctx, const char * acl_name, unsigned int acl_id, onm_tc_ace_element_t* ace){
	int ret = 0;
	switch (ace->ace.name_change_op) {
		case SR_OP_CREATED:
			// handle complete ACE creation
			SRPLG_LOG_INF(PLUGIN_NAME, "Apply 'ACE Created' operation, ACE Name %s, Priority %d",ace->ace.name,ace->ace.priority);
			ret = apply_ace_created_operation(ctx,ace,acl_id);
			if (ret < 0){
				return ret;
			}
			break;
		case SR_OP_DELETED: {
				// handle complete ACE delete operation
				onm_tc_ace_element_t * running_ace = onm_tc_get_ace_in_acl_list_by_name(ctx->running_acls_list,acl_name,ace->ace.name);
				if(!running_ace){
					printf("Failed to get running ace to delete ace name %s",ace->ace.name);
					return -1;
				}
				ret = apply_ace_deleted_operation(ctx,running_ace,acl_id);
				if (ret < 0){
					return ret;
				}
			}
			break;
		case SR_OP_MOVED:{
			// handle ace moved operation
			// no longer handled here
			break;
		}
		case DEFAULT_CHANGE_OPERATION: {
				// handle individual ace elements SR_OP_MODIFIED, SR_OP_CREATED, SR_OP_DELETED
				printf("apply ace modifed changes %s change op %d\n",ace->ace.name,ace->ace.name_change_op);
				onm_tc_ace_element_t * running_ace = onm_tc_get_ace_in_acl_list_by_name(ctx->running_acls_list,acl_name,ace->ace.name);
				if (!running_ace){
					printf("this is the problem\n");
				}
				ret = apply_ace_modified_operation(ctx, ace,running_ace,acl_id);
				if (ret < 0){
					return ret; 
				}
			}
			break;
	}
	return 0;
}