#include "plugin/api/acls/acl/ace_change.h"
#include "plugin/api/tcnl.h"
#include "plugin/common.h"
#include "plugin/data/acls/acl/aces.h"

bool ace_reconstruct_needed(onm_tc_ace_element_t* ace){
	/*if (ace->ace.matches.eth.source_address_mask_change_op == SR_OP_MODIFIED || 
	ace->ace.matches.eth.destination_address_mask_change_op == SR_OP_MODIFIED) {
		return true;
	}
	else{
		return false;
	}*/
	return true;
}

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
	}
	else {
		SRPLG_LOG_INF(PLUGIN_NAME, "Change event extract change operation set, found no matching operation element, ACE Name %s, Priority %d",ace->ace.name,ace->ace.priority);
		onm_tc_ace_free(&ret_ace);
		return NULL;
	}

    return ret_ace;
}

int apply_ace_created_operation(onm_tc_ace_element_t * ace, unsigned int acl_id){
	int ret = 0;
	int change_op_set[] = {SR_OP_CREATED};
	size_t set_size = sizeof(change_op_set) / sizeof(change_op_set[0]);
	onm_tc_ace_element_t* created_ace = extract_ace_elements_with_change_ops(ace,change_op_set,set_size);
	if (created_ace == NULL){
		SRPLG_LOG_ERR(PLUGIN_NAME, "Change operation 'ACE Created' no ACE elements found, ACE Name %s, Priority %d",ace->ace.name,ace->ace.priority);
		return -1;
	}
	ret = tcnl_filter_modify_ace(acl_id,created_ace,RTM_DELTFILTER,0);
	onm_tc_ace_element_free(&created_ace);
	return ret;
}

int apply_ace_deleted_operation(onm_tc_ace_element_t * ace, unsigned int acl_id){
	int ret = 0;
	int change_op_set[] = {SR_OP_MODIFIED, DEFAULT_CHANGE_OPERATION, SR_OP_DELETED};
	size_t set_size = sizeof(change_op_set) / sizeof(change_op_set[0]);
	onm_tc_ace_element_t* deleted_ace = extract_ace_elements_with_change_ops(ace,change_op_set,set_size);
	if (deleted_ace == NULL){
		SRPLG_LOG_ERR(PLUGIN_NAME, "Change operation 'ACE Deleted' no ACE elements found, ACE Name %s, Priority %d",ace->ace.name,ace->ace.priority);
		return -1;
	}
	ret = tcnl_filter_modify_ace(acl_id,deleted_ace,RTM_DELTFILTER,0);
	onm_tc_ace_element_free(&deleted_ace);
	return ret;
}

int apply_ace_modified_operation(onm_tc_ace_element_t * ace, unsigned int acl_id){
	int ret = 0;
	// delete existing ace tc config
	ret = tcnl_filter_modify_ace(acl_id,ace,RTM_DELTFILTER,0);

	// create modified ace
	int created_op_set[] = {SR_OP_MODIFIED, DEFAULT_CHANGE_OPERATION, SR_OP_CREATED};
	int set_size = sizeof(created_op_set) / sizeof(created_op_set[0]);
	onm_tc_ace_element_t* created_ace = extract_ace_elements_with_change_ops(ace,created_op_set,set_size);
	if (created_ace == NULL){
		SRPLG_LOG_ERR(PLUGIN_NAME, "Change operation 'ACE Modified' no ACE elements found, ACE Name %s, Priority %d",ace->ace.name,ace->ace.priority);
		return -1;
	}
	ret = tcnl_filter_modify_ace(acl_id,created_ace,RTM_NEWTFILTER,0);
	onm_tc_ace_element_free(&created_ace);
	return ret;
}


int apply_events_ace_changes(onm_tc_ctx_t * ctx, unsigned int acl_id, onm_tc_ace_element_t* ace){
	int ret = 0;
	switch (ace->ace.name_change_op) {
		case SR_OP_CREATED:
			// handle complete ACE creation
			SRPLG_LOG_INF(PLUGIN_NAME, "Apply 'ACE Created' operation, ACE Name %s, Priority %d",ace->ace.name,ace->ace.priority);
			ret = apply_ace_created_operation(ace,acl_id);
			break;
		case SR_OP_DELETED:
			// handle complete ACE delete operation
			SRPLG_LOG_INF(PLUGIN_NAME, "Apply 'ACE Deleted' operation, ACE Name %s, Priority %d",ace->ace.name,ace->ace.priority);
			ret = apply_ace_deleted_operation(ace,acl_id);
			if (ret < 0){
				return ret;
			}
			break;
		case DEFAULT_CHANGE_OPERATION: {
				// handle individual ace elements SR_OP_MODIFIED, SR_OP_CREATED, SR_OP_DELETED
				SRPLG_LOG_INF(PLUGIN_NAME, "Apply 'ACE Modified' operation, ACE Name %s, Priority %d",ace->ace.name,ace->ace.priority);
				ret = apply_ace_modified_operation(ace,acl_id);
				if (ret < 0){
					return ret; 
				}

			}
			break;
	}
	return 0;
}