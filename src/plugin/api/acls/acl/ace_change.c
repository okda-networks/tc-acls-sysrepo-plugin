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

bool is_change_op_in_set(int change_op, const int* change_op_set, size_t set_size) {
    for (size_t i = 0; i < set_size; ++i) {
        if (change_op == change_op_set[i]) {
            return true;
        }
    }
    return false;
}

onm_tc_ace_element_t* get_ace_elements_with_change_ops(const onm_tc_ace_element_t* ace, const int* change_op_set, size_t set_size) {
    if (ace == NULL || change_op_set == NULL || set_size == 0) {
        return NULL;
    }
	bool is_updated = false;
	onm_tc_ace_element_t* ret_ace = malloc(sizeof(onm_tc_ace_element_t));
    if (ret_ace == NULL) {
        return NULL;
    }
    memset(ret_ace, 0, sizeof(onm_tc_ace_element_t));

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
    if (is_change_op_in_set(ace->ace.matches.tcp.source_port.port_change_op, change_op_set, set_size)) {
		ret_ace->ace.matches.tcp.source_port.port_operator = ace->ace.matches.tcp.source_port.port_operator;
        ret_ace->ace.matches.tcp.source_port.port = ace->ace.matches.tcp.source_port.port;
		ret_ace->ace.matches.tcp.source_port.lower_port = ace->ace.matches.tcp.source_port.lower_port;
		ret_ace->ace.matches.tcp.source_port.upper_port = ace->ace.matches.tcp.source_port.upper_port;
		ret_ace->ace.matches.tcp._is_set = ace->ace.matches.tcp._is_set;
        ret_ace->ace.matches.tcp.source_port.port_change_op = ace->ace.matches.tcp.source_port.port_change_op;
		is_updated = true;
    }
	// TCP destination port
	if (is_change_op_in_set(ace->ace.matches.tcp.destination_port.port_change_op, change_op_set, set_size)) {
        ret_ace->ace.matches.tcp.destination_port.port_operator = ace->ace.matches.tcp.destination_port.port_operator;
        ret_ace->ace.matches.tcp.destination_port.port = ace->ace.matches.tcp.destination_port.port;
        ret_ace->ace.matches.tcp.destination_port.lower_port = ace->ace.matches.tcp.destination_port.lower_port;
        ret_ace->ace.matches.tcp.destination_port.upper_port = ace->ace.matches.tcp.destination_port.upper_port;
		ret_ace->ace.matches.tcp._is_set = ace->ace.matches.tcp._is_set;
        ret_ace->ace.matches.tcp.destination_port.port_change_op = ace->ace.matches.tcp.destination_port.port_change_op;
		is_updated = true;
    }

    // UDP source port
    if (is_change_op_in_set(ace->ace.matches.udp.source_port.port_change_op, change_op_set, set_size)) {
        ret_ace->ace.matches.udp.source_port.port_operator = ace->ace.matches.udp.source_port.port_operator;
        ret_ace->ace.matches.udp.source_port.port = ace->ace.matches.udp.source_port.port;
        ret_ace->ace.matches.udp.source_port.lower_port = ace->ace.matches.udp.source_port.lower_port;
        ret_ace->ace.matches.udp.source_port.upper_port = ace->ace.matches.udp.source_port.upper_port;
		ret_ace->ace.matches.udp._is_set = ace->ace.matches.udp._is_set;
        ret_ace->ace.matches.udp.source_port.port_change_op = ace->ace.matches.udp.source_port.port_change_op;
		is_updated = true;
    }

    // UDP destination port
    if (is_change_op_in_set(ace->ace.matches.udp.destination_port.port_change_op, change_op_set, set_size)) {
        ret_ace->ace.matches.udp.destination_port.port_operator = ace->ace.matches.udp.destination_port.port_operator;
        ret_ace->ace.matches.udp.destination_port.port = ace->ace.matches.udp.destination_port.port;
        ret_ace->ace.matches.udp.destination_port.lower_port = ace->ace.matches.udp.destination_port.lower_port;
        ret_ace->ace.matches.udp.destination_port.upper_port = ace->ace.matches.udp.destination_port.upper_port;
		ret_ace->ace.matches.udp._is_set = ace->ace.matches.udp._is_set;
        ret_ace->ace.matches.udp.destination_port.port_change_op = ace->ace.matches.udp.destination_port.port_change_op;
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
		printf("setting ace name to %s\n", ace->ace.name);
		printf("setting ace priority to %d\n", ace->ace.priority);
		onm_tc_ace_hash_element_set_ace_name(&ret_ace,ace->ace.name, ace->ace.name_change_op);
		onm_tc_ace_hash_element_set_ace_priority(&ret_ace,ace->ace.priority, ace->ace.prio_change_op);
	}
	else {
		onm_tc_ace_free(&ret_ace);
		return NULL;
	}

    return ret_ace;
}

int apply_ace_modified_change(onm_tc_ace_element_t * ace, unsigned int acl_id){
	int ret = 0;
	int change_op_set[] = {SR_OP_MODIFIED, SR_OP_DELETED, DEFAULT_CHANGE_OPERATION};
	size_t set_size = sizeof(change_op_set) / sizeof(change_op_set[0]);
	onm_tc_ace_element_t* modified_ace = get_ace_elements_with_change_ops(ace,change_op_set,set_size);
	if (ace_reconstruct_needed(modified_ace)){
		tcnl_filter_modify_ace(acl_id,modified_ace,RTM_DELTFILTER,0);
	}
	ret = tcnl_filter_modify_ace(acl_id,modified_ace,RTM_NEWTFILTER,0);
	return ret;
}

int apply_ace_deleted_change(onm_tc_ace_element_t * ace, unsigned int acl_id){
	int ret = 0;
	int change_op_set[] = {SR_OP_MODIFIED, SR_OP_DELETED, DEFAULT_CHANGE_OPERATION};
	size_t set_size = sizeof(change_op_set) / sizeof(change_op_set[0]);
	onm_tc_ace_element_t* modified_ace = get_ace_elements_with_change_ops(ace,change_op_set,set_size);
	ret = tcnl_filter_modify_ace(acl_id,modified_ace,RTM_DELTFILTER,0);
	if (ret < 0) {
		return ret;
	}
	return ret;
}

int apply_events_ace_changes(onm_tc_ctx_t * ctx, unsigned int acl_id, onm_tc_ace_element_t* ace){
	int ret = 0;
	switch (ace->ace.name_change_op) {
		case SR_OP_CREATED:
			// handle complete ACE creation
			break;
		case SR_OP_DELETED:
			// handle complete ACE delete
			printf("ace delete \n");
			ret = apply_ace_deleted_change(ace,acl_id);
			break;
		case DEFAULT_CHANGE_OPERATION: {
				// handle individual ace elements SR_OP_MODIFIED, SR_OP_CREATED, SR_OP_DELETED
				// handle modifed:
				ret = apply_ace_modified_change(ace,acl_id);
				if (ret < 0){
					printf("return apply_ace_event_modified_change %d\n",ret);
					return ret; 
				}

			}
			break;
	}
	return 0;
}