#include "acl_change.h"
#include "plugin/common.h"

#include <sysrepo.h>
#include "plugin/data/acls/acl.h"
#include "plugin/api/acls/acl/ace_change.h"
#include <stdio.h>
#include <linux/limits.h>
#include "plugin/context.h"

#include "plugin/data/acls/acl.h"
#include "plugin/data/acls/acl/aces.h"

#include "plugin/data/acls/acl/linked_list.h"
#include "sysrepo/xpath.h"
#include "plugin/api/acls/acl_change.h"

#include "plugin/api/tcnl.h"

int apply_events_acls_hash(onm_tc_ctx_t * ctx){
	onm_tc_acl_hash_element_t * events_acls = ctx->events_acls_list;
	int ret = 0;
    onm_tc_acl_hash_element_t *iter = NULL, *tmp = NULL;
    onm_tc_ace_element_t* ace_iter = NULL;
	char* acl_name = NULL;
	SRPLG_LOG_INF(PLUGIN_NAME, "Apply change event data");
    HASH_ITER(hh, events_acls, iter, tmp)
	{
		acl_name = iter->acl.name;
    	unsigned int acl_id = acl_name2id(acl_name);
		SRPLG_LOG_INF(PLUGIN_NAME, "Apply change event data for acl %d",acl_id);
		ret = tcnl_filter_flower_modify(acl_id,ctx->events_acls_list);
		if (ret){
			return -1; 
		}
	}
	
}

int validate_and_update_events_acls_hash(onm_tc_ctx_t * ctx)
{
	onm_tc_acl_hash_element_t * events_acls = ctx->events_acls_list;
	onm_tc_acl_hash_element_t * running_acls = ctx->running_acls_list;


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
		iter->acl.name, iter->acl.acl_name_change_op);
		// if acl name event is SR_OP_CREATED or SR_OP_DELETED, no need to continue validation
		if (iter->acl.acl_name_change_op != DEFAUTL_CHANGE_OPERATION){
			continue;
		}

        LL_FOREACH(iter->acl.aces.ace, ace_iter){
			if (!ace_iter->ace.name){
				SRPLG_LOG_ERR(PLUGIN_NAME, "Bad ACE element");
				return -1;
			}
			SRPLG_LOG_INF(PLUGIN_NAME, "Validating ACE '%s' data, event change operation '%d'",
			ace_iter->ace.name, ace_iter->ace.ace_name_change_op);
			// if ace name event is SR_OP_CREATED or SR_OP_DELETED, no need to continue validation
			if (ace_iter->ace.ace_name_change_op != DEFAUTL_CHANGE_OPERATION){
				continue;
			}
			onm_tc_ace_element_t * running_ace = onm_tc_get_ace_in_acl_list(ctx->running_acls_list,iter->acl.name,ace_iter->ace.name);
			
			VALIDATE_AND_UPDATE_EVENT_MAC_ADDR_MASK(ace_iter, source_mac_address, source_mac_address_mask, "Update ACE '%s' source mac address mask", onm_tc_ace_hash_element_set_match_src_mac_addr_mask);
			VALIDATE_AND_UPDATE_EVENT_MAC_ADDR_MASK(ace_iter, destination_mac_address, destination_mac_address_mask, "Update ACE '%s' destination mac address mask", onm_tc_ace_hash_element_set_match_dst_mac_addr_mask);

			VALIDATE_AND_UPDATE_EVENT_SINGLE_PORT_OPERATOR(ace_iter, tcp, source_port, "Update ACE '%s' tcp source port operator", PORT_ATTR_SRC, PORT_ATTR_PROTO_TCP);
			VALIDATE_AND_UPDATE_EVENT_SINGLE_PORT_OPERATOR(ace_iter, tcp, destination_port, "Update ACE '%s' tcp destination port operator", PORT_ATTR_DST, PORT_ATTR_PROTO_TCP);
			VALIDATE_AND_UPDATE_EVENT_SINGLE_PORT_OPERATOR(ace_iter, udp, source_port, "Update ACE '%s' udp source port operator", PORT_ATTR_SRC, PORT_ATTR_PROTO_UDP);
			VALIDATE_AND_UPDATE_EVENT_SINGLE_PORT_OPERATOR(ace_iter, udp, destination_port, "Update ACE '%s' udp destination port operator", PORT_ATTR_DST, PORT_ATTR_PROTO_UDP);

			VALIDATE_AND_UPDATE_EVENT_SINGLE_PORT_VALUE(ace_iter, tcp, source_port, "Update ACE '%s' tcp source port value", PORT_ATTR_SRC, PORT_ATTR_PROTO_TCP);
			VALIDATE_AND_UPDATE_EVENT_SINGLE_PORT_VALUE(ace_iter, tcp, destination_port, "Update ACE '%s' tcp destination port value", PORT_ATTR_DST, PORT_ATTR_PROTO_TCP);
			VALIDATE_AND_UPDATE_EVENT_SINGLE_PORT_VALUE(ace_iter, udp, source_port, "Update ACE '%s' udp source port value", PORT_ATTR_SRC, PORT_ATTR_PROTO_UDP);
			VALIDATE_AND_UPDATE_EVENT_SINGLE_PORT_VALUE(ace_iter, udp, destination_port, "Update ACE '%s' udp destination port value", PORT_ATTR_DST, PORT_ATTR_PROTO_UDP);
			
			VALIDATE_AND_UPDATE_EVENT_PORT_RANGE_LOWER(ace_iter, tcp, source_port, "Update ACE '%s' tcp source port range lower port value", PORT_ATTR_SRC, PORT_ATTR_PROTO_TCP, onm_tc_ace_hash_element_set_match_port);
    		VALIDATE_AND_UPDATE_EVENT_PORT_RANGE_LOWER(ace_iter, udp, source_port, "Update ACE '%s' udp source port range lower port value", PORT_ATTR_SRC, PORT_ATTR_PROTO_UDP, onm_tc_ace_hash_element_set_match_port);
			VALIDATE_AND_UPDATE_EVENT_PORT_RANGE_LOWER(ace_iter, tcp, destination_port, "Update ACE '%s' tcp destination port range lower port value", PORT_ATTR_DST, PORT_ATTR_PROTO_TCP, onm_tc_ace_hash_element_set_match_port);
			VALIDATE_AND_UPDATE_EVENT_PORT_RANGE_LOWER(ace_iter, udp, destination_port, "Update ACE '%s' udp destination port range lower port value", PORT_ATTR_DST, PORT_ATTR_PROTO_UDP, onm_tc_ace_hash_element_set_match_port);
			
			VALIDATE_AND_UPDATE_EVENT_PORT_RANGE_UPPER(ace_iter, tcp, source_port, "Update ACE '%s' tcp source port range upper port value", PORT_ATTR_SRC, PORT_ATTR_PROTO_TCP, onm_tc_ace_hash_element_set_match_port);
			VALIDATE_AND_UPDATE_EVENT_PORT_RANGE_UPPER(ace_iter, udp, source_port, "Update ACE '%s' udp source port range upper port value", PORT_ATTR_SRC, PORT_ATTR_PROTO_UDP, onm_tc_ace_hash_element_set_match_port);
			VALIDATE_AND_UPDATE_EVENT_PORT_RANGE_UPPER(ace_iter, tcp, destination_port, "Update ACE '%s' tcp destination port range upper port value", PORT_ATTR_DST, PORT_ATTR_PROTO_TCP, onm_tc_ace_hash_element_set_match_port);
			VALIDATE_AND_UPDATE_EVENT_PORT_RANGE_UPPER(ace_iter, udp, destination_port, "Update ACE '%s' udp destination port range upper port value", PORT_ATTR_DST, PORT_ATTR_PROTO_UDP, onm_tc_ace_hash_element_set_match_port);
		}
	}
}