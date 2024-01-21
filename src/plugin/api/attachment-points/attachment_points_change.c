#include "plugin/api/attachment-points/attachment_points_change.h"
#include "plugin/common.h"

#include <sysrepo.h>

#include <linux/limits.h>
#include "plugin/api/tcnl.h"
#include "plugin/api/attachment-points/attachment_points_change.h"
#include "plugin/store.h"
#include "plugin/data/acls/acl.h"

int reload_running_aps_list(onm_tc_ctx_t * ctx){
	SRPLG_LOG_DBG(PLUGIN_NAME, "[CHANGE EVENT] Reloading running attachment points list from sysrepo");
	if (&ctx->attachment_points_interface_hash_element){
		onm_tc_aps_interface_hash_free(&ctx->attachment_points_interface_hash_element);
	}
	onm_tc_store(ctx,ctx->running_session,false,true,false);
}

int acls_attachment_points_change_interface_init(void *priv)
{
	int error = 0;
	return error;
}

int apply_attachment_points_events_acl_set_deleted(void *priv, const onm_tc_aps_interface_hash_element_t *interface_element, const unsigned int if_idx){
	unsigned int ingress_acl_id = 0, egress_acl_id = 0;
	int error = 0;
	unsigned int running_ingress_acl_id = 0, running_egress_acl_id = 0;
	onm_tc_ctx_t *ctx = (onm_tc_ctx_t *) priv;
	onm_tc_aps_acl_set_element_t* acl_set_iter = NULL;
	if (interface_element->interface.ingress.acl_sets.acl_set){
		LL_FOREACH(interface_element->interface.ingress.acl_sets.acl_set, acl_set_iter){
			if (acl_set_iter->acl_set.name_change_op == SR_OP_DELETED) {
				ingress_acl_id = acl_name2id(acl_set_iter->acl_set.name);
				SRPLG_LOG_DBG(PLUGIN_NAME, "[CHANGE EVENT][DELETED] Delete ingress ACL %s from interface %s qdisc",acl_set_iter->acl_set.name,interface_element->interface.interface_id);
				onm_tc_aps_acl_set_element_t* acl_set_iter = NULL;
				// get first element only
				break;
			}
		}
	}
	if (interface_element->interface.egress.acl_sets.acl_set){
		LL_FOREACH(interface_element->interface.egress.acl_sets.acl_set, acl_set_iter){
			if (acl_set_iter->acl_set.name_change_op == SR_OP_DELETED) {
				egress_acl_id = acl_name2id(acl_set_iter->acl_set.name);
				SRPLG_LOG_DBG(PLUGIN_NAME, "[CHANGE EVENT][DELETED] Delete egress ACL %s from interface %s qdisc",acl_set_iter->acl_set.name,interface_element->interface.interface_id);
				onm_tc_aps_acl_set_element_t* acl_set_iter = NULL;
				// get first element only
				break;
			}
		}
	}
	if (ingress_acl_id ==0 && egress_acl_id ==0) {
		return 0;
	}

	if (ingress_acl_id != 0 && egress_acl_id == 0 && !interface_element->interface.egress.acl_sets.acl_set){
		// get egress acl id if exists on qdisc
		// delete qdisc then reapply using egress acl_id only if exists on running aps.
		onm_tc_aps_interface_hash_element_t* running_interface_element = onm_tc_aps_interface_hash_get_element(&ctx->attachment_points_interface_hash_element,interface_element->interface.interface_id);
		if (running_interface_element){
			if (running_interface_element->interface.egress.acl_sets.acl_set){
				running_egress_acl_id = acl_name2id(running_interface_element->interface.egress.acl_sets.acl_set->acl_set.name);
			}
		}
	}
	else if (egress_acl_id != 0 && ingress_acl_id == 0 && !interface_element->interface.ingress.acl_sets.acl_set){
		// get ingress acl id if exists on qdisc
		// delete qdisc then reapply using ingress acl_id only if exits on running aps.
		onm_tc_aps_interface_hash_element_t* running_interface_element = onm_tc_aps_interface_hash_get_element(&ctx->attachment_points_interface_hash_element,interface_element->interface.interface_id);
		if (running_interface_element){
			if (running_interface_element->interface.ingress.acl_sets.acl_set){
				running_ingress_acl_id = acl_name2id(running_interface_element->interface.ingress.acl_sets.acl_set->acl_set.name);
			}
		}
	}

	if (tcnl_qdisc_exists(ctx,if_idx,DEFAULT_QDISC_KIND)){
		error = tcnl_qdisc_modify(ctx,RTM_DELQDISC, DEFAULT_QDISC_KIND, if_idx, 0,0,true);
		if (error < 0 ) return error;
	}
	if (running_ingress_acl_id != 0 || running_egress_acl_id !=0){
		error = tcnl_qdisc_modify(ctx,RTM_NEWQDISC, DEFAULT_QDISC_KIND, if_idx, running_ingress_acl_id,running_egress_acl_id,true);
		if (error < 0 ) return error;

		if (running_ingress_acl_id != 0){
			if (!tcnl_block_exists(ctx,running_ingress_acl_id)){
				error = tcnl_block_modify(ctx->running_acls_list, running_ingress_acl_id,ctx, RTM_NEWTFILTER, NLM_F_CREATE);
				if (error < 0) return error;
			}
		}
		if (running_egress_acl_id != 0){
			if (!tcnl_block_exists(ctx,running_egress_acl_id)){
				error = tcnl_block_modify(ctx->running_acls_list, running_egress_acl_id,ctx, RTM_NEWTFILTER, NLM_F_CREATE);
				if (error < 0) return error;
			}
		}
	}
	return 0;
}

int apply_attachment_points_events_acl_set_created(void *priv, const onm_tc_aps_interface_hash_element_t *interface_element, const unsigned int if_idx){
unsigned int ingress_acl_id = 0, egress_acl_id = 0;
	int error = 0;
	onm_tc_ctx_t *ctx = (onm_tc_ctx_t *) priv;
	onm_tc_aps_acl_set_element_t* acl_set_iter = NULL;
	if (interface_element->interface.ingress.acl_sets.acl_set){
		LL_FOREACH(interface_element->interface.ingress.acl_sets.acl_set, acl_set_iter){
			if (acl_set_iter->acl_set.name_change_op == SR_OP_CREATED) {
				ingress_acl_id = acl_name2id(acl_set_iter->acl_set.name);
				SRPLG_LOG_DBG(PLUGIN_NAME, "[CHANGE EVENT][CREATED] Add ingress ACL %s for interface %s qdisc",acl_set_iter->acl_set.name,interface_element->interface.interface_id);
				onm_tc_aps_acl_set_element_t* acl_set_iter = NULL;
				// get first element only
				break;
			}
		}
	}
	if (interface_element->interface.egress.acl_sets.acl_set){
		LL_FOREACH(interface_element->interface.egress.acl_sets.acl_set, acl_set_iter){
			if (acl_set_iter->acl_set.name_change_op == SR_OP_CREATED) {
				egress_acl_id = acl_name2id(acl_set_iter->acl_set.name);
				SRPLG_LOG_DBG(PLUGIN_NAME, "[CHANGE EVENT][CREATED] Add egress ACL %s for interface %s qdisc",acl_set_iter->acl_set.name,interface_element->interface.interface_id);
				onm_tc_aps_acl_set_element_t* acl_set_iter = NULL;
				// get first element only
				break;
			}
		}
	}
	if (ingress_acl_id ==0 && egress_acl_id ==0) {
		return 0;
	}
	
	if (ingress_acl_id != 0 && egress_acl_id==0 && !interface_element->interface.egress.acl_sets.acl_set){
		// get egress acl id if exists on qdisc
		// delete qdisc then reapply using both.
		onm_tc_aps_interface_hash_element_t* running_interface_element = onm_tc_aps_interface_hash_get_element(&ctx->attachment_points_interface_hash_element,interface_element->interface.interface_id);
		if (running_interface_element){
			if (running_interface_element->interface.egress.acl_sets.acl_set){
				egress_acl_id = acl_name2id(running_interface_element->interface.egress.acl_sets.acl_set->acl_set.name);
			}
		}
	}
	else if (egress_acl_id != 0 && ingress_acl_id==0 && !interface_element->interface.ingress.acl_sets.acl_set){
		// get ingress acl id if exists on qdisc
		// delete qdisc then reapply reapply using both.
		onm_tc_aps_interface_hash_element_t* running_interface_element = onm_tc_aps_interface_hash_get_element(&ctx->attachment_points_interface_hash_element,interface_element->interface.interface_id);
		if (running_interface_element){
			if (running_interface_element->interface.ingress.acl_sets.acl_set){
				ingress_acl_id = acl_name2id(running_interface_element->interface.ingress.acl_sets.acl_set->acl_set.name);
			}
		}
	}
	if (tcnl_qdisc_exists(ctx,if_idx,DEFAULT_QDISC_KIND)){
		error = tcnl_qdisc_modify(ctx,RTM_DELQDISC, DEFAULT_QDISC_KIND, if_idx, 0,0,true);
		if (error < 0) return error;
	}
	error = tcnl_qdisc_modify(ctx,RTM_NEWQDISC, DEFAULT_QDISC_KIND, if_idx, ingress_acl_id,egress_acl_id,true);
	if (error < 0) return error;

	if (ingress_acl_id != 0){
		if (!tcnl_block_exists(ctx,ingress_acl_id)){
			SRPLG_LOG_DBG(PLUGIN_NAME, "[CHANGE EVENT][QDISC] reconfigure interface ingress ACL ID %d",ingress_acl_id);
			error = tcnl_block_modify(ctx->running_acls_list, ingress_acl_id,ctx, RTM_NEWTFILTER, NLM_F_CREATE);
        	if (error == -11) {
				error = tcnl_block_modify(ctx->events_acls_list, ingress_acl_id,ctx, RTM_NEWTFILTER, NLM_F_CREATE);
			}
			if (error < 0) return error;
		}
	}
	if (egress_acl_id != 0){
		if (!tcnl_block_exists(ctx,egress_acl_id)){
			SRPLG_LOG_DBG(PLUGIN_NAME, "[CHANGE EVENT][QDISC] reconfigure interface egress ACL ID %d",egress_acl_id);

			error = tcnl_block_modify(ctx->running_acls_list, egress_acl_id,ctx, RTM_NEWTFILTER, NLM_F_CREATE);
			if (error == -11) {
				error = tcnl_block_modify(ctx->events_acls_list, egress_acl_id,ctx, RTM_NEWTFILTER, NLM_F_CREATE);
			}
        	if (error < 0) return error;
		}
	}

	return 0;
}

int count_total_ingress_acls_set(onm_tc_ctx_t * ctx, const onm_tc_aps_interface_hash_element_t * change_interface_element){
	int acls_count = 0;
	onm_tc_aps_acl_set_element_t* acl_set_iter = NULL;
	LL_FOREACH(change_interface_element->interface.ingress.acl_sets.acl_set, acl_set_iter){
		if (acl_set_iter->acl_set.name_change_op == SR_OP_CREATED) {
			acls_count += 1;
		}
		if (acl_set_iter->acl_set.name_change_op == SR_OP_DELETED) {
			acls_count -= 1;
		}
	}
	const onm_tc_aps_interface_hash_element_t * running_interface_element = onm_tc_aps_interface_hash_get_element(&ctx->attachment_points_interface_hash_element,change_interface_element->interface.interface_id);
	if (running_interface_element){
		LL_FOREACH(running_interface_element->interface.ingress.acl_sets.acl_set, acl_set_iter){
			acls_count +=1;
		}
	}
	SRPLG_LOG_DBG(PLUGIN_NAME, "[CHANGE EVENT][%s] Total ingress acls count to be applied %d",change_interface_element->interface.interface_id, acls_count);
	return acls_count;
}

int count_total_egress_acls_set(onm_tc_ctx_t * ctx, const onm_tc_aps_interface_hash_element_t * change_interface_element){
	int acls_count = 0;
	onm_tc_aps_acl_set_element_t* acl_set_iter = NULL;
	LL_FOREACH(change_interface_element->interface.egress.acl_sets.acl_set, acl_set_iter){
		if (acl_set_iter->acl_set.name_change_op == SR_OP_CREATED) {
			acls_count += 1;
		}
		if (acl_set_iter->acl_set.name_change_op == SR_OP_DELETED) {
			acls_count -= 1;
		}
	}
	const onm_tc_aps_interface_hash_element_t * running_interface_element = onm_tc_aps_interface_hash_get_element(&ctx->attachment_points_interface_hash_element,change_interface_element->interface.interface_id);
	if (running_interface_element){
		LL_FOREACH(running_interface_element->interface.egress.acl_sets.acl_set, acl_set_iter){
			acls_count +=1;
		}
	}
	SRPLG_LOG_DBG(PLUGIN_NAME, "[CHANGE EVENT][%s] Total egress acls count to be applied %d",change_interface_element->interface.interface_id, acls_count);
	return acls_count;
}

int apply_attachment_points_events_list_changes(void *priv)
{
	int ret = 0;
	onm_tc_ctx_t *ctx = (onm_tc_ctx_t *) priv;
	onm_tc_nl_ctx_t* nl_ctx = &ctx->nl_ctx;
    // TODO free link and link_cache at the end of this function
    struct rtnl_link * link = NULL;
    const onm_tc_aps_interface_hash_element_t *interface_element = NULL, *aps_tmp = NULL;
    onm_tc_aps_acl_set_element_t* acl_set_iter = NULL;

	char* interface_id = NULL;

    ret = rtnl_link_alloc_cache(nl_ctx->socket, AF_UNSPEC, &nl_ctx->link_cache);
	if (ret < 0) return ret;

    HASH_ITER(hh, ctx->events_attachment_points_list, interface_element, aps_tmp){
        interface_id = interface_element->interface.interface_id;
        /* lookup interface index of interface_id */
        link = rtnl_link_get_by_name(nl_ctx->link_cache, interface_id);
		if (!link) {
			SRPLG_LOG_ERR(PLUGIN_NAME, "[CHANGE EVENT] Error deleting ACL qdisc from interface %s, error getting interface link info",interface_id);
			if (nl_ctx->link_cache != NULL) nl_cache_free(nl_ctx->link_cache);
			return -1;
		}
		int if_idx = rtnl_link_get_ifindex(link);

		ret = apply_attachment_points_events_acl_set_deleted(ctx, interface_element,if_idx);
		if (ret < 0) return ret;

		if (count_total_ingress_acls_set(ctx,interface_element) > 1) {
			SRPLG_LOG_ERR(PLUGIN_NAME, "[CHANGE EVENT][%s] Only one ingress acl is supported", interface_element->interface.interface_id);
			return -1;
		}

		if (count_total_egress_acls_set(ctx,interface_element) > 1) {
			SRPLG_LOG_ERR(PLUGIN_NAME, "[CHANGE EVENT][%s] Only one egress acl is supported", interface_element->interface.interface_id);
			return -1;
		}

		ret = apply_attachment_points_events_acl_set_created(ctx, interface_element,if_idx);
		if (ret < 0) return ret;
	}

	return 0;
}

void acls_attachment_points_change_interface_free(void *priv)
{
}

