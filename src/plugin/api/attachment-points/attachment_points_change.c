#include "plugin/api/attachment-points/attachment_points_change.h"
#include "plugin/common.h"

#include <sysrepo.h>

#include <linux/limits.h>
#include "plugin/api/tcnl.h"
#include "plugin/api/attachment-points/attachment_points_change.h"

int acls_attachment_points_change_interface_init(void *priv)
{
	int error = 0;
	return error;
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
    char* ingress_acl_name = NULL;
    char* egress_acl_name = NULL;

    ret = rtnl_link_alloc_cache(nl_ctx->socket, AF_UNSPEC, &nl_ctx->link_cache);
	if (ret < 0){
		return ret;
	}
    HASH_ITER(hh, ctx->events_attachment_points_list, interface_element, aps_tmp)
    {
        interface_id = interface_element->interface.interface_id;
        /* lookup interface index of interface_id */
        SRPC_SAFE_CALL_PTR(link, rtnl_link_get_by_name(nl_ctx->link_cache, interface_id), error_out);

        if (interface_element->interface.ingress.acl_sets.acl_set){
            
            SRPLG_LOG_INF(PLUGIN_NAME, "Applying acls for interface %s",interface_id);
            
            int if_idx = rtnl_link_get_ifindex(link);
            LL_FOREACH(interface_element->interface.ingress.acl_sets.acl_set, acl_set_iter){
                ingress_acl_name = acl_set_iter->acl_set.name;
                unsigned int acl_id = acl_name2id(ingress_acl_name);

				switch (acl_set_iter->acl_set.name_change_op) {
					struct nl_msg *msg;
					case SR_OP_CREATED:
						ret = tcnl_qdisc_modify(ctx,RTM_DELQDISC, DEFAULT_QDISC_KIND, if_idx, acl_id,0,true);
						ret = tcnl_qdisc_modify(ctx,RTM_NEWQDISC, DEFAULT_QDISC_KIND, if_idx, acl_id,0,true);
						if (ret < 0) return ret;
						if (!tcnl_block_exists(ctx,acl_id)){
							ret = tcnl_block_modify(ctx->running_acls_list,acl_id,ctx,RTM_NEWTFILTER,NLM_F_CREATE);
							// if acl not found in running acls list, it must have been configured at the same change event that sets the attachment point
							// get the acl and apply it from events acls list.
							if (ret == -11) {
								ret = tcnl_block_modify(ctx->events_acls_list,acl_id,ctx,RTM_NEWTFILTER,NLM_F_CREATE);
								if (ret < 0) return ret;
							}
						}
						break;
					case SR_OP_MODIFIED:
						break;
					case SR_OP_DELETED:
						ret = tcnl_qdisc_modify(ctx,RTM_DELQDISC, DEFAULT_QDISC_KIND, if_idx, acl_id,0,true);
						if (ret<0) return ret;
						break;
					case SR_OP_MOVED:
						break;
				}
            }
        }
	}
	
	goto out;
error_out:
	if (link != NULL){
		rtnl_link_put(link);
	}
	if (nl_ctx->link_cache != NULL) {
        nl_cache_free(nl_ctx->link_cache);
    }
	return -1;
out:
	if (link != NULL){
		rtnl_link_put(link);
	}
	if (nl_ctx->link_cache != NULL) {
        nl_cache_free(nl_ctx->link_cache);
    }
	return 0;
}

void acls_attachment_points_change_interface_free(void *priv)
{
}

