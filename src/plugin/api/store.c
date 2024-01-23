#include "store.h"
#include <plugin/types.h>
#include "plugin/common.h"
#include <srpc.h>
#include "utlist.h"
#include "tcnl.h"
#include <netlink/route/qdisc.h>
#include <netlink/route/classifier.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/tc.h>
#include "plugin/data/acls/acl.h"

int acls_store_api(onm_tc_ctx_t *ctx)
{
    int error = 0;
    char* interface_id = NULL;
    onm_tc_nl_ctx_t* nl_ctx = &ctx->nl_ctx;

    struct rtnl_link *link = NULL;

    const onm_tc_aps_interface_hash_element_t *i = NULL, *aps_tmp = NULL;
    onm_tc_aps_acl_set_element_t* acl_set_iter = NULL;

    // socket + cache
    SRPC_SAFE_CALL_PTR(nl_ctx->socket, nl_socket_alloc(), error_out);
    SRPC_SAFE_CALL_ERR(error, nl_connect(nl_ctx->socket, NETLINK_ROUTE), error_out);
    SRPC_SAFE_CALL_ERR(error, rtnl_link_alloc_cache(nl_ctx->socket, AF_UNSPEC, &nl_ctx->link_cache), error_out);

    HASH_ITER(hh, ctx->attachment_points_interface_hash_element, i, aps_tmp)
    {
        unsigned int ingress_acl_id = 0, egress_acl_id = 0;
        interface_id = i->interface.interface_id;
        /* lookup interface index of interface_id */
        link = rtnl_link_get_by_name(nl_ctx->link_cache, interface_id);
        if (link == NULL) goto error_out;

        int if_idx = rtnl_link_get_ifindex(link);
        if (i->interface.ingress.acl_sets.acl_set){
            // get the first element only
            ingress_acl_id = acl_name2id(i->interface.ingress.acl_sets.acl_set->acl_set.name);
            SRPLG_LOG_DBG(PLUGIN_NAME, "Add ingress ACL name %s to interface %s qdisc",i->interface.ingress.acl_sets.acl_set->acl_set.name,interface_id);            
        }
        if (i->interface.egress.acl_sets.acl_set){
            // get the first element only
            egress_acl_id = acl_name2id(i->interface.egress.acl_sets.acl_set->acl_set.name);
            SRPLG_LOG_DBG(PLUGIN_NAME, "Add egress ACL %s to interface %s qdisc",i->interface.egress.acl_sets.acl_set->acl_set.name,interface_id);  
        }

        if (ingress_acl_id != 0 || egress_acl_id !=0 ){
            // delete existing qdisc
            if (tcnl_qdisc_exists(ctx,if_idx,DEFAULT_QDISC_KIND)){
                error = tcnl_qdisc_modify(ctx,RTM_DELQDISC,DEFAULT_QDISC_KIND,if_idx,0,0,true);
            }
            // add new qdisc
            error = tcnl_qdisc_modify(ctx,RTM_NEWQDISC,DEFAULT_QDISC_KIND,if_idx,ingress_acl_id,egress_acl_id,true);
            if (error < 0) goto out;

            // apply ingress acl tc block
            if (ingress_acl_id != 0){
                error = tcnl_block_modify(ctx->running_acls_list, ingress_acl_id,ctx, RTM_NEWTFILTER, NLM_F_CREATE);
                if (error < 0) goto out;
            }
            // apply egress acl tc block
            if (egress_acl_id != 0 && egress_acl_id != ingress_acl_id){
                error = tcnl_block_modify(ctx->running_acls_list, egress_acl_id,ctx, RTM_NEWTFILTER, NLM_F_CREATE);
                if (error < 0) goto out;
            }
        }
        // no acl applied on interface, delete any existing qdisc
        else if (ingress_acl_id == 0 && egress_acl_id == 0){
            if (tcnl_qdisc_exists(ctx,if_idx,DEFAULT_QDISC_KIND)){
                error = tcnl_qdisc_modify(ctx,RTM_DELQDISC,DEFAULT_QDISC_KIND,if_idx,0,0,true);
            }
        }
    }
    goto out;

error_out:
    SRPLG_LOG_ERR(PLUGIN_NAME, "Failed to apply interface %s qdisc", interface_id); 

out:
    // dealloc nl_ctx data
    if (nl_ctx->link_cache != NULL) {
        nl_cache_free(nl_ctx->link_cache);
    }
    if (link != NULL){
        rtnl_link_put(link);
    }
    return error;
}
