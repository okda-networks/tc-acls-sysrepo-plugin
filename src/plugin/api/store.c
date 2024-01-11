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
    char* ingress_acl_name = NULL;
    char* egress_acl_name = NULL;

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
        interface_id = i->interface.interface_id;
        /* lookup interface index of interface_id */
        SRPC_SAFE_CALL_PTR(link, rtnl_link_get_by_name(nl_ctx->link_cache, interface_id), error_out);

        if (i->interface.ingress.acl_sets.acl_set){
            
            SRPLG_LOG_INF(PLUGIN_NAME, "Applying acls for interface %s",interface_id);
            
            int if_idx = rtnl_link_get_ifindex(link);
            LL_FOREACH(i->interface.ingress.acl_sets.acl_set, acl_set_iter)
            {
                ingress_acl_name = acl_set_iter->acl_set.name;
                unsigned int acl_id = acl_name2id(ingress_acl_name);

                //  Add interface qdisc with shared tc block for the acl name
                // TODO use safe sysrepo call
                SRPLG_LOG_INF(PLUGIN_NAME, "Add ACL name %s ingress qdisc to interface %s",ingress_acl_name,interface_id);
                tcnl_qdisc_modify(ctx,RTM_NEWQDISC,DEFAULT_QDISC_KIND,if_idx,acl_id,0,true);
                error = tcnl_block_modify(ctx->running_acls_list, acl_id,ctx, RTM_NEWTFILTER, NLM_F_CREATE);
                
                if (error < 0){
                    goto out;
                }
            }
        }
        if (i->interface.egress.acl_sets.acl_set){
            LL_FOREACH(i->interface.egress.acl_sets.acl_set, acl_set_iter)
            {
                egress_acl_name = acl_set_iter->acl_set.name;
            }
        }
    }

error_out:
    error = -1;

out:
    // dealloc nl_ctx data

    if (nl_ctx->link_cache != NULL) {
        nl_cache_free(nl_ctx->link_cache);
    }
    if (link != NULL){
        rtnl_link_put(link);
    }

    // address and neighbor caches should be freed by their functions (_load_address and _load_neighbor)
    return error;
}
