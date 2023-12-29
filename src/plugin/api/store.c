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

    // TODO free link and link_cache at the end of this function
    struct rtnl_link *link;
    //struct nl_cache *link_cache;

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
            
            SRPLG_LOG_INF(PLUGIN_NAME, "NETLINK: applying acls for interface %s",interface_id);
            
            int if_idx = rtnl_link_get_ifindex(link);
            LL_FOREACH(i->interface.ingress.acl_sets.acl_set, acl_set_iter)
            {
                
                ingress_acl_name = acl_set_iter->acl_set.name;
                unsigned int acl_id = acl_name2id(ingress_acl_name);

                //  Add interface qdisc with shared tc block for the acl name
                // TODO use safe sysrepo call
                tcnl_modify_ingress_qdisc_shared_block(nl_ctx,if_idx,acl_id);
                SRPLG_LOG_INF(PLUGIN_NAME, "NETLINK: ACL name %s is set to interface %s ingress",ingress_acl_name,interface_id);

                // check if shared block already exists:
                /*if (tcnl_tc_block_exists(nl_ctx,acl_id) == true)
                {
                    // if yes, no further action needed.
                    // TODO evalulate if we need to iterate through acl aces and compair netlink config vs sysrepo config
                    SRPLG_LOG_INF(PLUGIN_NAME, "NETLINK: ACL name %s ID %d exists, no further action is needed",ingress_acl_name,acl_id);
                }
                else
                {*/
                    // if no, get ACL content and apply it on netlink
                    SRPLG_LOG_INF(PLUGIN_NAME, "NETLINK: ACL name %s ID %d needs to be configured in a new shared block",ingress_acl_name,acl_id);
                    tcnl_filter_flower_modify(acl_id,ctx->running_acls_list);
                    
                //}
                
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

    //if (!element_added) {
        //interfaces_interface_hash_element_free(&new_element);
    //}

out:
    // dealloc nl_ctx data

    if (nl_ctx->socket != NULL) {
        nl_socket_free(nl_ctx->socket);
    }

    if (nl_ctx->link_cache != NULL) {
        nl_cache_free(nl_ctx->link_cache);
    }

    // address and neighbor caches should be freed by their functions (_load_address and _load_neighbor)

    return error;

    return error;
}
