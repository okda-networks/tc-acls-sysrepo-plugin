#include "store.h"
#include <plugin/types.h>
#include "plugin/common.h"
#include <srpc.h>
#include "utlist.h"
#include "tcnl.h"
#include <netlink/route/qdisc.h>


int acls_store_api(onm_tc_ctx_t *ctx)
{
    int error = 0;
    
    char* interface_id = NULL;
    char* ingress_acl_name = NULL;
    char* egress_acl_name = NULL;

    struct nl_sock *sock;
    struct rtnl_link *link;
    struct nl_cache *link_cache;

    const onm_tc_aps_interface_hash_element_t *i = NULL, *aps_tmp = NULL;
    onm_tc_aps_acl_set_element_t* acl_set_iter = NULL;

    if (!(sock = nl_socket_alloc())) {
        SRPLG_LOG_ERR(PLUGIN_NAME, "NETLINK: store_api: Unable to allocate netlink socket");
        exit(1);
    }
    
    if ((error = nl_connect(sock, NETLINK_ROUTE)) < 0 ) {
        SRPLG_LOG_ERR(PLUGIN_NAME, "NETLINK: store_api: Unable to connect to NETLINK!");
        nl_socket_free(sock);
        exit(1);
    }

    if ((error = rtnl_link_alloc_cache(sock, AF_UNSPEC, &link_cache)) < 0) {
        SRPLG_LOG_ERR(PLUGIN_NAME, "NETLINK: store_api: Unable to allocate link cache: %s",nl_geterror(error));
        nl_socket_free(sock);
        exit(1);
    }

    HASH_ITER(hh, ctx->attachment_points_interface_hash_element, i, aps_tmp)
    {
        interface_id = i->interface.interface_id;
        /* lookup interface index of interface_id */
        if (!(link = rtnl_link_get_by_name(link_cache, interface_id))) {
            /* error */
            SRPLG_LOG_ERR(PLUGIN_NAME, "NETLINK: Interface %s not found",interface_id);
            nl_socket_free(sock);
            exit(1);
        }

        if (i->interface.ingress.acl_sets.acl_set){
            
            SRPLG_LOG_INF(PLUGIN_NAME, "NETLINK: applying acls for interface %s",interface_id);
            
            int if_idx = rtnl_link_get_ifindex(link);
            LL_FOREACH(i->interface.ingress.acl_sets.acl_set, acl_set_iter)
            {

                ingress_acl_name = acl_set_iter->acl_set.name;
                
                printf("ACL name %s\n",ingress_acl_name);
                // TODO use safe sysrepo call
                tcnl_modify_ingress_qdisc_shared_block(if_idx,djb2_hash(ingress_acl_name));

                // TODO 
                // check ifshared block already exists:
                // if yes, then just apply the same acl name to interface_id.
                // if no, get ACL content and apply it on interface_name via netlink.
                
            }
        }
        if (i->interface.egress.acl_sets.acl_set){
            printf("parsing egress acls\n");
            LL_FOREACH(i->interface.egress.acl_sets.acl_set, acl_set_iter)
            {
                egress_acl_name = acl_set_iter->acl_set.name;
            }
        }
    }

    return error;
}
