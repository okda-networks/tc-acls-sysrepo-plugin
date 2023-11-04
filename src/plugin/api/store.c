#include "store.h"
#include <plugin/types.h>
#include "plugin/common.h"
#include <srpc.h>
#include "utlist.h"

#include <netlink/route/qdisc.h>

int qdisc_add_ingress(struct nl_sock *sock, struct rtnl_link *rtnlLink)
{
    struct rtnl_qdisc *qdisc;
    int error;
    char* interface_id = rtnl_link_get_name(rtnlLink);

    SRPLG_LOG_INF(PLUGIN_NAME, "NETLINK: Allocating ingress qdisc for interface %s", interface_id);
    /* Allocation of a qdisc object */
    if (!(qdisc = rtnl_qdisc_alloc())) {
        SRPLG_LOG_ERR(PLUGIN_NAME, "NETLINK: store_api: can not allocate qdisc");
	return -1;
    }

    rtnl_tc_set_link(TC_CAST(qdisc), rtnlLink);
    rtnl_tc_set_parent(TC_CAST(qdisc), TC_H_INGRESS);

    //printf("Delete current qdisc\n");
    //rtnl_qdisc_delete(sock, qdisc);

    rtnl_tc_set_handle(TC_CAST(qdisc), TC_HANDLE(0xffff, 0));
    rtnl_tc_set_kind(TC_CAST(qdisc), "ingress");

    /* Submit request to kernel and wait for response */
    SRPC_SAFE_CALL_ERR(error, rtnl_qdisc_add(sock, qdisc, NLM_F_CREATE), error_out);
    SRPLG_LOG_INF(PLUGIN_NAME, "NETLINK: Added ingress qdisc for interface %s successfully",  interface_id);
    goto out;

error_out:
    SRPLG_LOG_ERR(PLUGIN_NAME, "NETLINK: Adding qdisc for interface %s have failed, error code: %s",interface_id, nl_geterror(error));
    error = -1;

out:
    /* Return the qdisc object to free memory resources */
    rtnl_qdisc_put(qdisc);
    return error;
}

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
            SRPLG_LOG_ERR(PLUGIN_NAME, "NETLINK: store_api: Interface %s not found",interface_id);
            nl_socket_free(sock);
            exit(1);
        }
        error=qdisc_add_ingress(sock, link);

        if (i->interface.ingress.acl_sets.acl_set){

            LL_FOREACH(i->interface.ingress.acl_sets.acl_set, acl_set_iter)
            {
                ingress_acl_name = acl_set_iter->acl_set.name;

                // TODO 
                // check if ACL name is already applied on tc on another interface.
                // if yes, then just apply the same acl name to interface_id.
                
                // rtnl_qdisc_add()
                // if no, get ACL content and apply it on interface_name via netlink.
                //error=qdisc_add_ingress(sock, link);
            }
        }
        if (i->interface.egress.acl_sets.acl_set){
            LL_FOREACH(i->interface.egress.acl_sets.acl_set, acl_set_iter)
            {
                egress_acl_name = acl_set_iter->acl_set.name;
            }
        }
    }

    return error;
}
