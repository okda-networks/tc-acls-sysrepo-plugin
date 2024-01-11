#ifndef ONM_TC_PLUGIN_CONTEXT_H
#define ONM_TC_PLUGIN_CONTEXT_H

#include <sysrepo_types.h>
#include "plugin/types.h"

typedef struct onm_tc_ctx_s onm_tc_ctx_t;
typedef struct onm_tc_nl_ctx onm_tc_nl_ctx_t;


struct onm_tc_nl_ctx {
    struct nl_sock* socket;
    struct nl_cache* link_cache;
};

struct onm_tc_ctx_s {
    sr_session_ctx_t* startup_session;
    sr_session_ctx_t* running_session;
    onm_tc_aps_interface_hash_element_t* attachment_points_interface_hash_element;
    onm_tc_aps_interface_hash_element_t* events_attachment_points_list;
    onm_tc_acl_hash_element_t* running_acls_list;
    onm_tc_acl_hash_element_t* events_acls_list;
    onm_tc_nl_ctx_t nl_ctx;
};


#endif // ONM_TC_PLUGIN_CONTEXT_H