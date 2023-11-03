#ifndef ONM_TC_PLUGIN_CONTEXT_H
#define ONM_TC_PLUGIN_CONTEXT_H

#include <sysrepo_types.h>
#include "plugin/types.h"

typedef struct onm_tc_ctx_s onm_tc_ctx_t;

struct onm_tc_ctx_s {
    sr_session_ctx_t *startup_session;
    onm_tc_aps_interface_hash_element_t* attachment_points_interface_hash_element;
    onm_tc_acl_hash_element_t* acl_hash_element;
};

#endif // ONM_TC_PLUGIN_CONTEXT_H