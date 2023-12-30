#ifndef ONM_TC_PLUGIN_API_ACLS_ACL_ACES_CHANGE_H
#define ONM_TC_PLUGIN_API_ACLS_ACL_ACES_CHANGE_H

#include <utarray.h>
#include <srpc.h>
#include "plugin/types.h"
#include "plugin/context.h"

int apply_events_ace_changes(onm_tc_ctx_t * ctx, unsigned int acl_id, onm_tc_ace_element_t* ace);

#endif // ONM_TC_PLUGIN_API_ACLS_ACL_ACES_CHANGE_H