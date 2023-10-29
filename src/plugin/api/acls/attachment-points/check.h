#ifndef ONM_TC_PLUGIN_API_ACLS_ATTACHMENT_POINTS_CHECK_H
#define ONM_TC_PLUGIN_API_ACLS_ATTACHMENT_POINTS_CHECK_H

#include "plugin/context.h"
#include <utarray.h>

#include <srpc.h>

srpc_check_status_t acls_attachment_points_check_interface(onm_tc_ctx_t *ctx, const UT_array *interface);

#endif // ONM_TC_PLUGIN_API_ACLS_ATTACHMENT_POINTS_CHECK_H