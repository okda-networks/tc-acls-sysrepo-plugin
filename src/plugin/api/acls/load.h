#ifndef ONM_TC_PLUGIN_API_ACLS_LOAD_H
#define ONM_TC_PLUGIN_API_ACLS_LOAD_H

#include "plugin/context.h"
#include <utarray.h>

int acls_load_acl(onm_tc_ctx_t *ctx, UT_array **acl);

#endif // ONM_TC_PLUGIN_API_ACLS_LOAD_H