#ifndef ONM_TC_PLUGIN_API_ACLS_STORE_H
#define ONM_TC_PLUGIN_API_ACLS_STORE_H

#include "plugin/context.h"
#include <utarray.h>

int acls_store_acl(onm_tc_ctx_t *ctx, const UT_array *acl);

#endif // ONM_TC_PLUGIN_API_ACLS_STORE_H