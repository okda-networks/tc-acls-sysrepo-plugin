#ifndef ONM_TC_PLUGIN_CONTEXT_H
#define ONM_TC_PLUGIN_CONTEXT_H

#include <sysrepo_types.h>
#include "plugin/types.h"

typedef struct onm_tc_ctx_s onm_tc_ctx_t;

struct onm_tc_ctx_s {
    sr_session_ctx_t *startup_session;
};

#endif // ONM_TC_PLUGIN_CONTEXT_H