#ifndef ONM_TC_PLUGIN_API_ACLS_ACL_ACES_CHANGE_H
#define ONM_TC_PLUGIN_API_ACLS_ACL_ACES_CHANGE_H

#include <utarray.h>
#include <srpc.h>
#include "plugin/types.h"

// this code is no longer used, proper code are defined in /data/acls/*
/*
int process_change_ace_top_level_leafs
(srpc_change_ctx_t * change_ctx,onm_tc_acl_hash_element_t * change_acl_hash, onm_tc_ace_element_t * change_ace_element, char * acl_name);

int process_change_ace_leafs
(srpc_change_ctx_t * change_ctx,onm_tc_acl_hash_element_t * change_acl_hash, onm_tc_ace_element_t * change_ace_element, char * acl_name);

int change_ace_init(void *priv);
//int change_ace(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void change_ace_free(void *priv);

//int ace_entries_update(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
*/
#endif // ONM_TC_PLUGIN_API_ACLS_ACL_ACES_CHANGE_H