#ifndef ONM_TC_PLUGIN_API_ACLS_ACL_ACES_ACE_ACTIONS_CHANGE_H
#define ONM_TC_PLUGIN_API_ACLS_ACL_ACES_ACE_ACTIONS_CHANGE_H

#include <utarray.h>
#include <srpc.h>

int acls_acl_aces_ace_actions_change_logging_init(void *priv);
int acls_acl_aces_ace_actions_change_logging(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_actions_change_logging_free(void *priv);
int acls_acl_aces_ace_actions_change_forwarding_init(void *priv);
int acls_acl_aces_ace_actions_change_forwarding(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_actions_change_forwarding_free(void *priv);

#endif // ONM_TC_PLUGIN_API_ACLS_ACL_ACES_ACE_ACTIONS_CHANGE_H