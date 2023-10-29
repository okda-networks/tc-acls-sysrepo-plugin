#ifndef ONM_TC_PLUGIN_API_ACLS_ACL_ACES_ACE_MATCHES_CHANGE_H
#define ONM_TC_PLUGIN_API_ACLS_ACL_ACES_ACE_MATCHES_CHANGE_H

#include <utarray.h>
#include <srpc.h>

int acls_acl_aces_ace_matches_change_ingress_interface_init(void *priv);
int acls_acl_aces_ace_matches_change_ingress_interface(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_matches_change_ingress_interface_free(void *priv);
int acls_acl_aces_ace_matches_change_egress_interface_init(void *priv);
int acls_acl_aces_ace_matches_change_egress_interface(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_matches_change_egress_interface_free(void *priv);

#endif // ONM_TC_PLUGIN_API_ACLS_ACL_ACES_ACE_MATCHES_CHANGE_H