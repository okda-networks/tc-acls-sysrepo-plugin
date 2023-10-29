#ifndef ONM_TC_PLUGIN_API_ACLS_ACL_ACES_ACE_MATCHES_ICMP_CHANGE_H
#define ONM_TC_PLUGIN_API_ACLS_ACL_ACES_ACE_MATCHES_ICMP_CHANGE_H

#include <utarray.h>
#include <srpc.h>

int acls_acl_aces_ace_matches_icmp_change_rest_of_header_init(void *priv);
int acls_acl_aces_ace_matches_icmp_change_rest_of_header(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_matches_icmp_change_rest_of_header_free(void *priv);
int acls_acl_aces_ace_matches_icmp_change_code_init(void *priv);
int acls_acl_aces_ace_matches_icmp_change_code(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_matches_icmp_change_code_free(void *priv);
int acls_acl_aces_ace_matches_icmp_change_type_init(void *priv);
int acls_acl_aces_ace_matches_icmp_change_type(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_matches_icmp_change_type_free(void *priv);

#endif // ONM_TC_PLUGIN_API_ACLS_ACL_ACES_ACE_MATCHES_ICMP_CHANGE_H