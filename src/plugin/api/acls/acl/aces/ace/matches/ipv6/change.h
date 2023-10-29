#ifndef ONM_TC_PLUGIN_API_ACLS_ACL_ACES_ACE_MATCHES_IPV6_CHANGE_H
#define ONM_TC_PLUGIN_API_ACLS_ACL_ACES_ACE_MATCHES_IPV6_CHANGE_H

#include <utarray.h>
#include <srpc.h>

int acls_acl_aces_ace_matches_ipv6_change_flow_label_init(void *priv);
int acls_acl_aces_ace_matches_ipv6_change_flow_label(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_matches_ipv6_change_flow_label_free(void *priv);
int acls_acl_aces_ace_matches_ipv6_change_source_ipv6_network_init(void *priv);
int acls_acl_aces_ace_matches_ipv6_change_source_ipv6_network(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_matches_ipv6_change_source_ipv6_network_free(void *priv);
int acls_acl_aces_ace_matches_ipv6_change_destination_ipv6_network_init(void *priv);
int acls_acl_aces_ace_matches_ipv6_change_destination_ipv6_network(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_matches_ipv6_change_destination_ipv6_network_free(void *priv);
int acls_acl_aces_ace_matches_ipv6_change_protocol_init(void *priv);
int acls_acl_aces_ace_matches_ipv6_change_protocol(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_matches_ipv6_change_protocol_free(void *priv);
int acls_acl_aces_ace_matches_ipv6_change_ttl_init(void *priv);
int acls_acl_aces_ace_matches_ipv6_change_ttl(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_matches_ipv6_change_ttl_free(void *priv);
int acls_acl_aces_ace_matches_ipv6_change_length_init(void *priv);
int acls_acl_aces_ace_matches_ipv6_change_length(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_matches_ipv6_change_length_free(void *priv);
int acls_acl_aces_ace_matches_ipv6_change_ecn_init(void *priv);
int acls_acl_aces_ace_matches_ipv6_change_ecn(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_matches_ipv6_change_ecn_free(void *priv);
int acls_acl_aces_ace_matches_ipv6_change_dscp_init(void *priv);
int acls_acl_aces_ace_matches_ipv6_change_dscp(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_matches_ipv6_change_dscp_free(void *priv);

#endif // ONM_TC_PLUGIN_API_ACLS_ACL_ACES_ACE_MATCHES_IPV6_CHANGE_H