#ifndef ONM_TC_PLUGIN_API_ACLS_ACL_ACES_ACE_MATCHES_TCP_CHANGE_H
#define ONM_TC_PLUGIN_API_ACLS_ACL_ACES_ACE_MATCHES_TCP_CHANGE_H

#include <utarray.h>
#include <srpc.h>

int acls_acl_aces_ace_matches_tcp_change_options_init(void *priv);
int acls_acl_aces_ace_matches_tcp_change_options(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_matches_tcp_change_options_free(void *priv);
int acls_acl_aces_ace_matches_tcp_change_urgent_pointer_init(void *priv);
int acls_acl_aces_ace_matches_tcp_change_urgent_pointer(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_matches_tcp_change_urgent_pointer_free(void *priv);
int acls_acl_aces_ace_matches_tcp_change_window_size_init(void *priv);
int acls_acl_aces_ace_matches_tcp_change_window_size(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_matches_tcp_change_window_size_free(void *priv);
int acls_acl_aces_ace_matches_tcp_change_flags_init(void *priv);
int acls_acl_aces_ace_matches_tcp_change_flags(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_matches_tcp_change_flags_free(void *priv);
int acls_acl_aces_ace_matches_tcp_change_reserved_init(void *priv);
int acls_acl_aces_ace_matches_tcp_change_reserved(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_matches_tcp_change_reserved_free(void *priv);
int acls_acl_aces_ace_matches_tcp_change_data_offset_init(void *priv);
int acls_acl_aces_ace_matches_tcp_change_data_offset(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_matches_tcp_change_data_offset_free(void *priv);
int acls_acl_aces_ace_matches_tcp_change_acknowledgement_number_init(void *priv);
int acls_acl_aces_ace_matches_tcp_change_acknowledgement_number(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_matches_tcp_change_acknowledgement_number_free(void *priv);
int acls_acl_aces_ace_matches_tcp_change_sequence_number_init(void *priv);
int acls_acl_aces_ace_matches_tcp_change_sequence_number(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_matches_tcp_change_sequence_number_free(void *priv);

#endif // ONM_TC_PLUGIN_API_ACLS_ACL_ACES_ACE_MATCHES_TCP_CHANGE_H