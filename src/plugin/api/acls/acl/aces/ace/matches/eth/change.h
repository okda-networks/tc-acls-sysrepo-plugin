#ifndef ONM_TC_PLUGIN_API_ACLS_ACL_ACES_ACE_MATCHES_ETH_CHANGE_H
#define ONM_TC_PLUGIN_API_ACLS_ACL_ACES_ACE_MATCHES_ETH_CHANGE_H

#include <utarray.h>
#include <srpc.h>

int acls_acl_aces_ace_matches_eth_change_ethertype_init(void *priv);
int acls_acl_aces_ace_matches_eth_change_ethertype(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_matches_eth_change_ethertype_free(void *priv);
int acls_acl_aces_ace_matches_eth_change_source_mac_address_mask_init(void *priv);
int acls_acl_aces_ace_matches_eth_change_source_mac_address_mask(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_matches_eth_change_source_mac_address_mask_free(void *priv);
int acls_acl_aces_ace_matches_eth_change_source_mac_address_init(void *priv);
int acls_acl_aces_ace_matches_eth_change_source_mac_address(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_matches_eth_change_source_mac_address_free(void *priv);
int acls_acl_aces_ace_matches_eth_change_destination_mac_address_mask_init(void *priv);
int acls_acl_aces_ace_matches_eth_change_destination_mac_address_mask(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_matches_eth_change_destination_mac_address_mask_free(void *priv);
int acls_acl_aces_ace_matches_eth_change_destination_mac_address_init(void *priv);
int acls_acl_aces_ace_matches_eth_change_destination_mac_address(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_acl_aces_ace_matches_eth_change_destination_mac_address_free(void *priv);

#endif // ONM_TC_PLUGIN_API_ACLS_ACL_ACES_ACE_MATCHES_ETH_CHANGE_H