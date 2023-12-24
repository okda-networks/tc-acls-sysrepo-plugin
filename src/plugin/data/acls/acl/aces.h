#include "plugin/types.h"
#include <srpc.h>

onm_tc_ace_element_t* onm_tc_ace_element_new(void);
onm_tc_ace_element_t* onm_tc_ace_hash_element_new(void);
void onm_tc_ace_free (onm_tc_ace_element_t** ace);
void onm_tc_ace_element_free(onm_tc_ace_element_t** el);

int acls_list_add_ace_element(onm_tc_acl_hash_element_t** acl_hash, const char* acl_name, onm_tc_ace_element_t* new_ace);
int events_acls_hash_add_ace_element(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);

int ace_element_update_data(onm_tc_ace_element_t* updated_ace, const char * node_name, const char * node_value);
int events_acls_hash_update_ace_element(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);

int onm_tc_ace_hash_element_set_ace_name(onm_tc_ace_element_t** el, const char* name);
int onm_tc_ace_hash_element_set_match_src_mac_addr(onm_tc_ace_element_t** el, const char* src_mac_addr);
int onm_tc_ace_hash_element_set_match_src_mac_addr_mask(onm_tc_ace_element_t** el, const char* src_mac_mask);
int onm_tc_ace_hash_element_set_match_dst_mac_addr(onm_tc_ace_element_t** el, const char* dst_mac_addr);
int onm_tc_ace_hash_element_set_match_dst_mac_addr_mask(onm_tc_ace_element_t** el, const char* dst_mac_mask);
int onm_tc_ace_hash_element_set_match_eth_ethertype(onm_tc_ace_element_t** el, uint16_t ethertype);
int onm_tc_ace_hash_element_set_match_ipv4_src_network(onm_tc_ace_element_t** el, const char* ipv4_src_addr);
int onm_tc_ace_hash_element_set_match_ipv4_dst_network(onm_tc_ace_element_t** el, const char* ipv4_dst_addr);
int onm_tc_ace_hash_element_set_match_ipv6_src_network(onm_tc_ace_element_t** el, const char* ipv6_src_addr);
int onm_tc_ace_hash_element_set_match_ipv6_dst_network(onm_tc_ace_element_t** el, const char* ipv6_dst_addr);
int onm_tc_ace_hash_element_set_match_icmp_code(onm_tc_ace_element_t** el, const uint8_t icmp_code);
int onm_tc_ace_hash_element_set_action_forwarding(onm_tc_ace_element_t** el, const char* action);
int onm_tc_ace_hash_element_set_action_logging(onm_tc_ace_element_t** el, const char* action);
int onm_tc_ace_hash_element_set_match_port(onm_tc_ace_element_t** el,onm_tc_port_attributes_t * port_attr);
int onm_tc_ace_hash_element_set_operation(onm_tc_ace_element_t** el,sr_change_oper_t operation);