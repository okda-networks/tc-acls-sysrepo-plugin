#include "plugin/types.h"
#include <srpc.h>

onm_tc_ace_element_t* onm_tc_ace_element_new(void);
onm_tc_ace_element_t* onm_tc_ace_hash_element_new(void);
void onm_tc_ace_free (onm_tc_ace_element_t** ace);
void onm_tc_ace_element_free(onm_tc_ace_element_t** el);

int acls_list_add_ace_element(onm_tc_acl_hash_element_t** acl_hash, const char* acl_name, onm_tc_ace_element_t* new_ace);
int events_acls_hash_add_ace_element(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);

onm_tc_ace_element_t* onm_tc_get_ace_in_acl_list_by_name(onm_tc_acl_hash_element_t* acl_hash, const char* acl_name, const char* ace_name);
int ace_element_update_from_lyd_node(onm_tc_ace_element_t* updated_ace, const struct lyd_node * node,sr_change_oper_t change_operation);
int events_acls_hash_update_ace_element_from_change_ctx(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);

int reorder_events_acls_aces_from_change_ctx(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
int remove_unchanged_priority_aces_from_events_list(void *priv);

int onm_tc_ace_hash_element_set_ace_name(onm_tc_ace_element_t** el, const char* name, sr_change_oper_t change_operation);
int onm_tc_ace_hash_element_set_ace_priority(onm_tc_ace_element_t** el, const unsigned int priority, sr_change_oper_t change_operation);
int onm_tc_ace_hash_element_set_ace_handle(onm_tc_ace_element_t** el, const unsigned int handle);
int onm_tc_ace_hash_element_set_match_src_mac_addr(onm_tc_ace_element_t** el, const char* src_mac_addr, sr_change_oper_t change_operation);
int onm_tc_ace_hash_element_set_match_src_mac_addr_mask(onm_tc_ace_element_t** el, const char* src_mac_mask, sr_change_oper_t change_operation);
int onm_tc_ace_hash_element_set_match_dst_mac_addr(onm_tc_ace_element_t** el, const char* dst_mac_addr, sr_change_oper_t change_operation);
int onm_tc_ace_hash_element_set_match_dst_mac_addr_mask(onm_tc_ace_element_t** el, const char* dst_mac_mask, sr_change_oper_t change_operation);
int onm_tc_ace_hash_element_set_match_eth_ethertype(onm_tc_ace_element_t** el, uint16_t ethertype, sr_change_oper_t change_operation);
int onm_tc_ace_hash_element_set_match_ipv4_src_network(onm_tc_ace_element_t** el, const char* ipv4_src_addr, sr_change_oper_t change_operation);
int onm_tc_ace_hash_element_set_match_ipv4_dst_network(onm_tc_ace_element_t** el, const char* ipv4_dst_addr, sr_change_oper_t change_operation);
int onm_tc_ace_hash_element_set_match_ipv6_src_network(onm_tc_ace_element_t** el, const char* ipv6_src_addr, sr_change_oper_t change_operation);
int onm_tc_ace_hash_element_set_match_ipv6_dst_network(onm_tc_ace_element_t** el, const char* ipv6_dst_addr, sr_change_oper_t change_operation);
int onm_tc_ace_hash_element_set_match_icmp_code(onm_tc_ace_element_t** el, const uint8_t icmp_code, sr_change_oper_t change_operation);
int onm_tc_ace_hash_element_set_action_forwarding(onm_tc_ace_element_t** el, const char* action, sr_change_oper_t change_operation);
int onm_tc_ace_hash_element_set_action_logging(onm_tc_ace_element_t** el, const char* action, sr_change_oper_t change_operation);
int onm_tc_ace_hash_element_set_match_port_operator(onm_tc_ace_element_t** el, onm_tc_port_attributes_t* port_attr, sr_change_oper_t change_operation);
int set_ace_port_single(onm_tc_ace_element_t* el, onm_tc_port_attributes_t* port_attr, sr_change_oper_t change_operation);
int set_ace_port_range_lower_port(onm_tc_ace_element_t* el, onm_tc_port_attributes_t* port_attr, sr_change_oper_t change_operation);
int set_ace_port_range_upper_port(onm_tc_ace_element_t* el, onm_tc_port_attributes_t* port_attr, sr_change_oper_t change_operation);
int set_ace_port_range(onm_tc_ace_element_t* el, onm_tc_port_attributes_t* port_attr, sr_change_oper_t change_operation);
port_operator_t onm_tc_ace_port_oper_a2i(const char * oper_str);

void onm_tc_ace_hash_print_debug(const onm_tc_ace_element_t* ace_element);
int port_str_to_port_attr (onm_tc_port_attributes_t *port_attr, const char * lower_str, const char * upper_str, const char * single_port_value_str, const port_operator_t single_port_opr,onm_tc_port_attr_direction_t direction, onm_tc_port_attr_proto_t proto);