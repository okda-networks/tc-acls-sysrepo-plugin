#include "plugin/types.h"
#include "plugin/context.h"

int onm_tc_aps_interface_hash_from_ly(onm_tc_aps_interface_hash_element_t** interface_hash, const struct lyd_node* interfaces_list_node);
void onm_tc_aps_interface_hash_print_debug(const onm_tc_aps_interface_hash_element_t* aps_interface_hash);
int events_aps_hash_update_from_change_ctx(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void onm_tc_aps_interface_hash_free(onm_tc_aps_interface_hash_element_t** hash);
void onm_tc_aps_interface_hash_print_debug(const onm_tc_aps_interface_hash_element_t* aps_interface_hash);
onm_tc_aps_interface_hash_element_t* onm_tc_aps_interface_hash_get_element(onm_tc_aps_interface_hash_element_t** hash, const char* name);
