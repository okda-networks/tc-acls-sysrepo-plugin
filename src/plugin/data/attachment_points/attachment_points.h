#include "plugin/types.h"

int onm_tc_aps_interface_hash_from_ly(onm_tc_aps_interface_hash_element_t** interface_hash, const struct lyd_node* interfaces_list_node);
void onm_tc_aps_interface_hash_print_debug(const onm_tc_aps_interface_hash_element_t* aps_interface_hash);
