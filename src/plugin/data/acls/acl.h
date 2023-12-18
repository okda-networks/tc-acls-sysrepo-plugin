#include "plugin/types.h"

int onm_tc_acl_hash_from_ly(onm_tc_acl_hash_element_t** if_hash, const struct lyd_node* acl_list_node);
onm_tc_acl_hash_element_t* onm_tc_acl_hash_element_new(void);
int onm_tc_acl_hash_add_element(onm_tc_acl_hash_element_t** hash, onm_tc_acl_hash_element_t* new_element);
void onm_tc_acl_hash_print_debug(const onm_tc_acl_hash_element_t* acl_hash);


int onm_tc_acl_hash_element_set_name(onm_tc_acl_hash_element_t** el, const char* type);
int onm_tc_acl_hash_element_set_type(onm_tc_acl_hash_element_t** el, const char* type);


void onm_tc_acl_element_hash_free(onm_tc_acl_hash_element_t** el);
void onm_tc_acl_list_hash_free(onm_tc_acl_hash_element_t** hash);
onm_tc_acl_hash_element_t* onm_tc_acl_hash_new(void);
