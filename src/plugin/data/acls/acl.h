#include "plugin/types.h"
#include <srpc.h>
#include "plugin/context.h"

int onm_tc_acls_list_from_ly(onm_tc_acl_hash_element_t** if_hash, const struct lyd_node* acl_list_node);
onm_tc_acl_hash_element_t* onm_tc_acl_hash_element_new(void);

void onm_tc_acls_list_print_debug(const onm_tc_acl_hash_element_t* acl_hash);


int onm_tc_acl_hash_element_set_name(onm_tc_acl_hash_element_t** el, const char* name,sr_change_oper_t change_operation);
int onm_tc_acl_hash_element_set_type(onm_tc_acl_hash_element_t** el, const char* type,sr_change_oper_t change_operation);
int onm_tc_acl_hash_element_set_operation(onm_tc_acl_hash_element_t** el,sr_change_oper_t operation);

void onm_tc_acl_element_hash_free(onm_tc_acl_hash_element_t** el);
void onm_tc_acls_list_hash_free(onm_tc_acl_hash_element_t** hash);
onm_tc_acl_hash_element_t* onm_tc_acl_hash_new(void);


onm_tc_acl_hash_element_t* onm_tc_acl_hash_get_element(onm_tc_acl_hash_element_t** hash, const char* name);
int onm_tc_acls_hash_add_acl_element(onm_tc_acl_hash_element_t** hash, onm_tc_acl_hash_element_t* new_element);
int onm_tc_events_acls_hash_add_acl_element(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);

int events_acl_init(void *priv);
void events_acl_free(void *priv);
