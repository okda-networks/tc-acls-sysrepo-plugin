#ifndef ONM_TC_PLUGIN_SUBSCRIPTION_CHANGE_H
#define ONM_TC_PLUGIN_SUBSCRIPTION_CHANGE_H

#include <sysrepo_types.h>

int onm_tc_subscription_change_acls_acl(sr_session_ctx_t *session, uint32_t subscription_id, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);
int onm_tc_subscription_change_acls_attachment_points_interface(sr_session_ctx_t *session, uint32_t subscription_id, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);

#endif // ONM_TC_PLUGIN_SUBSCRIPTION_CHANGE_H