#ifndef ONM_TC_PLUGIN_API_ACLS_ATTACHMENT_POINTS_INTERFACE_CHANGE_H
#define ONM_TC_PLUGIN_API_ACLS_ATTACHMENT_POINTS_INTERFACE_CHANGE_H

#include <utarray.h>
#include <srpc.h>

int acls_attachment_points_interface_change_interface_id_init(void *priv);
int acls_attachment_points_interface_change_interface_id(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_attachment_points_interface_change_interface_id_free(void *priv);

#endif // ONM_TC_PLUGIN_API_ACLS_ATTACHMENT_POINTS_INTERFACE_CHANGE_H