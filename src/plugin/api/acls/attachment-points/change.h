#ifndef ONM_TC_PLUGIN_API_ACLS_ATTACHMENT_POINTS_CHANGE_H
#define ONM_TC_PLUGIN_API_ACLS_ATTACHMENT_POINTS_CHANGE_H

#include <utarray.h>
#include <srpc.h>

int acls_attachment_points_change_interface_init(void *priv);
int acls_attachment_points_change_interface(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx);
void acls_attachment_points_change_interface_free(void *priv);

#endif // ONM_TC_PLUGIN_API_ACLS_ATTACHMENT_POINTS_CHANGE_H