#include "change.h"
#include "plugin/common.h"

#include <sysrepo.h>

int acls_acl_aces_ace_change_name_init(void *priv)
{
	int error = 0;
	return error;
}

int acls_acl_aces_ace_change_name(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx)
{
	int error = 0;
	const char *node_name = LYD_NAME(change_ctx->node);
	const char *node_value = lyd_get_value(change_ctx->node);

	
	switch (change_ctx->operation) {
		case SR_OP_CREATED:
		if(node_value)
		{
			SRPLG_LOG_INF(PLUGIN_NAME, "ACE NAME CHANGE Node Name: %s; Value: %s; Operation: %d", node_name, node_value, change_ctx->operation);
		}
			break;
		case SR_OP_MODIFIED:
			break;
		case SR_OP_DELETED:
			break;
		case SR_OP_MOVED:
			break;
	}

	return error;
}

void acls_acl_aces_ace_change_name_free(void *priv)
{
}

