#include "change.h"
#include "plugin/common.h"

#include "plugin/context.h"
#include "plugin/api/acls/acl/aces/ace/change.h"

#include <sysrepo.h>

int acls_acl_aces_change_ace_init(void *priv)
{
	int error = 0;
	return error;
}

int acls_acl_aces_change_ace(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx)
{
	int error = 0;
	const char *node_name = LYD_NAME(change_ctx->node);
	const char *node_value = lyd_get_value(change_ctx->node);

	char change_path[PATH_MAX] = {0};


	char change_xpath_buffer[PATH_MAX] = { 0 };
	int rc = 0;



	error = (lyd_path(change_ctx->node, LYD_PATH_STD, change_path, sizeof(change_path)) == NULL);
	if (error) {
		SRPLG_LOG_ERR(PLUGIN_NAME, "lyd_path() error");
		//goto error_out;
	}

	switch (change_ctx->operation) {
		case SR_OP_CREATED:
		if(node_value)
		{
			//SRPLG_LOG_INF(PLUGIN_NAME, "ACE CHANGE: Node Path: %s", change_path);
			SRPLG_LOG_INF(PLUGIN_NAME, "Node Name: %s; Value: %s; Operation: %d", node_name,node_value, change_ctx->operation);
		}
			break;
		case SR_OP_MODIFIED:
			break;
		case SR_OP_DELETED:
			break;
		case SR_OP_MOVED:
			break;
	}

	if (strcmp(node_name,"ace") == 0)
	{
		onm_tc_ctx_t* ctx = (onm_tc_ctx_t*)priv;
		SRPC_SAFE_CALL_ERR_COND(rc, rc < 0, snprintf(change_xpath_buffer, sizeof(change_xpath_buffer), "%s/name", change_path), error_out);
    	SRPC_SAFE_CALL_ERR(rc, srpc_iterate_changes(ctx, session, change_xpath_buffer, acls_acl_aces_ace_change_name, acls_acl_aces_change_ace_init, acls_acl_aces_change_ace_free), error_out);

		//action forwarding
		SRPC_SAFE_CALL_ERR_COND(rc, rc < 0, snprintf(change_xpath_buffer, sizeof(change_xpath_buffer), "%s/actions/forwarding", change_path), error_out);
    	SRPC_SAFE_CALL_ERR(rc, srpc_iterate_changes(ctx, session, change_xpath_buffer, acls_acl_aces_ace_change_name, acls_acl_aces_change_ace_init, acls_acl_aces_change_ace_free), error_out);
	
	}

	return error;
error_out:
	return error;
}

void acls_acl_aces_change_ace_free(void *priv)
{
}

