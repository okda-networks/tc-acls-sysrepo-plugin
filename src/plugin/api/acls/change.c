#include "change.h"
#include "plugin/common.h"

#include <sysrepo.h>
#include "plugin/data/acls/acl.h"
#include "plugin/api/acls/acl/aces/change.h"
#include <stdio.h>
#include <limits.h>
#include "plugin/context.h"

int acls_change_acl_init(void *priv)
{
	int error = 0;
	return error;
}

int acls_change_acl(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx)
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
			//SRPLG_LOG_INF(PLUGIN_NAME, "Node Path: %s", change_path);
			SRPLG_LOG_INF(PLUGIN_NAME, "Node Name: %s; Value: %s; Operation: %d", node_name, node_value, change_ctx->operation);
		}
			break;
		case SR_OP_MODIFIED:
		SRPLG_LOG_INF(PLUGIN_NAME, "Node Path: %s", change_path);
		SRPLG_LOG_INF(PLUGIN_NAME, "Node Name: %s; Previous Value: %s, Value: %s; Operation: %d", node_name, change_ctx->previous_value, node_value, change_ctx->operation);

			break;
		case SR_OP_DELETED:
			break;
		case SR_OP_MOVED:
			break;
	}

	if (strcmp(node_name,"aces") == 0)
	{
		onm_tc_ctx_t* ctx = (onm_tc_ctx_t*)priv;
		//SRPLG_LOG_INF(PLUGIN_NAME, "A new list for aces: %s", change_path);
		SRPC_SAFE_CALL_ERR_COND(rc, rc < 0, snprintf(change_xpath_buffer, sizeof(change_xpath_buffer), "%s/*", change_path), error_out);
    	SRPC_SAFE_CALL_ERR(rc, srpc_iterate_changes(ctx, session, change_xpath_buffer, acls_acl_aces_change_ace, acls_acl_aces_change_ace_init, acls_acl_aces_change_ace_free), error_out);
	}

	return error;
error_out:
	return error;
}

void acls_change_acl_free(void *priv)
{
}

