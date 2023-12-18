#include "acl_change.h"
#include "plugin/common.h"

#include <sysrepo.h>
#include "plugin/data/acls/acl.h"
#include "plugin/api/acls/acl/ace_change.h"
#include <stdio.h>
#include <linux/limits.h>
#include "plugin/context.h"

#include "plugin/data/acls/acl.h"
#include "plugin/data/acls/acl/linked_list.h"


int onm_tc_change_acl_init(void *priv)
{
	int error = 0;
	return error;
}

int onm_tc_change_acl(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx)
{
	int error = 0;
	const char *node_name = LYD_NAME(change_ctx->node);
	const char *node_value = lyd_get_value(change_ctx->node);
	char change_path[PATH_MAX] = {0};

	onm_tc_ctx_t *ctx = (onm_tc_ctx_t *) priv;

	char change_xpath_buffer[PATH_MAX] = { 0 };
	int rc = 0;
	
	error = (lyd_path(change_ctx->node, LYD_PATH_STD, change_path, sizeof(change_path)) == NULL);
	if (error) {
		SRPLG_LOG_ERR(PLUGIN_NAME, "lyd_path() error");
		//goto error_out;
	}


	switch (change_ctx->operation) {
		case SR_OP_CREATED:
			{
				SRPLG_LOG_INF(PLUGIN_NAME, "Node Name: %s; Value: %s; Operation: %d", node_name, node_value, change_ctx->operation);
				if (strcmp(node_name,"name")==0)
				{	
					//printf("CREATED NEW CHANGE ACL ELEMENT\n\n");
					
					// a new name means a new acl, initialize temp change acl hash element
					change_acl_hash = onm_tc_acl_hash_element_new();
					SRPC_SAFE_CALL_ERR(error, onm_tc_acl_hash_element_set_name(&change_acl_hash, node_value), error_out);
				}
				if (strcmp(node_name,"type")==0)
				{
					SRPC_SAFE_CALL_ERR(error, onm_tc_acl_hash_element_set_type(&change_acl_hash, node_value), error_out);
				}

				if (strcmp(node_name,"aces") == 0 && change_ctx->node->schema->nodetype == LYS_CONTAINER)
				{
					onm_tc_ctx_t* ctx = (onm_tc_ctx_t*)priv;
					//SRPLG_LOG_INF(PLUGIN_NAME, "A new list for aces: %s", change_path);

					// init ace list inside temp change acl hash element
					ONM_TC_ACL_LIST_NEW(change_acl_hash->acl.aces.ace);

					SRPC_SAFE_CALL_ERR_COND(rc, rc < 0, snprintf(change_xpath_buffer, sizeof(change_xpath_buffer), "%s/*", change_path), error_out);
					SRPC_SAFE_CALL_ERR(rc, srpc_iterate_changes(ctx, session, change_xpath_buffer, acls_acl_aces_change_ace, acls_acl_aces_change_ace_init, acls_acl_aces_change_ace_free), error_out);
				
					if (change_acl_hash)
					{
						onm_tc_acl_hash_add_element(&change_acl_list_hash, change_acl_hash);
					}
				}
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

	
	goto out;

error_out:
	return error;
out:
	return error;
}

void onm_tc_change_acl_free(void *priv)
{
	
}

