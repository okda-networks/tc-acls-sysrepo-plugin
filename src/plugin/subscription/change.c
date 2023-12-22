#include "change.h"
#include "plugin/context.h"
#include "plugin/common.h"

#include <libyang/libyang.h>
#include <sysrepo.h>
#include <srpc.h>
#include <linux/limits.h>

// change API
#include "plugin/api/attachment-points/attachment_points_change.h"
#include "plugin/api/acls/acl_change.h"

// data
#include "plugin/data/acls/acl.h"

// TODO for debugging, remove later
int change_path_print(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx)
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
		goto error_out;
	}

	SRPLG_LOG_INF(PLUGIN_NAME, "Change PATH PRINT: %s;\n\t Value: %s;\n\t Operation: %d,\n\tchange path %s", node_name, node_value, change_ctx->operation,change_path);

	goto out;

error_out:
	error = -1;
out:
	return error;
}

int onm_tc_subscription_change_acls_acl(sr_session_ctx_t *session, uint32_t subscription_id, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data)
{
	onm_tc_acl_hash_element_t *change_acls_list = NULL;
	onm_tc_ace_element_t *temp_ace_element = NULL;

	int error = SR_ERR_OK;
	onm_tc_ctx_t *ctx = (onm_tc_ctx_t *)private_data;

	// sysrepo
	sr_change_iter_t *changes_iterator = NULL;
	sr_change_oper_t operation = SR_OP_CREATED;
	const char *prev_value = NULL, *prev_list = NULL;
	int prev_default;

	const char *node_name = NULL;
	const char *node_value = NULL;

	char change_xpath_buffer[PATH_MAX] = {0};
	int rc = 0;
	// libyang
	const struct lyd_node *node = NULL;
	// printf("ACL LIST changed to new\n\n");
	//change_acl_list_hash = onm_tc_acl_hash_new();

	if (event == SR_EV_ABORT)
	{
		SRPLG_LOG_ERR(PLUGIN_NAME, "Aborting changes for %s", xpath);
		goto error_out;
	}
	else if (event == SR_EV_DONE)
	{
		// error = sr_copy_config(ctx->startup_session, BASE_YANG_MODEL, SR_DS_RUNNING, 0);
		// Done with the change, free the change acls list
		onm_tc_acls_list_hash_free(&ctx->change_acls_list);
		if (error)
		{
			SRPLG_LOG_ERR(PLUGIN_NAME, "sr_copy_config() error (%d): %s", error, sr_strerror(error));
			
			goto error_out;
		}
	}
	else if (event == SR_EV_CHANGE)
	{
		SRPLG_LOG_INF(PLUGIN_NAME, "Changes on xpath %s", xpath);

		ctx->change_acls_list = onm_tc_acl_hash_new();
		SRPC_SAFE_CALL_ERR_COND(rc, rc < 0, snprintf(change_xpath_buffer, sizeof(change_xpath_buffer), "%s//.", xpath), error_out);
		SRPC_SAFE_CALL_ERR(rc,acl_change_iterator(ctx,session,change_xpath_buffer), error_out);
		//SRPC_SAFE_CALL_ERR(rc, srpc_iterate_changes(ctx, session, change_xpath_buffer, change_path_print, change_acl_init, change_acl_free), error_out);
		
		// print acl list
		onm_tc_acls_list_print_debug(ctx->change_acls_list);
		// apply change acl list changes.
	}
	goto out;

error_out:
	SRPLG_LOG_ERR(PLUGIN_NAME, "acl_change_iterator() failed: %d", rc);
	error = SR_ERR_CALLBACK_FAILED;

out:
	// TODO, review: free change ace, change acl and change acl list
	//onm_tc_acl_list_hash_free(&change_acl_list_hash);
	
	return error;
}

int onm_tc_subscription_change_acls_attachment_points_interface(sr_session_ctx_t *session, uint32_t subscription_id, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data)
{
	int error = SR_ERR_OK;
	onm_tc_ctx_t *ctx = (onm_tc_ctx_t *)private_data;

	// sysrepo
	sr_change_iter_t *changes_iterator = NULL;
	sr_change_oper_t operation = SR_OP_CREATED;
	const char *prev_value = NULL, *prev_list = NULL;
	int prev_default;

	const char *node_name = NULL;
	const char *node_value = NULL;

	// libyang
	const struct lyd_node *node = NULL;

	if (event == SR_EV_ABORT)
	{
		SRPLG_LOG_ERR(PLUGIN_NAME, "Aborting changes for %s", xpath);
		goto error_out;
	}
	else if (event == SR_EV_DONE)
	{
		// error = sr_copy_config(ctx->startup_session, BASE_YANG_MODEL, SR_DS_RUNNING, 0);
		if (error)
		{
			SRPLG_LOG_ERR(PLUGIN_NAME, "sr_copy_config() error (%d): %s", error, sr_strerror(error));
			goto error_out;
		}
	}
	else if (event == SR_EV_CHANGE)
	{
		// connect change API
		SRPLG_LOG_INF(PLUGIN_NAME, "Changes on xpath %s", xpath);
		error = srpc_iterate_changes(ctx, session, xpath, acls_attachment_points_change_interface, acls_attachment_points_change_interface_init, acls_attachment_points_change_interface_free);
		if (error)
		{
			SRPLG_LOG_ERR(PLUGIN_NAME, "srpc_iterate_changes() for acls_attachment_points_change_interface failed: %d", error);
			goto error_out;
		}
	}

	goto out;

error_out:
	error = SR_ERR_CALLBACK_FAILED;

out:
	return error;
}
