#include "change.h"
#include "plugin/context.h"
#include "plugin/common.h"

#include <libyang/libyang.h>
#include <sysrepo.h>
#include <srpc.h>

// change API
#include "plugin/api/attachment-points/attachment_points_change.h"
#include "plugin/api/acls/acl_change.h"
#include "plugin/api/acls/acl/ace_change.h"


#include <linux/limits.h>
#include "plugin/data/acls/acl.h"
#include "plugin/data/acls/acl/aces.h"

onm_tc_acl_hash_element_t *change_acl_hash = NULL;
onm_tc_acl_hash_element_t *change_acl_list_hash = NULL;
onm_tc_ace_element_t *change_ace_element = NULL;

int onm_tc_subscription_change_acls_acl(sr_session_ctx_t *session, uint32_t subscription_id, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data)
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

	char change_xpath_buffer[PATH_MAX] = {0};
	int rc = 0;
	// libyang
	const struct lyd_node *node = NULL;
	// printf("ACL LIST changed to new\n\n");
	change_acl_list_hash = onm_tc_acl_hash_new();

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
		SRPLG_LOG_INF(PLUGIN_NAME, "Changes on xpath %s", xpath);

		// parse acl name, type and aces container:
		SRPC_SAFE_CALL_ERR_COND(rc, rc < 0, snprintf(change_xpath_buffer, sizeof(change_xpath_buffer), "%s/*", xpath), error_out);
		SRPC_SAFE_CALL_ERR(rc, srpc_iterate_changes(ctx, session, change_xpath_buffer, onm_tc_change_acl, onm_tc_change_acl_init, onm_tc_change_acl_free), error_out);

		// print changes acls list
		onm_tc_acl_hash_print_debug(change_acl_list_hash);


		// connect change API
		// error = srpc_iterate_changes(ctx, session, xpath, acls_change_acl, acls_change_acl_init, acls_change_acl_free);
		if (error)
		{
			SRPLG_LOG_ERR(PLUGIN_NAME, "srpc_iterate_changes() for acls_change_acl failed: %d", error);
			goto error_out;
		}
	}

	goto out;

error_out:
	error = SR_ERR_CALLBACK_FAILED;

out:
	// TODO, review: free change ace, change acl and change acl list
	onm_tc_acl_list_hash_free(&change_acl_list_hash);
	
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
