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
#include "plugin/data/acls/acl/aces.h"

// TODO for debugging, remove later
int change_path_print(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx)
{
	int error = 0;
	const char *node_name = LYD_NAME(change_ctx->node);
	const char *node_value = lyd_get_value(change_ctx->node);
	const char *prev_value = change_ctx->previous_value;
	const char *prev_list = change_ctx->previous_list;
	char change_path[PATH_MAX] = {0};
	onm_tc_ctx_t *ctx = (onm_tc_ctx_t *) priv;

	char change_xpath_buffer[PATH_MAX] = { 0 };
	int rc = 0;
	
	error = (lyd_path(change_ctx->node, LYD_PATH_STD, change_path, sizeof(change_path)) == NULL);
	if (error) {
		SRPLG_LOG_ERR(PLUGIN_NAME, "lyd_path() error");
		goto error_out;
	}

	SRPLG_LOG_INF(PLUGIN_NAME, "Change PATH PRINT: %s;\n\t New Value: %s;\n\t Previous Value: %s;\n\t Previous list: %s;\n\t Operation: %d,\n\tchange path %s",
	node_name, node_value,prev_value,prev_list, change_ctx->operation,change_path);

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
		reload_running_acls_list(ctx);
		//onm_tc_acls_list_print_debug(ctx->running_acls_list);
		// Done with the change, free the change acls list
		if (&ctx->events_acls_list){
			onm_tc_acls_list_hash_free(&ctx->events_acls_list);
		}
	}
	else if (event == SR_EV_CHANGE)
	{
		SRPLG_LOG_INF(PLUGIN_NAME, "Changes on xpath %s", xpath);

		// ACL Name (complete acl SR_OP_CREATED, SR_OP_DELETED)
		SRPC_SAFE_CALL_ERR_COND(rc, rc < 0, snprintf(change_xpath_buffer, sizeof(change_xpath_buffer), "%s/*", xpath), error_out);
        SRPC_SAFE_CALL_ERR(rc, srpc_iterate_changes(ctx, session, change_xpath_buffer, onm_tc_events_acls_hash_add_acl_element,events_acl_init, events_acl_free), error_out);

		// ACE Name (complete ace SR_OP_CREATED, SR_OP_DELETED)
		SRPC_SAFE_CALL_ERR_COND(rc, rc < 0, snprintf(change_xpath_buffer, sizeof(change_xpath_buffer), "%s/aces/ace/*", xpath), error_out);
		SRPC_SAFE_CALL_ERR(rc, srpc_iterate_changes(ctx, session, change_xpath_buffer, events_acls_hash_update_ace_element_from_change_ctx, events_acl_init, events_acl_free), error_out);

		// ACE nodes (ACEs reorder SR_OP_CREATED, SR_OP_MOVED, SR_OP_DELETED)
		SRPC_SAFE_CALL_ERR_COND(rc, rc < 0, snprintf(change_xpath_buffer, sizeof(change_xpath_buffer), "%s/aces/*", xpath), error_out);
        SRPC_SAFE_CALL_ERR(rc, srpc_iterate_changes(ctx, session, change_xpath_buffer, reorder_events_acls_aces_from_change_ctx,events_acl_init, events_acl_free), error_out);

		// events list cleanup: remove aces that had no change on their priority from events list
		remove_unchanged_priority_aces_from_events_list(ctx);

		// Changes within the ACE: match on eth (SR_OP_CREATED, SR_OP_DELETED, SR_OP_MODIFIED)
		SRPC_SAFE_CALL_ERR_COND(rc, rc < 0, snprintf(change_xpath_buffer, sizeof(change_xpath_buffer), "%s/aces/ace/matches/eth/*", xpath), error_out);
		SRPC_SAFE_CALL_ERR(rc, srpc_iterate_changes(ctx, session, change_xpath_buffer, events_acls_hash_update_ace_element_from_change_ctx, events_acl_init, events_acl_free), error_out);

		//  Changes within the ACE: match on ipv4 (SR_OP_CREATED, SR_OP_DELETED, SR_OP_MODIFIED)
		SRPC_SAFE_CALL_ERR_COND(rc, rc < 0, snprintf(change_xpath_buffer, sizeof(change_xpath_buffer), "%s/aces/ace/matches/ipv4/*", xpath), error_out);
		SRPC_SAFE_CALL_ERR(rc, srpc_iterate_changes(ctx, session, change_xpath_buffer, events_acls_hash_update_ace_element_from_change_ctx, events_acl_init, events_acl_free), error_out);

		//  Changes within the ACE: match on ipv6 (SR_OP_CREATED, SR_OP_DELETED, SR_OP_MODIFIED)
		SRPC_SAFE_CALL_ERR_COND(rc, rc < 0, snprintf(change_xpath_buffer, sizeof(change_xpath_buffer), "%s/aces/ace/matches/ipv6/*", xpath), error_out);
		SRPC_SAFE_CALL_ERR(rc, srpc_iterate_changes(ctx, session, change_xpath_buffer, events_acls_hash_update_ace_element_from_change_ctx, events_acl_init, events_acl_free), error_out);

		//  Changes within the ACE: match on tcp (SR_OP_CREATED, SR_OP_DELETED, SR_OP_MODIFIED)
		SRPC_SAFE_CALL_ERR_COND(rc, rc < 0, snprintf(change_xpath_buffer, sizeof(change_xpath_buffer), "%s/aces/ace/matches/tcp/*/*", xpath), error_out);
		SRPC_SAFE_CALL_ERR(rc, srpc_iterate_changes(ctx, session, change_xpath_buffer, events_acls_hash_update_ace_element_from_change_ctx, events_acl_init, events_acl_free), error_out);
		
		//  Changes within the ACE: match on udp (SR_OP_CREATED, SR_OP_DELETED, SR_OP_MODIFIED)
		SRPC_SAFE_CALL_ERR_COND(rc, rc < 0, snprintf(change_xpath_buffer, sizeof(change_xpath_buffer), "%s/aces/ace/matches/udp/*/*", xpath), error_out);
		SRPC_SAFE_CALL_ERR(rc, srpc_iterate_changes(ctx, session, change_xpath_buffer, events_acls_hash_update_ace_element_from_change_ctx, events_acl_init, events_acl_free), error_out);

		//  Changes within the ACE: actions (SR_OP_MODIFIED)
		SRPC_SAFE_CALL_ERR_COND(rc, rc < 0, snprintf(change_xpath_buffer, sizeof(change_xpath_buffer), "%s/aces/ace/actions/forwarding", xpath), error_out);
		SRPC_SAFE_CALL_ERR(rc, srpc_iterate_changes(ctx, session, change_xpath_buffer, events_acls_hash_update_ace_element_from_change_ctx, events_acl_init, events_acl_free), error_out);
		
		/*
		validate events_acls hash data: to solve problems on netlink where change data is not a complete filter data.
		(e.g. user changes eth mask without changing the eth mac, while netlink requres full filter details).
		This validation gets the unchanged ace data and adds them to events list with default change operation (-1).
		*/
		rc = validate_and_update_events_acls_hash(ctx);
		if (rc < 0){
			return rc;
		}

		// print acl list
		//onm_tc_acls_list_print_debug(ctx->events_acls_list);

		// apply change acl list changes.
		rc = apply_events_acls_changes(ctx);
		//rc = -1;
		if (rc < 0){
			goto error_out;
		}

		if (rc < 0){
			goto error_out;
		}
	}
	goto out;

error_out:
	onm_tc_acl_element_hash_free(&ctx->events_acls_list);
	error = SR_ERR_CALLBACK_FAILED;

out:
	return error;
}

int onm_tc_subscription_change_acls_attachment_points_interface(sr_session_ctx_t *session, uint32_t subscription_id, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data)
{
	int error = SR_ERR_OK;
	onm_tc_ctx_t *ctx = (onm_tc_ctx_t *)private_data;

	// sysrepo
	char change_xpath_buffer[PATH_MAX] = {0};

	if (event == SR_EV_ABORT)
	{
		SRPLG_LOG_ERR(PLUGIN_NAME, "Aborting changes for %s", xpath);
		goto error_out;
	}
	else if (event == SR_EV_DONE)
	{
		// error = sr_copy_config(ctx->startup_session, BASE_YANG_MODEL, SR_DS_RUNNING, 0);
		onm_tc_aps_interface_hash_free(&ctx->events_attachment_points_list);
		if (error)
		{
			SRPLG_LOG_ERR(PLUGIN_NAME, "sr_copy_config() error (%d): %s", error, sr_strerror(error));
			goto error_out;
		}
	}
	else if (event == SR_EV_CHANGE){
		SRPLG_LOG_INF(PLUGIN_NAME, "Changes on xpath %s", xpath);
		SRPC_SAFE_CALL_ERR_COND(error, error < 0, snprintf(change_xpath_buffer, sizeof(change_xpath_buffer), "%s/ingress/acl-sets/acl-set/*", xpath), error_out);
		error = srpc_iterate_changes(ctx, session, change_xpath_buffer, events_aps_hash_update_from_change_ctx, acls_attachment_points_change_interface_init, acls_attachment_points_change_interface_free);
		// todo error handling

		SRPLG_LOG_INF(PLUGIN_NAME, "Changes on xpath %s", xpath);
		SRPC_SAFE_CALL_ERR_COND(error, error < 0, snprintf(change_xpath_buffer, sizeof(change_xpath_buffer), "%s/egress/acl-sets/acl-set/*", xpath), error_out);
		error = srpc_iterate_changes(ctx, session, change_xpath_buffer, events_aps_hash_update_from_change_ctx, acls_attachment_points_change_interface_init, acls_attachment_points_change_interface_free);
		

		error = apply_attachment_points_events_list_changes(ctx);
		if (error)
		{
			SRPLG_LOG_ERR(PLUGIN_NAME, "Attachment points change failed %d", error);
			goto error_out;
		}
	}

	goto out;

error_out:
	error = SR_ERR_CALLBACK_FAILED;

out:
	return error;
}
