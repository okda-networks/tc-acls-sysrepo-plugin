#include "plugin.h"
#include "plugin/common.h"
#include "plugin/context.h"
#include "plugin/common.h"

// startup
#include "plugin/startup/load.h"
#include "plugin/store.h"

// subscription
#include "plugin/subscription/change.h"
#include "plugin/subscription/operational.h"
#include "plugin/subscription/rpc.h"

#include <libyang/libyang.h>
#include <sysrepo.h>
#include <srpc.h>

int sr_plugin_init_cb(sr_session_ctx_t *running_session, void **private_data)
{
	int error = 0;

	bool empty_startup_ds = false;
	bool empty_running_ds = false;

	// sysrepo
	sr_session_ctx_t *startup_session = NULL;
	sr_conn_ctx_t *connection = NULL;
	sr_subscription_ctx_t *subscription = NULL;

	// plugin
	onm_tc_ctx_t *ctx = NULL;

	// init context
	ctx = malloc(sizeof(*ctx));
	*ctx = (onm_tc_ctx_t){0};

	*private_data = ctx;

	// module changes
	srpc_module_change_t module_changes[] = {
        {
            ONM_TC_ACLS_ACL_YANG_PATH,
            onm_tc_subscription_change_acls_acl,
        },
        {
            ONM_TC_ACLS_ATTACHMENT_POINTS_INTERFACE_YANG_PATH,
            onm_tc_subscription_change_acls_attachment_points_interface,
        },
	};

	// rpcs
	srpc_rpc_t rpcs[] = {
	};

	// operational getters
	//TODO Fix operational data getters
	srpc_operational_t oper[] = {
        /*{
			BASE_YANG_MODEL,
            ONM_TC_ACLS_ACL_ACES_ACE_STATISTICS_MATCHED_PACKETS_YANG_PATH,
            onm_tc_subscription_operational_acls_acl_aces_ace_statistics_matched_packets,
        },
        {
			BASE_YANG_MODEL,
            ONM_TC_ACLS_ACL_ACES_ACE_STATISTICS_MATCHED_OCTETS_YANG_PATH,
            onm_tc_subscription_operational_acls_acl_aces_ace_statistics_matched_octets,
        },*/
        {
			BASE_YANG_MODEL,
            ONM_TC_ACLS_ACL_ACES_ACE_YANG_PATH,
            onm_tc_subscription_operational_acls_acl_aces_ace,
        },
        {
			BASE_YANG_MODEL,
            ONM_TC_ACLS_ACL_YANG_PATH,
            onm_tc_subscription_operational_acls_acl,
        },
        /*{
			BASE_YANG_MODEL,
            ONM_TC_ACLS_ATTACHMENT_POINTS_INTERFACE_INGRESS_ACL_SETS_ACL_SET_ACE_STATISTICS_NAME_YANG_PATH,
            onm_tc_subscription_operational_acls_attachment_points_interface_ingress_acl_sets_acl_set_ace_statistics_name,
        },
        {
			BASE_YANG_MODEL,
            ONM_TC_ACLS_ATTACHMENT_POINTS_INTERFACE_INGRESS_ACL_SETS_ACL_SET_ACE_STATISTICS_MATCHED_PACKETS_YANG_PATH,
            onm_tc_subscription_operational_acls_attachment_points_interface_ingress_acl_sets_acl_set_ace_statistics_matched_packets,
        },
        {
			BASE_YANG_MODEL,
            ONM_TC_ACLS_ATTACHMENT_POINTS_INTERFACE_INGRESS_ACL_SETS_ACL_SET_ACE_STATISTICS_MATCHED_OCTETS_YANG_PATH,
            onm_tc_subscription_operational_acls_attachment_points_interface_ingress_acl_sets_acl_set_ace_statistics_matched_octets,
        },
        {
			BASE_YANG_MODEL,
            ONM_TC_ACLS_ATTACHMENT_POINTS_INTERFACE_INGRESS_ACL_SETS_ACL_SET_ACE_STATISTICS_YANG_PATH,
            onm_tc_subscription_operational_acls_attachment_points_interface_ingress_acl_sets_acl_set_ace_statistics,
        },*/
        {
			BASE_YANG_MODEL,
            ONM_TC_ACLS_ATTACHMENT_POINTS_INTERFACE_INGRESS_ACL_SETS_ACL_SET_YANG_PATH,
            onm_tc_subscription_operational_acls_attachment_points_interface_ingress_acl_sets_acl_set,
        },
        /*{
			BASE_YANG_MODEL,
            ONM_TC_ACLS_ATTACHMENT_POINTS_INTERFACE_EGRESS_ACL_SETS_ACL_SET_ACE_STATISTICS_NAME_YANG_PATH,
            onm_tc_subscription_operational_acls_attachment_points_interface_egress_acl_sets_acl_set_ace_statistics_name,
        },
        {
			BASE_YANG_MODEL,
            ONM_TC_ACLS_ATTACHMENT_POINTS_INTERFACE_EGRESS_ACL_SETS_ACL_SET_ACE_STATISTICS_MATCHED_PACKETS_YANG_PATH,
            onm_tc_subscription_operational_acls_attachment_points_interface_egress_acl_sets_acl_set_ace_statistics_matched_packets,
        },
        {
			BASE_YANG_MODEL,
            ONM_TC_ACLS_ATTACHMENT_POINTS_INTERFACE_EGRESS_ACL_SETS_ACL_SET_ACE_STATISTICS_MATCHED_OCTETS_YANG_PATH,
            onm_tc_subscription_operational_acls_attachment_points_interface_egress_acl_sets_acl_set_ace_statistics_matched_octets,
        },
        {
			BASE_YANG_MODEL,
            ONM_TC_ACLS_ATTACHMENT_POINTS_INTERFACE_EGRESS_ACL_SETS_ACL_SET_ACE_STATISTICS_YANG_PATH,
            onm_tc_subscription_operational_acls_attachment_points_interface_egress_acl_sets_acl_set_ace_statistics,
        },*/
        {
			BASE_YANG_MODEL,
            ONM_TC_ACLS_ATTACHMENT_POINTS_INTERFACE_EGRESS_ACL_SETS_ACL_SET_YANG_PATH,
            onm_tc_subscription_operational_acls_attachment_points_interface_egress_acl_sets_acl_set,
        },
        {
			BASE_YANG_MODEL,
            ONM_TC_ACLS_ATTACHMENT_POINTS_INTERFACE_YANG_PATH,
            onm_tc_subscription_operational_acls_attachment_points_interface,
        },
	};

	connection = sr_session_get_connection(running_session);
	error = sr_session_start(connection, SR_DS_STARTUP, &startup_session);
	if (error) {
		SRPLG_LOG_ERR(PLUGIN_NAME, "sr_session_start() error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	ctx->startup_session = startup_session;
	ctx->running_session = running_session;

	error = srpc_check_empty_datastore(running_session, ONM_TC_ACLS_ACL_YANG_PATH, &empty_running_ds);
	if (error) {
		SRPLG_LOG_ERR(PLUGIN_NAME, "Failed checking datastore contents: %d", error);
		goto error_out;
	}
	if (empty_running_ds){
		SRPLG_LOG_INF(PLUGIN_NAME, "Running datastore is empty");
		SRPLG_LOG_INF(PLUGIN_NAME, "Checking startup data store");
		error = srpc_check_empty_datastore(startup_session, ONM_TC_ACLS_ACL_YANG_PATH, &empty_startup_ds);
		if (error) {
			SRPLG_LOG_ERR(PLUGIN_NAME, "Failed checking datastore contents: %d", error);
			goto error_out;
		}

		if (empty_startup_ds) {
			// both running and startup sessions are empty
			SRPLG_LOG_INF(PLUGIN_NAME, "Startup datastore is empty");
			SRPLG_LOG_INF(PLUGIN_NAME, "Loading initial system data");
			// load initial running DS data on the system
			//SRPC_SAFE_CALL_ERR(error, onm_tc_startup_load(ctx, startup_session), error_out);
			//if (error) {
			//	SRPLG_LOG_ERR(PLUGIN_NAME, "Error loading initial data into the startup datastore... exiting");
			//	goto error_out;
			//}
		} else {
			// running ds is empty and startup ds contains data
			SRPLG_LOG_INF(PLUGIN_NAME, "Startup datastore contains data");
			SRPLG_LOG_INF(PLUGIN_NAME, "Storing startup datastore data in the system");

			// apply config data from startup DS to netlink tc
			error = onm_tc_store(ctx, startup_session,true);
			if (error) {
				SRPLG_LOG_ERR(PLUGIN_NAME, "Error applying initial data from startup datastore to the system... exiting");
				goto error_out;
			}
			// successfully applied startup config on netlink tc
			// copy contents of the startup ds to running ds
			//error = sr_copy_config(running_session, BASE_YANG_MODEL, SR_DS_STARTUP, 0);
			if (error) {
				SRPLG_LOG_ERR(PLUGIN_NAME, "sr_copy_config() error (%d): %s", error, sr_strerror(error));
				goto error_out;
			}
		}

	}
	else{
		// running ds contains data
		SRPLG_LOG_INF(PLUGIN_NAME, "Running datastore contains data");
		SRPLG_LOG_INF(PLUGIN_NAME, "Reconfiguring running datastore data in the system");

		error = onm_tc_store(ctx, running_session,true);
		if (error) {
			SRPLG_LOG_ERR(PLUGIN_NAME, "Error applying initial data from startup datastore to the system... exiting");
			goto error_out;
		}
	}

	// subscribe every module change in running_session
	for (size_t i = 0; i < ARRAY_SIZE(module_changes); i++) {
		const srpc_module_change_t *change = &module_changes[i];
		SRPLG_LOG_INF(PLUGIN_NAME, "Subscribing module change callback %s", change->path);
		// in case of work on a specific callback set it to NULL
		if (change->cb) {
			error = sr_module_change_subscribe(running_session, BASE_YANG_MODEL, change->path, change->cb, *private_data, 0, SR_SUBSCR_DEFAULT, &subscription);
			if (error) {
				SRPLG_LOG_ERR(PLUGIN_NAME, "sr_module_change_subscribe() error for \"%s\" (%d): %s", change->path, error, sr_strerror(error));
				goto error_out;
			}
		}
	}

	// subscribe every rpc in running session
	for (size_t i = 0; i < ARRAY_SIZE(rpcs); i++) {
		const srpc_rpc_t *rpc = &rpcs[i];

		// in case of work on a specific callback set it to NULL
		if (rpc->cb) {
			error = sr_rpc_subscribe(running_session, rpc->path, rpc->cb, *private_data, 0, SR_SUBSCR_DEFAULT, &subscription);
			if (error) {
				SRPLG_LOG_ERR(PLUGIN_NAME, "sr_rpc_subscribe error (%d): %s", error, sr_strerror(error));
				goto error_out;
			}
		}
	}

	// subscribe every operational getter
	for (size_t i = 0; i < ARRAY_SIZE(oper); i++) {
		const srpc_operational_t *op = &oper[i];

		// in case of work on a specific callback set it to NULL
		if (op->cb) {
			//error = sr_oper_get_subscribe(running_session, BASE_YANG_MODEL, op->path, op->cb, NULL, SR_SUBSCR_DEFAULT, &subscription);
			if (error) {
				SRPLG_LOG_ERR(PLUGIN_NAME, "sr_oper_get_subscribe() error (%d): %s", error, sr_strerror(error));
				goto error_out;
			}
		}
	}

	goto out;

error_out:
	error = -1;
	SRPLG_LOG_ERR(PLUGIN_NAME, "Error occured while initializing the plugin (%d)", error);

out:
	return error ? SR_ERR_CALLBACK_FAILED : SR_ERR_OK;
}

void sr_plugin_cleanup_cb(sr_session_ctx_t *running_session, void *private_data)
{
	int error = 0;

	onm_tc_ctx_t *ctx = (onm_tc_ctx_t *) private_data;

	// save current running configuration into startup for next time when the plugin starts
	//error = sr_copy_config(ctx->startup_session, BASE_YANG_MODEL, SR_DS_RUNNING, 0);
	if (error) {
		SRPLG_LOG_ERR(PLUGIN_NAME, "sr_copy_config() error (%d): %s", error, sr_strerror(error));
	}
	free(ctx);
}