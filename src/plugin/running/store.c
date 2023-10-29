#include "store.h"
#include "plugin/common.h"
#include "plugin/data/acls/acl.h"
#include <libyang/libyang.h>
#include <sysrepo.h>
#include <srpc.h>

static int onm_tc_running_store_attachment_points(void *priv, const struct lyd_node *parent_container);
static int onm_tc_running_store_acl(void *priv, const struct lyd_node *parent_container);

int onm_tc_running_store(onm_tc_ctx_t *ctx, sr_session_ctx_t *session)
{
	int error = 0;
	sr_data_t *subtree = NULL;

	error = sr_get_subtree(session, ONM_TC_ACLS_CONTAINER_YANG_PATH, 0, &subtree);
	if (error) {
		SRPLG_LOG_ERR(PLUGIN_NAME, "sr_get_subtree() error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	srpc_startup_store_t store_values[] = {
		{
			"/ietf-access-control-list:acls/attachment-points",
			onm_tc_running_store_attachment_points,
		},
		{
			"/ietf-access-control-list:acls/acl[name='%s']",
			onm_tc_running_store_acl,
		},
	};

	for (size_t i = 0; i < ARRAY_SIZE(store_values); i++) {
		const srpc_startup_store_t *store = &store_values[i];

		error = store->cb(ctx, subtree->tree);
		if (error != 0) {
			SRPLG_LOG_ERR(PLUGIN_NAME, "running store callback failed for value %s", store->name);
			goto error_out;
		}
	}

	goto out;

error_out:
	error = -1;

out:
	if (subtree) {
		sr_release_data(subtree);
	}

	return error;
}

static int onm_tc_running_store_attachment_points(void *priv, const struct lyd_node *parent_container)
{
	int error = 0;
	return error;
}

static int onm_tc_running_store_acl(void *priv, const struct lyd_node *parent_container)
{
	int error = 0;
    onm_tc_ctx_t* ctx = (onm_tc_ctx_t*)priv;
    srpc_check_status_t check_status = srpc_check_status_none;
    onm_tc_acl_hash_element_t* acl_hash = NULL;
    struct lyd_node* acl_node = NULL;

    acl_node = srpc_ly_tree_get_child_list(parent_container, "acl");
    if (acl_node == NULL) {
        SRPLG_LOG_ERR(PLUGIN_NAME, "srpc_ly_tree_get_child_leaf returned NULL for 'acls'");
        goto error_out;
    }

    // map libyang data to the acl hash
    SRPC_SAFE_CALL_ERR(error, onm_tc_acl_hash_from_ly(&acl_hash, acl_node), error_out);

    onm_tc_acl_hash_print_debug(acl_hash);

    // check running data

    // if needed, apply acl_hash to netlink here

    goto out;

error_out:
    error = -1;

out:
    if (acl_hash) {
        //TODO remove return error and define hash free function
		//onm_tc_acl_hash_free(&acl_hash);
		//return error;
    }

	return error;
}