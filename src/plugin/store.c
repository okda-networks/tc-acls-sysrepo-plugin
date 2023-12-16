#include "store.h"
#include "plugin/common.h"
#include "plugin/data/acls/acl.h"
#include "plugin/data/attachment_points/attachment_points.h"
#include "plugin/api/store.h"
#include <libyang/libyang.h>
#include <sysrepo.h>
#include <srpc.h>

static int onm_tc_store_attachment_points(void *priv, const struct lyd_node *parent_container);
static int onm_tc_store_acl(void *priv, const struct lyd_node *parent_container);

int onm_tc_store(onm_tc_ctx_t *ctx, sr_session_ctx_t *session)
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
			"/ietf-access-control-list:acls/acl",
			onm_tc_store_acl,
		},
		{
			"/ietf-access-control-list:acls/attachment-points",
			onm_tc_store_attachment_points,
		},		
	};

	for (size_t i = 0; i < ARRAY_SIZE(store_values); i++) {
		const srpc_startup_store_t *store = &store_values[i];
		SRPLG_LOG_INF(PLUGIN_NAME, "Store name %s", store->name);
		error = store->cb(ctx, subtree->tree);
		if (error != 0) {
			SRPLG_LOG_ERR(PLUGIN_NAME, "Startup store callback failed for value %s", store->name);
			goto error_out;
		}
	}

	// apply to netlink through api store function.
	acls_store_api(ctx);
	goto out;

error_out:
	error = -1;

out:
	if (subtree) {
		sr_release_data(subtree);
	}

	if(ctx->attachment_points_interface_hash_element)
	{
		//TODO define hash free function
		//onm_tc_acl_hash_free(&ctx->attachment_points_interface_hash_element);
	}
	if(ctx->acl_hash_element)
	{
		//TODO define hash free function
		//onm_tc_acl_hash_free(&ctx->attachment_points_interface_hash_element);
	}

	return error;
}

static int onm_tc_store_attachment_points(void *priv, const struct lyd_node *parent_container)
{
	int error = 0;
    onm_tc_ctx_t* ctx = (onm_tc_ctx_t*)priv;
    srpc_check_status_t check_status = srpc_check_status_none;
    onm_tc_aps_interface_hash_element_t* aps_interface_hash = NULL;
	struct lyd_node* aps_container_node = NULL;
    struct lyd_node* aps_interface_list_node = NULL;

	aps_container_node = srpc_ly_tree_get_child_container(parent_container, "attachment-points");
    aps_interface_list_node = srpc_ly_tree_get_child_list(aps_container_node, "interface");
    if (aps_interface_list_node == NULL) {
        SRPLG_LOG_ERR(PLUGIN_NAME, "srpc_ly_tree_get_child_leaf returned NULL for 'attachment-points/interface'");
        goto error_out;
    }

    // map libyang data to the interfaces hash
    SRPC_SAFE_CALL_ERR(error, onm_tc_aps_interface_hash_from_ly(&aps_interface_hash, aps_interface_list_node), error_out);

    onm_tc_aps_interface_hash_print_debug(aps_interface_hash);

	ctx->attachment_points_interface_hash_element = aps_interface_hash;
    // check startup data

    goto out;

error_out:
    error = -1;

out:
	return error;
}

static int onm_tc_store_acl(void *priv, const struct lyd_node *parent_container)
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

    // check startup data

    // apply acl_hash to netlink here
	// since there is no way for tc to defind a tc block without assigning it to an interfaces,
	// we pass acl_hash to context so that it gets processed after processing the attachment points,
	// at that point we get both acls and attachment_points hash tables we get a list of interfaces and their acl blocks,
	// this allows us to define netling tc (acl_hash) blocks to the interfaces (aps_interface_hash).
	ctx->acl_hash_element = acl_hash;
    goto out;

error_out:
    error = -1;

out:
	return error;
}

