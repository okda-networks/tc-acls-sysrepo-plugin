#include "load.h"
#include "plugin/common.h"

#include <libyang/libyang.h>
#include <sysrepo.h>
#include <srpc.h>
#include "plugin/ly_tree.h"

static int onm_tc_startup_load_attachment_points(void *priv, sr_session_ctx_t *session, const struct ly_ctx *ly_ctx, struct lyd_node *parent_node);
static int onm_tc_startup_load_acl(void *priv, sr_session_ctx_t *session, const struct ly_ctx *ly_ctx, struct lyd_node *parent_node);

int onm_tc_startup_load(onm_tc_ctx_t *ctx, sr_session_ctx_t *session)
{
    int error = 0;

    const struct ly_ctx *ly_ctx = NULL;
    struct lyd_node *root_node = NULL;
    sr_conn_ctx_t *conn_ctx = NULL;

    srpc_startup_load_t load_values[] = {
        {
            "/ietf-access-control-list:acls/attachment-points",
            onm_tc_startup_load_attachment_points,
        },
        {
            "/ietf-access-control-list:acls/acl",
            onm_tc_startup_load_acl,
        },
    };
    SRPC_SAFE_CALL_PTR(conn_ctx, sr_session_get_connection(session), error_out);
    SRPC_SAFE_CALL_PTR(ly_ctx, sr_acquire_context(conn_ctx), error_out);

    SRPC_SAFE_CALL_ERR(error, onm_tc_ly_tree_create_acls(ly_ctx, &root_node), error_out);

    if (ly_ctx == NULL) {
        SRPLG_LOG_ERR(PLUGIN_NAME, "Unable to get ly_ctx variable");
        goto error_out;
    }

    // load system container info
    // [LOAD ROOT NODE HERE]
    for (size_t i = 0; i < ARRAY_SIZE(load_values); i++) {
        const srpc_startup_load_t *load = &load_values[i];

        error = load->cb((void *) ctx, session, ly_ctx, root_node);
        if (error) {
            SRPLG_LOG_ERR(PLUGIN_NAME, "Node creation callback failed for value %s", load->name);
            goto error_out;
        }
    }

    error = sr_edit_batch(session, root_node, "merge");
    if (error != SR_ERR_OK) {
        SRPLG_LOG_ERR(PLUGIN_NAME, "sr_edit_batch() error (%d): %s", error, sr_strerror(error));
        goto error_out;
    }

    error = sr_apply_changes(session, 0);
    if (error != 0) {
        SRPLG_LOG_ERR(PLUGIN_NAME, "sr_apply_changes() error (%d): %s", error, sr_strerror(error));
        goto error_out;
    }

    goto out;

error_out:
    error = -1;

out:
    if (root_node) {
        lyd_free_tree(root_node);
    }
    sr_release_context(conn_ctx);
    return error;
}

static int onm_tc_startup_load_attachment_points(void *priv, sr_session_ctx_t *session, const struct ly_ctx *ly_ctx, struct lyd_node *parent_node)
{
    int error = 0;
    return error;
}

static int onm_tc_startup_load_acl(void *priv, sr_session_ctx_t *session, const struct ly_ctx *ly_ctx, struct lyd_node *parent_node)
{
    int error = 0;
    onm_tc_ctx_t* ctx = (onm_tc_ctx_t*)priv;
    onm_tc_acl_hash_element_t* acl_hash = NULL;

    // load acl data
    //SRPC_SAFE_CALL_ERR(error, onm_tc_load_acl(ctx, &acl_hash), error_out);

    // convert to libyang
    //SRPC_SAFE_CALL_ERR(error, interfaces_interface_hash_to_ly(ly_ctx, interface_hash, &parent_node), error_out);

    // print created tree
    // lyd_print_file(stdout, parent_node, LYD_XML, 0);

    goto out;

error_out:
    error = -1;
out:
    //interfaces_interface_hash_free(&acl_hash);

    return error;
}

