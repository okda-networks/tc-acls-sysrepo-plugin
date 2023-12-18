#include "change.h"
#include "plugin/common.h"

#include "plugin/context.h"
#include "plugin/api/acls/acl/aces/ace/change.h"

#include <sysrepo.h>
#include <linux/limits.h>


#include "plugin/data/acls/acl/linked_list.h"
#include "plugin/data/acls/acl/aces.h"
#include "plugin/data/acls/acl.h"

int acls_acl_aces_ace_change_name(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx)
{
	int error = 0;
	const char *node_name = LYD_NAME(change_ctx->node);
	const char *node_value = lyd_get_value(change_ctx->node);

	onm_tc_ctx_t *ctx = (onm_tc_ctx_t *) priv;

	switch (change_ctx->operation) {
		case SR_OP_CREATED:
		//if(node_value)
		{
			SRPLG_LOG_INF(PLUGIN_NAME, "ACE NODE CHANGE: %s; Value: %s; Operation: %d", node_name, node_value, change_ctx->operation);
			if (strcmp(node_name,"name")==0)
			{
				// initilize change ace element
				change_ace_element = onm_tc_ace_hash_element_new();
				SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_ace_name(&change_ace_element, node_value), error_out);
			}
		}
			break;
		case SR_OP_MODIFIED:
			break;
		case SR_OP_DELETED:
			break;
		case SR_OP_MOVED:
			break;
	}
	goto out;
error_out:
	error = -1;

out:
	return error;
}


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
	//if (strcmp(node_name,"ace") == 0)
	{
		onm_tc_ctx_t* ctx = (onm_tc_ctx_t*)priv;
		SRPC_SAFE_CALL_ERR_COND(rc, rc < 0, snprintf(change_xpath_buffer, sizeof(change_xpath_buffer), "%s/name", change_path), error_out);
    	SRPC_SAFE_CALL_ERR(rc, srpc_iterate_changes(ctx, session, change_xpath_buffer, acls_acl_aces_ace_change_name, acls_acl_aces_change_ace_init, acls_acl_aces_change_ace_free), error_out);

		// match eth
		//SRPC_SAFE_CALL_ERR_COND(rc, rc < 0, snprintf(change_xpath_buffer, sizeof(change_xpath_buffer), "%s/matches/eth/*", change_path), error_out);
        //SRPC_SAFE_CALL_ERR(rc, srpc_iterate_changes(ctx, session, change_xpath_buffer, acls_acl_aces_ace_change_name, acls_acl_aces_change_ace_init, acls_acl_aces_change_ace_free), error_out);

		// match ipv4
		//SRPC_SAFE_CALL_ERR_COND(rc, rc < 0, snprintf(change_xpath_buffer, sizeof(change_xpath_buffer), "%s/matches/ipv4/*", change_path), error_out);
        //SRPC_SAFE_CALL_ERR(rc, srpc_iterate_changes(ctx, session, change_xpath_buffer, acls_acl_aces_ace_change_name, acls_acl_aces_change_ace_init, acls_acl_aces_change_ace_free), error_out);

		// match ipv6
		//SRPC_SAFE_CALL_ERR_COND(rc, rc < 0, snprintf(change_xpath_buffer, sizeof(change_xpath_buffer), "%s/matches/ipv6/*", change_path), error_out);
        //SRPC_SAFE_CALL_ERR(rc, srpc_iterate_changes(ctx, session, change_xpath_buffer, acls_acl_aces_ace_change_name, acls_acl_aces_change_ace_init, acls_acl_aces_change_ace_free), error_out);

		
		// match tcp
		//SRPC_SAFE_CALL_ERR_COND(rc, rc < 0, snprintf(change_xpath_buffer, sizeof(change_xpath_buffer), "%s/matches/tcp/*", change_path), error_out);
        //SRPC_SAFE_CALL_ERR(rc, srpc_iterate_changes(ctx, session, change_xpath_buffer, acls_acl_aces_ace_change_name, acls_acl_aces_change_ace_init, acls_acl_aces_change_ace_free), error_out);

		//match udp
		//SRPC_SAFE_CALL_ERR_COND(rc, rc < 0, snprintf(change_xpath_buffer, sizeof(change_xpath_buffer), "%s/matches/udp/*", change_path), error_out);
        //SRPC_SAFE_CALL_ERR(rc, srpc_iterate_changes(ctx, session, change_xpath_buffer, acls_acl_aces_ace_change_name, acls_acl_aces_change_ace_init, acls_acl_aces_change_ace_free), error_out);

		//match icmp
		//SRPC_SAFE_CALL_ERR_COND(rc, rc < 0, snprintf(change_xpath_buffer, sizeof(change_xpath_buffer), "%s/matches/icmp/*", change_path), error_out);
        //SRPC_SAFE_CALL_ERR(rc, srpc_iterate_changes(ctx, session, change_xpath_buffer, acls_acl_aces_ace_change_name, acls_acl_aces_change_ace_init, acls_acl_aces_change_ace_free), error_out);

		//action forwarding
		//SRPC_SAFE_CALL_ERR_COND(rc, rc < 0, snprintf(change_xpath_buffer, sizeof(change_xpath_buffer), "%s/actions/forwarding", change_path), error_out);
        //SRPC_SAFE_CALL_ERR(rc, srpc_iterate_changes(ctx, session, change_xpath_buffer, acls_acl_aces_ace_change_name, acls_acl_aces_change_ace_init, acls_acl_aces_change_ace_free), error_out);
	
		// add new ace element to change acl element
		if(change_ace_element)
		{
			ONM_TC_ACL_LIST_ADD_ELEMENT(change_acl_hash->acl.aces.ace, change_ace_element);
		}
	}

	return error;
error_out:
	return error;
}

void acls_acl_aces_change_ace_free(void *priv)
{
}

