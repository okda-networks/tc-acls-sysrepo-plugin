#include "ace_change.h"
#include "plugin/common.h"

#include "plugin/context.h"

#include <sysrepo.h>
#include <linux/limits.h>


#include "plugin/data/acls/acl/linked_list.h"
#include "plugin/data/acls/acl/aces.h"
#include "plugin/data/acls/acl.h"


#include "plugin/api/tcnl.h"

// this code is no longer used, proper code are defined in /data/acls/*
/*
int process_change_ace_top_level_leafs
(srpc_change_ctx_t * change_ctx,onm_tc_acl_hash_element_t * change_acl_hash, onm_tc_ace_element_t * change_ace_element, char * acl_name)
{
	int error = 0;
	const char *node_name = LYD_NAME(change_ctx->node);
	const char *parent_node_name = LYD_NAME(&change_ctx->node->parent->node);
	const char *node_value = lyd_get_value(change_ctx->node);
	// when the change happens on an individual ace, the acl name will not be present in the change ctx, hence we are setting it here
	if (strcmp(parent_node_name,"ace") == 0 && strcmp(node_name,"name") ==0)
	{
		if (!change_acl_hash->acl.name)
		{
			SRPLG_LOG_INF(PLUGIN_NAME, "Processing ACE change, ACL Name: %s, Change operation: %d.",acl_name,change_ctx->operation);
			SRPC_SAFE_CALL_ERR(error, onm_tc_acl_hash_element_set_name(&change_acl_hash, acl_name), error_out);
			printf("added ACL name to ACL hash, name: %s\n",change_acl_hash->acl.name);
			//init aces list inside temp change acl hash element
			ONM_TC_ACL_LIST_NEW(change_acl_hash->acl.aces.ace);
		}

		// change_ace_element was filled by process_change_ace_leafs and we started a new ace processing
		// we add the previous ace element to the acl_hash and start the new ace processing
		if (change_ace_element != NULL)
		{
			ONM_TC_ACL_LIST_ADD_ELEMENT(change_acl_hash->acl.aces.ace, change_ace_element);
		}
		
		
		change_ace_element = onm_tc_ace_hash_element_new();
		
		SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_ace_name(&change_ace_element, node_value), error_out);
		
		onm_tc_ace_hash_element_set_operation(&change_ace_element, change_ctx->operation);
		printf("added ACE name to ACE element, name: %s, operation: %d\n",change_ace_element->ace.name,change_ace_element->change_operation);
	}

	goto out;

error_out:
	return error;
out:
	return error;
}

int process_change_ace_leafs(srpc_change_ctx_t * change_ctx,onm_tc_acl_hash_element_t * change_acl_hash, onm_tc_ace_element_t * change_ace_element, char * acl_name)
{
	int error = 0;
	const char *node_name = LYD_NAME(change_ctx->node);
	const char *parent_node_name = LYD_NAME(&change_ctx->node->parent->node);
	const char *node_value = lyd_get_value(change_ctx->node);

	if (strcmp(node_name,"logging") == 0)
	{
		SRPLG_LOG_INF(PLUGIN_NAME, "ADDING VALUES to ACE %s to ACL %s\n",change_ace_element->ace.name, change_acl_hash->acl.name);
		
	}
	

error_out:
	return error;
out:
	return error;
}




int ace_entries_update(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx)
{
	int error = 0;
	const char *node_name = LYD_NAME(change_ctx->node);
	const char *node_value = lyd_get_value(change_ctx->node);

	char change_path[PATH_MAX] = {0};

	int rc = 0;
	
	error = (lyd_path(change_ctx->node, LYD_PATH_STD, change_path, sizeof(change_path)) == NULL);
	if (error) {
		SRPLG_LOG_ERR(PLUGIN_NAME, "lyd_path() error");
		goto error_out;
	}
	//onm_tc_ctx_t *ctx = (onm_tc_ctx_t *) priv;
	switch (change_ctx->operation) {
		case SR_OP_CREATED:
		SRPLG_LOG_INF(PLUGIN_NAME, "Change PATH PRINT: %s\n\t Value: %s\n\t Operation: %d\n\tChange path %s", node_name, node_value, change_ctx->operation,change_path);
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


int change_ace_init(void *priv)
{
	int error = 0;
	return error;
}

/*
int change_ace(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx)
{
	int error = 0;
	const char *node_name = LYD_NAME(change_ctx->node);
	const char *node_value = lyd_get_value(change_ctx->node);

	char change_path[PATH_MAX] = {0};


	char change_xpath_buffer[PATH_MAX] = { 0 };
	int rc = 0;

	onm_tc_ctx_t* ctx = (onm_tc_ctx_t*)priv;

	error = (lyd_path(change_ctx->node, LYD_PATH_STD, change_path, sizeof(change_path)) == NULL);
	if (error) {
		SRPLG_LOG_ERR(PLUGIN_NAME, "lyd_path() error");
		goto error_out;
	}

	SRPLG_LOG_INF(PLUGIN_NAME, "ACE CHANGE Node: %s;\n\t Value: %s;\n\t Operation: %d,\n\tchange path %s", node_name, node_value, change_ctx->operation,change_path);
	//SRPLG_LOG_INF(PLUGIN_NAME, "ACE CHANGE, Node Name: %s; Value: %s; Operation: %d, change path: %s", node_name, node_value, change_ctx->operation,change_path);
	switch (change_ctx->operation) {
		case SR_OP_CREATED:
		{
			if (strcmp(node_name,"ace") == 0)
			{
				// ace name
				SRPC_SAFE_CALL_ERR_COND(rc, rc < 0, snprintf(change_xpath_buffer, sizeof(change_xpath_buffer), "%s/name", change_path), error_out);
    			SRPC_SAFE_CALL_ERR(rc, srpc_iterate_changes(ctx, session, change_xpath_buffer, ace_change_name, change_ace_init, change_ace_free), error_out);

				// ace match
				SRPC_SAFE_CALL_ERR_COND(rc, rc < 0, snprintf(change_xpath_buffer, sizeof(change_xpath_buffer), "%s/matches/eth/*", change_path), error_out);
				SRPC_SAFE_CALL_ERR(rc, srpc_iterate_changes(ctx, session, change_xpath_buffer, ace_change_match_eth, change_ace_init, change_ace_free), error_out);
				
				// add new ace element to change acl element
				if(change_ace_element)
				{
					SRPLG_LOG_INF(PLUGIN_NAME, "ADDING ACE %s to ACL %s",change_ace_element->ace.name,change_acl_hash->acl.name);
					ONM_TC_ACL_LIST_ADD_ELEMENT(change_acl_hash->acl.aces.ace, change_ace_element);
				}
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

	return error;
error_out:
	return error;
}


void change_ace_free(void *priv)
{
}
*/
