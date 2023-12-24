#include "acl_change.h"
#include "plugin/common.h"

#include <sysrepo.h>
#include "plugin/data/acls/acl.h"
#include "plugin/api/acls/acl/ace_change.h"
#include <stdio.h>
#include <linux/limits.h>
#include "plugin/context.h"

#include "plugin/data/acls/acl.h"
#include "plugin/data/acls/acl/aces.h"

#include "plugin/data/acls/acl/linked_list.h"
#include "sysrepo/xpath.h"

// this code is no longer used, proper code are defined in /data/acls/*
/*
int process_change_acl_top_level_leafs(srpc_change_ctx_t * change_ctx,onm_tc_acl_hash_element_t * change_acl_hash)
{
	const char *node_name = LYD_NAME(change_ctx->node);
	const char *parent_node_name = LYD_NAME(&change_ctx->node->parent->node);
	const char *node_value = lyd_get_value(change_ctx->node);

	//printf("ADD ACL DATA:\n\tNode Name: %s\n\tNode Value: %s\n\tParent Node Name: %s\n\tOperation: %d\n",node_name,node_value,parent_node_name,change_ctx->operation);
	
	int error = 0;
	if (strcmp(node_name,"name")==0)
	{
		SRPLG_LOG_INF(PLUGIN_NAME, "Processing new ACL change, ACL Name: %s, Change operation: %d.",node_value,change_ctx->operation);
		SRPC_SAFE_CALL_ERR(error, onm_tc_acl_hash_element_set_name(&change_acl_hash, node_value), error_out);
		onm_tc_acl_hash_element_set_operation(&change_acl_hash,change_ctx->operation);
	}
	if (strcmp(node_name,"type")==0)
	{
		error = onm_tc_acl_hash_element_set_type(&change_acl_hash, node_value);
	}
	//init aces list inside temp change acl hash element
	ONM_TC_ACL_LIST_NEW(change_acl_hash->acl.aces.ace);

	goto out;

error_out:
	return error;

out:
	return error;
}

int change_acls_list_order()
{

}

int update_change_acls_list_element(void* priv, srpc_change_ctx_t * change_ctx)
{
	onm_tc_ctx_t *ctx = (onm_tc_ctx_t *) priv;
}

int set_acl_element_hash_from_ctx_change_node
(srpc_change_ctx_t * change_ctx, onm_tc_acl_hash_element_t** change_acl_hash, onm_tc_ace_element_t ** change_ace_element, char * acl_name)
{
	int error = 0;
	const char *node_name = LYD_NAME(change_ctx->node);
	const char *parent_node_name = LYD_NAME(&change_ctx->node->parent->node);
	const char *node_value = lyd_get_value(change_ctx->node);
	char change_path[PATH_MAX] = {0};
	error = (lyd_path(change_ctx->node, LYD_PATH_STD, change_path, sizeof(change_path)) != NULL);
	
	if (node_value)
	{
		
		// set acl name and type
		if (strcmp(parent_node_name,"acl") == 0)
		{
			// TODO change to safe sysrepo call
			error = process_change_acl_top_level_leafs (change_ctx,(*change_acl_hash));
		}
		else{
			//printf("ADD ACE DATA:\n\tNode Name: %s\n\tNode Value: %s\n\tParent Node Name: %s\n\tOperation %d\n",node_name,node_value,parent_node_name,change_ctx->operation);
			// parse aces
			if (strcmp(parent_node_name,"ace") == 0 && strcmp(node_name,"name") ==0)
			{
				
				// when changing on aces directly, acl name will not be present in change event, adding it here.
				if (!(*change_acl_hash)->acl.name)
				{
					SRPC_SAFE_CALL_ERR(error, onm_tc_acl_hash_element_set_name(change_acl_hash, acl_name), error_out);				
					ONM_TC_ACL_LIST_NEW((*change_acl_hash)->acl.aces.ace);
				}

				// We add aces to acl hast at the begging of a new ace
				// so here we add the previous ace element if it exists to the acl_hash and start the new ace processing 
				// last ace element of last acl should be added at the end of acl_change_iterator()
				if ((*change_ace_element))
				{
					ONM_TC_ACL_LIST_ADD_ELEMENT((*change_acl_hash)->acl.aces.ace, (*change_ace_element));
					printf("ADDED ACE ELEMENT %s TO ACL HASH %s\n",(*change_ace_element)->ace.name,(*change_acl_hash)->acl.name);
				}
				
				// parsing ace name means a new ace to be parsed.
				printf("set_acl_element_hash_from_ctx_change_node ACE NEW\n");
				(*change_ace_element) = onm_tc_ace_hash_element_new();

				
			}
			

			// case where change happens directly on individual leaf
			if(!(*change_ace_element))
			{
				
				if (!(*change_acl_hash)->acl.name)
				{
					SRPC_SAFE_CALL_ERR(error, onm_tc_acl_hash_element_set_name(change_acl_hash, acl_name), error_out);				
					ONM_TC_ACL_LIST_NEW((*change_acl_hash)->acl.aces.ace);
				}
				printf("set_acl_element_hash_from_ctx_change_node 2 ACE NEW\n");
				(*change_ace_element) = onm_tc_ace_hash_element_new();
				// get ace name
				char ace_name_buffer[100] = { 0 };
				SRPC_SAFE_CALL_ERR(error, srpc_extract_xpath_key_value(change_path, "ace", "name", ace_name_buffer, sizeof(ace_name_buffer)), error_out);
				
				printf("ace name %s\n",ace_name_buffer);
				// set ace name only, don't set ace operation because the operation is happening only on child leaf
				SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_ace_name(change_ace_element, ace_name_buffer), error_out);
				//onm_tc_ace_hash_element_set_operation(change_ace_element, change_ctx->operation);
				printf("ADD ACE DATA:\n\tNode Name: %s\n\tNode Value: %s\n\tParent Node Name: %s\n\tOperation %d,\n\tACL Name: %s\n\tACE Name: %s\n",
				node_name,node_value,parent_node_name,change_ctx->operation, acl_name,(*change_ace_element)->ace.name);
			}
			
			// parse the rest of ace leafs
			if (strcmp(node_name,"source-mac-address") == 0)
			{
				SRPC_SAFE_CALL_ERR(error, onm_tc_ace_hash_element_set_match_src_mac_addr(change_ace_element, node_value), error_out);
			}
			if (strcmp(node_name,"logging") == 0)
			{
				SRPLG_LOG_INF(PLUGIN_NAME, "DONE WITH ACE %s\n",(*change_ace_element)->ace.name);
			}
		}
	
	}
	
	//set aces data
	goto out;

error_out:
	SRPLG_LOG_ERR(PLUGIN_NAME, "Failed to set change data, ACL Name: %s, Change Node Name: %s, Change Node Value: %s, Change Operation: %d.",acl_name,node_name, node_value,change_ctx->operation);
	return error;

out:
	return error;	
}



int acl_change_iterator(void *priv, sr_session_ctx_t *session, const char *xpath)
{
	int error = 0;
	char * current_iter_acl_name = NULL;
	char previous_iter_acl_name [100] = {0};

	// sysrepo
	sr_change_iter_t *changes_iterator = NULL;
	srpc_change_ctx_t change_ctx;

	// internal
	onm_tc_ctx_t *ctx = (onm_tc_ctx_t *) priv;

	onm_tc_acl_hash_element_t* change_acl_hash = NULL;
    onm_tc_ace_element_t * change_ace_element = NULL;

	SRPC_SAFE_CALL_ERR(error,sr_get_changes_iter(session, xpath, &changes_iterator), error_out);
	ctx->events_acls_list = NULL;

	char acl_name_buffer[100] = { 0 };
	char change_path[PATH_MAX] = {0};

	change_acl_hash = onm_tc_acl_hash_element_new();
	while (sr_get_change_tree_next(session, changes_iterator, &change_ctx.operation, &change_ctx.node,
								&change_ctx.previous_value, &change_ctx.previous_list,
								&change_ctx.previous_default) == SR_ERR_OK)
	{
		switch (change_ctx.operation)
			{
				case SR_OP_CREATED:
				case SR_OP_DELETED:
					printf("operation CREATED || DELETED\n");
					
					// set iteration acl name buffer
					error = (lyd_path(change_ctx.node, LYD_PATH_STD, change_path, sizeof(change_path)) != NULL);
					SRPC_SAFE_CALL_ERR(error, srpc_extract_xpath_key_value(change_path, "acl", "name", acl_name_buffer, sizeof(acl_name_buffer)), error_out);
					//printf("change path %s\n",change_path);
					
					// first itereation only
					if (strcmp(previous_iter_acl_name, "") == 0)
					{
						strcpy(previous_iter_acl_name, acl_name_buffer);
						current_iter_acl_name = acl_name_buffer;
					}

					// if iterating within the same acl, set the change data to temp acl element hash
					if (strcmp(previous_iter_acl_name,current_iter_acl_name) == 0)
					{
						SRPC_SAFE_CALL_ERR_COND(error, error < 0, set_acl_element_hash_from_ctx_change_node(&change_ctx,&change_acl_hash,&change_ace_element,current_iter_acl_name), error_out);
						//error = set_acl_element_hash_from_ctx_change_node(&change_ctx,&change_acl_hash,&change_ace_element,current_iter_acl_name);
						current_iter_acl_name = acl_name_buffer;
					}
					// first iteration of a new acl
					else
					{
						//printf("ADD LAST ACE ELEMENT %s TO ACL HASH %s\n",change_ace_element->ace.name,change_acl_hash->acl.name);
						// add last ace of previous acl to acl_hash
						printf("ADD ACE element info: name: %s\n",change_ace_element->ace.name);
						ONM_TC_ACL_LIST_ADD_ELEMENT(change_acl_hash->acl.aces.ace, change_ace_element);
						printf("acl_change_iterator ACE NEW\n");
						change_ace_element = onm_tc_ace_hash_element_new();

						// add previous acl_hash to acls_list
						onm_tc_acls_hash_add_acl_element(&ctx->events_acls_list, change_acl_hash);
						change_acl_hash = onm_tc_acl_hash_element_new();

						strcpy(previous_iter_acl_name, current_iter_acl_name);
					}
					break;
				case SR_OP_MODIFIED:
					printf("operation MODIFIED\n");
					break;
				case SR_OP_MOVED:
					printf("operation MOVED\n");
					break;
			
			}
	}

	if (change_ctx.operation == SR_OP_CREATED || change_ctx.operation == SR_OP_DELETED )
	{
		// add last ace element to last acl hash
		if(change_ace_element)
			ONM_TC_ACL_LIST_ADD_ELEMENT(change_acl_hash->acl.aces.ace, change_ace_element);
		//else
		//	goto error_out;
		// add last acl hash to acls list
		error = onm_tc_acls_hash_add_acl_element(&ctx->events_acls_list, change_acl_hash);
	}
	
	//TODO make sure to free change_ace_element, change_acl_hash and change_acls_list after compleing netlink operations.
	goto out;

error_out:
	SRPLG_LOG_ERR(PLUGIN_NAME, "Failed to add ace element to acl hash");
	error = -1;

out:
	return error;
}


int acl_change_iterator2(void *priv, sr_session_ctx_t *session, const char *xpath)
{
	int error = 0;
	//char * current_iter_acl_name = NULL;
	//char previous_iter_acl_name [100] = {0};
	
	
	// sysrepo
	sr_change_iter_t *changes_iterator = NULL;
	srpc_change_ctx_t change_ctx;

	// internal
	onm_tc_ctx_t *ctx = (onm_tc_ctx_t *) priv;

	//onm_tc_acl_hash_element_t* change_acl_hash = NULL;
    //onm_tc_ace_element_t * change_ace_element = NULL;

	SRPC_SAFE_CALL_ERR(error,sr_get_changes_iter(session, xpath, &changes_iterator), error_out);
	//ctx->change_acls_list = NULL;
	printf("\n\nXPATH: %s\n", xpath);
	char acl_name_buffer[100] = { 0 };
	char change_path[PATH_MAX] = {0};

	struct lyd_node *acl_iter = (struct lyd_node*)change_ctx.node;

	//change_acl_hash = onm_tc_acl_hash_element_new();
	while (sr_get_change_tree_next(session, changes_iterator, &change_ctx.operation, &change_ctx.node,
								&change_ctx.previous_value, &change_ctx.previous_list,
								&change_ctx.previous_default) == SR_ERR_OK)
	{
		// set iteration acl name buffer
		error = (lyd_path(change_ctx.node, LYD_PATH_STD, change_path, sizeof(change_path)) != NULL);
		//SRPC_SAFE_CALL_ERR(error, srpc_extract_xpath_key_value(change_path, "acl", "name", acl_name_buffer, sizeof(acl_name_buffer)), error_out);
		printf("change path %s\n",change_path);
	}
	goto out;

error_out:
	return -1;

out:
	return 0;

}

int change_acl_init(void *priv)
{
	int error = 0;
	return error;
}

void change_acl_free(void *priv)
{
	
}

*/