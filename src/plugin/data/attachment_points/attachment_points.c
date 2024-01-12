/*
 * okda-networks / onm-tc-acls
 *
 * This program is made available under the terms of the
 * BSD 3-Clause license which is available at
 * https://opensource.org/licenses/BSD-3-Clause
 *
 * SPDX-FileCopyrightText: 2023 Okda Networks
 * SPDX-FileContributor: Sartura Ltd, Deutsche Telekom AG.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "libyang/log.h"
#include "libyang/tree_data.h"
#include "plugin/common.h"
#include "plugin/ly_tree.h"
#include "plugin/types.h"
#include "srpc/ly_tree.h"
#include "sysrepo.h"
#include "uthash.h"
#include "utils/memory.h"
#include "utlist.h"
#include "memory.h"
// other data API
#include "linked_list.h"

#include <assert.h>
#include <srpc.h>
#include <stdio.h>
#include <stdlib.h>


#include <linux/limits.h>
#include "plugin/data/attachment_points/attachment_points.h"

/*
    Libyang conversion functions.
*/

onm_tc_aps_interface_hash_element_t* onm_tc_aps_interface_hash_new(void)
{
    return NULL;
}


onm_tc_aps_interface_hash_element_t* onm_tc_aps_interface_hash_element_new(void)
{
    onm_tc_aps_interface_hash_element_t* new_element = NULL;

    new_element = xmalloc(sizeof(onm_tc_aps_interface_hash_element_t));
    if (!new_element)
        return NULL;

    // NULL all fields
    new_element->interface = (onm_tc_aps_interface_t) { 0 };

    return new_element;
}

void onm_tc_aps_interface_hash_element_free(onm_tc_aps_interface_hash_element_t** el)
{
    if (*el) {
        
        //TODO free all elements 

        free(*el);
        *el = NULL;
    }
}

void onm_tc_aps_interface_hash_free(onm_tc_aps_interface_hash_element_t** hash)
{
    onm_tc_aps_interface_hash_element_t *tmp = NULL, *element = NULL;

    HASH_ITER(hh, *hash, element, tmp)
    {
        HASH_DEL(*hash, element);
        onm_tc_aps_interface_hash_element_free(&element);
    }

    *hash = NULL;
}

int onm_tc_aps_interface_hash_add_element(onm_tc_aps_interface_hash_element_t** hash, onm_tc_aps_interface_hash_element_t* new_element)
{
    onm_tc_aps_interface_hash_element_t* found_element = NULL;

    HASH_FIND_STR(*hash, new_element->interface.interface_id, found_element);

    // element already exists
    if (found_element != NULL) {
        return -1;
    }

    // element not found - add new element to the hash
    HASH_ADD_KEYPTR(hh, *hash, new_element->interface.interface_id, strlen(new_element->interface.interface_id), new_element);

    return 0;
}

onm_tc_aps_interface_hash_element_t* onm_tc_aps_interface_hash_get_element(onm_tc_aps_interface_hash_element_t** hash, const char* name)
{
    onm_tc_aps_interface_hash_element_t* found_element = NULL;

    HASH_FIND_STR(*hash, name, found_element);

    return found_element;
}

int onm_tc_aps_interface_hash_element_set_interface_id (onm_tc_aps_interface_hash_element_t** el, const char* interface_id)
{
    if ((*el)->interface.interface_id) {
        FREE_SAFE((*el)->interface.interface_id);
    }
    if (interface_id) {
        (*el)->interface.interface_id = xstrdup(interface_id);
        return (*el)->interface.interface_id == NULL;
    }

    return 0;
}

int onm_tc_aps_interface_hash_element_set_acl_name(onm_tc_aps_acl_set_element_t** el, const char* acl_name, sr_change_oper_t name_change_op)
{
    if ((*el)->acl_set.name) {
        FREE_SAFE((*el)->acl_set.name);
    }
    if (acl_name) {
        (*el)->acl_set.name = xstrdup(acl_name);
        (*el)->acl_set.name_change_op = name_change_op;
        return (*el)->acl_set.name == NULL;
    }

    return 0;
}

onm_tc_aps_acl_set_element_t* onm_tc_aps_acl_set_hash_element_new(void)
{
    onm_tc_aps_acl_set_element_t* new_aps_acl_set_element = NULL;

    new_aps_acl_set_element = xmalloc(sizeof(onm_tc_aps_acl_set_element_t));
    if (!new_aps_acl_set_element)
        return NULL;

    // NULL all fields
    new_aps_acl_set_element->acl_set = (onm_tc_aps_acl_set_t) { 0 };

    return new_aps_acl_set_element;
}


int events_aps_hash_update_from_change_ctx(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx)
{
    int error = 0;
    const struct lyd_node * node = change_ctx->node;
    const char *node_name = LYD_NAME(node);
	const char *node_value = lyd_get_value(node);
    onm_tc_ctx_t *ctx = (onm_tc_ctx_t *) priv;
    char change_path[PATH_MAX] = {0};
    char interface_id[100] = {0};
    char ace_name_buffer[100] = {0};

    struct lyd_node * grand_parent_node = &(node->parent->node.parent->node.parent->node);
    const char *grand_parent_node_name = LYD_NAME(grand_parent_node);
    
    onm_tc_aps_acl_set_element_t* new_egress_acl_set_element = NULL;
    if (node_value){
        error = (lyd_path(change_ctx->node, LYD_PATH_STD, change_path, sizeof(change_path)) != NULL);
        SRPC_SAFE_CALL_ERR(error, srpc_extract_xpath_key_value(change_path, "interface", "interface-id", interface_id, sizeof(interface_id)), error_out);

        onm_tc_aps_interface_hash_element_t* updated_interface_element = onm_tc_aps_interface_hash_get_element(&ctx->events_attachment_points_list,interface_id);
        
        // ensure interface element exists
        if (!updated_interface_element){
            // create new element
            updated_interface_element = onm_tc_aps_interface_hash_element_new();
            SRPC_SAFE_CALL_ERR(error, onm_tc_aps_interface_hash_element_set_interface_id(&updated_interface_element, interface_id), error_out);
            ONM_TC_APS_ACL_SET_NEW(updated_interface_element->interface.ingress.acl_sets.acl_set);
            ONM_TC_APS_ACL_SET_NEW(updated_interface_element->interface.egress.acl_sets.acl_set);
            onm_tc_aps_interface_hash_add_element(&ctx->events_attachment_points_list, updated_interface_element);
        }
        // check if change is on ingress interface set
        if (strcmp(grand_parent_node_name,"ingress")== 0){
            
            onm_tc_aps_acl_set_element_t* ingress_acl_set_element = onm_tc_aps_acl_set_hash_element_new();

            SRPC_SAFE_CALL_ERR(error, onm_tc_aps_interface_hash_element_set_acl_name(&ingress_acl_set_element, node_value,change_ctx->operation), error_out);
            // add ingress acl_set list to main interfaces list
            ONM_TC_APS_ACL_SET_ADD_ELEMENT(updated_interface_element->interface.ingress.acl_sets.acl_set, ingress_acl_set_element);
        }
        if (strcmp(grand_parent_node_name,"egress")== 0){
            onm_tc_aps_acl_set_element_t*  egress_acl_set_element = onm_tc_aps_acl_set_hash_element_new();
            SRPC_SAFE_CALL_ERR(error, onm_tc_aps_interface_hash_element_set_acl_name(&egress_acl_set_element, node_value,change_ctx->operation), error_out);
            ONM_TC_APS_ACL_SET_ADD_ELEMENT(updated_interface_element->interface.egress.acl_sets.acl_set, egress_acl_set_element);
        }

        
        goto out;
    }

error_out:
	return error;

out:
	return error;
}


int onm_tc_aps_interface_hash_from_ly(onm_tc_aps_interface_hash_element_t** interface_hash, const struct lyd_node* interfaces_list_node)
{
    int error = 0;

    // make sure the hash is empty at the start
    assert(*interface_hash == NULL);

    // libyang
    struct lyd_node *interfaces_iter = (struct lyd_node*)interfaces_list_node;
    struct lyd_node *aps_interface_id_node = NULL;
    struct lyd_node *aps_ingress_interface_container_node = NULL, *aps_egress_interface_container_node = NULL;
    struct lyd_node *aps_acl_sets_ingress_container_node = NULL, *aps_acl_sets_egress_container_node = NULL;
    struct lyd_node *aps_ingress_acl_set_list_node = NULL, *aps_egress_acl_set_list_node;
    struct lyd_node *aps_acl_name;

    // internal DS
    onm_tc_aps_interface_hash_element_t* new_element = NULL;
    onm_tc_aps_acl_set_element_t* new_ingress_acl_set_element = NULL;
    onm_tc_aps_acl_set_element_t* new_egress_acl_set_element = NULL;

    while (interfaces_iter) {
        // create new element
        new_element = onm_tc_aps_interface_hash_element_new();

        // get existing nodes
        SRPC_SAFE_CALL_PTR(aps_interface_id_node, srpc_ly_tree_get_child_leaf(interfaces_iter, "interface-id"), error_out);
        aps_ingress_interface_container_node = srpc_ly_tree_get_child_container(interfaces_iter, "ingress");
        aps_egress_interface_container_node = srpc_ly_tree_get_child_container(interfaces_iter, "egress");

        //set data
        if (aps_interface_id_node){
            SRPC_SAFE_CALL_ERR(error, onm_tc_aps_interface_hash_element_set_interface_id(&new_element, lyd_get_value(aps_interface_id_node)), error_out);
            aps_interface_id_node = NULL;
        }

        // ingress container node
        if (aps_ingress_interface_container_node){
            aps_acl_sets_ingress_container_node = srpc_ly_tree_get_child_container(aps_ingress_interface_container_node, "acl-sets");
            aps_ingress_interface_container_node = NULL;

            if (aps_acl_sets_ingress_container_node){
                aps_ingress_acl_set_list_node = srpc_ly_tree_get_child_list(aps_acl_sets_ingress_container_node, "acl-set");
                ONM_TC_APS_ACL_SET_NEW(new_element->interface.ingress.acl_sets.acl_set);
                aps_acl_sets_ingress_container_node = NULL;

                while(aps_ingress_acl_set_list_node){
                    new_ingress_acl_set_element = onm_tc_aps_acl_set_hash_element_new();
                    SRPC_SAFE_CALL_PTR(aps_acl_name, srpc_ly_tree_get_child_leaf(aps_ingress_acl_set_list_node, "name"), error_out);
                    if (aps_acl_name){
                        SRPC_SAFE_CALL_ERR(error, onm_tc_aps_interface_hash_element_set_acl_name(&new_ingress_acl_set_element, lyd_get_value(aps_acl_name),DEFAULT_CHANGE_OPERATION), error_out);
                        aps_acl_name = NULL;
                    }
                    // add ingress acl_set list to main interfaces list
                    ONM_TC_APS_ACL_SET_ADD_ELEMENT(new_element->interface.ingress.acl_sets.acl_set, new_ingress_acl_set_element);
                    new_ingress_acl_set_element = NULL;

                    aps_ingress_acl_set_list_node = srpc_ly_tree_get_list_next(aps_ingress_acl_set_list_node);
                }
            }
        }

        // egress container node
        if (aps_egress_interface_container_node){
            aps_acl_sets_egress_container_node = srpc_ly_tree_get_child_container(aps_egress_interface_container_node, "acl-sets");

            if (aps_acl_sets_egress_container_node){
                aps_egress_acl_set_list_node = srpc_ly_tree_get_child_list(aps_acl_sets_egress_container_node, "acl-set");
                ONM_TC_APS_ACL_SET_NEW(new_element->interface.egress.acl_sets.acl_set);

                while(aps_egress_acl_set_list_node){
                    new_egress_acl_set_element = onm_tc_aps_acl_set_hash_element_new();
                    SRPC_SAFE_CALL_PTR(aps_acl_name, srpc_ly_tree_get_child_leaf(aps_egress_acl_set_list_node, "name"), error_out);                 
                    if (aps_acl_name){
                        SRPC_SAFE_CALL_ERR(error, onm_tc_aps_interface_hash_element_set_acl_name(&new_egress_acl_set_element, lyd_get_value(aps_acl_name), DEFAULT_CHANGE_OPERATION), error_out);
                        aps_acl_name = NULL;
                    }

                    ONM_TC_APS_ACL_SET_ADD_ELEMENT(new_element->interface.egress.acl_sets.acl_set, new_egress_acl_set_element);
                    new_egress_acl_set_element = NULL;

                    aps_egress_acl_set_list_node = srpc_ly_tree_get_list_next(aps_egress_acl_set_list_node);
                }
            }
        }

        // add element to the hash
        onm_tc_aps_interface_hash_add_element(interface_hash, new_element);
        // set to NULL
        new_element = NULL;
        // move to next acl entry
        interfaces_iter = srpc_ly_tree_get_list_next(interfaces_iter);
    }

    goto out;
error_out:
    error = -1;

out:
    if (new_element) {
        onm_tc_aps_interface_hash_element_free(&new_element);
    }

    return error;
}

void onm_tc_aps_interface_hash_print_debug(const onm_tc_aps_interface_hash_element_t* aps_interface_hash)
{
    const onm_tc_aps_interface_hash_element_t *iter = NULL, *tmp = NULL;
    onm_tc_aps_acl_set_element_t* acl_set_iter = NULL;
    SRPLG_LOG_INF(PLUGIN_NAME, "+ attachment-points: ");
    HASH_ITER(hh, aps_interface_hash, iter, tmp)
    {
        SRPLG_LOG_INF(PLUGIN_NAME, "| \t+ interface %s: ", iter->interface.interface_id);
        SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\tinterface-id = %s", iter->interface.interface_id);

        if (iter->interface.ingress.acl_sets.acl_set){
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t+ingress:");
            LL_FOREACH(iter->interface.ingress.acl_sets.acl_set, acl_set_iter){
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|---- ACL Name: %s (change operation %d)", acl_set_iter->acl_set.name, acl_set_iter->acl_set.name_change_op);
            }
        }
        if (iter->interface.egress.acl_sets.acl_set){
            SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t+egress:");
            LL_FOREACH(iter->interface.egress.acl_sets.acl_set, acl_set_iter){
                SRPLG_LOG_INF(PLUGIN_NAME, "| \t|\t|---- ACL Name: %s (change operation %d)", acl_set_iter->acl_set.name,acl_set_iter->acl_set.name_change_op);
            }
        }

    }
}

