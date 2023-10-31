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

int onm_tc_aps_interface_hash_element_set_acl_name(onm_tc_aps_acl_set_element_t** el, const char* acl_name)
{
    if ((*el)->acl_set.name) {
        FREE_SAFE((*el)->acl_set.name);
    }
    if (acl_name) {
        (*el)->acl_set.name = xstrdup(acl_name);
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
        //TODO set netlink TC configuration
        if (aps_interface_id_node){
            SRPC_SAFE_CALL_ERR(error, onm_tc_aps_interface_hash_element_set_interface_id(&new_element, lyd_get_value(aps_interface_id_node)), error_out);  
        }

        // ingress container node
        if (aps_ingress_interface_container_node){
            aps_acl_sets_ingress_container_node = srpc_ly_tree_get_child_container(aps_ingress_interface_container_node, "acl-sets");

            if (aps_acl_sets_ingress_container_node){
                aps_ingress_acl_set_list_node = srpc_ly_tree_get_child_list(aps_acl_sets_ingress_container_node, "acl-set");
                ONM_TC_APS_ACL_SET_NEW(new_element->interface.ingress.acl_sets.acl_set);

                while(aps_ingress_acl_set_list_node){
                    new_ingress_acl_set_element = onm_tc_aps_acl_set_hash_element_new();
                    SRPC_SAFE_CALL_PTR(aps_acl_name, srpc_ly_tree_get_child_leaf(aps_ingress_acl_set_list_node, "name"), error_out);
                    if (aps_acl_name){
                        SRPC_SAFE_CALL_ERR(error, onm_tc_aps_interface_hash_element_set_acl_name(&new_ingress_acl_set_element, lyd_get_value(aps_acl_name)), error_out);
                    }
                    // add ingress acl_set list to main interfaces list
                    ONM_TC_APS_ACL_SET_ADD_ELEMENT(new_element->interface.ingress.acl_sets.acl_set, aps_ingress_acl_set_list_node);
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
                        SRPC_SAFE_CALL_ERR(error, onm_tc_aps_interface_hash_element_set_acl_name(&new_egress_acl_set_element, lyd_get_value(aps_acl_name)), error_out);
                    }

                    ONM_TC_APS_ACL_SET_ADD_ELEMENT(new_element->interface.egress.acl_sets.acl_set, aps_egress_acl_set_list_node);
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
        //TODO fix this function not cause a memeory leak, not all data are freed now
        onm_tc_aps_interface_hash_element_free(&new_element);
    }

    return error;
}

void onm_tc_aps_interface_hash_print_debug(const onm_tc_aps_interface_hash_element_t* aps_interface_hash)
{
    const onm_tc_aps_interface_hash_element_t *iter = NULL, *tmp = NULL;
    

    HASH_ITER(hh, aps_interface_hash, iter, tmp)
    {
        SRPLG_LOG_INF(PLUGIN_NAME, "+ Interface-ID %s:", iter->interface.interface_id);
    }
}

