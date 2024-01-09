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
#ifndef ONM_TC_PLUGIN_DATA_ATTACHMENT_POINTS_ACL_SET_LIST_H
#define ONM_TC_PLUGIN_DATA_ATTACHMENT_POINTS_ACL_SET_LIST_H


#include "plugin/types.h"

#include <string.h>
#include <utlist.h>

/*
    Linked list operations
*/
/* used append instead of prepend since we process the last added attachment point acl-set */
#define ONM_TC_APS_ACL_SET_ADD_ELEMENT(ll_ptr, new_element_ptr) \
    do {                                                        \
        LL_APPEND(ll_ptr, new_element_ptr);                    \
    } while (0)
    
#define ONM_TC_APS_ACL_SET_NEW(ll_ptr) \
    do {                               \
        (ll_ptr) = NULL;               \
    } while (0)

#define ONM_TC_APS_ACL_SET_FREE(ll_ptr)         \
    _Generic((ll_ptr),                          \
             onm_tc_aps_acl_set_element_t *     \
             : onm_tc_aps_acl_set_free)(&ll_ptr)



#define ONM_TC_APS_ACL_SET_GET_ELEMENT_STRING(ll_ptr, element_ptr, member, value) \
    do {                                                                          \
        LL_FOREACH(ll_ptr, element_ptr)                                           \
        {                                                                         \
            if (strcmp(element_ptr->member, value) == 0) {                        \
                break;                                                            \
            }                                                                     \
        }                                                                         \
    } while (0)

#define ONM_TC_APS_ACL_SET_GET_ELEMENT_SCALAR(ll_ptr, element_ptr, member, value) \
    do {                                                                          \
        LL_SEARCH_SCALAR(ll_ptr, element_ptr, member, value);                     \
    } while (0)

#endif // ONM_TC_PLUGIN_DATA_ATTACHMENT_POINTS_ACL_SET_LIST_H
