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
#include "plugin/api/acls/acl_change.h"

#include "plugin/api/tcnl.h"


int apply_events_acls_changes(onm_tc_ctx_t * ctx){
	onm_tc_acl_hash_element_t * events_acls = ctx->events_acls_list;
	if (events_acls == NULL){
		SRPLG_LOG_INF(PLUGIN_NAME, "No change operation of 'add', 'delete' or 'modify' to be applied");
		return 0;
	}
	int ret = 0;
    onm_tc_acl_hash_element_t *iter = NULL, *tmp = NULL;
    onm_tc_ace_element_t* ace_iter = NULL;
	char* acl_name = NULL;
    HASH_ITER(hh, events_acls, iter, tmp)
	{
		switch (iter->acl.name_change_op) {
			case SR_OP_CREATED:
				// handle complete acl creation.
				break;
			case SR_OP_DELETED:
				// handle complete acl deletion.
				break;
			case DEFAULT_CHANGE_OPERATION:
				// handle ACEs change operations.
				if (iter->acl.type_change_op != SR_OPER_DEFAULT){
					// handle acl type change event.
					// ignored for now as we currently don't look at acl type in tcnl
				}
				acl_name = iter->acl.name;
				unsigned int acl_id = iter->acl.acl_id;
				// iterate over aces
				LL_FOREACH(iter->acl.aces.ace, ace_iter)
				{
					SRPLG_LOG_INF(PLUGIN_NAME, "Apply ace event changes");
					ret = apply_events_ace_changes(ctx,acl_id,ace_iter);
					if (ret < 0){
						printf("return of apply_events_ace_changes %d\n",ret);
						return ret;
					}
				}
				break;
		}
		
	}
	return ret;
}


