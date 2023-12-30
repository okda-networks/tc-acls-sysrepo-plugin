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

int apply_events_acls_hash(onm_tc_ctx_t * ctx){
	onm_tc_acl_hash_element_t * events_acls = ctx->events_acls_list;
	int ret = 0;
    onm_tc_acl_hash_element_t *iter = NULL, *tmp = NULL;
    onm_tc_ace_element_t* ace_iter = NULL;
	char* acl_name = NULL;
	SRPLG_LOG_INF(PLUGIN_NAME, "Apply change event data");
    HASH_ITER(hh, events_acls, iter, tmp)
	{
		acl_name = iter->acl.name;
    	unsigned int acl_id = iter->acl.acl_id;
		SRPLG_LOG_INF(PLUGIN_NAME, "Apply change event data for acl %d",acl_id);
		// iterate over aces
			LL_FOREACH(iter->acl.aces.ace, ace_iter)
			{
				ret = tcnl_filter_modify_ace(acl_id,ace_iter);
				if (ret){
					return -1; 
				}
			}
		
	}
	
}


