#include "plugin/api/acls/acl/ace_change.h"
#include "plugin/api/tcnl.h"
#include "plugin/common.h"

int apply_events_ace_changes(onm_tc_ctx_t * ctx, unsigned int acl_id, onm_tc_ace_element_t* ace){
	int ret = 0;
	switch (ace->ace.name_change_op) {
		case SR_OP_CREATED:
			// handle complete ACE creation
			break;
		case SR_OP_DELETED:
			// handle complete ACE deletion
			break;
		case DEFAULT_CHANGE_OPERATION:
			// handle individual ace elements SR_OP_MODIFIED, SR_OP_CREATED, SR_OP_DELETED
			ret = tcnl_filter_modify_ace(acl_id,ace);
			if (ret){
				return -1; 
			}
			break;
	}
	return 0;
}