#ifndef ONM_TC_PLUGIN_API_ACLS_ATTACHMENT_POINTS_CHANGE_H
#define ONM_TC_PLUGIN_API_ACLS_ATTACHMENT_POINTS_CHANGE_H

#include <utarray.h>
#include <srpc.h>
#include "plugin/types.h"
#include "plugin/data/attachment_points/attachment_points.h"
#include "plugin/context.h"
#include <netlink/route/qdisc.h>
#include <netlink/route/classifier.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/tc.h>
#include "plugin/data/acls/acl.h"

int acls_attachment_points_change_interface_init(void *priv);
int apply_attachment_points_events_list_changes(void *priv);
void acls_attachment_points_change_interface_free(void *priv);

#endif // ONM_TC_PLUGIN_API_ACLS_ATTACHMENT_POINTS_CHANGE_H