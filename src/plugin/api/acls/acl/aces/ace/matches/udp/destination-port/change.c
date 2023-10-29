#include "change.h"
#include "plugin/common.h"

#include <sysrepo.h>

int acls_acl_aces_ace_matches_udp_destination_port_change_port_init(void *priv)
{
	int error = 0;
	return error;
}

int acls_acl_aces_ace_matches_udp_destination_port_change_port(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx)
{
	int error = 0;
	const char *node_name = LYD_NAME(change_ctx->node);
	const char *node_value = lyd_get_value(change_ctx->node);

	SRPLG_LOG_DBG(PLUGIN_NAME, "Node Name: %s; Previous Value: %s, Value: %s; Operation: %d", node_name, change_ctx->previous_value, node_value, change_ctx->operation);

	switch (change_ctx->operation) {
		case SR_OP_CREATED:
			break;
		case SR_OP_MODIFIED:
			break;
		case SR_OP_DELETED:
			break;
		case SR_OP_MOVED:
			break;
	}

	return error;
}

void acls_acl_aces_ace_matches_udp_destination_port_change_port_free(void *priv)
{
}

int acls_acl_aces_ace_matches_udp_destination_port_change_operator_init(void *priv)
{
	int error = 0;
	return error;
}

int acls_acl_aces_ace_matches_udp_destination_port_change_operator(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx)
{
	int error = 0;
	const char *node_name = LYD_NAME(change_ctx->node);
	const char *node_value = lyd_get_value(change_ctx->node);

	SRPLG_LOG_DBG(PLUGIN_NAME, "Node Name: %s; Previous Value: %s, Value: %s; Operation: %d", node_name, change_ctx->previous_value, node_value, change_ctx->operation);

	switch (change_ctx->operation) {
		case SR_OP_CREATED:
			break;
		case SR_OP_MODIFIED:
			break;
		case SR_OP_DELETED:
			break;
		case SR_OP_MOVED:
			break;
	}

	return error;
}

void acls_acl_aces_ace_matches_udp_destination_port_change_operator_free(void *priv)
{
}

int acls_acl_aces_ace_matches_udp_destination_port_change_upper_port_init(void *priv)
{
	int error = 0;
	return error;
}

int acls_acl_aces_ace_matches_udp_destination_port_change_upper_port(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx)
{
	int error = 0;
	const char *node_name = LYD_NAME(change_ctx->node);
	const char *node_value = lyd_get_value(change_ctx->node);

	SRPLG_LOG_DBG(PLUGIN_NAME, "Node Name: %s; Previous Value: %s, Value: %s; Operation: %d", node_name, change_ctx->previous_value, node_value, change_ctx->operation);

	switch (change_ctx->operation) {
		case SR_OP_CREATED:
			break;
		case SR_OP_MODIFIED:
			break;
		case SR_OP_DELETED:
			break;
		case SR_OP_MOVED:
			break;
	}

	return error;
}

void acls_acl_aces_ace_matches_udp_destination_port_change_upper_port_free(void *priv)
{
}

int acls_acl_aces_ace_matches_udp_destination_port_change_lower_port_init(void *priv)
{
	int error = 0;
	return error;
}

int acls_acl_aces_ace_matches_udp_destination_port_change_lower_port(void *priv, sr_session_ctx_t *session, const srpc_change_ctx_t *change_ctx)
{
	int error = 0;
	const char *node_name = LYD_NAME(change_ctx->node);
	const char *node_value = lyd_get_value(change_ctx->node);

	SRPLG_LOG_DBG(PLUGIN_NAME, "Node Name: %s; Previous Value: %s, Value: %s; Operation: %d", node_name, change_ctx->previous_value, node_value, change_ctx->operation);

	switch (change_ctx->operation) {
		case SR_OP_CREATED:
			break;
		case SR_OP_MODIFIED:
			break;
		case SR_OP_DELETED:
			break;
		case SR_OP_MOVED:
			break;
	}

	return error;
}

void acls_acl_aces_ace_matches_udp_destination_port_change_lower_port_free(void *priv)
{
}

