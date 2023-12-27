#ifndef ONM_TC_PLUGIN_API_ACLS_CHANGE_H
#define ONM_TC_PLUGIN_API_ACLS_CHANGE_H

#include <utarray.h>
#include <srpc.h>
#include "plugin/context.h"

#define VALIDATE_AND_UPDATE_EVENT_MAC_ADDR_MASK(ACE_ITER, ADDR_FIELD, MASK_FIELD, LOG_MSG, SET_FUNC) \
    do { \
        if ((ACE_ITER)->ace.matches.eth.ADDR_FIELD) { \
            if (!(ACE_ITER)->ace.matches.eth.MASK_FIELD && running_ace->ace.matches.eth.MASK_FIELD) { \
                SRPLG_LOG_INF(PLUGIN_NAME, LOG_MSG, (ACE_ITER)->ace.name); \
                SET_FUNC(&(ACE_ITER), running_ace->ace.matches.eth.MASK_FIELD, (ACE_ITER)->ace.matches.eth.src_mac_change_op); \
            } \
        } \
    } while (0)

#define VALIDATE_AND_UPDATE_EVENT_PORT_OPERATOR(ACE_ITER, PROTO, PORT_FIELD, LOG_MSG, PORT_ATTR_DIR, PORT_ATTR_PROTO) \
    do { \
        if ((ACE_ITER)->ace.matches.PROTO.PORT_FIELD.port != 0 && (ACE_ITER)->ace.matches.PROTO.PORT_FIELD.port_operator == PORT_NOOP) { \
            SRPLG_LOG_INF(PLUGIN_NAME, LOG_MSG, (ACE_ITER)->ace.name); \
            onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t)); \
            if (port_attr) { \
                port_str_to_port_attr(port_attr, NULL, NULL, running_ace->ace.matches.PROTO.PORT_FIELD.port_operator, PORT_ATTR_DIR, PORT_ATTR_PROTO); \
                onm_tc_ace_hash_element_set_match_port_operator(&(ACE_ITER), port_attr, (ACE_ITER)->ace.matches.PROTO.PORT_FIELD.port_change_op); \
                free(port_attr); \
            } \
        } \
    } while (0)

#define VALIDATE_AND_UPDATE_EVENT_PORT_VALUE(ACE_ITER, PROTO, PORT_FIELD, LOG_MSG, PORT_ATTR_DIR, PORT_ATTR_PROTO) \
    do { \
        if ((ACE_ITER)->ace.matches.PROTO.PORT_FIELD.port == 0 && (ACE_ITER)->ace.matches.PROTO.PORT_FIELD.port_operator != PORT_NOOP) { \
            SRPLG_LOG_INF(PLUGIN_NAME, LOG_MSG, (ACE_ITER)->ace.name); \
            onm_tc_port_attributes_t *port_attr = malloc(sizeof(onm_tc_port_attributes_t)); \
            if (port_attr) { \
                port_attr->direction = PORT_ATTR_DIR; \
                port_attr->proto = PORT_ATTR_PROTO; \
                port_attr->port = running_ace->ace.matches.PROTO.PORT_FIELD.port; \
                port_attr->port_operator = (ACE_ITER)->ace.matches.PROTO.PORT_FIELD.port_operator; \
                onm_tc_ace_hash_element_set_match_port(&(ACE_ITER), port_attr, (ACE_ITER)->ace.matches.PROTO.PORT_FIELD.port_change_op); \
                free(port_attr); \
            } \
        } \
    } while (0)

int validate_and_update_events_acls_hash(onm_tc_ctx_t * ctx);

// this code is no longer used, proper code are defined in /data/acls/*
/*
int change_acl_init(void *priv);
void change_acl_free(void *priv);
int acl_change_iterator(void *priv, sr_session_ctx_t *session, const char *xpath);
int acl_change_iterator2(void *priv, sr_session_ctx_t *session, const char *xpath);
*/
#endif // ONM_TC_PLUGIN_API_ACLS_CHANGE_H