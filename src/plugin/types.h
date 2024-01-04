#ifndef ONM_TC_PLUGIN_TYPES_H
#define ONM_TC_PLUGIN_TYPES_H

#include <stdbool.h>
#include <stdint.h>
#include <uthash.h>
#include <sysrepo.h>
// typedefs
typedef struct onm_tc_eth onm_tc_eth_t;
typedef struct onm_tc_ipv4 onm_tc_ipv4_t;
typedef struct onm_tc_ipv6 onm_tc_ipv6_t;
typedef struct onm_tc_tcp onm_tc_tcp_t;
typedef struct onm_tc_source_port onm_tc_source_port_t;
typedef struct onm_tc_destination_port onm_tc_destination_port_t;
typedef struct onm_tc_udp onm_tc_udp_t;
typedef struct onm_tc_icmp onm_tc_icmp_t;
typedef struct onm_tc_matches onm_tc_matches_t;
typedef struct onm_tc_ace onm_tc_ace_t;
typedef struct onm_tc_ace_element onm_tc_ace_element_t;
typedef struct onm_tc_aces onm_tc_aces_t;
typedef struct onm_tc_acl onm_tc_acl_t;
typedef struct onm_tc_acl_element onm_tc_acl_element_t;
//typedef struct onm_tc_acls onm_tc_acls_t;

typedef struct onm_tc_aps_ingress onm_tc_aps_ingress_t;
typedef struct onm_tc_aps_egress onm_tc_aps_egress_t;
typedef struct onm_tc_aps_acl_sets onm_tc_aps_acl_sets_t;
typedef struct onm_tc_aps_acl_set onm_tc_aps_acl_set_t;
typedef struct onm_tc_aps_acl_set_element onm_tc_aps_acl_set_element_t;
typedef struct onm_tc_aps_interface onm_tc_aps_interface_t;
typedef struct onm_tc_aps_interface_element onm_tc_aps_interface_element_t;
typedef struct onm_tc_aps onm_tc_aps_t;

typedef struct ietf_interface ietf_interface_t;
typedef enum forwarding_action forwarding_action_t;
typedef enum logging_action logging_action_t;
typedef enum port_operator port_operator_t;

typedef struct onm_tc_port_attributes onm_tc_port_attributes_t;
typedef enum onm_tc_port_attr_direction onm_tc_port_attr_direction_t;
typedef enum onm_tc_port_attr_proto onm_tc_port_attr_proto_t;

typedef struct onm_tc_actions onm_tc_actions_t;
typedef enum onm_tc_acl_type onm_tc_acl_type_t;

typedef struct onm_tc_acl_hash_element onm_tc_acl_hash_element_t;
typedef struct onm_tc_aps_interface_hash_element onm_tc_aps_interface_hash_element_t;


//TODO Add more details to interface definition
struct ietf_interface {
    char * name;
};

enum forwarding_action{
    FORWARD_NOOP,
    FORWARD_ACCEPT,
    FORWARD_DROP,
    FORWARD_REJECT
};

enum logging_action{
    LOG_NOOP,
    LOG_SYSLOG,
    LOG_NONE
};

enum port_operator{
    PORT_NOOP,
    PORT_EQUAL,
    PORT_LTE,
    PORT_GTE,
    PORT_NOT_EQUAL
};

struct onm_tc_actions {
    forwarding_action_t forwarding;
    forwarding_action_t logging;
    sr_change_oper_t forwarding_change_op;
    sr_change_oper_t logging_change_op;
};

enum onm_tc_port_attr_proto{
    PROT_ATTR_NOPROTO,
    PORT_ATTR_PROTO_TCP,
    PORT_ATTR_PROTO_UDP
};

enum onm_tc_port_attr_direction{
    PROT_ATTR_NODIRECTION,
    PORT_ATTR_SRC,
    PORT_ATTR_DST
};

struct onm_tc_port_attributes{
    onm_tc_port_attr_proto_t proto;
    onm_tc_port_attr_direction_t direction;
    port_operator_t single_port_operator;
    uint16_t single_port_value;
    uint16_t range_lower_port;
    uint16_t range_upper_port;
};



struct onm_tc_eth {
    char * destination_address;
    char * destination_address_mask;
    char * source_address;
    char * source_address_mask;
    uint16_t ethertype;
    uint8_t _is_set;
    sr_change_oper_t source_address_change_op;
    sr_change_oper_t source_address_mask_change_op;
    sr_change_oper_t destination_address_change_op;
    sr_change_oper_t destination_address_mask_change_op;
    sr_change_oper_t ethertype_change_op;
};

struct onm_tc_ipv4 {
    uint8_t dscp;
    uint8_t ecn;
    uint16_t length;
    uint8_t ttl;
    uint8_t protocol;
    uint8_t ihl;
    uint64_t flags;
    uint16_t offset;
    uint16_t identification;
    char * destination_network;
    char * source_network;
    uint8_t _is_set;
    sr_change_oper_t source_network_change_op;
    sr_change_oper_t destination_network_change_op;
};

struct onm_tc_ipv6 {
    uint8_t dscp;
    uint8_t ecn;
    uint16_t length;
    uint8_t ttl;
    uint8_t protocol;
    char * destination_network;
    char * source_network;
    uint32_t flow_label;
    uint8_t _is_set;
    sr_change_oper_t source_network_change_op;
    sr_change_oper_t destination_network_change_op;
};

struct onm_tc_source_port {
    uint16_t lower_port;
    uint16_t upper_port;
    uint16_t port;
    port_operator_t port_operator;
    sr_change_oper_t single_port_change_op;
    sr_change_oper_t range_port_change_op;
};

struct onm_tc_destination_port {
    uint16_t lower_port;
    uint16_t upper_port;
    uint16_t port;
    port_operator_t port_operator;
    sr_change_oper_t single_port_change_op;
    sr_change_oper_t range_port_change_op;
};

struct onm_tc_tcp {
    uint32_t sequence_number;
    uint32_t acknowledgement_number;
    uint8_t data_offset;
    uint8_t reserved;
    uint64_t flags;
    uint16_t window_size;
    uint16_t urgent_pointer;
    void * options;
    onm_tc_source_port_t source_port;
    onm_tc_destination_port_t destination_port;
    uint8_t _is_set;
};


struct onm_tc_udp {
    uint16_t length;
    onm_tc_source_port_t source_port;
    onm_tc_destination_port_t destination_port;
    uint8_t _is_set;
};

struct onm_tc_icmp {
    uint8_t type;
    uint8_t code;
    void * rest_of_header;
    uint8_t _is_set;
    sr_change_oper_t type_change_op;
    sr_change_oper_t code_change_op;
};

struct onm_tc_matches {
    onm_tc_eth_t eth;
    onm_tc_ipv4_t ipv4;
    onm_tc_ipv6_t ipv6;
    onm_tc_tcp_t tcp;
    onm_tc_udp_t udp;
    onm_tc_icmp_t icmp;
    ietf_interface_t egress_interface;
    ietf_interface_t ingress_interface;
};

struct onm_tc_aces {
    onm_tc_ace_element_t* ace;
};

struct onm_tc_ace {
    char * name;
    uint16_t priority;
    uint16_t handle;
    onm_tc_matches_t matches;
    onm_tc_actions_t actions;
    sr_change_oper_t name_change_op;
    sr_change_oper_t prio_change_op;
};

struct onm_tc_ace_element {
    onm_tc_ace_element_t* next;
    onm_tc_ace_t ace;
};


enum onm_tc_acl_type{
    ACL_BASE,
    IPV4_ACL_TYPE,
    IPV6_ACL_TYPE,
    ETH_ACL_TYPE,
    MIXED_ETH_IPV4_ACL_TYPE,
    MIXED_ETH_IPV6_ACL_TYPE,
    MIXED_ETH_IPV4_IPV6_ACL_TYPE
};


struct onm_tc_acl {
    char * name;
    unsigned int acl_id;
    onm_tc_acl_type_t type;
    onm_tc_aces_t aces;
    sr_change_oper_t name_change_op;
    sr_change_oper_t type_change_op;
};

struct onm_tc_acl_element {
    onm_tc_acl_t acl;
    onm_tc_acl_element_t* next;
};

struct onm_tc_aps_acl_set {
    char * name;
};

struct onm_tc_aps_acl_sets {
    onm_tc_aps_acl_set_element_t* acl_set;
};

struct onm_tc_aps_ingress {
    onm_tc_aps_acl_sets_t acl_sets;
};

struct onm_tc_aps_acl_set_element {
    onm_tc_aps_acl_set_t acl_set;
    onm_tc_aps_acl_set_element_t* next;
};



struct onm_tc_aps_egress {
    onm_tc_aps_acl_sets_t acl_sets;
};

struct onm_tc_aps_interface {
    //TODO review interface_id type (referes to interface name)
    char * interface_id;
    onm_tc_aps_ingress_t ingress;
    onm_tc_aps_egress_t egress;
};

struct onm_tc_aps_interface_element {
    onm_tc_aps_interface_t interface;
    onm_tc_aps_interface_element_t* next;
};

struct onm_tc_aps {
    onm_tc_aps_interface_element_t* interface;
};

struct onm_tc_acl_hash_element {
    onm_tc_acl_t acl;
    UT_hash_handle hh;
};

struct onm_tc_aps_interface_hash_element {
    onm_tc_aps_interface_t interface;
    UT_hash_handle hh;
};

#endif // ONM_TC_PLUGIN_TYPES_H