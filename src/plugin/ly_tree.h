#ifndef ONM_TC_PLUGIN_LY_TREE_H
#define ONM_TC_PLUGIN_LY_TREE_H

#include <libyang/libyang.h>

int onm_tc_ly_tree_create_acls(const struct ly_ctx *ly_ctx, struct lyd_node **acls_node);
int onm_tc_ly_tree_create_acls_attachment_points(const struct ly_ctx *ly_ctx, struct lyd_node *acls_node, struct lyd_node **attachment_points_node);
int onm_tc_ly_tree_create_acls_attachment_points_interface(
        const struct ly_ctx *ly_ctx, 
        struct lyd_node *attachment_points_node, 
        struct lyd_node **interface_node
            , const char *interface_id
    );
int onm_tc_ly_tree_create_acls_attachment_points_interface_egress(const struct ly_ctx *ly_ctx, struct lyd_node *interface_node, struct lyd_node **egress_node);
int onm_tc_ly_tree_create_acls_attachment_points_interface_egress_acl_sets(const struct ly_ctx *ly_ctx, struct lyd_node *egress_node, struct lyd_node **acl_sets_node);
int onm_tc_ly_tree_create_acls_attachment_points_interface_egress_acl_sets_acl_set(
        const struct ly_ctx *ly_ctx, 
        struct lyd_node *acl_sets_node, 
        struct lyd_node **acl_set_node
            , const char *name
    );
int onm_tc_ly_tree_create_acls_attachment_points_interface_egress_acl_sets_acl_set_ace_statistics(
        const struct ly_ctx *ly_ctx, 
        struct lyd_node *acl_set_node, 
        struct lyd_node **ace_statistics_node
            , const char *name
    );
int onm_tc_ly_tree_create_acls_attachment_points_interface_egress_acl_sets_acl_set_ace_statistics_matched_octets(const struct ly_ctx *ly_ctx, struct lyd_node *ace_statistics_node, const char *matched_octets);
int onm_tc_ly_tree_create_acls_attachment_points_interface_egress_acl_sets_acl_set_ace_statistics_matched_packets(const struct ly_ctx *ly_ctx, struct lyd_node *ace_statistics_node, const char *matched_packets);
int onm_tc_ly_tree_create_acls_attachment_points_interface_egress_acl_sets_acl_set_ace_statistics_name(const struct ly_ctx *ly_ctx, struct lyd_node *ace_statistics_node, const char *name);
int onm_tc_ly_tree_create_acls_attachment_points_interface_egress_acl_sets_acl_set_name(const struct ly_ctx *ly_ctx, struct lyd_node *acl_set_node, const char *name);
int onm_tc_ly_tree_create_acls_attachment_points_interface_ingress(const struct ly_ctx *ly_ctx, struct lyd_node *interface_node, struct lyd_node **ingress_node);
int onm_tc_ly_tree_create_acls_attachment_points_interface_ingress_acl_sets(const struct ly_ctx *ly_ctx, struct lyd_node *ingress_node, struct lyd_node **acl_sets_node);
int onm_tc_ly_tree_create_acls_attachment_points_interface_ingress_acl_sets_acl_set(
        const struct ly_ctx *ly_ctx, 
        struct lyd_node *acl_sets_node, 
        struct lyd_node **acl_set_node
            , const char *name
    );
int onm_tc_ly_tree_create_acls_attachment_points_interface_ingress_acl_sets_acl_set_ace_statistics(
        const struct ly_ctx *ly_ctx, 
        struct lyd_node *acl_set_node, 
        struct lyd_node **ace_statistics_node
            , const char *name
    );
int onm_tc_ly_tree_create_acls_attachment_points_interface_ingress_acl_sets_acl_set_ace_statistics_matched_octets(const struct ly_ctx *ly_ctx, struct lyd_node *ace_statistics_node, const char *matched_octets);
int onm_tc_ly_tree_create_acls_attachment_points_interface_ingress_acl_sets_acl_set_ace_statistics_matched_packets(const struct ly_ctx *ly_ctx, struct lyd_node *ace_statistics_node, const char *matched_packets);
int onm_tc_ly_tree_create_acls_attachment_points_interface_ingress_acl_sets_acl_set_ace_statistics_name(const struct ly_ctx *ly_ctx, struct lyd_node *ace_statistics_node, const char *name);
int onm_tc_ly_tree_create_acls_attachment_points_interface_ingress_acl_sets_acl_set_name(const struct ly_ctx *ly_ctx, struct lyd_node *acl_set_node, const char *name);
int onm_tc_ly_tree_create_acls_attachment_points_interface_interface_id(const struct ly_ctx *ly_ctx, struct lyd_node *interface_node, const char *interface_id);
int onm_tc_ly_tree_create_acls_acl(
        const struct ly_ctx *ly_ctx, 
        struct lyd_node *acls_node, 
        struct lyd_node **acl_node
            , const char *name
    );
int onm_tc_ly_tree_create_acls_acl_aces(const struct ly_ctx *ly_ctx, struct lyd_node *acl_node, struct lyd_node **aces_node);
int onm_tc_ly_tree_create_acls_acl_aces_ace(
        const struct ly_ctx *ly_ctx, 
        struct lyd_node *aces_node, 
        struct lyd_node **ace_node
            , const char *name
    );
int onm_tc_ly_tree_create_acls_acl_aces_ace_statistics(const struct ly_ctx *ly_ctx, struct lyd_node *ace_node, struct lyd_node **statistics_node);
int onm_tc_ly_tree_create_acls_acl_aces_ace_statistics_matched_octets(const struct ly_ctx *ly_ctx, struct lyd_node *statistics_node, const char *matched_octets);
int onm_tc_ly_tree_create_acls_acl_aces_ace_statistics_matched_packets(const struct ly_ctx *ly_ctx, struct lyd_node *statistics_node, const char *matched_packets);
int onm_tc_ly_tree_create_acls_acl_aces_ace_actions(const struct ly_ctx *ly_ctx, struct lyd_node *ace_node, struct lyd_node **actions_node);
int onm_tc_ly_tree_create_acls_acl_aces_ace_actions_logging(const struct ly_ctx *ly_ctx, struct lyd_node *actions_node, const char *logging);
int onm_tc_ly_tree_create_acls_acl_aces_ace_actions_forwarding(const struct ly_ctx *ly_ctx, struct lyd_node *actions_node, const char *forwarding);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches(const struct ly_ctx *ly_ctx, struct lyd_node *ace_node, struct lyd_node **matches_node);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ingress_interface(const struct ly_ctx *ly_ctx, struct lyd_node *matches_node, const char *ingress_interface);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_egress_interface(const struct ly_ctx *ly_ctx, struct lyd_node *matches_node, const char *egress_interface);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_icmp(const struct ly_ctx *ly_ctx, struct lyd_node *matches_node, struct lyd_node **icmp_node);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_icmp_rest_of_header(const struct ly_ctx *ly_ctx, struct lyd_node *icmp_node, const char *rest_of_header);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_icmp_code(const struct ly_ctx *ly_ctx, struct lyd_node *icmp_node, const char *code);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_icmp_type(const struct ly_ctx *ly_ctx, struct lyd_node *icmp_node, const char *type);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_udp(const struct ly_ctx *ly_ctx, struct lyd_node *matches_node, struct lyd_node **udp_node);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_udp_destination_port(const struct ly_ctx *ly_ctx, struct lyd_node *udp_node, struct lyd_node **destination_port_node);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_udp_destination_port_port(const struct ly_ctx *ly_ctx, struct lyd_node *destination_port_node, const char *port);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_udp_destination_port_operator(const struct ly_ctx *ly_ctx, struct lyd_node *destination_port_node, const char *operator);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_udp_destination_port_upper_port(const struct ly_ctx *ly_ctx, struct lyd_node *destination_port_node, const char *upper_port);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_udp_destination_port_lower_port(const struct ly_ctx *ly_ctx, struct lyd_node *destination_port_node, const char *lower_port);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_udp_source_port(const struct ly_ctx *ly_ctx, struct lyd_node *udp_node, struct lyd_node **source_port_node);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_udp_source_port_port(const struct ly_ctx *ly_ctx, struct lyd_node *source_port_node, const char *port);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_udp_source_port_operator(const struct ly_ctx *ly_ctx, struct lyd_node *source_port_node, const char *operator);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_udp_source_port_upper_port(const struct ly_ctx *ly_ctx, struct lyd_node *source_port_node, const char *upper_port);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_udp_source_port_lower_port(const struct ly_ctx *ly_ctx, struct lyd_node *source_port_node, const char *lower_port);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_udp_length(const struct ly_ctx *ly_ctx, struct lyd_node *udp_node, const char *length);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp(const struct ly_ctx *ly_ctx, struct lyd_node *matches_node, struct lyd_node **tcp_node);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_destination_port(const struct ly_ctx *ly_ctx, struct lyd_node *tcp_node, struct lyd_node **destination_port_node);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_destination_port_port(const struct ly_ctx *ly_ctx, struct lyd_node *destination_port_node, const char *port);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_destination_port_operator(const struct ly_ctx *ly_ctx, struct lyd_node *destination_port_node, const char *operator);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_destination_port_upper_port(const struct ly_ctx *ly_ctx, struct lyd_node *destination_port_node, const char *upper_port);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_destination_port_lower_port(const struct ly_ctx *ly_ctx, struct lyd_node *destination_port_node, const char *lower_port);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_source_port(const struct ly_ctx *ly_ctx, struct lyd_node *tcp_node, struct lyd_node **source_port_node);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_source_port_port(const struct ly_ctx *ly_ctx, struct lyd_node *source_port_node, const char *port);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_source_port_operator(const struct ly_ctx *ly_ctx, struct lyd_node *source_port_node, const char *operator);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_source_port_upper_port(const struct ly_ctx *ly_ctx, struct lyd_node *source_port_node, const char *upper_port);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_source_port_lower_port(const struct ly_ctx *ly_ctx, struct lyd_node *source_port_node, const char *lower_port);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_options(const struct ly_ctx *ly_ctx, struct lyd_node *tcp_node, const char *options);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_urgent_pointer(const struct ly_ctx *ly_ctx, struct lyd_node *tcp_node, const char *urgent_pointer);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_window_size(const struct ly_ctx *ly_ctx, struct lyd_node *tcp_node, const char *window_size);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_flags(const struct ly_ctx *ly_ctx, struct lyd_node *tcp_node, const char *flags);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_reserved(const struct ly_ctx *ly_ctx, struct lyd_node *tcp_node, const char *reserved);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_data_offset(const struct ly_ctx *ly_ctx, struct lyd_node *tcp_node, const char *data_offset);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_acknowledgement_number(const struct ly_ctx *ly_ctx, struct lyd_node *tcp_node, const char *acknowledgement_number);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_sequence_number(const struct ly_ctx *ly_ctx, struct lyd_node *tcp_node, const char *sequence_number);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv6(const struct ly_ctx *ly_ctx, struct lyd_node *matches_node, struct lyd_node **ipv6_node);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv6_flow_label(const struct ly_ctx *ly_ctx, struct lyd_node *ipv6_node, const char *flow_label);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv6_source_ipv6_network(const struct ly_ctx *ly_ctx, struct lyd_node *ipv6_node, const char *source_ipv6_network);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv6_destination_ipv6_network(const struct ly_ctx *ly_ctx, struct lyd_node *ipv6_node, const char *destination_ipv6_network);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv6_protocol(const struct ly_ctx *ly_ctx, struct lyd_node *ipv6_node, const char *protocol);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv6_ttl(const struct ly_ctx *ly_ctx, struct lyd_node *ipv6_node, const char *ttl);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv6_length(const struct ly_ctx *ly_ctx, struct lyd_node *ipv6_node, const char *length);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv6_ecn(const struct ly_ctx *ly_ctx, struct lyd_node *ipv6_node, const char *ecn);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv6_dscp(const struct ly_ctx *ly_ctx, struct lyd_node *ipv6_node, const char *dscp);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv4(const struct ly_ctx *ly_ctx, struct lyd_node *matches_node, struct lyd_node **ipv4_node);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv4_source_ipv4_network(const struct ly_ctx *ly_ctx, struct lyd_node *ipv4_node, const char *source_ipv4_network);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv4_destination_ipv4_network(const struct ly_ctx *ly_ctx, struct lyd_node *ipv4_node, const char *destination_ipv4_network);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv4_identification(const struct ly_ctx *ly_ctx, struct lyd_node *ipv4_node, const char *identification);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv4_offset(const struct ly_ctx *ly_ctx, struct lyd_node *ipv4_node, const char *offset);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv4_flags(const struct ly_ctx *ly_ctx, struct lyd_node *ipv4_node, const char *flags);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv4_ihl(const struct ly_ctx *ly_ctx, struct lyd_node *ipv4_node, const char *ihl);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv4_protocol(const struct ly_ctx *ly_ctx, struct lyd_node *ipv4_node, const char *protocol);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv4_ttl(const struct ly_ctx *ly_ctx, struct lyd_node *ipv4_node, const char *ttl);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv4_length(const struct ly_ctx *ly_ctx, struct lyd_node *ipv4_node, const char *length);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv4_ecn(const struct ly_ctx *ly_ctx, struct lyd_node *ipv4_node, const char *ecn);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv4_dscp(const struct ly_ctx *ly_ctx, struct lyd_node *ipv4_node, const char *dscp);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_eth(const struct ly_ctx *ly_ctx, struct lyd_node *matches_node, struct lyd_node **eth_node);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_eth_ethertype(const struct ly_ctx *ly_ctx, struct lyd_node *eth_node, const char *ethertype);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_eth_source_mac_address_mask(const struct ly_ctx *ly_ctx, struct lyd_node *eth_node, const char *source_mac_address_mask);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_eth_source_mac_address(const struct ly_ctx *ly_ctx, struct lyd_node *eth_node, const char *source_mac_address);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_eth_destination_mac_address_mask(const struct ly_ctx *ly_ctx, struct lyd_node *eth_node, const char *destination_mac_address_mask);
int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_eth_destination_mac_address(const struct ly_ctx *ly_ctx, struct lyd_node *eth_node, const char *destination_mac_address);
int onm_tc_ly_tree_create_acls_acl_aces_ace_name(const struct ly_ctx *ly_ctx, struct lyd_node *ace_node, const char *name);
int onm_tc_ly_tree_create_acls_acl_type(const struct ly_ctx *ly_ctx, struct lyd_node *acl_node, const char *type);
int onm_tc_ly_tree_create_acls_acl_name(const struct ly_ctx *ly_ctx, struct lyd_node *acl_node, const char *name);

#endif // ONM_TC_PLUGIN_LY_TREE_H