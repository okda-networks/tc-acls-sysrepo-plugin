#include "ly_tree.h"
#include "common.h"

#include <srpc.h>

int onm_tc_ly_tree_create_acls(const struct ly_ctx *ly_ctx, struct lyd_node **acls_node)
{
    return srpc_ly_tree_create_container(ly_ctx, NULL, acls_node, "/ietf-access-control-list:acls");
}

int onm_tc_ly_tree_create_acls_attachment_points(const struct ly_ctx *ly_ctx, struct lyd_node *acls_node, struct lyd_node **attachment_points_node)
{
    return srpc_ly_tree_create_container(ly_ctx, acls_node, attachment_points_node, "attachment-points");
}

int onm_tc_ly_tree_create_acls_attachment_points_interface(const struct ly_ctx *ly_ctx, struct lyd_node *attachment_points_node, struct lyd_node **interface_node, const char *interface_id)
{
    // TODO: fix this for multiple keys with SRPC library and review interface_id key
    return srpc_ly_tree_create_list(ly_ctx, attachment_points_node, interface_node, "interface", "name", interface_id);
}

int onm_tc_ly_tree_create_acls_attachment_points_interface_egress(const struct ly_ctx *ly_ctx, struct lyd_node *interface_node, struct lyd_node **egress_node)
{
    return srpc_ly_tree_create_container(ly_ctx, interface_node, egress_node, "egress");
}

int onm_tc_ly_tree_create_acls_attachment_points_interface_egress_acl_sets(const struct ly_ctx *ly_ctx, struct lyd_node *egress_node, struct lyd_node **acl_sets_node)
{
    return srpc_ly_tree_create_container(ly_ctx, egress_node, acl_sets_node, "acl-sets");
}

int onm_tc_ly_tree_create_acls_attachment_points_interface_egress_acl_sets_acl_set(const struct ly_ctx *ly_ctx, struct lyd_node *acl_sets_node, struct lyd_node **acl_set_node, const char *name)
{
    // TODO: fix this for multiple keys with SRPC library
    return srpc_ly_tree_create_list(ly_ctx, acl_sets_node, acl_set_node, "acl-set", "name", name);
}

int onm_tc_ly_tree_create_acls_attachment_points_interface_egress_acl_sets_acl_set_ace_statistics(const struct ly_ctx *ly_ctx, struct lyd_node *acl_set_node, struct lyd_node **ace_statistics_node, const char *name)
{
    // TODO: fix this for multiple keys with SRPC library
    return srpc_ly_tree_create_list(ly_ctx, acl_set_node, ace_statistics_node, "ace-statistics", "name", name);
}

int onm_tc_ly_tree_create_acls_attachment_points_interface_egress_acl_sets_acl_set_ace_statistics_matched_octets(const struct ly_ctx *ly_ctx, struct lyd_node *ace_statistics_node, const char *matched_octets)
{
    return srpc_ly_tree_create_leaf(ly_ctx, ace_statistics_node, NULL, "matched-octets", matched_octets);
}

int onm_tc_ly_tree_create_acls_attachment_points_interface_egress_acl_sets_acl_set_ace_statistics_matched_packets(const struct ly_ctx *ly_ctx, struct lyd_node *ace_statistics_node, const char *matched_packets)
{
    return srpc_ly_tree_create_leaf(ly_ctx, ace_statistics_node, NULL, "matched-packets", matched_packets);
}

int onm_tc_ly_tree_create_acls_attachment_points_interface_egress_acl_sets_acl_set_ace_statistics_name(const struct ly_ctx *ly_ctx, struct lyd_node *ace_statistics_node, const char *name)
{
    return srpc_ly_tree_create_leaf(ly_ctx, ace_statistics_node, NULL, "name", name);
}

int onm_tc_ly_tree_create_acls_attachment_points_interface_egress_acl_sets_acl_set_name(const struct ly_ctx *ly_ctx, struct lyd_node *acl_set_node, const char *name)
{
    return srpc_ly_tree_create_leaf(ly_ctx, acl_set_node, NULL, "name", name);
}

int onm_tc_ly_tree_create_acls_attachment_points_interface_ingress(const struct ly_ctx *ly_ctx, struct lyd_node *interface_node, struct lyd_node **ingress_node)
{
    return srpc_ly_tree_create_container(ly_ctx, interface_node, ingress_node, "ingress");
}

int onm_tc_ly_tree_create_acls_attachment_points_interface_ingress_acl_sets(const struct ly_ctx *ly_ctx, struct lyd_node *ingress_node, struct lyd_node **acl_sets_node)
{
    return srpc_ly_tree_create_container(ly_ctx, ingress_node, acl_sets_node, "acl-sets");
}

int onm_tc_ly_tree_create_acls_attachment_points_interface_ingress_acl_sets_acl_set(const struct ly_ctx *ly_ctx, struct lyd_node *acl_sets_node, struct lyd_node **acl_set_node, const char *name)
{
    // TODO: fix this for multiple keys with SRPC library
    return srpc_ly_tree_create_list(ly_ctx, acl_sets_node, acl_set_node, "acl-set", "name", name);
}

int onm_tc_ly_tree_create_acls_attachment_points_interface_ingress_acl_sets_acl_set_ace_statistics(const struct ly_ctx *ly_ctx, struct lyd_node *acl_set_node, struct lyd_node **ace_statistics_node, const char *name)
{
    // TODO: fix this for multiple keys with SRPC library
    return srpc_ly_tree_create_list(ly_ctx, acl_set_node, ace_statistics_node, "ace-statistics", "name", name);
}

int onm_tc_ly_tree_create_acls_attachment_points_interface_ingress_acl_sets_acl_set_ace_statistics_matched_octets(const struct ly_ctx *ly_ctx, struct lyd_node *ace_statistics_node, const char *matched_octets)
{
    return srpc_ly_tree_create_leaf(ly_ctx, ace_statistics_node, NULL, "matched-octets", matched_octets);
}

int onm_tc_ly_tree_create_acls_attachment_points_interface_ingress_acl_sets_acl_set_ace_statistics_matched_packets(const struct ly_ctx *ly_ctx, struct lyd_node *ace_statistics_node, const char *matched_packets)
{
    return srpc_ly_tree_create_leaf(ly_ctx, ace_statistics_node, NULL, "matched-packets", matched_packets);
}

int onm_tc_ly_tree_create_acls_attachment_points_interface_ingress_acl_sets_acl_set_ace_statistics_name(const struct ly_ctx *ly_ctx, struct lyd_node *ace_statistics_node, const char *name)
{
    return srpc_ly_tree_create_leaf(ly_ctx, ace_statistics_node, NULL, "name", name);
}

int onm_tc_ly_tree_create_acls_attachment_points_interface_ingress_acl_sets_acl_set_name(const struct ly_ctx *ly_ctx, struct lyd_node *acl_set_node, const char *name)
{
    return srpc_ly_tree_create_leaf(ly_ctx, acl_set_node, NULL, "name", name);
}

int onm_tc_ly_tree_create_acls_attachment_points_interface_interface_id(const struct ly_ctx *ly_ctx, struct lyd_node *interface_node, const char *interface_id)
{
    return srpc_ly_tree_create_leaf(ly_ctx, interface_node, NULL, "interface-id", interface_id);
}

int onm_tc_ly_tree_create_acls_acl(const struct ly_ctx *ly_ctx, struct lyd_node *acls_node, struct lyd_node **acl_node, const char *name)
{
    // TODO: fix this for multiple keys with SRPC library
    return srpc_ly_tree_create_list(ly_ctx, acls_node, acl_node, "acl", "name", name);
}

int onm_tc_ly_tree_create_acls_acl_aces(const struct ly_ctx *ly_ctx, struct lyd_node *acl_node, struct lyd_node **aces_node)
{
    return srpc_ly_tree_create_container(ly_ctx, acl_node, aces_node, "aces");
}

int onm_tc_ly_tree_create_acls_acl_aces_ace(const struct ly_ctx *ly_ctx, struct lyd_node *aces_node, struct lyd_node **ace_node, const char *name)
{
    // TODO: fix this for multiple keys with SRPC library
    return srpc_ly_tree_create_list(ly_ctx, aces_node, ace_node, "ace", "name", name);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_statistics(const struct ly_ctx *ly_ctx, struct lyd_node *ace_node, struct lyd_node **statistics_node)
{
    return srpc_ly_tree_create_container(ly_ctx, ace_node, statistics_node, "statistics");
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_statistics_matched_octets(const struct ly_ctx *ly_ctx, struct lyd_node *statistics_node, const char *matched_octets)
{
    return srpc_ly_tree_create_leaf(ly_ctx, statistics_node, NULL, "matched-octets", matched_octets);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_statistics_matched_packets(const struct ly_ctx *ly_ctx, struct lyd_node *statistics_node, const char *matched_packets)
{
    return srpc_ly_tree_create_leaf(ly_ctx, statistics_node, NULL, "matched-packets", matched_packets);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_actions(const struct ly_ctx *ly_ctx, struct lyd_node *ace_node, struct lyd_node **actions_node)
{
    return srpc_ly_tree_create_container(ly_ctx, ace_node, actions_node, "actions");
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_actions_logging(const struct ly_ctx *ly_ctx, struct lyd_node *actions_node, const char *logging)
{
    return srpc_ly_tree_create_leaf(ly_ctx, actions_node, NULL, "logging", logging);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_actions_forwarding(const struct ly_ctx *ly_ctx, struct lyd_node *actions_node, const char *forwarding)
{
    return srpc_ly_tree_create_leaf(ly_ctx, actions_node, NULL, "forwarding", forwarding);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches(const struct ly_ctx *ly_ctx, struct lyd_node *ace_node, struct lyd_node **matches_node)
{
    return srpc_ly_tree_create_container(ly_ctx, ace_node, matches_node, "matches");
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ingress_interface(const struct ly_ctx *ly_ctx, struct lyd_node *matches_node, const char *ingress_interface)
{
    return srpc_ly_tree_create_leaf(ly_ctx, matches_node, NULL, "ingress-interface", ingress_interface);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_egress_interface(const struct ly_ctx *ly_ctx, struct lyd_node *matches_node, const char *egress_interface)
{
    return srpc_ly_tree_create_leaf(ly_ctx, matches_node, NULL, "egress-interface", egress_interface);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_icmp(const struct ly_ctx *ly_ctx, struct lyd_node *matches_node, struct lyd_node **icmp_node)
{
    return srpc_ly_tree_create_container(ly_ctx, matches_node, icmp_node, "icmp");
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_icmp_rest_of_header(const struct ly_ctx *ly_ctx, struct lyd_node *icmp_node, const char *rest_of_header)
{
    return srpc_ly_tree_create_leaf(ly_ctx, icmp_node, NULL, "rest-of-header", rest_of_header);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_icmp_code(const struct ly_ctx *ly_ctx, struct lyd_node *icmp_node, const char *code)
{
    return srpc_ly_tree_create_leaf(ly_ctx, icmp_node, NULL, "code", code);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_icmp_type(const struct ly_ctx *ly_ctx, struct lyd_node *icmp_node, const char *type)
{
    return srpc_ly_tree_create_leaf(ly_ctx, icmp_node, NULL, "type", type);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_udp(const struct ly_ctx *ly_ctx, struct lyd_node *matches_node, struct lyd_node **udp_node)
{
    return srpc_ly_tree_create_container(ly_ctx, matches_node, udp_node, "udp");
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_udp_destination_port(const struct ly_ctx *ly_ctx, struct lyd_node *udp_node, struct lyd_node **destination_port_node)
{
    return srpc_ly_tree_create_container(ly_ctx, udp_node, destination_port_node, "destination-port");
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_udp_destination_port_port(const struct ly_ctx *ly_ctx, struct lyd_node *destination_port_node, const char *port)
{
    return srpc_ly_tree_create_leaf(ly_ctx, destination_port_node, NULL, "port", port);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_udp_destination_port_operator(const struct ly_ctx *ly_ctx, struct lyd_node *destination_port_node, const char *operator)
{
    return srpc_ly_tree_create_leaf(ly_ctx, destination_port_node, NULL, "operator", operator);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_udp_destination_port_upper_port(const struct ly_ctx *ly_ctx, struct lyd_node *destination_port_node, const char *upper_port)
{
    return srpc_ly_tree_create_leaf(ly_ctx, destination_port_node, NULL, "upper-port", upper_port);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_udp_destination_port_lower_port(const struct ly_ctx *ly_ctx, struct lyd_node *destination_port_node, const char *lower_port)
{
    return srpc_ly_tree_create_leaf(ly_ctx, destination_port_node, NULL, "lower-port", lower_port);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_udp_source_port(const struct ly_ctx *ly_ctx, struct lyd_node *udp_node, struct lyd_node **source_port_node)
{
    return srpc_ly_tree_create_container(ly_ctx, udp_node, source_port_node, "source-port");
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_udp_source_port_port(const struct ly_ctx *ly_ctx, struct lyd_node *source_port_node, const char *port)
{
    return srpc_ly_tree_create_leaf(ly_ctx, source_port_node, NULL, "port", port);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_udp_source_port_operator(const struct ly_ctx *ly_ctx, struct lyd_node *source_port_node, const char *operator)
{
    return srpc_ly_tree_create_leaf(ly_ctx, source_port_node, NULL, "operator", operator);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_udp_source_port_upper_port(const struct ly_ctx *ly_ctx, struct lyd_node *source_port_node, const char *upper_port)
{
    return srpc_ly_tree_create_leaf(ly_ctx, source_port_node, NULL, "upper-port", upper_port);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_udp_source_port_lower_port(const struct ly_ctx *ly_ctx, struct lyd_node *source_port_node, const char *lower_port)
{
    return srpc_ly_tree_create_leaf(ly_ctx, source_port_node, NULL, "lower-port", lower_port);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_udp_length(const struct ly_ctx *ly_ctx, struct lyd_node *udp_node, const char *length)
{
    return srpc_ly_tree_create_leaf(ly_ctx, udp_node, NULL, "length", length);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp(const struct ly_ctx *ly_ctx, struct lyd_node *matches_node, struct lyd_node **tcp_node)
{
    return srpc_ly_tree_create_container(ly_ctx, matches_node, tcp_node, "tcp");
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_destination_port(const struct ly_ctx *ly_ctx, struct lyd_node *tcp_node, struct lyd_node **destination_port_node)
{
    return srpc_ly_tree_create_container(ly_ctx, tcp_node, destination_port_node, "destination-port");
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_destination_port_port(const struct ly_ctx *ly_ctx, struct lyd_node *destination_port_node, const char *port)
{
    return srpc_ly_tree_create_leaf(ly_ctx, destination_port_node, NULL, "port", port);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_destination_port_operator(const struct ly_ctx *ly_ctx, struct lyd_node *destination_port_node, const char *operator)
{
    return srpc_ly_tree_create_leaf(ly_ctx, destination_port_node, NULL, "operator", operator);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_destination_port_upper_port(const struct ly_ctx *ly_ctx, struct lyd_node *destination_port_node, const char *upper_port)
{
    return srpc_ly_tree_create_leaf(ly_ctx, destination_port_node, NULL, "upper-port", upper_port);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_destination_port_lower_port(const struct ly_ctx *ly_ctx, struct lyd_node *destination_port_node, const char *lower_port)
{
    return srpc_ly_tree_create_leaf(ly_ctx, destination_port_node, NULL, "lower-port", lower_port);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_source_port(const struct ly_ctx *ly_ctx, struct lyd_node *tcp_node, struct lyd_node **source_port_node)
{
    return srpc_ly_tree_create_container(ly_ctx, tcp_node, source_port_node, "source-port");
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_source_port_port(const struct ly_ctx *ly_ctx, struct lyd_node *source_port_node, const char *port)
{
    return srpc_ly_tree_create_leaf(ly_ctx, source_port_node, NULL, "port", port);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_source_port_operator(const struct ly_ctx *ly_ctx, struct lyd_node *source_port_node, const char *operator)
{
    return srpc_ly_tree_create_leaf(ly_ctx, source_port_node, NULL, "operator", operator);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_source_port_upper_port(const struct ly_ctx *ly_ctx, struct lyd_node *source_port_node, const char *upper_port)
{
    return srpc_ly_tree_create_leaf(ly_ctx, source_port_node, NULL, "upper-port", upper_port);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_source_port_lower_port(const struct ly_ctx *ly_ctx, struct lyd_node *source_port_node, const char *lower_port)
{
    return srpc_ly_tree_create_leaf(ly_ctx, source_port_node, NULL, "lower-port", lower_port);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_options(const struct ly_ctx *ly_ctx, struct lyd_node *tcp_node, const char *options)
{
    return srpc_ly_tree_create_leaf(ly_ctx, tcp_node, NULL, "options", options);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_urgent_pointer(const struct ly_ctx *ly_ctx, struct lyd_node *tcp_node, const char *urgent_pointer)
{
    return srpc_ly_tree_create_leaf(ly_ctx, tcp_node, NULL, "urgent-pointer", urgent_pointer);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_window_size(const struct ly_ctx *ly_ctx, struct lyd_node *tcp_node, const char *window_size)
{
    return srpc_ly_tree_create_leaf(ly_ctx, tcp_node, NULL, "window-size", window_size);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_flags(const struct ly_ctx *ly_ctx, struct lyd_node *tcp_node, const char *flags)
{
    return srpc_ly_tree_create_leaf(ly_ctx, tcp_node, NULL, "flags", flags);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_reserved(const struct ly_ctx *ly_ctx, struct lyd_node *tcp_node, const char *reserved)
{
    return srpc_ly_tree_create_leaf(ly_ctx, tcp_node, NULL, "reserved", reserved);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_data_offset(const struct ly_ctx *ly_ctx, struct lyd_node *tcp_node, const char *data_offset)
{
    return srpc_ly_tree_create_leaf(ly_ctx, tcp_node, NULL, "data-offset", data_offset);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_acknowledgement_number(const struct ly_ctx *ly_ctx, struct lyd_node *tcp_node, const char *acknowledgement_number)
{
    return srpc_ly_tree_create_leaf(ly_ctx, tcp_node, NULL, "acknowledgement-number", acknowledgement_number);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_tcp_sequence_number(const struct ly_ctx *ly_ctx, struct lyd_node *tcp_node, const char *sequence_number)
{
    return srpc_ly_tree_create_leaf(ly_ctx, tcp_node, NULL, "sequence-number", sequence_number);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv6(const struct ly_ctx *ly_ctx, struct lyd_node *matches_node, struct lyd_node **ipv6_node)
{
    return srpc_ly_tree_create_container(ly_ctx, matches_node, ipv6_node, "ipv6");
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv6_flow_label(const struct ly_ctx *ly_ctx, struct lyd_node *ipv6_node, const char *flow_label)
{
    return srpc_ly_tree_create_leaf(ly_ctx, ipv6_node, NULL, "flow-label", flow_label);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv6_source_ipv6_network(const struct ly_ctx *ly_ctx, struct lyd_node *ipv6_node, const char *source_ipv6_network)
{
    return srpc_ly_tree_create_leaf(ly_ctx, ipv6_node, NULL, "source-ipv6-network", source_ipv6_network);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv6_destination_ipv6_network(const struct ly_ctx *ly_ctx, struct lyd_node *ipv6_node, const char *destination_ipv6_network)
{
    return srpc_ly_tree_create_leaf(ly_ctx, ipv6_node, NULL, "destination-ipv6-network", destination_ipv6_network);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv6_protocol(const struct ly_ctx *ly_ctx, struct lyd_node *ipv6_node, const char *protocol)
{
    return srpc_ly_tree_create_leaf(ly_ctx, ipv6_node, NULL, "protocol", protocol);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv6_ttl(const struct ly_ctx *ly_ctx, struct lyd_node *ipv6_node, const char *ttl)
{
    return srpc_ly_tree_create_leaf(ly_ctx, ipv6_node, NULL, "ttl", ttl);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv6_length(const struct ly_ctx *ly_ctx, struct lyd_node *ipv6_node, const char *length)
{
    return srpc_ly_tree_create_leaf(ly_ctx, ipv6_node, NULL, "length", length);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv6_ecn(const struct ly_ctx *ly_ctx, struct lyd_node *ipv6_node, const char *ecn)
{
    return srpc_ly_tree_create_leaf(ly_ctx, ipv6_node, NULL, "ecn", ecn);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv6_dscp(const struct ly_ctx *ly_ctx, struct lyd_node *ipv6_node, const char *dscp)
{
    return srpc_ly_tree_create_leaf(ly_ctx, ipv6_node, NULL, "dscp", dscp);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv4(const struct ly_ctx *ly_ctx, struct lyd_node *matches_node, struct lyd_node **ipv4_node)
{
    return srpc_ly_tree_create_container(ly_ctx, matches_node, ipv4_node, "ipv4");
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv4_source_ipv4_network(const struct ly_ctx *ly_ctx, struct lyd_node *ipv4_node, const char *source_ipv4_network)
{
    return srpc_ly_tree_create_leaf(ly_ctx, ipv4_node, NULL, "source-ipv4-network", source_ipv4_network);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv4_destination_ipv4_network(const struct ly_ctx *ly_ctx, struct lyd_node *ipv4_node, const char *destination_ipv4_network)
{
    return srpc_ly_tree_create_leaf(ly_ctx, ipv4_node, NULL, "destination-ipv4-network", destination_ipv4_network);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv4_identification(const struct ly_ctx *ly_ctx, struct lyd_node *ipv4_node, const char *identification)
{
    return srpc_ly_tree_create_leaf(ly_ctx, ipv4_node, NULL, "identification", identification);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv4_offset(const struct ly_ctx *ly_ctx, struct lyd_node *ipv4_node, const char *offset)
{
    return srpc_ly_tree_create_leaf(ly_ctx, ipv4_node, NULL, "offset", offset);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv4_flags(const struct ly_ctx *ly_ctx, struct lyd_node *ipv4_node, const char *flags)
{
    return srpc_ly_tree_create_leaf(ly_ctx, ipv4_node, NULL, "flags", flags);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv4_ihl(const struct ly_ctx *ly_ctx, struct lyd_node *ipv4_node, const char *ihl)
{
    return srpc_ly_tree_create_leaf(ly_ctx, ipv4_node, NULL, "ihl", ihl);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv4_protocol(const struct ly_ctx *ly_ctx, struct lyd_node *ipv4_node, const char *protocol)
{
    return srpc_ly_tree_create_leaf(ly_ctx, ipv4_node, NULL, "protocol", protocol);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv4_ttl(const struct ly_ctx *ly_ctx, struct lyd_node *ipv4_node, const char *ttl)
{
    return srpc_ly_tree_create_leaf(ly_ctx, ipv4_node, NULL, "ttl", ttl);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv4_length(const struct ly_ctx *ly_ctx, struct lyd_node *ipv4_node, const char *length)
{
    return srpc_ly_tree_create_leaf(ly_ctx, ipv4_node, NULL, "length", length);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv4_ecn(const struct ly_ctx *ly_ctx, struct lyd_node *ipv4_node, const char *ecn)
{
    return srpc_ly_tree_create_leaf(ly_ctx, ipv4_node, NULL, "ecn", ecn);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_ipv4_dscp(const struct ly_ctx *ly_ctx, struct lyd_node *ipv4_node, const char *dscp)
{
    return srpc_ly_tree_create_leaf(ly_ctx, ipv4_node, NULL, "dscp", dscp);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_eth(const struct ly_ctx *ly_ctx, struct lyd_node *matches_node, struct lyd_node **eth_node)
{
    return srpc_ly_tree_create_container(ly_ctx, matches_node, eth_node, "eth");
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_eth_ethertype(const struct ly_ctx *ly_ctx, struct lyd_node *eth_node, const char *ethertype)
{
    return srpc_ly_tree_create_leaf(ly_ctx, eth_node, NULL, "ethertype", ethertype);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_eth_source_mac_address_mask(const struct ly_ctx *ly_ctx, struct lyd_node *eth_node, const char *source_mac_address_mask)
{
    return srpc_ly_tree_create_leaf(ly_ctx, eth_node, NULL, "source-mac-address-mask", source_mac_address_mask);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_eth_source_mac_address(const struct ly_ctx *ly_ctx, struct lyd_node *eth_node, const char *source_mac_address)
{
    return srpc_ly_tree_create_leaf(ly_ctx, eth_node, NULL, "source-mac-address", source_mac_address);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_eth_destination_mac_address_mask(const struct ly_ctx *ly_ctx, struct lyd_node *eth_node, const char *destination_mac_address_mask)
{
    return srpc_ly_tree_create_leaf(ly_ctx, eth_node, NULL, "destination-mac-address-mask", destination_mac_address_mask);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_matches_eth_destination_mac_address(const struct ly_ctx *ly_ctx, struct lyd_node *eth_node, const char *destination_mac_address)
{
    return srpc_ly_tree_create_leaf(ly_ctx, eth_node, NULL, "destination-mac-address", destination_mac_address);
}

int onm_tc_ly_tree_create_acls_acl_aces_ace_name(const struct ly_ctx *ly_ctx, struct lyd_node *ace_node, const char *name)
{
    return srpc_ly_tree_create_leaf(ly_ctx, ace_node, NULL, "name", name);
}

int onm_tc_ly_tree_create_acls_acl_type(const struct ly_ctx *ly_ctx, struct lyd_node *acl_node, const char *type)
{
    return srpc_ly_tree_create_leaf(ly_ctx, acl_node, NULL, "type", type);
}

int onm_tc_ly_tree_create_acls_acl_name(const struct ly_ctx *ly_ctx, struct lyd_node *acl_node, const char *name)
{
    return srpc_ly_tree_create_leaf(ly_ctx, acl_node, NULL, "name", name);
}
