# ONM-TC-ACLs Sysrepo Plugin

## Overview

The Okda Network Manager Traffic Control Access Control Lists (ONM-TC-ACLs) is a Sysrepo plugin designed to configure the `ietf-access-control-lists` YANG module data into Linux TC (Traffic Control) filters. This plugin aims to facilitate the implementation of a fully functional access control lists control plane for Linux-based Network Operating Systems (NOSes).


## Getting Started

### Prerequisites
libyang  
sysrepo  
[sysrepo-plugins-common](https://github.com/telekom/sysrepo-plugins-common)  
[sysrepo-plugin-interfaces](https://github.com/telekom/sysrepo-plugin-interfaces)  

### Build

1. Clone the repository:
```
git clone https://github.com/okda-networks/onm-tc-acls.git
```
2. Navigate to the cloned directory and createa build directory:
```
cd onm-tc-acls/
mkdir build
cd build/
```

3. Compile and install the plugin:
```
cmake ..
make
```

## Installation

Before running the plugin, you need to ensure that ietf-access-lists yang module and its depenedencies are installed on sysrepo:
```
cd onm-tc-acls/
sysrepoctl -i ./yang/ietf-yang-types@2013-07-15.yang
sysrepoctl -i ./yang/ietf-inet-types@2013-07-15.yang
sysrepoctl -i ./yang/ietf-ethertypes@2019-03-04.yang
sysrepoctl -i ./yang/ietf-packet-fields@2019-03-04.yang
sysrepoctl -i ./yang/ietf-access-control-list@2019-03-04.yang
```
Then enable the access lists features on sysrepo:
```
sysrepoctl -c ietf-access-control-list --enable-feature eth
sysrepoctl -c ietf-access-control-list --enable-feature ipv4
sysrepoctl -c ietf-access-control-list --enable-feature ipv6
sysrepoctl -c ietf-access-control-list --enable-feature match-on-eth
sysrepoctl -c ietf-access-control-list --enable-feature match-on-ipv4
sysrepoctl -c ietf-access-control-list --enable-feature match-on-ipv6
sysrepoctl -c ietf-access-control-list --enable-feature match-on-tcp
sysrepoctl -c ietf-access-control-list --enable-feature match-on-udp
sysrepoctl -c ietf-access-control-list --enable-feature mixed-eth-ipv4
sysrepoctl -c ietf-access-control-list --enable-feature mixed-eth-ipv6
sysrepoctl -c ietf-access-control-list --enable-feature mixed-eth-ipv4-ipv6
sysrepoctl -c ietf-access-control-list --enable-feature interface-attachment
```

## Usage
1- Before running the onm-tc-acls plugin ensure to start [sysrepo-plugin-interfaces](https://github.com/telekom/sysrepo-plugin-interfaces) to update your system's interfaces to sysrepo running data store.  
2- Run onm-tc-acls with privilege access to linux netlink:
```
sudo ./onm-tc-acls
```
3- Any changes made to the `ietf-access-control-lists` module in Sysrepo will reflect in the Linux TC filter configuration.  
4- We recommend using [onmcli](https://github.com/okda-networks/onm-cli) for sysrepo switch like CLI configuration experiance.  

## Verify
- Please note that onm-tc-acls plugin configures acls to linux tc only they are applied to an interface (interface acl-set is configured on ietf-access-control-lists attachment points).  
- Since linux tc doesn't support configuring names to tc filers shared blacks, onm-tc-acls plugins converts every acl name to a unique ACL ID that then gets used on linux tc.  
- Below are some linux command examples to verify an acl with name acl1 and applied to an interface:  
a- check if the acl is applied to the desiged attachment point (interface):  
```
$ sudo tc qdisc show dev <interface_name> clsact 
qdisc clsact ffff: parent ffff:fff1 ingress_block <ingress_acl_id> egress_block <egress_acl_id> 
```
b- if the acl is applied to an interface, then it would be applied to linux tc as a shared block, use the following command to check it:
```
$ sudo tc filter show block <acl_id>
filter protocol ip pref 10 flower chain 0 
filter protocol ip pref 10 flower chain 0 handle 0x1 
  eth_type ipv4
  dst_ip 10.10.32.0/20
  not_in_hw
	action order 1: gact action pass
	 random type none pass val 0
	 index 1 ref 1 bind 1

filter protocol ipv6 pref 20 flower chain 0 
filter protocol ipv6 pref 20 flower chain 0 handle 0x1 
  src_mac 20:20:20:20:20:20/24
  eth_type ipv6
  src_ip 2603:300b:8c5::/64
  not_in_hw
	action order 1: gact action drop
	 random type none pass val 0
	 index 2 ref 1 bind 1
```

## Contributing

Contributions to the ONM-TC-ACLs Sysrepo Plugin are welcome.

## License



## Acknowledgments

- [Sysrepo](https://www.sysrepo.org/)
- [Telekom Open Source Software](https://github.com/telekom)

## Contact

Email: contact@okdanetworks.com 


## Features
The following are supported features from ietf-access-control-lists yang module:
```
   module: ietf-access-control-list
     +--rw acls
        +--rw acl* [name]
        |  +--rw name    supported
        |  +--rw type?    not supported
        |  +--rw aces
        |     +--rw ace* [name]    supported
        |        +--rw name    supported
        |        +--rw matches
        |        |  +--rw (l2)
        |        |  |  +--:(eth)
        |        |  |     +--rw eth {match-on-eth}    supported
        |        |  |        +--rw destination-mac-address    supported
        |        |  |        +--rw destination-mac-address-mask    supported
        |        |  |        +--rw source-mac-address     supported
        |        |  |        +--rw source-mac-address-mask     supported
        |        |  |        +--rw ethertype     needs enhacements

        |        |  +--rw (l3)?
        |        |  |  +--:(ipv4)
        |        |  |  |  +--rw ipv4 {match-on-ipv4}     supported
        |        |  |  |     +--rw dscp     not supported
        |        |  |  |     +--rw ecn      not supported
        |        |  |  |     +--rw length     not supported
        |        |  |  |     +--rw ttl     not supported
        |        |  |  |     +--rw protocol     supported
        |        |  |  |     +--rw ihl     not supported
        |        |  |  |     +--rw flags     not supported
        |        |  |  |     +--rw offset    not supported
        |        |  |  |     +--rw identification    not supported
        |        |  |  |     +--rw (destination-network)    supported
        |        |  |  |     +--rw (source-network)    supported
        |        |  |  +--:(ipv6)
        |        |  |     +--rw ipv6 {match-on-ipv6}    supported
        |        |  |        +--rw dscp    not supported
        |        |  |        +--rw ecn    not supported
        |        |  |        +--rw length    not supported
        |        |  |        +--rw ttl    not supported
        |        |  |        +--rw protocol    supported
        |        |  |        +--rw (destination-network)    supported
        |        |  |        +--rw (source-network)    supported
        |        |  |        +--rw flow-label    supported
        |        |  +--rw (l4)
        |        |  |  +--:(tcp)
        |        |  |  |  +--rw tcp {match-on-tcp}    supported
        |        |  |  |     +--rw sequence-number    not supported
        |        |  |  |     +--rw acknowledgement-number    not supported
        |        |  |  |     +--rw data-offset    not supported
        |        |  |  |     +--rw reserved    not supported
        |        |  |  |     +--rw flags    not supported
        |        |  |  |     +--rw window-size    not supported
        |        |  |  |     +--rw urgent-pointer    not supported
        |        |  |  |     +--rw options    not supported
        |        |  |  |     +--rw source-port    supported
        |        |  |  |     |  +--rw (source-port)    supported
        |        |  |  |     |     +--:(range-or-operator)    supported
        |        |  |  |     |           +--:(range)    supported
        |        |  |  |     |           +--:(operator)    supported
        |        |  |  |     +--rw destination-port    supported
        |        |  |  |        +--rw (destination-port)    supported
        |        |  |  |           +--:(range-or-operator)    supported
        |        |  |  |                 +--:(range)    supported
        |        |  |  |                 +--:(operator)    supported
        |        |  |  +--:(udp)
        |        |  |  |  +--rw udp {match-on-udp}
        |        |  |  |     +--rw length    not supported
        |        |  |  |     +--rw source-port    supported
        |        |  |  |     |  +--rw (source-port)    supported
        |        |  |  |     |     +--:(range-or-operator)    supported
        |        |  |  |     |           +--:(range)    supported
        |        |  |  |     |           +--:(operator)    supported
        |        |  |  |     +--rw destination-port    supported
        |        |  |  |        +--rw (destination-port)    supported
        |        |  |  |           +--:(range-or-operator)    supported
        |        |  |  |                 +--:(range)    supported
        |        |  |  |                 +--:(operator)    supported
        |        |  |  +--:(icmp)
        |        |  |     +--rw icmp {match-on-icmp}    not supported
        |        |  |        +--rw type    not supported
        |        |  |        +--rw code    not supported
        |        |  |        +--rw rest-of-header    not supported
        |        |  +--rw egress-interface    if:interface-ref
        |        |  +--rw ingress-interface    if:interface-ref
        |        +--rw actions
        |        |  +--rw forwarding    supported
        |        |  +--rw logging    not supported
        |        +--ro statistics {acl-aggregate-stats}
        |           +--ro matched-packets    not supported
        |           +--ro matched-octets    not supported
        +--rw attachment-points
           +--rw interface* [interface-id]
              +--rw interface-id    supported
              +--rw ingress    supported
              |  +--rw acl-sets
              |     +--rw acl-set* [name]    supported (only one acl-set per-interface)
              +--rw egress    supported
                 +--rw acl-sets
                    +--rw acl-set* [name]    supported (only one acl-set per-interface)
```
