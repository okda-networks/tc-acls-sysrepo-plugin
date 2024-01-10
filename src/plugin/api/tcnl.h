#include "plugin/context.h"
#include <linux/if_ether.h>
#include <netlink/msg.h>
#include <errno.h>
#include "plugin/common.h"
#include "utlist.h"
#include <linux/tc_act/tc_gact.h>

#define TCA_BUF_MAX	(64*1024)
#define MAX_MSG 16384 // for tcmsg
#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

struct proto {
	int id;
	const char *name;
};

#define __PF(f,n) { ETH_P_##f, #n },

static const struct proto llproto_names[] = {
__PF(LOOP,loop)
__PF(PUP,pup)
__PF(PUPAT,pupat)
__PF(IP,ip)
__PF(X25,x25)
__PF(ARP,arp)
__PF(BPQ,bpq)
__PF(IEEEPUP,ieeepup)
__PF(IEEEPUPAT,ieeepupat)
__PF(DEC,dec)
__PF(DNA_DL,dna_dl)
__PF(DNA_RC,dna_rc)
__PF(DNA_RT,dna_rt)
__PF(LAT,lat)
__PF(DIAG,diag)
__PF(CUST,cust)
__PF(SCA,sca)
__PF(RARP,rarp)
__PF(ATALK,atalk)
__PF(AARP,aarp)
__PF(IPX,ipx)
__PF(IPV6,ipv6)
__PF(PPP_DISC,ppp_disc)
__PF(PPP_SES,ppp_ses)
__PF(ATMMPOA,atmmpoa)
__PF(ATMFATE,atmfate)
__PF(802_3,802_3)
__PF(AX25,ax25)
__PF(ALL,all)
__PF(802_2,802_2)
__PF(SNAP,snap)
__PF(DDCMP,ddcmp)
__PF(WAN_PPP,wan_ppp)
__PF(PPP_MP,ppp_mp)
__PF(LOCALTALK,localtalk)
__PF(CAN,can)
__PF(PPPTALK,ppptalk)
__PF(TR_802_2,tr_802_2)
__PF(MOBITEX,mobitex)
__PF(CONTROL,control)
__PF(IRDA,irda)
__PF(ECONET,econet)
__PF(TIPC,tipc)

__PF(AOE,aoe)

__PF(8021Q,802.1Q)
__PF(8021AD,802.1ad)
__PF(MPLS_UC,mpls_uc)
__PF(MPLS_MC,mpls_mc)
__PF(TEB,teb)


{ 0x8100, "802.1Q" },
{ 0x8100, "vlan" },
{ 0x88cc, "LLDP" },
{ ETH_P_IP, "ipv4" },
};
#undef __PF



struct nl_request {
    struct nlmsghdr nlh;
    struct tcmsg tcm;
    char buf[TCA_BUF_MAX];
};


bool tcnl_tc_block_exists(onm_tc_nl_ctx_t* nl_ctx,unsigned int block_index);
int tcnl_block_modify(onm_tc_acl_hash_element_t * acls_hash, unsigned int acl_id, onm_tc_ctx_t * ctx, int request_type, unsigned int flags);
int tcnl_qdisc_modify(onm_tc_ctx_t * ctx, int request_type, char * qdisc_kind, int if_idx, uint32_t ingress_block_id, uint32_t egress_block_id, bool override);
int tcnl_filter_modify(onm_tc_ctx_t * ctx, onm_tc_ace_element_t* ace, unsigned int acl_id,unsigned int request_type, unsigned int flags, bool override_exisitng);
int ll_proto_a2n(unsigned short *id, const char *buf);


int tcnl_set_qdisc_msg(struct nl_msg** msg, int request_type, unsigned int flags, char * qdisc_kind, int if_idx, uint32_t ingress_block_id, uint32_t egress_block_id);

bool tcnl_block_exists(onm_tc_ctx_t * ctx, unsigned int acl_id);
int tcnl_talk(struct nl_msg** msg, onm_tc_ctx_t * ctx, void * rcv_callback, bool msg_clear);