/*
 * (C) 2008 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#include "internal/internal.h"
#include <linux/icmp.h>
#include <linux/icmpv6.h>

static const u_int8_t invmap_icmp[] = {
	[ICMP_ECHO]		= ICMP_ECHOREPLY + 1,
	[ICMP_ECHOREPLY]	= ICMP_ECHO + 1,
	[ICMP_TIMESTAMP]	= ICMP_TIMESTAMPREPLY + 1,
	[ICMP_TIMESTAMPREPLY]	= ICMP_TIMESTAMP + 1,
	[ICMP_INFO_REQUEST]	= ICMP_INFO_REPLY + 1,
	[ICMP_INFO_REPLY]	= ICMP_INFO_REQUEST + 1,
	[ICMP_ADDRESS]		= ICMP_ADDRESSREPLY + 1,
	[ICMP_ADDRESSREPLY]	= ICMP_ADDRESS + 1
};

#ifndef ICMPV6_NI_QUERY
#define ICMPV6_NI_QUERY 139
#endif

#ifndef ICMPV6_NI_REPLY
#define ICMPV6_NI_REPLY 140
#endif

static const u_int8_t invmap_icmpv6[] = {
	[ICMPV6_ECHO_REQUEST - 128]	= ICMPV6_ECHO_REPLY + 1,
	[ICMPV6_ECHO_REPLY - 128]	= ICMPV6_ECHO_REQUEST + 1,
	[ICMPV6_NI_QUERY - 128]		= ICMPV6_NI_QUERY + 1,
	[ICMPV6_NI_REPLY - 128]		= ICMPV6_NI_REPLY + 1
};

static void set_attr_grp_orig_ipv4(struct nf_conntrack *ct, const void *value)
{
	const struct nfct_attr_grp_ipv4 *this = value;
	ct->tuple[__DIR_ORIG].src.v4 = this->src;
	ct->tuple[__DIR_ORIG].dst.v4 = this->dst;
	ct->tuple[__DIR_ORIG].l3protonum = AF_INET;
}

static void set_attr_grp_repl_ipv4(struct nf_conntrack *ct, const void *value)
{
	const struct nfct_attr_grp_ipv4 *this = value;
	ct->tuple[__DIR_REPL].src.v4 = this->src;
	ct->tuple[__DIR_REPL].dst.v4 = this->dst;
	ct->tuple[__DIR_REPL].l3protonum = AF_INET;
}

static void set_attr_grp_orig_ipv6(struct nf_conntrack *ct, const void *value)
{
	const struct nfct_attr_grp_ipv6 *this = value;
	memcpy(&ct->tuple[__DIR_ORIG].src.v6, this->src, sizeof(u_int32_t)*4);
	memcpy(&ct->tuple[__DIR_ORIG].dst.v6, this->dst, sizeof(u_int32_t)*4);
	ct->tuple[__DIR_ORIG].l3protonum = AF_INET6;
}

static void set_attr_grp_repl_ipv6(struct nf_conntrack *ct, const void *value)
{
	const struct nfct_attr_grp_ipv6 *this = value;
	memcpy(&ct->tuple[__DIR_REPL].src.v6, this->src, sizeof(u_int32_t)*4);
	memcpy(&ct->tuple[__DIR_REPL].dst.v6, this->dst, sizeof(u_int32_t)*4);
	ct->tuple[__DIR_REPL].l3protonum = AF_INET6;
}

static void set_attr_grp_orig_port(struct nf_conntrack *ct, const void *value)
{
	const struct nfct_attr_grp_port *this = value;
	ct->tuple[__DIR_ORIG].l4src.all = this->sport;
	ct->tuple[__DIR_ORIG].l4dst.all = this->dport;
}

static void set_attr_grp_repl_port(struct nf_conntrack *ct, const void *value)
{
	const struct nfct_attr_grp_port *this = value;
	ct->tuple[__DIR_REPL].l4src.all = this->sport;
	ct->tuple[__DIR_REPL].l4dst.all = this->dport;
}

static void set_attr_grp_icmp(struct nf_conntrack *ct, const void *value)
{
	u_int8_t rtype;
	const struct nfct_attr_grp_icmp *this = value;

	ct->tuple[__DIR_ORIG].l4dst.icmp.type = this->type;

	switch(ct->tuple[__DIR_ORIG].l3protonum) {
		case AF_INET:
			rtype = invmap_icmp[this->type];
			break;

		case AF_INET6:
			rtype = invmap_icmpv6[this->type - 128];
			break;

		default:
			rtype = 0;	/* not found */
	}

	if (rtype)
		ct->tuple[__DIR_REPL].l4dst.icmp.type = rtype - 1;
	else
		ct->tuple[__DIR_REPL].l4dst.icmp.type = 255;	/* -EINVAL */

	ct->tuple[__DIR_ORIG].l4dst.icmp.code = this->code;
	ct->tuple[__DIR_REPL].l4dst.icmp.code = this->code;

	ct->tuple[__DIR_ORIG].l4src.icmp.id = this->id;
	ct->tuple[__DIR_REPL].l4src.icmp.id = this->id;
}

static void set_attr_grp_master_ipv4(struct nf_conntrack *ct, const void *value)
{
	const struct nfct_attr_grp_ipv4 *this = value;
	ct->tuple[__DIR_MASTER].src.v4 = this->src;
	ct->tuple[__DIR_MASTER].dst.v4 = this->dst;
	ct->tuple[__DIR_MASTER].l3protonum = AF_INET;
}

static void set_attr_grp_master_ipv6(struct nf_conntrack *ct, const void *value)
{
	const struct nfct_attr_grp_ipv6 *this = value;
	memcpy(&ct->tuple[__DIR_MASTER].src.v6, this->src, sizeof(u_int32_t)*4);
	memcpy(&ct->tuple[__DIR_MASTER].dst.v6, this->dst, sizeof(u_int32_t)*4);
	ct->tuple[__DIR_MASTER].l3protonum = AF_INET6;
}

static void set_attr_grp_master_port(struct nf_conntrack *ct, const void *value)
{
	const struct nfct_attr_grp_port *this = value;
	ct->tuple[__DIR_MASTER].l4src.all = this->sport;
	ct->tuple[__DIR_MASTER].l4dst.all = this->dport;
}

static void set_attr_grp_do_nothing(struct nf_conntrack *ct, const void *value)
{
}

const set_attr_grp set_attr_grp_array[ATTR_GRP_MAX] = {
	[ATTR_GRP_ORIG_IPV4]		= set_attr_grp_orig_ipv4,
	[ATTR_GRP_REPL_IPV4]		= set_attr_grp_repl_ipv4,
	[ATTR_GRP_ORIG_IPV6]		= set_attr_grp_orig_ipv6,
	[ATTR_GRP_REPL_IPV6]		= set_attr_grp_repl_ipv6,
	[ATTR_GRP_ORIG_PORT]		= set_attr_grp_orig_port,
	[ATTR_GRP_REPL_PORT]		= set_attr_grp_repl_port,
	[ATTR_GRP_ICMP]			= set_attr_grp_icmp,
	[ATTR_GRP_MASTER_IPV4]		= set_attr_grp_master_ipv4,
	[ATTR_GRP_MASTER_IPV6]		= set_attr_grp_master_ipv6,
	[ATTR_GRP_MASTER_PORT]		= set_attr_grp_master_port,
	[ATTR_GRP_ORIG_COUNTERS]	= set_attr_grp_do_nothing,
	[ATTR_GRP_REPL_COUNTERS]	= set_attr_grp_do_nothing,
};
