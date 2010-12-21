/*
 * (C) 2008 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#include "internal/internal.h"

static void get_attr_grp_orig_ipv4(const struct nf_conntrack *ct, void *data)
{
	struct nfct_attr_grp_ipv4 *this = data;
	this->src = ct->tuple[__DIR_ORIG].src.v4;
	this->dst = ct->tuple[__DIR_ORIG].dst.v4;
}

static void get_attr_grp_repl_ipv4(const struct nf_conntrack *ct, void *data)
{
	struct nfct_attr_grp_ipv4 *this = data;
	this->src = ct->tuple[__DIR_REPL].src.v4;
	this->dst = ct->tuple[__DIR_REPL].dst.v4;
}

static void get_attr_grp_orig_ipv6(const struct nf_conntrack *ct, void *data)
{
	struct nfct_attr_grp_ipv6 *this = data;
	memcpy(this->src, &ct->tuple[__DIR_ORIG].src.v6, sizeof(u_int32_t)*4);
	memcpy(this->dst, &ct->tuple[__DIR_ORIG].dst.v6, sizeof(u_int32_t)*4);
}

static void get_attr_grp_repl_ipv6(const struct nf_conntrack *ct, void *data)
{
	struct nfct_attr_grp_ipv6 *this = data;
	memcpy(this->src, &ct->tuple[__DIR_REPL].src.v6, sizeof(u_int32_t)*4);
	memcpy(this->dst, &ct->tuple[__DIR_REPL].dst.v6, sizeof(u_int32_t)*4);
}

static void get_attr_grp_orig_port(const struct nf_conntrack *ct, void *data)
{
	struct nfct_attr_grp_port *this = data;
	this->sport = ct->tuple[__DIR_ORIG].l4src.all;
	this->dport = ct->tuple[__DIR_ORIG].l4dst.all;
}

static void get_attr_grp_repl_port(const struct nf_conntrack *ct, void *data)
{
	struct nfct_attr_grp_port *this = data;
	this->sport = ct->tuple[__DIR_REPL].l4src.all;
	this->dport = ct->tuple[__DIR_REPL].l4dst.all;
}

static void get_attr_grp_icmp(const struct nf_conntrack *ct, void *data)
{
	struct nfct_attr_grp_icmp *this = data;
	this->type = ct->tuple[__DIR_ORIG].l4dst.icmp.type;
	this->code = ct->tuple[__DIR_ORIG].l4dst.icmp.code;
	this->id = ct->tuple[__DIR_ORIG].l4src.icmp.id;
}

static void get_attr_grp_master_ipv4(const struct nf_conntrack *ct, void *data)
{
	struct nfct_attr_grp_ipv4 *this = data;
	this->src = ct->tuple[__DIR_MASTER].src.v4;
	this->dst = ct->tuple[__DIR_MASTER].dst.v4;
}

static void get_attr_grp_master_ipv6(const struct nf_conntrack *ct, void *data)
{
	struct nfct_attr_grp_ipv6 *this = data;
	memcpy(this->src, &ct->tuple[__DIR_MASTER].src.v6, sizeof(u_int32_t)*4);
	memcpy(this->dst, &ct->tuple[__DIR_MASTER].dst.v6, sizeof(u_int32_t)*4);
}

static void get_attr_grp_master_port(const struct nf_conntrack *ct, void *data)
{
	struct nfct_attr_grp_port *this = data;
	this->sport = ct->tuple[__DIR_MASTER].l4src.all;
	this->dport = ct->tuple[__DIR_MASTER].l4dst.all;
}

static void get_attr_grp_orig_ctrs(const struct nf_conntrack *ct, void *data)
{
	struct nfct_attr_grp_ctrs *this = data;
	this->packets = ct->counters[__DIR_ORIG].packets;
	this->bytes = ct->counters[__DIR_ORIG].bytes;
}

static void get_attr_grp_repl_ctrs(const struct nf_conntrack *ct, void *data)
{
	struct nfct_attr_grp_ctrs *this = data;
	this->packets = ct->counters[__DIR_REPL].packets;
	this->bytes = ct->counters[__DIR_REPL].bytes;
}

const get_attr_grp get_attr_grp_array[ATTR_GRP_MAX] = {
	[ATTR_GRP_ORIG_IPV4]		= get_attr_grp_orig_ipv4,
	[ATTR_GRP_REPL_IPV4]		= get_attr_grp_repl_ipv4,
	[ATTR_GRP_ORIG_IPV6]		= get_attr_grp_orig_ipv6,
	[ATTR_GRP_REPL_IPV6]		= get_attr_grp_repl_ipv6,
	[ATTR_GRP_ORIG_PORT]		= get_attr_grp_orig_port,
	[ATTR_GRP_REPL_PORT]		= get_attr_grp_repl_port,
	[ATTR_GRP_ICMP]			= get_attr_grp_icmp,
	[ATTR_GRP_MASTER_IPV4]		= get_attr_grp_master_ipv4,
	[ATTR_GRP_MASTER_IPV6]		= get_attr_grp_master_ipv6,
	[ATTR_GRP_MASTER_PORT]		= get_attr_grp_master_port,
	[ATTR_GRP_ORIG_COUNTERS]	= get_attr_grp_orig_ctrs,
	[ATTR_GRP_REPL_COUNTERS]	= get_attr_grp_repl_ctrs
};
