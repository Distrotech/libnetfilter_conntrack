/*
 * (C) 2006 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#include "internal/internal.h"

static void __autocomplete(struct nf_conntrack *ct, int dir)
{
	int other = (dir == __DIR_ORIG) ? __DIR_REPL : __DIR_ORIG;

	ct->tuple[dir].l3protonum = ct->tuple[other].l3protonum;
	ct->tuple[dir].protonum = ct->tuple[other].protonum;

	memcpy(&ct->tuple[dir].src.v6, 
	       &ct->tuple[other].dst.v6,
	       sizeof(union __nfct_address));
	memcpy(&ct->tuple[dir].dst.v6, 
	       &ct->tuple[other].src.v6,
	       sizeof(union __nfct_address));

	switch(ct->tuple[dir].protonum) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
	case IPPROTO_SCTP:
	case IPPROTO_DCCP:
	case IPPROTO_GRE:
	case IPPROTO_UDPLITE:
		ct->tuple[dir].l4src.all = ct->tuple[other].l4dst.all;
		ct->tuple[dir].l4dst.all = ct->tuple[other].l4src.all;
		break;
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		/* the setter already autocompletes the reply tuple. */
		break;
	}

	/* XXX: this is safe but better convert bitset to uint64_t */
        ct->set[0] |= TS_ORIG | TS_REPL;
}

static void setobjopt_undo_snat(struct nf_conntrack *ct)
{
	ct->snat.min_ip = ct->tuple[__DIR_REPL].dst.v4;
	ct->snat.max_ip = ct->snat.min_ip;
	ct->tuple[__DIR_REPL].dst.v4 = ct->tuple[__DIR_ORIG].src.v4;
	set_bit(ATTR_SNAT_IPV4, ct->set);
}

static void setobjopt_undo_dnat(struct nf_conntrack *ct)
{
	ct->dnat.min_ip = ct->tuple[__DIR_REPL].src.v4;
	ct->dnat.max_ip = ct->dnat.min_ip;
	ct->tuple[__DIR_REPL].src.v4 = ct->tuple[__DIR_ORIG].dst.v4;
	set_bit(ATTR_DNAT_IPV4, ct->set);
}

static void setobjopt_undo_spat(struct nf_conntrack *ct)
{
	ct->snat.l4min.all = ct->tuple[__DIR_REPL].l4dst.tcp.port;
	ct->snat.l4max.all = ct->snat.l4max.all;
	ct->tuple[__DIR_REPL].l4dst.tcp.port =
			ct->tuple[__DIR_ORIG].l4src.tcp.port;
	set_bit(ATTR_SNAT_PORT, ct->set);
}

static void setobjopt_undo_dpat(struct nf_conntrack *ct)
{
	ct->dnat.l4min.all = ct->tuple[__DIR_REPL].l4src.tcp.port;
	ct->dnat.l4max.all = ct->dnat.l4min.all;
	ct->tuple[__DIR_REPL].l4src.tcp.port =
			ct->tuple[__DIR_ORIG].l4dst.tcp.port;
	set_bit(ATTR_DNAT_PORT, ct->set);
}

static void setobjopt_setup_orig(struct nf_conntrack *ct)
{
	__autocomplete(ct, __DIR_ORIG);
}

static void setobjopt_setup_repl(struct nf_conntrack *ct)
{
	__autocomplete(ct, __DIR_REPL);
}

static const setobjopt setobjopt_array[__NFCT_SOPT_MAX] = {
	[NFCT_SOPT_UNDO_SNAT] 		= setobjopt_undo_snat,
	[NFCT_SOPT_UNDO_DNAT] 		= setobjopt_undo_dnat,
	[NFCT_SOPT_UNDO_SPAT] 		= setobjopt_undo_spat,
	[NFCT_SOPT_UNDO_DPAT] 		= setobjopt_undo_dpat,
	[NFCT_SOPT_SETUP_ORIGINAL] 	= setobjopt_setup_orig,
	[NFCT_SOPT_SETUP_REPLY]		= setobjopt_setup_repl,
};

int __setobjopt(struct nf_conntrack *ct, unsigned int option)
{
	if (unlikely(option > NFCT_SOPT_MAX))
		return -1;

	setobjopt_array[option](ct);
	return 0;
}

static int getobjopt_is_snat(const struct nf_conntrack *ct)
{
	return ((test_bit(ATTR_STATUS, ct->set) ?
		ct->status & IPS_SRC_NAT_DONE : 1) &&
		ct->tuple[__DIR_REPL].dst.v4 != 
		ct->tuple[__DIR_ORIG].src.v4);
}

static int getobjopt_is_dnat(const struct nf_conntrack *ct)
{
	return ((test_bit(ATTR_STATUS, ct->set) ?
		ct->status & IPS_DST_NAT_DONE : 1) &&
		ct->tuple[__DIR_REPL].src.v4 !=
		ct->tuple[__DIR_ORIG].dst.v4);
}

static int getobjopt_is_spat(const struct nf_conntrack *ct)
{
	return ((test_bit(ATTR_STATUS, ct->set) ?
		ct->status & IPS_SRC_NAT_DONE : 1) &&
		ct->tuple[__DIR_REPL].l4dst.tcp.port !=
		ct->tuple[__DIR_ORIG].l4src.tcp.port);
}

static int getobjopt_is_dpat(const struct nf_conntrack *ct)
{
	return ((test_bit(ATTR_STATUS, ct->set) ?
		ct->status & IPS_DST_NAT_DONE : 1) &&
		ct->tuple[__DIR_REPL].l4src.tcp.port !=
		ct->tuple[__DIR_ORIG].l4dst.tcp.port);
}

static const getobjopt getobjopt_array[__NFCT_GOPT_MAX] = {
	[NFCT_GOPT_IS_SNAT] = getobjopt_is_snat,
	[NFCT_GOPT_IS_DNAT] = getobjopt_is_dnat,
	[NFCT_GOPT_IS_SPAT] = getobjopt_is_spat,
	[NFCT_GOPT_IS_DPAT] = getobjopt_is_dpat,
};

int __getobjopt(const struct nf_conntrack *ct, unsigned int option)
{
	if (unlikely(option > NFCT_GOPT_MAX))
		return -1;

	return getobjopt_array[option](ct);
}
