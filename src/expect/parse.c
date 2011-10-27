/*
 * (C) 2006-2007 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#include "internal/internal.h"

int __parse_expect_message_type(const struct nlmsghdr *nlh)
{
	u_int16_t type = NFNL_MSG_TYPE(nlh->nlmsg_type);
	u_int16_t flags = nlh->nlmsg_flags;
	int ret = NFCT_T_UNKNOWN;

	if (type == IPCTNL_MSG_EXP_NEW) {
		if (flags & (NLM_F_CREATE|NLM_F_EXCL))
			ret = NFCT_T_NEW;
		else
			ret = NFCT_T_UPDATE;
	} else if (type == IPCTNL_MSG_EXP_DELETE)
		ret = NFCT_T_DESTROY;

	return ret;
}

void __parse_expect(const struct nlmsghdr *nlh,
		    struct nfattr *cda[],
		    struct nf_expect *exp)
{
	struct nfgenmsg *nfhdr = NLMSG_DATA(nlh);

	/* XXX: this is ugly, clean it up, please */
	exp->expected.tuple[__DIR_ORIG].l3protonum = nfhdr->nfgen_family;
	set_bit(ATTR_ORIG_L3PROTO, exp->expected.set);

	exp->mask.tuple[__DIR_REPL].l3protonum = nfhdr->nfgen_family;
	set_bit(ATTR_ORIG_L3PROTO, exp->mask.set);

	if (cda[CTA_EXPECT_MASTER-1]) {
		__parse_tuple(cda[CTA_EXPECT_MASTER-1], 
			      &exp->master.tuple[__DIR_ORIG],
			      __DIR_ORIG,
			      exp->master.set);
		set_bit(ATTR_EXP_MASTER, exp->set);
	}
	if (cda[CTA_EXPECT_TUPLE-1]) {
		__parse_tuple(cda[CTA_EXPECT_TUPLE-1], 
			      &exp->expected.tuple[__DIR_ORIG],
			      __DIR_ORIG,
			      exp->expected.set);
		set_bit(ATTR_EXP_EXPECTED, exp->set);
	}
	if (cda[CTA_EXPECT_MASK-1]) {
		__parse_tuple(cda[CTA_EXPECT_MASK-1], 
			      &exp->mask.tuple[__DIR_ORIG], 
			      __DIR_ORIG,
			      exp->mask.set);
		set_bit(ATTR_EXP_MASK, exp->set);
	}
	if (cda[CTA_EXPECT_TIMEOUT-1]) {
		exp->timeout = 
		      ntohl(*(u_int32_t *)NFA_DATA(cda[CTA_EXPECT_TIMEOUT-1]));
		set_bit(ATTR_EXP_TIMEOUT, exp->set);
	}

	if (cda[CTA_EXPECT_ZONE-1]) {
		exp->zone =
		      ntohs(*(u_int16_t *)NFA_DATA(cda[CTA_EXPECT_ZONE-1]));
		set_bit(ATTR_EXP_ZONE, exp->set);
	}
	if (cda[CTA_EXPECT_FLAGS-1]) {
		exp->flags =
		      ntohl(*(u_int32_t *)NFA_DATA(cda[CTA_EXPECT_FLAGS-1]));
		set_bit(ATTR_EXP_FLAGS, exp->set);
	}
}
