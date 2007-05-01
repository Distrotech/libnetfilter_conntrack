/*
 * (C) 2006-2007 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#include "internal.h"

static void __build_timeout(struct nfnlhdr *req,
			    size_t size,
			    const struct nf_expect *exp)
{
	nfnl_addattr32(&req->nlh, size, CTA_EXPECT_TIMEOUT,htonl(exp->timeout));
}

int __build_expect(struct nfnl_subsys_handle *ssh,
		   struct nfnlhdr *req,
		   size_t size,
		   u_int16_t type,
		   u_int16_t flags,
		   const struct nf_expect *exp)
{
	u_int8_t l3num = exp->master.tuple[NFCT_DIR_ORIGINAL].l3protonum;

	if (!test_bit(ATTR_ORIG_L3PROTO, exp->master.set)) {
		errno = EINVAL;
		return -1;
	}

	memset(req, 0, size);

	nfnl_fill_hdr(ssh, &req->nlh, 0, l3num, 0, type, flags);

	__build_tuple(req,
		      size,
		      &exp->expected.tuple[__DIR_ORIG],
		      CTA_EXPECT_TUPLE);

	/* get and delete only require the expectation tuple */
	if (type == IPCTNL_MSG_EXP_GET || type == IPCTNL_MSG_EXP_DELETE)
		return 0;

	__build_tuple(req,
		      size,
		      &exp->master.tuple[__DIR_ORIG],
		      CTA_EXPECT_MASTER);
	
	__build_tuple(req,
		      size,
		      &exp->mask.tuple[__DIR_ORIG],
		      CTA_EXPECT_MASK);

	if (test_bit(ATTR_EXP_TIMEOUT, exp->set))
		__build_timeout(req, size, exp);

	return 0;
}
