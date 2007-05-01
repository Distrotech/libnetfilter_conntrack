/*
 * (C) 2006-2007 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#include "internal.h"

static int __snprintf_expect_proto(char *buf, 
				   unsigned int len,
				   const struct nf_expect *exp)
{
	 return(snprintf(buf, len, "%u proto=%d ", 
	 		 exp->timeout, 
			 exp->expected.tuple[__DIR_ORIG].protonum));
}

int __snprintf_expect_default(char *buf, 
			      unsigned int remain,
			      const struct nf_expect *exp,
			      unsigned int msg_type,
			      unsigned int flags) 
{
	int ret = 0, size = 0;

	switch(msg_type) {
		case NFCT_T_NEW:
			ret = snprintf(buf, remain, "%9s ", "[NEW]");
			break;
		default:
			break;
	}

	if (ret == -1)
		return -1;
	size += ret;
	remain -= ret;

	ret = __snprintf_expect_proto(buf+size, remain, exp);
	if (ret == -1)
		return -1;
	size += ret;
	remain -= ret;

	ret = __snprintf_address(buf+size, remain, &exp->expected.tuple[__DIR_ORIG]);
	if (ret == -1)
		return -1;
	size += ret;
	remain -= ret;

	ret = __snprintf_proto(buf+size, remain, &exp->expected.tuple[__DIR_ORIG]);
	if (ret == -1)
		return -1;
	size += ret;
	remain -= ret;

	/* Delete the last blank space */
	size--;

	return size;
}
