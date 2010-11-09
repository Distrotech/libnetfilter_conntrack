/*
 * (C) 2006-2007 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#include "internal/internal.h"

static int __snprintf_expect_proto(char *buf, 
				   unsigned int len,
				   const struct nf_expect *exp)
{
	 return(snprintf(buf, len, "%u proto=%d ", 
	 		 exp->timeout, 
			 exp->expected.tuple[__DIR_ORIG].protonum));
}

int __snprintf_expect_default(char *buf, 
			      unsigned int len,
			      const struct nf_expect *exp,
			      unsigned int msg_type,
			      unsigned int flags) 
{
	int ret = 0, size = 0, offset = 0;
	const char *delim = "";

	switch(msg_type) {
		case NFCT_T_NEW:
			ret = snprintf(buf, len, "%9s ", "[NEW]");
			break;
		case NFCT_T_UPDATE:
			ret = snprintf(buf, len, "%9s ", "[UPDATE]");
			break;
		case NFCT_T_DESTROY:
			ret = snprintf(buf, len, "%9s ", "[DESTROY]");
			break;
		default:
			break;
	}

	BUFFER_SIZE(ret, size, len, offset);

	ret = __snprintf_expect_proto(buf+offset, len, exp);
	BUFFER_SIZE(ret, size, len, offset);

	ret = __snprintf_address(buf+offset, len, &exp->expected.tuple[__DIR_ORIG]);
	BUFFER_SIZE(ret, size, len, offset);

	ret = __snprintf_proto(buf+offset, len, &exp->expected.tuple[__DIR_ORIG]);
	BUFFER_SIZE(ret, size, len, offset);

	if (test_bit(ATTR_EXP_ZONE, exp->set)) {
		ret = snprintf(buf+offset, len, "zone=%u ", exp->zone);
		BUFFER_SIZE(ret, size, len, offset);
	}

	if (exp->flags & NF_CT_EXPECT_PERMANENT) {
		ret = snprintf(buf+offset, len, "PERMANENT");
		BUFFER_SIZE(ret, size, len, offset);
		delim = ",";
	}
	if (exp->flags & NF_CT_EXPECT_INACTIVE) {
		ret = snprintf(buf+offset, len, "%sINACTIVE", delim);
		BUFFER_SIZE(ret, size, len, offset);
		delim = ",";
	}
	if (exp->flags & NF_CT_EXPECT_USERSPACE) {
		ret = snprintf(buf+offset, len, "%sUSERSPACE", delim);
		BUFFER_SIZE(ret, size, len, offset);
	}

	/* Delete the last blank space if needed */
	if (len > 0 && buf[size-1] == ' ')
		size--;

	return size;
}
