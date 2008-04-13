/*
 * (C) 2008 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#include "internal.h"

#define TS_ORIG								\
({									\
	((1 << ATTR_ORIG_IPV4_SRC) | (1 << ATTR_ORIG_IPV4_DST) |	\
	 (1 << ATTR_ORIG_IPV6_SRC) | (1 << ATTR_ORIG_IPV6_DST) |	\
	 (1 << ATTR_ORIG_PORT_SRC) | (1 << ATTR_ORIG_PORT_DST) | 	\
	 (1 << ATTR_ORIG_L3PROTO)  | (1 << ATTR_ORIG_L4PROTO)  | 	\
	 (1 << ATTR_ICMP_TYPE)	   | (1 << ATTR_ICMP_CODE)     | 	\
	 (1 << ATTR_ICMP_ID));						\
})

#define TS_REPL								\
({									\
	((1 << ATTR_REPL_IPV4_SRC) | (1 << ATTR_REPL_IPV4_DST) | 	\
	 (1 << ATTR_REPL_IPV6_SRC) | (1 << ATTR_REPL_IPV6_DST) | 	\
	 (1 << ATTR_REPL_PORT_SRC) | (1 << ATTR_REPL_PORT_DST) | 	\
	 (1 << ATTR_REPL_L3PROTO)  | (1 << ATTR_REPL_L4PROTO)  |	\
	 (1 << ATTR_ICMP_TYPE)	   | (1 << ATTR_ICMP_CODE)     | 	\
	 (1 << ATTR_ICMP_ID));						\
})

#define TUPLE_SET(dir) (dir == __DIR_ORIG ? TS_ORIG : TS_REPL)

void __copy_tuple(struct nf_conntrack *ct2,
		  const struct nf_conntrack *ct1,
		  int dir)
{
	memcpy(&ct2->tuple[dir].src,
	       &ct1->tuple[dir].src,
	       sizeof(union __nfct_address));

	memcpy(&ct2->tuple[dir].dst,
	       &ct1->tuple[dir].dst,
	       sizeof(union __nfct_address));

	ct2->tuple[dir].l3protonum = ct1->tuple[dir].l3protonum;
	ct2->tuple[dir].protonum = ct1->tuple[dir].protonum;

	memcpy(&ct2->tuple[dir].l4src,
	       &ct1->tuple[dir].l4src,
	       sizeof(union __nfct_l4));

	memcpy(&ct2->tuple[dir].l4dst,
	       &ct1->tuple[dir].l4dst,
	       sizeof(union __nfct_l4));

	/* XXX: this is safe but better convert bitset to uint64_t */
	ct2->set[0] |= ct1->set[0] & TUPLE_SET(__DIR_ORIG);
}
