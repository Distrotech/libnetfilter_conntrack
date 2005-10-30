/*
 * (C) 2005 by Pablo Neira Ayuso <pablo@eurodev.net>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#ifndef _LIBNETFILTER_CONNTRACK_EXTENSIONS_H_
#define _LIBNETFILTER_CONNTRACK_EXTENSIONS_H_

#include "linux_list.h"

struct nfct_proto {
	struct list_head head;
	
	char 		*name;
	u_int8_t 	protonum;
	char		*version;
	
	void (*parse_proto)(struct nfattr **, struct nfct_tuple *);
	void (*parse_protoinfo)(struct nfattr **, struct nfct_conntrack *);
	void (*build_tuple_proto)(struct nfnlhdr *, int, struct nfct_tuple *);
	void (*build_protoinfo)(struct nfnlhdr *, int, struct nfct_conntrack *);
	int (*print_protoinfo)(char *, union nfct_protoinfo *);
	int (*print_proto)(char *, struct nfct_tuple *);
};

extern void nfct_register_proto(struct nfct_proto *h);

#endif
