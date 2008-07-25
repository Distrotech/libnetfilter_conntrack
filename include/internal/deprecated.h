/*
 * WARNING: Do *NOT* ever include this file, only for internal use!
 */
#ifndef _NFCT_DEPRECATED_H_
#define _NFCT_DEPRECATED_H_

typedef int (*nfct_handler)(struct nfct_handle *cth, struct nlmsghdr *nlh,
			    void *arg);

/* some systems have old libc's */
#include <netinet/in.h>
#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP	132
#endif

#include "internal/linux_list.h"

/* extensions */
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
	int (*compare)(struct nfct_conntrack *, struct nfct_conntrack *,
		       unsigned int);
};

extern void nfct_register_proto(struct nfct_proto *h);

struct nfct_l3proto {
	struct list_head head;
	
	char 		*name;
	u_int16_t 	protonum;
	char		*version;
	
	void (*parse_proto)(struct nfattr **, struct nfct_tuple *);
	void (*build_tuple_proto)(struct nfnlhdr *, int, struct nfct_tuple *);
	int (*print_proto)(char *, struct nfct_tuple *);
	int (*compare)(struct nfct_conntrack *, struct nfct_conntrack *,
		       unsigned int);
};

extern void nfct_register_l3proto(struct nfct_l3proto *h);

/* backward compatibility of the deprecated API */
extern struct nfct_l3proto ipv4;
extern struct nfct_l3proto ipv6;

extern struct nfct_proto tcp;
extern struct nfct_proto udp;
extern struct nfct_proto sctp;
extern struct nfct_proto icmp;

extern void deprecated_backward_support();

#endif
