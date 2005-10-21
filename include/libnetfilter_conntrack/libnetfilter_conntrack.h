/*
 * (C) 2005 by Pablo Neira Ayuso <pablo@eurodev.net>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#ifndef _LIBNETFILTER_CONNTRACK_H_
#define _LIBNETFILTER_CONNTRACK_H_

#include <netinet/in.h>
#include <asm/types.h>
#include <linux/if.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h> 
#include <libnfnetlink/libnfnetlink.h>
#include <linux/netfilter_ipv4/ip_conntrack.h>
#include "linux_list.h"

#define LIBNETFILTER_CONNTRACK_VERSION "0.1.2"

enum {
	CONNTRACK = NFNL_SUBSYS_CTNETLINK,
	EXPECT = NFNL_SUBSYS_CTNETLINK_EXP
};

union nfct_l4 {
	/* Add other protocols here. */
	u_int16_t all;
	struct {
		u_int16_t port;
	} tcp;
	struct {
		u_int16_t port;
	} udp;
	struct {
		u_int8_t type, code;
		u_int16_t id;
	} icmp;
	struct {
		u_int16_t port;
	} sctp;
};

struct nfct_tuple {
	union {
		u_int32_t v4;
		u_int64_t v6;
	} src;

	union {
		u_int32_t v4;
		u_int64_t v6;
	} dst;

	u_int8_t protonum;
	union nfct_l4 l4src;
	union nfct_l4 l4dst;
};

union nfct_protoinfo {
	struct {
		u_int8_t state;
	} tcp;
};

struct nfct_counters {
	u_int64_t packets;
	u_int64_t bytes;
};

struct nfct_nat {
	u_int32_t min_ip, max_ip;
	union nfct_l4 l4min, l4max;
};

#define NFCT_DIR_ORIGINAL 0
#define NFCT_DIR_REPLY 1
#define NFCT_DIR_MAX NFCT_DIR_REPLY+1

struct nfct_conntrack {
	struct nfct_tuple tuple[NFCT_DIR_MAX];
	
	unsigned long 	timeout;
	unsigned long	mark;
	unsigned int 	status;
	unsigned int	use;
	unsigned int	id;

	union nfct_protoinfo protoinfo;
	struct nfct_counters counters[NFCT_DIR_MAX];
	struct nfct_nat nat;
};

struct nfct_expect {
	struct nfct_tuple master;
	struct nfct_tuple tuple;
	struct nfct_tuple mask;
	unsigned long timeout;
	unsigned int id;
};

struct nfct_proto {
	struct list_head head;
	
	char 		*name;
	u_int8_t 	protonum;
	char		*version;
	
	void (*parse_proto)(struct nfattr **, struct nfct_tuple *);
	void (*parse_protoinfo)(struct nfattr **, struct nfct_conntrack *);
	int (*print_protoinfo)(char *, union nfct_protoinfo *);
	int (*print_proto)(char *, struct nfct_tuple *);
};

enum {
	NFCT_STATUS_BIT = 0,
	NFCT_STATUS = (NFCT_STATUS_BIT << 1),
	
	NFCT_PROTOINFO_BIT = 1,
	NFCT_PROTOINFO = (NFCT_PROTOINFO_BIT << 1),

	NFCT_TIMEOUT_BIT = 2,
	NFCT_TIMEOUT = (NFCT_TIMEOUT_BIT << 1),

	NFCT_MARK_BIT = 3,
	NFCT_MARK = (NFCT_MARK_BIT << 1),

	NFCT_COUNTERS_BIT = 4,
	NFCT_COUNTERS = (NFCT_COUNTERS_BIT << 1),

	NFCT_USE_BIT = 5,
	NFCT_USE = (NFCT_USE_BIT << 1),

	NFCT_ID_BIT = 6,
	NFCT_ID = (NFCT_ID_BIT << 1)
};

typedef void (*nfct_callback)(void *arg, unsigned int flags);

struct nfct_msg_handler {
	int type;
	int (*handler)(struct sockaddr_nl *, struct nlmsghdr *, void *arg);
};

struct nfct_handle {
	struct nfnl_handle nfnlh;
	nfct_callback callback;
	struct nfct_msg_handler *handler[IPCTNL_MSG_MAX];
};

extern struct nfct_conntrack *
nfct_conntrack_alloc(struct nfct_tuple *orig, struct nfct_tuple *reply,
		     unsigned long timeout, union nfct_protoinfo *proto,
		     unsigned int status, struct nfct_nat *range);
extern void nfct_conntrack_free(struct nfct_conntrack *ct);

extern struct nfct_expect *
nfct_expect_alloc(struct nfct_tuple *master, struct nfct_tuple *tuple,
		  struct nfct_tuple *mask, unsigned long timeout);
extern void nfct_expect_free(struct nfct_expect *exp);

extern void nfct_register_proto(struct nfct_proto *h);
extern void nfct_unregister_proto(struct nfct_proto *h);

extern struct nfct_handle *nfct_open(u_int8_t, unsigned);
extern int nfct_close(struct nfct_handle *cth);
extern void nfct_set_callback(struct nfct_handle *cth, nfct_callback callback);

/*
 * callback displayers
 */
extern void nfct_default_conntrack_display(void *arg, unsigned int flags); 
extern void nfct_default_expect_display(void *arg, unsigned int flags);

extern int nfct_create_conntrack(struct nfct_handle *cth, 
				 struct nfct_conntrack *ct);
extern int nfct_update_conntrack(struct nfct_handle *cth,
				 struct nfct_conntrack *ct);
extern int nfct_delete_conntrack(struct nfct_handle *cth, 
				 struct nfct_tuple *tuple, int dir);
extern int nfct_get_conntrack(struct nfct_handle *cth, 
			      struct nfct_tuple *tuple, int dir); 
extern int nfct_dump_conntrack_table(struct nfct_handle *cth);
extern int nfct_dump_conntrack_table_reset_counters(struct nfct_handle *cth);
extern int nfct_event_conntrack(struct nfct_handle *cth); 

/* 
 * Expectations
 */
extern int nfct_dump_expect_list(struct nfct_handle *cth);
extern int nfct_flush_conntrack_table(struct nfct_handle *cth);
extern int nfct_get_expectation(struct nfct_handle *cth,struct nfct_tuple *tuple);
extern int nfct_create_expectation(struct nfct_handle *cth, struct nfct_expect *);
extern int nfct_delete_expectation(struct nfct_handle *cth,struct nfct_tuple *tuple);
extern int nfct_event_expectation(struct nfct_handle *cth);
extern int nfct_flush_expectation_table(struct nfct_handle *cth);

#endif	/* _LIBNETFILTER_CONNTRACK_H_ */
