/* libctnetlink.h: Header file for the Connection Tracking library.
 *
 * Jay Schulist <jschlst@samba.org>, Copyright (c) 2001.
 * (C) 2002 by Harald Welte <laforge@gnumonks.org>
 * (C) 2005 by Pablo Neira Ayuso <pablo@eurodev.net>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#ifndef __LIBCTNETLINK_H
#define __LIBCTNETLINK_H

#include <netinet/in.h>
#include <asm/types.h>
#include <linux/if.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h> 

/* we need this for "enum ip_conntrack_status" */
#include <linux/netfilter_ipv4/ip_conntrack.h>

#include <libnfnetlink/libnfnetlink.h>

#define CTNL_BUFFSIZE	4096

union ctnl_l4 {
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

struct ctnl_tuple {
	union {
		u_int32_t v4;
		u_int64_t v6;
	} src;

	union {
		u_int32_t v4;
		u_int64_t v6;
	} dst;

	u_int8_t protonum;
	union ctnl_l4 l4src;
	union ctnl_l4 l4dst;
};

union ctnl_protoinfo {
	struct {
		u_int8_t state;
	} tcp;
};

struct ctnl_counters {
	u_int64_t packets;
	u_int64_t bytes;
};

struct ctnl_nat {
	u_int32_t min_ip, max_ip;
	union ctnl_l4 l4min, l4max;
};

#define CTNL_DIR_ORIGINAL 0
#define CTNL_DIR_REPLY 1
#define CTNL_DIR_MAX CTNL_DIR_REPLY+1

struct ctnl_conntrack {
	struct ctnl_tuple tuple[CTNL_DIR_MAX];
	
	unsigned long 	timeout;
	unsigned long	mark;
	unsigned int 	status;
	unsigned int	use;
	unsigned int	id;

	union ctnl_protoinfo protoinfo;
	struct ctnl_counters counters[CTNL_DIR_MAX];
	struct ctnl_nat nat;
};

struct ctnl_msg_handler {
	int type;
	int (*handler)(struct sockaddr_nl *, struct nlmsghdr *, void *arg);
};

struct ctnl_handle {
	struct nfnl_handle nfnlh;
	struct ctnl_msg_handler *handler[IPCTNL_MSG_MAX];
};

extern int ctnl_open(struct ctnl_handle *, u_int8_t, unsigned);
extern int ctnl_close(struct ctnl_handle *);
extern int ctnl_unregister_handler(struct ctnl_handle *, int);
extern int ctnl_register_handler(struct ctnl_handle *, 
				 struct ctnl_msg_handler *);
extern int ctnl_new_conntrack(struct ctnl_handle *, struct ctnl_conntrack *);
extern int ctnl_upd_conntrack(struct ctnl_handle *, struct ctnl_conntrack *);
extern int ctnl_get_conntrack(struct ctnl_handle *, struct ctnl_tuple *, int);
extern int ctnl_del_conntrack(struct ctnl_handle *, struct ctnl_tuple *, int);
extern int ctnl_list_conntrack(struct ctnl_handle *, int);
extern int ctnl_list_conntrack_zero_counters(struct ctnl_handle *, int);
extern int ctnl_event_conntrack(struct ctnl_handle *, int);
extern int ctnl_flush_conntrack(struct ctnl_handle *);

extern int ctnl_new_expect(struct ctnl_handle *, struct ctnl_tuple *, 
			   struct ctnl_tuple *, struct ctnl_tuple *, 
			   unsigned long);
extern int ctnl_del_expect(struct ctnl_handle *,struct ctnl_tuple *);
extern int ctnl_get_expect(struct ctnl_handle *, struct ctnl_tuple *);
extern int ctnl_list_expect(struct ctnl_handle *, int);
extern int ctnl_event_expect(struct ctnl_handle *, int);
extern int ctnl_flush_expect(struct ctnl_handle *);

extern int ctnl_send(struct ctnl_handle *, struct nlmsghdr *);
extern int ctnl_wilddump_request(struct ctnl_handle *, int , int);

#endif	/* __LIBCTNETLINK_H */
