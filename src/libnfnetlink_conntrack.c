/* libctnetlink.c: generic library for access to connection tracking.
 *
 * (C) 2001 by Jay Schulist <jschlst@samba.org>
 * (C) 2002-2005 by Harald Welte <laforge@gnumonks.org>
 * (C) 2005 by Pablo Neira Ayuso <pablo@eurodev.net>
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com)
 *
 * this software may be used and distributed according to the terms
 * of the gnu general public license, incorporated herein by reference.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <asm/types.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

#include <libnfnetlink/libnfnetlink.h>
#include <libnfnetlink_conntrack/libnfnetlink_conntrack.h>

#define ctnl_error printf

/***********************************************************************
 * low level stuff 
 ***********************************************************************/
int ctnl_send(struct ctnl_handle *cth, struct nlmsghdr *n)
{
	return nfnl_send(&cth->nfnlh, n);
}

int ctnl_wilddump_request(struct ctnl_handle *cth, int family, int type)
{
        struct {
                struct nlmsghdr nlh;
                struct nfgenmsg g;
        } req;

	nfnl_fill_hdr(&cth->nfnlh, &req.nlh, 0, AF_INET, 0,
		      type, NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST);

	return nfnl_send(&cth->nfnlh, &req.nlh);
}

/* handler used for nfnl_listen */
static int list_conntrack_handler(struct sockaddr_nl *nladdr, 
				  struct nlmsghdr *n, void *arg)
{
	struct ctnl_handle *cth = (struct ctnl_handle *) arg;
	int type = NFNL_MSG_TYPE(n->nlmsg_type);
	struct ctnl_msg_handler *hdlr = cth->handler[type];
	int ret;

	if (NFNL_SUBSYS_ID(n->nlmsg_type) != NFNL_SUBSYS_CTNETLINK) {
		ctnl_error("received message for wrong subsys, skipping\n");
		nfnl_dump_packet(n, n->nlmsg_len, "list_conntrack_handler");
		return 0;
	}

	if (!hdlr) {
		ctnl_error("no handler for type %d\n", type);
		return 0;
	}

	if (!hdlr->handler) {
		ctnl_error("no handler function for type %d\n", type);
		return 0;
	}

	ret = hdlr->handler(nladdr, n, arg);

	return ret;
}

/***********************************************************************
 * high level stuff 
 ***********************************************************************/

/**
 * ctnl_open - open a libctnetlink handle
 *
 * cth: pointer to already allocated library handle
 * subscriptions: netlink groups we are interested in
 */
int ctnl_open(struct ctnl_handle *cth, unsigned subscriptions)
{
	int err;

	memset(cth, 0, sizeof(*cth));

	err = nfnl_open(&cth->nfnlh, NFNL_SUBSYS_CTNETLINK, subscriptions);
	if (err < 0) {
		return err;
	}

	return 0;
}

/**
 * ctnl_close - close a libctnetlink handle
 *
 * cth: libctnetlink handle
 */
int ctnl_close(struct ctnl_handle *cth)
{
	int err;

	err = nfnl_close(&cth->nfnlh);

	return err;
}

/* ctnl_register_handler - register handler for ctnetlink mesage type
 *
 * cth: libctnetlink handle
 * hndlr: handler structure
 */
int ctnl_register_handler(struct ctnl_handle *cth, 
			  struct ctnl_msg_handler *hndlr)
{
	if (hndlr->type >= IPCTNL_MSG_MAX)
		return -EINVAL;

	cth->handler[hndlr->type] = hndlr;
	
	return 0;
}

/**
 * ctnl_unregister_handler - unregister handler for ctnetlink msgtype
 *
 * cth: libctnetlink handle
 * type: message type
 */
int ctnl_unregister_handler(struct ctnl_handle *cth, int type)
{
	if (type >= IPCTNL_MSG_MAX)
		return -EINVAL;

	cth->handler[type] = NULL;
	return 0;
}

int ctnl_flush_conntrack(struct ctnl_handle *cth)
{
	struct {
		struct nlmsghdr nlh;
		struct nfgenmsg g;
	} *req;

	char buf[sizeof(*req)];
	memset(&buf, 0, sizeof(buf));

	req = (void *) &buf;

	nfnl_fill_hdr(&cth->nfnlh, (struct nlmsghdr *) &buf,
			0, AF_INET, 0, IPCTNL_MSG_CT_DELETE,
			NLM_F_REQUEST|NLM_F_ACK);

	if (nfnl_send(&cth->nfnlh, (struct nlmsghdr *)&buf) < 0 )
		return -1;

	return nfnl_listen(&cth->nfnlh, &list_conntrack_handler, cth);
}

/**
 * ctnl_list_conntrack - list connection tracking table
 * cth: libctnetlink handle
 * family: AF_INET, ...
 */
int ctnl_list_conntrack(struct ctnl_handle *cth, int family)
{
	if (ctnl_wilddump_request(cth, family, IPCTNL_MSG_CT_GET) < 0)
		return -1;

	return nfnl_listen(&cth->nfnlh, &list_conntrack_handler, cth);
}

int ctnl_list_conntrack_zero_counters(struct ctnl_handle *cth, int family)
{
	if (ctnl_wilddump_request(cth, family, IPCTNL_MSG_CT_GET_CTRZERO) < 0)
		return -1;

	return nfnl_listen(&cth->nfnlh, &list_conntrack_handler, cth);
}

int ctnl_event_conntrack(struct ctnl_handle *cth, int family)
{
	return nfnl_listen(&cth->nfnlh, &list_conntrack_handler, cth);
}

struct nfnlhdr {
	struct nlmsghdr nlh;
	struct nfgenmsg nfmsg;
}; 

static void ctnl_build_tuple_ip(struct nfnlhdr *req, int size,
			        struct ctnl_tuple *t)
{
	struct nfattr *nest;

	nest = nfnl_nest(&req->nlh, size, CTA_TUPLE_IP);

	nfnl_addattr_l(&req->nlh, size, CTA_IP_V4_SRC, &t->src.v4, 
		       sizeof(u_int32_t));

	nfnl_addattr_l(&req->nlh, size, CTA_IP_V4_DST, &t->dst.v4,
		       sizeof(u_int32_t));

	nfnl_nest_end(&req->nlh, nest);
}

static void ctnl_build_tuple_proto(struct nfnlhdr *req, int size,
				   struct ctnl_tuple *t)
{
	struct nfattr *nest;

	nest = nfnl_nest(&req->nlh, size, CTA_TUPLE_PROTO);

	nfnl_addattr_l(&req->nlh, size, CTA_PROTO_NUM, &t->protonum,
		       sizeof(u_int16_t));

	switch(t->protonum) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_SCTP:
		nfnl_addattr_l(&req->nlh, size, CTA_PROTO_SRC_PORT,
			       &t->l4src.tcp.port, sizeof(u_int16_t));
		nfnl_addattr_l(&req->nlh, size, CTA_PROTO_DST_PORT,
			       &t->l4dst.tcp.port, sizeof(u_int16_t));
		break;
	case IPPROTO_ICMP:
		nfnl_addattr_l(&req->nlh, size, CTA_PROTO_ICMP_CODE,
			       &t->l4src.icmp.code, sizeof(u_int8_t));
		nfnl_addattr_l(&req->nlh, size, CTA_PROTO_ICMP_TYPE,
			       &t->l4dst.icmp.type, sizeof(u_int8_t));
		break;
	}
	nfnl_nest_end(&req->nlh, nest);
}

static void ctnl_build_tuple(struct nfnlhdr *req, int size, 
			     struct ctnl_tuple *t, int dir)
{
	enum ctattr_type type = dir ? CTA_TUPLE_REPLY : CTA_TUPLE_ORIG;
	struct nfattr *nest;

	nest = nfnl_nest(&req->nlh, size, type);

	ctnl_build_tuple_ip(req, size, t);
	ctnl_build_tuple_proto(req, size, t);

	nfnl_nest_end(&req->nlh, nest);
}

static void ctnl_build_protoinfo(struct nfnlhdr *req, int size,
				 struct ctnl_conntrack *ct)
{
	struct nfattr *nest;
	
	nest = nfnl_nest(&req->nlh, size, CTA_PROTOINFO);

	switch (ct->tuple[CTNL_DIR_ORIGINAL].protonum) {
	case IPPROTO_TCP:
		nfnl_addattr_l(&req->nlh, size, CTA_PROTOINFO_TCP_STATE,
			       &ct->protoinfo.tcp.state, sizeof(u_int8_t));
		break;
	}

	nfnl_nest_end(&req->nlh, nest);
}

static void ctnl_build_protonat(struct nfnlhdr *req, int size,
				 struct ctnl_conntrack *ct)
{
	struct nfattr *nest;
	
	nest = nfnl_nest(&req->nlh, size, CTA_NAT_PROTO);

	switch (ct->tuple[CTNL_DIR_ORIGINAL].protonum) {
#if 0
	case IPPROTO_TCP:
		nfnl_addattr_l(&req->nlh, size, CTA_PROTONAT_TCP_MIN,
			       &ct->nat.l4min.tcp.port, sizeof(u_int16_t));
		nfnl_addattr_l(&req->nlh, size, CTA_PROTONAT_TCP_MAX,
			       &ct->nat.l4max.tcp.port, sizeof(u_int16_t));
		break;
	case IPPROTO_UDP:
		nfnl_addattr_l(&req->nlh, size, CTA_PROTONAT_UDP_MIN,
			       &ct->nat.l4min.udp.port, sizeof(u_int16_t));
		nfnl_addattr_l(&req->nlh, size, CTA_PROTONAT_UDP_MAX,
			       &ct->nat.l4max.udp.port, sizeof(u_int16_t));
		break;
#endif
	}
	nfnl_nest_end(&req->nlh, nest);
}

static void ctnl_build_nat(struct nfnlhdr *req, int size,
			   struct ctnl_conntrack *ct)
{
	struct nfattr *nest;

	nest = nfnl_nest(&req->nlh, size, CTA_NAT);

	nfnl_addattr_l(&req->nlh, size, CTA_NAT_MINIP,
		       &ct->nat.min_ip, sizeof(u_int32_t));
	
	if (ct->nat.min_ip != ct->nat.max_ip)
		nfnl_addattr_l(&req->nlh, size, CTA_NAT_MAXIP,
			       &ct->nat.max_ip, sizeof(u_int32_t));

	if (ct->nat.l4min.all != ct->nat.l4max.all)
		ctnl_build_protonat(req, size, ct);

	nfnl_nest_end(&req->nlh, nest);
}

static void ctnl_build_conntrack(struct nfnlhdr *req, int size, 
				 struct ctnl_conntrack *ct)
{
	ctnl_build_tuple(req, size, &ct->tuple[CTNL_DIR_ORIGINAL], 
			 CTNL_DIR_ORIGINAL);
	ctnl_build_tuple(req, size, &ct->tuple[CTNL_DIR_REPLY],
			 CTNL_DIR_REPLY);
	
	nfnl_addattr_l(&req->nlh, size, CTA_STATUS, &ct->status, 
		       sizeof(unsigned int));
	nfnl_addattr_l(&req->nlh, size, CTA_TIMEOUT, &ct->timeout, 
		       sizeof(unsigned long));

	ctnl_build_protoinfo(req, size, ct);
	if (ct->nat.min_ip != 0)
		ctnl_build_nat(req, size, ct);
}

/**
 * ctnl_get_conntrack - get a connection from conntrack hashtable
 * cth: libctnetlink handle
 * t: tuple of connection to get
 * cb: a struct nfattr to put the connection in
 */
int ctnl_get_conntrack(struct ctnl_handle *cth, 
		       struct ctnl_tuple *tuple,
		       int dir)
{
	struct nfnlhdr *req;
	char buf[CTNL_BUFFSIZE];
	
	memset(&buf, 0, sizeof(buf));
	req = (void *) &buf;

	nfnl_fill_hdr(&cth->nfnlh, (struct nlmsghdr *) &buf,
			0, AF_INET, 0, IPCTNL_MSG_CT_GET,
			NLM_F_REQUEST|NLM_F_ACK);

	ctnl_build_tuple(req, sizeof(buf), tuple, dir); 

	if (nfnl_send(&cth->nfnlh, (struct nlmsghdr *)&buf) < 0)
		return -1;

	return nfnl_listen(&cth->nfnlh, &list_conntrack_handler, cth);
}

/**
 * ctnl_del_conntrack - delete a connection from conntrack hashtable
 * cth: libctnetlink handle
 * t: tuple of to-be-deleted connection
 */
int ctnl_del_conntrack(struct ctnl_handle *cth, 
		       struct ctnl_tuple *tuple,
		       int dir)
{
	struct nfnlhdr *req;
	char buf[CTNL_BUFFSIZE];

	memset(&buf, 0, sizeof(buf));
	req = (void *) &buf;

	nfnl_fill_hdr(&cth->nfnlh, (struct nlmsghdr *) &buf,
		      0, AF_INET, 0, IPCTNL_MSG_CT_DELETE,
		      NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST|NLM_F_ACK);

	ctnl_build_tuple(req, sizeof(buf), tuple, dir); 

	if (nfnl_send(&cth->nfnlh, (struct nlmsghdr *)&buf) < 0)
		return -1;

	return nfnl_listen(&cth->nfnlh, &list_conntrack_handler, cth);
}
static int new_update_conntrack(struct ctnl_handle *cth,
				struct ctnl_conntrack *ct,
				u_int16_t msg_flags)
{
	struct nfnlhdr *req;
	char buf[CTNL_BUFFSIZE];

	memset(&buf, 0, sizeof(buf));
	req = (void *) &buf;

	nfnl_fill_hdr(&cth->nfnlh, (struct nlmsghdr *) &buf,
		      0, AF_INET, 0, IPCTNL_MSG_CT_NEW,
		      NLM_F_REQUEST|NLM_F_CREATE|NLM_F_ACK|msg_flags);

	ctnl_build_conntrack(req, sizeof(buf), ct);

	if (nfnl_send(&cth->nfnlh, (struct nlmsghdr *)&buf) < 0 )
		return -1;

	return nfnl_listen(&cth->nfnlh, &list_conntrack_handler, cth);
}

/**
 * ctnl_new_conntrack - create a connection in the conntrack hashtable
 * cth: libctnetlink handle
 * t: tuple of to-be-created connection
 */
int ctnl_new_conntrack(struct ctnl_handle *cth, struct ctnl_conntrack *ct)
{
	return new_update_conntrack(cth, ct, NLM_F_EXCL);
}

int ctnl_upd_conntrack(struct ctnl_handle *cth, struct ctnl_conntrack *ct)
{
	return new_update_conntrack(cth, ct, 0);
}

/**
 * ctnl_list_expect - retrieve a list of expectations from conntrack subsys
 * cth: libctnetlink handle
 * family: AF_INET, ...
 */
int ctnl_list_expect(struct ctnl_handle *cth, int family)
{
	if (ctnl_wilddump_request(cth, family, IPCTNL_MSG_EXP_GET) < 0)
		return -1;

	return nfnl_listen(&cth->nfnlh, &list_conntrack_handler, cth);

}

int ctnl_event_expect(struct ctnl_handle *cth, int family)
{
	return nfnl_listen(&cth->nfnlh, &list_conntrack_handler, cth);
}

int ctnl_flush_expect(struct ctnl_handle *cth)
{
	struct nfnlhdr *req;
	char buf[sizeof(*req)];

	memset(&buf, 0, sizeof(buf));
	req = (void *) &buf;

	nfnl_fill_hdr(&cth->nfnlh, (struct nlmsghdr *) &buf,
			0, AF_INET, 0, IPCTNL_MSG_EXP_DELETE,
			NLM_F_REQUEST|NLM_F_ACK);

	if (nfnl_send(&cth->nfnlh, (struct nlmsghdr *)&buf) < 0 )
		return -1;

	return nfnl_listen(&cth->nfnlh, &list_conntrack_handler, cth);
}
