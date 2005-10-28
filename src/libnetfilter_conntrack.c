/*
 * (C) 2005 by Pablo Neira Ayuso <pablo@netfilter.org>
 *             Harald Welte <laforge@netfilter.org>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 */
#include <stdio.h>
#include <getopt.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include "linux_list.h"
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#define NFCT_BUFSIZE 4096

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

static char *lib_dir = LIBNETFILTER_CONNTRACK_DIR;
static LIST_HEAD(proto_list);
static char *proto2str[IPPROTO_MAX] = {
	[IPPROTO_TCP] = "tcp",
        [IPPROTO_UDP] = "udp",
        [IPPROTO_ICMP] = "icmp",
        [IPPROTO_SCTP] = "sctp"
};

/* handler used for nfnl_listen */
static int callback_handler(struct sockaddr_nl *nladdr,
			    struct nlmsghdr *n, void *arg)
{
	struct nfct_handle *cth = (struct nfct_handle *) arg;
	int ret;

	if (NFNL_SUBSYS_ID(n->nlmsg_type) != NFNL_SUBSYS_CTNETLINK &&
	    NFNL_SUBSYS_ID(n->nlmsg_type) != NFNL_SUBSYS_CTNETLINK_EXP) {
		nfnl_dump_packet(n, n->nlmsg_len, "callback_handler");
		return 0;
	}

	if (!cth)
		return -ENODEV;

	if (!cth->handler)
		return -ENODEV;

	ret = cth->handler(cth, n, NULL);

	return ret;
}

struct nfct_handle *nfct_open(u_int8_t subsys_id, unsigned subscriptions)
{
	int err;
	u_int8_t cb_count;
	struct nfct_handle *cth;

	switch(subsys_id) {
		case NFNL_SUBSYS_CTNETLINK:
			cb_count = IPCTNL_MSG_MAX;
			break;
		case NFNL_SUBSYS_CTNETLINK_EXP:
			cb_count = IPCTNL_MSG_EXP_MAX;
			break;
		default:
			return NULL;
			break;
	}
	cth = (struct nfct_handle *)
		malloc(sizeof(struct nfct_handle));
	if (!cth)
		return NULL;
	
	memset(cth, 0, sizeof(*cth));

	err = nfnl_open(&cth->nfnlh, subsys_id, cb_count, subscriptions);
	if (err < 0) {
		free(cth);
		return NULL;
	}

	return cth;
}

int nfct_close(struct nfct_handle *cth)
{
	int err;

	err = nfnl_close(&cth->nfnlh);
	free(cth);

	return err;
}

void nfct_register_callback(struct nfct_handle *cth, nfct_callback callback)
{
	cth->callback = callback;
}

void nfct_unregister_callback(struct nfct_handle *cth)
{
	cth->callback = NULL;
}

static void nfct_build_tuple_ip(struct nfnlhdr *req, int size, 
				struct nfct_tuple *t)
{
	struct nfattr *nest;

	nest = nfnl_nest(&req->nlh, size, CTA_TUPLE_IP);

	nfnl_addattr_l(&req->nlh, size, CTA_IP_V4_SRC, &t->src.v4, 
		       sizeof(u_int32_t));

	nfnl_addattr_l(&req->nlh, size, CTA_IP_V4_DST, &t->dst.v4,
		       sizeof(u_int32_t));

	nfnl_nest_end(&req->nlh, nest);
}

static void nfct_build_tuple_proto(struct nfnlhdr *req, int size,
				   struct nfct_tuple *t)
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
			       &t->l4dst.icmp.code, sizeof(u_int8_t));
		nfnl_addattr_l(&req->nlh, size, CTA_PROTO_ICMP_TYPE,
			       &t->l4dst.icmp.type, sizeof(u_int8_t));
		/* This is an ICMP echo */
		if (t->l4dst.icmp.type == 8)
			nfnl_addattr_l(&req->nlh, size, CTA_PROTO_ICMP_ID,
				       &t->l4src.icmp.id, sizeof(u_int16_t));
		break;
	}
	nfnl_nest_end(&req->nlh, nest);
}

static void nfct_build_tuple(struct nfnlhdr *req, int size, 
			     struct nfct_tuple *t, int type)
{
	struct nfattr *nest;

	nest = nfnl_nest(&req->nlh, size, type);

	nfct_build_tuple_ip(req, size, t);
	nfct_build_tuple_proto(req, size, t);

	nfnl_nest_end(&req->nlh, nest);
}

static void nfct_build_protoinfo(struct nfnlhdr *req, int size,
				 struct nfct_conntrack *ct)
{
	struct nfattr *nest;

	nest = nfnl_nest(&req->nlh, size, CTA_PROTOINFO);

	switch (ct->tuple[NFCT_DIR_ORIGINAL].protonum) {
	case IPPROTO_TCP: {
		struct nfattr *nest_proto;
		nest_proto = nfnl_nest(&req->nlh, size, CTA_PROTOINFO_TCP);
		nfnl_addattr_l(&req->nlh, size, CTA_PROTOINFO_TCP_STATE,
			       &ct->protoinfo.tcp.state, sizeof(u_int8_t));
		nfnl_nest_end(&req->nlh, nest_proto);
		break;
		}
	default:
		break;
	}

	nfnl_nest_end(&req->nlh, nest);
}

static void nfct_build_protonat(struct nfnlhdr *req, int size,
				struct nfct_conntrack *ct)
{
	struct nfattr *nest;

	nest = nfnl_nest(&req->nlh, size, CTA_NAT_PROTO);

	switch (ct->tuple[NFCT_DIR_ORIGINAL].protonum) {
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

static void nfct_build_nat(struct nfnlhdr *req, int size,
			   struct nfct_conntrack *ct)
{
	struct nfattr *nest;

	nest = nfnl_nest(&req->nlh, size, CTA_NAT);

	nfnl_addattr_l(&req->nlh, size, CTA_NAT_MINIP,
		       &ct->nat.min_ip, sizeof(u_int32_t));
	
	if (ct->nat.min_ip != ct->nat.max_ip)
		nfnl_addattr_l(&req->nlh, size, CTA_NAT_MAXIP,
			       &ct->nat.max_ip, sizeof(u_int32_t));

	if (ct->nat.l4min.all != ct->nat.l4max.all)
		nfct_build_protonat(req, size, ct);

	nfnl_nest_end(&req->nlh, nest);
}

static void nfct_build_conntrack(struct nfnlhdr *req, int size, 
				 struct nfct_conntrack *ct)
{
	nfct_build_tuple(req, size, &ct->tuple[NFCT_DIR_ORIGINAL], 
				 CTA_TUPLE_ORIG);
	nfct_build_tuple(req, size, &ct->tuple[NFCT_DIR_REPLY],
				 CTA_TUPLE_REPLY);
	
	nfnl_addattr_l(&req->nlh, size, CTA_STATUS, &ct->status, 
		       sizeof(unsigned int));
	nfnl_addattr_l(&req->nlh, size, CTA_TIMEOUT, &ct->timeout, 
		       sizeof(unsigned long));

	if (ct->id != NFCT_ANY_ID)
		nfnl_addattr_l(&req->nlh, size, CTA_ID, &ct->id, 
			       sizeof(unsigned int));

	nfct_build_protoinfo(req, size, ct);
	if (ct->nat.min_ip != 0)
		nfct_build_nat(req, size, ct);
}

void nfct_dump_tuple(struct nfct_tuple *tp)
{
	fprintf(stdout, "tuple %p: %u %u.%u.%u.%u:%hu -> %u.%u.%u.%u:%hu\n",
			tp, tp->protonum,
			NIPQUAD(tp->src.v4), ntohs(tp->l4src.all),
			NIPQUAD(tp->dst.v4), ntohs(tp->l4dst.all));
}

static struct nfct_proto *findproto(char *name)
{
	struct list_head *i;
	struct nfct_proto *cur = NULL, *handler = NULL;

	if (!name) 
		return handler;

	lib_dir = getenv("LIBNETFILTER_CONNTRACK_DIR");
	if (!lib_dir)
		lib_dir = LIBNETFILTER_CONNTRACK_DIR;

	list_for_each(i, &proto_list) {
		cur = (struct nfct_proto *) i;
		if (strcmp(cur->name, name) == 0) {
			handler = cur;
			break;
		}
	}

	if (!handler) {
		char path[sizeof("libnetfilter_conntrack_.so")
			 + strlen(name) + strlen(lib_dir)];
                sprintf(path, "%s/libnetfilter_conntrack_%s.so", lib_dir, name);
		if (dlopen(path, RTLD_NOW))
			handler = findproto(name);
		else
			fprintf(stderr, "%s\n", dlerror());
	}

	return handler;
}

int nfct_sprintf_status_assured(char *buf, struct nfct_conntrack *ct)
{
	int size = 0;
	
	if (ct->status & IPS_ASSURED)
		size = sprintf(buf, "[ASSURED] ");

	return size;
}

int nfct_sprintf_status_seen_reply(char *buf, struct nfct_conntrack *ct)
{
	int size = 0;
	
        if (!(ct->status & IPS_SEEN_REPLY))
                size = sprintf(buf, "[UNREPLIED] ");

	return size;
}

static void parse_ip(struct nfattr *attr, struct nfct_tuple *tuple)
{
	struct nfattr *tb[CTA_IP_MAX];

        nfnl_parse_nested(tb, CTA_IP_MAX, attr);
	if (tb[CTA_IP_V4_SRC-1])
		tuple->src.v4 = *(u_int32_t *)NFA_DATA(tb[CTA_IP_V4_SRC-1]);

	if (tb[CTA_IP_V4_DST-1])
		tuple->dst.v4 = *(u_int32_t *)NFA_DATA(tb[CTA_IP_V4_DST-1]);
}

static void parse_proto(struct nfattr *attr, struct nfct_tuple *tuple)
{
	struct nfattr *tb[CTA_PROTO_MAX];
	struct nfct_proto *h;

	nfnl_parse_nested(tb, CTA_PROTO_MAX, attr);
	if (tb[CTA_PROTO_NUM-1])
		tuple->protonum = *(u_int8_t *)NFA_DATA(tb[CTA_PROTO_NUM-1]);
	
	h = findproto(proto2str[tuple->protonum]);
	if (h && h->parse_proto)
		h->parse_proto(tb, tuple);
}

static void parse_tuple(struct nfattr *attr, struct nfct_tuple *tuple)
{
	struct nfattr *tb[CTA_TUPLE_MAX];

	nfnl_parse_nested(tb, CTA_TUPLE_MAX, attr);

	if (tb[CTA_TUPLE_IP-1])
		parse_ip(tb[CTA_TUPLE_IP-1], tuple);
	if (tb[CTA_TUPLE_PROTO-1])
		parse_proto(tb[CTA_TUPLE_PROTO-1], tuple);
}

static void parse_protoinfo(struct nfattr *attr, struct nfct_conntrack *ct)
{
	struct nfattr *tb[CTA_PROTOINFO_MAX];
	struct nfct_proto *h;

	nfnl_parse_nested(tb,CTA_PROTOINFO_MAX, attr);

	h = findproto(proto2str[ct->tuple[NFCT_DIR_ORIGINAL].protonum]);
        if (h && h->parse_protoinfo)
		h->parse_protoinfo(tb, ct);
}

static void nfct_parse_counters(struct nfattr *attr,
					struct nfct_conntrack *ct,
					enum ctattr_type parent)
{
	struct nfattr *tb[CTA_COUNTERS_MAX];
	int dir = (parent == CTA_COUNTERS_ORIG ? NFCT_DIR_REPLY 
					       : NFCT_DIR_ORIGINAL);

	nfnl_parse_nested(tb, CTA_COUNTERS_MAX, attr);
	if (tb[CTA_COUNTERS_PACKETS-1])
		ct->counters[dir].packets
			= __be64_to_cpu(*(u_int64_t *)
					NFA_DATA(tb[CTA_COUNTERS_PACKETS-1]));
	if (tb[CTA_COUNTERS_BYTES-1])
		ct->counters[dir].bytes
			= __be64_to_cpu(*(u_int64_t *)
					NFA_DATA(tb[CTA_COUNTERS_BYTES-1]));
	if (tb[CTA_COUNTERS32_PACKETS-1])
		ct->counters[dir].packets
			= htonl(*(u_int32_t *)
				NFA_DATA(tb[CTA_COUNTERS32_PACKETS-1]));
	if (tb[CTA_COUNTERS32_BYTES-1])
		ct->counters[dir].bytes
			= htonl(*(u_int32_t *)
				NFA_DATA(tb[CTA_COUNTERS32_BYTES-1]));
}

static char *msgtype[] = {"[UNKNOWN]", "[NEW]", "[UPDATE]", "[DESTROY]"};

static int typemsg2enum(u_int8_t type, u_int8_t flags)
{
	int ret = NFCT_MSG_UNKNOWN;

	if (type == IPCTNL_MSG_CT_NEW) {
		if (flags & NLM_F_CREATE)
			ret = NFCT_MSG_NEW;
		else
			ret = NFCT_MSG_UPDATE;
	} else if (type == IPCTNL_MSG_CT_DELETE)
		ret = NFCT_MSG_DESTROY;

	return ret;
}

static int nfct_conntrack_netlink_handler(struct nfct_handle *cth, 
					  struct nlmsghdr *nlh, void *arg)
{
	struct nfgenmsg *nfmsg;
	struct nfattr *attr = NFM_NFA(NLMSG_DATA(nlh));
	int attrlen = NLMSG_LENGTH(nlh->nlmsg_len) - NFNL_HEADER_LEN;
	struct nfct_conntrack ct;
	unsigned int flags = 0;
	int type = NFNL_MSG_TYPE(nlh->nlmsg_type), ret = 0;

	memset(&ct, 0, sizeof(struct nfct_conntrack));

	nfmsg = NLMSG_DATA(nlh);

	if (NLMSG_LENGTH(nlh->nlmsg_len) < NFNL_HEADER_LEN)
		return -EINVAL;

	while (NFA_OK(attr, attrlen)) {
		switch(NFA_TYPE(attr)) {
		case CTA_TUPLE_ORIG:
			parse_tuple(attr, &ct.tuple[NFCT_DIR_ORIGINAL]);
			break;
		case CTA_TUPLE_REPLY:
			parse_tuple(attr, &ct.tuple[NFCT_DIR_REPLY]);
			break;
		case CTA_STATUS:
			ct.status = ntohl(*(u_int32_t *)NFA_DATA(attr));
			flags |= NFCT_STATUS;
			break;
		case CTA_PROTOINFO:
			parse_protoinfo(attr, &ct);
			flags |= NFCT_PROTOINFO;
			break;
		case CTA_TIMEOUT:
			ct.timeout = ntohl(*(u_int32_t *)NFA_DATA(attr));
			flags |= NFCT_TIMEOUT;
			break;
		case CTA_MARK:
			ct.mark = ntohl(*(u_int32_t *)NFA_DATA(attr));
			flags |= NFCT_MARK;
			break;
		case CTA_COUNTERS_ORIG:
			nfct_parse_counters(attr, &ct, NFA_TYPE(attr)-1);
			flags |= NFCT_COUNTERS_ORIG;
			break;
		case CTA_COUNTERS_REPLY:
			nfct_parse_counters(attr, &ct, NFA_TYPE(attr)-1);
			flags |= NFCT_COUNTERS_RPLY;
			break;
		case CTA_USE:
			ct.use = ntohl(*(u_int32_t *)NFA_DATA(attr));
			flags |= NFCT_USE;
			break;
		case CTA_ID:
			ct.id = ntohl(*(u_int32_t *)NFA_DATA(attr));
			flags |= NFCT_ID;
			break;
		default:
			fprintf(stderr, "Unknown Attribute %d\n", NFA_TYPE(attr));
			break;
		}
		attr = NFA_NEXT(attr, attrlen);
	}
	if (cth->callback)
		ret = cth->callback((void *) &ct, flags,
				    typemsg2enum(type, nlh->nlmsg_flags));

	return ret;
}

int nfct_sprintf_protocol(char *buf, struct nfct_conntrack *ct)
{
	return (sprintf(buf, "%-8s %u ", 
		proto2str[ct->tuple[NFCT_DIR_ORIGINAL].protonum] == NULL ?
		"unknown" : proto2str[ct->tuple[NFCT_DIR_ORIGINAL].protonum], 
		 ct->tuple[NFCT_DIR_ORIGINAL].protonum));
}

int nfct_sprintf_timeout(char *buf, struct nfct_conntrack *ct)
{
	return sprintf(buf, "%lu ", ct->timeout);
}

int nfct_sprintf_protoinfo(char *buf, struct nfct_conntrack *ct)
{
	int size = 0;
	struct nfct_proto *h = NULL;
	
	h = findproto(proto2str[ct->tuple[NFCT_DIR_ORIGINAL].protonum]);
	if (h && h->print_protoinfo)
		size += h->print_protoinfo(buf+size, &ct->protoinfo);
	
	return size;
}

int nfct_sprintf_address(char *buf, struct nfct_conntrack *ct, int dir)
{
	return (sprintf(buf, "src=%u.%u.%u.%u dst=%u.%u.%u.%u ",
			NIPQUAD(ct->tuple[dir].src.v4),
			NIPQUAD(ct->tuple[dir].dst.v4)));
}

int nfct_sprintf_proto(char *buf, struct nfct_conntrack *ct, int dir)
{
	int size = 0;
	struct nfct_proto *h = NULL;

	h = findproto(proto2str[ct->tuple[NFCT_DIR_ORIGINAL].protonum]);
	if (h && h->print_proto)
		size += h->print_proto(buf, &ct->tuple[dir]);

	return size;
}

int nfct_sprintf_counters(char *buf, struct nfct_conntrack *ct, int dir)
{
	return (sprintf(buf, "packets=%llu bytes=%llu ",
			ct->counters[dir].packets,
			ct->counters[dir].bytes));
}

int nfct_sprintf_mark(char *buf, struct nfct_conntrack *ct)
{
	return (sprintf(buf, "mark=%lu ", ct->mark));
}

int nfct_sprintf_use(char *buf, struct nfct_conntrack *ct)
{
	return (sprintf(buf, "use=%u ", ct->use));
}

int nfct_sprintf_id(char *buf, struct nfct_conntrack *ct)
{
	return (sprintf(buf, "id=%u ", ct->id));
}

int nfct_sprintf_conntrack(char *buf, struct nfct_conntrack *ct, 
			  unsigned int flags)
{
	int size = 0;

	size += nfct_sprintf_protocol(buf, ct);

	if (flags & NFCT_TIMEOUT)
		size += nfct_sprintf_timeout(buf+size, ct);

        if (flags & NFCT_PROTOINFO)
		size += nfct_sprintf_protoinfo(buf+size, ct);

	size += nfct_sprintf_address(buf+size, ct, NFCT_DIR_ORIGINAL);
	size += nfct_sprintf_proto(buf+size, ct, NFCT_DIR_ORIGINAL);

	if (flags & NFCT_COUNTERS_ORIG)
		size += nfct_sprintf_counters(buf+size, ct, NFCT_DIR_ORIGINAL);

	if (flags & NFCT_STATUS)
		size += nfct_sprintf_status_seen_reply(buf+size, ct);

	size += nfct_sprintf_address(buf+size, ct, NFCT_DIR_REPLY);
	size += nfct_sprintf_proto(buf+size, ct, NFCT_DIR_REPLY);

	if (flags & NFCT_COUNTERS_RPLY)
		size += nfct_sprintf_counters(buf+size, ct, NFCT_DIR_REPLY);
	
	if (flags & NFCT_STATUS)
		size += nfct_sprintf_status_assured(buf+size, ct);

	if (flags & NFCT_MARK)
		size += nfct_sprintf_mark(buf+size, ct);

	if (flags & NFCT_USE)
		size += nfct_sprintf_use(buf+size, ct);

	return size;
}

int nfct_sprintf_conntrack_id(char *buf, struct nfct_conntrack *ct, 
			     unsigned int flags)
{
	int size;
	
	size = nfct_sprintf_conntrack(buf, ct, flags);
	if (flags & NFCT_ID)
		size += nfct_sprintf_id(buf+size, ct);

	return size;
}

int nfct_default_conntrack_display(void *arg, unsigned int flags, int type)
{
	char buf[512];
	int size;

	size = nfct_sprintf_conntrack(buf, arg, flags);
	sprintf(buf+size, "\n");
	fprintf(stdout, buf);

	return 0;
}

int nfct_default_conntrack_display_id(void *arg, unsigned int flags, int type)
{
	char buf[512];
	int size;

	size = nfct_sprintf_conntrack_id(buf, arg, flags);
	sprintf(buf+size, "\n");
	fprintf(stdout, buf);

	return 0;
}

int nfct_default_expect_display(void *arg, unsigned int flags, int type)
{
	struct nfct_expect *exp = arg;
	char buf[256];
	int size = 0;
	
	size += sprintf(buf, "%ld proto=%d ", exp->timeout, exp->tuple.protonum);
	size += sprintf(buf+size, "src=%u.%u.%u.%u dst=%u.%u.%u.%u ",
					NIPQUAD(exp->tuple.src.v4),
					NIPQUAD(exp->tuple.dst.v4));
	size += sprintf(buf+size, "src=%u.%u.%u.%u dst=%u.%u.%u.%u ",
					NIPQUAD(exp->mask.src.v4),
					NIPQUAD(exp->mask.dst.v4));
	size += sprintf(buf+size, "id=%u ", exp->id);
	size += sprintf(buf, "\n");
	fprintf(stdout, buf);

	return 0;
}

static int nfct_event_netlink_handler(struct nfct_handle *cth, 
				      struct nlmsghdr *nlh,
				      void *arg)
{
	int type = NFNL_MSG_TYPE(nlh->nlmsg_type);
	fprintf(stdout, "%9s ", msgtype[typemsg2enum(type, nlh->nlmsg_flags)]);
	return nfct_conntrack_netlink_handler(cth, nlh, arg);
}

static int nfct_expect_netlink_handler(struct nfct_handle *cth, 
				       struct nlmsghdr *nlh, void *arg)
{
	struct nfgenmsg *nfmsg;
	struct nfattr *attr = NFM_NFA(NLMSG_DATA(nlh));
	int attrlen = NLMSG_LENGTH(nlh->nlmsg_len) - NFNL_HEADER_LEN;
	struct nfct_expect exp;
	int type = NFNL_MSG_TYPE(nlh->nlmsg_type), ret = 0;

	memset(&exp, 0, sizeof(struct nfct_expect));

	nfmsg = NLMSG_DATA(nlh);

	if (NLMSG_LENGTH(nlh->nlmsg_len) < NFNL_HEADER_LEN)
		return -EINVAL;

	while (NFA_OK(attr, attrlen)) {
		switch(NFA_TYPE(attr)) {

			case CTA_EXPECT_TUPLE:
				parse_tuple(attr, &exp.tuple);
				break;
			case CTA_EXPECT_MASK:
				parse_tuple(attr, &exp.mask);
				break;
			case CTA_EXPECT_TIMEOUT:
				exp.timeout = htonl(*(unsigned long *)
						NFA_DATA(attr));
				break;
			case CTA_EXPECT_ID:
				exp.id = htonl(*(u_int32_t *)NFA_DATA(attr));	
				break;
		}
		attr = NFA_NEXT(attr, attrlen);
	}
	if (cth->callback)
		ret = cth->callback((void *)&exp, 0, 
				    typemsg2enum(type, nlh->nlmsg_flags));

	return 0;
}

struct nfct_conntrack *
nfct_conntrack_alloc(struct nfct_tuple *orig, struct nfct_tuple *reply,
		     unsigned long timeout, union nfct_protoinfo *proto,
		     unsigned int status, unsigned long mark, 
		     unsigned int id, struct nfct_nat *range)
{
	struct nfct_conntrack *ct;

	ct = malloc(sizeof(struct nfct_conntrack));
	if (!ct)
		return NULL;
	memset(ct, 0, sizeof(struct nfct_conntrack));

	ct->tuple[NFCT_DIR_ORIGINAL] = *orig;
	ct->tuple[NFCT_DIR_REPLY] = *reply;
	ct->timeout = htonl(timeout);
	ct->status = htonl(status);
	ct->protoinfo = *proto;
	ct->mark = htonl(mark);
	if (id != NFCT_ANY_ID)
		ct->id = htonl(id);
	if (range)
		ct->nat = *range;

	return ct;
}

void nfct_conntrack_free(struct nfct_conntrack *ct)
{
	free(ct);
}

int nfct_create_conntrack(struct nfct_handle *cth, struct nfct_conntrack *ct)
{
	struct nfnlhdr *req;
	char buf[NFCT_BUFSIZE];

	req = (void *) buf;

	memset(buf, 0, sizeof(buf));
	
	nfnl_fill_hdr(&cth->nfnlh, &req->nlh, 0, AF_INET, 0, IPCTNL_MSG_CT_NEW,
		      NLM_F_REQUEST|NLM_F_CREATE|NLM_F_ACK|NLM_F_EXCL);

	nfct_build_conntrack(req, sizeof(buf), ct);

	return nfnl_talk(&cth->nfnlh, &req->nlh, 0, 0, NULL, NULL, NULL);
}

int nfct_update_conntrack(struct nfct_handle *cth, struct nfct_conntrack *ct)
{
	struct nfnlhdr *req;
	char buf[NFCT_BUFSIZE];
	int err;

	req = (void *) &buf;
	memset(&buf, 0, sizeof(buf));

	nfnl_fill_hdr(&cth->nfnlh, &req->nlh, 0, AF_INET, 0, IPCTNL_MSG_CT_NEW,
		      NLM_F_REQUEST|NLM_F_ACK);	

	nfct_build_conntrack(req, sizeof(buf), ct);

	err = nfnl_send(&cth->nfnlh, &req->nlh);
	if (err < 0)
		return err;

	return nfnl_listen(&cth->nfnlh, &callback_handler, cth);
}

int nfct_delete_conntrack(struct nfct_handle *cth, struct nfct_tuple *tuple, 
			  int dir, unsigned int id)
{
	struct nfnlhdr *req;
	char buf[NFCT_BUFSIZE];
	int type = dir ? CTA_TUPLE_REPLY : CTA_TUPLE_ORIG;

	memset(&buf, 0, sizeof(buf));
	req = (void *) &buf;

	nfnl_fill_hdr(&cth->nfnlh, &req->nlh, 0, 
		      AF_INET, 0, IPCTNL_MSG_CT_DELETE, 
		      NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST|NLM_F_ACK);

	nfct_build_tuple(req, sizeof(buf), tuple, type);

	if (id != NFCT_ANY_ID)
		nfnl_addattr_l(&req->nlh, sizeof(buf), CTA_ID, &id, 
			       sizeof(unsigned int));

	return nfnl_talk(&cth->nfnlh, &req->nlh, 0, 0, NULL, NULL, NULL);
}

int nfct_get_conntrack(struct nfct_handle *cth, struct nfct_tuple *tuple, 
		       int dir, unsigned int id)
{
	int err;
	struct nfnlhdr *req;
	char buf[NFCT_BUFSIZE];
	int type = dir ? CTA_TUPLE_REPLY : CTA_TUPLE_ORIG;

	cth->handler = nfct_conntrack_netlink_handler;
	
	memset(&buf, 0, sizeof(buf));
	req = (void *) &buf;

	nfnl_fill_hdr(&cth->nfnlh, &req->nlh, 0,
		      AF_INET, 0, IPCTNL_MSG_CT_GET,
		      NLM_F_REQUEST|NLM_F_ACK);
	
	nfct_build_tuple(req, sizeof(buf), tuple, type);

        if (id != NFCT_ANY_ID)
		nfnl_addattr_l(&req->nlh, sizeof(buf), CTA_ID, &id,
			       sizeof(unsigned int));

	err = nfnl_send(&cth->nfnlh, &req->nlh);
	if (err < 0)
		return err;

	return nfnl_listen(&cth->nfnlh, &callback_handler, cth);
}

static int __nfct_dump_conntrack_table(struct nfct_handle *cth, int zero)
{
	int err, msg;
	struct nfnlhdr req;

	memset(&req, 0, sizeof(req));
	cth->handler = nfct_conntrack_netlink_handler;

	if (zero)
		msg = IPCTNL_MSG_CT_GET_CTRZERO;
	else
		msg = IPCTNL_MSG_CT_GET;

	nfnl_fill_hdr(&cth->nfnlh, &req.nlh, 0, AF_INET, 0,
		      msg, NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST|NLM_F_DUMP);

	err = nfnl_send(&cth->nfnlh, &req.nlh);
	if (err < 0)
		return err;

	return nfnl_listen(&cth->nfnlh, &callback_handler, cth); 
}

int nfct_dump_conntrack_table(struct nfct_handle *cth)
{
	return(__nfct_dump_conntrack_table(cth, 0));
}

int nfct_dump_conntrack_table_reset_counters(struct nfct_handle *cth)
{
	return(__nfct_dump_conntrack_table(cth, 1));
}

int nfct_event_conntrack(struct nfct_handle *cth)
{
	cth->handler = nfct_event_netlink_handler;
	return nfnl_listen(&cth->nfnlh, &callback_handler, cth);
}

void nfct_register_proto(struct nfct_proto *h)
{
	if (strcmp(h->version, LIBNETFILTER_CONNTRACK_VERSION) != 0) {
		fprintf(stderr, "plugin `%s': version %s (I'm %s)\n",
			h->name, h->version, LIBNETFILTER_CONNTRACK_VERSION);
		exit(1);
	}
	list_add(&h->head, &proto_list);
}

int nfct_dump_expect_list(struct nfct_handle *cth)
{
	int err;
	struct nfnlhdr req;

	memset(&req, 0, sizeof(req));

	cth->handler = nfct_expect_netlink_handler;
	nfnl_fill_hdr(&cth->nfnlh, &req.nlh, 0, AF_INET, 0,
		      IPCTNL_MSG_EXP_GET, NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST);

	err = nfnl_send(&cth->nfnlh, &req.nlh);
	if (err < 0)
		return err;

	return nfnl_listen(&cth->nfnlh, &callback_handler, cth);
}

int nfct_flush_conntrack_table(struct nfct_handle *cth)
{
	struct nfnlhdr req;

	memset(&req, 0, sizeof(req));

	nfnl_fill_hdr(&cth->nfnlh, (struct nlmsghdr *) &req,
			0, AF_INET, 0, IPCTNL_MSG_CT_DELETE,
			NLM_F_REQUEST|NLM_F_ACK);

	return nfnl_talk(&cth->nfnlh, &req.nlh, 0, 0, NULL, NULL, NULL);
}

int nfct_get_expectation(struct nfct_handle *cth, struct nfct_tuple *tuple,
			 unsigned int id)
{
	int err;
	struct nfnlhdr *req;
	char buf[NFCT_BUFSIZE];

	memset(&buf, 0, sizeof(buf));
	req = (void *) &buf;

	nfnl_fill_hdr(&cth->nfnlh, &req->nlh, 0, AF_INET, 0, IPCTNL_MSG_EXP_GET,
		      NLM_F_REQUEST|NLM_F_ACK);

	cth->handler = nfct_expect_netlink_handler;
	nfct_build_tuple(req, sizeof(buf), tuple, CTA_EXPECT_MASTER);

	if (id != NFCT_ANY_ID)
		nfnl_addattr_l(&req->nlh, sizeof(buf), CTA_EXPECT_ID, &id,
			       sizeof(unsigned int));

	err = nfnl_send(&cth->nfnlh, &req->nlh);
	if (err < 0)
		return err;

	return nfnl_listen(&cth->nfnlh, &callback_handler, cth);
}

struct nfct_expect *
nfct_expect_alloc(struct nfct_tuple *master, struct nfct_tuple *tuple,
		  struct nfct_tuple *mask, unsigned long timeout, 
		  unsigned int id)
{
	struct nfct_expect *exp;

	exp = malloc(sizeof(struct nfct_expect));
	if (!exp)
		return NULL;
	memset(exp, 0, sizeof(struct nfct_expect));

	exp->master = *master;
	exp->tuple = *tuple;
	exp->mask = *mask;
	exp->timeout = htonl(timeout);
	if (id != NFCT_ANY_ID)
		exp->id = htonl(id);

	return exp;
}

void nfct_expect_free(struct nfct_expect *exp)
{
	free(exp);
}

int nfct_create_expectation(struct nfct_handle *cth, struct nfct_expect *exp)
{
	int err;
	struct nfnlhdr *req;
	char buf[NFCT_BUFSIZE];
	req = (void *) &buf;

	memset(&buf, 0, sizeof(buf));

	nfnl_fill_hdr(&cth->nfnlh, &req->nlh, 0, AF_INET, 0, IPCTNL_MSG_EXP_NEW,
		      NLM_F_REQUEST|NLM_F_CREATE|NLM_F_ACK);

	nfct_build_tuple(req, sizeof(buf), &exp->master, CTA_EXPECT_MASTER);
	nfct_build_tuple(req, sizeof(buf), &exp->tuple, CTA_EXPECT_TUPLE);
	nfct_build_tuple(req, sizeof(buf), &exp->mask, CTA_EXPECT_MASK);
	
	nfnl_addattr_l(&req->nlh, sizeof(buf), CTA_EXPECT_TIMEOUT, 
		       &exp->timeout, sizeof(unsigned long));

	err = nfnl_send(&cth->nfnlh, &req->nlh);
	if (err < 0)
		return err;

	return nfnl_listen(&cth->nfnlh, &callback_handler, cth);
}

int nfct_delete_expectation(struct nfct_handle *cth,struct nfct_tuple *tuple,
			    unsigned int id)
{
	int err;
	struct nfnlhdr *req;
	char buf[NFCT_BUFSIZE];

	memset(&buf, 0, sizeof(buf));
	req = (void *) &buf;
	
	nfnl_fill_hdr(&cth->nfnlh, &req->nlh, 0, AF_INET, 
		      0, IPCTNL_MSG_EXP_DELETE,
		      NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST|NLM_F_ACK);

	nfct_build_tuple(req, sizeof(buf), tuple, CTA_EXPECT_MASTER);

	if (id != NFCT_ANY_ID)
		nfnl_addattr_l(&req->nlh, sizeof(buf), CTA_EXPECT_ID, &id,
			       sizeof(unsigned int));
	
	err = nfnl_send(&cth->nfnlh, &req->nlh);
	if (err < 0)
		return err;

	return nfnl_listen(&cth->nfnlh, &callback_handler, cth);
}

int nfct_event_expectation(struct nfct_handle *cth)
{
	cth->handler = nfct_expect_netlink_handler;
	return nfnl_listen(&cth->nfnlh, &callback_handler, cth);
}

int nfct_flush_expectation_table(struct nfct_handle *cth)
{
	struct nfnlhdr req;

	memset(&req, 0, sizeof(req));
	
	nfnl_fill_hdr(&cth->nfnlh, (struct nlmsghdr *) &req,
		      0, AF_INET, 0, IPCTNL_MSG_EXP_DELETE,
		      NLM_F_REQUEST|NLM_F_ACK);

	return nfnl_talk(&cth->nfnlh, &req.nlh, 0, 0, NULL, NULL, NULL);
}
