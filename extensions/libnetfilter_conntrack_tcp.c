/*
 * (C) 2005 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 */
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h> /* For htons */
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

static const char *states[] = {
	"NONE",
	"SYN_SENT",
	"SYN_RECV",
	"ESTABLISHED",
	"FIN_WAIT",
	"CLOSE_WAIT",
	"LAST_ACK",
	"TIME_WAIT",
	"CLOSE",
	"LISTEN"
};

void parse_proto(struct nfattr *cda[], struct nfct_tuple *tuple)
{
	if (cda[CTA_PROTO_SRC_PORT-1])
		tuple->l4src.tcp.port =
			*(u_int16_t *)NFA_DATA(cda[CTA_PROTO_SRC_PORT-1]);
	if (cda[CTA_PROTO_DST_PORT-1])
		tuple->l4dst.tcp.port =
			*(u_int16_t *)NFA_DATA(cda[CTA_PROTO_DST_PORT-1]);
}

void parse_protoinfo(struct nfattr *cda[], struct nfct_conntrack *ct)
{
	struct nfattr *tb[CTA_PROTOINFO_TCP_MAX];
	
	nfnl_parse_nested(tb,CTA_PROTOINFO_TCP_MAX, cda[CTA_PROTOINFO_TCP-1]);
	
	if (tb[CTA_PROTOINFO_TCP_STATE-1])
                ct->protoinfo.tcp.state =
                        *(u_int8_t *)NFA_DATA(tb[CTA_PROTOINFO_TCP_STATE-1]);
}

int print_protoinfo(char *buf, union nfct_protoinfo *protoinfo)
{
	return(sprintf(buf, "%s ", states[protoinfo->tcp.state]));
}

int print_proto(char *buf, struct nfct_tuple *tuple)
{
	return(sprintf(buf, "sport=%u dport=%u ", htons(tuple->l4src.tcp.port),
					          htons(tuple->l4dst.tcp.port)));
}

static struct nfct_proto tcp = {
	.name 			= "tcp",
	.protonum		= IPPROTO_TCP,
	.parse_protoinfo	= parse_protoinfo,
	.parse_proto		= parse_proto,
	.print_protoinfo	= print_protoinfo,
	.print_proto		= print_proto,
	.version		= LIBNETFILTER_CONNTRACK_VERSION
};

void __attribute__ ((constructor)) init(void);
void __attribute__ ((destructor)) fini(void);

void init(void)
{
	nfct_register_proto(&tcp);
}

void fini(void)
{
	nfct_unregister_proto(&tcp);
}
