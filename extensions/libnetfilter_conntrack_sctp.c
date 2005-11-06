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
#include <libnetfilter_conntrack/libnetfilter_conntrack_extensions.h>

static void parse_proto(struct nfattr *cda[], struct nfct_tuple *tuple)
{
	if (cda[CTA_PROTO_SRC_PORT-1])
		tuple->l4src.sctp.port =
			*(u_int16_t *)NFA_DATA(cda[CTA_PROTO_SRC_PORT-1]);
	if (cda[CTA_PROTO_DST_PORT-1])
		tuple->l4dst.sctp.port =
			*(u_int16_t *)NFA_DATA(cda[CTA_PROTO_DST_PORT-1]);
}

static void parse_protoinfo(struct nfattr *cda[], struct nfct_conntrack *ct)
{
/*	if (cda[CTA_PROTOINFO_SCTP_STATE-1])
                ct->protoinfo.sctp.state =
                        *(u_int8_t *)NFA_DATA(cda[CTA_PROTOINFO_SCTP_STATE-1]);
*/
}

static void build_tuple_proto(struct nfnlhdr *req, int size, 
			      struct nfct_tuple *t)
{
	nfnl_addattr_l(&req->nlh, size, CTA_PROTO_SRC_PORT,
		       &t->l4src.tcp.port, sizeof(u_int16_t));
	nfnl_addattr_l(&req->nlh, size, CTA_PROTO_DST_PORT,
		       &t->l4dst.tcp.port, sizeof(u_int16_t));
}

static int print_protoinfo(char *buf, union nfct_protoinfo *protoinfo)
{
/*	fprintf(stdout, "%s ", states[protoinfo->sctp.state]); */
	return 0;
}

static int print_proto(char *buf, struct nfct_tuple *tuple)
{
	return(sprintf(buf, "sport=%u dport=%u ", htons(tuple->l4src.sctp.port),
						  htons(tuple->l4dst.sctp.port)));
}

static struct nfct_proto sctp = {
	.name 			= "sctp",
	.protonum		= IPPROTO_SCTP,
	.parse_proto		= parse_proto,
	.parse_protoinfo	= parse_protoinfo,
	.build_tuple_proto	= build_tuple_proto,
	.print_proto		= print_proto,
	.print_protoinfo	= print_protoinfo,
	.version		= VERSION
};

static void __attribute__ ((constructor)) init(void);

static void init(void)
{
	nfct_register_proto(&sctp);
}
