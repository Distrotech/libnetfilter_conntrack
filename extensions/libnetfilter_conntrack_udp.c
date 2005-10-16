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

void parse_proto(struct nfattr *cda[], struct nfct_tuple *tuple)
{
	if (cda[CTA_PROTO_SRC_PORT-1])
		tuple->l4src.udp.port =
			*(u_int16_t *)NFA_DATA(cda[CTA_PROTO_SRC_PORT-1]);
	if (cda[CTA_PROTO_DST_PORT-1])
		tuple->l4dst.udp.port =
			*(u_int16_t *)NFA_DATA(cda[CTA_PROTO_DST_PORT-1]);
}

int print_proto(char *buf, struct nfct_tuple *tuple)
{
	return (sprintf(buf, "sport=%u dport=%u ", htons(tuple->l4src.udp.port),
					           htons(tuple->l4dst.udp.port)));
}

static struct nfct_proto udp = {
	.name 			= "udp",
	.protonum		= IPPROTO_UDP,
	.parse_proto		= parse_proto,
	.print_proto		= print_proto,
	.version		= LIBNETFILTER_CONNTRACK_VERSION,
};

void __attribute__ ((constructor)) init(void);
void __attribute__ ((destructor)) fini(void);

void init(void)
{
	nfct_register_proto(&udp);
}

void fini(void)
{
	nfct_unregister_proto(&udp);
}
