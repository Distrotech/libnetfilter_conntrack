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
	if (cda[CTA_PROTO_ICMP_TYPE-1])
		tuple->l4dst.icmp.type =
			*(u_int8_t *)NFA_DATA(cda[CTA_PROTO_ICMP_TYPE-1]);

	if (cda[CTA_PROTO_ICMP_CODE-1])
		tuple->l4dst.icmp.code =
			*(u_int8_t *)NFA_DATA(cda[CTA_PROTO_ICMP_CODE-1]);

	if (cda[CTA_PROTO_ICMP_ID-1])
		tuple->l4src.icmp.id =
			*(u_int16_t *)NFA_DATA(cda[CTA_PROTO_ICMP_ID-1]);
}

int print_proto(char *buf, struct nfct_tuple *t)
{
	int size = 0;
	
	size += sprintf(buf, "type=%d code=%d ", t->l4dst.icmp.type,
					         t->l4dst.icmp.code);
	/* ID only makes sense with ECHO */
	if (t->l4dst.icmp.type == 8)
		size += sprintf(buf, "id=%d ", t->l4src.icmp.id);

	return size;
}

static struct nfct_proto icmp = {
	.name 			= "icmp",
	.protonum		= IPPROTO_ICMP,
	.parse_proto		= parse_proto,
	.print_proto		= print_proto,
	.version		= LIBNETFILTER_CONNTRACK_VERSION
};

void __attribute__ ((constructor)) init(void);
void __attribute__ ((destructor)) fini(void);

void init(void)
{
	nfct_register_proto(&icmp);
}

void fini(void)
{
	nfct_unregister_proto(&icmp);
}
