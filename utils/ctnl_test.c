/*
 * (C) 2005 by Pablo Neira Ayuso <pablo@eurodev.net>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * libnetfilter_conntrack test file: yet incomplete
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

int main(int argc, char **argv)
{
	struct nfct_conntrack *ct;
	struct nfct_tuple orig = {
		.src = { .v4 = inet_addr("1.1.1.1") },
		.dst = { .v4 = inet_addr("2.2.2.2") },
		.protonum = IPPROTO_TCP,
		.l4src = { .tcp = { .port = 10 } },
		.l4dst = { .tcp = { .port = 20 } }
	};
	struct nfct_tuple reply = {
		.src = { .v4 = inet_addr("2.2.2.2") },
		.dst = { .v4 = inet_addr("1.1.1.1") },
		.protonum = IPPROTO_TCP,
		.l4src = { .tcp = { .port = 20 } },
		.l4dst = { .tcp = { .port = 10 } }
	};
	union nfct_protoinfo proto = {
		.tcp = { .state = 1 },
	};
	unsigned long status = IPS_ASSURED | IPS_CONFIRMED;
	unsigned long timeout = 100;
	unsigned long mark = 0;
	unsigned long id = NFCT_ANY_ID;
	struct nfct_handle *cth;
	int ret = 0, errors = 0;

	/* Here we go... */
	fprintf(stdout, "Test for libnetfilter_conntrack\n\n");

	ct = nfct_conntrack_alloc(&orig, &reply, timeout, &proto, status,
				  mark, id, NULL);
	if (!ct) {
		fprintf(stderr, "Not enough memory");
		errors++;
		ret = -ENOMEM;
		goto end;
	}

	cth = nfct_open(CONNTRACK, 0);
	if (!cth) {
		fprintf(stderr, "Can't open handler\n");
		errors++;
		ret = -ENOENT;
		nfct_conntrack_free(ct);
		goto end;
	}

	ret = nfct_create_conntrack(cth, ct);
	fprintf(stdout, "TEST 1: create conntrack (%d)\n", ret);
	
	/* Skip EEXIST error, in case that the test has been called
	 * twice this spot a bogus error */
	if (ret < 0 && ret != -EEXIST)
		errors++;

	nfct_set_callback(cth, nfct_default_conntrack_display);
	ret = nfct_dump_conntrack_table(cth);
	fprintf(stdout, "TEST 2: dump conntrack table (%d)\n", ret);
	if (ret < 0)
		errors++;
	
	nfct_close(cth);
	nfct_conntrack_free(ct);

end:
	if (errors)
		fprintf(stdout, "Test failed with error %d. Errors=%d\n", 
			ret, errors);
	else
		fprintf(stdout, "Test OK\n");
}
