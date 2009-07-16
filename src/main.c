/*
 * (C) 2005-2006 by Pablo Neira Ayuso <pablo@netfilter.org>
 *                  Harald Welte <laforge@netfilter.org>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 */
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include "internal/internal.h"

struct nfct_handle *nfct_open_nfnl(struct nfnl_handle *nfnlh,
				   u_int8_t subsys_id,
				   unsigned int subscriptions)
{
	struct nfct_handle *cth;

	cth = (struct nfct_handle *) malloc(sizeof(struct nfct_handle));
	if (!cth)
		return NULL;
	
	memset(cth, 0, sizeof(*cth));
	cth->nfnlh = nfnlh;

	if (subsys_id == 0 || subsys_id == NFNL_SUBSYS_CTNETLINK) {
		cth->nfnlssh_ct = nfnl_subsys_open(cth->nfnlh, 
						   NFNL_SUBSYS_CTNETLINK, 
						   IPCTNL_MSG_MAX,
						   subscriptions);
		if (!cth->nfnlssh_ct)
			goto out_free;
	}

	if (subsys_id == 0 || subsys_id == NFNL_SUBSYS_CTNETLINK_EXP) {
		cth->nfnlssh_exp = nfnl_subsys_open(cth->nfnlh,
						    NFNL_SUBSYS_CTNETLINK_EXP,
						    IPCTNL_MSG_EXP_MAX,
						    subscriptions);
		if (!cth->nfnlssh_exp)
			goto out_free;
	}

	return cth;

out_free:
	if (cth->nfnlssh_exp) {
		nfnl_subsys_close(cth->nfnlssh_exp);
		cth->nfnlssh_exp = NULL;
	}
	if (cth->nfnlssh_ct) {
		nfnl_subsys_close(cth->nfnlssh_ct);
		cth->nfnlssh_ct = NULL;
	}
	free(cth);
	return NULL;
}

struct nfct_handle *nfct_open(u_int8_t subsys_id, unsigned subscriptions)
{
	struct nfnl_handle *nfnlh = nfnl_open();
	struct nfct_handle *nfcth;

	if (!nfnlh)
		return NULL;

	nfcth = nfct_open_nfnl(nfnlh, subsys_id, subscriptions);
	if (!nfcth)
		nfnl_close(nfnlh);

	return nfcth;
}

int nfct_close(struct nfct_handle *cth)
{
	int err;

	if (cth->nfnlssh_exp) {
		nfnl_subsys_close(cth->nfnlssh_exp);
		cth->nfnlssh_exp = NULL;
	}
	if (cth->nfnlssh_ct) {
		nfnl_subsys_close(cth->nfnlssh_ct);
		cth->nfnlssh_ct = NULL;
	}

	/* required by the new API */
	cth->cb = NULL;
	cth->cb2 = NULL;
	cth->expect_cb = NULL;
	cth->expect_cb2 = NULL;
	free(cth->nfnl_cb.data);

	cth->nfnl_cb.call = NULL; 
	cth->nfnl_cb.data = NULL;
	cth->nfnl_cb.attr_count = 0;

	err = nfnl_close(cth->nfnlh);
	free(cth);

	return err;
}

int nfct_fd(struct nfct_handle *cth)
{
	return nfnl_fd(cth->nfnlh);
}

const struct nfnl_handle *nfct_nfnlh(struct nfct_handle *cth)
{
	return cth->nfnlh;
}
