/*
 * (C) 2006-2007 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#include "internal/internal.h"

static const void *get_exp_attr_master(const struct nf_expect *exp)
{
	return &exp->master;
}

static const void *get_exp_attr_expected(const struct nf_expect *exp)
{
	return &exp->expected;
}

static const void *get_exp_attr_mask(const struct nf_expect *exp)
{
	return &exp->mask;
}

static const void *get_exp_attr_timeout(const struct nf_expect *exp)
{
	return &exp->timeout;
}

static const void *get_exp_attr_zone(const struct nf_expect *exp)
{
	return &exp->zone;
}

static const void *get_exp_attr_flags(const struct nf_expect *exp)
{
	return &exp->flags;
}

const get_exp_attr get_exp_attr_array[ATTR_EXP_MAX] = {
	[ATTR_EXP_MASTER]		= get_exp_attr_master,
	[ATTR_EXP_EXPECTED]		= get_exp_attr_expected,
	[ATTR_EXP_MASK]			= get_exp_attr_mask,
	[ATTR_EXP_TIMEOUT]		= get_exp_attr_timeout,
	[ATTR_EXP_ZONE]			= get_exp_attr_zone,
	[ATTR_EXP_FLAGS]		= get_exp_attr_flags,
};
