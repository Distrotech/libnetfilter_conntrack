/*
 * (C) 2006-2007 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#include "internal/internal.h"

static void set_exp_attr_master(struct nf_expect *exp, const void *value)
{
	exp->master = *((struct nf_conntrack *) value);
}

static void set_exp_attr_expected(struct nf_expect *exp, const void *value)
{
	exp->expected = *((struct nf_conntrack *) value);
}

static void set_exp_attr_mask(struct nf_expect *exp, const void *value)
{
	exp->mask = *((struct nf_conntrack *) value);
}

static void set_exp_attr_timeout(struct nf_expect *exp, const void *value)
{
	exp->timeout = *((u_int32_t *) value);
}

static void set_exp_attr_zone(struct nf_expect *exp, const void *value)
{
	exp->zone = *((u_int16_t *) value);
}

static void set_exp_attr_flags(struct nf_expect *exp, const void *value)
{
	exp->flags = *((u_int32_t *) value);
}

const set_exp_attr set_exp_attr_array[ATTR_EXP_MAX] = {
	[ATTR_EXP_MASTER]		= set_exp_attr_master,
	[ATTR_EXP_EXPECTED]		= set_exp_attr_expected,
	[ATTR_EXP_MASK]			= set_exp_attr_mask,
	[ATTR_EXP_TIMEOUT]		= set_exp_attr_timeout,
	[ATTR_EXP_ZONE]			= set_exp_attr_zone,
	[ATTR_EXP_FLAGS]		= set_exp_attr_flags,
};
