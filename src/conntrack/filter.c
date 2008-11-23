/*
 * (C) 2008 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#include "internal/internal.h"

static void filter_attr_l4proto(struct nfct_filter *filter, const void *value)
{
	set_bit(*((int *) value), filter->l4proto_map);
}

static void 
filter_attr_l4proto_state(struct nfct_filter *filter, const void *value)
{
	const struct nfct_filter_proto *this = value;

	set_bit_u16(this->state, &filter->l4proto_state[this->proto].map);
}

static void filter_attr_src_ipv4(struct nfct_filter *filter, const void *value)
{
	const struct nfct_filter_ipv4 *this = value;

	filter->l3proto[0][filter->l3proto_elems[0]].addr = this->addr;
	filter->l3proto[0][filter->l3proto_elems[0]].mask = this->mask;
	filter->l3proto_elems[0]++;
}

static void filter_attr_dst_ipv4(struct nfct_filter *filter, const void *value)
{
	const struct nfct_filter_ipv4 *this = value;

	filter->l3proto[1][filter->l3proto_elems[1]].addr = this->addr;
	filter->l3proto[1][filter->l3proto_elems[1]].mask = this->mask;
	filter->l3proto_elems[1]++;
}

filter_attr filter_attr_array[NFCT_FILTER_MAX] = {
	[NFCT_FILTER_L4PROTO]		= filter_attr_l4proto,
	[NFCT_FILTER_L4PROTO_STATE]	= filter_attr_l4proto_state,
	[NFCT_FILTER_SRC_IPV4]		= filter_attr_src_ipv4,
	[NFCT_FILTER_DST_IPV4]		= filter_attr_dst_ipv4,
};
