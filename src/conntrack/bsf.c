/*
 * (C) 2008 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#include "internal.h"
#include <linux/filter.h>

#ifndef SKF_AD_NLATTR
#define SKF_AD_NLATTR		12
#endif

#define NFCT_FILTER_REJECT	0U
#define NFCT_FILTER_ACCEPT	~0U

#if 0
static void show_filter(struct sock_filter *this, int size)
{
	int i;

	for(i=0; i<size; i++)
		printf("(%.4x) code=%.4x jt=%.2x jf=%.2x k=%.8x\n", 
					     i,
					     this[i].code & 0xFFFF,
					     this[i].jt   & 0xFF,
					     this[i].jf   & 0xFF,
					     this[i].k    & 0xFFFFFFFF);
}
#else
static inline void show_filter(struct sock_filter *this, int size) {}
#endif

static void set_basic_filter(struct sock_filter *this,
			     unsigned int first_type,
			     unsigned int second_type,
			     unsigned int third_type,
			     unsigned int label,
			     unsigned int word_size)
{
	struct sock_filter filter[] = {
	[0] = {
		/* A = sizeof(struct nlmsghdr) + sizeof(struct nfgenmsg) */
		.code	= BPF_LD|BPF_IMM,
		.k	= sizeof(struct nlmsghdr) + sizeof(struct nfgenmsg),
		},
	[1] = {
		/* X = first_type */
		.code	= BPF_LDX|BPF_IMM,
		.k	= first_type,
		},
	[2] = {
		/* A = netlink attribute offset */
		.code	= BPF_LD|BPF_B|BPF_ABS,
		.k	= SKF_AD_OFF + SKF_AD_NLATTR,
		},
	[3] = {
		/* Reject if not found (A == 0) */
		.code	= BPF_JMP|BPF_JEQ|BPF_K,
		.k	= 0,
		.jt	= label - 3 - 1,
		},
	[4] = {
		/* A += sizeof(struct nfattr) */
		.code	= BPF_ALU|BPF_ADD|BPF_K,
		.k	= sizeof(struct nfattr),
		},
	[5] = {
		/* X = second_type */
		.code	= BPF_LDX|BPF_IMM,
		.k	= second_type,
		},
	[6] = {
		/* A = netlink attribute offset */
		.code	= BPF_LD|BPF_B|BPF_ABS,
		.k	= SKF_AD_OFF + SKF_AD_NLATTR,
		},
	[7] = {
		/* Reject if not found (A == 0) */
		.code	= BPF_JMP|BPF_JEQ|BPF_K,
		.k	= 0,
		.jt	= label - 7 - 1,
		},
	[8] = {
		/* A += sizeof(struct nfattr) */
		.code	= BPF_ALU|BPF_ADD|BPF_K,
		.k	= sizeof(struct nfattr),
		},
	[9] = {
		/* X = third_type */
		.code	= BPF_LDX|BPF_IMM,
		.k	= third_type,
		},
	[10] = {
		/* A = netlink attribute offset */
		.code	= BPF_LD|BPF_B|BPF_ABS,
		.k	= SKF_AD_OFF + SKF_AD_NLATTR,
		},
	[11] = {
		/* Reject if not found (A == 0) */
		.code	= BPF_JMP|BPF_JEQ|BPF_K,
		.k	= 0,
		.jt	= label - 11 - 1,
		},
	[12] = {
		/* X = A */
		.code	= BPF_MISC|BPF_TAX,
		},
	[13] = {
		/* A = skb->data[X + k:word_size] */
		.code	= BPF_LD|word_size|BPF_IND,
		.k	= sizeof(struct nfattr),
		},
	};

	memcpy(this, filter, sizeof(filter));
}

static int
add_state_filter_cta(struct sock_filter *this,
		     unsigned int cta_protoinfo_proto,
		     unsigned int cta_protoinfo_state,
		     u_int16_t state_flags,
		     size_t remain)
{
	struct sock_filter filter[14 + __FILTER_PROTO_MAX];
	struct sock_filter verdict = {
		/* Reject */
		.code	= BPF_RET|BPF_K,
		.k	= NFCT_FILTER_REJECT,
	};
	unsigned int i, j;
	unsigned int label_continue;

	/* calculate the number of filter lines */
	for (i = 0, j = 0; i < sizeof(state_flags) * 8; i++) {
		if (state_flags & (1 << i)) {
			j++;
		}
	}

	/* nothing to filter, skip */
	if (j == 0)
		return 0;

	if (j + 14 >= __FILTER_PROTO_MAX + 14 || j + 14 > remain) {
		errno = ENOSPC;
		return -1;
	}

	memset(filter, 0, sizeof(filter));

	label_continue = j + 1;

	set_basic_filter(filter,
			 CTA_PROTOINFO,
			 cta_protoinfo_proto,
			 cta_protoinfo_state,
			 14 + label_continue,
			 BPF_B);

	for (i = 0, j = 0; i < sizeof(state_flags) * 8; i++) {
		struct sock_filter cmp = {
			.code	= BPF_JMP|BPF_JEQ|BPF_K,
			.k	= i,
			.jt	= label_continue - j - 1,
		};

		if (state_flags & (1 << i)) {
			memcpy(&filter[j + 14], &cmp, sizeof(cmp));
			j++;
		}
	}

	memcpy(this, filter, sizeof(struct sock_filter) * (j + 14));
	memcpy(&this[j + 14], &verdict, sizeof(verdict));

	return j + 14 + 1;
}

static int 
add_state_filter(struct sock_filter *this, 
		 int proto,
		 u_int16_t flags,
		 size_t remain)
{
	struct {
		unsigned int cta_protoinfo;
		unsigned int cta_state;
	} cta[IPPROTO_MAX] = {
		[IPPROTO_TCP] = {
			.cta_protoinfo = CTA_PROTOINFO_TCP,
			.cta_state = CTA_PROTOINFO_TCP_STATE,
		},
		[IPPROTO_SCTP] = {
			.cta_protoinfo = CTA_PROTOINFO_SCTP,
			.cta_state = CTA_PROTOINFO_SCTP_STATE,
		},
		[IPPROTO_DCCP] = {
			.cta_protoinfo = CTA_PROTOINFO_DCCP,
			.cta_state = CTA_PROTOINFO_DCCP_STATE,
		},
	};

	if (cta[proto].cta_protoinfo == 0 && cta[proto].cta_state == 0) {
		errno = ENOTSUP;
		return -1;
	}

	return add_state_filter_cta(this,
				    cta[proto].cta_protoinfo,
				    cta[proto].cta_state,
				    flags,
				    remain);
}

static int 
bsf_add_state_filter(const struct nfct_filter *filter,
		     struct sock_filter *this, 
		     size_t remain)
{
	unsigned int i, j;

	for (i = 0, j = 0; i < IPPROTO_MAX; i++) {
		if (test_bit(i, filter->l4proto_map) &&
		    filter->l4proto_state[i].map) {
			j += add_state_filter(this, 
					      i, 
					      filter->l4proto_state[i].map,
					      remain);
		}
	}

	return j;
}

static int 
bsf_add_proto_filter(const struct nfct_filter *f,
		     struct sock_filter *this,
		     size_t remain)
{
	struct sock_filter filter[14 + IPPROTO_MAX];
	struct sock_filter verdict = {
		/* Reject */
		.code	= BPF_RET|BPF_K,
		.k	= NFCT_FILTER_REJECT,
	};
	unsigned int i, j;
	unsigned int label_continue;

	for (i = 0, j = 0; i < IPPROTO_MAX; i++) {
		if (test_bit(i, f->l4proto_map)) {
			j++;
		}
	}

	/* nothing to filter, skip */
	if (j == 0)
		return 0;

	if (j + 14 >= IPPROTO_MAX + 14 || j + 14 > remain) {
		errno = ENOSPC;
		return -1;
	}

	label_continue = j + 1;

	memset(filter, 0, sizeof(filter));

	set_basic_filter(filter,
			 CTA_TUPLE_ORIG,
			 CTA_TUPLE_PROTO,
			 CTA_PROTO_NUM,
			 14 + label_continue,
			 BPF_B);

	for (i = 0, j = 0; i < IPPROTO_MAX; i++) {
		struct sock_filter cmp = {
			.code	= BPF_JMP|BPF_JEQ|BPF_K,
			.k	= i,
			.jt	= label_continue - j - 1,
		};

		if (test_bit(i, f->l4proto_map)) {
			memcpy(&filter[j + 14], &cmp, sizeof(cmp));
			j++;
		}
	}

	memcpy(this, filter, sizeof(struct sock_filter) * (j + 14));
	memcpy(&this[j + 14], &verdict, sizeof(verdict));

	return j + 14 + 1;
}

static int
bsf_add_addr_ipv4_filter(const struct nfct_filter *f,
		         struct sock_filter *this,
			 unsigned int type,
		         size_t remain)
{
	struct sock_filter filter[14 + __FILTER_ADDR_MAX];
	struct sock_filter verdict = {
		/* Reject */
		.code	= BPF_RET|BPF_K,
		.k	= NFCT_FILTER_REJECT,
	};
	unsigned int i, j, dir;
	unsigned int label_continue;

	switch(type) {
	case CTA_IP_V4_SRC:
		dir = __FILTER_ADDR_SRC;
		break;
	case CTA_IP_V4_DST:
		dir = __FILTER_ADDR_DST;
		break;
	default:
		return 0;
	}

	/* nothing to filter, skip */
	if (f->l3proto_elems[dir] == 0)
		return 0;

	if (f->l3proto_elems[dir] + 14 >= __FILTER_ADDR_MAX + 14 ||
	    f->l3proto_elems[dir] + 14 > remain) {
	    	errno = ENOSPC;
		return -1;
	}

	label_continue = (f->l3proto_elems[dir] * 2) + 1;

	memset(filter, 0, sizeof(filter));

	set_basic_filter(filter,
			 CTA_TUPLE_ORIG,
			 CTA_TUPLE_IP,
			 type,
			 14 + label_continue,
			 BPF_W);

	for (i = 0, j = 0; i < f->l3proto_elems[dir]; i++) {
		struct sock_filter cmp[] = {
		[0] = {
			.code 	= BPF_ALU|BPF_AND|BPF_K,
			.k	= f->l3proto[dir][i].mask,
			},
		[1] = {
			.code	= BPF_JMP|BPF_JEQ|BPF_K,
			.k	= f->l3proto[dir][i].addr & 
				  f->l3proto[dir][i].mask,
			.jt	= label_continue - j - 2,
			},
		};
		memcpy(&filter[j + 14], cmp, sizeof(cmp));
		j+=2;
	}

	memcpy(this, filter, sizeof(struct sock_filter) * (j + 14));
	memcpy(&this[j + 14], &verdict, sizeof(verdict));

	return j + 14 + 1;
}

static int
bsf_add_saddr_ipv4_filter(const struct nfct_filter *f,
			  struct sock_filter *this,
			  size_t remain)
{
	return bsf_add_addr_ipv4_filter(f, this, CTA_IP_V4_SRC, remain);
}

static int 
bsf_add_daddr_ipv4_filter(const struct nfct_filter *f,
			  struct sock_filter *this,
			  size_t remain)
{
	return bsf_add_addr_ipv4_filter(f, this, CTA_IP_V4_DST, remain);
}

/* this buffer must be big enough to store all the autogenerated lines */
#define BSF_BUFFER_SIZE 	1024

int __setup_netlink_socket_filter(int fd, struct nfct_filter *f)
{
	struct sock_filter bsf[BSF_BUFFER_SIZE];	
	struct sock_filter bsf_accept = {
		/* Accept */
		.code	= BPF_RET|BPF_K,
		.k	= NFCT_FILTER_ACCEPT,
	};
	struct sock_fprog sf;	
	unsigned int j = 0;

	memset(bsf, 0, sizeof(bsf));

	j += bsf_add_proto_filter(f, &bsf[j], BSF_BUFFER_SIZE-j);
	j += bsf_add_saddr_ipv4_filter(f, &bsf[j], BSF_BUFFER_SIZE-j);
	j += bsf_add_daddr_ipv4_filter(f, &bsf[j], BSF_BUFFER_SIZE-j);
	j += bsf_add_state_filter(f, &bsf[j], BSF_BUFFER_SIZE-j);

	/* nothing to filter, skip */
	if (j == 0)
		return 0;

	memcpy(&bsf[j], &bsf_accept, sizeof(struct sock_filter));

	show_filter(bsf, j+1);

	sf.len = (sizeof(struct sock_filter) * (j + 1)) / sizeof(bsf[0]);
	sf.filter = bsf;

	return setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &sf, sizeof(sf));
}
