#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <string.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#include <linux/filter.h>

#define SKF_AD_NLATTR	12

#define FILTER_REJECT	0x0000
#define FILTER_ACCEPT	0xFFFF

static int sk_set_filter(int fd)
{
	struct sock_filter filt[] = {
		{
			/* A=sizeof(struct nlmsghdr)+sizeof(struct nfgenmsg) */
			.code	= BPF_LD|BPF_IMM,
			.k	= sizeof(struct nlmsghdr) + sizeof(struct nfgenmsg),
		},
		{
			/* X = CTA_PROTOINFO */
			.code	= BPF_LDX|BPF_IMM,
			.k	= CTA_PROTOINFO,
		},
		{
			/* A = netlink attribute offset */
			.code	= BPF_LD|BPF_B|BPF_ABS,
			.k	= SKF_AD_OFF + SKF_AD_NLATTR,
		},
		{
			/* Reject if not found (A == 0) */
			.code	= BPF_JMP|BPF_JEQ|BPF_K,
			.k	= 0,
			.jt	= 20 - 3 - 1,
		},

		{
			/* A += sizeof(struct nlattr) */
			.code	= BPF_ALU|BPF_ADD|BPF_K,
			.k	= sizeof(struct nlattr),
		},
		{
			/* X = CTA_PROTOINFO_TCP */
			.code	= BPF_LDX|BPF_IMM,
			.k	= CTA_PROTOINFO_TCP,
		},
		{
			/* A = netlink attribute offset */
			.code	= BPF_LD|BPF_B|BPF_ABS,
			.k	= SKF_AD_OFF + SKF_AD_NLATTR,
		},
		{
			/* Reject if not found (A == 0) */
			.code	= BPF_JMP|BPF_JEQ|BPF_K,
			.k	= 0,
			.jt	= 20 - 7 - 1,
		},

		{
			/* A += sizeof(struct nlattr) */
			.code	= BPF_ALU|BPF_ADD|BPF_K,
			.k	= sizeof(struct nlattr),
		},
		{
			/* X = CTA_PROTOINFO_TCP_STATE */
			.code	= BPF_LDX|BPF_IMM,
			.k	= CTA_PROTOINFO_TCP_STATE,
		},
		{
			/* A = netlink attribute offset */
			.code	= BPF_LD|BPF_B|BPF_ABS,
			.k	= SKF_AD_OFF + SKF_AD_NLATTR,
		},
		{
			/* Reject if not found (A == 0) */
			.code	= BPF_JMP|BPF_JEQ|BPF_K,
			.k	= 0,
			.jt	= 20 - 11 - 1,
		},

		{
			/* X = A */
			.code	= BPF_MISC|BPF_TAX,
		},
		{
			/* A = skb->data[X + k] */
			.code	= BPF_LD|BPF_B|BPF_IND,
			.k	= sizeof(struct nlattr),
		},
		{
			/* Reject if A != TCA_CONNTRACK_ESTABLISHED */
			.code	= BPF_JMP|BPF_JEQ|BPF_K,
			.k	= TCP_CONNTRACK_ESTABLISHED,
			.jt	= 20 - 14 - 1,
		},

		{
			/* Reject */
			.code	= BPF_RET|BPF_K,
			.k	= 0,
		},
		[20]	= {
			/* Accept */
			.code	= BPF_RET|BPF_K,
			.k	= 0xFFFF,
		},
	};
	struct sock_fprog fprog = {
		.len		= sizeof(filt) / sizeof(filt[0]),
		.filter		= filt,
	};

	return setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER,
			  &fprog, sizeof(fprog));
}

#define LABEL_REJECT	29
#define LABEL_ACCEPT	30

struct sock_filter filter[] = {
	[0] = {
		/* A = sizeof(struct nlmsghdr) + sizeof(struct nfgenmsg) */
		.code	= BPF_LD|BPF_IMM,
		.k	= sizeof(struct nlmsghdr) + sizeof(struct nfgenmsg),
	},
	[1] = {
		/* X = CTA_PROTOINFO */
		.code	= BPF_LDX|BPF_IMM,
		.k	= CTA_PROTOINFO,
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
		.jt	= LABEL_REJECT - 3 - 1,
	},
	[4] = {
		/* A += sizeof(struct nlattr) */
		.code	= BPF_ALU|BPF_ADD|BPF_K,
		.k	= sizeof(struct nlattr),
	},
	[5] = {
		/* X = CTA_PROTOINFO_TCP */
		.code	= BPF_LDX|BPF_IMM,
		.k	= CTA_PROTOINFO_TCP,
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
		.jt	= LABEL_REJECT - 7 - 1,
	},
	[8] = {
		/* A += sizeof(struct nlattr) */
		.code	= BPF_ALU|BPF_ADD|BPF_K,
		.k	= sizeof(struct nlattr),
	},
	[9] = {
		/* X = CTA_PROTOINFO_TCP_STATE */
		.code	= BPF_LDX|BPF_IMM,
		.k	= CTA_PROTOINFO_TCP_STATE,
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
		.jt	= LABEL_REJECT - 11 - 1,
	},
	[12] = {
		/* X = A */
		.code	= BPF_MISC|BPF_TAX,
	},
	[13] = {
		/* A = skb->data[X + k] */
		.code	= BPF_LD|BPF_B|BPF_IND,
		.k	= sizeof(struct nlattr),
	},
#define FILTER_LINE 	14
	/* 
	 *
	 * We add TCP states matching code here
	 *
	 */
	[LABEL_REJECT] = {
		/* Reject */
		.code	= BPF_RET|BPF_K,
		.k	= FILTER_REJECT,
	},
	[LABEL_ACCEPT] = {
		/* Accept */
		.code	= BPF_RET|BPF_K,
		.k	= FILTER_ACCEPT,
	},
};

static void build_bsf_netlink(int *tcp_state_array, int len)
{
	struct sock_filter reject = {
		/* Reject */
		.code	= BPF_RET|BPF_K,
		.k	= 0,
	};
	int i;

	for (i=0; i<len; i++) {
		struct sock_filter cmp = {
			.code	= BPF_JMP|BPF_JEQ|BPF_K,
			.k	= tcp_state_array[i],
			.jt	= LABEL_ACCEPT - (i + FILTER_LINE) - 1,
		};

		memcpy(&filter[i+FILTER_LINE],&cmp,sizeof(struct sock_filter));
	}

//	memcpy(&filter[i+FILTER_LINE],&reject,sizeof(struct sock_filter));
}

static int event_cb(enum nf_conntrack_msg_type type,
		    struct nf_conntrack *ct,
		    void *data)
{
	static int n = 0;
	char buf[1024];

	nfct_snprintf(buf, 1024, ct, type, NFCT_O_PLAIN, NFCT_OF_TIME);
	printf("%s\n", buf);

	if (++n == 10)
		return NFCT_CB_STOP;

	return NFCT_CB_CONTINUE;
}

int main()
{
	int ret;
	u_int8_t family = AF_INET;
	struct nfct_handle *h;
	struct nf_conntrack *ct;
	char buf[1024];

	struct sock_fprog fprog = {
		.len		= sizeof(filter) / sizeof(filter[0]),
		.filter		= filter,
	};

	int i;
	int state[] = { TCP_CONNTRACK_ESTABLISHED, 
			TCP_CONNTRACK_FIN_WAIT };

	build_bsf_netlink(state, sizeof(state)/sizeof(int));

	h = nfct_open(CONNTRACK, NFCT_ALL_CT_GROUPS);
	if (!h) {
		perror("nfct_open");
		return 0;
	}

	if (setsockopt(nfct_fd(h), SOL_SOCKET, SO_ATTACH_FILTER, 
		       &fprog, sizeof(fprog)) < 0) {
//	if (sk_set_filter(nfct_fd(h)) < 0) {
		perror("setsockopt");
		return -1;
	}

	nfct_callback_register(h, NFCT_T_ALL, event_cb, NULL);

	printf("TEST: waiting for 10 events...\n");

	ret = nfct_catch(h);

	printf("TEST: OK (%d)(%s)\n", ret, strerror(errno));

	if (ret == -1)
		exit(EXIT_FAILURE);

	nfct_close(h);
}
