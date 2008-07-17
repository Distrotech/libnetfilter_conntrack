#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>

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
	struct nfct_filter *filter;
	struct nf_conntrack *ct;
	char buf[1024];

	h = nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_NEW | 
				 NF_NETLINK_CONNTRACK_UPDATE);
	if (!h) {
		perror("nfct_open");
		return 0;
	}

	filter = nfct_filter_create();
	if (!filter) {
		perror("nfct_create_filter");
		return 0;
	}

	nfct_filter_add_attr_u32(filter, NFCT_FILTER_L4PROTO, IPPROTO_UDP);
	nfct_filter_add_attr_u32(filter, NFCT_FILTER_L4PROTO, IPPROTO_TCP);

	struct nfct_filter_proto filter_proto = {
		.proto = IPPROTO_TCP,
		.state = TCP_CONNTRACK_ESTABLISHED
	};

	nfct_filter_add_attr(filter, NFCT_FILTER_L4PROTO_STATE, &filter_proto);

	struct nfct_filter_ipv4 filter_ipv4 = {
		.addr = htonl(inet_addr("127.0.0.1")),
		.mask = 0xffffffff,
	};

	nfct_filter_add_attr(filter, NFCT_FILTER_SRC_IPV4, &filter_ipv4);

	if (nfct_filter_attach(nfct_fd(h), filter) == -1) {
		perror("nfct_filter_attach");
		return 0;
	}

	/* release the filter object, this does not detach the filter */
	nfct_filter_destroy(filter);

	nfct_callback_register(h, NFCT_T_ALL, event_cb, NULL);

	printf("TEST: waiting for 10 events...\n");

	ret = nfct_catch(h);

	printf("TEST: OK (%d)(%s)\n", ret, strerror(errno));

	if (ret == -1)
		exit(EXIT_FAILURE);

	nfct_close(h);
}
