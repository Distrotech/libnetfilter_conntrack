#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>

static int cb(enum nf_conntrack_msg_type type,
	      struct nf_expect *exp,
	      void *data)
{
	char buf[1024];

	nfexp_snprintf(buf, 1024, exp, NFCT_T_UNKNOWN, NFCT_O_DEFAULT, 0);
	printf("%s\n", buf);

	return NFCT_CB_CONTINUE;
}

static int event_cb(enum nf_conntrack_msg_type type,
		    struct nf_expect *exp,
		    void *data)
{
	static int n = 0;
	char buf[1024];

	nfexp_snprintf(buf, 1024, exp, type, NFCT_O_DEFAULT, 0);
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
	struct nf_conntrack *master, *expected, *mask;
	struct nf_expect *exp;
	char buf[1024];

	printf("Test for NEW expectation libnetfilter_conntrack API\n");
	printf("===================================================\n");

	master = nfct_new();
	if (!master) {
		perror("nfct_new");
		exit(EXIT_FAILURE);
	}

	nfct_set_attr_u8(master, ATTR_ORIG_L3PROTO, AF_INET);
	nfct_set_attr_u32(master, ATTR_ORIG_IPV4_SRC, inet_addr("1.1.1.1"));
	nfct_set_attr_u32(master, ATTR_ORIG_IPV4_DST, inet_addr("2.2.2.2"));

	nfct_set_attr_u8(master, ATTR_ORIG_L4PROTO, IPPROTO_TCP);
	nfct_set_attr_u16(master, ATTR_ORIG_PORT_SRC, htons(1025));
	nfct_set_attr_u16(master, ATTR_ORIG_PORT_DST, htons(21));

	nfct_set_attr_u8(master, ATTR_REPL_L3PROTO, AF_INET);
	nfct_set_attr_u32(master, ATTR_REPL_IPV4_SRC, inet_addr("2.2.2.2"));
	nfct_set_attr_u32(master, ATTR_REPL_IPV4_DST, inet_addr("1.1.1.1"));

	nfct_set_attr_u8(master, ATTR_REPL_L4PROTO, IPPROTO_TCP);
	nfct_set_attr_u16(master, ATTR_REPL_PORT_SRC, htons(21));
	nfct_set_attr_u16(master, ATTR_REPL_PORT_DST, htons(1025));

	nfct_set_attr_u8(master, ATTR_TCP_STATE, TCP_CONNTRACK_LISTEN);
	nfct_set_attr_u32(master, ATTR_TIMEOUT, 200);

	h = nfct_open(CONNTRACK, 0);
	if (!h) {
		perror("nfct_open");
		return -1;
	}

	ret = nfct_query(h, NFCT_Q_CREATE, master);

	printf("TEST 1: create conntrack (%d)(%s)\n", ret, strerror(errno));

	nfct_close(h);

	expected = nfct_new();
	if (!expected) {
		perror("nfct_new");
		exit(EXIT_FAILURE);
	}

	nfct_set_attr_u8(expected, ATTR_ORIG_L3PROTO, AF_INET);
	nfct_set_attr_u32(expected, ATTR_ORIG_IPV4_SRC, inet_addr("4.4.4.4"));
	nfct_set_attr_u32(expected, ATTR_ORIG_IPV4_DST, inet_addr("5.5.5.5"));

	nfct_set_attr_u8(expected, ATTR_ORIG_L4PROTO, IPPROTO_TCP);
	nfct_set_attr_u16(expected, ATTR_ORIG_PORT_SRC, htons(10240));
	nfct_set_attr_u16(expected, ATTR_ORIG_PORT_DST, htons(10241));

	mask = nfct_new();
	if (!mask) {
		perror("nfct_new");
		exit(EXIT_FAILURE);
	}

	nfct_set_attr_u8(mask, ATTR_ORIG_L3PROTO, AF_INET);
	nfct_set_attr_u32(mask, ATTR_ORIG_IPV4_SRC, 0xffffffff);
	nfct_set_attr_u32(mask, ATTR_ORIG_IPV4_DST, 0xffffffff);

	nfct_set_attr_u8(mask, ATTR_ORIG_L4PROTO, IPPROTO_TCP);
	nfct_set_attr_u16(mask, ATTR_ORIG_PORT_SRC, 0xffff);
	nfct_set_attr_u16(mask, ATTR_ORIG_PORT_DST, 0xffff);
	
	exp = nfexp_new();
	if (!exp) {
		perror("nfexp_new");
		exit(EXIT_FAILURE);
	}

	nfexp_set_attr(exp, ATTR_EXP_MASTER, master);
	nfexp_set_attr(exp, ATTR_EXP_EXPECTED, expected);
	nfexp_set_attr(exp, ATTR_EXP_MASK, mask);
	nfexp_set_attr_u32(exp, ATTR_EXP_TIMEOUT, 200);

	h = nfct_open(EXPECT, 0);
	if (!h) {
		perror("nfct_open");
		return -1;
	}

	ret = nfexp_query(h, NFCT_Q_CREATE, exp);

	printf("TEST 2: create expectation (%d)(%s)\n", ret, strerror(errno));

	nfexp_callback_register(h, NFCT_T_ALL, cb, NULL);
	ret = nfexp_query(h, NFCT_Q_GET, exp);

	printf("TEST 3: get expectation (%d)(%s)\n", ret, strerror(errno));

	ret = nfexp_query(h, NFCT_Q_DESTROY, exp);

	printf("TEST 4: destroy expectation (%d)(%s)\n", ret, strerror(errno));

	nfct_close(h);

	h = nfct_open(EXPECT, NF_NETLINK_CONNTRACK_EXP_NEW);
	if (!h) {
		perror("nfct_open");
		return -1;
	}

	nfexp_callback_register(h, NFCT_T_ALL, event_cb, NULL);

	printf("TEST 5: waiting for 10 events...\n");

	ret = nfexp_catch(h);

	printf("TEST 5: OK (%d)(%s)\n", ret, strerror(errno));

	nfct_close(h);
}
