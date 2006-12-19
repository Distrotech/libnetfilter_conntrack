#include <stdio.h>
#include <errno.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>

static int cb(enum nf_conntrack_msg_type type,
	      struct nf_conntrack *ct,
	      void *data)
{
	char buf[1024];

	nfct_snprintf(buf, 1024, ct, NFCT_T_UNKNOWN, NFCT_O_DEFAULT, NFCT_OF_SHOW_LAYER3);
	printf("%s\n", buf);

	return NFCT_CB_CONTINUE;
}

static int event_cb(enum nf_conntrack_msg_type type,
		    struct nf_conntrack *ct,
		    void *data)
{
	static int n = 0;
	char buf[1024];

	nfct_snprintf(buf, 1024, ct, type, NFCT_O_XML, 0);
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

	printf("Test for NEW libnetfilter_conntrack API\n");
	printf("=======================================\n");

	ct = nfct_new();
	if (!ct) {
		perror("nfct_new");
		return 0;
	}

	nfct_set_attr_u8(ct, ATTR_ORIG_L3PROTO, AF_INET);
	nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_SRC, inet_addr("1.1.1.1"));
	nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_DST, inet_addr("2.2.2.2"));
	
	nfct_set_attr_u8(ct, ATTR_ORIG_L4PROTO, IPPROTO_TCP);
	nfct_set_attr_u16(ct, ATTR_ORIG_PORT_SRC, ntohs(20));
	nfct_set_attr_u16(ct, ATTR_ORIG_PORT_DST, ntohs(10));

	nfct_set_attr_u8(ct, ATTR_REPL_L3PROTO, AF_INET);
	nfct_set_attr_u32(ct, ATTR_REPL_IPV4_SRC, inet_addr("2.2.2.2"));
	nfct_set_attr_u32(ct, ATTR_REPL_IPV4_DST, inet_addr("1.1.1.1"));
	
	nfct_set_attr_u8(ct, ATTR_REPL_L4PROTO, IPPROTO_TCP);
	nfct_set_attr_u16(ct, ATTR_REPL_PORT_SRC, ntohs(10));
	nfct_set_attr_u16(ct, ATTR_REPL_PORT_DST, ntohs(20));

	nfct_set_attr_u8(ct, ATTR_TCP_STATE, TCP_CONNTRACK_LISTEN);
	nfct_set_attr_u32(ct, ATTR_TIMEOUT, 100);

	h = nfct_open(CONNTRACK, 0);
	if (!h) {
		perror("nfct_open");
		return -1;
	}

	ret = nfct_query(h, NFCT_Q_CREATE, ct);

	printf("TEST 1: create conntrack (%d)(%s)\n", ret, strerror(errno));
	
	ret = nfct_query(h, NFCT_Q_UPDATE, ct);

	printf("TEST 2: update conntrack (%d)(%s)\n", ret, strerror(errno));

	nfct_callback_register(h, NFCT_T_ALL, cb, NULL);
	ret = nfct_query(h, NFCT_Q_GET, ct);

	printf("TEST 3: get conntrack (%d)(%s)\n", ret, strerror(errno));

	ret = nfct_query(h, NFCT_Q_DESTROY, ct);

	printf("TEST 4: destroy conntrack (%d)(%s)\n", ret, strerror(errno));

	nfct_set_attr_u32(ct, ATTR_SNAT_IPV4, inet_addr("8.8.8.8"));
	ret = nfct_query(h, NFCT_Q_CREATE, ct);

	printf("TEST 5: create NAT conntrack (%d)(%s)\n", ret, strerror(errno));

	ret = nfct_query(h, NFCT_Q_GET, ct);

	printf("TEST 6: get NAT conntrack (%d)(%s)\n", ret, strerror(errno));

	ret = nfct_query(h, NFCT_Q_DESTROY, ct);

	printf("TEST 7: destroy NAT conntrack (%d)(%s)\n",ret,strerror(errno));

	nfct_close(h);

	h = nfct_open(CONNTRACK, NFCT_ALL_CT_GROUPS);
	if (!h) {
		perror("nfct_open");
		return -1;
	}

	nfct_callback_register(h, NFCT_T_ALL, event_cb, NULL);

	printf("TEST 8: waiting for 10 events...\n");

	ret = nfct_catch(h);

	printf("TEST 8: OK (%d)(%s)\n", ret, strerror(errno));

	nfct_close(h);
}
