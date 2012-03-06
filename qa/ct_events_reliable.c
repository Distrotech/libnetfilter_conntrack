#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

static int event_cb(enum nf_conntrack_msg_type type,
		    struct nf_conntrack *ct,
		    void *data)
{
	static int i = 0;
	static int new, destroy;

	if (type == NFCT_T_NEW)
		new++;
	else if (type == NFCT_T_DESTROY)
		destroy++;

	if ((++i % 10000) == 0)
		printf("%d events received (%d new, %d destroy)\n",
			i, new, destroy);

	return NFCT_CB_CONTINUE;
}

int main(void)
{
	int ret;
	struct nfct_handle *h;
	int on = 1;

	h = nfct_open(CONNTRACK, NFCT_ALL_CT_GROUPS);
	if (!h) {
		perror("nfct_open");
		return 0;
	}

	setsockopt(nfct_fd(h), SOL_NETLINK,
			NETLINK_BROADCAST_SEND_ERROR, &on, sizeof(int));
	setsockopt(nfct_fd(h), SOL_NETLINK,
			NETLINK_NO_ENOBUFS, &on, sizeof(int));

	nfct_callback_register(h, NFCT_T_ALL, event_cb, NULL);

	printf("TEST: waiting for events...\n");

	ret = nfct_catch(h);

	printf("TEST: conntrack events ");
	if (ret == -1)
		printf("(%d)(%s)\n", ret, strerror(errno));
	else
		printf("(OK)\n");

	nfct_close(h);

	ret == -1 ? exit(EXIT_FAILURE) : exit(EXIT_SUCCESS);
}
