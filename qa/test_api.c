/*
 * Run this after adding a new attribute to the nf_conntrack object
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <errno.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

/*
 * this file contains a test to check the set/get/copy/cmp APIs.
 */

static void eval_sigterm(int status)
{
	switch(WTERMSIG(status)) {
	case SIGSEGV:
		printf("received SIGSEV\n");
		break;
	case 0:
		printf("OK\n");
		break;
	default:
		printf("exited with signal: %d\n", WTERMSIG(status));
		break;
	}
}

static void test_nfct_bitmask(void)
{
	struct nfct_bitmask *a, *b;
	unsigned short int maxb, i;

	printf("== test nfct_bitmask_* API ==\n");

	maxb = rand() & 0xffff;

	a = nfct_bitmask_new(maxb);

	assert(!nfct_bitmask_test_bit(a, maxb + 32));
	nfct_bitmask_set_bit(a, maxb + 32);
	assert(!nfct_bitmask_test_bit(a, maxb + 32));

	for (i = 0; i <= maxb; i++)
		assert(!nfct_bitmask_test_bit(a, i));

	for (i = 0; i <= maxb; i++) {
		if (rand() & 1) {
			assert(!nfct_bitmask_test_bit(a, i));
			continue;
		}
		nfct_bitmask_set_bit(a, i);
		assert(nfct_bitmask_test_bit(a, i));
	}

	b = nfct_bitmask_clone(a);
	assert(b);

	for (i = 0; i <= maxb; i++) {
		if (nfct_bitmask_test_bit(a, i))
			assert(nfct_bitmask_test_bit(b, i));
		else
			assert(!nfct_bitmask_test_bit(b, i));
	}

	nfct_bitmask_destroy(a);

	for (i = 0; i <= maxb; i++) {
		if (rand() & 1)
			continue;
		nfct_bitmask_unset_bit(b, i);
		assert(!nfct_bitmask_test_bit(b, i));
	}

	nfct_bitmask_destroy(b);
	printf("OK\n");
}


int main(void)
{
	int ret, i;
	struct nf_conntrack *ct, *ct2, *tmp;
	struct nf_expect *exp, *tmp_exp;
	char data[256];
	const char *val;
	int status;
	struct nfct_bitmask *b;

	srand(time(NULL));

	/* initialize fake data for testing purposes */
	for (i=0; i<sizeof(data); i++)
		data[i] = 0x01;

	ct = nfct_new();
	if (!ct) {
		perror("nfct_new");
		return 0;
	}
	tmp = nfct_new();
	if (!tmp) {
		perror("nfct_new");
		return 0;
	}

	printf("== test set API ==\n");
	ret = fork();
	if (ret == 0) {
		for (i=0; i<ATTR_MAX; i++)
			nfct_set_attr(ct, i, data);
		exit(0);
	} else {
		wait(&status);
		eval_sigterm(status);
	}

	for (i=0; i<ATTR_MAX; i++) {
		if (i != ATTR_CONNLABELS) {
			nfct_set_attr(ct, i, data);
			continue;
		}
		b = nfct_bitmask_new(rand() & 0xffff);
		assert(b);
		nfct_set_attr(ct, i, b);
	}

	printf("== test get API ==\n");
	ret = fork();
	if (ret == 0) {
		for (i=0; i<ATTR_MAX; i++)
			nfct_get_attr(ct, i);
		exit(0);
	} else {
		wait(&status);
		eval_sigterm(status);
	}

	printf("== validate set API ==\n");
	ret = fork();
	if (ret == 0) {
		for (i=0; i<ATTR_MAX; i++) {
			/* These attributes cannot be set, ignore them. */
			switch(i) {
			case ATTR_ORIG_COUNTER_PACKETS:
			case ATTR_REPL_COUNTER_PACKETS:
			case ATTR_ORIG_COUNTER_BYTES:
			case ATTR_REPL_COUNTER_BYTES:
			case ATTR_USE:
			case ATTR_SECCTX:
			case ATTR_TIMESTAMP_START:
			case ATTR_TIMESTAMP_STOP:
				continue;
			/* These attributes require special handling */
			case ATTR_HELPER_INFO:
				nfct_set_attr_l(ct, i, data, sizeof(data));
				break;
			case ATTR_CONNLABELS:
				/* already set above */
				break;
			default:
				data[0] = (uint8_t) i;
				nfct_set_attr(ct, i, data);
			}
			val = nfct_get_attr(ct, i);
			switch (i) {
			case ATTR_CONNLABELS:
				assert((void *) val == b);
				continue;
			}

			if (val[0] != data[0]) {
				printf("ERROR: set/get operations don't match "
				       "for attribute %d (%x != %x)\n",
					i, val[0], data[0]);
			}
		}
		exit(0);
	} else {
		wait(&status);
		eval_sigterm(status);
	}

	printf("== test copy API ==\n");
	ret = fork();
	if (ret == 0) {
		for (i=0; i<ATTR_MAX; i++)
			nfct_copy_attr(tmp, ct, i);
		exit(0);
	} else {
		wait(&status);
		eval_sigterm(status);
	}

	printf("== test cmp API ==\n");
	ret = fork();
	if (ret == 0) {
		nfct_cmp(tmp, ct, NFCT_CMP_ALL);
		exit(0);
	} else {
		wait(&status);
		eval_sigterm(status);
	}

	exp = nfexp_new();
	if (!exp) {
		perror("nfexp_new");
		return 0;
	}
	tmp_exp = nfexp_new();
	if (!tmp_exp) {
		perror("nfexp_new");
		return 0;
	}

	printf("== test expect set API ==\n");
	ret = fork();
	if (ret == 0) {
		for (i=0; i<ATTR_EXP_MAX; i++)
			nfexp_set_attr(exp, i, data);
		exit(0);
	} else {
		wait(&status);
		eval_sigterm(status);
	}

	for (i=0; i<ATTR_EXP_MAX; i++)
		nfexp_set_attr(exp, i, data);

	printf("== test expect get API ==\n");
	ret = fork();
	if (ret == 0) {
		for (i=0; i<ATTR_EXP_MAX; i++)
			nfexp_get_attr(exp, i);
		exit(0);
	} else {
		wait(&status);
		eval_sigterm(status);
	}

	printf("== validate expect set API ==\n");
	ret = fork();
	if (ret == 0) {
		for (i=0; i<ATTR_EXP_MAX; i++) {
			data[0] = (uint8_t) i;
			nfexp_set_attr(exp, i, data);
			val = nfexp_get_attr(exp, i);
			if (val[0] != data[0]) {
				printf("ERROR: set/get operations don't match "
				       "for attribute %d (%x != %x)\n",
					i, val[0], data[0]);
			}
		}
		exit(0);
	} else {
		wait(&status);
		eval_sigterm(status);
	}

	/* XXX: missing nfexp_copy API. */
	memcpy(tmp_exp, exp, nfexp_maxsize());

	printf("== test expect cmp API ==\n");
	ret = fork();
	if (ret == 0) {
		nfexp_cmp(tmp_exp, exp, 0);
		exit(0);
	} else {
		wait(&status);
		eval_sigterm(status);
	}

	ct2 = nfct_clone(ct);
	assert(ct2);
	assert(nfct_cmp(ct, ct2, NFCT_CMP_ALL) == 1);
	nfct_destroy(ct2);

	ct2 = nfct_new();
	if (!ct2) {
		perror("nfct_new");
		return 0;
	}

	printf("== test set grp API ==\n");
	ret = fork();
	if (ret == 0) {
		for (i=0; i<ATTR_GRP_MAX; i++)
			nfct_set_attr_grp(ct2, i, data);
		exit(0);
	} else {
		wait(&status);
		eval_sigterm(status);
	}

	for (i=0; i<ATTR_GRP_MAX; i++)
		nfct_set_attr_grp(ct2, i, data);

	printf("== test get grp API ==\n");
	ret = fork();
	if (ret == 0) {
		char buf[32]; /* IPv6 group address is 16 bytes * 2 */

		for (i=0; i<ATTR_GRP_MAX; i++)
			nfct_get_attr_grp(ct2, i, buf);
		exit(0);
	} else {
		wait(&status);
		eval_sigterm(status);
	}

	printf("== validate set grp API ==\n");
	ret = fork();
	if (ret == 0) {
		for (i=0; i<ATTR_GRP_MAX; i++) {
			char buf[32]; /* IPv6 group address is 16 bytes */

			data[0] = (uint8_t) i;
			nfct_set_attr_grp(ct2, i, data);
			nfct_get_attr_grp(ct2, i, buf);
			/* These attributes cannot be set, ignore them. */
			switch(i) {
			case ATTR_GRP_ORIG_COUNTERS:
			case ATTR_GRP_REPL_COUNTERS:
			case ATTR_GRP_ORIG_ADDR_SRC:
			case ATTR_GRP_ORIG_ADDR_DST:
			case ATTR_GRP_REPL_ADDR_SRC:
			case ATTR_GRP_REPL_ADDR_DST:
				continue;
			}
			if (buf[0] != data[0]) {
				printf("ERROR: set/get operations don't match "
				       "for attribute %d (%x != %x)\n",
					i, buf[0], data[0]);
			}
		}
		exit(0);
	} else {
		wait(&status);
		eval_sigterm(status);
	}

	nfct_destroy(ct2);
	printf("== destroy cloned ct entry ==\n");
	nfct_destroy(ct);
	nfct_destroy(tmp);
	nfexp_destroy(exp);
	nfexp_destroy(tmp_exp);

	printf("OK\n");

	test_nfct_bitmask();

	return EXIT_SUCCESS;
}
