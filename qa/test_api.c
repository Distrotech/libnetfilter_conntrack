/*
 * Run this after adding a new attribute to the nf_conntrack object
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
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

int main(void)
{
	int ret, i;
	struct nf_conntrack *ct, *tmp;
	char data[32];
	int status;

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

	for (i=0; i<ATTR_MAX; i++)
		nfct_set_attr(ct, i, data);

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

	nfct_destroy(ct);
	nfct_destroy(tmp);
	return EXIT_SUCCESS;
}
