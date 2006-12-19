/*
 * (C) 2006 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#include "internal.h"

static char *proto2str[IPPROTO_MAX] = {
	[IPPROTO_TCP] = "tcp",
        [IPPROTO_UDP] = "udp",
        [IPPROTO_ICMP] = "icmp",
        [IPPROTO_SCTP] = "sctp"
};

static char *l3proto2str[AF_MAX] = {
	[AF_INET] = "ipv4",
	[AF_INET6] = "ipv6"
};

static const char *states[] = {
	"NONE",
	"SYN_SENT",
	"SYN_RECV",
	"ESTABLISHED",
	"FIN_WAIT",
	"CLOSE_WAIT",
	"LAST_ACK",
	"TIME_WAIT",
	"CLOSE",
	"LISTEN"
};

static int __snprintf_l3protocol(char *buf,
				 unsigned int len,
				 const struct nf_conntrack *ct)
{
	return (snprintf(buf, len, "%-8s %u ", 
		l3proto2str[ct->tuple[__DIR_ORIG].l3protonum] == NULL ?
		"unknown" : l3proto2str[ct->tuple[__DIR_ORIG].l3protonum], 
		 ct->tuple[__DIR_ORIG].l3protonum));
}

static int __snprintf_protocol(char *buf,
			       unsigned int len,
			       const struct nf_conntrack *ct)
{
	return (snprintf(buf, len, "%-8s %u ", 
		proto2str[ct->tuple[__DIR_ORIG].protonum] == NULL ?
		"unknown" : proto2str[ct->tuple[__DIR_ORIG].protonum], 
		 ct->tuple[__DIR_ORIG].protonum));
}

int __snprintf_timeout(char *buf,
		       unsigned int len,
		       const struct nf_conntrack *ct)
{
	return snprintf(buf, len, "%u ", ct->timeout);
}

int __snprintf_protoinfo(char *buf, 
			 unsigned int len,
			 const struct nf_conntrack *ct)
{
	return snprintf(buf, len, "%s ", states[ct->protoinfo.tcp.state]);
}

int __snprintf_address_ipv4(char *buf,
			    unsigned int len,
			    const struct __nfct_tuple *tuple)
{
	int ret, size;
	struct in_addr src = { .s_addr = tuple->src.v4 };
	struct in_addr dst = { .s_addr = tuple->dst.v4 };

	ret = snprintf(buf, len, "src=%s ", inet_ntoa(src));
	if (ret == -1)
		return -1;
	size = ret;

	ret = snprintf(buf+size, len-size, "dst=%s ", inet_ntoa(dst));
	if (ret == -1)
		return -1;
	size += ret;

	return size;
}

int __snprintf_address_ipv6(char *buf, 
			    unsigned int len,
			    const struct __nfct_tuple *tuple)
{
	int size;
	struct in6_addr src;
	struct in6_addr dst;
	char tmp[INET6_ADDRSTRLEN];

	memcpy(&src.in6_u, &tuple->src.v6, sizeof(struct in6_addr));
	memcpy(&dst.in6_u, &tuple->dst.v6, sizeof(struct in6_addr));

	if (!inet_ntop(AF_INET6, &src, tmp, sizeof(tmp)))
		return -1;

	size = snprintf(buf, len, "src=%s ", tmp); 

	if (!inet_ntop(AF_INET6, &dst, tmp, sizeof(tmp)))
		return -1;

	size += snprintf(buf+size, len-size, "dst=%s ", tmp);

	return size;
}

int __snprintf_address(char *buf,
		       unsigned int len,
		       const struct __nfct_tuple *tuple)
{
	int size = 0;

	switch (tuple->l3protonum) {
	case AF_INET:
		size = __snprintf_address_ipv4(buf, len, tuple);
		break;
	case AF_INET6:
		size = __snprintf_address_ipv4(buf, len, tuple);
		break;
	}

	return size;
}

int __snprintf_proto(char *buf, 
		     unsigned int len,
		     const struct __nfct_tuple *tuple)
{
	int size = 0;

	switch(tuple->protonum) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_SCTP:
		return snprintf(buf, len, "sport=%u dport=%u ",
			        htons(tuple->l4src.tcp.port),
			        htons(tuple->l4dst.tcp.port));
		break;
	case IPPROTO_ICMP:
		/* The ID only makes sense some ICMP messages but we want to
		 * display the same output that /proc/net/ip_conntrack does */
		return (snprintf(buf, len, "type=%d code=%d id=%d ",
			tuple->l4dst.icmp.type,
			tuple->l4dst.icmp.code,
			ntohs(tuple->l4src.icmp.id)));
		break;
	}

	return size;
}

int __snprintf_status_assured(char *buf,
			      unsigned int len,
			      const struct nf_conntrack *ct)
{
	int size = 0;
	
	if (ct->status & IPS_ASSURED)
		size = snprintf(buf, len, "[ASSURED] ");

	return size;
}

int __snprintf_status_not_seen_reply(char *buf,
				     unsigned int len,
				     const struct nf_conntrack *ct)
{
	int size = 0;
	
        if (!(ct->status & IPS_SEEN_REPLY))
                size = snprintf(buf, len, "[UNREPLIED] ");

	return size;
}

int __snprintf_counters(char *buf, 
		        unsigned int len, 
		        const struct nf_conntrack *ct,
		        int dir)
{
	return (snprintf(buf, len, "packets=%llu bytes=%llu ",
			 (unsigned long long) ct->counters[dir].packets,
			 (unsigned long long) ct->counters[dir].bytes));
}

int __snprintf_mark(char *buf, unsigned int len, const struct nf_conntrack *ct)
{
	return (snprintf(buf, len, "mark=%u ", ct->mark));
}

int __snprintf_use(char *buf, unsigned int len, const struct nf_conntrack *ct)
{
	return (snprintf(buf, len, "use=%u ", ct->use));
}

int __snprintf_id(char *buf, unsigned int len, u_int32_t id)
{
	return (snprintf(buf, len, "id=%u ", id));
}

int __snprintf_conntrack_default(char *buf, 
				 unsigned int remain,
				 const struct nf_conntrack *ct,
				 unsigned int msg_type,
				 unsigned int flags) 
{
	int ret = 0, size = 0;

	switch(msg_type) {
		case NFCT_T_NEW:
			ret = snprintf(buf, remain, "%9s ", "[NEW]");
			break;
		case NFCT_T_UPDATE:
			ret = snprintf(buf, remain, "%9s ", "[UPDATE]");
			break;
		case NFCT_T_DESTROY:
			ret = snprintf(buf, remain, "%9s ", "[DESTROY]");
			break;
		default:
			break;
	}

	if (ret == -1)
		return -1;
	size += ret;
	remain -= ret;

	if (flags & NFCT_OF_SHOW_LAYER3) {
		ret = __snprintf_l3protocol(buf+size, remain, ct);
		if (ret == -1)
			return -1;
		size += ret;
		remain -= ret;
	}

	ret = __snprintf_protocol(buf+size, remain, ct);
	if (ret == -1)
		return -1;
	size += ret;
	remain -= ret;

	if (test_bit(ATTR_TIMEOUT, ct->set)) {
		ret = __snprintf_timeout(buf+size, remain, ct);
		if (ret == -1)
			return -1;
		size += ret;
		remain -= ret;
	}

        if (test_bit(ATTR_TCP_STATE, ct->set)) {
		ret = __snprintf_protoinfo(buf+size, remain, ct);
		if (ret == -1)
			return -1;
		size += ret;
		remain -= ret;
	}

	ret = __snprintf_address(buf+size, remain, &ct->tuple[__DIR_ORIG]);
	if (ret == -1)
		return -1;
	size += ret;
	remain -= ret;

	ret = __snprintf_proto(buf+size, remain, &ct->tuple[__DIR_ORIG]);
	if (ret == -1)
		return -1;
	size += ret;
	remain -= ret;

	if (test_bit(ATTR_ORIG_COUNTER_PACKETS, ct->set) &&
	    test_bit(ATTR_ORIG_COUNTER_BYTES, ct->set)) {
		ret = __snprintf_counters(buf+size, remain, ct, __DIR_ORIG);
		if (ret == -1)
			return -1;
		size += ret;
		remain -= ret;
	}

	if (test_bit(ATTR_STATUS, ct->set)) {
		ret = __snprintf_status_not_seen_reply(buf+size, remain, ct);
		if (ret == -1)
			return -1;
		size += ret;
		remain -= ret;
	}

	ret = __snprintf_address(buf+size, remain, &ct->tuple[__DIR_REPL]);
	if (ret == -1)
		return -1;
	size += ret;
	remain -= ret;

	ret = __snprintf_proto(buf+size, remain, &ct->tuple[__DIR_REPL]);
	if (ret == -1)
		return -1;
	size += ret;
	remain -= ret;

	if (test_bit(ATTR_REPL_COUNTER_PACKETS, ct->set) &&
	    test_bit(ATTR_REPL_COUNTER_BYTES, ct->set)) {
		ret = __snprintf_counters(buf+size, remain, ct, __DIR_REPL);
		if (ret == -1)
			return -1;
		size += ret;
		remain -= ret;
	}

	if (test_bit(ATTR_STATUS, ct->set)) {
		ret = __snprintf_status_assured(buf+size, remain, ct);
		if (ret == -1)
			return -1;
		size += ret;
		remain -= ret;
	}

	if (test_bit(ATTR_MARK, ct->set)) {
		ret = __snprintf_mark(buf+size, remain, ct);
		if (ret == -1)
			return -1;
		size += ret;
		remain -= ret;
	}

	if (test_bit(ATTR_USE, ct->set)) {
		ret = __snprintf_use(buf+size, remain, ct);
		if (ret == -1)
			return -1;
		size += ret;
		remain -= ret;
	}

	/* Delete the last blank space */
	size--;

	return size;
}
