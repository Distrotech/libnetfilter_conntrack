/*
 * (C) 2006 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#include "internal/internal.h"

static void __parse_ip(const struct nfattr *attr,
		       struct __nfct_tuple *tuple,
		       const int dir,
		       u_int32_t *set)
{
	struct nfattr *tb[CTA_IP_MAX];

        nfnl_parse_nested(tb, CTA_IP_MAX, attr);

	if (tb[CTA_IP_V4_SRC-1]) {
		tuple->src.v4 = *(u_int32_t *)NFA_DATA(tb[CTA_IP_V4_SRC-1]);
		switch(dir) {
		case __DIR_ORIG:
			set_bit(ATTR_ORIG_IPV4_SRC, set);
			break;
		case __DIR_REPL:
			set_bit(ATTR_REPL_IPV4_SRC, set);
			break;
		case __DIR_MASTER:
			set_bit(ATTR_MASTER_IPV4_SRC, set);
			break;
		}
	}

	if (tb[CTA_IP_V4_DST-1]) {
		tuple->dst.v4 = *(u_int32_t *)NFA_DATA(tb[CTA_IP_V4_DST-1]);
		switch(dir) {
		case __DIR_ORIG:
			set_bit(ATTR_ORIG_IPV4_DST, set);
			break;
		case __DIR_REPL:
			set_bit(ATTR_REPL_IPV4_DST, set);
			break;
		case __DIR_MASTER:
			set_bit(ATTR_MASTER_IPV4_DST, set);
			break;
		}
	}

	if (tb[CTA_IP_V6_SRC-1]) {
		memcpy(&tuple->src.v6, NFA_DATA(tb[CTA_IP_V6_SRC-1]), 
		       sizeof(struct in6_addr));
		switch(dir) {
		case __DIR_ORIG:
			set_bit(ATTR_ORIG_IPV6_SRC, set);
			break;
		case __DIR_REPL:
			set_bit(ATTR_REPL_IPV6_SRC, set);
			break;
		case __DIR_MASTER:
			set_bit(ATTR_MASTER_IPV6_SRC, set);
			break;
		}
	}

	if (tb[CTA_IP_V6_DST-1]) {
		memcpy(&tuple->dst.v6, NFA_DATA(tb[CTA_IP_V6_DST-1]),
		       sizeof(struct in6_addr));
		switch(dir) {
		case __DIR_ORIG:
			set_bit(ATTR_ORIG_IPV6_DST, set);
			break;
		case __DIR_REPL:
			set_bit(ATTR_REPL_IPV6_DST, set);
			break;
		case __DIR_MASTER:
			set_bit(ATTR_MASTER_IPV6_DST, set);
			break;
		}
	}
}

static void __parse_proto(const struct nfattr *attr,
			  struct __nfct_tuple *tuple,
		   const int dir,
		   u_int32_t *set)
{
	struct nfattr *tb[CTA_PROTO_MAX];

	nfnl_parse_nested(tb, CTA_PROTO_MAX, attr);

	if (tb[CTA_PROTO_NUM-1]) {
		tuple->protonum = *(u_int8_t *)NFA_DATA(tb[CTA_PROTO_NUM-1]);
		switch(dir) {
		case __DIR_ORIG:
			set_bit(ATTR_ORIG_L4PROTO, set);
			break;
		case __DIR_REPL:
			set_bit(ATTR_REPL_L4PROTO, set);
			break;
		case __DIR_MASTER:
			set_bit(ATTR_MASTER_L4PROTO, set);
			break;
		}
	}

	if (tb[CTA_PROTO_SRC_PORT-1]) {
		tuple->l4src.tcp.port =
			*(u_int16_t *)NFA_DATA(tb[CTA_PROTO_SRC_PORT-1]);
		switch(dir) {
		case __DIR_ORIG:
			set_bit(ATTR_ORIG_PORT_SRC, set);
			break;
		case __DIR_REPL:
			set_bit(ATTR_REPL_PORT_SRC, set);
			break;
		case __DIR_MASTER:
			set_bit(ATTR_MASTER_PORT_SRC, set);
			break;
		}
	}
	
	if (tb[CTA_PROTO_DST_PORT-1]) {
		tuple->l4dst.tcp.port =
			*(u_int16_t *)NFA_DATA(tb[CTA_PROTO_DST_PORT-1]);
		switch(dir) {
		case __DIR_ORIG:
			set_bit(ATTR_ORIG_PORT_DST, set);
			break;
		case __DIR_REPL:
			set_bit(ATTR_REPL_PORT_DST, set);
			break;
		case __DIR_MASTER:
			set_bit(ATTR_MASTER_PORT_DST, set);
			break;
		}
	}
	
	if (tb[CTA_PROTO_ICMP_TYPE-1]) {
		tuple->l4dst.icmp.type =
			*(u_int8_t *)NFA_DATA(tb[CTA_PROTO_ICMP_TYPE-1]);
		set_bit(ATTR_ICMP_TYPE, set);
	}
	
	if (tb[CTA_PROTO_ICMP_CODE-1]) {
		tuple->l4dst.icmp.code =
			*(u_int8_t *)NFA_DATA(tb[CTA_PROTO_ICMP_CODE-1]);
		set_bit(ATTR_ICMP_CODE, set);
	}
	
	if (tb[CTA_PROTO_ICMP_ID-1]) {
		tuple->l4src.icmp.id =
			*(u_int16_t *)NFA_DATA(tb[CTA_PROTO_ICMP_ID-1]);
		set_bit(ATTR_ICMP_ID, set);
	}

	if (tb[CTA_PROTO_ICMPV6_TYPE-1]) {
		tuple->l4dst.icmp.type =
			*(u_int8_t *)NFA_DATA(tb[CTA_PROTO_ICMPV6_TYPE-1]);
		set_bit(ATTR_ICMP_TYPE, set);
	}
	
	if (tb[CTA_PROTO_ICMPV6_CODE-1]) {
		tuple->l4dst.icmp.code =
			*(u_int8_t *)NFA_DATA(tb[CTA_PROTO_ICMPV6_CODE-1]);
		set_bit(ATTR_ICMP_CODE, set);
	}
	
	if (tb[CTA_PROTO_ICMPV6_ID-1]) {
		tuple->l4src.icmp.id =
			*(u_int16_t *)NFA_DATA(tb[CTA_PROTO_ICMPV6_ID-1]);
		set_bit(ATTR_ICMP_ID, set);
	}
}

void __parse_tuple(const struct nfattr *attr,
		   struct __nfct_tuple *tuple, 
		   int dir,
		   u_int32_t *set)
{
	struct nfattr *tb[CTA_TUPLE_MAX];

	nfnl_parse_nested(tb, CTA_TUPLE_MAX, attr);

	if (tb[CTA_TUPLE_IP-1])
		__parse_ip(tb[CTA_TUPLE_IP-1], tuple, dir, set);
	if (tb[CTA_TUPLE_PROTO-1])
		__parse_proto(tb[CTA_TUPLE_PROTO-1], tuple, dir, set);
}

static void __parse_protoinfo_tcp(const struct nfattr *attr, 
				  struct nf_conntrack *ct)
{
	struct nfattr *tb[CTA_PROTOINFO_TCP_MAX];

	nfnl_parse_nested(tb, CTA_PROTOINFO_TCP_MAX, attr);

	if (tb[CTA_PROTOINFO_TCP_STATE-1]) {
                ct->protoinfo.tcp.state =
                        *(u_int8_t *)NFA_DATA(tb[CTA_PROTOINFO_TCP_STATE-1]);
		set_bit(ATTR_TCP_STATE, ct->set);
	}

	if (tb[CTA_PROTOINFO_TCP_WSCALE_ORIGINAL-1]) {
		memcpy(&ct->protoinfo.tcp.wscale[__DIR_ORIG],
		       NFA_DATA(tb[CTA_PROTOINFO_TCP_WSCALE_ORIGINAL-1]),
		       sizeof(u_int8_t));
		set_bit(ATTR_TCP_WSCALE_ORIG, ct->set);
	}

	if (tb[CTA_PROTOINFO_TCP_WSCALE_REPLY-1]) {
		memcpy(&ct->protoinfo.tcp.wscale[__DIR_REPL],
		       NFA_DATA(tb[CTA_PROTOINFO_TCP_WSCALE_REPLY-1]),
		       sizeof(u_int8_t));
		set_bit(ATTR_TCP_WSCALE_REPL, ct->set);
	}

	if (tb[CTA_PROTOINFO_TCP_FLAGS_ORIGINAL-1]) {
		memcpy(&ct->protoinfo.tcp.flags[0], 
		       NFA_DATA(tb[CTA_PROTOINFO_TCP_FLAGS_ORIGINAL-1]),
		       sizeof(u_int16_t));
		set_bit(ATTR_TCP_FLAGS_ORIG, ct->set);
		set_bit(ATTR_TCP_MASK_ORIG, ct->set);
	}

	if (tb[CTA_PROTOINFO_TCP_FLAGS_REPLY-1]) {
		memcpy(&ct->protoinfo.tcp.flags[1], 
		       NFA_DATA(tb[CTA_PROTOINFO_TCP_FLAGS_REPLY-1]),
		       sizeof(u_int16_t));
		set_bit(ATTR_TCP_FLAGS_REPL, ct->set);
		set_bit(ATTR_TCP_MASK_REPL, ct->set);
	}
}

static void __parse_protoinfo_sctp(const struct nfattr *attr, 
				   struct nf_conntrack *ct)
{
	struct nfattr *tb[CTA_PROTOINFO_SCTP_MAX];

	nfnl_parse_nested(tb, CTA_PROTOINFO_SCTP_MAX, attr);

	if (tb[CTA_PROTOINFO_SCTP_STATE-1]) {
                ct->protoinfo.sctp.state =
                        *(u_int8_t *)NFA_DATA(tb[CTA_PROTOINFO_SCTP_STATE-1]);
		set_bit(ATTR_SCTP_STATE, ct->set);
	}

	if (tb[CTA_PROTOINFO_SCTP_VTAG_ORIGINAL-1]) {
		ct->protoinfo.sctp.vtag[__DIR_ORIG] = 
			ntohl(*(u_int32_t *)NFA_DATA(tb[CTA_PROTOINFO_SCTP_VTAG_ORIGINAL-1]));
		set_bit(ATTR_SCTP_VTAG_ORIG, ct->set);
	}

	if (tb[CTA_PROTOINFO_SCTP_VTAG_REPLY-1]) {
		ct->protoinfo.sctp.vtag[__DIR_REPL] = 
			ntohl(*(u_int32_t *)NFA_DATA(tb[CTA_PROTOINFO_SCTP_VTAG_REPLY-1]));
		set_bit(ATTR_SCTP_VTAG_REPL, ct->set);
	}

}

static void __parse_protoinfo_dccp(const struct nfattr *attr, 
				   struct nf_conntrack *ct)
{
	struct nfattr *tb[CTA_PROTOINFO_DCCP_MAX];

	nfnl_parse_nested(tb, CTA_PROTOINFO_DCCP_MAX, attr);

	if (tb[CTA_PROTOINFO_DCCP_STATE-1]) {
                ct->protoinfo.dccp.state =
                        *(u_int8_t *)NFA_DATA(tb[CTA_PROTOINFO_DCCP_STATE-1]);
		set_bit(ATTR_DCCP_STATE, ct->set);
	}
	if (tb[CTA_PROTOINFO_DCCP_ROLE-1]) {
                ct->protoinfo.dccp.role =
                        *(u_int8_t *)NFA_DATA(tb[CTA_PROTOINFO_DCCP_ROLE-1]);
		set_bit(ATTR_DCCP_ROLE, ct->set);
	}
	if (tb[CTA_PROTOINFO_DCCP_HANDSHAKE_SEQ-1]) {
		u_int64_t tmp;
		memcpy(&tmp,
		       NFA_DATA(tb[CTA_PROTOINFO_DCCP_HANDSHAKE_SEQ-1]),
		       sizeof(tmp));
		ct->protoinfo.dccp.handshake_seq = __be64_to_cpu(tmp);
		set_bit(ATTR_DCCP_HANDSHAKE_SEQ, ct->set);
	}
}

static void __parse_protoinfo(const struct nfattr *attr,
			      struct nf_conntrack *ct)
{
	struct nfattr *tb[CTA_PROTOINFO_MAX];

	nfnl_parse_nested(tb, CTA_PROTOINFO_MAX, attr);

	if (tb[CTA_PROTOINFO_TCP-1])
		__parse_protoinfo_tcp(tb[CTA_PROTOINFO_TCP-1], ct);

	if (tb[CTA_PROTOINFO_SCTP-1])
		__parse_protoinfo_sctp(tb[CTA_PROTOINFO_SCTP-1], ct);

	if (tb[CTA_PROTOINFO_DCCP-1])
		__parse_protoinfo_dccp(tb[CTA_PROTOINFO_DCCP-1], ct);
}

static void __parse_counters(const struct nfattr *attr,
			     struct nf_conntrack *ct,
			     int dir)
{
	struct nfattr *tb[CTA_COUNTERS_MAX];

	nfnl_parse_nested(tb, CTA_COUNTERS_MAX, attr);
	if (tb[CTA_COUNTERS_PACKETS-1] || tb[CTA_COUNTERS32_PACKETS-1]) {

		if (tb[CTA_COUNTERS32_PACKETS-1])
			ct->counters[dir].packets
				= ntohl(*(u_int32_t *)
					NFA_DATA(tb[CTA_COUNTERS32_PACKETS-1]));

		if (tb[CTA_COUNTERS_PACKETS-1]) {
			u_int64_t tmp;
			memcpy(&tmp,
			       NFA_DATA(tb[CTA_COUNTERS_PACKETS-1]),
			       sizeof(tmp));
			ct->counters[dir].packets = __be64_to_cpu(tmp);
		}

		switch(dir) {
		case __DIR_ORIG:
			set_bit(ATTR_ORIG_COUNTER_PACKETS, ct->set);
			break;
		case __DIR_REPL:
			set_bit(ATTR_REPL_COUNTER_PACKETS, ct->set);
			break;
		}
	}
	if (tb[CTA_COUNTERS_BYTES-1] || tb[CTA_COUNTERS32_BYTES-1]) {

		if (tb[CTA_COUNTERS32_BYTES-1])
			ct->counters[dir].bytes
				= ntohl(*(u_int32_t *)
					NFA_DATA(tb[CTA_COUNTERS32_BYTES-1]));

		if (tb[CTA_COUNTERS_BYTES-1]) {
			u_int64_t tmp;
			memcpy(&tmp,
			       NFA_DATA(tb[CTA_COUNTERS_BYTES-1]),
			       sizeof(tmp));
			ct->counters[dir].bytes = __be64_to_cpu(tmp);
		}

		switch(dir) {
		case __DIR_ORIG:
			set_bit(ATTR_ORIG_COUNTER_BYTES, ct->set);
			break;
		case __DIR_REPL:
			set_bit(ATTR_REPL_COUNTER_BYTES, ct->set);
			break;
		}
	}
}

static void 
__parse_nat_seq(const struct nfattr *attr, struct nf_conntrack *ct, int dir)
{
	struct nfattr *tb[CTA_NAT_SEQ_MAX];

	nfnl_parse_nested(tb, CTA_NAT_SEQ_MAX, attr);

	if (tb[CTA_NAT_SEQ_CORRECTION_POS-1]) {
		ct->tuple[dir].natseq.correction_pos =
		ntohl(*(u_int32_t *)NFA_DATA(tb[CTA_NAT_SEQ_CORRECTION_POS-1]));
		switch(dir) {
		case __DIR_ORIG:
			set_bit(ATTR_ORIG_NAT_SEQ_CORRECTION_POS, ct->set);
			break;
		case __DIR_REPL:
			set_bit(ATTR_REPL_NAT_SEQ_CORRECTION_POS, ct->set);
			break;
		}
	}
					
	if (tb[CTA_NAT_SEQ_OFFSET_BEFORE-1]) {
		ct->tuple[dir].natseq.offset_before =
		ntohl(*(u_int32_t *)NFA_DATA(tb[CTA_NAT_SEQ_OFFSET_BEFORE-1]));
		switch(dir) {
		case __DIR_ORIG:
			set_bit(ATTR_ORIG_NAT_SEQ_OFFSET_BEFORE, ct->set);
			break;
		case __DIR_REPL:
			set_bit(ATTR_REPL_NAT_SEQ_OFFSET_BEFORE, ct->set);
			break;
		}
	}

	if (tb[CTA_NAT_SEQ_OFFSET_AFTER-1]) {
		ct->tuple[dir].natseq.offset_after =
		ntohl(*(u_int32_t *)NFA_DATA(tb[CTA_NAT_SEQ_OFFSET_AFTER-1]));
		switch(dir) {
		case __DIR_ORIG:
			set_bit(ATTR_ORIG_NAT_SEQ_OFFSET_AFTER, ct->set);
			break;
		case __DIR_REPL:
			set_bit(ATTR_REPL_NAT_SEQ_OFFSET_AFTER, ct->set);
			break;
		}
	}
}

static void 
__parse_helper(const struct nfattr *attr, struct nf_conntrack *ct)
{
	struct nfattr *tb[CTA_HELP_MAX];

	nfnl_parse_nested(tb, CTA_HELP_MAX, attr);
	if (!tb[CTA_HELP_NAME-1])
		return;

	strncpy(ct->helper_name, 
		NFA_DATA(tb[CTA_HELP_NAME-1]),
		__NFCT_HELPER_NAMELEN);
	ct->helper_name[__NFCT_HELPER_NAMELEN-1] = '\0';
	set_bit(ATTR_HELPER_NAME, ct->set);
}

static void
__parse_secctx(const struct nfattr *attr, struct nf_conntrack *ct)
{
	struct nfattr *tb[CTA_SECCTX_MAX];

	nfnl_parse_nested(tb, CTA_SECCTX_MAX, attr);
	if (!tb[CTA_SECCTX_NAME-1])
		return;

	ct->secctx = strdup(NFA_DATA(tb[CTA_SECCTX_NAME-1]));
	if (ct->secctx)
		set_bit(ATTR_SECCTX, ct->set);
}

int __parse_message_type(const struct nlmsghdr *nlh)
{
	u_int16_t type = NFNL_MSG_TYPE(nlh->nlmsg_type);
	u_int16_t flags = nlh->nlmsg_flags;
	int ret = NFCT_T_UNKNOWN;

	if (type == IPCTNL_MSG_CT_NEW) {
		if (flags & (NLM_F_CREATE|NLM_F_EXCL))
			ret = NFCT_T_NEW;
		else
			ret = NFCT_T_UPDATE;
	} else if (type == IPCTNL_MSG_CT_DELETE)
		ret = NFCT_T_DESTROY;

	return ret;
}

static void
__parse_timestamp(const struct nfattr *attr, struct nf_conntrack *ct)
{
	struct nfattr *tb[CTA_TIMESTAMP_MAX];

	nfnl_parse_nested(tb, CTA_TIMESTAMP_MAX, attr);
	if (tb[CTA_TIMESTAMP_START-1]) {
		u_int64_t tmp;
		memcpy(&tmp, NFA_DATA(tb[CTA_TIMESTAMP_START-1]), sizeof(tmp));
		ct->timestamp.start = __be64_to_cpu(tmp);
		set_bit(ATTR_TIMESTAMP_START, ct->set);
	}
	if (tb[CTA_TIMESTAMP_STOP-1]) {
		u_int64_t tmp;
		memcpy(&tmp, NFA_DATA(tb[CTA_TIMESTAMP_STOP-1]), sizeof(tmp));
		ct->timestamp.stop = __be64_to_cpu(tmp);
		set_bit(ATTR_TIMESTAMP_STOP, ct->set);
	}
}

void __parse_conntrack(const struct nlmsghdr *nlh,
		       struct nfattr *cda[],
		       struct nf_conntrack *ct)
{
	struct nfgenmsg *nfhdr = NLMSG_DATA(nlh);

	if (cda[CTA_TUPLE_ORIG-1]) {
		ct->tuple[__DIR_ORIG].l3protonum = nfhdr->nfgen_family;
		set_bit(ATTR_ORIG_L3PROTO, ct->set);

		__parse_tuple(cda[CTA_TUPLE_ORIG-1], 
			      &ct->tuple[__DIR_ORIG], __DIR_ORIG, ct->set);
	}

	if (cda[CTA_TUPLE_REPLY-1]) {
		ct->tuple[__DIR_REPL].l3protonum = nfhdr->nfgen_family;
		set_bit(ATTR_REPL_L3PROTO, ct->set);

		__parse_tuple(cda[CTA_TUPLE_REPLY-1], 
			      &ct->tuple[__DIR_REPL], __DIR_REPL, ct->set);
	}

	if (cda[CTA_TUPLE_MASTER-1]) {
		ct->tuple[__DIR_MASTER].l3protonum = nfhdr->nfgen_family;
		set_bit(ATTR_MASTER_L3PROTO, ct->set);

		__parse_tuple(cda[CTA_TUPLE_MASTER-1], 
			      &ct->tuple[__DIR_MASTER], __DIR_MASTER, ct->set);
	}

	if (cda[CTA_NAT_SEQ_ADJ_ORIG-1])
		__parse_nat_seq(cda[CTA_NAT_SEQ_ADJ_ORIG-1], ct, __DIR_ORIG);

	if (cda[CTA_NAT_SEQ_ADJ_REPLY-1])
		__parse_nat_seq(cda[CTA_NAT_SEQ_ADJ_REPLY-1], ct, __DIR_REPL);

	if (cda[CTA_STATUS-1]) {
		ct->status = ntohl(*(u_int32_t *)NFA_DATA(cda[CTA_STATUS-1]));
		set_bit(ATTR_STATUS, ct->set);
	}

	if (cda[CTA_PROTOINFO-1])
		__parse_protoinfo(cda[CTA_PROTOINFO-1], ct);

	if (cda[CTA_TIMEOUT-1]) {
		ct->timeout = ntohl(*(u_int32_t *)NFA_DATA(cda[CTA_TIMEOUT-1]));
		set_bit(ATTR_TIMEOUT, ct->set);
	}
	
	if (cda[CTA_MARK-1]) {
		ct->mark = ntohl(*(u_int32_t *)NFA_DATA(cda[CTA_MARK-1]));
		set_bit(ATTR_MARK, ct->set);
	}

	if (cda[CTA_SECMARK-1]) {
		ct->secmark = ntohl(*(u_int32_t *)NFA_DATA(cda[CTA_SECMARK-1]));
		set_bit(ATTR_SECMARK, ct->set);
	}

	if (cda[CTA_COUNTERS_ORIG-1])
		__parse_counters(cda[CTA_COUNTERS_ORIG-1], ct, __DIR_ORIG);

	if (cda[CTA_COUNTERS_REPLY-1])
		__parse_counters(cda[CTA_COUNTERS_REPLY-1], ct, __DIR_REPL);

	if (cda[CTA_USE-1]) {
		ct->use = ntohl(*(u_int32_t *)NFA_DATA(cda[CTA_USE-1]));
		set_bit(ATTR_USE, ct->set);
	}

	if (cda[CTA_ID-1]) {
		ct->id = ntohl(*(u_int32_t *)NFA_DATA(cda[CTA_ID-1]));
		set_bit(ATTR_ID, ct->set);
	}

	if (cda[CTA_HELP-1])
		__parse_helper(cda[CTA_HELP-1], ct);

	if (cda[CTA_ZONE-1]) {
		ct->zone = ntohs(*(u_int16_t *)NFA_DATA(cda[CTA_ZONE-1]));
		set_bit(ATTR_ZONE, ct->set);
	}

	if (cda[CTA_SECCTX-1])
		__parse_secctx(cda[CTA_SECCTX-1], ct);

	if (cda[CTA_TIMESTAMP-1])
		__parse_timestamp(cda[CTA_TIMESTAMP-1], ct);
}
