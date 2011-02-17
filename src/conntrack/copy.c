/*
 * (C) 2008 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#include "internal/internal.h"

static void copy_attr_orig_ipv4_src(struct nf_conntrack *dest,
				    const struct nf_conntrack *orig)
{
	dest->tuple[__DIR_ORIG].src.v4 = orig->tuple[__DIR_ORIG].src.v4;
}

static void copy_attr_orig_ipv4_dst(struct nf_conntrack *dest,
				    const struct nf_conntrack *orig)
{
	dest->tuple[__DIR_ORIG].dst.v4 = orig->tuple[__DIR_ORIG].dst.v4;
}

static void copy_attr_repl_ipv4_src(struct nf_conntrack *dest,
				    const struct nf_conntrack *orig)
{
	dest->tuple[__DIR_REPL].src.v4 = orig->tuple[__DIR_REPL].src.v4;
}

static void copy_attr_repl_ipv4_dst(struct nf_conntrack *dest,
				    const struct nf_conntrack *orig)
{
	dest->tuple[__DIR_REPL].dst.v4 = orig->tuple[__DIR_REPL].dst.v4;
}

static void copy_attr_orig_ipv6_src(struct nf_conntrack *dest,
				    const struct nf_conntrack *orig)
{
	memcpy(&dest->tuple[__DIR_ORIG].src,
	       &orig->tuple[__DIR_ORIG].src,
	       sizeof(union __nfct_address));
}

static void copy_attr_orig_ipv6_dst(struct nf_conntrack *dest,
				    const struct nf_conntrack *orig)
{
	memcpy(&dest->tuple[__DIR_ORIG].dst,
	       &orig->tuple[__DIR_ORIG].dst,
	       sizeof(union __nfct_address));
}

static void copy_attr_repl_ipv6_src(struct nf_conntrack *dest,
				    const struct nf_conntrack *orig)
{
	memcpy(&dest->tuple[__DIR_REPL].src,
	       &orig->tuple[__DIR_REPL].src,
	       sizeof(union __nfct_address));
}

static void copy_attr_repl_ipv6_dst(struct nf_conntrack *dest,
				    const struct nf_conntrack *orig)
{
	memcpy(&dest->tuple[__DIR_REPL].dst,
	       &orig->tuple[__DIR_REPL].dst,
	       sizeof(union __nfct_address));
}

static void copy_attr_orig_port_src(struct nf_conntrack *dest,
				    const struct nf_conntrack *orig)
{
	dest->tuple[__DIR_ORIG].l4src.all = orig->tuple[__DIR_ORIG].l4src.all;
}

static void copy_attr_orig_port_dst(struct nf_conntrack *dest,
				    const struct nf_conntrack *orig)
{
	dest->tuple[__DIR_ORIG].l4dst.all = orig->tuple[__DIR_ORIG].l4dst.all;
}

static void copy_attr_repl_port_src(struct nf_conntrack *dest,
				    const struct nf_conntrack *orig)
{
	dest->tuple[__DIR_REPL].l4src.all = orig->tuple[__DIR_REPL].l4src.all;
}

static void copy_attr_repl_port_dst(struct nf_conntrack *dest,
				    const struct nf_conntrack *orig)
{
	dest->tuple[__DIR_REPL].l4dst.all = orig->tuple[__DIR_REPL].l4dst.all;
}

static void copy_attr_icmp_type(struct nf_conntrack *dest,
				const struct nf_conntrack *orig)
{
	dest->tuple[__DIR_ORIG].l4dst.icmp.type = 
		orig->tuple[__DIR_ORIG].l4dst.icmp.type;

}

static void copy_attr_icmp_code(struct nf_conntrack *dest,
				const struct nf_conntrack *orig)
{
	dest->tuple[__DIR_ORIG].l4dst.icmp.code = 
		orig->tuple[__DIR_ORIG].l4dst.icmp.code;

}

static void copy_attr_icmp_id(struct nf_conntrack *dest,
			      const struct nf_conntrack *orig)
{
	dest->tuple[__DIR_ORIG].l4src.icmp.id = 
		orig->tuple[__DIR_ORIG].l4src.icmp.id;
}

static void copy_attr_orig_l3proto(struct nf_conntrack *dest,
				   const struct nf_conntrack *orig)
{
	dest->tuple[__DIR_ORIG].l3protonum = orig->tuple[__DIR_ORIG].l3protonum;
}

static void copy_attr_repl_l3proto(struct nf_conntrack *dest,
				   const struct nf_conntrack *orig)
{
	dest->tuple[__DIR_REPL].l3protonum = orig->tuple[__DIR_REPL].l3protonum;
}

static void copy_attr_orig_l4proto(struct nf_conntrack *dest,
				   const struct nf_conntrack *orig)
{
	dest->tuple[__DIR_ORIG].protonum = orig->tuple[__DIR_ORIG].protonum;
}

static void copy_attr_repl_l4proto(struct nf_conntrack *dest,
				   const struct nf_conntrack *orig)
{
	dest->tuple[__DIR_REPL].protonum = orig->tuple[__DIR_REPL].protonum;
}

static void copy_attr_master_ipv4_src(struct nf_conntrack *dest,
				      const struct nf_conntrack *orig)
{
	dest->tuple[__DIR_MASTER].src.v4 = orig->tuple[__DIR_MASTER].src.v4;
}

static void copy_attr_master_ipv4_dst(struct nf_conntrack *dest,
				      const struct nf_conntrack *orig)
{
	dest->tuple[__DIR_MASTER].dst.v4 = orig->tuple[__DIR_MASTER].dst.v4;
}

static void copy_attr_master_ipv6_src(struct nf_conntrack *dest,
				      const struct nf_conntrack *orig)
{
	memcpy(&dest->tuple[__DIR_MASTER].src,
	       &orig->tuple[__DIR_MASTER].src,
	       sizeof(union __nfct_address));
}

static void copy_attr_master_ipv6_dst(struct nf_conntrack *dest,
				      const struct nf_conntrack *orig)
{
	memcpy(&dest->tuple[__DIR_MASTER].dst,
	       &orig->tuple[__DIR_MASTER].dst,
	       sizeof(union __nfct_address));
}

static void copy_attr_master_port_src(struct nf_conntrack *dest,
				      const struct nf_conntrack *orig)
{
	dest->tuple[__DIR_MASTER].l4src.all =
		orig->tuple[__DIR_MASTER].l4src.all;
}

static void copy_attr_master_port_dst(struct nf_conntrack *dest,
				      const struct nf_conntrack *orig)
{
	dest->tuple[__DIR_MASTER].l4dst.all =
		orig->tuple[__DIR_MASTER].l4dst.all;
}

static void copy_attr_master_l3proto(struct nf_conntrack *dest,
				     const struct nf_conntrack *orig)
{
	dest->tuple[__DIR_MASTER].l3protonum =
		orig->tuple[__DIR_MASTER].l3protonum;
}

static void copy_attr_master_l4proto(struct nf_conntrack *dest,
				     const struct nf_conntrack *orig)
{
	dest->tuple[__DIR_MASTER].protonum =
		orig->tuple[__DIR_MASTER].protonum;
}

static void copy_attr_tcp_state(struct nf_conntrack *dest,
				const struct nf_conntrack *orig)
{
	dest->protoinfo.tcp.state = orig->protoinfo.tcp.state;
}

static void copy_attr_tcp_flags_orig(struct nf_conntrack *dest,
				     const struct nf_conntrack *orig)
{
	dest->protoinfo.tcp.flags[__DIR_ORIG].value =
		orig->protoinfo.tcp.flags[__DIR_ORIG].value;
}

static void copy_attr_tcp_flags_repl(struct nf_conntrack *dest,
				     const struct nf_conntrack *orig)
{
	dest->protoinfo.tcp.flags[__DIR_REPL].value =
		orig->protoinfo.tcp.flags[__DIR_REPL].value;
}

static void copy_attr_tcp_mask_orig(struct nf_conntrack *dest,
				    const struct nf_conntrack *orig)
{
	dest->protoinfo.tcp.flags[__DIR_ORIG].mask =
		orig->protoinfo.tcp.flags[__DIR_ORIG].mask;
}

static void copy_attr_tcp_mask_repl(struct nf_conntrack *dest,
				    const struct nf_conntrack *orig)
{
	dest->protoinfo.tcp.flags[__DIR_REPL].mask =
		orig->protoinfo.tcp.flags[__DIR_REPL].mask;
}

static void copy_attr_tcp_wscale_orig(struct nf_conntrack *dest,
				      const struct nf_conntrack *orig)
{
	dest->protoinfo.tcp.wscale[__DIR_ORIG] =
		orig->protoinfo.tcp.wscale[__DIR_ORIG];
}

static void copy_attr_tcp_wscale_repl(struct nf_conntrack *dest,
				      const struct nf_conntrack *orig)
{
	dest->protoinfo.tcp.wscale[__DIR_REPL] =
		orig->protoinfo.tcp.wscale[__DIR_REPL];
}

static void copy_attr_sctp_state(struct nf_conntrack *dest,
				 const struct nf_conntrack *orig)
{
	dest->protoinfo.sctp.state = orig->protoinfo.sctp.state;
}

static void copy_attr_sctp_vtag_orig(struct nf_conntrack *dest,
				     const struct nf_conntrack *orig)
{
	dest->protoinfo.sctp.vtag[__DIR_ORIG] =
		orig->protoinfo.sctp.vtag[__DIR_ORIG];
}

static void copy_attr_sctp_vtag_repl(struct nf_conntrack *dest,
				     const struct nf_conntrack *orig)
{
	dest->protoinfo.sctp.vtag[__DIR_REPL] =
		orig->protoinfo.sctp.vtag[__DIR_REPL];
}

static void copy_attr_dccp_state(struct nf_conntrack *dest,
				 const struct nf_conntrack *orig)
{
	dest->protoinfo.dccp.state = orig->protoinfo.dccp.state;
}

static void copy_attr_dccp_role(struct nf_conntrack *dest,
				const struct nf_conntrack *orig)
{
	dest->protoinfo.dccp.role = orig->protoinfo.dccp.role;
}

static void copy_attr_dccp_handshake_seq(struct nf_conntrack *dest,
					 const struct nf_conntrack *orig)
{
	dest->protoinfo.dccp.handshake_seq = orig->protoinfo.dccp.handshake_seq;
}

static void copy_attr_snat_ipv4(struct nf_conntrack *dest,
				const struct nf_conntrack *orig)
{
	dest->snat.min_ip = orig->snat.min_ip;
}

static void copy_attr_dnat_ipv4(struct nf_conntrack *dest,
				const struct nf_conntrack *orig)
{
	dest->dnat.min_ip = orig->dnat.min_ip;
}

static void copy_attr_snat_port(struct nf_conntrack *dest,
				const struct nf_conntrack *orig)
{
	dest->snat.l4min.all = orig->snat.l4min.all;
}

static void copy_attr_dnat_port(struct nf_conntrack *dest,
				const struct nf_conntrack *orig)
{
	dest->dnat.l4min.all = orig->dnat.l4min.all;
}

static void copy_attr_timeout(struct nf_conntrack *dest,
			      const struct nf_conntrack *orig)
{
	dest->timeout = orig->timeout;
}

static void copy_attr_mark(struct nf_conntrack *dest,
			   const struct nf_conntrack *orig)
{
	dest->mark = orig->mark;
}

static void copy_attr_secmark(struct nf_conntrack *dest,
			      const struct nf_conntrack *orig)
{
	dest->secmark = orig->secmark;
}

static void copy_attr_orig_counter_packets(struct nf_conntrack *dest,
					   const struct nf_conntrack *orig)
{
	dest->counters[__DIR_ORIG].packets = orig->counters[__DIR_ORIG].packets;
}

static void copy_attr_repl_counter_packets(struct nf_conntrack *dest,
					   const struct nf_conntrack *orig)
{
	dest->counters[__DIR_REPL].packets = orig->counters[__DIR_REPL].packets;
}

static void copy_attr_orig_counter_bytes(struct nf_conntrack *dest,
					 const struct nf_conntrack *orig)
{
	dest->counters[__DIR_ORIG].bytes = orig->counters[__DIR_ORIG].bytes;
}

static void copy_attr_repl_counter_bytes(struct nf_conntrack *dest,
					 const struct nf_conntrack *orig)
{
	dest->counters[__DIR_REPL].bytes = orig->counters[__DIR_REPL].bytes;
}

static void copy_attr_status(struct nf_conntrack *dest,
			     const struct nf_conntrack *orig)
{
	dest->status = orig->status;
}

static void copy_attr_use(struct nf_conntrack *dest,
			  const struct nf_conntrack *orig)
{
	dest->use = orig->use;
}

static void copy_attr_id(struct nf_conntrack *dest,
			 const struct nf_conntrack *orig)
{
	dest->id = orig->id;
}

static void copy_attr_orig_cor_pos(struct nf_conntrack *dest,
				   const struct nf_conntrack *orig)
{
	dest->tuple[__DIR_ORIG].natseq.correction_pos =
		orig->tuple[__DIR_ORIG].natseq.correction_pos;
}

static void copy_attr_orig_off_bfr(struct nf_conntrack *dest,
				   const struct nf_conntrack *orig)
{
	dest->tuple[__DIR_ORIG].natseq.offset_before =
		orig->tuple[__DIR_ORIG].natseq.offset_before;
}

static void copy_attr_orig_off_aft(struct nf_conntrack *dest,
				   const struct nf_conntrack *orig)
{
	dest->tuple[__DIR_ORIG].natseq.offset_after =
		orig->tuple[__DIR_ORIG].natseq.offset_after;
}

static void copy_attr_repl_cor_pos(struct nf_conntrack *dest,
				   const struct nf_conntrack *orig)
{
	dest->tuple[__DIR_REPL].natseq.correction_pos =
		orig->tuple[__DIR_REPL].natseq.correction_pos;
}

static void copy_attr_repl_off_bfr(struct nf_conntrack *dest,
				   const struct nf_conntrack *orig)
{
	dest->tuple[__DIR_REPL].natseq.offset_before =
		orig->tuple[__DIR_REPL].natseq.offset_before;
}

static void copy_attr_repl_off_aft(struct nf_conntrack *dest,
				   const struct nf_conntrack *orig)
{
	dest->tuple[__DIR_REPL].natseq.offset_after =
		orig->tuple[__DIR_REPL].natseq.offset_after;
}

static void copy_attr_helper_name(struct nf_conntrack *dest,
				  const struct nf_conntrack *orig)
{
	strncpy(dest->helper_name, orig->helper_name, __NFCT_HELPER_NAMELEN);
	dest->helper_name[__NFCT_HELPER_NAMELEN-1] = '\0';
}

static void copy_attr_zone(struct nf_conntrack *dest,
			   const struct nf_conntrack *orig)
{
	dest->zone = orig->zone;
}

static void copy_attr_secctx(struct nf_conntrack *dest,
			     const struct nf_conntrack *orig)
{
	if (dest->secctx) {
		free(dest->secctx);
		dest->secctx = NULL;
	}
	if (orig->secctx)
		dest->secctx = strdup(orig->secctx);
}

static void copy_attr_timestamp_start(struct nf_conntrack *dest,
				      const struct nf_conntrack *orig)
{
	dest->timestamp.start = orig->timestamp.start;
}

static void copy_attr_timestamp_stop(struct nf_conntrack *dest,
				     const struct nf_conntrack *orig)
{
	dest->timestamp.stop = orig->timestamp.stop;
}

const copy_attr copy_attr_array[ATTR_MAX] = {
	[ATTR_ORIG_IPV4_SRC]		= copy_attr_orig_ipv4_src,
	[ATTR_ORIG_IPV4_DST] 		= copy_attr_orig_ipv4_dst,
	[ATTR_REPL_IPV4_SRC]		= copy_attr_repl_ipv4_src,
	[ATTR_REPL_IPV4_DST]		= copy_attr_repl_ipv4_dst,
	[ATTR_ORIG_IPV6_SRC]		= copy_attr_orig_ipv6_src,
	[ATTR_ORIG_IPV6_DST]		= copy_attr_orig_ipv6_dst,
	[ATTR_REPL_IPV6_SRC]		= copy_attr_repl_ipv6_src,
	[ATTR_REPL_IPV6_DST]		= copy_attr_repl_ipv6_dst,
	[ATTR_ORIG_PORT_SRC]		= copy_attr_orig_port_src,
	[ATTR_ORIG_PORT_DST]		= copy_attr_orig_port_dst,
	[ATTR_REPL_PORT_SRC]		= copy_attr_repl_port_src,
	[ATTR_REPL_PORT_DST]		= copy_attr_repl_port_dst,
	[ATTR_ICMP_TYPE]		= copy_attr_icmp_type,
	[ATTR_ICMP_CODE]		= copy_attr_icmp_code,
	[ATTR_ICMP_ID]			= copy_attr_icmp_id,
	[ATTR_ORIG_L3PROTO]		= copy_attr_orig_l3proto,
	[ATTR_REPL_L3PROTO]		= copy_attr_repl_l3proto,
	[ATTR_ORIG_L4PROTO]		= copy_attr_orig_l4proto,
	[ATTR_REPL_L4PROTO]		= copy_attr_repl_l4proto,
	[ATTR_TCP_STATE]		= copy_attr_tcp_state,
	[ATTR_SNAT_IPV4]		= copy_attr_snat_ipv4,
	[ATTR_DNAT_IPV4]		= copy_attr_dnat_ipv4,
	[ATTR_SNAT_PORT]		= copy_attr_snat_port,
	[ATTR_DNAT_PORT]		= copy_attr_dnat_port,
	[ATTR_TIMEOUT]			= copy_attr_timeout,
	[ATTR_MARK]			= copy_attr_mark,
	[ATTR_ORIG_COUNTER_PACKETS] 	= copy_attr_orig_counter_packets,
	[ATTR_ORIG_COUNTER_BYTES]	= copy_attr_orig_counter_bytes,
	[ATTR_REPL_COUNTER_PACKETS]	= copy_attr_repl_counter_packets,
	[ATTR_REPL_COUNTER_BYTES]	= copy_attr_repl_counter_bytes,
	[ATTR_USE]			= copy_attr_use,
	[ATTR_ID]			= copy_attr_id,
	[ATTR_STATUS]			= copy_attr_status,
	[ATTR_TCP_FLAGS_ORIG]		= copy_attr_tcp_flags_orig,
	[ATTR_TCP_FLAGS_REPL]		= copy_attr_tcp_flags_repl,
	[ATTR_TCP_MASK_ORIG]		= copy_attr_tcp_mask_orig,
	[ATTR_TCP_MASK_REPL]		= copy_attr_tcp_mask_repl,
	[ATTR_MASTER_IPV4_SRC]		= copy_attr_master_ipv4_src,
	[ATTR_MASTER_IPV4_DST] 		= copy_attr_master_ipv4_dst,
	[ATTR_MASTER_IPV6_SRC]		= copy_attr_master_ipv6_src,
	[ATTR_MASTER_IPV6_DST]		= copy_attr_master_ipv6_dst,
	[ATTR_MASTER_PORT_SRC]		= copy_attr_master_port_src,
	[ATTR_MASTER_PORT_DST]		= copy_attr_master_port_dst,
	[ATTR_MASTER_L3PROTO]		= copy_attr_master_l3proto,
	[ATTR_MASTER_L4PROTO]		= copy_attr_master_l4proto,
	[ATTR_SECMARK]			= copy_attr_secmark,
	[ATTR_ORIG_NAT_SEQ_CORRECTION_POS]	= copy_attr_orig_cor_pos,
	[ATTR_ORIG_NAT_SEQ_OFFSET_BEFORE]	= copy_attr_orig_off_bfr,
	[ATTR_ORIG_NAT_SEQ_OFFSET_AFTER]	= copy_attr_orig_off_aft,
	[ATTR_REPL_NAT_SEQ_CORRECTION_POS]	= copy_attr_repl_cor_pos,
	[ATTR_REPL_NAT_SEQ_OFFSET_BEFORE]	= copy_attr_repl_off_bfr,
	[ATTR_REPL_NAT_SEQ_OFFSET_AFTER]	= copy_attr_repl_off_aft,
	[ATTR_SCTP_STATE]		= copy_attr_sctp_state,
	[ATTR_SCTP_VTAG_ORIG]		= copy_attr_sctp_vtag_orig,
	[ATTR_SCTP_VTAG_REPL]		= copy_attr_sctp_vtag_repl,
	[ATTR_HELPER_NAME]		= copy_attr_helper_name,
	[ATTR_DCCP_STATE]		= copy_attr_dccp_state,
	[ATTR_DCCP_ROLE]		= copy_attr_dccp_role,
	[ATTR_DCCP_HANDSHAKE_SEQ]	= copy_attr_dccp_handshake_seq,
	[ATTR_TCP_WSCALE_ORIG]		= copy_attr_tcp_wscale_orig,
	[ATTR_TCP_WSCALE_REPL]		= copy_attr_tcp_wscale_repl,
	[ATTR_ZONE]			= copy_attr_zone,
	[ATTR_SECCTX]			= copy_attr_secctx,
	[ATTR_TIMESTAMP_START]		= copy_attr_timestamp_start,
	[ATTR_TIMESTAMP_STOP]		= copy_attr_timestamp_stop,
};

/* this is used by nfct_copy() with the NFCT_CP_OVERRIDE flag set. */
void __copy_fast(struct nf_conntrack *ct1, const struct nf_conntrack *ct2)
{
	memcpy(ct1, ct2, sizeof(*ct1));
	/* special case: secctx attribute is allocated dinamically. */
	copy_attr_secctx(ct1, ct2);
}
