#ifndef _NFCT_EXTERN_H_
#define _NFCT_EXTERN_H_

extern set_attr 	set_attr_array[];
extern get_attr 	get_attr_array[];
extern copy_attr 	copy_attr_array[];
extern filter_attr 	filter_attr_array[];
extern set_attr_grp	set_attr_grp_array[];
extern get_attr_grp	get_attr_grp_array[];

extern set_exp_attr	set_exp_attr_array[];
extern get_exp_attr	get_exp_attr_array[];

extern uint32_t attr_grp_bitmask[ATTR_GRP_MAX][__NFCT_BITSET];

/* for the snprintf infrastructure */
extern const char 	*l3proto2str[AF_MAX];
extern const char	*proto2str[IPPROTO_MAX];
extern const char	*states[TCP_CONNTRACK_MAX];
extern const char	*sctp_states[SCTP_CONNTRACK_MAX];
extern const char	*dccp_states[DCCP_CONNTRACK_MAX];

#endif
