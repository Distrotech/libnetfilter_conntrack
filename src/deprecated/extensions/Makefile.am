include $(top_srcdir)/Make_global.am

AUTOMAKE_OPTIONS = no-dependencies foreign

AM_CFLAGS=-fPIC -Wall
LIBS= @LIBNFCONNTRACK_LIBS@

noinst_LTLIBRARIES = libnfct_proto_tcp.la libnfct_proto_udp.la 	\
		     libnfct_proto_icmp.la libnfct_proto_sctp.la

libnfct_proto_tcp_la_SOURCES = libnetfilter_conntrack_tcp.c 
libnfct_proto_udp_la_SOURCES = libnetfilter_conntrack_udp.c
libnfct_proto_icmp_la_SOURCES = libnetfilter_conntrack_icmp.c
libnfct_proto_sctp_la_SOURCES = libnetfilter_conntrack_sctp.c
