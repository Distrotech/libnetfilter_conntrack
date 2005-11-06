AUTOMAKE_OPTIONS = no-dependencies foreign

EXTRA_DIST = $(man_MANS) 

man_MANS =

INCLUDES=-I../include -I${KERNELDIR}
CFLAGS=-fPIC -Wall
LIBS=

pkglib_LTLIBRARIES = nfct_proto_tcp.la nfct_proto_udp.la 		\
		     nfct_proto_icmp.la nfct_proto_sctp.la

nfct_proto_tcp_la_SOURCES = libnetfilter_conntrack_tcp.c 
nfct_proto_tcp_la_LDFLAGS = -module
nfct_proto_tcp_la_LIBADD = ../src/libnetfilter_conntrack.la

nfct_proto_udp_la_SOURCES = libnetfilter_conntrack_udp.c
nfct_proto_udp_la_LDFLAGS = -module
nfct_proto_udp_la_LIBADD = ../src/libnetfilter_conntrack.la

nfct_proto_icmp_la_SOURCES = libnetfilter_conntrack_icmp.c
nfct_proto_icmp_la_LDFLAGS = -module
nfct_proto_icmp_la_LIBADD = ../src/libnetfilter_conntrack.la

nfct_proto_sctp_la_SOURCES = libnetfilter_conntrack_sctp.c
nfct_proto_sctp_la_LDFLAGS = -module
nfct_proto_sctp_la_LIBADD = ../src/libnetfilter_conntrack.la
