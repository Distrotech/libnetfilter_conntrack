AUTOMAKE_OPTIONS = no-dependencies foreign

EXTRA_DIST = $(man_MANS) 

man_MANS =

INCLUDES=-I../include -I${KERNELDIR}
CFLAGS=-fPIC -Wall
LIBS=

pkglib_LTLIBRARIES = libnfct_proto_tcp.la libnfct_proto_udp.la 		\
		     libnfct_proto_icmp.la libnfct_proto_sctp.la

libnfct_proto_tcp_la_SOURCES = libnetfilter_conntrack_tcp.c 
libnfct_proto_tcp_la_LDFLAGS = -module
libnfct_proto_udp_la_SOURCES = libnetfilter_conntrack_udp.c
libnfct_proto_udp_la_LDFLAGS = -module
libnfct_proto_icmp_la_SOURCES = libnetfilter_conntrack_icmp.c
libnfct_proto_icmp_la_LDFLAGS = -module
libnfct_proto_sctp_la_SOURCES = libnetfilter_conntrack_sctp.c
libnfct_proto_sctp_la_LDFLAGS = -module
