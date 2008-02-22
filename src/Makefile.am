include $(top_srcdir)/Make_global.am

#AUTOMAKE_OPTIONS = no-dependencies foreign

#EXTRA_DIST = $(man_MANS) acinclude.m4

SUBDIRS=conntrack expect deprecated

AM_CFLAGS = -fPIC -Wall
LIBS = @LIBNFCONNTRACK_LIBS@

lib_LTLIBRARIES = libnetfilter_conntrack.la 

libnetfilter_conntrack_la_LIBADD = conntrack/libnfconntrack.la \
				   expect/libnfexpect.la \
			deprecated/l3extensions/libnfct_l3proto_ipv4.la \
			deprecated/l3extensions/libnfct_l3proto_ipv6.la \
			deprecated/extensions/libnfct_proto_tcp.la \
			deprecated/extensions/libnfct_proto_udp.la \
			deprecated/extensions/libnfct_proto_icmp.la \
			deprecated/extensions/libnfct_proto_sctp.la
libnetfilter_conntrack_la_LDFLAGS = -Wc,-nostartfiles -lnfnetlink -ldl 	\
				    -version-info $(LIBVERSION)
libnetfilter_conntrack_la_SOURCES = main.c deprecated.c
