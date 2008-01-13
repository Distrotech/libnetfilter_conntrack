include $(top_srcdir)/Make_global.am

AM_CFLAGS=-fPIC -Wall
LIBS = @LIBNFCONNTRACK_LIBS@

noinst_LTLIBRARIES = libnfct_l3proto_ipv4.la libnfct_l3proto_ipv6.la

libnfct_l3proto_ipv4_la_SOURCES = libnetfilter_conntrack_ipv4.c
libnfct_l3proto_ipv6_la_SOURCES = libnetfilter_conntrack_ipv6.c
