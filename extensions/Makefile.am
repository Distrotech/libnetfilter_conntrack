AUTOMAKE_OPTIONS = no-dependencies foreign

EXTRA_DIST = $(man_MANS) acinclude.m4

man_MANS =

INCLUDES=-I../include -I${KERNELDIR}
CFLAGS=-fPIC -Wall
LIBS=

lib_LTLIBRARIES = libnetfilter_conntrack_tcp.la libnetfilter_conntrack_udp.la libnetfilter_conntrack_icmp.la libnetfilter_conntrack_sctp.la

libnetfilter_conntrack_tcp_la_SOURCES = libnetfilter_conntrack_tcp.c 
libnetfilter_conntrack_udp_la_SOURCES = libnetfilter_conntrack_udp.c
libnetfilter_conntrack_icmp_la_SOURCES = libnetfilter_conntrack_icmp.c
libnetfilter_conntrack_sctp_la_SOURCES = libnetfilter_conntrack_sctp.c
