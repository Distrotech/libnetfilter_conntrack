#AUTOMAKE_OPTIONS = no-dependencies foreign

#EXTRA_DIST = $(man_MANS) acinclude.m4

INCLUDES = $(all_includes) -I$(top_srcdir)/include -I${KERNELDIR} 
AM_CFLAGS=-fPIC -Wall
LIBS=

lib_LTLIBRARIES = libnetfilter_conntrack.la 

libnetfilter_conntrack_la_LDFLAGS = -Wc,-nostartfiles
libnetfilter_conntrack_la_SOURCES = libnetfilter_conntrack.c 
