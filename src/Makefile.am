#AUTOMAKE_OPTIONS = no-dependencies foreign

#EXTRA_DIST = $(man_MANS) acinclude.m4

INCLUDES = $(all_includes) -I$(top_srcdir)/include -I${KERNELDIR} 
AM_CFLAGS=-fPIC -Wall
LIBS=

lib_LTLIBRARIES = libnfnetlink_conntrack.la 

libnfnetlink_conntrack_la_LDFLAGS = -Wc,-nostartfiles
libnfnetlink_conntrack_la_SOURCES = libnfnetlink_conntrack.c 
