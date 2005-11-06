
# This is _NOT_ the library release version, it's an API version.
# Please read Chapter 6 "Library interface versions" of the libtool documentation before making any modification
LIBVERSION=1:0:0

#AUTOMAKE_OPTIONS = no-dependencies foreign

#EXTRA_DIST = $(man_MANS) acinclude.m4

INCLUDES = $(all_includes) -I$(top_srcdir)/include -I${KERNELDIR} 
AM_CFLAGS=-fPIC -Wall
LIBS=

lib_LTLIBRARIES = libnetfilter_conntrack.la 

libnetfilter_conntrack_la_LDFLAGS = -Wc,-nostartfiles -lnfnetlink 	\
				    -version-info $(LIBVERSION)
libnetfilter_conntrack_la_SOURCES = libnetfilter_conntrack.c 
