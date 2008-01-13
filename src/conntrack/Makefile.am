include $(top_srcdir)/Make_global.am

AM_CFLAGS = -fPIC -Wall
LIBS = @LIBNFCONNTRACK_LIBS@

noinst_LTLIBRARIES = libnfconntrack.la 

libnfconntrack_la_SOURCES = api.c callback.c \
			    getter.c setter.c \
			    parse.c build.c \
			    snprintf.c \
			    snprintf_default.c snprintf_xml.c \
			    objopt.c \
			    compare.c
