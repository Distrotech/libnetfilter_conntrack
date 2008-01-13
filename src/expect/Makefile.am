include $(top_srcdir)/Make_global.am

AM_CFLAGS = -fPIC -Wall
LIBS = @LIBNFCONNTRACK_LIBS@

noinst_LTLIBRARIES = libnfexpect.la 

libnfexpect_la_SOURCES = api.c callback.c \
			 getter.c setter.c \
			 parse.c build.c \
			 snprintf.c \
			 snprintf_default.c
