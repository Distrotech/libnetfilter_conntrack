include $(top_srcdir)/Make_global.am

check_PROGRAMS = test_api

test_api_SOURCES = test_api.c
test_api_LDADD = ../src/libnetfilter_conntrack.la
test_api_LDFLAGS = -dynamic -ldl
