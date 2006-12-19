include $(top_srcdir)/Make_global.am

bin_PROGRAMS = ctnl_test new_api_test

new_api_test_SOURCES = new_api_test.c
new_api_test_LDADD = ../src/libnetfilter_conntrack.la
new_api_test_LDFLAGS = -dynamic -ldl

ctnl_test_SOURCES = ctnl_test.c
ctnl_test_LDADD = ../src/libnetfilter_conntrack.la
ctnl_test_LDFLAGS = -dynamic -ldl
