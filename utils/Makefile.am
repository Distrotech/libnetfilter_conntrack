INCLUDES = $(all_includes) -I$(top_srcdir)/include -I${KERNELDIR} 

bin_PROGRAMS = ctnl_test

ctnl_test_SOURCES = ctnl_test.c
ctnl_test_LDADD = ../src/libnfnetlink_conntrack.la
ctnl_test_LDFLAGS = -dynamic

