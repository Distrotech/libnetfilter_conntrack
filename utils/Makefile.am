bin_PROGRAMS = ctnl_test
ctnl_test_SOURCES = ctnl_test.c


INCLUDES = $(all_includes) -I$(top_srcdir)/include -I${KERNELDIR} 

ctnl_test_LDFLAGS = $(all_libraries) -lnfnetlink_conntrack -lnfnetlink

