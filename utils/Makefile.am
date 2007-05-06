include $(top_srcdir)/Make_global.am

bin_PROGRAMS = ctnl_test new_api_test \
	       expect_dump expect_create expect_get expect_delete \
	       expect_flush expect_events

new_api_test_SOURCES = new_api_test.c
new_api_test_LDADD = ../src/libnetfilter_conntrack.la
new_api_test_LDFLAGS = -dynamic -ldl

ctnl_test_SOURCES = ctnl_test.c
ctnl_test_LDADD = ../src/libnetfilter_conntrack.la
ctnl_test_LDFLAGS = -dynamic -ldl

expect_dump_SOURCES = expect_dump.c
expect_dump_LDADD = ../src/libnetfilter_conntrack.la
expect_dump_LDFLAGS = -dynamic -ldl

expect_create_SOURCES = expect_create.c
expect_create_LDADD = ../src/libnetfilter_conntrack.la
expect_create_LDFLAGS = -dynamic -ldl

expect_get_SOURCES = expect_get.c
expect_get_LDADD = ../src/libnetfilter_conntrack.la
expect_get_LDFLAGS = -dynamic -ldl

expect_delete_SOURCES = expect_delete.c
expect_delete_LDADD = ../src/libnetfilter_conntrack.la
expect_delete_LDFLAGS = -dynamic -ldl

expect_flush_SOURCES = expect_flush.c
expect_flush_LDADD = ../src/libnetfilter_conntrack.la
expect_flush_LDFLAGS = -dynamic -ldl

expect_events_SOURCES = expect_events.c
expect_events_LDADD = ../src/libnetfilter_conntrack.la
expect_events_LDFLAGS = -dynamic -ldl
