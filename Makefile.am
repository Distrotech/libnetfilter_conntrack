AUTOMAKE_OPTIONS = foreign

INCLUDES =$(all_includes) -I$(top_srcdir)/include -I${KERNELDIR}
SUBDIRS	= include src utils
LINKOPTS = -lnfnetlink

man_MANS = #nfnetlink_conntrack.3 nfnetlink_conntrack.7

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
