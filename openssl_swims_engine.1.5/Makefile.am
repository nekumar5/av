ACLOCAL_AMFLAGS=-I m4
SUBDIRS = test src obs

EXTRA_DIST = README openssl.cnf

#confdir = ${sysconfdir}/ssl
#conf_DATA = openssl.cnf

#openssl.cnf:

rpms srcrpm: dist
	$(MAKE) -C obs $(AM_MAKEFLAGS) $@
	rpmarch=`rpm --showrc | grep ^build\ arch | sed 's/\(.*: \)\(.*\)/\2/'`; \
	test -z $$rpmarch || ( mv $$rpmarch/* .; rm -rf $$rpmarch )
	-rm -rf $(distdir)

dist-hook:
	-rm -rf `find $(distdir) -name .svn`

CLEANFILES = *.rpm *.tar.gz

.PHONY: srcrpm rpms

