# http://mij.oltrelinux.com/devel/autoconf-automake/

bin_PROGRAMS = openforticli
openforticli_SOURCES = src/config.c src/config.h src/hdlc.c src/hdlc.h \
		       src/http.c src/http.h src/io.c src/io.h src/ipv4.c \
		       src/ipv4.h src/log.c src/log.h src/tunnel.c \
		       src/tunnel.h src/main.c src/ssl.h src/xml.c \
		       src/xml.h src/userinput.c src/userinput.h \
		       src/openssl_hostname_validation.c \
		       src/openssl_hostname_validation.h \
			   src/patch.c src/patch.h
openforticli_CPPFLAGS = -DSYSCONFDIR=\"$(sysconfdir)\" \
			-DPPP_PATH=\"@PPP_PATH@\" \
			-DNETSTAT_PATH=\"@NETSTAT_PATH@\" \
			-DRESOLVCONF_PATH=\"@RESOLVCONF_PATH@\" \
			-DREVISION=\"@REVISION@\" \
			 $(OPENSSL_CFLAGS) $(LIBSYSTEMD_CFLAGS) $(LIBOATH_CFLAGS)
openforticli_CFLAGS = -Wall -pedantic
openforticli_LDADD = $(OPENSSL_LIBS) $(LIBSYSTEMD_LIBS) $(LIBOATH_LIBS)

PATHFILES =
CLEAN_LOCALS =
EXTRA_DIST = \
	autogen.sh \
	CHANGELOG.md \
	LICENSE \
	LICENSE.OpenSSL \
	README.md

DISTCHECK_CONFIGURE_FLAGS = \
	CFLAGS=-Werror \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

# configuration file template
datadir=$(prefix)/share/@PACKAGE@
data_DATA=etc/openforticli/config.template

EXTRA_DIST += $(data_DATA)

# initial configuration file
confdir=$(sysconfdir)/@PACKAGE@

etc/openforticli/config: $(srcdir)/etc/openforticli/config.template
	@$(MKDIR_P) etc/openforticli
	$(AM_V_GEN)$(SED) -e '/^#/n;/^\s*$$/n;s/^/# /' $(srcdir)/etc/openforticli/config.template >$@

install-data-hook: etc/openforticli/config
	if ! test -f $(DESTDIR)$(confdir)/config ; then \
		$(MKDIR_P) $(DESTDIR)$(confdir) ; \
		$(INSTALL) -m 600 etc/openforticli/config \
			$(DESTDIR)$(confdir)/config ; \
	fi

clean-local-config:
	-rm -f $(top_builddir)/etc/openforticli/config

CLEAN_LOCALS += clean-local-config

# systemd service file
PATHFILES += lib/systemd/system/openforticli@.service

if HAVE_SYSTEMD
lib/systemd/system/openforticli@.service: $(srcdir)/lib/systemd/system/openforticli@.service.in
	@$(MKDIR_P) lib/systemd/system
	$(AM_V_GEN)$(SED) -e 's|[@]BINDIR[@]|$(bindir)|g;s|[@]SYSCONFDIR[@]|$(sysconfdir)|g' $(srcdir)/lib/systemd/system/openforticli@.service.in >$@

systemdsystemunit_DATA = lib/systemd/system/openforticli@.service

clean-local-systemd:
	-rm -f $(top_builddir)/lib/systemd/system/openforticli@.service

CLEAN_LOCALS += clean-local-systemd
endif

# man page
PATHFILES += doc/openforticli.1
dist_man_MANS = doc/openforticli.1

doc/openforticli.1: $(srcdir)/doc/openforticli.1.in
	@$(MKDIR_P) doc
	$(AM_V_GEN)$(SED) -e 's|[@]SYSCONFDIR[@]|$(sysconfdir)|g;s|[@]DATADIR[@]|$(datadir)|g' $(srcdir)/doc/openforticli.1.in >$@

clean-local-man:
	-rm -f $(top_builddir)/doc/openforticli.1

CLEAN_LOCALS += clean-local-man


EXTRA_DIST += $(PATHFILES:=.in)

all-local: etc/openforticli/config

clean-local: $(CLEAN_LOCALS)
