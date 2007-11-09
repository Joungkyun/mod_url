# $Id: GNUmakefile,v 1.3 2007-11-09 18:25:58 oops Exp $
#

#
# modurl has dependency with mod_userdir. If your apache
# don't include mod_userdir, set URL_NOUSERDIR constant.
#
# #EXTRA_CFLAGS = -DURL_NOUSERDIR
EXTRA_CFLAGS =

all:
	/usr/sbin/apxs -i -c $(EXTRA_CFLAGS) mod_url.c

clean:
	rm -r .libs mod_url.{la,lo,o,slo}
