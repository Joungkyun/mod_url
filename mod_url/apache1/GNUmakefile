# $Id: GNUmakefile,v 1.4 2007-11-09 09:16:24 oops Exp $
#

#
# modurl has dependency with mod_userdir. If your apache
# don't include mod_userdir, set URL_NOUSERDIR constant.
#
#EXTRA_CFLAGS = -DURL_NOUSERDIR
EXTRA_CFLAGS =

all:
	/usr/sbin/apxs -i -c $(EXTRA_CFLAGS) mod_url.c

clean:
	rm -f mod_url.{so,o}
