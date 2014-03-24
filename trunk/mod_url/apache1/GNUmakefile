# $Id: GNUmakefile,v 1.5 2014-03-24 16:19:25 oops Exp $
#

EXTRA_CFLAGS =

all:
	/usr/sbin/apxs -i -c $(EXTRA_CFLAGS) mod_url.c

clean:
	rm -f mod_url.{so,o}
