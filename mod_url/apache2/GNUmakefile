# $Id: GNUmakefile,v 1.4 2014-03-24 16:13:19 oops Exp $
#

EXTRA_CFLAGS =

all:
	/usr/sbin/apxs -i -c $(EXTRA_CFLAGS) mod_url.c

clean:
	rm -r .libs mod_url.{la,lo,o,slo}
