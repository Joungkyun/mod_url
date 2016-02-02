# $Id: GNUmakefile,v 1.5 2016-02-02 17:39:15 oops Exp $
#

EXTRA_CFLAGS =
APXS         = apxs

all:
	$(APXS) -i -c $(EXTRA_CFLAGS) mod_url.c

clean:
	rm -r .libs mod_url.{la,lo,o,slo}
