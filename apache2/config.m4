dnl apache/modules/modurl/config.m4   13 July 2002  JoungKyun Kim <http://www.oops.org>
dnl $Id: config.m4,v 1.1 2007-06-05 19:50:35 oops Exp $
dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(modurl)

dnl The APACHE_MODULE macro is defined in apache/acinclude.m4.
dnl If the "default" is "yes", then the "configure" script will ask if you
dnl want to disable this module.
dnl If the "default" is "no", then the "configure" script will ask if you
dnl want to _enable_ this module.

APACHE_MODULE(url, converted Sent UTF8 of IE to EUC-kr, , , yes)

dnl The "export-dynamic" parameter is explained in "man ld", but I
dnl don't understand the explanation.

APR_ADDTO(LT_LDFLAGS,-export-dynamic)

APACHE_MODPATH_FINISH
