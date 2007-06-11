/* ====================================================================
 * Copyright (c) 1996-1999 The Apache Group.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Group.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */

#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"

#include <iconv.h>

#define REDURL_SERVER_ENCODING "EUC-KR"
#define REDURL_CLIENT_ENCODING "UTF-8"
#define REDURL_ICONV_TRUE 0
#define REDURL_ICONV_FALSE 1

/*
 * mod_url.c:: fix mismatched URL encoding between server and clients
 * Writer:
 *   JoungKyun.Kim <http://oops.org>
 *   Won-Kyu Park <wkpark@kldp.net>
 * URL:
 *   http://modurl.kldp.net/
 *
 * $Id: mod_url.c,v 1.10 2007-06-11 08:01:20 oops Exp $
 */

/*
 * Usage:
 *
 * 1. Compile :
 *    /usr/sbin/apxs -i -a -c mod_url.c
 *
 * 2. Edit your conf/httpd.conf file, and add a LoadModule line:
 *
 *    LoadModule  redurl_module   modules/mod_url.so
 *
 * 3. Activate the mod_url and set encoding variables properly:
 *    <IfModule mod_url.c>
 *        CheckURL On
 *        ServerEncoding EUC-KR
 *        ClientEncoding UTF-8
 *    </IfModule>
 */

MODULE_VAR_EXPORT module redurl_module;

typedef struct {
	int enabled;
	const char * server_encoding;
	const char * client_encoding;
	iconv_t cd;
} urlconfig;

typedef struct {
	char  * uri;
	size_t  len;
	size_t  flen;
	size_t  tlen;
	size_t  ret;
	short   alloc;
} iconv_s;

/*
 * Create a configuration specific to this module for a server or directory
 * location, and fill it with the default settings.
 *
 * The API says that in the absence of a merge function, the record for the
 * closest ancestor is used exclusively. That's what we want, so we don't
 * bother to have such a function.
 */

static void * mkconfig (pool * p)
{
	urlconfig * cfg = ap_pcalloc (p, sizeof (urlconfig));

	cfg->enabled = 0;
	cfg->cd = 0;
	return cfg;
}

/*
 * Respond to a callback to create configuration record for a server or
 * vhost environment.
 */
static void * create_mconfig_for_server (pool * p, server_rec * s)
{
	return mkconfig (p);
}

/*
 * Respond to a callback to create a config record for a specific directory.
 */
static void * create_mconfig_for_directory (pool * p, char * dir)
{
	return mkconfig (p);
}

static void * merge_mconfig_for_directory (pool * p, void * basev, void * overridesv)
{
	urlconfig * a = (urlconfig *) ap_pcalloc (p, sizeof (urlconfig));
	urlconfig * base = (urlconfig *) basev;
	urlconfig * over = (urlconfig *) overridesv;

	a->server_encoding =
		over->server_encoding ? over->server_encoding : base->server_encoding;
	a->client_encoding =
		over->client_encoding ? over->client_encoding : base->client_encoding;
	a->enabled = over->enabled;
	a->cd = 0;
	return a;
}

/*
 * Handler for the CheckURL encoding directive, which is FLAG.
 */
static const char * set_redurl( cmd_parms * cmd, void * mconfig, int arg)
{
	urlconfig * cfg = (urlconfig *) mconfig;

	cfg->enabled = arg;
	return NULL;
}

/* ServerEncoding charset
 */
static const char * set_server_encoding (cmd_parms * cmd, void * mconfig,
									   const char * name)
{
	urlconfig * cfg = (urlconfig *) mconfig;

	cfg->server_encoding = name;
	return NULL;
}

/* ClientEncoding charset
 */
static const char * set_client_encoding (cmd_parms * cmd, void * mconfig,
									   const char * name)
{
	urlconfig * cfg = (urlconfig *) mconfig;

	cfg->client_encoding = name;
	return NULL;
}

/*
 * Define the directives specific to this module. This structure is referenced
 * later by the 'module' structure.
 */
static const command_rec redurl_cmds[] =
{
	{ "CheckURL", set_redurl, NULL, OR_OPTIONS, FLAG,
	  "whether or not to fix mis-encoded URL requests" },
	{ "ServerEncoding", set_server_encoding, NULL, OR_FILEINFO, TAKE1,
	  "name of server encoding (default EUC-KR)"},
	{ "ClientEncoding", set_client_encoding, NULL, OR_FILEINFO, TAKE1,
	  "name of client url encoding (default UTF-8)"},
	{ NULL }
};

char * check_redurl_encode (const char * str, int len, int * retlen)
{
	static unsigned char hexs[] = "0123456789ABCDEF";
	unsigned char * o, * r;
	unsigned char * s;
	int l;

	r = (unsigned char *) malloc (sizeof (char) * (len * 3 + 1));
	if ( r == NULL )
		return NULL;

	o = r;
	s = (unsigned char *) str;

	while ( len-- ) {
		/* ASCII area */
		if ( *s > 32 && *s < 127 ) {
			*o++ = *s++;
			l++;
			continue;
		}

		*o++ = 37;
		*o++ = hexs[*s >> 0x4];
		*o++ = hexs[*s++ & 0xf];
		l += 3;
	}
	*o = 0;

	if ( retlen )
		*retlen = l;

	return (char *) r;
}

void redurl_mem_error (const request_rec * s, const char * file, int line, char * r) {
	ap_log_rerror (file, line, APLOG_ERR, s,
			"%s variable: memory allocation failed", r);
}

void check_redurl_iconv (request_rec * r, urlconfig * cfg, iconv_s * ic, char * s_uri)
{
	char * src = s_uri;
	char * to;
	const char * s_enc, * c_enc;
	size_t flen, tlen;

	ic->len = ic->tlen = ic->flen = ic->ret = 0;

	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"check_redurl_iconv: iconv convert start -------------------");

	s_enc = cfg->server_encoding ? cfg->server_encoding : REDURL_SERVER_ENCODING;
	c_enc = cfg->client_encoding ? cfg->client_encoding : REDURL_CLIENT_ENCODING;

	ic->alloc = 0;

	cfg->cd = iconv_open (s_enc, c_enc);
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"mod_url configuration: ServerEncoding %s, ClientEndoding %s",
			s_enc, c_enc);
	if ( cfg->cd == (iconv_t)(-1) ) {
		ic->ret = -1;
		ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
				"incomplete configuration: ServerEncoding %s, ClientEndoding %s",
				s_enc, c_enc);
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
				"check_redurl_iconv: iconv convert end   -------------------");
		return;
	}

	flen = ic->len = strlen (src);
	tlen = flen * 4 + 1; /* MB_CUR_MAX ~ 4 */

	if ( (ic->uri = (char *) malloc (sizeof (char) * tlen)) == NULL ) {
		ic->ret = -1;
		redurl_mem_error (r, APLOG_MARK, "ic->uri");
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
				"check_redurl_iconv: iconv convert end   -------------------");
		return;
	} else
		memset (ic->uri, 0, sizeof (char) * tlen);

	ic->alloc = 1;
	to = ic->uri;

	ic->ret = iconv (cfg->cd, &src, &flen, &to, &tlen);

	tlen = strlen (ic->uri);
	ic->tlen = tlen;
	ic->flen = flen;

	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"  Oirg       => %s (%d)", s_uri, ic->len);
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"  Fixed      => %s (%d)", ic->uri, tlen);
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"  Check Code => %d", ic->ret);
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"check_redurl_iconv: iconv convert end   -------------------");
}

void check_redurl_iconv_free (iconv_s * ic)
{
	if ( ic->alloc )
		free (ic->uri);

	free (ic);
}

int check_redurl_iconv_result (iconv_s * ic)
{
	if ( ic->ret >= 0
#if __GLIBC_MINOR__ == 2
		&& ic->ret == 0
#endif
		&& ic->len != 0 && ic->tlen != ic->len )
		return REDURL_ICONV_TRUE;
	else
		return REDURL_ICONV_FALSE;
}

static int check_redurl (request_rec * r)
{
	urlconfig		* cfg;
	iconv_s			* uic;
	iconv_s			* ric;
	struct			  stat realstat;
	char			* realpath, * c_uri, * enc;
	int				  rlen, flen, plen;
	int				  uic_r, ric_r;

	cfg = ap_get_module_config (r->per_dir_config, &redurl_module);
	if ( ! cfg->enabled )
		return DECLINED;

	/* We only want to worry about GETs */
	if ( r->method_number != M_GET )
		return DECLINED;

	/* We've already got a file of some kind or another */
	if ( r->proxyreq || (r->finfo.st_mode != 0) )
		return DECLINED;

	/* This is a sub request - don't mess with it */
	if ( r->main )
		return DECLINED;

	/*
	 * Don't do anything if the request doesn't contain a slash, or
	 * requests "/" 
	 */
	if ( ap_rind (r->filename, '/') == -1 || strcmp (r->uri, "/") == 0 )
		return DECLINED;

	/*
	 * Removes double or multiple slashes from a r->uri
	 */
	ap_no2slash (r->uri);

	/* make completly full path */
	flen = strlen (r->filename);
	plen = r->path_info ? strlen (r->path_info) : 0;

	if ( (realpath = (char *) malloc (sizeof (char) * (flen + plen + 1))) == NULL ) {
		redurl_mem_error (r, APLOG_MARK, "realpath");
		return DECLINED;
	}

	strcpy (realpath, r->filename);
	if ( plen )
		strcat (realpath, r->path_info);

	/*
	 * Original Information logging
	 */
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"ORIG URI       => %s", r->uri);
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"ORIG URI_C     => %s", r->unparsed_uri);
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"ORIG PATH      => %s", r->filename);
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"ORIG PATH INFO => %s", r->path_info);
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"REAL PATH      => %s", realpath);

	/* convert uri */
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"URI Converting");

	if ( (uic = (iconv_s *) malloc (sizeof (iconv_s) + 1)) == NULL ) {
		redurl_mem_error (r, APLOG_MARK, "uic");
		free (realpath);

		return DECLINED;
	}

	check_redurl_iconv (r, cfg, uic, r->uri);
	uic_r = check_redurl_iconv_result (uic);
	/*
	 * Converted URI Information logging
	 */
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"  S_URI => %s", r->uri);
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"  URI   => %s", uic->uri);
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"  S_LEN => %d", uic->len);
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"  LEN   => %d", uic->tlen);
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"  CODE  => %d", uic->ret);

	if ( uic_r == REDURL_ICONV_FALSE ) {
		/* converting failed */
		check_redurl_iconv_free (uic);
		free (realpath);

		return DECLINED;
	}

	if ( ! strcmp (r->uri, uic->uri) ) {
		check_redurl_iconv_free (uic);
		free (realpath);

		return OK;
	}

	if ( (enc = check_redurl_encode (uic->uri, strlen (uic->uri), NULL)) == NULL ) {
		redurl_mem_error (r, APLOG_MARK, "enc");
		check_redurl_iconv_free (uic);
		free (realpath);

		return DECLINED;
	}

	c_uri = ap_pstrcat (r->pool, enc,
				r->parsed_uri.query ? "?" : "",
				r->parsed_uri.query ? r->parsed_uri.query : "",
				NULL);
	free (enc);
	check_redurl_iconv_free (uic);

	/* convert real path */
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"Real path Converting"); 

	if ( (ric = (iconv_s *) malloc (sizeof (iconv_s) + 1)) == NULL ) {
		redurl_mem_error (r, APLOG_MARK, "ric");
		free (realpath);

		return DECLINED;
	}
	check_redurl_iconv (r, cfg, ric, realpath);
	ric_r = check_redurl_iconv_result (ric);

	/*
	 * Converted Real Path Information logging
	 */
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"  S_PATH => %s", realpath);
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"  PATH   => %s", ric->uri);
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"  S_LEN  => %d", ric->len);
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"  LEN    => %d", ric->tlen);
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"  CODE   => %d", ric->ret);

	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"Fixed Information");
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"  Orig  => %s", r->unparsed_uri);
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"  Fixed => %s", c_uri);

	/*
	 * Full path and uri have character that is out of range ascii.
	 * But, encoding is different each other. So, mod_url sending
	 * 301 HTTP_MOVED_PERMANENTLY with converted URL
	 */
	if ( ric_r == REDURL_ICONV_FALSE ) {
		/* working ready */
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
				"  Goto => %s", ap_construct_url (r->pool, c_uri, r));

		ap_table_setn (r->headers_out, "Location",
			ap_construct_url (r->pool, c_uri, r));

		return HTTP_MOVED_PERMANENTLY;
	}

	if ( ! strcmp (realpath, ric->uri) ) {
		check_redurl_iconv_free (ric);
		free (realpath);

		return OK;
	}
	free (realpath);

	/*
	 * Full path check on file system
	 */
	if ( stat (ric->uri, &realstat) < 0 ) {
		/* file not found */
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
				"  Not Found => %s", ric->uri);

		check_redurl_iconv_free (ric);

		return DECLINED;
	}

	ap_parse_uri (r, c_uri);
	r->filename                = ap_pstrdup (r->pool, ric->uri);
	r->case_preserved_filename = r->filename;
	r->path_info               = "";
	stat (r->filename, &r->finfo);

	check_redurl_iconv_free (ric);

	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"  r->uri             => %s", r->uri);
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"  r->unparsed_uri    => %s", r->unparsed_uri);
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"  r->parsed_uri.path => %s", r->parsed_uri.path);
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"  r->filename        => %s", r->filename);
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"  r->case_preserved_filenames => %s", r->case_preserved_filename);

	return OK;
}

module MODULE_VAR_EXPORT redurl_module =
{
	STANDARD_MODULE_STUFF,
	NULL,							/* initializer */
	create_mconfig_for_directory,	/* create per-dir config */
	merge_mconfig_for_directory,	/* merge per-dir config */
	create_mconfig_for_server,		/* server config */
	NULL,							/* merge server config */
	redurl_cmds,					/* command table */
	NULL,							/* handlers */
	NULL,							/* filename translation */
	NULL,							/* check_user_id */
	NULL,							/* check auth */
	NULL,							/* check access */
	NULL,							/* type_checker */
	check_redurl,					/* fixups */
	NULL,							/* logger */
	NULL,							/* header parser */
	NULL,							/* child_init */
	NULL,							/* child_exit */
	NULL
};

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
