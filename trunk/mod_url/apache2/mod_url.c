/* Copyright 1999-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "apr.h"
#include "apr_file_io.h"
#include "apr_strings.h"
#include "apr_lib.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#define WANT_BASENAME_MATCH

#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_log.h"

#include <iconv.h>

#ifndef _UNISTD_H
#include <unistd.h>
#endif
#ifndef _SYS_STAT_H
#include <sys/stat.h>
#endif

#define REDURL_SERVER_ENCODING "EUC-KR"
#define REDURL_CLIENT_ENCODING "UTF-8"
#define REDURL_ICONV_TRUE 0
#define REDURL_ICONV_FALSE 1

/*
 * mod_url.c: fix mismatched URL encoding between server and clients
 * Writer:
 *   JoungKyun.Kim <http://oops.org>
 *   Won-Kyu Park <wkpark@kldp.net>
 * URL:
 *   http://modurl.kldp.net/
 *
 * $Id: mod_url.c,v 1.7 2007-06-05 19:50:35 oops Exp $
 */

/*
 * Usage:
 *
 * 1. Compile it:
 *    /usr/sbin/apxs -i -c mod_url.c
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

module AP_MODULE_DECLARE_DATA redurl_module;

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
 * closest ancestor is used exclusively.  That's what we want, so we don't
 * bother to have such a function.
 */

static void * mkconfig (apr_pool_t * p)
{
	urlconfig * cfg = apr_pcalloc (p, sizeof (urlconfig));

	cfg->enabled = 0;
	cfg->cd      = 0;
	return cfg;
}

/*
 * Respond to a callback to create configuration record for a server or
 * vhost environment.
 */
static void * create_mconfig_for_server (apr_pool_t * p, server_rec * s)
{
	return mkconfig (p);
}

/*
 * Respond to a callback to create a config record for a specific directory.
 */
static void * create_mconfig_for_directory (apr_pool_t * p, char * dir)
{
	return mkconfig (p);
}

static void * merge_mconfig_for_directory (apr_pool_t * p, void * basev, void * overridesv)
{
	urlconfig * a    = (urlconfig *) apr_pcalloc (p, sizeof (urlconfig));
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
static const char * set_redurl (cmd_parms * cmd, void * mconfig, int arg)
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
	AP_INIT_FLAG("CheckURL", set_redurl, NULL, OR_OPTIONS,
				"whether or not to fix mis-encoded URL requests"),
	AP_INIT_TAKE1("ServerEncoding", set_server_encoding, NULL, OR_FILEINFO,
				"name of server encoding (default EUC-KR)"),
	AP_INIT_TAKE1("ClientEncoding", set_client_encoding, NULL, OR_FILEINFO,
				"name of client url encoding (default UTF-8)"),
	{ NULL }
};

char * check_redurl_encode (const char * str, int len, int * retlen)
{
	static unsigned char hexs[] = "0123456789ABCDEF";
	unsigned char * o, * r;
	unsigned char * s ;
	int l = 0;

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

void redurl_mem_error (const request_rec * s, const char * file, int line, char * r)
{
	ap_log_rerror (file, line, APLOG_ERR, APR_ENOPOOL, s,
			"%s variable: memory allocation failed", r);
}

void check_redurl_iconv (request_rec * r, urlconfig * cfg, iconv_s * ic, char * s_uri)
{
	char * src = s_uri;
	char * to;
	const char * s_enc, * c_enc;
	size_t flen, tlen;

	ic->len = ic->tlen = ic->flen = ic->ret = 0;

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"check_redurl_iconv: iconv convert start -------------------");

	s_enc = cfg->server_encoding ? cfg->server_encoding : REDURL_SERVER_ENCODING;
	c_enc = cfg->client_encoding ? cfg->client_encoding : REDURL_CLIENT_ENCODING;

	ic->alloc = 0;

	cfg->cd = iconv_open (s_enc, c_enc);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"mod_url configuration: ServerEncoding %s, ClientEndoding %s",
			s_enc, c_enc);
	if ( cfg->cd == (iconv_t)(-1) ) {
		ic->ret = -1;
		ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_INCOMPLETE, r,
				"incomplete configuration: ServerEncoding %s, ClientEndoding %s",
				s_enc, c_enc);
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
				"check_redurl_iconv: iconv convert end   -------------------");
		return;
	}

	flen = ic->len = strlen (src);
	tlen = flen * 4 + 1; /* MB_CUR_MAX ~ 4 */

	if ( (ic->uri = (char *) malloc (sizeof (char) * tlen)) == NULL ) {
		ic->ret = -1;
		redurl_mem_error (r, APLOG_MARK, "ic->uri");
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
				"check_redurl_iconv: iconv convert end   -------------------");
		return;
	}

	ic->alloc = 1;
	to = ic->uri;

	ic->ret = iconv (cfg->cd, &src, &flen, &to, &tlen);

	tlen = strlen (ic->uri);
	ic->tlen = tlen;
	ic->flen = flen;

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"  Oirg       => %s (%d)", s_uri, ic->len);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"  Fixed      => %s (%d)", ic->uri, tlen);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"  Check Code => %d", ic->ret);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
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
	int				  flen, plen;
	int				  uic_r, ric_r;

	cfg = ap_get_module_config (r->per_dir_config, &redurl_module);
	if ( ! cfg->enabled )
		return DECLINED;

	/* We only want to worry about GETs */
	if ( r->method_number != M_GET )
		return DECLINED;

	/* We've already got a file of some kind or another */
	if ( r->proxyreq || (r->finfo.filetype != 0) )
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
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"ORIG URI       => %s", r->uri);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"ORIG URI_C     => %s", r->unparsed_uri);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"ORIG PATH      => %s", r->filename);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"ORIG PATH INFO => %s", r->path_info);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"REAL PATH      => %s", realpath);

	/* convert uri */
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
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
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"  S_URI => %s", r->uri);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"  URI   => %s", uic->uri);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"  S_LEN => %d", uic->len);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"  LEN   => %d", uic->tlen);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
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

	c_uri = apr_pstrcat (r->pool, enc,
				r->parsed_uri.query ? "?" : "",
				r->parsed_uri.query ? r->parsed_uri.query : "",
				NULL);
	free (enc);
	check_redurl_iconv_free (uic);

	/* convert real path */
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
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
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"  S_PATH => %s", realpath);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"  PATH   => %s", ric->uri);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"  S_LEN  => %d", ric->len);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"  LEN    => %d", ric->tlen);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"  CODE   => %d", ric->ret);

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"Fixed Information");
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"  Orig  => %s", r->unparsed_uri);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"  Fixed => %s", c_uri);

	/*
	 * Full path and uri have character that is out of range ascii.
	 * But, encoding is different each other. So, mod_url sending
	 * 301 HTTP_MOVED_PERMANENTLY with converted URL
	 */
	if ( ric_r == REDURL_ICONV_FALSE ) {
		/* working ready */
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
				"  Goto => %s", ap_construct_url (r->pool, c_uri, r));

		apr_table_setn (r->headers_out, "Location",
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
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
				"  Not Found => %s", ric->uri);

		check_redurl_iconv_free (ric);

		return DECLINED;
	}

	ap_parse_uri (r, (const char *) c_uri);
	r->filename                = apr_pstrdup (r->pool, ric->uri);
	r->canonical_filename      = r->filename;
	r->path_info               = "";
	r->used_path_info          = 0;

	apr_stat (&r->finfo, r->filename, APR_FINFO_MIN, r->pool);
	check_redurl_iconv_free (ric);

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"  r->uri             => %s", r->uri);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"  r->unparsed_uri    => %s", r->unparsed_uri);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"  r->parsed_uri.path => %s", r->parsed_uri.path);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"  r->filename        => %s", r->filename);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"  r->canonical_filename => %s", r->canonical_filename);

	return OK;
}

static void register_hooks (apr_pool_t * p)
{
	ap_hook_fixups (check_redurl, NULL, NULL, APR_HOOK_LAST);
}

module AP_MODULE_DECLARE_DATA redurl_module =
{
	STANDARD20_MODULE_STUFF,
	create_mconfig_for_directory,	/* create per-dir config */
	merge_mconfig_for_directory,	/* merge per-dir config */
	create_mconfig_for_server,		/* server config */
	NULL,							/* merge server config */
	redurl_cmds,					/* command apr_table_t */
	register_hooks					/* register hooks */
};

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
