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

#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_request.h"
#include "http_log.h"

#include <iconv.h>

#define DEFAULT_SERVER_ENCODING "EUC-KR"
#define DEFAULT_CLIENT_ENCODING "UTF-8"

/* mod_url.c: fix mismatched URL encoding between server and clients
 *            based on mod_spelling
 *  Writer:
 *    Won-kyu Park <wkpark@kldp.net>
 *    JoungKyun.Kim <http://oops.org>
 *  URL:
 *    http://modurl.kldp.net
 *
 * based mod_speling.c Alexei Kosut <akosut@organic.com> June, 1996
 */

/*
 * Usage:
 *
 * 1. Compile it:
 * /usr/sbin/apxs -i -a -c mod_url.c
 *
 * 2. Edit your conf/httpd.conf file, and add a LoadModule line:
 *
 * LoadModule  redurl_module   modules/mod_url.so
 *
 * 3. Activate the mod_url and set encoding variables properly:
 * <IfModule mod_url.c>
 *  CheckURL On
 *  ServerEncoding EUC-KR
 *  ClientEncoding UTF-8
 * </IfModule>
 */

module AP_MODULE_DECLARE_DATA redurl_module;

typedef struct {
	int enabled;
	const char *server_encoding;
	const char *client_encoding;
	iconv_t cd;
} urlconfig;

/*
 * Create a configuration specific to this module for a server or directory
 * location, and fill it with the default settings.
 *
 * The API says that in the absence of a merge function, the record for the
 * closest ancestor is used exclusively. That's what we want, so we don't
 * bother to have such a function.
 */

static void *mkconfig(apr_pool_t *p)
{
	urlconfig *cfg = apr_pcalloc(p, sizeof(urlconfig));

	cfg->enabled = 0;
	cfg->cd = 0;
	return cfg;
}

/*
 * Respond to a callback to create configuration record for a server or
 * vhost environment.
 */
static void *create_mconfig_for_server(apr_pool_t *p, server_rec *s)
{
	return mkconfig(p);
}

/*
 * Respond to a callback to create a config record for a specific directory.
 */
static void *create_mconfig_for_directory(apr_pool_t *p, char *dir)
{
	return mkconfig(p);
}

static void *merge_mconfig_for_directory(apr_pool_t *p, void *basev, void *overridesv)
{
	urlconfig *a = (urlconfig *)apr_pcalloc (p, sizeof(urlconfig));
	urlconfig *base = (urlconfig *)basev;
	urlconfig *over = (urlconfig *)overridesv;

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
static const char *set_redurl(cmd_parms *cmd, void *mconfig, int arg)
{
	urlconfig *cfg = (urlconfig *) mconfig;

	cfg->enabled = arg;
	return NULL;
}

/* ServerEncoding charset
 */
static const char *set_server_encoding(cmd_parms *cmd, void *mconfig,
									   const char *name)
{
	urlconfig *cfg = (urlconfig *) mconfig;

	cfg->server_encoding = name;
	return NULL;
}

/* ClientEncoding charset
 */
static const char *set_client_encoding(cmd_parms *cmd, void *mconfig,
									   const char *name)
{
	urlconfig *cfg = (urlconfig *) mconfig;

	cfg->client_encoding = name;
	return NULL;
}

/*
 * Define the directives specific to this module.  This structure is referenced
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


static int check_redurl(request_rec *r)
{
	urlconfig *cfg;
	char *good, *bad, *postgood, *url;
	apr_finfo_t dirent;
	int filoc, dotloc, urlen, pglen;
	apr_array_header_t *candidates = NULL;
	apr_dir_t		  *dir;

	cfg = ap_get_module_config(r->per_dir_config, &redurl_module);
	if (!cfg->enabled) {
		return DECLINED;
	}

	/* We only want to worry about GETs */
	if (r->method_number != M_GET) {
		return DECLINED;
	}

	/* We've already got a file of some kind or another */
	if (r->proxyreq || (r->finfo.filetype != 0)) {
		return DECLINED;
	}

	/* This is a sub request - don't mess with it */
	if (r->main) {
		return DECLINED;
	}

	/*
	 * The request should end up looking like this:
	 * r->uri: /correct-url/mispelling/more
	 * r->filename: /correct-file/mispelling r->path_info: /more
	 *
	 * So we do this in steps. First break r->filename into two pieces
	 */

	filoc = ap_rind(r->filename, '/');
	/*
	 * Don't do anything if the request doesn't contain a slash, or
	 * requests "/" 
	 */
	if (filoc == -1 || strcmp(r->uri, "/") == 0) {
		return DECLINED;
	}

	/* good = /correct-file */
	good = apr_pstrndup(r->pool, r->filename, filoc);
	/* bad = mispelling */
	bad = apr_pstrdup(r->pool, r->filename + filoc + 1);
	/* postgood = mispelling/more */
	postgood = apr_pstrcat(r->pool, bad, r->path_info, NULL);

	urlen = strlen(r->uri);
	pglen = strlen(postgood);

	/* Check to see if the URL pieces add up */
	if (strcmp(postgood, r->uri + (urlen - pglen))) {
		return DECLINED;
	}

	/* url = /correct-url */
	url = apr_pstrndup(r->pool, r->uri, (urlen - pglen));

	/* start of main routine */
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
		 "Orig URL: %s %s url:%s",
		 r->uri, good, url);
	{
		char *src = r->uri;
		char *buf, *to;
		const char *s_enc, *c_enc;
		apr_pool_t *p = r->pool;
		size_t len, flen, tlen, ret;

		s_enc = cfg->server_encoding ? cfg->server_encoding : DEFAULT_SERVER_ENCODING;
		c_enc = cfg->client_encoding ? cfg->client_encoding : DEFAULT_CLIENT_ENCODING;

		if (cfg->cd == 0) {
			cfg->cd = iconv_open(s_enc, c_enc);
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
				"mod_url configuration: ServerEncoding %s, ClientEndoding %s",
				s_enc, c_enc);
			if (cfg->cd == (iconv_t)(-1)) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"incomplete configuration: ServerEncoding %s, ClientEndoding %s",
					s_enc, c_enc);
				return DECLINED;
			}
		}

		flen = len = strlen(src);
		tlen = flen * 4 + 1; /* MB_CUR_MAX ~ 4 */
		buf = (char*)apr_pcalloc(p, tlen);
		to= buf;

		ret=iconv(cfg->cd, &src, &flen, &to, &tlen);

		tlen=strlen(buf);
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			 "ICONV: from uri %s to %s(%d->%d): CHECK CODE '%d'",
			 r->uri, buf, len, tlen, ret);
		if (ret >= 0
#if __GLIBC_MINOR__ >= 2
			&& ret == 0
#endif
			&& len != 0 && tlen != len) {
			/*
			 * ret ==-1: URL is valid already: no need to convert 
			 * ret > 0: strlen of converted URL in the glibc 2.1.[2,3]
			 * flen == tlen then URL is ascii */
			char *nuri;
			char *enc = check_redurl_encode (buf, strlen (buf), NULL);

			nuri = apr_pstrcat(r->pool, enc,
						r->parsed_uri.query ? "?" : "",
						r->parsed_uri.query ? r->parsed_uri.query : "",
						NULL);

			if ( enc )
				free (enc);

			apr_table_setn(r->headers_out, "Location",
							ap_construct_url(r->pool, nuri, r));

			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
				 "Fixed URL: %s to %s",
				 r->uri, nuri);

			return HTTP_MOVED_PERMANENTLY;
		} else
			return DECLINED;
	} 
	/* end of main routine */

	return OK;
}

static void register_hooks(apr_pool_t *p)
{
	ap_hook_fixups(check_redurl,NULL,NULL,APR_HOOK_LAST);
}

module AP_MODULE_DECLARE_DATA redurl_module =
{
	STANDARD20_MODULE_STUFF,
	create_mconfig_for_directory,   /* create per-dir config */
	merge_mconfig_for_directory,    /* merge per-dir config */
	create_mconfig_for_server,      /* server config */
	NULL,                           /* merge server config */
	redurl_cmds,                    /* command apr_table_t */
	register_hooks                  /* register hooks */
};
