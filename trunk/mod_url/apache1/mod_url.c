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

/* mod_url.c:: fix mismatched URL encoding between server and clients
 *   by Won-kyu Park <wkpark@kldp.org>
 * 
 * based mod_speling.c Alexei Kosut <akosut@organic.com> June, 1996
 */

/* ChangLog:
 *
 * 2000: initial release
 * 2000/10/11: fix for glibc-2.1.x glibc-2.2
 * 2002: fix for glibc-2.2 iconv: by JoungKyun Kim <http://www.oops.org>
 * 2004/08/03: add 'ServerEncoding' 'ClientEncoding' options
 *  - add per-dir support
 *
 * Usage:
 *
 * 1. Compile:
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

MODULE_VAR_EXPORT module redurl_module;

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
 * closest ancestor is used exclusively.  That's what we want, so we don't
 * bother to have such a function.
 */

static void *mkconfig(pool *p)
{
    urlconfig *cfg = ap_pcalloc(p, sizeof(urlconfig));

    cfg->enabled = 0;
    cfg->cd = 0;
    return cfg;
}

/*
 * Respond to a callback to create configuration record for a server or
 * vhost environment.
 */
static void *create_mconfig_for_server(pool *p, server_rec *s)
{
    return mkconfig(p);
}

/*
 * Respond to a callback to create a config record for a specific directory.
 */
static void *create_mconfig_for_directory(pool *p, char *dir)
{
    return mkconfig(p);
}

static void *merge_mconfig_for_directory(pool *p, void *basev, void *overridesv)
{
    urlconfig *a = (urlconfig *)ap_pcalloc (p, sizeof(urlconfig));
    urlconfig *base = (urlconfig *)basev,
        *over = (urlconfig *)overridesv;

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
    { "CheckURL", set_redurl, NULL, OR_OPTIONS, FLAG,
      "whether or not to fix mis-encoded URL requests" },
    { "ServerEncoding", set_server_encoding, NULL, OR_FILEINFO, TAKE1,
                  "name of server encoding"},
    { "ClientEncoding", set_client_encoding, NULL, OR_FILEINFO, TAKE1,
                  "name of client url encoding"},
    { NULL }
};

static int check_redurl(request_rec *r)
{
    urlconfig *cfg;
    char *good, *bad, *postgood, *url;
    int filoc, dotloc, urlen, pglen;
    DIR *dirp;
    struct DIR_TYPE *dir_entry;
    array_header *candidates = NULL;

    cfg = ap_get_module_config(r->per_dir_config, &redurl_module);
    if (!cfg->enabled) {
        return DECLINED;
    }

    /* We only want to worry about GETs */
    if (r->method_number != M_GET) {
        return DECLINED;
    }

    /* We've already got a file of some kind or another */
    if (r->proxyreq || (r->finfo.st_mode != 0)) {
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
    good = ap_pstrndup(r->pool, r->filename, filoc);
    /* bad = mispelling */
    bad = ap_pstrdup(r->pool, r->filename + filoc + 1);
    /* postgood = mispelling/more */
    postgood = ap_pstrcat(r->pool, bad, r->path_info, NULL);

    urlen = strlen(r->uri);
    pglen = strlen(postgood);

    /* Check to see if the URL pieces add up */
    if (strcmp(postgood, r->uri + (urlen - pglen))) {
        return DECLINED;
    }

    /* url = /correct-url */
    url = ap_pstrndup(r->pool, r->uri, (urlen - pglen));

    /* ½ÃÀÛ */
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, r,
		 "Orig URL: %s %s url:%s",
		 r->uri, good, url);

    {
	char *src = r->uri;
        char *buf, *to;
        pool *p = r->pool;
	size_t len, flen, tlen, ret;
	if (cfg->cd == 0) {
	    cfg->cd = iconv_open(cfg->server_encoding, cfg->client_encoding);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, r,
                "mod_url configuration: ServerEncoding %s, ClientEndoding %s",
                cfg->server_encoding ? cfg->server_encoding : "unspecified",
                cfg->client_encoding ? cfg->client_encoding : "unspecified");
            if (cfg->cd == (iconv_t)(-1)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
                    "incomplete configuration: ServerEncoding %s, ClientEndoding %s",
                    cfg->server_encoding ? cfg->server_encoding : "unspecified",
                    cfg->client_encoding ? cfg->client_encoding : "unspecified");
                return DECLINED;
	    }
	}
	flen = len = strlen(src);
        tlen = flen * 4 + 1; /* MB_CUR_MAX ~ 4 */
        buf = (char*)ap_pcalloc(p, tlen);
	to= buf;

	ret=iconv(cfg->cd, &src, &flen, &to, &tlen);

	tlen=strlen(buf);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, r,
		 "ICONV: from uri %s to %s(%d->%d): CHECK CODE '%d'",
		 r->uri, buf, len, tlen, ret);
       if (ret >= 0
#if __GLIBC_MINOR__ == 2
	&& ret == 0
#endif
	&& len != 0 && tlen != len) {
	/*
	 * ret ==-1: URL is valid already: no need to convert
	 * ret > 0: strlen of converted URL in the glibc 2.1.[2,3]
	 * flen == tlen then URL is ascii */
	    char *nuri;

            nuri = ap_pstrcat(r->pool, buf,
			      r->parsed_uri.query ? "?" : "",
			      r->parsed_uri.query ? r->parsed_uri.query : "",
			      NULL);

            ap_table_setn(r->headers_out, "Location",
			  ap_construct_url(r->pool, nuri, r));

            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, r,
			 "Fixed URL: %s to %s",
			 r->uri, nuri);

            return HTTP_MOVED_PERMANENTLY;
       } else
            return DECLINED;
    } 
    /* end of main routine */

    return OK;
}

module MODULE_VAR_EXPORT redurl_module =
{
    STANDARD_MODULE_STUFF,
    NULL,                       /* initializer */
    create_mconfig_for_directory,  /* create per-dir config */
    merge_mconfig_for_directory,   /* merge per-dir config */
    create_mconfig_for_server,  /* server config */
    NULL,                       /* merge server config */
    redurl_cmds,                /* command table */
    NULL,                       /* handlers */
    NULL,                       /* filename translation */
    NULL,                       /* check_user_id */
    NULL,                       /* check auth */
    NULL,                       /* check access */
    NULL,                       /* type_checker */
    check_redurl,               /* fixups */
    NULL,                       /* logger */
    NULL,                       /* header parser */
    NULL,                       /* child_init */
    NULL,                       /* child_exit */
    NULL                        /* post read-request */
};
