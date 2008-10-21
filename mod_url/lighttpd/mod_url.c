/*
 * mod_url : fix mismatched URL encoding between server and clients
 * Writer  :
 *          JoungKyun.Kim <http://oops.org>
 * URL     :
 *          http://oops.org
 *          http://modurl.kldp.net
 * $Id: mod_url.c,v 1.5 2008-10-21 11:18:34 oops Exp $
 *
 * License of this module follows GPL v2.
 */

#define _GNU_SOURCE
#include <iconv.h>

#include "server.h"
#include "response.h"
#include "connections.h"
#include "log.h"

#include "plugin.h"

#ifndef _UNISTD_H
#include <unistd.h>
#endif
#ifndef _SYS_STAT_H
#include <sys/stat.h>
#endif

/*
 ******************************************************************************
 * prototype for throttle
 ******************************************************************************
 */

#define DEFAULT_SERVER_CHARSET "EUC-KR"
#define DEFAULT_CLIENT_CHARSET "UTF-8"

#define URL_ICONV_TRUE 0
#define URL_ICONV_FALSE 1

#define URL_TRUE 0
#define URL_FALSE 1

#define __URL_DEBUG 0

typedef struct {
	short enabled;
	short debug;

	buffer * server_encoding;
	buffer * client_encoding;
} plugin_config;

typedef struct {
	PLUGIN_DATA;

	plugin_config ** config_storage;
	plugin_config conf;
} plugin_data;

typedef struct {
	iconv_t cd;
	char  * uri;
	size_t  len;
	size_t  flen;
	size_t  tlen;
	short   ret;
	short   alloc;
	short   clloc;
} iconv_s;

void url_mem_error (server *, char *);
void url_iconv_free (iconv_s *, int);
static short url_iconv_result (iconv_s *);
short url_iconv (server *, plugin_config, iconv_s *, char *);
void check_url (server *, connection *, plugin_data *);
void url_log_error_hex_write (server *, char *, char *);
short url_file_exists (char *);

INIT_FUNC(mod_url_init) {
	plugin_data *p;

	p = calloc (1, sizeof (*p));

	return p;
}

FREE_FUNC(mod_url_free) {
	plugin_data *p = p_d;
	UNUSED (srv);

#if __URL_DEBUG
	log_error_write (srv, __FILE__, __LINE__, "s", "** mod_url_free");
#endif

	if ( ! p ) {
		log_error_write (srv, __FILE__, __LINE__, "s",
						"FREE_FUNC: plugin_data has no data");
		return HANDLER_GO_ON;
	}

	if ( p->config_storage ) {
		size_t i;
		for ( i = 0; i < srv->config_context->used; i++ ) {
			plugin_config *s = p->config_storage[i];

			if ( ! s ) continue;

			buffer_free(s->server_encoding);
			buffer_free(s->client_encoding);
			s->enabled = 0;
			s->debug   = 0;
			free (s);
		}
		free(p->config_storage);
	}

	free (p);

	return HANDLER_GO_ON;
}

SETDEFAULTS_FUNC(mod_url_set_default) {
	plugin_data *p = p_d;
	size_t i;

	config_values_t cv[] = {
		{ "url.enabled",			NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },
		{ "url.debug",				NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },
		{ "url.server_encoding",	NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
		{ "url.client_encoding",	NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
		{ NULL,						NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};

#if __URL_DEBUG
	log_error_write (srv, __FILE__, __LINE__, "s", "** mod_url_set_defaults");
#endif

	if ( !p ) {
		log_error_write (srv, __FILE__, __LINE__, "s", "can't initionalize plugin_data");
		return HANDLER_ERROR;
	}

	p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));

	for ( i=0; i < srv->config_context->used; i++ ) {
		plugin_config *s;

		s = calloc(1, sizeof(plugin_config));
		s->enabled = 0;
		s->debug   = 0;
		s->server_encoding = buffer_init ();
		s->client_encoding = buffer_init ();

		cv[0].destination = &(s->enabled);
		cv[1].destination = &(s->debug);
		cv[2].destination = s->server_encoding;
		cv[3].destination = s->client_encoding;

		p->config_storage[i] = s;

		if ( 0 != config_insert_values_global (srv, ((data_config *) srv->config_context->data[i])->value, cv) ) {
			log_error_write (srv, __FILE__, __LINE__, "s", "Can't insert global config value");
			return HANDLER_ERROR;
		}
	}

	return HANDLER_GO_ON;
}

#define PATCH(x) \
	p->conf.x = s->x;

static int mod_url_patch_connection (server *srv, connection *con, plugin_data *p) {
	plugin_config *s = p->config_storage[0];
	size_t i, j;

#if __URL_DEBUG
	log_error_write (srv, __FILE__, __LINE__, "s", "** mod_url_patch_connection");
#endif

	PATCH (enabled);
	PATCH (debug);
	PATCH (server_encoding);
	PATCH (client_encoding);

	/* skip the first, the global context */
	for ( i=1; i < srv->config_context->used; i++ ) {
		data_config *dc = (data_config *) srv->config_context->data[i];
		s = p->config_storage[i];

		/* condition didn't match */
		if ( ! config_check_cond (srv, con, dc) ) continue;

		/* merge config */
		for ( j=0; j < dc->value->used; j++ ) {
			data_unset *du = dc->value->data[j];

			if ( buffer_is_equal_string (du->key, CONST_STR_LEN("url.enabled")) ) {
				 PATCH (enabled);
			} else if ( buffer_is_equal_string (du->key, CONST_STR_LEN("url.debug")) ) {
				 PATCH (debug);
			} else if ( buffer_is_equal_string (du->key, CONST_STR_LEN("url.server_client")) ) {
				 PATCH (server_encoding);
			} else if ( buffer_is_equal_string (du->key, CONST_STR_LEN("url.client_client")) ) {
				 PATCH (client_encoding);
			}
		}
	}

	if ( buffer_is_empty (s->server_encoding) )
		buffer_copy_string (s->server_encoding, DEFAULT_SERVER_CHARSET);

	if ( buffer_is_empty (s->client_encoding) )
		buffer_copy_string (s->client_encoding, DEFAULT_CLIENT_CHARSET);

	if ( p->conf.debug ) {
		log_error_write (srv, __FILE__, __LINE__, "sd", "url.enabled:", p->conf.enabled);
		log_error_write (srv, __FILE__, __LINE__, "ss", "url.server_encoding:", p->conf.server_encoding->ptr);
		log_error_write (srv, __FILE__, __LINE__, "ss", "url.client_encoding:", p->conf.client_encoding->ptr);
	}

	return 0;
}
#undef PATCH

//URIHANDLER_FUNC(mod_url_uri_handler) {
//REQUESTDONE_FUNC (mod_url_handler) {
PHYSICALPATH_FUNC (mod_url_handler) {
	plugin_data *p = p_d;

#if __URL_DEBUG
	log_error_write (srv, __FILE__, __LINE__, "s", "** mod_url_handler");
#endif

	UNUSED (srv);

	mod_url_patch_connection (srv, con, p);

	/* if module not used */
	if ( ! p->conf.enabled )
		return HANDLER_GO_ON;

	check_url (srv, con, p);

	return HANDLER_GO_ON;
}

/* this function is called at dlopen() time and inits the callbacks */
int mod_url_plugin_init (plugin *p) {
	p->version			= LIGHTTPD_VERSION_ID;
	p->name				= buffer_init_string ("url");

	p->init				= mod_url_init;
	p->set_defaults		= mod_url_set_default;
	p->cleanup			= mod_url_free;

	p->handle_physical  = mod_url_handler;

	p->data = NULL;

	return 0;
}

/* User Define API */

void url_mem_error (server * srv, char * r) {
	log_error_write (srv, __FILE__, __LINE__, "ss",
			r, "variable: memory allocation failed");
}

void url_iconv_free (iconv_s * ic, int type) {
	if ( ic->alloc )
		free (ic->uri);

	if ( ic->clloc )
		iconv_close (ic->cd);

	/* init structure members */
	ic->alloc = ic->clloc = ic->len = ic->tlen = ic->flen = ic->ret = 0;

	if ( ! type )
		free (ic);
}

static short url_iconv_result (iconv_s * ic) {
	if (
#if __GLIBC_MINOR__ >= 2
		ic->ret == 0
#else
		ic->ret >= 0
#endif
			&& ic->len != 0 && ic->tlen != ic->len )
		return URL_ICONV_TRUE;
	else
		return URL_ICONV_FALSE;
}

short url_iconv (server * srv, plugin_config p, iconv_s * ic, char * path) {
	char * src = path;
#if __GLIBC_MINOR__ < 2
	const
#endif
	char * to;
	size_t flen, tlen;
	short ic_r;

	ic->len = ic->tlen = ic->flen = ic->ret = 0;

	if ( p.debug ) {
		log_error_write (srv, __FILE__, __LINE__, "s",
				"check_url_iconv: iconv convert start ----------------------");
	}

	ic->alloc = 0;
	ic->clloc = 0;

	ic->cd = iconv_open (p.server_encoding->ptr, p.client_encoding->ptr);

	if ( p.debug ) {
		log_error_write (srv, __FILE__, __LINE__, "ssss",
				"mod_url configuration: Server Encoding",
			   	p.server_encoding->ptr,
				"Client Encoding",
				p.client_encoding->ptr
		);
	}

	if ( ic->cd == (iconv_t) (-1) ) {
		ic->ret = -1;
		log_error_write (srv, __FILE__, __LINE__, "ssss",
				"Incomplete configuration: Server Encoding",
				p.server_encoding->ptr,
				"Client Encoding",
				p.client_encoding->ptr
		);

		if ( p.debug ) {
			log_error_write (srv, __FILE__, __LINE__, "s",
					"check_url_iconv: iconv convert end   ----------------------");
		}

		return URL_ICONV_FALSE;
	}
	ic->clloc++;

	flen = ic->len = strlen (src);
	tlen = flen * 4 + 1; /* MB_CUR_MAX ~ 4 */

	if ( (ic->uri = (char *) malloc (sizeof (char) * tlen)) == NULL ) {
		ic->ret = -1;
		url_mem_error (srv, "ic->uri");	

		if ( p.debug ) {
			log_error_write (srv, __FILE__, __LINE__, "s",
					"check_url_iconv: iconv convert end   ----------------------");
		}

		return URL_ICONV_FALSE;
	}
	memset (ic->uri, 0, tlen);

	ic->alloc = 1;
	to = ic->uri;

	ic->ret = iconv (ic->cd, &src, &flen, &to, &tlen);

	tlen = strlen (ic->uri);
	ic->tlen = tlen;
	ic->flen = flen;

	/*
	 * Converted URI information loggin
	 */
	if ( p.debug ) {
		url_log_error_hex_write (srv, "  S_URI => ", path);
		url_log_error_hex_write (srv, "  URI   => ", ic->uri);
		log_error_write (srv, __FILE__, __LINE__, "sd", "  SLEN  =>", ic->len);
		log_error_write (srv, __FILE__, __LINE__, "sd", "  LEN   =>", ic->tlen);
		log_error_write (srv, __FILE__, __LINE__, "sd", "  CODE  =>", ic->ret);
		log_error_write (srv, __FILE__, __LINE__, "s",
				"check_url_iconv: iconv convert end   ----------------------");
	}

	ic_r = url_iconv_result (ic);

	/* converting failed */
	if ( ic_r == URL_ICONV_FALSE )
		return ic_r;

	if ( ! strcmp (path, ic->uri) )
		return URL_ICONV_FALSE;

	return URL_ICONV_TRUE;
}

void check_url (server * srv, connection * c, plugin_data * p) {
	plugin_config s = p->conf;
	iconv_s * ic;
	char * new_uri;

	if ( s.debug ) {
		url_log_error_hex_write (srv, "URI   : ", c->uri.path->ptr);
		url_log_error_hex_write (srv, "PATH  : ", c->physical.path->ptr);
		url_log_error_hex_write (srv, "RPATH : ", c->physical.rel_path->ptr);
	}

	/* if physical path is exists, skip */
	if ( url_file_exists (c->physical.path->ptr) == URL_TRUE )
		return;

	/*
	 * Convert URI
	 */

	if ( s.debug )
		log_error_write (srv, __FILE__, __LINE__, "s", "++ URI Convert");

	if ( (ic = (iconv_s *) malloc (sizeof (iconv_s) + 1)) == NULL ) {
		url_mem_error (srv, "iconv_s structure");	
		return;
	}

	/* Failed iconv */
	if ( url_iconv (srv, s, ic, c->uri.path->ptr) == URL_ICONV_FALSE ) {
		url_iconv_free (ic, 0);
		return;
	}

	if ( (new_uri = (char *) malloc (sizeof (char) * (ic->tlen + 1))) == NULL ) {
		url_mem_error (srv, "new_uri");	
		url_iconv_free (ic, 0);
		return;
	}

	strcpy (new_uri, ic->uri);
	url_iconv_free (ic, 1);

	/*
	 * Convert Physical path
	 */

	if ( s.debug )
		log_error_write (srv, __FILE__, __LINE__, "s", "++ Physical path Convert");

	/* Failed iconv */
	if ( url_iconv (srv, s, ic, c->physical.path->ptr) == URL_ICONV_FALSE ) {
		url_iconv_free (ic, 0);
		free (new_uri);
		return;
	}

	/*
	 * Physical converted path check on file system
	 */
	if ( url_file_exists (ic->uri) == URL_FALSE ) {
		/* flie not found */
		log_error_write (srv, __FILE__, __LINE__, "ss", "  Not Found =>", ic->uri);
		url_iconv_free (ic, 0);
		free (new_uri);
		return;
	}

	buffer_reset (c->uri.path);
	buffer_copy_string (c->uri.path, new_uri);

	buffer_reset (c->physical.rel_path);
	buffer_copy_string (c->physical.rel_path, new_uri);
	free (new_uri);

	buffer_reset (c->physical.path);
	buffer_copy_string (c->physical.path, ic->uri);

	url_iconv_free (ic, 0);

	if ( s.debug ) {
		url_log_error_hex_write (srv, "URI   : ", c->uri.path->ptr);
		url_log_error_hex_write (srv, "PATH  : ", c->physical.path->ptr);
		url_log_error_hex_write (srv, "RPATH : ", c->physical.rel_path->ptr);
	}
}

void url_log_error_hex_write (server * srv, char * src, char * value) {
	buffer * r;

	r = buffer_init ();
	buffer_copy_string (r, src);
	buffer_append_string_encoded (r, value, strlen (value), ENCODING_REL_URI);

	log_error_write (srv, __FILE__, __LINE__, "s", r->ptr);

	buffer_free (r);
}

short url_file_exists (char * path) {
	struct stat s;

	if ( stat (path, &s) < 0 )
		return URL_FALSE;

	return URL_TRUE;
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
