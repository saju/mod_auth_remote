/*
 * mod_auth_remote - Remote authentication module for apache httpd 2.2
 *
 * saju.pillai@gmail.com
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */
#include <apr_strings.h>
#include <apr_uri.h>
#include <apr_base64.h>
#include <apr_md5.h>
#include <apr_time.h>
#include <apr_lib.h>
#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <ap_provider.h>
#include <mod_auth.h>

#include "auth_remote.h"

#define NOT_CONFIGURED      -42

unsigned char auth_remote_salt[8];
short want_salt = 0;
short init_ssl = 0;
void *ssl_ctx = NULL;

typedef struct {
  int remote_port;                 /* the remote port of the authenticating server */
  int cookie_life;                 /* the duration for which the cookie should live */
  const char *remote_server;       /* hostname/ip for the remote server */
  const char *remote_path;         /* the protected resource on the remote server */
  const char *cookie_name;         /* the name of the cookie */
  const char *cookie_path;         /* the cookie path */
  io_abs *io;
  void *ctx;
} auth_remote_config_rec;

module AP_MODULE_DECLARE_DATA auth_remote_module;

static void *create_auth_remote_dir_config(apr_pool_t *p, char *d) 
{
  auth_remote_config_rec *conf = apr_palloc(p, sizeof(*conf));
  conf->remote_port   = NOT_CONFIGURED;
  conf->cookie_life   = NOT_CONFIGURED;
  conf->remote_server = NULL;
  conf->remote_path   = NULL;
  conf->cookie_name   = NULL;
  conf->cookie_path   = NULL;
  conf->io            = NULL;
  want_salt = 1;
  return conf;
}


static const char *auth_remote_parse_loc(cmd_parms *cmd, void *config, const char *arg)
{
  apr_uri_t uri;
  auth_remote_config_rec *conf = config;
  apr_status_t rv;
  
  rv = apr_uri_parse(cmd->pool, arg, &uri);
  if (rv != APR_SUCCESS )
    return "AuthRemoteURL should be an URL or path to the authenticating server";
  
  if (!uri.scheme) {
    conf->io = auth_remote_plain_io();
    conf->remote_path = arg;
  } 
  else {    
    if (!strncmp(uri.scheme, "https", 5)) {
#ifdef AUTH_REMOTE_NO_SSL
      return "mod_auth_remote is not built with SSL support and cannot process https urls";
#endif
      conf->io = auth_remote_ssl_io();
    } else if (!strncmp(uri.scheme, "http", 4)) {
      conf->io = auth_remote_plain_io();
    } else {
      return "AuthRemoteURL only accepts http and https urls";
    }
    conf->remote_server = uri.hostname;
    conf->remote_port = uri.port ? uri.port : 80;
    if (!uri.path)
      conf->remote_path = "/";
    else {
      conf->remote_path = uri.path;
      if (uri.query) 
        conf->remote_path = apr_pstrcat(cmd->pool, conf->remote_path, "?", uri.query, NULL);
      if (uri.fragment)
        conf->remote_path = apr_pstrcat(cmd->pool, conf->remote_path, "#", uri.fragment, NULL);
    }
  }
  return NULL;
}

static const char *auth_remote_config_cookie(cmd_parms *cmd, void *config, const char *arg1, 
                                             const char *arg2, const char *arg3)
{
#ifdef AUTH_REMOTE_NO_SALT
  return "AuthRemoteCookie can only be used if mod_auth_remote is compiled with random() support";
#else  
  auth_remote_config_rec *conf = config;
  conf->cookie_name = arg1;
  if (arg2)
    conf->cookie_path = arg2;
  else 
    conf->cookie_path = "/";
  if (arg3) 
    conf->cookie_life = atoi(arg3);
  else
    conf->cookie_life = TWENTY_MINS;
  
  return NULL;
#endif
}

static const command_rec auth_remote_cmds[] = 
  {
    /* for backward compatibility */
    AP_INIT_TAKE1("AuthRemotePort", ap_set_int_slot, 
                  (void *)APR_OFFSETOF(auth_remote_config_rec, remote_port),
                  OR_AUTHCFG, "remote port to authenticate against"),
    /* for backward compatibility */
    AP_INIT_TAKE1("AuthRemoteServer", ap_set_string_slot, 
                  (void *)APR_OFFSETOF(auth_remote_config_rec, remote_server),
                  OR_AUTHCFG, "remote server to authenticate against"),
    /* accepts a full url, superceedes AuthRemotePort and AuthRemoteServer */
    AP_INIT_TAKE1("AuthRemoteURL", auth_remote_parse_loc, NULL, OR_AUTHCFG,
                  "remote server path or full url to authenticate against"),
    AP_INIT_TAKE123("AuthRemoteCookie", auth_remote_config_cookie, NULL, OR_AUTHCFG,
                    "name of the cookie, the cookie path and the duration it is valid for"),
    {NULL}
  };


static char *auth_remote_signature(apr_pool_t *p, const char *user, apr_int64_t curr, 
                                    unsigned char *salt)
{
  int blen = apr_base64_encode_len(APR_MD5_DIGESTSIZE);
  unsigned char md5[APR_MD5_DIGESTSIZE];
  char *md5_b64 = apr_palloc(p, blen);
  char *s = apr_psprintf(p, "%s:%lld:%s", user, curr, salt);
  
  apr_md5(md5, s, strlen(s));
  apr_base64_encode_binary(md5_b64, md5, APR_MD5_DIGESTSIZE);
  return md5_b64;
}

static short auth_remote_validate_cookie(request_rec *r, const char *exp_user, char *cookie, 
                                         auth_remote_config_rec *conf)
{
  /*
    our cookie looks like this ...
    NAME=USER^TSTAMP^MD5(USER:TSTAMP:salt)
  */
  apr_time_t new_time = apr_time_sec(apr_time_now());
  char *payload = apr_pstrdup(r->pool, cookie + strlen(conf->cookie_name) + 1);
  char *last, *user, *tstamp, *sig, *nsig;
  apr_int64_t old_time;

  user = apr_strtok(payload, "^", &last);
  if (!user) {
    ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, 
                  "%s - tampering(?). \"user\" missing from cookie", exp_user);
    return 0;
  } else if (strncmp(exp_user, user, strlen(exp_user))) {
    ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, 
                  "%s - tampering(?). \"user\" (%s) mismatch in cookie", exp_user, user);
    return 0;
  }
  
  tstamp = apr_strtok(NULL, "^", &last);
  if (!tstamp) {
    ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, 
                  "%s - tampering(?). \"tstamp\" missing from cookie", exp_user);
    return 0;
  }
  old_time = apr_atoi64(tstamp);
  if ((new_time - old_time) > conf->cookie_life) {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, "cookie expired for %s", exp_user);
    return 0;
  }
  
  sig = apr_strtok(NULL, "^", &last);
  if (!sig) {
    ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, 
                  "%s - tampering(?). \"signature\" missing from cookie", exp_user);
    return 0;
  }
  nsig = auth_remote_signature(r->pool, user, old_time, auth_remote_salt);
  if (strncmp(sig, nsig, strlen(nsig))) {
    ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, 
                  "%s - tampering(?). \"signature\" mismatch in cookie", exp_user);
    return 0;
  }
  return 1;
}

static void auth_remote_set_cookie(request_rec *r, const char *user, auth_remote_config_rec *conf)
{
  apr_time_t now = apr_time_sec(apr_time_now());
  char *cookie = apr_psprintf(r->pool, "%s=%s^%lld^%s;path=%s", conf->cookie_name, user, now, 
                              auth_remote_signature(r->pool, user, now, auth_remote_salt), 
                              conf->cookie_path);
  apr_table_addn(r->err_headers_out, "Set-Cookie", cookie);
}

static authn_status do_remote_auth(request_rec *r, const char *user, const char *passwd, 
                                   auth_remote_config_rec *conf)
{
  int rz;
  char *user_pass, *b64_user_pass, *req;
  unsigned char *rbuf;
  apr_status_t rv;
  void *ctx;
  
  /* we were not configured */
  if (conf->remote_port == NOT_CONFIGURED) {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, "remote_auth was not configured for uri %s", 
                  r->unparsed_uri);
    return AUTH_USER_NOT_FOUND;
  }
 
  rv = conf->io->create(r->pool, ssl_ctx, &ctx);
  if (rv != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, conf->io->error(ctx));
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  
  /* the base64 encoded Authorization header */
  user_pass = apr_pstrcat(r->pool, user, ":", passwd, NULL);
  b64_user_pass = apr_palloc(r->pool, apr_base64_encode_len(strlen(user_pass)) + 1);
  apr_base64_encode(b64_user_pass, user_pass, strlen(user_pass));

  /* the http request for the remote end */
  req = apr_psprintf(r->pool, "HEAD %s HTTP/1.0%sAuthorization: Basic %s%s%s", conf->remote_path, 
                     CRLF, b64_user_pass, CRLF, CRLF);

  /* send the request to the remote server */
  rv = conf->io->connect(conf->remote_server, conf->remote_port, ctx);
  if (rv != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, conf->io->error(ctx));
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  rz = strlen(req);
  rv = conf->io->write((const char *)req, (apr_size_t *)&rz, ctx);
  if (rv != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, conf->io->error(ctx));
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  /* read the response from the remote end, 20 bytes should be enough parse the remote server's intent */
  rbuf = apr_palloc(r->pool, rz);
  rz = 20;
  rv = conf->io->read((char *)rbuf, (apr_size_t *)&rz, ctx);
  conf->io->close(ctx);
  if (rv != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, conf->io->error(ctx));
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  if (rz < 13) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "non HTTP reply from remote server");
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  if (apr_toupper(rbuf[0]) == 'H' && apr_toupper(rbuf[1]) == 'T' && apr_toupper(rbuf[2]) == 'T' 
      && apr_toupper(rbuf[3]) == 'P' && rbuf[8] == ' ' && rbuf[9] == '2') {
    return AUTH_GRANTED;
  }
  return AUTH_DENIED;
}

static authn_status check_authn(request_rec *r, const char *user, const char *passwd)
{
  const char *cookies;
  authn_status remote_status = AUTH_DENIED;
  auth_remote_config_rec *conf = ap_get_module_config(r->per_dir_config, &auth_remote_module);

  /* no auth cookie was configured, authn against remote server */
  if (conf->cookie_life == NOT_CONFIGURED) {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "cookie is not configured");
    return do_remote_auth(r, user, passwd, conf);
  }

  /* cookie is configured, check if a cookie came in */
  cookies = apr_table_get(r->headers_in, "Cookie");
  if (cookies) {
    char *our_cookie = ap_strstr((char *)cookies, conf->cookie_name);
    if (our_cookie && auth_remote_validate_cookie(r, user, our_cookie, conf)) {
      return AUTH_GRANTED;
    }
  }
  
  /** If our cookie 
   *    -> didn't come in -or-
   *    -> it came in but has expired -or-
   *    -> we detect user tampering;
   *  in all these cases always force a remote authentication and reset the cookie if needed 
   **/
  remote_status = do_remote_auth(r, user, passwd, conf);
  if (remote_status == AUTH_GRANTED) {
    auth_remote_set_cookie(r, user, conf);
  }
  return remote_status;
}

static int auth_remote_setup_secret(server_rec *s) 
{
  apr_status_t rv;

  rv = apr_generate_random_bytes(auth_remote_salt, sizeof(auth_remote_salt));
  if (rv != APR_SUCCESS) {
    ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "auth_remote: could not generate random salt");
    return !OK;
  }
  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "secret salt generated");
  return OK;
}

static int auth_remote_setup_ssl(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
  /* 
   * Init OpenSSL only if mod_ssl was not loaded. We should always let mod_ssl init openssl.
   * OpenSSL library cannot be init'd twice.
   */
  int i;
  apr_status_t rv;
  char *err;


  if (!ap_find_linked_module("mod_ssl.c")) {
    rv = auth_remote_ssl_init(s, &err);
    if (rv != APR_SUCCESS) {
      ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, err);
      return !OK;
    }
  }
  
  /* 
   * XXX: setup ssl ctx for each per dir config record at some point we 
   * should accept configurable ssl options that can be set per dir
   */
  rv = auth_remote_ssl_create_ctx(&ssl_ctx, &err);
  if (rv != APR_SUCCESS) {
    ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, err);
    return !OK;
  }
  return OK;
}
  
static int auth_remote_init_module(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
  void *was_here;
  apr_status_t rv;

  apr_pool_userdata_get(&was_here, "auth_remote_key", s->process->pool);
  if (!was_here) {
    apr_pool_userdata_set((void *)1, "auth_remote_key", apr_pool_cleanup_null, s->process->pool);
    return OK;
  }
#ifndef AUTH_REMOTE_NO_SALT
#ifndef APR_HAS_RANDOM
#error APR random number support is needed to generate secret salt
#endif
  if (want_salt) {
    rv = auth_remote_setup_secret(s);
    if (rv != OK)
      return rv;
  }
#endif
#ifndef AUTH_REMOTE_NO_SSL
  rv = auth_remote_setup_ssl(p, plog, ptemp, s);
#endif
  return rv;
}

static const authn_provider auth_remote_provider =
  {
    &check_authn,
    NULL
  };

static void register_hooks(apr_pool_t *p)
{
  static const char * const pre_run[] = {"mod_ssl.c", NULL};
  ap_hook_post_config(auth_remote_init_module, pre_run, NULL, APR_HOOK_MIDDLE);
  ap_register_provider(p, AUTHN_PROVIDER_GROUP, "remote", "0", &auth_remote_provider);
}


module AP_MODULE_DECLARE_DATA auth_remote_module = 
  {
    STANDARD20_MODULE_STUFF,
    create_auth_remote_dir_config,
    NULL,
    NULL,
    NULL,
    auth_remote_cmds,
    register_hooks
  };

