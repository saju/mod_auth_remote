/*
 * mod_auth_remote - Remote authentication module for apache httpd 2.2
 *
 * saju.pillai@gmail.com
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */
#include <apr_strings.h>
#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <mod_auth.h>

#define NOT_CONFIGURED -42
#define DEFAULT_TIMEOUT 5000000

typedef struct {
  int remote_port;
  char *remote_server;
  char *remote_path;
} auth_remote_config_rec;


module AP_MODULE_DECLARE_DATA auth_remote_module;

static void *create_auth_remote_dir_config(apr_pool_t *p, char *d) 
{
  auth_remote_config_rec *conf = apr_palloc(p, sizeof(*conf));
  conf->remote_port = NOT_CONFIGURED;
  conf->remote_server = NULL;
  conf->remote_path = NULL;
  return conf;
}

static const command_rec auth_remote_cmds[] = 
  {
    AP_INIT_TAKE1("AuthRemotePort", ap_set_int_slot, 
		  (void *)APR_OFFSETOF(auth_remote_config_rec, remote_port),
		  OR_AUTHCFG, "remote port to authenticate against"),
    AP_INIT_TAKE1("AuthRemoteServer", ap_set_string_slot, 
		  (void *)APR_OFFSETOF(auth_remote_config_rec, remote_server),
		  OR_AUTHCFG, "remote server to authenticate against"),
    AP_INIT_TAKE1("AuthRemoteURL", ap_set_string_slot,
		  (void *)APR_OFFSETOF(auth_remote_config_rec, remote_path),
		  OR_AUTHCFG, "remote server path to authenticate against"),
    {NULL}
  };

static authn_status do_remote_auth(request_rec *r, const char *user, const char *passwd)
{
  int rz;
  char *remote, *user_pass, *b64_user_pass, *req, *rbuf;
  apr_socket_t *rsock;
  apr_sockaddr_t *addr;
  apr_status_t rv;
  auth_remote_config_rec *conf = ap_get_module_config(r->per_dir_config, &auth_remote_module);
  
  /* we were not configured */
  if (conf->remote_port == NOT_CONFIGURED) {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, "remote_auth was not configured for uri %s", r->unparsed_uri);
    return AUTH_USER_NOT_FOUND;
  }

  rv = apr_socket_create(&rsock, APR_INET, SOCK_STREAM, APR_PROTO_TCP, r->pool);
  if (rv != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "failed to create socket");
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  rv = apr_socket_timeout_set(rsock, DEFAULT_TIMEOUT);
  if (rv != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "failed to set timeout on socket");
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  rv = apr_sockaddr_info_get(&addr, conf->remote_server, APR_INET, conf->remote_port, 0, r->pool);
  if (rv != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "failed to setup sockaddr for %s:%d", conf->remote_server, conf->remote_port);
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  
  /* the base64 encoded Authorization header */
  user_pass = apr_pstrcat(r->pool, user, ":", passwd, NULL);
  b64_user_pass = apr_palloc(r->pool, apr_base64_encode_len(strlen(user_pass)) + 1);
  apr_base64_encode(b64_user_pass, user_pass, strlen(user_pass));

  /* the http request for the remote end */
  req = apr_psprintf(r->pool, "HEAD %s HTTP/1.0%sAuthorization: Basic %s%s%s", conf->remote_path, CRLF, b64_user_pass, CRLF, CRLF);
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, "remote request is %s", req);

  /* send the request to the remote server */
  rv = apr_socket_connect(rsock, addr);
  if (rv != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "failed to connect to remote server %s:%d", conf->remote_server, conf->remote_port);
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  rz = strlen(req);
  rv = apr_socket_send(rsock, (const char *)req, (apr_size_t *)&rz);
  if (rv != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "write() to remote server failed");
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  /* read the response from the remote end, 20 bytes should be enough parse the remote server's intent */
  rbuf = apr_palloc(r->pool, rz);
  rz = 20;
  rv = apr_socket_recv(rsock, rbuf, (apr_size_t *)&rz);
  apr_socket_close(rsock);
  if (rv != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "recv() from remote server failed");
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  if (rz < 13) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, r, "non HTTP reply from remote server");
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  if (toupper(rbuf[0]) == 'H' && toupper(rbuf[1]) == 'T' && toupper(rbuf[2]) == 'T' && toupper(rbuf[3]) == 'P' 
      && toupper(rbuf[8]) == ' ' && toupper(rbuf[9]) == '2') {
    return AUTH_GRANTED;
  }
  return AUTH_DENIED;
}

static const authn_provider auth_remote_provider =
  {
    &do_remote_auth,
    NULL
  };

static void register_hooks(apr_pool_t *p)
{
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

