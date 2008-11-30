#include "auth_remote.h"

typedef struct {
  apr_pool_t *pool;
  apr_socket_t *sock;
  char *err;
} ctx_plain;

char *error_plain(void *ctx)
{
  return ((ctx_plain *)ctx)->err;
}

apr_status_t create_plain(apr_pool_t *p, void *ignored, void **ctx) 
{
  apr_socket_t *fd;
  apr_status_t rv;
  ctx_plain *c = apr_palloc(p, sizeof(*c));

  rv = apr_socket_create(&fd, APR_INET, SOCK_STREAM, APR_PROTO_TCP, p);
  if (rv != APR_SUCCESS) {
    c->err = "cannot create socket";
    return rv;
  }
  c->pool = p;
  c->sock = fd;
  *ctx = c;
  return APR_SUCCESS;
}

apr_status_t connect_plain(const char *name, apr_port_t port, void *actx)
{
  apr_status_t rv;
  apr_sockaddr_t *addr;
  ctx_plain *ctx = actx;

  rv = apr_sockaddr_info_get(&addr, name, APR_INET, port, 0, ctx->pool);
  if (rv != APR_SUCCESS) {
    ctx->err = "getsockaddr failed";
    return rv;
  }

  rv = apr_socket_timeout_set(ctx->sock, DEFAULT_TIMEOUT);
  if (rv != APR_SUCCESS) {
    ctx->err = "failed to set timeout on socket";
    return rv;
  }

  rv = apr_socket_connect(ctx->sock, addr);
  if (rv != APR_SUCCESS) {
    ctx->err = apr_psprintf(ctx->pool, "failed to connect to remote server %s:%d", name, port);
    return rv;
  }

  return APR_SUCCESS;
}

apr_status_t write_plain(const char *buf, apr_size_t *len, void *actx)
{
  apr_status_t rv;
  ctx_plain *ctx = actx;

  rv = apr_socket_send(ctx->sock, buf, len);
  if (rv != APR_SUCCESS) {
    ctx->err = "write failed";
    return rv;
  }
  return APR_SUCCESS;
}

apr_status_t read_plain(char *buf, apr_size_t *len, void *actx)
{
  apr_status_t rv;
  ctx_plain *ctx = (ctx_plain *)actx;
  
  rv = apr_socket_recv(ctx->sock, buf, len);
  if (rv != APR_SUCCESS) {
    ctx->err = "read failed";
    return rv;
  }
  return APR_SUCCESS;
}

apr_status_t close_plain(void *actx)
{
  ctx_plain *ctx = actx;
  apr_socket_close(ctx->sock);
  return APR_SUCCESS;
}

static io_abs plain = {
  create_plain,
  connect_plain,
  read_plain,
  write_plain,
  close_plain,
  error_plain,
};

io_abs *auth_remote_plain_io()
{
  return &plain;
}
