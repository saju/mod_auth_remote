/***
 *  SSL routines for Mod_Auth_Remote
 * 
 *  saju.pillai@gmail.com
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <apr.h>
#include <apr_time.h>
#ifdef APR_RANDOM
#include <apr_random.h>
#endif

#include "auth_remote.h"

#define ZZZ  (200 * 1000)

typedef struct {
  apr_pool_t *pool;
  apr_socket_t *sock;
  SSL *ssl;
  BIO *bio[2];
  char *err;
  apr_status_t ecode;
} ctx_ssl;


int apr_bio_write(BIO *b, const char *in, int len)
{
  apr_size_t ilen = len;
  apr_status_t rv;
  ctx_ssl *ctx = b->ptr;

  rv = apr_socket_send(ctx->sock, in, &ilen);
  if (rv != APR_SUCCESS) {
    ctx->err = "socket send failed";
    ctx->ecode = rv;
    return -1;
  }
  return ilen;
}

int apr_bio_read(BIO *b, char *out, int len)
{
  apr_size_t ilen = len;
  apr_status_t rv;
  ctx_ssl *ctx = b->ptr;

  rv = apr_socket_recv(ctx->sock, out, &ilen);
  if (rv != APR_SUCCESS) {
    ctx->err = "socket recv failed";
    ctx->ecode = rv;
    return -1;
  }
  return ilen;
}

long apr_bio_ctrl(BIO *b,int cmd, long num, void *ptr)
{
  switch (cmd) {
  case BIO_CTRL_FLUSH:
    return 1;
  default:
    return 0;
  }
}

int apr_bio_create(BIO *b)
{
  b->init = 1;
  b->num = -1;
  b->shutdown = 1;
  b->ptr = NULL;
  return 1;
}

static BIO_METHOD apr_bio = {
  BIO_TYPE_SOCKET,
  "APR socket read/write",
  apr_bio_write,
  apr_bio_read,
  NULL,
  NULL,
  apr_bio_ctrl,
  apr_bio_create,
  NULL,
};

char *error_ssl(void *ctx)
{
  return ((ctx_ssl *)ctx)->err;
}

apr_status_t close_ssl(void *actx) 
{
  ctx_ssl *ctx = actx;

  if (!SSL_shutdown(ctx->ssl))
    SSL_shutdown(ctx->ssl);

  apr_socket_close(ctx->sock);
  return APR_SUCCESS;
}

apr_status_t read_ssl(char *buf, apr_size_t *len, void *actx)
{
  int r;
  ctx_ssl *ctx = actx;

  r = SSL_read(ctx->ssl, buf, *len);
  if (r <= 0) {
    ctx->err = ERR_error_string(ERR_peek_last_error(), NULL);
    return ctx->ecode != APR_SUCCESS ? ctx->ecode : APR_EGENERAL;
  }
  *len = r;
  return APR_SUCCESS;
}

apr_status_t write_ssl(const char *buf, apr_size_t *len, void *actx)
{
  int r;
  ctx_ssl *ctx = actx;

  r = SSL_write(ctx->ssl, buf, *len);
  if (r <= 0) {
    ctx->err = ERR_error_string(ERR_peek_last_error(), NULL);
    return ctx->ecode != APR_SUCCESS ? ctx->ecode : APR_EGENERAL;
  }
  *len = r;
  return APR_SUCCESS;
}

apr_status_t connect_ssl(const char *remote, apr_port_t port, void *actx)
{
  int ret;
  apr_status_t rv;
  apr_sockaddr_t *addr;
  ctx_ssl *ctx = actx;

  rv = apr_sockaddr_info_get(&addr, remote, APR_INET, port, 0, ctx->pool);
  if (rv != APR_SUCCESS) {
    ctx->err = "failed to resolve remote hostname";
    return rv;
  }
  rv = apr_socket_connect(ctx->sock, addr);
  if (rv != APR_SUCCESS) {
    ctx->err = "connect() error";
    return rv;
  }
  SSL_set_bio(ctx->ssl, ctx->bio[0], ctx->bio[1]);
  ret = SSL_connect(ctx->ssl);
  if (ret != 1)
    {
      switch (ret)
        {
        case SSL_ERROR_SYSCALL:
          /* see if we had timed out */
          if (ctx->ecode == APR_TIMEUP) 
            ctx->err = "i/o timed out";
          return ctx->ecode;
        default:
          ctx->err = ERR_error_string(ERR_peek_last_error(), NULL);
          return APR_EGENERAL;
        }
    }
  return APR_SUCCESS;
}
 
apr_status_t create_ssl(apr_pool_t *p, void *ssl_ctx, void **ctx)
{
  apr_socket_t *fd;
  apr_status_t rv;
  BIO *rbio, *wbio;
  ctx_ssl *c = apr_palloc(p, sizeof(*c));
 
  rv = apr_socket_create(&fd, APR_INET, SOCK_STREAM, APR_PROTO_TCP, p);
  if (rv != APR_SUCCESS) {
    c->err = "cannot create socket";
    return rv;
  }
  rv = apr_socket_timeout_set(fd, DEFAULT_TIMEOUT);
  if (rv != APR_SUCCESS) {
    c->err = "failed to set timeout on socket";
    return rv;
  }

  c->ssl  = SSL_new((SSL_CTX *)ssl_ctx);
  rbio = BIO_new(&apr_bio);
  wbio = BIO_new(&apr_bio);
  rbio->ptr = c;
  wbio->ptr = c;
  c->bio[0] = rbio;
  c->bio[1] = wbio;
  c->pool = p;
  c->sock = fd;
  c->ecode = APR_SUCCESS;
  *ctx = c;

  return APR_SUCCESS;
}   


static io_abs ssl_io_abs = {
  create_ssl,
  connect_ssl,
  read_ssl,
  write_ssl,
  close_ssl,
  error_ssl,
};

io_abs *auth_remote_ssl_io()
{
  return &ssl_io_abs;
}

int seed_prng()
{
  unsigned char randomness[256];
  apr_time_t now;
  int i;

#ifdef APR_RANDOM
  /*
    XXX: this could take terribly too long if apr random uses truerand lib 
     or even /dev/random on linux. 
  */
  apr_generate_random_bytes(randomness, 256);
#else
  /*
    use the current timestamp to seed the C library's PRNG 
    then ask it for 256 bytes of randomness :P
  */
  now = apr_time_as_msec(apr_time_now());

  srandom(now);
  for (i = 0; i < 256 / sizeof(unsigned int); i++) {
    unsigned int r = random();
    memcpy(randomness + i*sizeof(unsigned int), (void *)&r, sizeof(unsigned int));
  }
#endif
  
  RAND_seed(randomness, 256);
  return RAND_status();
}

apr_status_t auth_remote_ssl_init(char **err)
{
  CRYPTO_malloc_init();
  ERR_load_crypto_strings();
  SSL_load_error_strings();
  SSL_library_init();
#if HAVE_ENGINE_LOAD_BUILTIN_ENGINES
  ENGINE_load_builtin_engines();
#endif
  OpenSSL_add_all_algorithms();
#if OPENSSL_VERSION_NUMBER >= 0x00907001
  OPENSSL_load_builtin_modules();
#endif

  /* 
     try seeding openssl prng till it is happy. the delay of ZZZms helps
     increase entropy
   */
  while (!seed_prng())
    apr_sleep(apr_time_from_sec(ZZZ));

  return APR_SUCCESS;
}
  
apr_status_t auth_remote_ssl_create_ctx(void **ctx, char **err)
{
  SSL_CTX *sctx = SSL_CTX_new(SSLv23_client_method());
  if (!sctx) {
    *err = ERR_error_string(ERR_peek_last_error(), NULL);
    return APR_EGENERAL;
  }
  *ctx = sctx;
  return APR_SUCCESS;
}


