#include <apr_strings.h>
#include <apr_uri.h>
#include <apr_network_io.h>

#define TWENTY_MINS         1200
#define DEFAULT_TIMEOUT     5000000

typedef struct {
  apr_status_t (*create)(apr_pool_t *, void *, void **);
  apr_status_t (*connect)(const char *, apr_port_t, void *);
  apr_status_t (*read)(char *, apr_size_t *, void *);
  apr_status_t (*write)(const char *, apr_size_t *, void *);
  apr_status_t (*close)(void *);
  char *(*error)(void *);
} io_abs;

io_abs *auth_remote_plain_io();
io_abs *auth_remote_ssl_io();

apr_status_t auth_remote_ssl_init();
apr_status_t auth_remote_ssl_create_ctx(void **ctx, char **msg);
