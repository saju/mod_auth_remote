#include <apr.h>

apr_status_t auth_remote_ssl_init();
apr_status_t auth_remote_ssl_create_ctx(void **ctx, char **msg);
