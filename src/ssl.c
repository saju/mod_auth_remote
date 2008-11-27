/***
 *  SSL routines for Mod_Auth_Remote
 * 
 *  saju.pillai@gmail.com
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <apr.h>
#include <apr_time.h>
#ifdef APR_RANDOM
#include <apr_random.h>
#endif

#define ZZZ  (200 * 1000)

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
  unsigned char randomess[256];

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


