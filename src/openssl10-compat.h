#ifndef OPENSSL10_COMPAT_H
#define OPENSSL10_COMPAT_H

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)

#define BIO_set_init(b, v) ((b)->init = (v))
#define BIO_set_data(b, v) ((b)->ptr = (v))
#define BIO_get_data(b) ((b)->ptr)
#define BIO_get_new_index() BIO_TYPE_MEM
#define BIO_meth_set_write(biom, fn) ((biom)->bwrite = (fn))
#define BIO_meth_set_read(biom, fn) ((biom)->bread = (fn))
#define BIO_meth_set_puts(biom, fn) ((biom)->bputs = (fn))
#define BIO_meth_set_gets(biom, fn) ((biom)->bgets = (fn))
#define BIO_meth_set_ctrl(biom, fn) ((biom)->ctrl = (fn))
#define BIO_meth_set_create(biom, fn) ((biom)->create = (fn))
#define BIO_meth_set_destroy(biom, fn) ((biom)->destroy = (fn))
#define BIO_meth_set_callback_ctrl(biom, fn) ((biom)->callback_ctrl = (fn))
static inline BIO_METHOD *BIO_meth_new(int type, const char *name)
{
  BIO_METHOD *biom = calloc(1, sizeof(BIO_METHOD));

  if (biom != NULL)
    {
      biom->name = strdup(name);
      biom->type = type;
     }
  return biom;
}

#define TLS_ST_CR_SRVR_HELLO SSL3_ST_CR_SRVR_HELLO_A
#define SSL_get_server_random(ssl, out, outlen) memcpy(out, ssl->s3->server_random, outlen)
#define TLS_client_method() SSLv23_client_method()
#define X509_STORE_get0_param(cert_store) ((cert_store)->param)

#endif
#endif
