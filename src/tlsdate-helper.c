/* Copyright (c) 2012, Jacob Appelbaum.
 * Copyright (c) 2012, The Tor Project, Inc.
 * Copyright (c) 2012, Christian Grothoff. */
/* See LICENSE for licensing information */
/*
                    This file contains the license for tlsdate,
        a free software project to set your system clock securely.

        It also lists the licenses for other components used by tlsdate.

      For more information about tlsdate, see https://github.com/ioerror/tlsdate

             If you got this file as a part of a larger bundle,
        there may be other license terms that you should be aware of.

===============================================================================
tlsdate is distributed under this license:

Copyright (c) 2011-2012, Jacob Appelbaum <jacob@appelbaum.net>
Copyright (c) 2011-2012, The Tor Project, Inc.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

    * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.

    * Neither the names of the copyright owners nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
===============================================================================
If you got tlsdate as a static binary with OpenSSL included, then you should
know:

 "This product includes software developed by the OpenSSL Project for use in
  the OpenSSL Toolkit (http://www.openssl.org/)"

===============================================================================
*/

/**
 * \file tlsdate-helper.c
 * \brief Helper program that does the actual work of setting the system clock.
 **/

/*
 * tlsdate is a tool for setting the system clock by hand or by communication
 * with the network. It does not set the RTC. It is designed to be as secure as
 * TLS (RFC 2246) but of course the security of TLS is often reduced to
 * whichever CA racket you believe is trustworthy. By default, tlsdate trusts
 * your local CA root store - so any of these companies could assist in a MITM
 * attack against you and you'd be screwed.

 * This tool is designed to be run by hand or as a system daemon. It must be
 * run as root or otherwise have the proper caps; it will not be able to set
 * the system time without running as root or another privileged user.
 */

#include "config.h"
#include "src/tlsdate-helper.h"
#include "src/util.h"

#ifndef USE_POLARSSL
#include "src/proxy-bio.h"
#else
#include "src/proxy-polarssl.h"
#endif

#include "src/util.h"
#include "src/compat/clock.h"

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

#ifdef USE_POLARSSL
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/ssl.h"
#else
#include <fcntl.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include "openssl10-compat.h"
#endif

static void
validate_proxy_scheme(const char *scheme)
{
  if (!strcmp(scheme, "http"))
    return;
  if (!strcmp(scheme, "socks4"))
    return;
  if (!strcmp(scheme, "socks5"))
    return;
  die("invalid proxy scheme");
}

static void
validate_proxy_host(const char *host)
{
  const char *kValid = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                       "abcdefghijklmnopqrstuvwxyz"
                       "0123456789"
                       ".-";
  if (strspn(host, kValid) != strlen(host))
    die("invalid char in host");
}

static void
validate_proxy_port(const char *port)
{
  while (*port)
    if (!isdigit((int)(unsigned char)*port++))
      die("invalid char in port");
}

static void
parse_proxy_uri(char *proxy, char **scheme, char **host, char **port)
{
  /* Expecting a URI, so: <scheme> '://' <host> ':' <port> */
  *scheme = proxy;
  proxy = strstr(proxy, "://");
  if (!proxy)
    die("malformed proxy URI");
  *proxy = '\0'; /* terminate scheme string */
  proxy += strlen("://");

  *host = proxy;
  proxy = strchr(proxy, ':');
  if (!proxy)
    die("malformed proxy URI");
  *proxy++ = '\0';

  *port = proxy;

  validate_proxy_scheme(*scheme);
  validate_proxy_host(*host);
  validate_proxy_port(*port);
}

#ifndef USE_POLARSSL
static void
setup_proxy(BIO *ssl)
{
  BIO *bio;
  char *scheme;
  char *proxy_host;
  char *proxy_port;

  if (!proxy)
    return;
  /*
   * grab the proxy's host and port out of the URI we have for it. We want the
   * underlying connect BIO to connect to this, not the target host and port, so
   * we squirrel away the target host and port in the proxy BIO (as the proxy
   * target) and swap out the connect BIO's target host and port so it'll
   * connect to the proxy instead.
   */
  parse_proxy_uri(proxy, &scheme, &proxy_host, &proxy_port);
  bio = BIO_new_proxy();
  BIO_proxy_set_type(bio, scheme);
  BIO_proxy_set_host(bio, host);
  BIO_proxy_set_port(bio, atoi(port));
  host = proxy_host;
  port = proxy_port;
  BIO_push(ssl, bio);
}

static const char *
sockaddr_to_str(void *_sa) {
  static char out[128];
  struct sockaddr_in *sin = _sa;
  return inet_ntop(sin->sin_family, &sin->sin_addr, out, sizeof(out));
}

static const char *
sock_peername(int sock) {
  struct sockaddr_storage sa;
  socklen_t salen = sizeof(sa);

  if (getpeername(sock, (struct sockaddr *)&sa, &salen) < 0) {
    perror("getpeername");
    return "(unknown)";
  }
  return sockaddr_to_str((struct sockaddr *)&sa);
}

static int
parallel_connect(struct addrinfo *ai) {
  struct addrinfo *cai;
  int socks[64], nsocks = 0, connsock = -1, i;

  // connect a socket for each possible address
  for (cai = ai; cai; cai = cai->ai_next) {
    int sock = -1;
    if (nsocks >= sizeof(socks)/sizeof(socks[0])) break;

    socks[nsocks++] = sock = socket(cai->ai_family, SOCK_STREAM, 0);
    if (sock < 0) {
      perror("socket");
      nsocks--;
      continue;
    }

    if (fcntl(sock, F_SETFL, (long)O_NONBLOCK) < 0) {
      perror("fcntl(O_NONBLOCK)");
      close(sock);
      nsocks--;
      continue;
    }

    verb("V: connecting fd#%d to %s", sock, sockaddr_to_str(cai->ai_addr));
    if (!connect(sock, cai->ai_addr, cai->ai_addrlen)) {
      // instant success!
      connsock = sock;
      goto done;
    }
    if (errno != EINPROGRESS) {
      perror("connect");
      close(sock);
      nsocks--;
      continue;
    }
  }

  // wait for the sockets to finish connectin
  while (nsocks > 0) {
    int fd_max = 0, readyfds;
    fd_set wfd;
    struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };

    verb("V: Waiting for %d server IP addresses...", nsocks);

    FD_ZERO(&wfd);
    for (i = 0; i < nsocks; i++) {
      if (socks[i] > fd_max) fd_max = socks[i];
      FD_SET(socks[i], &wfd);
    }

    readyfds = select(fd_max + 1, NULL, &wfd, NULL, &tv);
    if (readyfds < 0) {
      perror("select(connect)");
      break;
    } else if (readyfds == 0) {
      fprintf(stderr, "timed out waiting for TCP connection\n");
      break;
    }

    for (i = 0; i < nsocks; i++) {
      if (FD_ISSET(socks[i], &wfd)) {
        int v = 0;
        socklen_t vlen = sizeof(v);
        if (getsockopt(socks[i], SOL_SOCKET, SO_ERROR, &v, &vlen) < 0) {
          perror("getsockopt(SO_ERROR)");
          close(socks[i]);
          socks[i] = socks[--nsocks];
          break;
        }
        if (v) {
          fprintf(stderr, "connect(fd#%d): %s\n", socks[i], strerror(v));
          close(socks[i]);
          socks[i] = socks[--nsocks];
        } else {
          verb("V: connected fd#%d to %s",
               socks[i], sock_peername(socks[i]));
          connsock = socks[i];
          goto done;
        }
        break;
      }
    }
  }

done:
  if (connsock >= 0 && fcntl(connsock, F_SETFL, 0) < 0) {
    perror("fcntl(!O_NONBLOCK)");
    connsock = -1;
  }
  for (i = 0; i < nsocks; i++) {
    if (socks[i] != connsock) {
      close(socks[i]);
    }
  }
  return connsock;
}

static BIO *
make_ssl_bio(SSL_CTX *ctx, const char *host, const char *port)
{
  BIO *con = NULL;
  BIO *ssl = NULL;
  int err, sock = -1;
  struct addrinfo *ai = NULL;
  struct addrinfo hints = {
    .ai_flags = AI_ADDRCONFIG,
    .ai_family = AF_UNSPEC,
    .ai_socktype = SOCK_STREAM,
  };
  err = getaddrinfo(host, port, &hints, &ai);
  if (err != 0 || !ai) {
    fprintf(stderr, "getaddrinfo(%s): %s\n", host, gai_strerror(err));
    goto error;
  }
  sock = parallel_connect(ai);
  freeaddrinfo(ai);
  if (sock < 0) goto error;

  if (!(con = BIO_new_fd(sock, 1)))
    die("BIO_new_fd failed\n");
  if (!(ssl = BIO_new_ssl(ctx, 1)))
    die("BIO_new_ssl failed");
  setup_proxy(ssl);
  BIO_push(ssl, con);
  return ssl;

error:
  die("connection failed\n");
  return NULL;
}


static int
write_all_to_bio(BIO *bio, const char *string)
{
  int n = (int) strlen(string);
  int r;

  while (n) {
    r = BIO_write(bio, string, n);
    if (r > 0) {
      if (r > n)
        return -1;
      n -= r;
      string += r;
    } else {
      return 0;
    }
  }

  return 1;
}

/* If the string is all nice clean ascii that it's safe to log, return
 * it. Otherwise return a placeholder "This is junk" string. */
static const char *
sanitize_string(const char *s)
{
  const unsigned char *cp;
  for (cp = (const unsigned char *)s; *cp; cp++) {
    if (*cp < 32 || *cp >= 127)
      return "string with invalid characters";
  }
  return s;
}

static int
handle_date_line(const char *dateline, uint32_t *result)
{
  int year,mon,day,hour,min,sec;
  char month[4];
  struct tm tm;
  int i;
  time_t t;
  /* We recognize the three formats in RFC2616, section 3.3.1.  Month
     names are always in English.  The formats are:

      Sun, 06 Nov 1994 08:49:37 GMT  ; RFC 822, updated by RFC 1123
      Sunday, 06-Nov-94 08:49:37 GMT ; RFC 850, obsoleted by RFC 1036
      Sun Nov  6 08:49:37 1994       ; ANSI C's asctime() format

     Note that the first is preferred.
   */

  static const char *MONTHS[] =
    { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec", NULL };

  if (strncmp("\r\nDate: ", dateline, 8))
    return 0;

  dateline += 8;
  if (strlen(dateline) > MAX_DATE_LINE_LEN) {
    verb("V: The date line was impossibly long.");
    return -1;
  }
  verb("V: The alleged date is <%s>", sanitize_string(dateline));

  while (*dateline == ' ')
    ++dateline;
  while (*dateline && *dateline != ' ')
    ++dateline;
  while (*dateline == ' ')
    ++dateline;
  /* We just skipped over the day of the week. Now we have:*/
  if (sscanf(dateline, "%d %3s %d %d:%d:%d",
             &day, month, &year, &hour, &min, &sec) == 6 ||
      sscanf(dateline, "%d-%3s-%d %d:%d:%d",
             &day, month, &year, &hour, &min, &sec) == 6 ||
      sscanf(dateline, "%3s %d %d:%d:%d %d",
             month, &day, &hour, &min, &sec, &year) == 6) {

    /* Two digit dates are defined to be relative to 1900; all other dates
     * are supposed to be represented as four digits. */
    if (year < 100)
      year += 1900;

    verb("V: Parsed the date: %04d-%s-%02d %02d:%02d:%02d",
         year, month, day, hour, min, sec);
  } else {
    verb("V: Couldn't parse date.");
    return -1;
  }

  for (i = 0; ; ++i) {
    if (!MONTHS[i])
      return -2;
    if (!strcmp(month, MONTHS[i])) {
      mon = i;
      break;
    }
  }

  memset(&tm, 0, sizeof(tm));
  tm.tm_year = year - 1900;
  tm.tm_mon = mon;
  tm.tm_mday = day;
  tm.tm_hour = hour;
  tm.tm_min = min;
  tm.tm_sec = sec;

  t = timegm(&tm);
  if (t > 0xffffffff || t < 0)
    return -1;

  *result = (uint32_t) t;

  return 1;
}

static int
read_http_date_from_bio(BIO *bio, uint32_t *result)
{
  int n;
  char buf[MAX_HTTP_HEADERS_SIZE];
  int buf_len=0;
  char *dateline, *endofline;

  while (buf_len < sizeof(buf)-1) {
    n = BIO_read(bio, buf+buf_len, sizeof(buf)-buf_len-1);
    if (n <= 0)
      return 0;
    buf_len += n;
    buf[buf_len] = 0;
    verb_debug ("V: read %d bytes.", n, buf);

    dateline = memmem(buf, buf_len, "\r\nDate: ", 8);
    if (NULL == dateline)
      continue;

    endofline = memmem(dateline+2, buf_len - (dateline-buf+2), "\r\n", 2);
    if (NULL == endofline)
      continue;

    *endofline = 0;
    return handle_date_line(dateline, result);
  }
  return -2;
}

void
openssl_time_callback (const SSL* ssl, int where, int ret)
{
  if (where == SSL_CB_CONNECT_LOOP && SSL_get_state(ssl) == TLS_ST_CR_SRVR_HELLO)
  {
    // XXX TODO: If we want to trust the remote system for time,
    // can we just read that time out of the remote system and if the
    // cert verifies, decide that the time is reasonable?
    // Such a process seems to indicate that a once valid cert would be
    // forever valid - we stopgap that by ensuring it isn't less than
    // the latest compiled_time and isn't above max_reasonable_time...
    // XXX TODO: Solve eternal question about the Chicken and the Egg...
    uint32_t compiled_time = RECENT_COMPILE_DATE;
    uint32_t max_reasonable_time = MAX_REASONABLE_TIME;
    uint32_t server_time;
    verb("V: freezing time for x509 verification");
    SSL_get_server_random(ssl, (unsigned char *)&server_time, sizeof server_time);
    if (compiled_time < ntohl(server_time)
        &&
        ntohl(server_time) < max_reasonable_time)
    {
      verb("V: remote peer provided: %d, preferred over compile time: %d",
            ntohl(server_time), compiled_time);
      verb("V: freezing time with X509_VERIFY_PARAM_set_time");
      X509_VERIFY_PARAM_set_time(X509_STORE_get0_param(SSL_CTX_get_cert_store(SSL_get_SSL_CTX(ssl))),
                                 (time_t) ntohl(server_time) + 86400);
    } else {
      die("V: the remote server is a false ticker! server: %d compile: %d",
           ntohl(server_time), compiled_time);
    }
  }
}

uint32_t
get_certificate_keybits (EVP_PKEY *public_key)
{
  uint32_t key_bits;
  switch (EVP_PKEY_base_id(public_key))
  {
    case EVP_PKEY_RSA:
      verb("V: key type: EVP_PKEY_RSA");
      break;
    case EVP_PKEY_DSA:
      verb("V: key type: EVP_PKEY_DSA");
      break;
    case EVP_PKEY_DH:
      verb("V: key type: EVP_PKEY_DH");
      break;
    case EVP_PKEY_EC:
      verb("V: key type: EVP_PKEY_EC");
      break;
#ifdef EVP_PKEY_ED448
    case EVP_PKEY_ED448:
      verb("V: key type: EVP_PKEY_ED448");
      break;
#endif
#ifdef EVP_PKEY_ED25519
    case EVP_PKEY_ED25519:
      verb("V: key type: EVP_PKEY_ED25519");
      break;
#endif
    // Should we also care about EVP_PKEY_HMAC and EVP_PKEY_CMAC?
    default:
      key_bits = 0;
      die ("unknown public key type");
      break;
  }
  key_bits = EVP_PKEY_bits(public_key);
  verb ("V: keybits: %d", key_bits);
  return key_bits;
}
#endif

#ifndef USE_POLARSSL
uint32_t
check_name (SSL *ssl, const char *hostname)
{
  X509 *cert;
  uint32_t ret;

  if (NULL == (cert = SSL_get_peer_certificate(ssl)))
  {
    die ("Getting certificate failed");
  }

  ret = X509_check_host(cert, hostname, 0, 0, NULL);
  if (ret == 1)
  {
    verb ("V: hostname verification passed");
  } else {
    die ("hostname verification failed for host %s!", host);
  }
  X509_free(cert);
  return ret;
}
#endif

#ifdef USE_POLARSSL
uint32_t
verify_signature (ssl_context *ssl, const char *hostname)
{
  int ssl_verify_result;

  ssl_verify_result = ssl_get_verify_result (ssl);
  if (ssl_verify_result & BADCERT_EXPIRED)
  {
    die ("certificate has expired");
  }
  if (ssl_verify_result & BADCERT_REVOKED)
  {
    die ("certificate has been revoked");
  }
  if (ssl_verify_result & BADCERT_CN_MISMATCH)
  {
    die ("CN and subject AltName mismatch for certificate");
  }
  if (ssl_verify_result & BADCERT_NOT_TRUSTED)
  {
    die ("certificate is self-signed or not signed by a trusted CA");
  }

  if (0 == ssl_verify_result)
  {
    verb ("V: verify success");
  }
  else
  {
    die ("certificate verification error: -0x%04x", -ssl_verify_result);
  }
  return 0;
}
#else
uint32_t
verify_signature (SSL *ssl, const char *hostname)
{
  long ssl_verify_result;
  X509 *certificate;

  certificate = SSL_get_peer_certificate(ssl);
  if (NULL == certificate)
  {
    die ("Getting certificate failed");
  }
  // In theory, we verify that the cert is valid
  ssl_verify_result = SSL_get_verify_result(ssl);
  switch (ssl_verify_result)
  {
  case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
  case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
    die ("certificate is self signed");
  case X509_V_OK:
    verb ("V: certificate verification passed");
    break;
  default:
    die ("certification verification error: %ld",
         ssl_verify_result);
  }
 return 0;
}
#endif

#ifdef USE_POLARSSL
void
check_key_length (ssl_context *ssl)
{
  uint32_t key_bits;
  const x509_cert *certificate;
  const rsa_context *public_key;
  char buf[1024];

  certificate = ssl_get_peer_cert (ssl);
  if (NULL == certificate)
  {
    die ("Getting certificate failed");
  }

  x509parse_dn_gets(buf, 1024, &certificate->subject);
  verb_debug ("V: Certificate for subject '%s'", buf);

  public_key = &certificate->rsa;
  if (NULL == public_key)
  {
    die ("public key extraction failure");
  } else {
    verb_debug ("V: public key is ready for inspection");
  }
  key_bits = mpi_msb (&public_key->N);
  if (MIN_PUB_KEY_LEN >= key_bits)
  {
    die ("Unsafe public key size: %d bits", key_bits);
  } else {
    verb_debug ("V: key length appears safe");
  }
}
#else
void
check_key_length (SSL *ssl)
{
  uint32_t key_bits;
  X509 *certificate;
  EVP_PKEY *public_key;
  certificate = SSL_get_peer_certificate (ssl);
  if (NULL == certificate)
  {
    die ("Getting certificate failed");
  }
  public_key = X509_get_pubkey (certificate);
  if (NULL == public_key)
  {
    die ("public key extraction failure");
  } else {
    verb_debug ("V: public key is ready for inspection");
  }

  key_bits = get_certificate_keybits (public_key);
  if (MIN_PUB_KEY_LEN >= key_bits && EVP_PKEY_id(public_key) != EVP_PKEY_EC)
  {
    die ("Unsafe public key size: %d bits", key_bits);
  } else {
     if (EVP_PKEY_id(public_key) == EVP_PKEY_EC)
       if(key_bits >= MIN_ECC_PUB_KEY_LEN
          && key_bits <= MAX_ECC_PUB_KEY_LEN)
       {
         verb_debug ("V: ECC key length appears safe");
       } else {
         die ("Unsafe ECC key size: %d bits", key_bits);
     } else {
       verb_debug ("V: key length appears safe");
     }
  }
  EVP_PKEY_free (public_key);
}
#endif

#ifdef USE_POLARSSL
void
inspect_key (ssl_context *ssl, const char *hostname)
{
  verify_signature (ssl, hostname);

  // ssl_get_verify_result() already checks for CN / subjectAltName match
  // and reports the mismatch as error. So check_name() is not called
}
#else
void
inspect_key (SSL *ssl, const char *hostname)
{

    verify_signature (ssl, hostname);
    check_name (ssl, hostname);
}
#endif

#ifdef USE_POLARSSL
void
check_timestamp (uint32_t server_time)
{
  uint32_t compiled_time = RECENT_COMPILE_DATE;
  uint32_t max_reasonable_time = MAX_REASONABLE_TIME;
  if (compiled_time < server_time
      &&
      server_time < max_reasonable_time)
  {
    verb("V: remote peer provided: %d, preferred over compile time: %d",
          server_time, compiled_time);
  } else {
    die("V: the remote server is a false ticker! server: %d compile: %d",
         server_time, compiled_time);
  }
}

static int ssl_do_handshake_part(ssl_context *ssl)
{
  int ret = 0;

  /* Only do steps till ServerHello is received */
  while (ssl->state != SSL_SERVER_HELLO)
  {
    ret = ssl_handshake_step (ssl);
    if (0 != ret)
    {
      die("SSL handshake failed");
    }
  }
  /* Do ServerHello so we can skim the timestamp */
  ret = ssl_handshake_step (ssl);
  if (0 != ret)
  {
    die("SSL handshake failed");
  }

  return 0;
}

/**
 * Run SSL handshake and store the resulting time value in the
 * 'time_map'.
 *
 * @param time_map where to store the current time
 * @param time_is_an_illusion
 * @param http whether to do an http request and take the date from that
 *     instead.
 */
static void
run_ssl (uint32_t *time_map, int time_is_an_illusion, int http)
{
  entropy_context entropy;
  ctr_drbg_context ctr_drbg;
  ssl_context ssl;
  proxy_polarssl_ctx proxy_ctx;
  x509_cert cacert;
  struct stat statbuf;
  int ret = 0, server_fd = 0;
  char *pers = "tlsdate-helper";

  memset (&ssl, 0, sizeof(ssl_context));
  memset (&cacert, 0, sizeof(x509_cert));

  verb("V: Using PolarSSL for SSL");
  if (ca_racket)
  {
    if (-1 == stat (ca_cert_container, &statbuf))
    {
      die("Unable to stat CA certficate container %s", ca_cert_container);
    }
    else
    {
      switch (statbuf.st_mode & S_IFMT)
      {
      case S_IFREG:
        if (0 > x509parse_crtfile(&cacert, ca_cert_container))
          fprintf(stderr, "x509parse_crtfile failed");
        break;
      case S_IFDIR:
        if (0 > x509parse_crtpath(&cacert, ca_cert_container))
          fprintf(stderr, "x509parse_crtpath failed");
        break;
      default:
        die("Unable to load CA certficate container %s", ca_cert_container);
      }
    }
  }

  entropy_init (&entropy);
  if (0 != ctr_drbg_init (&ctr_drbg, entropy_func, &entropy,
                         (unsigned char *) pers, strlen(pers)))
  {
    die("Failed to initialize CTR_DRBG");
  }

  if (0 != ssl_init (&ssl))
  {
    die("SSL initialization failed");
  }
  ssl_set_endpoint (&ssl, SSL_IS_CLIENT);
  ssl_set_rng (&ssl, ctr_drbg_random, &ctr_drbg);
  ssl_set_ca_chain (&ssl, &cacert, NULL, hostname_to_verify);
  if (ca_racket)
  {
      // You can do SSL_VERIFY_REQUIRED here, but then the check in
      // inspect_key() never happens as the ssl_handshake() will fail.
      ssl_set_authmode (&ssl, SSL_VERIFY_OPTIONAL);
  }

  if (proxy)
  {
    char *scheme;
    char *proxy_host;
    char *proxy_port;

    parse_proxy_uri (proxy, &scheme, &proxy_host, &proxy_port);

    verb("V: opening socket to proxy %s:%s", proxy_host, proxy_port);
    if (0 != net_connect (&server_fd, proxy_host, atoi(proxy_port)))
    {
      die ("SSL connection failed");
    }

    proxy_polarssl_init (&proxy_ctx);
    proxy_polarssl_set_bio (&proxy_ctx, net_recv, &server_fd, net_send, &server_fd);
    proxy_polarssl_set_host (&proxy_ctx, host);
    proxy_polarssl_set_port (&proxy_ctx, atoi(port));
    proxy_polarssl_set_scheme (&proxy_ctx, scheme);

    ssl_set_bio (&ssl, proxy_polarssl_recv, &proxy_ctx, proxy_polarssl_send, &proxy_ctx);

    verb("V: Handle proxy connection");
    if (0 == proxy_ctx.f_connect (&proxy_ctx))
      die("Proxy connection failed");
  }
  else
  {
    verb("V: opening socket to %s:%s", host, port);
    if (0 != net_connect (&server_fd, host, atoi(port)))
    {
      die ("SSL connection failed");
    }

    ssl_set_bio (&ssl, net_recv, &server_fd, net_send, &server_fd);
  }

  verb("V: starting handshake");
  if (0 != ssl_do_handshake_part (&ssl))
    die("SSL handshake first part failed");

  uint32_t timestamp = ( (uint32_t) ssl.in_msg[6] << 24 )
                     | ( (uint32_t) ssl.in_msg[7] << 16 )
                     | ( (uint32_t) ssl.in_msg[8] <<  8 )
                     | ( (uint32_t) ssl.in_msg[9]       );
  check_timestamp (timestamp);

  verb("V: continuing handshake");
  /* Continue with handshake */
  while (0 != (ret = ssl_handshake (&ssl)))
  {
    if (POLARSSL_ERR_NET_WANT_READ  != ret &&
        POLARSSL_ERR_NET_WANT_WRITE != ret)
    {
      die("SSL handshake failed");
    }
  }

  // Verify the peer certificate against the CA certs on the local system
  if (ca_racket) {
    inspect_key (&ssl, hostname_to_verify);
  } else {
    verb ("V: Certificate verification skipped!");
  }
  check_key_length (&ssl);

  memcpy (time_map, &timestamp, sizeof(uint32_t));
  proxy_polarssl_free (&proxy_ctx);
  ssl_free (&ssl);
  x509_free (&cacert);
}
#else /* USE_POLARSSL */
/**
 * Run SSL handshake and store the resulting time value in the
 * 'time_map'.
 *
 * @param time_map where to store the current time
 * @param time_is_an_illusion
 * @param http whether to do an http request and take the date from that
 *     instead.
 */
static void
run_ssl (uint32_t *time_map, int time_is_an_illusion, int http)
{
  BIO *s_bio;
  SSL_CTX *ctx;
  SSL *ssl;
  struct stat statbuf;
  uint32_t result_time;

  SSL_load_error_strings();
  SSL_library_init();

  ctx = SSL_CTX_new(TLS_client_method());
  if (ctx == NULL)
    die("OpenSSL failed to support protocol `%s'", protocol);

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
  if (!http)
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
#endif

  verb("V: Using OpenSSL for SSL (" OPENSSL_VERSION_TEXT ")");
  if (ca_racket)
  {
    if (-1 == stat(ca_cert_container, &statbuf))
    {
      die("Unable to stat CA certificate container %s", ca_cert_container);
    } else
    {
      switch (statbuf.st_mode & S_IFMT)
      {
      case S_IFREG:
        if (1 != SSL_CTX_load_verify_locations(ctx, ca_cert_container, NULL))
          fprintf(stderr, "SSL_CTX_load_verify_locations failed");
        break;
      case S_IFDIR:
        if (1 != SSL_CTX_load_verify_locations(ctx, NULL, ca_cert_container))
          fprintf(stderr, "SSL_CTX_load_verify_locations failed");
        break;
      default:
        if (1 != SSL_CTX_load_verify_locations(ctx, NULL, ca_cert_container))
        {
          fprintf(stderr, "SSL_CTX_load_verify_locations failed");
          die("Unable to load CA certficate container %s", ca_cert_container);
        }
      }
    }
  }

  verb("V: opening socket to %s:%s", host, port);
  if (NULL == (s_bio = make_ssl_bio(ctx, host, port)))
    die ("SSL BIO setup failed");
  BIO_get_ssl(s_bio, &ssl);
  if (NULL == ssl)
    die ("SSL setup failed");

  if (time_is_an_illusion)
  {
    SSL_set_info_callback(ssl, openssl_time_callback);
  }

  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
  SSL_set_tlsext_host_name (ssl, host);

  if (NULL == BIO_new_fp(stdout, BIO_NOCLOSE))
    die ("BIO_new_fp returned error, possibly: %s", strerror(errno));

  // This should run in seccomp
  // eg:     prctl(PR_SET_SECCOMP, 1);
  if (1 != BIO_do_connect(s_bio)) // XXX TODO: BIO_should_retry() later?
    die ("SSL connection failed");
  if (1 != BIO_do_handshake(s_bio))
    die ("SSL handshake failed");

  // from /usr/include/openssl/ssl3.h
  //  ssl->s3->server_random is an unsigned char of 32 bits
  SSL_get_server_random(ssl, (unsigned char *)&result_time, sizeof result_time);
  verb("V: In TLS response, T=%lu", (unsigned long)ntohl(result_time));

  if (http) {
    char buf[1024];
    verb_debug ("V: Starting HTTP");
    if (snprintf(buf, sizeof(buf),
                 HTTP_REQUEST, HTTPS_USER_AGENT, hostname_to_verify) >= 1024)
      die("hostname too long");
    buf[1023]='\0'; /* Unneeded. */
    verb_debug ("V: Writing HTTP request");
    if (1 != write_all_to_bio(s_bio, buf))
      die ("write all to bio failed.");
    verb_debug ("V: Reading HTTP response");
    if (1 != read_http_date_from_bio(s_bio, &result_time))
      die ("read all from bio failed.");
    verb ("V: Received HTTP response. T=%lu", (unsigned long)result_time);

    result_time = htonl(result_time);
  }

  // Verify the peer certificate against the CA certs on the local system
  if (ca_racket) {
    inspect_key (ssl, hostname_to_verify);
  } else {
    verb ("V: Certificate verification skipped!");
  }
  check_key_length(ssl);

  memcpy(time_map, &result_time, sizeof (uint32_t));

  SSL_free(ssl);
  SSL_CTX_free(ctx);
}
#endif /* USE_POLARSSL */
/** drop root rights and become 'nobody' */

int
main(int argc, char **argv)
{
  uint32_t *time_map;
  struct tlsdate_time start_time, end_time, warp_time;
  int status;
  pid_t ssl_child;
  long long rt_time_ms;
  uint32_t server_time_s;
  int setclock;
  int showtime;
  int showtime_raw;
  int timewarp;
  int leap;
  int http;

  /* Sometimes tlsdate gets "stuck" and never exits, so force it here. */
  alarm(60);

  if (argc != 13)
    return 1;
  host = argv[1];
  hostname_to_verify = argv[1];
  port = argv[2];
  protocol = argv[3];
  ca_cert_container = argv[6];
  ca_racket = (0 != strcmp ("unchecked", argv[4]));
  verbose = (0 != strcmp ("quiet", argv[5]));
  verbose_debug = (0 != strcmp ("verbose", argv[5]));
  setclock = (0 == strcmp ("setclock", argv[7]));
  showtime = (0 == strcmp ("showtime", argv[8]));
  showtime_raw = (0 == strcmp ("showtime=raw", argv[8]));
  timewarp = (0 == strcmp ("timewarp", argv[9]));
  leap = (0 == strcmp ("leapaway", argv[10]));
  proxy = (0 == strcmp ("none", argv[11]) ? NULL : argv[11]);
  http = (0 == (strcmp("http", argv[12])));

  /* Initalize warp_time with RECENT_COMPILE_DATE */
  clock_init_time(&warp_time, RECENT_COMPILE_DATE, 0);

  verb ("V: RECENT_COMPILE_DATE is %lu.%06lu",
       (unsigned long) CLOCK_SEC(&warp_time),
       (unsigned long) CLOCK_USEC(&warp_time));

  if (1 != timewarp)
  {
    verb ("V: we'll do the time warp another time - we're not setting clock");
  }

  /* We are not going to set the clock, thus no need to stay root */
  if (0 == setclock && 0 == timewarp)
  {
    verb ("V: attemping to drop administrator privileges");
    drop_privs_to (UNPRIV_USER, UNPRIV_GROUP);
  }

  // We cast the mmap value to remove this error when compiling with g++:
  // src/tlsdate-helper.c: In function ‘int main(int, char**)’:
  // src/tlsdate-helper.c:822:41: error: invalid conversion from ‘void*’ to ‘uint32_t
  time_map = (uint32_t *) mmap (NULL, sizeof (uint32_t),
       PROT_READ | PROT_WRITE,
       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
   if (MAP_FAILED == time_map)
  {
    fprintf (stderr, "mmap failed: %s",
             strerror (errno));
    return 1;
  }

  /* Get the current time from the system clock. */
  if (0 != clock_get_real_time(&start_time))
  {
    die ("Failed to read current time of day: %s", strerror (errno));
  }

  verb ("V: time is currently %lu.%06lu",
       (unsigned long) CLOCK_SEC(&start_time),
       (unsigned long) CLOCK_NSEC(&start_time));

  if (((unsigned long) CLOCK_SEC(&start_time)) < ((unsigned long) CLOCK_SEC(&warp_time)))
  {
    verb ("V: local clock time is less than RECENT_COMPILE_DATE");
    if (timewarp)
    {
      verb ("V: Attempting to warp local clock into the future");
      if (0 != clock_set_real_time(&warp_time))
      {
        die ("setting time failed: %s (Attempted to set clock to %lu.%06lu)",
        strerror (errno),
        (unsigned long) CLOCK_SEC(&warp_time),
        (unsigned long) CLOCK_SEC(&warp_time));
      }
      if (0 != clock_get_real_time(&start_time))
      {
        die ("Failed to read current time of day: %s", strerror (errno));
      }
      verb ("V: time is currently %lu.%06lu",
           (unsigned long) CLOCK_SEC(&start_time),
           (unsigned long) CLOCK_NSEC(&start_time));
      verb ("V: It's just a step to the left...");
    }
  } else {
    verb ("V: time is greater than RECENT_COMPILE_DATE");
  }

  /* initialize to bogus value, just to be on the safe side */
  *time_map = 0;

  /* Run SSL interaction in separate process (and not as 'root') */
  ssl_child = fork ();
  if (-1 == ssl_child)
    die ("fork failed: %s", strerror (errno));
  if (0 == ssl_child)
  {
    drop_privs_to (UNPRIV_USER, UNPRIV_GROUP);
    run_ssl (time_map, leap, http);
    (void) munmap (time_map, sizeof (uint32_t));
    _exit (0);
  }
  if (ssl_child != platform->process_wait (ssl_child, &status, 1))
    die ("waitpid failed: %s", strerror (errno));
  if (! (WIFEXITED (status) && (0 == WEXITSTATUS (status)) ))
    die ("child process failed in SSL handshake");

  if (0 != clock_get_real_time(&end_time))
    die ("Failed to read current time of day: %s", strerror (errno));

  /* calculate RTT */
  rt_time_ms = (CLOCK_SEC(&end_time) - CLOCK_SEC(&start_time)) * 1000 + (CLOCK_USEC(&end_time) - CLOCK_USEC(&start_time)) / 1000;
  if (rt_time_ms < 0)
    rt_time_ms = 0; /* non-linear time... */
#ifdef USE_POLARSSL
  server_time_s = *time_map;
#else
  server_time_s = ntohl (*time_map);
#endif
  // We should never have a time_map of zero here;
  // It either stayed zero or we have a false ticker.
  if ( 0 == server_time_s )
    die ("child process failed to update time map; weird platform issues?");
  munmap (time_map, sizeof (uint32_t));

  verb ("V: server time %u (difference is about %d s) was fetched in %lld ms",
  (unsigned int) server_time_s,
  CLOCK_SEC(&start_time) - server_time_s,
  rt_time_ms);

  /* warning if the handshake took too long */
  if (rt_time_ms > TLS_RTT_UNREASONABLE) {
    die ("the TLS handshake took more than %d msecs - consider using a different " \
      "server or run it again", TLS_RTT_UNREASONABLE);
  }
  if (rt_time_ms > TLS_RTT_THRESHOLD) {
    verb ("V: the TLS handshake took more than %d msecs - consider using a different " \
      "server or run it again", TLS_RTT_THRESHOLD);
  }

  if (showtime_raw)
  {
    fwrite(&server_time_s, sizeof(server_time_s), 1, stdout);
  }

  if (showtime)
  {
     struct tm  ltm;
     time_t tim = server_time_s;
     char       buf[256];

     localtime_r(&tim, &ltm);
     if (0 == strftime(buf, sizeof buf, "%a %b %e %H:%M:%S %Z %Y", &ltm))
     {
       die ("strftime returned 0");
     }
     fprintf(stdout, "%s\n", buf);
  }

  /* finally, actually set the time */
  if (setclock)
  {
    struct tlsdate_time server_time;

    clock_init_time(&server_time,  server_time_s + (rt_time_ms / 2 / 1000),
                   (rt_time_ms / 2) % 1000);

    // We should never receive a time that is before the time we were last
    // compiled; we subscribe to the linear theory of time for this program
    // and this program alone!
    if (CLOCK_SEC(&server_time) >= MAX_REASONABLE_TIME)
      die("remote server is a false ticker from the future!");
    if (CLOCK_SEC(&server_time) <= RECENT_COMPILE_DATE)
      die ("remote server is a false ticker!");
    if (0 != clock_set_real_time(&server_time))
      die ("setting time failed: %s (Difference from server is about %d s)",
     strerror (errno),
     CLOCK_SEC(&start_time) - server_time_s);
    verb ("V: setting time succeeded");
  }
  return 0;
}
