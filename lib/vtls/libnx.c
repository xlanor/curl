/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

/*
 * Source file for libnx-specific TLS/SSL code for Nintendo Switch.
 * Uses the Switch's ssl-service via libnx.
 *
 * Based on the devkitPro curl fork by yellows8.
 */

#include "../curl_setup.h"

#ifdef USE_LIBNX

#undef BIT
#include <switch.h>
#undef BIT
#define BIT(x) bit x:1
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

#include "libnx.h"
#include "vtls.h"
#include "vtls_int.h"
#include "vtls_scache.h"
#include "x509asn1.h"
#include "../urldata.h"
#include "../sendf.h"
#include "../connect.h"
#include "../select.h"
#include "../multiif.h"
#include "../strdup.h"
#include "../curl_sha256.h"
#include "../curl_printf.h"

/* ALPN for http2 - available on firmware 9.0.0+ */
#ifdef USE_HTTP2
#define HAS_ALPN_LIBNX
#endif

/* libnx ssl-service error codes */
#define LIBNX_SSL_ERROR_WOULDBLOCK  MAKERESULT(123, 204)

struct libnx_ssl_backend_data {
  SslContext context;
  SslConnection conn;
  u8 *certbuf;
  size_t certbuf_size;
  bool context_ready;
  bool conn_ready;
  BIT(sent_shutdown);
};

/* Helper function to load a file into memory */
static CURLcode load_file(const char *filename, u8 **outbuf, size_t *outsize)
{
  struct stat st;
  FILE *fp;
  u8 *buf;
  size_t readsize;

  if(stat(filename, &st) != 0)
    return CURLE_READ_ERROR;

  if(st.st_size <= 0)
    return CURLE_READ_ERROR;

  fp = fopen(filename, "rb");
  if(!fp)
    return CURLE_READ_ERROR;

  buf = malloc((size_t)st.st_size);
  if(!buf) {
    fclose(fp);
    return CURLE_OUT_OF_MEMORY;
  }

  readsize = fread(buf, 1, (size_t)st.st_size, fp);
  fclose(fp);

  if(readsize != (size_t)st.st_size) {
    free(buf);
    return CURLE_READ_ERROR;
  }

  *outbuf = buf;
  *outsize = (size_t)st.st_size;
  return CURLE_OK;
}

/* Load CA certificates from a directory */
static CURLcode load_capath(struct Curl_easy *data,
                            SslContext *context,
                            const char *capath)
{
  DIR *dir;
  struct dirent *entry;
  char filepath[PATH_MAX];
  u8 *certdata = NULL;
  size_t certsize = 0;
  int loaded = 0;
  Result rc;

  dir = opendir(capath);
  if(!dir) {
    failf(data, "libnx: failed to open CA path: %s", capath);
    return CURLE_SSL_CACERT_BADFILE;
  }

  while((entry = readdir(dir)) != NULL) {
    struct stat st;

    if(entry->d_name[0] == '.')
      continue;

    snprintf(filepath, sizeof(filepath), "%s/%s", capath, entry->d_name);

    if(stat(filepath, &st) != 0)
      continue;

    if(!S_ISREG(st.st_mode))
      continue;

    if(load_file(filepath, &certdata, &certsize) != CURLE_OK)
      continue;

    rc = sslContextImportServerPki(context, certdata, certsize,
                                   SslCertificateFormat_Pem, NULL);
    free(certdata);
    certdata = NULL;

    if(R_SUCCEEDED(rc)) {
      loaded++;
      infof(data, "libnx: loaded CA cert: %s", entry->d_name);
    }
  }

  closedir(dir);

  if(loaded == 0) {
    failf(data, "libnx: no CA certificates loaded from: %s", capath);
    return CURLE_SSL_CACERT_BADFILE;
  }

  infof(data, "libnx: loaded %d CA certificates from %s", loaded, capath);
  return CURLE_OK;
}

/* Set TLS version range (min and max) */
static CURLcode set_ssl_version_min_max(struct Curl_easy *data,
                                        u32 *out_version,
                                        long ssl_version,
                                        long ssl_version_max)
{
  u32 libnx_ver_min = 0;
  u32 libnx_ver_max = 0;

  /* Get minimum version */
  switch(ssl_version) {
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1:
  case CURL_SSLVERSION_TLSv1_0:
    libnx_ver_min = SslVersion_TlsV10;
    break;
  case CURL_SSLVERSION_TLSv1_1:
    libnx_ver_min = SslVersion_TlsV11;
    break;
  case CURL_SSLVERSION_TLSv1_2:
    libnx_ver_min = SslVersion_TlsV12;
    break;
  case CURL_SSLVERSION_TLSv1_3:
    /* TLS 1.3 available on firmware 11.0.0+ */
    if(!hosversionAtLeast(11, 0, 0)) {
      failf(data, "libnx: TLS 1.3 requires firmware 11.0.0+");
      return CURLE_SSL_CONNECT_ERROR;
    }
    libnx_ver_min = SslVersion_TlsV13;
    break;
  default:
    failf(data, "libnx: unsupported minimum TLS version");
    return CURLE_SSL_CONNECT_ERROR;
  }

  /* Get maximum version */
  switch(ssl_version_max) {
  case CURL_SSLVERSION_MAX_NONE:
  case CURL_SSLVERSION_MAX_DEFAULT:
  case CURL_SSLVERSION_MAX_TLSv1_3:
    /* TLS 1.3 available on firmware 11.0.0+ */
    if(hosversionAtLeast(11, 0, 0)) {
      libnx_ver_max = SslVersion_TlsV13;
    }
    else {
      libnx_ver_max = SslVersion_TlsV12;
    }
    break;
  case CURL_SSLVERSION_MAX_TLSv1_2:
    libnx_ver_max = SslVersion_TlsV12;
    break;
  case CURL_SSLVERSION_MAX_TLSv1_1:
    libnx_ver_max = SslVersion_TlsV11;
    break;
  case CURL_SSLVERSION_MAX_TLSv1_0:
    libnx_ver_max = SslVersion_TlsV10;
    break;
  default:
    failf(data, "libnx: unsupported maximum TLS version");
    return CURLE_SSL_CONNECT_ERROR;
  }

  /* Validate min <= max */
  if(libnx_ver_min > libnx_ver_max) {
    failf(data, "libnx: minimum TLS version exceeds maximum");
    return CURLE_SSL_CONNECT_ERROR;
  }

  /* Combine min and max versions with bitwise OR as libnx expects */
  *out_version = libnx_ver_min | libnx_ver_max;
  return CURLE_OK;
}

static int libnx_init(void)
{
  /* sslInitialize takes num_sessions (must be 0x1-0x4), default is 0x3 */
  Result rc = sslInitialize(3);
  if(R_FAILED(rc))
    return 0;

  /* Initialize CSRNG for random number generation */
  rc = csrngInitialize();
  if(R_FAILED(rc)) {
    sslExit();
    return 0;
  }

  return 1;
}

static void libnx_cleanup(void)
{
  csrngExit();
  sslExit();
}

static size_t libnx_version(char *buffer, size_t size)
{
  return curl_msnprintf(buffer, size, "libnx");
}

static CURLcode libnx_random(struct Curl_easy *data,
                             unsigned char *entropy, size_t length)
{
  Result rc;
  (void)data;

  rc = csrngGetRandomBytes(entropy, length);
  if(R_FAILED(rc)) {
    return CURLE_FAILED_INIT;
  }
  return CURLE_OK;
}

static CURLcode libnx_connect_step1(struct Curl_cfilter *cf,
                                    struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct libnx_ssl_backend_data *backend =
    (struct libnx_ssl_backend_data *)connssl->backend;
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  const char *ssl_cafile = conn_config->CAfile;
  const char *ssl_capath = conn_config->CApath;
  const char *ssl_cert = ssl_config->primary.clientcert;
  const char *key_passwd = ssl_config->key_passwd;
  const bool verifypeer = conn_config->verifypeer;
  const bool verifyhost = conn_config->verifyhost;
  Result rc;
  u32 ssl_version;
  curl_socket_t sockfd;
  CURLcode result;

  DEBUGASSERT(backend);

  /* Determine TLS version range */
  result = set_ssl_version_min_max(data, &ssl_version,
                                   conn_config->version,
                                   conn_config->version_max);
  if(result != CURLE_OK)
    return result;

  /* Create SSL context */
  rc = sslCreateContext(&backend->context, ssl_version);
  if(R_FAILED(rc)) {
    failf(data, "libnx: sslCreateContext failed: 0x%x", rc);
    return CURLE_SSL_CONNECT_ERROR;
  }
  backend->context_ready = true;

  /* Load CA certificate file */
  if(ssl_cafile) {
    u8 *certdata = NULL;
    size_t certsize = 0;

    if(load_file(ssl_cafile, &certdata, &certsize) == CURLE_OK) {
      rc = sslContextImportServerPki(&backend->context, certdata, certsize,
                                     SslCertificateFormat_Pem, NULL);
      free(certdata);
      if(R_FAILED(rc)) {
        failf(data, "libnx: failed to import CA cert: 0x%x", rc);
        return CURLE_SSL_CACERT_BADFILE;
      }
      infof(data, "libnx: loaded CA cert from %s", ssl_cafile);
    }
    else {
      failf(data, "libnx: failed to load CA file: %s", ssl_cafile);
      return CURLE_SSL_CACERT_BADFILE;
    }
  }

  /* Load CA certificates from path */
  if(ssl_capath) {
    CURLcode result = load_capath(data, &backend->context, ssl_capath);
    if(result != CURLE_OK)
      return result;
  }

  /* Load client certificate (PKCS#12 format) */
  if(ssl_cert) {
    u8 *certdata = NULL;
    size_t certsize = 0;
    u32 passwd_len = key_passwd ? (u32)strlen(key_passwd) : 0;

    if(load_file(ssl_cert, &certdata, &certsize) == CURLE_OK) {
      rc = sslContextImportClientPki(&backend->context, certdata, certsize,
                                     key_passwd, passwd_len, NULL);
      free(certdata);
      if(R_FAILED(rc)) {
        failf(data, "libnx: failed to import client cert: 0x%x", rc);
        return CURLE_SSL_CERTPROBLEM;
      }
      infof(data, "libnx: loaded client cert from %s", ssl_cert);
    }
    else {
      failf(data, "libnx: failed to load client cert: %s", ssl_cert);
      return CURLE_SSL_CERTPROBLEM;
    }
  }

  /* Create SSL connection */
  rc = sslContextCreateConnection(&backend->context, &backend->conn);
  if(R_FAILED(rc)) {
    failf(data, "libnx: sslContextCreateConnection failed: 0x%x", rc);
    return CURLE_SSL_CONNECT_ERROR;
  }
  backend->conn_ready = true;

  /* Tell libnx not to close the socket - we manage it
   * NOTE: This must be set BEFORE socketSslConnectionSetSocketDescriptor */
  rc = sslConnectionSetOption(&backend->conn,
                              SslOptionType_DoNotCloseSocket, TRUE);
  if(R_FAILED(rc)) {
    failf(data, "libnx: DoNotCloseSocket failed: 0x%x", rc);
    return CURLE_SSL_CONNECT_ERROR;
  }

  /* Set socket descriptor - must be done early!
   * Many other SSL options require the socket to be set first. */
  sockfd = Curl_conn_cf_get_socket(cf, data);
  {
    int ret = socketSslConnectionSetSocketDescriptor(&backend->conn,
                                                     (int)sockfd);
    if(ret == -1 && errno != ENOENT) {
      failf(data, "libnx: socketSslConnectionSetSocketDescriptor failed, "
            "errno=%d", errno);
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  /* Set hostname for SNI - required before other options */
  if(connssl->peer.sni) {
    rc = sslConnectionSetHostName(&backend->conn, connssl->peer.sni,
                                  strlen(connssl->peer.sni));
    if(R_FAILED(rc)) {
      failf(data, "libnx: sslConnectionSetHostName failed: 0x%x", rc);
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  /* Skip default verify - allows custom certificate validation
   * Available on firmware 5.0.0+ */
  sslConnectionSetOption(&backend->conn,
                         SslOptionType_SkipDefaultVerify, TRUE);
  /* Ignore errors - not available on all firmware versions */

  /* Configure verification options (combined flags) */
  {
    u32 verifyopt = SslVerifyOption_DateCheck; /* Always check cert dates */
    if(verifypeer)
      verifyopt |= SslVerifyOption_PeerCa;
    if(verifyhost)
      verifyopt |= SslVerifyOption_HostName;
    rc = sslConnectionSetVerifyOption(&backend->conn, verifyopt);
    if(R_FAILED(rc)) {
      failf(data, "libnx: sslConnectionSetVerifyOption failed: 0x%x", rc);
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  /* Request server certificate chain on firmware 3.0.0+ */
  if(hosversionAtLeast(3, 0, 0)) {
    rc = sslConnectionSetOption(&backend->conn,
                                SslOptionType_GetServerCertChain, TRUE);
    if(R_FAILED(rc)) {
      infof(data, "libnx: GetServerCertChain not available: 0x%x", rc);
    }
  }

  /* Configure session caching - requires socket descriptor to be set */
  {
    SslSessionCacheMode cache_mode = SslSessionCacheMode_None;
    if(ssl_config->primary.cache_session)
      cache_mode = SslSessionCacheMode_SessionId;
    rc = sslConnectionSetSessionCacheMode(&backend->conn, cache_mode);
    if(R_FAILED(rc)) {
      infof(data, "libnx: session cache config failed: 0x%x (ignored)", rc);
    }
  }

#ifdef HAS_ALPN_LIBNX
  /* Set ALPN protocols if requested (requires firmware 9.0.0+) */
  if(connssl->alpn && hosversionAtLeast(9, 0, 0)) {
    struct alpn_proto_buf proto;
    CURLcode result = Curl_alpn_to_proto_buf(&proto, connssl->alpn);
    if(result == CURLE_OK && proto.len > 0) {
      rc = sslConnectionSetNextAlpnProto(&backend->conn,
                                         proto.data, (u32)proto.len);
      if(R_FAILED(rc)) {
        infof(data, "libnx: ALPN setup failed: 0x%x (non-fatal)", rc);
        /* Not fatal - continue without ALPN */
      }
    }
  }
#endif

  /* Set I/O mode - use blocking for simpler handshake handling */
  rc = sslConnectionSetIoMode(&backend->conn, SslIoMode_Blocking);
  if(R_FAILED(rc)) {
    failf(data, "libnx: sslConnectionSetIoMode failed: 0x%x", rc);
    return CURLE_SSL_CONNECT_ERROR;
  }

  connssl->connecting_state = ssl_connect_2;
  return CURLE_OK;
}

/* Certificate buffer size for handshake output */
#define LIBNX_CERTBUF_SIZE 0x10000

static CURLcode libnx_connect_step2(struct Curl_cfilter *cf,
                                    struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct libnx_ssl_backend_data *backend =
    (struct libnx_ssl_backend_data *)connssl->backend;
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  const char *pinnedpubkey = Curl_ssl_cf_is_proxy(cf) ?
    data->set.str[STRING_SSL_PINNEDPUBLICKEY_PROXY] :
    data->set.str[STRING_SSL_PINNEDPUBLICKEY];
  Result rc;
  u32 out_size = 0;
  u32 total_certs = 0;
  CURLcode result = CURLE_OK;
  u8 *peercert = NULL;
  size_t peercert_size = 0;

  DEBUGASSERT(backend);

  /* Allocate certificate buffer if not already done */
  if(!backend->certbuf) {
    backend->certbuf = calloc(1, LIBNX_CERTBUF_SIZE);
    if(!backend->certbuf) {
      failf(data, "libnx: out of memory for cert buffer");
      return CURLE_OUT_OF_MEMORY;
    }
    backend->certbuf_size = LIBNX_CERTBUF_SIZE;
  }

  /* Perform TLS handshake */
  rc = sslConnectionDoHandshake(&backend->conn, &out_size, &total_certs,
                                backend->certbuf, backend->certbuf_size);

  if(R_FAILED(rc)) {
    if(rc == LIBNX_SSL_ERROR_WOULDBLOCK) {
      connssl->io_need = CURL_SSL_IO_NEED_RECV;
      return CURLE_AGAIN;
    }

    /* Get detailed certificate verification error if available */
    if(conn_config->verifypeer) {
      Result verify_rc = sslConnectionGetVerifyCertError(&backend->conn);
      if(R_FAILED(verify_rc)) {
        /* Map specific cert errors */
        u32 mod = R_MODULE(verify_rc);
        u32 desc = R_DESCRIPTION(verify_rc);
        if(mod == 123) {
          switch(desc) {
          case 323:  /* cert not trusted */
          case 1509: /* cert signature failure */
          case 1511: /* cert format error */
          case 1512: /* cert path error */
            failf(data, "libnx: certificate problem: 0x%x", verify_rc);
            return CURLE_SSL_CERTPROBLEM;
          case 301:  /* hostname mismatch */
          case 303:  /* expired */
          case 304:  /* not yet valid */
            failf(data, "libnx: certificate verification failed: 0x%x",
                  verify_rc);
            return CURLE_PEER_FAILED_VERIFICATION;
          }
        }
      }
    }

    failf(data, "libnx: sslConnectionDoHandshake failed: 0x%x", rc);
    return CURLE_SSL_CONNECT_ERROR;
  }

  /* Handshake complete */
  infof(data, "libnx: SSL connection established (certs: %u, size: %u)",
        total_certs, out_size);

  /* Extract certificate info if requested or if pinning is needed */
  if(out_size && total_certs) {
    /* Set up certificate info if requested */
    if(data->set.ssl.certinfo) {
      result = Curl_ssl_init_certinfo(data, (int)total_certs);
      if(result)
        return result;
    }

    /* Extract peer certificate for verification/pinning */
    if(hosversionAtLeast(3, 0, 0) && total_certs > 0) {
      /* New firmware path - get cert details */
      u32 i;
      for(i = 0; i < total_certs; i++) {
        void *certdata = NULL;
        u32 certdata_size = 0;

        rc = sslConnectionGetServerCertDetail(backend->certbuf, out_size,
                                              i, &certdata, &certdata_size);
        if(R_SUCCEEDED(rc) && certdata && certdata_size > 0) {
          if(i == 0) {
            /* First cert is the peer cert */
            peercert = certdata;
            peercert_size = certdata_size;
          }

          if(data->set.ssl.certinfo) {
            Curl_extract_certinfo(data, (int)i, (const char *)certdata,
                                  (const char *)certdata + certdata_size);
          }
        }
      }
    }
    else if(out_size > 0) {
      /* Old firmware path - raw certificate buffer */
      peercert = backend->certbuf;
      peercert_size = out_size;

      if(data->set.ssl.certinfo) {
        Curl_extract_certinfo(data, 0, (const char *)backend->certbuf,
                              (const char *)backend->certbuf + out_size);
      }
    }
  }

  /* Check pinned public key */
  if(pinnedpubkey) {
    struct Curl_X509certificate cert;

    if(!peercert || !peercert_size) {
      if(!conn_config->verifypeer) {
        failf(data, "libnx: pinned pubkey requires verifypeer to be enabled");
      }
      else {
        failf(data, "libnx: failed to get peer certificate for pinning");
      }
      return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    }

    /* Parse the X.509 certificate */
    memset(&cert, 0, sizeof(cert));
    result = Curl_parseX509(&cert, peercert, peercert + peercert_size);
    if(result) {
      failf(data, "libnx: failed to parse certificate for pinning");
      return result;
    }

    /* Verify the pinned public key */
    result = Curl_pin_peer_pubkey(data, pinnedpubkey,
                                  (const unsigned char *)cert.subjectPublicKey.beg,
                                  cert.subjectPublicKey.end -
                                  cert.subjectPublicKey.beg);
    if(result) {
      failf(data, "libnx: pinned public key verification failed");
      return result;
    }

    infof(data, "libnx: pinned public key verified");
  }

#ifdef HAS_ALPN_LIBNX
  /* Check negotiated ALPN protocol */
  if(connssl->alpn) {
    u8 next_protocol[0x33] = {0};
    SslAlpnProtoState state = 0;
    u32 proto_size = 0;

    rc = sslConnectionGetNextAlpnProto(&backend->conn, &state, &proto_size,
                                       next_protocol, sizeof(next_protocol) - 1);
    if(R_SUCCEEDED(rc) && next_protocol[0] &&
       (state == SslAlpnProtoState_Negotiated ||
        state == SslAlpnProtoState_Selected)) {
      infof(data, "libnx: ALPN negotiated: %s", next_protocol);
      Curl_alpn_set_negotiated(cf, data, connssl,
                               next_protocol, proto_size);
    }
  }
#endif

  connssl->connecting_state = ssl_connect_done;
  return CURLE_OK;
}

static CURLcode libnx_connect(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  CURLcode result = CURLE_OK;

  if(connssl->state == ssl_connection_complete) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(connssl->connecting_state == ssl_connect_1) {
    result = libnx_connect_step1(cf, data);
    if(result != CURLE_OK)
      return result;
  }

  if(connssl->connecting_state == ssl_connect_2) {
    result = libnx_connect_step2(cf, data);
    if(result != CURLE_OK)
      return result;
  }

  if(connssl->connecting_state == ssl_connect_done) {
    connssl->state = ssl_connection_complete;
    *done = TRUE;
  }
  else {
    *done = FALSE;
  }

  return result;
}

static CURLcode libnx_shutdown(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               bool send_shutdown, bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct libnx_ssl_backend_data *backend =
    (struct libnx_ssl_backend_data *)connssl->backend;

  (void)data;
  (void)send_shutdown;

  if(backend && backend->conn_ready && !backend->sent_shutdown) {
    /* Attempt graceful shutdown - ignore errors */
    sslConnectionClose(&backend->conn);
    backend->sent_shutdown = TRUE;
  }

  *done = TRUE;
  return CURLE_OK;
}

static void libnx_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct libnx_ssl_backend_data *backend =
    (struct libnx_ssl_backend_data *)connssl->backend;

  (void)data;

  if(backend) {
    if(backend->conn_ready) {
      sslConnectionClose(&backend->conn);
      backend->conn_ready = false;
    }
    if(backend->context_ready) {
      sslContextClose(&backend->context);
      backend->context_ready = false;
    }
    if(backend->certbuf) {
      free(backend->certbuf);
      backend->certbuf = NULL;
      backend->certbuf_size = 0;
    }
  }
}

static bool libnx_data_pending(struct Curl_cfilter *cf,
                               const struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct libnx_ssl_backend_data *backend =
    (struct libnx_ssl_backend_data *)connssl->backend;

  (void)data;

  if(backend && backend->conn_ready) {
    u32 pending = 0;
    Result rc = sslConnectionPending(&backend->conn, &pending);
    if(R_SUCCEEDED(rc) && pending > 0)
      return TRUE;
  }
  return FALSE;
}

static CURLcode libnx_recv(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           char *buf, size_t len, size_t *pnread)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct libnx_ssl_backend_data *backend =
    (struct libnx_ssl_backend_data *)connssl->backend;
  Result rc;
  u32 actual_size = 0;

  (void)data;

  if(!backend || !backend->conn_ready) {
    *pnread = 0;
    return CURLE_RECV_ERROR;
  }

  rc = sslConnectionRead(&backend->conn, buf, len, &actual_size);

  if(R_FAILED(rc)) {
    if(rc == LIBNX_SSL_ERROR_WOULDBLOCK) {
      connssl->io_need = CURL_SSL_IO_NEED_RECV;
      *pnread = 0;
      return CURLE_AGAIN;
    }
    *pnread = 0;
    failf(data, "libnx: sslConnectionRead failed: 0x%x", rc);
    return CURLE_RECV_ERROR;
  }

  if(actual_size == 0) {
    /* Connection closed */
    connssl->peer_closed = TRUE;
  }

  *pnread = actual_size;
  return CURLE_OK;
}

static CURLcode libnx_send(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           const void *mem, size_t len, size_t *pnwritten)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct libnx_ssl_backend_data *backend =
    (struct libnx_ssl_backend_data *)connssl->backend;
  Result rc;
  u32 actual_size = 0;

  (void)data;

  if(!backend || !backend->conn_ready) {
    *pnwritten = 0;
    return CURLE_SEND_ERROR;
  }

  rc = sslConnectionWrite(&backend->conn, mem, len, &actual_size);

  if(R_FAILED(rc)) {
    if(rc == LIBNX_SSL_ERROR_WOULDBLOCK) {
      connssl->io_need = CURL_SSL_IO_NEED_SEND;
      *pnwritten = 0;
      return CURLE_AGAIN;
    }
    *pnwritten = 0;
    failf(data, "libnx: sslConnectionWrite failed: 0x%x", rc);
    return CURLE_SEND_ERROR;
  }

  *pnwritten = actual_size;
  return CURLE_OK;
}

static void *libnx_get_internals(struct ssl_connect_data *connssl,
                                 CURLINFO info)
{
  struct libnx_ssl_backend_data *backend =
    (struct libnx_ssl_backend_data *)connssl->backend;
  (void)info;
  return backend ? &backend->conn : NULL;
}

static CURLcode libnx_sha256sum(const unsigned char *input, size_t inputlen,
                                unsigned char *sha256sum, size_t sha256len)
{
  if(sha256len < 32)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  /* Use curl's built-in SHA256 implementation */
  return Curl_sha256it(sha256sum, input, inputlen);
}

const struct Curl_ssl Curl_ssl_libnx = {
  { CURLSSLBACKEND_LIBNX, "libnx" }, /* info */

  SSLSUPP_CA_PATH |
  SSLSUPP_CAINFO_BLOB |
  SSLSUPP_PINNEDPUBKEY |
  SSLSUPP_CERTINFO |
  SSLSUPP_HTTPS_PROXY,

  sizeof(struct libnx_ssl_backend_data),

  libnx_init,                       /* init */
  libnx_cleanup,                    /* cleanup */
  libnx_version,                    /* version */
  libnx_shutdown,                   /* shutdown */
  libnx_data_pending,               /* data_pending */
  libnx_random,                     /* random */
  NULL,                             /* cert_status_request */
  libnx_connect,                    /* connect */
  Curl_ssl_adjust_pollset,          /* adjust_pollset */
  libnx_get_internals,              /* get_internals */
  libnx_close,                      /* close_one */
  NULL,                             /* close_all */
  NULL,                             /* set_engine */
  NULL,                             /* set_engine_default */
  NULL,                             /* engines_list */
  libnx_sha256sum,                  /* sha256sum */
  libnx_recv,                       /* recv decrypted data */
  libnx_send,                       /* send data to encrypt */
  NULL,                             /* get_channel_binding */
};

#endif /* USE_LIBNX */
