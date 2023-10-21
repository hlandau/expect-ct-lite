/*
 * ============================================================================
 * Expect-CT Lite Demo Code for OpenSSL
 * 2023 Hugo Landau <hlandau@devever.net>  MIT License
 *
 * For an introduction to the underlying idea, see:
 *
 *   https://www.devever.net/~hl/expect-ct-lite
 *   https://github.com/hlandau/expect-ct-lite
 * ============================================================================
 */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <assert.h>

/* CT validation callback. */
static int on_ct_validation(const CT_POLICY_EVAL_CTX *ctx,
                            const STACK_OF(SCT) *scts, void *arg)
{
  int num_sct = sk_SCT_num(scts);
  int num_signed_sct = 0;

  if (num_sct <= 0) {
    fprintf(stderr, "No SCTs received, not considering this connection valid\n");
    return 0;
  }

  BIO *stderr_bio = BIO_new_fp(stderr, BIO_NOCLOSE);
  fprintf(stderr, "SCTs:\n");

  /*
   * SCTs can be delivered via X509v3 extension, via OCSP extension, or via a
   * TLS extension. Only in the first two cases is the SCT signed by the CA, so
   * it's essential we ensure at least one SCT was delivered via one of these
   * methods. We take this as evidence in good faith that the CA has submitted
   * the server sertificate to a CT log.
   */
  for (int i = 0; i < num_sct; ++i) {
    SCT *sct = sk_SCT_value(scts, i);

    assert(sct);

    if (stderr_bio) {
      SCT_print(sct, stderr_bio, 2, NULL);
      fprintf(stderr, "\n");
    }

    switch (SCT_get_source(sct)) {
    case SCT_SOURCE_X509V3_EXTENSION:
      fprintf(stderr, "    ==> Got an SCT delivered via X509v3 (CA-signed)\n");
      ++num_signed_sct;
      break;

    case SCT_SOURCE_OCSP_STAPLED_RESPONSE:
      fprintf(stderr, "    ==> Got an SCT delivered via OCSP (CA-signed)\n");
      ++num_signed_sct;
      break;

    case SCT_SOURCE_TLS_EXTENSION:
      fprintf(stderr, "    ==> Got an SCT delivered via TLS extension (not CA-signed)\n");
      break;

    default:
      fprintf(stderr, "    ==> Got an SCT delivered via unknown source (assuming not CA-signed)\n");
      break;
    }
  }

  BIO_free(stderr_bio);
  stderr_bio = NULL;

  if (num_signed_sct <= 0) {
    fprintf(stderr, "No SCTs were received via a CA-signed delivery method, "
            "not considering this connection valid\n");
    return 0;
  }

  fprintf(stderr, "Got %d SCTs of which %d were via CA-signed channels, "
          "considering this connection valid\n", num_sct, num_signed_sct);

  fprintf(stderr, "SCT signatures have NOT been validated\n");

  return 1;
}

/* Configures an arbitrary SSL_CTX to do Expect-CT Lite enforcement. */
static int configure_ct_lite_enforcement(SSL_CTX *ctx)
{

  /*
   * Turn on CT validation and set a custom callback which overrides what we
   * consider valid or not. Note that both of these calls are essential;
   * setting a callback alone is not enough.
   */
  if (!SSL_CTX_enable_ct(ctx, SSL_CT_VALIDATION_STRICT))
    return 0;

  if (!SSL_CTX_set_ct_validation_callback(ctx, on_ct_validation, NULL))
    return 0;

  return 1;
}

int main(int argc, char **argv)
{
  int rc = 1;
  SSL_CTX *ctx = NULL;
  SSL *ssl = NULL;
  BIO *bio = NULL;
  const char *hostname, *bare_hostname;

  /* Parse arguments. */
  if (argc < 2) {
    fprintf(stderr, "usage: %s <hostname:port>\n", argv[0]);
    goto err;
  }

  hostname = argv[1];

  /* The following is just a boilerplate demo for using OpenSSL's TLS
   * functionality and demonstrates a reasonable best practice usage. The
   * Expect-CT Lite specific code is all in configure_ct_lite_enforcement()
   * above. */

  /* Set up our SSL_CTX for making TLS client connections. */
  ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx)
    goto err;

  /* Make sure we enable server certificate verification (IMPORTANT). */
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

  /* Load trusted root CAs. */
  if (!SSL_CTX_set_default_verify_paths(ctx))
    goto err;

  /* Set a minimum safe TLS version. Here we require TLSv1.2, though we could
   * also require TLSv1.3 or later. */
  if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION))
    goto err;

  /* Configure the SSL_CTX for Expect-CT Lite enforcement. */
  if (!configure_ct_lite_enforcement(ctx))
    goto err;

  /* Create a BIO which will do name resolution, TCP connection and SSL object
   * creation for us automatically. */
  bio = BIO_new_ssl_connect(ctx);
  if (!bio)
    goto err;

  if (!BIO_get_ssl(bio, &ssl))
    goto err;

  /* Give the BIO_ssl_connect instance a "hostname:port" string. */
  if (!BIO_set_conn_hostname(bio, hostname))
    goto err;

  /* Ask the BIO_ssl_connect for the hostname part of the "hostname:port"
   * string. */
  bare_hostname = BIO_get_conn_hostname(bio);
  if (!bare_hostname)
    goto err;

  /* Tell SSL what hostname to require on the server's TLS certificate. */
  if (!SSL_set1_host(ssl, bare_hostname))
    goto err;

  /* Do the connection in blocking mode. */
  if (BIO_do_handshake(bio) <= 0)
    goto err;

  fprintf(stderr, "Successfully connected\n");

  /* (An application is responsible for doing what it wants with the connection
   * at this point.) */

  rc = 0;
err:
  if (rc)
    ERR_print_errors_fp(stderr);

  BIO_free_all(bio);
  SSL_CTX_free(ctx);
  return rc;
}
