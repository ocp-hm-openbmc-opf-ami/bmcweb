// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <memory>
#include <string_view>

namespace redfish
{
namespace ssl_cert_utils
{

using Bio = std::unique_ptr<BIO, decltype(&BIO_free)>;
using Certificate = std::unique_ptr<X509, decltype(&X509_free)>;

// Give OpenSSL's PEM readers access to the in-memory PEM contents.
inline Bio makeBio(std::string_view pem)
{
    return {BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())),
            BIO_free};
}

// Parse the first PEM-encoded X.509 certificate, or return an empty pointer.
inline Certificate readCertificate(std::string_view pem)
{
    Bio bio = makeBio(pem);
    return {bio ? PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)
                : nullptr,
            X509_free};
}

// Check that the certificate's validity period includes the current time.
inline bool isCurrentlyValid(X509* cert)
{
    return X509_cmp_current_time(X509_get0_notBefore(cert)) < 0 &&
           X509_cmp_current_time(X509_get0_notAfter(cert)) > 0;
}

// Accept a current CA certificate that OpenSSL can add to a TLS trust store.
inline bool verifyCaCertificate(std::string_view pem)
{
    Certificate cert = readCertificate(pem);
    if (!cert || X509_check_ca(cert.get()) <= 0 ||
        !isCurrentlyValid(cert.get()))
    {
        return false;
    }

    // Use a temporary client context to check that the CA can be loaded.
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> sslCtx(
        SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    return sslCtx && X509_STORE_add_cert(SSL_CTX_get_cert_store(sslCtx.get()),
                                         cert.get()) == 1;
}

// Accept a current certificate suitable for TLS server use and loadable by SSL.
inline bool verifyServerCertificate(std::string_view pem)
{
    Certificate cert = readCertificate(pem);
    if (!cert || X509_check_ca(cert.get()) > 0 ||
        !isCurrentlyValid(cert.get()) ||
        X509_check_purpose(cert.get(), X509_PURPOSE_SSL_SERVER, 0) != 1)
    {
        return false;
    }

    // Use a temporary server context to check that the certificate can be set.
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> sslCtx(
        SSL_CTX_new(TLS_server_method()), SSL_CTX_free);
    return sslCtx && SSL_CTX_use_certificate(sslCtx.get(), cert.get()) == 1;
}

// Accept an unencrypted PEM private key that OpenSSL can load into a TLS
// context.
inline bool verifyPrivateKey(std::string_view pem)
{
    Bio bio = makeBio(pem);
    if (!bio)
    {
        return false;
    }

    // Returning 0 rejects a password prompt, so encrypted keys are not
    // accepted.
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
        PEM_read_bio_PrivateKey(
            bio.get(), nullptr, [](char*, int, int, void*) -> int { return 0; },
            nullptr),
        EVP_PKEY_free);
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> sslCtx(
        SSL_CTX_new(TLS_server_method()), SSL_CTX_free);

    return key && sslCtx &&
           SSL_CTX_use_PrivateKey(sslCtx.get(), key.get()) == 1;
}

} // namespace ssl_cert_utils
} // namespace redfish
