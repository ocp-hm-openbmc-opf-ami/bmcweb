#pragma once

#include "registries.hpp"

namespace redfish::registries::certificate  {
const Header header = {
    "Copyright 2023 AMI. All rights reserved",
    "#MessageRegistry.v1_5_0.MessageRegistry",
    "CertificateService.1.0.0",
    "CertificateService Message Registry",
    "en",
    "This registry defines the certificate service messages for Redfish",
    "CertificateService",
    "0.0.1",
    "Ami",
};

constexpr std::array registry = {
    MessageEntry{
        "CertificateFileExpired",
        {
            "Certificate file is expired.",
            "Certificate file is expired.",
            "Critical",
            0,
            {},
            "Please check certificate file is expired or not."
        }
    },
    MessageEntry{
        "CertificateFileUntrusted",
        {
            "Certificate File Untrusted.",
            "Certificate File Untrusted.",
            "Critical",
            0,
            {},
            "Please check Certificate File Untrusted."
        }
    },
    MessageEntry{
        "PrivateKeyFileEncrypted",
        {
            "Private key is encrypted/failed to read the private key.",
            "Private key is encrypted/failed to read the private key.",
            "Critical",
            0,
            {},
            "If privatekey file is encrypted."
        }
    },
    MessageEntry{
        "PrivateKeyCertificateFileNotMatch",
        {
            "Publickey/PrivateKey Certificate File Not Match.",
            "Publickey/PrivateKey Certificate File Not Match.",
            "Critical",
            0,
            {},
            "Publickey/PrivateKey Certificate File is not Match."
        }
    },
    MessageEntry{
        "VerifyCertificateFileFailed",
        {
            "Verify Certificate File Failed.",
            "Verify Certificate File Failed.",
            "Critical",
            0,
            {},
            "ASN1_VALIDATION_FAILS"
        }
    },
    MessageEntry{
        "CertificateFileSizeExceeded",
        {
            "Private/public key file size (should be < 4096 bytes).",
            "Private/public key file size (should be < 4096 bytes).",
            "Critical",
            0,
            {},
            "Please check certificate key file size (should be < 10240 bytes)."
        }
    },
    MessageEntry{
        "PrivateKeyFileSizeExceeded",
        {
            "Private key file size (should be < 4096 bytes).",
            "Private key file size (should be < 4096 bytes).",
            "Critical",
            0,
            {},
            "Please check private key file size (should be < 10240 bytes)"
        }
    },
    MessageEntry{
        "CertificateKeyLengthTooSmall",
        {
            "Certificate file is less than minimum allowable size (2048) for https.",
            "Certificate file is less than minimum allowable size (2048) for https.",
            "Critical",
            0,
            {},
            "Please check certifcate key length of the certificate file is less than minimum allowable size (2048) for https."
        }
    },
};

enum class Index {
    certificateFileExpired              = 0,
    certificateFileUntrusted            = 1,
    privateKeyFileEncrypted             = 2,
    privateKeyCertificateFileNotMatch   = 3,
    verifyCertificateFileFailed         = 4,
    certificateFileSizeExceeded         = 5,
    privateKeyFileSizeExceeded          = 6,
    certificateKeyLengthTooSmall        = 7,
};
} // namespace redfish::registries::certificate