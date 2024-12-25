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
            "Indicates that the certificate file expired.",
            "The certificate file expired.",
            "Critical",
            0,
            {},
            "Please make sure the certificate is correct for SSL server usage and it should not expire or be encrypted."
        }
    },
    MessageEntry{
        "CertificateFileUntrusted",
        {
            "Indicates that the certificate file is untrusted.",
            "The certificate file is untrusted, it can not used for the server certificate.",
            "Critical",
            0,
            {},
            "Please make sure the certificate is correct for SSL server usage and it should not expire or be encrypted."
        }
    },
    MessageEntry{
        "PrivateKeyFileEncrypted",
        {
            "Indicates that the private key file is encrypted.",
            "The private key file is encrypted. PEM pass phrase encrypted certificates are not supported.",
            "Critical",
            0,
            {},
            "Please make sure the certificate is correct for SSL server usage and it should not expire or be encrypted."
        }
    },
    MessageEntry{
        "PrivateKeyCertificateFileNotMatch",
        {
            "Indicates that the certificate file and private key file are not matched.",
            "The certificate file and private key file are not matched.",
            "Critical",
            0,
            {},
            "Please make sure the certificate file and private key file are correct and resubmit the request."
        }
    },
    MessageEntry{
        "VerifyCertificateFileFailed",
        {
            "Indicates that the certificate file validate asn1 failed.",
            "The certificate file validate asn1 failed.",
            "Critical",
            0,
            {},
            "Please make sure the certificate is correct for SSL server usage and it should not expire or be encrypted."
        }
    },
    MessageEntry{
        "CertificateFileSizeExceeded",
        {
            "Indicates that the size of the certificate file exceeded the maximum allowable size.",
            "The size of certificate file has exceeded the maximum allowable size 4096 bytes.",
            "Critical",
            0,
            {},
            "Reduce the size of the certificate file or increase the size of default allowable size and resubmit the request."
        }
    },
    MessageEntry{
        "PrivateKeyFileSizeExceeded",
        {
            "Indicates that the size of the private key file exceeded the maximum allowable size.",
            "The size of private key file has exceeded the maximum allowable size 4096 bytes.",
            "Critical",
            0,
            {},
            "Reduce the size of the private key file or increase the size of default allowable size and resubmit the request."
        }
    },
    MessageEntry{
        "CertificateKeyLengthTooSmall",
        {
            "Indicates that the key length of the certificate file is less than minimum allowable size.",
            "The key length of the certificate file is less than minimum allowable size 2048 bit.",
            "Critical",
            0,
            {},
            "Increase the key length of the certificate file or reduce the key length of default allowable size and resubmit the request."
        }
    },
    MessageEntry{
        "InvalidTypeForCertificateString",
        {
            "Indicates that the validation of CertificateType for the given CertificateString failed.",
            "The CertificateType %1 didn't match to the CertificateString in request body.",
            "Critical",
            1,
            {"string"},
            "Please make sure the CertificateType is correct and match to the given CertificateString."
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
    invalidTypeForCertificateString     = 8,
};
} // namespace redfish::registries::certificate