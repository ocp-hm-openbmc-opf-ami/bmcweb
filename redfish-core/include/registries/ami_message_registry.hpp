// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#pragma once
/****************************************************************
 * This header contains definitions for AMI custom Redfish messages.
 ***************************************************************/
#include "registries.hpp"

#include <array>

// clang-format off

namespace redfish::registries::custom
{
const Header header = {
    "Copyright 2023 OpenBMC. All rights reserved.",
    "#MessageRegistry.v1_4_0.MessageRegistry",
    1,
    0,
    0,
    "AMI Custom Message Registry",
    "en",
    "This registry defines the AMI custom messages.",
    "AMI",
    "AMI",
};
constexpr std::array registry =
{
    MessageEntry{
        "invalidImageSize",
        {
            "Indicates that the image provided is invalid or the image size is less than the required minimum size.",
            "The image provided is invalid or the image size is less than 600KB.",
            "Critical",
            0,
            {},
            "Ensure that the image is valid with size greater than 600KB and resubmit the request.",
        }},
    MessageEntry{
        "dumpQuotaExceeded",
        {
            "Indicates that the maximum number of dump records has been reached or the dump storage is full.",
            "The dump cannot be created because either the MaxNumberOfRecords (150) has been reached or the available dump storage (1024 KB) is insufficient.",
            "Critical",
            0,
            {},
            "Delete existing dump files to free space, then retry the request.",
        }},
    MessageEntry{
        "FirmwareUpdateFailed",
        {
            "The firmware image validation timed out.",
            "This may be due to an invalid firmware image or D-Bus service unavailability.",
            "Warning",
            0,
            {},
            "The firmware image may be invalid or the D-Bus service is currently unavailable. Please check the format and try again later.",
        }},
    MessageEntry{
        "PasswordCorruption",
        {
            "Indicates that the password authentication token is corrupted in the system.",
            "Password authentication token corruption detected. The system encountered an internal error while processing the password.",
            "Critical",
            0,
            {},
            "Contact the system administrator. The password storage may be corrupted and require system maintenance.",
        }},
};

enum class Index
{
    invalidImageSize = 0,
    dumpQuotaExceeded = 1,
    firmwareUpdateFailed = 2,
    passwordCorruption = 3,
};
} // namespace redfish::registries::custom
 