/*
// Copyright 2020 Intel Corporation.

// This software and the related documents are Intel copyrighted materials,
// and your use of them is governed by the express license under which they
// were provided to you ("License"). Unless the License provides otherwise,
// you may not use, modify, copy, publish, distribute, disclose or transmit
// this software or the related documents without Intel's prior written
// permission.

// This software and the related documents are provided as is, with
// no express or implied warranties, other than those that are expressly
// stated in the License.
*/

#pragma once
#include <registries.hpp>

namespace redfish::registries::nm
{
const Header header = {
    "Copyright 2021 Intel. All rights reserved.",
    "#MessageRegistry.v1_4_0.MessageRegistry",
    0,
    1,
    0,
    "NodeManager Message Registry",
    "en",
    "This registry defines the NodeManager messages for OpenBMC.",
    "NodeManager",
    "Intel",
};
constexpr std::array<MessageEntry, 9> registry = {
    MessageEntry{"NmStopping",
                 {
                     "Indicates SPS NodeManager is Enabled.",
                     "SPS NodeManager enabled, stopping OpenBMC NodeManager.",
                     "OK",
                     0,
                     {},
                     "None.",
                 }},
    MessageEntry{
        "NmUnableToDisableSpsNm",
        {
            "Indicates problems with disabling the SPS NodeManager.",
            "Unable to disable the SPS NodeManager, stopping OpenBMC NodeManager.",
            "Critical",
            0,
            {},
            "None.",
        }},
    MessageEntry{
        "NmInitializationMode3",
        {
            "Indicates that OpenBMC NodeManager is disabled by configuration settings.",
            "NodeManager initialization mode is set to 3, stopping OpenBMC NodeManager unconditionally.",
            "OK",
            0,
            {},
            "None.",
        }},
    MessageEntry{
        "NmLimitExceptionOccurred",
        {
            "Indicates that Policy Limit Exception occurred in NodeManager.",
            "NodeManager reports limit exception for policy: %1",
            "Warning",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "NmInitializeSoftShutdown",
        {
            "Indicates that the NodeManager is about to initialize platform shutdown.",
            "NodeManager is about to initiate soft shutdown within next 30s.",
            "OK",
            0,
            {},
            "None.",
        }},
    MessageEntry{"NmPowerShutdownFailed",
                 {
                     "Indicates that platform shutdown has failed.",
                     "NodeManager was unable to shutdown platform.",
                     "Warning",
                     0,
                     {},
                     "None.",
                 }},
    MessageEntry{
        "NmPolicyAttributeAdjusted",
        {
            "Indicates that some policy attributes of the NodeManager were adjusted.",
            "NodeManager reports some attributes adjustment for policy: %1",
            "Warning",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "NmReadingMissing",
        {
            "Indicates that some required reading used by the NodeManager is missing.",
            "NodeManager reports disappearance of required reading type: `%1`",
            "Warning",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{"NmPolicyAttributeIncorrect",
                 {
                     "Indicates that some policy attributes of the NodeManager "
                     "are incorrect.",
                     "NodeManager reports some attributes for policy %1 were "
                     "incorrect. Error description: %2",
                     "Warning",
                     2,
                     {"string", "string"},
                     "None.",
                 }}};
} // namespace redfish::registries::nm
