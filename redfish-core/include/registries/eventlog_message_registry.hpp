// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#pragma once
/****************************************************************
 *                 READ THIS WARNING FIRST
 * This is an auto-generated header which contains definitions
 * for Redfish DMTF defined messages.
 * DO NOT modify this registry outside of running the
 * parse_registries.py script.  The definitions contained within
 * this file are owned by DMTF.  Any modifications to these files
 * should be first pushed to the relevant registry in the DMTF
 * github organization.
 ***************************************************************/
#include "registries.hpp"

#include <array>

// clang-format off

namespace redfish::registries::eventlog
{
const Header header = {
    "Copyright 2023 OpenBMC. All rights reserved.",
    "#MessageRegistry.v1_4_0.MessageRegistry",
    1,
    0,
    0,
    "Security Message Registry",
    "en",
    "This registry defines the base messages for Security.",
    "EventLog",
    "EventLog",
};
constexpr std::array registry =
{
		MessageEntry{
        "ResourceAdded",
        {
            "Indicates that a resource was added successfully.",
            "The resource at %1 was successfully added.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
		MessageEntry{
        "ResourceUpdated",
        {
            "Indicates that a resource was successfully updated.",
            "The value of attribute %1 at %2 was successfully updated from %3 to %4.",
            "OK",
            4,
            { "string","string","string","string" },
            "None",
        }},
		MessageEntry{
        "ResourceRemoved",
        {
            "Indicates that a resource was successfully removed.",
            "The resource at %1 was successfully removed.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
		MessageEntry{
        "StatusChange",
        {
            "Indicates that the status of a resource has changed.",
            "The status %1 of resource at %2 has changed from %3 to %4",
            "Critical",
            4,
            { "string","string","string","string" },
            "None.",
        }},
		MessageEntry{
        "Alert",
        {
            "Indicates that a condition exists which requires attention.",
            "%1 - %2 action was triggered which requires attention",
            "OK",
            2,
            {"string","string"},
            "None.",
        }},
		MessageEntry{
        "TriggerAlert",
        {
            "The trigger condition '%1' under the resource '%2' was triggered for the MetricProperty '%3' with a Value '%4' which requires attention.",
            "The trigger condition '%1' under the resource '%2' was triggered for the MetricProperty '%3' with a Value '%4' which requires attention.",
            "Critical",
            4,
            {"string","string","string","string"},
            "None.",
        }},
		
		
};

enum class Index
{
	resourceAdded = 1,
	resourceUpdated = 2,
	resourceRemoved = 3,
	statusChange = 4,
	alert = 5,
	triggerAlert  = 6
};
} // namespace redfish::registries::openbmc
