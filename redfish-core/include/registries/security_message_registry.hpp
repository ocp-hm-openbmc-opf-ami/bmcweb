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

namespace redfish::registries::security
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
    "Security",
    "Security",
};
constexpr std::array registry =
{
		MessageEntry{
        "Alert",
        {
            "Indicates that a condition exists which requires attention",
            "%1 - %2 action was triggered which requires attention",
            "OK",
            2,
            {
                "string",
				"string"
            },
            "None.",
        }},
		MessageEntry{
        "ResourceModified",
        {
            "Indicates that the resource at a given URI was successfully modified.",
            "The value of attribute %1 at %2 was successfully updated from %3 to %4.",
            "OK",
            4,
            {
                "string",
				"string",
				"string",
				"string"
            },
            "None.",
        }},
		MessageEntry{
        "LoginFailure",
        {
            "Indicates that there was an error while attempting to login",
            "Login for user %1 was a failure because %2",
            "Critical",
            2,
            {
                "string",
				"string"
            },
            "Verify that the login credentials are correct",
        }},
		MessageEntry{
        "LoginSuccess",
        {
            "Indicates that the login attempt was successful.",
            "Login for user %1 using %2 authentication was a success.",
            "OK",
            2,
            {
                "string",
				"string"
            },
            "None.",
        }},
		MessageEntry{
        "UserLogOff",
        {
            "Indicates that the log-off attempt was successful.",
            "User %1 is now logged off.",
            "OK",
            1,
            {
                "string"
            },
            "None.",
        }},
		MessageEntry{
        "SessionExpired",
        {
            "Indicates that a session has been inactive for a period and will now be invalidated.",
            "Invalidating session for user %1.",
            "OK",
            1,
            {
                "string"
            },
            "None.",
        }},MessageEntry{
        "AccessAllowed",
        {
            "Indicates that the service has allowed access, connection to or transfer to/from another resource.",
            "Access to the resource located at %1 was allowed.",
            "OK",
            1,
            {
                "string"
            },
            "None.",
        }},
		MessageEntry{
        "AccessDenied",
        {
            "Indicates that while attempting to access, connect to or transfer to/from another resource, the service was denied access.",
            "While attempting to establish a connection to %1, the service was denied access.",
            "Critical",
            1,
            {
                "string"
            },
            "Attempt to ensure that the URI is correct and that the service has the appropriate credentials.",
        }},
		MessageEntry{
        "ResourceCreated",
        {
            "Indicates that the resource was successfully created at a given URI.",
            "The resource at %1 has been successfully created.",
            "OK",
            1,
            {
                "string"
            },
            "None.",
        }},
		MessageEntry{
        "ResourceDeleted",
        {
            "Indicates that the resource at a given URI was successfully deleted.",
            "The resource at %1 has been successfully deleted.",
            "OK",
            1,
            {
                "string"
            },
            "None.",
        }},
		MessageEntry{
        "InsufficientPrivilege",
        {
            "Indicates that the credentials associated with the established session do not have sufficient privileges for the requested operation",
            "There are insufficient privileges for the account or credentials associated with the current session to perform the requested %1 operation at %2.",
            "Critical",
            2,
            {
                "string",
				"string"
            },
            "None.",
        }},
		MessageEntry{
        "ResourceNotWritable",
        {
            "Indicates that a request is trying to modify a resource, but the resource cannot be modified.",
            "The resource at %1 cannot be modified.",
            "Warning",
            1,
            {
                "string"
            },
            "Do not try to modify this resource",
        }},
		MessageEntry{
        "InsufficientPrivilegeForProperty",
        {
            "Indicates that the credentials associated with the established session do not have sufficient privileges to modify this property",
            "There are insufficient privileges for the account or credentials associated with the current session to modify the property %1",
            "Critical",
            1,
            {
                "string",
				"string",
				"string",
				"string"
            },
            "Either abandon the operation or change the associated access rights and resubmit the request if the operation failed.",
        }},
		MessageEntry{
        "FWUpdateInProgress",
        {
            "Service is forbidden caused by FWUpdateInProgress",
            "The server is now in firmware update, please access the server after the firmware update is finished.",
            "Critical",
            0,
            {},
            "Access the service after FWUpdateInProgress is finished.",
        }},
		
};

enum class Index
{
	alert = 1,
	resourceModified = 2,
	loginFailure = 3,
	loginSuccess = 4,
	userLogOff = 5,
	sessionExpired  = 6,
	accessAllowed = 7,
	accessDenied = 8,
	resourceCreated = 9,
	resourceDeleted = 10,
	insufficientPrivilege = 11,
	resourceNotWritable = 12,
	insufficientPrivilegeForProperty = 13,
	fWUpdateInProgress = 14
};
} // namespace redfish::registries::openbmc
