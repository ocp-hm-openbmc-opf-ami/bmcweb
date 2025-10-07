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

namespace redfish::registries::ami
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
    "Ami",
    "Ami",
};
constexpr std::array registry =
{
		MessageEntry{
        "PropertyValueSizeNotMatched",
        {
            "Indicates that a property was given the wrong number of value[s], such as more or less number of arguments are supplied for a property.",
            "The value %1 for the property %2 is of a different number of argument[s] than the property can accept.",
            "Warning",
            2,
            {"string","string"},
            "Correct the value for the property in the request body and resubmit the request if the operation failed.",
        }},
		MessageEntry{
        "PropertyValueNotEqual",
        {
            "Indicates that property value is not equal.",
            "The value %1 for the property %2 is different from the value %3 for the property %4.",
            "Warning",
            4,
            { "string","string","string","string"},
            "Make Sure both the properties have same value in the request body and resubmit the request",
        }},
		MessageEntry{
        "PropertyValueRequiredFirstTime",
        {
            "Indicates that property value is not set first time.",
            "The Property %1 is required to be configured first time.",
            "Warning",
            1,
            {"string"},
            "Make Sure the property is Set First time",
        }},
		MessageEntry{
        "CannotUseStandardTCPPorts",
        {
            "Indicates that property value is one of the standard TCP Port that can't be used.",
            "The value %1 for Property %2 is one of the standard TCP Ports that cannot be used.",
            "Warning",
            2,
            { "string","string"},
            "Correct the value for the property in request body and resubmit the request.",
        }},
		MessageEntry{
        "OffsetValueFormatError",
        {
            "Indicates that a property was given the correct value type but the value of that offset was not supported. This is an invalid offset.",
            "The offset value %1 for the property %2 is of a different format than the property can accept. Accepts the minutes which are divisible by 15.",
            "Warning",
            2,
            {"string","string"},
            "Correct the value for the property in the request body and resubmit the request if the operation failed.",
        }},
		MessageEntry{
        "DuplicateOffsetFound",
        {
            "Indicates that the properties were given might be correct but different offset are not supported.",
            "The value %1(with Offset) of property %2 and value %3 of property %4 are different, can't be accept at a time.",
            "Warning",
            4,
            {"string","string","string","string"},
            "Correct the value for the properties in the request body and resubmit the request if the operation failed.",
        }},
		MessageEntry{
        "ActionRequiresFile",
        {
            "Indicates that the action needs a file to be uploaded before proceeding this action.",
            "It needs a mandatory file to be uploaded before proceeding the action.",
            "Warning",
            0,
            {},
            "Upload the required file using the appropriate action and resubmit the request with proper request body.",
        }},
		MessageEntry{
        "Licenserequire",
        {
            "Indicates that the License validity might be not available or expired.",
            "Operation failed because %1 License would have been expired or not available.",
            "Warning",
            1,
            {"string"},
            "Retry the action with valid RMedia License.",
        }},
		MessageEntry{
        "QueryParameterFormatError",
		{
           "Indicates that a query parameter was given in a wrong format, such as when the value is not supplied or missing '=' or '$'or when the qameter itself is missing.",
            "The format of the query parameter request %1 is wrong. General format is url followed by ?$query1=value1&$query2=value2&..",
            "Warning",
            1,
            {"string"},
            "Correct the format of the query parameter in the request and resubmit the request if the operation failed.",
        }},
		MessageEntry{
        "ServiceDisabled",
        {
            "Indicates that the operation failed because this particular service is disabled and cannot accept additional requests.",
            "The operation failed because this service is disabled and can no longer take incoming requests.",
            "Critical",
            0,
            {},
            "Enable the service and resubmit the request.",
        }},
		MessageEntry{
        "QueryParameterOnlyFormatError",
        {
            "Indicates that a query parameter was given in a wrong format, 'only' query parameter can't include invalid punctuation marks.",
            "The format of the query parameter request %1 is wrong. General format is url followed by ?only.",
            "Warning",
            1,
            {"string"},
            "Correct the format of the query parameter in the request and resubmit the request if the operation failed.",
        }},
		MessageEntry{
        "QueryParameterExcerptFormatError",
        {
            "Indicates that a query parameter was given in a wrong format, 'excerpt' query parameter can't include invalid punctuation marks.",
            "The format of the query parameter request %1 is wrong. General format is url followed by ?excerpt",
            "Warning",
            1,
            {"string"},
            "Correct the format of the query parameter in the request and resubmit the request if the operation failed.",
        }},
		MessageEntry{
        "ServiceEnabled",
        {
            "Indicates that the operation failed because %1 service is enabled and cannot accept additional requests.",
            "The operation failed because %1 service is enabled and can no longer take incoming requests.",
            "Critical",
            1,
            {"string"},
            "Disable the service and resubmit the request.",
        }},
		MessageEntry{
        "HostInterfaceStatus",
        {
            "Indicates that Request was given through normal interface, not through Host Interface.",
            "Request was given through normal interface, not through Host Interface.",
            "Critical",
            0,
            {},
            "Ensure that patch operation is sent through hostinterface.",
        }},
		MessageEntry{
        "ModifyingValues",
        {
            "Indicates that the values are being modified in the Interface.",
            "Modifying the values. It may take a few seconds for the changes to reflect.",
            "OK",
            0,
            {},
            "Wait a few seconds before sending additional requests to this resource.",
        }},
		MessageEntry{
        "PropertiesMustHaveSameValue",
        {
            "Indicates that the values Properties must be Equal.",
            "The values provided for %1 and %2 must be same",
            "Warning",
            2,
            {"string","string"},
            "Provide same values for both the properties and try again.",
        }},
		MessageEntry{
        "InventoryDataIncomplete",
        {
            "Indicates that the BIOS Inventory data is not completely transferred to BMC.",
            "The BIOS Inventory data was partially populated due to CONf space limitation or due to timeout between BIOS, BMC communication.",
            "Critical",
            0,
            {},
            "Clean up Redfish/BMC data.",
        }},
		MessageEntry{
        "CertificateDataIncomplete",
        {
            "Indicates that the BIOS Inventory data is not completely transferred to BMC.",
            "The certificate processing is incomplete due to error or due to timeout between BIOS, BMC communication.",
            "Critical",
            0,
            {},
            "Reboot Host to start processing again.",
        }},
		MessageEntry{
        "PreconditionHeaderMissing",
        {
            "Indicates that the server requires the request to be conditional for PUT/PATCH.",
            "The request did not provide the required precondition, such as an If-Match or If-None-Match header.",
            "Critical",
            0,
            {},
            "Include the required precondition header in the request.",
        }},
		MessageEntry{
        "InsufficientStorageForResponse",
        {
            "Indicates that the service is unable to return the payload due to its size",
            "The server is unable to build the response for the client due to the size of the response.",
            "Critical",
            0,
            {},
            "Remove the $expand query parameter from the request and resubmit.",
        }},
		MessageEntry{
        "AuthenticationDisabled",
        {
            "Indicates that the Authentication support for this interface is disabled.",
            "The operation failed because the %1 Authentication for this Interface is Disabled.",
            "Critical",
            1,
            {"string"},
            "Enable the %1 Authentication and resubmit the request.",
        }},
		MessageEntry{
        "QueryParameterIgnored",
        {
            "Indicates that the Query parameter is ignored as the Query Expression is invalid.",
            "%1 query parameter for %2 is ignored as the query expression is invalid or cannot be processed.",
            "Warning",
            2,
            {"string","string"},
            "Correct the Query Expression and resubmit the request.",
        }},
		MessageEntry{
        "QueryParameterFailed",
        {
            "Indicates that the Request with Query parameter failed as the Query Expression is invalid",
            "%1 query parameter for %2 failed as the query expression is invalid or cannot be processed",
            "Warning",
            2,
            {"string","string"},
            "Correct the Query Expression and resubmit the request.",
        }},
		MessageEntry{
        "FilterOptionsNotSupported",
        {
            "Indicates that the filter of options use unsupported expression",
            "%1 query parameter for %2 failed with unsupported operations or functions. The filter options only supported '()、and、not、or、eq、ge、gt、le、lt、ne' these options.",
            "Warning",
            2,
            {"string","string"},
            "Correct the filter options and resubmit the request.",
        }},
		MessageEntry{
        "PropertyOutOfRange",
        {
            "Indicates that a property supplied was out of range. This can happen with values that are too low or beyond that possible for the supplied resource.",
            "The value %1 for the property %2 is out of range %3.",
            "Warning",
            3,
            {"string","string","string"},
            "Make sure the value is inside the range for the property and resubmit the request.",
        }},MessageEntry{
        "PropertyLimit",
        {
            "Indicates that a property doesn't follow limit of the property.",
            "The value %1 for the property %2 doesn't follow the %3 property limit %4.",
            "Warning",
            4,
            {"string","string","string","string"},
            "Make sure the value follows the property limit.",
        }},
		MessageEntry{
        "LastExistingAccount",
        {
            "Indicates that the modification was requested on only existing account with sufficient privileges",
            "Cannot modify/Disable the property %1 of the only %2 account.",
            "Warning",
            2,
            {"string","string"},
            "The modification may have failed due to non-availability of another account with sufficient privileges.",
        }},MessageEntry{
        "UserNameAlreadyExists",
        {
            "Indicates that modification was requested with a UserName which already exists.",
            "The requested UserName already exists.",
            "Critical",
            0,
            {},
            "Change the UserName and resubmit the request.",
        }},MessageEntry{
        "PropertyValueMismatch",
        {
            "Indicates that a dependent property was given wrong value.",
            "The property %1 must have value %2 to complete this operation.",
            "Warning",
            2,
            {"string","string"},
            "Correct the value for the property in the request body and resubmit the request if the operation failed.",
        }},MessageEntry{
        "PropertyCannotExistInRequestBody",
        {
            "Indicates that an invalid property was passed in the request body.",
            "To complete this operation, the property %1 cannot exist in the request body when the property %2 has a value %3.",
            "Warning",
            3,
            {"string","string","string"},
            "Remove the invalid property from the request body and resubmit the request if the operation failed.",
        }},MessageEntry{
        "PasswordChangeRequired",
        {
            "Indicates that the password for the account provided must be changed before accessing the service.  The password can be changed with a PATCH to the 'Password' property in the ManagerAccount resource instance.  Implementations that provide a default password for an account may require a password change prior to first access to the service.",
            "The password provided for this account must be changed before access is granted.  PATCH the 'Password' property for this account located at the target URI '%1' to complete this process.",
            "Critical",
            1,
            {"string"},
            "Change the password for this account using a PATCH to the 'Password' property at the URI provided.",
        }},MessageEntry{
        "KVMActionExist",
        {
            "KVM/Media Redirection is in progress, so this post call action is Restricted",
            "KVM/Media Redirection is in progress, so unable to perform this action",
            "Warning",
            0,
            {},
            "Please try again after the KVM/Media redirection is completed.",
        }},MessageEntry{
        "ActionExist",
        {
            "InsertMedia Action is already Issued or InProgress, so action Post call is Restricted",
            "InsertMedia Action is already Issued or InProgress",
            "Warning",
            0,
            {},
            "Execute EjectMedia action for this VMedia Instance.",
        }},
		MessageEntry{
        "ActionNotExist",
        {
            "No Redirection is going on for the given media instance, so action Post call is Restricted",
            "No Redirection is going on for the given media",
            "Warning",
            0,
            {},
            "Execute InsertMedia action for this VMedia Instance.",
        }},
		MessageEntry{
        "CreateLimitReachedForMetricReportsResource",
        {
            "Indicates that no more resources can be created on the Metric Reports resource as it has reached its create limit.",
            "The create operation failed because the MetricReports resource %1 has reached the limit of possible resources.",
            "Critical",
            1,
            {"string"},
            "Either delete the MetricReports resource by deleting the corresponding MetricReportDefinition and resubmit the request if the operation failed or do not resubmit the request.",
        }},
		MessageEntry{
        "DelayInActionCompletion",
        {
            "Action has been initiated successfully. Allow up to 4-5 seconds for the action to complete",
            "%1 action has been initiated successfully. Please allow up to 4-5 seconds and verify the value of %2 property in %3 instance",
            "OK",
            3,
            {"string","string","string"},
            "Check the property value update after 4-5 seconds.",
        }},
		MessageEntry{
        "RequestBodySizeExceeded",
        {
            "Indicates that request body size exceeds the allowable size.",
            "Request Body size exceeds the default allowable size %1KB.",
            "Critical",
            1,
            {"string"},
            "Reduce the size of the request body and resubmit the request.",
        }},
		MessageEntry{
        "PropertyValueSizeExceeded",
        {
            "Indicates that the size of the property value exceeded the maximum allowable size.",
            "The value %1 for the property %2 have exceeded the maximum allowable string size.",
            "Warning",
            2,
            {"string","string"},
            "Reduce the size of the property value or increase the size of default allowable string size and resubmit the request.",
        }},
		MessageEntry{
        "AlreadyScheduledTask",
        {
            "Indicates that the task has already been scheduled at the same time.",
            "The task has already been scheduled at the time %1.",
            "Warning",
            1,
            {"string"},
            "Reschedule the task at different time and resubmit the request.",
        }},MessageEntry{
        "MaintenanceWindowIncorrectTime",
        {
            "Indicates that the time is in the past.",
            "The time value %1 for the property %2 is in the past.",
            "Warning",
            2,
            {"string","string"},
            "Change the time value to the upcoming or future time and resubmit the request.",
        }},MessageEntry{
        "EmptyObjectOrArrayInRequest",
        {
            "Indicates that the value for the given JSON request parameter is empty",
            "The value for the given property is either an empty Object or Array. Please specify a valid value for this property.",
            "Critical",
            0,
            {},
            "Ensure that the value for the given request body parameter is not empty and resubmit the request.",
        }},MessageEntry{
        "EmptyObjectOrArrayInRequestSpecific",
        {
            "Indicates that the value for the given JSON request parameter is empty",
            "The value for %1 is either an empty Object or Array. Please specify a valid value for this property.",
            "Critical",
            1,
            {"string"},
            "Ensure that the value for the given request body parameter is not empty and resubmit the request.",
        }},MessageEntry{
        "PasswordResetFailed",
        {
            "Old Password Not Accepted",
            "Last password cannot be used to reset the redfish account password. Please change the password value and resubmit the request.",
            "Critical",
            0,
            {},
            "Change the password value and resubmit the request.",
        }},MessageEntry{
        "LimitExceeded",
        {
            "Unable to process the request as the given %1 size exceeds the maximum allowed value",
            "Maximum %2 %1 can be configured. The value for the given property exceeds the maximum allowed value. Please Change the value of the property and resubmit the request.",
            "Warning",
            2,
            {"string","string"},
            "Change the value of the property and resubmit the request.",
        }},MessageEntry{
        "MetricReportDefinitionReportDoesNotSupportEvent",
        {
            "Report Action for the MetricReportDefinition does not have RedfishEvent as its ReportAction.",
            "The requested MetricReportDefinition %1 does not support RedfishEvent as its ReportAction",
            "Warning",
            1,
            {"string"},
            "Change the value of the property and resubmit the request.",
        }},MessageEntry{
        "UserModifiedData",
        {
            "Indicates that the data under this URI have been updated by user and require Host Systems reboot to apply.",
            "The data under this URI have been updated by user and require Host Systems reboot to apply",
            "Warning",
            0,
            {},
            "Perform a Host Systems reboot to apply the new settings.",
        }},MessageEntry{
        "DisablingLocalAccountAuthFailed",
        {
            "Disabling LocalAccountAuth cannot be accepted",
            "PAM might be disabled or external account provider like LDAP or AD or RADIUS service is disabled.",
            "Critical",
            0,
            {},
            "Please make sure PAM is enabled in redfish service and any of the external account provider(LDAP, AD, RADIUS) service is enabled",
        }},MessageEntry{
        "ServiceTemporarilyUnavailableDueToHostBooting",
        {
            "Indicates the operation is temporarily unavailable since Host Reboot is in Progress or Host is in BiosSetup.",
            "The requested operation is temporarily unavailable since Host System Reboot might be in progress or Host might be in Bios Setup or Redfish Inventory processing might be in progress. Please try after some time.",
            "Critical",
            0,
            {},
            "Retry after some time.",
        }},
		MessageEntry{
        "ActionNotSupported",
        {
            "The action cannot be applied since it's in same state",
            "Unable to perform %3 operation on the Host Machine since %2 is already in %1 state !!",
            "Warning",
            3,
            {"string","string","string"},
            "Resubmit the request with appropriate state.",
        }},
		MessageEntry{
        "InvalidOffsetValue",
        {
            "Indicates that the Offset value was in the UTC offset allowable range but value was Invalid.",
            "The value %1 for the property %2 is not allowable.",
            "Critical",
            2,
            {"string","string"},
            "Make sure the offset value is inside the range for the property and resubmit the request.",
        }},
		MessageEntry{
        "OffsetValueOutofRange",
        {
            "Indicates that the offset value was out of range. This can happen with values that are too low or beyond those possible allowable values of UTC offset.",
            "The value %1 for the property %2 is out of range.",
            "Critical",
            2,
            {"string","string"},
            "Make sure the offset value is inside the range for the property and resubmit the request",
        }},
		MessageEntry{
        "ServerAddressFormatError",
        {
            "Indicates that the Server Address specified is not a valid format",
            "The Server Address, '%1' specified for the property %2 is not a valid format!!",
            "Warning",
            2,
            {"string","string"},
            "Resubmit the request with appropriate server address (Supported formats are ipv4 and ipv6). Enter a FQDN address if using StartTLS with FQDN.",
        }},MessageEntry{
        "ServerPasswordFormatError",
        {
            "Indicates that the password specified is not a valid format",
            "Indicates that the password specified is not a valid format",
            "Warning",
            0,
            {},
            "Password must be at least 1 character long. White space is not allowed and password more than 47 characters are not allowed. Resubmit the request with correct password.",
        }},
		MessageEntry{
        "SMTPPasswordFormatError",
        {
            "Indicates that the SMTP password specified is not a valid format",
            "Indicates that the SMTP password specified is not a valid format",
            "Warning",
            0,
            {},
            "Password must be at least 4 character long. White space is not allowed and password more than 64 characters are not allowed. Resubmit the request with correct password.",
        }},
		MessageEntry{
        "SMTPUsernameFormatError",
        {
            "Indicates that the SMTP Username specified is not a valid format",
            "Indicates that the SMTP Username specified is not a valid format",
            "Warning",
            0,
            {},
            "Username must be at least 4 character long. White space is not allowed and Username more than 64 characters are not allowed. Resubmit the request with correct username.",
        }},
		MessageEntry{
        "SMTPAddressError",
        {
            "Indicates that the SMTP Address specified is not a valid format",
            "Indicates that the SMTP Address specified is not a valid format",
            "Warning",
            0,
            {},
            "White space is not allowed and Address more than 64 characters are not allowed. Valid Email Format is needed. Resubmit the request with correct username.",
        }},
		MessageEntry{
        "ServerUsernameFormatError",
        {
            "Indicates that the username specified is not a valid format",
            "Indicates that the username specified is not a valid format",
            "Warning",
            0,
            {},
            "Username is a string of 4 to 253 alpha-numeric characters. Special symbols such as: dot(.), comma(,), hyphen(-), underscore(_), equal-to(=) are allowed. Resubmit the request with correct password.",
        }},
		MessageEntry{
        "LDAPSearchBaseFormatError",
        {
            "Indicates that the BaseDistinguishedNames specified is not a valid format",
            "Indicates that the BaseDistinguishedNames specified is not a valid format",
            "Warning",
            0,
            {},
            "BaseDistinguishedNames is a string of 4 to 253 alpha numeric characters. Resubmit the request with correct BaseDistinguishedNames.",
        }},
		MessageEntry{
        "LDAPRemoteGroupFormatError",
        {
            "Indicates that the RemoteGroup specified is not a valid format",
            "Indicates that the RemoteGroup specified is not a valid format",
            "Warning",
            0,
            {},
            "RemoteGroup is a string of 64 alpha-numeric characters. Special symbols hyphen and underscore are allowed. Resubmit the request with correct RemoteGroup.",
        }},
		MessageEntry{
        "LDAPRemoteUserFormatError",
        {
            "Indicates that the RemoteUser specified is not a valid format",
            "Indicates that the RemoteUser specified is not a valid format",
            "Warning",
            0,
            {},
            "RemoteUser is a string of 255 alpha-numeric characters. Special Symbols like dot(.), comma(,), hyphen(-), underscore(_), equal-to(=) are allowed. Resubmit the request with correct RemoteUser.",
        }},MessageEntry{
        "ActiveDirectoryPasswordFormatError",
        {
            "Indicates that the password specified is not a valid format",
            "Indicates that the password specified is not a valid format",
            "Warning",
            0,
            {},
            "Password must be at least 6 character long. White space is not allowed and password more than 127 characters are not allowed. Resubmit the request with correct password.",
        }},MessageEntry{
        "ActiveDirectoryUsernameFormatError",
        {
            "Indicates that the ActiveDirectory username specified is not a valid format",
            "Indicates that the ActiveDirectory username specified is not a valid format",
            "Warning",
            0,
            {},
            "Username is a string of 1 to 64 alpha-numeric characters. Special symbols and white space not allowed. Resubmit the request with correct Username.",
        }},MessageEntry{
        "ActiveDirectoryRemoteGroupFormatError",
        {
            "Indicates that the RemoteGroup specified is not a valid format",
            "Indicates that the RemoteGroup specified is not a valid format",
            "Warning",
            0,
            {},
            "RemoteGroup is a string of 255 alpha-numeric characters. Special symbols hyphen(-) and underscore(_) are allowed. Resubmit the request with correct RemoteGroup.",
        }},MessageEntry{
        "ActiveDirectoryRemoteUserFormatError",
        {
            "Indicates that the RemoteUser specified is not a valid format",
            "Indicates that the RemoteUser specified is not a valid format",
            "Warning",
            0,
            {},
            "RemoteUser is a string of 255 alpha-numeric characters. Special Symbols like dot(.), hyphen(-), underscore(_) are allowed. Resubmit the request with correct RemoteUser.",
        }},MessageEntry{
        "ServiceTemporarilyUnavailableDueToMutex",
        {
            "Indicates the service is temporarily unavailable.",
            "The service is temporarily unavailable.  Retry in %1 seconds. %2",
            "Critical",
            2,
            {"string","string"},
            "Wait for the indicated retry duration and retry the operation.",
        }},
		MessageEntry{
        "AMILDAPCertificateUploadFailed",
        {
            "Indicates that the LDAP certificates upload is failed.",
            "The value %1 for the property %2 is not valid.",
            "Critical",
            2,
            {"string","string"},
            "Please make sure to give the correct certificate id by creating it using URI, /AccountService/LDAP/Certificates",
        }},
		MessageEntry{
        "AMILDAPAccountCreationFailed",
        {
            "Indicates that the LDAP Account creation failed.",
            "The value given for #/CommonNameType is not valid even though its value comes under the list of acceptable values.",
            "Critical",
            0,
            {},
            "Please make sure to give the value for  #/CommonNameType property to 'IPAddress' if the value for #/EncryptionType is 'NoEncryption' or 'SSL'. Resubmit the request with correct value",
        }},
		MessageEntry{
        "NonASCIICharacterDetected",
        {
            "Indicates that a Non ASCII Character has been found.",
            "A Non ASCII Value was found and is not acceptable for this Application",
            "Critical",
            0,
            {},
            "Please Enter a Value that uses all ASCII Characters",
        }},
		MessageEntry{
        "EmptyArrayValue",
        {
            "Indicates that the Indicated Array has an Empty Value that is Incompatible with the current System",
            "The value given is an Empty Value",
            "Critical",
            0,
            {},
            "Submit a Valid Value for the Specified Array",
        }},
		MessageEntry{
        "AlreadyRunningTask",
        {
            "Indicates that the task already in Running State",
            "The %1 task already Running for %2 Action with %3 operation",
            "Warning",
            3,
            {"string","string","string"},
            "Wait for the task to complete and resubmit the request.",
        }},
		MessageEntry{
        "AMILDAPRootCACertFailed",
        {
            "Indicates that the LDAP configuration save operation failed.",
            "The required root ca certificate is not uploaded into BMC.",
            "Critical",
            0,
            {},
            "Please make sure to upload root ca certificate before saving LDAP configuration if the value for #/EncryptionType is 'NoEncryption' or 'SSL'. Resubmit the request with correct value",
        }},
		MessageEntry{
        "AMILDAPCertDeleteFailed",
        {
            "Indicates that the LDAP certificate cannot be deleted.",
            "The LDAP certificate cannot be deleted.",
            "Warning",
            0,
            {},
            "The LDAP certificate cannot be deleted as it is used in LDAP configuration",
        }},
		MessageEntry{
        "PropertyValueDuplicatedInRequestBody",
        {
            "Indicates that the property value is duplicated in the request body.",
            "The value %1 for the property %2 is duplicated in the request body",
            "Warning",
            2,
            {"string","string"},
            "Change the value of the property and resubmit the request.",
        }},
		MessageEntry{
        "SupportDisabled",
        {
            "Indicates that the operation failed because %1 is already disabled and cannot accept additional requests.",
            "The operation failed because %1 is already disabled and can no longer take incoming requests.",
            "Critical",
            1,
            {"string"},
            "Enable the support and resubmit the request.",
        }},
		MessageEntry{
        "SupportEnabled",
        {
            "Indicates that the operation failed because %1 is already enabled and cannot accept additional requests.",
            "The operation failed because %1 is already enabled and can no longer take incoming requests.",
            "Critical",
            1,
            {"string"},
            "Disable the support and resubmit the request.",
        }},MessageEntry{
        "AMILDAPCertPostFailed",
        {
            "Indicates that the LDAP certificate is already uploading into BMC.",
            "The LDAP certificate is already available in BMC.",
            "Warning",
            0,
            {},
            "The LDAP certificate is already available in BMC. Please delete the certificate and re-post it again or use ReplaceCertificate action URI(/redfish/v1/CertificateService/Actions/CertificateService.ReplaceCertificate) for replacing the certificate.",
        }},
		MessageEntry{
        "AMIADCertPostFailed",
        {
            "Indicates that the AD certificate is already available in BMC.",
            "The AD certificate is already available in BMC.",
            "Warning",
            0,
            {},
            "The AD certificate is already available in BMC. Please delete the certificate and re-post it again or use ReplaceCertificate action URI(/redfish/v1/CertificateService/Actions/CertificateService.ReplaceCertificate) for replacing the certificate.",
        }},
		MessageEntry{
        "AMILDAPUpdateFailed",
        {
            "Indicates that the LDAP configurations like Authentication, LDAPService, ServiceAddresses, RemoteRoleMapping cannot be updated / created when LDAP service is disabled",
            "Indicates that the LDAP configurations like Authentication, LDAPService, ServiceAddresses, RemoteRoleMapping cannot be updated / created when LDAP service is disabled",
            "Critical",
            0,
            {},
            "For updating LDAP configurations, enable the LDAP service",
        }},
		MessageEntry{
        "AMIRADIUSUpdateFailed",
        {
            "Indicates that the RADIUS configurations like KVMAccess, VMediaAccess, Secret, ServiceAddress, ServicePort cannot be updated when RADIUS service is disabled",
            "Indicates that the RADIUS configurations like Authentication, RADIUSService, ServiceAddresses, RemoteRoleMapping cannot be updated when RADIUS service is disabled",
            "Critical",
            0,
            {},
            "For updating RADIUS configurations, enable the RADIUS service.",
        }},
		MessageEntry{
        "StringSizeNotInRange",
        {
            "Indicates that a property size applied is out of range. This can happen with values that are too low or beyond that possible for the supplied resource.",
            "The size of value %1 for the property %2 applied is not in range of allowed string length between %3 to %4.",
            "Warning",
            4,
            {"string","string","number", "number"},
            "Make sure the size of value is inside the range for the property and resubmit the request",
        }},
		MessageEntry{
        "DomainNameResolveError",
        {
            "Indicates that the given domain name is failed to be resolved by Domain Name System.",
            "Indicates that the given domain name is failed to lookup by Domain Name System.",
            "Critical",
            0,
            {},
            "Please make sure the BMC Domain Name System is enabled and the given domain name is valid.",
        }},
		MessageEntry{
        "ErrorAccountLockoutCounterResetAfter",
        {
            "Indicates that the property value for AccountLockoutCounterResetAfter is greater than AccountLockoutDuration",
            "Indicates that the property value for AccountLockoutCounterResetAfter is greater than AccountLockoutDuration",
            "Warning",
            0,
            {},
            "Please change the value of AccountLockoutCounterResetAfter property less than or equal to AccountLockoutDuration and resubmit the request.",
        }},
		MessageEntry{
        "ErrorAccountLockoutDuration",
        {
            "Indicates that the property value for AccountLockoutDuration is less than AccountLockoutCounterResetAfter.",
            "Indicates that the property value for AccountLockoutDuration is less than AccountLockoutCounterResetAfter.",
            "Warning",
            0,
            {},
            "Please change the value of AccountLockoutDuration property greater than or equal to AccountLockoutCounterResetAfter and resubmit the request.",
        }},
		MessageEntry{
        "ConfigurationConflict",
        {
            "Indicates that the current Configuration is in Conflict with another Configuration",
            "The configuration for %1 is not available for this operation while %2 is %3.",
            "Critical",
            3,
            {"string","string","string"},
            "Please resolve the other configuration before changing the current operation.",
        }},
		MessageEntry{
        "CouldNotEstablishConnection",
        {
            "Indicates that the service failed to establish a connection with the specified URI for the corresponding Event Subscription.",
            "The service failed to establish a connection with the URI %1 for the Event Subscription with Id %2.",
            "Critical",
            2,
            {"string","string"},
            "Ensure that the URI contains a valid and reachable node name, protocol information and other URI components.",
        }},
		MessageEntry{
        "SourceDoesNotSupportProtocol",
        {
            "Indicates that the other end of the connection at the URI does not support the specified protocol https for the corresponding Event Subscription.",
            "The other end of the connection at %1 does not support the specified protocol %2 for the Event Subscription with Id %3.",
            "Critical",
            3,
            {"string","string","string"},
            "Change protocols or URIs.",
        }},
		MessageEntry{
        "Success",
        {
            "Indicates that the request was completed successfully for the corresponding Event Subscription.",
            "Successfully Completed Request for the Event Subscription with Id %1.",
            "OK",
            1,
            {"string"},
            "None",
        }},
		MessageEntry{
        "NoActiveSubscriptionPresent",
        {
            "Indicates that no Active Event Subscriptions are present and hence the SubmitTestEvent/SubmitTestMetricReport Action failed.",
            "No Active Event Subscriptions are present and hence the %1 Action failed.",
            "Warning",
            1,
            {"string"},
            "Create an Event Subscription of EventFormatType Event/MetricReport and resubmit the SubmitTestEvent/SubmitTestMetricReport Action request.",
        }},
		MessageEntry{
        "NoActiveSubscriptionOfFormatTypeEventPresent",
        {
            "Indicates that no Active Event Subscriptions of EventFormatType 'Event' are present and hence the Event Service SubmitTestEvent Action failed.",
            "No Active Event Subscriptions of EventFormatType 'Event' are present and hence the Event Service SubmitTestEvent Action failed.",
            "Warning",
            0,
            {},
            "Create an Event Subscription of EventFormatType 'Event' and resubmit the SubmitTestEvent Action request.",
        }},
		MessageEntry{
        "NoActiveSubscriptionOfFormatTypeMetricReportPresent",
        {
            "Indicates that no Active Event Subscriptions of EventFormatType 'MetricReport' are present and hence the Telemetry Service SubmitTestMetricReport Action failed.",
            "No Active Event Subscriptions of EventFormatType 'MetricReport' are present and hence the Telemetry Service SubmitTestMetricReport Action failed.",
            "Warning",
            0,
            {},
            "Create an Event Subscription of EventFormatType 'MetricReport' and resubmit the SubmitTestMetricReport Action request.",
        }},
		MessageEntry{
        "MaximumLimitReachedForResource",
        {
            "Indicates that no more concurrent requests can be issued to the specified resource as it has reached its maximum limit of 3 concurrent requests.",
            "No more concurrent requests can be issued to the resource %1 as it has reached its maximum limit of 3 concurrent requests.",
            "Warning",
            1,
            {"string"},
            "Wait a few seconds for the ongoing concurrent requests to finish and resubmit the request if the operation failed or do not resubmit the request.",
        }},
		MessageEntry{
        "SubmitTestEventPreconditionsFailed",
        {
            "Indicates that one or more of the precondition(s), involving the Event Subscription attributes 'OriginResources','MessageIds','RegistryPrefixes' and 'ResourceTypes' failed to satisfy, in order to complete the Event Service SubmitTestEvent Action.",
            "One or more of the precondition(s), involving the Event Subscription attributes 'OriginResources','MessageIds','RegistryPrefixes' and 'ResourceTypes' failed to satisfy for the Event Subscription with Id %1, in order to complete the Event Service SubmitTestEvent Action.",
            "Warning",
            1,
            {"string"},
            "Ensure that the request body is valid with reference to the corresponding Event Subscription and resubmit the request.",
        }},
		MessageEntry{
        "SubmitTestMetricReportPreconditionsFailed",
        {
            "Indicates that one or more of the precondition(s), involving the Event Subscription attributes 'OriginResources','MessageIds','RegistryPrefixes' and 'ResourceTypes' failed to satisfy, in order to complete the Telemetry Service SubmitTestMetricReport Action.",
            "One or more of the precondition(s), involving the Event Subscription attributes 'OriginResources','MessageIds','RegistryPrefixes' and 'ResourceTypes' failed to satisfy for the Event Subscription with Id %1, in order to complete the Telemetry Service SubmitTestMetricReport Action.",
            "Warning",
            1,
            {"string"},
            "Ensure that the request body is valid with reference to the corresponding Event Subscription and resubmit the request.",
        }},
		MessageEntry{
        "OperationSupportedInFutureStateURI",
        {
            "Indicates that this operation for %1 is supported only in FutureState(SD) URI",
            "Support of this Operation for %1 Properties is moved to FutureState URI(%2)",
            "Critical",
            2,
            {"string","string"},
            "Repeat the operation on FutureState(SD) URI for applying these changes",
        }},
		MessageEntry{
        "FeatureNotEnabled",
        {
            "Indicates that %1 cannot be enabled since %3 feature is disabled.",
            "Value %2 for the property %1 cannot be applied since %3 feature is disabled.",
            "Warning",
            3,
            {"string","string","string"},
            "None",
        }},
		MessageEntry{
        "PAMOrderRadiusNotAllowed",
        {
            "Indicates that the operation failed because %1 should be kept as last in the PAM Order.",
            "The operation failed because %1 should be kept as last in the PAM Order.",
            "Critical",
            1,
            {"string"},
            "Keep RADIUS as last in the PAM Order and resubmit the request.",
        }},
		MessageEntry{
        "TimeStampInvalid",
        {
            "Indicates that the TimeStamp is invalid.",
            "The TimeStamp value %1 for the property %2 is in the past or more than 2 mins to the BMC time.",
            "Warning",
            2,
            {"string","string"},
            "Change the TimeStamp value same as DateTime property in the Manager Instance Resource.",
        }},
		MessageEntry{
        "SameValue",
        {
            "Indicates same value is provided",
            "Indicates same value is provided",
            "Warning",
            0,
            {"string"},
            "Try with different value",
        }},
		MessageEntry{
        "TaskAlreadyExists",
        {
            "Indicates previous task ID for this action is in Pending/Running state.",
            "Previous task for this %1 action is in Pending/Running state.",
            "Critical",
            1,
            {"string"},
            "Please wait till the previous task state for this action to complete.",
        }},
		MessageEntry{
        "Success",
        {
            "Indicates that the request was completed successfully for the corresponding Event Subscription.",
            "Successfully Completed Request for the Event Subscription with Id %1.",
            "OK",
            1,
            {"string"},
            "None",
        }},
		MessageEntry{
        "PropertyValueURINotSupported",
        {
            "Indicates that a parameter was given the correct value type but the value of that parameter was not supported.",
            "The URI %1 for the parameter %2 in the action %3 is not supported by the Service.",
            "Warning",
            3,
            {"string","string","string"},
            "Ensure that the given URI is supported by the Service.",
        }},
		MessageEntry{
        "InvalidDateTime",
        {
            "Indicates that the DateTime is invalid.",
            "The value %1 for the property %2 is invalid.",
            "Warning",
            2,
            {"string","string"},
            "Please make sure that correct values are given to date and time.",
        }},
		MessageEntry{
        "MaximumLimitReachedForDate",
        {
            "Indicates that the Date crossed Unix maximum representable number.",
            "The value %1 for the property %2 crossed Unix maximum representable number.",
            "Critical",
            2,
            {"string","string"},
            "Ensure that the given date is not greater than 2038-01-18",
        }},
		MessageEntry{
        "MinimumLimitUnixDate",
        {
            "Indicates that the Date is before the Unix minimum representable number.",
            "The value %1 for the property %2 is before the Unix minimum representable number.",
            "Critical",
            2,
            {"string","string"},
            "Ensure that the given date is before the Unix Minimum date 1970-01-02",
        }},
		MessageEntry{
        "PrivilegeNotAvailable",
        {
            "Indicates that the given User %1 does not have %2 access",
            "The given User %1 does not have %2 access. Please select a user with %2 access",
            "Warning",
            2,
            {"string","string"},
            "Please select a user with required access",
        }},
		MessageEntry{
        "UserNotAvailable",
        {
            "Indicates that the given username %1 does not exist",
            "The given username %1 does not exist",
            "Warning",
            1,
            {"string"},
            "Please give a valid username and try again.",
        }},
		MessageEntry{
        "SNMPAccountNotAllowed",
        {
            "Indicates that the operation failed because AccountType with only %1 Account not allowed.",
            "The operation failed because AccountType with only %1 is not allowed.",
            "Warning",
            2,
            {"string"},
            "Resubmit the request with allowed AccountTypes.",
        }},
		MessageEntry{
        "SNMPConfigurationFailed",
        {
            "Indicates that the operation failed because %1 is not in list of AccountTypes property and cannot accept additional requests.",
            "The operation failed because %1 is not in list of AccountTypes property and can no longer take incoming requests.",
            "Warning",
            1,
            {"string"},
            "Provide SNMP in AccountTypes property and resubmit the request.",
        }},MessageEntry{
        "AccountTypesRequired",
        {
            "Indicates that the operation failed because AccountTypes property Missed or Invalid data, %1 configuration is based on AccountTypes Property and cannot accept additional requests.",
            "The %1 Configuration failed because AccountTypes is either not provided in the request or contains invalid allowable data.",
            "Warning",
            1,
            {"string"},
            "Provide valid Allowable AccountTypes i.e ['Redfish', 'SNMP'] for SNMP configuration and resubmit the request.",
        }},MessageEntry{
        "SNMPSupportDisabled",
        {
            "Indicates that the operation failed because %1 is already disabled and cannot accept additional requests.",
            "The operation failed because %1 is already disabled and can no longer take incoming requests.",
            "Warning",
            1,
            {"string"},
            "Remove SNMP configuration and resubmit the request.",
        }},MessageEntry{
        "InvalidMessageId",
        {
            "Indicates that a property was given in the request body is incorrect MessageId value.",
            "The value %1 for the property %2 is dependent on the property %3, provide the correct %3.",
            "Warning",
            3,
            {"string","string","string"},
            "Make sure the MessageId property in the request body should provide correct MessageId and resubmit the request.",
        }},MessageEntry{
        "UserAccessDisabled",
        {
            "User Access is disabled.",
            "User Access is disabled for this Account so %1 configuration is not allowed",
            "Warning",
            1,
            {"string"},
            "Enable/provide User Access for this Account and resubmit the request.",
        }},
		MessageEntry{
        "InvalidRemoteGroup",
        {
            "Indicates that the given RemoteGroup(Group Name) is already existing in BMC for an another RoleGroup.",
            "The value %1 for the property %2 is already existing for another RoleGroup %3 in BMC. Try with different RemoteGroup name.",
            "Warning",
            3,
            {"string","string","string"},
            "Setting the same RemoteGroup(Group Name) is not allowed in the operation. Either Rename/Delete the existing Role Group having same RemoteGroup(Group Name) and resubmit the request.",
        }},MessageEntry{
        "InvalidResourceBlocks",
        {
            "Indicates that the value for the given ResourceBlock is not valid",
            "The property %1 must have at least one ResourceBlock.",
            "Critical",
            1,
            {"string"},
            "Ensure that at least one ResourceBlock exists and resubmit the request.",
        }},MessageEntry{
        "PropertyValueEmpty",
        {
            "Indicates that a property value is empty.",
            "The value %1 for the property %2 should not be empty.",
            "Critical",
            2,
            {"string","string"},
            "Please make sure that correct value for the property is provided in the request body and resubmit the request",
        }},MessageEntry{
        "DeepOperationResourceNotFound",
        {
            "Indicates that can't find the resource at deep operation",
            "The resource %1 isn't existing.",
            "Warning",
            1,
            {"string"},
            "Please make sure that the resource is existing",
        }},
		MessageEntry{
        "SDCardMissing",
        {
            "Indicates that there is no SD card inserted.",
            "There is no SD Card inserted.",
            "Critical",
            0,
            {},
            "Please insert SD card for backup conf or extended log partition.",
        }},
		MessageEntry{
        "TaskInRunningState",
        {
            "InsertMedia/EjectMedia task is in Running state for other CD instance, so action Post call is Restricted",
            "InsertMedia/EjectMedia task is in Running state for other CD instance",
            "Warning",
            0,
            {},
            "Please wait till the on going InsertMedia/EjectMedia task to get completed and resubmit the request.",
        }},
		MessageEntry{
        "PortIsNotAvailable",
        {
            "Indicated the port number %1 for the property %2 is not available.",
            "Port number %1 for the property %2 is not available.",
            "Warning",
            2,
            { "number" , "string"},
            "Patch another port or try again later.",
        }},
		MessageEntry{
        "ServiceStartFailed",
        {
            "The service %1 start failed.",
            "The service %1 start failed.",
            "Critical",
            1,
            {"string"},
            "Please check the configuration of the service.",
        }},
		MessageEntry{
        "MutuallyExclusiveProperties",
        {
            "The %1 and %2 properties are considered mutually exclusive. Hence both properties cannot be configured together.",
            "The %1 and %2 properties are considered mutually exclusive. Hence both properties cannot be configured together",
            "Critical",
            2,
            {"string","string"},
            "Please proceed the action with any one of the property.",
        }},
		MessageEntry{
        "PropertyConflict",
        {
            "Indicates that the current Property is in Conflict with another Property",
            "Property %1 and %2 conflict, can only choose one.",
            "Critical",
            2,
            {"string","string"},
            "Please remove one of the properties",
        }},
		MessageEntry{
        "SMTPPortNotSupported",
        {
            "Indicates that the port number %1 for the property %2 is not supported.",
            "The port number %1 specified for the property %2 is not supported for SMTP %3 connection protocol. Please provide %4 port number for %3",
            "Warning",
            4,
            {"string","string","string","string"},
            "Resubmit the request with appropriate Port number for SMTP connection protocol.",
        }},
		MessageEntry{
        "InvalidSubscriptionType",
        {
            "Indicates that a property was given in the request body is incorrect SubscriptionType value.",
            "The value %1 for the property %2 is not supported in Post Subscription Collection",
            "Warning",
            2,
            {"string","string"},
            "Resubmit the request with appropriate SubscriptionType.",
        }},
		MessageEntry{
        "PatchRestricted",
        {
            "Indicates that a property was given in the request body is not patchable because the Account Role is Restricted.",
            " The property %1 is not patchable because the Account Role   is Restricted.",
            "Warning",
            1,
            {"string","string"},
            "No resolution required. For Accounts using RestrictedRole patch is allowed only for Enabled property.",
        }},
		MessageEntry{
        "InvalidDeviceAmount",
        {
            "Indicates that invalid devices amount in creating volume.",
            "The amount of physical devices (%1) is invalid to create volume of raid type '%2'",
            "Critical",
            2,
            {"number","string"},
            "Resubmit the request with appropriate amount of physical devices",
        }},
		MessageEntry{
        "DifferentIpSeries",
        {
            "Indicates that the IP addresses are not in the same series",
            "The values of %1 and %2 are in different series.",
            "Warning",
            2,
            {"string","string"},
            "Provide IP Addresses in the same series.",
        }},
		MessageEntry{
        "SubscriptionActionFailed",
        {
            "The given action has been Failed",
            "%1 The given action has been Failed",
            "Warning",
            1,
            {"string"},
            "Resubmit the request with proper data",
        }},
		MessageEntry{
        "HostInterfacePatchRestricted",
        {
            "Indicates that a property was given in the request body is not patchable because the HostInterface InterfaceEnabled is Restricted.",
            "The property %1 is not patchable because the HostInterface InterfaceEnabled is Restricted.",
            "Warning",
            1,
            {"string"},
            "No resolution required. For HostInterface using InterfaceEnabled patch is allowed only when Restrict Redfish HostInterface feature disabled.",
        }},
		MessageEntry{
        "IPMIPreserveConfigurationConflict",
        {
            "IPMI, Network configuration are related, please check it.",
            "IPMI, Network configuration conflict, please check it.",
            "Warning",
            0,
            {},
            "IPMI and Network should be set at the same time, and their values should be the same.",
        }},
		MessageEntry{
        "SNMPPreserveConfigurationConflict",
        {
            "IPMI, Network, SNMP, configuration are related, please check it.",
            "IPMI, Network, SNMP, configuration conflict, please check it.",
            "Warning",
            0,
            {},
            "IPMI and Network should be set at the same time, and their values should be the same. SNMP can be 'true' only if both IPMI and Network are 'true'.",
        }},
		MessageEntry{
        "REDFISHPreserveConfigurationConflict",
        {
            "IPMI, REDFISH configuration are related, please check it.",
            "IPMI, REDFISH configuration conflict, please check it.",
            "Warning",
            0,
            {},
            "Due to the unified account being enabled, IPMI and REDFISH should be set to the same value to ensure account synchronization.",
        }},MessageEntry{
        "CertificateDateOverLimitUnixDate",
        {
            "Indicates that the Date crossed Unix maximum representable number.",
            "The validity of Not After for the certificate string crossed Unix maximum representable number, it can not exceed 2038-01-18.",
            "Critical",
            0,
            {},
            "Ensure that the given date is not greater than 2038-01-18",
        }},
		
};

enum class Index
{
	propertyValueSizeNotMatched = 1,
	propertyValueNotEqual = 2,
	propertyValueRequiredFirstTime = 3,
	cannotUseStandardTCPPorts = 4,
	offsetValueFormatError = 5,
	duplicateOffsetFound  = 6,
	actionRequiresFile = 7,
	licenserequire = 8,
	queryParameterFormatError = 9,
	serviceDisabled = 10,
	queryParameterOnlyFormatError = 11,
	queryParameterExcerptFormatError = 12,
	serviceEnabled = 13,
	hostInterfaceStatus = 14,
	modifyingValues = 15,
	propertiesMustHaveSameValue = 16,
	inventoryDataIncomplete = 17,
	certificateDataIncomplete = 18,
	preconditionHeaderMissing = 19,
	insufficientStorageForResponse = 20,
	authenticationDisabled = 21,
	queryParameterIgnored = 22,
	queryParameterFailed = 23,
	filterOptionsNotSupported = 24,
	propertyOutOfRange = 25,
	propertyLimit = 26,
	lastExistingAccount = 27,
	userNameAlreadyExists = 28,
	propertyValueMismatch = 29,
	propertyCannotExistInRequestBody = 30,
	passwordChangeRequired = 31,
	kVMActionExist = 32,
	actionExist = 33,
	actionNotExist = 34,
	createLimitReachedForMetricReportsResource = 35,
	delayInActionCompletion = 36,
	requestBodySizeExceeded = 37,
	propertyValueSizeExceeded = 38,
	alreadyScheduledTask = 39,
	maintenanceWindowIncorrectTime = 40,
	emptyObjectOrArrayInRequest = 41,
	emptyObjectOrArrayInRequestSpecific = 42,
	passwordResetFailed = 43,
	limitExceeded = 44,
	metricReportDefinitionReportDoesNotSupportEvent = 45,
	userModifiedData = 46,
	disablingLocalAccountAuthFailed = 47,
	serviceTemporarilyUnavailableDueToHostBooting = 48,
	actionNotSupported = 49,
	invalidOffsetValue = 50,
	offsetValueOutofRange = 51,
	serverAddressFormatError = 52,
	serverPasswordFormatError = 53,
	sMTPPasswordFormatError = 54,
	sMTPUsernameFormatError = 55,
	sMTPAddressError = 56,
	serverUsernameFormatError = 57,
	lDAPSearchBaseFormatError = 58,
	lDAPRemoteGroupFormatError = 59,
	lDAPRemoteUserFormatError = 60,
	activeDirectoryPasswordFormatError = 61,
	activeDirectoryUsernameFormatError = 62,
	activeDirectoryRemoteGroupFormatError = 63,
	activeDirectoryRemoteUserFormatError = 64,
	serviceTemporarilyUnavailableDueToMutex = 65,
	aMILDAPCertificateUploadFailed = 66,
	aMILDAPAccountCreationFailed = 67,
	nonASCIICharacterDetected = 68,
	emptyArrayValue = 69,
	alreadyRunningTask = 70,
	aMILDAPRootCACertFailed = 71,
	aMILDAPCertDeleteFailed = 72,
	propertyValueDuplicatedInRequestBody = 73,
	supportDisabled = 74,
	supportEnabled = 75,
	aMILDAPCertPostFailed = 76,
	aMIADCertPostFailed = 77,
	aMILDAPUpdateFailed = 78,
	aMIRADIUSUpdateFailed = 79,
	stringSizeNotInRange = 80,
	domainNameResolveError = 81,
	errorAccountLockoutCounterResetAfter = 82,
	errorAccountLockoutDuration = 83,
	configurationConflict = 84,
	couldNotEstablishConnection = 85,
	sourceDoesNotSupportProtocol = 86,
	success = 87,
	noActiveSubscriptionPresent = 88,
	noActiveSubscriptionOfFormatTypeEventPresent = 89,
	noActiveSubscriptionOfFormatTypeMetricReportPresent = 90,
	maximumLimitReachedForResource = 91,
	submitTestEventPreconditionsFailed = 92,
	submitTestMetricReportPreconditionsFailed = 93,
	operationSupportedInFutureStateURI = 94,
	featureNotEnabled = 95,
	pAMOrderRadiusNotAllowed = 96,
	timeStampInvalid = 97,
	sameValue = 98,
	taskAlreadyExists = 99,
	propertyValueURINotSupported = 100,
	invalidDateTime = 101,
	maximumLimitReachedForDate = 102,
	minimumLimitUnixDate = 103,
	privilegeNotAvailable = 104,
	userNotAvailable = 105,
	sNMPAccountNotAllowed = 106,
	sNMPConfigurationFailed = 107,
	accountTypesRequired = 108,
	sNMPSupportDisabled = 109,
	invalidMessageId = 110,
	userAccessDisabled = 111,
	invalidRemoteGroup = 112,
	invalidResourceBlocks = 113,
	propertyValueEmpty = 114,
	deepOperationResourceNotFound = 115,
	sDCardMissing = 116,
	taskInRunningState = 117,
	portIsNotAvailable = 118,
	serviceStartFailed = 119,
	mutuallyExclusiveProperties = 120,
	propertyConflict = 121,
	sMTPPortNotSupported = 122,
	invalidSubscriptionType  = 123,
	patchRestricted = 124,
	invalidDeviceAmount = 125,
	differentIpSeries = 126,
	subscriptionActionFailed = 127,
	hostInterfacePatchRestricted = 128,
	iPMIPreserveConfigurationConflict = 129,
	sNMPPreserveConfigurationConflict = 130,
	rEDFISHPreserveConfigurationConflict = 131,
	certificateDateOverLimitUnixDate = 132
	
};
} // namespace redfish::registries::openbmc
