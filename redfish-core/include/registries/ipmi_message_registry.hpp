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

namespace redfish::registries::ipmi
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
    "IPMI",
    "IPMI",
};
constexpr std::array registry =
{
		MessageEntry{
        "CompletedNormally",
        {
            "Command Completed Normally.",
            "The request was processed and completed normally.",
            "OK",
            0,
            {},
            "None.",
        }},
		MessageEntry{
        "NodeBusy",
        {
            "Node Busy. Command could not be processed because command processing resources are temporarily unavailable.",
            "The request could not be completed because the required service is busy.",
            "Critical",
            0,
            {},
            "Verify other pending operations have finished and resubmit the request.",
        }},
		MessageEntry{
        "InvalidCommand",
        {
            "Invalid Command. Used to indicate an unrecognized or unsupported command.",
            "The request could not be completed due to the use of an unrecognized or unsupported IPMI command.",
            "Critical",
            0,
            {},
            "None.",
        }},
		MessageEntry{
        "InvalidCommandForLUN",
        {
            "Command invalid for given LUN.",
            "The request could not be completed due to the use of an IPMI command not recognized and/or supported by the LUN it was sent to.",
            "Critical",
            0,
            {},
            "None.",
        }},
		MessageEntry{
        "Timeout",
        {
            "Timeout while processing command. Response unavailable.",
            "A timeout occurred while processing the request. No response available.",
            "Critical",
            0,
            {},
            "Verify that the IPMI service is functional and resubmit the request.",
        }},
		MessageEntry{
        "OutOfSpace",
        {
            "Out of space. Command could not be completed because of a lack of storage space required to execute the given command operation.",
            "The request could not be completed because of a lack of storage space required to execute the given command operation.",
            "Critical",
            0,
            {},
            "Create additional storage space and resubmit the request.",
        }},
		MessageEntry{
        "NoReservation",
        {
            "Reservation Canceled or Invalid Reservation ID.",
            "The request could not be completed due to an invalid or cancelled IPMI Reservation ID.",
            "Critical",
            0,
            {},
            "None.",
        }},
		MessageEntry{
        "DataTruncated",
        {
            "Request data truncated.",
            "The request could not be completed because an underlying IPMI request was truncated.",
            "Critical",
            0,
            {},
            "Verify the request parameters and resubmit the request.",
        }},
		MessageEntry{
        "DataLengthInvalid",
        {
            "Request data length invalid.",
            "The request could not be completed because an underlying IPMI request sent an invalid data length.",
            "Critical",
            0,
            {},
            "Verify the request parameters and resubmit the request.",
        }},
		MessageEntry{
        "DataLengthExceeded",
        {
            "Request data field length limit exceeded.",
            "The request could not be completed because an underlying IPMI request exceeded its data length limit.",
            "Critical",
            0,
            {},
            "Verify the request parameters and resubmit the request.",
        }},
		MessageEntry{
        "ParamaterOutOfRange",
        {
            "Parameter out of range. One or more parameters in the data field of the Request are out of range. This is different from ‘Invalid data field’ (CCh) code in that it indicates that the erroneous field(s) has a contiguous range of possible values.",
            "The request could not be completed because one or more parameters were not within the range of acceptable values.",
            "Critical",
            0,
            {},
            "Verify that all parameter values are valid and resubmit the request.",
        }},
		MessageEntry{
        "ResponseSize",
        {
            "Cannot return number of requested data bytes.",
            "The request could not be completed because the response was too large.",
            "Critical",
            0,
            {},
            "None",
        }},
		MessageEntry{
        "ResourceNotFound",
        {
            "Requested Sensor, data, or record not present.",
            "The request could not be completed because it referenced a sensor, record, or data field that could not be found.",
            "Critical",
            0,
            {},
            "Verify that the correct resource was specified and resubmit the request.",
        }},
		MessageEntry{
        "InvalidRequestData",
        {
            "Invalid data field in Request",
            "The request could not be completed because one or more parameters were invalid.",
            "Critical",
            0,
            {},
            "Verify that all parameter values are valid and resubmit the request.",
        }},
		MessageEntry{
        "IllegalCommand",
        {
            "Command illegal for specified sensor or record type.",
            "The request could not be completed due to the use of an IPMI command not recognized and/or supported by the sensor or record it was sent to.",
            "Critical",
            0,
            {},
            "Verify the requested command and resource and resubmit the request.",
        }},
		MessageEntry{
        "NoResponse",
        {
            "Command response could not be provided.",
            "The request was accepted but returned with no response",
            "Critical",
            0,
            {},
            "Verify the IPMI service is functional and resubmit the request.",
        }},
		MessageEntry{
        "CannotExecuteDuplicate",
        {
            "Cannot execute duplicated request. This completion code is for devices which cannot return the response that was returned for the original instance of the request. Such devices should provide separate commands that allow the completion status of the original request to be determined. An Event Receiver does not use this completion code, but returns the 00h completion code in the response to (valid) duplicated requests.",
            "The request could not be completed because it was detected as a duplicate of a previous request.",
            "Critical",
            0,
            {},
            "None.",
        }},
		MessageEntry{
        "SDRInUpdateMode",
        {
            "Command response could not be provided. SDR Repository in update mode.",
            "The request could not be completed because the SDR Repository is in update mode.",
            "Critical",
            0,
            {},
            "Resubmit the request after SDR Repository update is complete.",
        }},
		MessageEntry{
        "FirmwareInUpdateMode",
        {
            "Command response could not be provided. Device in firmware update mode.",
            "The request could not be completed because the device is in firmware update mode.",
            "Critical",
            0,
            {},
            "Resubmit the request after the Firmware update is completed.",
        }},
		MessageEntry{
        "BMCInitializing",
        {
            "Command response could not be provided. BMC initialization or initialization agent in progress.",
            "The request could not be completed because BMC initialization is in progress",
            "Critical",
            0,
            {},
            "Resubmit the request after the BMC initialization is completed.",
        }},
		MessageEntry{
        "DestinationUnavailable",
        {
            "Destination unavailable. Cannot deliver request to selected destination. E.g. this code can be returned if a request message is targeted to SMS, but receive message queue reception is disabled for the particular channel.",
            "The request could not be completed because the target destination is unavailable.",
            "Critical",
            0,
            {},
            "None.",
        }},
		MessageEntry{
        "InsufficientPrivilege",
        {
            "Cannot execute command due to insufficient privilege level or other security-based restriction (e.g. disabled for ‘firmware firewall’).",
            "The request could not be completed because it was sent with insufficient privilege level or other security restriction.",
            "Critical",
            0,
            {},
            "Resubmit the request with proper security clearance.",
        }},
		MessageEntry{
        "IncompatibleState",
        {
            "Cannot execute command. Command, or request parameter(s), not supported in present state.",
            "The request could not be completed because a command or request parameter is not supported in the present state.",
            "Critical",
            0,
            {},
            "Verify that the service is not in a conflicting state and resubmit the request.",
        }},MessageEntry{
        "SubfunctionDisabled",
        {
            "Cannot execute command. Parameter is illegal because command sub-function has been disabled or is unavailable (e.g. disabled for ‘firmware firewall’).",
            "The request could not be completed because it relied on a sub-function has been disabled or is unavailable.",
            "Critical",
            0,
            {},
            "Verify that the service is functional and resubmit the request.",
        }},
		MessageEntry{
        "UnspecifiedError",
        {
            "Unspecified error.",
            "The request could not be completed due to an unspecified error.",
            "Critical",
            0,
            {},
            "None.",
        }},
		MessageEntry{
        "DeviceSpecific",
        {
            "Device specific (OEM) completion code. This range is used for command-specific codes that are also specific for a particular device and version. A-priori knowledge of the device command set is required for interpretation of these codes.",
            "Device specific (OEM) completion code: %1.",
            "Critical",
            1,
            {"string"},
            "Consult OEM documentation for the given completion code.",
        }},
		MessageEntry{
        "CommandSpecific",
        {
            "Standard command-specific codes. This range is reserved for command-specific completion codes described by IPMI specification.",
            "Standard command-specific code: %1.",
            "Critical",
            1,
            {"string"},
            "Consult IPMI specification for the given completion code.",
        }},
		MessageEntry{
        "Reserved",
        {
            "Reserved completion code.",
            "Reserved completion code: %1.",
            "Critical",
            1,
            {"string"},
            "None.",
        }},
		MessageEntry{
        "MediumError",
        {
            "Indicates that the error occurred not during the IPMI operation, but in the communication medium.",
            "An error occurred in the IPMI communication medium: %1.",
            "Critical",
            1,
            {"string"},
            "Verify that the IPMI service is functional and resubmit the request.",
        }},
		MessageEntry{
        "PortAlreadyInUse",
        {
            "Indicates that the given Port is already in use.",
            "Indicates that the given Port is already in use.",
            "Critical",
            0,
            {},
            "Resubmit the request with different port value which ranges from 1 to 65535.",
        }},
		MessageEntry{
        "RAIDCommandFailed",
        {
            "Indicates that the given RAID command is failed.",
            "Indicates that the given RAID command is failed.",
            "Warning",
            0,
            {},
            "Resubmit the request with correct RAID parameters.",
        }},
		MessageEntry{
        "SelLogCreated",
        {
            "Indicates that IPMI sel log is created.",
            "Indicates the SEL Specific Message.",
            "Critical",
            0,
            {},
            "None.",
        }},
		
};

enum class Index
{
	completedNormally = 1,
	nodeBusy = 2,
	invalidCommand = 3,
	invalidCommandForLUN = 4,
	timeout = 5,
	outOfSpace  = 6,
	noReservation = 7,
	dataTruncated = 8,
	dataLengthInvalid = 9,
	dataLengthExceeded = 10,
	paramaterOutOfRange = 11,
	responseSize = 12,
	resourceNotFound = 13,
	invalidRequestData = 14,
	illegalCommand = 15,
	noResponse = 16,
	cannotExecuteDuplicate = 17,
	sDRInUpdateMode = 18,
	firmwareInUpdateMode = 19,
	bMCInitializing = 20,
	destinationUnavailable = 21,
	insufficientPrivilege = 22,
	incompatibleState = 23,
	subfunctionDisabled = 24,
	unspecifiedError = 25,
	deviceSpecific = 26,
	commandSpecific = 27,
	reserved = 28,
	mediumError = 29,
	portAlreadyInUse = 30,
	rAIDCommandFailed = 31,
	selLogCreated = 32
};
} // namespace redfish::registries::openbmc
