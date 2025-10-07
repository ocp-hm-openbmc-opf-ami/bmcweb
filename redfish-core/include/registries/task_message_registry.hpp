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

namespace redfish::registries::task
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
    "Task",
    "Task",
};
constexpr std::array registry =
{
		MessageEntry{
        "New",
        {
            "This task is newly created but the operation has not yet started.",
            "A new task %1 was created.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
		MessageEntry{
        "Running",
        {
            "Indicates that the operation is executing.",
            "Task %1 is running normally.",
            "OK",
            1,
            { "string"},
            "None",
        }},
		MessageEntry{
        "Completed",
        {
            "The operation is complete and completed successfully or with warnings.",
            "Task %1 has completed.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
		MessageEntry{
        "Exception",
        {
            "The operation is complete and completed with errors.",
            "Task %1 has stopped due to an exception condition.",
            "Warning",
            1,
            { "string"},
            "None.",
        }},
		MessageEntry{
        "Interrupted",
        {
            "The operation has been interrupted but is expected to restart and is therefore not complete.",
            "Task %1 has been interrupted.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
		MessageEntry{
        "Killed",
        {
            "This value shall represent that the operation is complete because the task was killed by an operator.",
            "Task %1 was terminated.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
		MessageEntry{
        "Pending",
        {
            "The operation is pending some condition and has not yet begun to execute.",
            "Task %1 is pending and has not started.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
		MessageEntry{
        "Service",
        {
            "The operation is now running as a service and expected to continue operation until stopped or killed.",
            "Task %1 is running as a service.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
		MessageEntry{
        "Starting",
        {
            "The operation is starting.",
            "Task %1 is starting.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
		MessageEntry{
        "Stopping",
        {
            "The operation is stopping but is not yet complete.",
            "Task %1 is in the process of stopping.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
		MessageEntry{
        "Suspended",
        {
            "This value shall represent that the operation has been suspended but is expected to restart and is therefore not complete.",
            "Task %1 has been suspended.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
		MessageEntry{
        "Cancelled",
        {
            "This value shall represent that either a DELETE operation on a Task Monitor or Task Resource or by an internal process cancelled the task.",
            "Task %1 cancelled by an operator or internal process.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
		
};

enum class Index
{
	running = 2,
	completed = 3,
	exception = 4,
	interrupted = 5,
	killed  = 6,
	pending = 7,
	service = 8,
	starting = 9,
	stopping = 10,
	suspended = 11,
	cancelled = 12
};
} // namespace redfish::registries::openbmc
