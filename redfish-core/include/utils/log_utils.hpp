// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#pragma once

#include "dbus_singleton.hpp"
#include "logging.hpp"

#include <boost/system/error_code.hpp>

#include <map>
#include <string>

namespace redfish
{

// Generic helper to raise a phosphor-logging event log entry over D-Bus.
// Usable by any feature that needs to record an audit/event log message.
inline void createEventLogEntry(
    std::string msg,
    std::string eventLogSeverity =
        "xyz.openbmc_project.Logging.Entry.Level.Informational",
    std::map<std::string, std::string> additionalData = {})
{
    const std::string eventLogService = "xyz.openbmc_project.Logging";
    const std::string eventLogObjPath = "/xyz/openbmc_project/logging";
    const std::string eventLogIface = "xyz.openbmc_project.Logging.Create";
    crow::connections::systemBus->async_method_call(
        [msg](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("createEventLogEntry D-Bus error: {}",
                                 ec.message());
            }
            else
            {
                BMCWEB_LOG_INFO(
                    "createEventLogEntry D-Bus call succeeded for message: {}",
                    msg);
            }
        },
        eventLogService, eventLogObjPath, eventLogIface, "Create", msg,
        eventLogSeverity, additionalData);
}

} // namespace redfish
