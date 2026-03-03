#pragma once

#include "async_resp.hpp"
#include "error_messages.hpp"
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/bus.hpp>
#include <optional>

#include <string>

namespace redfish
{
namespace system_utils
{

inline bool isDualHostEnabled()
{
    static std::optional<bool> enabled;

    if (enabled.has_value())
    {
        return *enabled;
    }

    sdbusplus::bus::bus bus = sdbusplus::bus::new_default();
    try
    {
        const char* service = "xyz.openbmc_project.Settings";
        auto method = bus.new_method_call(
            service, "/xyz/openbmc_project/control/HostMode",
            "org.freedesktop.DBus.Properties", "Get");
        method.append("xyz.openbmc_project.Control.HostMode", "CurrentMode");
        sdbusplus::message::message reply = bus.call(method);
        std::variant<uint16_t> value;
        reply.read(value);
        enabled = (std::get<uint16_t>(value) == 1);
    }
    catch (const sdbusplus::exception::exception& e)
    {
        BMCWEB_LOG_ERROR("D-Bus call failed to get HostMode: {}", e.what());
        enabled = false;
    }
    return *enabled;
}

inline bool validateSystemName(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& systemName)
{
    if(!isDualHostEnabled()) {
        // For single node, accept only "system"
        if (systemName != "system") {
            messages::resourceNotFound(asyncResp->res, "ComputerSystem", systemName);
            return false;
        }
    } else {
        // For dual node, accept system and system1
        if (systemName != "system" && systemName != "system1") {
            messages::resourceNotFound(asyncResp->res, "ComputerSystem", systemName);
            return false;
        }
    }
    return true;
  
}

} // namespace system_utils
} // namespace redfish

