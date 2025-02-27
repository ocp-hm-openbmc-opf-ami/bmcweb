#pragma once

// #include "dbus_utility.hpp"
// #include "error_messages.hpp"
// #include "openbmc_dbus_rest.hpp"

// #include <boost/container/flat_map.hpp>
// #include <nlohmann/json.hpp>

namespace redfish
{
namespace service_util
{

inline void getSerialConsoleSshMasked(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& serviceName, const std::string& ObjectName,
    const std::string& subObjectName, const std::string& propertyName);

inline void getMasked(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
               const std::string& serviceName, const std::string& ObjectName,
               const std::string& propertyName);

inline void getRunning(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                const std::string& serviceName,
                const nlohmann::json::json_pointer& valueJsonPtr);

inline void getEnabled(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                const std::string& serviceName,
                const nlohmann::json::json_pointer& valueJsonPtr);

inline void getPortNumber(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& serviceName,
                   const nlohmann::json::json_pointer& valueJsonPtr);


inline void setMasked(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
               const std::string& serviceName, const bool enabled);

inline void setEnabled(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                const std::string& serviceName, const bool enabled);

inline void setPortNumber(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& serviceName, const uint16_t portNumber);

} // namespace service_util
} // namespace redfish
