#pragma once

#include "dbus_utility.hpp"
#include "error_messages.hpp"
#include "openbmc_dbus_rest.hpp"

#include <boost/container/flat_map.hpp>
#include <nlohmann/json.hpp>

namespace redfish
{
namespace service_util
{
static constexpr const char* serviceManagerService =
    "xyz.openbmc_project.Control.Service.Manager";
static constexpr const char* serviceManagerPath =
    "/xyz/openbmc_project/control/service/";
static constexpr const char* serviceConfigInterface =
    "xyz.openbmc_project.Control.Service.Attributes";
static constexpr const char* portConfigInterface =
    "xyz.openbmc_project.Control.Service.SocketAttributes";

static bool matchService(const sdbusplus::message::object_path& objPath,
                         const std::string& serviceName)
{
    // For service named as <unitName>@<instanceName>, only compare the unitName
    // part. In DBus object path, '@' is escaped as "_40"
    // service-config-manager's object path is NOT encoded with sdbusplus, so
    // here we have to use the hardcoded "_40" to match
    std::string fullUnitName = objPath.filename();

    // If either serviceName or fullUnitName contains "_40", we need to be more
    // careful
    if (serviceName.find("_40") != std::string::npos ||
        fullUnitName.find("_40") != std::string::npos)
    {
        // If serviceName has "_40", do exact match
        if (serviceName.find("_40") != std::string::npos)
        {
            return fullUnitName == serviceName;
        }
        // If only fullUnitName has "_40", compare unit name part
        else
        {
            size_t pos = fullUnitName.find("_40");
            return fullUnitName.substr(0, pos) == serviceName;
        }
    }

    // Neither has "_40", do exact match
    return fullUnitName == serviceName;
}

inline void getSerialConsoleSshMasked(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& serviceName,
    const nlohmann::json::json_pointer& valueJsonPtr)
{
    dbus::utility::getProperty<bool>(
        serviceManagerService, serviceManagerPath + serviceName,
        serviceConfigInterface, "Masked",
        [asyncResp,
         valueJsonPtr](const boost::system::error_code& ec, bool eventValue) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-BUS response error on Masked Get: {}", ec);
                return;
            }

            // Use JSON pointer to set the value directly
            asyncResp->res.jsonValue[valueJsonPtr] = eventValue;

            asyncResp->res.jsonValue["Oem"]["Ami"]["@odata.type"] =
                json_util::odataType("AmiManagerNetworkProtocol");
        });
}

inline void getMasked(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                      const std::string& serviceName,
                      const std::string& ObjectName,
                      const std::string& propertyName,
                      const std::optional<std::string>& vendorName)
{
    dbus::utility::getProperty<bool>(
        serviceManagerService, serviceManagerPath + serviceName,
        serviceConfigInterface, propertyName,
        [asyncResp, vendorName, ObjectName,
         propertyName](const boost::system::error_code& ec, bool eventValue) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-BUS response error on EventSeverity Get{}",
                                 ec);
                return;
            }
            if (vendorName)
            {
                asyncResp->res
                    .jsonValue["Oem"][*vendorName][ObjectName][propertyName] =
                    eventValue;
            }
            else
            {
                asyncResp->res
                    .jsonValue["Oem"]["Ami"][ObjectName][propertyName] =
                    eventValue;
            }
            asyncResp->res.jsonValue["Oem"]["Ami"]["@odata.type"] =
                json_util::odataType("AmiManagerNetworkProtocol");
        });
}

inline void getMaskedStatus(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& serviceName, const std::string& ObjectName,
    const std::string& propertyName,
    std::function<void(bool)> callback) // Use a callback to handle the result
{
    sdbusplus::asio::getProperty<bool>(
        *crow::connections::systemBus, serviceManagerService,
        serviceManagerPath + serviceName, serviceConfigInterface, propertyName,
        [asyncResp, ObjectName, propertyName,
         callback](const boost::system::error_code& ec, bool eventValue) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-BUS response error on {} Get for {}: {}",
                                 propertyName, ObjectName, ec);
                callback(false); // Default to false on error
                return;
            }
            BMCWEB_LOG_DEBUG("getMaskedStatus = {}", eventValue);
            callback(eventValue); // Pass the result to the callback
        });
}

// Resolve the correct obmc-console service name for a dual-node serial
// interface by enumerating the service manager's managed objects and
// looking for object paths containing "obmc_2dconsole_40tty".
//
// Mapping (IPMI-SOL = node1, IPMI-SOL1 = node2):
//   LPC  : ttyS13  -> IPMI-SOL,   ttyS3     -> IPMI-SOL1
//   eSPI : ttyVUART0 -> IPMI-SOL, ttyVUART1 -> IPMI-SOL1
//
// Once the service name is resolved, the callback is invoked with it.
// On failure (no matching service found), an internalError is set and
// the callback receives an empty string.
inline void resolveConsoleServiceName(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& serialName,
    std::function<void(const std::string&)> callback)
{
    sdbusplus::message::object_path basePath(
        "/xyz/openbmc_project/control/service");

    dbus::utility::getManagedObjects(
        serviceManagerService, basePath,
        [asyncResp, serialName, callback = std::move(callback)](
            const boost::system::error_code& ec,
            const dbus::utility::ManagedObjectType& objects) {
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "Failed to getManagedObjects from Service.Manager: {}", ec);
                messages::internalError(asyncResp->res);
                callback("");
                return;
            }

            // Collect all obmc_2dconsole_40tty* object names
            // and find the one that maps to the requested serialName.
            //
            // IPMI-SOL  (node1): ttyS13 or ttyVUART0
            // IPMI-SOL1 (node2): ttyS3  or ttyVUART1
            std::string resolved;
            for (const auto& [objPath, interfaces] : objects)
            {
                std::string filename = objPath.filename();
                if (filename.find("obmc_2dconsole_40tty") == std::string::npos)
                {
                    continue;
                }

                bool matchesNode1 = (filename == "obmc_2dconsole_40ttyS13" ||
                                     filename == "obmc_2dconsole_40ttyVUART0");
                bool matchesNode2 = (filename == "obmc_2dconsole_40ttyS3" ||
                                     filename == "obmc_2dconsole_40ttyVUART1");

                if (serialName == "IPMI-SOL" && matchesNode1)
                {
                    resolved = filename;
                    break;
                }
                if (serialName == "IPMI-SOL1" && matchesNode2)
                {
                    resolved = filename;
                    break;
                }
            }

            if (resolved.empty())
            {
                BMCWEB_LOG_ERROR("No obmc-console tty service found for {}",
                                 serialName);
                messages::internalError(asyncResp->res);
            }
            callback(resolved);
        });
}

inline void getRunning(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                       const std::string& serviceName,
                       const nlohmann::json::json_pointer& valueJsonPtr)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp, serviceName,
         valueJsonPtr](const boost::system::error_code ec,
                       const dbus::utility::ManagedObjectType& objects) {
            if (ec)
            {
                messages::internalError(asyncResp->res);
                return;
            }

            bool serviceFound = false;
            for (const auto& [path, interfaces] : objects)
            {
                if (matchService(path, serviceName))
                {
                    serviceFound = true;
                    for (const auto& [interface, properties] : interfaces)
                    {
                        if (interface != serviceConfigInterface)
                        {
                            continue;
                        }

                        for (const auto& [key, val] : properties)
                        {
                            // Service is enabled if one instance is running or
                            // enabled
                            if (key == "Running")
                            {
                                const auto* runningStatus =
                                    std::get_if<bool>(&val);
                                if (runningStatus == nullptr)
                                {
                                    messages::internalError(asyncResp->res);
                                    return;
                                }
                                if (*runningStatus)
                                {
                                    asyncResp->res.jsonValue[valueJsonPtr] =
                                        true;
                                    if (serviceName == "start_2dipkvm")
                                        asyncResp->res.jsonValue
                                            ["GraphicalConsole"]
                                            ["MaxConcurrentSessions"] = 1;
                                    return;
                                }
                                else
                                {
                                    if (serviceName == "start_2dipkvm")
                                        asyncResp->res.jsonValue
                                            ["GraphicalConsole"]
                                            ["MaxConcurrentSessions"] = 0;
                                }
                            }
                        }
                    }
                }
            }
            // Not populating the property when service is not found
            if (serviceFound)
            {
                asyncResp->res.jsonValue[valueJsonPtr] = false;
            }
        },
        serviceManagerService, "/xyz/openbmc_project/control/service",
        "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");
}
inline void getEnabled(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                       const std::string& objectName,
                       const nlohmann::json::json_pointer& valueJsonPtr)
{
    constexpr std::array<std::string_view, 1> interfaces = {
        serviceConfigInterface};

    dbus::utility::getSubTreePaths(
        "/xyz/openbmc_project/control/service", 0, interfaces,
        [asyncResp, objectName, valueJsonPtr](
            const boost::system::error_code& ec,
            const dbus::utility::MapperGetSubTreePathsResponse& subtreePaths) {
            if (ec)
            {
                // Don't report error; the field was already prepopulated with a
                // safe default (false)
                return;
            }

            std::string matchedObjectPath;
            for (const std::string& pathStr : subtreePaths)
            {
                if (matchService(sdbusplus::message::object_path(pathStr),
                                 objectName))
                {
                    matchedObjectPath = pathStr;
                    break;
                }
            }

            if (matchedObjectPath.empty())
            {
                asyncResp->res.jsonValue[valueJsonPtr] = false;
                return;
            }

            dbus::utility::getProperty<bool>(
                serviceManagerService, matchedObjectPath,
                serviceConfigInterface, "Running",
                [asyncResp, objectName,
                 valueJsonPtr](const boost::system::error_code& runningEc,
                               bool isRunning) {
                    if (runningEc)
                    {
                        asyncResp->res.jsonValue[valueJsonPtr] = false;
                        return;
                    }

                    // Service enabled depends only on Running.
                    asyncResp->res.jsonValue[valueJsonPtr] = isRunning;

                    if (objectName == "start_2dipkvm" ||
                        objectName == "start_2dipkvm1")
                    {
                        asyncResp->res.jsonValue["GraphicalConsole"]
                                                ["MaxConcurrentSessions"] =
                            isRunning ? 1 : 0;
                    }
                });
        });
}

inline void getPortNumber(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                          const std::string& serviceName,
                          const nlohmann::json::json_pointer& valueJsonPtr)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp, serviceName,
         valueJsonPtr](const boost::system::error_code ec,
                       const dbus::utility::ManagedObjectType& objects) {
            if (ec)
            {
                messages::internalError(asyncResp->res);
                return;
            }

            bool serviceFound = false;
            for (const auto& [path, interfaces] : objects)
            {
                if (matchService(path, serviceName))
                {
                    serviceFound = true;
                    for (const auto& [interface, properties] : interfaces)
                    {
                        if (interface != portConfigInterface)
                        {
                            continue;
                        }

                        for (const auto& [key, val] : properties)
                        {
                            // For service with multiple instances, return the
                            // port of first instance found as redfish only
                            // support one port value, they should be same
                            if (key == "Port")
                            {
                                const auto* port = std::get_if<uint16_t>(&val);
                                if (port == nullptr)
                                {
                                    messages::internalError(asyncResp->res);
                                    return;
                                }
                                asyncResp->res.jsonValue[valueJsonPtr] = *port;
                                return;
                            }
                        }
                    }
                }
            }
            // Not populating the property when service is not found
            if (serviceFound)
            {
                asyncResp->res.jsonValue[valueJsonPtr] = 0;
            }
        },
        serviceManagerService, "/xyz/openbmc_project/control/service",
        "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");
}

template <typename T>
static inline void setProperty(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& path, const std::string& interface,
    const std::string& property, T value)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code ec) {
            if (ec)
            {
                messages::internalError(asyncResp->res);
                return;
            }
            asyncResp->res.result(boost::beast::http::status::no_content);
        },
        serviceManagerService, path, "org.freedesktop.DBus.Properties", "Set",
        interface, property, dbus::utility::DbusVariantType{value});
}

inline void setMasked(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                      const std::string& serviceName, const bool masked,
                      std::function<void()> onSuccess = nullptr)
{
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, serviceManagerService,
        serviceManagerPath + serviceName, serviceConfigInterface, "Masked",
        masked, [asyncResp, onSuccess](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-Bus responses error: {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }
            if (onSuccess)
            {
                onSuccess();
            }
        });
}

inline void setEnabled(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                       const std::string& serviceName, const bool enabled)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp, serviceName,
         enabled](const boost::system::error_code ec,
                  const dbus::utility::ManagedObjectType& objects) {
            if (ec)
            {
                messages::internalError(asyncResp->res);
                return;
            }

            bool serviceFound = false;
            for (const auto& [path, _] : objects)
            {
                if (matchService(path, serviceName))
                {
                    serviceFound = true;
                    setProperty(asyncResp, path, serviceConfigInterface,
                                "Running", enabled);
                    setProperty(asyncResp, path, serviceConfigInterface,
                                "Enabled", enabled);
                }
            }

            // The Redfish property will not be populated in if service is not
            // found, return PropertyUnknown for PATCH request
            if (!serviceFound)
            {
                messages::propertyUnknown(asyncResp->res, "Enabled");
                return;
            }
        },
        serviceManagerService, "/xyz/openbmc_project/control/service",
        "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");
}

inline void setPortNumber(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                          const std::string& serviceName,
                          const uint16_t portNumber)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp, serviceName,
         portNumber](const boost::system::error_code ec,
                     const dbus::utility::ManagedObjectType& objects) {
            if (ec)
            {
                messages::internalError(asyncResp->res);
                return;
            }

            bool serviceFound = false;
            for (const auto& [path, _] : objects)
            {
                if (matchService(path, serviceName))
                {
                    serviceFound = true;
                    setProperty(asyncResp, path, portConfigInterface, "Port",
                                portNumber);
                }
            }

            // The Redfish property will not be populated in if service is not
            // found, return PropertyUnknown for PATCH request
            if (!serviceFound)
            {
                messages::propertyUnknown(asyncResp->res, "Enabled");
                return;
            }
        },
        serviceManagerService, "/xyz/openbmc_project/control/service",
        "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");
}

inline void setServiceEnabled(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& serviceName, const bool enabled)
{
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, serviceManagerService,
        serviceManagerPath + serviceName, serviceConfigInterface, "Enabled",
        enabled, [asyncResp](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "setServiceEnabled D-Bus error for service: {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }
        });
}

inline void getAllAvailableTtyServices(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    std::function<void(const std::vector<std::string>&)> callback)
{
    constexpr std::array<std::string_view, 1> interfaces = {
        serviceConfigInterface};

    dbus::utility::getSubTreePaths(
        "/xyz/openbmc_project/control/service", 0, interfaces,
        [asyncResp, callback](
            const boost::system::error_code& ec,
            const dbus::utility::MapperGetSubTreePathsResponse& subtreePaths) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-Bus error when getting TTY services: {}",
                                 ec);
                messages::internalError(asyncResp->res);
                callback({});
                return;
            }

            std::vector<std::string> availableTtys;
            // Look for console services matching the pattern
            // obmc_2dconsole_40tty*
            for (const std::string& path : subtreePaths)
            {
                const size_t lastSlash = path.rfind('/');
                if (lastSlash == std::string::npos)
                {
                    continue;
                }

                std::string serviceName = path.substr(lastSlash + 1);
                if (serviceName.find("obmc_2dconsole_40tty") == 0)
                {
                    // Extract the tty part (e.g., "ttyS0" from
                    // "obmc_2dconsole_40ttyS0")
                    availableTtys.push_back(serviceName.substr(
                        std::string("obmc_2dconsole_40").size()));
                }
            }
            callback(availableTtys);
        });
}

} // namespace service_util
} // namespace redfish
