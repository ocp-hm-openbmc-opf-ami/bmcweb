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
    size_t pos = fullUnitName.find("_40");
    return fullUnitName.substr(0, pos) == serviceName;
}

void getSerialConsoleSshMasked(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& serviceName, const std::string& ObjectName,
    const std::string& subObjectName, const std::string& propertyName)
{
    sdbusplus::asio::getProperty<bool>(
        *crow::connections::systemBus, serviceManagerService,
        serviceManagerPath + serviceName, serviceConfigInterface, "Masked",
        [asyncResp, ObjectName, subObjectName,
         propertyName](const boost::system::error_code& ec, bool eventValue) {
        if (ec)
        {
            BMCWEB_LOG_ERROR("D-BUS response error on EventSeverity Get{}", ec);
            // messages::internalError(asyncResp->res);
            return;
        }
        asyncResp->res.jsonValue["Oem"]["OpenBmc"][ObjectName][subObjectName]
                                [propertyName] = eventValue;
        asyncResp->res.jsonValue["Oem"]["OpenBmc"][ObjectName][subObjectName]
                                ["@odata.type"] = "#AMIManagerNetworkProtocol.v1_0_0.AMIManagerNetworkProtocol";
    });
}

void getMasked(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
               const std::string& serviceName, const std::string& ObjectName,
               const std::string& propertyName)
{
    sdbusplus::asio::getProperty<bool>(
        *crow::connections::systemBus, serviceManagerService,
        serviceManagerPath + serviceName, serviceConfigInterface, propertyName,
        [asyncResp, ObjectName,
         propertyName](const boost::system::error_code& ec, bool eventValue) {
        if (ec)
        {
            BMCWEB_LOG_ERROR("D-BUS response error on EventSeverity Get{}", ec);
            // messages::internalError(asyncResp->res);
            return;
        }
        asyncResp->res.jsonValue["Oem"]["OpenBmc"][ObjectName][propertyName] =
            eventValue;
        if(ObjectName == "IPMB")
        {
            asyncResp->res.jsonValue["Oem"]["OpenBmc"][ObjectName]["@odata.type"] =
            "#AMIManagerNetworkProtocol.v1_0_0.AMIIPMB";
        }
        else
        {
            asyncResp->res.jsonValue["Oem"]["OpenBmc"][ObjectName]["@odata.type"] =
            "#AMIManagerNetworkProtocol.v1_0_0.AMIManagerNetworkProtocol";
        }
        
    });
}
void getRunning(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
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
                            const auto* runningStatus = std::get_if<bool>(&val);
                            if (runningStatus == nullptr)
                            {
                                messages::internalError(asyncResp->res);
                                return;
                            }
                            if (*runningStatus)
                            {
                                asyncResp->res.jsonValue[valueJsonPtr] = true;
                                return;
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
void getEnabled(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
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
                        if (key == "Enabled")
                        {
                            const auto* enabled = std::get_if<bool>(&val);
                            if (enabled == nullptr)
                            {
                                messages::internalError(asyncResp->res);
                                return;
                            }
                            if (*enabled)
                            {
                                asyncResp->res.jsonValue[valueJsonPtr] = true;
                                if (serviceName == "start_2dipkvm")
                                    asyncResp->res
                                        .jsonValue["GraphicalConsole"]
                                                  ["MaxConcurrentSessions"] = 1;
                                return;
                            }
                            else
                            {
                                if (serviceName == "start_2dipkvm")
                                    asyncResp->res
                                        .jsonValue["GraphicalConsole"]
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

void getPortNumber(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
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
static inline void
    setProperty(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
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
    }, serviceManagerService, path, "org.freedesktop.DBus.Properties", "Set",
        interface, property, dbus::utility::DbusVariantType{value});
}

void setMasked(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
               const std::string& serviceName, const bool enabled)
{
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, serviceManagerService,
        serviceManagerPath + serviceName, serviceConfigInterface, "Masked",
        enabled, [asyncResp](const boost::system::error_code& ec) {
        if (ec)
        {
            BMCWEB_LOG_ERROR("D-Bus responses error: {}", ec);
            messages::internalError(asyncResp->res);
            return;
        }
    });
}

void setEnabled(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
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
                setProperty(asyncResp, path, serviceConfigInterface, "Running",
                            enabled);
                setProperty(asyncResp, path, serviceConfigInterface, "Enabled",
                            enabled);
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

void setPortNumber(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& serviceName, const uint16_t portNumber)
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

} // namespace service_util
} // namespace redfish
