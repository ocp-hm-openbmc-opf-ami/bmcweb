// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
// SPDX-FileCopyrightText: Copyright 2018 Intel Corporation
#pragma once

#include "app.hpp"
#include "dbus_utility.hpp"
#include "error_messages.hpp"
#include "generated/enums/resource.hpp"
#include "query.hpp"
#include "redfish_util.hpp"
#include "registries/privilege_registry.hpp"
#include "utils/json_utils.hpp"
#include "utils/stl_utils.hpp"

#include <boost/system/error_code.hpp>
#include <boost/url/format.hpp>
#include <sdbusplus/asio/property.hpp>
#include <utils/service_utils.hpp>

#include <array>
#include <optional>
#include <string_view>
#include <variant>
#include <vector>

namespace redfish
{

void getNTPProtocolEnabled(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp);
std::string getHostName();

static constexpr const char* serviceManagerService =
    "xyz.openbmc_project.Control.Service.Manager";
static constexpr const char* serviceManagerPath =
    "/xyz/openbmc_project/control/service/";
static constexpr const char* portConfigInterface =
    "xyz.openbmc_project.Control.Service.SocketAttributes";

static constexpr const char* sshServiceName = "dropbear";
static constexpr const char* httpsServiceName = "bmcweb";
static constexpr const char* ipmbServiceName = "ipmb";
static constexpr const char* ipmiServiceName = "phosphor_2dipmi_2dnet_40eth0";

// Mapping from Redfish NetworkProtocol key name to backend service that hosts
// that protocol.
static constexpr std::array<std::pair<const char*, const char*>, 4>

    networkProtocolToDbus = {{{"SSH", sshServiceName},
                              {"HTTPS", httpsServiceName},
                              {"IPMI", ipmiServiceName},
                              {"IPMB", ipmbServiceName}}};

inline void extractNTPServersAndDomainNamesData(
    const dbus::utility::ManagedObjectType& dbusData,
    std::vector<std::string>& ntpData, std::vector<std::string>& dynamicNtpData,
    std::vector<std::string>& dnData)
{
    for (const auto& obj : dbusData)
    {
        for (const auto& ifacePair : obj.second)
        {
            if (ifacePair.first !=
                "xyz.openbmc_project.Network.EthernetInterface")
            {
                continue;
            }

            for (const auto& propertyPair : ifacePair.second)
            {
                if (propertyPair.first == "StaticNTPServers")
                {
                    const std::vector<std::string>* ntpServers =
                        std::get_if<std::vector<std::string>>(
                            &propertyPair.second);
                    if (ntpServers != nullptr)
                    {
                        ntpData.insert(ntpData.end(), ntpServers->begin(),
                                       ntpServers->end());
                    }
                    else if (propertyPair.first == "NTPServers")
                    {
                        const std::vector<std::string>* dynamicNtpServers =
                            std::get_if<std::vector<std::string>>(
                                &propertyPair.second);
                        if (dynamicNtpServers != nullptr)
                        {
                            dynamicNtpData = *dynamicNtpServers;
                        }
                    }
                }
                else if (propertyPair.first == "DomainName")
                {
                    const std::vector<std::string>* domainNames =
                        std::get_if<std::vector<std::string>>(
                            &propertyPair.second);
                    if (domainNames != nullptr)
                    {
                        dnData.insert(dnData.end(), domainNames->begin(),
                                      domainNames->end());
                    }
                }
            }
        }
    }
    stl_utils::removeDuplicate(ntpData);
    stl_utils::removeDuplicate(dnData);
}

template <typename CallbackFunc>
void getEthernetIfaceData(CallbackFunc&& callback)
{
    sdbusplus::message::object_path path("/xyz/openbmc_project/network");
    dbus::utility::getManagedObjects(
        "xyz.openbmc_project.Network", path,
        [callback = std::forward<CallbackFunc>(callback)](
            const boost::system::error_code& ec,
            const dbus::utility::ManagedObjectType& dbusData) {
            std::vector<std::string> ntpServers;
            std::vector<std::string> dynamicNtpServers;
            std::vector<std::string> domainNames;

            if (ec)
            {
                callback(false, ntpServers, dynamicNtpServers, domainNames);
                return;
            }

            extractNTPServersAndDomainNamesData(dbusData, ntpServers,
                                                dynamicNtpServers, domainNames);

            callback(true, ntpServers, dynamicNtpServers, domainNames);
        });
}

inline void afterNetworkPortRequest(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const boost::system::error_code& ec,
    const std::vector<std::tuple<std::string, std::string, bool>>& socketData)
{
    if (ec)
    {
        messages::internalError(asyncResp->res);
        return;
    }
    for (const auto& data : socketData)
    {
        const std::string& socketPath = get<0>(data);
        const std::string& protocolName = get<1>(data);
        bool isProtocolEnabled = get<2>(data);

        asyncResp->res.jsonValue[protocolName]["ProtocolEnabled"] =
            isProtocolEnabled;
        asyncResp->res.jsonValue[protocolName]["Port"] = nullptr;
        getPortNumber(socketPath, [asyncResp, protocolName](
                                      const boost::system::error_code& ec2,
                                      int portNumber) {
            if (ec2)
            {
                messages::internalError(asyncResp->res);
                return;
            }
            asyncResp->res.jsonValue[protocolName]["Port"] = portNumber;
        });
    }
}

inline void
    getSNMPProtocolEnabled(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    dbus::utility::getProperty<bool>(
        "xyz.openbmc_project.Snmp", "/xyz/openbmc_project/Snmp",
        "xyz.openbmc_project.Snmp.SnmpUtils", "SnmpTrapStatus",
        [asyncResp](const boost::system::error_code& ec, bool protocolEnabled) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-BUS response error on SnmpTrapStatus Get{}",
                                 ec);
                messages::internalError(asyncResp->res);
                return;
            }
            asyncResp->res.jsonValue["SNMP"]["Port"] = 162;
            asyncResp->res.jsonValue["SNMP"]["ProtocolEnabled"] =
                protocolEnabled;
        });
}

inline void
    getSNMPVersionEnabled(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    dbus::utility::getProperty<bool>(
        "xyz.openbmc_project.Snmp", "/xyz/openbmc_project/Snmp",
        "xyz.openbmc_project.Snmp.SnmpConf", "disableSNMPv1",
        [asyncResp](const boost::system::error_code& ec, bool enableSNMPv1) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-BUS response error on SnmpTrapStatus Get{}",
                                 ec);
                messages::internalError(asyncResp->res);
                return;
            }
            asyncResp->res.jsonValue["SNMP"]["EnableSNMPv1"] = !enableSNMPv1;
        });

    dbus::utility::getProperty<bool>(
        "xyz.openbmc_project.Snmp", "/xyz/openbmc_project/Snmp",
        "xyz.openbmc_project.Snmp.SnmpConf", "disableSNMPv2c",
        [asyncResp](const boost::system::error_code& ec, bool enableSNMPv2c) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-BUS response error on SnmpTrapStatus Get{}",
                                 ec);
                messages::internalError(asyncResp->res);
                return;
            }
            asyncResp->res.jsonValue["SNMP"]["EnableSNMPv2c"] = !enableSNMPv2c;
        });

    dbus::utility::getProperty<bool>(
        "xyz.openbmc_project.Snmp", "/xyz/openbmc_project/Snmp",
        "xyz.openbmc_project.Snmp.SnmpConf", "disableSNMPv3",
        [asyncResp](const boost::system::error_code& ec, bool enableSNMPv3) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-BUS response error on SnmpTrapStatus Get{}",
                                 ec);
                messages::internalError(asyncResp->res);
                return;
            }
            asyncResp->res.jsonValue["SNMP"]["EnableSNMPv3"] = !enableSNMPv3;
        });
}

inline void getNetworkData(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                           const crow::Request& req)
{
    if (req.session == nullptr)
    {
        messages::internalError(asyncResp->res);
        return;
    }

    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/ManagerNetworkProtocol/NetworkProtocol.json>; rel=describedby");
    asyncResp->res.jsonValue["@odata.type"] =
        "#ManagerNetworkProtocol.v1_9_0.ManagerNetworkProtocol";
    asyncResp->res.jsonValue["@odata.id"] =
        boost::urls::format("/redfish/v1/Managers/{}/NetworkProtocol",
                            BMCWEB_REDFISH_MANAGER_URI_NAME);
    asyncResp->res.jsonValue["Id"] = "NetworkProtocol";
    asyncResp->res.jsonValue["Name"] = "Manager Network Protocol";
    asyncResp->res.jsonValue["Description"] = "Manager Network Service";
    asyncResp->res.jsonValue["Status"]["Health"] = resource::Health::OK;
    asyncResp->res.jsonValue["Status"]["HealthRollup"] = resource::Health::OK;
    asyncResp->res.jsonValue["Status"]["State"] = resource::State::Enabled;

    // HTTP is Mandatory attribute as per OCP Baseline Profile - v1.0.0,
    // but from security perspective it is not recommended to use.
    // Hence using protocolEnabled as false to make it OCP and security-wise
    // compliant
    asyncResp->res.jsonValue["HTTP"]["Port"] = nullptr;
    asyncResp->res.jsonValue["HTTP"]["ProtocolEnabled"] = false;

    // The ProtocolEnabled of the following protocols is determined by
    // inspecting the state of associated systemd sockets. If these protocols
    // have been disabled, then the systemd socket unit files will not be found
    // and the protocols will not be returned in this Redfish query. Set some
    // defaults to ensure something is always returned.
    for (const auto& nwkProtocol : networkProtocolToDbus)
    {
        if (nwkProtocol.first != std::string("IPMB"))
        {
            asyncResp->res.jsonValue[nwkProtocol.first]["Port"] = nullptr;
            asyncResp->res.jsonValue[nwkProtocol.first]["ProtocolEnabled"] =
                false;
        }
        else
        {
            asyncResp->res
                .jsonValue["Oem"]["OpenBmc"][nwkProtocol.first]["Port"] =
                nullptr;
            asyncResp->res.jsonValue["Oem"]["OpenBmc"][nwkProtocol.first]
                                    ["ProtocolEnabled"] = false;
        }

        if (nwkProtocol.first == std::string("IPMI"))
        {
            asyncResp->res.jsonValue[nwkProtocol.first]["Port"] = 623;
            asyncResp->res.jsonValue[nwkProtocol.first]["ProtocolEnabled"] =
                false;
        }
    }

    std::string hostName = getHostName();

    asyncResp->res.jsonValue["HostName"] = hostName;

    getNTPProtocolEnabled(asyncResp);
    getSNMPProtocolEnabled(asyncResp);
    getSNMPVersionEnabled(asyncResp);

    getEthernetIfaceData([hostName, asyncResp](
                             const bool& success,
                             const std::vector<std::string>& ntpServers,
                             const std::vector<std::string>& dynamicNtpServers,
                             const std::vector<std::string>& domainNames) {
        if (!success)
        {
            messages::resourceNotFound(asyncResp->res, "ManagerNetworkProtocol",
                                       "NetworkProtocol");
            return;
        }
        asyncResp->res.jsonValue["NTP"]["NTPServers"] = ntpServers;
        asyncResp->res.jsonValue["NTP"]["NetworkSuppliedServers"] =
            dynamicNtpServers;
        if (!hostName.empty())
        {
            std::string fqdn = hostName;
            if (!domainNames.empty())
            {
                fqdn += ".";
                fqdn += domainNames[0];
            }
            asyncResp->res.jsonValue["FQDN"] = std::move(fqdn);
        }
    });

    Privileges effectiveUserPrivileges =
        redfish::getUserPrivileges(*req.session);

    // /redfish/v1/Managers/bmc/NetworkProtocol/HTTPS/Certificates is
    // something only ConfigureManager can access then only display when
    // the user has permissions ConfigureManager
    if (isOperationAllowedWithPrivileges({{"ConfigureManager"}},
                                         effectiveUserPrivileges))
    {
        asyncResp->res.jsonValue["HTTPS"]["Certificates"]["@odata.id"] =
            boost::urls::format(
                "/redfish/v1/Managers/{}/NetworkProtocol/HTTPS/Certificates",
                BMCWEB_REDFISH_MANAGER_URI_NAME);
    }

    for (const auto& protocol : networkProtocolToDbus)
    {
        const std::string& protocolName = protocol.first;
        const std::string& serviceName = protocol.second;

        std::cerr << "protocolName " << protocolName << "\n";
        std::cerr << "serviceName " << serviceName << "\n";
        if (ipmbServiceName == serviceName)
        {
            service_util::getEnabled(
                asyncResp, serviceName,
                nlohmann::json::json_pointer(
                    "/Oem/OpenBmc/" + protocolName + "/ProtocolEnabled"));
            service_util::getPortNumber(
                asyncResp, serviceName,
                nlohmann::json::json_pointer(
                    "/Oem/OpenBmc/" + protocolName + "/Port"));
        }
        else
        {
            if (ipmiServiceName != serviceName)
            {
                service_util::getEnabled(
                    asyncResp, serviceName,
                    nlohmann::json::json_pointer(
                        std::string("/") + protocolName + "/ProtocolEnabled"));
            }
            service_util::getPortNumber(
                asyncResp, serviceName,
                nlohmann::json::json_pointer(
                    std::string("/") + protocolName + "/Port"));
        }
    }

} // namespace redfish

inline void afterSetNTP(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                        const boost::system::error_code& ec)
{
    if (ec)
    {
        BMCWEB_LOG_DEBUG("Failed to set elapsed time. DBUS response error {}",
                         ec);
        messages::internalError(asyncResp->res);
        return;
    }
    asyncResp->res.result(boost::beast::http::status::no_content);
}

inline void handleNTPProtocolEnabled(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp, bool ntpEnabled)
{
    bool interactive = false;
    auto callback = [asyncResp](const boost::system::error_code& ec) {
        afterSetNTP(asyncResp, ec);
    };
    crow::connections::systemBus->async_method_call(
        std::move(callback), "org.freedesktop.timedate1",
        "/org/freedesktop/timedate1", "org.freedesktop.timedate1", "SetNTP",
        ntpEnabled, interactive);
}

// Redfish states that ip addresses can be
// string, to set a value
// null, to delete the value
// object_t, empty json object, to ignore the value
using IpAddress =
    std::variant<std::string, nlohmann::json::object_t, std::nullptr_t>;

inline void storeNtpServers(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                     const std::vector<IpAddress>& NTPServers,
                     std::vector<nlohmann::json>& input)
{
    for (size_t index = 0; index < NTPServers.size(); index++)
    {
        const IpAddress& ntpServer = NTPServers[index];
        const std::string* ntpServerStr = std::get_if<std::string>(&ntpServer);
        if (ntpServerStr == nullptr)
        {
            messages::internalError(asyncResp->res);
            return;
        }
        // If the variant holds a string, store it in the input vector as a JSON
        // string
        input.push_back(*ntpServerStr);
    }
}

inline void handleNTPServersPatch(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    // const std::vector<nlohmann::json>& ntpServerObjects,
    const std::vector<IpAddress>& ntpServerObjects,
    std::vector<std::string> currentNtpServers)
{
    std::vector<std::string>::iterator currentNtpServer =
        currentNtpServers.begin();

    size_t limit = 3;

    std::vector<nlohmann::json> ntpServerJsonObjects;
    storeNtpServers(asyncResp, ntpServerObjects, ntpServerJsonObjects);

    if (ntpServerObjects.size() > limit)
    {
        BMCWEB_LOG_DEBUG("out of Limit");
        messages::propertyValueOutOfRange(asyncResp->res, ntpServerJsonObjects,
                                          "NTP/NTPServers");
        return;
    }

    auto isValidNtpServer = [](const std::string& server) -> bool {
        for (char c : server)
        {
            if (!isdigit(c) && !isalpha(c) && c != '-' && c != '.')
            {
                return false; // Found an invalid character
            }
        }
        return true; // All characters are valid
    };

    /*for (const auto& ntpServerObject : ntpServerObjects)
    {
        // std::string ntpServerAddress = ntpServerObject.get<std::string>();
        //  const std::string* ntpServerAddress =
        //      std::get_if<std::string>(&ntpServerObject);

        // if (!isValidNtpServer(ntpServerAddress))
        if (!ntpServerObject.empty() && ntpServerObject.is_string() &&
            !isValidNtpServer(ntpServerObject.get<std::string>()))
        {
            BMCWEB_LOG_DEBUG("Invalid character found in NTP server address.");
            messages::propertyValueFormatError(asyncResp->res, ntpServerObject,
                                               "NTPServers");
            return;
        }
    }*/

    for (size_t index = 0; index < ntpServerObjects.size(); index++)
    {
        const IpAddress& ntpServer = ntpServerObjects[index];
        // const nlohmann::json& ntpServer = ntpServerObjects[index];
        if (std::holds_alternative<std::nullptr_t>(ntpServer))
        // (ntpServer.is_null())
        {
            // Can't delete an item that doesn't exist
            if (currentNtpServer == currentNtpServers.end())
            {
                messages::propertyValueNotInList(
                    asyncResp->res, "null",
                    "NTP/NTPServers/" + std::to_string(index));

                return;
            }
            currentNtpServer = currentNtpServers.erase(currentNtpServer);
            continue;
        }
        const nlohmann::json::object_t* ntpServerObject =
            std::get_if<nlohmann::json::object_t>(&ntpServer);
        // ntpServer.get_ptr<const nlohmann::json::object_t*>();
        if (ntpServerObject != nullptr)
        {
            if (!ntpServerObject->empty())
            {
                messages::propertyValueNotInList(
                    asyncResp->res, *ntpServerObject,
                    "NTP/NTPServers/" + std::to_string(index));
                return;
            }
            // Can't retain an item that doesn't exist
            if (currentNtpServer == currentNtpServers.end())
            {
                messages::propertyValueOutOfRange(
                    asyncResp->res, *ntpServerObject,
                    "NTP/NTPServers/" + std::to_string(index));

                return;
            }
            // empty objects should leave the NtpServer unmodified
            currentNtpServer++;
            continue;
        }

        const std::string* ntpServerStr = std::get_if<std::string>(&ntpServer);
        // ntpServer.get_ptr<const std::string*>();
        if (ntpServerStr == nullptr)
        {
            messages::internalError(asyncResp->res);
            return;
        }
        if (currentNtpServer == currentNtpServers.end())
        {
            // if we're at the end of the list, append to the end
            currentNtpServers.push_back(*ntpServerStr);
            currentNtpServer = currentNtpServers.end();
            continue;
        }

        if (!isValidNtpServer(*ntpServerStr))
        {
            BMCWEB_LOG_DEBUG("Invalid character found in NTP server address.");
            messages::propertyValueFormatError(asyncResp->res, *ntpServerStr,
                                               "NTPServers");
            return;
        }

        *currentNtpServer = *ntpServerStr;
        currentNtpServer++;
    }

    // Any remaining array elements should be removed
    currentNtpServers.erase(currentNtpServer, currentNtpServers.end());

    constexpr std::array<std::string_view, 1> ethInterfaces = {
        "xyz.openbmc_project.Network.EthernetInterface"};
    dbus::utility::getSubTree(
        "/xyz/openbmc_project", 0, ethInterfaces,
        [asyncResp, currentNtpServers](
            const boost::system::error_code& ec,
            const dbus::utility::MapperGetSubTreeResponse& subtree) {
            if (ec)
            {
                BMCWEB_LOG_WARNING("D-Bus error: {}, {}", ec, ec.message());
                messages::internalError(asyncResp->res);
                return;
            }

            for (const auto& [objectPath, serviceMap] : subtree)
            {
                for (const auto& [service, interfaces] : serviceMap)
                {
                    for (const auto& interface : interfaces)
                    {
                        if (interface !=
                            "xyz.openbmc_project.Network.EthernetInterface")
                        {
                            continue;
                        }

                        setDbusProperty(asyncResp, "NTP/NTPServers/", service,
                                        objectPath, interface,
                                        "StaticNTPServers", currentNtpServers);
                    }
                }
            }
        });
}
inline void setRunning(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                const bool running)
{
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus,
        "xyz.openbmc_project.Control.Service.Manager",
        "/xyz/openbmc_project/control/service/phosphor_2dipmi_2dnet_40eth0",
        "xyz.openbmc_project.Control.Service.Attributes", "Running", running,
        [asyncResp](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-Bus responses error: {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }
        });
}
inline void
    handleProtocolRunning(const bool protocolRunning,
                          const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                          const std::string& netBasePath)
{
    constexpr std::array<std::string_view, 1> interfaces = {
        "xyz.openbmc_project.Control.Service.Attributes"};
    dbus::utility::getSubTree(
        "/xyz/openbmc_project/control/service", 0, interfaces,
        [protocolRunning, asyncResp,
         netBasePath](const boost::system::error_code& ec,
                      const dbus::utility::MapperGetSubTreeResponse& subtree) {
            if (ec)
            {
                messages::internalError(asyncResp->res);
                return;
            }

            for (const auto& entry : subtree)
            {
                if (entry.first.starts_with(netBasePath))
                {
                    setDbusProperty(
                        asyncResp, "IPMI/ProtocolEnabled",
                        entry.second.begin()->first, entry.first,
                        "xyz.openbmc_project.Control.Service.Attributes",
                        "Running", protocolRunning);
                }
            }
        });
}
inline void setEnabled(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                const bool enabled)
{
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus,
        "xyz.openbmc_project.Control.Service.Manager",
        "/xyz/openbmc_project/control/service/phosphor_2dipmi_2dnet_40eth0",
        "xyz.openbmc_project.Control.Service.Attributes", "Enabled", enabled,
        [asyncResp](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-Bus responses error: {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }
        });
}

inline void
    handleProtocolEnabled(const bool protocolEnabled,
                          const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                          const std::string& netBasePath)
{
    constexpr std::array<std::string_view, 1> interfaces = {
        "xyz.openbmc_project.Control.Service.Attributes"};
    dbus::utility::getSubTree(
        "/xyz/openbmc_project/control/service", 0, interfaces,
        [protocolEnabled, asyncResp,
         netBasePath](const boost::system::error_code& ec,
                      const dbus::utility::MapperGetSubTreeResponse& subtree) {
            if (ec)
            {
                messages::internalError(asyncResp->res);
                return;
            }

            for (const auto& entry : subtree)
            {
                if (entry.first.starts_with(netBasePath))
                {
                    if (protocolEnabled)
                    {
                        BMCWEB_LOG_DEBUG("wait for get properties");
                        sleep(5);
                    }
                    setDbusProperty(
                        asyncResp, "IPMI/ProtocolEnabled",
                        entry.second.begin()->first, entry.first,
                        "xyz.openbmc_project.Control.Service.Attributes",
                        "Enabled", protocolEnabled);
                }
            }
        });
}
inline std::string getHostName()
{
    std::string hostName;

    std::array<char, HOST_NAME_MAX + 1> hostNameCStr{};
    if (gethostname(hostNameCStr.data(), hostNameCStr.size()) == 0)
    {
        hostName = hostNameCStr.data();
    }
    return hostName;
}

inline void
    getNTPProtocolEnabled(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    dbus::utility::getProperty<bool>(
        "org.freedesktop.timedate1", "/org/freedesktop/timedate1",
        "org.freedesktop.timedate1", "NTP",
        [asyncResp](const boost::system::error_code& ec, bool enabled) {
            if (ec)
            {
                BMCWEB_LOG_WARNING(
                    "Failed to get NTP status, assuming not supported");
                return;
            }

            asyncResp->res.jsonValue["NTP"]["ProtocolEnabled"] = enabled;
        });
}

inline std::string encodeServiceObjectPath(std::string_view serviceName)
{
    sdbusplus::message::object_path objPath(
        "/xyz/openbmc_project/control/service");
    objPath /= serviceName;
    return objPath.str;
}

inline void handleBmcNetworkProtocolHead(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/ManagerNetworkProtocol/ManagerNetworkProtocol.json>; rel=describedby");
}

inline void handleManagersNetworkProtocolPatch(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& managerId)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
    {
        messages::resourceNotFound(asyncResp->res, "Manager", managerId);
        return;
    }

    std::optional<std::string> newHostName;
    std::optional<nlohmann::json> ntp;
    std::optional<nlohmann::json> ipmi;
    std::optional<nlohmann::json> bmcweb;
    std::optional<nlohmann::json> ssh;
    std::optional<nlohmann::json> snmp;
    std::optional<std::string> vId;
    std::optional<bool> bmcwebMasked;
    std::optional<bool> ipmbMasked;
    std::optional<bool> ipmbEnabled;
    std::optional<bool> ipmiMasked;
    std::optional<bool> sshMasked;
    std::optional<bool> ipmiRunning;
    std::optional<bool> bmcwebRunning;
    std::optional<bool> sshRunning;
    std::optional<bool> ipmbRunning;

    // clang-format off
        if (!json_util::readJsonPatch(
                req, asyncResp->res,
                "HostName", newHostName,
                "NTP",ntp,
                "IPMI",ipmi,
                "HTTPS", bmcweb,
                "SSH",ssh,
                "Id", vId,
                "SNMP",snmp,
                "Oem/OpenBmc/HTTPS/Masked",bmcwebMasked,
                "Oem/OpenBmc/IPMB/Masked",ipmbMasked,
                "Oem/OpenBmc/IPMB/ProtocolEnabled",ipmbEnabled,
                "Oem/OpenBmc/IPMI/Masked",ipmiMasked,
                "Oem/OpenBmc/SSH/Masked",sshMasked,
                "Oem/OpenBmc/IPMI/Running",ipmiRunning,
                "Oem/OpenBmc/HTTPS/Running",bmcwebRunning,
                "Oem/OpenBmc/SSH/Running",sshRunning,
                "Oem/OpenBmc/IPMB/Running",ipmbRunning))
        {
            return;
        }
      if(vId)
        {
                messages::propertyNotWritable(asyncResp->res, "Id");
                asyncResp->res.result(boost::beast::http::status::bad_request);
                return;
        }

    // clang-format on

    if (newHostName)
    {
        messages::propertyNotWritable(asyncResp->res, "HostName");
        return;
    }

    if (ntp)
    {
        std::optional<bool> ntpEnabled;
        // std::optional<std::vector<nlohmann::json>> ntpServerObjects;
        std::optional<std::vector<IpAddress>> ntpServerObjects;

        std::size_t ntp_size = ntp.value().size();
        if (ntp_size == 0)
        {
            messages::propertyValueTypeError(asyncResp->res, ntp.value(),
                                             "NTP");
        }
        if (!json_util::readJson( //
                *ntp, asyncResp->res, //
                "ProtocolEnabled", ntpEnabled, //
                "NTPServers", ntpServerObjects //
                ))
        {
            return;
        }
        if (ntpEnabled)
        {
            handleNTPProtocolEnabled(asyncResp, *ntpEnabled);
        }
        if (ntpServerObjects)
        {
            getEthernetIfaceData(
                [asyncResp, ntpServerObjects](
                    const bool success,
                    std::vector<std::string>& currentNtpServers,
                    const std::vector<std::string>& /*dynamicNtpServers*/,
                    const std::vector<std::string>& /*domainNames*/) {
                    if (!success)
                    {
                        messages::internalError(asyncResp->res);
                        return;
                    }
                    handleNTPServersPatch(asyncResp, *ntpServerObjects,
                                          std::move(currentNtpServers));
                });
        }
    }
    if (ipmi)
    {
        std::optional<bool> ipmiEnabled;
        std::size_t ipmi_size = ipmi.value().size();
        if (ipmi_size == 0)
        {
            messages::propertyValueTypeError(asyncResp->res, ipmi.value(),
                                             "IPMI");
        }
        if (!json_util::readJson( //
                *ipmi, asyncResp->res, //
                "ProtocolEnabled", ipmiEnabled //
                ))
        {
            return;
        }
        if (ipmiEnabled)
        {
            /*handleProtocolEnabled(
                *ipmiEnabled, asyncResp,
                encodeServiceObjectPath(std::string(ipmiServiceName)));*/
            setEnabled(asyncResp, *ipmiEnabled);
        }
    }
    if (bmcweb)
    {
        std::optional<bool> bmcwebEnabled;
        std::size_t bmcweb_size = bmcweb.value().size();
        if (bmcweb_size == 0)
        {
            messages::propertyValueTypeError(asyncResp->res, bmcweb.value(),
                                             "HTTPS");
            return;
        }
        if (!json_util::readJson( //
                *bmcweb, asyncResp->res, //
                "ProtocolEnabled", bmcwebEnabled //
                ))
        {
            return;
        }
        if (bmcwebEnabled)
        {
            handleProtocolEnabled(
                *bmcwebEnabled, asyncResp,
                encodeServiceObjectPath(std::string(httpsServiceName)));
        }
    }
    if (ssh)
    {
        std::optional<bool> sshEnabled;
        std::size_t ssh_size = ssh.value().size();
        if (ssh_size == 0)
        {
            messages::propertyValueTypeError(asyncResp->res, ssh.value(),
                                             "SSH");
        }
        if (!json_util::readJson( //
                *ssh, asyncResp->res, //
                "ProtocolEnabled", sshEnabled //
                ))
        {
            return;
        }
        if (sshEnabled)
        {
            handleProtocolEnabled(*sshEnabled, asyncResp,
                                  encodeServiceObjectPath(sshServiceName));
        }
    }
    if (snmp)
    {
        std::optional<bool> enableSNMPv1;
        std::optional<bool> enableSNMPv2c;
        std::optional<bool> enableSNMPv3;
        std::optional<bool> snmpEnabled;
        std::size_t snmp_size = snmp.value().size();
        if (snmp_size == 0)
        {
            messages::propertyValueTypeError(asyncResp->res, snmp.value(),
                                             "SNMP");
        }

        if (!json_util::readJson( //
                *snmp, asyncResp->res, //
                "ProtocolEnabled", snmpEnabled, //
                "EnableSNMPv1", enableSNMPv1, //
                "EnableSNMPv2c", enableSNMPv2c, //
                "EnableSNMPv3", enableSNMPv3 //
                ))
        {
            return;
        }

        if (enableSNMPv1)
        {
            sdbusplus::asio::setProperty(
                *crow::connections::systemBus, "xyz.openbmc_project.Snmp",
                "/xyz/openbmc_project/Snmp",
                "xyz.openbmc_project.Snmp.SnmpConf", "disableSNMPv1",
                !(*enableSNMPv1),
                [asyncResp](const boost::system::error_code& ec) {
                    if (ec)
                    {
                        BMCWEB_LOG_ERROR("D-Bus responses error: {}", ec);
                        messages::internalError(asyncResp->res);
                        return;
                    }
                });
        }
        if (enableSNMPv2c)
        {
            sdbusplus::asio::setProperty(
                *crow::connections::systemBus, "xyz.openbmc_project.Snmp",
                "/xyz/openbmc_project/Snmp",
                "xyz.openbmc_project.Snmp.SnmpConf", "disableSNMPv2c",
                !(*enableSNMPv2c),
                [asyncResp](const boost::system::error_code& ec) {
                    if (ec)
                    {
                        BMCWEB_LOG_ERROR("D-Bus responses error: {}", ec);
                        messages::internalError(asyncResp->res);
                        return;
                    }
                });
        }
        if (enableSNMPv3)
        {
            sdbusplus::asio::setProperty(
                *crow::connections::systemBus, "xyz.openbmc_project.Snmp",
                "/xyz/openbmc_project/Snmp",
                "xyz.openbmc_project.Snmp.SnmpConf", "disableSNMPv3",
                !(*enableSNMPv3),
                [asyncResp](const boost::system::error_code& ec) {
                    if (ec)
                    {
                        BMCWEB_LOG_ERROR("D-Bus responses error: {}", ec);
                        messages::internalError(asyncResp->res);
                        return;
                    }
                });
        }

        if (snmpEnabled)
        {
            sdbusplus::asio::setProperty(
                *crow::connections::systemBus, "xyz.openbmc_project.Snmp",
                "/xyz/openbmc_project/Snmp",
                "xyz.openbmc_project.Snmp.SnmpUtils", "SnmpTrapStatus",
                *snmpEnabled, [asyncResp](const boost::system::error_code& ec) {
                    if (ec)
                    {
                        BMCWEB_LOG_ERROR("D-Bus responses error: {}", ec);
                        messages::internalError(asyncResp->res);
                        return;
                    }
                });
        }
    }
    if (ipmiMasked)
    {
        service_util::setMasked(asyncResp, ipmiServiceName, *ipmiMasked);
    }
    if (bmcwebMasked)
    {
        service_util::setMasked(asyncResp, httpsServiceName, *bmcwebMasked);
    }
    if (ipmbMasked)
    {
        service_util::setMasked(asyncResp, ipmbServiceName, *ipmbMasked);
    }
    if (sshMasked)
    {
        service_util::setMasked(asyncResp, sshServiceName, *sshMasked);
    }
    if (ipmbEnabled)
    {
        handleProtocolEnabled(
            *ipmbEnabled, asyncResp,
            encodeServiceObjectPath(std::string(ipmbServiceName)));
    }
    if (ipmiRunning)
    {
        service_util::getMaskedStatus(
            asyncResp, ipmiServiceName, "IPMI", "Masked",
            [ipmiRunning, asyncResp](bool isMasked) {
                if (!isMasked)
                {
                    setRunning(asyncResp, *ipmiRunning);
                }
                else
                {
                    asyncResp->res.result(
                        boost::beast::http::status::bad_request);
                    return;
                }
            });
    }
    if (bmcwebRunning)
    {
        handleProtocolRunning(
            *bmcwebRunning, asyncResp,
            encodeServiceObjectPath(std::string(httpsServiceName)));
    }
    if (sshRunning)
    {
        service_util::getMaskedStatus(
            asyncResp, sshServiceName, "SSH", "Masked",
            [sshRunning, asyncResp](bool isMasked) {
                if (!isMasked)
                {
                    handleProtocolRunning(
                        *sshRunning, asyncResp,
                        encodeServiceObjectPath(sshServiceName));
                }
                else
                {
                    asyncResp->res.result(
                        boost::beast::http::status::bad_request);
                    return;
                }
            });
    }
    if (ipmbRunning)
    {
        handleProtocolRunning(*ipmbRunning, asyncResp,
                              encodeServiceObjectPath(ipmbServiceName));
    }
}

inline void handleManagersNetworkProtocolHead(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& managerId)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/ManagerNetworkProtocol/ManagerNetworkProtocol.json>; rel=describedby");
    if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
    {
        messages::resourceNotFound(asyncResp->res, "Manager", managerId);
        return;
    }
}

inline void getEnabled(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                const std::string& serviceName, const std::string& ObjectName,
                const std::string& propertyName)
{
    dbus::utility::getProperty<bool>(
        serviceManagerService, serviceManagerPath + serviceName,
        "xyz.openbmc_project.Control.Service.Attributes", "Enabled",
        [asyncResp, ObjectName,
         propertyName](const boost::system::error_code& ec, bool eventValue) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-BUS response error on EventSeverity Get{}",
                                 ec);
                return;
            }
            asyncResp->res.jsonValue[ObjectName][propertyName] = eventValue;
        });
}

inline void getIpmiMasked(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    service_util::getMasked(asyncResp, ipmiServiceName, "IPMI", "Masked");
    service_util::getMasked(asyncResp, ipmiServiceName, "IPMI", "Running");
}

inline void getIpmiEnabled(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    getEnabled(asyncResp, ipmiServiceName, "IPMI", "ProtocolEnabled");
}

inline void getSSHMasked(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    service_util::getMasked(asyncResp, sshServiceName, "SSH", "Masked");
    service_util::getMasked(asyncResp, sshServiceName, "SSH", "Running");
}

inline void getBMCWEBMasked(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    service_util::getMasked(asyncResp, httpsServiceName, "HTTPS", "Masked");
    service_util::getMasked(asyncResp, httpsServiceName, "HTTPS", "Running");
}
inline void getIpmbMasked(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    service_util::getMasked(asyncResp, ipmbServiceName, "IPMB", "Masked");
    service_util::getMasked(asyncResp, ipmbServiceName, "IPMB", "Running");
}

inline void handleManagersNetworkProtocolGet(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& managerId)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/ManagerNetworkProtocol/ManagerNetworkProtocol.json>; rel=describedby");
    if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
    {
        messages::resourceNotFound(asyncResp->res, "Manager", managerId);
        return;
    }

    getNetworkData(asyncResp, req);
    getIpmiMasked(asyncResp);
    getSSHMasked(asyncResp);
    getBMCWEBMasked(asyncResp);
    getIpmbMasked(asyncResp);
    getIpmiEnabled(asyncResp);
}

inline void requestRoutesNetworkProtocol(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Managers/<str>/NetworkProtocol/")
        .privileges(redfish::privileges::patchManagerNetworkProtocol)
        .methods(boost::beast::http::verb::patch)(
            std::bind_front(handleManagersNetworkProtocolPatch, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Managers/<str>/NetworkProtocol/")
        .privileges(redfish::privileges::headManagerNetworkProtocol)
        .methods(boost::beast::http::verb::head)(
            std::bind_front(handleManagersNetworkProtocolHead, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Managers/<str>/NetworkProtocol/")
        .privileges(redfish::privileges::getManagerNetworkProtocol)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleManagersNetworkProtocolGet, std::ref(app)));
}

} // namespace redfish
