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
        "xyz.openbmc_project.Snmp.Conf", "/xyz/openbmc_project/snmp/SnmpUtils",
        "xyz.openbmc_project.Snmp.SnmpUtils", "SnmpTrapStatus",
        [asyncResp](const boost::system::error_code& ec, bool protocolEnabled) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-BUS response error on SnmpTrapStatus Get{}",
                                 ec);
                messages::internalError(asyncResp->res);
                return;
            }
            asyncResp->res.jsonValue["SNMP"]["Port"] = 161;
            asyncResp->res.jsonValue["SNMP"]["ProtocolEnabled"] =
                protocolEnabled;
        });
}

inline void
    getSNMPVersionEnabled(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    dbus::utility::getProperty<bool>(
        "xyz.openbmc_project.Snmp.Conf", "/xyz/openbmc_project/snmp/SnmpUtils",
        "xyz.openbmc_project.Snmp.SnmpUtils", "EnableSNMPV1",
        [asyncResp](const boost::system::error_code& ec, bool enableSNMPv1) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-BUS response error on SnmpTrapStatus Get{}",
                                 ec);
                messages::internalError(asyncResp->res);
                return;
            }
            asyncResp->res.jsonValue["SNMP"]["EnableSNMPv1"] = enableSNMPv1;
        });

    dbus::utility::getProperty<bool>(
        "xyz.openbmc_project.Snmp.Conf", "/xyz/openbmc_project/snmp/SnmpUtils",
        "xyz.openbmc_project.Snmp.SnmpUtils", "EnableSNMPV2",
        [asyncResp](const boost::system::error_code& ec, bool enableSNMPv2c) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-BUS response error on SnmpTrapStatus Get{}",
                                 ec);
                messages::internalError(asyncResp->res);
                return;
            }
            asyncResp->res.jsonValue["SNMP"]["EnableSNMPv2c"] = enableSNMPv2c;
        });

    dbus::utility::getProperty<bool>(
        "xyz.openbmc_project.Snmp.Conf", "/xyz/openbmc_project/snmp/SnmpUtils",
        "xyz.openbmc_project.Snmp.SnmpUtils", "EnableSNMPV3",
        [asyncResp](const boost::system::error_code& ec, bool enableSNMPv3) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-BUS response error on SnmpTrapStatus Get{}",
                                 ec);
                messages::internalError(asyncResp->res);
                return;
            }
            asyncResp->res.jsonValue["SNMP"]["EnableSNMPv3"] = enableSNMPv3;
        });
}

inline void
    getSNMPCommunityString(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    sdbusplus::message::object_path path("/xyz/openbmc_project/snmp/CommunityStrManager");
    dbus::utility::getManagedObjects(
    "xyz.openbmc_project.Snmp.Conf", path,
    [asyncResp](const boost::system::error_code& ec,
                const dbus::utility::ManagedObjectType& resp) 
    {
        nlohmann::json::array_t CommunityStrings;
        nlohmann::json::array_t oem_CommunityStrings;
        nlohmann::json::object_t CommunityStringData;
        nlohmann::json::object_t oem_CommunityStringData;
        const std::string *communityString = nullptr;
        const std::string *readwritepermission = nullptr;
        const std::string *communityprofile = nullptr;

        bool snmpflag = false;
        bool oemsnmpflag = false;

        if (ec)
        {
            BMCWEB_LOG_ERROR("D-Bus responses error: {}", ec);
            messages::internalError(asyncResp->res);
            return;
        }
        if (resp.empty())
        {
            asyncResp->res.jsonValue["SNMP"]["CommunityStrings"] = {nullptr};
            asyncResp->res.jsonValue["Oem"]["Ami"]["SNMP"]["CommunityStrings"] = {nullptr};
            asyncResp->res.jsonValue["Oem"]["Ami"]["@odata.type"] = json_util::odataType("AmiManagerNetworkProtocol", "ManagerNetworkProtocol");
        }
        else
        {
            for (const auto& objectPath : resp) 
            {
                for (const auto& interfaceMap : objectPath.second)
                {
                    if(interfaceMap.first == "xyz.openbmc_project.Snmp.CommunityStrManager")
                    {
                        for (const auto& propertyMap : interfaceMap.second)
                        {
                            if(propertyMap.first == "CommunityString")
                            {
                                communityString = std::get_if<std::string>(&propertyMap.second);
                                if(communityString != nullptr &&  *communityString != "")
                                {
                                    CommunityStringData["CommunityString"] = *communityString;
                                    snmpflag = true;
                                }
                            }
                            else if(propertyMap.first == "CommunityProfile")
                            {
                                communityprofile = std::get_if<std::string>(&propertyMap.second);
                                if (communityprofile != nullptr && *communityprofile != "")
                                {
                                    oem_CommunityStringData["AllowedMiBs"] = *communityprofile;
                                    auto it = CommunityStringData.find("CommunityString");
                                    if (it != CommunityStringData.end()) {
                                        oem_CommunityStringData["CommunityString"] = CommunityStringData["CommunityString"];
                                        oemsnmpflag = true;
                                    }
                                }
                            }
                            else if (propertyMap.first == "ReadWritePermission")
                            {
                                readwritepermission = std::get_if<std::string>(&propertyMap.second);
                                if(readwritepermission != nullptr)
                                {
                                    if (*readwritepermission == "rwcommunity")
                                    {
                                        CommunityStringData["AccessMode"] = "Full";
                                        snmpflag = true;
                                    }
                                    else if(*readwritepermission == "rocommunity")
                                    {
                                        CommunityStringData["AccessMode"] = "Limited";
                                        snmpflag = true;
                                    }
                                }
                            }
                        }
                    }
                }
                if(snmpflag == true){
                    CommunityStrings.emplace_back(std::move(CommunityStringData));
                    snmpflag = false;
                }
                if(oemsnmpflag == true){
                    oem_CommunityStrings.emplace_back(std::move(oem_CommunityStringData));
                    oemsnmpflag = false;
                }
            }
            asyncResp->res.jsonValue["SNMP"]["CommunityStrings"] = std::move(CommunityStrings);
            asyncResp->res.jsonValue["Oem"]["Ami"]["@odata.type"] = json_util::odataType("AmiManagerNetworkProtocol", "ManagerNetworkProtocol");
            asyncResp->res.jsonValue["Oem"]["Ami"]["SNMP"]["CommunityStrings"] = std::move(oem_CommunityStrings);
        }
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
    asyncResp->res.jsonValue["@odata.type"] = json_util::odataType("ManagerNetworkProtocol");
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
        if (nwkProtocol.first == std::string("IPMI"))
        {
            asyncResp->res.jsonValue[nwkProtocol.first]["Port"] = 623;
            asyncResp->res.jsonValue[nwkProtocol.first]["ProtocolEnabled"] =
                false;
        }
        else if (nwkProtocol.first == std::string("IPMB"))
        {
            // IPMB protocol structure under Oem/Ami
            asyncResp->res.jsonValue["Oem"]["Ami"]["IPMB"]["ProtocolEnabled"] = false;
        }
        else
        {
            asyncResp->res.jsonValue[nwkProtocol.first]["Port"] = nullptr;
            asyncResp->res.jsonValue[nwkProtocol.first]["ProtocolEnabled"] =
                false;
        }
    }

    std::string hostName = getHostName();

    asyncResp->res.jsonValue["HostName"] = hostName;

    // Set up Oem/Ami structure for IPMB and other vendor-specific properties
    asyncResp->res.jsonValue["Oem"]["Ami"]["@odata.type"] = 
        json_util::odataType("AmiManagerNetworkProtocol");

    getNTPProtocolEnabled(asyncResp);
    getSNMPProtocolEnabled(asyncResp);
    getSNMPVersionEnabled(asyncResp);
    getSNMPCommunityString(asyncResp);

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
                    "/Oem/Ami/" + protocolName + "/ProtocolEnabled"));
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
        if (std::holds_alternative<nlohmann::json::object_t>(ntpServer))
        {
            input.push_back(
                std::get<nlohmann::json::object_t>(ntpServer));
        }
        else if (std::holds_alternative<std::nullptr_t>(ntpServer))
        {
            // Handle nullptr_t case if necessary
            input.push_back(
                std::get<std::nullptr_t>(ntpServer));
        }
        else if (std::holds_alternative<std::string>(ntpServer))
        {
            input.push_back(std::get<std::string>(ntpServer));
        }
        else
        {
            messages::internalError(asyncResp->res);
            return;
        }
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
        messages::arraySizeTooLong(asyncResp->res, "NTP/NTPServers", 3);
        asyncResp->res.result(boost::beast::http::status::bad_request);
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
                asyncResp->res.result(boost::beast::http::status::bad_request);
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
                asyncResp->res.result(boost::beast::http::status::bad_request);
                return;
            }
            // Can't retain an item that doesn't exist
            if (currentNtpServer == currentNtpServers.end())
            {
                messages::propertyValueOutOfRange(
                    asyncResp->res, *ntpServerObject,
                    "NTP/NTPServers/" + std::to_string(index));
                asyncResp->res.result(boost::beast::http::status::bad_request);

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
            asyncResp->res.result(boost::beast::http::status::bad_request);
            return;
        }

        *currentNtpServer = *ntpServerStr;
        currentNtpServer++;
    }

    // Any remaining array elements should be removed
    currentNtpServers.erase(currentNtpServer, currentNtpServers.end());

    crow::connections::systemBus->async_method_call(
        [currentNtpServers, asyncResp](const boost::system::error_code ec,
                                const dbus::utility::ManagedObjectType& objects)
        {
            if (ec)
            {
                BMCWEB_LOG_ERROR("GetManagedObjects failed: {}", ec.message());
                messages::internalError(asyncResp->res);
                return;
            }

            for (const auto& objpath : objects)
            {
                for (const auto & ifacePair : objpath.second)
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
                            sdbusplus::asio::setProperty(
                                    *crow::connections::systemBus, "xyz.openbmc_project.Network",
                                    objpath.first, ifacePair.first,
                                    "StaticNTPServers", currentNtpServers,
                                    [asyncResp](const boost::system::error_code& ec)
                                    {
                                        if (ec)
                                        {
                                            BMCWEB_LOG_ERROR("D-Bus responses error setting StaticNTPServers: {}", ec);
                                            messages::internalError(asyncResp->res);
                                            return;
                                        }
                                    });
                        }
                    }
                }
            }
        },
        "xyz.openbmc_project.Network", "/xyz/openbmc_project/network",
        "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");

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

inline void patchsnmpcommunitystring(std::optional<std::vector<std::variant<nlohmann::json::object_t, std::nullptr_t>>>& communityStrings, std::optional<std::vector<std::variant<nlohmann::json::object_t, std::nullptr_t>>>& oem_communityStrings, const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    sdbusplus::message::object_path path("/xyz/openbmc_project/snmp/CommunityStrManager");
    dbus::utility::getManagedObjects(
        "xyz.openbmc_project.Snmp.Conf", path,
        [asyncResp, communityStrings, oem_communityStrings](const boost::system::error_code& ec,
                    const dbus::utility::ManagedObjectType& resp) 
    {
        nlohmann::json::array_t communitystr_jsonArray;
        nlohmann::json::array_t oem_communitystr_jsonArray;
        nlohmann::json::array_t dbus_communitystr_array;
        nlohmann::json::object_t dbus_communitystrdata;
        nlohmann::json::array_t commstr_array;
        nlohmann::json::array_t comstr;
        nlohmann::json::array_t oemcomstr;
        nlohmann::json::array_t remove_index_array;
        std::vector<std::string> CommunityProfile_vec = {"all", "smtp", "system"};
        int index = 0;
        int oem_index = 0;

        for (const auto& communityStr : *communityStrings)
        {
            if (std::holds_alternative<nlohmann::json::object_t>(communityStr))
            {
                communitystr_jsonArray.push_back(
                    std::get<nlohmann::json::object_t>(communityStr));
            }
            else if (std::holds_alternative<std::nullptr_t>(communityStr))
            {
                // Handle nullptr_t case if necessary
                communitystr_jsonArray.push_back(
                    std::get<std::nullptr_t>(communityStr));
            }
        }

        for (const auto& communityStr : *oem_communityStrings)
        {
            if (std::holds_alternative<nlohmann::json::object_t>(communityStr))
            {
                oem_communitystr_jsonArray.push_back(
                    std::get<nlohmann::json::object_t>(communityStr));
            }
            else if (std::holds_alternative<std::nullptr_t>(communityStr))
            {
                // Handle nullptr_t case if necessary
                oem_communitystr_jsonArray.push_back(
                    std::get<std::nullptr_t>(communityStr));
            }
        }

        if(communitystr_jsonArray.size() == oem_communitystr_jsonArray.size())
        {
            if (ec)
            {
                BMCWEB_LOG_DEBUG(
                    "dbus error");
                messages::internalError(asyncResp->res);                        
            }
            else //patching and delete block
            {
                int exist_success_flag = 0;
                int create_success_flag = 0;
                int null_success_flag = 0;
                int empty_success_flag = 0;
                int update_oem_success_flag = 0;
                int create_oem_success_flag = 0;
                int null_oem_success_flag = 0;
                int empty_oem_success_flag = 0;
                nlohmann::json::array_t setdbus_communitystr_array;
                nlohmann::json::object_t setdbus_communitystrdata;
                for (const auto& objectPath : resp) 
                {
                    std::string objectPathStr(objectPath.first);
                    for (const auto& interfaceMap : objectPath.second)
                    {
                        if(interfaceMap.first == "xyz.openbmc_project.Snmp.CommunityStrManager")
                        {
                            for (const auto& propertyMap : interfaceMap.second)
                            {
                                if(propertyMap.first == "CommunityString")
                                {
                                    const std::string *communityString = std::get_if<std::string>(&propertyMap.second);
                                    if(communityString != nullptr &&  *communityString != "")
                                    {
                                        dbus_communitystrdata["CommunityString"] = *communityString;
                                    }
                                }
                                else if(propertyMap.first == "CommunityProfile")
                                {
                                    const std::string *communityprofile = std::get_if<std::string>(&propertyMap.second);
                                    if (communityprofile != nullptr && *communityprofile != "")
                                    {
                                        dbus_communitystrdata["CommunityProfile"] = *communityprofile;
                                    }
                                }
                                else if (propertyMap.first == "ReadWritePermission")
                                {
                                    const std::string *readwritepermission = std::get_if<std::string>(&propertyMap.second);
                                    //CommunityStringData["AccessMode"] = nullptr;
                                    if(readwritepermission != nullptr)
                                    {
                                        if (*readwritepermission == "rwcommunity")
                                        {
                                            dbus_communitystrdata["ReadWritePermission"] = "Full";
                                        }
                                        else if(*readwritepermission == "rocommunity")
                                        {
                                            dbus_communitystrdata["ReadWritePermission"] = "Full";
                                        }
                                    }
                                }
                            }
                            dbus_communitystrdata["ObjectPath"] = objectPathStr;
                            dbus_communitystr_array.emplace_back(std::move(dbus_communitystrdata));
                        }
                    }
                }

                for (const auto& communityStringData : communitystr_jsonArray)
                {
                    if (communityStringData.is_object() || communityStringData.is_null()) {
                        bool valid_commstrdata = true;
                        bool dmtf_missing_flag = false;
                        bool dmtf_unknown_flag = false;
                        if (communityStringData.is_object() && !(communityStringData.empty()))
                        {  
                            bool commstr_flag = false;
                            bool access_flag = false; 
                            for (auto it_5 = communityStringData.begin(); it_5 != communityStringData.end(); ++it_5) {
                                if (it_5.key() != "CommunityString" && it_5.key() != "AccessMode") {
                                    messages::propertyUnknown(asyncResp->res, it_5.key());
                                    dmtf_unknown_flag = true;
                                }
                                else if(it_5.key() == "CommunityString"){
                                    commstr_flag = true;
                                }
                                else if(it_5.key() == "AccessMode")
                                {
                                    access_flag = true;
                                }
                            }
                            if (commstr_flag == false){
                                messages::propertyMissing(asyncResp->res,"SNMP/CommunityStrings/" + std::to_string(index) + "/CommunityString");
                                dmtf_missing_flag = true;
                            }
                            else if (access_flag == false){
                                messages::propertyMissing(asyncResp->res,"SNMP/CommunityStrings/" + std::to_string(index) + "/AccessMode");
                                dmtf_missing_flag = true;
                            }
                        }
                        if ((dmtf_unknown_flag == false) && (dmtf_missing_flag == false) && !(communityStringData.is_null()) && !(communityStringData.empty())){
                            std::string commstring = communityStringData["CommunityString"].get<std::string>();
                            bool commstr_present = false;
                            std::string lowerCase_Commstr = commstring;
                            std::transform(lowerCase_Commstr.begin(), lowerCase_Commstr.end(), lowerCase_Commstr.begin(), ::tolower);
                            if (lowerCase_Commstr != "private" && lowerCase_Commstr != "public"){
                                auto it_6 = std::find(comstr.begin(), comstr.end(), commstring);
                                if (it_6 != comstr.end()) {
                                    size_t it_index = static_cast<size_t>(std::distance(comstr.begin(), it_6));
                                    messages::propertyValueConflict(asyncResp->res, "SNMP/CommunityStrings/" + std::to_string(index) + "/CommunityString", "SNMP/CommunityStrings/" + std::to_string(it_index) + "/CommunityString");
                                    valid_commstrdata = false;
                                }
                                else
                                {
                                    comstr.push_back(commstring);
                                }
                            }
                            else{
                                messages::propertyValueError(asyncResp->res, "SNMP/CommunityStrings/" + std::to_string(index) + "/CommunityString");
                                valid_commstrdata = false;
                            }
                            bool valid_accessdata = true;
                            std::string accessdata = communityStringData["AccessMode"].get<std::string>();
                            if (accessdata == "Full")
                            {
                                accessdata = "rwcommunity";
                            }
                            else if (accessdata == "Limited")
                            {
                                accessdata = "rocommunity";
                            }
                            else
                            {
                                messages::propertyValueNotInList(asyncResp->res, accessdata, "SNMP/CommunityStrings/" + std::to_string(index) + "/AccessMode");
                                valid_accessdata = false;
                            }
                            if(valid_commstrdata == true && valid_accessdata == true)
                            {
                                for (const auto& dbus_commstr : dbus_communitystr_array)
                                {
                                    auto it_7 = dbus_commstr.find("CommunityString");
                                    if (it_7 != dbus_commstr.end() ){
                                        std::string dbuscommstr= it_7.value().get<std::string>();
                                        if (dbuscommstr == commstring) {
                                            auto objpathIt = dbus_commstr.find("ObjectPath");
                                            if (objpathIt != dbus_commstr.end()) {

                                                if(dbus_commstr["ReadWritePermission"] != accessdata){
                                                    std::string commstr_objectpath = objpathIt.value().get<std::string>();
                                                    setdbus_communitystrdata["ObjectPath"] = commstr_objectpath;
                                                    setdbus_communitystrdata["AccessMode"] = accessdata;
                                                    setdbus_communitystr_array.emplace_back(std::move(setdbus_communitystrdata));
                                                }
                                                commstr_present = true;
                                                exist_success_flag++;
                                            }
                                            break;
                                        }
                                    }
                                }
                                if (commstr_present == false)
                                {
                                    commstr_array.emplace_back(std::move(communityStringData));
                                    create_success_flag++;
                                }
                            }
                        }

                        if (communityStringData.is_null()){
                            if (index >= 0 && static_cast<size_t>(index) < dbus_communitystr_array.size())
                            {
                                std::string commstr_objectpath = dbus_communitystr_array[static_cast<size_t>(index)]["ObjectPath"];
                                if (!(commstr_objectpath.empty())){
                                    const boost::urls::url commstr_objPath = boost::urls::format("{}", commstr_objectpath);
                                    crow::connections::systemBus->async_method_call(
                                        [asyncResp, &null_success_flag](const boost::system::error_code& ec_1) {
                                            if (ec_1)
                                            {
                                                BMCWEB_LOG_DEBUG(
                                                    "Failed to delete community string");
                                                messages::internalError(asyncResp->res);
                                                return;
                                            }
                                            null_success_flag++;
                                    },
                                    "xyz.openbmc_project.Snmp.Conf",
                                    commstr_objPath.data(),
                                    "xyz.openbmc_project.Object.Delete",
                                    "Delete");
                                }
                            }   
                        }

                        if (communityStringData.empty()){
                            empty_success_flag++;
                        }
                    }
                    else
                    {
                        messages::propertyValueError(asyncResp->res, "SNMP/CommunityStrings/" + std::to_string(index));
                    }
                    index++;
                }

                for (const auto& oem_communityStringData : oem_communitystr_jsonArray)
                {
                    if (oem_communityStringData.is_object() || oem_communityStringData.is_null()) 
                    {
                        bool valid_allowedmibs = true;
                        bool valid_oemcommstr  = true; 
                        bool allowedmibs_flag = false;
                        bool comstr_flag = false;
                        bool oem_missing_flag = false;
                        bool oem_unknown_flag = false; 
                        if (oem_communityStringData.is_object() && !(oem_communityStringData.empty()))
                        {
                            for (auto it_8 = oem_communityStringData.begin(); it_8 != oem_communityStringData.end(); ++it_8) {
                                if (it_8.key() != "AllowedMiBs" && it_8.key() != "CommunityString") {
                                    messages::propertyUnknown(asyncResp->res, it_8.key());
                                    oem_unknown_flag = true;
                                }
                                else if(it_8.key() == "CommunityString"){
                                    comstr_flag = true;
                                }
                                else if(it_8.key() == "AllowedMiBs")
                                {
                                    allowedmibs_flag = true;
                                }

                            }
                            if (comstr_flag == false){
                                messages::propertyMissing(asyncResp->res, "Oem/Ami/SNMP/CommunityStrings/" + std::to_string(oem_index) + "/CommunityString");
                                oem_missing_flag = true;
                            }
                            else if (allowedmibs_flag == false){
                                messages::propertyMissing(asyncResp->res, "Oem/Ami/SNMP/CommunityStrings/" + std::to_string(oem_index) + "/AllowedMiBs");
                                oem_missing_flag = true;
                            }

                        }
                        if ((oem_unknown_flag == false) && (oem_missing_flag == false) && !(oem_communityStringData.is_null()) && !(oem_communityStringData.empty()))
                        {
                            std::string oem_commstr = oem_communityStringData["CommunityString"].get<std::string>();
                            bool oem_commstr_present = false;
                            std::string lowerCase_OemCommstr = oem_commstr;
                            std::transform(lowerCase_OemCommstr.begin(), lowerCase_OemCommstr.end(), lowerCase_OemCommstr.begin(), ::tolower);
                            if (lowerCase_OemCommstr != "private" && lowerCase_OemCommstr != "public"){
                                auto it_4 = std::find(comstr.begin(), comstr.end(), oem_commstr);
                                if (it_4 == comstr.end()) {
                                    messages::propertyValueIncorrect(asyncResp->res, "Oem/Ami/SNMP/CommunityStrings/" + std::to_string(oem_index) + "/CommunityString", oem_commstr);
                                    valid_oemcommstr = false;
                                }
                                else
                                {
                                    auto it_9 = std::find(oemcomstr.begin(), oemcomstr.end(), oem_commstr);
                                    if (it_9 != oemcomstr.end()) {
                                        size_t it_index = static_cast<size_t>(std::distance(oemcomstr.begin(), it_9));
                                        messages::propertyValueConflict(asyncResp->res, "Oem/Ami/SNMP/CommunityStrings/" + std::to_string(oem_index) + "/CommunityString", "Oem/Ami/SNMP/CommunityStrings/" + std::to_string(it_index) + "/CommunityString");
                                        valid_oemcommstr = false;
                                    }
                                    else
                                    {
                                        oemcomstr.push_back(oem_commstr);
                                    }
                                }
                            }
                            else{
                                messages::propertyValueError(asyncResp->res, "Oem/Ami/SNMP/CommunityStrings/" + std::to_string(oem_index) + "/CommunityString");
                                valid_oemcommstr = false;
                            }
                            std::string allowedmibs = oem_communityStringData["AllowedMiBs"].get<std::string>();
                            auto it_11 = std::find(CommunityProfile_vec.begin(), CommunityProfile_vec.end(), allowedmibs);
                            if (it_11 == CommunityProfile_vec.end()) {
                                messages::propertyValueNotInList(asyncResp->res, allowedmibs, "Oem/Ami/SNMP/CommunityStrings/" + std::to_string(oem_index) + "/AllowedMiBs");
                                valid_allowedmibs = false;
                            }
                            if (valid_oemcommstr == true && valid_allowedmibs == true)
                            {
                                for (const auto& dbus_commstr : dbus_communitystr_array)
                                {
                                    auto it_10 = dbus_commstr.find("CommunityString");
                                    if (it_10 != dbus_commstr.end()){
                                        std::string dbusoemcommstr = it_10.value().get<std::string>();
                                        if (dbusoemcommstr == oem_commstr) {
                                            auto objpathIt = dbus_commstr.find("ObjectPath");
                                            if (objpathIt != dbus_commstr.end()) {
                                                if(dbus_commstr["CommunityProfile"] != allowedmibs)
                                                {
                                                    std::string oemcommstr_objectpath = objpathIt.value().get<std::string>();
                                                    setdbus_communitystrdata["ObjectPath"] = oemcommstr_objectpath;
                                                    setdbus_communitystrdata["allowedmibs"] = allowedmibs;
                                                    setdbus_communitystr_array.emplace_back(std::move(setdbus_communitystrdata));
                                                }
                                                oem_commstr_present = true;
                                                update_oem_success_flag++;
                                            }
                                            break;
                                        }
                                    }
                                }
                                if (oem_commstr_present == false)
                                {
                                    for (auto& commstrdata : commstr_array)
                                    {
                                        auto it_12 = commstrdata.find("CommunityString");
                                        if (it_12 != commstrdata.end()){
                                            std::string new_oemcommstr = it_12.value().get<std::string>();
                                            if(new_oemcommstr == oem_commstr) 
                                            {
                                                commstrdata["AllowedMiBs"] = allowedmibs;
                                                create_oem_success_flag++;
                                                break;
                                            }
                                        }
                                    }

                                }
                            }
                        }

                        if (oem_communityStringData.is_null())
                        {
                            if (oem_index >= 0 && static_cast<size_t>(oem_index) < dbus_communitystr_array.size())
                            {
                                std::string commstr_objectpath = dbus_communitystr_array[static_cast<size_t>(oem_index)]["ObjectPath"];
                                if (!(commstr_objectpath.empty())){
                                    const boost::urls::url commstr_objPath = boost::urls::format("{}", commstr_objectpath);
                                    crow::connections::systemBus->async_method_call(
                                        [asyncResp, &null_oem_success_flag](const boost::system::error_code& ec_2) {
                                            if (ec_2)
                                            {
                                                BMCWEB_LOG_DEBUG(
                                                    "Already objectpath is deleted");
                                            }
                                            null_oem_success_flag++;
                                    },
                                    "xyz.openbmc_project.Snmp.Conf",
                                    commstr_objPath.data(),
                                    "xyz.openbmc_project.Object.Delete",
                                    "Delete");
                                }
                            }
                        }

                        if (oem_communityStringData.empty()){
                            empty_oem_success_flag++;
                        }
                    }
                    else
                    {
                        messages::propertyValueError(asyncResp->res, "CommunityString/" + std::to_string(index));
                    }
                    oem_index++;
                }
                if ((static_cast<size_t>(exist_success_flag + null_success_flag + create_success_flag + empty_success_flag) == communitystr_jsonArray.size()) && (static_cast<size_t>(update_oem_success_flag + null_oem_success_flag + create_oem_success_flag + empty_oem_success_flag) == oem_communitystr_jsonArray.size()))
                {
                    if (commstr_array.size() > 0 ){
                        for (const auto& commstrdata : commstr_array)
                        {
                            std::string comstrdata = commstrdata["CommunityString"].get<std::string>();
                            std::string accessdata = commstrdata["AccessMode"].get<std::string>();
                            if (accessdata == "Full")
                            {
                                accessdata = "rwcommunity";
                            }
                            else
                            {
                                accessdata = "rocommunity";
                            }
                            std::string allowedmibsdata = commstrdata["AllowedMiBs"].get<std::string>();
                            if (!comstrdata.empty() && !accessdata.empty() && !allowedmibsdata.empty())
                            {
                                crow::connections::systemBus->async_method_call(
                                    [asyncResp](const boost::system::error_code& ec_3) {
                                        if (ec_3)
                                        {
                                            BMCWEB_LOG_DEBUG(
                                                "Failed to create community string");
                                            messages::internalError(asyncResp->res);
                                            return;
                                        }
                                },
                                "xyz.openbmc_project.Snmp.Conf",
                                "/xyz/openbmc_project/snmp/CommunityStrManager",
                                "xyz.openbmc_project.Snmp.CommunityStrManager.Create",
                                "Client", comstrdata, accessdata, allowedmibsdata);
                            }
                        }
                    }

                    if (setdbus_communitystr_array.size() > 0)
                    {
                        for (const auto& setdbus_communitystr : setdbus_communitystr_array)
                        {
                            auto it_13 = setdbus_communitystr.find("AccessMode");
                            if (it_13 != setdbus_communitystr.end()) {
                                std::string accessdata = setdbus_communitystr["AccessMode"].get<std::string>();
                                auto objpathIt = setdbus_communitystr.find("ObjectPath");
                                if (objpathIt != setdbus_communitystr.end()) {
                                    const std::string objPathString = objpathIt.value().get<std::string>();
                                    const boost::urls::url objPath = boost::urls::format("{}", objPathString);
                                    sdbusplus::asio::setProperty(
                                        *crow::connections::systemBus, "xyz.openbmc_project.Snmp.Conf",
                                        objPath.data(),
                                        "xyz.openbmc_project.Snmp.CommunityStrManager", "ReadWritePermission",
                                        accessdata,
                                        [asyncResp](const boost::system::error_code& ec_4) {
                                        if (ec_4)
                                        {
                                            BMCWEB_LOG_ERROR("D-Bus responses error: {}", ec_4);
                                            return;
                                        }
                                    });
                                }
                            }
                            
                            auto allowedMibsIt = setdbus_communitystr.find("allowedmibs");
                            if (allowedMibsIt != setdbus_communitystr.end()) {
                                std::string allowedmibs = setdbus_communitystr["allowedmibs"].get<std::string>();
                                auto objpathIt = setdbus_communitystr.find("ObjectPath");
                                if (objpathIt != setdbus_communitystr.end()) {
                                    const std::string objPathString = objpathIt.value().get<std::string>();
                                    const boost::urls::url objPath = boost::urls::format("{}", objPathString);
                                    sdbusplus::asio::setProperty(
                                        *crow::connections::systemBus, "xyz.openbmc_project.Snmp.Conf",
                                        objPath.data(),
                                        "xyz.openbmc_project.Snmp.CommunityStrManager", "CommunityProfile",
                                        allowedmibs,
                                        [asyncResp](const boost::system::error_code& ec_5) {
                                        if (ec_5)
                                        {
                                            BMCWEB_LOG_ERROR("D-Bus responses error: {}", ec_5);
                                            return;
                                        }
                                    });
                                }
                            }
                        }
                    }
                    if (((communitystr_jsonArray.size() < dbus_communitystr_array.size()) || (communitystr_jsonArray.size() == 1 && dbus_communitystr_array.size() == 1)) && dbus_communitystr_array.size() > 0){
                        int removeindex = 0;
                        for (const auto& dbus_communitystring : dbus_communitystr_array)
                        {
                            if (dbus_communitystring.contains("CommunityString"))
                            {
                                std::string dbuscommunitystring = dbus_communitystring["CommunityString"].get<std::string>();
                                auto it_14 = std::find(comstr.begin(), comstr.end(), dbuscommunitystring);
                                if (it_14 == comstr.end()) {
                                    remove_index_array.push_back(removeindex);
                                }
                            }
                            removeindex++;
                        }
                        for(const auto& remove_index : remove_index_array)
                        {
                            std::string commstr_objectpath = dbus_communitystr_array[remove_index]["ObjectPath"];
                            const boost::urls::url commstr_objPath = boost::urls::format("{}", commstr_objectpath);
                            crow::connections::systemBus->async_method_call(
                                [asyncResp, &null_oem_success_flag](const boost::system::error_code& ec_6) {
                                    if (ec_6)
                                    {
                                        BMCWEB_LOG_DEBUG(
                                            "Already objectpath is deleted");
                                    }
                            },
                            "xyz.openbmc_project.Snmp.Conf",
                            commstr_objPath.data(),
                            "xyz.openbmc_project.Object.Delete",
                            "Delete");
                        }
                    }
                    asyncResp->res.result(boost::beast::http::status::no_content);
                }
            }
        }
        else if (communitystr_jsonArray.size() > oem_communitystr_jsonArray.size())
        {
            for(size_t i = oem_communitystr_jsonArray.size(); i < 5; i++){
                messages::propertyMissing(asyncResp->res,"Oem/Ami/SNMP/CommunityStrings/" + std::to_string(i));
            }
        }
        else
        {
            for(size_t i = communitystr_jsonArray.size(); i < 5; i++){
                messages::propertyMissing(asyncResp->res,"SNMP/CommunityStrings/" + std::to_string(i));
            }
        }

    });
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
    bool isInValid = false;
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
    std::optional<bool> bmcwebRunning;
    std::optional<bool> ipmbMasked;
    std::optional<bool> ipmbEnabled;
    std::optional<bool> ipmbRunning;
    std::optional<bool> ipmiMasked;
    std::optional<bool> ipmiRunning;
    std::optional<bool> sshMasked;
    std::optional<bool> sshRunning;
    std::optional<nlohmann::json> oem_snmp;

    // Parse the JSON request body
    nlohmann::json jsonRequest;
    if (!nlohmann::json::accept(req.body()))
    {
        messages::malformedJSON(asyncResp->res);
        return;
    }
    
    try
    {
        jsonRequest = nlohmann::json::parse(req.body());
    }
    catch (const nlohmann::json::exception& e)
    {
        BMCWEB_LOG_ERROR("JSON parse error: {}", e.what());
        messages::malformedJSON(asyncResp->res);
        return;
    }

    if (!json_util::readJsonPatch(
            req, asyncResp->res,
            "HostName", newHostName,
            "NTP", ntp,
            "IPMI", ipmi,
            "HTTPS", bmcweb,
            "SSH", ssh,
            "Id", vId,
            "SNMP", snmp,
            "Oem/Ami/HTTPS/Masked", bmcwebMasked,
            "Oem/Ami/HTTPS/Running", bmcwebRunning,
            "Oem/Ami/IPMB/ProtocolEnabled", ipmbEnabled,
            "Oem/Ami/IPMB/Masked", ipmbMasked,
            "Oem/Ami/IPMB/Running", ipmbRunning,
            "Oem/Ami/IPMI/Running", ipmiRunning,
            "Oem/Ami/IPMI/Masked", ipmiMasked,
            "Oem/Ami/SSH/Masked", sshMasked,
            "Oem/Ami/SSH/Running", sshRunning,
            "Oem/Ami/SNMP", oem_snmp))
    {
        return;
    }

    if (vId)
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
            isInValid = true;
        }
        if (!isInValid)
        {
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
    }
    if (ipmi)
    {
        std::optional<bool> ipmiEnabled;
        std::size_t ipmi_size = ipmi.value().size();
        if (ipmi_size == 0)
        {
            messages::propertyValueTypeError(asyncResp->res, ipmi.value(),
                                             "IPMI");
            isInValid = true;
        }
        if (!json_util::readJson( //
                *ipmi, asyncResp->res, //
                "ProtocolEnabled", ipmiEnabled //
                ))
        {
            isInValid = true;
        }
        if (ipmiEnabled && !isInValid)
        {
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
            isInValid = true;
        }
        if (!json_util::readJson( //
                *bmcweb, asyncResp->res, //
                "ProtocolEnabled", bmcwebEnabled //
                ))
        {
            isInValid = true;
        }
        if (bmcwebEnabled && !isInValid)
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
            isInValid = true;
        }
        if (!json_util::readJson( //
                *ssh, asyncResp->res, //
                "ProtocolEnabled", sshEnabled //
                ))
        {
           isInValid = true;
        }
        if (sshEnabled && !isInValid)
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
        std::optional<std::vector<std::variant<nlohmann::json::object_t, std::nullptr_t>>> communityStrings;
        std::size_t snmp_size = snmp.value().size();
        if (snmp_size == 0)
        {
            messages::propertyValueTypeError(asyncResp->res, snmp.value(),
                                             "SNMP");
            isInValid = true;
        }

        if (!json_util::readJson( //
                *snmp, asyncResp->res, //
                "ProtocolEnabled", snmpEnabled, //
                "EnableSNMPv1", enableSNMPv1, //
                "EnableSNMPv2c", enableSNMPv2c, //
                "EnableSNMPv3", enableSNMPv3, //
                "CommunityStrings", communityStrings //
                ))
        {
             isInValid = true;
        }
        if ( !isInValid)
        {
            if (enableSNMPv1)
            {
                sdbusplus::asio::setProperty(
                    *crow::connections::systemBus, "xyz.openbmc_project.Snmp.Conf",
                    "/xyz/openbmc_project/snmp/SnmpUtils",
                    "xyz.openbmc_project.Snmp.SnmpUtils", "EnableSNMPV1",
                    (*enableSNMPv1),
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
                    *crow::connections::systemBus, "xyz.openbmc_project.Snmp.Conf",
                    "/xyz/openbmc_project/snmp/SnmpUtils",
                    "xyz.openbmc_project.Snmp.SnmpUtils", "EnableSNMPV2",
                    (*enableSNMPv2c),
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
                    *crow::connections::systemBus, "xyz.openbmc_project.Snmp.Conf",
                    "/xyz/openbmc_project/snmp/SnmpUtils",
                    "xyz.openbmc_project.Snmp.SnmpUtils", "EnableSNMPV3",
                    (*enableSNMPv3),
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
                    *crow::connections::systemBus, "xyz.openbmc_project.Snmp.Conf",
                    "/xyz/openbmc_project/snmp/SnmpUtils",
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

            if (communityStrings) {
                if(oem_snmp){
                    std::optional<std::vector<std::variant<nlohmann::json::object_t, std::nullptr_t>>> oem_communityStrings;
                    std::size_t oem_snmp_size = oem_snmp.value().size();
                    if (oem_snmp_size == 0)
                    {
                        messages::propertyValueTypeError(asyncResp->res, oem_snmp.value(),
                                                    "Oem/Ami/SNMP");
                    }
                    if (!json_util::readJson(*oem_snmp, asyncResp->res, "CommunityStrings", oem_communityStrings))
                    {
                        syslog(LOG_WARNING,"ReadJson Failed");
                    return;
                    }
                    patchsnmpcommunitystring(communityStrings,oem_communityStrings,asyncResp);
                }
            }
        }
    }
    if (isInValid)
    {
        return;
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
    service_util::getMasked(asyncResp, ipmiServiceName, "IPMI", "Masked", "Ami");
    service_util::getMasked(asyncResp, ipmiServiceName, "IPMI", "Running", "Ami");
}

inline void getIpmiEnabled(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    getEnabled(asyncResp, ipmiServiceName, "IPMI", "ProtocolEnabled");
}

inline void getSSHMasked(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    service_util::getMasked(asyncResp, sshServiceName, "SSH", "Masked", "Ami");
    service_util::getMasked(asyncResp, sshServiceName, "SSH", "Running", "Ami");
}

inline void getBMCWEBMasked(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    service_util::getMasked(asyncResp, httpsServiceName, "HTTPS", "Masked", "Ami");
    service_util::getMasked(asyncResp, httpsServiceName, "HTTPS", "Running", "Ami");
}
inline void getIpmbMasked(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    service_util::getMasked(asyncResp, ipmbServiceName, "IPMB", "Masked", "Ami");
    service_util::getMasked(asyncResp, ipmbServiceName, "IPMB", "Running", "Ami");
}

inline void getOEMAMIChannelInfo(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code& ec,
                   const std::map<uint8_t, std::string>& channelMap) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("D-Bus Method GetChannelInterfaceMap Response Error: {}", ec);
                return;
            }
            nlohmann::json channelJson = nlohmann::json::array();
            bool defaultChannel = false;

            for (const auto& [channel, interface] : channelMap)
            {
                if (!defaultChannel)
                {
                    nlohmann::json entry = {
                        {"ChannelId", channel},
                        {"ChannelName", interface}
                    };
                    asyncResp->res.jsonValue["Oem"]["Ami"]["DefaultChannel"] = entry;
                    defaultChannel = true;
                }
                
                channelJson.push_back({
                    {"ChannelId", channel},
                    {"ChannelName", interface}
                });
            }

            asyncResp->res.jsonValue["Oem"]["Ami"]["AvailableChannelList"] = channelJson;
        },
        "xyz.openbmc_project.User.Manager", // Service
        "/xyz/openbmc_project/user", // Object path
        "xyz.openbmc_project.User.AccountPolicy", // Interface
        "GetChannelInterfaceMap" // Method name
    );
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
    getOEMAMIChannelInfo(asyncResp);

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
