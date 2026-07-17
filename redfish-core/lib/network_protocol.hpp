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

static constexpr const char* snmpConfObject =
    "/xyz/openbmc_project/snmp/SnmpUtils";
static constexpr const char* snmpConfIface =
    "xyz.openbmc_project.Snmp.SnmpUtils";
static constexpr const char* snmpCommunityStrManagerIface =
    "xyz.openbmc_project.Snmp.CommunityStrManager";

struct SnmpCommunityString
{
    std::string CommunityString;
    std::string AccessMode;
    std::string AllowedMiBs;
    std::string objectPath;
};

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

inline void getSNMPProperties(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    dbus::utility::getAllProperties(
        snmpConfService, snmpConfObject, snmpConfIface,
        [asyncResp](const boost::system::error_code& ec,
                    const dbus::utility::DBusPropertiesMap& propertiesList) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-BUS response error on SnmpUtils GetAll: {}",
                                 ec);
                messages::internalError(asyncResp->res);
                return;
            }

            const bool* snmpTrapStatus = nullptr;
            const bool* enableSNMPV1 = nullptr;
            const bool* enableSNMPV2 = nullptr;
            const bool* enableSNMPV3 = nullptr;

            const bool success = sdbusplus::unpackPropertiesNoThrow(
                dbus_utils::UnpackErrorPrinter(), propertiesList,
                "SnmpTrapStatus", snmpTrapStatus, "EnableSNMPV1", enableSNMPV1,
                "EnableSNMPV2", enableSNMPV2, "EnableSNMPV3", enableSNMPV3);

            if (!success)
            {
                messages::internalError(asyncResp->res);
                return;
            }

            if (snmpTrapStatus != nullptr)
            {
                asyncResp->res.jsonValue["SNMP"]["ProtocolEnabled"] =
                    *snmpTrapStatus;
            }
            if (enableSNMPV1 != nullptr)
            {
                asyncResp->res.jsonValue["SNMP"]["EnableSNMPv1"] =
                    *enableSNMPV1;
            }
            if (enableSNMPV2 != nullptr)
            {
                asyncResp->res.jsonValue["SNMP"]["EnableSNMPv2c"] =
                    *enableSNMPV2;
            }
            if (enableSNMPV3 != nullptr)
            {
                asyncResp->res.jsonValue["SNMP"]["EnableSNMPv3"] =
                    *enableSNMPV3;
            }
        });
}

// Helper to check if a community string name is reserved
inline bool isReservedCommunityString(const std::string& name)
{
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    return (lower == "private" || lower == "public");
}

// Helper to validate AllowedMiBs value
inline bool isValidAllowedMiBs(const std::string& value)
{
    constexpr std::array<std::string_view, 3> validProfiles = {
        "all", "smtp", "system"};
    return std::find(validProfiles.begin(), validProfiles.end(), value) !=
           validProfiles.end();
}

// Helper to collect existing D-Bus community string entries into structs
inline std::vector<SnmpCommunityString> collectDbusCommStrEntries(
    const dbus::utility::ManagedObjectType& resp)
{
    std::vector<SnmpCommunityString> dbusEntries;
    for (const auto& objPath : resp)
    {
        SnmpCommunityString entry;
        entry.objectPath = objPath.first;
        bool found = false;

        for (const auto& interfaceMap : objPath.second)
        {
            if (interfaceMap.first != snmpCommunityStrManagerIface)
            {
                continue;
            }
            found = true;
            for (const auto& propertyMap : interfaceMap.second)
            {
                const std::string* val =
                    std::get_if<std::string>(&propertyMap.second);
                if (val == nullptr)
                {
                    continue;
                }
                if (propertyMap.first == "CommunityString")
                {
                    entry.CommunityString = *val;
                }
                else if (propertyMap.first == "ReadWritePermission")
                {
                    entry.AccessMode = *val;
                }
                else if (propertyMap.first == "CommunityProfile")
                {
                    entry.AllowedMiBs = *val;
                }
            }
        }
        if (found && (!entry.CommunityString.empty()))
        {
            dbusEntries.emplace_back(std::move(entry));
        }
    }
    // Sort by CommunityString to ensure consistent ordering between
    // GET and PATCH (D-Bus GetManagedObjects does not guarantee order)
    std::sort(dbusEntries.begin(), dbusEntries.end(),
              [](const SnmpCommunityString& a, const SnmpCommunityString& b) {
                  return a.CommunityString < b.CommunityString;
              });
    return dbusEntries;
}

// Helper to convert variant array to JSON array
inline nlohmann::json::array_t variantToJsonArray(
    const std::vector<std::variant<nlohmann::json::object_t, std::nullptr_t>>&
        input)
{
    nlohmann::json::array_t result;
    for (const auto& item : input)
    {
        if (std::holds_alternative<nlohmann::json::object_t>(item))
        {
            result.push_back(std::get<nlohmann::json::object_t>(item));
        }
        else
        {
            result.push_back(std::get<std::nullptr_t>(item));
        }
    }
    return result;
}

// Helper to find a D-Bus entry by community string name
inline const SnmpCommunityString* findDbusEntry(
    const std::vector<SnmpCommunityString>& entries, const std::string& name)
{
    for (const auto& entry : entries)
    {
        if (entry.CommunityString == name)
        {
            return &entry;
        }
    }
    return nullptr;
}

// Helper to validate SNMP community string JSON fields
inline bool validateSnmpFields(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const nlohmann::json& data, size_t index,
    std::initializer_list<std::string_view> requiredKeys,
    const std::string& pathPrefix)
{
    for (auto it = data.begin(); it != data.end(); ++it)
    {
        if (std::find(requiredKeys.begin(), requiredKeys.end(), it.key()) ==
            requiredKeys.end())
        {
            messages::propertyUnknown(asyncResp->res, it.key());
            return false;
        }
    }
    for (const auto& key : requiredKeys)
    {
        if (!data.contains(key))
        {
            messages::propertyMissing(
                asyncResp->res,
                pathPrefix + std::to_string(index) + "/" + std::string(key));
            return false;
        }
        if (!data[std::string(key)].is_string())
        {
            messages::propertyValueTypeError(
                asyncResp->res, data[std::string(key)],
                pathPrefix + std::to_string(index) + "/" + std::string(key));
            return false;
        }
    }
    return true;
}

// Helper to delete a D-Bus community string object
inline void deleteDbusCommStr(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& objPathStr)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp, objPathStr](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("Failed to delete community string: {}",
                                 objPathStr);
                messages::internalError(asyncResp->res);
                return;
            }
        },
        snmpConfService, objPathStr, "xyz.openbmc_project.Object.Delete",
        "Delete");
}

// Shared helper: fetch SNMP community strings from D-Bus and invoke callback
// with parsed entries. Handles D-Bus error internally.
template <typename CallbackFunc>
void fetchSnmpCommunityStrings(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    CallbackFunc&& callback)
{
    sdbusplus::message::object_path path(
        "/xyz/openbmc_project/snmp/CommunityStrManager");
    dbus::utility::getManagedObjects(
        snmpConfService, path,
        [asyncResp, callback = std::forward<CallbackFunc>(callback)](
            const boost::system::error_code& ec,
            const dbus::utility::ManagedObjectType& resp) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-Bus error fetching community strings: {}",
                                 ec);
                messages::internalError(asyncResp->res);
                return;
            }
            std::vector<SnmpCommunityString> entries =
                collectDbusCommStrEntries(resp);
            callback(entries);
        });
}

// Shared helper: build paired SNMP + OEM JSON arrays from struct vector
// and set them on the asyncResp.
inline void buildCommunityStringJsonResponse(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::vector<SnmpCommunityString>& communityData)
{
    if (communityData.empty())
    {
        asyncResp->res.jsonValue["SNMP"]["CommunityStrings"] = {nullptr};
        asyncResp->res.jsonValue["Oem"]["Ami"]["SNMP"]["CommunityStrings"] = {
            nullptr};
        return;
    }

    nlohmann::json::array_t snmpCommunityStrings;
    nlohmann::json::array_t oemCommunityStrings;

    for (const auto& data : communityData)
    {
        nlohmann::json::object_t snmpEntry;
        snmpEntry["AccessMode"] =
            (data.AccessMode == "rwcommunity") ? "Full" : "Limited";
        snmpEntry["CommunityString"] = data.CommunityString;
        snmpCommunityStrings.emplace_back(std::move(snmpEntry));

        nlohmann::json::object_t oemEntry;
        oemEntry["AllowedMiBs"] =
            data.AllowedMiBs.empty() ? "all" : data.AllowedMiBs;
        oemEntry["CommunityString"] = data.CommunityString;
        oemCommunityStrings.emplace_back(std::move(oemEntry));
    }

    asyncResp->res.jsonValue["SNMP"]["CommunityStrings"] =
        std::move(snmpCommunityStrings);
    asyncResp->res.jsonValue["Oem"]["Ami"]["SNMP"]["CommunityStrings"] =
        std::move(oemCommunityStrings);
}

inline void getSNMPCommunityString(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    fetchSnmpCommunityStrings(
        asyncResp,
        [asyncResp](const std::vector<SnmpCommunityString>& communityData) {
            buildCommunityStringJsonResponse(asyncResp, communityData);
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
        json_util::odataType("ManagerNetworkProtocol");
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
            asyncResp->res.jsonValue["Oem"]["Ami"]["IPMB"]["ProtocolEnabled"] =
                false;
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
    getNTPProtocolEnabled(asyncResp);
    getSNMPProperties(asyncResp);
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

        BMCWEB_LOG_DEBUG("protocolName {}", protocolName);
        BMCWEB_LOG_DEBUG("serviceName {}", serviceName);
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
    std::string syncMethod =
        ntpEnabled ? "xyz.openbmc_project.Time.Synchronization.Method.NTP"
                   : "xyz.openbmc_project.Time.Synchronization.Method.Manual";
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, "xyz.openbmc_project.Settings",
        "/xyz/openbmc_project/time/sync_method",
        "xyz.openbmc_project.Time.Synchronization", "TimeSyncMethod",
        syncMethod, [asyncResp](const boost::system::error_code& ec) {
            afterSetNTP(asyncResp, ec);
        });
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
            input.push_back(std::get<nlohmann::json::object_t>(ntpServer));
        }
        else if (std::holds_alternative<std::nullptr_t>(ntpServer))
        {
            // Handle nullptr_t case if necessary
            input.push_back(std::get<std::nullptr_t>(ntpServer));
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
            if (!isdigit(c) && !isalpha(c) && c != '-' && c != '.' && c != ':')
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
        [currentNtpServers,
         asyncResp](const boost::system::error_code ec,
                    const dbus::utility::ManagedObjectType& objects) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("GetManagedObjects failed: {}", ec.message());
                messages::internalError(asyncResp->res);
                return;
            }

            for (const auto& objpath : objects)
            {
                for (const auto& ifacePair : objpath.second)
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
                                *crow::connections::systemBus,
                                "xyz.openbmc_project.Network", objpath.first,
                                ifacePair.first, "StaticNTPServers",
                                currentNtpServers,
                                [asyncResp](
                                    const boost::system::error_code& ec) {
                                    if (ec)
                                    {
                                        BMCWEB_LOG_ERROR(
                                            "D-Bus responses error setting StaticNTPServers: {}",
                                            ec);
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
inline void handleProtocolRunning(
    const bool protocolRunning,
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

inline void handleProtocolEnabled(
    const bool protocolEnabled,
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

inline void getNTPProtocolEnabled(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
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

inline void patchSnmpCommunityString(
    std::optional<
        std::vector<std::variant<nlohmann::json::object_t, std::nullptr_t>>>&
        communityStrings,
    std::optional<
        std::vector<std::variant<nlohmann::json::object_t, std::nullptr_t>>>&
        oemCommunityStrings,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    fetchSnmpCommunityStrings(
        asyncResp, [asyncResp, communityStrings, oemCommunityStrings](
                       const std::vector<SnmpCommunityString>& dbusEntries) {
            // Convert variant arrays to JSON arrays
            nlohmann::json::array_t snmpArray =
                variantToJsonArray(*communityStrings);
            nlohmann::json::array_t oemArray =
                variantToJsonArray(*oemCommunityStrings);

            // Both arrays must have the same size (paired entries)
            if (snmpArray.size() != oemArray.size())
            {
                size_t larger = std::max(snmpArray.size(), oemArray.size());
                const std::string& missingPath =
                    (snmpArray.size() < oemArray.size())
                        ? "SNMP/CommunityStrings/"
                        : "Oem/Ami/SNMP/CommunityStrings/";
                size_t smaller = std::min(snmpArray.size(), oemArray.size());
                for (size_t i = smaller; i < larger; i++)
                {
                    messages::propertyMissing(asyncResp->res,
                                              missingPath + std::to_string(i));
                }
                return;
            }

            // Pre-collect all SNMP CommunityString names for OEM
            // validation (order-independent)
            std::vector<std::string> allSnmpCommStrs;
            for (size_t i = 0; i < snmpArray.size(); i++)
            {
                const nlohmann::json& s = snmpArray[i];
                if (s.is_object() && !s.empty() &&
                    s.contains("CommunityString") &&
                    s["CommunityString"].is_string())
                {
                    allSnmpCommStrs.push_back(
                        s["CommunityString"].get<std::string>());
                }
            }

            // Phase 1: Validate all input and build action lists
            std::vector<std::string> seenCommStrs;
            std::vector<SnmpCommunityString> toCreate;
            // Existing entries needing property updates (AccessMode
            // and/or AllowedMiBs stored in same struct)
            std::vector<SnmpCommunityString> toUpdate;
            std::vector<std::string> toDelete;

            bool validationFailed = false;

            for (size_t i = 0; i < snmpArray.size(); i++)
            {
                const nlohmann::json& snmpData = snmpArray[i];
                const nlohmann::json& oemData = oemArray[i];

                // Handle null (delete at index)
                if (snmpData.is_null() && oemData.is_null())
                {
                    continue;
                }

                // Mismatched null: one is null while the other is not
                if (snmpData.is_null() != oemData.is_null())
                {
                    const std::string& missingPath =
                        snmpData.is_null() ? "SNMP/CommunityStrings/"
                                           : "Oem/Ami/SNMP/CommunityStrings/";
                    messages::propertyMissing(asyncResp->res,
                                              missingPath + std::to_string(i));
                    validationFailed = true;
                    continue;
                }

                // Handle empty object (skip/retain)
                if ((snmpData.is_object() && snmpData.empty()) &&
                    (oemData.is_object() && oemData.empty()))
                {
                    if (i < dbusEntries.size())
                    {
                        seenCommStrs.push_back(dbusEntries[i].CommunityString);
                    }
                    continue;
                }

                // Mismatched empty: one is empty object while the other
                // has content
                if ((snmpData.is_object() && snmpData.empty()) !=
                    (oemData.is_object() && oemData.empty()))
                {
                    const std::string& missingPath =
                        (snmpData.is_object() && snmpData.empty())
                            ? "SNMP/CommunityStrings/"
                            : "Oem/Ami/SNMP/CommunityStrings/";
                    messages::propertyMissing(asyncResp->res,
                                              missingPath + std::to_string(i));
                    validationFailed = true;
                    continue;
                }

                // Validate SNMP entry fields
                if (!snmpData.is_object() || snmpData.empty())
                {
                    if (!snmpData.is_null() && !snmpData.is_object())
                    {
                        messages::propertyValueError(
                            asyncResp->res,
                            "SNMP/CommunityStrings/" + std::to_string(i));
                        validationFailed = true;
                    }
                    continue;
                }

                if (!validateSnmpFields(asyncResp, snmpData, i,
                                        {"CommunityString", "AccessMode"},
                                        "SNMP/CommunityStrings/"))
                {
                    validationFailed = true;
                    continue;
                }

                // Validate OEM entry fields
                if (oemData.is_object() && !oemData.empty())
                {
                    if (!validateSnmpFields(asyncResp, oemData, i,
                                            {"CommunityString", "AllowedMiBs"},
                                            "Oem/Ami/SNMP/CommunityStrings/"))
                    {
                        validationFailed = true;
                        continue;
                    }
                }

                std::string commStr =
                    snmpData["CommunityString"].get<std::string>();
                std::string accessMode =
                    snmpData["AccessMode"].get<std::string>();

                // Validate empty string values
                if (commStr.empty())
                {
                    messages::propertyValueError(
                        asyncResp->res,
                        "SNMP/CommunityStrings/" + std::to_string(i) +
                            "/CommunityString");
                    validationFailed = true;
                    continue;
                }
                if (accessMode.empty())
                {
                    messages::propertyValueError(
                        asyncResp->res, "SNMP/CommunityStrings/" +
                                            std::to_string(i) + "/AccessMode");
                    validationFailed = true;
                    continue;
                }

                // Validate community string name
                if (isReservedCommunityString(commStr))
                {
                    messages::propertyValueError(
                        asyncResp->res,
                        "SNMP/CommunityStrings/" + std::to_string(i) +
                            "/CommunityString");
                    validationFailed = true;
                    continue;
                }

                // Check for duplicates in input
                auto dupIt = std::find(seenCommStrs.begin(), seenCommStrs.end(),
                                       commStr);
                if (dupIt != seenCommStrs.end())
                {
                    size_t dupIdx = static_cast<size_t>(
                        std::distance(seenCommStrs.begin(), dupIt));
                    messages::propertyValueConflict(
                        asyncResp->res,
                        "SNMP/CommunityStrings/" + std::to_string(i) +
                            "/CommunityString",
                        "SNMP/CommunityStrings/" + std::to_string(dupIdx) +
                            "/CommunityString");
                    validationFailed = true;
                    continue;
                }
                seenCommStrs.push_back(commStr);

                // Validate AccessMode
                std::string dbusPermission =
                    (accessMode == "Full")
                        ? "rwcommunity"
                        : ((accessMode == "Limited") ? "rocommunity" : "");
                if (dbusPermission.empty())
                {
                    messages::propertyValueNotInList(
                        asyncResp->res, accessMode,
                        "SNMP/CommunityStrings/" + std::to_string(i) +
                            "/AccessMode");
                    validationFailed = true;
                    continue;
                }

                // Validate OEM AllowedMiBs
                std::string allowedMiBs;
                if (oemData.is_object() && !oemData.empty())
                {
                    std::string oemCommStr =
                        oemData["CommunityString"].get<std::string>();

                    if (oemCommStr.empty())
                    {
                        messages::propertyValueError(
                            asyncResp->res,
                            "Oem/Ami/SNMP/CommunityStrings/" +
                                std::to_string(i) + "/CommunityString");
                        validationFailed = true;
                        continue;
                    }

                    // OEM CommunityString must match SNMP CommunityString
                    if (isReservedCommunityString(oemCommStr))
                    {
                        messages::propertyValueError(
                            asyncResp->res,
                            "Oem/Ami/SNMP/CommunityStrings/" +
                                std::to_string(i) + "/CommunityString");
                        validationFailed = true;
                        continue;
                    }

                    // OEM CommunityString must be present in SNMP array
                    if (std::find(allSnmpCommStrs.begin(),
                                  allSnmpCommStrs.end(), oemCommStr) ==
                        allSnmpCommStrs.end())
                    {
                        messages::propertyValueIncorrect(
                            asyncResp->res,
                            "Oem/Ami/SNMP/CommunityStrings/" +
                                std::to_string(i) + "/CommunityString",
                            oemCommStr);
                        validationFailed = true;
                        continue;
                    }

                    allowedMiBs = oemData["AllowedMiBs"].get<std::string>();
                    if (allowedMiBs.empty())
                    {
                        messages::propertyValueError(
                            asyncResp->res,
                            "Oem/Ami/SNMP/CommunityStrings/" +
                                std::to_string(i) + "/AllowedMiBs");
                        validationFailed = true;
                        continue;
                    }
                    if (!isValidAllowedMiBs(allowedMiBs))
                    {
                        messages::propertyValueNotInList(
                            asyncResp->res, allowedMiBs,
                            "Oem/Ami/SNMP/CommunityStrings/" +
                                std::to_string(i) + "/AllowedMiBs");
                        validationFailed = true;
                        continue;
                    }
                }

                // Determine action: update existing or create new
                const SnmpCommunityString* existing =
                    findDbusEntry(dbusEntries, commStr);
                if (existing != nullptr)
                {
                    bool needsUpdate = false;
                    SnmpCommunityString update;
                    update.objectPath = existing->objectPath;

                    if (existing->AccessMode != dbusPermission)
                    {
                        update.AccessMode = dbusPermission;
                        needsUpdate = true;
                    }
                    if (!allowedMiBs.empty() &&
                        existing->AllowedMiBs != allowedMiBs)
                    {
                        update.AllowedMiBs = allowedMiBs;
                        needsUpdate = true;
                    }
                    if (needsUpdate)
                    {
                        toUpdate.emplace_back(std::move(update));
                    }
                }
                else
                {
                    SnmpCommunityString newEntry;
                    newEntry.CommunityString = commStr;
                    newEntry.AccessMode = dbusPermission;
                    newEntry.AllowedMiBs =
                        allowedMiBs.empty() ? "all" : allowedMiBs;
                    toCreate.emplace_back(std::move(newEntry));
                }
            }

            if (validationFailed)
            {
                return;
            }

            // Find D-Bus entries not in the input (to be removed)
            for (const auto& dbusEntry : dbusEntries)
            {
                if (std::find(seenCommStrs.begin(), seenCommStrs.end(),
                              dbusEntry.CommunityString) ==
                        seenCommStrs.end() &&
                    std::find(toDelete.begin(), toDelete.end(),
                              dbusEntry.objectPath) == toDelete.end())
                {
                    toDelete.push_back(dbusEntry.objectPath);
                }
            }

            // Phase 2: Execute D-Bus operations

            // Delete entries
            for (const auto& objPathStr : toDelete)
            {
                deleteDbusCommStr(asyncResp, objPathStr);
            }

            // Create new entries
            for (const auto& entry : toCreate)
            {
                crow::connections::systemBus->async_method_call(
                    [asyncResp](const boost::system::error_code& ec2) {
                        if (ec2)
                        {
                            BMCWEB_LOG_ERROR(
                                "Failed to create community string: {}", ec2);
                            messages::internalError(asyncResp->res);
                        }
                    },
                    snmpConfService,
                    "/xyz/openbmc_project/snmp/CommunityStrManager",
                    "xyz.openbmc_project.Snmp.CommunityStrManager.Create",
                    "Client", entry.CommunityString, entry.AccessMode,
                    entry.AllowedMiBs);
            }

            // Update properties on existing entries
            for (const auto& entry : toUpdate)
            {
                if (!entry.AccessMode.empty())
                {
                    sdbusplus::asio::setProperty(
                        *crow::connections::systemBus, snmpConfService,
                        entry.objectPath, snmpCommunityStrManagerIface,
                        "ReadWritePermission", entry.AccessMode,
                        [asyncResp](const boost::system::error_code& ec2) {
                            if (ec2)
                            {
                                BMCWEB_LOG_ERROR(
                                    "Failed to update ReadWritePermission: {}",
                                    ec2);
                                messages::internalError(asyncResp->res);
                            }
                        });
                }
                if (!entry.AllowedMiBs.empty())
                {
                    sdbusplus::asio::setProperty(
                        *crow::connections::systemBus, snmpConfService,
                        entry.objectPath, snmpCommunityStrManagerIface,
                        "CommunityProfile", entry.AllowedMiBs,
                        [asyncResp](const boost::system::error_code& ec2) {
                            if (ec2)
                            {
                                BMCWEB_LOG_ERROR(
                                    "Failed to update CommunityProfile: {}",
                                    ec2);
                                messages::internalError(asyncResp->res);
                            }
                        });
                }
            }

            asyncResp->res.result(boost::beast::http::status::no_content);
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

// Common helper to set a bool property on the SNMP SnmpUtils D-Bus object
inline void setSnmpUtilsProperty(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& propertyName, bool value)
{
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, snmpConfService, snmpConfObject,
        snmpConfIface, propertyName, value,
        [asyncResp, propertyName](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-Bus set {} error: {}", propertyName, ec);
                messages::internalError(asyncResp->res);
            }
        });
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
    std::optional<bool> enableSNMPv1;
    std::optional<bool> enableSNMPv2c;
    std::optional<bool> enableSNMPv3;
    std::optional<bool> snmpEnabled;
    std::optional<
        std::vector<std::variant<nlohmann::json::object_t, std::nullptr_t>>>
        oemCommunityStrings;
    std::optional<
        std::vector<std::variant<nlohmann::json::object_t, std::nullptr_t>>>
        communityStrings;

    if (!json_util::readJsonPatch(
            req, asyncResp->res, "HostName", newHostName, "NTP", ntp, "IPMI",
            ipmi, "HTTPS", bmcweb, "SSH", ssh, "SNMP", snmp, "Id", vId,
            "Oem/Ami/HTTPS/Masked", bmcwebMasked, "Oem/Ami/HTTPS/Running",
            bmcwebRunning, "Oem/Ami/IPMB/ProtocolEnabled", ipmbEnabled,
            "Oem/Ami/IPMB/Masked", ipmbMasked, "Oem/Ami/IPMB/Running",
            ipmbRunning, "Oem/Ami/IPMI/Running", ipmiRunning,
            "Oem/Ami/IPMI/Masked", ipmiMasked, "Oem/Ami/SSH/Masked", sshMasked,
            "Oem/Ami/SSH/Running", sshRunning, "Oem/Ami/SNMP/CommunityStrings",
            oemCommunityStrings))
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
        if (!json_util::readJson(              //
                *ntp, asyncResp->res,          //
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
        if (!json_util::readJson(              //
                *ipmi, asyncResp->res,         //
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
        if (!json_util::readJson(                //
                *bmcweb, asyncResp->res,         //
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
        if (!json_util::readJson(             //
                *ssh, asyncResp->res,         //
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
        std::size_t snmp_size = snmp.value().size();
        if (snmp_size == 0)
        {
            messages::propertyValueTypeError(asyncResp->res, snmp.value(),
                                             "SNMP");
            isInValid = true;
        }
        if (!json_util::readJson(                    //
                *snmp, asyncResp->res,               //
                "ProtocolEnabled", snmpEnabled,      //
                "EnableSNMPv1", enableSNMPv1,        //
                "EnableSNMPv2c", enableSNMPv2c,      //
                "EnableSNMPv3", enableSNMPv3,        //
                "CommunityStrings", communityStrings //
                ))
        {
            isInValid = true;
        }
    }

    if (!isInValid)
    {
        // If disabling SNMP, force all version flags to false as well
        if (snmpEnabled && !(*snmpEnabled))
        {
            // Reject if caller also tries to enable any version flag
            if ((enableSNMPv1 && *enableSNMPv1) ||
                (enableSNMPv2c && *enableSNMPv2c) ||
                (enableSNMPv3 && *enableSNMPv3))
            {
                BMCWEB_LOG_ERROR(
                    "Conflicting request: cannot enable SNMP version "
                    "flags while disabling SNMP service");
                messages::propertyValueConflict(
                    asyncResp->res, "EnableSNMPv1/EnableSNMPv2c/EnableSNMPv3",
                    "SNMP/ProtocolEnabled");
                asyncResp->res.result(boost::beast::http::status::bad_request);
                return;
            }
            setSnmpUtilsProperty(asyncResp, "SnmpTrapStatus", false);
            setSnmpUtilsProperty(asyncResp, "EnableSNMPV1", false);
            setSnmpUtilsProperty(asyncResp, "EnableSNMPV2", false);
            setSnmpUtilsProperty(asyncResp, "EnableSNMPV3", false);
        }
        else
        {
            if (snmpEnabled && *snmpEnabled)
            {
                setSnmpUtilsProperty(asyncResp, "SnmpTrapStatus", true);
            }

            if (enableSNMPv1 || enableSNMPv2c || enableSNMPv3)
            {
                if (snmpEnabled && *snmpEnabled)
                {
                    // SNMP being enabled in same request — safe to patch
                    // versions
                    if (enableSNMPv1)
                    {
                        setSnmpUtilsProperty(asyncResp, "EnableSNMPV1",
                                             *enableSNMPv1);
                    }
                    if (enableSNMPv2c)
                    {
                        setSnmpUtilsProperty(asyncResp, "EnableSNMPV2",
                                             *enableSNMPv2c);
                    }
                    if (enableSNMPv3)
                    {
                        setSnmpUtilsProperty(asyncResp, "EnableSNMPV3",
                                             *enableSNMPv3);
                    }
                }
                else
                {
                    // Check current SnmpTrapStatus before patching versions
                    dbus::utility::getProperty<bool>(
                        snmpConfService, snmpConfObject, snmpConfIface,
                        "SnmpTrapStatus",
                        [asyncResp, enableSNMPv1, enableSNMPv2c,
                         enableSNMPv3](const boost::system::error_code& ec,
                                       bool snmpStatus) {
                            if (ec)
                            {
                                messages::internalError(asyncResp->res);
                                return;
                            }
                            if (!snmpStatus)
                            {
                                BMCWEB_LOG_ERROR(
                                    "SNMP service is disabled; cannot "
                                    "patch version flags");
                                messages::propertyValueConflict(
                                    asyncResp->res,
                                    "EnableSNMPv1/EnableSNMPv2c/"
                                    "EnableSNMPv3",
                                    "SNMP/ProtocolEnabled");
                                return;
                            }
                            if (enableSNMPv1)
                            {
                                setSnmpUtilsProperty(asyncResp, "EnableSNMPV1",
                                                     *enableSNMPv1);
                            }
                            if (enableSNMPv2c)
                            {
                                setSnmpUtilsProperty(asyncResp, "EnableSNMPV2",
                                                     *enableSNMPv2c);
                            }
                            if (enableSNMPv3)
                            {
                                setSnmpUtilsProperty(asyncResp, "EnableSNMPV3",
                                                     *enableSNMPv3);
                            }
                        });
                }
            }
        }

        if (communityStrings && oemCommunityStrings)
        {
            patchSnmpCommunityString(communityStrings, oemCommunityStrings,
                                     asyncResp);
        }
    } // end if (!isInValid) for SNMP

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
                       const std::string& serviceName,
                       const std::string& ObjectName,
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
    service_util::getMasked(asyncResp, ipmiServiceName, "IPMI", "Masked",
                            "Ami");
    service_util::getMasked(asyncResp, ipmiServiceName, "IPMI", "Running",
                            "Ami");
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
    service_util::getMasked(asyncResp, httpsServiceName, "HTTPS", "Masked",
                            "Ami");
    service_util::getMasked(asyncResp, httpsServiceName, "HTTPS", "Running",
                            "Ami");
}
inline void getIpmbMasked(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    service_util::getMasked(asyncResp, ipmbServiceName, "IPMB", "Masked",
                            "Ami");
    service_util::getMasked(asyncResp, ipmbServiceName, "IPMB", "Running",
                            "Ami");
}

inline void getOEMAMIChannelInfo(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code& ec,
                    const std::map<uint8_t, std::string>& channelMap) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG(
                    "D-Bus Method GetChannelInterfaceMap Response Error: {}",
                    ec);
                return;
            }
            nlohmann::json channelJson = nlohmann::json::array();
            bool defaultChannel = false;

            for (const auto& [channel, interface] : channelMap)
            {
                if (!defaultChannel)
                {
                    nlohmann::json entry = {{"ChannelId", channel},
                                            {"ChannelName", interface}};
                    asyncResp->res.jsonValue["Oem"]["Ami"]["DefaultChannel"] =
                        entry;
                    defaultChannel = true;
                }

                channelJson.push_back(
                    {{"ChannelId", channel}, {"ChannelName", interface}});
            }

            asyncResp->res.jsonValue["Oem"]["Ami"]["AvailableChannelList"] =
                channelJson;
        },
        "xyz.openbmc_project.User.Manager",       // Service
        "/xyz/openbmc_project/user",              // Object path
        "xyz.openbmc_project.User.AccountPolicy", // Interface
        "GetChannelInterfaceMap"                  // Method name
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
