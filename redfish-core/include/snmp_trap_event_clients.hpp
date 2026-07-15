// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#pragma once

#include "async_resp.hpp"
#include "dbus_singleton.hpp"
#include "dbus_utility.hpp"
#include "error_messages.hpp"
#include "event_service_manager.hpp"
#include "generated/enums/event_destination.hpp"
#include "http_request.hpp"
#include "http_response.hpp"
#include "logging.hpp"
#include "utils/dbus_utils.hpp"

#include <boost/asio/ip/address.hpp>
#include <boost/system/error_code.hpp>
#include <boost/url/format.hpp>
#include <sdbusplus/asio/property.hpp>
#include <sdbusplus/unpack_properties.hpp>

#include <array>
#include <charconv>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace redfish
{

static constexpr size_t snmpSubscriptionSlotCount = 15;
static constexpr const char* snmpAddressDefaultIpv4 = "0.0.0.0";
static constexpr const char* snmpAddressDefaultIpv6 =
    "0000:0000:0000:0000:0000:0000:0000:0000";
static constexpr const char* snmpLanParamConfigIface =
    "xyz.openbmc_project.pef.LanParamConfig";
static constexpr const char* snmpAlertManagerService =
    "xyz.openbmc_project.pef.alert.manager";
static constexpr const char* snmpAlertManagerRoot =
    "/xyz/openbmc_project/PefAlertManager";
static constexpr const char* snmpInterfacePathPrefix =
    "/xyz/openbmc_project/PefAlertManager/Interface_";
static constexpr const char* snmpUserManagerService =
    "xyz.openbmc_project.User.Manager";
static constexpr const char* userRootPath = "/xyz/openbmc_project/user";
static constexpr const char* userAttributesIface =
    "xyz.openbmc_project.User.Attributes";

struct SnmpSubscriptionEntryInfo
{
    std::string id;
    std::string interfaceName;
    std::string dbusPath;
    size_t slotIndex = 0;
};

struct SnmpLanParamConfig
{
    std::vector<std::string> ipv4;
    std::vector<std::string> ipv6;
    std::vector<uint8_t> addressType;
    std::vector<uint8_t> type;
    std::vector<std::string> userName;
    std::string communityString;
};

std::string getSnmpInterfaceDbusPath(std::string_view interfaceName)
{
    return std::string(snmpInterfacePathPrefix) + std::string(interfaceName);
}

bool parseSnmpSubscriptionId(const std::string& id,
                             SnmpSubscriptionEntryInfo& entryInfo)
{
    auto isValidEntry = [](const std::string& entryId) {
        const size_t pos = entryId.rfind('_');
        return pos != std::string::npos && entryId.starts_with("eth") &&
               pos > 3 && pos + 1 < entryId.size();
    };

    if (!isValidEntry(id))
    {
        return false;
    }

    const size_t pos = id.rfind('_');
    std::string_view interfaceName(id.data(), pos);
    std::string_view slotSuffix(id.data() + pos + 1, id.size() - pos - 1);

    int slotIndex = 0;
    auto [endPtr, ec] = std::from_chars(
        slotSuffix.data(), slotSuffix.data() + slotSuffix.size(), slotIndex);
    if (ec != std::errc() || endPtr != slotSuffix.data() + slotSuffix.size() ||
        slotIndex < 0 ||
        slotIndex >= static_cast<int>(snmpSubscriptionSlotCount))
    {
        return false;
    }

    entryInfo.id = id;
    entryInfo.interfaceName = std::string(interfaceName);
    entryInfo.dbusPath = getSnmpInterfaceDbusPath(interfaceName);
    entryInfo.slotIndex = static_cast<size_t>(slotIndex);
    return true;
}

bool isSnmpSubscriptionInterfacePresentInDbusPaths(
    const SnmpSubscriptionEntryInfo& entryInfo,
    const dbus::utility::MapperGetSubTreePathsResponse& dbusPaths)
{
    return std::ranges::find(dbusPaths, entryInfo.dbusPath) != dbusPaths.end();
}

void withValidatedSnmpSubscriptionEntry(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp, const std::string& id,
    std::function<void(const SnmpSubscriptionEntryInfo&)> onValid)
{
    SnmpSubscriptionEntryInfo entryInfo;
    if (!parseSnmpSubscriptionId(id, entryInfo))
    {
        messages::resourceNotFound(asyncResp->res, "Subscriptions", id);
        return;
    }

    constexpr std::array<std::string_view, 1> interfaces = {
        snmpLanParamConfigIface};
    dbus::utility::getSubTreePaths(
        std::string(snmpAlertManagerRoot), 0, interfaces,
        [asyncResp, entryInfo, onValid{std::move(onValid)}](
            const boost::system::error_code& ec,
            const dbus::utility::MapperGetSubTreePathsResponse& dbusPaths) {
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "D-Bus response error on SNMP interface GetSubTreePaths: {}",
                    ec);
                messages::internalError(asyncResp->res);
                return;
            }

            if (!isSnmpSubscriptionInterfacePresentInDbusPaths(entryInfo,
                                                               dbusPaths))
            {
                messages::resourceNotFound(asyncResp->res, "Subscriptions",
                                           entryInfo.id);
                return;
            }

            onValid(entryInfo);
        });
}

bool unpackSnmpLanParamConfig(
    const dbus::utility::DBusPropertiesMap& properties,
    SnmpLanParamConfig& config)
{
    const std::vector<std::string>* ipv4Array = nullptr;
    const std::vector<std::string>* ipv6Array = nullptr;
    const std::vector<uint8_t>* addressTypeArray = nullptr;
    const std::vector<uint8_t>* typeArray = nullptr;
    const std::vector<std::string>* userNameArray = nullptr;

    bool success = sdbusplus::unpackPropertiesNoThrow(
        dbus_utils::UnpackErrorPrinter(), properties, "IPv4", ipv4Array, "IPv6",
        ipv6Array, "AddressType", addressTypeArray, "Type", typeArray,
        "userName", userNameArray, "CommunityString", config.communityString);

    if (!success || ipv4Array == nullptr || ipv6Array == nullptr ||
        addressTypeArray == nullptr || typeArray == nullptr ||
        userNameArray == nullptr)
    {
        return false;
    }

    config.ipv4 = *ipv4Array;
    config.ipv6 = *ipv6Array;
    config.addressType = *addressTypeArray;
    config.type = *typeArray;
    config.userName = *userNameArray;
    return true;
}

// D-Bus read/validation with the selected slot config.
void getSnmpLanParamConfig(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const SnmpSubscriptionEntryInfo& entryInfo,
    std::function<void(const SnmpSubscriptionEntryInfo&, SnmpLanParamConfig&&)>
        onConfig)
{
    dbus::utility::getAllProperties(
        std::string(snmpAlertManagerService), entryInfo.dbusPath,
        std::string(snmpLanParamConfigIface),
        [asyncResp, entryInfo, onConfig{std::move(onConfig)}](
            const boost::system::error_code& ec,
            const dbus::utility::DBusPropertiesMap& properties) {
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "D-Bus error getting SNMP interface properties: {}",
                    ec.message());
                messages::internalError(asyncResp->res);
                return;
            }

            SnmpLanParamConfig config;
            if (!unpackSnmpLanParamConfig(properties, config) ||
                config.ipv4.size() <= entryInfo.slotIndex ||
                config.ipv6.size() <= entryInfo.slotIndex ||
                config.addressType.size() <= entryInfo.slotIndex ||
                config.type.size() <= entryInfo.slotIndex ||
                config.userName.size() <= entryInfo.slotIndex)
            {
                messages::internalError(asyncResp->res);
                return;
            }

            onConfig(entryInfo, std::move(config));
        });
}

void setSnmpLanParamConfig(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                           const SnmpSubscriptionEntryInfo& entryInfo,
                           const SnmpLanParamConfig& config,
                           std::function<void()> onComplete)
{
    auto pending = std::make_shared<size_t>(6);
    auto done = std::make_shared<bool>(false);

    auto handleResult =
        [asyncResp, entryInfo, config, onComplete{std::move(onComplete)},
         pending, done](std::string_view propertyName,
                        const boost::system::error_code& ec) mutable {
            if (*done)
            {
                return;
            }

            if (ec)
            {
                *done = true;
                BMCWEB_LOG_ERROR("Failed to set {} for {}: {}", propertyName,
                                 entryInfo.id, ec.message());
                if (propertyName == "CommunityString")
                {
                    messages::propertyValueIncorrect(asyncResp->res,
                                                     config.communityString,
                                                     "SNMP/TrapCommunity");
                    return;
                }

                messages::internalError(asyncResp->res);
                return;
            }

            *pending -= 1;
            if (*pending == 0)
            {
                onComplete();
            }
        };

    auto setProperty = [entryInfo, handleResult](std::string_view propertyName,
                                                 const auto& value) mutable {
        crow::connections::systemBus->async_method_call(
            [propertyName,
             handleResult](const boost::system::error_code& ec) mutable {
                handleResult(propertyName, ec);
            },
            std::string(snmpAlertManagerService), entryInfo.dbusPath,
            "org.freedesktop.DBus.Properties", "Set",
            std::string(snmpLanParamConfigIface), std::string(propertyName),
            dbus::utility::DbusVariantType(value));
    };

    setProperty("IPv4", config.ipv4);
    setProperty("IPv6", config.ipv6);
    setProperty("AddressType", config.addressType);
    setProperty("Type", config.type);
    setProperty("CommunityString", config.communityString);
    setProperty("userName", config.userName);
}

static bool isUnspecifiedIpv4Address(const std::string& address)
{
    if (address.empty())
    {
        return true;
    }

    boost::system::error_code ec;
    boost::asio::ip::address_v4 parsed =
        boost::asio::ip::make_address_v4(address, ec);
    return !ec && parsed.is_unspecified();
}

static bool isUnspecifiedIpv6Address(const std::string& address)
{
    if (address.empty())
    {
        return true;
    }

    boost::system::error_code ec;
    boost::asio::ip::address_v6 parsed =
        boost::asio::ip::make_address_v6(address, ec);
    return !ec && parsed.is_unspecified();
}

std::string getDefaultSnmpIpv6Value(const std::vector<std::string>& ipv6Array,
                                    size_t currentIndex)
{
    for (size_t index = 0; index < ipv6Array.size(); ++index)
    {
        if (index != currentIndex && isUnspecifiedIpv6Address(ipv6Array[index]))
        {
            return ipv6Array[index];
        }
    }
    return "0000:0000:0000:0000:0000:0000:0000:0000";
}

std::string getSnmpSlotId(const std::string& interfaceName, int slotIndex)
{
    return interfaceName + "_" + std::to_string(slotIndex);
}

std::string_view getDbusObjectNameFromPath(std::string_view path)
{
    size_t lastSlash = path.rfind('/');
    if (lastSlash == std::string_view::npos || lastSlash + 1 >= path.size())
    {
        return std::string_view{};
    }
    return path.substr(lastSlash + 1);
}

void withUserAttributesObjectPath(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& userName, std::string_view redfishErrorProperty,
    std::function<void(const std::string&)> onPathReady)
{
    constexpr std::array<std::string_view, 1> userInterfaces = {
        userAttributesIface};
    dbus::utility::getSubTreePaths(
        std::string(userRootPath), 0, userInterfaces,
        [asyncResp, userName, redfishErrorProperty,
         onPathReady{std::move(onPathReady)}](
            const boost::system::error_code& ec,
            const dbus::utility::MapperGetSubTreePathsResponse& userPaths) {
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "Failed to query User.Attributes subtree paths: {}",
                    ec.message());
                messages::internalError(asyncResp->res);
                return;
            }

            for (const std::string& userPath : userPaths)
            {
                if (getDbusObjectNameFromPath(userPath) == userName)
                {
                    onPathReady(userPath);
                    return;
                }
            }

            messages::propertyValueIncorrect(asyncResp->res, userName,
                                             std::string(redfishErrorProperty));
        });
}

template <typename PropertyType>
void withUserAttributesProperty(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& userName, std::string_view propertyName,
    std::string_view redfishErrorProperty,
    std::function<void(const PropertyType&)> onPropertyReady)
{
    withUserAttributesObjectPath(
        asyncResp, userName, redfishErrorProperty,
        [asyncResp, propertyName = std::string(propertyName),
         onPropertyReady{std::move(onPropertyReady)}](
            const std::string& userPath) {
            sdbusplus::asio::getProperty<PropertyType>(
                *crow::connections::systemBus,
                std::string(snmpUserManagerService), userPath,
                std::string(userAttributesIface), propertyName,
                [asyncResp, propertyName,
                 onPropertyReady{std::move(onPropertyReady)}](
                    const boost::system::error_code& ec,
                    const PropertyType& propertyValue) {
                    if (ec)
                    {
                        BMCWEB_LOG_ERROR("Failed to read {}: {}", propertyName,
                                         ec.message());
                        messages::internalError(asyncResp->res);
                        return;
                    }

                    onPropertyReady(propertyValue);
                });
        });
}

constexpr uint8_t snmpAddressTypeIpv4 = 1;
constexpr uint8_t snmpAddressTypeIpv6 = 2;

// Type stores the configured protocol. AddressType stores whether the slot
// uses IPv4 or IPv6.
bool isConfiguredSnmpSlot(uint8_t protocolType, uint8_t addressType,
                          const std::string& ipv4Dest,
                          const std::string& ipv6Dest)
{
    if (protocolType == 3)
    {
        // SMTP slots are valid without an IP destination.
        return true;
    }

    if (addressType == snmpAddressTypeIpv6)
    {
        return !isUnspecifiedIpv6Address(ipv6Dest);
    }

    return !isUnspecifiedIpv4Address(ipv4Dest);
}

std::optional<uint8_t> getTypeFromProtocol(std::string_view protocol)
{
    if (protocol == "SNMPv1")
    {
        return 0;
    }
    if (protocol == "SNMPv2c")
    {
        return 1;
    }
    if (protocol == "SNMPv3")
    {
        return 2;
    }
    if (protocol == "SMTP")
    {
        return 3;
    }
    return std::nullopt;
}

std::string getProtocolFromType(uint8_t type)
{
    switch (type)
    {
        case 0:
            return "SNMPv1";
        case 1:
            return "SNMPv2c";
        case 2:
            return "SNMPv3";
        case 3:
            return "SMTP";
        default:
            return "SNMPv2c";
    }
}

std::string getSubscriptionTypeFromProtocolType(uint8_t type)
{
    // Redfish EventDestination maps SNMPv1 to Trap and v2c/v3 to Inform.
    if (type == 0)
    {
        return "SNMPTrap";
    }
    if (type == 3)
    {
        return "OEM";
    }
    return "SNMPInform";
}

void getSnmpTrapClient(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                       const std::string& id)
{
    withValidatedSnmpSubscriptionEntry(
        asyncResp, id, [asyncResp](const SnmpSubscriptionEntryInfo& entryInfo) {
            getSnmpLanParamConfig(
                asyncResp, entryInfo,
                [asyncResp](const SnmpSubscriptionEntryInfo& validatedEntry,
                            SnmpLanParamConfig&& config) {
                    asyncResp->res.jsonValue["@odata.type"] =
                        "#EventDestination.v1_14_1.EventDestination";
                    asyncResp->res.jsonValue["@odata.id"] = boost::urls::format(
                        "/redfish/v1/EventService/Subscriptions/{}",
                        validatedEntry.id);
                    asyncResp->res.jsonValue["Id"] = validatedEntry.id;
                    asyncResp->res.jsonValue["Name"] =
                        "Event LAN Destination " + validatedEntry.id;
                    asyncResp->res.jsonValue["EventFormatType"] = "Event";

                    const uint8_t protocolType =
                        config.type[validatedEntry.slotIndex];
                    const uint8_t addressType =
                        config.addressType[validatedEntry.slotIndex];
                    const std::string& ipv4Dest =
                        config.ipv4[validatedEntry.slotIndex];
                    const std::string& ipv6Dest =
                        config.ipv6[validatedEntry.slotIndex];
                    const std::string& slotUserName =
                        config.userName[validatedEntry.slotIndex];

                    asyncResp->res.jsonValue["SubscriptionType"] =
                        getSubscriptionTypeFromProtocolType(protocolType);
                    asyncResp->res.jsonValue["Protocol"] =
                        getProtocolFromType(protocolType);
                    asyncResp->res.jsonValue["UserName"] = "";
                    asyncResp->res.jsonValue["Destination"] = "";
                    asyncResp->res.jsonValue["SNMP"]["TrapCommunity"] = "";

                    if (protocolType == 3)
                    {
                        asyncResp->res.jsonValue["UserName"] = slotUserName;
                        asyncResp->res.jsonValue["Context"] =
                            "SMTP_" + validatedEntry.id;
                        asyncResp->res.result(boost::beast::http::status::ok);
                        return;
                    }

                    if (!isConfiguredSnmpSlot(protocolType, addressType,
                                              ipv4Dest, ipv6Dest))
                    {
                        asyncResp->res.jsonValue["Context"] =
                            "SNMP_" + validatedEntry.id;
                        asyncResp->res.result(boost::beast::http::status::ok);
                        return;
                    }

                    const std::string& destAddr =
                        (addressType == snmpAddressTypeIpv6)
                            ? ipv6Dest
                            : ipv4Dest;

                    static constexpr uint16_t defaultSnmpTrapPort = 162;
                    const bool isSnmpV3 = (protocolType == 2);

                    if (addressType == snmpAddressTypeIpv6)
                    {
                        if (isSnmpV3 && !slotUserName.empty())
                        {
                            asyncResp->res.jsonValue["Destination"] =
                                "snmp://" + slotUserName + "@[" + destAddr +
                                "]:" + std::to_string(defaultSnmpTrapPort);
                        }
                        else
                        {
                            asyncResp->res.jsonValue["Destination"] =
                                "snmp://[" + destAddr +
                                "]:" + std::to_string(defaultSnmpTrapPort);
                        }
                    }
                    else if (isSnmpV3 && !slotUserName.empty())
                    {
                        asyncResp->res.jsonValue["Destination"] =
                            "snmp://" + slotUserName + "@" + destAddr + ":" +
                            std::to_string(defaultSnmpTrapPort);
                    }
                    else
                    {
                        asyncResp->res.jsonValue["Destination"] =
                            "snmp://" + destAddr + ":" +
                            std::to_string(defaultSnmpTrapPort);
                    }

                    if (!isSnmpV3)
                    {
                        asyncResp->res.jsonValue["SNMP"]["TrapCommunity"] =
                            config.communityString;
                    }

                    asyncResp->res.jsonValue["Context"] =
                        "SNMP_" + validatedEntry.id;
                    asyncResp->res.result(boost::beast::http::status::ok);
                });
        });
}

inline void setprotocolEnable(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, "xyz.openbmc_project.Snmp.Conf",
        "/xyz/openbmc_project/snmp/SnmpUtils",
        "xyz.openbmc_project.Snmp.SnmpUtils", "SnmpTrapStatus", true,
        [asyncResp](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("Unable to set SNMPTrap");
                messages::internalError(asyncResp->res);
                return;
            }
        });
}

inline bool afterSnmpClientCreate(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const boost::system::error_code& ec, const sdbusplus::message_t& msg,
    const std::string& host, const std::string& dbusSNMPid,
    const std::shared_ptr<Subscription>& subValue,
    const std::shared_ptr<std::string>& subId)

{
    if (ec)
    {
        const sd_bus_error* dbusError = msg.get_error();
        if (dbusError != nullptr)
        {
            if (std::string_view(
                    "xyz.openbmc_project.Common.Error.InvalidArgument") ==
                dbusError->name)
            {
                messages::propertyValueIncorrect(asyncResp->res, "Destination",
                                                 host);
                return false;
            }
            if (ec.value() != EBADR)
            {
                // SNMP not installed
                messages::propertyValueOutOfRange(
                    asyncResp->res, subValue->userSub->protocol, "Protocol");
                return false;
            }
        }
        messages::internalError(asyncResp->res);
        return false;
    }
    sdbusplus::message::object_path path(dbusSNMPid);
    const std::string snmpId = path.filename();
    if (snmpId.empty())
    {
        messages::internalError(asyncResp->res);
        return false;
    }
    *subId = "snmp" + snmpId;
    EventServiceManager::getInstance().addPushSubscription(subValue, *subId);
    boost::urls::url uri = boost::urls::format(
        "/redfish/v1/EventService/Subscriptions/{}", *subId);
    asyncResp->res.addHeader("Location", uri.buffer());
    return true;
}

inline void verifySnmpSubscriptionConfiguration(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& interfaceName, int slotIndex,
    std::function<void(bool)> verificationCallback)
{
    SnmpSubscriptionEntryInfo entryInfo;
    entryInfo.id = getSnmpSlotId(interfaceName, slotIndex);
    entryInfo.interfaceName = interfaceName;
    entryInfo.dbusPath = getSnmpInterfaceDbusPath(interfaceName);
    entryInfo.slotIndex = static_cast<size_t>(slotIndex);

    getSnmpLanParamConfig(
        asyncResp, entryInfo,
        [asyncResp, verificationCallback{std::move(verificationCallback)},
         interfaceName](const SnmpSubscriptionEntryInfo& validatedEntry,
                        SnmpLanParamConfig&& config) mutable {
            const uint8_t protocolType = config.type[validatedEntry.slotIndex];
            const uint8_t addressType =
                config.addressType[validatedEntry.slotIndex];
            const std::string& ipv4Dest = config.ipv4[validatedEntry.slotIndex];
            const std::string& ipv6Dest = config.ipv6[validatedEntry.slotIndex];

            if (!isConfiguredSnmpSlot(protocolType, addressType, ipv4Dest,
                                      ipv6Dest))
            {
                const std::string slotId = getSnmpSlotId(
                    interfaceName, static_cast<int>(validatedEntry.slotIndex));
                BMCWEB_LOG_ERROR(
                    "SNMP subscription not properly configured: Type={}, "
                    "AddressType={}, IPv4={}, IPv6={}",
                    protocolType, addressType, ipv4Dest, ipv6Dest);
                messages::propertyValueEmpty(asyncResp->res, "", "Destination");
                messages::resourceNotFound(asyncResp->res, "Subscriptions",
                                           slotId);
                verificationCallback(false);
                return;
            }

            verificationCallback(true);
        });
}

inline void addSnmpTrapClient(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& host, uint16_t snmpTrapPort, const std::string& protocol,
    const std::string& username, const std::shared_ptr<Subscription>& subValue,
    const std::string& oemsnmpcommunitystring, const std::string& interfaceName,
    int slotIndex, const std::shared_ptr<std::string>& subId,
    std::function<void(bool)> snmpCompletionHandler)

{
    if (slotIndex < 0 || slotIndex > 14)
    {
        messages::propertyValueOutOfRange(
            asyncResp->res, std::to_string(slotIndex), "SlotIndex");
        return;
    }

    SnmpSubscriptionEntryInfo entryInfo{
        .id = getSnmpSlotId(interfaceName, slotIndex),
        .interfaceName = interfaceName,
        .dbusPath = getSnmpInterfaceDbusPath(interfaceName),
        .slotIndex = static_cast<size_t>(slotIndex)};

    auto applySnmpLanConfig = std::make_shared<std::function<void()>>(
        [asyncResp, host, snmpTrapPort, protocol, username, subValue,
         oemsnmpcommunitystring, interfaceName, slotIndex, subId,
         snmpCompletionHandler, entryInfo]() {
            getSnmpLanParamConfig(
                asyncResp, entryInfo,
                [asyncResp, host, snmpTrapPort, protocol, username,
                 oemsnmpcommunitystring, interfaceName, slotIndex, subId,
                 snmpCompletionHandler](
                    const SnmpSubscriptionEntryInfo& validatedEntry,
                    SnmpLanParamConfig&& config) {
                    if (protocol == "SMTP")
                    {
                        config.ipv4[validatedEntry.slotIndex] =
                            std::string(snmpAddressDefaultIpv4);
                        config.ipv6[validatedEntry.slotIndex] =
                            std::string(snmpAddressDefaultIpv6);
                    }
                    else
                    {
                        boost::system::error_code ipEc;
                        boost::asio::ip::address ipAddr =
                            boost::asio::ip::make_address(host, ipEc);
                        if (ipEc)
                        {
                            messages::propertyValueIncorrect(
                                asyncResp->res, "Destination", host);
                            return;
                        }

                        if (ipAddr.is_v6())
                        {
                            std::string bareIpv6 = host;
                            if (bareIpv6.size() >= 2 &&
                                bareIpv6.front() == '[' &&
                                bareIpv6.back() == ']')
                            {
                                bareIpv6 =
                                    bareIpv6.substr(1, bareIpv6.size() - 2);
                            }
                            config.ipv6[validatedEntry.slotIndex] = bareIpv6;
                            config.ipv4[validatedEntry.slotIndex] =
                                std::string(snmpAddressDefaultIpv4);
                        }
                        else
                        {
                            config.ipv4[validatedEntry.slotIndex] = host;
                            config.ipv6[validatedEntry.slotIndex] =
                                std::string(snmpAddressDefaultIpv6);
                        }
                    }

                    for (size_t index = 0; index < config.addressType.size() &&
                                           index < config.ipv4.size() &&
                                           index < config.ipv6.size();
                         ++index)
                    {
                        config.addressType[index] =
                            isUnspecifiedIpv6Address(config.ipv6[index])
                                ? snmpAddressTypeIpv4
                                : snmpAddressTypeIpv6;
                    }

                    std::optional<uint8_t> protocolType =
                        getTypeFromProtocol(protocol);
                    if (!protocolType)
                    {
                        messages::propertyValueNotInList(asyncResp->res,
                                                         protocol, "Protocol");
                        return;
                    }

                    config.type[validatedEntry.slotIndex] = *protocolType;
                    if (*protocolType == 2 || *protocolType == 3)
                    {
                        config.userName[validatedEntry.slotIndex] = username;
                    }
                    else
                    {
                        config.userName[validatedEntry.slotIndex].clear();
                    }

                    if ((*protocolType == 0 || *protocolType == 1) &&
                        oemsnmpcommunitystring.empty())
                    {
                        messages::propertyMissing(asyncResp->res,
                                                  "SNMP/TrapCommunity");
                        return;
                    }

                    if (!oemsnmpcommunitystring.empty())
                    {
                        config.communityString = oemsnmpcommunitystring;
                    }

                    setSnmpLanParamConfig(
                        asyncResp, validatedEntry, config,
                        [subId, interfaceName, slotIndex,
                         snmpCompletionHandler =
                             std::move(snmpCompletionHandler)]() mutable {
                            *subId = interfaceName + "_" +
                                     std::to_string(slotIndex);
                            snmpCompletionHandler(true);
                        });
                });
        });

    if (protocol == "SNMPv3")
    {
        if (username.empty())
        {
            messages::propertyValueFormatError(
                asyncResp->res,
                "snmp://@" + host + ":" + std::to_string(snmpTrapPort),
                "Destination");
            return;
        }

        withUserAttributesProperty<bool>(
            asyncResp, username, "SNMPAccessEnableStatus", "Destination",
            [asyncResp, applySnmpLanConfig](bool snmpAccessEnableStatus) {
                if (!snmpAccessEnableStatus)
                {
                    messages::propertyValueConflict(asyncResp->res,
                                                    "Destination",
                                                    "SNMPAccessEnableStatus");
                    return;
                }

                (*applySnmpLanConfig)();
            });
        return;
    }

    if (protocol == "SMTP")
    {
        if (username.empty())
        {
            messages::propertyMissing(asyncResp->res, "UserName");
            return;
        }

        withUserAttributesProperty<std::string>(
            asyncResp, username, "SMTPMailID", "UserName",
            [asyncResp, applySnmpLanConfig](const std::string& smtpMailId) {
                if (smtpMailId.empty())
                {
                    messages::propertyValueEmpty(asyncResp->res, smtpMailId,
                                                 "SMTPMailID");
                    return;
                }

                (*applySnmpLanConfig)();
            });
        return;
    }

    (*applySnmpLanConfig)();
}

inline void deleteSnmpTrapClient(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& param)
{
    withValidatedSnmpSubscriptionEntry(
        asyncResp, param,
        [asyncResp](const SnmpSubscriptionEntryInfo& entryInfo) {
            getSnmpLanParamConfig(
                asyncResp, entryInfo,
                [asyncResp](const SnmpSubscriptionEntryInfo& validatedEntry,
                            SnmpLanParamConfig&& config) {
                    config.ipv4[validatedEntry.slotIndex] =
                        std::string(snmpAddressDefaultIpv4);
                    config.ipv6[validatedEntry.slotIndex] =
                        std::string(snmpAddressDefaultIpv6);
                    config.addressType[validatedEntry.slotIndex] =
                        snmpAddressTypeIpv4;
                    config.type[validatedEntry.slotIndex] = 0;
                    config.userName[validatedEntry.slotIndex].clear();

                    setSnmpLanParamConfig(
                        asyncResp, validatedEntry, config, [asyncResp]() {
                            asyncResp->res.result(
                                boost::beast::http::status::no_content);
                        });
                });
        });
}

} // namespace redfish
