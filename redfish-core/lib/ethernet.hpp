// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
// SPDX-FileCopyrightText: Copyright 2018 Intel Corporation
#pragma once

#include "app.hpp"
#include "dbus_singleton.hpp"
#include "dbus_utility.hpp"
#include "error_messages.hpp"
#include "generated/enums/ethernet_interface.hpp"
#include "generated/enums/resource.hpp"
#include "human_sort.hpp"
#include "query.hpp"
#include "registries/privilege_registry.hpp"
#include "utils/ip_utils.hpp"
#include "utils/json_utils.hpp"
#if BMCWEB_AMI_REP_MACRO
    #include "ext/include/ami_errors.hpp"
#endif

#include <boost/system/error_code.hpp>
#include <boost/url/format.hpp>

#include <array>
#include <cstddef>
#include <memory>
#include <optional>
#include <ranges>
#include <regex>
#include <string_view>
#include <variant>
#include <vector>

#define MAX_MTU 1500
#define MIN_MTU 68

#define MAX_VLANPRIORITY 7

namespace redfish
{

enum class LinkType
{
    Local,
    Global
};

enum class Type
{
    GATEWAY4_ADDRESS,
    GATEWAY6_ADDRESS,
    IP4_ADDRESS,
    IP6_ADDRESS,
    SUBNETMASK
};

enum class IpVersion
{
    IpV4,
    IpV6
};

enum class IPType
{
    IPv4,
    IPv6,
    Both,
    Invalid,
    None
};

/**
 * Structure for keeping IPv4 data required by Redfish
 */
struct IPv4AddressData
{
    std::string id;
    std::string address;
    std::string domain;
    std::string gateway;
    std::string netmask;
    std::string origin;
    LinkType linktype{};
    bool isActive{};
};

/**
 * Structure for keeping IPv6 data required by Redfish
 */
struct IPv6AddressData
{
    std::string id;
    std::string address;
    std::string origin;
    uint8_t prefixLength = 0;
    uint8_t ipv6Index  = 0;
};

/**
 * Structure for keeping static route data required by Redfish
 */
struct StaticGatewayData
{
    std::string id;
    std::string gateway;
    size_t prefixLength = 0;
    std::string protocol;
};

/**
 * Structure for keeping basic single Ethernet Interface information
 * available from DBus
 */
struct EthernetInterfaceData
{
    uint32_t speed;
    size_t mtuSize;
    bool autoNeg;
    bool dnsv4Enabled;
    bool dnsv6Enabled;
    bool domainv4Enabled;
    bool domainv6Enabled;
    bool ntpv4Enabled;
    bool ntpv6Enabled;
    bool hostNamev4Enabled;
    bool hostNamev6Enabled;
    bool linkUp;
    bool nicEnabled;
    bool ipv6AcceptRa;
    std::string dhcpEnabled;
    std::string operatingMode;
    std::string hostName;
    std::string defaultGateway;
    std::string ipv6DefaultGateway;
    std::string ipv6StaticDefaultGateway;
    std::optional<std::string> macAddress;
    std::optional<uint32_t> vlanId;
    std::optional<uint32_t> vlanPriority;
    std::vector<std::string> nameServers;
    std::vector<std::string> staticNameServers;
    std::vector<std::string> domainnames;
    bool ipv4Enable;
    bool ipv6Enable;
};

struct DHCPParameters
{
    std::optional<bool> dhcpv4Enabled;
    std::optional<bool> useDnsServers;
    std::optional<bool> useNtpServers;
    std::optional<bool> useDomainName;
    std::optional<std::string> dhcpv6OperatingMode;
};

inline std::optional<std::string> defaultGatewayValue;
inline size_t completedOperations = 0;
inline size_t totalOperations = 0;
inline size_t interfacesChecked = 0; // Use atomic for thread safety

struct InterfaceState {
    bool hasIP = false;
    bool isEnabled = false;
};
inline std::map<std::string, InterfaceState> interfaceStates;

// Helper function that changes bits netmask notation (i.e. /24)
// into full dot notation
inline std::string getNetmask(unsigned int bits)
{
    uint32_t value = 0xffffffff << (32 - bits);
    std::string netmask = std::to_string((value >> 24) & 0xff) + "." +
                          std::to_string((value >> 16) & 0xff) + "." +
                          std::to_string((value >> 8) & 0xff) + "." +
                          std::to_string(value & 0xff);
    return netmask;
}

inline bool translateDhcpEnabledToBool(const std::string& inputDHCP,
                                       bool isIPv4)
{
    if (isIPv4)
    {
        return (
            (inputDHCP ==
             "xyz.openbmc_project.Network.EthernetInterface.DHCPConf.v4") ||
            (inputDHCP ==
             "xyz.openbmc_project.Network.EthernetInterface.DHCPConf.both") ||
            (inputDHCP == "xyz.openbmc_project.Network.EthernetInterface."
                          "DHCPConf.v4v6stateless"));
    }
    return ((inputDHCP ==
             "xyz.openbmc_project.Network.EthernetInterface.DHCPConf.v6") ||
            (inputDHCP ==
             "xyz.openbmc_project.Network.EthernetInterface.DHCPConf.both"));
}

inline std::string getDhcpEnabledEnumeration(bool isIPv4, bool isIPv6,
                                             bool ipv6AcceptRA = false)
{
    if (isIPv4 && isIPv6) // When both IPv4 and IPv6 is in DHCP Mode
    {
        return "xyz.openbmc_project.Network.EthernetInterface.DHCPConf.both";
    }
    if (isIPv4) // When IPv4 is in DHCP Mode, IPv6 is in Static Mode
    {
        if (ipv6AcceptRA) // When AcceptRA is true
        {
            return "xyz.openbmc_project.Network.EthernetInterface.DHCPConf."
                   "v4v6stateless";
        }
        else // When AcceptRA is false
        {
            return "xyz.openbmc_project.Network.EthernetInterface.DHCPConf.v4";
        }
    }
    if (isIPv6) // When IPv4 is in Static Mode, IPv6 is in DHCP Mode
    {
        return "xyz.openbmc_project.Network.EthernetInterface.DHCPConf.v6";
    }
    // When both IPv4 and IPv6 is in Static Mode
    if (ipv6AcceptRA) // When AcceptRA is true
    {
        return "xyz.openbmc_project.Network.EthernetInterface.DHCPConf."
               "v6stateless";
    }
    else // When AcceptRA is false
    {
        return "xyz.openbmc_project.Network.EthernetInterface.DHCPConf.none";
    }
}

inline std::string translateAddressOriginDbusToRedfish(
    const std::string& inputOrigin, bool isIPv4)
{
    if (inputOrigin == "xyz.openbmc_project.Network.IP.AddressOrigin.Static")
    {
        return "Static";
    }
    if (inputOrigin == "xyz.openbmc_project.Network.IP.AddressOrigin.LinkLocal")
    {
        if (isIPv4)
        {
            return "IPv4LinkLocal";
        }
        return "LinkLocal";
    }
    if (inputOrigin == "xyz.openbmc_project.Network.IP.AddressOrigin.DHCP")
    {
        if (isIPv4)
        {
            return "DHCP";
        }
        return "DHCPv6";
    }
    if (inputOrigin == "xyz.openbmc_project.Network.IP.AddressOrigin.SLAAC")
    {
        return "SLAAC";
    }
    return "";
}

inline bool extractEthernetInterfaceData(
    const std::string& ethifaceId,
    const dbus::utility::ManagedObjectType& dbusData,
    EthernetInterfaceData& ethData)
{
    bool idFound = false;
    for (const auto& objpath : dbusData)
    {
        for (const auto& ifacePair : objpath.second)
        {
            if (objpath.first == "/xyz/openbmc_project/network/" + ethifaceId)
            {
                idFound = true;
                if (ifacePair.first == "xyz.openbmc_project.Network.MACAddress")
                {
                    for (const auto& propertyPair : ifacePair.second)
                    {
                        if (propertyPair.first == "MACAddress")
                        {
                            const std::string* mac =
                                std::get_if<std::string>(&propertyPair.second);
                            if (mac != nullptr)
                            {
                                ethData.macAddress = *mac;
                            }
                        }
                    }
                }
                else if (ifacePair.first == "xyz.openbmc_project.Network.VLAN")
                {
                    for (const auto& propertyPair : ifacePair.second)
                    {
                        if (propertyPair.first == "Id")
                        {
                            const uint32_t* id =
                                std::get_if<uint32_t>(&propertyPair.second);
                            if (id != nullptr)
                            {
                                ethData.vlanId = *id;
                            }
                        }
                        else if (propertyPair.first == "Priority")
                        {
                            const uint32_t* priority =
                                std::get_if<uint32_t>(&propertyPair.second);
                            if (priority != nullptr)
                            {
                                ethData.vlanPriority = *priority;
                            }
                        }
                    }
                }
                else if (ifacePair.first ==
                         "xyz.openbmc_project.Network.EthernetInterface")
                {
                    for (const auto& propertyPair : ifacePair.second)
                    {
                        if (propertyPair.first == "AutoNeg")
                        {
                            const bool* autoNeg =
                                std::get_if<bool>(&propertyPair.second);
                            if (autoNeg != nullptr)
                            {
                                ethData.autoNeg = *autoNeg;
                            }
                        }
                        else if (propertyPair.first == "Speed")
                        {
                            const uint32_t* speed =
                                std::get_if<uint32_t>(&propertyPair.second);
                            if (speed != nullptr)
                            {
                                ethData.speed = *speed;
                            }
                        }
                        else if (propertyPair.first == "MTU")
                        {
                            const size_t* mtuSize =
                                std::get_if<size_t>(&propertyPair.second);
                            if (mtuSize != nullptr)
                            {
                                ethData.mtuSize = *mtuSize;
                            }
                        }
                        else if (propertyPair.first == "LinkUp")
                        {
                            const bool* linkUp =
                                std::get_if<bool>(&propertyPair.second);
                            if (linkUp != nullptr)
                            {
                                ethData.linkUp = *linkUp;
                            }
                        }
                        else if (propertyPair.first == "NICEnabled")
                        {
                            const bool* nicEnabled =
                                std::get_if<bool>(&propertyPair.second);
                            if (nicEnabled != nullptr)
                            {
                                ethData.nicEnabled = *nicEnabled;
                            }
                        }
                        else if (propertyPair.first == "IPv6AcceptRA")
                        {
                            const bool* ipv6AcceptRa =
                                std::get_if<bool>(&propertyPair.second);
                            if (ipv6AcceptRa != nullptr)
                            {
                                ethData.ipv6AcceptRa = *ipv6AcceptRa;
                            }
                        }
                        else if (propertyPair.first == "Nameservers")
                        {
                            const std::vector<std::string>* nameservers =
                                std::get_if<std::vector<std::string>>(
                                    &propertyPair.second);
                            if (nameservers != nullptr)
                            {
                                ethData.nameServers = *nameservers;
                            }
                        }
                        else if (propertyPair.first == "StaticNameServers")
                        {
                            const std::vector<std::string>* staticNameServers =
                                std::get_if<std::vector<std::string>>(
                                    &propertyPair.second);
                            if (staticNameServers != nullptr)
                            {
                                ethData.staticNameServers = *staticNameServers;
                            }
                        }
                        else if (propertyPair.first == "DHCPEnabled")
                        {
                            const std::string* dhcpEnabled =
                                std::get_if<std::string>(&propertyPair.second);
                            if (dhcpEnabled != nullptr)
                            {
                                ethData.dhcpEnabled = *dhcpEnabled;
                            }
                        }
                        else if (propertyPair.first == "DomainName")
                        {
                            const std::vector<std::string>* domainNames =
                                std::get_if<std::vector<std::string>>(
                                    &propertyPair.second);
                            if (domainNames != nullptr)
                            {
                                ethData.domainnames = *domainNames;
                            }
                        }
                        else if (propertyPair.first == "DefaultGateway")
                        {
                            const std::string* defaultGateway =
                                std::get_if<std::string>(&propertyPair.second);
                            if (defaultGateway != nullptr)
                            {
                                std::string defaultGatewayStr = *defaultGateway;
                                if (defaultGatewayStr.empty())
                                {
                                    ethData.defaultGateway = "0.0.0.0";
                                }
                                else
                                {
                                    ethData.defaultGateway = defaultGatewayStr;
                                }
                            }
                        }
                        else if (propertyPair.first == "DefaultGateway6")
                        {
                            const std::string* defaultGateway6 =
                                std::get_if<std::string>(&propertyPair.second);
                            if (defaultGateway6 != nullptr)
                            {
                                std::string defaultGateway6Str = *defaultGateway6;
                                ethData.ipv6DefaultGateway = defaultGateway6Str;
                            }
                        }
                        else if (propertyPair.first == "IPv4Enable")
                        {
                            const bool* ipv4Enable =
                                std::get_if<bool>(&propertyPair.second);
                            if (ipv4Enable != nullptr)
                            {
                                ethData.ipv4Enable = *ipv4Enable;
                            }
                        }
                        else if (propertyPair.first == "IPv6Enable")
                        {
                            const bool* ipv6Enable =
                                std::get_if<bool>(&propertyPair.second);
                            if (ipv6Enable != nullptr)
                            {
                                ethData.ipv6Enable = *ipv6Enable;
                            }
                        }
                    }
                }
            }

            sdbusplus::message::object_path path(
                "/xyz/openbmc_project/network");
            sdbusplus::message::object_path dhcp4Path =
                path / ethifaceId / "dhcp4";

            if (sdbusplus::message::object_path(objpath.first) == dhcp4Path)
            {
                if (ifacePair.first ==
                    "xyz.openbmc_project.Network.DHCPConfiguration")
                {
                    for (const auto& propertyPair : ifacePair.second)
                    {
                        if (propertyPair.first == "DNSEnabled")
                        {
                            const bool* dnsEnabled =
                                std::get_if<bool>(&propertyPair.second);
                            if (dnsEnabled != nullptr)
                            {
                                ethData.dnsv4Enabled = *dnsEnabled;
                            }
                        }
                        else if (propertyPair.first == "DomainEnabled")
                        {
                            const bool* domainEnabled =
                                std::get_if<bool>(&propertyPair.second);
                            if (domainEnabled != nullptr)
                            {
                                ethData.domainv4Enabled = *domainEnabled;
                            }
                        }
                        else if (propertyPair.first == "NTPEnabled")
                        {
                            const bool* ntpEnabled =
                                std::get_if<bool>(&propertyPair.second);
                            if (ntpEnabled != nullptr)
                            {
                                ethData.ntpv4Enabled = *ntpEnabled;
                            }
                        }
                        else if (propertyPair.first == "HostNameEnabled")
                        {
                            const bool* hostNameEnabled =
                                std::get_if<bool>(&propertyPair.second);
                            if (hostNameEnabled != nullptr)
                            {
                                ethData.hostNamev4Enabled = *hostNameEnabled;
                            }
                        }
                    }
                }
            }

            sdbusplus::message::object_path dhcp6Path =
                path / ethifaceId / "dhcp6";

            if (sdbusplus::message::object_path(objpath.first) == dhcp6Path)
            {
                if (ifacePair.first ==
                    "xyz.openbmc_project.Network.DHCPConfiguration")
                {
                    for (const auto& propertyPair : ifacePair.second)
                    {
                        if (propertyPair.first == "DNSEnabled")
                        {
                            const bool* dnsEnabled =
                                std::get_if<bool>(&propertyPair.second);
                            if (dnsEnabled != nullptr)
                            {
                                ethData.dnsv6Enabled = *dnsEnabled;
                            }
                        }
                        if (propertyPair.first == "DomainEnabled")
                        {
                            const bool* domainEnabled =
                                std::get_if<bool>(&propertyPair.second);
                            if (domainEnabled != nullptr)
                            {
                                ethData.domainv6Enabled = *domainEnabled;
                            }
                        }
                        else if (propertyPair.first == "NTPEnabled")
                        {
                            const bool* ntpEnabled =
                                std::get_if<bool>(&propertyPair.second);
                            if (ntpEnabled != nullptr)
                            {
                                ethData.ntpv6Enabled = *ntpEnabled;
                            }
                        }
                        else if (propertyPair.first == "HostNameEnabled")
                        {
                            const bool* hostNameEnabled =
                                std::get_if<bool>(&propertyPair.second);
                            if (hostNameEnabled != nullptr)
                            {
                                ethData.hostNamev6Enabled = *hostNameEnabled;
                            }
                        }
                    }
                }
            }
            // System configuration shows up in the global namespace, so no need
            // to check eth number
            if (ifacePair.first ==
                "xyz.openbmc_project.Network.SystemConfiguration")
            {
                for (const auto& propertyPair : ifacePair.second)
                {
                    if (propertyPair.first == "HostName")
                    {
                        const std::string* hostname =
                            std::get_if<std::string>(&propertyPair.second);
                        if (hostname != nullptr)
                        {
                            ethData.hostName = *hostname;
                        }
                    }
                }
            }
        }
    }
    return idFound;
}

// Helper function that extracts data for single ethernet ipv6 address
inline void extractIPV6Data(const std::string& ethifaceId,
                            const dbus::utility::ManagedObjectType& dbusData,
                            std::vector<IPv6AddressData>& ipv6Config)
{
    const std::string ipPathStart =
        "/xyz/openbmc_project/network/" + ethifaceId;

    // Since there might be several IPv6 configurations aligned with
    // single ethernet interface, loop over all of them
    for (const auto& objpath : dbusData)
    {
        // Check if proper pattern for object path appears
        if (objpath.first.str.starts_with(ipPathStart + "/"))
        {
            for (const auto& interface : objpath.second)
            {
                if (interface.first == "xyz.openbmc_project.Network.IP")
                {
                    auto type = std::ranges::find_if(
                        interface.second, [](const auto& property) {
                            return property.first == "Type";
                        });
                    if (type == interface.second.end())
                    {
                        continue;
                    }

                    const std::string* typeStr =
                        std::get_if<std::string>(&type->second);

                    if (typeStr == nullptr ||
                        (*typeStr !=
                         "xyz.openbmc_project.Network.IP.Protocol.IPv6"))
                    {
                        continue;
                    }

                    // Instance IPv6AddressData structure, and set as
                    // appropriate
                    IPv6AddressData& ipv6Address = ipv6Config.emplace_back();
                    ipv6Address.id =
                        objpath.first.str.substr(ipPathStart.size());
                    for (const auto& property : interface.second)
                    {
                        if (property.first == "Address")
                        {
                            const std::string* address =
                                std::get_if<std::string>(&property.second);
                            if (address != nullptr)
                            {
                                ipv6Address.address = *address;
                            }
                        }
                        else if (property.first == "Origin")
                        {
                            const std::string* origin =
                                std::get_if<std::string>(&property.second);
                            if (origin != nullptr)
                            {
                                ipv6Address.origin =
                                    translateAddressOriginDbusToRedfish(*origin,
                                                                        false);
                            }
                        }
                        else if (property.first == "PrefixLength")
                        {
                            const uint8_t* prefix =
                                std::get_if<uint8_t>(&property.second);
                            if (prefix != nullptr)
                            {
                                ipv6Address.prefixLength = *prefix;
                            }
                        }
                        else if (property.first == "Idx")
                        {
                            const uint8_t* ipindex =
                                std::get_if<uint8_t>(&property.second);

                            if (ipindex != nullptr)
                            {
				                ipv6Address.ipv6Index = *ipindex;
                            }
                        }
                        else if (property.first == "Type" ||
                                 property.first == "Gateway")
                        {
                            // Type & Gateway is not used
                        }
                        else
                        {
                            BMCWEB_LOG_ERROR(
                                "Got extra property: {} on the {} object",
                                property.first, objpath.first.str);
                        }
                    }
                }
            }
        }
    }
    // **Sort the entire ipv6Config vector** in ascending order based on 'ipv6Index'
    #if (BMCWEB_AMI_REP_MACRO)
    {
        std::sort(ipv6Config.begin(), ipv6Config.end(), 
            [](const IPv6AddressData& a, const IPv6AddressData& b) {
                return a.ipv6Index < b.ipv6Index;  // Ascending order
            });
    }
    #endif
}

// Helper function that extracts data for single ethernet ipv4 address
inline void extractIPData(const std::string& ethifaceId,
                          const dbus::utility::ManagedObjectType& dbusData,
                          std::vector<IPv4AddressData>& ipv4Config)
{
    const std::string ipPathStart =
        "/xyz/openbmc_project/network/" + ethifaceId;

    // Since there might be several IPv4 configurations aligned with
    // single ethernet interface, loop over all of them
    for (const auto& objpath : dbusData)
    {
        // Check if proper pattern for object path appears
        if (objpath.first.str.starts_with(ipPathStart + "/"))
        {
            for (const auto& interface : objpath.second)
            {
                if (interface.first == "xyz.openbmc_project.Network.IP")
                {
                    auto type = std::ranges::find_if(
                        interface.second, [](const auto& property) {
                            return property.first == "Type";
                        });
                    if (type == interface.second.end())
                    {
                        continue;
                    }

                    const std::string* typeStr =
                        std::get_if<std::string>(&type->second);

                    if (typeStr == nullptr ||
                        (*typeStr !=
                         "xyz.openbmc_project.Network.IP.Protocol.IPv4"))
                    {
                        continue;
                    }

                    // Instance IPv4AddressData structure, and set as
                    // appropriate
                    IPv4AddressData& ipv4Address = ipv4Config.emplace_back();
                    ipv4Address.id =
                        objpath.first.str.substr(ipPathStart.size());
                    for (const auto& property : interface.second)
                    {
                        if (property.first == "Address")
                        {
                            const std::string* address =
                                std::get_if<std::string>(&property.second);
                            if (address != nullptr)
                            {
                                ipv4Address.address = *address;
                            }
                        }
                        else if (property.first == "Origin")
                        {
                            const std::string* origin =
                                std::get_if<std::string>(&property.second);
                            if (origin != nullptr)
                            {
                                ipv4Address.origin =
                                    translateAddressOriginDbusToRedfish(*origin,
                                                                        true);
                            }
                        }
                        else if (property.first == "PrefixLength")
                        {
                            const uint8_t* mask =
                                std::get_if<uint8_t>(&property.second);
                            if (mask != nullptr)
                            {
                                // convert it to the string
                                ipv4Address.netmask = getNetmask(*mask);
                            }
                        }
                        else if (property.first == "Idx")
                        {
                            // Type & Gateway is not used
                        }
                        else if (property.first == "Type" ||
                                 property.first == "Gateway")
                        {
                            // Type & Gateway is not used
                        }
                        else
                        {
                            BMCWEB_LOG_ERROR(
                                "Got extra property: {} on the {} object",
                                property.first, objpath.first.str);
                        }
                    }
                    // Check if given address is local, or global
                    ipv4Address.linktype =
                        ipv4Address.address.starts_with("169.254.")
                            ? LinkType::Local
                            : LinkType::Global;
                }
            }
        }
    }
}

/**
 * @brief Modifies the default gateway assigned to the NIC
 *
 * @param[in] ifaceId     Id of network interface whose default gateway is to be
 *                        changed
 * @param[in] gateway     The new gateway value. Assigning an empty string
 *                        causes the gateway to be deleted
 * @param[io] asyncResp   Response object that will be returned to client
 *
 * @return None
 */
inline void updateIPv4DefaultGateway(
    const std::string& ifaceId, const std::string& gateway,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    setDbusProperty(
        asyncResp, "Gateway", "xyz.openbmc_project.Network",
        sdbusplus::message::object_path("/xyz/openbmc_project/network") /
            ifaceId,
        "xyz.openbmc_project.Network.EthernetInterface", "DefaultGateway",
        gateway);
}

/**
 * @brief Deletes given static IP address for the interface
 *
 * @param[in] ifaceId     Id of interface whose IP should be deleted
 * @param[in] ipHash      DBus Hash id of IP that should be deleted
 * @param[io] asyncResp   Response object that will be returned to client
 *
 * @return None
 */
inline void deleteIPAddress(const std::string& ifaceId,
                            const std::string& ipHash,
                            const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code& ec) {
            if (ec)
            {
                messages::internalError(asyncResp->res);
            }
        },
        "xyz.openbmc_project.Network",
        "/xyz/openbmc_project/network/" + ifaceId + ipHash,
        "xyz.openbmc_project.Object.Delete", "Delete");
}

// When any validation failes in handleIPv4StaticPatch function
// then this function used to enable DHCP4 property in back-end.
// so, we can restrict to disappear of IPv4 address
// while update any invalid addr, gateway or subnetMask.
inline void enableDHCP4(const std::string& ifaceId,
                        const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, "xyz.openbmc_project.Network",
        "/xyz/openbmc_project/network/" + ifaceId,
        "xyz.openbmc_project.Network.EthernetInterface", "DHCP4", true,
        [asyncResp](const boost::system::error_code& ec) {
            if (ec)
            {
                messages::internalError(asyncResp->res);
                return;
            }
        });
}

/**
 * @brief Creates a static IPv4 entry
 *
 * @param[in] ifaceId      Id of interface upon which to create the IPv4 entry
 * @param[in] prefixLength IPv4 prefix syntax for the subnet mask
 * @param[in] gateway      IPv4 address of this interfaces gateway
 * @param[in] address      IPv4 address to assign to this interface
 * @param[io] asyncResp    Response object that will be returned to client
 *
 * @return None
 */
inline void createIPv4(const std::string& ifaceId, uint8_t prefixLength,
                       const std::string& gateway, const std::string& address,
                       const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    auto createIpHandler =
        [asyncResp, ifaceId, gateway](const boost::system::error_code& ec) {
            if (ec)
            {
                messages::internalError(asyncResp->res);
                return;
            }
        };

    crow::connections::systemBus->async_method_call(
        std::move(createIpHandler), "xyz.openbmc_project.Network",
        "/xyz/openbmc_project/network/" + ifaceId,
        "xyz.openbmc_project.Network.IP.Create", "IP",
        "xyz.openbmc_project.Network.IP.Protocol.IPv4", address, prefixLength,
        gateway);
}

/**
 * @brief Deletes the IP entry for this interface and creates a replacement
 * static entry
 *
 * @param[in] ifaceId        Id of interface upon which to create the IPv6 entry
 * @param[in] id             The unique hash entry identifying the DBus entry
 * @param[in] prefixLength   Prefix syntax for the subnet mask
 * @param[in] address        Address to assign to this interface
 * @param[in] numStaticAddrs Count of IPv4 static addresses
 * @param[io] asyncResp      Response object that will be returned to client
 *
 * @return None
 */

inline void deleteAndCreateIPAddress(
    IpVersion version, const std::string& ifaceId, const std::string& id,
    uint8_t prefixLength, const std::string& address,
    const std::string& gateway,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp, version, ifaceId, address, prefixLength,
         gateway](const boost::system::error_code& ec) {
            if (ec)
            {
                messages::internalError(asyncResp->res);
            }
            std::string protocol = "xyz.openbmc_project.Network.IP.Protocol.";
            protocol += version == IpVersion::IpV4 ? "IPv4" : "IPv6";
            crow::connections::systemBus->async_method_call(
                [asyncResp, address,
                 ifaceId](const boost::system::error_code& ec2) {
                    if (ec2)
                    {
                        enableDHCP4(ifaceId, asyncResp);
                        messages::invalidip(asyncResp->res, "Address", address);
                        return;
                    }
                    messages::success(asyncResp->res);
                },
                "xyz.openbmc_project.Network",
                "/xyz/openbmc_project/network/" + ifaceId,
                "xyz.openbmc_project.Network.IP.Create", "IP", protocol,
                address, prefixLength, gateway);
        },
        "xyz.openbmc_project.Network",
        "/xyz/openbmc_project/network/" + ifaceId + id,
        "xyz.openbmc_project.Object.Delete", "Delete");
}

inline bool extractIPv6DefaultGatewayData(
    const std::string& ethifaceId,
    const dbus::utility::ManagedObjectType& dbusData,
    std::vector<StaticGatewayData>& staticGatewayConfig)
{
    std::string staticGatewayPathStart("/xyz/openbmc_project/network/");
    staticGatewayPathStart += ethifaceId;

    for (const auto& objpath : dbusData)
    {
        if (!std::string_view(objpath.first.str)
                 .starts_with(staticGatewayPathStart))
        {
            continue;
        }
        for (const auto& interface : objpath.second)
        {
            if (interface.first != "xyz.openbmc_project.Network.StaticGateway")
            {
                continue;
            }
            StaticGatewayData& staticGateway =
                staticGatewayConfig.emplace_back();
            staticGateway.id = objpath.first.filename();

            bool success = sdbusplus::unpackPropertiesNoThrow(
                redfish::dbus_utils::UnpackErrorPrinter(), interface.second,
                "Gateway", staticGateway.gateway, "ProtocolType",
                staticGateway.protocol);
            if (!success)
            {
                return false;
            }
        }
    }
    return true;
}

/**
 * @brief Creates IPv6 with given data
 *
 * @param[in] ifaceId      Id of interface whose IP should be added
 * @param[in] address      IP address that needs to be added
 * @param[io] asyncResp    Response object that will be returned to client
 *
 * @return None
 */
inline void createIPv6(const std::string& ifaceId, uint8_t prefixLength,
                       const std::string& address,
                       const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                       std::function<void(bool)> completionHandler)
{
    sdbusplus::message::object_path path("/xyz/openbmc_project/network");
    path /= ifaceId;

    auto createIpHandler =
        [asyncResp, address, completionHandler](const boost::system::error_code& ec) {
            if (ec)
            {
                if (ec == boost::system::errc::io_error)
                {
                    messages::invalidip(asyncResp->res, "Address", address);
                }
                else
                {
                    messages::internalError(asyncResp->res);
                }
                completionHandler(false);
            }
            else
            {
                completionHandler(true); // Notify completion with success
            }
        };
    // Passing null for gateway, as per redfish spec IPv6StaticAddresses
    // object does not have associated gateway property
    crow::connections::systemBus->async_method_call(
        std::move(createIpHandler), "xyz.openbmc_project.Network", path,
        "xyz.openbmc_project.Network.IP.Create", "IP",
        "xyz.openbmc_project.Network.IP.Protocol.IPv6", address, prefixLength,
        "");
}

/**
 * @brief Deletes given IPv6 Static Gateway
 *
 * @param[in] ifaceId     Id of interface whose IP should be deleted
 * @param[in] ipHash      DBus Hash id of IP that should be deleted
 * @param[io] asyncResp   Response object that will be returned to client
 *
 * @return None
 */
inline void
    deleteIPv6Gateway(std::string_view ifaceId, std::string_view gatewayId,
                      const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    sdbusplus::message::object_path path("/xyz/openbmc_project/network");
    path /= ifaceId;
    path /= gatewayId;
    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code& ec) {
            if (ec)
            {
                messages::internalError(asyncResp->res);
            }
        },
        "xyz.openbmc_project.Network", path,
        "xyz.openbmc_project.Object.Delete", "Delete");
}

/**
 * @brief Creates IPv6 static default gateway with given data
 *
 * @param[in] ifaceId      Id of interface whose IP should be added
 * @param[in] prefixLength Prefix length that needs to be added
 * @param[in] gateway      Gateway address that needs to be added
 * @param[io] asyncResp    Response object that will be returned to client
 *
 * @return None
 */
inline void createIPv6DefaultGateway(
    std::string_view ifaceId, const std::string& gateway,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    sdbusplus::message::object_path path("/xyz/openbmc_project/network");
    path /= ifaceId;
    auto createIpHandler = [asyncResp](const boost::system::error_code& ec) {
        if (ec)
        {
            messages::internalError(asyncResp->res);
        }
    };
    setDbusProperty(asyncResp, "DefaultGtaeway6", "xyz.openbmc_project.Network",
                    path, "xyz.openbmc_project.Network.EthernetInterface",
                    "DefaultGateway6", gateway);

    // For setting StaticGateway, back-end MR -
    // https://gerrit.openbmc.org/c/openbmc/phosphor-networkd/+/63033 not merged
    // yet for the time being commented method call and set DefaultGateway6
    // instead of StaticGateway

    /*    crow::connections::systemBus->async_method_call(
            std::move(createIpHandler), "xyz.openbmc_project.Network", path,
            "xyz.openbmc_project.Network.StaticGateway.Create", "StaticGateway",
            gateway, "xyz.openbmc_project.Network.IP.Protocol.IPv6");
    */
}

/**
 * @brief Deletes the IPv6 default gateway entry for this interface and
 * creates a replacement IPv6 default gateway entry
 *
 * @param[in] ifaceId      Id of interface upon which to create the IPv6
 * entry
 * @param[in] gateway      IPv6 gateway to assign to this interface
 * @param[io] asyncResp    Response object that will be returned to client
 *
 * @return None
 */
inline void deleteAndCreateIPv6DefaultGateway(
    std::string_view ifaceId, std::string_view gatewayId,
    const std::string& gateway,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    sdbusplus::message::object_path path("/xyz/openbmc_project/network");
    path /= ifaceId;
    path /= gatewayId;
    crow::connections::systemBus->async_method_call(
        [asyncResp, ifaceId, gateway](const boost::system::error_code& ec) {
            if (ec)
            {
                messages::internalError(asyncResp->res);
                return;
            }
            createIPv6DefaultGateway(ifaceId, gateway, asyncResp);
        },
        "xyz.openbmc_project.Network", path,
        "xyz.openbmc_project.Object.Delete", "Delete");
}

/**
 * @brief Sets IPv6 default gateway with given data
 *
 * @param[in] ifaceId      Id of interface whose gateway should be added
 * @param[in] input        Contains address that needs to be added
 * @param[in] staticGatewayData  Current static gateways in the system
 * @param[io] asyncResp    Response object that will be returned to client
 *
 * @return None
 */

inline void handleIPv6DefaultGateway(
    const std::string& ifaceId,
    std::vector<std::variant<nlohmann::json::object_t, std::nullptr_t>>& input,
    const std::vector<StaticGatewayData>& staticGatewayData,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    size_t entryIdx = 1;
    std::vector<StaticGatewayData>::const_iterator staticGatewayEntry =
        staticGatewayData.begin();

    for (std::variant<nlohmann::json::object_t, std::nullptr_t>& thisJson :
         input)
    {
        // find the next gateway entry
        while (staticGatewayEntry != staticGatewayData.end())
        {
            if (staticGatewayEntry->protocol ==
                "xyz.openbmc_project.Network.IP.Protocol.IPv6")
            {
                break;
            }
            staticGatewayEntry++;
        }
        std::string pathString =
            "IPv6StaticDefaultGateways/" + std::to_string(entryIdx);
        nlohmann::json::object_t* obj =
            std::get_if<nlohmann::json::object_t>(&thisJson);
        if (obj == nullptr)
        {
            if (staticGatewayEntry == staticGatewayData.end())
            {
                messages::resourceCannotBeDeleted(asyncResp->res);
                return;
            }
            deleteIPv6Gateway(ifaceId, staticGatewayEntry->id, asyncResp);
            return;
        }
        if (obj->empty())
        {
            // Do nothing, but make sure the entry exists.
            if (staticGatewayEntry == staticGatewayData.end())
            {
                messages::propertyValueFormatError(asyncResp->res, *obj,
                                                   pathString);
                return;
            }
        }
        std::optional<std::string> address;

        if (!json_util::readJsonObject( //
                *obj, asyncResp->res, //
                "Address", address //
                ))
        {
            return;
        }
        const std::string* addr = nullptr;
        if (address)
        {
            addr = &(*address);
        }
        else if (staticGatewayEntry != staticGatewayData.end())
        {
            addr = &(staticGatewayEntry->gateway);
        }
        else
        {
            messages::propertyMissing(asyncResp->res, pathString + "/Address");
            return;
        }
        if (staticGatewayEntry != staticGatewayData.end())
        {
            deleteAndCreateIPv6DefaultGateway(ifaceId, staticGatewayEntry->id,
                                              *addr, asyncResp);
            staticGatewayEntry++;
        }
        else
        {
            createIPv6DefaultGateway(ifaceId, *addr, asyncResp);
        }
        entryIdx++;
    }
}

/**
 * Function that retrieves all properties for given Ethernet Interface
 * Object
 * from EntityManager Network Manager
 * @param ethiface_id a eth interface id to query on DBus
 * @param callback a function that shall be called to convert Dbus output
 * into JSON
 */
template <typename CallbackFunc>
void getEthernetIfaceData(const std::string& ethifaceId,
                          CallbackFunc&& callback)
{
    sdbusplus::message::object_path path("/xyz/openbmc_project/network");
    dbus::utility::getManagedObjects(
        "xyz.openbmc_project.Network", path,
        [ethifaceId{std::string{ethifaceId}},
         callback = std::forward<CallbackFunc>(callback)](
            const boost::system::error_code& ec,
            const dbus::utility::ManagedObjectType& resp) mutable {
            EthernetInterfaceData ethData{};
            std::vector<IPv4AddressData> ipv4Data;
            std::vector<IPv6AddressData> ipv6Data;
            std::vector<StaticGatewayData> ipv6GatewayData;

            if (ec)
            {
                callback(false, ethData, ipv4Data, ipv6Data, ipv6GatewayData);
                return;
            }

            bool found =
                extractEthernetInterfaceData(ethifaceId, resp, ethData);
            if (!found)
            {
                callback(false, ethData, ipv4Data, ipv6Data, ipv6GatewayData);
                return;
            }

            extractIPData(ethifaceId, resp, ipv4Data);
            // Fix global GW
            for (IPv4AddressData& ipv4 : ipv4Data)
            {
                if (((ipv4.linktype == LinkType::Global) &&
                     (ipv4.gateway == "0.0.0.0")) ||
                    (ipv4.origin == "DHCP") || (ipv4.origin == "Static"))
                {
                    ipv4.gateway = ethData.defaultGateway;
                }
            }

            extractIPV6Data(ethifaceId, resp, ipv6Data);
            if (!extractIPv6DefaultGatewayData(ethifaceId, resp,
                                               ipv6GatewayData))
            {
                callback(false, ethData, ipv4Data, ipv6Data, ipv6GatewayData);
            }
            // Finally make a callback with useful data
            callback(true, ethData, ipv4Data, ipv6Data, ipv6GatewayData);
        });
}

/**
 * Function that retrieves all Ethernet Interfaces available through Network
 * Manager
 * @param callback a function that shall be called to convert Dbus output
 * into JSON.
 */
template <typename CallbackFunc>
void getEthernetIfaceList(CallbackFunc&& callback)
{
    sdbusplus::message::object_path path("/xyz/openbmc_project/network");
    dbus::utility::getManagedObjects(
        "xyz.openbmc_project.Network", path,
        [callback = std::forward<CallbackFunc>(callback)](
            const boost::system::error_code& ec,
            const dbus::utility::ManagedObjectType& resp) {
            // Callback requires vector<string> to retrieve all available
            // ethernet interfaces
            std::vector<std::string> ifaceList;
            ifaceList.reserve(resp.size());
            if (ec)
            {
                callback(false, ifaceList);
                return;
            }

            // Iterate over all retrieved ObjectPaths.
            for (const auto& objpath : resp)
            {
                // And all interfaces available for certain ObjectPath.
                for (const auto& interface : objpath.second)
                {
                    // If interface is
                    // xyz.openbmc_project.Network.EthernetInterface, this is
                    // what we're looking for.
                    if (interface.first ==
                        "xyz.openbmc_project.Network.EthernetInterface")
                    {
                        std::string ifaceId = objpath.first.filename();
                        if (ifaceId.empty())
                        {
                            continue;
                        }
                        // and put it into output vector.
                        ifaceList.emplace_back(ifaceId);
                    }
                }
            }

            std::ranges::sort(ifaceList, AlphanumLess<std::string>());

            // Finally make a callback with useful data
            callback(true, ifaceList);
        });
}

inline bool isHostnameValid(const std::string& hostname)
{
    // A valid host name can never have the dotted-decimal form (RFC 1123)
    if (std::ranges::all_of(hostname, ::isdigit))
    {
        return false;
    }
    // Each label(hostname/subdomains) within a valid FQDN
    // MUST handle host names of up to 63 characters (RFC 1123)
    // labels cannot start or end with hyphens (RFC 952)
    // labels can start with numbers (RFC 1123)
    // hostname starts with an alphanumeric character
    const std::regex pattern("^[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,62}[a-zA-Z0-9])?$");

    return std::regex_match(hostname, pattern);
}

inline bool isDomainnameValid(const std::string& domainname)
{
    // Can have Multiple Sub Domains
    // Top Level Domain is mandatory and max length is 63 characters, although
    // most are around 2-3 characters. Can have only alphabetical characters.
    // For Top Level Domain, we have limited max length and min length as 6 and
    // 2 respectively. Need to have at least one Sub Domain, apart from the Top
    // Level Domain(TLD) Each Sub Domain(label) can have up to 63 characters.
    // Each Sub Domain(label) can have alphanumeric characters, cannot start or
    // end with hyphens, need to have a trailing dot after each subdomain.
    const static std::regex pattern(
        "^([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+([a-zA-Z]{2,6})$");

    return std::regex_match(domainname, pattern);
}

inline void
    handleHostnamePatch(const std::string& hostname,
                        const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    // SHOULD handle host names of up to 255 characters(RFC 1123)
    if (hostname.length() > 255)
    {
        messages::propertyValueFormatError(asyncResp->res, hostname,
                                           "HostName");
        return;
    }
    if (!isHostnameValid(hostname))
    {
        messages::propertyValueFormatError(asyncResp->res, hostname,
                                           "HostName");
        return;
    }

    setDbusProperty(
        asyncResp, "HostName", "xyz.openbmc_project.Network",
        sdbusplus::message::object_path("/xyz/openbmc_project/network/config"),
        "xyz.openbmc_project.Network.SystemConfiguration", "HostName",
        hostname);
}

inline void
    handleMTUSizePatch(const std::string& ifaceId, const size_t mtuSize,
                       const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    sdbusplus::message::object_path objPath("/xyz/openbmc_project/network");
    objPath /= ifaceId;
    if ((mtuSize < MIN_MTU) || (mtuSize > MAX_MTU))
    {
        std::string mtu = std::to_string(mtuSize);
        std::string_view mtuview(mtu);
        messages::propertyValueOutOfRange(asyncResp->res, mtuview, "MTUSize");
        return;
    }
    setDbusProperty(asyncResp, "MTUSize", "xyz.openbmc_project.Network",
                    objPath, "xyz.openbmc_project.Network.EthernetInterface",
                    "MTU", mtuSize);
}

inline void handleDomainnamePatch(
    const std::string& ifaceId, const std::string& domainname,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    std::vector<std::string> vectorDomainname = {domainname};
    setDbusProperty(
        asyncResp, "FQDN", "xyz.openbmc_project.Network",
        sdbusplus::message::object_path("/xyz/openbmc_project/network") /
            ifaceId,
        "xyz.openbmc_project.Network.EthernetInterface", "DomainName",
        vectorDomainname);
}

inline bool
    validateFqdnHostName(const std::string& hostname, const std::string& fqdn,
                         const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    size_t pos = fqdn.find('.');
    if (pos == std::string::npos)
    {
        messages::propertyValueFormatError(asyncResp->res, fqdn, "FQDN");
        return false;
    }

    std::string fqdnhostname;
    fqdnhostname = (fqdn).substr(0, pos);

    if (fqdnhostname != hostname)
    {
        messages::propertyValueConflict(asyncResp->res, "FQDN", "HostName");
        return false;
    }

    return true;
}

inline void handleFqdnPatch(const std::string& ifaceId, const std::string& fqdn,
                            const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    // Total length of FQDN must not exceed 255 characters(RFC 1035)
    if (fqdn.length() > 255)
    {
        messages::propertyValueFormatError(asyncResp->res, fqdn, "FQDN");
        return;
    }

    size_t pos = fqdn.find('.');
    if (pos == std::string::npos)
    {
        messages::propertyValueFormatError(asyncResp->res, fqdn, "FQDN");
        return;
    }

    std::string hostname;
    std::string domainname;
    domainname = (fqdn).substr(pos + 1);
    hostname = (fqdn).substr(0, pos);

    if (!isHostnameValid(hostname) || !isDomainnameValid(domainname))
    {
        messages::propertyValueFormatError(asyncResp->res, fqdn, "FQDN");
        return;
    }

    handleHostnamePatch(hostname, asyncResp);
    handleDomainnamePatch(ifaceId, domainname, asyncResp);
}

inline void handleMACAddressPatch(
    const std::string& ifaceId, const std::string& macAddress,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    setDbusProperty(
        asyncResp, "MACAddress", "xyz.openbmc_project.Network",
        sdbusplus::message::object_path("/xyz/openbmc_project/network") /
            ifaceId,
        "xyz.openbmc_project.Network.MACAddress", "MACAddress", macAddress);
}

//function to set DHCP property
inline void setDHCP(const std::string& ifaceId, const std::string& propertyName, bool property, const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    std::string redfishPropertyName = propertyName;
    setDbusProperty(
        asyncResp, redfishPropertyName, "xyz.openbmc_project.Network",
        sdbusplus::message::object_path("/xyz/openbmc_project/network") /
            ifaceId,
        "xyz.openbmc_project.Network.EthernetInterface", propertyName, property);
}

enum class NetworkType
{
    dhcp4,
    dhcp6
};

inline void setEthernetInterfaceBoolProperty(
    const std::string& ifaceId, const std::string& propertyName,
    const bool& value, const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, "xyz.openbmc_project.Network",
        "/xyz/openbmc_project/network/" + ifaceId,
        "xyz.openbmc_project.Network.EthernetInterface", propertyName, value,
        [asyncResp](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-Bus responses error: {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }
            messages::success(asyncResp->res);
        });
}

inline void handleInterfacePatch(
    const std::string& ifaceId,const std::optional<bool>& interfaceEnabled,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    interfacesChecked = 0;
    interfaceStates.clear();

    auto fetchInterfaceCountAndIPCheck = [asyncResp{std::move(asyncResp)}, ifaceId, interfaceEnabled]() { 
        // Lambda to start after ActiveSlave check (or directly)
        sdbusplus::asio::getProperty<uint8_t>(
            *crow::connections::systemBus, "xyz.openbmc_project.Network",
            "/xyz/openbmc_project/network/config",
            "xyz.openbmc_project.Network.SystemConfiguration", "InterfaceCount",
            [asyncResp, ifaceId, interfaceEnabled](
                const boost::system::error_code, const uint8_t& interfaceCount) {

                constexpr std::array<std::string_view, 1> Interface = {
                    "xyz.openbmc_project.Network.EthernetInterface",
                };
                dbus::utility::getSubTreePaths(
                    "/xyz/openbmc_project/network", 0, Interface,
                    [asyncResp, ifaceId, interfaceEnabled, interfaceCount]
                    (const boost::system::error_code&, const dbus::utility::MapperGetSubTreePathsResponse& resps) {

                        std::vector<std::string> interfaceNames;
                        for (const auto& path : resps)
                        {
                            size_t lastSlash = path.rfind('/');
                            if (lastSlash != std::string::npos)
                            {
                                std::string interfaceName = path.substr(lastSlash + 1);
                                interfaceNames.push_back(interfaceName);
                            }
                        }

                        // This will be called when all interfaces are processed
                        auto finalCheck = [asyncResp, ifaceId, interfaceEnabled, interfaceCount]() {
                            if (interfacesChecked == interfaceCount)
                            {
                                // Same validation as above for when interface is being disabled
                                if (*interfaceEnabled == false)
                                {
                                    bool otherEnabledWithIP = false;
                                    for (const auto& [iface, state] : interfaceStates)
                                    {
                                        if (iface != ifaceId && state.isEnabled && state.hasIP)
                                        {
                                            otherEnabledWithIP = true;
                                            break;
                                        }
                                    }

                                    if (!otherEnabledWithIP)
                                    {
                                        #if (BMCWEB_AMI_REP_MACRO)
                                        {
                                            messages::singleEthernetEnabled(asyncResp->res,
                                                                           "InterfaceEnabled");
                                            return; // Exit the entire handleInterfacePatch function
                                        }
                                        #else
                                        {
                                            messages::propertyValueExternalConflict(
                                                asyncResp->res, "InterfaceEnabled",
                                                *interfaceEnabled);
                                            return; // Exit the entire handleInterfacePatch function
                                        }
                                        #endif
                                    }
                                }
                                setEthernetInterfaceBoolProperty(
                                    ifaceId, "NICEnabled", *interfaceEnabled,
                                    asyncResp);
                            }
                        };

                        for (uint8_t i = 0; i < interfaceCount; ++i)
                        {
                            std::string ethIface = interfaceNames[i];
                            interfaceStates[ethIface] = InterfaceState{};

                            // First check if interface is enabled
                            sdbusplus::asio::getProperty<bool>(
                                *crow::connections::systemBus, "xyz.openbmc_project.Network",
                                "/xyz/openbmc_project/network/" + ethIface,
                                "xyz.openbmc_project.Network.EthernetInterface", "NICEnabled",
                                [asyncResp, ethIface, ifaceId, interfaceEnabled, interfaceCount, finalCheck]
                                (const boost::system::error_code, const bool& nicEnabled) {

                                    interfaceStates[ethIface].isEnabled = nicEnabled;
                                    if (nicEnabled)
                                    {
                                        // Check if this enabled interface has IP addresses
                                        constexpr std::array<std::string_view, 1> interfacesIP = {
                                            "xyz.openbmc_project.Network.IP",
                                        };
                                        dbus::utility::getSubTreePaths(
                                            "/xyz/openbmc_project/network/" + ethIface, 0, interfacesIP,
                                            [asyncResp, ethIface, ifaceId, interfaceEnabled, interfaceCount, finalCheck]
                                            (const boost::system::error_code&, const dbus::utility::MapperGetSubTreePathsResponse& resp) {

                                                if (!resp.empty())
                                                {
                                                    interfaceStates[ethIface].hasIP = true;
                                                }
                                                interfacesChecked++;
                                                finalCheck();
                                            });
                                    }
                                    else
                                    {
                                        interfacesChecked++;
                                        finalCheck();
                                    }
                                });
                        }
                    });
            });
    };

    #if(BMCWEB_AMI_REP_MACRO)
        sdbusplus::asio::getProperty<std::string>(
            *crow::connections::systemBus, "xyz.openbmc_project.Network",
            "/xyz/openbmc_project/network/bond0",
            "xyz.openbmc_project.Network.Bond", "ActiveSlave",
            [asyncResp, ifaceId, interfaceEnabled, fetchInterfaceCountAndIPCheck]
            (const boost::system::error_code&, const std::string& activeSlave) {
                
                if (ifaceId == "bond0" && *interfaceEnabled == false)
                {
                    messages::singleEthernetEnabled(asyncResp->res,
                        "InterfaceEnabled");
                    return; // Exit the entire handleInterfacePatch function
                }
                if (ifaceId == activeSlave && *interfaceEnabled == false)
                {
                    messages::BondActiveSlaveDisable(asyncResp->res,
                                                    ifaceId);
                    return; // Exit the entire handleInterfacePatch function
                }
                // Proceed with the rest of the logic after the ActiveSlave check
                fetchInterfaceCountAndIPCheck();
                
            });
    #else
        // If the macro is not defined, directly fetch the interface count and proceed
        fetchInterfaceCountAndIPCheck();
    #endif
}

inline void setDHCPConfig(const std::string& propertyName, const bool& value,
                          const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                          const std::string& ethifaceId, NetworkType type)
{
    BMCWEB_LOG_DEBUG("{} = {}", propertyName, value);
    BMCWEB_LOG_DEBUG("IfaceId = {}", ethifaceId);
    std::string redfishPropertyName;
    sdbusplus::message::object_path path("/xyz/openbmc_project/network/");
    path /= ethifaceId;

    if (type == NetworkType::dhcp4)
    {
        path /= "dhcp4";
        redfishPropertyName = "DHCPv4";
    }
    else
    {
        path /= "dhcp6";
        redfishPropertyName = "DHCPv6";
    }

    setDbusProperty(
        asyncResp, redfishPropertyName, "xyz.openbmc_project.Network", path,
        "xyz.openbmc_project.Network.DHCPConfiguration", propertyName, value);
}

inline void handleSLAACAutoConfigPatch(
    const std::string& ifaceId, bool ipv6AutoConfigEnabled,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    sdbusplus::message::object_path path("/xyz/openbmc_project/network");
    path /= ifaceId;
    setDbusProperty(asyncResp,
                    "StatelessAddressAutoConfig/IPv6AutoConfigEnabled",
                    "xyz.openbmc_project.Network", path,
                    "xyz.openbmc_project.Network.EthernetInterface",
                    "IPv6AcceptRA", ipv6AutoConfigEnabled);
}

inline void handleDHCPv4v6Patch(
    const std::string& ifaceId,
    const DHCPParameters& v4dhcpParms, const DHCPParameters& v6dhcpParms,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    bool nextv4DHCPState = *v4dhcpParms.dhcpv4Enabled;
    bool nextv6DHCPState = (*v6dhcpParms.dhcpv6OperatingMode == "Enabled");

    if (v4dhcpParms.dhcpv4Enabled)
    {
        setDHCP(ifaceId, "DHCP4", nextv4DHCPState, asyncResp);
    }
    if(v6dhcpParms.dhcpv6OperatingMode)
    {
        setDHCP(ifaceId, "DHCP6", nextv6DHCPState, asyncResp);
    }
}

inline void handleDHCPPatch(
    const std::string& ifaceId, const EthernetInterfaceData& ethData,
    const DHCPParameters& v4dhcpParms, const DHCPParameters& v6dhcpParms,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    bool nextDNSv4 = ethData.dnsv4Enabled;
    bool nextDNSv6 = ethData.dnsv6Enabled;
    if (v4dhcpParms.useDnsServers)
    {
        nextDNSv4 = *v4dhcpParms.useDnsServers;
    }
    if (v6dhcpParms.useDnsServers)
    {
        nextDNSv6 = *v6dhcpParms.useDnsServers;
    }

    bool nextNTPv4 = ethData.ntpv4Enabled;
    bool nextNTPv6 = ethData.ntpv6Enabled;
    if (v4dhcpParms.useNtpServers)
    {
        nextNTPv4 = *v4dhcpParms.useNtpServers;
    }
    if (v6dhcpParms.useNtpServers)
    {
        nextNTPv6 = *v6dhcpParms.useNtpServers;
    }

    bool nextUsev4Domain = ethData.domainv4Enabled;
    bool nextUsev6Domain = ethData.domainv6Enabled;
    if (v4dhcpParms.useDomainName)
    {
        nextUsev4Domain = *v4dhcpParms.useDomainName;
    }
    if (v6dhcpParms.useDomainName)
    {
        nextUsev6Domain = *v6dhcpParms.useDomainName;
    }

    BMCWEB_LOG_DEBUG("set DNSEnabled...");
    setDHCPConfig("DNSEnabled", nextDNSv4, asyncResp, ifaceId,
                  NetworkType::dhcp4);
    BMCWEB_LOG_DEBUG("set NTPEnabled...");
    setDHCPConfig("NTPEnabled", nextNTPv4, asyncResp, ifaceId,
                  NetworkType::dhcp4);
    BMCWEB_LOG_DEBUG("set DomainEnabled...");
    setDHCPConfig("DomainEnabled", nextUsev4Domain, asyncResp, ifaceId,
                  NetworkType::dhcp4);
    BMCWEB_LOG_DEBUG("set DNSEnabled for dhcp6...");
    setDHCPConfig("DNSEnabled", nextDNSv6, asyncResp, ifaceId,
                  NetworkType::dhcp6);
    BMCWEB_LOG_DEBUG("set NTPEnabled for dhcp6...");
    setDHCPConfig("NTPEnabled", nextNTPv6, asyncResp, ifaceId,
                  NetworkType::dhcp6);
    BMCWEB_LOG_DEBUG("set DomainEnabled for dhcp6...");
    setDHCPConfig("DomainEnabled", nextUsev6Domain, asyncResp, ifaceId,
                  NetworkType::dhcp6);
}

inline std::vector<IPv4AddressData>::const_iterator getNextStaticIpEntry(
    const std::vector<IPv4AddressData>::const_iterator& head,
    const std::vector<IPv4AddressData>::const_iterator& end)
{
    return std::find_if(head, end, [](const IPv4AddressData& value) {
        return value.origin == "Static";
    });
}

inline std::vector<IPv6AddressData>::const_iterator getNextStaticIpEntry(
    const std::vector<IPv6AddressData>::const_iterator& head,
    const std::vector<IPv6AddressData>::const_iterator& end)
{
    return std::find_if(head, end, [](const IPv6AddressData& value) {
        return value.origin == "Static";
    });
}

inline bool isSameSeries(std::string ipStr, std::string gwStr,
                         uint8_t prefixLength)
{
    uint32_t ip = 0;
    if (inet_pton(AF_INET, ipStr.c_str(), &ip) !=
        1) // converting to numerical representation
    {
        return false;
    }
    uint32_t gw = 0;
    if (inet_pton(AF_INET, gwStr.c_str(), &gw) !=
        1) // converting to numerical representation
    {
        return false;
    }
    // Calculate netmask
    uint32_t netmask = htonl(~UINT32_C(0) << (32 - prefixLength));

    if ((ip & netmask) != (gw & netmask))
    {
        return false;
    }

    return true;
}

inline bool
    validateIPv4Json(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                     const nlohmann::json::array_t& input)
{
    if (input.empty())
    {
        messages::propertyValueTypeError(asyncResp->res, input,
                                         "IPv4StaticAddresses");
        return false;
    }
    if (input.size() > 1) // checking the array size of ipv4 address
    {
        messages::arraySizeTooLong(asyncResp->res, "IPv4StaticAddresses", 1);
        asyncResp->res.result(boost::beast::http::status::bad_request);
        return false;
    }
    unsigned entryIdx = 1;
    for (const nlohmann::json& thisJson : input)
    {
        std::string pathString =
            "IPv4StaticAddresses/" + std::to_string(entryIdx);
        if (!thisJson.is_null() && !thisJson.empty())
        {
            std::optional<std::string> address;
            std::optional<std::string> gateway;
            std::optional<std::string> subnetMask;
            nlohmann::json thisJsonCopy = thisJson;
            if (!json_util::readJson( //
                    thisJsonCopy, asyncResp->res, //
                    "Address", address, //
                    "SubnetMask", subnetMask, //
                    "Gateway", gateway //
                    ))
            {
                messages::propertyValueFormatError(asyncResp->res, thisJson,
                                                   pathString);
                return false;
            }
            if (address && gateway && subnetMask)
            {
                const std::string& ipAddress = *address;
                const std::string& ipGateway = *gateway;
                const std::string& ipSubnetMask = *subnetMask;
                uint8_t prefixLength = 0;

                if (!ip_util::isValidIPv4Addr(
                        ipAddress,
                        ip_util::Type::IP4_ADDRESS)) // checking the IPv4
                                                     // Address
                {
                    messages::invalidip(asyncResp->res, "Address", ipAddress);
                    return false;
                }
                if (!ip_util::isValidIPv4Addr(
                        ipGateway,
                        ip_util::Type::GATEWAY4_ADDRESS)) // checking the IPv4
                                                          // gateway Address
                {
                    messages::invalidip(asyncResp->res, "Gateway", ipGateway);
                    return false;
                }
                if (!ip_util::isValidIPv4Addr(
                        ipSubnetMask,
                        ip_util::Type::SUBNETMASK)) // checking the IPv4
                                                    // subnetmask Address
                {
                    messages::invalidip(asyncResp->res, "Subnetmask",
                                        ipSubnetMask);
                    return false;
                }
                if (subnetMask.has_value())
                {
                    if (ip_util::ipv4VerifyIpAndGetBitcount(*subnetMask,
                                                            &prefixLength))
                    {
                        if (!ip_util::isSameSeries(
                                ipAddress, ipGateway,
                                prefixLength)) // function call for checking if
                                               // the IPs are in the same series
                        {
                            messages::differentIpSeries(asyncResp->res,
                                                        "Address", "Gateway");
                            return false;
                            return false;
                        }
                    }
                    if (!ip_util::ipv4VerifyIpAndGetBitcount(*subnetMask,
                                                             &prefixLength))
                    {
                        messages::propertyValueFormatError(
                            asyncResp->res, *subnetMask, "SubnetMask");
                        return false;
                    }
                }
            }
        }
        entryIdx++;
    }
    return true;
}

inline void handleIPv4StaticPatch(
    const std::string& ifaceId,
    std::vector<std::variant<nlohmann::json::object_t, std::nullptr_t>>& input,
    const std::vector<IPv4AddressData>& ipv4Data,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (input.size() > 1)
    {
        return;
    }

    unsigned entryIdx = 1;
    // Find the first static IP address currently active on the NIC and
    // match it to the first JSON element in the IPv4StaticAddresses array.
    // Match each subsequent JSON element to the next static IP programmed
    // into the NIC.
    std::vector<IPv4AddressData>::const_iterator nicIpEntry =
        getNextStaticIpEntry(ipv4Data.cbegin(), ipv4Data.cend());

    // bool gatewayValueAssigned{};
    bool preserveGateway{};
    /*std::string activePath{};
    std::string activeGateway{};
    if (!ethData.defaultGateway.empty() && ethData.defaultGateway != "0.0.0.0")
    {
        // The NIC is already configured with a default gateway. Use this if
        // the leading entry in the PATCH is '{}', which is preserving an active
        // static address.
        activeGateway = ethData.defaultGateway;
        activePath = "IPv4StaticAddresses/1";
        gatewayValueAssigned = true;
    }*/

    for (std::variant<nlohmann::json::object_t, std::nullptr_t>& thisJson :
         input)
    {
        std::string pathString =
            "IPv4StaticAddresses/" + std::to_string(entryIdx);
        nlohmann::json::object_t* obj =
            std::get_if<nlohmann::json::object_t>(&thisJson);
        if (obj == nullptr)
        {
            if (nicIpEntry != ipv4Data.cend())
            {
                deleteIPAddress(ifaceId, nicIpEntry->id, asyncResp);
                nicIpEntry =
                    getNextStaticIpEntry(++nicIpEntry, ipv4Data.cend());
                if (!preserveGateway && (nicIpEntry == ipv4Data.cend()))
                {
                    // All entries have been processed, and this last has
                    // requested the IP address be deleted. No prior entry
                    // performed an action that created or modified a
                    // gateway. Deleting this IP address means the default
                    // gateway entry has to be removed as well.
                    updateIPv4DefaultGateway(ifaceId, "", asyncResp);
                }
                entryIdx++;
                continue;
            }
            // Received a DELETE action on an entry not assigned to the NIC
            messages::resourceCannotBeDeleted(asyncResp->res);
            return;
        }

        // An Add/Modify action is requested
        if (!obj->empty())
        {
            std::optional<std::string> address;
            std::optional<std::string> subnetMask;
            std::optional<std::string> gateway;

            if (!json_util::readJsonObject( //
                    *obj, asyncResp->res, //
                    "Address", address, //
                    "SubnetMask", subnetMask, //
                    "Gateway", gateway //
                    ))
            {
                enableDHCP4(ifaceId, asyncResp);
                messages::propertyValueFormatError(asyncResp->res, *obj,
                                                   pathString);
                return;
            }

            // Find the address/subnet/gateway values. Any values that are
            // not explicitly provided are assumed to be unmodified from the
            // current state of the interface. Merge existing state into the
            // current request.
            if (address)
            {
                if (*address == *defaultGatewayValue)
                {
                    enableDHCP4(ifaceId, asyncResp);
                    messages::propertyValueConflict(asyncResp->res, "Address",
                                                    "DefaultGateway");
                    return;
                }

                if (!ip_util::ipv4VerifyIpAndGetBitcount(*address))
                {
                    enableDHCP4(ifaceId, asyncResp);
                    messages::propertyValueFormatError(asyncResp->res, *address,
                                                       pathString + "/Address");
                    return;
                }
            }
            else if (nicIpEntry != ipv4Data.cend())
            {
                address = (nicIpEntry->address);
            }
            else
            {
                enableDHCP4(ifaceId, asyncResp);
                messages::propertyMissing(asyncResp->res,
                                          pathString + "/Address");
                return;
            }

            uint8_t prefixLength = 0;
            if (subnetMask)
            {
                if (!ip_util::ipv4VerifyIpAndGetBitcount(*subnetMask,
                                                         &prefixLength))
                {
                    enableDHCP4(ifaceId, asyncResp);
                    messages::propertyValueFormatError(
                        asyncResp->res, *subnetMask,
                        pathString + "/SubnetMask");
                    return;
                }
            }
            else if (nicIpEntry != ipv4Data.cend())
            {
                if (!ip_util::ipv4VerifyIpAndGetBitcount(nicIpEntry->netmask,
                                                         &prefixLength))
                {
                    enableDHCP4(ifaceId, asyncResp);
                    messages::propertyValueFormatError(
                        asyncResp->res, nicIpEntry->netmask,
                        pathString + "/SubnetMask");
                    return;
                }
            }
            else
            {
                enableDHCP4(ifaceId, asyncResp);
                messages::propertyMissing(asyncResp->res,
                                          pathString + "/SubnetMask");
                return;
            }

            if (gateway)
            {
                if (!ip_util::ipv4VerifyIpAndGetBitcount(*gateway))
                {
                    enableDHCP4(ifaceId, asyncResp);
                    messages::propertyValueFormatError(asyncResp->res, *gateway,
                                                       pathString + "/Gateway");
                    return;
                }
                if (*address == *gateway)
                {
                    enableDHCP4(ifaceId, asyncResp);
                    messages::propertyValueConflict(asyncResp->res, "Gateway",
                                                    "Address");
                    return;
                }
                defaultGatewayValue = gateway;
            }
            else if (nicIpEntry != ipv4Data.cend())
            {
                gateway = nicIpEntry->gateway;
            }
            else
            {
                enableDHCP4(ifaceId, asyncResp);
                messages::propertyMissing(asyncResp->res,
                                          pathString + "/Gateway");
                return;
            }

            /*if (gatewayValueAssigned)
            {
                if (activeGateway != gateway)
                {
                    // A NIC can only have a single active gateway value.
                    // If any gateway in the array of static addresses
                    // mismatch the PATCH is in error.
                    enableDHCP4(ifaceId, asyncResp);
                    std::string arg1 = pathString + "/Gateway";
                    std::string arg2 = activePath + "/Gateway";
                    messages::propertyValueConflict(asyncResp->res, arg1, arg2);
                    return;
                }
            }
            else
            {
                // Capture the very first gateway value from the incoming
                // JSON record and use it at the default gateway.
                updateIPv4DefaultGateway(ifaceId, *gateway, asyncResp);
                activeGateway = *gateway;
                activePath = pathString;
                gatewayValueAssigned = true;
            }*/

            if (nicIpEntry != ipv4Data.cend())
            {
                deleteAndCreateIPAddress(IpVersion::IpV4, ifaceId,
                                         nicIpEntry->id, prefixLength, *address,
                                         *gateway, asyncResp);
                nicIpEntry =
                    getNextStaticIpEntry(++nicIpEntry, ipv4Data.cend());
                preserveGateway = true;
            }
            else
            {
                createIPv4(ifaceId, prefixLength, *gateway, *address,
                           asyncResp);
                preserveGateway = true;
            }
            entryIdx++;
        }
        else
        {
            // Received {}, do not modify this address
            if (nicIpEntry != ipv4Data.cend())
            {
                nicIpEntry =
                    getNextStaticIpEntry(++nicIpEntry, ipv4Data.cend());
                preserveGateway = true;
                entryIdx++;
            }
            else
            {
                // Requested a DO NOT MODIFY action on an entry not assigned
                // to the NIC
                messages::propertyValueFormatError(asyncResp->res, *obj,
                                                   pathString);
                return;
            }
        }
    }
}

inline void handleStaticNameServersPatch(
    const std::string& ifaceId,
    const std::vector<std::string>& updatedStaticNameServers,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    setDbusProperty(
        asyncResp, "StaticNameServers", "xyz.openbmc_project.Network",
        sdbusplus::message::object_path("/xyz/openbmc_project/network") /
            ifaceId,
        "xyz.openbmc_project.Network.EthernetInterface", "StaticNameServers",
        updatedStaticNameServers);
}

inline void handleIPv6StaticAddressesPatch(
    const std::string& ifaceId,
    std::vector<std::variant<nlohmann::json::object_t, std::nullptr_t>>& input,
    const std::vector<IPv6AddressData>& ipv6Data, bool /*ipv6AcceptRA*/,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    std::vector<IPv6AddressData>::const_iterator nicIpv6Entry =
        getNextStaticIpEntry(ipv6Data.cbegin(), ipv6Data.cend());
    for (std::variant<nlohmann::json::object_t, std::nullptr_t>& thisJson :
         input)
    {
        if (auto* obj = std::get_if<nlohmann::json::object_t>(&thisJson))
        {
            if (obj->empty())
            {
                if (nicIpv6Entry != ipv6Data.cend())
                {
                    const IPv6AddressData& addressData = *nicIpv6Entry;
                    (*obj)["Address"] = addressData.address;
                    (*obj)["PrefixLength"] = addressData.prefixLength;
                }
            }
        }
        nicIpv6Entry = getNextStaticIpEntry(++nicIpv6Entry, ipv6Data.cend());
    }
    nicIpv6Entry = getNextStaticIpEntry(ipv6Data.cbegin(), ipv6Data.cend());
    size_t entryIdx = 1;
    std::vector<IPv6AddressData>::const_iterator nicIpEntry =
        getNextStaticIpEntry(ipv6Data.cbegin(), ipv6Data.cend());
    totalOperations = 0;
    completedOperations = 0;
    bool hasError = false;
    // Capture completedOperations by reference
    auto completionHandler = [asyncResp, &hasError](bool success) 
    {
        if (!success)
        {
            hasError = true;
        }
        else
        {
            completedOperations++; 
        }
        if (completedOperations == totalOperations && !hasError)
        {
            messages::success(asyncResp->res);
        }
    };
    for (std::variant<nlohmann::json::object_t, std::nullptr_t>& thisJson :
         input)
    {
        std::string pathString =
            "IPv6StaticAddresses/" + std::to_string(entryIdx);
        nlohmann::json::object_t* obj =
            std::get_if<nlohmann::json::object_t>(&thisJson);
        if (obj != nullptr && !obj->empty())
        {
            std::optional<std::string> address;
            std::optional<uint8_t> prefixLength;
            nlohmann::json::object_t thisJsonCopy = *obj;
            if (!json_util::readJsonObject( //
                    thisJsonCopy, asyncResp->res, //
                    "Address", address, //
                    "PrefixLength", prefixLength //
                    ))
            {
                return;
            }

            // Find the address and prefixLength values. Any values that are
            // not explicitly provided are assumed to be unmodified from the
            // current state of the interface. Merge existing state into the
            // current request.
            if (!address)
            {
                address = nicIpEntry->address;
            }

            if (!prefixLength)
            {
                prefixLength = nicIpEntry->prefixLength;
            }
            if (nicIpEntry != ipv6Data.end())
            {
                while (nicIpEntry != ipv6Data.cend())
                {
                    deleteIPAddress(ifaceId, nicIpEntry->id, asyncResp);
                    nicIpEntry =
                        getNextStaticIpEntry(++nicIpEntry, ipv6Data.cend());
                }
                totalOperations ++;
                createIPv6(ifaceId, *prefixLength, *address, asyncResp, completionHandler);
            }
            else
            {
                totalOperations ++;
                createIPv6(ifaceId, *prefixLength, *address, asyncResp, completionHandler);
            }
            entryIdx++;
        }
        else
        {
            if (obj == nullptr && nicIpEntry != ipv6Data.cend())
            {
                deleteIPAddress(ifaceId, nicIpEntry->id, asyncResp);
                nicIpEntry =
                    getNextStaticIpEntry(++nicIpEntry, ipv6Data.cend());
            }
            entryIdx++;
        }
        nicIpv6Entry = getNextStaticIpEntry(++nicIpv6Entry, ipv6Data.cend());
    }
}

inline std::string extractParentInterfaceName(const std::string& ifaceId)
{
    std::size_t pos = ifaceId.find('_');
    return ifaceId.substr(0, pos);
}

inline void parseInterfaceData(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& ifaceId, const EthernetInterfaceData& ethData,
    const std::vector<IPv4AddressData>& ipv4Data,
    const std::vector<IPv6AddressData>& ipv6Data,
    const std::vector<StaticGatewayData>& ipv6GatewayData)
{
    nlohmann::json& jsonResponse = asyncResp->res.jsonValue;
    jsonResponse["Id"] = ifaceId;
    jsonResponse["@odata.id"] =
        boost::urls::format("/redfish/v1/Managers/{}/EthernetInterfaces/{}",
                            BMCWEB_REDFISH_MANAGER_URI_NAME, ifaceId);
    jsonResponse["InterfaceEnabled"] = ethData.nicEnabled;

    if (ethData.nicEnabled)
    {
        jsonResponse["LinkStatus"] =
            ethData.linkUp ? ethernet_interface::LinkStatus::LinkUp
                           : ethernet_interface::LinkStatus::LinkDown;
        jsonResponse["Status"]["State"] = resource::State::Enabled;
    
        jsonResponse["LinkStatus"] = ethernet_interface::LinkStatus::NoLink;
        jsonResponse["Status"]["State"] = resource::State::Disabled;

        jsonResponse["SpeedMbps"] = ethData.speed;
        jsonResponse["MTUSize"] = ethData.mtuSize;
        if (ethData.macAddress)
        {
            jsonResponse["MACAddress"] = *ethData.macAddress;
        }
        jsonResponse["DHCPv4"]["DHCPEnabled"] =
            translateDhcpEnabledToBool(ethData.dhcpEnabled, true);
        jsonResponse["DHCPv4"]["UseNTPServers"] = ethData.ntpv4Enabled;
        jsonResponse["DHCPv4"]["UseDNSServers"] = ethData.dnsv4Enabled;
        jsonResponse["DHCPv4"]["UseDomainName"] = ethData.domainv4Enabled;
        // jsonResponse["DHCPv6"]["OperatingMode"] =
        //     translateDhcpEnabledToBool(ethData.dhcpEnabled, false) ? "Enabled"
        //                                                            : "Disabled";
        std::string dhcpv6OperatingMode =
            translateDhcpEnabledToBool(ethData.dhcpEnabled, false)
                ? "Enabled"
                : "Disabled";
        jsonResponse["DHCPv6"]["OperatingMode"] = dhcpv6OperatingMode;
        jsonResponse["DHCPv6"]["UseNTPServers"] = ethData.ntpv6Enabled;
        jsonResponse["DHCPv6"]["UseDNSServers"] = ethData.dnsv6Enabled;
        jsonResponse["DHCPv6"]["UseDomainName"] = ethData.domainv6Enabled;
        jsonResponse["StatelessAddressAutoConfig"]["IPv6AutoConfigEnabled"] =
            ethData.ipv6AcceptRa;

        if (!ethData.hostName.empty())
        {
            jsonResponse["HostName"] = ethData.hostName;

            // When domain name is empty then it means, that it is a network
            // without domain names, and the host name itself must be treated as
            // FQDN
            std::string fqdn = ethData.hostName;
            if (!ethData.domainnames.empty())
            {
                fqdn += "." + ethData.domainnames[0];
            }
            jsonResponse["FQDN"] = fqdn;
        }

        if (ethData.vlanId)
        {
            jsonResponse["EthernetInterfaceType"] =
                ethernet_interface::EthernetDeviceType::Virtual;
            jsonResponse["VLAN"]["VLANEnable"] = true;
            jsonResponse["VLAN"]["VLANId"] = *ethData.vlanId;
            jsonResponse["VLAN"]["VLANPriority"] = *ethData.vlanPriority;
            jsonResponse["VLAN"]["Tagged"] = true;

            nlohmann::json::array_t relatedInterfaces;
            nlohmann::json& parentInterface = relatedInterfaces.emplace_back();
            parentInterface["@odata.id"] =
                boost::urls::format("/redfish/v1/Managers/{}/EthernetInterfaces/{}",
                                    BMCWEB_REDFISH_MANAGER_URI_NAME,
                                    extractParentInterfaceName(ifaceId));
            jsonResponse["Links"]["RelatedInterfaces"] =
                std::move(relatedInterfaces);
        }
        else
        {
            jsonResponse["EthernetInterfaceType"] =
                ethernet_interface::EthernetDeviceType::Physical;
        }

        jsonResponse["NameServers"] = ethData.nameServers;
        jsonResponse["StaticNameServers"] = ethData.staticNameServers;

        nlohmann::json& ipv4Array = jsonResponse["IPv4Addresses"];
        nlohmann::json& ipv4StaticArray = jsonResponse["IPv4StaticAddresses"];
        ipv4Array = nlohmann::json::array();
        ipv4StaticArray = nlohmann::json::array();
        for (const auto& ipv4Config : ipv4Data)
        {
            std::string gatewayStr = ipv4Config.gateway;
            if (gatewayStr.empty())
            {
                gatewayStr = "0.0.0.0";
            }
            nlohmann::json::object_t ipv4;
            ipv4["AddressOrigin"] = ipv4Config.origin;
            ipv4["SubnetMask"] = ipv4Config.netmask;
            ipv4["Address"] = ipv4Config.address;
            ipv4["Gateway"] = gatewayStr;

            if (ipv4Config.origin == "Static")
            {
                ipv4StaticArray.push_back(ipv4);
            }

            ipv4Array.emplace_back(std::move(ipv4));
        }

        std::string ipv6GatewayStr = ethData.ipv6DefaultGateway;
        if (ipv6GatewayStr.empty())
        {
            jsonResponse["IPv6DefaultGateway"] = nullptr;
        }
        else
        {
            jsonResponse["IPv6DefaultGateway"] = ipv6GatewayStr;
        }

        nlohmann::json::array_t ipv6StaticGatewayArray;
        for (const auto& ipv6GatewayConfig : ipv6GatewayData)
        {
            nlohmann::json::object_t ipv6Gateway;
            ipv6Gateway["Address"] = ipv6GatewayConfig.gateway;
            ipv6StaticGatewayArray.emplace_back(std::move(ipv6Gateway));
        }
        // jsonResponse["IPv6StaticDefaultGateways"] =
        //     std::move(ipv6StaticGatewayArray);
        if (dhcpv6OperatingMode == "Disabled")
        {
            if (ipv6GatewayStr.empty())
            {
                jsonResponse["IPv6StaticDefaultGateways"] = 
                    std::move(ipv6StaticGatewayArray);;
            }
            else
            {
                nlohmann::json::object_t ipv6Gatewayobject;
                ipv6Gatewayobject["Address"] = std::move(ipv6GatewayStr);

                ipv6StaticGatewayArray.emplace_back(std::move(ipv6Gatewayobject));
                jsonResponse["IPv6StaticDefaultGateways"] =
                    std::move(ipv6StaticGatewayArray);
            }
        }
        else
        {
            jsonResponse["IPv6StaticDefaultGateways"] =
                std::move(ipv6StaticGatewayArray);
        }

        nlohmann::json& ipv6Array = jsonResponse["IPv6Addresses"];
        nlohmann::json& ipv6StaticArray = jsonResponse["IPv6StaticAddresses"];
        ipv6Array = nlohmann::json::array();
        ipv6StaticArray = nlohmann::json::array();
        nlohmann::json& ipv6AddrPolicyTable =
            jsonResponse["IPv6AddressPolicyTable"];
        ipv6AddrPolicyTable = nlohmann::json::array();
        for (const auto& ipv6Config : ipv6Data)
        {
            nlohmann::json::object_t ipv6;
            ipv6["Address"] = ipv6Config.address;
            ipv6["PrefixLength"] = ipv6Config.prefixLength;
            ipv6["AddressOrigin"] = ipv6Config.origin;

            ipv6Array.emplace_back(std::move(ipv6));
            if (ipv6Config.origin == "Static")
            {
                nlohmann::json::object_t ipv6Static;
                ipv6Static["Address"] = ipv6Config.address;
                ipv6Static["PrefixLength"] = ipv6Config.prefixLength;
                ipv6StaticArray.emplace_back(std::move(ipv6Static));
            }
        }
    }
    else
    {
        jsonResponse["LinkStatus"] = ethernet_interface::LinkStatus::NoLink;
        jsonResponse["Status"]["State"] = resource::State::Disabled;
        jsonResponse["IPv4Addresses"] = nlohmann::json::array();
        jsonResponse["IPv4StaticAddresses"] = nlohmann::json::array();
        jsonResponse["IPv6AddressPolicyTable"] = nlohmann::json::array();
        jsonResponse["IPv6Addresses"] = nlohmann::json::array();
        jsonResponse["IPv6StaticAddresses"] = nlohmann::json::array();
        jsonResponse["IPv6StaticDefaultGateways"] = nlohmann::json::array();
        jsonResponse["NameServers"] = nlohmann::json::array();
        jsonResponse["StaticNameServers"] = nlohmann::json::array();
    }
}

inline nlohmann::json::array_t convertToJSONArray(
    const std::optional<std::vector<
        std::variant<nlohmann::json::object_t, std::nullptr_t>>>& addresses)
{
    nlohmann::json::array_t jsonArray;

    if (addresses)
    {
        for (const auto& address : *addresses)
        {
            if (std::holds_alternative<nlohmann::json::object_t>(address))
            {
                jsonArray.push_back(
                    std::get<nlohmann::json::object_t>(address));
            }
            else if (std::holds_alternative<std::nullptr_t>(address))
            {
                // Handle nullptr_t case if necessary
                std::cout << "Address is null" << std::endl;
            }
        }
    }

    return jsonArray;
}

inline void afterDelete(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                        const std::string& ifaceId,
                        const boost::system::error_code& ec,
                        const sdbusplus::message_t& m)
{
    if (!ec)
    {
        return;
    }
    const sd_bus_error* dbusError = m.get_error();
    if (dbusError == nullptr)
    {
        messages::internalError(asyncResp->res);
        return;
    }
    BMCWEB_LOG_DEBUG("DBus error: {}", dbusError->name);

    if (std::string_view("org.freedesktop.DBus.Error.UnknownObject") ==
        dbusError->name)
    {
        messages::resourceNotFound(asyncResp->res, "EthernetInterface",
                                   ifaceId);
        return;
    }
    if (std::string_view("org.freedesktop.DBus.Error.UnknownMethod") ==
        dbusError->name)
    {
        messages::resourceCannotBeDeleted(asyncResp->res);
        return;
    }
    messages::internalError(asyncResp->res);
}

inline bool
    validateipv6AddressJson(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                            std::vector<std::variant<nlohmann::json::object_t, std::nullptr_t>>& input,
                            const std::vector<IPv6AddressData>& ipv6Data)
{
    size_t entryIdx = 1;
    std::vector<IPv6AddressData>::const_iterator nicIpEntry =
        getNextStaticIpEntry(ipv6Data.cbegin(), ipv6Data.cend());
    std::set<std::string> patchAddresses;

    if (input.empty())
    {
        messages::propertyValueTypeError(asyncResp->res, "[]",
                                         "IPv6StaticAddresses");
        return false;
    }
    if (input.size() > 16)
    {
        messages::arraySizeTooLong(asyncResp->res, "IPv6StaticAddresses", 16);
        asyncResp->res.result(boost::beast::http::status::bad_request);
        return false;
    }

    for (std::variant<nlohmann::json::object_t, std::nullptr_t>& thisJson : input)
    {
        std::string pathString = "IPv6StaticAddresses/" + std::to_string(entryIdx);
        nlohmann::json::object_t* obj = std::get_if<nlohmann::json::object_t>(&thisJson);

        if (obj != nullptr && !obj->empty())
        {
            std::optional<std::string> address;
            std::optional<uint8_t> prefixLength;
            nlohmann::json::object_t thisJsonCopy = *obj;
            if (!json_util::readJsonObject( //
                    thisJsonCopy, asyncResp->res, //
                    "Address", address, //
                    "PrefixLength", prefixLength //
                    ))
            {
                messages::propertyValueFormatError(asyncResp->res, thisJsonCopy,
                    pathString);
                return false;
            }
            if (prefixLength && prefixLength == 0)
            {
                messages::propertyValueFormatError(
                    asyncResp->res, "0", pathString + "/PrefixLength");
                return false;
            }
            if (!address)
            {
                if (nicIpEntry == ipv6Data.end())
                {
                    messages::propertyMissing(asyncResp->res,
                                              pathString + "/Address");
                    return false;
                }
                address = nicIpEntry->address;
            }
            if (!prefixLength)
            {
                if (nicIpEntry == ipv6Data.end())
                {
                    messages::propertyMissing(asyncResp->res,
                                              pathString + "/PrefixLength");
                    return false;
                }
                prefixLength = nicIpEntry->prefixLength;
            }

            if (address)
            {
                const std::string& ipAddress = *address;
                if (!(ip_util::validateIPv6address(ipAddress,
                                                ip_util::Type::IP6_ADDRESS)))
                {
                    messages::invalidip(asyncResp->res, "Address", ipAddress);
                    return false;
                }

                // AddressDuplicatedInRequest: Check for address
                if (patchAddresses.find(ipAddress)  != patchAddresses.end())
                {
                    messages::propertyValueIncorrect(asyncResp->res, "Address", ipAddress);
                    return false;
                }
                patchAddresses.insert(ipAddress);
            }
        }
        else
        {
            if (nicIpEntry == ipv6Data.end())
            {
                if (obj == nullptr)
                {
                    messages::resourceCannotBeDeleted(asyncResp->res);
                    asyncResp->res.result(boost::beast::http::status::bad_request);
                    return false;
                }
                messages::propertyValueFormatError(asyncResp->res, *obj,
                                                   pathString);
                return false;
            }
        }
        nicIpEntry = getNextStaticIpEntry(++nicIpEntry, ipv6Data.cend());

        //[[maybe_unused]] uint8_t prefix = prefixLength.value_or(0);
    }

    return true;
}

inline void
    handleVlanPriorityPatch(const std::string& ifaceId, uint32_t vlanPriority,
                            const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    sdbusplus::message::object_path objPath("/xyz/openbmc_project/network");
    objPath /= ifaceId;

    setDbusProperty(asyncResp, "VLANPriority", "xyz.openbmc_project.Network",
                    objPath, "xyz.openbmc_project.Network.VLAN", "Priority",
                    vlanPriority);
}

inline void afterVlanCreate(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& parentInterfaceUri, const std::string& vlanInterface,
    const uint32_t vlanPriorityVal, const uint32_t vlanId,
    const boost::system::error_code& ec, const sdbusplus::message_t& m

)
{
    if (ec)
    {
        const sd_bus_error* dbusError = m.get_error();
        if (dbusError == nullptr)
        {
            messages::internalError(asyncResp->res);
            return;
        }
        BMCWEB_LOG_DEBUG("DBus error: {}", dbusError->name);

        if (std::string_view(
                "xyz.openbmc_project.Common.Error.ResourceNotFound") ==
            dbusError->name)
        {
            messages::propertyValueNotInList(
                asyncResp->res, parentInterfaceUri,
                "Links/RelatedInterfaces/0/@odata.id");
            return;
        }
        if (std::string_view(
                "xyz.openbmc_project.Common.Error.InvalidArgument") ==
            dbusError->name)
        {
            // messages::resourceAlreadyExists(asyncResp->res,
            // "EthernetInterface",
            //                                 "Id", vlanInterface);
            messages::propertyValueIncorrect(asyncResp->res, "VLANId",
                                             std::to_string(vlanId));
            return;
        }
        if (std::string_view("xyz.openbmc_project.Common.Error.NotAllowed") ==
            dbusError->name)
        {
            messages::resourceCreationConflict(
                asyncResp->res,
                boost::urls::url(
                    "/redfish/v1/Managers/bmc/EthernetInterfaces"));
            return;
        }
        messages::internalError(asyncResp->res);
        return;
    }

    handleVlanPriorityPatch(vlanInterface, vlanPriorityVal, asyncResp);
    const boost::urls::url vlanInterfaceUri =
        boost::urls::format("/redfish/v1/Managers/{}/EthernetInterfaces/{}",
                            BMCWEB_REDFISH_MANAGER_URI_NAME, vlanInterface);
    asyncResp->res.addHeader("Location", vlanInterfaceUri.buffer());
}

inline bool isIfaceIdusb0(const std::string& ifaceId,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (ifaceId == "usb0")
    {
        BMCWEB_LOG_INFO("since usb0 interface is static by default, DHCPEnable "
                        "modification is not allowed");
        messages::actionNotSupported(asyncResp->res,
                                     "DHCPEnable in USB0 static");
        return true;
    }
    return false;
}

inline IPType checkIPTypes(const std::vector<std::string>& ipAddresses)
{
    bool hasIPv4 = false;
    bool hasIPv6 = false;

    for (const auto& ip : ipAddresses)
    {
        boost::system::error_code ec;
        boost::asio::ip::address addr = boost::asio::ip::make_address(ip, ec);

        if (ec)
        {
            return IPType::Invalid;
        }

        if (addr.is_v4() && addr.to_v4().to_string() == "0.0.0.0")
        {
            return IPType::Invalid;
        }
        else if (addr.is_v4())
        {
            hasIPv4 = true;
        }

        if (addr.is_v6() && addr.to_v6().to_string() == "::")
        {
            return IPType::Invalid;
        }
        else if (addr.is_v6())
        {
            hasIPv6 = true;
        }

        if (hasIPv4 && hasIPv6)
        {
            return IPType::Both;
        }
    }

    if (hasIPv4)
    {
        return IPType::IPv4;
    }

    if (hasIPv6)
    {
        return IPType::IPv6;
    }
    return IPType::None;
}

inline bool validateVlanPriority(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                          uint32_t vlanPriority)
{
    if (vlanPriority > MAX_VLANPRIORITY)
    {
        std::string priority = std::to_string(vlanPriority);
        std::string_view priorityview(priority);
        messages::propertyValueOutOfRange(asyncResp->res, priorityview,
                                          "VLANPriority");
        return false;
    }
    return true;
}

inline void handleEthernetInterfaceInstanceGet(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& managerId, const std::string& ifaceId)
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

    getEthernetIfaceData(
        ifaceId,
        [asyncResp,
         ifaceId](const bool& success, const EthernetInterfaceData& ethData,
                  const std::vector<IPv4AddressData>& ipv4Data,
                  const std::vector<IPv6AddressData>& ipv6Data,
                  const std::vector<StaticGatewayData>& ipv6GatewayData) {
            if (!success)
            {
                // TODO(Pawel)consider distinguish between non
                // existing object, and other errors
                messages::resourceNotFound(asyncResp->res, "EthernetInterface",
                                           ifaceId);
                return;
            }

            asyncResp->res.jsonValue["@odata.type"] = json_util::odataType("EthernetInterface");
            asyncResp->res.jsonValue["Name"] = "Manager Ethernet Interface";
            asyncResp->res.jsonValue["Description"] =
                "Management Network Interface";

            parseInterfaceData(asyncResp, ifaceId, ethData, ipv4Data, ipv6Data,
                               ipv6GatewayData);
        });
}

inline void handleEthernetInterfaceInstanceDelete(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& managerId, const std::string& ifaceId)
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

    crow::connections::systemBus->async_method_call(
        [asyncResp, ifaceId](const boost::system::error_code& ec,
                             const sdbusplus::message_t& m) {
            afterDelete(asyncResp, ifaceId, ec, m);
        },
        "xyz.openbmc_project.Network",
        std::string("/xyz/openbmc_project/network/") + ifaceId,
        "xyz.openbmc_project.Object.Delete", "Delete");
}

inline void requestEthernetInterfacesRoutes(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Managers/<str>/EthernetInterfaces/")
        .privileges(redfish::privileges::getEthernetInterfaceCollection)
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& managerId) {
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }

                if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
                {
                    messages::resourceNotFound(asyncResp->res, "Manager",
                                               managerId);
                    return;
                }

                asyncResp->res.jsonValue["@odata.type"] =
                    "#EthernetInterfaceCollection.EthernetInterfaceCollection";
                asyncResp->res.jsonValue["@odata.id"] = boost::urls::format(
                    "/redfish/v1/Managers/{}/EthernetInterfaces",
                    BMCWEB_REDFISH_MANAGER_URI_NAME);
                asyncResp->res.jsonValue["Name"] =
                    "Ethernet Network Interface Collection";
                asyncResp->res.jsonValue["Description"] =
                    "Collection of EthernetInterfaces for this Manager";

                // Get eth interface list, and call the below callback for JSON
                // preparation
                getEthernetIfaceList(
                    [asyncResp](const bool& success,
                                const std::vector<std::string>& ifaceList) {
                        if (!success)
                        {
                            messages::internalError(asyncResp->res);
                            return;
                        }

                        nlohmann::json& ifaceArray =
                            asyncResp->res.jsonValue["Members"];
                        ifaceArray = nlohmann::json::array();
                        for (const std::string& ifaceItem : ifaceList)
                        {
                            nlohmann::json::object_t iface;
                            iface["@odata.id"] = boost::urls::format(
                                "/redfish/v1/Managers/{}/EthernetInterfaces/{}",
                                BMCWEB_REDFISH_MANAGER_URI_NAME, ifaceItem);
                            ifaceArray.push_back(std::move(iface));
                        }

                        asyncResp->res.jsonValue["Members@odata.count"] =
                            ifaceArray.size();
                        asyncResp->res.jsonValue["@odata.id"] =
                            boost::urls::format(
                                "/redfish/v1/Managers/{}/EthernetInterfaces",
                                BMCWEB_REDFISH_MANAGER_URI_NAME);
                    });
            });

    BMCWEB_ROUTE(app, "/redfish/v1/Managers/<str>/EthernetInterfaces/")
        .privileges(redfish::privileges::postEthernetInterfaceCollection)
        .methods(boost::beast::http::verb::post)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& managerId) {
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }

                if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
                {
                    messages::resourceNotFound(asyncResp->res, "Manager",
                                               managerId);
                    return;
                }

                bool vlanEnable = false;
                uint32_t vlanId = 0;
                std::optional<uint32_t> vlanPriority;

                std::vector<nlohmann::json::object_t> relatedInterfaces;

                if (!json_util::readJsonPatch( //
                        req, asyncResp->res, //
                        "VLAN/VLANEnable", vlanEnable, //
                        "VLAN/VLANId", vlanId, //
                        "VLAN/VLANPriority", vlanPriority, //
                        "Links/RelatedInterfaces", relatedInterfaces //
                        ))
                {
                    return;
                }

                if (relatedInterfaces.size() != 1)
                {
                    messages::arraySizeTooLong(asyncResp->res,
                                               "Links/RelatedInterfaces",
                                               relatedInterfaces.size());
                    return;
                }

                std::string parentInterfaceUri;
                if (!json_util::readJsonObject( //
                        relatedInterfaces[0], asyncResp->res, //
                        "@odata.id", parentInterfaceUri //
                        ))
                {
                    messages::propertyMissing(
                        asyncResp->res, "Links/RelatedInterfaces/0/@odata.id");
                    return;
                }
                BMCWEB_LOG_INFO("Parent Interface URI: {}", parentInterfaceUri);

                boost::system::result<boost::urls::url_view> parsedUri =
                    boost::urls::parse_relative_ref(parentInterfaceUri);
                if (!parsedUri)
                {
                    messages::propertyValueFormatError(
                        asyncResp->res, parentInterfaceUri,
                        "Links/RelatedInterfaces/0/@odata.id");
                    return;
                }

                std::string parentInterface;
                if (!crow::utility::readUrlSegments(
                        *parsedUri, "redfish", "v1", "Managers", "bmc",
                        "EthernetInterfaces", std::ref(parentInterface)))
                {
                    messages::propertyValueNotInList(
                        asyncResp->res, parentInterfaceUri,
                        "Links/RelatedInterfaces/0/@odata.id");
                    return;
                }

                if (!vlanEnable)
                {
                    // In OpenBMC implementation, VLANEnable cannot be false on
                    // create
                    messages::propertyValueIncorrect(
                        asyncResp->res, "VLAN/VLANEnable", "false");
                    return;
                }

                uint32_t vlanPriorityVal = vlanPriority.value_or(0);

                std::string vlanInterface =
                    parentInterface + "_" + std::to_string(vlanId);

                if (validateVlanPriority(asyncResp, vlanPriorityVal))
                {
                    crow::connections::systemBus->async_method_call(
                        [asyncResp, parentInterfaceUri, vlanInterface, vlanId,
                         vlanPriorityVal](const boost::system::error_code& ec,
                                          const sdbusplus::message_t& m) {
                            afterVlanCreate(asyncResp, parentInterfaceUri,
                                            vlanInterface, vlanPriorityVal,
                                            vlanId, ec, m);
                        },
                        "xyz.openbmc_project.Network",
                        "/xyz/openbmc_project/network",
                        "xyz.openbmc_project.Network.VLAN.Create", "VLAN",
                        parentInterface, vlanId);
                }
            });

    BMCWEB_ROUTE(app, "/redfish/v1/Managers/<str>/EthernetInterfaces/<str>/")
        .privileges(redfish::privileges::getEthernetInterface)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleEthernetInterfaceInstanceGet, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Managers/<str>/EthernetInterfaces/<str>/")
        .privileges(
            redfish::privileges::patchSubOverManagerEthernetInterfaceCollection)
        .methods(
            boost::beast::http::verb::
                patch)([&app](
                           const crow::Request& req,
                           const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                           const std::string& managerId,
                           const std::string& ifaceId) {
            if (!redfish::setUpRedfishRoute(app, req, asyncResp))
            {
                return;
            }

            if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
            {
                messages::resourceNotFound(asyncResp->res, "Manager",
                                           managerId);
                return;
            }

            std::optional<std::string> hostname;
            std::optional<std::string> fqdn;
            std::optional<std::string> macAddress;
            std::optional<std::string> ipv6DefaultGateway;
            std::optional<std::vector<
                std::variant<nlohmann::json::object_t, std::nullptr_t>>>
                ipv4StaticAddresses;
            std::optional<std::vector<
                std::variant<nlohmann::json::object_t, std::nullptr_t>>>
                ipv6StaticAddresses;
            std::optional<std::vector<
                std::variant<nlohmann::json::object_t, std::nullptr_t>>>
                ipv6StaticDefaultGateways;
            std::optional<std::vector<std::string>> staticNameServers;
            std::optional<bool> ipv6AutoConfigEnabled;
            std::optional<bool> interfaceEnabled;
            std::optional<size_t> mtuSize;
            std::optional<uint32_t> vlanPriority;
            DHCPParameters v4dhcpParms;
            DHCPParameters v6dhcpParms;
            // clang-format off
        if (!json_util::readJsonPatch(req, asyncResp->res, //
                "DHCPv4/DHCPEnabled",   v4dhcpParms.dhcpv4Enabled, //
                "DHCPv4/UseDNSServers", v4dhcpParms.useDnsServers, //
                "DHCPv4/UseDomainName", v4dhcpParms.useDomainName, //
                "DHCPv4/UseNTPServers", v4dhcpParms.useNtpServers, //
                "DHCPv6/OperatingMode", v6dhcpParms.dhcpv6OperatingMode, //
                "DHCPv6/UseDNSServers", v6dhcpParms.useDnsServers, //
                "DHCPv6/UseDomainName", v6dhcpParms.useDomainName, //
                "DHCPv6/UseNTPServers", v6dhcpParms.useNtpServers, //
                "FQDN", fqdn, //
                "HostName", hostname, //
                "IPv4StaticAddresses", ipv4StaticAddresses, //
                "IPv6DefaultGateway", ipv6DefaultGateway, //
                "IPv6StaticAddresses", ipv6StaticAddresses, //
                "IPv6StaticDefaultGateways", ipv6StaticDefaultGateways, //
                "InterfaceEnabled", interfaceEnabled, //
                "MACAddress", macAddress, //
                "MTUSize", mtuSize, //
                "StatelessAddressAutoConfig/IPv6AutoConfigEnabled", ipv6AutoConfigEnabled, //
                "StaticNameServers", staticNameServers, //
                "VLAN/VLANPriority", vlanPriority //
                )
            )
        {
            return;
        }
            // clang-format on

            // Get single eth interface data, and call the below callback
            // for JSON preparation
            getEthernetIfaceData(
                ifaceId,
                [asyncResp, ifaceId, hostname = std::move(hostname),
                 fqdn = std::move(fqdn), macAddress = std::move(macAddress),
                 ipv4StaticAddresses = std::move(ipv4StaticAddresses),
                 ipv6DefaultGateway = std::move(ipv6DefaultGateway),
                 ipv6StaticAddresses = std::move(ipv6StaticAddresses),
                 ipv6StaticDefaultGateway =
                     std::move(ipv6StaticDefaultGateways),
                 staticNameServers = std::move(staticNameServers), mtuSize,
                 vlanPriority, ipv6AutoConfigEnabled,
                 v4dhcpParms = std::move(v4dhcpParms),
                 v6dhcpParms = std::move(v6dhcpParms), interfaceEnabled](
                    const bool success, const EthernetInterfaceData& ethData,
                    const std::vector<IPv4AddressData>& ipv4Data,
                    const std::vector<IPv6AddressData>& ipv6Data,
                    const std::vector<StaticGatewayData>&
                        ipv6GatewayData) mutable {
                    if (!success)
                    {
                        // ... otherwise return error
                        // TODO(Pawel)consider distinguish between non
                        // existing object, and other errors
                        messages::resourceNotFound(
                            asyncResp->res, "EthernetInterface", ifaceId);
                        return;
                    }

                    bool isNicEnabled = ethData.nicEnabled;

                    // Check for mixed attributes with interfaceEnabled
                    bool hasMixedAttributes =
                        (interfaceEnabled.has_value() &&
                         (hostname.has_value() || fqdn.has_value() ||
                          macAddress.has_value() ||
                          ipv6DefaultGateway.has_value() ||
                          ipv4StaticAddresses.has_value() ||
                          ipv6StaticAddresses.has_value() ||
                          ipv6StaticDefaultGateway.has_value() ||
                          staticNameServers.has_value() ||
                          ipv6AutoConfigEnabled.has_value() ||
                          mtuSize.has_value() ||
                          v4dhcpParms.dhcpv4Enabled.has_value() ||
                          v4dhcpParms.useDnsServers.has_value() ||
                          v4dhcpParms.useDomainName.has_value() ||
                          v4dhcpParms.useNtpServers.has_value() ||
                          v6dhcpParms.dhcpv6OperatingMode.has_value() ||
                          v6dhcpParms.useDnsServers.has_value() ||
                          v6dhcpParms.useDomainName.has_value() ||
                          v6dhcpParms.useNtpServers.has_value()));

                    if (hasMixedAttributes)
                    {
                        messages::propertyValueExternalConflict(
                            asyncResp->res, "InterfaceEnabled",
                            *interfaceEnabled);
                        return;
                    }

                    if (interfaceEnabled.has_value() && (!hasMixedAttributes))
                    {
                        handleInterfacePatch(ifaceId, interfaceEnabled, asyncResp);
                        isNicEnabled = *interfaceEnabled;
                    }
                    if (!isNicEnabled)
                    {
                        if (v4dhcpParms.dhcpv4Enabled ||
                            v4dhcpParms.useDnsServers ||
                            v4dhcpParms.useDomainName ||
                            v4dhcpParms.useNtpServers ||
                            v6dhcpParms.dhcpv6OperatingMode ||
                            v6dhcpParms.useDnsServers ||
                            v6dhcpParms.useDomainName ||
                            v4dhcpParms.useNtpServers || fqdn || hostname ||
                            ipv4StaticAddresses || ipv6DefaultGateway ||
                            ipv6StaticAddresses || macAddress || mtuSize ||
                            ipv6AutoConfigEnabled || staticNameServers)
                        {
                            messages::interfaceDisabled(asyncResp->res,
                                                        "InterfaceEnabled");
                            return;
                        }
                    }

                    bool ipv4AddressValid = true;
                    nlohmann::json::array_t IPv4Static;
                    nlohmann::json::array_t IPv6Static;
                    if (ipv4StaticAddresses) // IPv4StaticAddresses attribute is
                                             // present
                    {
                        IPv4Static = convertToJSONArray(*ipv4StaticAddresses);
                        if (!validateIPv4Json(asyncResp, IPv4Static))
                        {
                            // Invalid IPv4 address provided
                            ipv4AddressValid = false;
                        }
                    }
                    bool ipv6AddressValid = true;
                    if (ipv6StaticAddresses) // IPv6StaticAddresses attribute is
                                             // present
                    {
                        //IPv6Static = convertToJSONArray(*ipv6StaticAddresses);
                        if (!(validateipv6AddressJson(asyncResp, *ipv6StaticAddresses,ipv6Data)))
                        {
                            // Invalid IPv6 address provided
                            ipv6AddressValid = false;
                        }
                    }

                    bool ipv6AcceptRA;
                    if (ipv6AutoConfigEnabled.has_value())
                    {
                        ipv6AcceptRA = ipv6AutoConfigEnabled.value();
                    }
                    else
                    {
                        ipv6AcceptRA = ethData.ipv6AcceptRa;
                    }

                    bool staticAddrSetFlag = true;
                    bool dhcpPropCheckFlag = true;
                    bool ipv4Active = translateDhcpEnabledToBool(ethData.dhcpEnabled, true);
                    bool ipv6Active = translateDhcpEnabledToBool(ethData.dhcpEnabled, false);

                    if(ipv6Active == 1 && ipv6StaticAddresses && !v6dhcpParms.dhcpv6OperatingMode) // IPv6 is in DHCP Mode and IPv6StaticAddresses attribute is present but DHCPv6.OperatingMode attribute is not present 
                    {
                        dhcpPropCheckFlag = false;
                        messages::propertyMissing(asyncResp->res, "DHCPv6.OperatingMode");
                    }

                    if(ipv4Active == 1 && ipv4StaticAddresses && !v4dhcpParms.dhcpv4Enabled) // IPv4 is in DHCP Mode and IPv4StaticAddresses attribute is present but DHCPv4.DHCPEnabled attribute is not present 
                    {
                        dhcpPropCheckFlag = false;
                        messages::propertyMissing(asyncResp->res, "DHCPv4.DHCPEnabled");
                    }

                    if(v4dhcpParms.dhcpv4Enabled || v6dhcpParms.dhcpv6OperatingMode)
                    {
                        if (isIfaceIdusb0(ifaceId, asyncResp))
                        {
                            return;
                        }

                        if(v4dhcpParms.dhcpv4Enabled)
                        {
                            const bool v4Value = *v4dhcpParms.dhcpv4Enabled;
                            if (!v4Value) // DHCPv4.DHCPEnabled attribute is false
                            {
                                if (!ipv4StaticAddresses) // and IPv4StaticAddresses attribute is not present
                                {
                                    messages::propertyMissing(asyncResp->res, "IPv4StaticAddresses");
                                    dhcpPropCheckFlag = false;
                                }
                            }
                            else if(v4Value && ipv4StaticAddresses) // DHCPv4.DHCPEnabled attribute is true and IPv4StaticAddresses attribute is present
                            { 
                                messages::propertyValueConflict(asyncResp->res, "DHCPv4.DHCPEnabled","IPv4StaticAddresses");
                                dhcpPropCheckFlag = false;
                            }
                        }

                        if (v6dhcpParms.dhcpv6OperatingMode) // DHCPv6 -> OperatingMode is present
                        {
                            if ((*v6dhcpParms.dhcpv6OperatingMode == "Enabled") && ipv6StaticAddresses)
                            {
                                messages::propertyValueConflict(asyncResp->res, "DHCPv6.OperatingMode","IPv6StaticAddresses");
                                dhcpPropCheckFlag = false;
                            }
                            else if (*v6dhcpParms.dhcpv6OperatingMode == "Disabled")
                            {
                                if (!ipv6StaticAddresses) // and IPv6StaticAddresses attribute is not present
                                {
                                    messages::propertyMissing(asyncResp->res, "IPv6StaticAddresses");
                                    dhcpPropCheckFlag = false;
                                }
                            }
                            else if ((*v6dhcpParms.dhcpv6OperatingMode != "Enabled") && (*v6dhcpParms.dhcpv6OperatingMode != "Disabled"))
                            {
                                messages::propertyValueFormatError(asyncResp->res,
                                                    *v6dhcpParms.dhcpv6OperatingMode,
                                                    "OperatingMode");
                                dhcpPropCheckFlag = false;
                            }
                        }
                        
                        if(!dhcpPropCheckFlag) // Flag having false value indicates Validation Errors
                        {
                            return;
                        }
                        
                        if (ipv6AddressValid && dhcpPropCheckFlag) 
                        {
                            handleDHCPv4v6Patch(ifaceId, v4dhcpParms, v6dhcpParms,
                                            asyncResp);
                        }

                        if (ipv4AddressValid && dhcpPropCheckFlag)
                        {   
                            handleDHCPv4v6Patch(ifaceId, v4dhcpParms, v6dhcpParms,
                                            asyncResp);
                        }
                    }

                    if ((ipv4StaticAddresses || ipv6StaticAddresses) && dhcpPropCheckFlag)  
                    {
                        if (ipv4StaticAddresses && ipv6StaticAddresses)
                        {
                            staticAddrSetFlag = false;
                            if (ipv6AddressValid && ipv4AddressValid)
                            {
                                ipv6AcceptRA = false;
                            }

                            handleIPv6StaticAddressesPatch(
                                ifaceId, *ipv6StaticAddresses, ipv6Data, ipv6AcceptRA, asyncResp);

                            handleIPv4StaticPatch(ifaceId, *ipv4StaticAddresses, ipv4Data,
                                    asyncResp);
                        }

                        if (ipv4StaticAddresses && ipv4AddressValid)
                        {
                            if (staticAddrSetFlag)
                            {
                                handleIPv4StaticPatch(ifaceId, *ipv4StaticAddresses, ipv4Data,
                                    asyncResp);
                            }
                        }

                        if (ipv6StaticAddresses && ipv6AddressValid)
                        {
                            if (staticAddrSetFlag)
                            {
                                handleIPv6StaticAddressesPatch(
                                    ifaceId, *ipv6StaticAddresses, ipv6Data, ipv6AcceptRA, asyncResp);
                            }
                        }
                    }

                    bool isDnsv4Enabled = ethData.dnsv4Enabled;
                    bool isDnsv6Enabled = ethData.dnsv6Enabled;
                    
                    if(v4dhcpParms.useDnsServers || v4dhcpParms.useDomainName || v4dhcpParms.useNtpServers)
                    {
                        if (isIfaceIdusb0(ifaceId, asyncResp))
                        {
                            return;
                        }
                        if(v4dhcpParms.useDnsServers)
                        {
                            isDnsv4Enabled = *v4dhcpParms.useDnsServers;
                        }
    
                        handleDHCPPatch(ifaceId, ethData, v4dhcpParms, v6dhcpParms, asyncResp);
                    }

                    if (v6dhcpParms.useDnsServers || v6dhcpParms.useDomainName || v6dhcpParms.useNtpServers) 
                    {
                        if (isIfaceIdusb0(ifaceId, asyncResp))
                        {
                            return;
                        }

                        if(v6dhcpParms.useDnsServers)
                        {
                            isDnsv6Enabled = *v6dhcpParms.useDnsServers;
                        }

                        handleDHCPPatch(ifaceId, ethData, v4dhcpParms, v6dhcpParms, asyncResp);
                    }

                    bool FqdnHostnameValidate = true;
                    if (hostname && fqdn)
                    {
                        // handleHostnamePatch(*hostname, asyncResp);
                        FqdnHostnameValidate =
                            validateFqdnHostName(*hostname, *fqdn, asyncResp);
                        if (!FqdnHostnameValidate)
                        {
                            return;
                        }
                        else
                        {
                            handleFqdnPatch(ifaceId, *fqdn, asyncResp);
                        }
                    }
                    else
                    {
                        if (hostname)
                        {
                            handleHostnamePatch(*hostname, asyncResp);
                        }

                        if (fqdn)
                        {
                            handleFqdnPatch(ifaceId, *fqdn, asyncResp);
                        }
                    }

                    if (ipv6AutoConfigEnabled)
                    {
                        handleSLAACAutoConfigPatch(
                            ifaceId, *ipv6AutoConfigEnabled, asyncResp);
                    }

                    if (macAddress)
                    {
                        if (isIfaceIdusb0(ifaceId, asyncResp))
                        {
                            return;
                        }
                        handleMACAddressPatch(ifaceId, *macAddress, asyncResp);
                    }

                    if (staticNameServers)
                    {
                        if (staticNameServers->size() > 3)
                        {
                            messages::propertyValueOutOfRange(
                                asyncResp->res, staticNameServers.value(),
                                "StaticNameServers");
                            return;
                        }
                        IPType result = checkIPTypes(staticNameServers.value());

                        if (isDnsv4Enabled && result == redfish::IPType::IPv4)
                        {
                            messages::propertyValueConflict(
                                asyncResp->res, "StaticNameServers",
                                "DHCPv4.UseDNSServers");
                            return;
                        }
                        else if (isDnsv6Enabled &&
                                 result == redfish::IPType::IPv6)
                        {
                            messages::propertyValueConflict(
                                asyncResp->res, "StaticNameServers",
                                "DHCPv6.UseDNSServers");
                            return;
                        }
                        else if (result == redfish::IPType::Both)
                        {
                             if ( (isDnsv4Enabled && isDnsv6Enabled) )
                            {
                                messages::propertyValueConflict(asyncResp->res, "StaticNameServers",
                                    "DHCPv4.UseDNSServers/DHCPv6.UseDNSServers");
                                return;
                            }
                            else if ( isDnsv4Enabled && !isDnsv6Enabled )
                            {
                                messages::propertyValueConflict(asyncResp->res, "StaticNameServers",
                                "DHCPv4.UseDNSServers");
                                return;
                            }
                            else if (!isDnsv4Enabled && isDnsv6Enabled)
                            {
                                messages::propertyValueConflict(asyncResp->res, "StaticNameServers",
                                "DHCPv6.UseDNSServers");
                                return;
                            }
                        }
                        else if ((result == IPType::None || result == IPType::Invalid) && (staticNameServers->size() != 0))
                        {
                            for (const auto& ip : staticNameServers.value())
                    {
                        bool isIPv4 = redfish::ip_util::isValidIPv4Addr(ip, redfish::ip_util::Type::IP4_ADDRESS);
                        bool isIPv6 = redfish::ip_util::validateIPv6address(ip, redfish::ip_util::Type::IP6_ADDRESS);
                        if (!isIPv4 && !isIPv6)
                        {
                            messages::propertyValueFormatError(asyncResp->res,ip, "StaticNameServers");
                        }
                    }
                    asyncResp->res.result(boost::beast::http::status::bad_request);
                    return;
                        }
                        handleStaticNameServersPatch(
                            ifaceId, *staticNameServers, asyncResp);
                    }

                    if (ipv6DefaultGateway)
                    {
                        messages::propertyNotWritable(asyncResp->res,
                                                      "IPv6DefaultGateway");
                    }

                    if (ipv6StaticDefaultGateway)
                    {
                        handleIPv6DefaultGateway(ifaceId,
                                                 *ipv6StaticDefaultGateway,
                                                 ipv6GatewayData, asyncResp);
                    }

                    if (mtuSize)
                    {
                        handleMTUSizePatch(ifaceId, *mtuSize, asyncResp);
                    }

                    if (ethData.vlanId && vlanPriority &&
                        validateVlanPriority(asyncResp, *vlanPriority))
                    {
                        handleVlanPriorityPatch(ifaceId, *vlanPriority,
                                                asyncResp);
                    }
                });
        });

    BMCWEB_ROUTE(app, "/redfish/v1/Managers/<str>/EthernetInterfaces/<str>/")
        .privileges(redfish::privileges::deleteEthernetInterface)
        .methods(boost::beast::http::verb::delete_)(std::bind_front(
            handleEthernetInterfaceInstanceDelete, std::ref(app)));
}

} // namespace redfish
