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

#include <boost/system/error_code.hpp>
#include <boost/url/format.hpp>
#include <sdbusplus/asio/property.hpp>
#include <sdbusplus/unpack_properties.hpp>

#include <memory>
#include <string>
#include <string_view>

namespace redfish
{

inline std::string getProtocol(const std::string& snmpProtol)
{
    if (snmpProtol == "SNMPv1")
        return "v1";
    else if (snmpProtol == "SNMPv2c")
        return "v2c";
    else if (snmpProtol == "SNMPv3")
        return "v3";
    else
        return "";
}

inline void afterGetSnmpTrapClientdata(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const boost::system::error_code& ec,
    const dbus::utility::DBusPropertiesMap& propertiesList,
    const std::string& id)
{
    if (ec)
    {
        BMCWEB_LOG_ERROR("D-Bus response error on GetSubTree {}", ec);
        messages::internalError(asyncResp->res);
        return;
    }

    std::string address;
    std::string version;
    uint16_t port = 0;
    std::string user;

    bool success = sdbusplus::unpackPropertiesNoThrow(
        dbus_utils::UnpackErrorPrinter(), propertiesList, "Address", address,
        "Port", port, "Version", version, "User", user);

    if (!success)
    {
        messages::internalError(asyncResp->res);
        return;
    }
    std::shared_ptr<Subscription> subVal =
                    EventServiceManager::getInstance().getSubscription(id);
    if (version == "v3")
    {
        asyncResp->res.jsonValue["Destination"] =
            "snmp://" + user + "@" + address + ":" + std::to_string(port);
    }
    else 
    {
        asyncResp->res.jsonValue["Destination"] =
            "snmp://" + address + ":" + std::to_string(port);
        asyncResp->res.jsonValue["Oem"]["OpenBmc"]["@odata.type"] = json_util::odataType("OpenBMCEventDestination");
        asyncResp->res.jsonValue["Oem"]["OpenBmc"]["CommunityString"] = user;
    }
    asyncResp->res.jsonValue["Protocol"] = "SNMP" + version;
    asyncResp->res.jsonValue["Context"] = ((subVal != nullptr) && !subVal->userSub->customText.empty()) ? subVal->userSub->customText : "Event_Sub_" + id;
}

inline void
    getSnmpTrapClientdata(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                          const std::string& id, const std::string& objectPath)
{
    asyncResp->res.jsonValue["@odata.type"] = json_util::odataType("EventDestination");
    asyncResp->res.jsonValue["@odata.id"] =
        boost::urls::format("/redfish/v1/EventService/Subscriptions/{}", id);

    asyncResp->res.jsonValue["Id"] = id;
    asyncResp->res.jsonValue["Name"] = "Event Destination";

    asyncResp->res.jsonValue["SubscriptionType"] = event_destination::SubscriptionType::SNMPTrap;
    asyncResp->res.jsonValue["EventFormatType"] = event_destination::EventFormatType::Event;

    dbus::utility::getAllProperties(
        "xyz.openbmc_project.Network.SNMP", objectPath,
        "xyz.openbmc_project.Network.Client",
        [asyncResp, id](const boost::system::error_code& ec,
                    const dbus::utility::DBusPropertiesMap& properties) {
            afterGetSnmpTrapClientdata(asyncResp, ec, properties, id);
        });
}

inline void
    getSnmpTrapClient(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                      const std::string& id)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp, id](const boost::system::error_code& ec,
                        dbus::utility::ManagedObjectType& resp) {
        if (ec)
        {
            BMCWEB_LOG_ERROR("D-Bus response error on GetManagedObjects {}",
                             ec);
            messages::internalError(asyncResp->res);
            return;
        }

        for (const auto& objpath : resp)
        {
            sdbusplus::message::object_path path(objpath.first);
            const std::string snmpId = path.filename();
            if (snmpId.empty())
            {
                BMCWEB_LOG_ERROR("The SNMP client ID is wrong");
                messages::internalError(asyncResp->res);
                return;
            }
            const std::string subscriptionId = "snmp" + snmpId;
            if (id != subscriptionId)
            {
                continue;
            }
            getSnmpTrapClientdata(asyncResp, id, objpath.first);
            return;
        }

        messages::resourceNotFound(asyncResp->res, "Subscriptions", id);
        EventServiceManager::getInstance().deleteSubscription(id);
    },
        "xyz.openbmc_project.Network.SNMP",
        "/xyz/openbmc_project/network/snmp/manager",
        "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");
}

inline void
    setprotocolEnable(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, "xyz.openbmc_project.Snmp.Conf",
        "/xyz/openbmc_project/snmp/SnmpUtils", "xyz.openbmc_project.Snmp.SnmpUtils",
        "SnmpTrapStatus", true,
        [asyncResp](const boost::system::error_code& ec) {
        if (ec)
        {
            BMCWEB_LOG_DEBUG("Unable to set SNMPTrap");
            messages::internalError(asyncResp->res);
            return;
        }
        });
}

inline void afterSnmpClientCreate(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const boost::system::error_code& ec, const sdbusplus::message_t& msg,
    const std::string& host, const std::string& dbusSNMPid,
    const std::shared_ptr<Subscription>& subValue)

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
                return;
            }
            if (ec.value() != EBADR)
            {
                // SNMP not installed
                messages::propertyValueOutOfRange(
                    asyncResp->res, subValue->userSub->protocol, "Protocol");
                return;
            }
        }
        messages::internalError(asyncResp->res);
        return;
    }
    sdbusplus::message::object_path path(dbusSNMPid);
    const std::string snmpId = path.filename();
    if (snmpId.empty())
    {
        messages::internalError(asyncResp->res);
        return;
    }

    std::string subscriptionId = "snmp" + snmpId;

    EventServiceManager::getInstance().addPushSubscription(subValue,
                                                       subscriptionId);
    boost::urls::url uri = boost::urls::format(
        "/redfish/v1/EventService/Subscriptions/{}", subscriptionId);
    asyncResp->res.addHeader("Location", uri.buffer());
    messages::created(asyncResp->res);
}

inline void
    addSnmpTrapClient(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                      const std::string& host, uint16_t snmpTrapPort,
                      const std::string& protocol, const std::string& username,
                      const std::shared_ptr<Subscription>& subValue, const std::string& oemsnmpcommunitystring)

{
    if (protocol == "SNMPv3")
    {
        crow::connections::systemBus->async_method_call(
            [asyncResp, host, subValue](const boost::system::error_code& ec,
                                        const sdbusplus::message_t& msg,
                                        const std::string& dbusSNMPid) {
            afterSnmpClientCreate(asyncResp, ec, msg, host, dbusSNMPid, subValue);
            },
            "xyz.openbmc_project.Network.SNMP",
            "/xyz/openbmc_project/network/snmp/manager",
            "xyz.openbmc_project.Network.Client.Create", "Client", host,
            snmpTrapPort, getProtocol(protocol), username);
    }
    else
    {
        crow::connections::systemBus->async_method_call(
            [asyncResp, host, subValue](const boost::system::error_code& ec,
                                        const sdbusplus::message_t& msg,
                                        const std::string& dbusSNMPid) {
            afterSnmpClientCreate(asyncResp, ec, msg, host, dbusSNMPid, subValue);
            },
            "xyz.openbmc_project.Network.SNMP",
            "/xyz/openbmc_project/network/snmp/manager",
            "xyz.openbmc_project.Network.Client.Create", "Client", host,
            snmpTrapPort, getProtocol(protocol), oemsnmpcommunitystring);
    }
}

inline void
    getSnmpSubscriptionList(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                            const std::string& snmpId,
                            nlohmann::json& memberArray)
{
    const std::string subscriptionId = "snmp" + snmpId;

    nlohmann::json::object_t member;
    member["@odata.id"] = boost::urls::format(
        "/redfish/v1/EventService/Subscriptions/{}", subscriptionId);
    memberArray.push_back(std::move(member));

    asyncResp->res.jsonValue["Members@odata.count"] = memberArray.size();
}

inline void
    deleteSnmpTrapClient(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                         const std::string& param)
{
    std::string_view snmpTrapId = param;

    // Erase "snmp" in the request to find the corresponding
    // dbus snmp client id. For example, the snmpid in the
    // request is "snmp1", which will be "1" after being erased.
    snmpTrapId.remove_prefix(4);

    sdbusplus::message::object_path snmpPath =
        sdbusplus::message::object_path(
            "/xyz/openbmc_project/network/snmp/manager") /
        std::string(snmpTrapId);

    crow::connections::systemBus->async_method_call(
        [asyncResp, param](const boost::system::error_code& ec) {
        if (ec)
        {
            // The snmp trap id is incorrect
            if (ec.value() == EBADR)
            {
                messages::resourceNotFound(asyncResp->res, "Subscription",
                                           param);
                return;
            }
            messages::internalError(asyncResp->res);
            return;
        }
        messages::success(asyncResp->res);
    },
        "xyz.openbmc_project.Network.SNMP", static_cast<std::string>(snmpPath),
        "xyz.openbmc_project.Object.Delete", "Delete");
}

} // namespace redfish
