// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#pragma once

#include "app.hpp"
#include "generated/enums/resource.hpp"
#include "logging.hpp"
#include "query.hpp"
#include "registries/privilege_registry.hpp"
#include "utils/chassis_utils.hpp"

#include <boost/url/format.hpp>

#include <memory>
#include <optional>
#include <string>

namespace redfish
{

inline void
    getPSUMonitorProperties(std::shared_ptr<bmcweb::AsyncResp> asyncResp)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp](
            const boost::system::error_code ec2,
            const std::vector<std::pair<
                std::string, std::variant<uint8_t, uint16_t, std::string,
                                          std::vector<std::string>>>>&
                propertiesList) {
            if (ec2)
            {
                return;
            }
            for (const std::pair<std::string,
                                 std::variant<uint8_t, uint16_t, std::string,
                                              std::vector<std::string>>>&
                     property : propertiesList)
            {
                const std::string& propertyName = property.first;
                if ((propertyName == "AllocatedWatts") ||
                    (propertyName == "RequestedWatts"))
                {
                    const uint16_t* value =
                        std::get_if<uint16_t>(&property.second);
                    if (value != nullptr)
                    {
                        asyncResp->res.jsonValue["Allocation"][propertyName] =
                            *value;
                    }
                }
            }
        },
        "xyz.openbmc_project.Power.PSUMonitor",
        "/xyz/openbmc_project/inventory/system/powersupply",
        "org.freedesktop.DBus.Properties", "GetAll",
        "xyz.openbmc_project.PsuStatus");
}
inline void getCollectionOfPSUMembers(
    std::shared_ptr<bmcweb::AsyncResp> asyncResp,
    const boost::urls::url& collectionPath,
    std::span<const std::string_view> interfaces,
    const std::vector<std::pair<
        std::string, std::variant<uint8_t, std::string, bool>>>& propertiesList,
    const char* subtree = "/xyz/openbmc_project/inventory")
{
    dbus::utility::getSubTreePaths(
        subtree, 0, interfaces,
        [collectionPath, propertiesList, asyncResp](
            const boost::system::error_code& ec,
            const dbus::utility::MapperGetSubTreePathsResponse& objects) {
            if (ec)
            {
                // BMCWEB_LOG_DEBUG << "DBUS response error " << ec.value();
                messages::internalError(asyncResp->res);
                return;
            }
            nlohmann::json redundancyGroup;
            std::vector<std::string> pathNames;
            for (const auto& object : objects)
            {
                sdbusplus::message::object_path path(object);
                std::string leaf = path.filename();
                if (leaf.empty())
                {
                    continue;
                }
                pathNames.push_back(leaf);
            }
            std::sort(pathNames.begin(), pathNames.end(),
                      AlphanumLess<std::string>());
            nlohmann::json memberArray = nlohmann::json::array();
            for (const std::string& leaf : pathNames)
            {
                boost::urls::url url = collectionPath;
                crow::utility::appendUrlPieces(url, leaf);
                nlohmann::json memberObject;
                memberObject["@odata.id"] = std::move(url);
                memberArray.push_back(memberObject);
            }
            redundancyGroup["RedundancyGroup"] = std::move(memberArray);
            redundancyGroup["RedundancyType"] = "Failover";
            redundancyGroup["Status"]["State"] = "UnavailableOffline";
            redundancyGroup["Status"]["Health"] = "OK";
            for (const std::pair<std::string,
                                 std::variant<uint8_t, std::string, bool>>&
                     property : propertiesList)
            {
                const std::string& propertyName = property.first;
                if ((propertyName == "PSUNumber") ||
                    (propertyName == "RedundantCount"))
                {
                    const uint8_t* value =
                        std::get_if<uint8_t>(&property.second);
                    if (value != nullptr)
                    {
                        if (propertyName == "PSUNumber")
                        {
                            redundancyGroup["MaxSupportedInGroup"] = *value;
                        }
                        else
                        {
                            redundancyGroup["MinNeededInGroup"] = *value;
                        }
                    }
                }
            }
            asyncResp->res.jsonValue["PowerSupplyRedundancy"].push_back(
                redundancyGroup);
        });
}
inline void
    getPSURedundancy(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                     const std::string& chassisId,
                     const std::optional<std::string>& validChassisPath)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp, chassisId, validChassisPath](
            const boost::system::error_code ec2,
            const std::vector<std::pair<
                std::string, std::variant<uint8_t, std::string, bool>>>&
                propertiesList) {
            if (ec2)
            {
                return;
            }
            constexpr std::array<std::string_view, 1> interface{
                "xyz.openbmc_project.Inventory.Item.PowerSupply"};
            getCollectionOfPSUMembers(
                asyncResp,
                boost::urls::format(
                    "/redfish/v1/Chassis/{}/PowerSubsystem/PowerSupplies",
                    chassisId),
                interface, propertiesList);
        },
        "xyz.openbmc_project.PSURedundancy",
        "/xyz/openbmc_project/control/power_supply_redundancy",
        "org.freedesktop.DBus.Properties", "GetAll",
        "xyz.openbmc_project.Control.PowerSupplyRedundancy");
}

inline void doPowerSubsystemCollection(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId,
    const std::optional<std::string>& validChassisPath)
{
    if (!validChassisPath)
    {
        messages::resourceNotFound(asyncResp->res, "Chassis", chassisId);
        return;
    }

    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/PowerSubsystem/PowerSubsystem.json>; rel=describedby");
    asyncResp->res.jsonValue["@odata.type"] = json_util::odataType("PowerSubsystem");
    asyncResp->res.jsonValue["Name"] = "Power Subsystem";
    asyncResp->res.jsonValue["Description"] =
        "The Collection of Power Subsystem";
    asyncResp->res.jsonValue["Id"] = "PowerSubsystem";
    asyncResp->res.jsonValue["@odata.id"] =
        boost::urls::format("/redfish/v1/Chassis/{}/PowerSubsystem", chassisId);
    asyncResp->res.jsonValue["Status"]["State"] = resource::State::Enabled;
    asyncResp->res.jsonValue["Status"]["Health"] = resource::Health::OK;
    asyncResp->res.jsonValue["PowerSupplies"]["@odata.id"] =
        boost::urls::format(
            "/redfish/v1/Chassis/{}/PowerSubsystem/PowerSupplies", chassisId);
    getPSURedundancy(asyncResp, chassisId, validChassisPath);
    getPSUMonitorProperties(asyncResp);
}

inline void handlePowerSubsystemCollectionHead(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    auto respHandler = [asyncResp, chassisId](
                           const std::optional<std::string>& validChassisPath) {
        if (!validChassisPath)
        {
            messages::resourceNotFound(asyncResp->res, "Chassis", chassisId);
            return;
        }
        asyncResp->res.addHeader(
            boost::beast::http::field::link,
            "</redfish/v1/JsonSchemas/PowerSubsystem/PowerSubsystem.json>; rel=describedby");
    };
    redfish::chassis_utils::getValidChassisPath(asyncResp, chassisId,
                                                std::move(respHandler));
}

inline void handlePowerSubsystemCollectionGet(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    redfish::chassis_utils::getValidChassisPath(
        asyncResp, chassisId,
        std::bind_front(doPowerSubsystemCollection, asyncResp, chassisId));
}

inline void requestRoutesPowerSubsystem(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Chassis/<str>/PowerSubsystem/")
        .privileges(redfish::privileges::headPowerSubsystem)
        .methods(boost::beast::http::verb::head)(
            std::bind_front(handlePowerSubsystemCollectionHead, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Chassis/<str>/PowerSubsystem/")
        .privileges(redfish::privileges::getPowerSubsystem)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handlePowerSubsystemCollectionGet, std::ref(app)));
}

} // namespace redfish
