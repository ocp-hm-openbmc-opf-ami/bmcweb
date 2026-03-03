// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#pragma once

#include "app.hpp"
#include "generated/enums/resource.hpp"
#include "human_sort.hpp"
#include "logging.hpp"
#include "query.hpp"
#include "registries/privilege_registry.hpp"
#include "utils/chassis_utils.hpp"
#include "utils/json_utils.hpp"

#include <boost/url/format.hpp>
#include <dbus_utility.hpp>

#include <optional>
#include <string>

namespace redfish
{

inline void getFanRedundancy(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId,
    const dbus::utility::MapperGetSubTreePathsResponse& fanPaths)
{
    if (fanPaths.empty())
    {
        return;
    }
    asyncResp->res.jsonValue["FanRedundancy"] = nlohmann::json::array();
    nlohmann::json::object_t redundancy;
    redundancy["RedundancyType"] = "NPlusM";
    redundancy["MinNeededInGroup"] = 1;
    redundancy["Status"]["State"] = "Enabled";
    redundancy["Status"]["Health"] = "OK";
    redundancy["RedundancyGroup"] = nlohmann::json::array();

    for (const std::string& fanPath : fanPaths)
    {
        if (!(fanPath.find("fan_tach") != std::string::npos))
        {
            continue;
        }
        std::string fanName =
            sdbusplus::message::object_path(fanPath).filename();
        if (fanName.empty())
        {
            continue;
        }

        nlohmann::json item = nlohmann::json::object();
        item["@odata.id"] = boost::urls::format(
            "/redfish/v1/Chassis/{}/ThermalSubsystem/Fans/{}", chassisId,
            fanName);

        redundancy["RedundancyGroup"].push_back(std::move(item));
    }
    redundancy["MaxSupportedInGroup"] = redundancy["RedundancyGroup"].size();

    asyncResp->res.jsonValue["FanRedundancy"].push_back(std::move(redundancy));

}

inline void doThermalSubsystemCollection(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId,
    const std::optional<std::string>& validChassisPath)
{
    if (!validChassisPath)
    {
        BMCWEB_LOG_WARNING("Not a valid chassis ID{}", chassisId);
        messages::resourceNotFound(asyncResp->res, "Chassis", chassisId);
        return;
    }

    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/ThermalSubsystem/ThermalSubsystem.json>; rel=describedby");
    asyncResp->res.jsonValue["@odata.type"] = json_util::odataType("ThermalSubsystem");
    asyncResp->res.jsonValue["Name"] = "Thermal Subsystem";
    asyncResp->res.jsonValue["Id"] = "ThermalSubsystem";
    asyncResp->res.jsonValue["Description"] =
        "The Collection of Thermal Subsystem";

    asyncResp->res.jsonValue["@odata.id"] = boost::urls::format(
        "/redfish/v1/Chassis/{}/ThermalSubsystem", chassisId);

    asyncResp->res.jsonValue["Fans"]["@odata.id"] = boost::urls::format(
        "/redfish/v1/Chassis/{}/ThermalSubsystem/Fans", chassisId);

    asyncResp->res.jsonValue["ThermalMetrics"]["@odata.id"] =
        boost::urls::format(
            "/redfish/v1/Chassis/{}/ThermalSubsystem/ThermalMetrics",
            chassisId);

    asyncResp->res.jsonValue["Status"]["State"] = resource::State::Enabled;
    asyncResp->res.jsonValue["Status"]["Health"] = resource::Health::OK;
    if (chassisId != "Cpld" && chassisId != "CDU" && chassisId != "PowerShelf" && chassisId != "Rack")
    {
        getFanPaths(asyncResp, *validChassisPath,
                    std::bind_front(getFanRedundancy, asyncResp, chassisId));
    }
}

inline void handleThermalSubsystemCollectionHead(
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
            "</redfish/v1/JsonSchemas/ThermalSubsystem/ThermalSubsystem.json>; rel=describedby");
    };
    redfish::chassis_utils::getValidChassisPath(asyncResp, chassisId,
                                                std::bind_front(respHandler));
}

inline void handleThermalSubsystemCollectionGet(
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
        std::bind_front(doThermalSubsystemCollection, asyncResp, chassisId));
}

inline void requestRoutesThermalSubsystem(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Chassis/<str>/ThermalSubsystem/")
        .privileges(redfish::privileges::headThermalSubsystem)
        .methods(boost::beast::http::verb::head)(std::bind_front(
            handleThermalSubsystemCollectionHead, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Chassis/<str>/ThermalSubsystem/")
        .privileges(redfish::privileges::getThermalSubsystem)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleThermalSubsystemCollectionGet, std::ref(app)));
}

} // namespace redfish
