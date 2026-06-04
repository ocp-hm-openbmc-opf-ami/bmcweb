// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#pragma once

#include "app.hpp"
#include "dbus_utility.hpp"
#include "error_messages.hpp"
#include "generated/enums/power.hpp"
#include "query.hpp"
#include "registries/privilege_registry.hpp"
#include "sensors.hpp"
#include "utils/chassis_utils.hpp"
#include "utils/json_utils.hpp"
#include "utils/sensor_utils.hpp"

#include <sdbusplus/asio/property.hpp>

#include <cmath>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace redfish
{

// Structure to track PATCH operation results for comprehensive response
// handling
struct EnvironmentMetricsPatchState
{
    std::shared_ptr<SensorsAsyncResp> sensorsAsyncResp;
    // Any properties provided in request
    bool hasValidProperties = false;
    // Any properties successfully processed
    bool hasSuccessfulOperations = false;
    // Any properties failed processing
    bool hasFailedOperations = false;
    // Collect error details for partial success
    std::vector<std::string> errorMessages;

    void evaluateAndRespond()
    {
        if (!hasValidProperties)
        {
            // No valid properties provided
            sensorsAsyncResp->asyncResp->res.result(
                boost::beast::http::status::bad_request);
            return;
        }

        if (hasSuccessfulOperations && !hasFailedOperations)
        {
            // Complete success
            BMCWEB_LOG_DEBUG(
                "PATCH: Complete success - returning updated resource");
            return;
        }

        if (hasSuccessfulOperations && hasFailedOperations)
        {
            // Partial success
            BMCWEB_LOG_DEBUG(
                "PATCH: Partial success - resource updated with some errors");
            for (const auto& error : errorMessages)
            {
                // Add error messages to existing response
                BMCWEB_LOG_WARNING("PATCH partial failure: {}", error);
            }
            return;
        }

        if (!hasSuccessfulOperations && hasFailedOperations)
        {
            // Complete failure
            sensorsAsyncResp->asyncResp->res.result(
                boost::beast::http::status::bad_request);
            BMCWEB_LOG_DEBUG("PATCH: Complete failure - returning errors only");
            return;
        }
    }
};

inline void afterEnvironmentMetricsPowerCapGet(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId, const boost::system::error_code& ec,
    const dbus::utility::DBusPropertiesMap& properties)
{
    if (ec)
    {
        BMCWEB_LOG_DEBUG("Power Limit not available for chassis {}: {}",
                         chassisId, ec);
        return;
    }

    bool enabled = false;
    double powerCap = 0.0;
    int64_t scale = 0;

    for (const std::pair<std::string, dbus::utility::DbusVariantType>&
             property : properties)
    {
        if (property.first == "Scale")
        {
            const int64_t* i = std::get_if<int64_t>(&property.second);
            if (i != nullptr)
            {
                scale = *i;
            }
        }
        else if (property.first == "PowerCap")
        {
            const double* d = std::get_if<double>(&property.second);
            const int64_t* i = std::get_if<int64_t>(&property.second);
            const uint32_t* u = std::get_if<uint32_t>(&property.second);

            if (d != nullptr)
            {
                powerCap = *d;
            }
            else if (i != nullptr)
            {
                powerCap = static_cast<double>(*i);
            }
            else if (u != nullptr)
            {
                powerCap = *u;
            }
        }
        else if (property.first == "PowerCapEnable")
        {
            const bool* b = std::get_if<bool>(&property.second);
            if (b != nullptr)
            {
                enabled = *b;
            }
        }
    }

    // Add PowerLimitWatts structure to EnvironmentMetrics response
    nlohmann::json::object_t powerLimitWatts;

    if (enabled && powerCap > 0)
    {
        double limitInWatts =
            powerCap * std::pow(10, scale); // Calculated: powerCap * 10^scale
        powerLimitWatts["SetPoint"] = limitInWatts;
    }
    else
    {
        powerLimitWatts["SetPoint"] =
            nullptr; // Null when disabled or no limit set
    }

    asyncResp->res.jsonValue["PowerLimitWatts"] = std::move(powerLimitWatts);
}

// Shared function to build complete EnvironmentMetrics response
inline void buildEnvironmentMetricsResponse(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId)
{
    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/EnvironmentMetrics/EnvironmentMetrics.json>; rel=describedby");
    asyncResp->res.jsonValue["@odata.context"] =
        "/redfish/v1/$metadata#EnvironmentMetrics.EnvironmentMetrics";
    asyncResp->res.jsonValue["@odata.type"] =
        json_util::odataType("EnvironmentMetrics");
    asyncResp->res.jsonValue["Name"] = "Environment Metrics";
    asyncResp->res.jsonValue["Description"] =
        "Power control and management metrics for this chassis.";
    asyncResp->res.jsonValue["Id"] = "EnvironmentMetrics";
    asyncResp->res.jsonValue["Description"] =
        "Environment Metrics Information for Chassis";
    asyncResp->res.jsonValue["@odata.id"] =
        "/redfish/v1/Chassis/" + chassisId + "/EnvironmentMetrics";

    // This callback verifies that the power limit is provided
    // for the chassis that implements the Chassis inventory item.

    constexpr std::array<std::string_view, 2> interfaces = {
        "xyz.openbmc_project.Inventory.Item.Board",
        "xyz.openbmc_project.Inventory.Item.Chassis"};

    dbus::utility::getSubTreePaths(
        "/xyz/openbmc_project/inventory", 0, interfaces,
        [asyncResp, chassisId](
            const boost::system::error_code& ec2,
            const dbus::utility::MapperGetSubTreePathsResponse& chassisPaths) {
            if (ec2)
            {
                BMCWEB_LOG_ERROR("Power Limit GetSubTreePaths: Dbus error: {}",
                                 ec2);
                messages::internalError(asyncResp->res);
                return;
            }

            bool found = false;
            for (const std::string& chassis : chassisPaths)
            {
                size_t len = std::string::npos;
                size_t lastPos = chassis.rfind('/');
                if (lastPos == std::string::npos)
                {
                    continue;
                }

                if (lastPos == chassis.size() - 1)
                {
                    size_t end = lastPos;
                    lastPos = chassis.rfind('/', lastPos - 1);
                    if (lastPos == std::string::npos)
                    {
                        continue;
                    }
                    len = end - (lastPos + 1);
                }

                std::string interfaceChassisName =
                    chassis.substr(lastPos + 1, len);
                if (interfaceChassisName == chassisId)
                {
                    found = true;
                    break;
                }
            }

            if (!found)
            {
                BMCWEB_LOG_DEBUG("Power Limit not present for {}", chassisId);
                return;
            }

            // Retrieve power cap settings and format as PowerLimitWatts
            dbus::utility::getAllProperties(
                "xyz.openbmc_project.Settings",
                "/xyz/openbmc_project/control/host0/power_cap",
                "xyz.openbmc_project.Control.Power.Cap",
                [asyncResp, chassisId](
                    const boost::system::error_code& ec,
                    const dbus::utility::DBusPropertiesMap& properties) {
                    afterEnvironmentMetricsPowerCapGet(asyncResp, chassisId, ec,
                                                       properties);
                });
        });
}

inline void setEnvironmentMetricsPowerCapEnabled(
    const std::shared_ptr<SensorsAsyncResp>& sensorsAsyncResp,
    const bool enabled)
{
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, "xyz.openbmc_project.Settings",
        "/xyz/openbmc_project/control/host0/power_cap",
        "xyz.openbmc_project.Control.Power.Cap", "PowerCapEnable", enabled,

        [sensorsAsyncResp](const boost::system::error_code& ec) {
            if (ec)
            {
                messages::internalError(sensorsAsyncResp->asyncResp->res);
                BMCWEB_LOG_ERROR("Power Limit Enable Set: Dbus error: {}", ec);
                return;
            }
            BMCWEB_LOG_DEBUG("Power Limit Enable Set: Success");
        });
}

inline void afterGetEnvironmentMetricsPowerCapEnable(
    const std::shared_ptr<SensorsAsyncResp>& sensorsAsyncResp,
    uint32_t valueToSet, const boost::system::error_code& ec,
    bool powerCapEnable)
{
    if (ec)
    {
        messages::internalError(sensorsAsyncResp->asyncResp->res);
        BMCWEB_LOG_ERROR("Power Limit Enable Get: Dbus error: {}", ec);
        return;
    }
    if (!powerCapEnable && valueToSet != 0)
    {
        setEnvironmentMetricsPowerCapEnabled(sensorsAsyncResp, true);
    }
    else if (powerCapEnable && valueToSet == 0)
    {
        setEnvironmentMetricsPowerCapEnabled(sensorsAsyncResp, false);
    }

    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, "xyz.openbmc_project.Settings",
        "/xyz/openbmc_project/control/host0/power_cap",
        "xyz.openbmc_project.Control.Power.Cap", "PowerCap", valueToSet,
        [sensorsAsyncResp](const boost::system::error_code& ec) {
            if (ec)
            {
                messages::internalError(sensorsAsyncResp->asyncResp->res);
                BMCWEB_LOG_ERROR("Power Limit Set: Dbus error: {}", ec);
                return;
            }
            BMCWEB_LOG_DEBUG(
                "Power Limit Set: Success - retrieving updated resource");

            buildEnvironmentMetricsResponse(sensorsAsyncResp->asyncResp,
                                            sensorsAsyncResp->chassisId);
        });
}

inline void afterGetEnvironmentMetricsChassisPath(
    const std::shared_ptr<SensorsAsyncResp>& sensorsAsyncResp,
    std::vector<nlohmann::json::object_t>& powerControlCollections,
    const std::optional<std::string>& chassisPath)
{
    if (!chassisPath)
    {
        messages::resourceNotFound(sensorsAsyncResp->asyncResp->res, "Chassis",
                                   sensorsAsyncResp->chassisId);
        return;
    }

    if (powerControlCollections.size() != 1)
    {
        messages::resourceNotFound(sensorsAsyncResp->asyncResp->res, "Power",
                                   "PowerControl");
        return;
    }

    auto& item = powerControlCollections[0];

    std::optional<uint32_t> value;
    if (!json_util::readJsonObject(item, sensorsAsyncResp->asyncResp->res,
                                   "PowerLimit/LimitInWatts", value))
    {
        return;
    }
    if (!value)
    {
        return;
    }

    if (value)
    {
        sdbusplus::asio::getProperty<bool>(
            *crow::connections::systemBus, "xyz.openbmc_project.Settings",
            "/xyz/openbmc_project/control/host0/power_cap",
            "xyz.openbmc_project.Control.Power.Cap", "PowerCapEnable",
            std::bind_front(afterGetEnvironmentMetricsPowerCapEnable,
                            sensorsAsyncResp, *value));
    }
}

inline void handleEnvironmentMetricsHead(
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
            "</redfish/v1/JsonSchemas/EnvironmentMetrics/EnvironmentMetrics.json>; rel=describedby");
    };

    redfish::chassis_utils::getValidChassisPath(asyncResp, chassisId,
                                                std::move(respHandler));
}

inline void handleEnvironmentMetricsGet(
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

        buildEnvironmentMetricsResponse(asyncResp, chassisId);
    };

    redfish::chassis_utils::getValidChassisPath(asyncResp, chassisId,
                                                std::move(respHandler));
}

inline void handleEnvironmentMetricsPatch(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    auto sensorAsyncResp = std::make_shared<SensorsAsyncResp>(
        asyncResp, chassisId, sensors::dbus::powerPaths,
        sensor_utils::chassisSubNodeToString(
            sensor_utils::ChassisSubNode::powerNode));

    // Create shared state for tracking PATCH operations across async callbacks
    auto patchState = std::make_shared<EnvironmentMetricsPatchState>();
    patchState->sensorsAsyncResp = sensorAsyncResp;

    std::optional<nlohmann::json::object_t> powerLimitWatts;

    if (!json_util::readJsonPatch(                //
            req, sensorAsyncResp->asyncResp->res, //
            "PowerLimitWatts", powerLimitWatts    //
            ))
    {
        return;
    }

    if (powerLimitWatts)
    {
        patchState->hasValidProperties = true;

        // Handle PowerLimitWatts changes
        std::optional<uint32_t> setPoint;
        if (json_util::readJsonObject(*powerLimitWatts, asyncResp->res,
                                      "SetPoint", setPoint))
        {
            if (setPoint)
            {
                // Convert to PowerControl format for internal processing
                std::vector<nlohmann::json::object_t> powerCtlCol;
                nlohmann::json::object_t powerCtl;
                powerCtl["PowerLimit"]["LimitInWatts"] = *setPoint;
                powerCtlCol.emplace_back(std::move(powerCtl));

                redfish::chassis_utils::getValidChassisPath(
                    sensorAsyncResp->asyncResp, sensorAsyncResp->chassisId,
                    std::bind_front(afterGetEnvironmentMetricsChassisPath,
                                    sensorAsyncResp, powerCtlCol));

                patchState->hasSuccessfulOperations = true;
            }
            else
            {
                patchState->hasFailedOperations = true;
                patchState->errorMessages.push_back(
                    "PowerLimitWatts/SetPoint is required");
                messages::propertyMissing(asyncResp->res,
                                          "PowerLimitWatts/SetPoint");
            }
        }
        else
        {
            patchState->hasFailedOperations = true;
            patchState->errorMessages.push_back(
                "PowerLimitWatts/SetPoint validation failed");
        }
    }

    if (!patchState->hasValidProperties ||
        (patchState->hasFailedOperations &&
         !patchState->hasSuccessfulOperations))
    {
        asyncResp->res.result(boost::beast::http::status::bad_request);
        return;
    }
}

inline void requestRoutesEnvironmentMetrics(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Chassis/<str>/EnvironmentMetrics/")
        .privileges(redfish::privileges::headEnvironmentMetrics)
        .methods(boost::beast::http::verb::head)(
            std::bind_front(handleEnvironmentMetricsHead, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Chassis/<str>/EnvironmentMetrics/")
        .privileges(redfish::privileges::getEnvironmentMetrics)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleEnvironmentMetricsGet, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Chassis/<str>/EnvironmentMetrics/")
        .privileges(redfish::privileges::patchEnvironmentMetrics)
        .methods(boost::beast::http::verb::patch)(
            std::bind_front(handleEnvironmentMetricsPatch, std::ref(app)));
}

} // namespace redfish
