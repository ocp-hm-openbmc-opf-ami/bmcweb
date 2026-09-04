#pragma once

#include "app.hpp"
#include "dbus_utility.hpp"
#include "query.hpp"
#include "registries/privilege_registry.hpp"
#include "utils/json_utils.hpp"

#include <boost/url/format.hpp>

#include <string>

namespace redfish
{

inline void parseSensorProperties(
    nlohmann::json& sensorJson, const std::string& sensorPath,
    const ::dbus::utility::DBusPropertiesMap& properties)
{
    std::size_t lastSlash = sensorPath.rfind('/');
    if (lastSlash == std::string::npos)
    {
        return;
    }

    sensorJson["Name"] = sensorPath.substr(lastSlash + 1);
    sensorJson["Status"]["State"] = "Enabled";
    sensorJson["Status"]["Health"] = "OK";

    for (const auto& [propName, propValue] : properties)
    {
        if (propName == "Value")
        {
            const double* val = std::get_if<double>(&propValue);
            if (val != nullptr)
            {
                sensorJson["Reading"] = *val;
            }
        }
        else if (propName == "Unit")
        {
            const std::string* unit =
                std::get_if<std::string>(&propValue);
            if (unit != nullptr)
            {
                // Map D-Bus unit to Redfish ReadingUnits
                if (unit->ends_with("DegreesC"))
                {
                    sensorJson["ReadingUnits"] = "Cel";
                }
                else if (unit->ends_with("Volts"))
                {
                    sensorJson["ReadingUnits"] = "V";
                }
                else if (unit->ends_with("Amperes"))
                {
                    sensorJson["ReadingUnits"] = "A";
                }
                else if (unit->ends_with("Watts"))
                {
                    sensorJson["ReadingUnits"] = "W";
                }
                else if (unit->ends_with("RPMS"))
                {
                    sensorJson["ReadingUnits"] = "RPM";
                }
                else if (unit->ends_with("Percent"))
                {
                    sensorJson["ReadingUnits"] = "%";
                }
            }
        }
        else if (propName == "Available")
        {
            const bool* avail = std::get_if<bool>(&propValue);
            if (avail != nullptr && !(*avail))
            {
                sensorJson["Status"]["State"] = "Disabled";
            }
        }
        else if (propName == "WarningHigh")
        {
            const double* val = std::get_if<double>(&propValue);
            if (val != nullptr)
            {
                sensorJson["Thresholds"]["UpperCaution"]["Reading"] = *val;
            }
        }
        else if (propName == "WarningLow")
        {
            const double* val = std::get_if<double>(&propValue);
            if (val != nullptr)
            {
                sensorJson["Thresholds"]["LowerCaution"]["Reading"] = *val;
            }
        }
        else if (propName == "CriticalHigh")
        {
            const double* val = std::get_if<double>(&propValue);
            if (val != nullptr)
            {
                sensorJson["Thresholds"]["UpperCritical"]["Reading"] = *val;
            }
        }
        else if (propName == "CriticalLow")
        {
            const double* val = std::get_if<double>(&propValue);
            if (val != nullptr)
            {
                sensorJson["Thresholds"]["LowerCritical"]["Reading"] = *val;
            }
        }
        else if (propName == "NonRecoverableHigh")
        {
            const double* val = std::get_if<double>(&propValue);
            if (val != nullptr)
            {
                sensorJson["Thresholds"]["UpperFatal"]["Reading"] = *val;
            }
        }
        else if (propName == "NonRecoverableLow")
        {
            const double* val = std::get_if<double>(&propValue);
            if (val != nullptr)
            {
                sensorJson["Thresholds"]["LowerFatal"]["Reading"] = *val;
            }
        }
        else if (propName == "WarningAlarmHigh" ||
                 propName == "WarningAlarmLow" ||
                 propName == "CriticalAlarmHigh" ||
                 propName == "CriticalAlarmLow")
        {
            const bool* alarm = std::get_if<bool>(&propValue);
            if (alarm != nullptr && *alarm)
            {
                if (propName.starts_with("Critical"))
                {
                    sensorJson["Status"]["Health"] = "Critical";
                }
                else if (sensorJson["Status"]["Health"] != "Critical")
                {
                    sensorJson["Status"]["Health"] = "Warning";
                }
            }
        }
    }
}

inline void getSensorsSummaryData(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    asyncResp->res.jsonValue["Sensors"] = nlohmann::json::array();

    constexpr std::array<std::string_view, 1> interfaces = {
        "xyz.openbmc_project.Sensor.Value"};

    dbus::utility::getSubTree(
        "/xyz/openbmc_project/sensors", 2, interfaces,
        [asyncResp](const boost::system::error_code& ec,
                    const dbus::utility::MapperGetSubTreeResponse& subtree) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("SensorsSummary D-Bus error: {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }

            for (const auto& [sensorPath, serviceMap] : subtree)
            {
                if (serviceMap.empty())
                {
                    continue;
                }

                dbus::utility::getAllProperties(
                    serviceMap[0].first, sensorPath, "",
                    [asyncResp, sensorPath](
                        const boost::system::error_code& ec2,
                        const ::dbus::utility::DBusPropertiesMap& properties) {
                        if (ec2)
                        {
                            return;
                        }
                        nlohmann::json sensorJson;
                        parseSensorProperties(sensorJson, sensorPath,
                                              properties);
                        if (!sensorJson.empty())
                        {
                            asyncResp->res.jsonValue["Sensors"].push_back(
                                std::move(sensorJson));
                        }
                    });
            }
        });
}

inline void sensorsSummaryPage(
    App& /*app*/, const crow::Request& /*req*/,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    asyncResp->res.jsonValue["@odata.id"] =
        "/redfish/v1/Oem/Ami/SensorsSummary";
    asyncResp->res.jsonValue["@odata.type"] =
        "#OemSensorsSummary.v1_0_0.OemSensorsSummary";
    asyncResp->res.jsonValue["Name"] = "Sensors Summary";
    getSensorsSummaryData(asyncResp);
}

inline void requestRoutesSensorsSummary(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Oem/Ami/SensorsSummary")
        .privileges(redfish::privileges::privilegeSetLogin)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(sensorsSummaryPage, std::ref(app)));
}

} // namespace redfish
