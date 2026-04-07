// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#pragma once

#include "dbus_utility.hpp"
#include "generated/enums/resource.hpp"
#include "generated/enums/sensor.hpp"
#include "generated/enums/thermal.hpp"
#include "str_utility.hpp"
#include "utils/dbus_utils.hpp"
#include "utils/json_utils.hpp"

#include <sdbusplus/unpack_properties.hpp>

#include <algorithm>
#include <format>
#include <ranges>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace redfish
{
namespace sensor_utils
{

enum class ChassisSubNode
{
    powerNode,
    sensorsNode,
    thermalNode,
    unknownNode,
};

constexpr std::string_view chassisSubNodeToString(ChassisSubNode subNode)
{
    switch (subNode)
    {
        case ChassisSubNode::powerNode:
            return "Power";
        case ChassisSubNode::sensorsNode:
            return "Sensors";
        case ChassisSubNode::thermalNode:
            return "Thermal";
        case ChassisSubNode::unknownNode:
        default:
            return "";
    }
}

inline ChassisSubNode chassisSubNodeFromString(const std::string& subNodeStr)
{
    // If none match unknownNode is returned
    ChassisSubNode subNode = ChassisSubNode::unknownNode;

    if (subNodeStr == "Power")
    {
        subNode = ChassisSubNode::powerNode;
    }
    else if (subNodeStr == "Sensors")
    {
        subNode = ChassisSubNode::sensorsNode;
    }
    else if (subNodeStr == "Thermal")
    {
        subNode = ChassisSubNode::thermalNode;
    }

    return subNode;
}
/**
 * Possible states for physical inventory leds
 */
enum class LedState
{
    OFF,
    ON,
    BLINK,
    UNKNOWN
};

/**
 * D-Bus inventory item associated with one or more sensors.
 */
class InventoryItem
{
  public:
    explicit InventoryItem(const std::string& objPath) : objectPath(objPath)
    {
        // Set inventory item name to last node of object path
        sdbusplus::message::object_path path(objectPath);
        name = path.filename();
        if (name.empty())
        {
            BMCWEB_LOG_ERROR("Failed to find '/' in {}", objectPath);
        }
    }

    std::string objectPath;
    std::string name;
    bool isPresent = true;
    bool isFunctional = true;
    bool isPowerSupply = false;
    int powerSupplyEfficiencyPercent = -1;
    std::string manufacturer;
    std::string model;
    std::string partNumber;
    std::string serialNumber;
    std::set<std::string> sensors;
    std::string ledObjectPath;
    std::string firmwareVersion;
    std::string plugType;
    std::string nominalVoltageType;
    std::string powerSupplyType;
    std::string sparePartNumber;
    std::string psuState;
    uint16_t powerCapacityWatts;
    uint16_t efficiencyRatings;
    std::map<double, std::string> outputRails;

    LedState ledState = LedState::UNKNOWN;
};

inline std::string getSensorId(std::string_view sensorName,
                               std::string_view sensorType)
{
    std::string normalizedType(sensorType);
    auto remove = std::ranges::remove(normalizedType, '_');
    normalizedType.erase(std::ranges::begin(remove), normalizedType.end());

    return std::format("{}_{}", normalizedType, sensorName);
}

inline std::pair<std::string, std::string> splitSensorNameAndType(
    std::string_view sensorId)
{
    size_t index = sensorId.find('_');
    if (index == std::string::npos)
    {
        return std::make_pair<std::string, std::string>("", "");
    }
    std::string sensorType{sensorId.substr(0, index)};
    std::string sensorName{sensorId.substr(index + 1)};
    // fan_pwm and fan_tach need special handling
    if (sensorType == "fantach" || sensorType == "fanpwm")
    {
        sensorType.insert(3, 1, '_');
    }
    // PLDM base_unit_XX types: "baseunitNN" -> "base_unit_NN"
    else if (sensorType.starts_with("baseunit"))
    {
        std::string digits = sensorType.substr(8);
        sensorType = "base_unit_" + digits;
    }

    return std::make_pair(sensorType, sensorName);
}

namespace sensors
{
inline std::string_view toReadingUnits(std::string_view sensorType)
{
    if (sensorType == "voltage")
    {
        return "V";
    }
    if (sensorType == "power")
    {
        return "W";
    }
    if (sensorType == "current")
    {
        return "A";
    }
    if (sensorType == "fan_tach")
    {
        return "RPM";
    }
    if (sensorType == "temperature")
    {
        return "Cel";
    }
    if (sensorType == "fan_pwm" || sensorType == "utilization" ||
        sensorType == "humidity")
    {
        return "%";
    }
    if (sensorType == "altitude")
    {
        return "m";
    }
    if (sensorType == "airflow")
    {
        // return "cft_i/min";
        return "cft/min";
    }
    if (sensorType == "energy")
    {
        return "J";
    }
    if (sensorType == "pressurekpa")
    {
        return "kPa";
    }
    if (sensorType == "flowrate")
    {
        return "L/min";
    }
    if (sensorType == "tach")
    {
        return "RPM";
    }
    if (sensorType == "pwm")
    {
        return "%";
    }
    if (sensorType == "hours")
    {
        return "hours";
    }
    return "";
}
inline sensor::ReadingType toReadingType(std::string_view sensorType)
{
    if (sensorType == "voltage")
    {
        return sensor::ReadingType::Voltage;
    }
    if (sensorType == "power")
    {
        return sensor::ReadingType::Power;
    }
    if (sensorType == "current")
    {
        return sensor::ReadingType::Current;
    }
    if (sensorType == "fan_tach")
    {
        return sensor::ReadingType::Rotational;
    }
    if (sensorType == "temperature")
    {
        return sensor::ReadingType::Temperature;
    }
    if (sensorType == "fan_pwm" || sensorType == "utilization")
    {
        return sensor::ReadingType::Percent;
    }
    if (sensorType == "humidity")
    {
        return sensor::ReadingType::Humidity;
    }
    if (sensorType == "altitude")
    {
        return sensor::ReadingType::Altitude;
    }
    if (sensorType == "airflow")
    {
        return sensor::ReadingType::AirFlow;
    }
    if (sensorType == "energy")
    {
        return sensor::ReadingType::EnergyJoules;
    }
    if (sensorType == "pwm")
    {
        return sensor::ReadingType::Percent;
    }
    if (sensorType == "tach")
    {
        return sensor::ReadingType::Rotational;
    }
    if (sensorType == "flowrate")
    {
        return sensor::ReadingType::LiquidFlowLPM;
    }
    if (sensorType == "pressurekpa")
    {
        return sensor::ReadingType::PressurekPa;
    }
    return sensor::ReadingType::Invalid;
}
} // namespace sensors
/**
 * @brief Returns the Redfish State value for the specified inventory item.
 * @param inventoryItem D-Bus inventory item associated with a sensor.
 * @param sensorAvailable Boolean representing if D-Bus sensor is marked as
 * available.
 * @return State value for inventory item.
 */
inline resource::State getState(const InventoryItem* inventoryItem,
                                const bool sensorAvailable)
{
    if ((inventoryItem != nullptr) && !(inventoryItem->isPresent))
    {
        return resource::State::Absent;
    }

    if (!sensorAvailable)
    {
        return resource::State::UnavailableOffline;
    }

    return resource::State::Enabled;
}
/**
 * @brief Returns the Redfish Health value for the specified sensor.
 * @param sensorJson Sensor JSON object.
 * @param valuesDict Map of all sensor DBus values.
 * @param inventoryItem D-Bus inventory item associated with the sensor.  Will
 * be nullptr if no associated inventory item was found.
 * @return Health value for sensor.
 */
inline std::string getHealth(nlohmann::json& sensorJson,
                             const dbus::utility::DBusPropertiesMap& valuesDict,
                             const InventoryItem* inventoryItem)
{
    // Get current health value (if any) in the sensor JSON object.  Some JSON
    // objects contain multiple sensors (such as PowerSupplies).  We want to set
    // the overall health to be the most severe of any of the sensors.
    std::string currentHealth;
    auto statusIt = sensorJson.find("Status");
    if (statusIt != sensorJson.end())
    {
        auto healthIt = statusIt->find("Health");
        if (healthIt != statusIt->end())
        {
            std::string* health = healthIt->get_ptr<std::string*>();
            if (health != nullptr)
            {
                currentHealth = *health;
            }
        }
    }

    // If current health in JSON object is already Critical, return that.  This
    // should override the sensor health, which might be less severe.
    if (currentHealth == "Critical")
    {
        return "Critical";
    }

    const bool* criticalAlarmHigh = nullptr;
    const bool* criticalAlarmLow = nullptr;
    const bool* warningAlarmHigh = nullptr;
    const bool* warningAlarmLow = nullptr;

    const bool success = sdbusplus::unpackPropertiesNoThrow(
        dbus_utils::UnpackErrorPrinter(), valuesDict, "CriticalAlarmHigh",
        criticalAlarmHigh, "CriticalAlarmLow", criticalAlarmLow,
        "WarningAlarmHigh", warningAlarmHigh, "WarningAlarmLow",
        warningAlarmLow);

    if (success)
    {
        // Check if sensor has critical threshold alarm
        if ((criticalAlarmHigh != nullptr && *criticalAlarmHigh) ||
            (criticalAlarmLow != nullptr && *criticalAlarmLow))
        {
            return "Critical";
        }
    }

    // Check if associated inventory item is not functional
    if ((inventoryItem != nullptr) && !(inventoryItem->isFunctional))
    {
        return "Critical";
    }

    // If current health in JSON object is already Warning, return that. This
    // should override the sensor status, which might be less severe.
    if (currentHealth == "Warning")
    {
        return "Warning";
    }

    if (success)
    {
        // Check if sensor has warning threshold alarm
        if ((warningAlarmHigh != nullptr && *warningAlarmHigh) ||
            (warningAlarmLow != nullptr && *warningAlarmLow))
        {
            return "Warning";
        }
    }

    return "OK";
}
inline void setLedState(nlohmann::json& sensorJson,
                        const InventoryItem* inventoryItem)
{
    if (inventoryItem != nullptr && !inventoryItem->ledObjectPath.empty())
    {
        switch (inventoryItem->ledState)
        {
            case LedState::OFF:
                sensorJson["IndicatorLED"] = resource::IndicatorLED::Off;
                break;
            case LedState::ON:
                sensorJson["IndicatorLED"] = resource::IndicatorLED::Lit;
                break;
            case LedState::BLINK:
                sensorJson["IndicatorLED"] = resource::IndicatorLED::Blinking;
                break;
            default:
                break;
        }
    }
}
/**
 * @brief Builds a json sensor representation of a sensor.
 * @param sensorName  The name of the sensor to be built
 * @param sensorType  The type (temperature, fan_tach, etc) of the sensor to
 * build
 * @param chassisSubNode The subnode (thermal, sensor, etc) of the sensor
 * @param propertiesDict A dictionary of the properties to build the sensor
 * from.
 * @param sensorJson  The json object to fill
 * @param inventoryItem D-Bus inventory item associated with the sensor.  Will
 * be nullptr if no associated inventory item was found.
 */
inline void objectPropertiesToJson(
    std::string_view sensorName, std::string_view sensorType,
    ChassisSubNode chassisSubNode,
    const dbus::utility::DBusPropertiesMap& propertiesDict,
    nlohmann::json& sensorJson, InventoryItem* inventoryItem)
{
    if (chassisSubNode == ChassisSubNode::sensorsNode)
    {
        std::string subNodeEscaped =
            redfish::sensor_utils::getSensorId(sensorName, sensorType);
        // For sensors in SensorCollection we set Id instead of MemberId,
        // including power sensors.
        sensorJson["Id"] = std::move(subNodeEscaped);

        std::string sensorNameEs(sensorName);
        std::replace(sensorNameEs.begin(), sensorNameEs.end(), '_', ' ');
        sensorJson["Name"] = std::move(sensorNameEs);
    }
    else if (sensorType != "power")
    {
        // Set MemberId and Name for non-power sensors.  For PowerSupplies and
        // PowerControl, those properties have more general values because
        // multiple sensors can be stored in the same JSON object.
        std::string sensorNameEs(sensorName);
        std::replace(sensorNameEs.begin(), sensorNameEs.end(), '_', ' ');
        sensorJson["Name"] = std::move(sensorNameEs);
    }

    const bool* checkAvailable = nullptr;
    bool available = true;
    const bool success = sdbusplus::unpackPropertiesNoThrow(
        dbus_utils::UnpackErrorPrinter(), propertiesDict, "Available",
        checkAvailable);
    if (!success)
    {
        messages::internalError();
    }
    if (checkAvailable != nullptr)
    {
        available = *checkAvailable;
    }

    sensorJson["Status"]["State"] = getState(inventoryItem, available);
    sensorJson["Status"]["Health"] =
        getHealth(sensorJson, propertiesDict, inventoryItem);

    // Parameter to set to override the type we get from dbus, and force it to
    // int, regardless of what is available.  This is used for schemas like fan,
    // that require integers, not floats.
    bool forceToInt = false;

    nlohmann::json::json_pointer unit("/Reading");
    if (chassisSubNode == ChassisSubNode::sensorsNode)
    {
        sensorJson["@odata.type"] = json_util::odataType("Sensor");

        sensor::ReadingType readingType = sensors::toReadingType(sensorType);
        if (readingType == sensor::ReadingType::Invalid)
        {
            BMCWEB_LOG_ERROR("Redfish cannot map reading type for {}",
                             sensorType);
        }
        else
        {
            sensorJson["ReadingType"] = readingType;
            if (readingType == sensor::ReadingType::Temperature)
            {
                if (sensorName.find("CPU") != std::string::npos)
                {
                    sensorJson["PhysicalContext"] = "CPU";
                }
                else if (sensorName.find("Inlet") != std::string::npos)
                {
                    sensorJson["PhysicalContext"] = "Intake";
                }
                else if (sensorName.find("HSBP") != std::string::npos)
                {
                    sensorJson["PhysicalContext"] = "Backplane";
                }
                else
                {
                    sensorJson["PhysicalContext"] = "SystemBoard";
                }
            }
        }

        std::string_view readingUnits = sensors::toReadingUnits(sensorType);
        if (readingUnits.empty())
        {
            BMCWEB_LOG_ERROR("Redfish cannot map reading unit for {}",
                             sensorType);
        }
        else
        {
            sensorJson["ReadingUnits"] = readingUnits;
        }
    }
    else if (sensorType == "temperature")
    {
        unit = "/ReadingCelsius"_json_pointer;
        sensorJson["@odata.type"] =
            json_util::odataType("Thermal", "Temperature");
        // TODO(ed) Documentation says that path should be type fan_tach,
        // implementation seems to implement fan
    }
    else if (sensorType == "fan" || sensorType == "fan_tach")
    {
        unit = "/Reading"_json_pointer;
        sensorJson["ReadingUnits"] = thermal::ReadingUnits::RPM;
        sensorJson["@odata.type"] = json_util::odataType("Thermal", "Fan");
        setLedState(sensorJson, inventoryItem);
        forceToInt = true;
    }
    else if (sensorType == "fan_pwm")
    {
        unit = "/Reading"_json_pointer;
        sensorJson["ReadingUnits"] = thermal::ReadingUnits::Percent;
        sensorJson["@odata.type"] = json_util::odataType("Thermal", "Fan");
        setLedState(sensorJson, inventoryItem);
        forceToInt = true;
    }
    else if (sensorType == "voltage")
    {
        unit = "/ReadingVolts"_json_pointer;
        sensorJson["@odata.type"] = json_util::odataType("Power", "Voltage");
    }
    else if (sensorType == "power")
    {
        std::string lower;
        std::ranges::transform(sensorName, std::back_inserter(lower),
                               bmcweb::asciiToLower);
        if (lower == "total_power")
        {
            sensorJson["@odata.type"] =
                json_util::odataType("Power", "PowerControl");
            // Put multiple "sensors" into a single PowerControl, so have
            // generic names for MemberId and Name. Follows Redfish mockup.
            sensorJson["MemberId"] = "0";
            sensorJson["Name"] = "Chassis Power Control";
            unit = "/PowerConsumedWatts"_json_pointer;
        }
        else if (lower.find("input") != std::string::npos)
        {
            unit = "/PowerCapacityWatts"_json_pointer;
        }
        else if (!(boost::ifind_first(sensorName, "output").empty()))
        {
            return;
        }
    }
    else
    {
        BMCWEB_LOG_ERROR("Redfish cannot map object type for {}", sensorName);
        return;
    }
    // Map of dbus interface name, dbus property name and redfish property_name
    std::vector<
        std::tuple<const char*, const char*, nlohmann::json::json_pointer>>
        properties;

    properties.emplace_back("xyz.openbmc_project.Sensor.Value", "Value", unit);

    if (chassisSubNode == ChassisSubNode::sensorsNode)
    {
        properties.emplace_back(
            "xyz.openbmc_project.Sensor.Threshold.Warning", "WarningHigh",
            "/Thresholds/UpperCaution/Reading"_json_pointer);
        properties.emplace_back(
            "xyz.openbmc_project.Sensor.Threshold.Warning", "WarningLow",
            "/Thresholds/LowerCaution/Reading"_json_pointer);
        properties.emplace_back(
            "xyz.openbmc_project.Sensor.Threshold.Critical", "CriticalHigh",
            "/Thresholds/UpperCritical/Reading"_json_pointer);
        properties.emplace_back(
            "xyz.openbmc_project.Sensor.Threshold.Critical", "CriticalLow",
            "/Thresholds/LowerCritical/Reading"_json_pointer);
        properties.emplace_back(
            "xyz.openbmc_project.Sensor.Threshold.NonRecoverable",
            "NonRecoverableHigh",
            "/Thresholds/UpperFatal/Reading"_json_pointer);
        properties.emplace_back(
            "xyz.openbmc_project.Sensor.Threshold.NonRecoverable",
            "NonRecoverableLow", "/Thresholds/LowerFatal/Reading"_json_pointer);

        /* Add additional properties specific to sensorType */
        if (sensorType == "fan_tach")
        {
            properties.emplace_back("xyz.openbmc_project.Sensor.Value", "Value",
                                    "/SpeedRPM"_json_pointer);
        }
    }
    else if (sensorType != "power")
    {
        properties.emplace_back("xyz.openbmc_project.Sensor.Threshold.Warning",
                                "WarningHigh",
                                "/UpperThresholdNonCritical"_json_pointer);
        properties.emplace_back("xyz.openbmc_project.Sensor.Threshold.Warning",
                                "WarningLow",
                                "/LowerThresholdNonCritical"_json_pointer);
        properties.emplace_back("xyz.openbmc_project.Sensor.Threshold.Critical",
                                "CriticalHigh",
                                "/UpperThresholdCritical"_json_pointer);
        properties.emplace_back("xyz.openbmc_project.Sensor.Threshold.Critical",
                                "CriticalLow",
                                "/LowerThresholdCritical"_json_pointer);
    }

    // TODO Need to get UpperThresholdFatal and LowerThresholdFatal

    if (chassisSubNode == ChassisSubNode::sensorsNode)
    {
        properties.emplace_back("xyz.openbmc_project.Sensor.Value", "MinValue",
                                "/ReadingRangeMin"_json_pointer);
        properties.emplace_back("xyz.openbmc_project.Sensor.Value", "MaxValue",
                                "/ReadingRangeMax"_json_pointer);
        properties.emplace_back("xyz.openbmc_project.Sensor.Accuracy",
                                "Accuracy", "/Accuracy"_json_pointer);
    }
    else if (sensorType == "temperature")
    {
        properties.emplace_back("xyz.openbmc_project.Sensor.Value", "MinValue",
                                "/MinReadingRangeTemp"_json_pointer);
        properties.emplace_back("xyz.openbmc_project.Sensor.Value", "MaxValue",
                                "/MaxReadingRangeTemp"_json_pointer);
    }
    else if (sensorType != "power")
    {
        properties.emplace_back("xyz.openbmc_project.Sensor.Value", "MinValue",
                                "/MinReadingRange"_json_pointer);
        properties.emplace_back("xyz.openbmc_project.Sensor.Value", "MaxValue",
                                "/MaxReadingRange"_json_pointer);
    }

    for (const std::tuple<const char*, const char*,
                          nlohmann::json::json_pointer>& p : properties)
    {
        for (const auto& [valueName, valueVariant] : propertiesDict)
        {
            if (valueName != std::get<1>(p))
            {
                continue;
            }

            // The property we want to set may be nested json, so use
            // a json_pointer for easy indexing into the json structure.
            const nlohmann::json::json_pointer& key = std::get<2>(p);
            const nlohmann::json::json_pointer& keyMax =
                nlohmann::json::json_pointer("/ReadingRangeMax");

            const double* doubleValue = std::get_if<double>(&valueVariant);
            if (doubleValue == nullptr)
            {
                BMCWEB_LOG_ERROR("Got value interface that wasn't double");
                continue;
            }
            if (!std::isfinite(*doubleValue))
            {
                if (valueName == "Value")
                {
                    // Readings are allowed to be NAN for unavailable;  coerce
                    // them to null in the json response.
                    sensorJson[key] = nullptr;
                    sensorJson["Status"]["State"] = "Disabled";
                    sensorJson["Status"].erase("Health");
                    sensorJson[keyMax] = nullptr;
                    continue;
                }
                BMCWEB_LOG_WARNING("Sensor value for {} was unexpectedly {}",
                                   valueName, *doubleValue);
                continue;
            }
            if (forceToInt)
            {
                sensorJson[key] = static_cast<int64_t>(*doubleValue);
                sensorJson[keyMax] = static_cast<int64_t>(*doubleValue);
            }
            else
            {
                if (key == nlohmann::json::json_pointer("/Reading"))
                {
                    double roundedValue =
                        std::round(*doubleValue * 100.0) / 100.0;
                    sensorJson[key] = roundedValue;
                }
                else if (key == nlohmann::json::json_pointer(
                                    "/Thresholds/LowerCaution/Reading") ||
                         key == nlohmann::json::json_pointer(
                                    "/Thresholds/LowerCritical/Reading") ||
                         key == nlohmann::json::json_pointer(
                                    "/Thresholds/UpperCaution/Reading") ||
                         key == nlohmann::json::json_pointer(
                                    "/Thresholds/UpperCritical/Reading"))
                {
                    BMCWEB_LOG_DEBUG(
                        "sensors :: Reading rounded for threshold");
                    // Round to two decimal places for Threshold Readings
                    double roundedValue =
                        std::round(*doubleValue * 100.0) / 100.0;
                    sensorJson[key] = roundedValue;
                }
                else
                {
                    sensorJson[key] = *doubleValue;
                }
                if (keyMax == nlohmann::json::json_pointer("/ReadingRangeMax"))
                {
                    double roundedValueMax =
                        std::round(*doubleValue * 100.0) / 100.0;
                    sensorJson[keyMax] = roundedValueMax;
                }
            }
        }
    }
}
} // namespace sensor_utils
} // namespace redfish
