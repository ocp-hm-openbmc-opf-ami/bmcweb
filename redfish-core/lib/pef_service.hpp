// Copyright (c) 2020 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include "dbus_utility.hpp"
#include "event_service.hpp"

#include <charconv>
#include <functional>
#include <system_error>
#include <type_traits>

namespace redfish
{
static constexpr const char* pefAlertSensorNumberIface =
    "xyz.openbmc_project.pef.alert.SensorNumber";
static constexpr const char* pefConfIface =
    "xyz.openbmc_project.pef.PEFConfInfo";
static constexpr const char* pefRetryConfService =
    "xyz.openbmc_project.pef.alerting";
static constexpr const char* pefRetryConfPath =
    "/xyz/openbmc_project/pef/alerting";
static constexpr const char* pefRetryConfIface =
    "xyz.openbmc_project.pef.pefTask";

static constexpr const char* pefAlertManagerService =
    "xyz.openbmc_project.pef.alert.manager";
static constexpr const char* pefAlertManagerBasePath =
    "/xyz/openbmc_project/PefAlertManager";
static constexpr const char* pefEventFilterTablePath =
    "/xyz/openbmc_project/PefAlertManager/EventFilterTable/";
static constexpr const char* pefEventFilterTableIface =
    "xyz.openbmc_project.pef.EventFilterTable";
static constexpr const char* pefSensorInfoIface =
    "xyz.openbmc_project.pef.SensorInfo";
static constexpr const char* pefAlertPolicyTablePath =
    "/xyz/openbmc_project/PefAlertManager/AlertPolicyTable/";
static constexpr const char* pefAlertPolicyTableIface =
    "xyz.openbmc_project.pef.AlertPolicyTable";

using GetSubTreeType = std::vector<
    std::pair<std::string,
              std::vector<std::pair<std::string, std::vector<std::string>>>>>;

static const std::unordered_map<uint8_t, const char*> severityToString = {
    {2, "Information"},
    {4, "OK"},
    {8, "Warning"},
    {16, "Critical"},
    {32, "All"}};

static const std::unordered_map<std::string, uint8_t> stringToSeverity = {
    {"Information", 2},
    {"OK", 4},
    {"Warning", 8},
    {"Critical", 16},
    {"All", 32}};

// Fetches all available sensor types from the backend.
// Example response: { "temperature": 69, "voltage": 91, "fan_tach": 31 }
inline void getAvailableSensorTypeMap(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    std::function<void(const std::map<std::string, uint8_t>&)> onSuccess)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp, onSuccess{std::move(onSuccess)}](
            const boost::system::error_code& ec,
            const std::map<std::string, uint8_t>& typeMap) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("GetAvailableSensorTypes failed: {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }
            onSuccess(typeMap);
        },
        pefAlertManagerService, pefAlertManagerBasePath, pefSensorInfoIface,
        "GetAvailableSensorTypes");
}

// Example: GetSensorNumNameMapForType "temperature"
//   -> { 69: "BMC_Temp", 74: "Inlet_BRD_Temp" }
inline void getSensorNumNameMapForType(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp, std::string_view type,
    std::function<void(const std::map<uint8_t, std::string>&)> onSuccess)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp, onSuccess{std::move(onSuccess)}](
            const boost::system::error_code& ec,
            const std::map<uint8_t, std::string>& mapResp) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("GetSensorNumNameMapForType failed: {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }
            onSuccess(mapResp);
        },
        pefAlertManagerService, pefAlertManagerBasePath, pefSensorInfoIface,
        "GetSensorNumNameMapForType", std::string(type));
}

// Example JSON output:
//   "SensorType": {
//     "logging": {
//       "Entries": [
//         {"SensorName": "System_Event_Log", "SensorId": 0}
//       ]
//     },
//     "temperature": {
//       "Entries": [
//         {"SensorName": "BMC_Temp", "SensorId": 69},
//         {"SensorName": "Inlet_BRD_Temp", "SensorId": 74}
//       ]
//     }
//   }
inline void addEventFilterSensorDetails(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    // First calls GetAvailableSensorTypes, then for each type calls
    getAvailableSensorTypeMap(
        asyncResp,
        [asyncResp](const std::map<std::string, uint8_t>& sensorTypeMap) {
            asyncResp->res.jsonValue["SensorType"] = nlohmann::json::object();

            for (const auto& [sensorTypeName, sensorTypeId] : sensorTypeMap)
            {
                // GetSensorNumNameMapForType to build the SensorType lookup
                // object.
                getSensorNumNameMapForType(
                    asyncResp, sensorTypeName,
                    [asyncResp, sensorTypeName, sensorTypeId](
                        const std::map<uint8_t, std::string>& nameMap) {
                        nlohmann::json::array_t names;
                        for (const auto& [sensorNum, sensorName] : nameMap)
                        {
                            names.push_back(
                                nlohmann::json{{"SensorName", sensorName},
                                               {"SensorId", sensorNum}});
                        }
                        asyncResp->res.jsonValue["SensorType"][sensorTypeName] =
                            nlohmann::json{{"Entries", std::move(names)}};
                    });
            }
        });
}

struct PefPatchParams
{
    std::optional<std::vector<uint8_t>> filterEnable;
    std::optional<int64_t> retryCountLimit;
    std::optional<int64_t> retryTimeInterval;
    std::optional<int64_t> pendingAlertsLimit;
    std::optional<uint8_t> pefActionGblControl;
    std::optional<bool> retryEnable;

    bool hasValue() const
    {
        return filterEnable.has_value() || pefActionGblControl.has_value() ||
               retryEnable.has_value() || retryCountLimit.has_value() ||
               retryTimeInterval.has_value() || pendingAlertsLimit.has_value();
    }
};

inline void getFilterEnable(const std::shared_ptr<bmcweb::AsyncResp>& aResp)
{
    crow::connections::systemBus->async_method_call(
        [aResp](const boost::system::error_code ec,
                const GetSubTreeType& subtreeLocal) {
            if (ec || subtreeLocal.empty())
            {
                BMCWEB_LOG_ERROR("GetFilterEnable: Error");
                messages::internalError(aResp->res);
                return;
            }
            if (subtreeLocal[0].second.size() != 1)
            {
                // invalid mapper response, should never happen
                BMCWEB_LOG_ERROR("GetPefAlertSensorNumberIface: Mapper Error");
                messages::internalError(aResp->res);
                return;
            }
            const std::string& path = subtreeLocal[0].first;
            const std::string& owner = subtreeLocal[0].second[0].first;

            crow::connections::systemBus->async_method_call(
                [path, owner, aResp](const boost::system::error_code ec2,
                                     std::vector<uint8_t>& resp) {
                    if (ec2)
                    {
                        BMCWEB_LOG_ERROR("GetPefAlert: Can't get "
                                         "pefAlertSensorNumberIface ",
                                         path);
                        messages::internalError(aResp->res);
                        return;
                    }
                    const std::vector<uint8_t>* filterEnable = &resp;
                    if (filterEnable == nullptr)
                    {
                        BMCWEB_LOG_ERROR("Field Illegal FilterEnable");
                        messages::internalError(aResp->res);
                        return;
                    }
                    aResp->res.jsonValue["FilterEnable"] = *filterEnable;
                },
                owner, path, pefAlertSensorNumberIface, "GetFilterEnable");
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTree", "/", 0,
        std::array<const char*, 1>{pefAlertSensorNumberIface});
}

inline void setFilterEnable(const std::shared_ptr<bmcweb::AsyncResp>& aResp,
                            std::vector<uint8_t>& filterEnable)
{
    crow::connections::systemBus->async_method_call(
        [aResp, filterEnable](const boost::system::error_code ec,
                              const GetSubTreeType& subtreeLocal) {
            if (ec || subtreeLocal.empty())
            {
                BMCWEB_LOG_ERROR("SetFilterEnable: Error");
                messages::internalError(aResp->res);
                return;
            }
            if (subtreeLocal[0].second.size() != 1)
            {
                // invalid mapper response, should never happen
                BMCWEB_LOG_ERROR("GetPefAlertSensorNumberIface: Mapper Error");
                messages::internalError(aResp->res);
                return;
            }
            const std::string& path = subtreeLocal[0].first;
            const std::string& owner = subtreeLocal[0].second[0].first;

            crow::connections::systemBus->async_method_call(
                [aResp, filterEnable](const boost::system::error_code ec2) {
                    if (ec2)
                    {
                        BMCWEB_LOG_ERROR(
                            "Set Property SetFilterEnable: Set Error");
                        messages::internalError(aResp->res);
                        return;
                    }
                },
                owner, path, pefAlertSensorNumberIface, "SetFilterEnable",
                std::vector<uint8_t>{filterEnable});
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTree", "/", 0,
        std::array<const char*, 1>{pefAlertSensorNumberIface});
}

inline void getPefConfParam(const std::shared_ptr<bmcweb::AsyncResp>& aResp)
{
    crow::connections::systemBus->async_method_call(
        [aResp](const boost::system::error_code ec,
                const GetSubTreeType& subtreeLocal) {
            if (ec || subtreeLocal.empty())
            {
                BMCWEB_LOG_ERROR("GetPefConfParam: Error");
                messages::internalError(aResp->res);
                return;
            }
            if (subtreeLocal[0].second.size() != 1)
            {
                // invalid mapper response, should never happen
                BMCWEB_LOG_ERROR("pefConfIface: Mapper Error");
                messages::internalError(aResp->res);
                return;
            }
            const std::string& path = subtreeLocal[0].first;
            const std::string& owner = subtreeLocal[0].second[0].first;

            crow::connections::systemBus->async_method_call(
                [path, owner, aResp](
                    const boost::system::error_code ec2,
                    const std::vector<
                        std::pair<std::string, dbus::utility::DbusVariantType>>&
                        propertiesList) {
                    if (ec2)
                    {
                        BMCWEB_LOG_ERROR("GetBootCount: Can't get "
                                         "pefConfIface ",
                                         path);
                        messages::internalError(aResp->res);
                        return;
                    }

                    for (const std::pair<std::string,
                                         dbus::utility::DbusVariantType>&
                             property : propertiesList)
                    {
                        if (property.first == "PEFActionGblControl")
                        {
                            const uint8_t* value =
                                std::get_if<uint8_t>(&property.second);
                            if (value != nullptr)
                            {
                                aResp->res.jsonValue["PEFActionGblControl"] =
                                    *value;
                            }
                        }
                    }
                },
                owner, path, "org.freedesktop.DBus.Properties", "GetAll",
                pefConfIface);
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTree", "/", 0,
        std::array<const char*, 1>{pefConfIface});
}

inline void setPefConfParam(const std::shared_ptr<bmcweb::AsyncResp>& aResp,
                            const std::optional<uint8_t>& pefActionGblControl)
{
    crow::connections::systemBus->async_method_call(
        [aResp, pefActionGblControl](const boost::system::error_code ec,
                                     const GetSubTreeType& subtreeLocal) {
            if (ec || subtreeLocal.empty())
            {
                BMCWEB_LOG_ERROR("SetPefConfParam: Error");
                messages::internalError(aResp->res);
                return;
            }
            if (subtreeLocal[0].second.size() != 1)
            {
                // invalid mapper response, should never happen
                BMCWEB_LOG_ERROR("SetPefConf: Mapper Error");
                messages::internalError(aResp->res);
                return;
            }
            const std::string& path = subtreeLocal[0].first;
            const std::string& owner = subtreeLocal[0].second[0].first;

            if (pefActionGblControl)
            {
                crow::connections::systemBus->async_method_call(
                    [aResp,
                     pefActionGblControl](const boost::system::error_code ec2) {
                        if (ec2)
                        {
                            BMCWEB_LOG_ERROR(
                                "SetPefActionGblControl: Set Error");
                            messages::internalError(aResp->res);
                            return;
                        }
                    },
                    owner, path, "org.freedesktop.DBus.Properties", "Set",
                    pefConfIface, "PEFActionGblControl",
                    dbus::utility::DbusVariantType(*pefActionGblControl));
            }
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTree", "/", 0,
        std::array<const char*, 1>{pefConfIface});
}

inline void getRetryConfiguration(
    const std::shared_ptr<bmcweb::AsyncResp>& aResp)
{
    crow::connections::systemBus->async_method_call(
        [aResp](const boost::system::error_code& ec,
                const std::vector<std::pair<
                    std::string, dbus::utility::DbusVariantType>>& properties) {
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "D-BUS response error on Retry Configuration GetAll: {}",
                    ec);
                return;
            }

            // Parse all retry configuration properties
            for (const auto& [key, value] : properties)
            {
                if (key == "retryEnable")
                {
                    if (const bool* dbus_value = std::get_if<bool>(&value))
                    {
                        aResp->res.jsonValue["RetryEnable"] = *dbus_value;
                    }
                }
                else if (key == "retryCount")
                {
                    if (const uint8_t* dbus_value =
                            std::get_if<uint8_t>(&value))
                    {
                        aResp->res.jsonValue["RetryCountLimit"] = *dbus_value;
                    }
                }
                else if (key == "timeInterval")
                {
                    if (const uint32_t* dbus_value =
                            std::get_if<uint32_t>(&value))
                    {
                        aResp->res.jsonValue["RetryTimeInterval"] = *dbus_value;
                    }
                }
                else if (key == "alertsLimit")
                {
                    if (const uint8_t* dbus_value =
                            std::get_if<uint8_t>(&value))
                    {
                        aResp->res.jsonValue["PendingAlertsLimit"] =
                            *dbus_value;
                    }
                }
            }
        },
        pefRetryConfService, pefRetryConfPath,
        "org.freedesktop.DBus.Properties", "GetAll", pefRetryConfIface);
}

inline void setRetryEnable(const std::shared_ptr<bmcweb::AsyncResp>& aResp,
                           const std::optional<bool>& retryEnable)
{
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, pefRetryConfService, pefRetryConfPath,
        pefRetryConfIface, "retryEnable", *retryEnable,
        [aResp](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-Bus response error setting RetryEnable: {}",
                                 ec);
                messages::internalError(aResp->res);
                return;
            }
        });
}

inline void setRetryCountLimit(const std::shared_ptr<bmcweb::AsyncResp>& aResp,
                               const std::optional<int64_t>& retryCountLimit)
{
    if (*retryCountLimit < 0 || *retryCountLimit > 10)
    {
        messages::propertyValueOutOfRange(aResp->res, *retryCountLimit,
                                          "RetryCountLimit");
        return;
    }

    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, pefRetryConfService, pefRetryConfPath,
        pefRetryConfIface, "retryCount", static_cast<uint8_t>(*retryCountLimit),
        [aResp](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "D-Bus response error setting RetryCountLimit: {}", ec);
                messages::internalError(aResp->res);
                return;
            }
        });
}

inline void setRetryTimeInterval(
    const std::shared_ptr<bmcweb::AsyncResp>& aResp,
    const std::optional<int64_t>& retryTimeInterval)
{
    if (*retryTimeInterval < 0 || *retryTimeInterval > 3600)
    {
        messages::propertyValueOutOfRange(aResp->res, *retryTimeInterval,
                                          "RetryTimeInterval");
        return;
    }

    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, pefRetryConfService, pefRetryConfPath,
        pefRetryConfIface, "timeInterval",
        static_cast<uint32_t>(*retryTimeInterval),
        [aResp](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "D-Bus response error setting RetryTimeInterval: {}", ec);
                messages::internalError(aResp->res);
                return;
            }
        });
}

inline void setPendingAlertsLimit(
    const std::shared_ptr<bmcweb::AsyncResp>& aResp,
    const std::optional<int64_t>& pendingAlertsLimit)
{
    if (*pendingAlertsLimit < 0 || *pendingAlertsLimit > 100)
    {
        messages::propertyValueOutOfRange(aResp->res, *pendingAlertsLimit,
                                          "PendingAlertsLimit");
        return;
    }

    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, pefRetryConfService, pefRetryConfPath,
        pefRetryConfIface, "alertsLimit",
        static_cast<uint8_t>(*pendingAlertsLimit),
        [aResp](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "D-Bus response error setting PendingAlertsLimit: {}", ec);
                messages::internalError(aResp->res);
                return;
            }
        });
}

void getPefServiceMembers(const std::shared_ptr<bmcweb::AsyncResp>& aResp)
{
    aResp->res.jsonValue["Members"].push_back(
        {{"@odata.id", "/redfish/v1/Oem/Ami/PefService/AlertPolicyTable"}});
    aResp->res.jsonValue["Members"].push_back(
        {{"@odata.id", "/redfish/v1/Oem/Ami/PefService/EventFilterTable"}});
    aResp->res.jsonValue["Members@odata.count"] =
        aResp->res.jsonValue["Members"].size();
}

// EntryType and parseSubscriptionEntryId are defined in event_service.hpp

inline bool isRequestedEntryListPresentInDbusPaths(
    const std::string& entryId, const std::vector<std::string>& dbusPaths)
{
    size_t underscorePos = entryId.rfind('_');
    if (underscorePos == std::string::npos)
    {
        return false;
    }

    std::string listPart = entryId.substr(0, underscorePos);
    return isRequestedObjectPresentInDbusPaths(listPart, dbusPaths);
}

template <typename T>
inline std::optional<T> getArrayElementAtIndex(
    const dbus::utility::DbusVariantType& variant, size_t index)
{
    const std::vector<T>* arrayPtr = std::get_if<std::vector<T>>(&variant);
    if (arrayPtr == nullptr || index >= arrayPtr->size())
    {
        return std::nullopt;
    }
    return (*arrayPtr)[index];
}

inline void getAllEventFilterProperties(
    const std::shared_ptr<bmcweb::AsyncResp>& aResp,
    const std::string& listName, size_t entryIndex)
{
    dbus::utility::getAllProperties(
        pefAlertManagerService, std::string(pefEventFilterTablePath) + listName,
        pefEventFilterTableIface,
        [aResp,
         entryIndex](const boost::system::error_code& ec,
                     const dbus::utility::DBusPropertiesMap& propertiesList) {
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "D-BUS response error on EventFilterTable GetAll: {}", ec);
                return;
            }

            std::optional<uint8_t> selectedSensorTypeId;
            std::optional<uint8_t> selectedSensorNum;

            for (const auto& [key, variant] : propertiesList)
            {
                if (key == "EventSeverity")
                {
                    auto value =
                        getArrayElementAtIndex<uint8_t>(variant, entryIndex);
                    if (!value)
                    {
                        continue;
                    }
                    uint8_t eventValue = *value;
                    auto it = severityToString.find(eventValue);
                    if (it != severityToString.end())
                    {
                        aResp->res.jsonValue[key] = it->second;
                    }
                    else
                    {
                        aResp->res.jsonValue[key] = nullptr;
                    }
                }
                else if (key == "EventData1OffsetMask")
                {
                    auto value =
                        getArrayElementAtIndex<uint16_t>(variant, entryIndex);
                    if (value)
                    {
                        aResp->res.jsonValue[key] = *value;
                    }
                }
                else
                {
                    auto value =
                        getArrayElementAtIndex<uint8_t>(variant, entryIndex);
                    if (value)
                    {
                        if (key == "SensorType")
                        {
                            selectedSensorTypeId = *value;
                        }
                        else if (key == "SensorNum")
                        {
                            selectedSensorNum = *value;
                        }
                        else
                        {
                            aResp->res.jsonValue[key] = *value;
                        }
                    }
                }
            }

            if (!selectedSensorTypeId)
            {
                return;
            }

            getAvailableSensorTypeMap(
                aResp, [aResp, selectedSensorTypeId, selectedSensorNum](
                           const std::map<std::string, uint8_t>& typeMap) {
                    auto typeIt = std::ranges::find_if(
                        typeMap, [selectedSensorTypeId](const auto& pair) {
                            return pair.second == *selectedSensorTypeId;
                        });
                    if (typeIt == typeMap.end())
                    {
                        return;
                    }

                    const std::string& sensorTypeName = typeIt->first;
                    aResp->res.jsonValue["SensorType"] = sensorTypeName;

                    if (!selectedSensorNum)
                    {
                        return;
                    }

                    getSensorNumNameMapForType(
                        aResp, sensorTypeName,
                        [aResp, selectedSensorNum](
                            const std::map<uint8_t, std::string>& nameMap) {
                            auto nameIt = nameMap.find(*selectedSensorNum);
                            if (nameIt == nameMap.end())
                            {
                                return;
                            }
                            aResp->res.jsonValue["SensorName"] = nameIt->second;
                        });
                });
        });
}

inline void handlePefPatch(PefPatchParams&& input,
                           const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                           bool currentRetryEnable,
                           std::function<void(bool, bool)> onComplete)
{
    bool pefAnyFailure = false;
    bool pefAnySuccess = false;

    bool effectiveRetryEnable =
        input.retryEnable ? *input.retryEnable : currentRetryEnable;

    if (input.retryEnable && !(*input.retryEnable))
    {
        if (input.retryCountLimit)
        {
            pefAnyFailure = true;
            messages::propertyValueConflict(
                asyncResp->res, "RetryCountLimit",
                "Cannot configure when RetryEnable is false");
        }
        if (input.retryTimeInterval)
        {
            pefAnyFailure = true;
            messages::propertyValueConflict(
                asyncResp->res, "RetryTimeInterval",
                "Cannot configure when RetryEnable is false");
        }
        if (input.pendingAlertsLimit)
        {
            pefAnyFailure = true;
            messages::propertyValueConflict(
                asyncResp->res, "PendingAlertsLimit",
                "Cannot configure when RetryEnable is false");
        }
    }
    else if (!input.retryEnable && !currentRetryEnable)
    {
        if (input.retryCountLimit)
        {
            pefAnyFailure = true;
            messages::propertyValueConflict(
                asyncResp->res, "RetryCountLimit",
                "Cannot configure when RetryEnable is false");
        }
        if (input.retryTimeInterval)
        {
            pefAnyFailure = true;
            messages::propertyValueConflict(
                asyncResp->res, "RetryTimeInterval",
                "Cannot configure when RetryEnable is false");
        }
        if (input.pendingAlertsLimit)
        {
            pefAnyFailure = true;
            messages::propertyValueConflict(
                asyncResp->res, "PendingAlertsLimit",
                "Cannot configure when RetryEnable is false");
        }
    }

    bool retryCountLimitValid = true;
    if (input.retryCountLimit)
    {
        if (*input.retryCountLimit < 0 || *input.retryCountLimit > 10)
        {
            retryCountLimitValid = false;
            pefAnyFailure = true;
            messages::propertyValueOutOfRange(
                asyncResp->res, *input.retryCountLimit, "RetryCountLimit");
        }
    }

    bool retryTimeIntervalValid = true;
    if (input.retryTimeInterval)
    {
        if (*input.retryTimeInterval < 0 || *input.retryTimeInterval > 3600)
        {
            retryTimeIntervalValid = false;
            pefAnyFailure = true;
            messages::propertyValueOutOfRange(
                asyncResp->res, *input.retryTimeInterval, "RetryTimeInterval");
        }
    }

    bool pendingAlertsLimitValid = true;
    if (input.pendingAlertsLimit)
    {
        if (*input.pendingAlertsLimit < 0 || *input.pendingAlertsLimit > 100)
        {
            pendingAlertsLimitValid = false;
            pefAnyFailure = true;
            messages::propertyValueOutOfRange(asyncResp->res,
                                              *input.pendingAlertsLimit,
                                              "PendingAlertsLimit");
        }
    }

    if (input.filterEnable)
    {
        bool filterEnableValid = true;
        if (input.filterEnable->size() != 18)
        {
            pefAnyFailure = true;
            messages::propertyValueIncorrect(
                asyncResp->res, "FilterEnable",
                "Array must contain exactly 18 elements");
            filterEnableValid = false;
        }
        else
        {
            // Check each element is 0 or 1
            for (uint8_t val : *input.filterEnable)
            {
                if (val != 0 && val != 1)
                {
                    pefAnyFailure = true;
                    messages::propertyValueIncorrect(
                        asyncResp->res, "FilterEnable",
                        "Each element must be 0 or 1");
                    filterEnableValid = false;
                    break;
                }
            }
        }
        if (filterEnableValid)
        {
            setFilterEnable(asyncResp, *input.filterEnable);
            pefAnySuccess = true;
        }
    }
    if (input.pefActionGblControl)
    {
        setPefConfParam(asyncResp, input.pefActionGblControl);
        pefAnySuccess = true;
    }
    if (input.retryEnable)
    {
        setRetryEnable(asyncResp, input.retryEnable);
        pefAnySuccess = true;
    }

    if (effectiveRetryEnable && input.retryCountLimit && retryCountLimitValid)
    {
        setRetryCountLimit(asyncResp, input.retryCountLimit);
        pefAnySuccess = true;
    }
    if (effectiveRetryEnable && input.retryTimeInterval &&
        retryTimeIntervalValid)
    {
        setRetryTimeInterval(asyncResp, input.retryTimeInterval);
        pefAnySuccess = true;
    }
    if (effectiveRetryEnable && input.pendingAlertsLimit &&
        pendingAlertsLimitValid)
    {
        setPendingAlertsLimit(asyncResp, input.pendingAlertsLimit);
        pefAnySuccess = true;
    }

    onComplete(pefAnyFailure, pefAnySuccess);
}

void getPefServiceInfo(crow::App& app, const crow::Request& req,
                       const std::shared_ptr<bmcweb::AsyncResp>& aResp)
{
    if (!redfish::setUpRedfishRoute(app, req, aResp))
    {
        return;
    }

    aResp->res.jsonValue = nlohmann::json{
        {"@odata.type", "#AmiPefService.v1_0_0.AmiPefService"},
        {"@odata.id", "/redfish/v1/Oem/Ami/PefService"},
        {"Id", "Pef Service"},
        {"Name", "Pef Service"},
        {"Description", "Pef Service Collections"},
        {"Members", nlohmann::json::array()}};

    getPefServiceMembers(aResp);
    getFilterEnable(aResp);
    getPefConfParam(aResp);
    getRetryConfiguration(aResp);
}

inline std::optional<uint8_t> getChannelNumberFromPolicyListName(
    const std::string& listName)
{
    std::optional<std::map<uint8_t, std::string>> channelMap =
        getChannelInterfaceMap();
    if (!channelMap)
    {
        return std::nullopt;
    }

    for (const auto& [channelNum, interfaceName] : *channelMap)
    {
        if (interfaceName == listName)
        {
            return channelNum;
        }
    }

    return std::nullopt;
}

inline std::optional<std::vector<uint8_t>> getEthChannelNumbers()
{
    std::optional<std::map<uint8_t, std::string>> channelMap =
        getChannelInterfaceMap();
    if (!channelMap)
    {
        return std::nullopt;
    }

    std::vector<uint8_t> channels;
    channels.reserve(channelMap->size());
    for (const auto& [channelNum, interfaceName] : *channelMap)
    {
        if (interfaceName.starts_with("eth"))
        {
            channels.push_back(channelNum);
        }
    }
    return channels;
}
inline void addAlertPolicyChannelMappings(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code& ec,
                    const std::map<uint8_t, std::string>& channelMap) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("GetChannelInterfaceMap failed: {}", ec);
                return;
            }

            nlohmann::json channelMappings = nlohmann::json::array();
            for (const auto& [channelNo, interfaceName] : channelMap)
            {
                if (!interfaceName.starts_with("eth"))
                {
                    continue;
                }

                channelMappings.push_back(
                    {{"ChannelNo", channelNo}, {"ChannelName", interfaceName}});
            }

            asyncResp->res.jsonValue["ChannelMappings"] =
                std::move(channelMappings);
            asyncResp->res.jsonValue["ChannelMappings@odata.count"] =
                asyncResp->res.jsonValue["ChannelMappings"].size();
        },
        "xyz.openbmc_project.User.Manager", "/xyz/openbmc_project/user",
        "xyz.openbmc_project.User.AccountPolicy", "GetChannelInterfaceMap");
}

inline void getAllAlertPolicyProperties(
    const std::shared_ptr<bmcweb::AsyncResp>& aResp,
    const std::string& listName, size_t entryIndex)
{
    dbus::utility::getAllProperties(
        pefAlertManagerService, std::string(pefAlertPolicyTablePath) + listName,
        pefAlertPolicyTableIface,
        [aResp,
         entryIndex](const boost::system::error_code& ec,
                     const dbus::utility::DBusPropertiesMap& propertiesList) {
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "D-BUS response error on AlertPolicyTable GetAll: {}", ec);
                return;
            }

            for (const auto& [key, variant] : propertiesList)
            {
                if (key == "EventSpecificAlertStr")
                {
                    auto value = getArrayElementAtIndex<std::string>(
                        variant, entryIndex);
                    if (value)
                    {
                        aResp->res.jsonValue[key] = *value;
                    }
                }
                else if (key == "AlertStingkey")
                {
                    auto value =
                        getArrayElementAtIndex<uint8_t>(variant, entryIndex);
                    if (value)
                    {
                        aResp->res.jsonValue["AlertStringKey"] = *value;
                    }
                }
                else
                {
                    auto value =
                        getArrayElementAtIndex<uint8_t>(variant, entryIndex);
                    if (value)
                    {
                        aResp->res.jsonValue[key] = *value;
                    }
                }
            }
        });
}

void getAlertPolicyTableCollection(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    asyncResp->res.jsonValue["@odata.type"] =
        "#AmiPefEntryCollection.AlertPolicyTable";
    asyncResp->res.jsonValue["@odata.id"] =
        "/redfish/v1/Oem/Ami/PefService/AlertPolicyTable";
    asyncResp->res.jsonValue["Name"] = "Alert Policy Table Collection";
    asyncResp->res.jsonValue["Description"] =
        "Collection of PEF Alert Policy Table entries";
    asyncResp->res.jsonValue["ChannelMappings"] = nlohmann::json::array();
    asyncResp->res.jsonValue["ChannelMappings@odata.count"] = 0;
    asyncResp->res.jsonValue["Members"] = nlohmann::json::array();

    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code ec,
                    const std::vector<std::string>& evnetList) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("AlertPolicyTable mapper call error");
                return;
            }

            for (const std::string& objpath : evnetList)
            {
                std::size_t lastPos = objpath.rfind('/');
                if (lastPos == std::string::npos ||
                    (objpath.size() <= lastPos + 1))
                {
                    BMCWEB_LOG_ERROR("Failed to parse path: {}", objpath);
                    continue;
                }

                const std::string listName = objpath.substr(lastPos + 1);
                if (!listName.starts_with("PolicyList_eth"))
                {
                    continue;
                }

                constexpr size_t alertPolicyEntriesPerList = 15;
                for (size_t entryIndex = 0;
                     entryIndex < alertPolicyEntriesPerList; entryIndex++)
                {
                    asyncResp->res.jsonValue["Members"].push_back(
                        {{"@odata.id",
                          "/redfish/v1/Oem/Ami/PefService/AlertPolicyTable/" +
                              listName + "_" + std::to_string(entryIndex)}});
                }
            }

            asyncResp->res.jsonValue["Members@odata.count"] =
                asyncResp->res.jsonValue["Members"].size();
            addAlertPolicyChannelMappings(asyncResp);
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths",
        pefAlertPolicyTablePath, 0,
        std::array<const char*, 1>{pefAlertPolicyTableIface});
}

void getAlertPolicyTableEntryInfo(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& entryId)
{
    std::string listName;
    size_t entryIndex = 0;
    if (!parseSubscriptionEntryId(entryId, EntryType::PolicyList, entryIndex,
                                  &listName))
    {
        messages::resourceNotFound(asyncResp->res, "AlertPolicyTable", entryId);
        return;
    }

    crow::connections::systemBus->async_method_call(
        [asyncResp, entryId, listName,
         entryIndex](const boost::system::error_code ec,
                     const std::vector<std::string>& evnetList) {
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "D-Bus call error while validating alert policy entry");
                asyncResp->res.result(
                    boost::beast::http::status::internal_server_error);
                return;
            }

            if (!isRequestedEntryListPresentInDbusPaths(entryId, evnetList))
            {
                messages::resourceNotFound(asyncResp->res, "AlertPolicyTable",
                                           entryId);
                return;
            }

            asyncResp->res.jsonValue = {
                {"@odata.type", "#AmiPefEntry.v1_0_0.AlertPolicyTable"},
                {"@odata.id",
                 "/redfish/v1/Oem/Ami/PefService/AlertPolicyTable/" + entryId},
                {"Id", entryId},
                {"Name", "PEF Alert Policy Entry"}};
            getAllAlertPolicyProperties(asyncResp, listName, entryIndex);
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths",
        pefAlertPolicyTablePath, 0,
        std::array<const char*, 1>{pefAlertPolicyTableIface});
}

template <typename T>
inline void setIndexedDbusProperty(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& service, const std::string& objectPath,
    const std::string& interface, const std::string& propertyName,
    const std::optional<T>& value, size_t entryIndex)
{
    if (!value)
    {
        return;
    }

    dbus::utility::getAllProperties(
        service, objectPath, interface,
        [asyncResp, service, objectPath, interface, propertyName, value,
         entryIndex](const boost::system::error_code& ec,
                     const dbus::utility::DBusPropertiesMap& propertiesList) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-BUS response error on GetAll for {}: {}",
                                 interface, ec);
                messages::internalError(asyncResp->res);
                return;
            }

            // Find the property in the returned map
            const std::vector<T>* currentValues = nullptr;
            for (const auto& [key, variant] : propertiesList)
            {
                if (key == propertyName)
                {
                    currentValues = std::get_if<std::vector<T>>(&variant);
                    break;
                }
            }

            if (currentValues == nullptr)
            {
                BMCWEB_LOG_ERROR("Property {} not found or has unexpected type",
                                 propertyName);
                messages::internalError(asyncResp->res);
                return;
            }

            if (entryIndex >= currentValues->size())
            {
                messages::propertyValueOutOfRange(
                    asyncResp->res, std::to_string(entryIndex), propertyName);
                return;
            }

            std::vector<T> updatedValues = *currentValues;
            updatedValues[entryIndex] = *value;
            sdbusplus::asio::setProperty(
                *crow::connections::systemBus, service, objectPath, interface,
                propertyName, updatedValues,
                [asyncResp,
                 propertyName](const boost::system::error_code& ec2) {
                    if (ec2)
                    {
                        BMCWEB_LOG_ERROR("D-BUS response error on {} Set: {}",
                                         propertyName, ec2);
                        messages::internalError(asyncResp->res);
                    }
                });
        });
}

template <typename T>
inline void setIndexedDbusPropertyValue(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& service, const std::string& objectPath,
    const std::string& interface, std::string propertyName, const T& value,
    size_t entryIndex,
    const std::shared_ptr<std::function<void(bool)>>& onComplete)
{
    dbus::utility::getProperty<std::vector<T>>(
        service, objectPath, interface, propertyName,
        [asyncResp, service, objectPath, interface, propertyName, value,
         entryIndex, onComplete](const boost::system::error_code& ec,
                                 const std::vector<T>& currentValues) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-BUS response error on Get {} {}: {}",
                                 interface, propertyName, ec);
                (*onComplete)(false);
                return;
            }

            if (entryIndex >= currentValues.size())
            {
                BMCWEB_LOG_ERROR(
                    "Entry index {} out of range for {} (size: {})", entryIndex,
                    propertyName, currentValues.size());
                (*onComplete)(false);
                return;
            }

            std::vector<T> updatedValues = currentValues;
            updatedValues[entryIndex] = value;
            sdbusplus::asio::setProperty(
                *crow::connections::systemBus, service, objectPath, interface,
                propertyName, updatedValues,
                [asyncResp, propertyName, value,
                 onComplete](const boost::system::error_code& ec2) {
                    if (ec2)
                    {
                        BMCWEB_LOG_ERROR("D-BUS response error on {} Set: {}",
                                         propertyName, ec2);

                        if (ec2.value() == EINVAL)
                        {
                            if constexpr (std::is_integral_v<T>)
                            {
                                messages::propertyValueOutOfRange(
                                    asyncResp->res,
                                    static_cast<uint64_t>(value), propertyName);
                            }
                            else
                            {
                                messages::propertyValueIncorrect(
                                    asyncResp->res, propertyName, propertyName);
                            }
                        }

                        (*onComplete)(false);
                        return;
                    }
                    (*onComplete)(true);
                });
        });
}

template <typename T>
inline bool validatePatchRange(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::optional<T>& value, std::type_identity_t<T> max,
    std::string_view propertyName)
{
    if (!value)
    {
        return true;
    }

    if (*value > max)
    {
        messages::propertyValueOutOfRange(
            asyncResp->res, static_cast<uint64_t>(*value), propertyName);
        return false;
    }
    return true;
}

inline bool validateEventSeverityPatch(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::optional<std::string>& eventSeverityString,
    std::optional<uint8_t>& eventSeverity)
{
    if (!eventSeverityString)
    {
        return true;
    }

    auto it = stringToSeverity.find(*eventSeverityString);
    if (it == stringToSeverity.end())
    {
        messages::propertyValueNotInList(asyncResp->res, *eventSeverityString,
                                         "EventSeverity");
        return false;
    }

    eventSeverity = it->second;
    return true;
}

void getEventFilterTableEntryInfo(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& entryId)
{
    size_t entryIndex = 0;
    if (!parseSubscriptionEntryId(entryId, EntryType::List, entryIndex))
    {
        messages::resourceNotFound(asyncResp->res, "EventFilterTable", entryId);
        return;
    }

    crow::connections::systemBus->async_method_call(
        [asyncResp, entryId,
         entryIndex](const boost::system::error_code ec,
                     const std::vector<std::string>& evnetList) {
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "D-Bus call error while validating event entry");
                asyncResp->res.result(
                    boost::beast::http::status::internal_server_error);
                return;
            }

            if (!isRequestedEntryListPresentInDbusPaths(entryId, evnetList))
            {
                messages::resourceNotFound(asyncResp->res, "EventFilterTable",
                                           entryId);
                return;
            }

            const std::string listName = entryId.substr(0, entryId.rfind('_'));

            asyncResp->res.jsonValue = {
                {"@odata.type", "#AmiPefEntry.v1_0_0.EventFilterTable"},
                {"@odata.id",
                 "/redfish/v1/Oem/Ami/PefService/EventFilterTable/" + entryId},
                {"Id", entryId},
                {"Name", "Pef Event Filter Entry"}};
            getAllEventFilterProperties(asyncResp, listName, entryIndex);
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths",
        pefEventFilterTablePath, 0,
        std::array<const char*, 1>{pefEventFilterTableIface});
}

inline void handleEventFilterTableEntryPatch(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const crow::Request& req, const std::string& entryId)
{
    size_t entryIndex = 0;
    if (!parseSubscriptionEntryId(entryId, EntryType::List, entryIndex))
    {
        messages::resourceNotFound(asyncResp->res, "EventFilterTable", entryId);
        return;
    }

    crow::connections::systemBus->async_method_call(
        [asyncResp, req, entryId,
         entryIndex](const boost::system::error_code ec,
                     const std::vector<std::string>& evnetList) {
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "D-Bus call error while validating event entry");
                asyncResp->res.result(
                    boost::beast::http::status::internal_server_error);
                return;
            }

            if (!isRequestedEntryListPresentInDbusPaths(entryId, evnetList))
            {
                messages::resourceNotFound(asyncResp->res, "EventFilterTable",
                                           entryId);
                return;
            }

            const std::string listName = entryId.substr(0, entryId.rfind('_'));

            std::optional<uint8_t> alertPolicyNum;
            std::optional<uint8_t> eventData1AndMask;
            std::optional<uint8_t> eventData1Cmp1;
            std::optional<uint8_t> eventData1Cmp2;
            std::optional<uint16_t> eventData1OffsetMask;
            std::optional<uint8_t> eventData2AndMask;
            std::optional<uint8_t> eventData2Cmp1;
            std::optional<uint8_t> eventData2Cmp2;
            std::optional<uint8_t> eventData3AndMask;
            std::optional<uint8_t> eventData3Cmp1;
            std::optional<uint8_t> eventData3Cmp2;
            std::optional<uint8_t> eventFilterTableEntry;
            std::optional<std::string> eventSeverityString;
            std::optional<uint8_t> eventSeverity;
            std::optional<uint8_t> eventTrigger;
            std::optional<uint8_t> evtFilterAction;
            std::optional<uint8_t> filterConfig;
            std::optional<uint8_t> genIdByte1;
            std::optional<uint8_t> genIdByte2;
            std::optional<std::string> selectedSensorType;
            std::optional<std::string> selectedSensorName;

            if (!json_util::readJsonPatch(
                    req, asyncResp->res, "AlertPolicyNum", alertPolicyNum,
                    "EventData1ANDMask", eventData1AndMask, "EventData1Cmp1",
                    eventData1Cmp1, "EventData1Cmp2", eventData1Cmp2,
                    "EventData1OffsetMask", eventData1OffsetMask,
                    "EventData2ANDMask", eventData2AndMask, "EventData2Cmp1",
                    eventData2Cmp1, "EventData2Cmp2", eventData2Cmp2,
                    "EventData3ANDMask", eventData3AndMask, "EventData3Cmp1",
                    eventData3Cmp1, "EventData3Cmp2", eventData3Cmp2,
                    "EventFilterTableEntry", eventFilterTableEntry,
                    "EventSeverity", eventSeverityString, "EventTrigger",
                    eventTrigger, "EvtFilterAction", evtFilterAction,
                    "FilterConfig", filterConfig, "GenIDByte1", genIdByte1,
                    "GenIDByte2", genIdByte2, "SensorType", selectedSensorType,
                    "SensorName", selectedSensorName))
            {
                return;
            }

            if (selectedSensorType.has_value() !=
                selectedSensorName.has_value())
            {
                messages::propertyMissing(
                    asyncResp->res,
                    !selectedSensorType ? "SensorType" : "SensorName");
                return;
            }

            bool valid = true;
            valid &= validatePatchRange(asyncResp, alertPolicyNum, 127,
                                        "AlertPolicyNum");
            valid &= validatePatchRange(asyncResp, eventData1AndMask, 255,
                                        "EventData1ANDMask");
            valid &= validatePatchRange(asyncResp, eventData1Cmp1, 255,
                                        "EventData1Cmp1");
            valid &= validatePatchRange(asyncResp, eventData1Cmp2, 255,
                                        "EventData1Cmp2");
            valid &= validatePatchRange(asyncResp, eventData1OffsetMask, 65535,
                                        "EventData1OffsetMask");
            valid &= validatePatchRange(asyncResp, eventData2AndMask, 255,
                                        "EventData2ANDMask");
            valid &= validatePatchRange(asyncResp, eventData2Cmp1, 255,
                                        "EventData2Cmp1");
            valid &= validatePatchRange(asyncResp, eventData2Cmp2, 255,
                                        "EventData2Cmp2");
            valid &= validatePatchRange(asyncResp, eventData3AndMask, 255,
                                        "EventData3ANDMask");
            valid &= validatePatchRange(asyncResp, eventData3Cmp1, 255,
                                        "EventData3Cmp1");
            valid &= validatePatchRange(asyncResp, eventData3Cmp2, 255,
                                        "EventData3Cmp2");
            valid &= validatePatchRange(asyncResp, eventFilterTableEntry, 40,
                                        "EventFilterTableEntry");
            valid &= validatePatchRange(asyncResp, eventTrigger, 255,
                                        "EventTrigger");
            valid &= validatePatchRange(asyncResp, evtFilterAction, 127,
                                        "EvtFilterAction");
            valid &=
                validatePatchRange(asyncResp, genIdByte1, 255, "GenIDByte1");
            valid &=
                validatePatchRange(asyncResp, genIdByte2, 255, "GenIDByte2");
            valid &= validateEventSeverityPatch(asyncResp, eventSeverityString,
                                                eventSeverity);

            if (filterConfig && *filterConfig != 0 && *filterConfig != 64 &&
                *filterConfig != 128 && *filterConfig != 192)
            {
                messages::propertyValueNotInList(
                    asyncResp->res, static_cast<uint64_t>(*filterConfig),
                    "FilterConfig");
                valid = false;
            }

            if (!valid)
            {
                return;
            }

            const std::string objectPath =
                std::string(pefEventFilterTablePath) + listName;

            size_t propertyCount = 0;
            propertyCount += alertPolicyNum.has_value() ? 1U : 0U;
            propertyCount += eventData1AndMask.has_value() ? 1U : 0U;
            propertyCount += eventData1Cmp1.has_value() ? 1U : 0U;
            propertyCount += eventData1Cmp2.has_value() ? 1U : 0U;
            propertyCount += eventData1OffsetMask.has_value() ? 1U : 0U;
            propertyCount += eventData2AndMask.has_value() ? 1U : 0U;
            propertyCount += eventData2Cmp1.has_value() ? 1U : 0U;
            propertyCount += eventData2Cmp2.has_value() ? 1U : 0U;
            propertyCount += eventData3AndMask.has_value() ? 1U : 0U;
            propertyCount += eventData3Cmp1.has_value() ? 1U : 0U;
            propertyCount += eventData3Cmp2.has_value() ? 1U : 0U;
            propertyCount += eventFilterTableEntry.has_value() ? 1U : 0U;
            propertyCount += eventSeverity.has_value() ? 1U : 0U;
            propertyCount += eventTrigger.has_value() ? 1U : 0U;
            propertyCount += evtFilterAction.has_value() ? 1U : 0U;
            propertyCount += filterConfig.has_value() ? 1U : 0U;
            propertyCount += genIdByte1.has_value() ? 1U : 0U;
            propertyCount += genIdByte2.has_value() ? 1U : 0U;
            propertyCount += selectedSensorType.has_value() ? 2U : 0U;

            if (propertyCount == 0)
            {
                asyncResp->res.result(boost::beast::http::status::no_content);
                return;
            }

            // Fan-out completion gate for parallel async writes.
            // Example: if 3 properties are PATCHed and one callback fails
            // first, done=true freezes the final error response so later
            // callbacks cannot overwrite it. If all 3 succeed, pending
            // counts down 3->0 and we return 204 once.
            auto pending = std::make_shared<size_t>(propertyCount);
            auto done = std::make_shared<bool>(false);
            auto onComplete = std::make_shared<std::function<void(bool)>>(
                [asyncResp, pending, done](bool success) {
                    if (*done)
                    {
                        return;
                    }

                    if (!success)
                    {
                        *done = true;
                        // Preserve any specific error generated earlier
                        // (for example propertyValueOutOfRange) and only
                        // fallback to internalError when none was set.
                        if (asyncResp->res.jsonValue.empty())
                        {
                            messages::internalError(asyncResp->res);
                        }
                        return;
                    }

                    (*pending)--;
                    if (*pending == 0)
                    {
                        *done = true;
                        asyncResp->res.result(
                            boost::beast::http::status::no_content);
                    }
                });

            if (alertPolicyNum)
            {
                setIndexedDbusPropertyValue<uint8_t>(
                    asyncResp, pefAlertManagerService, objectPath,
                    pefEventFilterTableIface, "AlertPolicyNum", *alertPolicyNum,
                    entryIndex, onComplete);
            }
            if (eventData1AndMask)
            {
                setIndexedDbusPropertyValue<uint8_t>(
                    asyncResp, pefAlertManagerService, objectPath,
                    pefEventFilterTableIface, "EventData1ANDMask",
                    *eventData1AndMask, entryIndex, onComplete);
            }
            if (eventData1Cmp1)
            {
                setIndexedDbusPropertyValue<uint8_t>(
                    asyncResp, pefAlertManagerService, objectPath,
                    pefEventFilterTableIface, "EventData1Cmp1", *eventData1Cmp1,
                    entryIndex, onComplete);
            }
            if (eventData1Cmp2)
            {
                setIndexedDbusPropertyValue<uint8_t>(
                    asyncResp, pefAlertManagerService, objectPath,
                    pefEventFilterTableIface, "EventData1Cmp2", *eventData1Cmp2,
                    entryIndex, onComplete);
            }
            if (eventData1OffsetMask)
            {
                setIndexedDbusPropertyValue<uint16_t>(
                    asyncResp, pefAlertManagerService, objectPath,
                    pefEventFilterTableIface, "EventData1OffsetMask",
                    *eventData1OffsetMask, entryIndex, onComplete);
            }
            if (eventData2AndMask)
            {
                setIndexedDbusPropertyValue<uint8_t>(
                    asyncResp, pefAlertManagerService, objectPath,
                    pefEventFilterTableIface, "EventData2ANDMask",
                    *eventData2AndMask, entryIndex, onComplete);
            }
            if (eventData2Cmp1)
            {
                setIndexedDbusPropertyValue<uint8_t>(
                    asyncResp, pefAlertManagerService, objectPath,
                    pefEventFilterTableIface, "EventData2Cmp1", *eventData2Cmp1,
                    entryIndex, onComplete);
            }
            if (eventData2Cmp2)
            {
                setIndexedDbusPropertyValue<uint8_t>(
                    asyncResp, pefAlertManagerService, objectPath,
                    pefEventFilterTableIface, "EventData2Cmp2", *eventData2Cmp2,
                    entryIndex, onComplete);
            }
            if (eventData3AndMask)
            {
                setIndexedDbusPropertyValue<uint8_t>(
                    asyncResp, pefAlertManagerService, objectPath,
                    pefEventFilterTableIface, "EventData3ANDMask",
                    *eventData3AndMask, entryIndex, onComplete);
            }
            if (eventData3Cmp1)
            {
                setIndexedDbusPropertyValue<uint8_t>(
                    asyncResp, pefAlertManagerService, objectPath,
                    pefEventFilterTableIface, "EventData3Cmp1", *eventData3Cmp1,
                    entryIndex, onComplete);
            }
            if (eventData3Cmp2)
            {
                setIndexedDbusPropertyValue<uint8_t>(
                    asyncResp, pefAlertManagerService, objectPath,
                    pefEventFilterTableIface, "EventData3Cmp2", *eventData3Cmp2,
                    entryIndex, onComplete);
            }
            if (eventFilterTableEntry)
            {
                setIndexedDbusPropertyValue<uint8_t>(
                    asyncResp, pefAlertManagerService, objectPath,
                    pefEventFilterTableIface, "EventFilterTableEntry",
                    *eventFilterTableEntry, entryIndex, onComplete);
            }
            if (eventSeverity)
            {
                setIndexedDbusPropertyValue<uint8_t>(
                    asyncResp, pefAlertManagerService, objectPath,
                    pefEventFilterTableIface, "EventSeverity", *eventSeverity,
                    entryIndex, onComplete);
            }
            if (eventTrigger)
            {
                setIndexedDbusPropertyValue<uint8_t>(
                    asyncResp, pefAlertManagerService, objectPath,
                    pefEventFilterTableIface, "EventTrigger", *eventTrigger,
                    entryIndex, onComplete);
            }
            if (evtFilterAction)
            {
                setIndexedDbusPropertyValue<uint8_t>(
                    asyncResp, pefAlertManagerService, objectPath,
                    pefEventFilterTableIface, "EvtFilterAction",
                    *evtFilterAction, entryIndex, onComplete);
            }
            if (filterConfig)
            {
                setIndexedDbusPropertyValue<uint8_t>(
                    asyncResp, pefAlertManagerService, objectPath,
                    pefEventFilterTableIface, "FilterConfig", *filterConfig,
                    entryIndex, onComplete);
            }
            if (genIdByte1)
            {
                setIndexedDbusPropertyValue<uint8_t>(
                    asyncResp, pefAlertManagerService, objectPath,
                    pefEventFilterTableIface, "GenIDByte1", *genIdByte1,
                    entryIndex, onComplete);
            }
            if (genIdByte2)
            {
                setIndexedDbusPropertyValue<uint8_t>(
                    asyncResp, pefAlertManagerService, objectPath,
                    pefEventFilterTableIface, "GenIDByte2", *genIdByte2,
                    entryIndex, onComplete);
            }

            // if no SensorType/SensorName in the payload, skip the extra
            // lookups and just return now.
            if (!selectedSensorType || !selectedSensorName)
            {
                return;
            }

            getAvailableSensorTypeMap(
                asyncResp, [asyncResp, objectPath, entryIndex, onComplete,
                            selectedType{*selectedSensorType},
                            selectedName{*selectedSensorName}](
                               const std::map<std::string, uint8_t>& typeMap) {
                    auto typeIt = typeMap.find(selectedType);
                    if (typeIt == typeMap.end())
                    {
                        messages::propertyValueNotInList(
                            asyncResp->res, selectedType, "SensorType");
                        (*onComplete)(false);
                        return;
                    }

                    uint8_t sensorTypeId = typeIt->second;

                    setIndexedDbusPropertyValue<uint8_t>(
                        asyncResp, pefAlertManagerService, objectPath,
                        pefEventFilterTableIface, "SensorType", sensorTypeId,
                        entryIndex, onComplete);

                    getSensorNumNameMapForType(
                        asyncResp, selectedType,
                        [asyncResp, objectPath, entryIndex, onComplete,
                         selectedName](
                            const std::map<uint8_t, std::string>& mapResp) {
                            auto matchIt = std::ranges::find_if(
                                mapResp, [&selectedName](const auto& pair) {
                                    return pair.second == selectedName;
                                });

                            if (matchIt == mapResp.end())
                            {
                                messages::propertyValueNotInList(
                                    asyncResp->res, selectedName, "SensorName");
                                (*onComplete)(false);
                                return;
                            }

                            setIndexedDbusPropertyValue<uint8_t>(
                                asyncResp, pefAlertManagerService, objectPath,
                                pefEventFilterTableIface, "SensorNum",
                                matchIt->first, entryIndex, onComplete);
                        });
                });
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths",
        pefEventFilterTablePath, 0,
        std::array<const char*, 1>{pefEventFilterTableIface});
}

inline void handleAlertPolicyTableEntryPatch(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const crow::Request& req, const std::string& entryId)
{
    std::string listName;
    size_t entryIndex = 0;
    if (!parseSubscriptionEntryId(entryId, EntryType::PolicyList, entryIndex,
                                  &listName))
    {
        messages::resourceNotFound(asyncResp->res, "AlertPolicyTable", entryId);
        return;
    }

    crow::connections::systemBus->async_method_call(
        [asyncResp, req, entryId, listName,
         entryIndex](const boost::system::error_code ec,
                     const std::vector<std::string>& evnetList) {
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "D-Bus call error while validating alert policy entry");
                asyncResp->res.result(
                    boost::beast::http::status::internal_server_error);
                return;
            }

            if (!isRequestedEntryListPresentInDbusPaths(entryId, evnetList))
            {
                messages::resourceNotFound(asyncResp->res, "AlertPolicyTable",
                                           entryId);
                return;
            }

            std::optional<uint8_t> alertPolicyGroupNum;
            std::optional<uint8_t> channelNo;
            std::optional<uint8_t> destinationSel;
            std::optional<uint8_t> enableAlert;
            std::optional<uint8_t> policyAction;

            if (!json_util::readJsonPatch(
                    req, asyncResp->res, "AlertPolicyGroupNum",
                    alertPolicyGroupNum, "ChannelNo", channelNo,
                    "DestinationSel", destinationSel, "EnableAlert",
                    enableAlert, "PolicyAction", policyAction))
            {
                return;
            }

            bool valid = true;
            valid &= validatePatchRange(asyncResp, alertPolicyGroupNum, 15,
                                        "AlertPolicyGroupNum");
            valid &=
                validatePatchRange(asyncResp, enableAlert, 1, "EnableAlert");
            valid &=
                validatePatchRange(asyncResp, policyAction, 4, "PolicyAction");
            valid &= validatePatchRange(asyncResp, destinationSel, 15,
                                        "DestinationSel");

            // ChannelNo is platform-dependent. Accept any eth-backed
            // channel from GetChannelInterfaceMap rather than forcing it to
            // match the current PolicyList_ethX name.
            if (channelNo)
            {
                std::optional<std::vector<uint8_t>> validChannels =
                    getEthChannelNumbers();
                if (validChannels &&
                    std::ranges::find(*validChannels, *channelNo) ==
                        validChannels->end())
                {
                    messages::propertyValueNotInList(
                        asyncResp->res, static_cast<uint64_t>(*channelNo),
                        "ChannelNo");
                    valid = false;
                }
            }

            if (!valid)
            {
                return;
            }

            const std::string objectPath =
                std::string(pefAlertPolicyTablePath) + listName;

            size_t propertyCount = 0;
            propertyCount += alertPolicyGroupNum.has_value() ? 1U : 0U;
            propertyCount += channelNo.has_value() ? 1U : 0U;
            propertyCount += destinationSel.has_value() ? 1U : 0U;
            propertyCount += enableAlert.has_value() ? 1U : 0U;
            propertyCount += policyAction.has_value() ? 1U : 0U;

            if (propertyCount == 0)
            {
                asyncResp->res.result(boost::beast::http::status::no_content);
                return;
            }

            // Fan-out completion gate for parallel async writes.
            // Example: 5 property updates start together; the first failure
            // sets done=true and fixes the error response, while all-success
            // completion decrements pending to zero and returns 204 once.
            auto pending = std::make_shared<size_t>(propertyCount);
            auto done = std::make_shared<bool>(false);
            auto onComplete = std::make_shared<std::function<void(bool)>>(
                [asyncResp, pending, done](bool success) {
                    if (*done)
                    {
                        return;
                    }

                    if (!success)
                    {
                        *done = true;
                        // Preserve any specific error generated earlier
                        // (for example propertyValueOutOfRange) and only
                        // fallback to internalError when none was set.
                        if (asyncResp->res.jsonValue.empty())
                        {
                            messages::internalError(asyncResp->res);
                        }
                        return;
                    }

                    (*pending)--;
                    if (*pending == 0)
                    {
                        *done = true;
                        asyncResp->res.result(
                            boost::beast::http::status::no_content);
                    }
                });

            if (alertPolicyGroupNum)
            {
                setIndexedDbusPropertyValue<uint8_t>(
                    asyncResp, pefAlertManagerService, objectPath,
                    pefAlertPolicyTableIface, "AlertPolicyGroupNum",
                    *alertPolicyGroupNum, entryIndex, onComplete);
            }
            if (channelNo)
            {
                setIndexedDbusPropertyValue<uint8_t>(
                    asyncResp, pefAlertManagerService, objectPath,
                    pefAlertPolicyTableIface, "ChannelNo", *channelNo,
                    entryIndex, onComplete);
            }
            if (destinationSel)
            {
                setIndexedDbusPropertyValue<uint8_t>(
                    asyncResp, pefAlertManagerService, objectPath,
                    pefAlertPolicyTableIface, "DestinationSel", *destinationSel,
                    entryIndex, onComplete);
            }
            if (enableAlert)
            {
                setIndexedDbusPropertyValue<uint8_t>(
                    asyncResp, pefAlertManagerService, objectPath,
                    pefAlertPolicyTableIface, "EnableAlert", *enableAlert,
                    entryIndex, onComplete);
            }
            if (policyAction)
            {
                setIndexedDbusPropertyValue<uint8_t>(
                    asyncResp, pefAlertManagerService, objectPath,
                    pefAlertPolicyTableIface, "PolicyAction", *policyAction,
                    entryIndex, onComplete);
            }
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths",
        pefAlertPolicyTablePath, 0,
        std::array<const char*, 1>{pefAlertPolicyTableIface});
}

inline void handleEventFilterTableEntryDelete(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& entryId)
{
    size_t entryIndex = 0;
    if (!parseSubscriptionEntryId(entryId, EntryType::List, entryIndex))
    {
        messages::resourceNotFound(asyncResp->res, "EventFilterTable", entryId);
        return;
    }

    crow::connections::systemBus->async_method_call(
        [asyncResp, entryId,
         entryIndex](const boost::system::error_code ec,
                     const std::vector<std::string>& evnetList) {
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "D-Bus call error while validating event filter delete");
                asyncResp->res.result(
                    boost::beast::http::status::internal_server_error);
                return;
            }

            if (!isRequestedEntryListPresentInDbusPaths(entryId, evnetList))
            {
                messages::resourceNotFound(asyncResp->res, "EventFilterTable",
                                           entryId);
                return;
            }

            const std::string listName = entryId.substr(0, entryId.rfind('_'));

            const std::string objectPath =
                std::string(pefEventFilterTablePath) + listName;

            auto pending = std::make_shared<size_t>(20);
            auto done = std::make_shared<bool>(false);

            auto onComplete = std::make_shared<std::function<void(bool)>>(
                [asyncResp, pending, done](bool success) {
                    if (*done)
                    {
                        return;
                    }

                    if (!success)
                    {
                        *done = true;
                        if (asyncResp->res.jsonValue.empty())
                        {
                            messages::internalError(asyncResp->res);
                        }
                        return;
                    }

                    (*pending)--;
                    if (*pending == 0)
                    {
                        *done = true;
                        asyncResp->res.result(
                            boost::beast::http::status::no_content);
                    }
                });

            setIndexedDbusPropertyValue<uint8_t>(
                asyncResp, pefAlertManagerService, objectPath,
                pefEventFilterTableIface, "AlertPolicyNum", 0, entryIndex,
                onComplete);
            setIndexedDbusPropertyValue<uint8_t>(
                asyncResp, pefAlertManagerService, objectPath,
                pefEventFilterTableIface, "EventData1ANDMask", 0, entryIndex,
                onComplete);
            setIndexedDbusPropertyValue<uint8_t>(
                asyncResp, pefAlertManagerService, objectPath,
                pefEventFilterTableIface, "EventData1Cmp1", 0, entryIndex,
                onComplete);
            setIndexedDbusPropertyValue<uint8_t>(
                asyncResp, pefAlertManagerService, objectPath,
                pefEventFilterTableIface, "EventData1Cmp2", 0, entryIndex,
                onComplete);
            setIndexedDbusPropertyValue<uint16_t>(
                asyncResp, pefAlertManagerService, objectPath,
                pefEventFilterTableIface, "EventData1OffsetMask", 0, entryIndex,
                onComplete);
            setIndexedDbusPropertyValue<uint8_t>(
                asyncResp, pefAlertManagerService, objectPath,
                pefEventFilterTableIface, "EventData2ANDMask", 0, entryIndex,
                onComplete);
            setIndexedDbusPropertyValue<uint8_t>(
                asyncResp, pefAlertManagerService, objectPath,
                pefEventFilterTableIface, "EventData2Cmp1", 0, entryIndex,
                onComplete);
            setIndexedDbusPropertyValue<uint8_t>(
                asyncResp, pefAlertManagerService, objectPath,
                pefEventFilterTableIface, "EventData2Cmp2", 0, entryIndex,
                onComplete);
            setIndexedDbusPropertyValue<uint8_t>(
                asyncResp, pefAlertManagerService, objectPath,
                pefEventFilterTableIface, "EventData3ANDMask", 0, entryIndex,
                onComplete);
            setIndexedDbusPropertyValue<uint8_t>(
                asyncResp, pefAlertManagerService, objectPath,
                pefEventFilterTableIface, "EventData3Cmp1", 0, entryIndex,
                onComplete);
            setIndexedDbusPropertyValue<uint8_t>(
                asyncResp, pefAlertManagerService, objectPath,
                pefEventFilterTableIface, "EventData3Cmp2", 0, entryIndex,
                onComplete);
            setIndexedDbusPropertyValue<uint8_t>(
                asyncResp, pefAlertManagerService, objectPath,
                pefEventFilterTableIface, "EventFilterTableEntry", 1,
                entryIndex, onComplete);
            setIndexedDbusPropertyValue<uint8_t>(
                asyncResp, pefAlertManagerService, objectPath,
                pefEventFilterTableIface, "EventSeverity", 2, entryIndex,
                onComplete);
            setIndexedDbusPropertyValue<uint8_t>(
                asyncResp, pefAlertManagerService, objectPath,
                pefEventFilterTableIface, "EventTrigger", 0, entryIndex,
                onComplete);
            setIndexedDbusPropertyValue<uint8_t>(
                asyncResp, pefAlertManagerService, objectPath,
                pefEventFilterTableIface, "EvtFilterAction", 0, entryIndex,
                onComplete);
            setIndexedDbusPropertyValue<uint8_t>(
                asyncResp, pefAlertManagerService, objectPath,
                pefEventFilterTableIface, "FilterConfig", 0, entryIndex,
                onComplete);
            setIndexedDbusPropertyValue<uint8_t>(
                asyncResp, pefAlertManagerService, objectPath,
                pefEventFilterTableIface, "GenIDByte1", 0, entryIndex,
                onComplete);
            setIndexedDbusPropertyValue<uint8_t>(
                asyncResp, pefAlertManagerService, objectPath,
                pefEventFilterTableIface, "GenIDByte2", 0, entryIndex,
                onComplete);
            setIndexedDbusPropertyValue<uint8_t>(
                asyncResp, pefAlertManagerService, objectPath,
                pefEventFilterTableIface, "SensorNum", 255, entryIndex,
                onComplete);
            setIndexedDbusPropertyValue<uint8_t>(
                asyncResp, pefAlertManagerService, objectPath,
                pefEventFilterTableIface, "SensorType", 255, entryIndex,
                onComplete);
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths",
        pefEventFilterTablePath, 0,
        std::array<const char*, 1>{pefEventFilterTableIface});
}

inline void handleAlertPolicyTableEntryDelete(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& entryId)
{
    std::string listName;
    size_t entryIndex = 0;
    if (!parseSubscriptionEntryId(entryId, EntryType::PolicyList, entryIndex,
                                  &listName))
    {
        messages::resourceNotFound(asyncResp->res, "AlertPolicyTable", entryId);
        return;
    }

    crow::connections::systemBus->async_method_call(
        [asyncResp, entryId, listName,
         entryIndex](const boost::system::error_code ec,
                     const std::vector<std::string>& evnetList) {
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "D-Bus call error while validating alert policy delete");
                asyncResp->res.result(
                    boost::beast::http::status::internal_server_error);
                return;
            }

            if (!isRequestedEntryListPresentInDbusPaths(entryId, evnetList))
            {
                messages::resourceNotFound(asyncResp->res, "AlertPolicyTable",
                                           entryId);
                return;
            }

            const std::string objectPath =
                std::string(pefAlertPolicyTablePath) + listName;
            const uint8_t mappedChannelNo =
                getChannelNumberFromPolicyListName(listName).value_or(1);

            constexpr size_t propertyCount = 5;

            auto pending = std::make_shared<size_t>(propertyCount);
            auto done = std::make_shared<bool>(false);
            auto onComplete = std::make_shared<std::function<void(bool)>>(
                [asyncResp, pending, done](bool success) {
                    if (*done)
                    {
                        return;
                    }

                    if (!success)
                    {
                        *done = true;
                        if (asyncResp->res.jsonValue.empty())
                        {
                            messages::internalError(asyncResp->res);
                        }
                        return;
                    }

                    (*pending)--;
                    if (*pending == 0)
                    {
                        *done = true;
                        asyncResp->res.result(
                            boost::beast::http::status::no_content);
                    }
                });

            setIndexedDbusPropertyValue<uint8_t>(
                asyncResp, pefAlertManagerService, objectPath,
                pefAlertPolicyTableIface, "AlertPolicyGroupNum",
                static_cast<uint8_t>(entryIndex + 1U), entryIndex, onComplete);
            setIndexedDbusPropertyValue<uint8_t>(
                asyncResp, pefAlertManagerService, objectPath,
                pefAlertPolicyTableIface, "ChannelNo",
                static_cast<uint8_t>((entryIndex == 0U) ? mappedChannelNo : 1U),
                entryIndex, onComplete);
            setIndexedDbusPropertyValue<uint8_t>(
                asyncResp, pefAlertManagerService, objectPath,
                pefAlertPolicyTableIface, "DestinationSel",
                static_cast<uint8_t>((entryIndex == 0U) ? 1U : 0U), entryIndex,
                onComplete);
            setIndexedDbusPropertyValue<uint8_t>(
                asyncResp, pefAlertManagerService, objectPath,
                pefAlertPolicyTableIface, "EnableAlert",
                static_cast<uint8_t>((entryIndex == 0U) ? 1U : 0U), entryIndex,
                onComplete);
            setIndexedDbusPropertyValue<uint8_t>(
                asyncResp, pefAlertManagerService, objectPath,
                pefAlertPolicyTableIface, "PolicyAction",
                static_cast<uint8_t>((entryIndex == 0U) ? 1U : 0U), entryIndex,
                onComplete);
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths",
        pefAlertPolicyTablePath, 0,
        std::array<const char*, 1>{pefAlertPolicyTableIface});
}

void getEventFilterTableCollection(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    asyncResp->res.jsonValue["@odata.type"] =
        "#AmiPefEntryCollection.EventFilterTable";
    asyncResp->res.jsonValue["@odata.id"] =
        "/redfish/v1/Oem/Ami/PefService/EventFilterTable";
    asyncResp->res.jsonValue["Name"] = "Event Filter Table Collection";
    asyncResp->res.jsonValue["Description"] =
        "Collection of PEF Event Filter Table entries";
    asyncResp->res.jsonValue["Members"] = nlohmann::json::array();
    addEventFilterSensorDetails(asyncResp);

    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code ec,
                    const std::vector<std::string>& evnetList) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("EventFilterTable mapper call error");
                return;
            }
            for (const std::string& objpath : evnetList)
            {
                std::size_t lastPos = objpath.rfind('/');
                if (lastPos == std::string::npos ||
                    (objpath.size() <= lastPos + 1))
                {
                    BMCWEB_LOG_ERROR("Failed to parse path: {}", objpath);
                    continue;
                }

                const std::string listName = objpath.substr(lastPos + 1);
                if (!listName.starts_with("List"))
                {
                    continue;
                }

                constexpr size_t eventFilterEntriesPerService = 10;
                for (size_t entryIndex = 0;
                     entryIndex < eventFilterEntriesPerService; entryIndex++)
                {
                    std::string entryId =
                        listName + "_" + std::to_string(entryIndex);

                    asyncResp->res.jsonValue["Members"].push_back(
                        {{"@odata.id",
                          "/redfish/v1/Oem/Ami/PefService/EventFilterTable/" +
                              entryId}});
                }
            }

            asyncResp->res.jsonValue["Members@odata.count"] =
                asyncResp->res.jsonValue["Members"].size();
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths",
        pefEventFilterTablePath, 0,
        std::array<const char*, 1>{pefEventFilterTableIface});
}

inline void requestRoutesPefService(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Oem/Ami/PefService/")
        .privileges(redfish::privileges::getPefService)
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& aResp) {
                getPefServiceInfo(app, req, aResp);
            });

    BMCWEB_ROUTE(app, "/redfish/v1/Oem/Ami/PefService/")
        .privileges(redfish::privileges::patchPefService)
        .methods(
            boost::beast::http::verb::
                patch)([&app](const crow::Request& req,
                              const std::shared_ptr<bmcweb::AsyncResp>& aResp) {
            if (!redfish::setUpRedfishRoute(app, req, aResp))
            {
                return;
            }

            PefPatchParams pefConfig;

            if (!json_util::readJsonPatch(                                //
                    req, aResp->res,                                      //
                    "FilterEnable", pefConfig.filterEnable,               //
                    "PEFActionGblControl", pefConfig.pefActionGblControl, //
                    "RetryEnable", pefConfig.retryEnable,                 //
                    "RetryCountLimit", pefConfig.retryCountLimit,         //
                    "RetryTimeInterval", pefConfig.retryTimeInterval,     //
                    "PendingAlertsLimit", pefConfig.pendingAlertsLimit    //
                    ))
            {
                return;
            }

            if (!pefConfig.hasValue())
            {
                return;
            }

            dbus::utility::getProperty<bool>(
                pefRetryConfService, pefRetryConfPath, pefRetryConfIface,
                "retryEnable",
                [&app, req, aResp, pefConfig = std::move(pefConfig)](
                    const boost::system::error_code& ec,
                    bool currentRetryEnable) mutable {
                    if (ec)
                    {
                        BMCWEB_LOG_DEBUG(
                            "Failed to get current RetryEnable, assuming false");
                        currentRetryEnable = false;
                    }

                    auto onComplete = [&app, req, aResp](bool pefAnyFailure,
                                                         bool pefAnySuccess) {
                        if (pefAnyFailure && !pefAnySuccess)
                        {
                            aResp->res.result(
                                boost::beast::http::status::bad_request);
                            return;
                        }

                        nlohmann::json errorsToPreserve =
                            nlohmann::json::object();
                        if (aResp->res.jsonValue.contains("error"))
                        {
                            errorsToPreserve = aResp->res.jsonValue["error"];
                        }

                        aResp->res.result(boost::beast::http::status::ok);

                        getPefServiceInfo(app, req, aResp);

                        if (pefAnyFailure && pefAnySuccess &&
                            !errorsToPreserve.empty())
                        {
                            if (!aResp->res.jsonValue.contains("error"))
                            {
                                aResp->res.jsonValue["error"] =
                                    errorsToPreserve;
                            }
                        }
                    };

                    handlePefPatch(std::move(pefConfig), aResp,
                                   currentRetryEnable, onComplete);
                });
        });

    BMCWEB_ROUTE(app, "/redfish/v1/Oem/Ami/PefService/EventFilterTable/")
        .privileges(redfish::privileges::getPefService)
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp) {
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }
                getEventFilterTableCollection(asyncResp);
            });

    BMCWEB_ROUTE(app, "/redfish/v1/Oem/Ami/PefService/EventFilterTable/<str>/")
        .privileges(redfish::privileges::getPefService)
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& entryId) {
                asyncResp->res.clearHeader(boost::beast::http::field::allow);
                asyncResp->res.addHeader("Allow", "GET, PATCH, DELETE");

                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }
                getEventFilterTableEntryInfo(asyncResp, entryId);
            });

    BMCWEB_ROUTE(app, "/redfish/v1/Oem/Ami/PefService/EventFilterTable/<str>/")
        .privileges(redfish::privileges::patchPefService)
        .methods(boost::beast::http::verb::patch)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& entryId) {
                asyncResp->res.clearHeader(boost::beast::http::field::allow);
                asyncResp->res.addHeader("Allow", "GET, PATCH, DELETE");
                handleEventFilterTableEntryPatch(asyncResp, req, entryId);
            });

    BMCWEB_ROUTE(app, "/redfish/v1/Oem/Ami/PefService/EventFilterTable/<str>/")
        .privileges(redfish::privileges::postPefService)
        .methods(boost::beast::http::verb::delete_)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& entryId) {
                asyncResp->res.clearHeader(boost::beast::http::field::allow);
                asyncResp->res.addHeader("Allow", "GET, PATCH, DELETE");

                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }

                handleEventFilterTableEntryDelete(asyncResp, entryId);
            });

    BMCWEB_ROUTE(app, "/redfish/v1/Oem/Ami/PefService/AlertPolicyTable/")
        .privileges(redfish::privileges::getPefService)
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp) {
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }
                getAlertPolicyTableCollection(asyncResp);
            });

    BMCWEB_ROUTE(app, "/redfish/v1/Oem/Ami/PefService/AlertPolicyTable/<str>/")
        .privileges(redfish::privileges::getPefService)
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& entryId) {
                asyncResp->res.clearHeader(boost::beast::http::field::allow);
                asyncResp->res.addHeader("Allow", "GET, PATCH, DELETE");

                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }
                getAlertPolicyTableEntryInfo(asyncResp, entryId);
            });

    BMCWEB_ROUTE(app, "/redfish/v1/Oem/Ami/PefService/AlertPolicyTable/<str>/")
        .privileges(redfish::privileges::patchPefService)
        .methods(boost::beast::http::verb::patch)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& entryId) {
                asyncResp->res.clearHeader(boost::beast::http::field::allow);
                asyncResp->res.addHeader("Allow", "GET, PATCH, DELETE");

                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }

                handleAlertPolicyTableEntryPatch(asyncResp, req, entryId);
            });

    BMCWEB_ROUTE(app, "/redfish/v1/Oem/Ami/PefService/AlertPolicyTable/<str>/")
        .privileges(redfish::privileges::postPefService)
        .methods(boost::beast::http::verb::delete_)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& entryId) {
                asyncResp->res.clearHeader(boost::beast::http::field::allow);
                asyncResp->res.addHeader("Allow", "GET, PATCH, DELETE");

                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }

                handleAlertPolicyTableEntryDelete(asyncResp, entryId);
            });
}

} // namespace redfish
