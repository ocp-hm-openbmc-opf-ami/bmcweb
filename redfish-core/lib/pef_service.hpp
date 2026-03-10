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

#include <system_error>

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

using GetSubTreeType = std::vector<
    std::pair<std::string,
              std::vector<std::pair<std::string, std::vector<std::string>>>>>;

// DestinationType mapping between D-Bus uint8_t values and Redfish string
// values
static const std::unordered_map<uint8_t, std::string> destTypeToString = {
    {0, "SnmpTrap"}, {1, "SMTP"}, {2, "Both"}};

static const std::unordered_map<std::string, uint8_t> stringToDestType = {
    {"SnmpTrap", 0}, {"SMTP", 1}, {"Both", 2}};

// Holds PEF configuration parameters for patching
struct PefPatchParams
{
    std::optional<std::vector<uint8_t>> filterEnable;
    std::optional<std::string> destinationType;
    std::optional<int64_t> retryCountLimit;
    std::optional<int64_t> retryTimeInterval;
    std::optional<int64_t> pendingAlertsLimit;
    std::optional<uint8_t> pefActionGblControl;
    std::optional<bool> retryEnable;

    bool hasValue() const
    {
        return filterEnable.has_value() || pefActionGblControl.has_value() ||
               destinationType.has_value() || retryEnable.has_value() ||
               retryCountLimit.has_value() || retryTimeInterval.has_value() ||
               pendingAlertsLimit.has_value();
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

inline void getDestinationType(const std::shared_ptr<bmcweb::AsyncResp>& aResp)
{
    dbus::utility::getProperty<uint8_t>(
        "xyz.openbmc_project.pef.alert.manager",
        "/xyz/openbmc_project/PefAlertManager/DestinationSelector/Entry1",
        "xyz.openbmc_project.pef.DestinationSelectorTable", "DestinationType",
        [aResp](const boost::system::error_code& ec, uint8_t destinationType) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-BUS response error on EventSeverity Get{}",
                                 ec);
                messages::internalError(aResp->res);
                return;
            }

            auto it = destTypeToString.find(destinationType);
            if (it != destTypeToString.end())
            {
                aResp->res.jsonValue["DestinationType"] = it->second;
            }
            else
            {
                BMCWEB_LOG_WARNING("Unknown destination type: {}",
                                   destinationType);
                aResp->res.jsonValue["DestinationType"] = nullptr;
            }
            nlohmann::json::array_t allowed;
            allowed.emplace_back("SnmpTrap");
            allowed.emplace_back("SMTP");
            allowed.emplace_back("Both");
            aResp->res.jsonValue["DestinationType@Redfish.AllowableValues"] =
                std::move(allowed);
        });
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

void setDestinationType(const std::shared_ptr<bmcweb::AsyncResp>& aResp,
                        const std::optional<std::string>& destinationType)
{
    auto it = stringToDestType.find(*destinationType);
    if (it == stringToDestType.end())
    {
        messages::propertyValueIncorrect(aResp->res, "DestinationType",
                                         *destinationType);
        return;
    }

    uint8_t desType = it->second;
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, "xyz.openbmc_project.pef.alert.manager",
        "/xyz/openbmc_project/PefAlertManager/DestinationSelector/Entry1",
        "xyz.openbmc_project.pef.DestinationSelectorTable", "DestinationType",
        desType, [aResp](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG(
                    "D-Bus response error setting Destination Type.");
                messages::internalError(aResp->res);
                return;
            }
        });
}

// Get Retry Configuration
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

// Set RetryEnable
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

// Set RetryCountLimit
inline void setRetryCountLimit(const std::shared_ptr<bmcweb::AsyncResp>& aResp,
                               const std::optional<int64_t>& retryCountLimit)
{
    // Validate range 0-10
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

// Set RetryTimeInterval
inline void setRetryTimeInterval(
    const std::shared_ptr<bmcweb::AsyncResp>& aResp,
    const std::optional<int64_t>& retryTimeInterval)
{
    // Validate range 0-3600
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

// SetPendingAlertsLimit
inline void setPendingAlertsLimit(
    const std::shared_ptr<bmcweb::AsyncResp>& aResp,
    const std::optional<int64_t>& pendingAlertsLimit)
{
    // Validate range 0-100
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

void getEventEntries(const std::shared_ptr<bmcweb::AsyncResp>& aResp,
                     nlohmann::json& entriesArray)
{
    std::cerr << "PEF getEventEntries: " << std::endl;
    crow::connections::systemBus->async_method_call(
        [aResp, &entriesArray](const boost::system::error_code ec,
                               const std::vector<std::string>& storageList) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("Volume mapper call error");
                return;
            }

            for (const std::string& objpath : storageList)
            {
                std::cerr << "PEF getEventEntries inside for: " << std::endl;
                std::size_t lastPos = objpath.rfind('/');
                if (lastPos == std::string::npos ||
                    (objpath.size() <= lastPos + 1))
                {
                    BMCWEB_LOG_ERROR("Failed to find '/' in ", objpath);
                    continue;
                }
                entriesArray.push_back(
                    {{"@odata.id", "/redfish/v1/Oem/Ami/PefService/" +
                                       objpath.substr(lastPos + 1)}});
                std::cerr << "PEF getEventEntries entry details : " << objpath;
            }
            aResp->res.jsonValue["Members@odata.count"] = entriesArray.size();
        },

        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths",
        "/xyz/openbmc_project/PefAlertManager/EventFilterTable/", 0,
        std::array<const char*, 1>{"xyz.openbmc_project.pef.EventFilterTable"});
}

inline void getEventSeverity(const std::shared_ptr<bmcweb::AsyncResp>& aResp,
                             const std::string entryValue)
{
    dbus::utility::getProperty<uint8_t>(
        "xyz.openbmc_project.pef.alert.manager",
        "/xyz/openbmc_project/PefAlertManager/EventFilterTable/" + entryValue,
        "xyz.openbmc_project.pef.EventFilterTable", "EventSeverity",
        [aResp](const boost::system::error_code& ec, uint8_t eventValue) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-BUS response error on EventSeverity Get{}",
                                 ec);
                messages::internalError(aResp->res);
                return;
            }
            if (eventValue == 2)
            {
                aResp->res.jsonValue["EventSeverity"] = "Information";
            }
            else if (eventValue == 4)
            {
                aResp->res.jsonValue["EventSeverity"] = "OK";
            }
            else if (eventValue == 8)
            {
                aResp->res.jsonValue["EventSeverity"] = "Warning";
            }
            else if (eventValue == 10)
            {
                aResp->res.jsonValue["EventSeverity"] = "Critical";
            }
            else if (eventValue == 30)
            {
                aResp->res.jsonValue["EventSeverity"] = "All";
            }
            else
                aResp->res.jsonValue["EventSeverity"] = nullptr;
        });
}

inline void setEventSeverity(const std::shared_ptr<bmcweb::AsyncResp>& aResp,
                             const std::optional<uint8_t>& eventId,
                             const std::string entryValue)
{
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, "xyz.openbmc_project.pef.alert.manager",
        "/xyz/openbmc_project/PefAlertManager/EventFilterTable/" + entryValue,
        "xyz.openbmc_project.pef.EventFilterTable", "EventSeverity", *eventId,
        [aResp](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-Bus responses error: {}", ec);
                messages::internalError(aResp->res);
                return;
            }
        });
}

const PropertyValue getSmtpEnable(const std::string& interfaceName)
{
    PropertyValue value{};
    auto b = sdbusplus::bus::new_default_system();
    auto method = b.new_method_call("xyz.openbmc_project.mail",
                                    "/xyz/openbmc_project/mail/alert",
                                    dbusPropertyInterface, "Get");

    method.append(interfaceName, "Enable");
    auto reply = b.call(method);
    reply.read(value);
    return value;
}

// Applies PEF patch parameters with validation and deferred D-Bus calls
inline void handlePefPatch(PefPatchParams&& input,
                           const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                           bool currentRetryEnable,
                           std::function<void(bool, bool)> onComplete)
{
    bool pefAnyFailure = false;
    bool pefAnySuccess = false;

    // Applies PEF patch parameters with validation and deferred D-Bus calls
    bool effectiveRetryEnable =
        input.retryEnable ? *input.retryEnable : currentRetryEnable;

    // If retryEnable is being set to FALSE, reject dependent properties
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
    // If retryEnable is NOT in payload and current state is FALSE, reject
    // dependent properties
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

    // Validate range constraints for allowed properties - validate ALL
    // independently
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

    // APPLY CHANGES - both valid properties and independent properties
    // filterEnable: must be exactly 18 elements, each 0 or 1
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
    // pefActionGblControl: uint8_t, any value is acceptable
    if (input.pefActionGblControl)
    {
        setPefConfParam(asyncResp, input.pefActionGblControl);
        pefAnySuccess = true;
    }
    // destinationType: must be one of "SnmpTrap", "SMTP", "Both"
    if (input.destinationType)
    {
        auto it = stringToDestType.find(*input.destinationType);
        if (it == stringToDestType.end())
        {
            pefAnyFailure = true;
            messages::propertyValueIncorrect(asyncResp->res, "DestinationType",
                                             *input.destinationType);
        }
        else
        {
            setDestinationType(asyncResp, input.destinationType);
            pefAnySuccess = true;
        }
    }

    // RetryEnable - always applied if provided
    if (input.retryEnable)
    {
        setRetryEnable(asyncResp, input.retryEnable);
        pefAnySuccess = true;
    }

    // Dependent properties - only applied if valid AND effective state is true
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

    // Invoke completion callback with validation results
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
        {"@odata.type", "#PefService.v1_0_0.PefService"},
        {"@odata.id", "/redfish/v1/Oem/Ami/PefService"},
        {"Id", "Pef Service"},
        {"Name", "Pef Service"},
        {"Description", "Pef Service Collections"},
        {"Members", nlohmann::json::array()},
        {"Actions",
         {{"#PefService.SendAlertMail",
           {{"target",
             "/redfish/v1/Oem/Ami/PefService/Actions/PefService.SendAlertMail"}}},
          {"#PefService.SendAlertSNMPTrap",
           {{"target",
             "/redfish/v1/Oem/Ami/PefService/Actions/PefService.SendAlertSNMPTrap"}}}}}};

    nlohmann::json& entriesControllerArray = aResp->res.jsonValue["Members"];

    getEventEntries(aResp, entriesControllerArray);
    getFilterEnable(aResp);
    getPefConfParam(aResp);
    getDestinationType(aResp);
    getRetryConfiguration(aResp);
}

void getPefServiceInfoId(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                         const std::string& entryId)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp, entryId](const boost::system::error_code ec,
                             const std::vector<std::string>& storageList) {
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "D-Bus call error while validating event entry");
                asyncResp->res.result(
                    boost::beast::http::status::internal_server_error);
                return;
            }

            // Loop through the event entries and check if the requested
            // entryId is valid
            bool isValid = false;
            for (const std::string& objpath : storageList)
            {
                std::size_t lastPos = objpath.rfind('/');
                if (lastPos != std::string::npos &&
                    objpath.substr(lastPos + 1) == entryId)
                {
                    isValid = true;
                    break;
                }
            }

            if (!isValid)
            {
                messages::resourceNotFound(asyncResp->res, "PefService",
                                           entryId);
                return;
            }
            else
            {
                asyncResp->res.jsonValue = {
                    {"@odata.type", "#PefEntry.v1_0_0.PefEntry"},
                    {"@odata.id", "/redfish/v1/PefService/" + entryId},
                    {"Id", entryId},
                    {"Name", "Pef Service Entry"}};
                getEventSeverity(asyncResp, entryId);
            }
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths",
        "/xyz/openbmc_project/PefAlertManager/EventFilterTable/", 0,
        std::array<const char*, 1>{"xyz.openbmc_project.pef.EventFilterTable"});
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
                    "DestinationType", pefConfig.destinationType,         //
                    "RetryEnable", pefConfig.retryEnable,                 //
                    "RetryCountLimit", pefConfig.retryCountLimit,         //
                    "RetryTimeInterval", pefConfig.retryTimeInterval,     //
                    "PendingAlertsLimit", pefConfig.pendingAlertsLimit    //
                    ))
            {
                return;
            }

            // Only process if there are values to patch
            if (!pefConfig.hasValue())
            {
                return;
            }

            // Fetch current retryEnable state to determine effective state
            // for validation This is required if incoming payload doesn't
            // have retryEnable
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

                    // Completion callback - handles response based on
                    // validation results
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

                        // Set success status
                        aResp->res.result(boost::beast::http::status::ok);

                        // Fetch and populate resource data
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

    BMCWEB_ROUTE(app, "/redfish/v1/Oem/Ami/PefService/<str>/")
        .privileges(redfish::privileges::getPefService)
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& entryId) {
                asyncResp->res.clearHeader(boost::beast::http::field::allow);
                asyncResp->res.addHeader("Allow", "GET, PATCH");

                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }
                getPefServiceInfoId(asyncResp, entryId);
            });

    BMCWEB_ROUTE(app, "/redfish/v1/Oem/Ami/PefService/<str>/")
        .privileges(redfish::privileges::patchPefService)
        .methods(
            boost::beast::http::verb::
                patch)([&app](
                           const crow::Request& req,
                           const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                           const std::string& entryId) {
            asyncResp->res.clearHeader(boost::beast::http::field::allow);
            asyncResp->res.addHeader("Allow", "GET, PATCH");

            crow::connections::systemBus->async_method_call(
                [asyncResp, entryId,
                 req](const boost::system::error_code ec,
                      const std::vector<std::string>& storageList) {
                    std::optional<std::string> eventSeverity;
                    if (ec)
                    {
                        BMCWEB_LOG_ERROR(
                            "D-Bus call error while validating event entry");
                        asyncResp->res.result(
                            boost::beast::http::status::internal_server_error);
                        return;
                    }

                    // Loop through the event entries and check if the
                    // requested entryId is valid
                    bool isValid = false;
                    for (const std::string& objpath : storageList)
                    {
                        std::size_t lastPos = objpath.rfind('/');
                        if (lastPos != std::string::npos &&
                            objpath.substr(lastPos + 1) == entryId)
                        {
                            isValid = true;
                            break;
                        }
                    }

                    if (!isValid)
                    {
                        messages::resourceNotFound(asyncResp->res, "PefService",
                                                   entryId);
                        return;
                    }
                    if (!json_util::readJsonPatch(         //
                            req, asyncResp->res,           //
                            "EventSeverity", eventSeverity //
                            ))
                    {
                        return;
                    }

                    if (eventSeverity)
                    {
                        if (eventSeverity == "Information")
                        {
                            setEventSeverity(asyncResp, 2, entryId);
                        }
                        else if (eventSeverity == "OK")
                        {
                            setEventSeverity(asyncResp, 4, entryId);
                        }
                        else if (eventSeverity == "Warning")
                        {
                            setEventSeverity(asyncResp, 8, entryId);
                        }
                        else if (eventSeverity == "Critical")
                        {
                            setEventSeverity(asyncResp, 10, entryId);
                        }
                        else if (eventSeverity == "All")
                        {
                            setEventSeverity(asyncResp, 30, entryId);
                        }
                        else
                        {
                            messages::propertyValueNotInList(asyncResp->res,
                                                             "EventSeverity",
                                                             *eventSeverity);
                            return;
                        }
                    }
                    getPefServiceInfoId(asyncResp, entryId);
                },
                "xyz.openbmc_project.ObjectMapper",
                "/xyz/openbmc_project/object_mapper",
                "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths",
                "/xyz/openbmc_project/PefAlertManager/EventFilterTable/", 0,
                std::array<const char*, 1>{
                    "xyz.openbmc_project.pef.EventFilterTable"});
        });

    BMCWEB_ROUTE(app, "/redfish/v1/Oem/Ami/PefService/<str>/")
        .privileges(redfish::privileges::postPefService)
        .methods(boost::beast::http::verb::post,
                 boost::beast::http::verb::
                     delete_)([&app](const crow::Request& req,
                                     const std::shared_ptr<bmcweb::AsyncResp>&
                                         asyncResp,
                                     const std::string& entryId) {
            asyncResp->res.clearHeader(boost::beast::http::field::allow);
            if (!redfish::setUpRedfishRoute(app, req, asyncResp))
            {
                return;
            }
            crow::connections::systemBus->async_method_call(
                [asyncResp,
                 entryId](const boost::system::error_code ec,
                          const std::vector<std::string>& storageList) {
                    if (ec)
                    {
                        BMCWEB_LOG_ERROR(
                            "D-Bus call error while validating event entry");
                        asyncResp->res.result(
                            boost::beast::http::status::internal_server_error);
                        return;
                    }

                    // Loop through the event entries and check if the
                    // requested entryId is valid
                    bool isValid = false;
                    for (const std::string& objpath : storageList)
                    {
                        std::size_t lastPos = objpath.rfind('/');
                        if (lastPos != std::string::npos &&
                            objpath.substr(lastPos + 1) == entryId)
                        {
                            isValid = true;
                            break;
                        }
                    }

                    if (!isValid)
                    {
                        messages::resourceNotFound(asyncResp->res, "PefService",
                                                   entryId);
                        return;
                    }
                    asyncResp->res.addHeader("Allow", "GET, PATCH");
                    messages::operationNotAllowed(asyncResp->res);
                    return;
                },
                "xyz.openbmc_project.ObjectMapper",
                "/xyz/openbmc_project/object_mapper",
                "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths",
                "/xyz/openbmc_project/PefAlertManager/EventFilterTable/", 0,
                std::array<const char*, 1>{
                    "xyz.openbmc_project.pef.EventFilterTable"});
        });

    BMCWEB_ROUTE(
        app, "/redfish/v1/Oem/Ami/PefService/Actions/PefService.SendAlertMail/")
        .privileges(redfish::privileges::postPefService)
        .methods(boost::beast::http::verb::post)(
            [](const crow::Request& req,
               const std::shared_ptr<bmcweb::AsyncResp>& aResp) {
                std::string subject;
                std::string mailBuf;
                std::optional<std::string> vId;

                if (!json_util::readJsonPatch(  //
                        req, aResp->res,        //
                        "Subject", subject,     //
                        "MailContent", mailBuf, //
                        "Id", vId               //
                        ))
                {
                    return;
                }
                if (vId)
                {
                    messages::propertyNotWritable(aResp->res, "Id");
                    aResp->res.result(boost::beast::http::status::bad_request);
                    return;
                }
                auto primaryvalue =
                    getSmtpEnable("xyz.openbmc_project.mail.alert.primary");
                auto primaryconfiguration = std::get<bool>(primaryvalue);

                auto secondaryvalue =
                    getSmtpEnable("xyz.openbmc_project.mail.alert.secondary");
                auto secondaryconfiguration = std::get<bool>(secondaryvalue);

                if (!primaryconfiguration && !secondaryconfiguration)
                {
                    messages::serviceDisabled(
                        aResp->res,
                        "Primary Configuration and secondary configuration");
                    aResp->res.result(boost::beast::http::status::bad_request);
                    return;
                }
                else
                {
                    crow::connections::systemBus->async_method_call(
                        [subject, mailBuf,
                         aResp](const boost::system::error_code ec1,
                                const std::uint16_t& response) {
                            if (ec1)
                            {
                                BMCWEB_LOG_ERROR("SendMail: Can't get "
                                                 "alertMailIface ");
                                messages::internalError(aResp->res);
                                return;
                            }
                            else if (response == 65535)
                            {
                                messages::operationFailed(aResp->res);
                                aResp->res.result(
                                    boost::beast::http::status::bad_request);
                                return;
                            }
                            else if (response == 65534)
                            {
                                messages::insufficientPrivilege(aResp->res);
                                return;
                            }
                            else
                            {
                                messages::success(aResp->res);
                            }
                        },
                        "xyz.openbmc_project.mail",
                        "/xyz/openbmc_project/mail/alert",
                        "xyz.openbmc_project.mail.alert", "SendMail", subject,
                        mailBuf);
                }
            });
}

inline void requestRoutesSendTrap(App& app)
{
    BMCWEB_ROUTE(
        app,
        "/redfish/v1/Oem/Ami/PefService/Actions/PefService.SendAlertSNMPTrap/")
        .privileges(redfish::privileges::postPefService)
        .methods(
            boost::beast::http::verb::
                post)([&app](const crow::Request& req,
                             const std::shared_ptr<bmcweb::AsyncResp>& aResp) {
            if (!redfish::setUpRedfishRoute(app, req, aResp))
            {
                return;
            }
            sdbusplus::message::object_path path(
                "/xyz/openbmc_project/network/snmp/manager");
            dbus::utility::getManagedObjects(
                "xyz.openbmc_project.Network.SNMP", path,
                [aResp](const boost::system::error_code& ec,
                        const dbus::utility::ManagedObjectType& resp) {
                    if (ec)
                    {
                        BMCWEB_LOG_DEBUG(
                            "Failed to get SNMP subscription objects: {}",
                            ec.message());
                        messages::internalError(aResp->res);
                        return;
                    }
                    if (resp.empty())
                    {
                        BMCWEB_LOG_DEBUG("No SNMP subscriptions found.");
                        messages::subscriptionTerminated(aResp->res);
                        aResp->res.result(
                            boost::beast::http::status::bad_request);
                        return;
                    }
                    else
                    {
                        dbus::utility::getProperty<bool>(
                            "xyz.openbmc_project.Snmp.Conf",
                            "/xyz/openbmc_project/snmp/SnmpUtils",
                            "xyz.openbmc_project.Snmp.SnmpUtils",
                            "SnmpTrapStatus",
                            [aResp, resp](const boost::system::error_code& ec,
                                          bool protocolEnabled) {
                                if (ec)
                                {
                                    BMCWEB_LOG_DEBUG(
                                        "D-BUS response error on SnmpTrapStatus Get{}",
                                        ec);
                                    messages::internalError(aResp->res);
                                    return;
                                }
                                else if (!protocolEnabled)
                                {
                                    messages::serviceDisabled(
                                        aResp->res, "SNMP Service Disabled");
                                    return;
                                }
                                else
                                {
                                    crow::connections::systemBus->async_method_call(
                                        [aResp](const boost::system::error_code&
                                                    ecTrapSend,
                                                bool result) {
                                            if (ecTrapSend)
                                            {
                                                BMCWEB_LOG_DEBUG(
                                                    "Failed to send SNMP trap: {}",
                                                    ecTrapSend.message());
                                                messages::internalError(
                                                    aResp->res);
                                                return;
                                            }
                                            if (!result)
                                            {
                                                messages::serviceDisabled(
                                                    aResp->res,
                                                    "SNMP Service Disabled");
                                                aResp->res.result(
                                                    boost::beast::http::status::
                                                        bad_request);
                                                return;
                                            }
                                            messages::success(aResp->res);
                                        },
                                        "xyz.openbmc_project.Snmp.Conf",
                                        "/xyz/openbmc_project/snmp/SnmpUtils",
                                        "xyz.openbmc_project.Snmp.SnmpUtils",
                                        "SendSNMPTrap");
                                }
                            });
                    }
                });
        });
}

} // namespace redfish
