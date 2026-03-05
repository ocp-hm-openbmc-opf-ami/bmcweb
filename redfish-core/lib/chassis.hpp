// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
// SPDX-FileCopyrightText: Copyright 2018 Intel Corporation
#pragma once

#include "app.hpp"
#include "chassis_header.hpp"
#include "dbus_utility.hpp"
#include "generated/enums/action_info.hpp"
#include "generated/enums/chassis.hpp"
#include "generated/enums/resource.hpp"
#include "led.hpp"
#include "query.hpp"
#include "redfish_util.hpp"
#include "registries/privilege_registry.hpp"
#include "utils/collection.hpp"
#include "utils/dbus_utils.hpp"
#include "utils/json_utils.hpp"

#include <boost/algorithm/string/predicate.hpp>
#include <boost/date_time.hpp>
#include <boost/system/error_code.hpp>
#include <boost/url/format.hpp>
#include <sdbusplus/asio/property.hpp>
#include <sdbusplus/message.hpp>
#include <sdbusplus/unpack_properties.hpp>
#include <task.hpp>
#include <utils/sw_utils.hpp>

#include <array>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <ranges>
#include <sstream>
#include <string>
#include <string_view>

namespace redfish
{

constexpr const char* dbusPropertyInterface = "org.freedesktop.DBus.Properties";

using PropertyValue = std::variant<uint8_t, uint16_t, uint64_t, std::string,
                                   std::vector<std::string>, bool>;

inline bool checkinvalidURIPatch = true;
static bool chassisTimerFlag = false;
static bool chassisTaskAlreadyHappened = false;

inline chassis::ChassisType translateChassisTypeToRedfish(
    const std::string_view& chassisType)
{
    if (chassisType ==
        "xyz.openbmc_project.Inventory.Item.Chassis.ChassisType.Blade")
    {
        return chassis::ChassisType::Blade;
    }
    if (chassisType ==
        "xyz.openbmc_project.Inventory.Item.Chassis.ChassisType.Component")
    {
        return chassis::ChassisType::Component;
    }
    if (chassisType ==
        "xyz.openbmc_project.Inventory.Item.Chassis.ChassisType.Enclosure")
    {
        return chassis::ChassisType::Enclosure;
    }
    if (chassisType ==
        "xyz.openbmc_project.Inventory.Item.Chassis.ChassisType.Module")
    {
        return chassis::ChassisType::Module;
    }
    if (chassisType ==
        "xyz.openbmc_project.Inventory.Item.Chassis.ChassisType.RackMount")
    {
        return chassis::ChassisType::RackMount;
    }
    if (chassisType ==
        "xyz.openbmc_project.Inventory.Item.Chassis.ChassisType.StandAlone")
    {
        return chassis::ChassisType::StandAlone;
    }
    if (chassisType ==
        "xyz.openbmc_project.Inventory.Item.Chassis.ChassisType.StorageEnclosure")
    {
        return chassis::ChassisType::StorageEnclosure;
    }
    if (chassisType ==
        "xyz.openbmc_project.Inventory.Item.Chassis.ChassisType.Zone")
    {
        return chassis::ChassisType::Zone;
    }
    return chassis::ChassisType::Invalid;
}

/**
 * @brief Retrieves resources over dbus to link to the chassis
 *
 * @param[in] asyncResp  - Shared pointer for completing asynchronous
 * calls
 * @param[in] path       - Chassis dbus path to look for the storage.
 *
 * Calls the Association endpoints on the path + "/storage" and add the link of
 * json["Links"]["Storage@odata.count"] =
 *    {"@odata.id", "/redfish/v1/Storage/" + resourceId}
 *
 * @return None.
 */
inline void getStorageLink(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                           const sdbusplus::message::object_path& path)
{
    dbus::utility::getProperty<std::vector<std::string>>(
        "xyz.openbmc_project.ObjectMapper", (path / "storage").str,
        "xyz.openbmc_project.Association", "endpoints",
        [asyncResp](const boost::system::error_code& ec,
                    const std::vector<std::string>& storageList) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("getStorageLink got DBUS response error");
                return;
            }

            nlohmann::json::array_t storages;
            for (const std::string& storagePath : storageList)
            {
                std::string id =
                    sdbusplus::message::object_path(storagePath).filename();
                if (id.empty())
                {
                    continue;
                }

                nlohmann::json::object_t storage;
                storage["@odata.id"] =
                    boost::urls::format("/redfish/v1/Systems/{}/Storage/{}",
                                        BMCWEB_REDFISH_SYSTEM_URI_NAME, id);
                storages.emplace_back(std::move(storage));
            }
            asyncResp->res.jsonValue["Links"]["Storage@odata.count"] =
                storages.size();
            asyncResp->res.jsonValue["Links"]["Storage"] = std::move(storages);
        });
}

/**
 * @brief Retrieves chassis state properties over dbus
 *
 * @param[in] asyncResp - Shared pointer for completing asynchronous calls.
 *
 * @return None.
 */
inline void getChassisState(std::shared_ptr<bmcweb::AsyncResp> asyncResp)
{
    // crow::connections::systemBus->async_method_call(
    dbus::utility::getProperty<std::string>(
        "xyz.openbmc_project.State.Chassis",
        "/xyz/openbmc_project/state/chassis0",
        "xyz.openbmc_project.State.Chassis", "CurrentPowerState",
        [asyncResp{std::move(asyncResp)}](const boost::system::error_code& ec,
                                          const std::string& chassisState) {
            if (ec)
            {
                if (ec == boost::system::errc::host_unreachable)
                {
                    // Service not available, no error, just don't return
                    // chassis state info
                    BMCWEB_LOG_DEBUG("Service not available {}", ec);
                    return;
                }
                BMCWEB_LOG_DEBUG("DBUS response error {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }

            BMCWEB_LOG_DEBUG("Chassis state: {}", chassisState);
            // Verify Chassis State
            if (chassisState ==
                "xyz.openbmc_project.State.Chassis.PowerState.On")
            {
                asyncResp->res.jsonValue["PowerState"] =
                    resource::PowerState::On;
                asyncResp->res.jsonValue["Status"]["State"] =
                    resource::State::Enabled;
            }
            else if (chassisState ==
                     "xyz.openbmc_project.State.Chassis.PowerState.Off")
            {
                asyncResp->res.jsonValue["PowerState"] =
                    resource::PowerState::Off;
                asyncResp->res.jsonValue["Status"]["State"] =
                    resource::State::StandbyOffline;
            }
        });
}

/**
 * Retrieves physical security properties over dbus
 */
inline void handlePhysicalSecurityGetSubTree(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const boost::system::error_code& ec,
    const dbus::utility::MapperGetSubTreeResponse& subtree)
{
    if (ec)
    {
        // do not add err msg in redfish response, because this is not
        //     mandatory property
        BMCWEB_LOG_INFO("DBUS error: no matched iface {}", ec);
        return;
    }
    // Iterate over all retrieved ObjectPaths.
    for (const auto& object : subtree)
    {
        if (!object.second.empty())
        {
            const auto& service = object.second.front();

            BMCWEB_LOG_DEBUG("Get intrusion status by service ");

            dbus::utility::getProperty<std::string>(
                service.first, object.first,
                "xyz.openbmc_project.Chassis.Intrusion", "Status",
                [asyncResp](const boost::system::error_code& ec1,
                            const std::string& value) {
                    if (ec1)
                    {
                        // do not add err msg in redfish response, because this
                        // is not
                        //     mandatory property
                        BMCWEB_LOG_ERROR("DBUS response error {}", ec1);
                        return;
                    }
                    asyncResp->res.jsonValue["PhysicalSecurity"]
                                            ["IntrusionSensorNumber"] = 1;
                    if (value ==
                        "xyz.openbmc_project.Chassis.Intrusion.Status.Normal")
                    {
                        asyncResp->res
                            .jsonValue["PhysicalSecurity"]["IntrusionSensor"] =
                            "Normal";
                    }
                    else if (
                        value ==
                        "xyz.openbmc_project.Chassis.Intrusion.Status.HardwareIntrusion")
                    {
                        asyncResp->res
                            .jsonValue["PhysicalSecurity"]["IntrusionSensor"] =
                            "HardwareIntrusion";
                    }
                    else if (
                        value ==
                        "xyz.openbmc_project.Chassis.Intrusion.Status.TamperingDetected")
                    {
                        asyncResp->res
                            .jsonValue["PhysicalSecurity"]["IntrusionSensor"] =
                            "TamperingDetected";
                    }
                    else
                    {
                        asyncResp->res
                            .jsonValue["PhysicalSecurity"]["IntrusionSensor"] =
                            value;
                    }
                });

            return;
        }
    }
}

inline void handleChassisCollectionGet(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    asyncResp->res.jsonValue["@odata.type"] =
        "#ChassisCollection.ChassisCollection";
    asyncResp->res.jsonValue["@odata.id"] = "/redfish/v1/Chassis";
    asyncResp->res.jsonValue["Name"] = "Chassis Collection";
    asyncResp->res.jsonValue["Description"] = "The Collection for Chassis";

    constexpr std::array<std::string_view, 3> interfaces{
        "xyz.openbmc_project.Inventory.Item.Board",
        "xyz.openbmc_project.Inventory.Item.Chassis",
        "xyz.openbmc_project.Inventory.Item.Blade"};
    collection_util::getCollectionMembers(
        asyncResp, boost::urls::url("/redfish/v1/Chassis"), interfaces,
        "/xyz/openbmc_project/inventory");
}

inline void getChassisContainedBy(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId, const boost::system::error_code& ec,
    const dbus::utility::MapperGetSubTreePathsResponse& upstreamChassisPaths)
{
    if (ec)
    {
        if (ec.value() != EBADR)
        {
            BMCWEB_LOG_ERROR("DBUS response error {}", ec);
            messages::internalError(asyncResp->res);
        }
        return;
    }
    if (upstreamChassisPaths.empty())
    {
        return;
    }
    if (upstreamChassisPaths.size() > 1)
    {
        BMCWEB_LOG_ERROR("{} is contained by multiple chassis", chassisId);
        messages::internalError(asyncResp->res);
        return;
    }

    sdbusplus::message::object_path upstreamChassisPath(
        upstreamChassisPaths[0]);
    std::string upstreamChassis = upstreamChassisPath.filename();
    if (upstreamChassis.empty())
    {
        BMCWEB_LOG_WARNING("Malformed upstream Chassis path {} on {}",
                           upstreamChassisPath.str, chassisId);
        return;
    }

    asyncResp->res.jsonValue["Links"]["ContainedBy"]["@odata.id"] =
        boost::urls::format("/redfish/v1/Chassis/{}", upstreamChassis);
}

inline void getChassisContains(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId, const boost::system::error_code& ec,
    const dbus::utility::MapperGetSubTreePathsResponse& downstreamChassisPaths)
{
    if (ec)
    {
        if (ec.value() != EBADR)
        {
            BMCWEB_LOG_ERROR("DBUS response error {}", ec);
            messages::internalError(asyncResp->res);
        }
        return;
    }
    if (downstreamChassisPaths.empty())
    {
        return;
    }
    nlohmann::json& jValue = asyncResp->res.jsonValue["Links"]["Contains"];
    if (!jValue.is_array())
    {
        // Create the array if it was empty
        jValue = nlohmann::json::array();
    }
    for (const auto& p : downstreamChassisPaths)
    {
        sdbusplus::message::object_path downstreamChassisPath(p);
        std::string downstreamChassis = downstreamChassisPath.filename();
        if (downstreamChassis.empty())
        {
            BMCWEB_LOG_WARNING("Malformed downstream Chassis path {} on {}",
                               downstreamChassisPath.str, chassisId);
            continue;
        }
        nlohmann::json link;
        link["@odata.id"] =
            boost::urls::format("/redfish/v1/Chassis/{}", downstreamChassis);
        jValue.push_back(std::move(link));
    }
    asyncResp->res.jsonValue["Links"]["Contains@odata.count"] = jValue.size();
}

inline void getChassisConnectivity(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId, const std::string& chassisPath)
{
    BMCWEB_LOG_DEBUG("Get chassis connectivity");

    constexpr std::array<std::string_view, 2> interfaces{
        "xyz.openbmc_project.Inventory.Item.Board",
        "xyz.openbmc_project.Inventory.Item.Chassis"};

    dbus::utility::getAssociatedSubTreePaths(
        chassisPath + "/contained_by",
        sdbusplus::message::object_path("/xyz/openbmc_project/inventory"), 0,
        interfaces,
        std::bind_front(getChassisContainedBy, asyncResp, chassisId));

    dbus::utility::getAssociatedSubTreePaths(
        chassisPath + "/containing",
        sdbusplus::message::object_path("/xyz/openbmc_project/inventory"), 0,
        interfaces, std::bind_front(getChassisContains, asyncResp, chassisId));
}

/**
 * ChassisCollection derived class for delivering Chassis Collection Schema
 *  Functions triggers appropriate requests on DBus
 */
inline void requestRoutesChassisCollection(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Chassis/")
        .privileges(redfish::privileges::getChassisCollection)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleChassisCollectionGet, std::ref(app)));
}

inline void getChassisLocationCode(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& connectionName, const std::string& path)
{
    dbus::utility::getProperty<std::string>(
        connectionName, path,
        "xyz.openbmc_project.Inventory.Decorator.LocationCode", "LocationCode",
        [asyncResp](const boost::system::error_code& ec,
                    const std::string& property) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("DBUS response error for Location");
                messages::internalError(asyncResp->res);
                return;
            }

            asyncResp->res
                .jsonValue["Location"]["PartLocation"]["ServiceLabel"] =
                property;
        });
}

inline void getChassisUUID(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                           const std::string& connectionName,
                           const std::string& path)
{
    dbus::utility::getProperty<std::string>(
        connectionName, path, "xyz.openbmc_project.Common.UUID", "UUID",
        [asyncResp](const boost::system::error_code& ec,
                    const std::string& chassisUUID) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("DBUS response error for UUID");
                messages::internalError(asyncResp->res);
                return;
            }
            asyncResp->res.jsonValue["UUID"] = chassisUUID;
        });
}

inline void handleDecoratorAssetProperties(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId, const std::string& path,
    const dbus::utility::DBusPropertiesMap& propertiesList)
{
    const std::string* partNumber = nullptr;
    const std::string* serialNumber = nullptr;
    const std::string* manufacturer = nullptr;
    const std::string* model = nullptr;
    const std::string* sparePartNumber = nullptr;

    const bool success = sdbusplus::unpackPropertiesNoThrow(
        dbus_utils::UnpackErrorPrinter(), propertiesList, "PartNumber",
        partNumber, "SerialNumber", serialNumber, "Manufacturer", manufacturer,
        "Model", model, "SparePartNumber", sparePartNumber);

    if (!success)
    {
        messages::internalError(asyncResp->res);
        return;
    }

    if (partNumber != nullptr)
    {
        asyncResp->res.jsonValue["PartNumber"] = *partNumber;
    }

    if (serialNumber != nullptr)
    {
        asyncResp->res.jsonValue["SerialNumber"] = *serialNumber;
    }

    if (manufacturer != nullptr)
    {
        asyncResp->res.jsonValue["Manufacturer"] = *manufacturer;
    }

    if (model != nullptr)
    {
        asyncResp->res.jsonValue["Model"] = *model;
    }

    // SparePartNumber is optional on D-Bus
    // so skip if it is empty
    if (sparePartNumber != nullptr && !sparePartNumber->empty())
    {
        asyncResp->res.jsonValue["SparePartNumber"] = *sparePartNumber;
    }

    asyncResp->res.jsonValue["Name"] = chassisId;
    asyncResp->res.jsonValue["Id"] = chassisId;

    if constexpr (BMCWEB_REDFISH_ALLOW_DEPRECATED_POWER_THERMAL)
    {
        asyncResp->res.jsonValue["Thermal"]["@odata.id"] =
            boost::urls::format("/redfish/v1/Chassis/{}/Thermal", chassisId);
    }

    if constexpr (BMCWEB_REDFISH_NEW_POWERSUBSYSTEM_THERMALSUBSYSTEM)
    {
        asyncResp->res.jsonValue["ThermalSubsystem"]["@odata.id"] =
            boost::urls::format("/redfish/v1/Chassis/{}/ThermalSubsystem",
                                chassisId);
        asyncResp->res.jsonValue["PowerSubsystem"]["@odata.id"] =
            boost::urls::format("/redfish/v1/Chassis/{}/PowerSubsystem",
                                chassisId);
        asyncResp->res.jsonValue["EnvironmentMetrics"]["@odata.id"] =
            boost::urls::format("/redfish/v1/Chassis/{}/EnvironmentMetrics",
                                chassisId);
    }

#ifdef ONETREE_NIC

    asyncResp->res.jsonValue["NetworkAdapters"]["@odata.id"] =
        boost::urls::format("/redfish/v1/Chassis/{}/NetworkAdapters",
                            chassisId);
#endif

// Power
#ifdef ONETREE_AMD_CHALUPA
    {
        asyncResp->res.jsonValue["Power"]["@odata.id"] =
            boost::urls::format("/redfish/v1/Chassis/{}/Power", chassisId);
    }
#endif
    // FRU Device
    asyncResp->res.jsonValue["Oem"]["AMI"]["FRU"]["@odata.id"] =
        boost::urls::format("/redfish/v1/Chassis/{}/FRU", chassisId);
    asyncResp->res.jsonValue["Oem"]["AMI"]["@odata.type"] =
        json_util::odataType("OemAMIChassis");
    asyncResp->res.jsonValue["Oem"]["AMI"]["@odata.id"] =
        boost::urls::format("/redfish/v1/Chassis/{}#/Oem/AMI", chassisId);
    // SensorCollection
    asyncResp->res.jsonValue["Sensors"]["@odata.id"] =
        boost::urls::format("/redfish/v1/Chassis/{}/Sensors", chassisId);
    asyncResp->res.jsonValue["Status"]["State"] = resource::State::Enabled;
#if (!defined(ONETREE_RM)) && (!defined(ONETREE_PSM))
    // SensorThreshold Collection
    asyncResp->res.jsonValue["Oem"]["AMI"]["SensorThreshold"]["@odata.id"] =
        boost::urls::format("/redfish/v1/Chassis/{}/Sensors/Oem/Ami/Threshold",
                            chassisId);
    asyncResp->res.jsonValue["Oem"]["AMI"]["SensorThreshold"]["@odata.type"] =
        json_util::odataType("OemAMISensor");
#endif
#ifndef ONETREE_PSM
    nlohmann::json::array_t computerSystems;
    nlohmann::json::object_t system;
    system["@odata.id"] =
        std::format("/redfish/v1/Systems/{}", BMCWEB_REDFISH_SYSTEM_URI_NAME);
    computerSystems.emplace_back(std::move(system));
    asyncResp->res.jsonValue["Links"]["ComputerSystems"] =
        std::move(computerSystems);
#endif
    nlohmann::json::array_t managedBy;
    nlohmann::json::object_t manager;
    manager["@odata.id"] = boost::urls::format("/redfish/v1/Managers/{}",
                                               BMCWEB_REDFISH_MANAGER_URI_NAME);
    managedBy.emplace_back(std::move(manager));
#ifdef ONETREE_PSM
    nlohmann::json::array_t managersInChassis = managedBy;
    asyncResp->res.jsonValue["Links"]["ManagersInChassis"] =
        std::move(managersInChassis);
#endif
    asyncResp->res.jsonValue["Links"]["ManagedBy"] = std::move(managedBy);
    getChassisState(asyncResp);
    getStorageLink(asyncResp, path);
}

inline void handleChassisProperties(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const dbus::utility::DBusPropertiesMap& propertiesList)
{
    const std::string* type = nullptr;
    const bool success = sdbusplus::unpackPropertiesNoThrow(
        dbus_utils::UnpackErrorPrinter(), propertiesList, "Type", type);
    if (!success)
    {
        messages::internalError(asyncResp->res);
        return;
    }

    // Chassis Type is a required property in Redfish
    // If there is an error or some enum we don't support just sit it to Rack
    // Mount
    asyncResp->res.jsonValue["ChassisType"] = chassis::ChassisType::RackMount;

    if (type != nullptr)
    {
        auto chassisType = translateChassisTypeToRedfish(*type);
        if (chassisType != chassis::ChassisType::Invalid)
        {
            asyncResp->res.jsonValue["ChassisType"] = chassisType;
        }
    }
}

inline void handleChassisSubTree(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId, const boost::system::error_code& ec,
    const std::optional<std::string>& methodName,
    const dbus::utility::MapperGetSubTreeResponse& subtree)
{
    if (ec)
    {
        BMCWEB_LOG_ERROR("DBUS response error {}", ec);
        messages::internalError(asyncResp->res);
        return;
    }
    // Iterate over all retrieved ObjectPaths.
    for (const std::pair<
             std::string,
             std::vector<std::pair<std::string, std::vector<std::string>>>>&
             object : subtree)
    {
        const std::string& path = object.first;
        std::string methodNameVal = methodName.value_or("");
        const std::vector<std::pair<std::string, std::vector<std::string>>>&
            connectionNames = object.second;

        sdbusplus::message::object_path objPath(path);
        if (objPath.filename() != chassisId)
        {
            continue;
        }
        if (connectionNames.empty())
        {
            BMCWEB_LOG_ERROR("Got 0 Connection names");
            continue;
        }
        if (methodNameVal == "patch")
        {
            checkinvalidURIPatch = false;
            return;
        }
        else
        {
            asyncResp->res.addHeader("Allow", "GET, PATCH");
            messages::operationNotAllowed(asyncResp->res);
            return;
        }
    }
    messages::resourceNotFound(asyncResp->res, "Chassis", chassisId);
    return;
}

inline void getMinMaxValues(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    const std::string sensorPath =
        "/xyz/openbmc_project/sensors/power/Platform_Power_Average_CPU1";
    sdbusplus::asio::getAllProperties(
        *crow::connections::systemBus,
        "xyz.openbmc_project.IntelCPUSensor", // Service
        sensorPath,
        "xyz.openbmc_project.Sensor.Value",   // Interface
        [asyncResp](const boost::system::error_code& ec,
                    const dbus::utility::DBusPropertiesMap& properties) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("DBUS response error: {}", ec);
                return;
            }
            const double* minValue = nullptr;
            const double* maxValue = nullptr;
            const bool success = sdbusplus::unpackPropertiesNoThrow(
                dbus_utils::UnpackErrorPrinter(), properties, "MinValue",
                minValue, "MaxValue", maxValue);
            if (!success)
            {
                BMCWEB_LOG_DEBUG("Failed to unpack MinValue/MaxValue");
                return;
            }
            if (minValue)
            {
                asyncResp->res.jsonValue["MinPowerWatts"] = *minValue;
            }
            if (maxValue)
            {
                asyncResp->res.jsonValue["MaxPowerWatts"] = *maxValue;
            }
        });
}

inline void handleChassisGetSubTree(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId, const boost::system::error_code& ec,
    const dbus::utility::MapperGetSubTreeResponse& subtree)
{
    if (ec)
    {
        BMCWEB_LOG_ERROR("DBUS response error {}", ec);
        messages::internalError(asyncResp->res);
        return;
    }
    // Iterate over all retrieved ObjectPaths.
    for (const std::pair<
             std::string,
             std::vector<std::pair<std::string, std::vector<std::string>>>>&
             object : subtree)
    {
        const std::string& path = object.first;
        const std::vector<std::pair<std::string, std::vector<std::string>>>&
            connectionNames = object.second;

        sdbusplus::message::object_path objPath(path);
        if (objPath.filename() != chassisId)
        {
            continue;
        }

        getChassisConnectivity(asyncResp, chassisId, path);

        if (connectionNames.empty())
        {
            BMCWEB_LOG_ERROR("Got 0 Connection names");
            continue;
        }

        constexpr std::array<std::string_view, 1> interfaces3 = {
            "xyz.openbmc_project.Chassis.Intrusion"};
        asyncResp->res.jsonValue["@odata.type"] =
            json_util::odataType("Chassis");
        asyncResp->res.jsonValue["@odata.id"] =
            boost::urls::format("/redfish/v1/Chassis/{}", chassisId);
        asyncResp->res.jsonValue["Name"] = "Chassis Collection";
        asyncResp->res.jsonValue["Description"] = "The Collection of Chassis";
        asyncResp->res.jsonValue["Actions"]["#Chassis.Reset"]["target"] =
            boost::urls::format("/redfish/v1/Chassis/{}/Actions/Chassis.Reset",
                                chassisId);
        asyncResp->res
            .jsonValue["Actions"]["#Chassis.Reset"]["@Redfish.ActionInfo"] =
            boost::urls::format("/redfish/v1/Chassis/{}/ResetActionInfo",
                                chassisId);

        dbus::utility::getSubTree(
            "/xyz/openbmc_project", 0, interfaces3,
            std::bind_front(handlePhysicalSecurityGetSubTree, asyncResp));
        getMinMaxValues(asyncResp);

#if (defined(ONETREE_RTP)) && (!defined(ONETREE_PSM))
        asyncResp->res.jsonValue["PCIeSlots"] = {
            {"@odata.id", boost::urls::format(
                              "/redfish/v1/Chassis/{}/PCIeSlots", chassisId)}};
#endif

#ifdef ONETREE_NVIDIASIPACK
        if (chassisId == "BMC_0")
        {
            asyncResp->res.jsonValue["Actions"]["Oem"]
                                    ["#NvidiaChassis.AuxPowerReset"]["target"] =
                "/redfish/v1/Chassis/" + chassisId +
                "/Actions/Oem/NvidiaChassis.AuxPowerReset";
            asyncResp->res
                .jsonValue["Actions"]["Oem"]["#NvidiaChassis.AuxPowerReset"]
                          ["@Redfish.ActionInfo"] =
                "/redfish/v1/Chassis/" + chassisId +
                "/Oem/Nvidia/AuxPowerResetActionInfo";
        }
#endif

        dbus::utility::getAssociationEndPoints(
            path + "/drive",
            [asyncResp, chassisId](const boost::system::error_code& ec3,
                                   const dbus::utility::MapperEndPoints& resp) {
                if (ec3 || resp.empty())
                {
                    return; // no drives = no failures
                }

                nlohmann::json reference;
                reference["@odata.id"] = boost::urls::format(
                    "/redfish/v1/Chassis/{}/Drives", chassisId);
                asyncResp->res.jsonValue["Drives"] = std::move(reference);
            });

        const std::string& connectionName = connectionNames[0].first;

        const std::vector<std::string>& interfaces2 = connectionNames[0].second;
        const std::array<const char*, 3> hasIndicatorLed = {
            "xyz.openbmc_project.Inventory.Item.Chassis",
            "xyz.openbmc_project.Inventory.Item.Panel",
            "xyz.openbmc_project.Inventory.Item.Board.Motherboard"};

        const std::string assetTagInterface =
            "xyz.openbmc_project.Inventory.Decorator.AssetTag";
        const std::string replaceableInterface =
            "xyz.openbmc_project.Inventory.Decorator.Replaceable";
        const std::string revisionInterface =
            "xyz.openbmc_project.Inventory.Decorator.Revision";
        for (const auto& interface : interfaces2)
        {
            if (interface == assetTagInterface)
            {
                dbus::utility::getProperty<std::string>(
                    connectionName, path, assetTagInterface, "AssetTag",
                    [asyncResp, chassisId](const boost::system::error_code& ec2,
                                           const std::string& property) {
                        if (ec2)
                        {
                            BMCWEB_LOG_ERROR(
                                "DBus response error for AssetTag: {}", ec2);
                            messages::internalError(asyncResp->res);
                            return;
                        }
                        asyncResp->res.jsonValue["AssetTag"] = property;
                    });
            }
            else if (interface == replaceableInterface)
            {
                dbus::utility::getProperty<bool>(
                    connectionName, path, replaceableInterface, "HotPluggable",
                    [asyncResp, chassisId](const boost::system::error_code& ec2,
                                           const bool property) {
                        if (ec2)
                        {
                            BMCWEB_LOG_ERROR(
                                "DBus response error for HotPluggable: {}",
                                ec2);
                            // messages::internalError(asyncResp->res);
                            return;
                        }
                        asyncResp->res.jsonValue["HotPluggable"] = property;
                    });
            }
            else if (interface == revisionInterface)
            {
                dbus::utility::getProperty<std::string>(
                    connectionName, path, revisionInterface, "Version",
                    [asyncResp, chassisId](const boost::system::error_code& ec2,
                                           const std::string& property) {
                        if (ec2)
                        {
                            BMCWEB_LOG_ERROR(
                                "DBus response error for Version: {}", ec2);
                            messages::internalError(asyncResp->res);
                            return;
                        }
                        asyncResp->res.jsonValue["Version"] = property;
                    });
            }
        }

        for (const char* interface : hasIndicatorLed)
        {
            if (std::ranges::find(interfaces2, interface) != interfaces2.end())
            {
                // getIndicatorLedState(asyncResp);
                getSystemLocationIndicatorActive(asyncResp);
                break;
            }
        }

        dbus::utility::getAllProperties(
            connectionName, path,
            "xyz.openbmc_project.Inventory.Decorator.Asset",
            [asyncResp, chassisId,
             path](const boost::system::error_code&,
                   const dbus::utility::DBusPropertiesMap& propertiesList) {
                handleDecoratorAssetProperties(asyncResp, chassisId, path,
                                               propertiesList);
            });
#if (!defined(ONETREE_RM)) && (!defined(ONETREE_PSM))
        dbus::utility::getAllProperties(
            connectionName, path, "xyz.openbmc_project.Inventory.Item.Chassis",
            [asyncResp](
                const boost::system::error_code&,
                const dbus::utility::DBusPropertiesMap& propertiesList) {
                handleChassisProperties(asyncResp, propertiesList);
            });
#endif
        for (const auto& interface : interfaces2)
        {
            if (interface == "xyz.openbmc_project.Common.UUID")
            {
                getChassisUUID(asyncResp, connectionName, path);
            }
            else if (interface ==
                     "xyz.openbmc_project.Inventory.Decorator.LocationCode")
            {
                getChassisLocationCode(asyncResp, connectionName, path);
            }
        }

        return;
    }

    // Couldn't find an object with that name.  return an error
    messages::resourceNotFound(asyncResp->res, "Chassis", chassisId);
}

inline void handleChassisGet(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId)
{
    asyncResp->res.clearHeader(boost::beast::http::field::allow);

    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (!membersResponseGet(asyncResp, chassisId, "ChassisCollection"))
    {
        return;
    }
    asyncResp->res.addHeader("Allow", "GET, PATCH");
    constexpr std::array<std::string_view, 2> interfaces = {
        "xyz.openbmc_project.Inventory.Item.Board",
        "xyz.openbmc_project.Inventory.Item.Chassis"};

    dbus::utility::getSubTree(
        "/xyz/openbmc_project/inventory", 0, interfaces,
        std::bind_front(handleChassisGetSubTree, asyncResp, chassisId));
}

inline void handleChassisPatch(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& param)
{
    asyncResp->res.clearHeader(boost::beast::http::field::allow);

    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (!membersResponseGet(asyncResp, param, "ChassisCollection"))
    {
        return;
    }
    constexpr std::array<std::string_view, 2> interfaces = {
        "xyz.openbmc_project.Inventory.Item.Board",
        "xyz.openbmc_project.Inventory.Item.Chassis"};

    dbus::utility::getSubTree(
        "/xyz/openbmc_project/inventory", 0, interfaces,
        [asyncResp, param, req,
         interfaces](const boost::system::error_code& ecs,
                     const dbus::utility::MapperGetSubTreeResponse& subtrees) {
            handleChassisSubTree(asyncResp, param, ecs, "patch", subtrees);

            if (!checkinvalidURIPatch)
            {
                checkinvalidURIPatch = true;

                std::optional<bool> locationIndicatorActive;
                std::optional<std::string> indicatorLed;
                std::optional<std::string> vId;

                if (param.empty())
                {
                    return;
                }

                if (!json_util::readJsonPatch(                              //
                        req, asyncResp->res,                                //
                        "LocationIndicatorActive", locationIndicatorActive, //
                        "IndicatorLED", indicatorLed,                       //
                        "Id", vId                                           //
                        ))
                {
                    return;
                }

                if (vId)
                {
                    messages::propertyNotWritable(asyncResp->res, "Id");
                    asyncResp->res.result(
                        boost::beast::http::status::bad_request);
                    return;
                }

                asyncResp->res.result(boost::beast::http::status::no_content);

                // TODO (Gunnar): Remove IndicatorLED after enough time has
                // passed
                if (!locationIndicatorActive && !indicatorLed)
                {
                    return; // delete this when we support more patch properties
                }
                if (indicatorLed)
                {
                    asyncResp->res.addHeader(
                        boost::beast::http::field::warning,
                        "299 - \"IndicatorLED is deprecated. Use LocationIndicatorActive instead.\"");
                }

                const std::string& chassisId = param;

                dbus::utility::getSubTree(
                    "/xyz/openbmc_project/inventory", 0, interfaces,
                    [asyncResp, chassisId, locationIndicatorActive,
                     indicatorLed](
                        const boost::system::error_code& ec,
                        const dbus::utility::MapperGetSubTreeResponse&
                            subtree) {
                        if (ec)
                        {
                            BMCWEB_LOG_ERROR("DBUS response error {}", ec);
                            messages::internalError(asyncResp->res);
                            return;
                        }

                        // Iterate over all retrieved ObjectPaths.
                        for (const std::pair<
                                 std::string,
                                 std::vector<std::pair<
                                     std::string, std::vector<std::string>>>>&
                                 object : subtree)
                        {
                            const std::string& path = object.first;
                            const std::vector<std::pair<
                                std::string, std::vector<std::string>>>&
                                connectionNames = object.second;

                            sdbusplus::message::object_path objPath(path);
                            if (objPath.filename() != chassisId)
                            {
                                continue;
                            }

                            if (connectionNames.empty())
                            {
                                BMCWEB_LOG_ERROR("Got 0 Connection names");
                                continue;
                            }

                            const std::vector<std::string>& interfaces3 =
                                connectionNames[0].second;

                            const std::array<const char*, 3> hasIndicatorLed = {
                                "xyz.openbmc_project.Inventory.Item.Chassis",
                                "xyz.openbmc_project.Inventory.Item.Panel",
                                "xyz.openbmc_project.Inventory.Item.Board.Motherboard"};
                            bool indicatorChassis = false;
                            for (const char* interface : hasIndicatorLed)
                            {
                                if (std::ranges::find(interfaces3, interface) !=
                                    interfaces3.end())
                                {
                                    indicatorChassis = true;
                                    break;
                                }
                            }
                            if (locationIndicatorActive)
                            {
                                if (indicatorChassis)
                                {
                                    setSystemLocationIndicatorActive(
                                        asyncResp, *locationIndicatorActive);
                                }
                                else
                                {
                                    messages::propertyUnknown(
                                        asyncResp->res,
                                        "LocationIndicatorActive");
                                }
                            }
                            if (indicatorLed)
                            {
                                if (indicatorChassis)
                                {
                                    setIndicatorLedState(asyncResp,
                                                         *indicatorLed);
                                }
                                else
                                {
                                    messages::propertyUnknown(asyncResp->res,
                                                              "IndicatorLED");
                                }
                            }
                            return;
                        }

                        messages::resourceNotFound(asyncResp->res, "Chassis",
                                                   chassisId);
                    });
            }
        });
}

inline void handleChassisPostDelete(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId)
{
    asyncResp->res.clearHeader(boost::beast::http::field::allow);

    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (!membersResponseGet(asyncResp, chassisId, "ChassisCollection"))
    {
        return;
    }
    constexpr std::array<std::string_view, 2> interfaces = {
        "xyz.openbmc_project.Inventory.Item.Board",
        "xyz.openbmc_project.Inventory.Item.Chassis"};
    dbus::utility::getSubTree(
        "/xyz/openbmc_project/inventory", 0, interfaces,
        [asyncResp, chassisId, req,
         interfaces](const boost::system::error_code& ecs,
                     const dbus::utility::MapperGetSubTreeResponse& subtrees) {
            handleChassisSubTree(asyncResp, chassisId, ecs, "post", subtrees);
        });
}

/**
 * Chassis override class for delivering Chassis Schema
 * Functions triggers appropriate requests on DBus
 */
inline void requestRoutesChassis(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Chassis/<str>/")
        .privileges(redfish::privileges::getChassis)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleChassisGet, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Chassis/<str>/")
        .privileges(redfish::privileges::patchChassis)
        .methods(boost::beast::http::verb::patch)(
            std::bind_front(handleChassisPatch, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Chassis/<str>/")
        .privileges(redfish::privileges::getChassis)
        .methods(boost::beast::http::verb::post,
                 boost::beast::http::verb::delete_)(
            std::bind_front(handleChassisPostDelete, std::ref(app)));
}

inline void setPowerTransitionTimer(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const uint64_t chassisHostTransitionTimeOut)
{
    BMCWEB_LOG_ERROR("setHostTransitionTimer");
    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code ec) {
            if (ec)
            {
                messages::internalError(asyncResp->res);
            }
        },
        "xyz.openbmc_project.State.Host0", "/xyz/openbmc_project/state/host0",
        "org.freedesktop.DBus.Properties", "Set",
        "xyz.openbmc_project.State.OperatingSystem.Status",
        "ChassisHostTransitionTimeOut",
        dbus::utility::DbusVariantType(chassisHostTransitionTimeOut));
}

inline void doChassisPowerCycle(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    constexpr std::array<std::string_view, 1> interfaces = {
        "xyz.openbmc_project.State.Chassis"};

    // Use mapper to get subtree paths.
    dbus::utility::getSubTreePaths(
        "/", 0, interfaces,
        [asyncResp](
            const boost::system::error_code& ec,
            const dbus::utility::MapperGetSubTreePathsResponse& chassisList) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("[mapper] Bad D-Bus request error: {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }

            const char* processName = "xyz.openbmc_project.State.Chassis";
            const char* interfaceName = "xyz.openbmc_project.State.Chassis";
            const char* destProperty = "RequestedPowerTransition";
            const std::string propertyValue =
                "xyz.openbmc_project.State.Chassis.Transition.PowerCycle";
            std::string objectPath =
                "/xyz/openbmc_project/state/chassis_system0";

            /* Look for system reset chassis path */
            if ((std::ranges::find(chassisList, objectPath)) ==
                chassisList.end())
            {
                /* We prefer to reset the full chassis_system, but if it doesn't
                 * exist on some platforms, fall back to a host-only power reset
                 */
                objectPath = "/xyz/openbmc_project/state/chassis0";
            }

            crow::connections::systemBus->async_method_call(
                [asyncResp](const boost::system::error_code& ec2) {
                    // Use "Set" method to set the property value.
                    if (ec2)
                    {
                        BMCWEB_LOG_ERROR("[Set] Bad D-Bus request error:", ec2);
                        messages::internalError(asyncResp->res);
                        return;
                    }
                },
                processName, objectPath, "org.freedesktop.DBus.Properties",
                "Set", interfaceName, destProperty,
                dbus::utility::DbusVariantType{propertyValue});
        });
}

/*
 * Function to get the status code ad 200 Ok with message response as
 * NoOperation
 *
 * @param[in] asyncResp - Shared pointer for completing asynchronous call
 */
inline void NoOperation(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    asyncResp->res.result(boost::beast::http::status::ok);
    asyncResp->res.jsonValue["@odata.type"] = json_util::odataType("Message");
    asyncResp->res.jsonValue["MessageId"] = "Base.1.13.0.NoOperation";
    asyncResp->res.jsonValue["Message"] =
        "The request body submitted contain no data to act upon "
        "and no changes to the resource took place.";
    asyncResp->res.jsonValue["MessageArgs"] = "[]";
    asyncResp->res.jsonValue["MessageSeverity"] = "Warning";
    asyncResp->res.jsonValue["Resolution"] =
        "Add properties in the JSON object and resubmit the request.";
}

inline const PropertyValue getHostState(
    const std::string& processName, const std::string& objectPath,
    const std::string& interfaceName, const std::string& propertyName)
{
    PropertyValue value{};

    auto b = sdbusplus::bus::new_default_system();
    auto method = b.new_method_call(processName.c_str(), objectPath.c_str(),
                                    dbusPropertyInterface, "Get");

    method.append(interfaceName, propertyName);
    auto reply = b.call(method);
    reply.read(value);
    return value;
}

inline const PropertyValue getchassisHostTransitionTimeOut(
    const std::string& servicePath, const std::string& objectName,
    const std::string& interface, const std::string& property_Name)
{
    PropertyValue value{};

    auto b = sdbusplus::bus::new_default_system();
    auto method = b.new_method_call(servicePath.c_str(), objectName.c_str(),
                                    dbusPropertyInterface, "Get");

    method.append(interface, property_Name);
    auto reply = b.call(method);
    reply.read(value);
    return value;
}

/*
 * Function to create the reboot status task
 *
 * @param[in] asyncResp - Shared pointer for completing asynchronous call
 * @param[in] payload - Double pointer to get the task Data
 */
inline void createImmediateResetTask(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    task::Payload&& payload, const std::string& resetType)
{
    BMCWEB_LOG_ERROR("after do Task creartion");

    std::shared_ptr<task::TaskData> task = task::TaskData::createTask(
        [resetType](boost::system::error_code ec, sdbusplus::message_t& msg,
                    const std::shared_ptr<task::TaskData>& taskData) {
            if (ec)
            {
                taskData->messages.emplace_back(messages::internalError());
                taskData->state = "Cancelled";
                return task::completed;
            }

            std::string iface;
            dbus::utility::DBusPropertiesMap values;

            std::string index = std::to_string(taskData->index);

            msg.read(iface, values);

            if (iface == "xyz.openbmc_project.State.OperatingSystem.Status")
            {
                const std::string* osState = nullptr;

                for (const auto& property : values)
                {
                    if (property.first == "OperatingSystemState")
                    {
                        osState = std::get_if<std::string>(&property.second);

                        if (osState == nullptr)
                        {
                            taskData->messages.emplace_back(
                                messages::internalError());
                            return task::completed;
                        }
                    }
                }

                if (osState == nullptr)
                {
                    return !task::completed;
                }

                if (*osState ==
                    "xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.Inactive")
                {
                    taskData->state = "Running";
                    taskData->messages.emplace_back(
                        messages::taskStarted(index));
                    taskData->extendTimer(std::chrono::minutes(5));
                    return !task::completed;
                }

                if (*osState ==
                    "xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.Standby")
                {
                    taskData->messages.emplace_back(
                        messages::taskCompletedOK(index));
                    taskData->state = "Completed";
                    return task::completed;
                }
                taskData->extendTimer(std::chrono::minutes(10));
            }
            return !task::completed;
        },
        "type='signal',interface='org.freedesktop.DBus.Properties',"
        "member='PropertiesChanged',path='/xyz/openbmc_project/state/host0'");
    task->startTimer(std::chrono::minutes(5));
    task->populateResp(asyncResp->res);
    task->payload.emplace(std::move(payload));
}

/*
 * Function to create the reboot status task
 *
 * @param[in] asyncResp - Shared pointer for completing asynchronous call
 * @param[in] payload - Double pointer to get the task Data
 */
inline void createMaintenanceWindowTask(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    task::Payload&& payload, const std::string& resetType)
{
    BMCWEB_LOG_ERROR("after do Task creation");

    std::shared_ptr<task::TaskData> task = task::TaskData::createTask(
        [resetType](boost::system::error_code ec, sdbusplus::message_t& msg,
                    const std::shared_ptr<task::TaskData>& taskData) {
            if (ec)
            {
                taskData->messages.emplace_back(messages::internalError());
                taskData->state = "Cancelled";
                return task::completed;
            }

            std::string iface;
            dbus::utility::DBusPropertiesMap values;

            std::string index = std::to_string(taskData->index);
            msg.read(iface, values);

            const char* servicePath = "xyz.openbmc_project.State.Host0";
            const char* interfacePath =
                "xyz.openbmc_project.State.OperatingSystem.Status";
            const char* property_Name = "ChassisHostTransitionTimeOut";
            const char* objectName = "/xyz/openbmc_project/state/host0";

            auto timeOut_value = getchassisHostTransitionTimeOut(
                servicePath, objectName, interfacePath, property_Name);

            auto reqchassisHostTransitionTimeOut =
                std::get<uint64_t>(timeOut_value);

            if (iface == "xyz.openbmc_project.State.OperatingSystem.Status")
            {
                const uint64_t* timeOutValue = nullptr;
                const std::string* osState = nullptr;

                for (const auto& property : values)
                {
                    if (property.first == "ChassisHostTransitionTimeOut")
                    {
                        timeOutValue = std::get_if<uint64_t>(&property.second);

                        if (timeOutValue == nullptr)
                        {
                            taskData->messages.emplace_back(
                                messages::internalError());
                            return task::completed;
                        }

                        if (*timeOutValue == 0)
                        {
                            chassisTimerFlag = true;
                        }
                        else
                        {
                            chassisTimerFlag = false;
                        }
                    }

                    if (property.first == "OperatingSystemState")
                    {
                        osState = std::get_if<std::string>(&property.second);

                        if (osState == nullptr)
                        {
                            taskData->messages.emplace_back(
                                messages::internalError());
                            return task::completed;
                        }
                    }
                }

                if (!chassisTimerFlag)
                {
                    if (*osState ==
                            "xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.Inactive" ||
                        *osState ==
                            "xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.Standby")
                    {
                        if (!chassisTaskAlreadyHappened)
                            chassisTaskAlreadyHappened = true;
                    }
                }

                if (chassisTimerFlag && chassisTaskAlreadyHappened)
                {
                    taskData->state = "Cancelled";
                    taskData->messages.emplace_back(
                        messages::taskCancelled(index));
                    chassisTaskAlreadyHappened = false;
                    chassisTimerFlag = false;
                    return task::completed;
                }

                if (reqchassisHostTransitionTimeOut == 0 && osState != nullptr)
                {
                    if (*osState ==
                        "xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.Inactive")
                    {
                        if (!chassisTaskAlreadyHappened)
                        {
                            taskData->state = "Running";
                            taskData->messages.emplace_back(
                                messages::taskStarted(index));
                        }
                        taskData->extendTimer(std::chrono::minutes(15));
                        return !task::completed;
                    }

                    if (*osState ==
                        "xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.Standby")
                    {
                        if (!chassisTaskAlreadyHappened)
                        {
                            taskData->messages.emplace_back(
                                messages::taskCompletedOK(index));
                            chassisTimerFlag = false;
                            taskData->state = "Completed";
                            return task::completed;
                        }
                    }
                }
                taskData->extendTimer(
                    std::chrono::seconds(reqchassisHostTransitionTimeOut) +
                    (std::chrono::minutes(10)));
            }
            return !task::completed;
        },
        "type='signal',interface='org.freedesktop.DBus.Properties',"
        "member='PropertiesChanged',path='/xyz/openbmc_project/state/host0'");
    task->startTimer(std::chrono::minutes(5));
    task->populateResp(asyncResp->res);
    task->payload.emplace(std::move(payload));

    auto chassis_Value = getchassisHostTransitionTimeOut(
        "xyz.openbmc_project.State.Host0", "/xyz/openbmc_project/state/host0",
        "xyz.openbmc_project.State.OperatingSystem.Status",
        "ChassisHostTransitionTimeOut");

    uint64_t requestedPowerTransition = std::get<uint64_t>(chassis_Value);
    if (requestedPowerTransition > 5)
    {
        // Will not get any signal from host for pending state so
        // considering after 5 seconds state will be pending state
        if (task->state == "New")
        {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            task->state = "Pending";
            task->messages.emplace_back(
                messages::taskPaused(std::to_string(task->index)));
        }
    }
}

/**
 * Func give the timeout value in seconds
 *
 * @param[in] posixTime_1 - MaintenanceWindowStarTime converted to posixtime
 * @param[in] redfishDateTimeOffset - Current BMC Timezone
 */
inline uint64_t handleDifferenceTime(boost::posix_time::ptime posixTime_1,
                                     std::string& redfishDateTimeOffset)
{
    uint64_t durSecs;

    std::stringstream stream2(redfishDateTimeOffset);
    boost::posix_time::ptime posixTime_2;
    // Facet gets deleted with the stringsteam
    auto ifc2 = std::make_unique<boost::local_time::local_time_input_facet>(
        "%Y-%m-%d %H:%M:%S%F %ZP");
    stream2.imbue(std::locale(stream2.getloc(), ifc2.release()));
    boost::local_time::local_date_time ldt2(boost::local_time::not_a_date_time);
    posixTime_2 = ldt2.utc_time();

    if (stream2 >> ldt2)
    {
        posixTime_2 = ldt2.utc_time();
    }

    boost::posix_time::time_duration dur = posixTime_1 - posixTime_2;
    durSecs = static_cast<uint64_t>(dur.total_seconds());
    return durSecs;
}

inline void handleChassisResetActionInfoPost(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId)
{
    crow::connections::systemBus->async_method_call(
        [&app, asyncResp, chassisId,
         req](const boost::system::error_code ec,
              const std::vector<std::string>& objects) {
            if (ec)
            {
                messages::internalError(asyncResp->res);
                return;
                return;
            }
            for (const std::string& object : objects)
            {
                if (!boost::ends_with(object, chassisId))
                {
                    continue;
                }

                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }
                BMCWEB_LOG_DEBUG("Post Chassis Reset.");

                std::string resetType;
                std::optional<std::string> operationApplyTime;
                std::optional<std::string> maintenanceWindowStartTime;
                std::string startTime;

                uint64_t timeOut = 0;

                // Current BMC Timezone
                std::string redfishDateTimeOffset =
                    redfish::time_utils::getDateTimeOffsetNow().first;

                task::Payload payload(req);

                const char* processName = "xyz.openbmc_project.State.Host";
                const char* interfaceName = "xyz.openbmc_project.State.Host";
                const char* propName = "CurrentHostState";
                const char* objectPath = "/xyz/openbmc_project/state/host0";

                const char* servicePath = "xyz.openbmc_project.State.Host0";
                const char* interfacePath =
                    "xyz.openbmc_project.State.OperatingSystem.Status";
                const char* property_Name = "ChassisHostTransitionTimeOut";
                const char* objectName = "/xyz/openbmc_project/state/host0";

                auto value = getHostState(processName, objectPath,
                                          interfaceName, propName);
                auto reqHostState = std::get<std::string>(value);

                auto timeOut_value = getchassisHostTransitionTimeOut(
                    servicePath, objectName, interfacePath, property_Name);
                auto reqchassisHostTransitionTimeOut =
                    std::get<uint64_t>(timeOut_value);

                if (!json_util::readJsonAction(                   //
                        req, asyncResp->res,                      //
                        "ResetType", resetType,                   //
                        "OperationApplyTime", operationApplyTime, //
                        "MaintenanceWindowStartTime",
                        maintenanceWindowStartTime                //
                        ))
                {
                    return;
                }

                // To provide as a stringstream object
                startTime = *maintenanceWindowStartTime;

                if (resetType != "PowerCycle")
                {
                    BMCWEB_LOG_ERROR("Invalid property value for ResetType:",
                                     resetType);
                    messages::actionParameterNotSupported(
                        asyncResp->res, resetType, "ResetType");
                    return;
                }

                if (reqHostState !=
                    "xyz.openbmc_project.State.Host.HostState.Running")
                {
                    NoOperation(asyncResp);
                    return;
                }

                if (resetType == "PowerCycle" && !operationApplyTime &&
                    !maintenanceWindowStartTime)
                {
                    doChassisPowerCycle(asyncResp);
                    messages::success(asyncResp->res);
                    return;
                }

                if (operationApplyTime == "Immediate")
                {
                    BMCWEB_LOG_ERROR("Immediate");
                    if (!(maintenanceWindowStartTime))
                    {
                        BMCWEB_LOG_ERROR("Not of maintenanceWindowStartTime");
                        createImmediateResetTask(asyncResp, std::move(payload),
                                                 resetType);
                        doChassisPowerCycle(asyncResp);
                        return;
                    }

                    else
                    {
                        BMCWEB_LOG_ERROR(
                            "Invalid Property for Immediate reboot");
                        messages::actionParameterNotSupported(
                            asyncResp->res, "MaintenanceWindowStartTime",
                            "Immediate");
                        return;
                    }
                }

                if (operationApplyTime == "AtMaintenanceWindowStart" &&
                    maintenanceWindowStartTime)
                {
                    BMCWEB_LOG_ERROR("AtMaintenanceWindowStart");

                    if (reqchassisHostTransitionTimeOut != 0)
                    {
                        messages::resourceInUse(asyncResp->res);
                        return;
                    }

                    if (maintenanceWindowStartTime <= redfishDateTimeOffset)
                    {
                        messages::propertyValueIncorrect(
                            asyncResp->res, "AtMaintenanceWindowStartTime",
                            startTime);
                        return;
                    }

                    std::stringstream stream1(startTime);
                    boost::posix_time::ptime posixTime_1;
                    // Facet gets deleted with the stringsteam
                    auto ifc1 = std::make_unique<
                        boost::local_time::local_time_input_facet>(
                        "%Y-%m-%d %H:%M:%S%F %ZP");
                    stream1.imbue(
                        std::locale(stream1.getloc(), ifc1.release()));
                    boost::local_time::local_date_time ldt1(
                        boost::local_time::not_a_date_time);

                    if (stream1 >> ldt1)
                    {
                        posixTime_1 = ldt1.utc_time();
                    }

                    else
                    {
                        BMCWEB_LOG_ERROR(
                            "MaintenanceWindowStartTime Format Error");
                        messages::propertyValueFormatError(
                            asyncResp->res, startTime,
                            "MaintenanceWindowStartTime");
                        return;
                    }

                    // Difference Time of BMCTime & MaintenanceWindowStartTime
                    timeOut = handleDifferenceTime(posixTime_1,
                                                   redfishDateTimeOffset);

                    setPowerTransitionTimer(asyncResp, timeOut);
                    createMaintenanceWindowTask(asyncResp, std::move(payload),
                                                resetType);
                    doChassisPowerCycle(asyncResp);
                    return;
                }
                else
                {
                    BMCWEB_LOG_ERROR(
                        "Missing Property AtMaintenanceWindowStartTime");
                    messages::actionParameterMissing(
                        asyncResp->res, "Reset",
                        "AtMaintenanceWindowStartTime");
                    return;
                }
            }
            messages::resourceNotFound(asyncResp->res, "#Chassis", chassisId);
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths",
        "/xyz/openbmc_project/inventory", 0,
        std::array<const char*, 2>{
            "xyz.openbmc_project.Inventory.Item.Board",
            "xyz.openbmc_project.Inventory.Item.Chassis"});
    return;
}

/**
 * ChassisResetAction class supports the POST method for the Reset
 * action.
 * Function handles POST method request.
 * Analyzes POST body before sending Reset request data to D-Bus.
 */

inline void requestRoutesChassisResetAction(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Chassis/<str>/Actions/Chassis.Reset/")
        .privileges(redfish::privileges::postChassis)
        .methods(boost::beast::http::verb::post)(
            std::bind_front(handleChassisResetActionInfoPost, std::ref(app)));
}

inline void handleChassisResetActionInfoGet(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    asyncResp->res.jsonValue["@odata.type"] =
        json_util::odataType("ActionInfo");
    asyncResp->res.jsonValue["@odata.id"] = boost::urls::format(
        "/redfish/v1/Chassis/{}/ResetActionInfo", chassisId);
    asyncResp->res.jsonValue["Name"] = "Reset Action Info";

    asyncResp->res.jsonValue["Id"] = "ResetActionInfo";
    asyncResp->res.jsonValue["Description"] =
        "Reset Action Information for Chassis";
    nlohmann::json::array_t parameters;
    nlohmann::json::object_t parameter;
    parameter["Name"] = "ResetType";
    parameter["Required"] = true;
    parameter["DataType"] = action_info::ParameterTypes::String;
    nlohmann::json::array_t allowed;
    allowed.emplace_back("PowerCycle");
    parameter["AllowableValues"] = std::move(allowed);
    parameters.emplace_back(std::move(parameter));

    asyncResp->res.jsonValue["Parameters"] = std::move(parameters);
}

/**
 * ChassisResetActionInfo derived class for delivering Chassis
 * ResetType AllowableValues using ResetInfo schema.
 */
inline void requestRoutesChassisResetActionInfo(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Chassis/<str>/ResetActionInfo/")
        .privileges(redfish::privileges::getActionInfo)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleChassisResetActionInfoGet, std::ref(app)));
}

} // namespace redfish
