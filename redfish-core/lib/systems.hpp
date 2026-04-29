// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
// SPDX-FileCopyrightText: Copyright 2018 Intel Corporation
#pragma once

#include "bmcweb_config.h"

#include "app.hpp"
#include "dbus_singleton.hpp"
#include "dbus_utility.hpp"
#include "generated/enums/action_info.hpp"
#include "generated/enums/computer_system.hpp"
#include "generated/enums/open_bmc_computer_system.hpp"
#include "generated/enums/resource.hpp"
#include "hypervisor_system.hpp"
#include "led.hpp"
#include "query.hpp"
#include "redfish_util.hpp"
#include "registries/privilege_registry.hpp"
#include "system_utils.hpp"
#include "systems_header.hpp"
#include "utils/dbus_utils.hpp"
#include "utils/json_utils.hpp"
#include "utils/pcie_util.hpp"
#include "utils/sw_utils.hpp"
#include "utils/time_utils.hpp"

#include <boost/asio/error.hpp>
#include <boost/container/flat_map.hpp>
#include <boost/date_time.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/linux_error.hpp>
#include <boost/url/format.hpp>
#include <chassis.hpp>
#include <sdbusplus/asio/property.hpp>
#include <sdbusplus/message.hpp>
#include <sdbusplus/unpack_properties.hpp>
#include <task.hpp>
#include <utils/service_utils.hpp>

#include <array>
#include <cstdlib>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace redfish
{

// D-Bus service and interface constants
static constexpr const char* hostStateService =
    "xyz.openbmc_project.State.Host0";
static constexpr const char* singleHostPath =
    "/xyz/openbmc_project/state/host0";
static constexpr const char* chassisStateService =
    "xyz.openbmc_project.State.Chassis0";
static constexpr const char* singleChassisPath =
    "/xyz/openbmc_project/state/chassis0";
static constexpr const char* chassisStateInterface =
    "xyz.openbmc_project.State.Chassis";

// Common interface
static constexpr const char* hostStateInterface =
    "xyz.openbmc_project.State.Host";

// Dual node D-Bus services and paths

// Node 1 (Dual-node systems - first node)
static constexpr const char* host1Service = "xyz.openbmc_project.State.Host1";
static constexpr const char* host1Path = "/xyz/openbmc_project/state/host1";
static constexpr const char* chassis1Service =
    "xyz.openbmc_project.State.Chassis1";
static constexpr const char* chassis1Path =
    "/xyz/openbmc_project/state/chassis1";

// Node 2 (Dual-node systems - second node)
static constexpr const char* host2Service = "xyz.openbmc_project.State.Host2";
static constexpr const char* host2Path = "/xyz/openbmc_project/state/host2";
static constexpr const char* chassis2Service =
    "xyz.openbmc_project.State.Chassis2";
static constexpr const char* chassis2Path =
    "/xyz/openbmc_project/state/chassis2";

// Timeout service (uses node suffix)
static constexpr const char* timeoutService = "xyz.openbmc_project.State.Host0";
static constexpr const char* timeoutInterface =
    "xyz.openbmc_project.State.OperatingSystem.Status";

static constexpr const char* serialConsoleSshServiceName =
    "obmc_2dconsole_2dssh";

const static std::array<std::pair<std::string_view, std::string_view>, 2>
    protocolToDBusForSystems{
        {{"SSH", "obmc-console-ssh"}, {"IPMI", "phosphor-ipmi-net"}}};
constexpr const char* dbus_Property_Interface =
    "org.freedesktop.DBus.Properties";

/**
 * @brief Updates the Functional State of DIMMs
 *
 * @param[in] asyncResp Shared pointer for completing asynchronous calls
 * @param[in] dimmState Dimm's Functional state, true/false
 *
 * @return None.
 */
inline void updateDimmProperties(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp, bool isDimmFunctional)
{
    BMCWEB_LOG_DEBUG("Dimm Functional: {}", isDimmFunctional);

    // Set it as Enabled if at least one DIMM is functional
    // Update STATE only if previous State was DISABLED and current Dimm is
    // ENABLED.
    const nlohmann::json& prevMemSummary =
        asyncResp->res.jsonValue["MemorySummary"]["Status"]["State"];
    if (prevMemSummary == "Disabled")
    {
        if (isDimmFunctional)
        {
            asyncResp->res.jsonValue["MemorySummary"]["Status"]["State"] =
                "Enabled";
        }
    }
}

/*
 * @brief Update "ProcessorSummary" "Status" "State" based on
 *        CPU Functional State
 *
 * @param[in] asyncResp Shared pointer for completing asynchronous calls
 * @param[in] cpuFunctionalState is CPU functional true/false
 *
 * @return None.
 */
inline void modifyCpuFunctionalState(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp, bool isCpuFunctional)
{
    BMCWEB_LOG_DEBUG("Cpu Functional: {}", isCpuFunctional);

    const nlohmann::json& prevProcState =
        asyncResp->res.jsonValue["ProcessorSummary"]["Status"]["State"];

    // Set it as Enabled if at least one CPU is functional
    // Update STATE only if previous State was Non_Functional and current CPU is
    // Functional.
    if (prevProcState == "Disabled")
    {
        if (isCpuFunctional)
        {
            asyncResp->res.jsonValue["ProcessorSummary"]["Status"]["State"] =
                "Enabled";
        }
    }
}

/*
 * @brief Update "ProcessorSummary" "Count" based on Cpu PresenceState
 *
 * @param[in] asyncResp Shared pointer for completing asynchronous calls
 * @param[in] cpuPresenceState CPU present or not
 *
 * @return None.
 */
inline void modifyCpuPresenceState(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp, bool isCpuPresent)
{
    BMCWEB_LOG_DEBUG("Cpu Present: {}", isCpuPresent);

    if (isCpuPresent)
    {
        nlohmann::json& procCount =
            asyncResp->res.jsonValue["ProcessorSummary"]["Count"];
        auto* procCountPtr =
            procCount.get_ptr<nlohmann::json::number_integer_t*>();
        if (procCountPtr != nullptr)
        {
            // shouldn't be possible to be nullptr
            *procCountPtr += 1;
        }
    }
}

inline void getProcessorProperties(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::vector<std::pair<std::string, dbus::utility::DbusVariantType>>&
        properties)
{
    BMCWEB_LOG_DEBUG("Got {} Cpu properties.", properties.size());

    const std::string* modelStr = nullptr;

    const bool modelsuccess = sdbusplus::unpackPropertiesNoThrow(
        dbus_utils::UnpackErrorPrinter(), properties, "Family", modelStr);

    if (!modelsuccess)
    {
        return;
    }

    if ((modelStr != nullptr) && (*modelStr != ""))
    {
        nlohmann::json& prevModel =
            asyncResp->res.jsonValue["ProcessorSummary"]["Model"];
        std::string* prevModelPtr = prevModel.get_ptr<std::string*>();

        // If CPU Models are different, use the first entry in
        // alphabetical order

        // If Model has never been set
        // before, set it to *modelStr
        if (prevModelPtr == nullptr)
        {
            prevModel = *modelStr;
        }
        // If Model has been set before, only change if new Model is
        // higher in alphabetical order
        else
        {
            if (*modelStr < *prevModelPtr)
            {
                prevModel = *modelStr;
            }
        }
    }
    const uint16_t* coreCount = nullptr;

    const bool success = sdbusplus::unpackPropertiesNoThrow(
        dbus_utils::UnpackErrorPrinter(), properties, "CoreCount", coreCount);

    if (!success)
    {
        messages::internalError(asyncResp->res);
        return;
    }

    if (coreCount != nullptr)
    {
        nlohmann::json& coreCountJson =
            asyncResp->res.jsonValue["ProcessorSummary"]["CoreCount"];
        uint64_t* coreCountJsonPtr = coreCountJson.get_ptr<uint64_t*>();

        if (coreCountJsonPtr == nullptr)
        {
            coreCountJson = *coreCount;
        }
        else
        {
            *coreCountJsonPtr += *coreCount;
        }
    }
}

/*
 * @brief Get ProcessorSummary fields
 *
 * @param[in] asyncResp Shared pointer for completing asynchronous calls
 * @param[in] service dbus service for Cpu Information
 * @param[in] path dbus path for Cpu
 *
 * @return None.
 */
inline void getProcessorSummary(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& service, const std::string& path)
{
    auto getCpuPresenceState = [asyncResp](const boost::system::error_code& ec3,
                                           const bool cpuPresenceCheck) {
        if (ec3)
        {
            BMCWEB_LOG_ERROR("DBUS response error {}", ec3);
            return;
        }
        modifyCpuPresenceState(asyncResp, cpuPresenceCheck);
    };

    // Get the Presence of CPU
    dbus::utility::getProperty<bool>(service, path,
                                     "xyz.openbmc_project.Inventory.Item",
                                     "Present", std::move(getCpuPresenceState));

    dbus::utility::getAllProperties(
        service, path, "xyz.openbmc_project.Inventory.Item.Cpu",
        [asyncResp, service,
         path](const boost::system::error_code& ec2,
               const dbus::utility::DBusPropertiesMap& properties) {
            if (ec2)
            {
                BMCWEB_LOG_ERROR("DBUS response error {}", ec2);
                messages::internalError(asyncResp->res);
                return;
            }
            getProcessorProperties(asyncResp, properties);
        });
}

/*
 * @brief processMemoryProperties fields
 *
 * @param[in] asyncResp Shared pointer for completing asynchronous calls
 * @param[in] DBUS properties for memory
 *
 * @return None.
 */
inline void processMemoryProperties(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const dbus::utility::DBusPropertiesMap& properties)
{
    BMCWEB_LOG_DEBUG("Got {} Dimm properties.", properties.size());

    if (properties.empty())
    {
        return;
    }

    const size_t* memorySizeInKB = nullptr;

    const bool success = sdbusplus::unpackPropertiesNoThrow(
        dbus_utils::UnpackErrorPrinter(), properties, "MemorySizeInKB",
        memorySizeInKB);

    if (!success)
    {
        messages::internalError(asyncResp->res);
        return;
    }

    if (memorySizeInKB != nullptr)
    {
        nlohmann::json& totalMemory =
            asyncResp->res.jsonValue["MemorySummary"]["TotalSystemMemoryGiB"];
        const double* preValue = totalMemory.get_ptr<const double*>();
        if (preValue == nullptr)
        {
            asyncResp->res.jsonValue["MemorySummary"]["TotalSystemMemoryGiB"] =
                static_cast<double>(*memorySizeInKB) / (1024 * 1024);
        }
        else
        {
            asyncResp->res.jsonValue["MemorySummary"]["TotalSystemMemoryGiB"] =
                static_cast<double>(*memorySizeInKB) / (1024 * 1024) +
                *preValue;
        }
    }
}

/*
 * @brief Get getMemorySummary fields
 *
 * @param[in] asyncResp Shared pointer for completing asynchronous calls
 * @param[in] service dbus service for memory Information
 * @param[in] path dbus path for memory
 *
 * @return None.
 */
inline void getMemorySummary(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& service, const std::string& path)
{
    dbus::utility::getAllProperties(
        service, path, "xyz.openbmc_project.Inventory.Item.Dimm",
        [asyncResp, service,
         path](const boost::system::error_code& ec2,
               const dbus::utility::DBusPropertiesMap& properties) {
            if (ec2)
            {
                BMCWEB_LOG_ERROR("DBUS response error {}", ec2);
                messages::internalError(asyncResp->res);
                return;
            }
            processMemoryProperties(asyncResp, properties);
        });
}

inline void afterGetUUID(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                         const boost::system::error_code& ec,
                         const dbus::utility::DBusPropertiesMap& properties)
{
    if (ec)
    {
        BMCWEB_LOG_ERROR("DBUS response error {}", ec);
        messages::internalError(asyncResp->res);
        return;
    }
    BMCWEB_LOG_DEBUG("Got {} UUID properties.", properties.size());

    const std::string* uUID = nullptr;

    const bool success = sdbusplus::unpackPropertiesNoThrow(
        dbus_utils::UnpackErrorPrinter(), properties, "UUID", uUID);

    if (!success)
    {
        messages::internalError(asyncResp->res);
        return;
    }

    if (uUID != nullptr)
    {
        std::string valueStr = *uUID;
        if (valueStr.size() == 32)
        {
            valueStr.insert(8, 1, '-');
            valueStr.insert(13, 1, '-');
            valueStr.insert(18, 1, '-');
            valueStr.insert(23, 1, '-');
        }
        BMCWEB_LOG_DEBUG("UUID = {}", valueStr);
        asyncResp->res.jsonValue["UUID"] = valueStr;
    }
}

inline void afterGetInventory(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const boost::system::error_code& ec,
    const dbus::utility::DBusPropertiesMap& propertiesList)
{
    if (ec)
    {
        // doesn't have to include this
        // interface
        return;
    }
    BMCWEB_LOG_DEBUG("Got {} properties for system", propertiesList.size());

    const std::string* partNumber = nullptr;
    const std::string* serialNumber = nullptr;
    const std::string* manufacturer = nullptr;
    const std::string* model = nullptr;
    const std::string* subModel = nullptr;

    const bool success = sdbusplus::unpackPropertiesNoThrow(
        dbus_utils::UnpackErrorPrinter(), propertiesList, "PartNumber",
        partNumber, "SerialNumber", serialNumber, "Manufacturer", manufacturer,
        "Model", model, "SubModel", subModel);

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

    if (subModel != nullptr)
    {
        asyncResp->res.jsonValue["SubModel"] = *subModel;
    }

    // Grab the bios version
    sw_util::populateSoftwareInformation(asyncResp, sw_util::biosPurpose,
                                         "BiosVersion", false);
}

inline void afterGetAssetTag(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const boost::system::error_code& ec, const std::string& value)
{
    if (ec)
    {
        // doesn't have to include this
        // interface
        return;
    }

    asyncResp->res.jsonValue["AssetTag"] = value;
}

inline void afterSystemGetSubTree(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const boost::system::error_code& ec,
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
        BMCWEB_LOG_DEBUG("Got path: {}", path);
        const std::vector<std::pair<std::string, std::vector<std::string>>>&
            connectionNames = object.second;
        if (connectionNames.empty())
        {
            continue;
        }

        // This is not system, so check if it's cpu, dimm, UUID or
        // BiosVer
        for (const auto& connection : connectionNames)
        {
            for (const auto& interfaceName : connection.second)
            {
                if (interfaceName == "xyz.openbmc_project.Inventory.Item.Dimm")
                {
                    BMCWEB_LOG_DEBUG("Found Dimm, now get its properties.");

                    getMemorySummary(asyncResp, connection.first, path);
                }
                else if (interfaceName ==
                         "xyz.openbmc_project.Inventory.Item.Cpu")
                {
                    BMCWEB_LOG_DEBUG("Found Cpu, now get its properties.");

                    getProcessorSummary(asyncResp, connection.first, path);
                }
                else if (interfaceName == "xyz.openbmc_project.Common.UUID")
                {
                    BMCWEB_LOG_DEBUG("Found UUID, now get its properties.");

                    dbus::utility::getAllProperties(
                        connection.first, path,
                        "xyz.openbmc_project.Common.UUID",
                        [asyncResp](const boost::system::error_code& ec3,
                                    const dbus::utility::DBusPropertiesMap&
                                        properties) {
                            afterGetUUID(asyncResp, ec3, properties);
                        });
                }
                else if (interfaceName ==
                         "xyz.openbmc_project.Inventory.Item.System")
                {
                    dbus::utility::getAllProperties(
                        connection.first, path,
                        "xyz.openbmc_project.Inventory.Decorator.Asset",
                        [asyncResp](const boost::system::error_code& ec3,
                                    const dbus::utility::DBusPropertiesMap&
                                        properties) {
                            afterGetInventory(asyncResp, ec3, properties);
                        });

                    dbus::utility::getProperty<std::string>(
                        connection.first, path,
                        "xyz.openbmc_project.Inventory.Decorator."
                        "AssetTag",
                        "AssetTag",
                        std::bind_front(afterGetAssetTag, asyncResp));
                }
            }
        }
    }
}

/*
 * @brief Retrieves computer system properties over dbus
 *
 * @param[in] asyncResp Shared pointer for completing asynchronous calls
 *
 * @return None.
 */
void getComputerSystem(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    BMCWEB_LOG_DEBUG("Get available system components.");
    constexpr std::array<std::string_view, 5> interfaces = {
        "xyz.openbmc_project.Inventory.Decorator.Asset",
        "xyz.openbmc_project.Inventory.Item.Cpu",
        "xyz.openbmc_project.Inventory.Item.Dimm",
        "xyz.openbmc_project.Inventory.Item.System",
        "xyz.openbmc_project.Common.UUID",
    };
    dbus::utility::getSubTree(
        "/xyz/openbmc_project/inventory", 0, interfaces,
        std::bind_front(afterSystemGetSubTree, asyncResp));
}

/**
 * @brief Retrieves host state properties over dbus
 *
 * @param[in] asyncResp     Shared pointer for completing asynchronous calls.
 * @param[in] systemName    Optional system name to determine node-specific
 * path. If empty, defaults to host0 for legacy support.
 *
 * @return None.
 */
void getHostState(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                  const std::string& systemName)
{
    BMCWEB_LOG_DEBUG("Get host information for {}",
                     systemName.empty() ? "default" : systemName);

    std::string hostService = hostStateService; // default
    std::string hostPath = singleHostPath;      // default

    if (system_utils::isDualHostEnabled())
    {
        // Dual-node system
        if (systemName == "system1")
        {
            // "system1" maps to Host2
            hostService = host2Service;
            hostPath = host2Path;
        }
        else
        {
            // "system" (default) maps to Host1 in dual-node mode
            hostService = host1Service;
            hostPath = host1Path;
        }
    }

    dbus::utility::getProperty<std::string>(
        hostService, hostPath, hostStateInterface, "CurrentHostState",
        [asyncResp, systemName](const boost::system::error_code& ec,
                                const std::string& hostState) {
            if (ec)
            {
                if (ec == boost::system::errc::host_unreachable)
                {
                    // Service not available, no error, just don't return
                    // host state info
                    BMCWEB_LOG_DEBUG("Service not available {}", ec);
                    return;
                }
                BMCWEB_LOG_ERROR("DBUS response error {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }

            BMCWEB_LOG_ERROR("Host state: {}", hostState);

            std::string currentState =
                hostState.substr(hostState.rfind('.') + 1);

            // Verify Host State by comparing only the final state value
            if (currentState == "Running")
            {
                asyncResp->res.jsonValue["PowerState"] =
                    resource::PowerState::On;
                asyncResp->res.jsonValue["Status"]["State"] =
                    resource::State::Enabled;
            }
            else if (currentState == "Quiesced")
            {
                asyncResp->res.jsonValue["PowerState"] =
                    resource::PowerState::On;
                asyncResp->res.jsonValue["Status"]["State"] =
                    resource::State::Quiesced;
            }
            else if (currentState == "DiagnosticMode")
            {
                asyncResp->res.jsonValue["PowerState"] =
                    resource::PowerState::On;
                asyncResp->res.jsonValue["Status"]["State"] =
                    resource::State::InTest;
            }
            else if (currentState == "TransitioningToRunning")
            {
                asyncResp->res.jsonValue["PowerState"] =
                    resource::PowerState::PoweringOn;
                asyncResp->res.jsonValue["Status"]["State"] =
                    resource::State::Starting;
            }
            else if (currentState == "TransitioningToOff")
            {
                asyncResp->res.jsonValue["PowerState"] =
                    resource::PowerState::PoweringOff;
                asyncResp->res.jsonValue["Status"]["State"] =
                    resource::State::Disabled;
            }
            else
            {
                asyncResp->res.jsonValue["PowerState"] =
                    resource::PowerState::Off;
                asyncResp->res.jsonValue["Status"]["State"] =
                    resource::State::Disabled;
            }
        });
}

/**
 * @brief Translates boot source DBUS property value to redfish.
 *
 * @param[in] dbusSource    The boot source in DBUS speak.
 *
 * @return Returns as a string, the boot source in Redfish terms. If translation
 * cannot be done, returns an empty string.
 */
inline std::string dbusToRfBootSource(const std::string& dbusSource)
{
    if (dbusSource == "xyz.openbmc_project.Control.Boot.Source.Sources.Default")
    {
        return "None";
    }
    if (dbusSource == "xyz.openbmc_project.Control.Boot.Source.Sources.Disk")
    {
        return "Hdd";
    }
    if (dbusSource ==
        "xyz.openbmc_project.Control.Boot.Source.Sources.ExternalMedia")
    {
        return "Cd";
    }
    if (dbusSource == "xyz.openbmc_project.Control.Boot.Source.Sources.Network")
    {
        return "Pxe";
    }
    if (dbusSource ==
        "xyz.openbmc_project.Control.Boot.Source.Sources.RemovableMedia")
    {
        return "Usb";
    }
    if (dbusSource == "xyz.openbmc_project.Control.Boot.Source.Sources.HTTP")
    {
        return "UefiHttp";
    }
    return "";
}

/**
 * @brief Translates boot type DBUS property value to redfish.
 *
 * @param[in] dbusType    The boot type in DBUS speak.
 *
 * @return Returns as a string, the boot type in Redfish terms. If translation
 * cannot be done, returns an empty string.
 */
inline std::string dbusToRfBootType(const std::string& dbusType)
{
    if (dbusType == "xyz.openbmc_project.Control.Boot.Type.Types.Legacy")
    {
        return "Legacy";
    }
    if (dbusType == "xyz.openbmc_project.Control.Boot.Type.Types.EFI")
    {
        return "UEFI";
    }
    return "";
}

/**
 * @brief Translates boot mode DBUS property value to redfish.
 *
 * @param[in] dbusMode    The boot mode in DBUS speak.
 *
 * @return Returns as a string, the boot mode in Redfish terms. If translation
 * cannot be done, returns an empty string.
 */
inline std::string dbusToRfBootMode(const std::string& dbusMode)
{
    if (dbusMode == "xyz.openbmc_project.Control.Boot.Mode.Modes.Regular")
    {
        return "None";
    }
    if (dbusMode == "xyz.openbmc_project.Control.Boot.Mode.Modes.Setup")
    {
        return "BiosSetup";
    }
    if (dbusMode == "xyz.openbmc_project.Control.Boot.Mode.Modes.Diag")
    {
        return "Diags";
    }
    return "";
}

/**
 * @brief Translates boot progress DBUS property value to redfish.
 *
 * @param[in] dbusBootProgress    The boot progress in DBUS speak.
 *
 * @return Returns as a string, the boot progress in Redfish terms. If
 *         translation cannot be done, returns "None".
 */
inline std::string dbusToRfBootProgress(const std::string& dbusBootProgress)
{
    // Now convert the D-Bus BootProgress to the appropriate Redfish
    // enum
    std::string rfBpLastState = "None";
    if (dbusBootProgress == "xyz.openbmc_project.State.Boot.Progress."
                            "ProgressStages.Unspecified")
    {
        rfBpLastState = "None";
    }
    else if (dbusBootProgress ==
             "xyz.openbmc_project.State.Boot.Progress.ProgressStages."
             "PrimaryProcInit")
    {
        rfBpLastState = "PrimaryProcessorInitializationStarted";
    }
    else if (dbusBootProgress ==
             "xyz.openbmc_project.State.Boot.Progress.ProgressStages."
             "BusInit")
    {
        rfBpLastState = "BusInitializationStarted";
    }
    else if (dbusBootProgress ==
             "xyz.openbmc_project.State.Boot.Progress.ProgressStages."
             "MemoryInit")
    {
        rfBpLastState = "MemoryInitializationStarted";
    }
    else if (dbusBootProgress ==
             "xyz.openbmc_project.State.Boot.Progress.ProgressStages."
             "SecondaryProcInit")
    {
        rfBpLastState = "SecondaryProcessorInitializationStarted";
    }
    else if (dbusBootProgress ==
             "xyz.openbmc_project.State.Boot.Progress.ProgressStages."
             "PCIInit")
    {
        rfBpLastState = "PCIResourceConfigStarted";
    }
    else if (dbusBootProgress ==
             "xyz.openbmc_project.State.Boot.Progress.ProgressStages."
             "SystemSetup")
    {
        rfBpLastState = "SetupEntered";
    }
    else if (dbusBootProgress ==
             "xyz.openbmc_project.State.Boot.Progress.ProgressStages."
             "SystemInitComplete")
    {
        rfBpLastState = "SystemHardwareInitializationComplete";
    }
    else if (dbusBootProgress ==
             "xyz.openbmc_project.State.Boot.Progress.ProgressStages."
             "OSStart")
    {
        rfBpLastState = "OSBootStarted";
    }
    else if (dbusBootProgress ==
             "xyz.openbmc_project.State.Boot.Progress.ProgressStages."
             "OSRunning")
    {
        rfBpLastState = "OSRunning";
    }
    else
    {
        BMCWEB_LOG_DEBUG("Unsupported D-Bus BootProgress {}", dbusBootProgress);
        // Just return the default
    }
    return rfBpLastState;
}

/**
 * @brief Translates boot source from Redfish to the DBus boot paths.
 *
 * @param[in] rfSource    The boot source in Redfish.
 * @param[out] bootSource The DBus source
 * @param[out] bootMode   the DBus boot mode
 *
 * @return Integer error code.
 */
inline int assignBootParameters(const std::string& rfSource,
                                std::string& bootSource, std::string& bootMode)
{
    bootSource = "xyz.openbmc_project.Control.Boot.Source.Sources.Default";
    bootMode = "xyz.openbmc_project.Control.Boot.Mode.Modes.Regular";

    if (rfSource == "None")
    {
        return 0;
    }
    if (rfSource == "Pxe")
    {
        bootSource = "xyz.openbmc_project.Control.Boot.Source.Sources.Network";
    }
    else if (rfSource == "Hdd")
    {
        bootSource = "xyz.openbmc_project.Control.Boot.Source.Sources.Disk";
    }
    else if (rfSource == "Cd")
    {
        bootSource =
            "xyz.openbmc_project.Control.Boot.Source.Sources.ExternalMedia";
    }
    else if (rfSource == "BiosSetup")
    {
        bootMode = "xyz.openbmc_project.Control.Boot.Mode.Modes.Setup";
    }
    else if (rfSource == "Usb")
    {
        bootSource =
            "xyz.openbmc_project.Control.Boot.Source.Sources.RemovableMedia";
    }
    else if (rfSource == "UefiHttp")
    {
        bootSource = "xyz.openbmc_project.Control.Boot.Source.Sources.HTTP";
    }
    else if (rfSource == "Diags")
    {
        bootMode = "xyz.openbmc_project.Control.Boot.Mode.Modes.Diag";
    }
    else
    {
        BMCWEB_LOG_DEBUG(
            "Invalid property value for BootSourceOverrideTarget: {}",
            bootSource);
        return -1;
    }
    return 0;
}

/**
 * @brief Retrieves boot progress of the system
 *
 * @param[in] asyncResp  Shared pointer for generating response message.
 *
 * @return None.
 */
inline void getBootProgress(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    dbus::utility::getProperty<std::string>(
        hostStateService, singleHostPath,
        "xyz.openbmc_project.State.Boot.Progress", "BootProgress",
        [asyncResp](const boost::system::error_code& ec,
                    const std::string& bootProgressStr) {
            if (ec)
            {
                // BootProgress is an optional object so just do nothing if
                // not found
                return;
            }

            BMCWEB_LOG_DEBUG("Boot Progress: {}", bootProgressStr);

            asyncResp->res.jsonValue["BootProgress"]["LastState"] =
                dbusToRfBootProgress(bootProgressStr);
        });
}

/**
 * @brief Retrieves boot progress Last Update of the system
 *
 * @param[in] asyncResp  Shared pointer for generating response message.
 *
 * @return None.
 */
void getBootProgressLastStateTime(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    dbus::utility::getProperty<uint64_t>(
        hostStateService, singleHostPath,
        "xyz.openbmc_project.State.Boot.Progress", "BootProgressLastUpdate",
        [asyncResp](const boost::system::error_code& ec,
                    const uint64_t lastStateTime) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("D-BUS response error {}", ec);
                return;
            }

            // BootProgressLastUpdate is the last time the BootProgress property
            // was updated. The time is the Epoch time, number of microseconds
            // since 1 Jan 1970 00::00::00 UTC."
            // https://github.com/openbmc/phosphor-dbus-interfaces/blob/master/
            // yaml/xyz/openbmc_project/State/Boot/Progress.interface.yaml#L11

            // Convert to ISO 8601 standard
            asyncResp->res.jsonValue["BootProgress"]["LastStateTime"] =
                redfish::time_utils::getDateTimeUintUs(lastStateTime);
        });
}

/**
 * @brief Retrieves boot progress of the system
 *
 * @param[in] aResp  Shared pointer for generating response message.
 *
 * @return None.
 */
void getCPLDBootProgress(const std::shared_ptr<bmcweb::AsyncResp>& aResp)
{
    BMCWEB_LOG_DEBUG("Get OEM information.");
    crow::connections::systemBus->async_method_call(
        [aResp](const boost::system::error_code ec,
                const std::vector<
                    std::pair<std::string, dbus::utility::DbusVariantType>>&
                    propertiesList) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("DBUS response error {}", ec);
                // not an error, don't have to have the interface
                return;
            }

            aResp->res
                .jsonValue["BootProgress"]["Oem"]["Intel"]["@odata.type"] =
                json_util::odataType("OpenBMCComputerSystem", "Intel");
            const std::string* errorSource = nullptr;
            const std::string* powerState = nullptr;
            for (const std::pair<std::string, dbus::utility::DbusVariantType>&
                     property : propertiesList)
            {
                if (property.first == "ErrorSource")
                {
                    errorSource = std::get_if<std::string>(&property.second);
                }
                else if (property.first == "PowerState")
                {
                    powerState = std::get_if<std::string>(&property.second);
                }
            }

            if ((errorSource == nullptr) || (powerState == nullptr))
            {
                BMCWEB_LOG_DEBUG("Unable to get CPLD power sequence state.");
                messages::internalError(aResp->res);
                return;
            }

            BMCWEB_LOG_DEBUG("CPLD Boot Progress: {} Err {}", *powerState,
                             *errorSource);
            aResp->res
                .jsonValue["BootProgress"]["Oem"]["Intel"]["CpldLastState"] =
                *powerState;
            aResp->res.jsonValue["BootProgress"]["Oem"]["Intel"]["CpldErr"] =
                *errorSource;
        },
        "xyz.openbmc_project.DCSCM.Cpld.Manager",
        "/xyz/openbmc_project/dcscm/cpld/manager/CPU",
        "org.freedesktop.DBus.Properties", "GetAll",
        "xyz.openbmc_project.DCSCM.CPU.PostCode");
}

/**
 * @brief Retrieves boot override type over DBUS and fills out the response
 *
 * @param[in] asyncResp         Shared pointer for generating response message.
 *
 * @return None.
 */

inline void getBootOverrideType(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    dbus::utility::getProperty<std::string>(
        "xyz.openbmc_project.Settings",
        "/xyz/openbmc_project/control/host0/boot",
        "xyz.openbmc_project.Control.Boot.Type", "BootType",
        [asyncResp](const boost::system::error_code& ec,
                    const std::string& bootType) {
            if (ec)
            {
                // not an error, don't have to have the interface
                return;
            }

            BMCWEB_LOG_DEBUG("Boot type: {}", bootType);

            asyncResp->res
                .jsonValue["Boot"]
                          ["BootSourceOverrideMode@Redfish.AllowableValues"] =
                nlohmann::json::array_t({"Legacy", "UEFI"});

            auto rfType = dbusToRfBootType(bootType);
            if (rfType.empty())
            {
                messages::internalError(asyncResp->res);
                return;
            }

            asyncResp->res.jsonValue["Boot"]["BootSourceOverrideMode"] = rfType;
        });
}

/**
 * @brief Retrieves boot override mode over DBUS and fills out the response
 *
 * @param[in] asyncResp         Shared pointer for generating response message.
 *
 * @return None.
 */

inline void getBootOverrideMode(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    dbus::utility::getProperty<std::string>(
        "xyz.openbmc_project.Settings",
        "/xyz/openbmc_project/control/host0/boot",
        "xyz.openbmc_project.Control.Boot.Mode", "BootMode",
        [asyncResp](const boost::system::error_code& ec,
                    const std::string& bootModeStr) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("DBUS response error {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }

            BMCWEB_LOG_DEBUG("Boot mode: {}", bootModeStr);

            nlohmann::json::array_t allowed;
            allowed.emplace_back("None");
            allowed.emplace_back("Pxe");
            allowed.emplace_back("Hdd");
            allowed.emplace_back("Cd");
            allowed.emplace_back("BiosSetup");
            allowed.emplace_back("Usb");
            allowed.emplace_back("UefiHttp");
            allowed.emplace_back("Diags");

            asyncResp->res
                .jsonValue["Boot"]
                          ["BootSourceOverrideTarget@Redfish.AllowableValues"] =
                std::move(allowed);
            if (bootModeStr !=
                "xyz.openbmc_project.Control.Boot.Mode.Modes.Regular")
            {
                auto rfMode = dbusToRfBootMode(bootModeStr);
                if (!rfMode.empty())
                {
                    asyncResp->res
                        .jsonValue["Boot"]["BootSourceOverrideTarget"] = rfMode;
                }
            }
        });
}

/**
 * @brief Retrieves boot override source over DBUS
 *
 * @param[in] asyncResp         Shared pointer for generating response message.
 *
 * @return None.
 */

inline void getBootOverrideSource(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    dbus::utility::getProperty<std::string>(
        "xyz.openbmc_project.Settings",
        "/xyz/openbmc_project/control/host0/boot",
        "xyz.openbmc_project.Control.Boot.Source", "BootSource",
        [asyncResp](const boost::system::error_code& ec,
                    const std::string& bootSourceStr) {
            if (ec)
            {
                if (ec.value() == boost::asio::error::host_unreachable)
                {
                    return;
                }
                BMCWEB_LOG_ERROR("DBUS response error {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }

            BMCWEB_LOG_DEBUG("Boot source: {}", bootSourceStr);

            auto rfSource = dbusToRfBootSource(bootSourceStr);
            if (!rfSource.empty())
            {
                asyncResp->res.jsonValue["Boot"]["BootSourceOverrideTarget"] =
                    rfSource;
            }

            // Get BootMode as BootSourceOverrideTarget is constructed
            // from both BootSource and BootMode
            getBootOverrideMode(asyncResp);
        });
}

/**
 * @brief This functions abstracts all the logic behind getting a
 * "BootSourceOverrideEnabled" property from an overall boot override enable
 * state
 *
 * @param[in] asyncResp     Shared pointer for generating response message.
 *
 * @return None.
 */

inline void processBootOverrideEnable(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const bool bootOverrideEnableSetting)
{
    if (!bootOverrideEnableSetting)
    {
        asyncResp->res.jsonValue["Boot"]["BootSourceOverrideEnabled"] =
            "Disabled";
        return;
    }

    // If boot source override is enabled, we need to check 'one_time'
    // property to set a correct value for the "BootSourceOverrideEnabled"
    dbus::utility::getProperty<bool>(
        "xyz.openbmc_project.Settings",
        "/xyz/openbmc_project/control/host0/boot/one_time",
        "xyz.openbmc_project.Object.Enable", "Enabled",
        [asyncResp](const boost::system::error_code& ec, bool oneTimeSetting) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("DBUS response error {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }

            if (oneTimeSetting)
            {
                asyncResp->res.jsonValue["Boot"]["BootSourceOverrideEnabled"] =
                    "Once";
            }
            else
            {
                asyncResp->res.jsonValue["Boot"]["BootSourceOverrideEnabled"] =
                    "Continuous";
            }
        });
}

/**
 * @brief Retrieves boot override enable over DBUS
 *
 * @param[in] asyncResp     Shared pointer for generating response message.
 *
 * @return None.
 */

inline void getBootOverrideEnable(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    dbus::utility::getProperty<bool>(
        "xyz.openbmc_project.Settings",
        "/xyz/openbmc_project/control/host0/boot",
        "xyz.openbmc_project.Object.Enable", "Enabled",
        [asyncResp](const boost::system::error_code& ec,
                    const bool bootOverrideEnable) {
            if (ec)
            {
                if (ec.value() == boost::asio::error::host_unreachable)
                {
                    return;
                }
                BMCWEB_LOG_ERROR("DBUS response error {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }

            processBootOverrideEnable(asyncResp, bootOverrideEnable);
        });
}

/**
 * @brief Retrieves boot source override properties
 *
 * @param[in] asyncResp     Shared pointer for generating response message.
 *
 * @return None.
 */
void getBootProperties(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    BMCWEB_LOG_DEBUG("Get boot information.");

    getBootOverrideSource(asyncResp);
    getBootOverrideType(asyncResp);
    getBootOverrideEnable(asyncResp);
}

/**
 * @brief Retrieves the Last Reset Time
 *
 * "Reset" is an overloaded term in Redfish, "Reset" includes power on
 * and power off. Even though this is the "system" Redfish object look at the
 * chassis D-Bus interface for the LastStateChangeTime since this has the
 * last power operation time.
 *
 * @param[in] asyncResp     Shared pointer for generating response message.
 * @param[in] systemName    Optional system name to determine node-specific
 * path. If empty, defaults to chassis0 for legacy support.
 *
 * @return None.
 */
void getLastResetTime(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                      const std::string& systemName)
{
    BMCWEB_LOG_DEBUG("Getting System Last Reset Time for {}",
                     systemName.empty() ? "default" : systemName);

    std::string chassisService = chassisStateService; // default
    std::string chassisPath = singleChassisPath;      // default

    if (system_utils::isDualHostEnabled())
    {
        // Dual-node system
        if (systemName == "system1")
        {
            // "system1" maps to Chassis2
            chassisService = chassis2Service;
            chassisPath = chassis2Path;
        }
        else
        {
            // "system" (default) maps to Chassis1 in dual-node mode
            chassisService = chassis1Service;
            chassisPath = chassis1Path;
        }
    }
    // For single-node systems (no ONETREE_MULTI_HOST_SUPPORT), use defaults

    dbus::utility::getProperty<uint64_t>(
        chassisService, chassisPath, chassisStateInterface,
        "LastStateChangeTime",
        [asyncResp](const boost::system::error_code& ec,
                    uint64_t lastResetTime) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("D-BUS response error {}", ec);
                return;
            }

            // LastStateChangeTime is epoch time, in milliseconds
            // https://github.com/openbmc/phosphor-dbus-interfaces/blob/33e8e1dd64da53a66e888d33dc82001305cd0bf9/xyz/openbmc_project/State/Chassis.interface.yaml#L19
            uint64_t lastResetTimeStamp = lastResetTime / 1000;

            // Convert to ISO 8601 standard
            asyncResp->res.jsonValue["LastResetTime"] =
                redfish::time_utils::getDateTimeUint(lastResetTimeStamp);
        });
}

/**
 * @brief Retrieves the number of automatic boot Retry attempts allowed/left.
 *
 * The total number of automatic reboot retries allowed "RetryAttempts" and its
 * corresponding property "AttemptsLeft" that keeps track of the amount of
 * automatic retry attempts left are hosted in phosphor-state-manager through
 * dbus.
 *
 * @param[in] asyncResp     Shared pointer for generating response message.
 *
 * @return None.
 */
inline void getAutomaticRebootAttempts(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    BMCWEB_LOG_DEBUG("Get Automatic Retry policy");

    dbus::utility::getAllProperties(
        hostStateService, singleHostPath,
        "xyz.openbmc_project.Control.Boot.RebootAttempts",
        [asyncResp{asyncResp}](
            const boost::system::error_code& ec,
            const dbus::utility::DBusPropertiesMap& propertiesList) {
            if (ec)
            {
                if (ec.value() != EBADR && ec.value() != EHOSTUNREACH)
                {
                    BMCWEB_LOG_ERROR("D-Bus responses error: {}", ec);
                    messages::internalError(asyncResp->res);
                }
                return;
            }

            const uint32_t* attemptsLeft = nullptr;
            const uint32_t* retryAttempts = nullptr;

            const bool success = sdbusplus::unpackPropertiesNoThrow(
                dbus_utils::UnpackErrorPrinter(), propertiesList,
                "AttemptsLeft", attemptsLeft, "RetryAttempts", retryAttempts);

            if (!success)
            {
                messages::internalError(asyncResp->res);
                return;
            }

            if (attemptsLeft != nullptr)
            {
                asyncResp->res
                    .jsonValue["Boot"]["RemainingAutomaticRetryAttempts"] =
                    *attemptsLeft;
            }

            if (retryAttempts != nullptr)
            {
                asyncResp->res.jsonValue["Boot"]["AutomaticRetryAttempts"] =
                    *retryAttempts;
            }
        });
}

/**
 * @brief Retrieves Automatic Retry properties. Known on D-Bus as AutoReboot.
 *
 * @param[in] asyncResp     Shared pointer for generating response message.
 *
 * @return None.
 */
void getAutomaticRetryPolicy(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    BMCWEB_LOG_DEBUG("Get Automatic Retry policy");

    dbus::utility::getProperty<bool>(
        "xyz.openbmc_project.Settings",
        "/xyz/openbmc_project/control/host0/auto_reboot",
        "xyz.openbmc_project.Control.Boot.RebootPolicy", "AutoReboot",
        [asyncResp](const boost::system::error_code& ec,
                    bool autoRebootEnabled) {
            if (ec)
            {
                if (ec.value() != EBADR)
                {
                    BMCWEB_LOG_ERROR("D-Bus responses error: {}", ec);
                    messages::internalError(asyncResp->res);
                }
                return;
            }

            BMCWEB_LOG_DEBUG("Auto Reboot: {}", autoRebootEnabled);
            if (autoRebootEnabled)
            {
                asyncResp->res.jsonValue["Boot"]["AutomaticRetryConfig"] =
                    "RetryAttempts";
            }
            else
            {
                asyncResp->res.jsonValue["Boot"]["AutomaticRetryConfig"] =
                    "Disabled";
            }
            getAutomaticRebootAttempts(asyncResp);

            // "AutomaticRetryConfig" can be 3 values, Disabled, RetryAlways,
            // and RetryAttempts. OpenBMC only supports Disabled and
            // RetryAttempts.
            nlohmann::json::array_t allowed;
            allowed.emplace_back("Disabled");
            allowed.emplace_back("RetryAttempts");
            asyncResp->res
                .jsonValue["Boot"]
                          ["AutomaticRetryConfig@Redfish.AllowableValues"] =
                std::move(allowed);
        });
}

/**
 * @brief Sets RetryAttempts
 *
 * @param[in] asyncResp   Shared pointer for generating response message.
 * @param[in] retryAttempts  "AutomaticRetryAttempts" from request.
 *
 *@return None.
 */

inline void setAutomaticRetryAttempts(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const uint32_t retryAttempts)
{
    BMCWEB_LOG_DEBUG("Set Automatic Retry Attempts.");
    setDbusProperty(asyncResp, "Boot/AutomaticRetryAttempts", hostStateService,
                    sdbusplus::message::object_path(singleHostPath),
                    "xyz.openbmc_project.Control.Boot.RebootAttempts",
                    "RetryAttempts", retryAttempts);
}

inline computer_system::PowerRestorePolicyTypes
    redfishPowerRestorePolicyFromDbus(std::string_view value)
{
    if (value ==
        "xyz.openbmc_project.Control.Power.RestorePolicy.Policy.AlwaysOn")
    {
        return computer_system::PowerRestorePolicyTypes::AlwaysOn;
    }
    if (value ==
        "xyz.openbmc_project.Control.Power.RestorePolicy.Policy.AlwaysOff")
    {
        return computer_system::PowerRestorePolicyTypes::AlwaysOff;
    }
    if (value ==
        "xyz.openbmc_project.Control.Power.RestorePolicy.Policy.Restore")
    {
        return computer_system::PowerRestorePolicyTypes::LastState;
    }
    if (value == "xyz.openbmc_project.Control.Power.RestorePolicy.Policy.None")
    {
        return computer_system::PowerRestorePolicyTypes::AlwaysOff;
    }
    return computer_system::PowerRestorePolicyTypes::Invalid;
}
/**
 * @brief Retrieves power restore policy over DBUS.
 *
 * @param[in] asyncResp     Shared pointer for generating response message.
 *
 * @return None.
 */
void getPowerRestorePolicy(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    BMCWEB_LOG_DEBUG("Get power restore policy");

    dbus::utility::getProperty<std::string>(
        "xyz.openbmc_project.Settings",
        "/xyz/openbmc_project/control/host0/power_restore_policy",
        "xyz.openbmc_project.Control.Power.RestorePolicy", "PowerRestorePolicy",
        [asyncResp](const boost::system::error_code& ec,
                    const std::string& policy) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("DBUS response error {}", ec);
                return;
            }
            computer_system::PowerRestorePolicyTypes restore =
                redfishPowerRestorePolicyFromDbus(policy);
            if (restore == computer_system::PowerRestorePolicyTypes::Invalid)
            {
                messages::internalError(asyncResp->res);
                return;
            }

            asyncResp->res.jsonValue["PowerRestorePolicy"] = restore;
        });
}

/**
 * @brief Stop Boot On Fault over DBUS.
 *
 * @param[in] asyncResp     Shared pointer for generating response message.
 *
 * @return None.
 */
void getStopBootOnFault(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    BMCWEB_LOG_DEBUG("Get Stop Boot On Fault");

    dbus::utility::getProperty<bool>(
        "xyz.openbmc_project.Settings", "/xyz/openbmc_project/logging/settings",
        "xyz.openbmc_project.Logging.Settings", "QuiesceOnHwError",
        [asyncResp](const boost::system::error_code& ec, bool value) {
            if (ec)
            {
                if (ec.value() != EBADR)
                {
                    BMCWEB_LOG_ERROR("DBUS response error {}", ec);
                    messages::internalError(asyncResp->res);
                }
                return;
            }

            if (value)
            {
                asyncResp->res.jsonValue["Boot"]["StopBootOnFault"] =
                    computer_system::StopBootOnFault::AnyFault;
            }
            else
            {
                asyncResp->res.jsonValue["Boot"]["StopBootOnFault"] =
                    computer_system::StopBootOnFault::Never;
            }
        });
}

/**
 * @brief Get TrustedModuleRequiredToBoot property. Determines whether or not
 * TPM is required for booting the host.
 *
 * @param[in] asyncResp     Shared pointer for generating response message.
 *
 * @return None.
 */
void getTrustedModuleRequiredToBoot(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    BMCWEB_LOG_DEBUG("Get TPM required to boot.");
    nlohmann::json::array_t tpmList;
    tpmList.emplace_back("Required");
    tpmList.emplace_back("Disabled");
    asyncResp->res
        .jsonValue["Boot"]
                  ["TrustedModuleRequiredToBoot@Redfish.AllowableValues"] =
        tpmList;

    constexpr std::array<std::string_view, 1> interfaces = {
        "xyz.openbmc_project.Control.TPM.Policy"};
    dbus::utility::getSubTree(
        "/", 0, interfaces,
        [asyncResp](const boost::system::error_code& ec,
                    const dbus::utility::MapperGetSubTreeResponse& subtree) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG(
                    "DBUS response error on TPM.Policy GetSubTree{}", ec);
                // This is an optional D-Bus object so just return if
                // error occurs
                return;
            }
            if (subtree.empty())
            {
                // As noted above, this is an optional interface so just return
                // if there is no instance found
                return;
            }

            /* When there is more than one TPMEnable object... */
            if (subtree.size() > 1)
            {
                BMCWEB_LOG_DEBUG(
                    "DBUS response has more than 1 TPM Enable object:{}",
                    subtree.size());
                // Throw an internal Error and return
                messages::internalError(asyncResp->res);
                return;
            }

            // Make sure the Dbus response map has a service and objectPath
            // field
            if (subtree[0].first.empty() || subtree[0].second.size() != 1)
            {
                BMCWEB_LOG_DEBUG("TPM.Policy mapper error!");
                messages::internalError(asyncResp->res);
                return;
            }

            const std::string& path = subtree[0].first;
            const std::string& serv = subtree[0].second.begin()->first;

            // Valid TPM Enable object found, now reading the current value
            dbus::utility::getProperty<bool>(
                serv, path, "xyz.openbmc_project.Control.TPM.Policy",
                "TPMEnable",
                [asyncResp](const boost::system::error_code& ec2,
                            bool tpmRequired) {
                    if (ec2)
                    {
                        BMCWEB_LOG_ERROR(
                            "D-BUS response error on TPM.Policy Get{}", ec2);
                        messages::internalError(asyncResp->res);
                        return;
                    }

                    if (tpmRequired)
                    {
                        asyncResp->res
                            .jsonValue["Boot"]["TrustedModuleRequiredToBoot"] =
                            "Required";
                    }
                    else
                    {
                        asyncResp->res
                            .jsonValue["Boot"]["TrustedModuleRequiredToBoot"] =
                            "Disabled";
                    }
                });
        });
}

/**
 * @brief Set TrustedModuleRequiredToBoot property. Determines whether or not
 * TPM is required for booting the host.
 *
 * @param[in] asyncResp     Shared pointer for generating response message.
 * @param[in] tpmRequired   Value to set TPM Required To Boot property to.
 *
 * @return None.
 */
inline void setTrustedModuleRequiredToBoot(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& bootTrustedModuleRequired)
{
    bool tpmRequired = false;

    if (bootTrustedModuleRequired == "Required")
    {
        tpmRequired = true;
    }
    else if (bootTrustedModuleRequired == "Disabled")
    {
        tpmRequired = false;
    }
    else
    {
        messages::propertyValueNotInList(asyncResp->res,
                                         bootTrustedModuleRequired,
                                         "TrustedModuleRequiredToBoot");
        return;
    }
    constexpr std::array<std::string_view, 1> interfaces = {
        "xyz.openbmc_project.Control.TPM.Policy"};
    dbus::utility::getSubTree(
        "/", 0, interfaces,
        [asyncResp,
         tpmRequired](const boost::system::error_code& ec,
                      const dbus::utility::MapperGetSubTreeResponse& subtree) {
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "DBUS response error on TPM.Policy GetSubTree{}", ec);
                messages::internalError(asyncResp->res);
                return;
            }
            if (subtree.empty())
            {
                messages::propertyValueNotInList(asyncResp->res,
                                                 "ComputerSystem",
                                                 "TrustedModuleRequiredToBoot");
                return;
            }

            /* When there is more than one TPMEnable object... */
            if (subtree.size() > 1)
            {
                BMCWEB_LOG_DEBUG(
                    "DBUS response has more than 1 TPM Enable object:{}",
                    subtree.size());
                // Throw an internal Error and return
                messages::internalError(asyncResp->res);
                return;
            }

            // Make sure the Dbus response map has a service and objectPath
            // field
            if (subtree[0].first.empty() || subtree[0].second.size() != 1)
            {
                BMCWEB_LOG_DEBUG("TPM.Policy mapper error!");
                messages::internalError(asyncResp->res);
                return;
            }

            const std::string& path = subtree[0].first;
            const std::string& serv = subtree[0].second.begin()->first;

            if (serv.empty())
            {
                BMCWEB_LOG_DEBUG("TPM.Policy service mapper error!");
                messages::internalError(asyncResp->res);
                return;
            }

            // Valid TPM Enable object found, now setting the value
            setDbusProperty(asyncResp, "Boot/TrustedModuleRequiredToBoot", serv,
                            path, "xyz.openbmc_project.Control.TPM.Policy",
                            "TPMEnable", tpmRequired);
        });
}

/**
 * @brief Sets boot properties into DBUS object(s).
 *
 * @param[in] asyncResp       Shared pointer for generating response message.
 * @param[in] bootType        The boot type to set.
 * @return Integer error code.
 */
inline void setBootType(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                        const std::optional<std::string>& bootType)
{
    std::string bootTypeStr;

    if (!bootType)
    {
        return;
    }

    // Source target specified
    BMCWEB_LOG_DEBUG("Boot type: {}", *bootType);
    // Figure out which DBUS interface and property to use
    if (*bootType == "Legacy")
    {
        bootTypeStr = "xyz.openbmc_project.Control.Boot.Type.Types.Legacy";
    }
    else if (*bootType == "UEFI")
    {
        bootTypeStr = "xyz.openbmc_project.Control.Boot.Type.Types.EFI";
    }
    else
    {
        BMCWEB_LOG_DEBUG("Invalid property value for "
                         "BootSourceOverrideMode: {}",
                         *bootType);
        messages::propertyValueNotInList(asyncResp->res, *bootType,
                                         "BootSourceOverrideMode");
        return;
    }

    // Act on validated parameters
    BMCWEB_LOG_DEBUG("DBUS boot type: {}", bootTypeStr);

    setDbusProperty(asyncResp, "Boot/BootSourceOverrideMode",
                    "xyz.openbmc_project.Settings",
                    sdbusplus::message::object_path(
                        "/xyz/openbmc_project/control/host0/boot"),
                    "xyz.openbmc_project.Control.Boot.Type", "BootType",
                    bootTypeStr);
}

/**
 * @brief Sets boot properties into DBUS object(s).
 *
 * @param[in] asyncResp           Shared pointer for generating response
 * message.
 * @param[in] bootType        The boot type to set.
 * @return Integer error code.
 */
inline void setBootEnable(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                          const std::optional<std::string>& bootEnable)
{
    if (!bootEnable)
    {
        return;
    }
    // Source target specified
    BMCWEB_LOG_DEBUG("Boot enable: {}", *bootEnable);

    bool bootOverrideEnable = false;
    bool bootOverridePersistent = false;
    // Figure out which DBUS interface and property to use
    if (*bootEnable == "Disabled")
    {
        bootOverrideEnable = false;
    }
    else if (*bootEnable == "Once")
    {
        bootOverrideEnable = true;
        bootOverridePersistent = false;
    }
    else if (*bootEnable == "Continuous")
    {
        bootOverrideEnable = true;
        bootOverridePersistent = true;
    }
    else
    {
        BMCWEB_LOG_DEBUG(
            "Invalid property value for BootSourceOverrideEnabled: {}",
            *bootEnable);
        messages::propertyValueNotInList(asyncResp->res, *bootEnable,
                                         "BootSourceOverrideEnabled");
        return;
    }

    // Act on validated parameters
    BMCWEB_LOG_DEBUG("DBUS boot override enable: {}", bootOverrideEnable);

    setDbusProperty(asyncResp, "Boot/BootSourceOverrideEnabled",
                    "xyz.openbmc_project.Settings",
                    sdbusplus::message::object_path(
                        "/xyz/openbmc_project/control/host0/boot"),
                    "xyz.openbmc_project.Object.Enable", "Enabled",
                    bootOverrideEnable);

    if (!bootOverrideEnable)
    {
        return;
    }

    // In case boot override is enabled we need to set correct value for the
    // 'one_time' enable DBus interface
    BMCWEB_LOG_DEBUG("DBUS boot override persistent: {}",
                     bootOverridePersistent);

    setDbusProperty(asyncResp, "Boot/BootSourceOverrideEnabled",
                    "xyz.openbmc_project.Settings",
                    sdbusplus::message::object_path(
                        "/xyz/openbmc_project/control/host0/boot/one_time"),
                    "xyz.openbmc_project.Object.Enable", "Enabled",
                    !bootOverridePersistent);
}

/**
 * @brief Sets boot properties into DBUS object(s).
 *
 * @param[in] asyncResp       Shared pointer for generating response message.
 * @param[in] bootSource      The boot source to set.
 *
 * @return Integer error code.
 */
inline void setBootModeOrSource(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::optional<std::string>& bootSource)
{
    std::string bootSourceStr;
    std::string bootModeStr;

    if (!bootSource)
    {
        return;
    }

    // Source target specified
    BMCWEB_LOG_DEBUG("Boot source: {}", *bootSource);
    // Figure out which DBUS interface and property to use
    if (assignBootParameters(*bootSource, bootSourceStr, bootModeStr) != 0)
    {
        BMCWEB_LOG_DEBUG(
            "Invalid property value for BootSourceOverrideTarget: {}",
            *bootSource);
        messages::propertyValueNotInList(asyncResp->res, *bootSource,
                                         "BootSourceTargetOverride");
        return;
    }

    // Act on validated parameters
    BMCWEB_LOG_DEBUG("DBUS boot source: {}", bootSourceStr);
    BMCWEB_LOG_DEBUG("DBUS boot mode: {}", bootModeStr);

    setDbusProperty(asyncResp, "Boot/BootSourceOverrideTarget",
                    "xyz.openbmc_project.Settings",
                    sdbusplus::message::object_path(
                        "/xyz/openbmc_project/control/host0/boot"),
                    "xyz.openbmc_project.Control.Boot.Source", "BootSource",
                    bootSourceStr);
    setDbusProperty(asyncResp, "Boot/BootSourceOverrideTarget",
                    "xyz.openbmc_project.Settings",
                    sdbusplus::message::object_path(
                        "/xyz/openbmc_project/control/host0/boot"),
                    "xyz.openbmc_project.Control.Boot.Mode", "BootMode",
                    bootModeStr);
}

/**
 * @brief Sets Boot source override properties.
 *
 * @param[in] asyncResp  Shared pointer for generating response message.
 * @param[in] bootSource The boot source from incoming RF request.
 * @param[in] bootType   The boot type from incoming RF request.
 * @param[in] bootEnable The boot override enable from incoming RF request.
 *
 * @return Integer error code.
 */

inline void setBootProperties(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::optional<std::string>& bootSource,
    const std::optional<std::string>& bootType,
    const std::optional<std::string>& bootEnable)
{
    BMCWEB_LOG_DEBUG("Set boot information.");

    setBootModeOrSource(asyncResp, bootSource);
    setBootType(asyncResp, bootType);
    setBootEnable(asyncResp, bootEnable);
}

/**
 * @brief Sets AssetTag
 *
 * @param[in] asyncResp Shared pointer for generating response message.
 * @param[in] assetTag  "AssetTag" from request.
 *
 * @return None.
 */
inline void setAssetTag(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                        const std::string& assetTag)
{
    constexpr std::array<std::string_view, 1> interfaces = {
        "xyz.openbmc_project.Inventory.Item.System"};
    dbus::utility::getSubTree(
        "/xyz/openbmc_project/inventory", 0, interfaces,
        [asyncResp,
         assetTag](const boost::system::error_code& ec,
                   const dbus::utility::MapperGetSubTreeResponse& subtree) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("D-Bus response error on GetSubTree {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }
            if (subtree.empty())
            {
                BMCWEB_LOG_DEBUG("Can't find system D-Bus object!");
                messages::internalError(asyncResp->res);
                return;
            }
            // Assume only 1 system D-Bus object
            // Throw an error if there is more than 1
            if (subtree.size() > 1)
            {
                BMCWEB_LOG_DEBUG("Found more than 1 system D-Bus object!");
                messages::internalError(asyncResp->res);
                return;
            }
            if (subtree[0].first.empty() || subtree[0].second.size() != 1)
            {
                BMCWEB_LOG_DEBUG("Asset Tag Set mapper error!");
                messages::internalError(asyncResp->res);
                return;
            }

            const std::string& path = subtree[0].first;
            const std::string& service = subtree[0].second.begin()->first;

            if (service.empty())
            {
                BMCWEB_LOG_DEBUG("Asset Tag Set service mapper error!");
                messages::internalError(asyncResp->res);
                return;
            }

            setDbusProperty(asyncResp, "AssetTag", service, path,
                            "xyz.openbmc_project.Inventory.Decorator.AssetTag",
                            "AssetTag", assetTag);
        });
}

/**
 * @brief Validate the specified stopBootOnFault is valid and return the
 * stopBootOnFault name associated with that string
 *
 * @param[in] stopBootOnFaultString  String representing the desired
 * stopBootOnFault
 *
 * @return stopBootOnFault value or empty  if incoming value is not valid
 */
inline std::optional<bool> validstopBootOnFault(
    const std::string& stopBootOnFaultString)
{
    if (stopBootOnFaultString == "AnyFault")
    {
        return true;
    }

    if (stopBootOnFaultString == "Never")
    {
        return false;
    }

    return std::nullopt;
}

/**
 * @brief Sets stopBootOnFault
 *
 * @param[in] asyncResp   Shared pointer for generating response message.
 * @param[in] stopBootOnFault  "StopBootOnFault" from request.
 *
 * @return None.
 */
inline void setStopBootOnFault(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& stopBootOnFault)
{
    BMCWEB_LOG_DEBUG("Set Stop Boot On Fault.");

    std::optional<bool> stopBootEnabled = validstopBootOnFault(stopBootOnFault);
    if (!stopBootEnabled)
    {
        BMCWEB_LOG_DEBUG("Invalid property value for StopBootOnFault: {}",
                         stopBootOnFault);
        messages::propertyValueNotInList(asyncResp->res, stopBootOnFault,
                                         "StopBootOnFault");
        return;
    }

    setDbusProperty(asyncResp, "Boot/StopBootOnFault",
                    "xyz.openbmc_project.Settings",
                    sdbusplus::message::object_path(
                        "/xyz/openbmc_project/logging/settings"),
                    "xyz.openbmc_project.Logging.Settings", "QuiesceOnHwError",
                    *stopBootEnabled);
}

/**
 * @brief Sets automaticRetry (Auto Reboot)
 *
 * @param[in] asyncResp   Shared pointer for generating response message.
 * @param[in] automaticRetryConfig  "AutomaticRetryConfig" from request.
 *
 * @return None.
 */
inline void setAutomaticRetry(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& automaticRetryConfig)
{
    BMCWEB_LOG_DEBUG("Set Automatic Retry.");

    // OpenBMC only supports "Disabled" and "RetryAttempts".
    bool autoRebootEnabled = false;

    if (automaticRetryConfig == "Disabled")
    {
        autoRebootEnabled = false;
    }
    else if (automaticRetryConfig == "RetryAttempts")
    {
        autoRebootEnabled = true;
    }
    else
    {
        BMCWEB_LOG_DEBUG("Invalid property value for AutomaticRetryConfig: {}",
                         automaticRetryConfig);
        messages::propertyValueNotInList(asyncResp->res, automaticRetryConfig,
                                         "AutomaticRetryConfig");
        return;
    }

    setDbusProperty(asyncResp, "Boot/AutomaticRetryConfig",
                    "xyz.openbmc_project.Settings",
                    sdbusplus::message::object_path(
                        "/xyz/openbmc_project/control/host0/auto_reboot"),
                    "xyz.openbmc_project.Control.Boot.RebootPolicy",
                    "AutoReboot", autoRebootEnabled);
}

inline std::string dbusPowerRestorePolicyFromRedfish(std::string_view policy)
{
    if (policy == "AlwaysOn")
    {
        return "xyz.openbmc_project.Control.Power.RestorePolicy.Policy.AlwaysOn";
    }
    if (policy == "AlwaysOff")
    {
        return "xyz.openbmc_project.Control.Power.RestorePolicy.Policy.AlwaysOff";
    }
    if (policy == "LastState")
    {
        return "xyz.openbmc_project.Control.Power.RestorePolicy.Policy.Restore";
    }
    return "";
}

/**
 * @brief Sets power restore policy properties.
 *
 * @param[in] asyncResp   Shared pointer for generating response message.
 * @param[in] policy  power restore policy properties from request.
 *
 * @return None.
 */
inline void setPowerRestorePolicy(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    std::string_view policy)
{
    BMCWEB_LOG_DEBUG("Set power restore policy.");

    std::string powerRestorePolicy = dbusPowerRestorePolicyFromRedfish(policy);

    if (powerRestorePolicy.empty())
    {
        messages::propertyValueNotInList(asyncResp->res, policy,
                                         "PowerRestorePolicy");
        return;
    }

    setDbusProperty(
        asyncResp, "PowerRestorePolicy", "xyz.openbmc_project.Settings",
        sdbusplus::message::object_path(
            "/xyz/openbmc_project/control/host0/power_restore_policy"),
        "xyz.openbmc_project.Control.Power.RestorePolicy", "PowerRestorePolicy",
        powerRestorePolicy);
}

/**
 * @brief Retrieves provisioned platform state
 *
 * @param[in] aResp     Shared pointer for completing asynchronous calls.
 *
 * @return None.
 */
inline void getPlatformState(std::shared_ptr<bmcweb::AsyncResp> aResp)
{
    BMCWEB_LOG_DEBUG("Get OEM information.");
    crow::connections::systemBus->async_method_call(
        [aResp](const boost::system::error_code ec,
                const std::vector<
                    std::pair<std::string, dbus::utility::DbusVariantType>>&
                    propertiesList) {
            nlohmann::json& oemPFR =
                aResp->res.jsonValue["Oem"]["OpenBmc"]["FirmwareProvisioning"]
                                    ["Status"];

            if (ec)
            {
                BMCWEB_LOG_DEBUG("DBUS response error {}", ec);
                // not an error, don't have to have the interface
                return;
            }

            const uint8_t* postcode = nullptr;
            const std::string* platformState = nullptr;
            for (const std::pair<std::string, dbus::utility::DbusVariantType>&
                     property : propertiesList)
            {
                if (property.first == "Data")
                {
                    postcode = std::get_if<uint8_t>(&property.second);
                }
                else if (property.first == "PlatformState")
                {
                    platformState = std::get_if<std::string>(&property.second);
                }
            }

            if ((postcode == nullptr) || (platformState == nullptr))
            {
                BMCWEB_LOG_DEBUG("Unable to get PFR platform state.");
                messages::internalError(aResp->res);
                return;
            }
            oemPFR["Data"] = *postcode;
            oemPFR["PlatformState"] = *platformState;
        },
        "xyz.openbmc_project.PFR.Manager", "/xyz/openbmc_project/pfr",
        "org.freedesktop.DBus.Properties", "GetAll",
        "xyz.openbmc_project.State.Boot.Platform");
}

/**
 * @brief Retrieves provisioning status
 *
 * @param[in] asyncResp     Shared pointer for completing asynchronous
 * calls.
 *
 * @return None.
 */
void getProvisioningStatus(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    BMCWEB_LOG_DEBUG("Get OEM information.");
    dbus::utility::getAllProperties(
        "xyz.openbmc_project.PFR.Manager", "/xyz/openbmc_project/pfr",
        "xyz.openbmc_project.PFR.Attributes",
        [asyncResp](const boost::system::error_code& ec,
                    const dbus::utility::DBusPropertiesMap& propertiesList) {
            nlohmann::json& oemPFR =
                asyncResp->res
                    .jsonValue["Oem"]["OpenBmc"]["FirmwareProvisioning"];
            asyncResp->res.jsonValue["Oem"]["OpenBmc"]["@odata.type"] =
                json_util::odataType("OpenBMCComputerSystem", "OpenBmc");
            oemPFR["@odata.type"] =
                "#OpenBMCComputerSystem.FirmwareProvisioning";

            if (ec)
            {
                BMCWEB_LOG_DEBUG("DBUS response error {}", ec);
                // not an error, don't have to have the interface
                oemPFR["ProvisioningStatus"] = open_bmc_computer_system::
                    FirmwareProvisioningStatus::NotProvisioned;
                return;
            }

            const bool* provState = nullptr;
            const bool* lockState = nullptr;

            const bool success = sdbusplus::unpackPropertiesNoThrow(
                dbus_utils::UnpackErrorPrinter(), propertiesList,
                "UfmProvisioned", provState, "UfmLocked", lockState);

            if (!success)
            {
                messages::internalError(asyncResp->res);
                return;
            }

            if ((provState == nullptr) || (lockState == nullptr))
            {
                BMCWEB_LOG_DEBUG("Unable to get PFR attributes.");
                messages::internalError(asyncResp->res);
                return;
            }

            if (*provState)
            {
                if (*lockState)
                {
                    oemPFR["ProvisioningStatus"] = open_bmc_computer_system::
                        FirmwareProvisioningStatus::ProvisionedAndLocked;
                }
                else
                {
                    oemPFR["ProvisioningStatus"] = open_bmc_computer_system::
                        FirmwareProvisioningStatus::ProvisionedButNotLocked;
                }
                getPlatformState(asyncResp);
            }
            else
            {
                oemPFR["ProvisioningStatus"] = open_bmc_computer_system::
                    FirmwareProvisioningStatus::NotProvisioned;
            }
        });
}

/**
 * @brief Translate the PowerMode string to enum value
 *
 * @param[in]  modeString PowerMode string to be translated
 *
 * @return PowerMode enum
 */
inline computer_system::PowerMode translatePowerModeString(
    const std::string& modeString)
{
    using PowerMode = computer_system::PowerMode;

    if (modeString == "xyz.openbmc_project.Control.Power.Mode.PowerMode.Static")
    {
        return PowerMode::Static;
    }
    if (modeString ==
        "xyz.openbmc_project.Control.Power.Mode.PowerMode.MaximumPerformance")
    {
        return PowerMode::MaximumPerformance;
    }
    if (modeString ==
        "xyz.openbmc_project.Control.Power.Mode.PowerMode.PowerSaving")
    {
        return PowerMode::PowerSaving;
    }
    if (modeString ==
        "xyz.openbmc_project.Control.Power.Mode.PowerMode.BalancedPerformance")
    {
        return PowerMode::BalancedPerformance;
    }
    if (modeString ==
        "xyz.openbmc_project.Control.Power.Mode.PowerMode.EfficiencyFavorPerformance")
    {
        return PowerMode::EfficiencyFavorPerformance;
    }
    if (modeString ==
        "xyz.openbmc_project.Control.Power.Mode.PowerMode.EfficiencyFavorPower")
    {
        return PowerMode::EfficiencyFavorPower;
    }
    if (modeString == "xyz.openbmc_project.Control.Power.Mode.PowerMode.OEM")
    {
        return PowerMode::OEM;
    }
    // Any other values would be invalid
    BMCWEB_LOG_ERROR("PowerMode value was not valid: {}", modeString);
    return PowerMode::Invalid;
}

inline void afterGetPowerMode(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const boost::system::error_code& ec,
    const dbus::utility::DBusPropertiesMap& properties)
{
    if (ec)
    {
        BMCWEB_LOG_ERROR("DBUS response error on PowerMode GetAll: {}", ec);
        messages::internalError(asyncResp->res);
        return;
    }

    std::string powerMode;
    const std::vector<std::string>* allowedModes = nullptr;
    const bool success = sdbusplus::unpackPropertiesNoThrow(
        dbus_utils::UnpackErrorPrinter(), properties, "PowerMode", powerMode,
        "AllowedPowerModes", allowedModes);

    if (!success)
    {
        messages::internalError(asyncResp->res);
        return;
    }

    nlohmann::json::array_t modeList;
    if (allowedModes == nullptr)
    {
        modeList.emplace_back("Static");
        modeList.emplace_back("MaximumPerformance");
        modeList.emplace_back("PowerSaving");
    }
    else
    {
        for (const auto& aMode : *allowedModes)
        {
            computer_system::PowerMode modeValue =
                translatePowerModeString(aMode);
            if (modeValue == computer_system::PowerMode::Invalid)
            {
                messages::internalError(asyncResp->res);
                continue;
            }
            modeList.emplace_back(modeValue);
        }
    }
    asyncResp->res.jsonValue["PowerMode@Redfish.AllowableValues"] = modeList;

    BMCWEB_LOG_DEBUG("Current power mode: {}", powerMode);
    const computer_system::PowerMode modeValue =
        translatePowerModeString(powerMode);
    if (modeValue == computer_system::PowerMode::Invalid)
    {
        messages::internalError(asyncResp->res);
        return;
    }
    asyncResp->res.jsonValue["PowerMode"] = modeValue;
}
/**
 * @brief Retrieves system power mode
 *
 * @param[in] asyncResp  Shared pointer for generating response message.
 *
 * @return None.
 */
void getPowerMode(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    BMCWEB_LOG_DEBUG("Get power mode.");

    // Get Power Mode object path:
    constexpr std::array<std::string_view, 1> interfaces = {
        "xyz.openbmc_project.Control.Power.Mode"};
    dbus::utility::getSubTree(
        "/", 0, interfaces,
        [asyncResp](const boost::system::error_code& ec,
                    const dbus::utility::MapperGetSubTreeResponse& subtree) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG(
                    "DBUS response error on Power.Mode GetSubTree {}", ec);
                // This is an optional D-Bus object so just return if
                // error occurs
                return;
            }
            if (subtree.empty())
            {
                // As noted above, this is an optional interface so just return
                // if there is no instance found
                return;
            }
            if (subtree.size() > 1)
            {
                // More then one PowerMode object is not supported and is an
                // error
                BMCWEB_LOG_DEBUG(
                    "Found more than 1 system D-Bus Power.Mode objects: {}",
                    subtree.size());
                messages::internalError(asyncResp->res);
                return;
            }
            if ((subtree[0].first.empty()) || (subtree[0].second.size() != 1))
            {
                BMCWEB_LOG_DEBUG("Power.Mode mapper error!");
                messages::internalError(asyncResp->res);
                return;
            }
            const std::string& path = subtree[0].first;
            const std::string& service = subtree[0].second.begin()->first;
            if (service.empty())
            {
                BMCWEB_LOG_DEBUG("Power.Mode service mapper error!");
                messages::internalError(asyncResp->res);
                return;
            }

            // Valid Power Mode object found, now read the mode properties
            dbus::utility::getAllProperties(
                service, path, "xyz.openbmc_project.Control.Power.Mode",
                [asyncResp](
                    const boost::system::error_code& ec2,
                    const dbus::utility::DBusPropertiesMap& properties) {
                    afterGetPowerMode(asyncResp, ec2, properties);
                });
        });
}

/**
 * @brief Validate the specified mode is valid and return the PowerMode
 * name associated with that string
 *
 * @param[in] asyncResp   Shared pointer for generating response message.
 * @param[in] modeValue   String representing the desired PowerMode
 *
 * @return PowerMode value or empty string if mode is not valid
 */
inline std::string validatePowerMode(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const nlohmann::json& modeValue)
{
    using PowerMode = computer_system::PowerMode;
    std::string mode;

    if (modeValue == PowerMode::Static)
    {
        mode = "xyz.openbmc_project.Control.Power.Mode.PowerMode.Static";
    }
    else if (modeValue == PowerMode::MaximumPerformance)
    {
        mode =
            "xyz.openbmc_project.Control.Power.Mode.PowerMode.MaximumPerformance";
    }
    else if (modeValue == PowerMode::PowerSaving)
    {
        mode = "xyz.openbmc_project.Control.Power.Mode.PowerMode.PowerSaving";
    }
    else if (modeValue == PowerMode::BalancedPerformance)
    {
        mode =
            "xyz.openbmc_project.Control.Power.Mode.PowerMode.BalancedPerformance";
    }
    else if (modeValue == PowerMode::EfficiencyFavorPerformance)
    {
        mode =
            "xyz.openbmc_project.Control.Power.Mode.PowerMode.EfficiencyFavorPerformance";
    }
    else if (modeValue == PowerMode::EfficiencyFavorPower)
    {
        mode =
            "xyz.openbmc_project.Control.Power.Mode.PowerMode.EfficiencyFavorPower";
    }
    else
    {
        messages::propertyValueNotInList(asyncResp->res, modeValue.dump(),
                                         "PowerMode");
    }
    return mode;
}

/**
 * @brief Sets system power mode.
 *
 * @param[in] asyncResp   Shared pointer for generating response message.
 * @param[in] pmode   System power mode from request.
 *
 * @return None.
 */
inline void setPowerMode(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                         const std::string& pmode)
{
    BMCWEB_LOG_DEBUG("Set power mode.");

    std::string powerMode = validatePowerMode(asyncResp, pmode);
    if (powerMode.empty())
    {
        return;
    }

    // Get Power Mode object path:
    constexpr std::array<std::string_view, 1> interfaces = {
        "xyz.openbmc_project.Control.Power.Mode"};
    dbus::utility::getSubTree(
        "/", 0, interfaces,
        [asyncResp,
         powerMode](const boost::system::error_code& ec,
                    const dbus::utility::MapperGetSubTreeResponse& subtree) {
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "DBUS response error on Power.Mode GetSubTree {}", ec);
                // This is an optional D-Bus object, but user attempted to patch
                messages::internalError(asyncResp->res);
                return;
            }
            if (subtree.empty())
            {
                // This is an optional D-Bus object, but user attempted to patch
                messages::resourceNotFound(asyncResp->res, "ComputerSystem",
                                           "PowerMode");
                return;
            }
            if (subtree.size() > 1)
            {
                // More then one PowerMode object is not supported and is an
                // error
                BMCWEB_LOG_DEBUG(
                    "Found more than 1 system D-Bus Power.Mode objects: {}",
                    subtree.size());
                messages::internalError(asyncResp->res);
                return;
            }
            if ((subtree[0].first.empty()) || (subtree[0].second.size() != 1))
            {
                BMCWEB_LOG_DEBUG("Power.Mode mapper error!");
                messages::internalError(asyncResp->res);
                return;
            }
            const std::string& path = subtree[0].first;
            const std::string& service = subtree[0].second.begin()->first;
            if (service.empty())
            {
                BMCWEB_LOG_DEBUG("Power.Mode service mapper error!");
                messages::internalError(asyncResp->res);
                return;
            }

            BMCWEB_LOG_DEBUG("Setting power mode({}) -> {}", powerMode, path);

            // Set the Power Mode property
            setDbusProperty(asyncResp, "PowerMode", service, path,
                            "xyz.openbmc_project.Control.Power.Mode",
                            "PowerMode", powerMode);
        });
}

/**
 * @brief Translates watchdog timeout action DBUS property value to redfish.
 *
 * @param[in] dbusAction    The watchdog timeout action in D-BUS.
 *
 * @return Returns as a string, the timeout action in Redfish terms. If
 * translation cannot be done, returns an empty string.
 */
inline std::string dbusToRfWatchdogAction(const std::string& dbusAction)
{
    if (dbusAction == "xyz.openbmc_project.State.Watchdog.Action.None")
    {
        return "None";
    }
    if (dbusAction == "xyz.openbmc_project.State.Watchdog.Action.HardReset")
    {
        return "ResetSystem";
    }
    if (dbusAction == "xyz.openbmc_project.State.Watchdog.Action.PowerOff")
    {
        return "PowerDown";
    }
    if (dbusAction == "xyz.openbmc_project.State.Watchdog.Action.PowerCycle")
    {
        return "PowerCycle";
    }

    return "";
}

/**
 *@brief Translates timeout action from Redfish to DBUS property value.
 *
 *@param[in] rfAction The timeout action in Redfish.
 *
 *@return Returns as a string, the time_out action as expected by DBUS.
 *If translation cannot be done, returns an empty string.
 */

inline std::string rfToDbusWDTTimeOutAct(const std::string& rfAction)
{
    if (rfAction == "None")
    {
        return "xyz.openbmc_project.State.Watchdog.Action.None";
    }
    if (rfAction == "PowerCycle")
    {
        return "xyz.openbmc_project.State.Watchdog.Action.PowerCycle";
    }
    if (rfAction == "PowerDown")
    {
        return "xyz.openbmc_project.State.Watchdog.Action.PowerOff";
    }
    if (rfAction == "ResetSystem")
    {
        return "xyz.openbmc_project.State.Watchdog.Action.HardReset";
    }

    return "";
}

/**
 * @brief Retrieves host watchdog timer properties over DBUS
 *
 * @param[in] asyncResp     Shared pointer for completing asynchronous calls.
 * @param[in] systemName    Optional system name to determine node-specific
 * watchdog. If empty, defaults to host0 for legacy support.
 *
 * @return None.
 */
void getHostWatchdogTimer(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                          const std::string& systemName)
{
    std::string watchdogServiceName = getWatchdogServiceName(systemName);
    std::string watchdogService = "xyz.openbmc_project.Watchdog.host0";
    std::string watchdogPath = "/xyz/openbmc_project/watchdog/host0";

    if (system_utils::isDualHostEnabled())
    {
        if (systemName == "system1")
        {
            watchdogService = "xyz.openbmc_project.Watchdog.host1";
            watchdogPath = "/xyz/openbmc_project/watchdog/host1";
        }
    }

    sdbusplus::message::object_path serviceObjectPath(
        std::string("/xyz/openbmc_project/State/SystemdUnit/") +
        watchdogServiceName + "_2eservice");

    dbus::utility::getAllProperties(
        watchdogService, watchdogPath, "xyz.openbmc_project.State.Watchdog",
        [asyncResp](const boost::system::error_code& ec,
                    const dbus::utility::DBusPropertiesMap& properties) {
            if (ec)
            {
                // watchdog service is stopped
                BMCWEB_LOG_DEBUG("DBUS response error {}", ec);
                return;
            }

            BMCWEB_LOG_DEBUG("Got {} wdt prop.", properties.size());

            nlohmann::json& hostWatchdogTimer =
                asyncResp->res.jsonValue["HostWatchdogTimer"];

            // watchdog service is running/enabled
            hostWatchdogTimer["Status"]["State"] = resource::State::Enabled;

            const bool* enabled = nullptr;
            const std::string* expireAction = nullptr;

            const bool success = sdbusplus::unpackPropertiesNoThrow(
                dbus_utils::UnpackErrorPrinter(), properties, "Enabled",
                enabled, "ExpireAction", expireAction);

            if (!success)
            {
                messages::internalError(asyncResp->res);
                return;
            }

            if (enabled != nullptr)
            {
                hostWatchdogTimer["FunctionEnabled"] = *enabled;
            }

            if (expireAction != nullptr)
            {
                std::string action = dbusToRfWatchdogAction(*expireAction);
                nlohmann::json::array_t timeoutList;
                timeoutList.emplace_back("None");
                timeoutList.emplace_back("ResetSystem");
                timeoutList.emplace_back("PowerCycle");
                timeoutList.emplace_back("PowerDown");
                timeoutList.emplace_back("OEM");
                hostWatchdogTimer["TimeoutAction@Redfish.AllowableValues"] =
                    timeoutList;

                if (action.empty())
                {
                    messages::internalError(asyncResp->res);
                    return;
                }
                hostWatchdogTimer["TimeoutAction"] = action;
            }
        });
}

/**
 * @brief Sets Host WatchDog Timer properties.
 *
 * @param[in] asyncResp  Shared pointer for generating response message.
 * @param[in] wdtEnable  The WDTimer Enable value (true/false) from incoming
 *                       RF request.
 * @param[in] wdtTimeOutAction The WDT Timeout action, from incoming RF request.
 * @param[in] systemName Optional system name to determine node-specific
 * watchdog. If empty, defaults to host0 for legacy support.
 *
 * @return None.
 */
inline void setWDTProperties(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::optional<bool> wdtEnable,
    const std::optional<std::string>& wdtTimeOutAction,
    const std::string& systemName)
{
    BMCWEB_LOG_DEBUG("Set host watchdog for {}",
                     systemName.empty() ? "default" : systemName);

    std::string watchdogServiceName = getWatchdogServiceName(systemName);
    std::string watchdogService = "xyz.openbmc_project.Watchdog.host0";
    std::string watchdogPath = "/xyz/openbmc_project/watchdog/host0";

    if (system_utils::isDualHostEnabled())
    {
        if (systemName == "system1")
        {
            watchdogService = "xyz.openbmc_project.Watchdog.host1";
            watchdogPath = "/xyz/openbmc_project/watchdog/host1";
        }
    }

    if (wdtTimeOutAction)
    {
        std::string wdtTimeOutActStr = rfToDbusWDTTimeOutAct(*wdtTimeOutAction);
        // check if TimeOut Action is Valid
        if (wdtTimeOutActStr.empty())
        {
            BMCWEB_LOG_DEBUG("Unsupported value for TimeoutAction: {}",
                             *wdtTimeOutAction);
            messages::propertyValueNotInList(asyncResp->res, *wdtTimeOutAction,
                                             "TimeoutAction");
            return;
        }

        setDbusProperty(asyncResp, "HostWatchdogTimer/TimeoutAction",
                        watchdogService,
                        sdbusplus::message::object_path(watchdogPath),
                        "xyz.openbmc_project.State.Watchdog", "ExpireAction",
                        wdtTimeOutActStr);
    }

    if (wdtEnable)
    {
        setDbusProperty(
            asyncResp, "HostWatchdogTimer/FunctionEnabled", watchdogService,
            sdbusplus::message::object_path(watchdogPath),
            "xyz.openbmc_project.State.Watchdog", "Enabled", *wdtEnable);
    }
}

/**
 * @brief Parse the Idle Power Saver properties into json
 *
 * @param[in] asyncResp   Shared pointer for completing asynchronous calls.
 * @param[in] properties  IPS property data from DBus.
 *
 * @return true if successful
 */
inline bool parseIpsProperties(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const dbus::utility::DBusPropertiesMap& properties)
{
    const bool* enabled = nullptr;
    const uint8_t* enterUtilizationPercent = nullptr;
    const uint64_t* enterDwellTime = nullptr;
    const uint8_t* exitUtilizationPercent = nullptr;
    const uint64_t* exitDwellTime = nullptr;

    const bool success = sdbusplus::unpackPropertiesNoThrow(
        dbus_utils::UnpackErrorPrinter(), properties, "Enabled", enabled,
        "EnterUtilizationPercent", enterUtilizationPercent, "EnterDwellTime",
        enterDwellTime, "ExitUtilizationPercent", exitUtilizationPercent,
        "ExitDwellTime", exitDwellTime);

    if (!success)
    {
        return false;
    }

    if (enabled != nullptr)
    {
        asyncResp->res.jsonValue["IdlePowerSaver"]["Enabled"] = *enabled;
    }

    if (enterUtilizationPercent != nullptr)
    {
        asyncResp->res.jsonValue["IdlePowerSaver"]["EnterUtilizationPercent"] =
            *enterUtilizationPercent;
    }

    if (enterDwellTime != nullptr)
    {
        const std::chrono::duration<uint64_t, std::milli> ms(*enterDwellTime);
        asyncResp->res.jsonValue["IdlePowerSaver"]["EnterDwellTimeSeconds"] =
            std::chrono::duration_cast<std::chrono::duration<uint64_t>>(ms)
                .count();
    }

    if (exitUtilizationPercent != nullptr)
    {
        asyncResp->res.jsonValue["IdlePowerSaver"]["ExitUtilizationPercent"] =
            *exitUtilizationPercent;
    }

    if (exitDwellTime != nullptr)
    {
        const std::chrono::duration<uint64_t, std::milli> ms(*exitDwellTime);
        asyncResp->res.jsonValue["IdlePowerSaver"]["ExitDwellTimeSeconds"] =
            std::chrono::duration_cast<std::chrono::duration<uint64_t>>(ms)
                .count();
    }

    return true;
}

/**
 * @brief Retrieves host watchdog timer properties over DBUS
 *
 * @param[in] asyncResp     Shared pointer for completing asynchronous calls.
 *
 * @return None.
 */
void getIdlePowerSaver(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    BMCWEB_LOG_DEBUG("Get idle power saver parameters");

    // Get IdlePowerSaver object path:
    constexpr std::array<std::string_view, 1> interfaces = {
        "xyz.openbmc_project.Control.Power.IdlePowerSaver"};
    dbus::utility::getSubTree(
        "/", 0, interfaces,
        [asyncResp](const boost::system::error_code& ec,
                    const dbus::utility::MapperGetSubTreeResponse& subtree) {
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "DBUS response error on Power.IdlePowerSaver GetSubTree {}",
                    ec);
                messages::internalError(asyncResp->res);
                return;
            }
            if (subtree.empty())
            {
                // This is an optional interface so just return
                // if there is no instance found
                BMCWEB_LOG_DEBUG("No instances found");
                return;
            }
            if (subtree.size() > 1)
            {
                // More then one PowerIdlePowerSaver object is not supported and
                // is an error
                BMCWEB_LOG_DEBUG("Found more than 1 system D-Bus "
                                 "Power.IdlePowerSaver objects: {}",
                                 subtree.size());
                messages::internalError(asyncResp->res);
                return;
            }
            if ((subtree[0].first.empty()) || (subtree[0].second.size() != 1))
            {
                BMCWEB_LOG_DEBUG("Power.IdlePowerSaver mapper error!");
                messages::internalError(asyncResp->res);
                return;
            }
            const std::string& path = subtree[0].first;
            const std::string& service = subtree[0].second.begin()->first;
            if (service.empty())
            {
                BMCWEB_LOG_DEBUG("Power.IdlePowerSaver service mapper error!");
                messages::internalError(asyncResp->res);
                return;
            }

            // Valid IdlePowerSaver object found, now read the current values
            dbus::utility::getAllProperties(
                service, path,
                "xyz.openbmc_project.Control.Power.IdlePowerSaver",
                [asyncResp](
                    const boost::system::error_code& ec2,
                    const dbus::utility::DBusPropertiesMap& properties) {
                    if (ec2)
                    {
                        BMCWEB_LOG_ERROR(
                            "DBUS response error on IdlePowerSaver GetAll: {}",
                            ec2);
                        messages::internalError(asyncResp->res);
                        return;
                    }

                    if (!parseIpsProperties(asyncResp, properties))
                    {
                        messages::internalError(asyncResp->res);
                        return;
                    }
                });
        });

    BMCWEB_LOG_DEBUG("EXIT: Get idle power saver parameters");
}

/**
 * @brief Sets Idle Power Saver properties.
 *
 * @param[in] asyncResp  Shared pointer for generating response message.
 * @param[in] ipsEnable  The IPS Enable value (true/false) from incoming
 *                       RF request.
 * @param[in] ipsEnterUtil The utilization limit to enter idle state.
 * @param[in] ipsEnterTime The time the utilization must be below ipsEnterUtil
 * before entering idle state.
 * @param[in] ipsExitUtil The utilization limit when exiting idle state.
 * @param[in] ipsExitTime The time the utilization must be above ipsExutUtil
 * before exiting idle state
 *
 * @return None.
 */
inline void setIdlePowerSaver(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::optional<bool> ipsEnable,
    const std::optional<uint8_t> ipsEnterUtil,
    const std::optional<uint64_t> ipsEnterTime,
    const std::optional<uint8_t> ipsExitUtil,
    const std::optional<uint64_t> ipsExitTime)
{
    BMCWEB_LOG_DEBUG("Set idle power saver properties");

    // Get IdlePowerSaver object path:
    constexpr std::array<std::string_view, 1> interfaces = {
        "xyz.openbmc_project.Control.Power.IdlePowerSaver"};
    dbus::utility::getSubTree(
        "/", 0, interfaces,
        [asyncResp, ipsEnable, ipsEnterUtil, ipsEnterTime, ipsExitUtil,
         ipsExitTime](const boost::system::error_code& ec,
                      const dbus::utility::MapperGetSubTreeResponse& subtree) {
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "DBUS response error on Power.IdlePowerSaver GetSubTree {}",
                    ec);
                messages::internalError(asyncResp->res);
                return;
            }
            if (subtree.empty())
            {
                // This is an optional D-Bus object, but user attempted to patch
                messages::resourceNotFound(asyncResp->res, "ComputerSystem",
                                           "IdlePowerSaver");
                return;
            }
            if (subtree.size() > 1)
            {
                // More then one PowerIdlePowerSaver object is not supported and
                // is an error
                BMCWEB_LOG_DEBUG(
                    "Found more than 1 system D-Bus Power.IdlePowerSaver objects: {}",
                    subtree.size());
                messages::internalError(asyncResp->res);
                return;
            }
            if ((subtree[0].first.empty()) || (subtree[0].second.size() != 1))
            {
                BMCWEB_LOG_DEBUG("Power.IdlePowerSaver mapper error!");
                messages::internalError(asyncResp->res);
                return;
            }
            const std::string& path = subtree[0].first;
            const std::string& service = subtree[0].second.begin()->first;
            if (service.empty())
            {
                BMCWEB_LOG_DEBUG("Power.IdlePowerSaver service mapper error!");
                messages::internalError(asyncResp->res);
                return;
            }

            // Valid Power IdlePowerSaver object found, now set any values that
            // need to be updated

            if (ipsEnable)
            {
                setDbusProperty(
                    asyncResp, "IdlePowerSaver/Enabled", service, path,
                    "xyz.openbmc_project.Control.Power.IdlePowerSaver",
                    "Enabled", *ipsEnable);
            }
            if (ipsEnterUtil)
            {
                setDbusProperty(
                    asyncResp, "IdlePowerSaver/EnterUtilizationPercent",
                    service, path,
                    "xyz.openbmc_project.Control.Power.IdlePowerSaver",
                    "EnterUtilizationPercent", *ipsEnterUtil);
            }
            if (ipsEnterTime)
            {
                // Convert from seconds into milliseconds for DBus
                const uint64_t timeMilliseconds = *ipsEnterTime * 1000;
                setDbusProperty(
                    asyncResp, "IdlePowerSaver/EnterDwellTimeSeconds", service,
                    path, "xyz.openbmc_project.Control.Power.IdlePowerSaver",
                    "EnterDwellTime", timeMilliseconds);
            }
            if (ipsExitUtil)
            {
                setDbusProperty(
                    asyncResp, "IdlePowerSaver/ExitUtilizationPercent", service,
                    path, "xyz.openbmc_project.Control.Power.IdlePowerSaver",
                    "ExitUtilizationPercent", *ipsExitUtil);
            }
            if (ipsExitTime)
            {
                // Convert from seconds into milliseconds for DBus
                const uint64_t timeMilliseconds = *ipsExitTime * 1000;
                setDbusProperty(
                    asyncResp, "IdlePowerSaver/ExitDwellTimeSeconds", service,
                    path, "xyz.openbmc_project.Control.Power.IdlePowerSaver",
                    "ExitDwellTime", timeMilliseconds);
            }
        });

    BMCWEB_LOG_DEBUG("EXIT: Set idle power saver parameters");
}

/**
 * @brief Retrieves Serial console over SSH properties
 * // https://github.com/openbmc/docs/blob/master/console.md
 *
 * @param[in] aResp     Shared pointer for completing asynchronous calls.
+ * @return None.
 */
void getSerialConsoleSshStatus(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& systemName)
{
    constexpr std::array<std::string_view, 1> interfaces = {
        "xyz.openbmc_project.Control.Service.Attributes"};
    dbus::utility::getSubTreePaths(
        "/xyz/openbmc_project/control/service", 0, interfaces,
        [asyncResp, systemName](
            const boost::system::error_code& ec,
            const dbus::utility::MapperGetSubTreePathsResponse& subtreePaths) {
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "DBUS response error in getSerialConsoleSshStatus: {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }

            if (subtreePaths.empty())
            {
                BMCWEB_LOG_DEBUG("No subtree found");
                return;
            }

            std::string sshService;
            std::vector<std::string> ttyServices;
            for (const std::string& path : subtreePaths)
            {
                const size_t lastSlash = path.rfind('/');
                if (lastSlash == std::string::npos)
                {
                    continue;
                }
                const std::string objName = path.substr(lastSlash + 1);
                if (system_utils::isDualHostEnabled())
                {
                    static const std::unordered_map<std::string,
                                                    std::vector<std::string>>
                        dualHostMap = {
                            {"system",
                             {"obmc_2dconsole_40ttyS13",
                              "obmc_2dconsole_40ttyVUART0"}},
                            {"system1",
                             {"obmc_2dconsole_40ttyS3",
                              "obmc_2dconsole_40ttyVUART1"}},
                        };

                    auto it = dualHostMap.find(systemName);
                    if (it != dualHostMap.end() &&
                        std::find(it->second.begin(), it->second.end(),
                                  objName) != it->second.end())
                    {
                        ttyServices.emplace_back(objName);
                    }
                }
                else
                {
                    if (objName == "obmc_2dconsole_2dssh")
                    {
                        sshService = objName;
                        break;
                    }
                    if (objName.starts_with("obmc_2dconsole_40tty"))
                    {
                        ttyServices.emplace_back(objName);
                    }
                }
            }

            // Handle standard SSH service
            if (!sshService.empty())
            {
                service_util::getEnabled(
                    asyncResp, sshService,
                    nlohmann::json::json_pointer(
                        "/SerialConsole/SSH/ServiceEnabled"));
                service_util::getSerialConsoleSshMasked(
                    asyncResp, sshService,
                    nlohmann::json::json_pointer(
                        "/Oem/Ami/SerialConsole/SSH/Masked"));
                service_util::getRunning(
                    asyncResp, sshService,
                    nlohmann::json::json_pointer(
                        "/Oem/Ami/SerialConsole/SSH/Running"));
                service_util::getPortNumber(
                    asyncResp, sshService,
                    nlohmann::json::json_pointer("/SerialConsole/SSH/Port"));
                service_util::getSerialConsoleSshMasked(
                    asyncResp, sshService,
                    nlohmann::json::json_pointer(
                        "/Oem/Ami/SerialConsole/IPMI/Masked"));
                asyncResp->res.jsonValue["SerialConsole"]["SSH"]
                                        ["HotKeySequenceDisplay"] =
                    "Press ~. to exit console";
            }

            // Handle Multi SOL SSH services
            if (!ttyServices.empty())
            {
                nlohmann::json solArray = nlohmann::json::array();

                for (size_t i = 0; i < ttyServices.size(); ++i)
                {
                    nlohmann::json solObj;

                    solObj["Id"] = ttyServices[i].substr(
                        std::string("obmc_2dconsole_40").size());

                    const std::string indexStr = std::to_string(i);
                    service_util::getEnabled(
                        asyncResp, ttyServices[i],
                        nlohmann::json::json_pointer(
                            "/Oem/Ami/SerialConsole/SSH/SOLSSH/" + indexStr +
                            "/ServiceEnabled"));
                    service_util::getSerialConsoleSshMasked(
                        asyncResp, ttyServices[i],
                        nlohmann::json::json_pointer(
                            "/Oem/Ami/SerialConsole/SSH/SOLSSH/" + indexStr +
                            "/Masked"));
                    service_util::getRunning(
                        asyncResp, ttyServices[i],
                        nlohmann::json::json_pointer(
                            "/Oem/Ami/SerialConsole/SSH/SOLSSH/" + indexStr +
                            "/Running"));

                    solArray.emplace_back(std::move(solObj));
                }

                asyncResp->res
                    .jsonValue["Oem"]["Ami"]["SerialConsole"]["SSH"]["SOLSSH"] =
                    std::move(solArray);
            }
        });
}

/**
 * @brief Retrieves virtual media properties
 *
 * @param[in] aResp     Shared pointer for completing asynchronous calls.
 *
 * @return None.
 */
void getVirtualMediaConfig(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                           const std::string& systemName)
{
    BMCWEB_LOG_DEBUG("Get VirtualMediaConfig for the System: {}", systemName);
    std::string vmServiceName;

    if (system_utils::isDualHostEnabled())
    {
        if (systemName == "system1")
        {
            vmServiceName = getVirtualMediaServiceName("system1");
        }
        else
        {
            vmServiceName = getVirtualMediaServiceName("system");
        }
    }
    else
    {
        vmServiceName = getVirtualMediaServiceName("system");
    }
    asyncResp->res.jsonValue["VirtualMediaConfig"]["ServiceEnabled"] = false;
    service_util::getEnabled(
        asyncResp, vmServiceName,
        nlohmann::json::json_pointer("/VirtualMediaConfig/ServiceEnabled"));
    service_util::getMasked(asyncResp, vmServiceName, "VirtualMediaConfig",
                            "Masked", "Ami");
}

/**
 * @brief Retrieves KVM properties
 *
 * @param[in] aResp     Shared pointer for completing asynchronous calls.
 *
 * @return None.
 */
void getKvmConfig(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                  const std::string& systemName)
{
    BMCWEB_LOG_DEBUG("Get VirtualMediaConfig for the System: {}", systemName);
    std::string kvmServiceName;

    if (system_utils::isDualHostEnabled())
    {
        if (systemName == "system1")
        {
            kvmServiceName = getKvmServiceName("system1");
        }
        else
        {
            kvmServiceName = getKvmServiceName("system");
        }
    }
    else
    {
        kvmServiceName = getKvmServiceName("system");
    }

    asyncResp->res.jsonValue["GraphicalConsole"]["ServiceEnabled"] = false;
    service_util::getEnabled(
        asyncResp, kvmServiceName,
        nlohmann::json::json_pointer("/GraphicalConsole/ServiceEnabled"));
    asyncResp->res.jsonValue["GraphicalConsole"]["ConnectTypesSupported"] = {
        "KVMIP"};
    service_util::getMasked(asyncResp, kvmServiceName, "GraphicalConsole",
                            "Masked", "Ami");
}

inline void handleComputerSystemCollectionHead(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/ComputerSystemCollection/ComputerSystemCollection.json>; rel=describedby");
}

inline void handleComputerSystemCollectionGet(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/ComputerSystemCollection.json>; rel=describedby");
    asyncResp->res.jsonValue["@odata.type"] =
        "#ComputerSystemCollection.ComputerSystemCollection";
    asyncResp->res.jsonValue["@odata.id"] = "/redfish/v1/Systems";
    asyncResp->res.jsonValue["Name"] = "Computer System Collection";
    asyncResp->res.jsonValue["Description"] = "Collection of Computer Systems";

    nlohmann::json& ifaceArray = asyncResp->res.jsonValue["Members"];
    ifaceArray = nlohmann::json::array();

    if (system_utils::isDualHostEnabled())
    {
        // Query ObjectMapper for available host nodes
        crow::connections::systemBus->async_method_call(
            [asyncResp, &ifaceArray](const boost::system::error_code ec,
                                     const std::vector<std::string>& paths) {
                if (ec)
                {
                    BMCWEB_LOG_ERROR("DBUS error: {}", ec);
                    messages::internalError(asyncResp->res);
                    return;
                }
                asyncResp->res.jsonValue["Members@odata.count"] = paths.size();
                for (const auto& path : paths)
                {
                    std::string nodeName = "system";
                    if (path.find("host1") != std::string::npos)
                    {
                        nodeName = "system1";
                    }
                    // host0 remains as "system" (default)
                    nlohmann::json system;
                    system["@odata.id"] =
                        boost::urls::format("/redfish/v1/Systems/{}", nodeName);
                    ifaceArray.emplace_back(std::move(system));
                }
            },
            "xyz.openbmc_project.ObjectMapper",
            "/xyz/openbmc_project/object_mapper",
            "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths",
            "/xyz/openbmc_project/state", 1,
            std::vector<std::string>{hostStateInterface});
    }
    else
    {
        asyncResp->res.jsonValue["Members@odata.count"] = 1;
        nlohmann::json::object_t system;
        system["@odata.id"] = boost::urls::format(
            "/redfish/v1/Systems/{}", BMCWEB_REDFISH_SYSTEM_URI_NAME);
        ifaceArray.emplace_back(std::move(system));
        if constexpr (BMCWEB_HYPERVISOR_COMPUTER_SYSTEM)
        {
            BMCWEB_LOG_DEBUG("Hypervisor is available");
            asyncResp->res.jsonValue["Members@odata.count"] = 2;
            nlohmann::json::object_t hypervisor;
            hypervisor["@odata.id"] = "/redfish/v1/Systems/hypervisor";
            ifaceArray.emplace_back(std::move(hypervisor));
        }
    }
}

const PropertyValue getHostTransitionTimeOut(
    const std::string& servicePath, const std::string& objectPath,
    const std::string& interface, const std::string& propertyName)
{
    BMCWEB_LOG_ERROR("getHostTransitionTimeOut");
    PropertyValue value{};

    auto b = sdbusplus::bus::new_default_system();
    auto method = b.new_method_call(servicePath.c_str(), objectPath.c_str(),
                                    dbus_Property_Interface, "Get");

    method.append(interface, propertyName);
    auto reply = b.call(method);
    reply.read(value);
    return value;
}

const PropertyValue getPowerTransitionTimeOut(
    const std::string& servicePath, const std::string& objectPath,
    const std::string& interface, const std::string& propertyName)
{
    BMCWEB_LOG_ERROR("getPowerTransitionTimeOut");
    PropertyValue value{};

    auto b = sdbusplus::bus::new_default_system();
    auto method = b.new_method_call(servicePath.c_str(), objectPath.c_str(),
                                    dbus_Property_Interface, "Get");

    method.append(interface, propertyName);
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

void createResetMaintenanceWindowTask(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    task::Payload&& payload, const std::string& resetType)
{
    BMCWEB_LOG_ERROR("after do Task creartion ");

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

            int convertedIndex = std::stoi(index);

            std::vector<uint16_t> defaultId;

            defaultId.push_back(static_cast<uint16_t>(convertedIndex));

            setTaskName(resetType);

            msg.read(iface, values);

            const char* processName = "xyz.openbmc_project.State.Host0";
            const char* objectPath = "/xyz/openbmc_project/state/host0";
            const char* interfaceName =
                "xyz.openbmc_project.State.OperatingSystem.Status";
            const char* prop_Name = "HostTransitionTimeOut";

            auto host_Value = getHostTransitionTimeOut(
                processName, objectPath, interfaceName, prop_Name);
            auto requestedHostTransition = std::get<uint64_t>(host_Value);

            if (iface == "xyz.openbmc_project.State.OperatingSystem.Status")
            {
                const uint64_t* timeOutValue = nullptr;
                const std::string* osState = nullptr;

                for (const auto& property : values)
                {
                    if (property.first == "HostTransitionTimeOut")
                    {
                        timeOutValue = std::get_if<uint64_t>(&property.second);

                        if (timeOutValue == nullptr)
                        {
                            taskData->messages.emplace_back(
                                messages::internalError());
                            return task::completed;
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

                if ((timeOutValue != nullptr && *timeOutValue != 0))
                {
                    setTaskId(defaultId);
                    setStatus(
                        "xyz.openbmc_project.Common.Task.OperationStatus.New");
                    taskData->state = "Pending";
                    taskData->messages.emplace_back(
                        messages::taskPaused(index));
                    taskData->extendTimer(
                        std::chrono::seconds(requestedHostTransition) +
                        (std::chrono::minutes(10)));
                    return !task::completed;
                }

                if (osState != nullptr && requestedHostTransition == 0)
                {
                    if ((resetType != "GracefulShutdown" &&
                         resetType != "ForceOff") &&
                        *osState ==
                            "xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.Inactive")
                    {
                        setStatus(
                            "xyz.openbmc_project.Common.Task.OperationStatus.InProgress");
                        taskData->state = "Running";
                        taskData->messages.emplace_back(
                            messages::taskStarted(index));
                        taskData->extendTimer(std::chrono::minutes(5));
                        return !task::completed;
                    }
                    else if (
                        (resetType != "GracefulShutdown" &&
                         resetType != "ForceOff") &&
                        *osState ==
                            "xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.Standby")
                    {
                        setStatus(
                            "xyz.openbmc_project.Common.Task.OperationStatus.Completed");
                        taskData->messages.emplace_back(
                            messages::taskCompletedOK(index));
                        taskData->state = "Completed";
                        return task::completed;
                    }

                    else if (
                        (resetType == "ForceOff" ||
                         resetType == "GracefulShutdown") &&
                        *osState ==
                            "xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.Standby")
                    {
                        setStatus(
                            "xyz.openbmc_project.Common.Task.OperationStatus.InProgress");
                        taskData->state = "Running";
                        taskData->messages.emplace_back(
                            messages::taskStarted(index));
                        taskData->extendTimer(std::chrono::minutes(5));
                        return !task::completed;
                    }

                    else if (
                        (resetType == "ForceOff" ||
                         resetType == "GracefulShutdown") &&
                        *osState ==
                            "xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.Inactive")
                    {
                        setStatus(
                            "xyz.openbmc_project.Common.Task.OperationStatus.Completed");
                        taskData->messages.emplace_back(
                            messages::taskCompletedOK(index));
                        taskData->state = "Completed";
                        return task::completed;
                    }
                }
                taskData->extendTimer(
                    std::chrono::seconds(requestedHostTransition) +
                    (std::chrono::minutes(10)));
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

void createSystemMaintenanceWindowTask(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    task::Payload&& payload, const std::string& resetType)
{
    BMCWEB_LOG_ERROR("after do Task creartion ");

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

            int convertedIndex = std::stoi(index);

            std::vector<uint16_t> defaultId;

            defaultId.push_back(static_cast<uint16_t>(convertedIndex));

            setTaskName(resetType);

            msg.read(iface, values);

            const char* processName = timeoutService;
            const char* objectPath = singleHostPath;
            const char* interfaceName = timeoutInterface;
            const char* propName = "PowerTransitionTimeOut";

            auto chassis_Value = getPowerTransitionTimeOut(
                processName, objectPath, interfaceName, propName);
            auto requestedPowerTransition = std::get<uint64_t>(chassis_Value);

            if (iface == "xyz.openbmc_project.State.OperatingSystem.Status")
            {
                const uint64_t* timeOutValue = nullptr;
                const std::string* osState = nullptr;

                for (const auto& property : values)
                {
                    if (property.first == "PowerTransitionTimeOut")
                    {
                        timeOutValue = std::get_if<uint64_t>(&property.second);

                        if (timeOutValue == nullptr)
                        {
                            taskData->messages.emplace_back(
                                messages::internalError());
                            return task::completed;
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

                if (timeOutValue != nullptr && *timeOutValue != 0)
                {
                    setTaskId(defaultId);
                    setStatus(
                        "xyz.openbmc_project.Common.Task.OperationStatus.New");
                    taskData->state = "Pending";
                    taskData->messages.emplace_back(
                        messages::taskPaused(index));
                    taskData->extendTimer(
                        std::chrono::seconds(requestedPowerTransition) +
                        (std::chrono::minutes(10)));
                    return !task::completed;
                }

                if (requestedPowerTransition == 0 && osState != nullptr &&
                    *osState ==
                        "xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.Standby")
                {
                    setStatus(
                        "xyz.openbmc_project.Common.Task.OperationStatus.InProgress");
                    taskData->state = "Running";
                    taskData->messages.emplace_back(
                        messages::taskStarted(index));
                    taskData->extendTimer(std::chrono::minutes(5));
                    return !task::completed;
                }

                if (requestedPowerTransition == 0 && osState != nullptr &&
                    *osState ==
                        "xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.Inactive")
                {
                    setStatus(
                        "xyz.openbmc_project.Common.Task.OperationStatus.Completed");
                    taskData->messages.emplace_back(
                        messages::taskCompletedOK(index));
                    taskData->state = "Completed";
                    return task::completed;
                }
                taskData->extendTimer(
                    std::chrono::seconds(requestedPowerTransition) +
                    (std::chrono::minutes(10)));
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

void SystemsImmediateResetTask(
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

            int convertedIndex = std::stoi(index);

            std::vector<uint16_t> defaultId;

            defaultId.push_back(static_cast<uint16_t>(convertedIndex));

            setTaskName(resetType);

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

                if ((resetType != "ForceOff" &&
                     resetType != "GracefulShutdown") &&
                    *osState ==
                        "xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.Inactive")
                {
                    setTaskId(defaultId);
                    setStatus(
                        "xyz.openbmc_project.Common.Task.OperationStatus.InProgress");
                    taskData->state = "Running";
                    taskData->messages.emplace_back(
                        messages::taskStarted(index));
                    taskData->extendTimer(std::chrono::minutes(5));
                    return !task::completed;
                }

                if ((resetType == "ForceOff" ||
                     resetType == "GracefulShutdown") &&
                    *osState ==
                        "xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.Standby")
                {
                    setStatus(
                        "xyz.openbmc_project.Common.Task.OperationStatus.InProgress");
                    taskData->state = "Running";
                    taskData->messages.emplace_back(
                        messages::taskStarted(index));
                    taskData->extendTimer(std::chrono::minutes(5));
                    return !task::completed;
                }

                if ((resetType != "ForceOff" ||
                     resetType != "GracefulShutdown") &&
                    *osState ==
                        "xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.Standby")
                {
                    setStatus(
                        "xyz.openbmc_project.Common.Task.OperationStatus.Completed");
                    taskData->messages.emplace_back(
                        messages::taskCompletedOK(index));
                    taskData->state = "Completed";
                    return task::completed;
                }

                else if (
                    (resetType == "ForceOff" ||
                     resetType == "GracefulShutdown") &&
                    *osState ==
                        "xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.Inactive")
                {
                    setStatus(
                        "xyz.openbmc_project.Common.Task.OperationStatus.Completed");
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

/**
 * Func give the timeout value in seconds
 *
 * @param[in] posixTime_1 - MaintenanceWindowStarTime converted to posixtime
 * @param[in] redfishDateTimeOffset - Current BMC Timezone
 */
inline uint64_t handleSystemsDifferenceTime(
    boost::posix_time::ptime posixTime_1, std::string& redfishDateTimeOffset)
{
    BMCWEB_LOG_ERROR("handleDifferenceTime");
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

inline void setSystemsPowerTransitionTimer(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const uint64_t powerTransitionTimeOut)
{
    BMCWEB_LOG_ERROR("setPowerTransitionTimer");
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
        "PowerTransitionTimeOut",
        dbus::utility::DbusVariantType(powerTransitionTimeOut));
}

inline void setHostTransitionTimer(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const uint64_t hostTransitionTimeOut)
{
    BMCWEB_LOG_ERROR("setHostTransitionTimer");
    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code ec) {
            if (ec)
            {
                messages::internalError(asyncResp->res);
            }
        },
        timeoutService, singleHostPath, "org.freedesktop.DBus.Properties",
        "Set", timeoutInterface, "HostTransitionTimeOut",
        dbus::utility::DbusVariantType(hostTransitionTimeOut));
}

/**
 * Handle error responses from d-bus for system power requests
 */
inline void handleSystemActionResetError(
    const boost::system::error_code& ec, const sdbusplus::message_t& eMsg,
    std::string_view resetType, crow::Response& res)
{
    if (ec.value() == boost::asio::error::invalid_argument)
    {
        messages::actionParameterNotSupported(res, resetType, "Reset");
        return;
    }

    if (eMsg.get_error() == nullptr)
    {
        BMCWEB_LOG_ERROR("D-Bus response error: {}", ec);
        messages::internalError(res);
        return;
    }
    std::string_view errorMessage = eMsg.get_error()->name;

    // If operation failed due to BMC not being in Ready state, tell
    // user to retry in a bit
    if ((errorMessage ==
         std::string_view(
             "xyz.openbmc_project.State.Chassis.Error.BMCNotReady")) ||
        (errorMessage ==
         std::string_view("xyz.openbmc_project.State.Host.Error.BMCNotReady")))
    {
        BMCWEB_LOG_DEBUG("BMC not ready, operation not allowed right now");
        messages::serviceTemporarilyUnavailable(res, "10");
        return;
    }

    BMCWEB_LOG_ERROR("System Action Reset transition fail {} sdbusplus:{}", ec,
                     errorMessage);
    messages::internalError(res);
}

/**
 * Function transceives data with dbus directly.
 */
// Currently NMI is not supported
/*inline void doNMI(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    constexpr const char* serviceName = "xyz.openbmc_project.Control.Host.NMI";
    constexpr const char* objectPath = "/xyz/openbmc_project/control/host0/nmi";
    constexpr const char* interfaceName =
        "xyz.openbmc_project.Control.Host.NMI";
    constexpr const char* method = "NMI";

    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code& ec) {
        if (ec)
        {
            BMCWEB_LOG_ERROR(" Bad D-Bus request error: {}", ec);
            messages::internalError(asyncResp->res);
            return;
        }
        messages::success(asyncResp->res);
    }, serviceName, objectPath, interfaceName, method);
}*/

inline void systemResetAction(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& resetType, const std::string& hostService,
    const std::string& hostPath, const std::string& chassisService,
    const std::string& chassisPath)
{
    BMCWEB_LOG_ERROR("systemResetAction - hostService: {}, hostPath: {}",
                     hostService, hostPath);

    std::string command;
    bool hostCommand = true;

    if ((resetType == "On") || (resetType == "ForceOn"))
    {
        command = "xyz.openbmc_project.State.Host.Transition.On";
        hostCommand = true;
    }

    else if (resetType == "ForceOff")
    {
        command = "xyz.openbmc_project.State.Chassis.Transition.Off";
        hostCommand = false;
    }

    else if (resetType == "ForceRestart")
    {
        command = "xyz.openbmc_project.State.Host.Transition.ForceWarmReboot";
        hostCommand = true;
    }

    else if (resetType == "GracefulShutdown")
    {
        command = "xyz.openbmc_project.State.Host.Transition.Off";
        hostCommand = true;
    }

    else if (resetType == "GracefulRestart")
    {
        command =
            "xyz.openbmc_project.State.Host.Transition.GracefulWarmReboot";
        hostCommand = true;
    }

    else if (resetType == "PowerCycle")
    {
        command = "xyz.openbmc_project.State.Host.Transition.Reboot";
        hostCommand = true;
    }

    else
    {
        messages::actionParameterNotSupported(asyncResp->res, resetType,
                                              "ResetType");
        return;
    }

    if (hostCommand)
    {
        sdbusplus::asio::setProperty(
            *crow::connections::systemBus, hostService, hostPath,
            hostStateInterface, "RequestedHostTransition", command,
            [asyncResp, resetType](const boost::system::error_code& ec,
                                   sdbusplus::message_t& sdbusErrMsg) {
                if (ec)
                {
                    handleSystemActionResetError(ec, sdbusErrMsg, resetType,
                                                 asyncResp->res);

                    return;
                }
            });
    }
    else
    {
        sdbusplus::asio::setProperty(
            *crow::connections::systemBus, chassisService, chassisPath,
            chassisStateInterface, "RequestedPowerTransition", command,
            [asyncResp, resetType](const boost::system::error_code& ec,
                                   sdbusplus::message_t& sdbusErrMsg) {
                if (ec)
                {
                    handleSystemActionResetError(ec, sdbusErrMsg, resetType,
                                                 asyncResp->res);
                    return;
                }
            });
    }
}

inline void handleComputerSystemResetActionPost(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& systemName)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    if (system_utils::isDualHostEnabled())
    {
        // Dual node code
        // Map systemName to D-Bus host and chassis objects
        std::string hostService, hostPath, chassisService, chassisPath;
        if (systemName == "system1")
        {
            // "system1" maps to Host2/Chassis2 in dual-node mode
            hostService = host2Service;
            hostPath = host2Path;
            chassisService = chassis2Service;
            chassisPath = chassis2Path;
        }
        else if (systemName == "system")
        {
            // "system" (default) maps to Host1/Chassis1 in dual-node mode
            hostService = host1Service;
            hostPath = host1Path;
            chassisService = chassis1Service;
            chassisPath = chassis1Path;
        }
        else
        {
            messages::resourceNotFound(asyncResp->res, "ComputerSystem",
                                       systemName);
            return;
        }

        std::string resetType;
        if (!json_util::readJsonAction(req, asyncResp->res, "ResetType",
                                       resetType))
        {
            return;
        }

        // Use the refactored systemResetAction with node-specific paths
        systemResetAction(asyncResp, resetType, hostService, hostPath,
                          chassisService, chassisPath);
        messages::success(asyncResp->res);
    }
    else
    {
        // Single node code
        if constexpr (BMCWEB_HYPERVISOR_COMPUTER_SYSTEM)
        {
            if (systemName == "hypervisor")
            {
                handleHypervisorSystemResetPost(req, asyncResp);
                return;
            }
        }

        if (!system_utils::validateSystemName(asyncResp, systemName))
        {
            return;
        }
        if constexpr (BMCWEB_EXPERIMENTAL_REDFISH_MULTI_COMPUTER_SYSTEM)
        {
            // Option currently returns no systems.  TBD
            messages::resourceNotFound(asyncResp->res, "ComputerSystem",
                                       systemName);
            return;
        }

        std::string resetType;
        std::optional<std::string> operationApplyTime;
        std::optional<std::string> maintenanceWindowStartTime;
        std::string startTime;

        task::Payload payload(req);

        // Current BMC Timezone
        std::string redfishDateTimeOffset =
            redfish::time_utils::getDateTimeOffsetNow().first;

        auto host_Value =
            getHostTransitionTimeOut(timeoutService, singleHostPath,
                                     timeoutInterface, "HostTransitionTimeOut");

        auto requestedHostTransition = std::get<uint64_t>(host_Value);

        auto chassis_Value = getPowerTransitionTimeOut(
            timeoutService, singleHostPath, timeoutInterface,
            "PowerTransitionTimeOut");
        auto requestedPowerTransition = std::get<uint64_t>(chassis_Value);

        // Get current host state synchronously for validation
        auto value =
            getHostTransitionTimeOut(hostStateService, singleHostPath,
                                     hostStateInterface, "CurrentHostState");
        auto reqHostState = std::get<std::string>(value);

        if (!json_util::readJsonAction(                                  //
                req, asyncResp->res,                                     //
                "ResetType", resetType,                                  //
                "OperationApplyTime", operationApplyTime,                //
                "MaintenanceWindowStartTime", maintenanceWindowStartTime //
                ))
        {
            return;
        }

        if ((resetType != "On") && (resetType != "ForceOn") &&
            (resetType != "ForceOff") && (resetType != "ForceRestart") &&
            (resetType != "GracefulShutdown") &&
            (resetType != "GracefulRestart") && (resetType != "PowerCycle"))
        {
            messages::actionParameterNotSupported(asyncResp->res, resetType,
                                                  "ResetType");
            return;
        }

        // To provide as a stringstream object
        startTime = *maintenanceWindowStartTime;

        if ((resetType == "On") || (resetType == "ForceOn"))
        {
            // Log DCPowerOn when the host is powered ON
            std::string severity =
                "xyz.openbmc_project.Logging.Entry.Level.Warning";
            auto bus = sdbusplus::bus::new_default_system();
            sdbusplus::message::message m = bus.new_method_call(
                "xyz.openbmc_project.Logging", "/xyz/openbmc_project/logging",
                "xyz.openbmc_project.Logging.Create", "Create");
            std::string journalMsg = "DCPowerOn"; // Logging power ON
            m.append(journalMsg, severity,
                     std::map<std::string, std::string>());
            try
            {
                bus.call(m);
            }
            catch (const sdbusplus::exception_t& e)
            {
                std::cerr << "Failed to create log entry: " << e.what()
                          << std::endl;
            }

            if (reqHostState ==
                "xyz.openbmc_project.State.Host.HostState.Running")
            {
                BMCWEB_LOG_ERROR(" Host is in Standby state");
                messages::noOperation(asyncResp->res);
                return;
            }
        }

        else if (resetType == "ForceOff" || resetType == "ForceRestart" ||
                 resetType == "GracefulShutdown" ||
                 resetType == "GracefulRestart" || resetType == "PowerCycle")
        {
            if (reqHostState !=
                "xyz.openbmc_project.State.Host.HostState.Running")
            {
                // Log DCPowerOff when the host is powered OFF
                std::string severity =
                    "xyz.openbmc_project.Logging.Entry.Level.Warning";
                auto bus = sdbusplus::bus::new_default_system();
                sdbusplus::message::message m = bus.new_method_call(
                    "xyz.openbmc_project.Logging",
                    "/xyz/openbmc_project/logging",
                    "xyz.openbmc_project.Logging.Create", "Create");
                std::string journalMsg = "DCPowerOff"; // Logging power OFF
                m.append(journalMsg, severity,
                         std::map<std::string, std::string>());
                try
                {
                    bus.call(m);
                }
                catch (const sdbusplus::exception_t& e)
                {
                    std::cerr << "Failed to create log entry: " << e.what()
                              << std::endl;
                }

                messages::noOperation(asyncResp->res);
                return;
            }
        }

        if (!(resetType.empty()) && !operationApplyTime &&
            !maintenanceWindowStartTime)
        {
            systemResetAction(asyncResp, resetType, hostStateService,
                              singleHostPath, chassisStateService,
                              singleChassisPath);
            messages::success(asyncResp->res);
            return;
        }

        if (operationApplyTime == "Immediate")
        {
            BMCWEB_LOG_ERROR("Immediate Reset");
            if (!(maintenanceWindowStartTime))
            {
                SystemsImmediateResetTask(asyncResp, std::move(payload),
                                          resetType);
                systemResetAction(asyncResp, resetType, hostStateService,
                                  singleHostPath, chassisStateService,
                                  singleChassisPath);
                return;
            }

            else
            {
                BMCWEB_LOG_ERROR("Invalid Property for Immediate reboot");
                messages::actionParameterNotSupported(
                    asyncResp->res, "MaintenanceWindowStartTime", "Immediate");
                return;
            }
        }

        else if (operationApplyTime == "AtMaintenanceWindowStart")
        {
            if (maintenanceWindowStartTime)
            {
                if (maintenanceWindowStartTime <= redfishDateTimeOffset)
                {
                    BMCWEB_LOG_ERROR(
                        "maintenanceWindowStartTime less than redfishDateTimeOffset");
                    messages::propertyValueIncorrect(
                        asyncResp->res, "AtMaintenanceWindowStartTime",
                        startTime);
                    return;
                }

                std::stringstream stream1(startTime);
                boost::posix_time::ptime posixTime_1;

                // Facet gets deleted with the stringsteam
                auto ifc1 =
                    std::make_unique<boost::local_time::local_time_input_facet>(
                        "%Y-%m-%d %H:%M:%S%F %ZP");
                stream1.imbue(std::locale(stream1.getloc(), ifc1.release()));
                boost::local_time::local_date_time ldt1(
                    boost::local_time::not_a_date_time);

                if (stream1 >> ldt1)
                {
                    posixTime_1 = ldt1.utc_time();
                }

                else
                {
                    BMCWEB_LOG_ERROR("MaintenanceWindowStartTime Format Error");
                    messages::propertyValueFormatError(
                        asyncResp->res, startTime,
                        "MaintenanceWindowStartTime");
                    return;
                }

                // Difference of BMCTime and MaintenanceWindowStartTime
                uint64_t timeOut = handleSystemsDifferenceTime(
                    posixTime_1, redfishDateTimeOffset);

                if (resetType == "ForceOff")
                {
                    if (requestedPowerTransition != 0)
                    {
                        messages::resourceInUse(asyncResp->res);
                        return;
                    }

                    setSystemsPowerTransitionTimer(asyncResp, timeOut);
                    createSystemMaintenanceWindowTask(
                        asyncResp, std::move(payload), resetType);
                    systemResetAction(asyncResp, resetType, hostStateService,
                                      singleHostPath, chassisStateService,
                                      singleChassisPath);
                    return;
                }

                if (resetType != "ForceOff")
                {
                    if (requestedHostTransition != 0)
                    {
                        messages::resourceInUse(asyncResp->res);
                        return;
                    }

                    setHostTransitionTimer(asyncResp, timeOut);
                    createResetMaintenanceWindowTask(
                        asyncResp, std::move(payload), resetType);
                    systemResetAction(asyncResp, resetType, hostStateService,
                                      singleHostPath, chassisStateService,
                                      singleChassisPath);
                    return;
                }
            }
            else
            {
                BMCWEB_LOG_ERROR(
                    "Missing Property AtMaintenanceWindowStartTime");
                messages::actionParameterMissing(
                    asyncResp->res, "Reset", "AtMaintenanceWindowStartTime");
                return;
            }
        }
        else
        {
            BMCWEB_LOG_ERROR("Missing Property OperationApplyTime");
            messages::actionParameterNotSupported(
                asyncResp->res, *operationApplyTime, "OperationApplyTime");
            return;
        }
    }
}

inline void handleComputerSystemHead(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& /*systemName*/)
{
    asyncResp->res.clearHeader(boost::beast::http::field::allow);
    asyncResp->res.addHeader("Allow", "GET, HEAD, PATCH");
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/ComputerSystem/ComputerSystem.json>; rel=describedby");
}

void afterPortRequest(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const boost::system::error_code& ec,
    const std::vector<std::tuple<std::string, std::string, bool>>& socketData)
{
    if (ec)
    {
        BMCWEB_LOG_ERROR("DBUS response error {}", ec);
        messages::internalError(asyncResp->res);
        return;
    }
    for (const auto& data : socketData)
    {
        const std::string& socketPath = get<0>(data);
        const std::string& protocolName = get<1>(data);
        bool isProtocolEnabled = get<2>(data);
        nlohmann::json& dataJson = asyncResp->res.jsonValue["SerialConsole"];
        dataJson[protocolName]["ServiceEnabled"] = isProtocolEnabled;
        // need to retrieve port number for
        // obmc-console-ssh service
        if (protocolName == "SSH")
        {
            getPortNumber(socketPath, [asyncResp, protocolName](
                                          const boost::system::error_code& ec1,
                                          int portNumber) {
                if (ec1)
                {
                    BMCWEB_LOG_ERROR("DBUS response error {}", ec1);
                    messages::internalError(asyncResp->res);
                    return;
                }
                nlohmann::json& dataJson1 =
                    asyncResp->res.jsonValue["SerialConsole"];
                dataJson1[protocolName]["Port"] = portNumber;
            });
        }
    }
}

inline void handleComputerSystemGet(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& systemName)
{
    asyncResp->res.clearHeader(boost::beast::http::field::allow);
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (!membersResponseGet(asyncResp, systemName, "ComputerSystemCollection"))
    {
        return;
    }
    if constexpr (BMCWEB_EXPERIMENTAL_REDFISH_MULTI_COMPUTER_SYSTEM)
    {
        // Option currently returns no systems.  TBD
        messages::resourceNotFound(asyncResp->res, "ComputerSystem",
                                   systemName);
        return;
    }
    asyncResp->res.addHeader("Allow", "GET, HEAD, PATCH");
    if constexpr (BMCWEB_HYPERVISOR_COMPUTER_SYSTEM)
    {
        if (systemName == "hypervisor")
        {
            handleHypervisorSystemGet(asyncResp);
            return;
        }
    }

    if (system_utils::isDualHostEnabled())
    {
        // For dual node, accept system and system1
        if (systemName != "system" && systemName != "system1")
        {
            messages::resourceNotFound(asyncResp->res, "ComputerSystem",
                                       systemName);
            return;
        }
    }
    else
    {
        if (systemName != BMCWEB_REDFISH_SYSTEM_URI_NAME)
        {
            messages::resourceNotFound(asyncResp->res, "ComputerSystem",
                                       systemName);
            return;
        }
    }

    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/ComputerSystem/ComputerSystem.json>; rel=describedby");
    asyncResp->res.jsonValue["@odata.type"] =
        json_util::odataType("ComputerSystem");
    asyncResp->res.jsonValue["Name"] = systemName;
    asyncResp->res.jsonValue["Id"] = systemName;
    asyncResp->res.jsonValue["@odata.id"] =
        boost::urls::format("/redfish/v1/Systems/{}", systemName);

    // Common properties for both dual node and single node
    asyncResp->res.jsonValue["SystemType"] =
        computer_system::SystemType::Physical;
    asyncResp->res.jsonValue["Description"] = "Computer System";

    asyncResp->res.jsonValue["Actions"]["#ComputerSystem.Reset"]["target"] =
        boost::urls::format(
            "/redfish/v1/Systems/{}/Actions/ComputerSystem.Reset", systemName);
    asyncResp->res
        .jsonValue["Actions"]["#ComputerSystem.Reset"]["@Redfish.ActionInfo"] =
        boost::urls::format("/redfish/v1/Systems/{}/ResetActionInfo",
                            systemName);

    asyncResp->res.jsonValue["LogServices"]["@odata.id"] =
        boost::urls::format("/redfish/v1/Systems/{}/LogServices", systemName);

    asyncResp->res.jsonValue["Storage"]["@odata.id"] =
        boost::urls::format("/redfish/v1/Systems/{}/Storage", systemName);

    nlohmann::json::array_t managedBy;
    nlohmann::json& manager = managedBy.emplace_back();
    manager["@odata.id"] = boost::urls::format("/redfish/v1/Managers/{}",
                                               BMCWEB_REDFISH_MANAGER_URI_NAME);
    asyncResp->res.jsonValue["Links"]["ManagedBy"] = std::move(managedBy);

    asyncResp->res.jsonValue["Status"]["Health"] = resource::Health::OK;

    // SerialConsole - common setup
    asyncResp->res.jsonValue["SerialConsole"]["MaxConcurrentSessions"] = 15;
    asyncResp->res.jsonValue["SerialConsole"]["IPMI"]["ServiceEnabled"] = true;
    if constexpr (BMCWEB_VM_NBDPROXY)
    {
        asyncResp->res.jsonValue["VirtualMedia"]["@odata.id"] =
            boost::urls::format("/redfish/v1/Systems/{}/VirtualMedia",
                                systemName);
    }

#if (BMCWEB_AMI_NIC_MACRO)
    asyncResp->res.jsonValue["NetworkInterfaces"]["@odata.id"] =
        boost::urls::format("/redfish/v1/Systems/{}/NetworkInterfaces",
                            systemName);
#endif

#ifdef BMCWEB_VM_NBDPROXY
    asyncResp->res.jsonValue["VirtualMedia"] =
        boost::urls::format("/redfish/v1/Systems/{}/VirtualMedia", systemName);
#endif
#ifndef ONETREE_RM
    getMainChassisId(
        asyncResp, [](const std::string& chassisId,
                      const std::shared_ptr<bmcweb::AsyncResp>& aRsp) {
            nlohmann::json::array_t chassisArray;
            nlohmann::json& chassis = chassisArray.emplace_back();
            chassis["@odata.id"] =
                boost::urls::format("/redfish/v1/Chassis/{}", chassisId);
            aRsp->res.jsonValue["Links"]["Chassis"] = std::move(chassisArray);
        });
#endif

    getPhysicalLedState(asyncResp);
    getHostWatchdogTimer(asyncResp, systemName);
    getPowerRestorePolicy(asyncResp);
    getKvmConfig(asyncResp, systemName);
    getVirtualMediaConfig(asyncResp, systemName);
    getHostState(asyncResp, systemName);
    getLastResetTime(asyncResp, systemName);
    getSerialConsoleSshStatus(asyncResp, systemName);

    if (system_utils::isDualHostEnabled())
    {
        // Dual node mode: minimal response, return early
        return;
    }
    else
    {
        // Single node mode: additional properties and full feature set
        asyncResp->res.jsonValue["ProcessorSummary"]["Count"] = 0;
        asyncResp->res.jsonValue["MemorySummary"]["TotalSystemMemoryGiB"] =
            double(0);
        asyncResp->res.jsonValue["@odata.id"] =
            boost::urls::format("/redfish/v1/Systems/{}", systemName);

        asyncResp->res.jsonValue["Processors"]["@odata.id"] =
            boost::urls::format("/redfish/v1/Systems/{}/Processors",
                                systemName);
        asyncResp->res.jsonValue["Memory"]["@odata.id"] =
            boost::urls::format("/redfish/v1/Systems/{}/Memory", systemName);
        asyncResp->res.jsonValue["Storage"]["@odata.id"] =
            boost::urls::format("/redfish/v1/Systems/{}/Storage", systemName);
        asyncResp->res.jsonValue["FabricAdapters"]["@odata.id"] =
            boost::urls::format("/redfish/v1/Systems/{}/FabricAdapters",
                                systemName);
#ifdef ONETREE_NIC
        asyncResp->res.jsonValue["NetworkInterfaces"]["@odata.id"] =
            boost::urls::format("/redfish/v1/Systems/{}/NetworkInterfaces",
                                systemName);
#endif

        asyncResp->res.jsonValue["Bios"]["@odata.id"] =
            boost::urls::format("/redfish/v1/Systems/{}/Bios", systemName);

        getSystemLocationIndicatorActive(asyncResp);
        getComputerSystem(asyncResp);
        getBootProperties(asyncResp);
        getBootProgress(asyncResp);
        getBootProgressLastStateTime(asyncResp);
        getCPLDBootProgress(asyncResp);
        pcie_util::getPCIeDeviceList(
            asyncResp, nlohmann::json::json_pointer("/PCIeDevices"));
        getStopBootOnFault(asyncResp);
        getAutomaticRetryPolicy(asyncResp);
        if constexpr (BMCWEB_REDFISH_PROVISIONING_FEATURE)
        {
            getProvisioningStatus(asyncResp);
        }
        getTrustedModuleRequiredToBoot(asyncResp);
        getPowerMode(asyncResp);
        getIdlePowerSaver(asyncResp);
        getSerialConsoleSshStatus(asyncResp, systemName);
    }
}

inline void handleComputerSystemPatch(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& systemName)
{
    asyncResp->res.clearHeader(boost::beast::http::field::allow);
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (!membersResponseGet(asyncResp, systemName, "ComputerSystemCollection"))
    {
        return;
    }
    if constexpr (BMCWEB_EXPERIMENTAL_REDFISH_MULTI_COMPUTER_SYSTEM)
    {
        // Option currently returns no systems.  TBD
        messages::resourceNotFound(asyncResp->res, "ComputerSystem",
                                   systemName);
        return;
    }
    if (!system_utils::validateSystemName(asyncResp, systemName))
    {
        return;
    }
    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/ComputerSystem/ComputerSystem.json>; rel=describedby");

    std::optional<bool> locationIndicatorActive;
    // std::optional<std::string> indicatorLed;
    std::optional<std::string> assetTag;
    std::optional<std::string> powerRestorePolicy;
    std::optional<std::string> powerMode;
    std::optional<bool> wdtEnable;
    std::optional<std::string> wdtTimeOutAction;
    std::optional<std::string> bootSource;
    std::optional<std::string> bootType;
    std::optional<std::string> bootEnable;
    std::optional<std::string> bootAutomaticRetry;
    std::optional<uint32_t> bootAutomaticRetryAttempts;
    std::optional<std::string> bootTrustedModuleRequired;
    std::optional<std::string> stopBootOnFault;
    std::optional<bool> ipsEnable;
    std::optional<uint8_t> ipsEnterUtil;
    std::optional<uint64_t> ipsEnterTime;
    std::optional<uint8_t> ipsExitUtil;
    std::optional<uint64_t> ipsExitTime;
    std::optional<nlohmann::json> serialConsole;
    std::optional<nlohmann::json> virtualMediaConfig;
    std::optional<nlohmann::json> kvmConfig;
    std::optional<std::string> vId;
    std::optional<nlohmann::json> oem;

    // clang-format off
    if (!json_util::readJsonPatch(
            req, asyncResp->res, //
            //"IndicatorLED", indicatorLed, //
            "LocationIndicatorActive", locationIndicatorActive, //
            "AssetTag", assetTag, //
            "PowerRestorePolicy", powerRestorePolicy, //
            "PowerMode", powerMode, //
            "HostWatchdogTimer/FunctionEnabled", wdtEnable, //
            "HostWatchdogTimer/TimeoutAction", wdtTimeOutAction, //
            "Boot/BootSourceOverrideTarget", bootSource, //
            "Boot/BootSourceOverrideMode", bootType, //
            "Boot/BootSourceOverrideEnabled", bootEnable, //
            "Boot/AutomaticRetryConfig", bootAutomaticRetry, //
            "Boot/AutomaticRetryAttempts", bootAutomaticRetryAttempts, //
            "Boot/TrustedModuleRequiredToBoot", bootTrustedModuleRequired, //
            "Boot/StopBootOnFault", stopBootOnFault, //
            "IdlePowerSaver/Enabled", ipsEnable, //
            "IdlePowerSaver/EnterUtilizationPercent", ipsEnterUtil, //
            "IdlePowerSaver/EnterDwellTimeSeconds", ipsEnterTime, //
            "IdlePowerSaver/ExitUtilizationPercent", ipsExitUtil, //
            "IdlePowerSaver/ExitDwellTimeSeconds", ipsExitTime, //
            "SerialConsole", serialConsole, //
            "VirtualMediaConfig", virtualMediaConfig, //
            "GraphicalConsole", kvmConfig, //
            "Id", vId, //
            "Oem", oem //
            ))

    {
        return;
    }
    
    if (vId)
    {
        messages::propertyNotWritable(asyncResp->res, "Id");
        asyncResp->res.result(boost::beast::http::status::bad_request);
        return;
    }
    // clang-format on
    asyncResp->res.result(boost::beast::http::status::no_content);

    if (assetTag)
    {
        setAssetTag(asyncResp, *assetTag);
    }

    if (wdtEnable || wdtTimeOutAction)
    {
        setWDTProperties(asyncResp, wdtEnable, wdtTimeOutAction, systemName);
    }

    if (bootSource || bootType || bootEnable)
    {
        setBootProperties(asyncResp, bootSource, bootType, bootEnable);
    }
    if (bootAutomaticRetry)
    {
        setAutomaticRetry(asyncResp, *bootAutomaticRetry);
    }

    if (bootAutomaticRetryAttempts)
    {
        setAutomaticRetryAttempts(asyncResp,
                                  bootAutomaticRetryAttempts.value());
    }

    if (bootTrustedModuleRequired)
    {
        setTrustedModuleRequiredToBoot(asyncResp, *bootTrustedModuleRequired);
    }

    if (stopBootOnFault)
    {
        setStopBootOnFault(asyncResp, *stopBootOnFault);
    }

    if (locationIndicatorActive)
    {
        setSystemLocationIndicatorActive(asyncResp, *locationIndicatorActive);
    }

    // TODO (Gunnar): Remove IndicatorLED after enough time has
    // passed
    /*if (indicatorLed)
    {
        setIndicatorLedState(asyncResp, *indicatorLed);
        asyncResp->res.addHeader(boost::beast::http::field::warning,
                                 "299 - \"IndicatorLED is deprecated. Use "
                                 "LocationIndicatorActive instead.\"");
    }*/

    if (powerRestorePolicy)
    {
        setPowerRestorePolicy(asyncResp, *powerRestorePolicy);
    }

    if (powerMode)
    {
        setPowerMode(asyncResp, *powerMode);
    }

    if (ipsEnable || ipsEnterUtil || ipsEnterTime || ipsExitUtil || ipsExitTime)
    {
        setIdlePowerSaver(asyncResp, ipsEnable, ipsEnterUtil, ipsEnterTime,
                          ipsExitUtil, ipsExitTime);
    }

    if (kvmConfig)
    {
        std::optional<bool> kvmServiceEnabled;

        if (!json_util::readJson(                   //
                *kvmConfig, asyncResp->res,         //
                "ServiceEnabled", kvmServiceEnabled //
                ))
        {
            return;
        }

        if (kvmServiceEnabled)
        {
            service_util::setEnabled(asyncResp, getKvmServiceName(systemName),
                                     *kvmServiceEnabled);
        }
    }

    if (serialConsole)
    {
        std::optional<nlohmann::json> ssh;
        if (!json_util::readJson(               //
                *serialConsole, asyncResp->res, //
                "SSH", ssh                      //
                ))
        {
            return;
        }

        if (ssh)
        {
            std::optional<bool> sshServiceEnabled;

            std::optional<uint16_t> sshPortNumber;
            if (!json_util::readJson(                    //
                    *ssh, asyncResp->res,                //
                    "ServiceEnabled", sshServiceEnabled, //
                    "Port", sshPortNumber                //
                    ))
            {
                return;
            }

            if (sshServiceEnabled)
            {
                service_util::setEnabled(asyncResp, serialConsoleSshServiceName,
                                         *sshServiceEnabled);
            }
            if (sshPortNumber)
            {
                service_util::setPortNumber(
                    asyncResp, serialConsoleSshServiceName, *sshPortNumber);
            }
        }
    }

    if (virtualMediaConfig)
    {
        std::optional<bool> vmServiceEnabled;
        if (!json_util::readJson(                    //
                *virtualMediaConfig, asyncResp->res, //
                "ServiceEnabled", vmServiceEnabled   //
                ))
        {
            return;
        }

        if (vmServiceEnabled)
        {
            service_util::setEnabled(asyncResp,
                                     getVirtualMediaServiceName(systemName),
                                     *vmServiceEnabled);
        }
    }

    if (oem)
    {
        if (oem->empty())
        {
            messages::propertyNotWritable(asyncResp->res, "Oem");
            return;
        }

        std::optional<nlohmann::json> ami;

        if (!json_util::readJson(*oem, asyncResp->res, "Ami", ami))
        {
            return;
        }

        if (ami)
        {
            if (ami->empty())
            {
                messages::propertyNotWritable(asyncResp->res, "Ami");
                return;
            }

            std::optional<nlohmann::json> serialConsoleOem;
            std::optional<nlohmann::json> graphicalConsole;
            std::optional<nlohmann::json> virtualMediaConfigOem;

            if (!json_util::readJson(*ami, asyncResp->res, "SerialConsole",
                                     serialConsoleOem, "GraphicalConsole",
                                     graphicalConsole, "VirtualMediaConfig",
                                     virtualMediaConfigOem))
            {
                return;
            }

            // Handle SerialConsole
            if (serialConsoleOem)
            {
                if (!serialConsoleOem->is_object())
                {
                    messages::propertyValueTypeError(
                        asyncResp->res, *serialConsoleOem, "SerialConsole");
                    return;
                }
                if (serialConsoleOem->empty())
                {
                    return;
                }

                std::optional<nlohmann::json> sshOem;
                if (!json_util::readJson(*serialConsoleOem, asyncResp->res,
                                         "SSH", sshOem))
                {
                    return;
                }

                if (sshOem)
                {
                    if (!sshOem->is_object())
                    {
                        messages::propertyValueTypeError(asyncResp->res,
                                                         *sshOem, "SSH");
                        return;
                    }
                    if (sshOem->empty())
                    {
                        return;
                    }

                    std::optional<bool> sshMaskedOem;
                    std::optional<nlohmann::json> solsshList;

                    if (!json_util::readJson(*sshOem, asyncResp->res, "Masked",
                                             sshMaskedOem, "SOLSSH",
                                             solsshList))
                    {
                        return;
                    }
                    // SOLSSH must be an array of objects, not
                    // null/object/scalar
                    if (solsshList && !solsshList->is_array())
                    {
                        messages::propertyValueTypeError(asyncResp->res,
                                                         *solsshList, "SOLSSH");
                        return;
                    }

                    // Handle single SOL Masked property
                    if (sshMaskedOem)
                    {
                        service_util::setMasked(asyncResp,
                                                serialConsoleSshServiceName,
                                                *sshMaskedOem);
                        return;
                    }
                    // Handle SOLSSH array property
                    if (solsshList)
                    {
                        service_util::getAllAvailableTtyServices(
                            asyncResp,
                            [asyncResp, solsshList, sshMaskedOem, systemName](
                                const std::vector<std::string>&
                                    availableTtys) mutable {
                                if (availableTtys.empty())
                                {
                                    return;
                                }

                                // Now process each SOLSSH item
                                for (nlohmann::json& solsshItem : *solsshList)
                                {
                                    if (!solsshItem.is_null() &&
                                        !solsshItem.empty())
                                    {
                                        std::string id;
                                        std::optional<bool> serviceEnabled;
                                        std::optional<bool> masked;
                                        std::optional<nlohmann::json> running;

                                        if (!json_util::readJson(
                                                solsshItem, asyncResp->res,
                                                "Id", id, "Masked", masked,
                                                "ServiceEnabled",
                                                serviceEnabled, "Running",
                                                running))
                                        {
                                            return;
                                        }

                                        // Running is a read-only status
                                        // property; reject PATCH attempts.
                                        if (running)
                                        {
                                            messages::propertyNotWritable(
                                                asyncResp->res, "Running");
                                            asyncResp->res.result(
                                                boost::beast::http::status::
                                                    bad_request);
                                            return;
                                        }

                                        if (!id.starts_with("tty"))
                                        {
                                            messages::propertyValueFormatError(
                                                asyncResp->res, id, "Id");
                                            return;
                                        }
                                        // Check if the TTY service exists
                                        bool ttyExists =
                                            std::find(availableTtys.begin(),
                                                      availableTtys.end(),
                                                      id) !=
                                            availableTtys.end();
                                        if (!ttyExists)
                                        {
                                            messages::propertyValueNotInList(
                                                asyncResp->res, id, "Id");
                                            continue;
                                        }
                                        if (serviceEnabled)
                                        {
                                            messages::propertyNotWritable(
                                                asyncResp->res,
                                                "ServiceEnabled");
                                            asyncResp->res.result(
                                                boost::beast::http::status::
                                                    bad_request);
                                            return;
                                        }
                                        if (system_utils::isDualHostEnabled())
                                        {
                                            if ((systemName == "system" &&
                                                 (id == "ttyS3" ||
                                                  id == "ttyVUART1")) ||
                                                (systemName == "system1" &&
                                                 (id == "ttyS13" ||
                                                  id == "ttyVUART0")))
                                            {
                                                messages::
                                                    propertyValueNotInList(
                                                        asyncResp->res, id,
                                                        "Id");
                                                continue;
                                            }
                                        }
                                        if (masked)
                                        {
                                            service_util::setMasked(
                                                asyncResp,
                                                "obmc_2dconsole_40" + id,
                                                *masked);
                                        }
                                    }
                                }
                            });
                    }
                }
            }

            // Handle GraphicalConsole/Masked
            if (graphicalConsole)
            {
                std::optional<bool> masked;
                if (!json_util::readJson(*graphicalConsole, asyncResp->res,
                                         "Masked", masked))
                {
                    return;
                }

                if (masked)
                {
                    service_util::setMasked(
                        asyncResp, getKvmServiceName(systemName), *masked);
                }
            }

            // Handle VirtualMediaConfig/Masked
            if (virtualMediaConfigOem)
            {
                std::optional<bool> masked;
                if (!json_util::readJson(*virtualMediaConfigOem, asyncResp->res,
                                         "Masked", masked))
                {
                    return;
                }

                if (masked)
                {
                    service_util::setMasked(
                        asyncResp, getVirtualMediaServiceName(systemName),
                        *masked);
                }
            }
        }
    }
}

inline void handleSystemCollectionResetActionHead(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& /*systemName*/)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/ActionInfo/ActionInfo.json>; rel=describedby");
}

/**
 * @brief Translates allowed host transitions to redfish string
 *
 * @param[in]  dbusAllowedHostTran The allowed host transition on dbus
 * @param[out] allowableValues     The translated host transition(s)
 *
 * @return Emplaces corresponding Redfish translated value(s) in
 * allowableValues. If translation not possible, does nothing to
 * allowableValues.
 */
inline void dbusToRfAllowedHostTransitions(
    const std::string& dbusAllowedHostTran,
    nlohmann::json::array_t& allowableValues)
{
    if (dbusAllowedHostTran == "xyz.openbmc_project.State.Host.Transition.On")
    {
        allowableValues.emplace_back(resource::ResetType::On);
        allowableValues.emplace_back(resource::ResetType::ForceOn);
    }
    else if (dbusAllowedHostTran ==
             "xyz.openbmc_project.State.Host.Transition.Off")
    {
        allowableValues.emplace_back(resource::ResetType::GracefulShutdown);
    }
    else if (dbusAllowedHostTran ==
             "xyz.openbmc_project.State.Host.Transition.GracefulWarmReboot")
    {
        allowableValues.emplace_back(resource::ResetType::GracefulRestart);
    }
    else if (dbusAllowedHostTran ==
             "xyz.openbmc_project.State.Host.Transition.ForceWarmReboot")
    {
        allowableValues.emplace_back(resource::ResetType::ForceRestart);
    }
    else
    {
        BMCWEB_LOG_WARNING("Unsupported host tran {}", dbusAllowedHostTran);
    }
}

inline void afterGetAllowedHostTransitions(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const boost::system::error_code& ec,
    const std::vector<std::string>& allowedHostTransitions)
{
    nlohmann::json::array_t allowableValues;

    // Supported on all systems currently
    allowableValues.emplace_back(resource::ResetType::ForceOff);
    allowableValues.emplace_back(resource::ResetType::PowerCycle);
    allowableValues.emplace_back(resource::ResetType::On);
    allowableValues.emplace_back(resource::ResetType::ForceOn);
    allowableValues.emplace_back(resource::ResetType::ForceRestart);
    allowableValues.emplace_back(resource::ResetType::GracefulRestart);
    allowableValues.emplace_back(resource::ResetType::GracefulShutdown);
    //  allowableValues.emplace_back(resource::ResetType::Nmi);

    if (ec)
    {
        // D-Bus call failed (e.g., AllowedHostTransitions property not
        // available) Log the error but continue with default allowed values
        BMCWEB_LOG_ERROR(
            "bmcweb D-Bus property AllowedHostTransitions not available: {}",
            ec);
    }
    else
    {
        for (const std::string& transition : allowedHostTransitions)
        {
            BMCWEB_LOG_DEBUG("bmcweb Found allowed host tran {}", transition);
            dbusToRfAllowedHostTransitions(transition, allowableValues);
        }
    }

    nlohmann::json::object_t parameter;
    parameter["Name"] = "ResetType";
    parameter["Required"] = true;
    parameter["DataType"] = action_info::ParameterTypes::String;
    parameter["AllowableValues"] = std::move(allowableValues);
    nlohmann::json::array_t parameters;
    parameters.emplace_back(std::move(parameter));
    asyncResp->res.jsonValue["Parameters"] = std::move(parameters);
}

inline void handleSystemCollectionResetActionGet(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& systemName)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if constexpr (BMCWEB_EXPERIMENTAL_REDFISH_MULTI_COMPUTER_SYSTEM)
    {
        // Option currently returns no systems.  TBD
        messages::resourceNotFound(asyncResp->res, "ComputerSystem",
                                   systemName);
        return;
    }

    if constexpr (BMCWEB_HYPERVISOR_COMPUTER_SYSTEM)
    {
        if (systemName == "hypervisor")
        {
            handleHypervisorResetActionGet(asyncResp);
            return;
        }
    }

    if (!system_utils::validateSystemName(asyncResp, systemName))
    {
        return;
    }

    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/ActionInfo/ActionInfo.json>; rel=describedby");

    asyncResp->res.jsonValue["@odata.id"] = boost::urls::format(
        "/redfish/v1/Systems/{}/ResetActionInfo", systemName);
    asyncResp->res.jsonValue["@odata.type"] =
        json_util::odataType("ActionInfo");
    asyncResp->res.jsonValue["Description"] =
        "This action is used to reset the Systems";
    asyncResp->res.jsonValue["Name"] = "Reset Action Info";
    asyncResp->res.jsonValue["Id"] = "ResetActionInfo";

    // Select the appropriate D-Bus service and path based on system name
    std::string hostService = hostStateService;
    std::string hostPath = singleHostPath;

    if (system_utils::isDualHostEnabled())
    {
        // Dual-node system
        if (systemName == "system1")
        {
            // "system1" maps to Host2
            hostService = host2Service;
            hostPath = host2Path;
        }
        else
        {
            // "system" (default) maps to Host1 in dual-node mode
            hostService = host1Service;
            hostPath = host1Path;
        }
    }

    // Look to see if system defines AllowedHostTransitions
    dbus::utility::getProperty<std::vector<std::string>>(
        hostService, hostPath, hostStateInterface, "AllowedHostTransitions",
        [asyncResp](const boost::system::error_code& ec,
                    const std::vector<std::string>& allowedHostTransitions) {
            afterGetAllowedHostTransitions(asyncResp, ec,
                                           allowedHostTransitions);
        });
}

inline void handleComputerSystemPostDelete(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& systemName)
{
    asyncResp->res.clearHeader(boost::beast::http::field::allow);
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (!membersResponseGet(asyncResp, systemName, "ComputerSystemCollection"))
    {
        return;
    }
    if (systemName != "system")
    {
        messages::resourceNotFound(asyncResp->res, "ComputerSystem",
                                   systemName);
        return;
    }
    asyncResp->res.addHeader("Allow", "GET, PATCH");
    messages::operationNotAllowed(asyncResp->res);
    return;
}

/**
 * SystemResetActionInfo derived class for delivering Computer Systems
 * ResetType AllowableValues using ResetInfo schema.
 */
inline void requestRoutesSystems(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Systems/")
        .privileges(redfish::privileges::headComputerSystemCollection)
        .methods(boost::beast::http::verb::head)(
            std::bind_front(handleComputerSystemCollectionHead, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Systems/")
        .privileges(redfish::privileges::getComputerSystemCollection)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleComputerSystemCollectionGet, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/")
        .privileges(redfish::privileges::headComputerSystem)
        .methods(boost::beast::http::verb::head)(
            std::bind_front(handleComputerSystemHead, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/")
        .privileges(redfish::privileges::getComputerSystem)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleComputerSystemGet, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/")
        .privileges(redfish::privileges::patchComputerSystem)
        .methods(boost::beast::http::verb::patch)(
            std::bind_front(handleComputerSystemPatch, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/")
        .privileges(redfish::privileges::getComputerSystem)
        .methods(boost::beast::http::verb::post,
                 boost::beast::http::verb::delete_)(
            std::bind_front(handleComputerSystemPostDelete, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/Actions/ComputerSystem.Reset/")
        .privileges(redfish::privileges::postComputerSystem)
        .methods(boost::beast::http::verb::post)(std::bind_front(
            handleComputerSystemResetActionPost, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/ResetActionInfo/")
        .privileges(redfish::privileges::headActionInfo)
        .methods(boost::beast::http::verb::head)(std::bind_front(
            handleSystemCollectionResetActionHead, std::ref(app)));
    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/ResetActionInfo/")
        .privileges(redfish::privileges::getActionInfo)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleSystemCollectionResetActionGet, std::ref(app)));
}
} // namespace redfish
