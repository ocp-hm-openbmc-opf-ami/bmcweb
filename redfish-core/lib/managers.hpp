// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
// SPDX-FileCopyrightText: Copyright 2018 Intel Corporation
#pragma once

#include "bmcweb_config.h"

#include "app.hpp"
#include "managers_header.hpp"
#include "dbus_utility.hpp"
#include "generated/enums/action_info.hpp"
#include "generated/enums/manager.hpp"
#include "generated/enums/resource.hpp"
#include "query.hpp"
#include "redfish_util.hpp"
#include "registries/privilege_registry.hpp"
#include "update_service.hpp"
#include "utils/dbus_utils.hpp"
#include "utils/json_utils.hpp"
#include "utils/sw_utils.hpp"
#include "utils/systemd_utils.hpp"
#include "utils/time_utils.hpp"

#include <boost/date_time.hpp>
#include <boost/system/error_code.hpp>
#include <boost/url/format.hpp>
#include <sdbusplus/asio/property.hpp>
#include <sdbusplus/unpack_properties.hpp>
#include <task.hpp>
#include <event_service_manager.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <ranges>
#include <sstream>
#include <string>
#include <string_view>
#include <variant>

namespace redfish
{

inline std::string
    getBMCUpdateServiceName()
{
    if constexpr (BMCWEB_REDFISH_UPDATESERVICE_USE_DBUS)
    {
        return "xyz.openbmc_project.Software.Manager";
    }
    return "xyz.openbmc_project.Software.BMC.Updater";
}
inline std::string
    getBMCUpdateServicePath()
{
    if constexpr (BMCWEB_REDFISH_UPDATESERVICE_USE_DBUS)
    {
        return "/xyz/openbmc_project/software/bmc";
    }
    return "/xyz/openbmc_project/software";
}

/**
 * Function reboots the BMC.
 *
 * @param[in] asyncResp - Shared pointer for completing asynchronous calls
 */
constexpr const char* MANAGER_DBUS_PROPERTY_IFACE =
    "org.freedesktop.DBus.Properties";
constexpr const char* consoleDbusService =
    "xyz.openbmc_project.Console.default";
constexpr const char* consoleDbusObject =
    "/xyz/openbmc_project/console/default";
constexpr const char* consoleDbusInterface = "xyz.openbmc_project.Console.UART";

using namespace std;
using managerPropertyValue = std::variant<uint8_t, uint16_t, std::string,
                                          std::vector<std::string>, bool>;
/**
 * Function to create the reboot status task
 *
 * @param[in] asyncResp - Shared pointer for completing asynchronous call
 * @param[in] payload - Double pointer to get the task Data
 */
inline void createTimeOutTask(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                       task::Payload&& payload, uint64_t timeDiff)
{
    BMCWEB_LOG_ERROR("do Task creartion");
    sdbusplus::message::object_path objPath;
    const std::uint64_t* timeOutValue = nullptr;

    std::shared_ptr<task::TaskData> task = task::TaskData::createTask(
	[&timeOutValue](boost::system::error_code ec, sdbusplus::message_t& msg,
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

            if (iface == "xyz.openbmc_project.State.BMC")
            {
                for (const auto& property : values)
                {
                    if (property.first == "TimeOut")
                    {
                        redfish::taskservice::setTaskState("Completed", 
                                        static_cast<size_t>( std::stoi(index)));
                        taskData->messages.emplace_back(
                                        messages::taskCompletedOK(index));
                        taskData->state = "Completed";
                        taskData->timer.cancel();
                        syslog(LOG_INFO, "BMC Reboot Task Completed\r\n");
                        return task::completed;
                    }
                    else
                    {
                        redfish::taskservice::setTaskState("Pending", 
                                    static_cast<size_t>( std::stoi(index)));
                        taskData->state = "Pending";
                        taskData->messages.emplace_back(messages::taskPaused(index));
                        syslog(LOG_INFO, "BMC Reboot Task Pending\r\n");
                        return !task::completed;             
                    }
                }
		        /*if (timeOutValue != nullptr && *timeOutValue != 0)
                {
                        redfish::taskservice::setTaskState("Pending", 
                                    static_cast<size_t>( std::stoi(index)));
                        taskData->state = "Pending";
                        taskData->messages.emplace_back(messages::taskPaused(index));
                        syslog(LOG_INFO, "BMC Reboot Task Pending\r\n");
                        return !task::completed;
                }
                */
            }
            return !task::completed;
        },
        "type='signal',interface='org.freedesktop.DBus.Properties',"
        "member='PropertiesChanged', path='/xyz/openbmc_project/state/bmc0'");
    task->startTimer(std::chrono::minutes(timeDiff));
    syslog(LOG_INFO, "BMC Reboot Task Started %llu \r\n", timeDiff);         
    task->populateResp(asyncResp->res);
    task->payload.emplace(std::move(payload));
}

/**
 * Function get the RequestedBMCTransition Property Value
 *
 * @param[in] servicePath - servicePath of the Property
 * @param[in] objectPath - objectPath of the Property
 * @param[in] interface - interface of the Property
 * @param[in] propertyName - propertyName of the Property
 */
inline const managerPropertyValue getProperty(
    const std::string& servicePath, const std::string& objectPath,
    const std::string& interface, const std::string& propertyName)
{
    managerPropertyValue value{};

    auto b = sdbusplus::bus::new_default_system();
    auto method = b.new_method_call(servicePath.c_str(), objectPath.c_str(),
                                    MANAGER_DBUS_PROPERTY_IFACE, "Get");

    method.append(interface, propertyName);
    auto reply = b.call(method);
    reply.read(value);
    return value;
}

void doBMCGracefulRestart(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    const char* processName = "xyz.openbmc_project.State.BMC";
    const char* objectPath = "/xyz/openbmc_project/state/bmc0";
    const char* interfaceName = "xyz.openbmc_project.State.BMC";
    const std::string& propertyValue =
        "xyz.openbmc_project.State.BMC.Transition.Reboot";
    const char* destProperty = "RequestedBMCTransition";

    // Create the D-Bus variant for D-Bus call.
    dbus::utility::DbusVariantType dbusPropertyValue(propertyValue);

    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code& ec) {
            // Use "Set" method to set the property value.
            if (ec)
            {
                BMCWEB_LOG_DEBUG("[Set] Bad D-Bus request error: {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }
        },
        processName, objectPath, "org.freedesktop.DBus.Properties", "Set",
        interfaceName, destProperty, dbusPropertyValue);
}

inline void
    doBMCForceRestart(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    const char* processName = "xyz.openbmc_project.State.BMC";
    const char* objectPath = "/xyz/openbmc_project/state/bmc0";
    const char* interfaceName = "xyz.openbmc_project.State.BMC";
    const std::string& propertyValue =
        "xyz.openbmc_project.State.BMC.Transition.HardReboot";
    const char* destProperty = "RequestedBMCTransition";

    // Create the D-Bus variant for D-Bus call.
    dbus::utility::DbusVariantType dbusPropertyValue(propertyValue);

    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code& ec) {
            // Use "Set" method to set the property value.
            if (ec)
            {
                BMCWEB_LOG_DEBUG("[Set] Bad D-Bus request error: {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }
        },
        processName, objectPath, "org.freedesktop.DBus.Properties", "Set",
        interfaceName, destProperty, dbusPropertyValue);
}
/**
 * Fun to choose the resetType for the reset action
 *
 * @param[in] asyncResp - Shared pointer for completing asynchronous calls
 * @param[in] resetType - string for completing reboot*/

inline void
    resetOperation(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& resetType)
{
    if (resetType == "GracefulRestart")
    {
        std::string alertMessageId = "Alert:" + resetType;
        EventServiceManager::getInstance().alertSystem(alertMessageId);
        BMCWEB_LOG_ERROR("Proceeding with", resetType);
        doBMCGracefulRestart(asyncResp);
        return;
    }
    if (resetType == "ForceRestart")
    {
        std::string alertMessageId = "Alert:" + resetType;
        EventServiceManager::getInstance().alertSystem(alertMessageId);
        BMCWEB_LOG_ERROR("Proceeding with", resetType);
        doBMCForceRestart(asyncResp);
        return;
    }
    BMCWEB_LOG_ERROR("Invalid property value for ResetType:", resetType);
    messages::actionParameterNotSupported(asyncResp->res, resetType,
                                          "ResetType");

    return;
}

/**
 * Func give the timeout value in seconds
 *
 * @param[in] posixTime_1 - MaintenanceWindowStarTime converted to posixtime
 * @param[in] redfishDateTimeOffset - Current BMC Timezone
 */
inline uint64_t differenceTime(boost::posix_time::ptime posixTime_1,
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

/**
 * Function sets the timeOut value for the BMC Transitin Timer
 *
 * @param[in] asyncResp - Shared pointer for completing asynchronous calls
 * @param[in] timeOut - Timer input in Seconds
 */

inline void setTimer(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                     const uint64_t timeOut)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code ec) {
            if (ec)
            {
                messages::internalError(asyncResp->res);
            }
        },
        "xyz.openbmc_project.State.BMC", "/xyz/openbmc_project/state/bmc0",
        "org.freedesktop.DBus.Properties", "Set",
        "xyz.openbmc_project.State.BMC", "TimeOut",
        dbus::utility::DbusVariantType(timeOut));
}

/**
 * ManagerResetAction class supports the POST method for the Reset (reboot)
 * action.
 */
inline void requestRoutesManagerResetAction(App& app)
{
    /**
     * Function handles POST method request.
     * Analyzes POST body before sending Reset (Reboot) request data to D-Bus.
     * OpenBMC supports ResetType "GracefulRestart" and "ForceRestart".
     */

    BMCWEB_ROUTE(app, "/redfish/v1/Managers/<str>/Actions/Manager.Reset/")
        .privileges(redfish::privileges::postManager)
        .methods(
            boost::beast::http::verb::
                post)([&app](
                          const crow::Request& req,
                          const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                          const std::string& managerId) {
            if (!redfish::setUpRedfishRoute(app, req, asyncResp))
            {
                return;
            }
            if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
            {
                messages::resourceNotFound(asyncResp->res, "Manager",
                                           managerId);
                return;
            }

            BMCWEB_LOG_ERROR("Post Manager Reset.");

            std::string servicePath = "xyz.openbmc_project.State.BMC";
            std::string interface = "xyz.openbmc_project.State.BMC";
            std::string objectPath = "/xyz/openbmc_project/state/bmc0";
            std::string propName = "RequestedBMCTransition";

            std::string resetType;
            std::optional<std::string> operationApplyTime;
            std::optional<std::string> maintenanceWindowStartTime;
            std::string startTime;

            // Current BMC Timezone
            std::string redfishDateTimeOffset =
                redfish::time_utils::getDateTimeOffsetNow().first;

            task::Payload payload(req);

            if (!json_util::readJsonAction(                                  //
                    req, asyncResp->res,                                     //
                    "ResetType", resetType,                                  //
                    "OperationApplyTime", operationApplyTime,                //
                    "MaintenanceWindowStartTime", maintenanceWindowStartTime //
                    ))
            {
                return;
            }

            // To provide as a stringstream object
            startTime = *maintenanceWindowStartTime;

            auto value =
                getProperty(servicePath, objectPath, interface, propName);
            /*auto requestedBMCTransition = std::get<std::string>(value);
            if (requestedBMCTransition !=
                "xyz.openbmc_project.State.BMC.Transition.None")
            {
                BMCWEB_LOG_ERROR("Already One Reboot Task is running");
                messages::resourceInUse(asyncResp->res);
                return;
            }*/ //commented to avoid 503 server error

            if ((resetType == "GracefulRestart" ||
                 resetType == "ForceRestart") &&
                !operationApplyTime && !maintenanceWindowStartTime)
            {
		setTimer(asyncResp, 0);
                resetOperation(asyncResp, resetType);
                messages::success(asyncResp->res);
                return;
            }

            if (operationApplyTime == "Immediate")
            {
                BMCWEB_LOG_ERROR(" Reboot Immediately");
                if (!(maintenanceWindowStartTime))
                {
                    resetOperation(asyncResp, resetType);
                    createTimeOutTask(asyncResp, std::move(payload), 1);
                    std::string index = asyncResp->res.jsonValue["Id"];
                    redfish::taskservice::setTaskState("Completed", 
                                    static_cast<size_t>(std::stoi(index)));
                    syslog(LOG_INFO, "BMC Immediate Reboot Task Completed\r\n");
                    
                    return;
                }

                else
                {
                    BMCWEB_LOG_ERROR("Invalid Property for Immediate reboot");
                    messages::actionParameterNotSupported(
                        asyncResp->res, "MaintenanceWindowStartTime",
                        "Immediate");
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
                            "maintenanceWindowStartTime is less than the BMCTime");
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
                    uint64_t timeOut =
                        differenceTime(posixTime_1, redfishDateTimeOffset);

                    setTimer(asyncResp, timeOut);
	            createTimeOutTask(asyncResp, std::move(payload),timeOut);
		    resetOperation(asyncResp, resetType);
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
        });
}

inline void handleFactoryDefaultGet(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& managerId)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
    {
        messages::resourceNotFound(asyncResp->res, "Manager", managerId);
        return;
    }

    asyncResp->res.jsonValue["@odata.type"] = json_util::odataType("AMIResetToDefaults");
    asyncResp->res.jsonValue["@odata.id"] = boost::urls::format("/redfish/v1/Managers/{}/Oem/Ami/ResetToDefaults",BMCWEB_REDFISH_MANAGER_URI_NAME);
    asyncResp->res.jsonValue["Name"]="AMI ResetToDefaults";
    asyncResp->res.jsonValue["Id"]="AMIResetToDefaults";
    redfish::getPreserveConfig(asyncResp, "Managers");
}
inline void requestRoutesManagerResetToDefaults(App& app)
{
    /**
     * Function handles ResetToDefaults POST method request.
     *
     * Analyzes POST body message and factory resets BMC by calling
     * BMC code updater factory reset followed by a BMC reboot.
     *
     * BMC code updater factory reset wipes the whole BMC read-write
     * filesystem which includes things like the network settings.
     *
     * OpenBMC only supports ResetToDefaultsType "ResetAll".
     */

    BMCWEB_ROUTE(app, "/redfish/v1/Managers/<str>/Actions/Manager.ResetToDefaults/")
        .privileges(redfish::privileges::postManager)
        .methods(boost::beast::http::verb::post)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& managerId) {
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }
                if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
                {
                    messages::resourceNotFound(asyncResp->res, "Manager",
                                               managerId);
                    return;
                }
                std::string resetType;

                if (!json_util::readJsonAction(
                    req, asyncResp->res,
                    "ResetType", resetType
                    ))
                {
                    return;
                }

                if(resetType != "ResetAll")
                {
                    messages::actionParameterNotSupported(asyncResp->res, resetType,
                                              "ResetType");
                    return;

                }
                for (const std::shared_ptr<task::TaskData>& task : task::tasks)
                {
                    if (task == nullptr)
                    {
                        continue; // shouldn't be possible
                    }
                    if (task->state == "Pending")
                    {
                        messages::factoryDefaultResetActionConflict(
                            asyncResp->res, "FactoryDefaultReset",
                            "FirmwareUpdate");
                        return;
                    }
                }
                crow::connections::systemBus->async_method_call(
                    [asyncResp](const boost::system::error_code& ec) {
                        if (ec)
                        {
                            BMCWEB_LOG_DEBUG("Failed to ResetToDefaults: {}",
                                             ec);
                            messages::internalError(asyncResp->res);
                            return;
                        }
                        // Factory Reset doesn't actually happen until a reboot
                        // Can't erase what the BMC is running on
                        doBMCGracefulRestart(asyncResp);
                        messages::success(asyncResp->res);
                    },
                    "xyz.openbmc_project.Software.BMC.Updater",
                    "/xyz/openbmc_project/software",
                    "xyz.openbmc_project.Common.FactoryReset", "Reset");
            });
}

/**
 * ManagerResetActionInfo derived class for delivering Manager
 * ResetType AllowableValues using ResetInfo schema.
 */
inline void
    requestRoutesManagerResetActionInfo(App& app)
{
    /**
     * Functions triggers appropriate requests on DBus
     */

    BMCWEB_ROUTE(app, "/redfish/v1/Managers/<str>/ResetActionInfo/")
        .privileges(redfish::privileges::getActionInfo)
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& managerId) {
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }

                if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
                {
                    messages::resourceNotFound(asyncResp->res, "Manager",
                                               managerId);
                    return;
                }

                asyncResp->res.jsonValue["@odata.type"] = json_util::odataType("ActionInfo");
                asyncResp->res.jsonValue["@odata.id"] = boost::urls::format(
                    "/redfish/v1/Managers/{}/ResetActionInfo",
                    BMCWEB_REDFISH_MANAGER_URI_NAME);
                asyncResp->res.jsonValue["Name"] = "Reset Action Info";
                asyncResp->res.jsonValue["Id"] = "ResetActionInfo";
                nlohmann::json::object_t parameter;
                parameter["Name"] = "ResetType";
                parameter["Required"] = true;
                parameter["DataType"] = action_info::ParameterTypes::String;

                nlohmann::json::array_t allowableValues;
                allowableValues.emplace_back("GracefulRestart");
                allowableValues.emplace_back("ForceRestart");
                parameter["AllowableValues"] = std::move(allowableValues);

                nlohmann::json::array_t parameters;
                parameters.emplace_back(std::move(parameter));

                asyncResp->res.jsonValue["Parameters"] = std::move(parameters);
            });
    BMCWEB_ROUTE(app, "/redfish/v1/Managers/<str>/ResetToDefaultsActionInfo/")
        .privileges(redfish::privileges::getActionInfo)
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& managerId) {
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }

                if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
                {
                    messages::resourceNotFound(asyncResp->res, "Manager",
                                               managerId);
                    return;
                }

                asyncResp->res.jsonValue["@odata.type"] = json_util::odataType("ActionInfo");
                asyncResp->res.jsonValue["@odata.id"] = boost::urls::format(
                    "/redfish/v1/Managers/{}/ResetToDefaultsActionInfo",
                    BMCWEB_REDFISH_MANAGER_URI_NAME);
                asyncResp->res.jsonValue["Name"] = "ResetToDefaults Action Info";
                asyncResp->res.jsonValue["Id"] = "ResetToDefaultsActionInfo";
                nlohmann::json::object_t parameter;
                parameter["Name"] = "ResetType";
                parameter["Required"] = true;
                parameter["DataType"] = action_info::ParameterTypes::String;

                nlohmann::json::array_t allowableValues;
                allowableValues.emplace_back("ResetAll");
                parameter["AllowableValues"] = std::move(allowableValues);

                nlohmann::json::array_t parameters;
                parameters.emplace_back(std::move(parameter));

                asyncResp->res.jsonValue["Parameters"] = std::move(parameters);
            });
}

static constexpr const char* objectManagerIface =
    "org.freedesktop.DBus.ObjectManager";
static constexpr const char* pidConfigurationIface =
    "xyz.openbmc_project.Configuration.Pid";
static constexpr const char* pidZoneConfigurationIface =
    "xyz.openbmc_project.Configuration.Pid.Zone";
static constexpr const char* stepwiseConfigurationIface =
    "xyz.openbmc_project.Configuration.Stepwise";
static constexpr const char* thermalModeIface =
    "xyz.openbmc_project.Control.ThermalMode";

static constexpr const char* sshConsoleConfigurationIface =
    "xyz.openbmc_project.Configuration.SSHConsoleService";
static constexpr const char* obmcConsoleLogFilePrefix = "obmc-console";
static constexpr const char* obmcConsoleLogFileRotatedSuffix = ".1";

inline void asyncPopulatePid(
    const std::string& connection, const std::string& path,
    const std::string& currentProfile,
    const std::vector<std::string>& supportedProfiles,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    sdbusplus::message::object_path objPath(path);
    dbus::utility::getManagedObjects(
        connection, objPath,
        [asyncResp, currentProfile, supportedProfiles](
            const boost::system::error_code& ec,
            const dbus::utility::ManagedObjectType& managedObj) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("{}", ec);
                messages::internalError(asyncResp->res);
                return;
            }
            nlohmann::json& configRoot =
                asyncResp->res.jsonValue["Oem"]["OpenBmc"]["Fan"];
            nlohmann::json& fans = configRoot["FanControllers"];
            fans["@odata.type"] = json_util::odataType("OpenBMCManager", "Manager", "FanControllers");
            fans["@odata.id"] = boost::urls::format(
                "/redfish/v1/Managers/{}#/Oem/OpenBmc/Fan/FanControllers",
                BMCWEB_REDFISH_MANAGER_URI_NAME);

            nlohmann::json& pids = configRoot["PidControllers"];
            pids["@odata.type"] = json_util::odataType("OpenBMCManager", "Manager", "PidControllers");
            pids["@odata.id"] = boost::urls::format(
                "/redfish/v1/Managers/{}#/Oem/OpenBmc/Fan/PidControllers",
                BMCWEB_REDFISH_MANAGER_URI_NAME);

            nlohmann::json& stepwise = configRoot["StepwiseControllers"];
            stepwise["@odata.type"] = json_util::odataType("OpenBMCManager", "Manager", "StepwiseControllers");
            stepwise["@odata.id"] = boost::urls::format(
                "/redfish/v1/Managers/{}#/Oem/OpenBmc/Fan/StepwiseControllers",
                BMCWEB_REDFISH_MANAGER_URI_NAME);

            nlohmann::json& zones = configRoot["FanZones"];
            zones["@odata.id"] = boost::urls::format(
                "/redfish/v1/Managers/{}#/Oem/OpenBmc/Fan/FanZones",
                BMCWEB_REDFISH_MANAGER_URI_NAME);
            zones["@odata.type"] = json_util::odataType("OpenBMCManager", "Manager", "FanZones");
            configRoot["@odata.id"] =
                boost::urls::format("/redfish/v1/Managers/{}#/Oem/OpenBmc/Fan",
                                    BMCWEB_REDFISH_MANAGER_URI_NAME);
            configRoot["@odata.type"] = json_util::odataType("OpenBMCManager", "Manager", "Fan");
            configRoot["Profile@Redfish.AllowableValues"] = supportedProfiles;

            if (!currentProfile.empty())
            {
                configRoot["Profile"] = currentProfile;
            }
            BMCWEB_LOG_DEBUG("profile = {} !", currentProfile);

            for (const auto& pathPair : managedObj)
            {
                for (const auto& intfPair : pathPair.second)
                {
                    if (intfPair.first != pidConfigurationIface &&
                        intfPair.first != pidZoneConfigurationIface &&
                        intfPair.first != stepwiseConfigurationIface)
                    {
                        continue;
                    }

                    std::string name;

                    for (const std::pair<std::string,
                                         dbus::utility::DbusVariantType>&
                             propPair : intfPair.second)
                    {
                        if (propPair.first == "Name")
                        {
                            const std::string* namePtr =
                                std::get_if<std::string>(&propPair.second);
                            if (namePtr == nullptr)
                            {
                                BMCWEB_LOG_ERROR("Pid Name Field illegal");
                                messages::internalError(asyncResp->res);
                                return;
                            }
                            name = *namePtr;
                            dbus::utility::escapePathForDbus(name);
                        }
                        else if (propPair.first == "Profiles")
                        {
                            const std::vector<std::string>* profiles =
                                std::get_if<std::vector<std::string>>(
                                    &propPair.second);
                            if (profiles == nullptr)
                            {
                                BMCWEB_LOG_ERROR("Pid Profiles Field illegal");
                                messages::internalError(asyncResp->res);
                                return;
                            }
                            if (std::find(profiles->begin(), profiles->end(),
                                          currentProfile) == profiles->end())
                            {
                                BMCWEB_LOG_INFO(
                                    "{} not supported in current profile",
                                    name);
                                continue;
                            }
                        }
                    }
                    nlohmann::json* config = nullptr;
                    const std::string* classPtr = nullptr;

                    for (const std::pair<std::string,
                                         dbus::utility::DbusVariantType>&
                             propPair : intfPair.second)
                    {
                        if (propPair.first == "Class")
                        {
                            classPtr =
                                std::get_if<std::string>(&propPair.second);
                        }
                    }

                    boost::urls::url url(
                        boost::urls::format("/redfish/v1/Managers/{}",
                                            BMCWEB_REDFISH_MANAGER_URI_NAME));
                    if (intfPair.first == pidZoneConfigurationIface)
                    {
                        std::string chassis;
                        if (!dbus::utility::getNthStringFromPath(
                                pathPair.first.str, 5, chassis))
                        {
                            chassis = "#IllegalValue";
                        }
                        nlohmann::json& zone = zones[name];
                        if (name.find("PSU") == std::string::npos)
                        {
                            constexpr std::array<std::string_view, 1> interfaces{
                                "xyz.openbmc_project.Inventory.Item.Board"};
                            dbus::utility::getSubTreePaths(
                                "/xyz/openbmc_project/inventory", 0, interfaces,
                                [asyncResp, name](const boost::system::error_code& ec,  // Capture name instead
                            const dbus::utility::MapperGetSubTreePathsResponse& chassisList) {
                            if (ec)
                            {
                                BMCWEB_LOG_ERROR("Chassis Name not found - {}", ec);
                                return;
                            }
                            for (const std::string& chassisPath : chassisList)
                            {
                                if(chassisPath.find_last_of('/') != std::string::npos)
                                {
                                    std::string chassisName = chassisPath.substr(chassisPath.find_last_of('/') + 1);
                                    if (chassisName != "Cpld")
                                    {
                                        asyncResp->res.jsonValue["Oem"]["OpenBmc"]["Fan"]["FanZones"][name]["Chassis"]["@odata.id"] =
                                            boost::urls::format("/redfish/v1/Chassis/{}", chassisName);
                                        return;
                                    }
                                }
                            }
                            });
                        }
                        url.set_fragment(
                            ("/Oem/OpenBmc/Fan/FanZones"_json_pointer / name)
                                .to_string());
                        zone["@odata.id"] = std::move(url);
                        zone["@odata.type"] = json_util::odataType("OpenBMCManager", "FanZone");
                        config = &zone;
                    }

                    else if (intfPair.first == stepwiseConfigurationIface)
                    {
                        if (classPtr == nullptr)
                        {
                            BMCWEB_LOG_ERROR("Pid Class Field illegal");
                            messages::internalError(asyncResp->res);
                            return;
                        }

                        nlohmann::json& controller = stepwise[name];
                        config = &controller;
                        url.set_fragment(
                            ("/Oem/OpenBmc/Fan/StepwiseControllers"_json_pointer /
                             name)
                                .to_string());
                        controller["@odata.id"] = std::move(url);
                        controller["@odata.type"] = json_util::odataType("OpenBMCManager", "Manager", "StepwiseController");

                        controller["Direction"] = *classPtr;
                    }

                    // pid and fans are off the same configuration
                    else if (intfPair.first == pidConfigurationIface)
                    {
                        if (classPtr == nullptr)
                        {
                            BMCWEB_LOG_ERROR("Pid Class Field illegal");
                            messages::internalError(asyncResp->res);
                            return;
                        }
                        bool isFan = *classPtr == "fan";
                        nlohmann::json& element =
                            isFan ? fans[name] : pids[name];
                        config = &element;
                        if (isFan)
                        {
                            url.set_fragment(
                                ("/Oem/OpenBmc/Fan/FanControllers"_json_pointer /
                                 name)
                                    .to_string());
                            element["@odata.id"] = std::move(url);
                            element["@odata.type"] = json_util::odataType("OpenBMCManager", "Manager", "FanController");
                        }
                        else
                        {
                            url.set_fragment(
                                ("/Oem/OpenBmc/Fan/PidControllers"_json_pointer /
                                 name)
                                    .to_string());
                            element["@odata.id"] = std::move(url);
                            element["@odata.type"] = json_util::odataType("OpenBMCManager", "Manager", "PidController");
                        }
                    }
                    else
                    {
                        BMCWEB_LOG_ERROR("Unexpected configuration");
                        messages::internalError(asyncResp->res);
                        return;
                    }

                    // used for making maps out of 2 vectors
                    const std::vector<double>* keys = nullptr;
                    const std::vector<double>* values = nullptr;

                    for (const auto& propertyPair : intfPair.second)
                    {
                        if (propertyPair.first == "Type" ||
                            propertyPair.first == "Class" ||
                            propertyPair.first == "Name" ||
                            propertyPair.first == "AccumulateSetPoint")
                        {
                            continue;
                        }

                        // zones
                        if (intfPair.first == pidZoneConfigurationIface)
                        {
                            const double* ptr =
                                std::get_if<double>(&propertyPair.second);
                            if (ptr == nullptr)
                            {
                                BMCWEB_LOG_ERROR("Field Illegal {}",
                                                 propertyPair.first);
                                messages::internalError(asyncResp->res);
                                return;
                            }
                            (*config)[propertyPair.first] = *ptr;
                        }

                        if (intfPair.first == stepwiseConfigurationIface)
                        {
                            if (propertyPair.first == "Reading" ||
                                propertyPair.first == "Output")
                            {
                                const std::vector<double>* ptr =
                                    std::get_if<std::vector<double>>(
                                        &propertyPair.second);

                                if (ptr == nullptr)
                                {
                                    BMCWEB_LOG_ERROR("Field Illegal {}",
                                                     propertyPair.first);
                                    messages::internalError(asyncResp->res);
                                    return;
                                }

                                if (propertyPair.first == "Reading")
                                {
                                    keys = ptr;
                                }
                                else
                                {
                                    values = ptr;
                                }
                                if (keys != nullptr && values != nullptr)
                                {
                                    if (keys->size() != values->size())
                                    {
                                        BMCWEB_LOG_ERROR(
                                            "Reading and Output size don't match ");
                                        messages::internalError(asyncResp->res);
                                        return;
                                    }
                                    nlohmann::json& steps = (*config)["Steps"];
                                    steps = nlohmann::json::array();
                                    for (size_t ii = 0; ii < keys->size(); ii++)
                                    {
                                        nlohmann::json::object_t step;
                                        step["Target"] = (*keys)[ii];
                                        step["Output"] = (*values)[ii];
                                        steps.emplace_back(std::move(step));
                                    }
                                }
                            }
                            if (propertyPair.first == "NegativeHysteresis" ||
                                propertyPair.first == "PositiveHysteresis")
                            {
                                const double* ptr =
                                    std::get_if<double>(&propertyPair.second);
                                if (ptr == nullptr)
                                {
                                    BMCWEB_LOG_ERROR("Field Illegal {}",
                                                     propertyPair.first);
                                    messages::internalError(asyncResp->res);
                                    return;
                                }
                                (*config)[propertyPair.first] = *ptr;
                            }
                        }

                        // pid and fans are off the same configuration
                        if (intfPair.first == pidConfigurationIface ||
                            intfPair.first == stepwiseConfigurationIface)
                            {
                            if (propertyPair.first == "Zones")
                            {
                                const std::vector<std::string>* inputs =
                                    std::get_if<std::vector<std::string>>(
                                        &propertyPair.second);

                                if (inputs == nullptr)
                                {
                                    BMCWEB_LOG_ERROR("Zones Pid Field Illegal");
                                    messages::internalError(asyncResp->res);
                                    return;
                                }
                                auto& data = (*config)[propertyPair.first];
                                data = nlohmann::json::array();
                                for (std::string itemCopy : *inputs)
                                {
                                    dbus::utility::escapePathForDbus(itemCopy);
                                    nlohmann::json::object_t input;
                                    boost::urls::url managerUrl =
                                        boost::urls::format(
                                            "/redfish/v1/Managers/{}#{}",
                                            BMCWEB_REDFISH_MANAGER_URI_NAME,
                                            ("/Oem/OpenBmc/Fan/FanZones"_json_pointer /
                                             itemCopy)
                                                .to_string());
                                    input["@odata.id"] = std::move(managerUrl);
                                    input["@odata.type"] = json_util::odataType("OpenBMCManager", "FanZone");
                                    data.emplace_back(std::move(input));
                                }
                            }
                            // todo(james): may never happen, but this
                            // assumes configuration data referenced in the
                            // PID config is provided by the same daemon, we
                            // could add another loop to cover all cases,
                            // but I'm okay kicking this can down the road a
                            // bit

                            else if (propertyPair.first == "Inputs" ||
                                     propertyPair.first == "Outputs")
                            {
                                auto& data = (*config)[propertyPair.first];
                                const std::vector<std::string>* inputs =
                                    std::get_if<std::vector<std::string>>(
                                        &propertyPair.second);

                                if (inputs == nullptr)
                                {
                                    BMCWEB_LOG_ERROR("Field Illegal {}",
                                                     propertyPair.first);
                                    messages::internalError(asyncResp->res);
                                    return;
                                }
                                data = *inputs;
                            }
                            else if (propertyPair.first == "SetPointOffset")
                            {
                                const std::string* ptr =
                                    std::get_if<std::string>(
                                        &propertyPair.second);

                                if (ptr == nullptr)
                                {
                                    BMCWEB_LOG_ERROR("Field Illegal {}",
                                                     propertyPair.first);
                                    messages::internalError(asyncResp->res);
                                    return;
                                }
                                // translate from dbus to redfish
                                if (*ptr == "WarningHigh")
                                {
                                    (*config)["SetPointOffset"] =
                                        "UpperThresholdNonCritical";
                                }
                                else if (*ptr == "WarningLow")
                                {
                                    (*config)["SetPointOffset"] =
                                        "LowerThresholdNonCritical";
                                }
                                else if (*ptr == "CriticalHigh")
                                {
                                    (*config)["SetPointOffset"] =
                                        "UpperThresholdCritical";
                                }
                                else if (*ptr == "CriticalLow")
                                {
                                    (*config)["SetPointOffset"] =
                                        "LowerThresholdCritical";
                                }
                                else
                                {
                                    BMCWEB_LOG_ERROR("Value Illegal {}", *ptr);
                                    messages::internalError(asyncResp->res);
                                    return;
                                }
                            }
                            // doubles
                            else if (propertyPair.first ==
                                         "FFGainCoefficient" ||
                                     propertyPair.first == "FFOffCoefficient" ||
                                     propertyPair.first == "ICoefficient" ||
                                     propertyPair.first == "ILimitMax" ||
                                     propertyPair.first == "ILimitMin" ||
                                     propertyPair.first ==
                                         "PositiveHysteresis" ||
                                     propertyPair.first ==
                                         "NegativeHysteresis" ||
                                     propertyPair.first == "OutLimitMax" ||
                                     propertyPair.first == "OutLimitMin" ||
                                     propertyPair.first == "PCoefficient" ||
                                     propertyPair.first == "SetPoint" ||
                                     propertyPair.first == "SlewNeg" ||
                                     propertyPair.first == "SlewPos")
                            {
                                const double* ptr =
                                    std::get_if<double>(&propertyPair.second);
                                if (ptr == nullptr)
                                {
                                    BMCWEB_LOG_ERROR("Field Illegal {}",
                                                     propertyPair.first);
                                    messages::internalError(asyncResp->res);
                                    return;
                                }
                                (*config)[propertyPair.first] = *ptr;
                            }
                        }
                    }
                }
            }
        });
}

enum class CreatePIDRet
{
    fail,
    del,
    patch
};

inline bool
    getZonesFromJsonReq(const std::shared_ptr<bmcweb::AsyncResp>& response,
                        std::vector<nlohmann::json::object_t>& config,
                        std::vector<std::string>& zones)
{
    if (config.empty())
    {
        BMCWEB_LOG_ERROR("Empty Zones");
        messages::propertyValueFormatError(response->res, config, "Zones");
        return false;
    }
    for (auto& odata : config)
    {
        std::string path;
        if (!redfish::json_util::readJsonObject( //
                odata, response->res,            //
                "@odata.id", path                //
                ))
        {
            return false;
        }
        std::string input;

        // 8 below comes from
        // /redfish/v1/Managers/bmc#/Oem/OpenBmc/Fan/FanZones/Left
        //     0    1     2      3    4    5      6     7      8
        if (!dbus::utility::getNthStringFromPath(path, 8, input))
        {
            BMCWEB_LOG_ERROR("Got invalid path {}", path);
            BMCWEB_LOG_ERROR("Illegal Type Zones");
            messages::propertyValueFormatError(response->res, odata, "Zones");
            return false;
        }
        std::replace(input.begin(), input.end(), '_', ' ');
        zones.emplace_back(std::move(input));
    }
    return true;
}

inline const dbus::utility::ManagedObjectType::value_type*
    findChassis(const dbus::utility::ManagedObjectType& managedObj,
                std::string_view value, std::string& chassis)
{
    BMCWEB_LOG_DEBUG("Find Chassis: {}", value);

    std::string escaped(value);
    std::replace(escaped.begin(), escaped.end(), ' ', '_');
    escaped = "/" + escaped;
    auto it = std::ranges::find_if(managedObj, [&escaped](const auto& obj) {
        if (obj.first.str.ends_with(escaped))
        {
            BMCWEB_LOG_DEBUG("Matched {}", obj.first.str);
            return true;
        }
        return false;
    });

    if (it == managedObj.end())
    {
        return nullptr;
    }
    // 5 comes from <chassis-name> being the 5th element
    // /xyz/openbmc_project/inventory/system/chassis/<chassis-name>
    if (dbus::utility::getNthStringFromPath(it->first.str, 5, chassis))
    {
        return &(*it);
    }

    return nullptr;
}

inline CreatePIDRet
    createPidInterface(const std::shared_ptr<bmcweb::AsyncResp>& response,
                       const std::string& type, std::string_view name,
                       nlohmann::json& jsonValue, const std::string& path,
                       const dbus::utility::ManagedObjectType& managedObj,
                       bool createNewObject,
                       dbus::utility::DBusPropertiesMap& output,
                       std::string& chassis, const std::string& profile)
{
    // common deleter
    if (jsonValue == nullptr)
    {
        std::string iface;
        if (type == "PidControllers" || type == "FanControllers")
        {
            iface = pidConfigurationIface;
        }
        else if (type == "FanZones")
        {
            iface = pidZoneConfigurationIface;
        }
        else if (type == "StepwiseControllers")
        {
            iface = stepwiseConfigurationIface;
        }
        else
        {
            BMCWEB_LOG_ERROR("Illegal Type {}", type);
            messages::propertyUnknown(response->res, type);
            return CreatePIDRet::fail;
        }

        BMCWEB_LOG_DEBUG("del {} {}", path, iface);
        // delete interface
        crow::connections::systemBus->async_method_call(
            [response, path](const boost::system::error_code& ec) {
                if (ec)
                {
                    BMCWEB_LOG_ERROR("Error patching {}: {}", path, ec);
                    messages::internalError(response->res);
                    return;
                }
                messages::success(response->res);
            },
            "xyz.openbmc_project.EntityManager", path, iface, "Delete");
        return CreatePIDRet::del;
    }

    const dbus::utility::ManagedObjectType::value_type* managedItem = nullptr;
    if (!createNewObject)
    {
        // if we aren't creating a new object, we should be able to find it on
        // d-bus
        managedItem = findChassis(managedObj, name, chassis);
        if (managedItem == nullptr)
        {
            BMCWEB_LOG_ERROR("Failed to get chassis from config patch");
            messages::invalidObject(
                response->res,
                boost::urls::format("/redfish/v1/Chassis/{}", chassis));
            return CreatePIDRet::fail;
        }
    }

    if (!profile.empty() &&
        (type == "PidControllers" || type == "FanControllers" ||
         type == "StepwiseControllers"))
    {
        if (managedItem == nullptr)
        {
            output.emplace_back("Profiles", std::vector<std::string>{profile});
        }
        else
        {
            std::string interface;
            if (type == "StepwiseControllers")
            {
                interface = stepwiseConfigurationIface;
            }
            else
            {
                interface = pidConfigurationIface;
            }
            bool ifaceFound = false;
            for (const auto& iface : managedItem->second)
            {
                if (iface.first == interface)
                {
                    ifaceFound = true;
                    for (const auto& prop : iface.second)
                    {
                        if (prop.first == "Profiles")
                        {
                            const std::vector<std::string>* curProfiles =
                                std::get_if<std::vector<std::string>>(
                                    &(prop.second));
                            if (curProfiles == nullptr)
                            {
                                BMCWEB_LOG_ERROR(
                                    "Illegal profiles in managed object");
                                messages::internalError(response->res);
                                return CreatePIDRet::fail;
                            }
                            if (std::find(curProfiles->begin(),
                                          curProfiles->end(), profile) ==
                                curProfiles->end())
                            {
                                std::vector<std::string> newProfiles =
                                    *curProfiles;
                                newProfiles.push_back(profile);
                                output.emplace_back("Profiles", newProfiles);
                            }
                        }
                    }
                }
            }

            if (!ifaceFound)
            {
                BMCWEB_LOG_ERROR("Failed to find interface in managed object");
                messages::internalError(response->res);
                return CreatePIDRet::fail;
            }
        }
    }

    if (type == "PidControllers" || type == "FanControllers")
    {
        if (createNewObject)
        {
            output.emplace_back("Class",
                                type == "PidControllers" ? "temp" : "fan");
            output.emplace_back("Type", "Pid");
        }

        std::optional<std::vector<nlohmann::json::object_t>> zones;
        std::optional<std::vector<std::string>> inputs;
        std::optional<std::vector<std::string>> outputs;
        std::map<std::string, std::optional<double>> doubles;
        std::optional<std::string> setpointOffset;
        if (!redfish::json_util::readJson(
                jsonValue, response->res, //
                "Inputs", inputs, //
                "Outputs", outputs, //
                "Zones", zones, //
                "FFGainCoefficient", doubles["FFGainCoefficient"], //
                "FFOffCoefficient", doubles["FFOffCoefficient"], //
                "ICoefficient", doubles["ICoefficient"], //
                "ILimitMax", doubles["ILimitMax"], //
                "ILimitMin", doubles["ILimitMin"], //
                "OutLimitMax", doubles["OutLimitMax"], //
                "OutLimitMin", doubles["OutLimitMin"], //
                "PCoefficient", doubles["PCoefficient"], //
                "SetPoint", doubles["SetPoint"], //
                "SetPointOffset", setpointOffset, //
                "SlewNeg", doubles["SlewNeg"], //
                "SlewPos", doubles["SlewPos"], //
                "PositiveHysteresis", doubles["PositiveHysteresis"], //
                "NegativeHysteresis", doubles["NegativeHysteresis"] //
                ))
        {
            return CreatePIDRet::fail;
        }
        if (zones)
        {
            std::vector<std::string> zonesStr;
            if (!getZonesFromJsonReq(response, *zones, zonesStr))
            {
                BMCWEB_LOG_ERROR("Illegal Zones");
                return CreatePIDRet::fail;
            }
            if (chassis.empty() &&
                findChassis(managedObj, zonesStr[0], chassis) == nullptr)
            {
                BMCWEB_LOG_ERROR("Failed to get chassis from config patch");
                messages::invalidObject(
                    response->res,
                    boost::urls::format("/redfish/v1/Chassis/{}", chassis));
                return CreatePIDRet::fail;
            }
            output.emplace_back("Zones", std::move(zonesStr));
        }

        if (inputs)
        {
            for (std::string& value : *inputs)
            {
                std::replace(value.begin(), value.end(), '_', ' ');
            }
            output.emplace_back("Inputs", *inputs);
        }

        if (outputs)
        {
            for (std::string& value : *outputs)
            {
                std::replace(value.begin(), value.end(), '_', ' ');
            }
            output.emplace_back("Outputs", *outputs);
        }

        if (setpointOffset)
        {
            // translate between redfish and dbus names
            if (*setpointOffset == "UpperThresholdNonCritical")
            {
                output.emplace_back("SetPointOffset", "WarningLow");
            }
            else if (*setpointOffset == "LowerThresholdNonCritical")
            {
                output.emplace_back("SetPointOffset", "WarningHigh");
            }
            else if (*setpointOffset == "LowerThresholdCritical")
            {
                output.emplace_back("SetPointOffset", "CriticalLow");
            }
            else if (*setpointOffset == "UpperThresholdCritical")
            {
                output.emplace_back("SetPointOffset", "CriticalHigh");
            }
            else
            {
                BMCWEB_LOG_ERROR("Invalid setpointoffset {}", *setpointOffset);
                messages::propertyValueNotInList(response->res, name,
                                                 "SetPointOffset");
                return CreatePIDRet::fail;
            }
        }

        // doubles
        for (const auto& pairs : doubles)
        {
            if (!pairs.second)
            {
                continue;
            }
            BMCWEB_LOG_DEBUG("{} = {}", pairs.first, *pairs.second);
            output.emplace_back(pairs.first, *pairs.second);
        }
    }

    else if (type == "FanZones")
    {
        output.emplace_back("Type", "Pid.Zone");

        std::optional<std::string> chassisId;
        std::optional<double> failSafePercent;
        std::optional<double> minThermalOutput;
        if (!redfish::json_util::readJson(           //
                jsonValue, response->res,            //
                "Chassis/@odata.id", chassisId,      //
                "FailSafePercent", failSafePercent,  //
                "MinThermalOutput", minThermalOutput //
                ))
        {
            return CreatePIDRet::fail;
        }

        if (chassisId)
        {
            // /redfish/v1/chassis/chassis_name/
            if (!dbus::utility::getNthStringFromPath(*chassisId, 3, chassis))
            {
                BMCWEB_LOG_ERROR("Got invalid path {}", *chassisId);
                messages::invalidObject(
                    response->res,
                    boost::urls::format("/redfish/v1/Chassis/{}", *chassisId));
                return CreatePIDRet::fail;
            }
        }
        if (minThermalOutput)
        {
            output.emplace_back("MinThermalOutput", *minThermalOutput);
        }
        if (failSafePercent)
        {
            output.emplace_back("FailSafePercent", *failSafePercent);
        }
    }
    else if (type == "StepwiseControllers")
    {
        output.emplace_back("Type", "Stepwise");

        std::optional<std::vector<nlohmann::json::object_t>> zones;
        std::optional<std::vector<nlohmann::json::object_t>> steps;
        std::optional<std::vector<std::string>> inputs;
        std::optional<double> positiveHysteresis;
        std::optional<double> negativeHysteresis;
        std::optional<std::string> direction; // upper clipping curve vs lower
        if (!redfish::json_util::readJson(    //
                jsonValue, response->res,     //
                "Zones", zones,               //
                "Steps", steps,               //
                "Inputs", inputs,             //
                "PositiveHysteresis", positiveHysteresis, //
                "NegativeHysteresis", negativeHysteresis, //
                "Direction", direction                    //
                ))
        {
            return CreatePIDRet::fail;
        }

        if (zones)
        {
            std::vector<std::string> zonesStrs;
            if (!getZonesFromJsonReq(response, *zones, zonesStrs))
            {
                BMCWEB_LOG_ERROR("Illegal Zones");
                return CreatePIDRet::fail;
            }
            if (chassis.empty() &&
                findChassis(managedObj, zonesStrs[0], chassis) == nullptr)
            {
                BMCWEB_LOG_ERROR("Failed to get chassis from config patch");
                messages::invalidObject(
                    response->res,
                    boost::urls::format("/redfish/v1/Chassis/{}", chassis));
                return CreatePIDRet::fail;
            }
            output.emplace_back("Zones", std::move(zonesStrs));
        }
        if (steps)
        {
            std::vector<double> readings;
            std::vector<double> outputs;
            for (auto& step : *steps)
            {
                double target = 0.0;
                double out = 0.0;

                if (!redfish::json_util::readJsonObject( //
                        step, response->res,             //
                        "Target", target,                //
                        "Output", out                    //
                        ))
                {
                    return CreatePIDRet::fail;
                }
                readings.emplace_back(target);
                outputs.emplace_back(out);
            }
            output.emplace_back("Reading", std::move(readings));
            output.emplace_back("Output", std::move(outputs));
        }
        if (inputs)
        {
            for (std::string& value : *inputs)
            {
                std::replace(value.begin(), value.end(), '_', ' ');
            }
            output.emplace_back("Inputs", std::move(*inputs));
        }
        if (negativeHysteresis)
        {
            output.emplace_back("NegativeHysteresis", *negativeHysteresis);
        }
        if (positiveHysteresis)
        {
            output.emplace_back("PositiveHysteresis", *positiveHysteresis);
        }
        if (direction)
        {
            constexpr const std::array<const char*, 2> allowedDirections = {
                "Ceiling", "Floor"};
            if (std::ranges::find(allowedDirections, *direction) ==
                allowedDirections.end())
            {
                messages::propertyValueTypeError(response->res, "Direction",
                                                 *direction);
                return CreatePIDRet::fail;
            }
            output.emplace_back("Class", *direction);
        }
    }
    else
    {
        BMCWEB_LOG_ERROR("Illegal Type {}", type);
        messages::propertyUnknown(response->res, type);
        return CreatePIDRet::fail;
    }
    return CreatePIDRet::patch;
}
struct GetPIDValues : std::enable_shared_from_this<GetPIDValues>
{
    struct CompletionValues
    {
        std::vector<std::string> supportedProfiles;
        std::string currentProfile;
        dbus::utility::MapperGetSubTreeResponse subtree;
    };

    explicit GetPIDValues(
        const std::shared_ptr<bmcweb::AsyncResp>& asyncRespIn) :
        asyncResp(asyncRespIn)

    {}

    void run()
    {
        std::shared_ptr<GetPIDValues> self = shared_from_this();

        // get all configurations
        constexpr std::array<std::string_view, 4> interfaces = {
            pidConfigurationIface, pidZoneConfigurationIface,
            objectManagerIface, stepwiseConfigurationIface};
        dbus::utility::getSubTree(
            "/", 0, interfaces,
            [self](
                const boost::system::error_code& ec,
                const dbus::utility::MapperGetSubTreeResponse& subtreeLocal) {
                if (ec)
                {
                    BMCWEB_LOG_ERROR("{}", ec);
                    messages::internalError(self->asyncResp->res);
                    return;
                }
                self->complete.subtree = subtreeLocal;
            });

        // at the same time get the selected profile
        constexpr std::array<std::string_view, 1> thermalModeIfaces = {
            thermalModeIface};
        dbus::utility::getSubTree(
            "/", 0, thermalModeIfaces,
            [self](
                const boost::system::error_code& ec,
                const dbus::utility::MapperGetSubTreeResponse& subtreeLocal) {
                if (ec || subtreeLocal.empty())
                {
                    return;
                }
                if (subtreeLocal[0].second.size() != 1)
                {
                    // invalid mapper response, should never happen
                    BMCWEB_LOG_ERROR("GetPIDValues: Mapper Error");
                    messages::internalError(self->asyncResp->res);
                    return;
                }

                const std::string& path = subtreeLocal[0].first;
                const std::string& owner = subtreeLocal[0].second[0].first;

                dbus::utility::getAllProperties(
                    owner, path, thermalModeIface,
                    [path, owner,
                     self](const boost::system::error_code& ec2,
                           const dbus::utility::DBusPropertiesMap& resp) {
                        if (ec2)
                        {
                            BMCWEB_LOG_ERROR(
                                "GetPIDValues: Can't get thermalModeIface {}",
                                path);
                            messages::internalError(self->asyncResp->res);
                            return;
                        }

                        const std::string* current = nullptr;
                        const std::vector<std::string>* supported = nullptr;

                        const bool success = sdbusplus::unpackPropertiesNoThrow(
                            dbus_utils::UnpackErrorPrinter(), resp, "Current",
                            current, "Supported", supported);

                        if (!success)
                        {
                            messages::internalError(self->asyncResp->res);
                            return;
                        }

                        if (current == nullptr || supported == nullptr)
                        {
                            BMCWEB_LOG_ERROR(
                                "GetPIDValues: thermal mode iface invalid {}",
                                path);
                            messages::internalError(self->asyncResp->res);
                            return;
                        }
                        self->complete.currentProfile = *current;
                        self->complete.supportedProfiles = *supported;
                    });
            });
    }

    static void processingComplete(
        const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
        const CompletionValues& completion)
    {
        if (asyncResp->res.result() != boost::beast::http::status::ok)
        {
            return;
        }
        // create map of <connection, path to objMgr>>
        boost::container::flat_map<
            std::string, std::string, std::less<>,
            std::vector<std::pair<std::string, std::string>>>
            objectMgrPaths;
        boost::container::flat_set<std::string, std::less<>,
                                   std::vector<std::string>>
            calledConnections;
        for (const auto& pathGroup : completion.subtree)
        {
            for (const auto& connectionGroup : pathGroup.second)
            {
                auto findConnection =
                    calledConnections.find(connectionGroup.first);
                if (findConnection != calledConnections.end())
                {
                    break;
                }
                for (const std::string& interface : connectionGroup.second)
                {
                    if (interface == objectManagerIface)
                    {
                        objectMgrPaths[connectionGroup.first] = pathGroup.first;
                    }
                    // this list is alphabetical, so we
                    // should have found the objMgr by now
                    if (interface == pidConfigurationIface ||
                        interface == pidZoneConfigurationIface ||
                        interface == stepwiseConfigurationIface)
                    {
                        auto findObjMgr =
                            objectMgrPaths.find(connectionGroup.first);
                        if (findObjMgr == objectMgrPaths.end())
                        {
                            BMCWEB_LOG_DEBUG("{}Has no Object Manager",
                                             connectionGroup.first);
                            continue;
                        }

                        calledConnections.insert(connectionGroup.first);

                        asyncPopulatePid(findObjMgr->first, findObjMgr->second,
                                         completion.currentProfile,
                                         completion.supportedProfiles,
                                         asyncResp);
                        break;
                    }
                }
            }
        }
    }

    ~GetPIDValues()
    {
        boost::asio::post(crow::connections::systemBus->get_io_context(),
                          std::bind_front(&processingComplete, asyncResp,
                                          std::move(complete)));
    }

    GetPIDValues(const GetPIDValues&) = delete;
    GetPIDValues(GetPIDValues&&) = delete;
    GetPIDValues&
        operator=(const GetPIDValues&) = delete;
    GetPIDValues&
        operator=(GetPIDValues&&) = delete;

    std::shared_ptr<bmcweb::AsyncResp> asyncResp;
    CompletionValues complete;
};

struct SetPIDValues : std::enable_shared_from_this<SetPIDValues>
{
    SetPIDValues(
        const std::shared_ptr<bmcweb::AsyncResp>& asyncRespIn,
        std::vector<
            std::pair<std::string, std::optional<nlohmann::json::object_t>>>&&
            configurationsIn,
        std::optional<std::string>& profileIn) :
        asyncResp(asyncRespIn),
        configuration(std::move(configurationsIn)),
        profile(std::move(profileIn))
    {}

    SetPIDValues(const SetPIDValues&) = delete;
    SetPIDValues(SetPIDValues&&) = delete;
    SetPIDValues&
        operator=(const SetPIDValues&) = delete;
    SetPIDValues&
        operator=(SetPIDValues&&) = delete;

    void
        run()
    {
        if (asyncResp->res.result() != boost::beast::http::status::ok)
        {
            return;
        }

        std::shared_ptr<SetPIDValues> self = shared_from_this();

        // todo(james): might make sense to do a mapper call here if this
        // interface gets more traction
        sdbusplus::message::object_path objPath(
            "/xyz/openbmc_project/inventory");
        dbus::utility::getManagedObjects(
            "xyz.openbmc_project.EntityManager", objPath,
            [self](const boost::system::error_code& ec,
                   const dbus::utility::ManagedObjectType& mObj) {
                if (ec)
                {
                    BMCWEB_LOG_ERROR("Error communicating to Entity Manager");
                    messages::internalError(self->asyncResp->res);
                    return;
                }
                const std::array<const char*, 3> configurations = {
                    pidConfigurationIface, pidZoneConfigurationIface,
                    stepwiseConfigurationIface};

                for (const auto& [path, object] : mObj)
                {
                    for (const auto& [interface, _] : object)
                    {
                        if (std::ranges::find(configurations, interface) !=
                            configurations.end())
                        {
                            self->objectCount++;
                            break;
                        }
                    }
                }
                self->managedObj = mObj;
            });

        // at the same time get the profile information
        constexpr std::array<std::string_view, 1> thermalModeIfaces = {
            thermalModeIface};
        dbus::utility::getSubTree(
            "/", 0, thermalModeIfaces,
            [self](const boost::system::error_code& ec,
                   const dbus::utility::MapperGetSubTreeResponse& subtree) {
                if (ec || subtree.empty())
                {
                    return;
                }
                if (subtree[0].second.empty())
                {
                    // invalid mapper response, should never happen
                    BMCWEB_LOG_ERROR("SetPIDValues: Mapper Error");
                    messages::internalError(self->asyncResp->res);
                    return;
                }

                const std::string& path = subtree[0].first;
                const std::string& owner = subtree[0].second[0].first;
                dbus::utility::getAllProperties(
                    owner, path, thermalModeIface,
                    [self, path,
                     owner](const boost::system::error_code& ec2,
                            const dbus::utility::DBusPropertiesMap& r) {
                        if (ec2)
                        {
                            BMCWEB_LOG_ERROR(
                                "SetPIDValues: Can't get thermalModeIface {}",
                                path);
                            messages::internalError(self->asyncResp->res);
                            return;
                        }
                        const std::string* current = nullptr;
                        const std::vector<std::string>* supported = nullptr;

                        const bool success = sdbusplus::unpackPropertiesNoThrow(
                            dbus_utils::UnpackErrorPrinter(), r, "Current",
                            current, "Supported", supported);

                        if (!success)
                        {
                            messages::internalError(self->asyncResp->res);
                            return;
                        }

                        if (current == nullptr || supported == nullptr)
                        {
                            BMCWEB_LOG_ERROR(
                                "SetPIDValues: thermal mode iface invalid {}",
                                path);
                            messages::internalError(self->asyncResp->res);
                            return;
                        }
                        self->currentProfile = *current;
                        self->supportedProfiles = *supported;
                        self->profileConnection = owner;
                        self->profilePath = path;
                    });
            });
    }
    void
        pidSetDone()
    {
        if (asyncResp->res.result() != boost::beast::http::status::ok)
        {
            return;
        }
        std::shared_ptr<bmcweb::AsyncResp> response = asyncResp;
        if (profile)
        {
            if (std::ranges::find(supportedProfiles, *profile) ==
                supportedProfiles.end())
            {
                messages::actionParameterUnknown(response->res, "Profile",
                                                 *profile);
                return;
            }
            currentProfile = *profile;
            sdbusplus::asio::setProperty(
                *crow::connections::systemBus, profileConnection, profilePath,
                thermalModeIface, "Current", *profile,
                [response](const boost::system::error_code& ec) {
                    if (ec)
                    {
                        BMCWEB_LOG_ERROR("Error patching profile{}", ec);
                        messages::internalError(response->res);
                    }
                });
        }

        for (auto& containerPair : configuration)
        {
            auto& container = containerPair.second;
            if (!container)
            {
                continue;
            }

            const std::string& type = containerPair.first;

            for (auto& [name, value] : *container)
            {
                std::string dbusObjName = name;
                std::replace(dbusObjName.begin(), dbusObjName.end(), ' ', '_');
                BMCWEB_LOG_DEBUG("looking for {}", name);

                auto pathItr = std::ranges::find_if(
                    managedObj, [&dbusObjName](const auto& obj) {
                        return obj.first.filename() == dbusObjName;
                    });
                dbus::utility::DBusPropertiesMap output;

                output.reserve(16); // The pid interface length

                // determines if we're patching entity-manager or
                // creating a new object
                bool createNewObject = (pathItr == managedObj.end());
                BMCWEB_LOG_DEBUG("Found = {}", !createNewObject);

                std::string iface;
                if (!createNewObject)
                {
                    bool findInterface = false;
                    for (const auto& interface : pathItr->second)
                    {
                        if (interface.first == pidConfigurationIface)
                        {
                            if (type == "PidControllers" ||
                                type == "FanControllers")
                            {
                                iface = pidConfigurationIface;
                                findInterface = true;
                                break;
                            }
                        }
                        else if (interface.first == pidZoneConfigurationIface)
                        {
                            if (type == "FanZones")
                            {
                                iface = pidZoneConfigurationIface;
                                findInterface = true;
                                break;
                            }
                        }
                        else if (interface.first == stepwiseConfigurationIface)
                        {
                            if (type == "StepwiseControllers")
                            {
                                iface = stepwiseConfigurationIface;
                                findInterface = true;
                                break;
                            }
                        }
                    }

                    // create new object if interface not found
                    if (!findInterface)
                    {
                        createNewObject = true;
                    }
                }

                if (createNewObject && value == nullptr)
                {
                    // can't delete a non-existent object
                    messages::propertyValueNotInList(response->res, value,
                                                     name);
                    continue;
                }

                std::string path;
                if (pathItr != managedObj.end())
                {
                    path = pathItr->first.str;
                }

                BMCWEB_LOG_DEBUG("Create new = {}", createNewObject);

                // arbitrary limit to avoid attacks
                constexpr const size_t controllerLimit = 500;
                if (createNewObject && objectCount >= controllerLimit)
                {
                    messages::resourceExhaustion(response->res, type);
                    continue;
                }
                std::string escaped = name;
                std::replace(escaped.begin(), escaped.end(), '_', ' ');
                output.emplace_back("Name", escaped);

                std::string chassis;
                CreatePIDRet ret = createPidInterface(
                    response, type, name, value, path, managedObj,
                    createNewObject, output, chassis, currentProfile);
                if (ret == CreatePIDRet::fail)
                {
                    return;
                }
                if (ret == CreatePIDRet::del)
                {
                    continue;
                }

                if (!createNewObject)
                {
                    for (const auto& property : output)
                    {
                        crow::connections::systemBus->async_method_call(
                            [response,
                             propertyName{std::string(property.first)}](
                                const boost::system::error_code& ec) {
                                if (ec)
                                {
                                    BMCWEB_LOG_ERROR("Error patching {}: {}",
                                                     propertyName, ec);
                                    messages::internalError(response->res);
                                    return;
                                }
                                messages::success(response->res);
                            },
                            "xyz.openbmc_project.EntityManager", path,
                            "org.freedesktop.DBus.Properties", "Set", iface,
                            property.first, property.second);
                    }
                }
                else
                {
                    if (chassis.empty())
                    {
                        BMCWEB_LOG_ERROR("Failed to get chassis from config");
                        messages::internalError(response->res);
                        return;
                    }

                    bool foundChassis = false;
                    for (const auto& obj : managedObj)
                    {
                        if (obj.first.filename() == chassis)
                        {
                            chassis = obj.first.str;
                            foundChassis = true;
                            break;
                        }
                    }
                    if (!foundChassis)
                    {
                        BMCWEB_LOG_ERROR("Failed to find chassis on dbus");
                        messages::resourceMissingAtURI(
                            response->res,
                            boost::urls::format("/redfish/v1/Chassis/{}",
                                                chassis));
                        return;
                    }

                    crow::connections::systemBus->async_method_call(
                        [response](const boost::system::error_code& ec) {
                            if (ec)
                            {
                                BMCWEB_LOG_ERROR("Error Adding Pid Object {}",
                                                 ec);
                                messages::internalError(response->res);
                                return;
                            }
                            messages::success(response->res);
                        },
                        "xyz.openbmc_project.EntityManager", chassis,
                        "xyz.openbmc_project.AddObject", "AddObject", output);
                }
            }
        }
    }

    ~SetPIDValues()
    {
        try
        {
            pidSetDone();
        }
        catch (...)
        {
            BMCWEB_LOG_CRITICAL("pidSetDone threw exception");
        }
    }

    std::shared_ptr<bmcweb::AsyncResp> asyncResp;
    std::vector<std::pair<std::string, std::optional<nlohmann::json::object_t>>>
        configuration;
    std::optional<std::string> profile;
    dbus::utility::ManagedObjectType managedObj;
    std::vector<std::string> supportedProfiles;
    std::string currentProfile;
    std::string profileConnection;
    std::string profilePath;
    size_t objectCount = 0;
};

/**
 * @brief Retrieves BMC manager location data over DBus
 *
 * @param[in] asyncResp Shared pointer for completing asynchronous calls
 * @param[in] connectionName - service name
 * @param[in] path - object path
 * @return none
 */
inline void
    getLocation(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                const std::string& connectionName, const std::string& path)
{
    BMCWEB_LOG_DEBUG("Get BMC manager Location data.");

    dbus::utility::getProperty<std::string>(
        connectionName, path,
        "xyz.openbmc_project.Inventory.Decorator.LocationCode", "LocationCode",
        [asyncResp](const boost::system::error_code& ec,
                    const std::string& property) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("DBUS response error for "
                                 "Location");
                messages::internalError(asyncResp->res);
                return;
            }

            asyncResp->res
                .jsonValue["Location"]["PartLocation"]["ServiceLabel"] =
                property;
        });
}

inline void
    getCurrentDateTimeValue(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                            const std::string& timeZoneName)
{
    BMCWEB_LOG_DEBUG("Getting Manager Date Time");
    dbus::utility::getProperty<uint64_t>(
        "org.freedesktop.timedate1", "/org/freedesktop/timedate1",
        "org.freedesktop.timedate1", "TimeUSec",
        [asyncResp, timeZoneName](const boost::system::error_code& ec,
                                  const uint64_t& timeUSec) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("D-BUS response error {}", ec);
                return;
            }
            const std::chrono::time_zone* tz =
                std::chrono::locate_zone(timeZoneName);
            auto now = std::chrono::system_clock::now();
            std::chrono::sys_info tzInfo =
                tz->get_info(std::chrono::floor<std::chrono::seconds>(now));
            auto offset = tzInfo.offset;

            uint64_t epochTime = timeUSec / 1000000;
            epochTime += static_cast<uint64_t>(offset.count());
            std::time_t time = static_cast<std::time_t>(epochTime);
            std::tm gmTime = *std::gmtime(&time);
            std::ostringstream oss;
            oss << std::put_time(&gmTime, "%Y-%m-%dT%H:%M:%SZ");
            asyncResp->res.jsonValue["DateTime"] = oss.str();
        });
}

// avoid name collision systems.hpp
inline void
    managerGetLastResetTime(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    BMCWEB_LOG_DEBUG("Getting Manager Last Reset Time");

    dbus::utility::getProperty<uint64_t>(
        "xyz.openbmc_project.State.BMC", "/xyz/openbmc_project/state/bmc0",
        "xyz.openbmc_project.State.BMC", "LastRebootTime",
        [asyncResp](const boost::system::error_code& ec,
                    const uint64_t lastResetTime) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("D-BUS response error {}", ec);
                return;
            }

            // LastRebootTime is epoch time, in milliseconds
            // https://github.com/openbmc/phosphor-dbus-interfaces/blob/7f9a128eb9296e926422ddc312c148b625890bb6/xyz/openbmc_project/State/BMC.interface.yaml#L19
            uint64_t lastResetTimeStamp = lastResetTime / 1000;

            // Convert to ISO 8601 standard
            asyncResp->res.jsonValue["LastResetTime"] =
                redfish::time_utils::getDateTimeUint(lastResetTimeStamp);
        });
}

/**
 * @brief Set the running firmware image
 *
 * @param[i,o] asyncResp - Async response object
 * @param[i] runningFirmwareTarget - Image to make the running image
 *
 * @return void
 */
inline void
    setActiveFirmwareImage(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                           const std::string& runningFirmwareTarget)
{
    // Get the Id from /redfish/v1/UpdateService/FirmwareInventory/<Id>
    std::string::size_type idPos = runningFirmwareTarget.rfind('/');
    if (idPos == std::string::npos)
    {
        messages::propertyValueNotInList(asyncResp->res, runningFirmwareTarget,
                                         "@odata.id");
        BMCWEB_LOG_DEBUG("Can't parse firmware ID!");
        return;
    }
    idPos++;
    if (idPos >= runningFirmwareTarget.size())
    {
        messages::propertyValueNotInList(asyncResp->res, runningFirmwareTarget,
                                         "@odata.id");
        BMCWEB_LOG_DEBUG("Invalid firmware ID.");
        return;
    }
    std::string firmwareId = runningFirmwareTarget.substr(idPos);

    // Make sure the image is valid before setting priority
    sdbusplus::message::object_path objPath("/xyz/openbmc_project/software");
    dbus::utility::getManagedObjects(
        getBMCUpdateServiceName(), objPath,
        [asyncResp, firmwareId, runningFirmwareTarget](
            const boost::system::error_code& ec,
            const dbus::utility::ManagedObjectType& subtree) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("D-Bus response error getting objects.");
                messages::internalError(asyncResp->res);
                return;
            }

            if (subtree.empty())
            {
                BMCWEB_LOG_DEBUG("Can't find image!");
                messages::internalError(asyncResp->res);
                return;
            }

            bool foundImage = false;
            for (const auto& object : subtree)
            {
                const std::string& path =
                    static_cast<const std::string&>(object.first);
                std::size_t idPos2 = path.rfind('/');

                if (idPos2 == std::string::npos)
                {
                    continue;
                }

                idPos2++;
                if (idPos2 >= path.size())
                {
                    continue;
                }

                if (path.substr(idPos2) == firmwareId)
                {
                    foundImage = true;
                    break;
                }
            }

            if (!foundImage)
            {
                messages::propertyValueNotInList(
                    asyncResp->res, runningFirmwareTarget, "@odata.id");
                BMCWEB_LOG_DEBUG("Invalid firmware ID.");
                return;
            }

            BMCWEB_LOG_DEBUG("Setting firmware version {} to priority 0.",
                             firmwareId);

            // Only support Immediate
            // An addition could be a Redfish Setting like
            // ActiveSoftwareImageApplyTime and support OnReset
            sdbusplus::asio::setProperty(
                *crow::connections::systemBus, getBMCUpdateServiceName(),
                "/xyz/openbmc_project/software/" + firmwareId,
                "xyz.openbmc_project.Software.RedundancyPriority", "Priority",
                static_cast<uint8_t>(0),
                [asyncResp](const boost::system::error_code& ec2) {
                    if (ec2)
                    {
                        BMCWEB_LOG_DEBUG("D-Bus response error setting.");
                        messages::internalError(asyncResp->res);
                        return;
                    }
                    doBMCGracefulRestart(asyncResp);
                });
        });
}

inline void
    afterSetDateTime(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                     const boost::system::error_code& ec,
                     const sdbusplus::message_t& msg)
{
    if (ec)
    {
        BMCWEB_LOG_DEBUG("Failed to set elapsed time. DBUS response error {}",
                         ec);
        const sd_bus_error* dbusError = msg.get_error();
        if (dbusError != nullptr)
        {
            std::string_view errorName(dbusError->name);
            if (errorName ==
                "org.freedesktop.timedate1.AutomaticTimeSyncEnabled")
            {
                BMCWEB_LOG_DEBUG("Setting conflict");
                messages::propertyValueConflict(
                    asyncResp->res, "DateTime",
                    "Managers/NetworkProtocol/NTPProcotolEnabled");
                return;
            }
        }
        messages::internalError(asyncResp->res);
        return;
    }
    asyncResp->res.result(boost::beast::http::status::no_content);
}

inline void
    setTimeZoneName(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                    const std::string& timeZoneName)
{
    BMCWEB_LOG_DEBUG("Set Time Zone Name: {}", timeZoneName);

    // Validate timezone before attempting to set it
    try
    {
        const std::chrono::time_zone* tz = std::chrono::locate_zone(timeZoneName);
        if (tz == nullptr)
        {
            BMCWEB_LOG_ERROR("Invalid timezone: {}", timeZoneName);
            messages::propertyValueFormatError(asyncResp->res, timeZoneName,
                                             "TimeZoneName");
            return;
        }
    }
    catch (const std::runtime_error& e)
    {
        BMCWEB_LOG_ERROR("Invalid timezone: {}, error: {}", timeZoneName, e.what());
        messages::propertyValueFormatError(asyncResp->res, timeZoneName,
                                         "TimeZoneName");
        return;
    }

    crow::utility::saveTimeZone(crow::utility::localTimeZone,timeZoneName);

    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code& ec,
                    const sdbusplus::message_t& msg) {
            afterSetDateTime(asyncResp, ec, msg);
        },
        "org.freedesktop.timedate1", "/org/freedesktop/timedate1",
        "org.freedesktop.timedate1", "SetTimezone", timeZoneName, true);
}

inline void
    setDateTime(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                const std::string& datetime)
{
    BMCWEB_LOG_DEBUG("Set date time: {}", datetime);

    std::optional<redfish::time_utils::usSinceEpoch> us =
        redfish::time_utils::dateStringToEpoch(datetime);
    if (!us)
    {
        messages::propertyValueFormatError(asyncResp->res, datetime,
                                           "DateTime");
        return;
    }
    dbus::utility::getProperty<std::string>(
        "org.freedesktop.timedate1", "/org/freedesktop/timedate1",
        "org.freedesktop.timedate1", "Timezone",
        [asyncResp,
         us](const boost::system::error_code& ec, const std::string& timezone) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("DBUS response error for "
                                 "TimeZoneName");
                messages::internalError(asyncResp->res);
                return;
            }
            // Set timezone
            setenv("TZ", timezone.c_str(), 1);
            tzset();

            // Get current time
            time_t now = time(nullptr);
            struct tm localTm;
            localtime_r(&now, &localTm);

            long int offset_sec = localTm.tm_gmtoff;
            int64_t offset_microseconds =
                static_cast<int64_t>(offset_sec) * 1000000;

            int64_t adjustedEpochTime = us->count() - (offset_microseconds);

            // Set the absolute datetime
            bool relative = false;
            bool interactive = false;
            crow::connections::systemBus->async_method_call(
                [asyncResp](const boost::system::error_code& ec1,
                            const sdbusplus::message_t& msg) {
                    afterSetDateTime(asyncResp, ec1, msg);
                },
                "org.freedesktop.timedate1", "/org/freedesktop/timedate1",
                "org.freedesktop.timedate1", "SetTime", adjustedEpochTime,
                relative, interactive);
        });
}

inline void
    checkForQuiesced(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    dbus::utility::getProperty<std::string>(
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1/unit/obmc-bmc-service-quiesce@0.target",
        "org.freedesktop.systemd1.Unit", "ActiveState",
        [asyncResp](const boost::system::error_code& ec,
                    const std::string& val) {
            if (!ec)
            {
                if (val == "active")
                {
                    asyncResp->res.jsonValue["Status"]["Health"] =
                        resource::Health::Critical;
                    asyncResp->res.jsonValue["Status"]["State"] =
                        resource::State::Quiesced;
                    return;
                }
            }
            asyncResp->res.jsonValue["Status"]["Health"] = resource::Health::OK;
            asyncResp->res.jsonValue["Status"]["State"] =
                resource::State::Enabled;
        });
}

inline void
    handleManagersInstanceGet(
        App& app, const crow::Request& req,
        const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
        const std::string& managerId)
{
    asyncResp->res.clearHeader(boost::beast::http::field::allow);

    std::string uuid = persistent_data::getConfig().systemUuid;
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (!membersResponseGet(asyncResp, managerId, "ManagerCollection"))
    {
        return;
    }
    if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
    {
        messages::resourceNotFound(asyncResp->res, "Manager", managerId);
        return;
    }
    asyncResp->res.addHeader("Allow", "GET, PATCH");
    ishandleManagersInstanceGet = true;

    asyncResp->res.jsonValue["@odata.id"] = boost::urls::format(
        "/redfish/v1/Managers/{}", BMCWEB_REDFISH_MANAGER_URI_NAME);
    asyncResp->res.jsonValue["@odata.type"] = json_util::odataType("Manager");
    asyncResp->res.jsonValue["Id"] = BMCWEB_REDFISH_MANAGER_URI_NAME;
    asyncResp->res.jsonValue["Name"] = "OpenBmc Manager";
    asyncResp->res.jsonValue["Description"] = "Baseboard Management Controller";
    asyncResp->res.jsonValue["PowerState"] = resource::PowerState::On;

    asyncResp->res.jsonValue["ManagerType"] = manager::ManagerType::BMC;
    asyncResp->res.jsonValue["UUID"] = systemd_utils::getUuid();
    asyncResp->res.jsonValue["ServiceEntryPointUUID"] = uuid;
    asyncResp->res.jsonValue["Model"] = "OpenBmc"; // TODO(ed), get model

    asyncResp->res.jsonValue["LogServices"]["@odata.id"] = boost::urls::format(
        "/redfish/v1/Managers/{}/LogServices", BMCWEB_REDFISH_MANAGER_URI_NAME);
    asyncResp->res.jsonValue["NetworkProtocol"]["@odata.id"] =
        boost::urls::format("/redfish/v1/Managers/{}/NetworkProtocol",
                            BMCWEB_REDFISH_MANAGER_URI_NAME);
    #if (!BMCWEB_AMI_RM_MACRO) && (!BMCWEB_AMI_PSM_MACRO)
    asyncResp->res.jsonValue["SerialInterfaces"]["@odata.id"] =
        boost::urls::format("/redfish/v1/Managers/{}/SerialInterfaces",
                            BMCWEB_REDFISH_MANAGER_URI_NAME);
    #endif
    asyncResp->res.jsonValue["EthernetInterfaces"]["@odata.id"] =
        boost::urls::format("/redfish/v1/Managers/{}/EthernetInterfaces",
                            BMCWEB_REDFISH_MANAGER_URI_NAME);
    #if (!BMCWEB_CHALUPA_AMD_MACRO && !BMCWEB_ARBEL_NUVOTON_MACRO && !BMCWEB_AST2700_EVB_MACRO && !BMCWEB_AMI_RM_MACRO && !BMCWEB_AMI_PSM_MACRO)
    {
    asyncResp->res.jsonValue["SecurityPolicy"]["@odata.id"] =
       	boost::urls::format("/redfish/v1/Managers/{}/SecurityPolicy",
               	            BMCWEB_REDFISH_MANAGER_URI_NAME);
    }
    #endif
    #if (!BMCWEB_AMI_RM_MACRO && !BMCWEB_AMI_PSM_MACRO)
    if constexpr (BMCWEB_VM_NBDPROXY)
    {
        asyncResp->res.jsonValue["VirtualMedia"]["@odata.id"] =
            boost::urls::format("/redfish/v1/Managers/{}/VirtualMedia",
                                BMCWEB_REDFISH_MANAGER_URI_NAME);
    }

    // default oem data
    nlohmann::json& oem = asyncResp->res.jsonValue["Oem"];
    nlohmann::json& oemOpenbmc = oem["OpenBmc"];
    nlohmann::json& oemIntel = oem["Intel"];
#if (BMCWEB_NVIDIA_RESET_URIS_MACRO)
    nlohmann::json& oemResetToDefaults =
	    asyncResp->res.jsonValue["Actions"]["Oem"]
	    ["#NvidiaManager.ResetToDefaults"];
    oemResetToDefaults["target"] =
	    boost::urls::format("/redfish/v1/Managers/{}/Actions/Oem/NvidiaManager.ResetToDefaults",
	     BMCWEB_REDFISH_MANAGER_URI_NAME);
#endif
    oemIntel["@odata.type"] = json_util::odataType("OpenBMCManager", "Intel");
    oemIntel["@odata.id"] = "/redfish/v1/Managers/bmc#/Oem/Intel";
#if (BMCWEB_AMI_NM_MACRO)
    oemIntel["NodeManager"] = {
        {"@odata.id", "/redfish/v1/Managers/bmc/Oem/Intel/NodeManager"}};
#endif
    oem["@odata.id"] = boost::urls::format("/redfish/v1/Managers/{}#/Oem",
                                           BMCWEB_REDFISH_MANAGER_URI_NAME);
    oemOpenbmc["@odata.type"] = json_util::odataType("OpenBMCManager", "Manager");
    oemOpenbmc["@odata.id"] =
        boost::urls::format("/redfish/v1/Managers/bmc#/Oem#/OpenBmc/",
                            BMCWEB_REDFISH_MANAGER_URI_NAME);

    #if (!BMCWEB_ARBEL_NUVOTON_MACRO)
    nlohmann::json::object_t jpeg;
    jpeg["@odata.id"] =
        boost::urls::format("/redfish/v1/Managers/{}/Oem/OpenBmc/Jpeg",
                            BMCWEB_REDFISH_MANAGER_URI_NAME);
    oemOpenbmc["Jpeg"] = std::move(jpeg);
    #endif
    nlohmann::json::object_t certificates;
    certificates["@odata.id"] =
        boost::urls::format("/redfish/v1/Managers/{}/Truststore/Certificates",
                            BMCWEB_REDFISH_MANAGER_URI_NAME);
    oemOpenbmc["Certificates"] = std::move(certificates);
    #endif
    // Manager.Reset (an action) can be many values, OpenBMC only
    // supports BMC reboot.
    nlohmann::json& managerReset =
        asyncResp->res.jsonValue["Actions"]["#Manager.Reset"];
    managerReset["target"] =
        boost::urls::format("/redfish/v1/Managers/{}/Actions/Manager.Reset",
                            BMCWEB_REDFISH_MANAGER_URI_NAME);
    managerReset["@Redfish.ActionInfo"] =
        boost::urls::format("/redfish/v1/Managers/{}/ResetActionInfo",
                            BMCWEB_REDFISH_MANAGER_URI_NAME);

    // ResetToDefaults (Factory Reset) has values like
    // PreserveNetworkAndUsers and PreserveNetwork that aren't supported
    // on OpenBMC
    #if (!BMCWEB_AMI_RM_MACRO && !BMCWEB_AMI_PSM_MACRO)
    nlohmann::json& ResetToDefaults =
        asyncResp->res.jsonValue["Actions"]["#Manager.ResetToDefaults"];
    ResetToDefaults["target"] =
        boost::urls::format("/redfish/v1/Managers/{}/Actions/Manager.ResetToDefaults",
                            BMCWEB_REDFISH_MANAGER_URI_NAME);
    ResetToDefaults["@Redfish.ActionInfo"] =
        boost::urls::format("/redfish/v1/Managers/{}/ResetActionInfo",
                            BMCWEB_REDFISH_MANAGER_URI_NAME);
    #endif
    #if (!BMCWEB_AMI_PSM_MACRO)
    
    dbus::utility::getProperty<std::string>(
        "org.freedesktop.timedate1", "/org/freedesktop/timedate1",
        "org.freedesktop.timedate1", "Timezone",
        [asyncResp](const boost::system::error_code& ec,
                    const std::string& property) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("DBUS response error for "
                                 "TimeZoneName");
                messages::internalError(asyncResp->res);
                return;
            }

            asyncResp->res.jsonValue["TimeZoneName"] = property;
            getCurrentDateTimeValue(asyncResp, property);
        });
    #endif
    // TODO (Gunnar): Remove these one day since moved to ComputerSystem
    // Still used by OCP profiles
    // https://github.com/opencomputeproject/OCP-Profiles/issues/23
    // Fill in CommandShell info
    asyncResp->res.jsonValue["CommandShell"]["ServiceEnabled"] = true;
    asyncResp->res.jsonValue["CommandShell"]["MaxConcurrentSessions"] = 1;
    asyncResp->res.jsonValue["CommandShell"]["ConnectTypesSupported"] = {
        "SSH", "IPMI"};
    if constexpr (!BMCWEB_EXPERIMENTAL_REDFISH_MULTI_COMPUTER_SYSTEM && !BMCWEB_AMI_PSM_MACRO)
    {
        asyncResp->res.jsonValue["Links"]["ManagerForServers@odata.count"] = 1;

        nlohmann::json::array_t managerForServers;
        nlohmann::json::object_t manager;
        manager["@odata.id"] = std::format("/redfish/v1/Systems/{}",
                                           BMCWEB_REDFISH_SYSTEM_URI_NAME);
        managerForServers.emplace_back(std::move(manager));

        asyncResp->res.jsonValue["Links"]["ManagerForServers"] =
            std::move(managerForServers);
    }
    #if (!BMCWEB_AMI_RM_MACRO) && (!BMCWEB_AMI_PSM_MACRO)
    sw_util::populateSoftwareInformation(asyncResp, sw_util::bmcPurpose,
                                         "FirmwareVersion", true);
    #endif
    managerGetLastResetTime(asyncResp);
    getSystemLocationIndicatorActive(asyncResp);
    #if (!BMCWEB_AMI_RM_MACRO) && (!BMCWEB_AMI_PSM_MACRO)
    // ManagerDiagnosticData is added for all BMCs.
    nlohmann::json& managerDiagnosticData =
        asyncResp->res.jsonValue["ManagerDiagnosticData"];
    managerDiagnosticData["@odata.id"] =
        boost::urls::format("/redfish/v1/Managers/{}/ManagerDiagnosticData",
                            BMCWEB_REDFISH_MANAGER_URI_NAME);

    if constexpr (BMCWEB_REDFISH_OEM_MANAGER_FAN_DATA)
    {
        auto pids = std::make_shared<GetPIDValues>(asyncResp);
        pids->run();
    }

    getMainChassisId(
        asyncResp, [](const std::string& chassisId,
                      const std::shared_ptr<bmcweb::AsyncResp>& aRsp) {
            aRsp->res.jsonValue["Links"]["ManagerForChassis@odata.count"] = 1;
            nlohmann::json::array_t managerForChassis;
            nlohmann::json::object_t managerObj;
            boost::urls::url chassiUrl =
                boost::urls::format("/redfish/v1/Chassis/{}", chassisId);
            managerObj["@odata.id"] = chassiUrl;
            managerForChassis.emplace_back(std::move(managerObj));
            aRsp->res.jsonValue["Links"]["ManagerForChassis"] =
                std::move(managerForChassis);
            aRsp->res.jsonValue["Links"]["ManagerInChassis"]["@odata.id"] =
                chassiUrl;
        });
    #endif
    dbus::utility::getProperty<double>(
        "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager", "Progress",
        [asyncResp](const boost::system::error_code& ec, double val) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("Error while getting progress");
                messages::internalError(asyncResp->res);
                return;
            }
            if (val < 1.0)
            {
                asyncResp->res.jsonValue["Status"]["Health"] =
                    resource::Health::OK;
                asyncResp->res.jsonValue["Status"]["State"] =
                    resource::State::Starting;
                return;
            }
            checkForQuiesced(asyncResp);
        });

    constexpr std::array<std::string_view, 1> interfaces = {
        "xyz.openbmc_project.Inventory.Item.Bmc"};
    dbus::utility::getSubTree(
        "/xyz/openbmc_project/inventory", 0, interfaces,
        [asyncResp](const boost::system::error_code& ec,
                    const dbus::utility::MapperGetSubTreeResponse& subtree) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("D-Bus response error on GetSubTree {}", ec);
                return;
            }
            if (subtree.empty())
            {
                BMCWEB_LOG_DEBUG("Can't find bmc D-Bus object!");
                return;
            }
            // Assume only 1 bmc D-Bus object
            // Throw an error if there is more than 1
            if (subtree.size() > 1)
            {
                BMCWEB_LOG_DEBUG("Found more than 1 bmc D-Bus object!");
                messages::internalError(asyncResp->res);
                return;
            }

            if (subtree[0].first.empty() || subtree[0].second.size() != 1)
            {
                BMCWEB_LOG_DEBUG("Error getting bmc D-Bus object!");
                messages::internalError(asyncResp->res);
                return;
            }

            const std::string& path = subtree[0].first;
            const std::string& connectionName = subtree[0].second[0].first;

            for (const auto& interfaceName : subtree[0].second[0].second)
            {
                if (interfaceName ==
                    "xyz.openbmc_project.Inventory.Decorator.Asset")
                {
                    dbus::utility::getAllProperties(
                        connectionName, path,
                        "xyz.openbmc_project.Inventory.Decorator.Asset",
                        [asyncResp](const boost::system::error_code& ec2,
                                    const dbus::utility::DBusPropertiesMap&
                                        propertiesList) {
                            if (ec2)
                            {
                                BMCWEB_LOG_DEBUG("Can't get bmc asset!");
                                return;
                            }

                            const std::string* partNumber = nullptr;
                            const std::string* serialNumber = nullptr;
                            const std::string* manufacturer = nullptr;
                            const std::string* model = nullptr;
                            const std::string* sparePartNumber = nullptr;

                            const bool success =
                                sdbusplus::unpackPropertiesNoThrow(
                                    dbus_utils::UnpackErrorPrinter(),
                                    propertiesList, "PartNumber", partNumber,
                                    "SerialNumber", serialNumber,
                                    "Manufacturer", manufacturer, "Model",
                                    model, "SparePartNumber", sparePartNumber);

                            if (!success)
                            {
                                messages::internalError(asyncResp->res);
                                return;
                            }

                            if (partNumber != nullptr)
                            {
                                asyncResp->res.jsonValue["PartNumber"] =
                                    *partNumber;
                            }

                            if (serialNumber != nullptr)
                            {
                                asyncResp->res.jsonValue["SerialNumber"] =
                                    *serialNumber;
                            }

                            if (manufacturer != nullptr)
                            {
                                asyncResp->res.jsonValue["Manufacturer"] =
                                    *manufacturer;
                            }

                            if (model != nullptr)
                            {
                                asyncResp->res.jsonValue["Model"] = *model;
                            }

                            if (sparePartNumber != nullptr)
                            {
                                asyncResp->res.jsonValue["SparePartNumber"] =
                                    *sparePartNumber;
                            }
                        });
                }
                else if (interfaceName ==
                         "xyz.openbmc_project.Inventory.Decorator.LocationCode")
                {
                    getLocation(asyncResp, connectionName, path);
                }
            }
        });
}

inline void
    requestRoutesManager(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Managers/<str>/")
        .privileges(redfish::privileges::getManager)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleManagersInstanceGet, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Managers/<str>/")
        .privileges(redfish::privileges::patchManager)
        .methods(
            boost::beast::http::verb::
                patch)([&app](
                           const crow::Request& req,
                           const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                           const std::string& managerId) {
	    
	        asyncResp->res.clearHeader(boost::beast::http::field::allow);

            if (!redfish::setUpRedfishRoute(app, req, asyncResp))
            {
                return;
            }
            if (!membersResponseGet(asyncResp, managerId, "ManagerCollection"))
            {
                return;
            }
            asyncResp->res.addHeader(
                boost::beast::http::field::link,
                "</redfish/v1/JsonSchemas/Manager/Manager.json>; rel=describedby");

            if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
            {
                messages::resourceNotFound(asyncResp->res, "Manager",
                                           managerId);
                return;
            }
            std::optional<std::string> activeSoftwareImageOdataId;
            std::optional<std::string> datetime;
            std::optional<std::string> timeZoneName;
            std::optional<bool> locationIndicatorActive;
            std::optional<std::string> vId;
            std::optional<nlohmann::json::object_t> pidControllers;
            std::optional<nlohmann::json::object_t> fanControllers;
            std::optional<nlohmann::json::object_t> fanZones;
            std::optional<nlohmann::json::object_t> stepwiseControllers;
            std::optional<std::string> profile;

            // clang-format off
        if (!json_util::readJsonPatch(//
        req, asyncResp->res, //
              "DateTime", datetime, //
              "Links/ActiveSoftwareImage/@odata.id", activeSoftwareImageOdataId, //
             /* "Oem/OpenBmc/Fan/FanControllers", fanControllers, //
              "Oem/OpenBmc/Fan/FanZones", fanZones, //
              "Oem/OpenBmc/Fan/PidControllers", pidControllers, //
              "Oem/OpenBmc/Fan/Profile", profile, //
              "Oem/OpenBmc/Fan/StepwiseControllers", stepwiseControllers, // */
              "Id", vId, //
              "TimeZoneName", timeZoneName, //
              "LocationIndicatorActive", locationIndicatorActive //
        ))
        {
            return;
        }
            // clang-format on
            if (vId)
            {
                messages::propertyNotWritable(asyncResp->res, "Id");
                asyncResp->res.result(boost::beast::http::status::bad_request);
                return;
            }

            /*    if (pidControllers || fanControllers || fanZones ||
                    stepwiseControllers || profile)
                {
                    if constexpr (BMCWEB_REDFISH_OEM_MANAGER_FAN_DATA)
                    {
                        std::vector<std::pair<std::string,
                                              std::optional<nlohmann::json::object_t>>>
                            configuration;
                        if (pidControllers)
                        {
                            configuration.emplace_back("PidControllers",
                                                       std::move(pidControllers));
                        }
                        if (fanControllers)
                        {
                            configuration.emplace_back("FanControllers",
                                                       std::move(fanControllers));
                        }
                        if (fanZones)
                        {
                            configuration.emplace_back("FanZones",
               std::move(fanZones));
                        }
                        if (stepwiseControllers)
                        {
                            configuration.emplace_back("StepwiseControllers",
                                                       std::move(stepwiseControllers));
                        }
                        auto pid = std::make_shared<SetPIDValues>(
                            asyncResp, std::move(configuration), profile);
                        pid->run();
                    }
                    else
                    {
                        messages::propertyUnknown(asyncResp->res, "Oem");
                        return;
                    }
                }*/

            if (activeSoftwareImageOdataId)
            {
                setActiveFirmwareImage(asyncResp, *activeSoftwareImageOdataId);
            }
            if (timeZoneName.has_value())
            {
                setTimeZoneName(asyncResp, *timeZoneName);
            }
            if (datetime)
            {
                setDateTime(asyncResp, *datetime);
            }
            if (locationIndicatorActive)
            {
                setSystemLocationIndicatorActive(asyncResp,
                                                 *locationIndicatorActive);
            }
        });

    BMCWEB_ROUTE(app, "/redfish/v1/Managers/<str>/")
        .privileges(redfish::privileges::getManager)
        .methods(boost::beast::http::verb::post,boost::beast::http::verb::delete_)(
            [&app](const crow::Request& req,
                const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                const std::string& managerId)
            {
               asyncResp->res.clearHeader(boost::beast::http::field::allow);
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }
                if (!membersResponseGet(asyncResp, managerId, "ManagerCollection"))
                {
                    return;
                }
                if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
                {
                    messages::resourceNotFound(asyncResp->res, "Manager", managerId);
                    return;
                }
                asyncResp->res.addHeader("Allow", "GET, PATCH");
                messages::operationNotAllowed(asyncResp->res);
                return;
           });
}

inline void
    handleManagerCollectionGet(
        App& app, const crow::Request& req,
        const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    // Collections don't include the static data added by SubRoute
    // because it has a duplicate entry for members
    asyncResp->res.jsonValue["@odata.id"] = "/redfish/v1/Managers";
    asyncResp->res.jsonValue["@odata.type"] =
        "#ManagerCollection.ManagerCollection";
    asyncResp->res.jsonValue["Name"] = "Manager Collection";
    asyncResp->res.jsonValue["Description"] = "The collection for Managers";
    asyncResp->res.jsonValue["Members@odata.count"] = 1;
    nlohmann::json::array_t members;
    nlohmann::json& bmc = members.emplace_back();
    bmc["@odata.id"] = boost::urls::format("/redfish/v1/Managers/{}",
                                           BMCWEB_REDFISH_MANAGER_URI_NAME);
    asyncResp->res.jsonValue["Members"] = std::move(members);
}

inline void requestRoutesManagerCollection(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Managers/")
        .privileges(redfish::privileges::getManagerCollection)
        .methods(boost::beast::http::verb::get)(
	std::bind_front(handleManagerCollectionGet, std::ref(app)));
}

// Add function declarations for functions used before they're defined:
static inline void findSerialDevice(std::vector<std::string>& tokens);
static inline void getSerialServiceState(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp, 
                                        const std::string& SerialName);
                                        
// Add these function declarations near the top of the namespace:
inline FILE* safe_popen(const char* command, const char* type)
{
    return popen(command, type);
}

inline int safe_system(const char* command)
{
    return system(command);
}

// Check if a serial device exists
inline bool isSerialDeviceExists(const std::string& serialName)
{
    std::string devicePath = "/dev/" + serialName;
    bool deviceExists = std::filesystem::exists(devicePath) && 
                                  std::filesystem::is_character_file(devicePath);
    return deviceExists;
}

void SttyValueCmd(const string& cmd, string item, string& value)
{
    char buffer[512];
    size_t found, found_end;
    FILE* pipe = safe_popen(cmd.c_str(), "r");
    if (!pipe)
    {
        return;
    }
    while (!feof(pipe))
    {
        if (fgets(buffer, sizeof(buffer), pipe) != NULL)
        {
            if ((found = string(buffer).find(item)) != std::string::npos)
            {
                found_end =
                    string(buffer).substr(found + item.size()).find(" ");
                value = string(buffer).substr(found + item.size(), found_end);
            }
        }
    }
    pclose(pipe);
}

void SttyStatusCmd(const string& cmd, string item, bool& result)
{
    char buffer[512];
    FILE* pipe = safe_popen(cmd.c_str(), "r");
    if (!pipe)
    {
        result = false;
        return;
    }
    result = false;  // Initialize to false
    while (!feof(pipe))
    {
        if (fgets(buffer, sizeof(buffer), pipe) != NULL)
        {
            std::string line(buffer);
            // Look for the item in the line
            size_t found = line.find(item);
            if (found != std::string::npos)
            {
                // Check if the item is negated (preceded by -)
                if (found > 0 && line[found - 1] == '-')
                {
                    result = false;  // Item is disabled
                }
                else
                {
                    result = true;   // Item is enabled
                }
                break;  // Found the item, stop searching
            }
        }
    }
    pclose(pipe);
}

inline void handleManagerSerialInterfaceGet(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp, const std::string& SerialName)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
   
    // FIX: Add proper macro check for IPMI-SOL support
    #if (!BMCWEB_ARBEL_NUVOTON_MACRO)
    if (SerialName == "IPMI-SOL")
    {
        asyncResp->res.addHeader("Allow", "GET, PATCH");
        dbus::utility::getProperty<uint64_t>(
            consoleDbusService, consoleDbusObject, consoleDbusInterface, "Baud",
            [asyncResp](const boost::system::error_code& ec, uint64_t val) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("Error while getting BitRate");
                messages::internalError(asyncResp->res);
                return;
            }
            asyncResp->res.jsonValue["@odata.type"] = json_util::odataType("SerialInterface");
            asyncResp->res.jsonValue["Id"] = "IPMI-SOL";
            asyncResp->res.jsonValue["Name"] = "Manager Serial Interface";
            asyncResp->res.jsonValue["Description"] = "Management for Serial Interface";
            asyncResp->res.jsonValue["@odata.id"] = boost::urls::format(
                "/redfish/v1/Managers/{}/SerialInterfaces/IPMI-SOL",
                BMCWEB_REDFISH_MANAGER_URI_NAME);
            asyncResp->res.jsonValue["BitRate"] = std::to_string(val);
        });
        return;  // Important: return after handling IPMI-SOL
    }
    #endif
    auto fillSerialResponseCb = [asyncResp, SerialName](const char* resourceName) {
        std::vector<std::string> tokens;
        bool check = false, StopBits = false, HwControl = false, SwControl = false, Parity_enable = false, Parity_Odd = false;
        std::string BitRate, DataBits;
        findSerialDevice(tokens);
           

        for (auto i : tokens)
        {
            if (SerialName == i)
            {
                check = true;
                asyncResp->res.addHeader("Allow", "GET, PATCH");
                // Populate JSON response only when device is found
                asyncResp->res.jsonValue["@odata.id"] = boost::urls::format(
                    "/redfish/v1/Managers/{}/SerialInterfaces/{}",
                    BMCWEB_REDFISH_MANAGER_URI_NAME, SerialName);
                asyncResp->res.jsonValue["@odata.type"] = json_util::odataType("SerialInterface");
                asyncResp->res.jsonValue["Name"] = "Manager Serial Interface";
                asyncResp->res.jsonValue["Description"] = "Management for Serial Interface";
                asyncResp->res.jsonValue["Id"] = SerialName;

                std::string sttyCmd = "stty -a -F /dev/" + SerialName;
                SttyStatusCmd(sttyCmd, "cstopb", StopBits);
                SttyStatusCmd(sttyCmd, "crtscts", HwControl);
                SttyStatusCmd(sttyCmd, "ixon", SwControl);
                SttyStatusCmd(sttyCmd, "parenb", Parity_enable);    
                SttyStatusCmd(sttyCmd, "parodd", Parity_Odd);       
                SttyValueCmd(sttyCmd, "speed ", BitRate);
                SttyValueCmd(sttyCmd, "cs", DataBits);
                if (!BitRate.empty())
                {
                    asyncResp->res.jsonValue["BitRate"] = BitRate;
                }
                if (!DataBits.empty())
                {
                    asyncResp->res.jsonValue["DataBits"] = DataBits;
                }
                getSerialServiceState(asyncResp, SerialName);

                if (StopBits)
                {
                    asyncResp->res.jsonValue["StopBits"] = "2";
                }
                else
                {
                    asyncResp->res.jsonValue["StopBits"] = "1";
                }

                if (SwControl == true)
                {
                    asyncResp->res.jsonValue["FlowControl"] = "Software";
                }
                else if (HwControl == true)
                {
                    asyncResp->res.jsonValue["FlowControl"] = "Hardware";
                }
                else
                {
                    asyncResp->res.jsonValue["FlowControl"] = "None";
                }
                
                if (!Parity_enable)
                {
                    asyncResp->res.jsonValue["Parity"] = "None";
                }
                else if (Parity_enable && Parity_Odd)
                {
                    asyncResp->res.jsonValue["Parity"] = "Odd";
                }
                else if (Parity_enable && !Parity_Odd)
                {
                    asyncResp->res.jsonValue["Parity"] = "Even";
                }
                
                if (resourceName != NULL && resourceName[0] != '\0')
                {
		            std::string name = std::string(resourceName);
                    std::filesystem::path logDir = "/var/log";
                    for (const std::filesystem::directory_entry& dirEnt :
                         std::filesystem::directory_iterator(logDir))
                    {
                        std::string filename = dirEnt.path().filename();
                        if (boost::starts_with(filename,
                                               obmcConsoleLogFilePrefix) &&
                            !boost::ends_with(
                                filename, obmcConsoleLogFileRotatedSuffix) &&
                            filename.find(name) != std::string::npos)
                        {
                            nlohmann::json& console =
                                asyncResp->res.jsonValue["Oem"]["ConsoleLog"];
                            console["@odata.id"] =
                                "/redfish/v1/Managers/bmc/SerialInterfaces/" +
                                name + "/ConsoleLog";
                            console["Name"] = name;
                            std::string rotateFileName =
                                filename + obmcConsoleLogFileRotatedSuffix;
                            std::ifstream logStream(logDir / rotateFileName);
                            std::uintmax_t totalSize = 0;
                            if (std::filesystem::exists(logDir /
                                                        rotateFileName))
                            {
                                totalSize += std::filesystem::file_size(
                                    logDir / rotateFileName);
                            }

                            if (std::filesystem::exists(logDir / filename))
                            {
                                totalSize += std::filesystem::file_size(
                                    logDir / filename);
                            }
                            else
                            {
                                messages::internalError(asyncResp->res);
                                asyncResp->res.jsonValue["error"]["message"] =
                                    "Failed to open " + name + "'s log files";
                                return;
                            }
                            console["OutputSize"] = totalSize;
                            std::filesystem::file_time_type ftime =
                                std::filesystem::last_write_time(logDir /
                                                                 filename);
                            std::time_t cftime =
                                std::chrono::system_clock::to_time_t(
                                    std::chrono::file_clock::to_sys(ftime));
                            std::string timeStr =
                                redfish::time_utils::getDateTimeStdtime(cftime);
                            console["LastUpdated"] = timeStr;
                            break;
                        }
                    }
                }
                break;
            }
        }
                
        if (check == false)
        {
            // FIX: Check if this is IPMI-SOL on unsupported platforms
            #if (BMCWEB_ARBEL_NUVOTON_MACRO)
            if (SerialName == "IPMI-SOL")
            {
                messages::resourceNotFound(asyncResp->res, "SerialInterface", SerialName);
                return;
            }
            #endif
            
            messages::resourceNotFound(asyncResp->res, "SerialInterface", SerialName);
            return;
        }
    };

    std::string targetConsoleInterface =
        std::string(sshConsoleConfigurationIface) + "." + SerialName;
    crow::connections::systemBus->async_method_call(
        [asyncResp, targetConsoleInterface, fillSerialResponseCb](
            const boost::system::error_code ec,
            const dbus::utility::MapperGetSubTreeResponse& subtree) {
        if (ec)
        {
            messages::internalError(asyncResp->res);
            return;
        }
        if (subtree.empty())
        {
            fillSerialResponseCb("");
        }
        else
        {
            if (subtree.size() > 1)
            {
                messages::internalError(asyncResp->res);
                return;
            }

            auto objectPath = subtree[0].first;
            crow::connections::systemBus->async_method_call(
                [asyncResp, fillSerialResponseCb](
                    const boost::system::error_code ec2,
                    const std::variant<std::string>& variantName) {
                if (ec2)
                {
                    messages::internalError(asyncResp->res);
                    return;
                }
		const std::string* foundName = 
		    std::get_if<std::string>(&(variantName));
                if (foundName == nullptr)
                {
                    messages::internalError(asyncResp->res);
                    return;
                }
                else
                {
                    fillSerialResponseCb(foundName->c_str());
                }
                },
                "xyz.openbmc_project.EntityManager", objectPath.c_str(),
                "org.freedesktop.DBus.Properties", "Get",
                targetConsoleInterface.c_str(), "Name");
        }
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTree", "/", 0,
        std::array<const char*, 1>{targetConsoleInterface.c_str()});
}


static inline void findSerialDevice(std::vector<std::string>&tokens)
{
    // Use the filesystem lib to search for ttyS* at /dev instead of find shellCmd,
    // to resolve the special character checking failure in safe_popen.
    std::filesystem::path devDir = "/dev";
    std::regex pattern("^ttyS[0-9]+$"); // Matches "ttyS*"
    for (const std::filesystem::directory_entry& entry :
        std::filesystem::directory_iterator(devDir))
    {
        if (entry.is_character_file()) { // Ensures it's a character device
            std::string filename = entry.path().filename().string();
            if (std::regex_match(filename, pattern)) {
                tokens.push_back(filename.c_str());
            }
        }
    }
    return;
}
static inline void getSerialServiceState(const std::shared_ptr<bmcweb::AsyncResp>& aResp, const std::string& token)
{
    std::string serviceName = "obmc-console@" + token + ".service";
    crow::connections::systemBus->async_method_call(
        [aResp](const boost::system::error_code ec,
                const std::vector<std::tuple<std::string, uint32_t, std::string>>& result) {
        // Check if the response array is empty
        if (ec || result.empty())
        {
            aResp->res.jsonValue["InterfaceEnabled"] = false;
            return;
        }
        // ttyS process found
        aResp->res.jsonValue["InterfaceEnabled"] = true;
        },
    "org.freedesktop.systemd1",         // Service
    "/org/freedesktop/systemd1",        // Object
    "org.freedesktop.systemd1.Manager", // Interface
    "GetUnitProcesses",                 // Method
    serviceName);
}
inline void
    requestRoutesManagerSerialInterface(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Managers/<str>/SerialInterfaces/")
        .privileges(redfish::privileges::getSerialInterfaceCollection)
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& managerId) {
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }

                if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
                {
                    messages::resourceNotFound(asyncResp->res, "Manager", 
		    				managerId);
                    return;
                }
                
                asyncResp->res.jsonValue["@odata.id"] = boost::urls::format(
                    "/redfish/v1/Managers/{}/SerialInterfaces/",
                    BMCWEB_REDFISH_MANAGER_URI_NAME);
                asyncResp->res.jsonValue["@odata.type"] =
                    "#SerialInterfaceCollection.SerialInterfaceCollection";
		// asyncResp->res.jsonValue["Id"] =
                //   BMCWEB_REDFISH_MANAGER_URI_NAME;
                asyncResp->res.jsonValue["Name"] = 
			"Serial Interface Collection";
                asyncResp->res.jsonValue["Description"] =
                    "Collection of Serial Interfaces for this System";
                
                // Initialize the members array
                nlohmann::json::array_t members;
               
                #if (!BMCWEB_ARBEL_NUVOTON_MACRO)
                nlohmann::json& bmc = members.emplace_back();
                bmc["@odata.id"] = boost::urls::format(
                    "/redfish/v1/Managers/{}/SerialInterfaces/IPMI-SOL",
                    BMCWEB_REDFISH_MANAGER_URI_NAME);
                #endif

                // Find and add serial devices 
                std::vector<std::string> tokens;
                findSerialDevice(tokens);
                for (const auto& token : tokens)
                {
                    nlohmann::json& serialInterface = members.emplace_back();
                    serialInterface["@odata.id"] = boost::urls::format(
                        "/redfish/v1/Managers/{}/SerialInterfaces/{}",
                        BMCWEB_REDFISH_MANAGER_URI_NAME, token);
                }
                
                // Set the members array and count
                asyncResp->res.jsonValue["Members"] = members;
                asyncResp->res.jsonValue["Members@odata.count"] = members.size();
            });

    BMCWEB_ROUTE(app, "/redfish/v1/Managers/<str>/SerialInterfaces/<str>")
        .privileges(redfish::privileges::getSerialInterface)
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& managerId, const std::string& SerialName) {
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }

                if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
                {
                    messages::resourceNotFound(asyncResp->res, "Manager",
                                               managerId);
                    return;
                }
                
                asyncResp->res.clearHeader(boost::beast::http::field::allow);

                handleManagerSerialInterfaceGet(app, req, asyncResp, SerialName);
            });

    BMCWEB_ROUTE(app, "/redfish/v1/Managers/<str>/SerialInterfaces/<str>/")
    .privileges(redfish::privileges::patchSerialInterface)
    .methods(boost::beast::http::verb::patch)(
        [&app](const crow::Request& req,
               const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
               const std::string& managerId, const std::string& SerialName) {
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    
    // Fix: Check managerId, not SerialName
    if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
    {
        messages::resourceNotFound(asyncResp->res, "Manager", managerId);
        return;
    }
    
    asyncResp->res.clearHeader(boost::beast::http::field::allow);
    

    #if (!BMCWEB_ARBEL_NUVOTON_MACRO)
    if (SerialName == "IPMI-SOL")
    {
        asyncResp->res.addHeader("Allow", "GET, PATCH");
        std::optional<std::string> bitRate;
        std::optional<std::string> vId;
        if (!json_util::readJsonPatch(req, asyncResp->res, "BitRate", bitRate, "Id", vId))
        {
            return;
        }
        if (vId)
        {
            messages::propertyNotWritable(asyncResp->res, "Id");
            asyncResp->res.result(boost::beast::http::status::bad_request);
            return;
        }
        if (bitRate)
        {
            if (*bitRate == "9600" || *bitRate == "19200" ||
                *bitRate == "38400" || *bitRate == "57600" ||
                *bitRate == "115200")
            {
                uint64_t baudRate = std::stoull(*bitRate);
                sdbusplus::asio::setProperty(
                    *crow::connections::systemBus, consoleDbusService,
                    consoleDbusObject, consoleDbusInterface, "Baud", baudRate,
                    [asyncResp, SerialName](const boost::system::error_code& ec) {
                        if (ec)
                        {
                            BMCWEB_LOG_DEBUG("Unable to set BitRate");
                            messages::internalError(asyncResp->res);
                            return;
                        }
                        messages::success(asyncResp->res);
                    });
            }
            else
            {
                messages::propertyValueNotInList(asyncResp->res, *bitRate, "BitRate");
                return;
            }
        }
        return;  // Important: return after handling IPMI-SOL
    }
    #else
    // FIX: For unsupported platforms, return error for IPMI-SOL
    if (SerialName == "IPMI-SOL")
    {
        messages::resourceNotFound(asyncResp->res, "SerialInterface", SerialName);
        return;
    }
    #endif
    
    // Validate that the serial device exists before processing PATCH
    if (!isSerialDeviceExists(SerialName))
    {
        messages::resourceNotFound(asyncResp->res, "SerialInterfaces", SerialName);
        return;
    }

    asyncResp->res.addHeader("Allow", "GET, PATCH");

    std::optional<std::string> bitrate;
    std::optional<std::string> databits;
    std::optional<std::string> flowcontrol;
    std::optional<std::string> parity;
    std::optional<std::string> stopbits;
    std::optional<bool> interfaceEnabled;
    std::optional<std::string> id;

    if (!json_util::readJsonPatch(
        req, asyncResp->res, "BitRate", bitrate, "DataBits", databits,
        "FlowControl", flowcontrol, "InterfaceEnabled",
        interfaceEnabled, "Parity", parity, "StopBits", stopbits,
        "Id", id))
    {
        return;
    }
    
    // Check for read-only properties and return propertyNotWritable error
    if (id)
    {
        messages::propertyNotWritable(asyncResp->res, "Id");
        return;
    }
 
    // Fix: Use serialName instead of undefined serialName
    char cmd[150];
    snprintf(cmd, sizeof(cmd), "stty -F /dev/%s ", SerialName.c_str());

        if (bitrate)
        {
            if (*bitrate == "1200" || *bitrate == "2400" || *bitrate == "4800" ||
                *bitrate == "9600" || *bitrate == "19200" || *bitrate == "38400" ||
                *bitrate == "57600" || *bitrate == "115200" || *bitrate == "230400")
            {
                sprintf(cmd + strlen(cmd), "ispeed %s ospeed %s ",
                        bitrate->c_str(), bitrate->c_str());
            }
            else
            {
                messages::propertyValueNotInList(asyncResp->res, *bitrate, "BitRate");
                return;
            }
        }


        if (databits)
        {
            if (*databits >= "5" && *databits <= "8")
            {
                sprintf(cmd + strlen(cmd), "cs%s ", databits->c_str());
            }
            else
            {
                messages::propertyValueNotInList(asyncResp->res, *databits, "DataBits");
                return;
            }
        }
        
        if (flowcontrol)
        {
            if (*flowcontrol == "Software")
            {
                sprintf(cmd + strlen(cmd), "ixon ");
            }
            else if (*flowcontrol == "Hardware")
            {
                sprintf(cmd + strlen(cmd), "crtscts -ixon ");
            }
            else if (*flowcontrol == "None")
            {
                sprintf(cmd + strlen(cmd), "-crtscts -ixon ");
            }
            else
            {
                messages::propertyValueNotInList(asyncResp->res, *flowcontrol, "FlowControl");
                return;
            }
        }
        
        if (interfaceEnabled)
        {
            // If trying to enable, check condition result
            std::string serviceName = "obmc-console@" + SerialName + ".service";
            std::string checkCmd = "systemctl show " + serviceName + " --property=ConditionResult --value";
            std::string conditionResult;
            char buffer[128];

            FILE* condPipe = safe_popen(checkCmd.c_str(), "r");
            if (condPipe != nullptr)
            {
                if (fgets(buffer, sizeof(buffer), condPipe) != nullptr)
                {
                    conditionResult = buffer;
                    conditionResult.erase(conditionResult.find_last_not_of(" \n\r\t") + 1);
                }
                pclose(condPipe);
            }
            
            // If condition check failed and user tries to enable, return error
            if (!conditionResult.empty() && conditionResult == "no")
            {
                BMCWEB_LOG_ERROR("Cannot start {} - unmet condition check", serviceName);
                messages::propertyValueExternalConflict(asyncResp->res, 
                        "InterfaceEnabled",
                        SerialName);
                return;
            }
           
            // Check current service status using systemctl is-active
            std::string statusCmd = "systemctl is-active " + serviceName + " 2>/dev/null";
            int currentStatus = std::system(statusCmd.c_str());
            bool isCurrentlyActive = (currentStatus == 0);
            
            // Check if service is already in desired state
            if ((*interfaceEnabled && isCurrentlyActive) || 
                (!(*interfaceEnabled) && !isCurrentlyActive))
            {
                BMCWEB_LOG_DEBUG("Service {} is already in the desired state, no operation needed", serviceName);
                messages::noOperation(asyncResp->res);
                return;
            }
                
            // Execute the start/stop command
            char enableCmd[100];
            if (*interfaceEnabled)
            {
                snprintf(enableCmd, sizeof(enableCmd), 
                        "systemctl start obmc-console@%s.service", SerialName.c_str());
            }
            else
            {
                snprintf(enableCmd, sizeof(enableCmd), 
                        "systemctl stop obmc-console@%s.service", SerialName.c_str());
            }
            int result = safe_system(enableCmd);
            if (result != 0)
            {
                BMCWEB_LOG_ERROR("Failed to {} service obmc-console@{}.service. Command failed with exit code: {}", 
                                (*interfaceEnabled ? "start" : "stop"), SerialName, result);
                messages::internalError(asyncResp->res);
                return;
            }
        }        
        
        if (parity)
        {
            if (*parity == "None")
            {
                sprintf(cmd + strlen(cmd), "-parenb ");
            }
            else if (*parity == "Odd")
            {
                sprintf(cmd + strlen(cmd), "parenb parodd ");
            }
            else if (*parity == "Even")
            {
                sprintf(cmd + strlen(cmd), "parenb -parodd ");
            }
            else
            {
                messages::propertyValueNotInList(asyncResp->res, *parity, "Parity");
                return;
            }
        }
        
        if (stopbits)
        {
            if (*stopbits == "1")
            {
                sprintf(cmd + strlen(cmd), "-cstopb ");
            }
            else if (*stopbits == "2")
            {
                sprintf(cmd + strlen(cmd), "cstopb ");
            }
            else
            {
                messages::propertyValueNotInList(asyncResp->res, *stopbits, "StopBits");
                return;
            }
        }
        
        int result = safe_system(cmd);
        (void)result;
        if (result != 0)
        {
            BMCWEB_LOG_ERROR("Failed to configure serial port {}. stty command failed with exit code: {}", 
                            SerialName, result);
            messages::internalError(asyncResp->res);
            return;
        }
        // Fix: Provide success response
	asyncResp->res.result(boost::beast::http::status::no_content);
    });

        // Handle POST, PUT, DELETE methods - return 404 if resource doesn't exist, 405 if it does
    BMCWEB_ROUTE(app, "/redfish/v1/Managers/<str>/SerialInterfaces/<str>/")
        .privileges(redfish::privileges::getSerialInterface)
        .methods(boost::beast::http::verb::post, boost::beast::http::verb::put, 
                 boost::beast::http::verb::delete_)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& managerId, const std::string& SerialName) {
                asyncResp->res.clearHeader(boost::beast::http::field::allow);
                
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }
                if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
                {
                    messages::resourceNotFound(asyncResp->res, "Manager", managerId);
                    return;
                }
                
                // Check if this is IPMI-SOL
                #if (!BMCWEB_ARBEL_NUVOTON_MACRO)
                if (SerialName == "IPMI-SOL")
                {
                    // Resource exists, but method not allowed
                    asyncResp->res.addHeader("Allow", "GET, PATCH");
                    messages::operationNotAllowed(asyncResp->res);
                    return;
                }
                #else
                if (SerialName == "IPMI-SOL")
                {
                    // Resource doesn't exist on this platform
                    messages::resourceNotFound(asyncResp->res, "SerialInterface", SerialName);
                    return;
                }
                #endif
                
                // Check if the serial device exists
                if (!isSerialDeviceExists(SerialName))
                {
                    // Return 404 for non-existent resources
                    messages::resourceNotFound(asyncResp->res, "SerialInterfaces", SerialName);
                    return;
                }
                
                // Resource exists but method not allowed
                asyncResp->res.addHeader("Allow", "GET, PATCH");
                messages::operationNotAllowed(asyncResp->res);
    });
}

inline void requestRoutesSerialConsoleLog(App& app)
{
    BMCWEB_ROUTE(
        app, "/redfish/v1/Managers/<str>/SerialInterfaces/<str>/ConsoleLog/")
        .privileges(redfish::privileges::getSerialInterface)
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& /*req*/,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& managerId,
                   const std::string& resourceName) {
                
                if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
                {
                    messages::resourceNotFound(asyncResp->res, "Manager", managerId);
                    return;
                }
                std::filesystem::path logDir = "/var/log";
                for (const std::filesystem::directory_entry& dirEnt :
                     std::filesystem::directory_iterator(logDir))
                {
                    std::string filename = dirEnt.path().filename();
                    if (boost::starts_with(filename, obmcConsoleLogFilePrefix) &&
                        !boost::ends_with(filename, obmcConsoleLogFileRotatedSuffix) &&
                        filename.find(resourceName) != std::string::npos)
                    {
                        asyncResp->res.addHeader("Content-Type", "text/plain");
                        std::string contentDispositionParam =
                            "attachment; filename=\"" + resourceName + "\"";
                        asyncResp->res.addHeader("Content-Disposition",
                                                 contentDispositionParam);
                        
                        // Build the entire response as one string
                        std::string responseContent;
                        
                        std::string rotateFileName =
                            filename + obmcConsoleLogFileRotatedSuffix;
                        std::ifstream logStream(logDir / rotateFileName);
                        if (logStream.is_open())
                        {
                            std::string line;
                            while (std::getline(logStream, line))
                            {
                                responseContent += line + "\n";
                            }
                            logStream.close();
                        }

                        logStream.open(logDir / filename, std::ifstream::in);
                        if (!logStream.is_open())
                        {
                            messages::internalError(asyncResp->res);
                            asyncResp->res.jsonValue["error"]["message"] =
                                "Failed to open " + resourceName + "'s log files";
                            return;
                        }
                        else
                        {
                            std::string line;
                            while (std::getline(logStream, line))
                            {
                                responseContent += line + "\n";
                            }
                            logStream.close();
                        }
                        
                        // Write the entire content at once
                        asyncResp->res.write(std::move(responseContent));
                        return;
                    }
                }

                messages::resourceNotFound(asyncResp->res,
                                           "#SerialInterfaces.v1_1_5.SerialInterfaces",
                                           resourceName);
                return;
            });
}

} // namespace redfish
