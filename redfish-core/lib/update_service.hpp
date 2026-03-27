// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
// SPDX-FileCopyrightText: Copyright 2018 Intel Corporation
#pragma once

#include "bmcweb_config.h"

#include "app.hpp"
#include "dbus_utility.hpp"
#include "error_messages.hpp"
#include "generated/enums/update_service.hpp"
#include "multipart_parser.hpp"
#include "ossl_random.hpp"
#include "query.hpp"
#include "registries/privilege_registry.hpp"
#include "task.hpp"
#include "task_messages.hpp"
#include "update_service_header.hpp"
#include "utils/collection.hpp"
#include "utils/dbus_utils.hpp"
#include "utils/json_utils.hpp"
#include "utils/sw_utils.hpp"

#include <sys/mman.h>

#include <boost/system/error_code.hpp>
#include <boost/url/format.hpp>
#include <sdbusplus/asio/property.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/unpack_properties.hpp>

#include <array>
#include <cstddef>
#include <filesystem>
#include <functional>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace redfish
{
// params for multiple firmware targets
inline std::vector<std::string> httpPushUriTargets;
inline bool httpPushUriTargetBusy = false;
// Match signals added on software path
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static std::unique_ptr<sdbusplus::bus::match_t> fwUpdateMatcher;
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static std::unique_ptr<sdbusplus::bus::match_t> fwUpdateErrorMatcher;
// Only allow one update at a time
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static bool fwUpdateInProgress = false;
// Timer for software available
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static std::unique_ptr<boost::asio::steady_timer> fwAvailableTimer;
static constexpr const char* versionIntf =
    "xyz.openbmc_project.Software.Version";
static constexpr const char* activationIntf =
    "xyz.openbmc_project.Software.Activation";
static constexpr const char* reqActivationPropName = "RequestedActivation";
static constexpr const char* reqActivationsActive =
    "xyz.openbmc_project.Software.Activation.RequestedActivations.Active";
static constexpr const char* reqActivationsStandBySpare =
    "xyz.openbmc_project.Software.Activation.RequestedActivations.StandbySpare";
static constexpr const char* activationsStandBySpare =
    "xyz.openbmc_project.Software.Activation.Activations.StandbySpare";

inline bool isPldmService = false;
inline bool isIntelservice = false;

using PropertyValue = std::variant<uint8_t, uint16_t, uint64_t, std::string,
                                   std::vector<std::string>, bool>;

struct MemoryFileDescriptor
{
    int fd = -1;

    explicit MemoryFileDescriptor(const std::string& filename) :
        fd(memfd_create(filename.c_str(), 0))
    {}

    MemoryFileDescriptor(const MemoryFileDescriptor&) = default;
    MemoryFileDescriptor(MemoryFileDescriptor&& other) noexcept : fd(other.fd)
    {
        other.fd = -1;
    }
    MemoryFileDescriptor& operator=(const MemoryFileDescriptor&) = delete;
    MemoryFileDescriptor& operator=(MemoryFileDescriptor&&) = default;

    ~MemoryFileDescriptor()
    {
        if (fd != -1)
        {
            close(fd);
        }
    }

    bool rewind() const
    {
        if (lseek(fd, 0, SEEK_SET) == -1)
        {
            BMCWEB_LOG_ERROR("Failed to seek to beginning of image memfd");
            return false;
        }
        return true;
    }
};

inline void cleanUp()
{
    fwUpdateInProgress = false;
    fwUpdateMatcher = nullptr;
    fwUpdateErrorMatcher = nullptr;
}

#if defined(ONETREE_EGS) || defined(ONETREE_BHS) ||                            \
    defined(ONETREE_ASPEED_SDK_LAYER) || defined(ONETREE_EVB_AST2600)
inline const PropertyValue getApplyTimePropertyValue(
    const std::string& servicePath, const std::string& objectName,
    const std::string& interface, const std::string& property_Name)
{
    PropertyValue value{};
    auto b = sdbusplus::bus::new_default_system();
    auto method = b.new_method_call(servicePath.c_str(), objectName.c_str(),
                                    "org.freedesktop.DBus.Properties", "Get");

    method.append(interface, property_Name);
    auto reply = b.call(method);
    reply.read(value);
    return value;
}
#endif

inline void activateImage(const std::string& objPath,
                          const std::string& service,
                          const std::vector<std::string>& imgUriTargets)
{
    BMCWEB_LOG_DEBUG("Activate image for {} {}", objPath, service);
#if defined(ONETREE_EGS) || defined(ONETREE_BHS) ||                            \
    defined(ONETREE_ASPEED_SDK_LAYER) || defined(ONETREE_EVB_AST2600)
    // If targets is empty, it will apply to the active.
    if (!imgUriTargets.empty())
    {
        // TODO: Now we support only one target becuase software-manager
        // code support one activation per object. It will be enhanced
        // to multiple targets for single image in future. For now,
        // consider first target alone.
        for (const auto& imgUri : imgUriTargets)
        {
            crow::connections::systemBus->async_method_call(
                [objPath, service, imgTarget{imgUri}](
                    const boost::system::error_code ec,
                    const dbus::utility::MapperGetSubTreeResponse& subtree) {
                    if (ec || !subtree.size())
                    {
                        return;
                    }
                    for (const auto& [invObjPath, invDict] : subtree)
                    {
                        std::size_t idPos = invObjPath.rfind("/");
                        if ((idPos == std::string::npos) ||
                            ((idPos + 1) >= invObjPath.size()))
                        {
                            BMCWEB_LOG_DEBUG("Can't parse firmware ID!!");
                            return;
                        }
                        std::string swId = invObjPath.substr(idPos + 1);

                        if (swId != imgTarget)
                        {
                            continue;
                        }

                        if (invDict.size() < 1)
                        {
                            continue;
                        }
                        BMCWEB_LOG_DEBUG("Image target matched with object {}",
                                         invObjPath);
#ifdef ONETREE_INTEL_PFR
                        crow::connections::systemBus->async_method_call(
                            [invObjPath, objPath,
                             service](const boost::system::error_code ec2,
                                      const std::variant<std::string> value) {
                                if (ec2)
                                {
                                    BMCWEB_LOG_DEBUG(
                                        "Error in querying activation value");
                                    // not all fwtypes are updateable,
                                    // this is ok
                                    return;
                                }
                                std::string activationValue =
                                    std::get<std::string>(value);
                                BMCWEB_LOG_DEBUG("Activation Value: {}",
                                                 activationValue);
                                std::string reqActivation =
                                    reqActivationsActive;
                                if (activationValue == activationsStandBySpare)
                                {
                                    reqActivation = reqActivationsStandBySpare;
                                }
                                BMCWEB_LOG_DEBUG(
                                    "Setting RequestedActivation value as {} for {} {}",
                                    reqActivation, service, objPath);
                                crow::connections::systemBus->async_method_call(
                                    [](const boost::system::error_code ec3) {
                                        if (ec3)
                                        {
                                            BMCWEB_LOG_DEBUG(
                                                "RequestedActivation failed: ec = {}",
                                                ec3);
                                        }
                                        return;
                                    },
                                    service, objPath,
                                    "org.freedesktop.DBus.Properties", "Set",
                                    activationIntf, reqActivationPropName,
                                    std::variant<std::string>(reqActivation));
#else
                        crow::connections::systemBus->async_method_call(
                            [invObjPath,
                             service](const boost::system::error_code ec2,
                                      const std::variant<std::string> value) {
                                if (ec2)
                                {
                                    BMCWEB_LOG_DEBUG(
                                        "Error in querying activation value");
                                    // not all fwtypes are updateable,
                                    // this is ok
                                    return;
                                }
                                std::string activationValue =
                                    std::get<std::string>(value);
                                BMCWEB_LOG_DEBUG("Activation Value: {}",
                                                 activationValue);
                                std::string reqActivation =
                                    reqActivationsActive;
                                if (activationValue == activationsStandBySpare)
                                {
                                    reqActivation = reqActivationsStandBySpare;
                                }
                                BMCWEB_LOG_DEBUG(
                                    "Setting RequestedActivation value as {} for {} {}",
                                    reqActivation, service, invObjPath);
                                crow::connections::systemBus->async_method_call(
                                    [](const boost::system::error_code ec3) {
                                        if (ec3)
                                        {
                                            BMCWEB_LOG_DEBUG(
                                                "RequestedActivation failed: ec = {}",
                                                ec3);
                                        }
                                        return;
                                    },
                                    service, invObjPath,
                                    "org.freedesktop.DBus.Properties", "Set",
                                    activationIntf, reqActivationPropName,
                                    std::variant<std::string>(reqActivation));
#endif
                            },
                            invDict[0].first,
                            "/xyz/openbmc_project/software/" + imgTarget,
                            "org.freedesktop.DBus.Properties", "Get",
                            activationIntf, "Activation");
                    }
                },
                "xyz.openbmc_project.ObjectMapper",
                "/xyz/openbmc_project/object_mapper",
                "xyz.openbmc_project.ObjectMapper", "GetSubTree", "/",
                static_cast<int32_t>(0),
                std::array<const char*, 1>{versionIntf});
        }
    }
    crow::connections::systemBus->async_method_call(
        [](const boost::system::error_code errorCode) {
            if (errorCode)
            {
                BMCWEB_LOG_DEBUG("RequestedActivation failed: error_code = {}",
                                 errorCode);
                BMCWEB_LOG_DEBUG("error msg = {}", errorCode.message());
            }
        },
        service, objPath, "org.freedesktop.DBus.Properties", "Set",
        activationIntf, reqActivationPropName,
        std::variant<std::string>(reqActivationsActive));
    return;
#else
    if (imgUriTargets.size() == 0)
    {
        crow::connections::systemBus->async_method_call(
            [](const boost::system::error_code errorCode) {
                if (errorCode)
                {
                    BMCWEB_LOG_DEBUG(
                        "RequestedActivation failed: error_code = {}",
                        errorCode);
                    BMCWEB_LOG_DEBUG("error msg = {}", errorCode.message());
                }
            },
            service, objPath, "org.freedesktop.DBus.Properties", "Set",
            activationIntf, reqActivationPropName,
            std::variant<std::string>(reqActivationsActive));
        return;
    }

    // TODO: Now we support only one target becuase software-manager
    // code support one activation per object. It will be enhanced
    // to multiple targets for single image in future. For now,
    // consider first target alone.
    crow::connections::systemBus->async_method_call(
        [objPath, service, imgTarget{imgUriTargets[0]}](
            const boost::system::error_code ec,
            const dbus::utility::MapperGetSubTreeResponse& subtree) {
            if (ec || !subtree.size())
            {
                return;
            }

            for (const auto& [invObjPath, invDict] : subtree)
            {
                std::size_t idPos = invObjPath.rfind("/");
                if ((idPos == std::string::npos) ||
                    ((idPos + 1) >= invObjPath.size()))
                {
                    BMCWEB_LOG_DEBUG("Can't parse firmware ID!!");
                    return;
                }
                std::string swId = invObjPath.substr(idPos + 1);

                if (swId != imgTarget)
                {
                    continue;
                }

                if (invDict.size() < 1)
                {
                    continue;
                }
                BMCWEB_LOG_DEBUG("Image target matched with object {}",
                                 invObjPath);
                crow::connections::systemBus->async_method_call(
                    [objPath, service](const boost::system::error_code ec2,
                                       const std::variant<std::string> value) {
                        if (ec2)
                        {
                            BMCWEB_LOG_DEBUG(
                                "Error in querying activation value");
                            // not all fwtypes are updateable,
                            // this is ok
                            return;
                        }
                        std::string activationValue =
                            std::get<std::string>(value);
                        BMCWEB_LOG_DEBUG("Activation Value: {}",
                                         activationValue);
                        std::string reqActivation = reqActivationsActive;
                        if (activationValue == activationsStandBySpare)
                        {
                            reqActivation = reqActivationsStandBySpare;
                        }
                        BMCWEB_LOG_DEBUG(
                            "Setting RequestedActivation value as {} for {} {}",
                            reqActivation, service, objPath);
                        crow::connections::systemBus->async_method_call(
                            [](const boost::system::error_code ec3) {
                                if (ec3)
                                {
                                    BMCWEB_LOG_DEBUG(
                                        "RequestedActivation failed: ec = {}",
                                        ec3);
                                }
                                return;
                            },
                            service, objPath, "org.freedesktop.DBus.Properties",
                            "Set", activationIntf, reqActivationPropName,
                            std::variant<std::string>(reqActivation));
                    },
                    invDict[0].first,
                    "/xyz/openbmc_project/software/" + imgTarget,
                    "org.freedesktop.DBus.Properties", "Get", activationIntf,
                    "Activation");
            }
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTree", "/",
        static_cast<int32_t>(0), std::array<const char*, 1>{versionIntf});
#endif
}

inline bool handleCreateTask(const boost::system::error_code& ec2,
                             sdbusplus::message_t& msg,
                             const std::shared_ptr<task::TaskData>& taskData)
{
    if (ec2)
    {
        return task::completed;
    }

    std::string iface;
    dbus::utility::DBusPropertiesMap values;

    std::string index = std::to_string(taskData->index);
    msg.read(iface, values);

    if (iface == "xyz.openbmc_project.Software.Activation")
    {
        const std::string* state = nullptr;
        for (const auto& property : values)
        {
            if (property.first == "Activation")
            {
                state = std::get_if<std::string>(&property.second);
                if (state == nullptr)
                {
                    taskData->messages.emplace_back(messages::internalError());
                    return task::completed;
                }
            }
        }

        if (state == nullptr)
        {
            return !task::completed;
        }

        if (state->ends_with("Invalid") || state->ends_with("Failed"))
        {
            taskData->state = "Exception";
            taskData->status = "Warning";
            taskData->messages.emplace_back(messages::taskAborted(index));
            return task::completed;
        }

        if (state->ends_with("Staged"))
        {
#ifdef ONETREE_INTEL_PFR

            BMCWEB_LOG_DEBUG("Task state = Complete");
            taskData->messages.emplace_back(messages::taskCompletedOK(index));
            taskData->state = "Completed";
            return task::completed;

#else
            taskData->state = "Pending";
            taskData->messages.emplace_back(messages::taskPaused(index));

            // its staged, set a long timer to
            // allow them time to complete the
            // update (probably cycle the
            // system) if this expires then
            // task will be canceled
            taskData->extendTimer(std::chrono::hours(5));
            return !task::completed;
#endif
        }

        if (state->ends_with("Active"))
        {
            taskData->messages.emplace_back(messages::taskCompletedOK(index));
            taskData->state = "Completed";
            return task::completed;
        }
    }
    else if (iface == "xyz.openbmc_project.Software.ActivationProgress")
    {
        const uint8_t* progress = nullptr;
        for (const auto& property : values)
        {
            if (property.first == "Progress")
            {
                progress = std::get_if<uint8_t>(&property.second);
                if (progress == nullptr)
                {
                    taskData->messages.emplace_back(messages::internalError());
                    return task::completed;
                }
            }
        }

        if (progress == nullptr)
        {
            return !task::completed;
        }
        taskData->percentComplete = *progress;
        taskData->messages.emplace_back(
            messages::taskProgressChanged(index, *progress));

        // if we're getting status updates it's
        // still alive, update timer
        taskData->extendTimer(std::chrono::minutes(BMCWEB_UPDATE_TIMEOUT));
    }
#if defined(ONETREE_EGS) || defined(ONETREE_BHS) ||                            \
    defined(ONETREE_ASPEED_SDK_LAYER) || defined(ONETREE_EVB_AST2600)

    else if (iface == "xyz.openbmc_project.Common.Task")
    {
        const std::string* taskState = nullptr;
        for (const auto& property : values)
        {
            if (property.first == "Status")
            {
                taskState = std::get_if<std::string>(&property.second);
                if (taskState == nullptr)
                {
                    taskData->messages.emplace_back(messages::internalError());
                    return task::completed;
                }
            }
        }

        if (taskState == nullptr)
        {
            return !task::completed;
        }

        if (taskState->ends_with("Cancelled"))
        {
            taskData->state = "Cancelled";
            taskData->status = "Warning";
            taskData->messages.emplace_back(messages::taskCancelled(index));
            return task::completed;
        }

        if (taskState->ends_with("New"))
        {
            taskData->state = "Pending";
            taskData->messages.emplace_back(messages::taskPaused(index));
            auto startTimeout = std::get<uint64_t>(getApplyTimePropertyValue(
                "xyz.openbmc_project.Settings",
                "/xyz/openbmc_project/software/apply_time",
                "xyz.openbmc_project.Software.ApplyTime",
                "MaintenanceWindowStartTime"));
            auto duration = std::get<uint64_t>(getApplyTimePropertyValue(
                "xyz.openbmc_project.Settings",
                "/xyz/openbmc_project/software/apply_time",
                "xyz.openbmc_project.Software.ApplyTime",
                "MaintenanceWindowDurationInSeconds"));
            // Current BMC Timezone
            const auto current_time = std::chrono::system_clock::to_time_t(
                std::chrono::system_clock::now());

            if ((startTimeout + duration) >
                static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::from_time_t(current_time)
                            .time_since_epoch())
                        .count()))
            {
                auto timeout =
                    (startTimeout + duration) -
                    (static_cast<std::uint64_t>(
                        std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::from_time_t(current_time)
                                .time_since_epoch())
                            .count()));

                taskData->extendTimer(std::chrono::seconds(timeout + (5 * 60)));
                return !task::completed;
            }
        }
    }
#endif
    // as firmware update often results in a
    // reboot, the task  may never "complete"
    // unless it is an error

    return !task::completed;
}

inline void createTask(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                       task::Payload&& payload,
                       const sdbusplus::message::object_path& objPath)
{
    std::shared_ptr<task::TaskData> task = task::TaskData::createTask(
        std::bind_front(handleCreateTask),
        "type='signal',interface='org.freedesktop.DBus.Properties',"
        "member='PropertiesChanged',path='" +
            objPath.str + "'");
    task->startTimer(std::chrono::minutes(5));
    task->populateResp(asyncResp->res);
    task->payload.emplace(std::move(payload));

    if (isIntelservice)
    {
#if defined(ONETREE_EGS) || defined(ONETREE_BHS) ||                            \
    defined(ONETREE_ASPEED_SDK_LAYER) || defined(ONETREE_EVB_AST2600)

        std::vector<uint16_t> vectorTaskId = {
            static_cast<uint16_t>(task->index)};

        // Set the requested image apply time
        sdbusplus::asio::setProperty(
            *crow::connections::systemBus,
            "xyz.openbmc_project.Software.BMC.Updater", objPath.str,
            "xyz.openbmc_project.Common.Task", "TaskId", vectorTaskId,
            [asyncResp](const boost::system::error_code& _ec) {
                if (_ec)
                {
                    BMCWEB_LOG_ERROR("D-Bus responses error: {}", _ec);
                    // messages::internalError(asyncResp->res);
                    return;
                }
                // messages::success(asyncResp->res);
            });

#endif
    }
}

// Note that asyncResp can be either a valid pointer or nullptr. If nullptr
// then no asyncResp updates will occur
inline void softwareInterfaceAdded(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::vector<std::string> imgUriTargets, sdbusplus::message_t& m,
    task::Payload&& payload)
{
    dbus::utility::DBusInterfacesMap interfacesProperties;

    sdbusplus::message::object_path objPath;

    m.read(objPath, interfacesProperties);
    BMCWEB_LOG_DEBUG("Software Interface Added. obj path = {}", objPath.str);

    std::string fwObjPath = objPath.str;
    if (!fwObjPath.empty())
    {
        auto bus = sdbusplus::bus::new_default();
        try
        {
            auto method = bus.new_method_call(
                "xyz.openbmc_project.ObjectMapper",
                "/xyz/openbmc_project/object_mapper",
                "xyz.openbmc_project.ObjectMapper", "GetObject");

            method.append(fwObjPath);
            method.append(std::vector<std::string>{
                "xyz.openbmc_project.Software.Activation"});
            auto reply = bus.call(method);
            std::map<std::string, std::vector<std::string>> objectResponse;
            reply.read(objectResponse);

            for (const auto& [service, ifaces] : objectResponse)
            {
                if (service == "xyz.openbmc_project.pldm")
                {
                    isPldmService = true;
                    break;
                }
                else if (service == "xyz.openbmc_project.Software.BMC.Updater")
                {
                    isIntelservice = true;
                    break;
                }
            }
        }
        catch (const sdbusplus::exception::SdBusError& e)
        {
            std::cerr << "D-Bus error: " << e.what() << std::endl;
            return;
        }
    }

    if (isIntelservice)
    {
#if defined(ONETREE_EGS) || defined(ONETREE_BHS) ||                            \
    defined(ONETREE_ASPEED_SDK_LAYER) || defined(ONETREE_EVB_AST2600)
        std::array<std::string, 1> inface = {
            "xyz.openbmc_project.Software.Version"};

        std::string fwPath = objPath.str;
        if (!fwPath.empty())
        {
            sdbusplus::asio::getProperty<std::string>(
                *crow::connections::systemBus,
                "xyz.openbmc_project.Software.Version", fwPath,
                "xyz.openbmc_project.Software.Version", "Purpose",
                [asyncResp](const boost::system::error_code& ec2,
                            const std::string& imageName) {
                    if (ec2)
                    {
                        BMCWEB_LOG_ERROR("DBUS response error {}", ec2);
                        // messages::internalError(asyncResp->res);
                    }
                    std::vector<std::string> purposeString;
                    std::stringstream ss(imageName);
                    std::string purpose;
                    while (std::getline(ss, purpose, '.'))
                    {
                        purposeString.push_back(purpose);
                    }
                    std::string updatingImage = purposeString.back();
                    asyncResp->res.jsonValue["Oem"]["ImageName"] =
                        updatingImage;
                });
        }
#endif
    }
    for (const auto& interface : interfacesProperties)
    {
        BMCWEB_LOG_DEBUG("interface = {}", interface.first);

        if (interface.first == activationIntf)
        {
            // Retrieve service and activate
            constexpr std::array<std::string_view, 1> interfaces = {
                "xyz.openbmc_project.Software.Activation"};
            dbus::utility::getDbusObject(
                objPath.str, interfaces,
                [objPath, asyncResp, payload(std::move(payload)),
                 imgTargets{imgUriTargets}](
                    const boost::system::error_code& ec,
                    const std::vector<
                        std::pair<std::string, std::vector<std::string>>>&
                        objInfo) mutable {
                    if (ec)
                    {
                        BMCWEB_LOG_DEBUG("error_code = {}", ec);
                        BMCWEB_LOG_DEBUG("error msg = {}", ec.message());
                        if (asyncResp)
                        {
                            messages::internalError(asyncResp->res);
                        }
                        cleanUp();
                        return;
                    }
                    // Ensure we only got one service back
                    if (objInfo.size() != 1)
                    {
                        BMCWEB_LOG_ERROR("Invalid Object Size {}",
                                         objInfo.size());
                        if (asyncResp)
                        {
                            messages::internalError(asyncResp->res);
                        }
                        cleanUp();
                        return;
                    }
                    // cancel timer only when
                    // xyz.openbmc_project.Software.Activation interface
                    // is added
                    fwAvailableTimer = nullptr;

                    activateImage(objPath.str, objInfo[0].first, imgTargets);
                    if (asyncResp)
                    {
                        createTask(asyncResp, std::move(payload), objPath);
                    }
                    fwUpdateInProgress = false;
                });

            break;
        }
    }
}

inline void afterAvailbleTimerAsyncWait(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const boost::system::error_code& ec)
{
    cleanUp();
    if (ec == boost::asio::error::operation_aborted)
    {
        // expected, we were canceled before the timer completed.
        return;
    }
    BMCWEB_LOG_ERROR("Timed out waiting for firmware object being created");
    BMCWEB_LOG_ERROR("FW image may has already been uploaded to server");
    if (ec)
    {
        BMCWEB_LOG_ERROR("Async_wait failed{}", ec);
        return;
    }
    if (asyncResp)
    {
        messages::firmwareUpdateFailed(asyncResp->res);
    }
}

inline void handleUpdateErrorType(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp, const std::string& url,
    const std::string& type)
{
    // NOLINTBEGIN(bugprone-branch-clone)
    if (type == "xyz.openbmc_project.Software.Image.Error.UnTarFailure")
    {
        messages::missingOrMalformedPart(asyncResp->res);
    }
    else if (type ==
             "xyz.openbmc_project.Software.Image.Error.ManifestFileFailure")
    {
        messages::missingOrMalformedPart(asyncResp->res);
    }
    else if (type == "xyz.openbmc_project.Software.Image.Error.ImageFailure")
    {
        messages::missingOrMalformedPart(asyncResp->res);
    }
    else if (type == "xyz.openbmc_project.Software.Version.Error.AlreadyExists")
    {
        messages::resourceAlreadyExists(asyncResp->res, "UpdateService",
                                        "Version", "uploaded version");
    }
    else if (type == "xyz.openbmc_project.Software.Image.Error.BusyFailure")
    {
        messages::serviceTemporarilyUnavailable(asyncResp->res, url);
    }
    else if (type == "xyz.openbmc_project.Software.Version.Error.Incompatible")
    {
        messages::internalError(asyncResp->res);
    }
    else if (type ==
             "xyz.openbmc_project.Software.Version.Error.ExpiredAccessKey")
    {
        messages::internalError(asyncResp->res);
    }
    else if (type ==
             "xyz.openbmc_project.Software.Version.Error.InvalidSignature")
    {
        messages::missingOrMalformedPart(asyncResp->res);
    }
    else if (type ==
                 "xyz.openbmc_project.Software.Image.Error.InternalFailure" ||
             type == "xyz.openbmc_project.Software.Version.Error.HostFile")
    {
        BMCWEB_LOG_ERROR("Software Image Error type={}", type);
        messages::internalError(asyncResp->res);
    }
    else
    {
        // Unrelated error types. Ignored
        BMCWEB_LOG_INFO("Non-Software-related Error type={}. Ignored", type);
        return;
    }
    // NOLINTEND(bugprone-branch-clone)
    // Clear the timer
    fwAvailableTimer = nullptr;
}

inline void afterUpdateErrorMatcher(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp, const std::string& url,
    sdbusplus::message_t& m)
{
    dbus::utility::DBusInterfacesMap interfacesProperties;
    sdbusplus::message::object_path objPath;
    m.read(objPath, interfacesProperties);
    BMCWEB_LOG_DEBUG("obj path = {}", objPath.str);
    for (const std::pair<std::string, dbus::utility::DBusPropertiesMap>&
             interface : interfacesProperties)
    {
        if (interface.first == "xyz.openbmc_project.Logging.Entry")
        {
            for (const std::pair<std::string, dbus::utility::DbusVariantType>&
                     value : interface.second)
            {
                if (value.first != "Message")
                {
                    continue;
                }
                const std::string* type =
                    std::get_if<std::string>(&value.second);
                if (type == nullptr)
                {
                    // if this was our message, timeout will cover it
                    return;
                }
                handleUpdateErrorType(asyncResp, url, *type);
            }
        }
    }
}

// Note that asyncResp can be either a valid pointer or nullptr. If nullptr
// then no asyncResp updates will occur
inline void monitorForSoftwareAvailable(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const crow::Request& req, const std::string& url,
    const std::vector<std::string>& imgUriTargets, int timeoutTimeSeconds = 40)
{
    // Only allow one FW update at a time
    if (fwUpdateInProgress)
    {
        if (asyncResp)
        {
            messages::serviceTemporarilyUnavailable(asyncResp->res, "30");
        }
        return;
    }

    if (req.ioService == nullptr)
    {
        messages::internalError(asyncResp->res);
        return;
    }

    fwAvailableTimer =
        std::make_unique<boost::asio::steady_timer>(*req.ioService);

    fwAvailableTimer->expires_after(std::chrono::seconds(timeoutTimeSeconds));

    fwAvailableTimer->async_wait(
        std::bind_front(afterAvailbleTimerAsyncWait, asyncResp));

    task::Payload payload(req);
    auto callback = [asyncResp, imgTargets{imgUriTargets},
                     payload](sdbusplus::message_t& m) mutable {
        BMCWEB_LOG_DEBUG("Match fired");
        softwareInterfaceAdded(asyncResp, imgTargets, m, std::move(payload));
    };

    fwUpdateInProgress = true;

    fwUpdateMatcher = std::make_unique<sdbusplus::bus::match_t>(
        *crow::connections::systemBus,
        "interface='org.freedesktop.DBus.ObjectManager',type='signal',"
        "member='InterfacesAdded',path='/xyz/openbmc_project/software'",
        callback);

    fwUpdateErrorMatcher = std::make_unique<sdbusplus::bus::match_t>(
        *crow::connections::systemBus,
        "interface='org.freedesktop.DBus.ObjectManager',type='signal',"
        "member='InterfacesAdded',"
        "path='/xyz/openbmc_project/logging'",
        std::bind_front(afterUpdateErrorMatcher, asyncResp, url));
}

inline std::optional<boost::urls::url> parseSimpleUpdateUrl(
    std::string imageURI, std::optional<std::string> transferProtocol,
    crow::Response& res)
{
    if (imageURI.find("://") == std::string::npos)
    {
        if (imageURI.starts_with("/"))
        {
            messages::actionParameterValueTypeError(
                res, imageURI, "ImageURI", "UpdateService.SimpleUpdate");
            return std::nullopt;
        }
        if (!transferProtocol)
        {
            messages::actionParameterValueTypeError(
                res, imageURI, "ImageURI", "UpdateService.SimpleUpdate");
            return std::nullopt;
        }
        // OpenBMC currently only supports HTTPS
        if (*transferProtocol == "HTTPS")
        {
            imageURI = "https://" + imageURI;
        }
        else
        {
            messages::actionParameterNotSupported(res, "TransferProtocol",
                                                  *transferProtocol);
            BMCWEB_LOG_ERROR("Request incorrect protocol parameter: {}",
                             *transferProtocol);
            return std::nullopt;
        }
    }

    boost::system::result<boost::urls::url> url =
        boost::urls::parse_absolute_uri(imageURI);
    if (!url)
    {
        messages::actionParameterValueTypeError(res, imageURI, "ImageURI",
                                                "UpdateService.SimpleUpdate");

        return std::nullopt;
    }
    url->normalize();

    if (url->scheme() == "tftp")
    {
        if (url->encoded_path().size() < 2)
        {
            messages::actionParameterNotSupported(res, "ImageURI",
                                                  url->buffer());
            return std::nullopt;
        }
    }
    else if (url->scheme() == "https")
    {
        // Empty paths default to "/"
        if (url->encoded_path().empty())
        {
            url->set_encoded_path("/");
        }
    }
    else
    {
        messages::actionParameterNotSupported(res, "ImageURI", imageURI);
        return std::nullopt;
    }

    if (url->encoded_path().empty())
    {
        messages::actionParameterValueTypeError(res, imageURI, "ImageURI",
                                                "UpdateService.SimpleUpdate");
        return std::nullopt;
    }

    return *url;
}

inline void doHttpsUpdate(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                          const boost::urls::url_view_base& url)
{
    messages::actionParameterNotSupported(asyncResp->res, "ImageURI",
                                          url.buffer());
}

inline void handleUpdateServiceSimpleUpdateAction(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    std::optional<std::string> transferProtocol;
    std::string imageURI;

    BMCWEB_LOG_DEBUG("Enter UpdateService.SimpleUpdate doPost");

    // User can pass in both TransferProtocol and ImageURI parameters or
    // they can pass in just the ImageURI with the transfer protocol
    // embedded within it.
    // 1) TransferProtocol:TFTP ImageURI:1.1.1.1/myfile.bin
    // 2) ImageURI:tftp://1.1.1.1/myfile.bin

    if (!json_util::readJsonAction(               //
            req, asyncResp->res,                  //
            "TransferProtocol", transferProtocol, //
            "ImageURI", imageURI                  //
            ))
    {
        BMCWEB_LOG_DEBUG("Missing TransferProtocol or ImageURI parameter");
        return;
    }

    std::optional<boost::urls::url> url =
        parseSimpleUpdateUrl(imageURI, transferProtocol, asyncResp->res);
    if (!url)
    {
        return;
    }
    if (url->scheme() == "https")
    {
        doHttpsUpdate(asyncResp, *url);
    }
    else
    {
        messages::actionParameterNotSupported(asyncResp->res, "ImageURI",
                                              url->buffer());
        return;
    }

    BMCWEB_LOG_DEBUG("Exit UpdateService.SimpleUpdate doPost");
}

inline void uploadImageFile(crow::Response& res, std::string_view body)
{
    std::filesystem::path filepath(
        std::string(BMCWEB_IMAGE_UPLOAD_DIR) + bmcweb::getRandomUUID());

    BMCWEB_LOG_DEBUG("Writing file to {}", filepath.string());
    std::ofstream out(filepath, std::ofstream::out | std::ofstream::binary |
                                    std::ofstream::trunc);
    // set the permission of the file to 640
    std::filesystem::perms permission =
        std::filesystem::perms::owner_read | std::filesystem::perms::group_read;
    std::filesystem::permissions(filepath, permission);
    out << body;

    if (out.bad())
    {
        messages::internalError(res);
        cleanUp();
    }
}

// Convert the Request Apply Time to the D-Bus value
inline bool convertApplyTime(crow::Response& res, const std::string& applyTime,
                             std::string& applyTimeNewVal)
{
#ifdef ONETREE_INTEL_PFR
    std::vector<std::string> applyTimeAllowableValues = {"Immediate",
                                                         "OnReset"};
#else
    std::vector<std::string> applyTimeAllowableValues = {
        "Immediate", "OnReset", "AtMaintenanceWindowStart",
        "InMaintenanceWindowOnReset"};
#endif
#if defined(ONETREE_EGS) || defined(ONETREE_BHS) ||                            \
    defined(ONETREE_ASPEED_SDK_LAYER) || defined(ONETREE_EVB_AST2600)

    auto it = std::find(applyTimeAllowableValues.begin(),
                        applyTimeAllowableValues.end(), applyTime);
    if (it != applyTimeAllowableValues.end())
    {
        applyTimeNewVal =
            "xyz.openbmc_project.Software.ApplyTime.RequestedApplyTimes." +
            applyTime;
    }
    else
    {
        BMCWEB_LOG_WARNING(
            "ApplyTime value {} is not in the list of acceptable values",
            applyTime);
        messages::propertyValueNotInList(res, applyTime, "ApplyTime");
        return false;
    }
    return true;
#else
    if (applyTime == "Immediate")
    {
        applyTimeNewVal =
            "xyz.openbmc_project.Software.ApplyTime.RequestedApplyTimes.Immediate";
    }
    else if (applyTime == "OnReset")
    {
        applyTimeNewVal =
            "xyz.openbmc_project.Software.ApplyTime.RequestedApplyTimes.OnReset";
    }
    else
    {
        BMCWEB_LOG_WARNING(
            "ApplyTime value {} is not in the list of acceptable values",
            applyTime);
        messages::propertyValueNotInList(res, applyTime, "ApplyTime");
        return false;
    }
    return true;
#endif
}

inline void setApplyTime(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                         const std::string& applyTime)
{
    std::string applyTimeNewVal;
    if (!convertApplyTime(asyncResp->res, applyTime, applyTimeNewVal))
    {
        return;
    }

    setDbusProperty(asyncResp, "ApplyTime", "xyz.openbmc_project.Settings",
                    sdbusplus::message::object_path(
                        "/xyz/openbmc_project/software/apply_time"),
                    "xyz.openbmc_project.Software.ApplyTime",
                    "RequestedApplyTime", applyTimeNewVal);
}

struct MultiPartUpdateParameters
{
    std::optional<std::string> applyTime;
    std::string uploadData;
    std::vector<std::string> targets;
};

inline std::optional<std::string> processUrl(
    boost::system::result<boost::urls::url_view>& url)
{
    if (!url)
    {
        return std::nullopt;
    }
    if (crow::utility::readUrlSegments(*url, "redfish", "v1", "Managers",
                                       BMCWEB_REDFISH_MANAGER_URI_NAME))
    {
        return std::make_optional(std::string(BMCWEB_REDFISH_MANAGER_URI_NAME));
    }
    // if constexpr (!BMCWEB_REDFISH_UPDATESERVICE_USE_DBUS)
    //{
    //     return std::nullopt;
    // }
    std::string firmwareId;
    if (!crow::utility::readUrlSegments(*url, "redfish", "v1", "UpdateService",
                                        "FirmwareInventory",
                                        std::ref(firmwareId)))
    {
        return std::nullopt;
    }

    return std::make_optional(firmwareId);
}

inline void isValidTarget(const std::string& fwId,
                          const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                          std::function<void(bool)> callback)
{
    constexpr std::array<std::string_view, 1> interfaces = {
        "xyz.openbmc_project.Software.Version"};

    dbus::utility::getSubTreePaths(
        "/xyz/openbmc_project/software/", 0, interfaces,
        [asyncResp, fwId, callback](
            const boost::system::error_code& ec,
            const dbus::utility::MapperGetSubTreePathsResponse& paths) mutable {
            BMCWEB_LOG_DEBUG("doGetPaths callback...");
            if (ec)
            {
                messages::internalError(asyncResp->res);
                callback(false);
                return;
            }

            bool found = false;
            for (const auto& path : paths)
            {
                if (path.ends_with(fwId))
                {
                    found = true;
                    break;
                }
            }

            if (!found)
            {
                messages::resourceNotFound(asyncResp->res, "FirmwareInventory",
                                           fwId);
            }

            callback(found);
        });
}

inline void extractMultipartUpdateParameters(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp, MultipartParser parser,
    std::function<void(std::optional<MultiPartUpdateParameters>)> callback)
{
    // Check if another firmware update is already in progress
    if (httpPushUriTargetBusy)
    {
        BMCWEB_LOG_DEBUG(
            "Other client has reserved the HttpPushUriTargets property for firmware updates.");
        messages::resourceInUse(asyncResp->res);
        callback(std::nullopt);
        return;
    }
    MultiPartUpdateParameters multiRet;
    std::string fwId;
    for (FormPart& formpart : parser.mime_fields)
    {
        boost::beast::http::fields::const_iterator it =
            formpart.fields.find("Content-Disposition");
        if (it == formpart.fields.end())
        {
            BMCWEB_LOG_ERROR("Couldn't find Content-Disposition");
            callback(std::nullopt);
            return;
        }
        BMCWEB_LOG_INFO("Parsing value {}", it->value());

        // The construction parameters of param_list must start with `;`
        size_t index = it->value().find(';');
        if (index == std::string::npos)
        {
            continue;
        }

        for (const auto& param :
             boost::beast::http::param_list{it->value().substr(index)})
        {
            if (param.first != "name" || param.second.empty())
            {
                continue;
            }

            if (param.second == "UpdateParameters")
            {
                std::vector<std::string> tempTargets;
                nlohmann::json content =
                    nlohmann::json::parse(formpart.content, nullptr, false);
                if (content.is_discarded())
                {
                    callback(std::nullopt);
                    return;
                }
                nlohmann::json::object_t* obj =
                    content.get_ptr<nlohmann::json::object_t*>();
                if (obj == nullptr)
                {
                    messages::propertyValueTypeError(
                        asyncResp->res, formpart.content, "UpdateParameters");
                    callback(std::nullopt);
                    return;
                }

                if (!json_util::readJsonObject(                           //
                        *obj, asyncResp->res,                             //
                        "Targets", tempTargets,                           //
                        "@Redfish.OperationApplyTime", multiRet.applyTime //
                        ))
                {
                    callback(std::nullopt);
                    return;
                }

                for (size_t urlIndex = 0; urlIndex < tempTargets.size();
                     urlIndex++)
                {
                    const std::string& target = tempTargets[urlIndex];
                    boost::system::result<boost::urls::url_view> url =
                        boost::urls::parse_origin_form(target);
                    auto res = processUrl(url);
                    if (!res.has_value())
                    {
                        messages::propertyValueFormatError(
                            asyncResp->res, target,
                            std::format("Targets/{}", urlIndex));
                        callback(std::nullopt);
                        return;
                    }
                    fwId = res.value();
                    multiRet.targets.emplace_back(res.value());
                }
                if (multiRet.targets.size() != 1)
                {
                    messages::propertyValueFormatError(
                        asyncResp->res, multiRet.targets, "Targets");
                    callback(std::nullopt);
                    return;
                }
            }
            else if (param.second == "UpdateFile")
            {
                multiRet.uploadData = std::move(formpart.content);
            }
        }
    }

    if (multiRet.uploadData.empty())
    {
        BMCWEB_LOG_ERROR("Upload data is NULL");
        messages::propertyMissing(asyncResp->res, "UpdateFile");
        callback(std::nullopt);
        return;
    }
    if (multiRet.targets.empty())
    {
        messages::propertyMissing(asyncResp->res, "Targets");
        callback(std::nullopt);
        return;
    }
    const std::string fwIdToCheck = multiRet.targets[0];

    // Move multiRet into a heap object so it can be captured by the async
    // callback safely.
    auto multiRetPtr =
        std::make_shared<MultiPartUpdateParameters>(std::move(multiRet));

    isValidTarget(
        fwIdToCheck, asyncResp,
        [callback, asyncResp, multiRetPtr](bool valid) mutable {
            if (!valid)
            {
                callback(std::nullopt);
                return;
            }
            if (multiRetPtr->uploadData.empty())
            {
                BMCWEB_LOG_ERROR("Upload data is NULL");
                messages::propertyMissing(asyncResp->res, "UpdateFile");
                callback(std::nullopt);
                return;
            }
            // Valid target found - set HttpPushUriTargets property in DBus
            sdbusplus::asio::setProperty(
                *crow::connections::systemBus,
                "xyz.openbmc_project.Software.BMC.Updater",
                "/xyz/openbmc_project/software",
                "xyz.openbmc_project.Software.FirmwareUpdateTarget",
                "HttpPushUriTargets", multiRetPtr->targets,
                [callback, asyncResp,
                 multiRetPtr](const boost::system::error_code& ec) {
                    if (ec)
                    {
                        BMCWEB_LOG_ERROR(
                            "HttpPushUriTargets D-Bus responses error: {}", ec);
                        messages::internalError(asyncResp->res);
                        callback(std::nullopt);
                        return;
                    }

                    BMCWEB_LOG_DEBUG(
                        "HttpPushUriTargets property set successfully");
                    httpPushUriTargets = multiRetPtr->targets;

                    // Now set HttpPushUriTargetsBusy to true
                    sdbusplus::asio::setProperty(
                        *crow::connections::systemBus,
                        "xyz.openbmc_project.Software.BMC.Updater",
                        "/xyz/openbmc_project/software",
                        "xyz.openbmc_project.Software.FirmwareUpdateTarget",
                        "HttpPushUriTargetsBusy", true,
                        [callback, asyncResp,
                         multiRetPtr](const boost::system::error_code& ec2) {
                            if (ec2)
                            {
                                BMCWEB_LOG_ERROR(
                                    "HttpPushUriTargetsBusy D-Bus set error: {}",
                                    ec2);
                                messages::internalError(asyncResp->res);

                                callback(std::nullopt);
                                return;
                            }
                            httpPushUriTargetBusy = true;

                            BMCWEB_LOG_DEBUG(
                                "HttpPushUriTargetsBusy set to true successfully");

                            // Valid target and has upload data — return the
                            // parsed parameters.
                            callback(
                                std::make_optional<MultiPartUpdateParameters>(
                                    std::move(*multiRetPtr)));
                        });
                });
        });
    return;
}

inline void handleStartUpdate(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp, task::Payload payload,
    const std::string& objectPath, const boost::system::error_code& ec,
    const sdbusplus::message::object_path& retPath)
{
    if (ec)
    {
        BMCWEB_LOG_ERROR("error_code = {}", ec);
        BMCWEB_LOG_ERROR("error msg = {}", ec.message());
        messages::internalError(asyncResp->res);
        return;
    }

    BMCWEB_LOG_INFO("Call to StartUpdate on {} Success, retPath = {}",
                    objectPath, retPath.str);
    createTask(asyncResp, std::move(payload), retPath);
}

inline void startUpdate(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp, task::Payload payload,
    const MemoryFileDescriptor& memfd, const std::string& applyTime,
    const std::string& objectPath, const std::string& serviceName)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp, payload = std::move(payload),
         objectPath](const boost::system::error_code& ec1,
                     const sdbusplus::message::object_path& retPath) mutable {
            handleStartUpdate(asyncResp, std::move(payload), objectPath, ec1,
                              retPath);
        },
        serviceName, objectPath, "xyz.openbmc_project.Software.Update",
        "StartUpdate", sdbusplus::message::unix_fd(memfd.fd), applyTime);
}

inline void getSwInfo(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                      task::Payload payload, const MemoryFileDescriptor& memfd,
                      const std::string& applyTime, const std::string& target,
                      const boost::system::error_code& ec,
                      const dbus::utility::MapperGetSubTreeResponse& subtree)
{
    using SwInfoMap = std::unordered_map<
        std::string, std::pair<sdbusplus::message::object_path, std::string>>;
    SwInfoMap swInfoMap;
    if (ec)
    {
        BMCWEB_LOG_ERROR("error_code = {}", ec);
        BMCWEB_LOG_ERROR("error msg = {}", ec.message());
        messages::internalError(asyncResp->res);
        return;
    }
    BMCWEB_LOG_DEBUG("Found {} software version paths", subtree.size());

    for (const auto& entry : subtree)
    {
        sdbusplus::message::object_path path(entry.first);
        std::string swId = path.filename();
        swInfoMap.emplace(swId, make_pair(path, entry.second[0].first));
    }

    auto swEntry = swInfoMap.find(target);
    if (swEntry == swInfoMap.end())
    {
        BMCWEB_LOG_WARNING("No valid DBus path for Target URI {}", target);
        messages::propertyValueFormatError(asyncResp->res, target, "Targets");
        return;
    }

    BMCWEB_LOG_DEBUG("Found software version path {} serviceName {}",
                     swEntry->second.first.str, swEntry->second.second);

    startUpdate(asyncResp, std::move(payload), memfd, applyTime,
                swEntry->second.first.str, swEntry->second.second);
}

inline void handleBMCUpdate(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp, task::Payload payload,
    const MemoryFileDescriptor& memfd, const std::string& applyTime,
    const boost::system::error_code& ec,
    const dbus::utility::MapperEndPoints& functionalSoftware)
{
    if (ec)
    {
        BMCWEB_LOG_ERROR("error_code = {}", ec);
        BMCWEB_LOG_ERROR("error msg = {}", ec.message());
        messages::internalError(asyncResp->res);
        return;
    }
    if (functionalSoftware.size() != 1)
    {
        BMCWEB_LOG_ERROR("Found {} functional software endpoints",
                         functionalSoftware.size());
        messages::internalError(asyncResp->res);
        return;
    }
    startUpdate(asyncResp, std::move(payload), memfd, applyTime,
                functionalSoftware[0], "xyz.openbmc_project.Software.Manager");
}

inline void processUpdateRequest(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    task::Payload&& payload, std::string_view body,
    const std::string& applyTime, std::vector<std::string>& targets)
{
    MemoryFileDescriptor memfd("update-image");
    if (memfd.fd == -1)
    {
        BMCWEB_LOG_ERROR("Failed to create image memfd");
        messages::internalError(asyncResp->res);
        return;
    }
    if (write(memfd.fd, body.data(), body.length()) !=
        static_cast<ssize_t>(body.length()))
    {
        BMCWEB_LOG_ERROR("Failed to write to image memfd");
        messages::internalError(asyncResp->res);
        return;
    }
    if (!memfd.rewind())
    {
        messages::internalError(asyncResp->res);
        return;
    }

    if (!targets.empty() && targets[0] == BMCWEB_REDFISH_MANAGER_URI_NAME)
    {
        dbus::utility::getAssociationEndPoints(
            "/xyz/openbmc_project/software/bmc/updateable",
            [asyncResp, payload = std::move(payload), memfd = std::move(memfd),
             applyTime](
                const boost::system::error_code& ec,
                const dbus::utility::MapperEndPoints& objectPaths) mutable {
                handleBMCUpdate(asyncResp, std::move(payload), memfd, applyTime,
                                ec, objectPaths);
            });
    }
    else
    {
        constexpr std::array<std::string_view, 1> interfaces = {
            "xyz.openbmc_project.Software.Version"};
        dbus::utility::getSubTree(
            "/xyz/openbmc_project/software", 1, interfaces,
            [asyncResp, payload = std::move(payload), memfd = std::move(memfd),
             applyTime, targets](const boost::system::error_code& ec,
                                 const dbus::utility::MapperGetSubTreeResponse&
                                     subtree) mutable {
                getSwInfo(asyncResp, std::move(payload), memfd, applyTime,
                          targets[0], ec, subtree);
            });
    }
}

inline void updateMultipartContext(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const crow::Request& req, MultipartParser&& parser)
{
    extractMultipartUpdateParameters(
        asyncResp, std::move(parser),
        [asyncResp, &req](std::optional<MultiPartUpdateParameters> multipart) {
            if (!multipart)
            {
                return;
            }

            // Ensure applyTime defaults
            if (!multipart->applyTime)
            {
                multipart->applyTime = "OnReset";
            }

            // For DBus flow create a payload and continue; extractor already
            // validated the target.
            if constexpr (BMCWEB_REDFISH_UPDATESERVICE_USE_DBUS)
            {
                std::string applyTimeNewVal;
                if (!convertApplyTime(asyncResp->res, *multipart->applyTime,
                                      applyTimeNewVal))
                {
                    return;
                }
                task::Payload payload(req);

                processUpdateRequest(asyncResp, std::move(payload),
                                     multipart->uploadData, applyTimeNewVal,
                                     multipart->targets);
            }
            else
            {
                setApplyTime(asyncResp, *multipart->applyTime);

                // Setup callback for when new software detected
                monitorForSoftwareAvailable(asyncResp, req,
                                            "/redfish/v1/UpdateService",
                                            httpPushUriTargets);

                uploadImageFile(asyncResp->res, multipart->uploadData);
            }
        });
}
#if defined(ONETREE_EGS) || defined(ONETREE_BHS) ||                            \
    defined(ONETREE_ASPEED_SDK_LAYER) || defined(ONETREE_EVB_AST2600)

inline bool checkApplyTime(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    auto requestedApplyTime = std::get<std::string>(getApplyTimePropertyValue(
        "xyz.openbmc_project.Settings",
        "/xyz/openbmc_project/software/apply_time",
        "xyz.openbmc_project.Software.ApplyTime", "RequestedApplyTime"));
    if (requestedApplyTime.substr(requestedApplyTime.find_last_of('.') + 1) ==
            "AtMaintenanceWindowStart" ||
        requestedApplyTime.substr(requestedApplyTime.find_last_of('.') + 1) ==
            "InMaintenanceWindowOnReset")
    {
        auto maintenanceWindowStartTime =
            std::get<uint64_t>(getApplyTimePropertyValue(
                "xyz.openbmc_project.Settings",
                "/xyz/openbmc_project/software/apply_time",
                "xyz.openbmc_project.Software.ApplyTime",
                "MaintenanceWindowStartTime"));
        auto maintenanceWindowDurationInSeconds =
            std::get<uint64_t>(getApplyTimePropertyValue(
                "xyz.openbmc_project.Settings",
                "/xyz/openbmc_project/software/apply_time",
                "xyz.openbmc_project.Software.ApplyTime",
                "MaintenanceWindowDurationInSeconds"));
        const auto current_time = std::chrono::system_clock::to_time_t(
            std::chrono::system_clock::now());
        if (static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::from_time_t(current_time)
                        .time_since_epoch())
                    .count()) >
            (static_cast<std::uint64_t>(maintenanceWindowStartTime) +
             static_cast<std::uint64_t>(maintenanceWindowDurationInSeconds)))
        {
            nlohmann::json jsonValue;
            jsonValue["HttpPushUriOptions"]["HttpPushUriApplyTime"]
                     ["ApplyTime"] = requestedApplyTime.substr(
                         requestedApplyTime.find_last_of('.') + 1);
            jsonValue["HttpPushUriOptions"]["HttpPushUriApplyTime"]
                     ["MaintenanceWindowStartTime"] =
                         redfish::time_utils::getDateTimeUint(
                             maintenanceWindowStartTime);
            jsonValue["HttpPushUriOptions"]["HttpPushUriApplyTime"]
                     ["MaintenanceWindowDurationInSeconds"] =
                         maintenanceWindowDurationInSeconds;

            messages::propertyValueIncorrect(
                asyncResp->res,
                "Combination of MaintenanceWindowStartTime and MaintenanceWindowDurationInSeconds is Invalid ",
                jsonValue);
            return false;
        }
        return true;
    }
    return true;
}
#endif

inline void doHTTPUpdate(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                         const crow::Request& req)
{
    //  Check for empty body
    if (req.body().empty())
    {
        BMCWEB_LOG_DEBUG("Upload body is empty");
        messages::propertyMissing(asyncResp->res, "FirmwareImage");
        return;
    }

    if constexpr (BMCWEB_REDFISH_UPDATESERVICE_USE_DBUS)
    {
        task::Payload payload(req);
        // HTTP push only supports BMC updates (with ApplyTime as immediate) for
        // backwards compatibility. Specific component updates will be handled
        // through Multipart form HTTP push.
        std::vector<std::string> targets;
        targets.emplace_back(BMCWEB_REDFISH_MANAGER_URI_NAME);

        processUpdateRequest(asyncResp, std::move(payload), req.body(),
                             "xyz.openbmc_project.Software.ApplyTime."
                             "RequestedApplyTimes.Immediate",
                             targets);
    }
    else
    {
        // Setup callback for when new software detected
        monitorForSoftwareAvailable(asyncResp, req, "/redfish/v1/UpdateService",
                                    httpPushUriTargets);

#if defined(ONETREE_EGS) || defined(ONETREE_BHS) ||                            \
    defined(ONETREE_ASPEED_SDK_LAYER) || defined(ONETREE_EVB_AST2600)
        if (checkApplyTime(asyncResp) == false)
        {
            messages::internalError(asyncResp->res);
            return;
        }
#endif

        uploadImageFile(asyncResp->res, req.body());
    }
}

inline void handleUpdateServicePost(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    std::string_view contentType = req.getHeaderValue("Content-Type");

    BMCWEB_LOG_DEBUG("doPost: contentType={}", contentType);

    // Make sure that content type is application/octet-stream or
    // multipart/form-data
    if (bmcweb::asciiIEquals(contentType, "application/octet-stream") ||
        bmcweb::asciiIEquals(contentType, "application/x-tar"))
    {
        doHTTPUpdate(asyncResp, req);
    }
    else if (contentType.starts_with("multipart/form-data"))
    {
        MultipartParser parser;

        ParserError ec = parser.parse(req);
        if (ec != ParserError::PARSER_SUCCESS)
        {
            // handle error
            BMCWEB_LOG_ERROR("MIME parse failed, ec : {}",
                             static_cast<int>(ec));
            messages::internalError(asyncResp->res);
            return;
        }

        updateMultipartContext(asyncResp, req, std::move(parser));
    }
    else
    {
        BMCWEB_LOG_DEBUG("Bad content type specified:{}", contentType);
        asyncResp->res.result(
            boost::beast::http::status::unsupported_media_type);
    }
}

inline void getpreserveProperties(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    std::string objectPaths, std::string uri)
{
    std::string propertyname;
    size_t lastPosition = objectPaths.find_last_of('/');
    if (lastPosition != std::string::npos)
    {
        propertyname = objectPaths.substr(lastPosition + 1);
    }

#if ONETREE_RM
    // When Rack Manager is enabled, hide KVM and Boot_Override from response
    if (propertyname == "KVM" || propertyname == "Boot_Override")
    {
        return;
    }
#endif

    dbus::utility::getProperty<bool>(
        *crow::connections::systemBus, "xyz.openbmc_project.EntityManager",
        objectPaths, "xyz.openbmc_project.Configuration.Preserve", "isEnable",
        [asyncResp, propertyname,
         uri](const boost::system::error_code ec1, bool Enable) {
            if (ec1)
            {
                messages::internalError(asyncResp->res);
                return;
            }
            if (uri == "UpdateService")
            {
                asyncResp->res.jsonValue["Oem"]["Ami"]["PreserveConfiguration"]
                                        [propertyname] = Enable;
            }
            else
            {
                asyncResp->res
                    .jsonValue["PreserveConfiguration"][propertyname] = Enable;
            }
        });
}

inline void getPreserveConfig(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp, std::string uri)
{
    auto bus = sdbusplus::bus::new_default();
    auto getpreserveobjectpaths = bus.new_method_call(
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths");
    getpreserveobjectpaths.append(
        "/", 0,
        std::vector<std::string>{"xyz.openbmc_project.Configuration.Preserve"});

    auto getpreserveobjects = bus.call(getpreserveobjectpaths);
    std::vector<std::string> configList;
    getpreserveobjects.read(configList);

    for (const auto& configObj : configList)
    {
        try
        {
            auto isOptionalCall = bus.new_method_call(
                "xyz.openbmc_project.EntityManager", configObj.c_str(),
                "org.freedesktop.DBus.Properties", "Get");
            isOptionalCall.append("xyz.openbmc_project.Configuration.Preserve",
                                  "isOptional");

            auto isOptionalReply = bus.call(isOptionalCall);
            std::variant<bool> isOptionalVariant;
            isOptionalReply.read(isOptionalVariant);
            bool isOptional = std::get<bool>(isOptionalVariant);

            if (!isOptional)
            {
                continue;
            }

            getpreserveProperties(asyncResp, configObj, uri);
        }
        catch (const sdbusplus::exception::SdBusError& e)
        {
            messages::internalError(asyncResp->res);
            return;
        }
    }
}

inline void handleUpdateServiceGet(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    asyncResp->res.jsonValue["@odata.type"] =
        json_util::odataType("UpdateService");
    asyncResp->res.jsonValue["@odata.id"] = "/redfish/v1/UpdateService";
    asyncResp->res.jsonValue["Id"] = "UpdateService";
    asyncResp->res.jsonValue["Description"] = "Service for Software Update";
    asyncResp->res.jsonValue["Name"] = "Update Service";

    asyncResp->res.jsonValue["HttpPushUri"] =
        "/redfish/v1/UpdateService/update";
    asyncResp->res.jsonValue["MultipartHttpPushUri"] =
        "/redfish/v1/UpdateService/update";
    // asyncResp->res.jsonValue["HttpPushUriTargets"] = httpPushUriTargets;
    // asyncResp->res.jsonValue["HttpPushUriTargetsBusy"] =
    // httpPushUriTargetBusy;

    // UpdateService cannot be disabled
    asyncResp->res.jsonValue["ServiceEnabled"] = true;
    asyncResp->res.jsonValue["FirmwareInventory"]["@odata.id"] =
        "/redfish/v1/UpdateService/FirmwareInventory";
    // Get the MaxImageSizeBytes
    asyncResp->res.jsonValue["MaxImageSizeBytes"] =
        BMCWEB_IMAGE_PAYLOAD_LIMIT * 1024 * 1024;

    if constexpr (BMCWEB_REDFISH_ALLOW_SIMPLE_UPDATE)
    {
        // Update Actions object.
        nlohmann::json& updateSvcSimpleUpdate =
            asyncResp->res.jsonValue["Actions"]["#UpdateService.SimpleUpdate"];
        updateSvcSimpleUpdate["target"] =
            "/redfish/v1/UpdateService/Actions/UpdateService.SimpleUpdate";

        nlohmann::json::array_t allowed;
        allowed.emplace_back(update_service::TransferProtocolType::HTTPS);
        updateSvcSimpleUpdate["TransferProtocol@Redfish.AllowableValues"] =
            std::move(allowed);
    }

    getPreserveConfig(asyncResp, "UpdateService");
    asyncResp->res.jsonValue["Oem"]["Ami"]["@odata.type"] =
        json_util::odataType("AmiUpdateService", "Ami");

#if defined(ONETREE_EGS) || defined(ONETREE_BHS) ||                            \
    defined(ONETREE_ASPEED_SDK_LAYER) || defined(ONETREE_EVB_AST2600)

    sdbusplus::asio::getAllProperties(
        *crow::connections::systemBus,
        "xyz.openbmc_project.Software.BMC.Updater",
        "/xyz/openbmc_project/software",
        "xyz.openbmc_project.Software.FirmwareUpdateTarget",
        [asyncResp](const boost::system::error_code& ec,
                    const std::vector<
                        std::pair<std::string, dbus::utility::DbusVariantType>>&
                        propertiesList) {
            if (ec)
            {
                // this interface isn't necessary
                return;
            }
            const bool* httpPushUriTargetsbusy = nullptr;
            const std::vector<std::string>* httpPushUritargets = nullptr;

            const bool success = sdbusplus::unpackPropertiesNoThrow(
                dbus_utils::UnpackErrorPrinter(), propertiesList,
                "HttpPushUriTargetsBusy", httpPushUriTargetsbusy,
                "HttpPushUriTargets", httpPushUritargets);
            if (!success)
            {
                // messages::internalError(asyncResp->res);
                return;
            }

            if (httpPushUriTargetsbusy != nullptr)
            {
                asyncResp->res.jsonValue["HttpPushUriTargetsBusy"] =
                    *httpPushUriTargetsbusy;
                httpPushUriTargetBusy = *httpPushUriTargetsbusy;
            }
            if (httpPushUritargets != nullptr)
            {
                asyncResp->res.jsonValue["HttpPushUriTargets"] =
                    *httpPushUritargets;
                httpPushUriTargets = *httpPushUritargets;
            }
        });

    sdbusplus::asio::getAllProperties(
        *crow::connections::systemBus, "xyz.openbmc_project.Settings",
        "/xyz/openbmc_project/software/apply_time",
        "xyz.openbmc_project.Software.ApplyTime",
        [asyncResp](const boost::system::error_code& ec,
                    const dbus::utility::DBusPropertiesMap& propertiesList) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("DBUS response error {}", ec);
                return;
            }
            BMCWEB_LOG_DEBUG("Got {}properties for apply_time",
                             propertiesList.size());
            const std::string* requestedApplyTime = nullptr;
            const uint64_t* maintenanceWindowDurationInSeconds = nullptr;
            const uint64_t* maintenanceWindowStartTime = nullptr;
            const bool success = sdbusplus::unpackPropertiesNoThrow(
                dbus_utils::UnpackErrorPrinter(), propertiesList,
                "RequestedApplyTime", requestedApplyTime,
                "MaintenanceWindowStartTime", maintenanceWindowStartTime,
                "MaintenanceWindowDurationInSeconds",
                maintenanceWindowDurationInSeconds);

            if (!success)
            {
                messages::internalError(asyncResp->res);
                return;
            }
            if (requestedApplyTime != nullptr)
            {
                asyncResp->res.jsonValue["HttpPushUriOptions"]
                                        ["HttpPushUriApplyTime"]["ApplyTime"] =
                    requestedApplyTime->substr(
                        requestedApplyTime->find_last_of('.') + 1);
            }

#ifdef ONETREE_INTEL_PFR
            asyncResp->res
                .jsonValue["HttpPushUriOptions"]["HttpPushUriApplyTime"]
                          ["ApplyTime@Redfish.AllowableValues"] = {
                "Immediate", "OnReset"};
#endif
            asyncResp->res
                .jsonValue["HttpPushUriOptions"]["HttpPushUriApplyTime"]
                          ["ApplyTime@Redfish.AllowableValues"] = {
                "Immediate", "OnReset", "AtMaintenanceWindowStart",
                "InMaintenanceWindowOnReset"};

            if (maintenanceWindowStartTime != nullptr)
            {
                asyncResp->res
                    .jsonValue["HttpPushUriOptions"]["HttpPushUriApplyTime"]
                              ["MaintenanceWindowStartTime"] =
                    redfish::time_utils::getDateTimeUint(
                        *maintenanceWindowStartTime);
            }

            if (maintenanceWindowDurationInSeconds != nullptr)
            {
                asyncResp->res
                    .jsonValue["HttpPushUriOptions"]["HttpPushUriApplyTime"]
                              ["MaintenanceWindowDurationInSeconds"] =
                    *maintenanceWindowDurationInSeconds;
            }
        });
#endif
    // Get the ApplyOptions value
    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code ec1,
                    const std::variant<bool> applyOption) {
            if (ec1)
            {
                BMCWEB_LOG_DEBUG("DBUS response error {}", ec1);
                messages::internalError(asyncResp->res);
                return;
            }

            const bool* b = std::get_if<bool>(&applyOption);

            if (b)
            {
                asyncResp->res.jsonValue["Oem"]["ApplyOptions"]["@odata.type"] =
                    "#OemUpdateService.ApplyOptions";
                asyncResp->res.jsonValue["Oem"]["ApplyOptions"]["ClearConfig"] =
                    *b;
            }
        },
        "xyz.openbmc_project.Software.BMC.Updater",
        "/xyz/openbmc_project/software", "org.freedesktop.DBus.Properties",
        "Get", "xyz.openbmc_project.Software.ApplyOptions", "ClearConfig");
}

inline void setPreserveConfigEnable(
    const std::shared_ptr<bmcweb::AsyncResp>& aResp, std::string ObjectPath,
    bool& property_value)
{
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, "xyz.openbmc_project.EntityManager",
        ObjectPath, "xyz.openbmc_project.Configuration.Preserve", "isEnable",
        property_value, [aResp](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-Bus responses error: {}", ec);
                messages::internalError(aResp->res);
                return;
            }
            messages::success(aResp->res);
            BMCWEB_LOG_DEBUG("Patch PreserveConfig Success");
        });
}

inline void handleUpdateServicePatch(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    BMCWEB_LOG_DEBUG("doPatch...");

    std::optional<std::vector<std::string>> imgTargets;
    std::optional<bool> imgTargetBusy;
    std::optional<nlohmann::json> oem;
#if defined(ONETREE_EGS) || defined(ONETREE_BHS) ||                            \
    defined(ONETREE_ASPEED_SDK_LAYER) || defined(ONETREE_EVB_AST2600)

    std::optional<std::string> applyTime;
    std::optional<std::string> maintenanceWindowStartTime;
    std::optional<std::uint64_t> maintenanceWindowDurationInSeconds;

    if (!json_util::readJsonPatch(
            req, asyncResp->res,                                            //
            "HttpPushUriTargets", imgTargets,                               //
            "HttpPushUriTargetsBusy", imgTargetBusy,                        //
            "Oem", oem,                                                     //
            "HttpPushUriOptions/HttpPushUriApplyTime/ApplyTime", applyTime, //
            "HttpPushUriOptions/HttpPushUriApplyTime/MaintenanceWindowDurationInSeconds",
            maintenanceWindowDurationInSeconds,                             //
            "HttpPushUriOptions/HttpPushUriApplyTime/MaintenanceWindowStartTime",
            maintenanceWindowStartTime                                      //
            ))
    {
        BMCWEB_LOG_DEBUG("UpdateService doPatch: Invalid request body");
        return;
    }

    if (applyTime)
    {
        if (applyTime == "AtMaintenanceWindowStart" ||
            applyTime == "InMaintenanceWindowOnReset")
        {
            if (maintenanceWindowStartTime &&
                maintenanceWindowDurationInSeconds)
            {
                std::optional<redfish::time_utils::usSinceEpoch> us =
                    redfish::time_utils::dateStringToEpoch(
                        *maintenanceWindowStartTime);
                if (!us)
                {
                    messages::propertyValueFormatError(
                        asyncResp->res, *maintenanceWindowStartTime,
                        "MaintenanceWindowStartTime");
                    return;
                }

                // Get current time
                time_t now = time(nullptr);
                struct tm localTm;
                localtime_r(&now, &localTm);

                long int offset_sec = localTm.tm_gmtoff;
                int64_t offset_microseconds =
                    static_cast<int64_t>(offset_sec) * 1000000;

                int64_t adjustedEpochTime = us->count() - (offset_microseconds);

                // Current BMC Timezone
                const auto current_time = std::chrono::system_clock::to_time_t(
                    std::chrono::system_clock::now());

                if (static_cast<std::uint64_t>(
                        std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::from_time_t(current_time)
                                .time_since_epoch())
                            .count()) >
                    (static_cast<std::uint64_t>(
                         std::chrono::seconds(adjustedEpochTime).count()) +
                     static_cast<std::uint64_t>(
                         *maintenanceWindowDurationInSeconds)))
                {
                    messages::propertyValueIncorrect(
                        asyncResp->res, "MaintenanceWindowStartTime",
                        *maintenanceWindowStartTime);
                    return;
                }

                // Set the MaintenanceWindowStartTime value
                sdbusplus::asio::setProperty(
                    *crow::connections::systemBus,
                    "xyz.openbmc_project.Settings",
                    "/xyz/openbmc_project/software/apply_time",
                    "xyz.openbmc_project.Software.ApplyTime",
                    "MaintenanceWindowStartTime",
                    static_cast<std::uint64_t>(
                        std::chrono::duration_cast<std::chrono::seconds>(*us)
                            .count()),
                    [asyncResp](const boost::system::error_code& ec) {
                        if (ec)
                        {
                            BMCWEB_LOG_ERROR("D-Bus responses error: {}", ec);
                            messages::internalError(asyncResp->res);
                            return;
                        }
                        // messages::success(asyncResp->res);
                    });

                if (maintenanceWindowDurationInSeconds)
                {
                    // Set the MaintenanceWindowDurationInSeconds
                    // value
                    sdbusplus::asio::setProperty(
                        *crow::connections::systemBus,
                        "xyz.openbmc_project.Settings",
                        "/xyz/openbmc_project/software/apply_time",
                        "xyz.openbmc_project.Software.ApplyTime",
                        "MaintenanceWindowDurationInSeconds",
                        *maintenanceWindowDurationInSeconds,
                        [asyncResp](const boost::system::error_code& ec) {
                            if (ec)
                            {
                                BMCWEB_LOG_ERROR("D-Bus responses error: {}",
                                                 ec);
                                messages::internalError(asyncResp->res);
                                return;
                            }
                            // messages::success(asyncResp->res);
                        });
                }
            }
            else
            {
                BMCWEB_LOG_ERROR("Missing Property MaintenanceWindowStartTime");
                messages::propertyMissing(asyncResp->res,
                                          "MaintenanceWindowStartTime");
                return;
            }
        }
        setApplyTime(asyncResp, *applyTime);
    }
#else
    if (!json_util::readJsonPatch(req, asyncResp->res, "HttpPushUriTargets",
                                  imgTargets, "HttpPushUriTargetsBusy",
                                  imgTargetBusy, "Oem", oem))
    {
        BMCWEB_LOG_DEBUG("UpdateService doPatch: Invalid request body");
        return;
    }
#endif

    if (imgTargetBusy)
    {
        sdbusplus::asio::getProperty<bool>(
            *crow::connections::systemBus,
            "xyz.openbmc_project.Software.BMC.Updater",
            "/xyz/openbmc_project/software",
            "xyz.openbmc_project.Software.FirmwareUpdateTarget",
            "HttpPushUriTargetsBusy",
            [asyncResp, imgTargets,
             imgTargetBusy](const boost::system::error_code& ec2,
                            const bool ishttpPushUriTargetbusy) {
                if (ec2)
                {
                    BMCWEB_LOG_ERROR("DBUS response error {}", ec2);
                }
                httpPushUriTargetBusy = ishttpPushUriTargetbusy;
                if ((httpPushUriTargetBusy) && (*imgTargetBusy))
                {
                    BMCWEB_LOG_DEBUG(
                        "Other client has reserved the HttpPushUriTargets property for firmware updates.");
                    messages::resourceInUse(asyncResp->res);
                    return;
                }

                if (imgTargets)
                {
                    if (!(*imgTargetBusy))
                    {
                        BMCWEB_LOG_DEBUG(
                            "UpdateService doPatch: httpPushUriTargetBusy should be true before setting httpPushUriTargets");
                        messages::invalidObject(
                            asyncResp->res,
                            boost::urls::format("HttpPushUriTargetsBusy"));
                        return;
                    }
                    if ((*imgTargets).size() != 0)
                    {
// TODO: Now we support max one target becuase
// software-manager code support one activation per
// object. It will be enhanced to multiple targets for
// single image in future. For now, consider first
// target alone.
#if defined(ONETREE_EGS) || defined(ONETREE_BHS) ||                            \
    defined(ONETREE_ASPEED_SDK_LAYER) || defined(ONETREE_EVB_AST2600)
                        if ((*imgTargets).size() > 3)
                        {
                            messages::invalidObject(
                                asyncResp->res,
                                boost::urls::format("HttpPushUriTargets"));
                            return;
                        }
#else
                        if ((*imgTargets).size() != 1)
                        {
                            messages::invalidObject(
                                asyncResp->res,
                                boost::urls::format("HttpPushUriTargets"));
                            return;
                        }
#endif
                        crow::connections::systemBus->async_method_call(
                            [asyncResp, uriTargets{*imgTargets},
                             targetBusy{*imgTargetBusy}](
                                const boost::system::error_code ec,
                                const std::vector<std::string> swInvPaths) {
                                if (ec)
                                {
                                    return;
                                }

                                bool swInvObjFound = false;
                                size_t uriCount = 0;

                                for (const std::string& path : swInvPaths)
                                {
                                    std::size_t idPos = path.rfind("/");
                                    if ((idPos == std::string::npos) ||
                                        ((idPos + 1) >= path.size()))
                                    {
                                        messages::internalError(asyncResp->res);
                                        BMCWEB_LOG_DEBUG(
                                            "Can't parse firmware ID!!");
                                        return;
                                    }
                                    std::string swId = path.substr(idPos + 1);
#if defined(ONETREE_EGS) || defined(ONETREE_BHS) ||                            \
    defined(ONETREE_ASPEED_SDK_LAYER) || defined(ONETREE_EVB_AST2600)

                                    for (const std::string& target : uriTargets)
                                    {
                                        if (swId == target)
                                        {
                                            uriCount++;
                                            if (uriCount == uriTargets.size())
                                            {
                                                swInvObjFound = true;
                                                break;
                                            }
                                        }
                                    }
#else
                                    if (swId == uriTargets[0])
                                    {
                                        swInvObjFound = true;
                                        break;
                                    }
#endif
                                }
                                BMCWEB_LOG_DEBUG("HttpPushUri count value {}",
                                                 uriCount);
                                if (!swInvObjFound)
                                {
                                    messages::invalidObject(
                                        asyncResp->res,
                                        boost::urls::format(
                                            "HttpPushUriTargets"));
                                    return;
                                }
                                sdbusplus::asio::setProperty(
                                    *crow::connections::systemBus,
                                    "xyz.openbmc_project.Software.BMC.Updater",
                                    "/xyz/openbmc_project/software",
                                    "xyz.openbmc_project.Software.FirmwareUpdateTarget",
                                    "HttpPushUriTargetsBusy", targetBusy,
                                    [asyncResp, targetBusy](
                                        const boost::system::error_code& ec1) {
                                        if (ec1)
                                        {
                                            BMCWEB_LOG_ERROR(
                                                "targetBusy D-Bus responses error: {}",
                                                ec1);
                                            messages::internalError(
                                                asyncResp->res);
                                            return;
                                        }
                                        httpPushUriTargetBusy = targetBusy;
                                        BMCWEB_LOG_DEBUG(
                                            "Patch httpPushUriTargetBusy Success");
                                        messages::success(asyncResp->res);
                                    });
                                sdbusplus::asio::setProperty(
                                    *crow::connections::systemBus,
                                    "xyz.openbmc_project.Software.BMC.Updater",
                                    "/xyz/openbmc_project/software",
                                    "xyz.openbmc_project.Software.FirmwareUpdateTarget",
                                    "HttpPushUriTargets", uriTargets,
                                    [asyncResp, uriTargets](
                                        const boost::system::error_code& ec2) {
                                        if (ec2)
                                        {
                                            BMCWEB_LOG_ERROR(
                                                "uriTargets D-Bus responses error: {}",
                                                ec2);
                                            messages::internalError(
                                                asyncResp->res);
                                            return;
                                        }
                                        httpPushUriTargets = uriTargets;
                                        BMCWEB_LOG_DEBUG(
                                            "Patch httpPushUriTargets Success");
                                        messages::success(asyncResp->res);
                                    });
                                // httpPushUriTargetBusy = targetBusy;
                                // httpPushUriTargets = uriTargets;
                            },
                            "xyz.openbmc_project.ObjectMapper",
                            "/xyz/openbmc_project/object_mapper",
                            "xyz.openbmc_project.ObjectMapper",
                            "GetSubTreePaths", "/", static_cast<int32_t>(0),
                            std::array<const char*, 1>{versionIntf});
                    }
                    else
                    {
                        sdbusplus::asio::setProperty(
                            *crow::connections::systemBus,
                            "xyz.openbmc_project.Software.BMC.Updater",
                            "/xyz/openbmc_project/software",
                            "xyz.openbmc_project.Software.FirmwareUpdateTarget",
                            "HttpPushUriTargetsBusy", *imgTargetBusy,
                            [asyncResp, imgTargetBusy](
                                const boost::system::error_code& ec3) {
                                if (ec3)
                                {
                                    BMCWEB_LOG_ERROR(
                                        "D-Bus responses error: {}", ec3);
                                    messages::internalError(asyncResp->res);
                                    return;
                                }
                                httpPushUriTargetBusy = *imgTargetBusy;
                                BMCWEB_LOG_DEBUG(
                                    "Patch httpPushUriTargetBusy Success");
                                messages::success(asyncResp->res);
                            });
                        sdbusplus::asio::setProperty(
                            *crow::connections::systemBus,
                            "xyz.openbmc_project.Software.BMC.Updater",
                            "/xyz/openbmc_project/software",
                            "xyz.openbmc_project.Software.FirmwareUpdateTarget",
                            "HttpPushUriTargets", *imgTargets,
                            [asyncResp,
                             imgTargets](const boost::system::error_code& ec4) {
                                if (ec4)
                                {
                                    BMCWEB_LOG_ERROR(
                                        "D-Bus responses error: {}", ec4);
                                    messages::internalError(asyncResp->res);
                                    return;
                                }
                                httpPushUriTargets = *imgTargets;
                                BMCWEB_LOG_DEBUG(
                                    "Patch httpPushUriTargets Success");
                                messages::success(asyncResp->res);
                            });
                        // httpPushUriTargetBusy = *imgTargetBusy;
                        // httpPushUriTargets = *imgTargets;
                    }
                }
                else
                {
                    sdbusplus::asio::setProperty(
                        *crow::connections::systemBus,
                        "xyz.openbmc_project.Software.BMC.Updater",
                        "/xyz/openbmc_project/software",
                        "xyz.openbmc_project.Software.FirmwareUpdateTarget",
                        "HttpPushUriTargetsBusy", *imgTargetBusy,
                        [asyncResp,
                         imgTargetBusy](const boost::system::error_code& ec5) {
                            if (ec5)
                            {
                                BMCWEB_LOG_ERROR("D-Bus responses error: {}",
                                                 ec5);
                                messages::internalError(asyncResp->res);
                                return;
                            }
                            httpPushUriTargetBusy = *imgTargetBusy;
                            BMCWEB_LOG_DEBUG(
                                "Patch httpPushUriTargetBusy Success");
                            messages::success(asyncResp->res);
                        });
                    // httpPushUriTargetBusy = *imgTargetBusy;
                }
            });
    }

    if (oem)
    {
        std::optional<nlohmann::json> ami;
        std::optional<nlohmann::json> applyoptions;
        std::size_t oem_size = oem.value().size();
        if (oem_size == 0)
        {
            messages::noOperation(asyncResp->res);
            return;
        }
        if (!json_util::readJson(*oem, asyncResp->res, "Ami", ami,
                                 "ApplyOptions", applyoptions))
        {
            return;
        }
        if (applyoptions)
        {
            std::optional<bool> clearConfig;
            std::size_t applyoptions_size = applyoptions.value().size();
            if (applyoptions_size == 0)
            {
                messages::noOperation(asyncResp->res);
                return;
            }
            if (!json_util::readJson(*applyoptions, asyncResp->res,
                                     "ClearConfig", clearConfig))
            {
                return;
            }
            if (clearConfig)
            {
                // Set the requested image apply time value
                crow::connections::systemBus->async_method_call(
                    [asyncResp](const boost::system::error_code ec) {
                        if (ec)
                        {
                            BMCWEB_LOG_ERROR("D-Bus responses error: {}", ec);
                            messages::internalError(asyncResp->res);
                            return;
                        }
                        messages::success(asyncResp->res);
                    },
                    "xyz.openbmc_project.Software.BMC.Updater",
                    "/xyz/openbmc_project/software",
                    "org.freedesktop.DBus.Properties", "Set",
                    "xyz.openbmc_project.Software.ApplyOptions", "ClearConfig",
                    std::variant<bool>{*clearConfig});
            }
        }
        if (ami)
        {
            std::optional<nlohmann::json> preserveconfiguration;
            std::size_t ami_size = ami.value().size();

            if (!ami.has_value() || !ami->is_object() || ami_size == 0)
            {
                BMCWEB_LOG_DEBUG(
                    "JSON value is not an object or is missing in ami");
                messages::propertyValueTypeError(asyncResp->res, *ami, "ami");
                return;
            }
            if (!json_util::readJson(*ami, asyncResp->res,
                                     "PreserveConfiguration",
                                     preserveconfiguration))
            {
                return;
            }
            if (preserveconfiguration)
            {
                std::optional<bool> authentication;
                std::optional<bool> fru;
                std::optional<bool> kvm;
                std::optional<bool> smtp;
                std::optional<bool> network;
                std::optional<bool> redfish;
                std::optional<bool> sdr;
                std::optional<bool> sel;
                std::optional<bool> snmp;
                std::optional<bool> uboot;
                std::optional<bool> ipmi;
                std::optional<bool> ntp;
                std::optional<bool> sol;
                std::optional<bool> syslog;
                std::optional<bool> boot_override;
                std::optional<bool> extlog;
                std::optional<bool> service_manager;

                if (!preserveconfiguration.has_value() ||
                    !preserveconfiguration->is_object())
                {
                    BMCWEB_LOG_DEBUG(
                        "JSON value is not an object or is missing in preserveconfiguration");
                    messages::propertyValueTypeError(asyncResp->res,
                                                     *preserveconfiguration,
                                                     "preserveconfiguration");
                    return;
                }
                if (preserveconfiguration->empty())
                {
                    BMCWEB_LOG_DEBUG(
                        "preserveconfiguration is an empty json object and is accepted.");
                    messages::success(asyncResp->res);
                    return;
                }
                if (!json_util::readJson(
                        *preserveconfiguration, asyncResp->res,
                        "AUTHENTICATION", authentication, "FRU", fru, "KVM",
                        kvm, "SMTP", smtp, "NETWORK", network, "REDFISH",
                        redfish, "SDR", sdr, "SEL", sel, "SNMP", snmp,
                        "U_BOOT_ENV", uboot, "IPMI", ipmi, "NTP", ntp, "SOL",
                        sol, "SYSLOG", syslog, "Boot_Override", boot_override,
                        "EXTLOG", extlog, "ServiceManager", service_manager))
                {
                    return;
                }
                std::string preserve_config =
                    "/xyz/openbmc_project/inventory/system/configuration/Preserve_Configuration/";
                std::string network_config =
                    "/xyz/openbmc_project/inventory/system/configuration/Network_Configuration/";
                if (authentication)
                {
                    setPreserveConfigEnable(asyncResp,
                                            preserve_config + "AUTHENTICATION",
                                            *authentication);
                }
                if (fru)
                {
                    setPreserveConfigEnable(asyncResp, preserve_config + "FRU",
                                            *fru);
                }
                if (kvm)
                {
#if (!defined(ONETREE_RM))
                    setPreserveConfigEnable(asyncResp, preserve_config + "KVM",
                                            *kvm);
#endif
                }
                if (smtp)
                {
                    setPreserveConfigEnable(asyncResp, preserve_config + "SMTP",
                                            *smtp);
                }
                if (network)
                {
                    setPreserveConfigEnable(
                        asyncResp, network_config + "NETWORK", *network);
                }
                if (redfish)
                {
                    setPreserveConfigEnable(
                        asyncResp, preserve_config + "REDFISH", *redfish);
                }
                if (sdr)
                {
                    setPreserveConfigEnable(asyncResp, preserve_config + "SDR",
                                            *sdr);
                }
                if (sel)
                {
                    setPreserveConfigEnable(asyncResp, preserve_config + "SEL",
                                            *sel);
                }
                if (snmp)
                {
                    setPreserveConfigEnable(asyncResp, preserve_config + "SNMP",
                                            *snmp);
                }
                if (uboot)
                {
                    setPreserveConfigEnable(
                        asyncResp, network_config + "U_BOOT_ENV", *uboot);
                }
                if (ipmi)
                {
                    setPreserveConfigEnable(asyncResp, network_config + "IPMI",
                                            *ipmi);
                }
                if (ntp)
                {
                    setPreserveConfigEnable(asyncResp, network_config + "NTP",
                                            *ntp);
                }
                if (sol)
                {
                    setPreserveConfigEnable(asyncResp, network_config + "SOL",
                                            *sol);
                }
                if (syslog)
                {
                    setPreserveConfigEnable(asyncResp,
                                            network_config + "SYSLOG", *syslog);
                }
                if (boot_override)
                {
#if (!defined(ONETREE_RM))
                    setPreserveConfigEnable(asyncResp,
                                            network_config + "Boot_Override",
                                            *boot_override);
#endif
                }
                if (extlog)
                {
                    setPreserveConfigEnable(asyncResp,
                                            network_config + "EXTLOG", *extlog);
                }
                if (service_manager)
                {
                    setPreserveConfigEnable(asyncResp,
                                            preserve_config + "ServiceManager",
                                            *service_manager);
                }
            }
        }
    }
}

inline void handleUpdateServiceFirmwareInventoryCollectionGet(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    asyncResp->res.jsonValue["@odata.type"] =
        "#SoftwareInventoryCollection.SoftwareInventoryCollection";
    asyncResp->res.jsonValue["@odata.id"] =
        "/redfish/v1/UpdateService/FirmwareInventory";
    asyncResp->res.jsonValue["Name"] = "Software Inventory Collection";
    asyncResp->res.jsonValue["Description"] = "Software Inventory Collection";
    const std::array<const std::string_view, 1> iface = {
        "xyz.openbmc_project.Software.Version"};

    redfish::collection_util::getCollectionMembers(
        asyncResp,
        boost::urls::url("/redfish/v1/UpdateService/FirmwareInventory"), iface,
        "/xyz/openbmc_project/software");
}

/* Fill related item links (i.e. bmc, bios) in for inventory */
inline void getRelatedItems(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                            const std::string& purpose)
{
    if (purpose == sw_util::bmcPurpose)
    {
        nlohmann::json& relatedItem = asyncResp->res.jsonValue["RelatedItem"];
        nlohmann::json::object_t item;
        item["@odata.id"] = boost::urls::format(
            "/redfish/v1/Managers/{}", BMCWEB_REDFISH_MANAGER_URI_NAME);
        relatedItem.emplace_back(std::move(item));
        asyncResp->res.jsonValue["RelatedItem@odata.count"] =
            relatedItem.size();
    }
    else if (purpose == sw_util::biosPurpose)
    {
        nlohmann::json& relatedItem = asyncResp->res.jsonValue["RelatedItem"];
        nlohmann::json::object_t item;
        item["@odata.id"] = std::format("/redfish/v1/Systems/{}/Bios",
                                        BMCWEB_REDFISH_SYSTEM_URI_NAME);
        relatedItem.emplace_back(std::move(item));
        asyncResp->res.jsonValue["RelatedItem@odata.count"] =
            relatedItem.size();
    }
    else
    {
        BMCWEB_LOG_DEBUG("Unknown software purpose {}", purpose);
    }
}

inline void getSoftwareVersion(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& service, const std::string& path,
    const std::string& swId)
{
    dbus::utility::getAllProperties(
        service, path, "xyz.openbmc_project.Software.Version",
        [asyncResp,
         swId](const boost::system::error_code& ec,
               const dbus::utility::DBusPropertiesMap& propertiesList) {
            if (ec)
            {
                messages::internalError(asyncResp->res);
                return;
            }

            const std::string* swInvPurpose = nullptr;
            const std::string* version = nullptr;

            const bool success = sdbusplus::unpackPropertiesNoThrow(
                dbus_utils::UnpackErrorPrinter(), propertiesList, "Purpose",
                swInvPurpose, "Version", version);

            if (!success)
            {
                messages::internalError(asyncResp->res);
                return;
            }

            if (swInvPurpose == nullptr)
            {
                BMCWEB_LOG_DEBUG("Can't find property \"Purpose\"!");
                messages::internalError(asyncResp->res);
                return;
            }

            BMCWEB_LOG_DEBUG("swInvPurpose = {}", *swInvPurpose);

            if (version == nullptr)
            {
                BMCWEB_LOG_DEBUG("Can't find property \"Version\"!");
                messages::internalError(asyncResp->res);
                return;
            }
            asyncResp->res.jsonValue["Version"] = *version;
            asyncResp->res.jsonValue["Id"] = swId;

            // swInvPurpose is of format:
            // xyz.openbmc_project.Software.Version.VersionPurpose.ABC
            // Translate this to "ABC image"
            size_t endDesc = swInvPurpose->rfind('.');
            if (endDesc == std::string::npos)
            {
                messages::internalError(asyncResp->res);
                return;
            }
            endDesc++;
            if (endDesc >= swInvPurpose->size())
            {
                messages::internalError(asyncResp->res);
                return;
            }

            std::string formatDesc = swInvPurpose->substr(endDesc);
            asyncResp->res.jsonValue["Description"] = formatDesc + " image";
            getRelatedItems(asyncResp, *swInvPurpose);
        });
}

inline void handleUpdateServiceFirmwareInventoryGet(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& param)
{
    asyncResp->res.clearHeader(boost::beast::http::field::allow);
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (!membersResponseGet(asyncResp, param, "SoftwareInventoryCollection"))
    {
        return;
    }
    asyncResp->res.addHeader("Allow", "GET");
    std::shared_ptr<std::string> swId = std::make_shared<std::string>(param);

    constexpr std::array<std::string_view, 1> interfaces = {
        "xyz.openbmc_project.Software.Version"};
    dbus::utility::getSubTree(
        "/", 0, interfaces,
        [asyncResp,
         swId](const boost::system::error_code& ec,
               const dbus::utility::MapperGetSubTreeResponse& subtree) {
            BMCWEB_LOG_DEBUG("doGet callback...");
            if (ec)
            {
                messages::internalError(asyncResp->res);
                return;
            }

            // Ensure we find our input swId, otherwise return an error
            bool found = false;
            for (const std::pair<std::string,
                                 std::vector<std::pair<
                                     std::string, std::vector<std::string>>>>&
                     obj : subtree)
            {
                if (!obj.first.ends_with(*swId))
                {
                    continue;
                }

                if (obj.second.empty())
                {
                    continue;
                }

                found = true;
                sw_util::getSwStatus(asyncResp, swId, obj.second[0].first);
                getSoftwareVersion(asyncResp, obj.second[0].first, obj.first,
                                   *swId);
            }
            if (!found)
            {
                BMCWEB_LOG_WARNING("Input swID {} not found!", *swId);
                messages::resourceMissingAtURI(
                    asyncResp->res,
                    boost::urls::format(
                        "/redfish/v1/UpdateService/FirmwareInventory/{}",
                        *swId));
                return;
            }
            asyncResp->res.jsonValue["@odata.id"] = boost::urls::format(
                "/redfish/v1/UpdateService/FirmwareInventory/{}", *swId);
            asyncResp->res.jsonValue["@odata.type"] =
                json_util::odataType("SoftwareInventory");
            asyncResp->res.jsonValue["Name"] = "Software Inventory";
            asyncResp->res.jsonValue["Status"]["HealthRollup"] =
                resource::Health::OK;

            asyncResp->res.jsonValue["Updateable"] = false;
            sw_util::getSwUpdatableStatus(asyncResp, swId);
        });
}

inline void requestRoutesUpdateService(App& app)
{
    if constexpr (BMCWEB_REDFISH_ALLOW_SIMPLE_UPDATE)
    {
        BMCWEB_ROUTE(
            app,
            "/redfish/v1/UpdateService/Actions/UpdateService.SimpleUpdate/")
            .privileges(redfish::privileges::postUpdateService)
            .methods(boost::beast::http::verb::post)(std::bind_front(
                handleUpdateServiceSimpleUpdateAction, std::ref(app)));
    }

    BMCWEB_ROUTE(app, "/redfish/v1/UpdateService/FirmwareInventory/<str>/")
        .privileges(redfish::privileges::getSoftwareInventory)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleUpdateServiceFirmwareInventoryGet, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/UpdateService/")
        .privileges(redfish::privileges::getUpdateService)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleUpdateServiceGet, std::ref(app)));
    BMCWEB_ROUTE(app, "/redfish/v1/UpdateService/")
        .privileges(redfish::privileges::patchUpdateService)
        .methods(boost::beast::http::verb::patch)(
            std::bind_front(handleUpdateServicePatch, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/UpdateService/update/")
        .privileges(redfish::privileges::postUpdateService)
        .methods(boost::beast::http::verb::post)(
            std::bind_front(handleUpdateServicePost, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/UpdateService/FirmwareInventory/")
        .privileges(redfish::privileges::getSoftwareInventoryCollection)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleUpdateServiceFirmwareInventoryCollectionGet, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/UpdateService/FirmwareInventory/<str>/")
        .privileges(redfish::privileges::getSoftwareInventory)
        .methods(boost::beast::http::verb::post,
                 boost::beast::http::verb::patch,
                 boost::beast::http::verb::delete_)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& param) {
                asyncResp->res.clearHeader(boost::beast::http::field::allow);
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }
                if (!membersResponseGet(asyncResp, param,
                                        "SoftwareInventoryCollection"))
                {
                    return;
                }
                std::shared_ptr<std::string> swId =
                    std::make_shared<std::string>(param);

                constexpr std::array<std::string_view, 1> interfaces = {
                    "xyz.openbmc_project.Software.Version"};
                dbus::utility::getSubTree(
                    "/", 0, interfaces,
                    [asyncResp,
                     swId](const boost::system::error_code& ec,
                           const dbus::utility::MapperGetSubTreeResponse&
                               subtree) {
                        BMCWEB_LOG_DEBUG("doGet callback...");
                        if (ec)
                        {
                            messages::internalError(asyncResp->res);
                            return;
                        }

                        // Ensure we find our input swId, otherwise return an
                        // error
                        bool found = false;
                        for (const std::pair<
                                 std::string,
                                 std::vector<std::pair<
                                     std::string, std::vector<std::string>>>>&
                                 obj : subtree)
                        {
                            if (!obj.first.ends_with(*swId))
                            {
                                continue;
                            }

                            if (obj.second.empty())
                            {
                                continue;
                            }

                            found = true;
                        }
                        if (!found)
                        {
                            BMCWEB_LOG_WARNING("Input swID {} not found!",
                                               *swId);
                            messages::resourceNotFound(
                                asyncResp->res, "FirmwareInventory", *swId);
                            return;
                        }
                        asyncResp->res.addHeader("Allow", "GET");
                        messages::operationNotAllowed(asyncResp->res);
                        return;
                    });
            });
}

} // namespace redfish
