// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
// SPDX-FileCopyrightText: Copyright 2020 Intel Corporation
#pragma once

#include "app.hpp"
#include "dbus_utility.hpp"
#include "event_service_manager.hpp"
#include "generated/enums/resource.hpp"
#include "generated/enums/task_service.hpp"
#include "http/parsing.hpp"
#include "query.hpp"
#include "registries/privilege_registry.hpp"
#include "task_messages.hpp"

#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/url/format.hpp>
#include <sdbusplus/bus/match.hpp>

#include <chrono>
#include <memory>
#include <ranges>
#include <variant>

namespace redfish
{

namespace task
{
constexpr size_t maxTaskCount = 100; // arbitrary limit

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static std::deque<std::shared_ptr<struct TaskData>> tasks;

static size_t lastTask = 1;
constexpr bool completed = true;

inline void setStatus(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                      const std::string status)
{
    std::array<std::string, 1> interfaces = {"xyz.openbmc_project.Common.Task"};

    crow::connections::systemBus->async_method_call(
        [asyncResp, status](const boost::system::error_code ec,
                            const std::vector<std::string>& ifaceList) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG(
                    "Error in querying GetSubTreePaths with Object Mapper. {}",
                    ec);
                messages::internalError(asyncResp->res);
                return;
            }
            if (ifaceList.size() == 0)
            {
                BMCWEB_LOG_DEBUG("Can't find Task Info Attributes!");
                return;
            }
            for (const std::string& fwPath : ifaceList)
            {
                setDbusProperty(asyncResp, "Status",
                                "xyz.openbmc_project.Software.BMC.Updater",
                                fwPath, "xyz.openbmc_project.Common.Task",
                                "Status", status);
            }
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths",
        "/xyz/openbmc_project/software/", 0, interfaces);

    // setting canceled task
    // status("xyz.openbmc_project.Common.Task.OperationStatus.Cancelled")
    //  for power operations

    auto bus = sdbusplus::bus::new_default();
    auto method = bus.new_method_call("xyz.openbmc_project.State.Host0",
                                      "/xyz/openbmc_project/state/host0",
                                      "org.freedesktop.DBus.Properties", "Set");

    method.append("xyz.openbmc_project.Common.Task", "Status",
                  dbus::utility::DbusVariantType(status));
    try
    {
        auto reply = bus.call(method);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        BMCWEB_LOG_ERROR("D-Bus error:", e.what());
    }
}

struct Payload
{
    explicit Payload(const crow::Request& req) :
        targetUri(req.url().encoded_path()), httpOperation(req.methodString()),
        httpHeaders(nlohmann::json::array())
    {
        using field_ns = boost::beast::http::field;
        constexpr const std::array<boost::beast::http::field, 7>
            headerWhitelist = {field_ns::accept,     field_ns::accept_encoding,
                               field_ns::user_agent, field_ns::host,
                               field_ns::connection, field_ns::content_length,
                               field_ns::upgrade};

        JsonParseResult ret = parseRequestAsJson(req, jsonBody);
        if (ret != JsonParseResult::Success)
        {
            return;
        }

        for (const auto& field : req.fields())
        {
            if (std::ranges::find(headerWhitelist, field.name()) ==
                headerWhitelist.end())
            {
                continue;
            }
            std::string header;
            header.reserve(
                field.name_string().size() + 2 + field.value().size());
            header += field.name_string();
            header += ": ";
            header += field.value();
            httpHeaders.emplace_back(std::move(header));
        }
    }
    Payload() = delete;

    std::string targetUri;
    std::string httpOperation;
    nlohmann::json httpHeaders;
    nlohmann::json jsonBody;
};

struct TaskData : std::enable_shared_from_this<TaskData>
{
  private:
    TaskData(
        std::function<bool(boost::system::error_code, sdbusplus::message_t&,
                           const std::shared_ptr<TaskData>&)>&& handler,
        const std::string& matchIn, size_t idx) :
        callback(std::move(handler)), matchStr(matchIn), index(idx),
        startTime(std::chrono::system_clock::to_time_t(
            std::chrono::system_clock::now())),
        status("OK"), state("New"), messages(nlohmann::json::array()),
        timer(crow::connections::systemBus->get_io_context())

    {}

  public:
    TaskData() = delete;

    static std::shared_ptr<TaskData>& createTask(
        std::function<bool(boost::system::error_code, sdbusplus::message_t&,
                           const std::shared_ptr<TaskData>&)>&& handler,
        const std::string& match)
    {
        if (tasks.size() == 0)
            lastTask = 1;
        struct MakeSharedHelper : public TaskData
        {
            MakeSharedHelper(
                std::function<bool(boost::system::error_code,
                                   sdbusplus::message_t&,
                                   const std::shared_ptr<TaskData>&)>&& handler,
                const std::string& match2, size_t idx) :
                TaskData(std::move(handler), match2, idx)
            {}
        };

        if (tasks.size() >= maxTaskCount)
        {
            const auto& last = tasks.front();

            // destroy all references
            last->timer.cancel();
            last->match.reset();
            tasks.pop_front();
        }

        return tasks.emplace_back(std::make_shared<MakeSharedHelper>(
            std::move(handler), match, lastTask++));
    }

    void populateResp(crow::Response& res, size_t retryAfterSeconds = 30)
    {
        if (!endTime)
        {
            res.result(boost::beast::http::status::accepted);
            std::string strIdx = std::to_string(index);
            boost::urls::url uri =
                boost::urls::format("/redfish/v1/TaskService/Tasks/{}", strIdx);

            res.jsonValue["@odata.id"] = uri;
            res.jsonValue["@odata.type"] = json_util::odataType("Task");
            res.jsonValue["Id"] = strIdx;
            res.jsonValue["TaskState"] = state;

            if (state == "Completed" || state == "Cancelled" ||
                state == "Exception")
            {
                res.jsonValue["TaskStatus"] = status;
            }

            boost::urls::url taskMonitor = boost::urls::format(
                "/redfish/v1/TaskService/TaskMonitors/{}", strIdx);

            res.addHeader(boost::beast::http::field::location,
                          taskMonitor.buffer());
            res.addHeader(boost::beast::http::field::retry_after,
                          std::to_string(retryAfterSeconds));
        }
        else if (!taskCompleted)
        {
            taskCompleted = true;
        }
    }

    inline void setLastTask()
    {
        for (const std::shared_ptr<task::TaskData>& task : task::tasks)
        {
            // Setting lastTask index after deleting task
            task::lastTask = task->index + 1;
        }
        return;
    }

    void deleteTasks(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                     const std::string& strParam)
    {
        int pos = 0;
        for (const std::shared_ptr<task::TaskData>& task : task::tasks)
        {
            if (std::to_string(task->index) == strParam)
            {
                setStatus(
                    asyncResp,
                    "xyz.openbmc_project.Common.Task.OperationStatus.Cancelled");
                auto taskToDelete = task::tasks.begin();
                advance(taskToDelete, pos);
                if (*taskToDelete != nullptr)
                {
                    BMCWEB_LOG_ERROR("Deleting Task", strParam);
                    task->timer.cancel();
                    task->match.reset();
                    task::tasks.erase(taskToDelete);
                    setLastTask();
                    return;
                }
            }
            pos++;
        }
    }

    void finishTask()
    {
        endTime = std::chrono::system_clock::to_time_t(
            std::chrono::system_clock::now());
    }

    void extendTimer(const std::chrono::seconds& timeout)
    {
        timer.expires_after(timeout);
        sendTaskEvent(state, index);
        timer.async_wait(
            [self = shared_from_this()](boost::system::error_code ec) {
                if (ec == boost::asio::error::operation_aborted)
                {
                    return; // completed successfully
                }
                if (!ec)
                {
                    // change ec to error as timer expired
                    ec = boost::asio::error::operation_aborted;
                }
                self->match.reset();
                sdbusplus::message_t msg;
                self->finishTask();
                self->state = "Cancelled";
                self->status = "Warning";
                self->messages.emplace_back(
                    messages::taskAborted(std::to_string(self->index)));
                // Send event :TaskAborted
                sendTaskEvent(self->state, self->index);
                self->callback(ec, msg, self);
            });
    }

    static void sendTaskEvent(std::string_view state, size_t index)
    {
        // TaskState enums which should send out an event are:
        // "Starting" = taskResumed
        // "Running" = taskStarted
        // "Suspended" = taskPaused
        // "Interrupted" = taskPaused
        // "Pending" = taskPaused
        // "Stopping" = taskAborted
        // "Completed" = taskCompletedOK
        // "Killed" = taskRemoved
        // "Exception" = taskCompletedWarning
        // "Cancelled" = taskCancelled
        nlohmann::json event;
        std::string indexStr = std::to_string(index);
        if (state == "Starting")
        {
            event = redfish::messages::taskResumed(indexStr);
        }
        else if (state == "Running")
        {
            event = redfish::messages::taskStarted(indexStr);
        }
        else if ((state == "Suspended") || (state == "Interrupted") ||
                 (state == "Pending"))
        {
            event = redfish::messages::taskPaused(indexStr);
        }
        else if (state == "Stopping")
        {
            event = redfish::messages::taskAborted(indexStr);
        }
        else if (state == "Completed")
        {
            event = redfish::messages::taskCompletedOK(indexStr);
        }
        else if (state == "Killed")
        {
            event = redfish::messages::taskRemoved(indexStr);
        }
        else if (state == "Exception")
        {
            event = redfish::messages::taskCompletedWarning(indexStr);
        }
        else if (state == "Cancelled")
        {
            event = redfish::messages::taskCancelled(indexStr);
        }
        // else if (state == "New")
        //{
        //     event = redfish::messages::taskCreated(indexStr);
        // }
        else
        {
            BMCWEB_LOG_INFO("sendTaskEvent: No events to send");
            return;
        }
        boost::urls::url origin =
            boost::urls::format("/redfish/v1/TaskService/Tasks/{}", index);
        EventServiceManager::getInstance().sendEvent(event, origin.buffer(),
                                                     "Task");
    }

    void startTimer(const std::chrono::seconds& timeout)
    {
        if (match)
        {
            return;
        }
        match = std::make_unique<sdbusplus::bus::match_t>(
            static_cast<sdbusplus::bus_t&>(*crow::connections::systemBus),
            matchStr,
            [self = shared_from_this()](sdbusplus::message_t& message) {
                boost::system::error_code ec;

                // callback to return True if callback is done, callback needs
                // to update status itself if needed
                if (self->callback(ec, message, self) == task::completed)
                {
                    self->timer.cancel();
                    self->finishTask();

                    // Send event
                    sendTaskEvent(self->state, self->index);

                    // reset the match after the callback was successful
                    boost::asio::post(
                        crow::connections::systemBus->get_io_context(),
                        [self] { self->match.reset(); });
                    return;
                }
            });

        extendTimer(timeout);
        // messages.emplace_back(messages::taskStarted(std::to_string(index)));
        //  Send event : TaskStarted
        // sendTaskEvent(state, index);
    }

    std::function<bool(boost::system::error_code, sdbusplus::message_t&,
                       const std::shared_ptr<TaskData>&)>
        callback;
    std::string matchStr;
    size_t index;
    time_t startTime;
    std::string status;
    std::string state;
    nlohmann::json messages;
    boost::asio::steady_timer timer;
    std::unique_ptr<sdbusplus::bus::match_t> match;
    std::optional<time_t> endTime;
    std::optional<Payload> payload;
    bool taskCompleted = false;
    int percentComplete = 0;
};

} // namespace task

inline void stopLogDumpProcess()
{
    int pid = -1;
    std::string command =
        "pgrep -f '/bin/bash /usr/bin/dreport -d /var/lib/phosphor-debug-collector/dumps/'";
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe)
    {
        return;
    }
    char buffer[128];
    if (fgets(buffer, sizeof(buffer), pipe) != nullptr)
    {
        pid = std::stoi(buffer);
        if (pid != -1)
        {
            if (kill(pid, SIGKILL) == 0)
            {
                BMCWEB_LOG_DEBUG(
                    "Successfully stopped dump process with PID:{}", pid);
            }
            else
            {
                BMCWEB_LOG_DEBUG("Failed to stop dump process with PID:{}",
                                 pid);
            }
        }
        else
        {
            BMCWEB_LOG_DEBUG("Dump process not found");
        }
        pclose(pipe);
    }
}

inline void
    handleTaskDelete(App& app, const crow::Request& req,
                     const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                     const std::string& strParam)
{
    asyncResp->res.clearHeader(boost::beast::http::field::allow);
    asyncResp->res.addHeader("Allow", "GET,DELETE");
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    auto find =
        std::find_if(task::tasks.begin(), task::tasks.end(),
                     [&strParam](const std::shared_ptr<task::TaskData>& task) {
                         if (!task)
                         {
                             return false;
                         }

                         // we compare against the string version as on failure
                         // strtoul returns 0
                         return std::to_string(task->index) == strParam;
                     });

    if (find == task::tasks.end())
    {
        messages::resourceNotFound(asyncResp->res, "Task", strParam);
        return;
    }

    std::shared_ptr<task::TaskData>& ptr = *find;

    if (ptr->state != "New" && ptr->state != "Pending" &&
        ptr->state != "Completed")
    {
        messages::resourceCannotBeDeleted(asyncResp->res);
        return;
    }

    ptr->deleteTasks(asyncResp, strParam);
    asyncResp->res.result(boost::beast::http::status::no_content);

    // Delete the dump initiated process
    std::string dumpUri;
    if (ptr->payload)
    {
	    const task::Payload& p = *(ptr->payload);
	    dumpUri = p.targetUri;
    }
    if(dumpUri == "/redfish/v1/Managers/bmc/LogServices/Dump/Actions/LogService.CollectDiagnosticData")
    {
    	stopLogDumpProcess();
    }
}

inline void
    handleTaskDeleteMonitor(App& app, const crow::Request& req,
                     const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                     const std::string& strParam)
{
    asyncResp->res.clearHeader(boost::beast::http::field::allow);
    auto find =
        std::find_if(task::tasks.begin(), task::tasks.end(),
                     [&strParam](const std::shared_ptr<task::TaskData>& task) {
                         if (!task)
                         {
                             return false;
                         }

                         // we compare against the string version as on failure
                         // strtoul returns 0
                         return std::to_string(task->index) == strParam;
    });
    std::shared_ptr<task::TaskData>& ptr = *find;
    std::string statusval = ptr->state;
    if(statusval == "Completed")
    {
        asyncResp->res.addHeader("Allow", "");
        messages::resourceNotFound(asyncResp->res, "Task", strParam);
        return;
    }
    else
    {
        asyncResp->res.addHeader("Allow", "GET,DELETE");
        handleTaskDelete(app, req, asyncResp, strParam);
    }
}

inline void requestRoutesTaskMonitor(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/TaskService/TaskMonitors/<str>/")
        .privileges(redfish::privileges::getTask)
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& strParam) {
                    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                    {
                        return;
                    }
 		asyncResp->res.clearHeader(boost::beast::http::field::allow);
                asyncResp->res.addHeader("Allow", "GET,DELETE");
                
		        if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }
                auto find = std::ranges::find_if(
                    task::tasks,
                    [&strParam](const std::shared_ptr<task::TaskData>& task) {
                        if (!task)
                        {
                            return false;
                        }

                        // we compare against the string version as on failure
                        // strtoul returns 0
                        return std::to_string(task->index) == strParam;
                    });

                if (find == task::tasks.end())
                {
                    messages::resourceNotFound(asyncResp->res, "Task",
                                               strParam);
                    return;
                }
                std::shared_ptr<task::TaskData>& ptr = *find;
                ptr->populateResp(asyncResp->res);
                // monitor expires after taskCompleted
                if (ptr->taskCompleted)
                {
                    messages::resourceNotFound(asyncResp->res, "Task",
                                               strParam);
                    return;
                }
            });
    BMCWEB_ROUTE(app, "/redfish/v1/TaskService/TaskMonitors/<str>/")
    .methods(boost::beast::http::verb::post, boost::beast::http::verb::patch)(
     [&app](const crow::Request& ,
            const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
            const std::string& strParam) {
                asyncResp->res.clearHeader(boost::beast::http::field::allow);
                auto find =
                std::find_if(task::tasks.begin(), task::tasks.end(),
                     [&strParam](const std::shared_ptr<task::TaskData>& task) {
                         if (!task)
                         {
                             return false;
                         }

                         // we compare against the string version as on failure
                         // strtoul returns 0
                         return std::to_string(task->index) == strParam;
                        });
                std::shared_ptr<task::TaskData>& ptr = *find;
                std::string statusval = ptr->state;
                if(statusval == "Completed")
                {
                        asyncResp->res.addHeader("Allow", "");
                        messages::resourceNotFound(asyncResp->res, "Task", strParam);
                        return;
                }
                else
                {
                        asyncResp->res.addHeader("Allow", "GET,DELETE");
                        messages::operationNotAllowed(asyncResp->res);
                        return;
                }
        });
}

inline void requestRoutesTask(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/TaskService/Tasks/<str>/")
        .privileges(redfish::privileges::getTask)
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& strParam) {
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
               {
                    return;
                }
                asyncResp->res.clearHeader(boost::beast::http::field::allow);
                asyncResp->res.addHeader("Allow", "GET, DELETE");
                auto find = std::ranges::find_if(
                    task::tasks,
                    [&strParam](const std::shared_ptr<task::TaskData>& task) {
                        if (!task)
                        {
                            return false;
                        }

                        // we compare against the string version as on failure
                        // strtoul returns 0
                        return std::to_string(task->index) == strParam;
                    });

                if (find == task::tasks.end())
                {
                    messages::resourceNotFound(asyncResp->res, "Task",
                                               strParam);
                    return;
                }

                const std::shared_ptr<task::TaskData>& ptr = *find;

                asyncResp->res.jsonValue["@odata.type"] = json_util::odataType("Task");
                asyncResp->res.jsonValue["Id"] = strParam;
                asyncResp->res.jsonValue["Name"] = "Task " + strParam;
                asyncResp->res.jsonValue["TaskState"] = ptr->state;
                asyncResp->res.jsonValue["StartTime"] =
                    redfish::time_utils::getDateTimeStdtime(ptr->startTime);
                if (ptr->endTime)
                {
                    asyncResp->res.jsonValue["EndTime"] =
                        redfish::time_utils::getDateTimeStdtime(
                            *(ptr->endTime));
                }

                if (ptr->state == "Completed" || ptr->state == "Cancelled" ||
                    ptr->state == "Exception")
                {
                    asyncResp->res.jsonValue["TaskStatus"] = ptr->status;
                }

                asyncResp->res.jsonValue["Messages"] = ptr->messages;
                asyncResp->res.jsonValue["@odata.id"] = boost::urls::format(
                    "/redfish/v1/TaskService/Tasks/{}", strParam);
		std::string status = ptr->state;                                                                                                     if(status != "Completed")                                                                                                            {                                                                                                                                            asyncResp->res.jsonValue["TaskMonitor"] =                                                                                            boost::urls::format(                                                                                                                     "/redfish/v1/TaskService/TaskMonitors/{}",                                                                                           strParam);                                                                                                               }

                asyncResp->res.jsonValue["HidePayload"] = !ptr->payload;

        std::string uri;
        if (ptr->payload)
        {
            const task::Payload& p = *(ptr->payload);
            asyncResp->res.jsonValue["Payload"]["TargetUri"] = p.targetUri;
            asyncResp->res.jsonValue["Payload"]["HttpOperation"] =
                p.httpOperation;
            asyncResp->res.jsonValue["Payload"]["HttpHeaders"] = p.httpHeaders;
            asyncResp->res.jsonValue["Payload"]["JsonBody"] = p.jsonBody.dump(
                -1, ' ', true, nlohmann::json::error_handler_t::replace);
            uri = p.targetUri;
        }
        if (ptr->state == "Pending")
        {
            if (uri == "/redfish/v1/UpdateService/update")
            {
                    sdbusplus::asio::getProperty<uint64_t>(
                        *crow::connections::systemBus,
                        "xyz.openbmc_project.Settings",
                        "/xyz/openbmc_project/software/apply_time",
                        "xyz.openbmc_project.Software.ApplyTime",
                        "MaintenanceWindowStartTime",
                        [asyncResp](const boost::system::error_code& ec, const uint64_t& maintenanceWindowStartTime) {
                            if (ec)
                            {
                                BMCWEB_LOG_ERROR("D-Bus responses error: {}",
                                                 ec);
                                messages::internalError(asyncResp->res);
                                return;                                                                                                                          }
                            const auto current_time = std::chrono::system_clock::to_time_t(
                                std::chrono::system_clock::now());
                            if (static_cast<uint64_t>(current_time) > maintenanceWindowStartTime)
                            {
                                  asyncResp->res.jsonValue["TaskState"] = "Stopping";
                            }
                        });
            }
        }
	else if(ptr->state == "Completed")
	{
		asyncResp->res.jsonValue["PercentComplete"] = 100;
	}
	else
	{
	        asyncResp->res.jsonValue["PercentComplete"] = ptr->percentComplete;
	}
    });

    BMCWEB_ROUTE(app, "/redfish/v1/TaskService/Tasks/<str>/")
        .privileges(redfish::privileges::getTask)
        .methods(boost::beast::http::verb::post,
                 boost::beast::http::verb::patch,
                 boost::beast::http::verb::put)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& strParam) {
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }
                asyncResp->res.clearHeader(boost::beast::http::field::allow);
                asyncResp->res.addHeader("Allow", "GET, DELETE");
                auto find = std::ranges::find_if(
                    task::tasks,
                    [&strParam](const std::shared_ptr<task::TaskData>& task) {
                        if (!task)
                        {
                            return false;
                        }

                        return std::to_string(task->index) == strParam;
                    });

                if (find == task::tasks.end())
                {
                    messages::resourceNotFound(asyncResp->res, "Task",
                                               strParam);
                    return;
                }

                messages::operationNotAllowed(asyncResp->res);
                return;
            });
}

inline void requestRoutesTaskCollection(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/TaskService/Tasks/")
        .privileges(redfish::privileges::getTaskCollection)
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp) {
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }
                asyncResp->res.jsonValue["@odata.type"] =
                    "#TaskCollection.TaskCollection";
                asyncResp->res.jsonValue["@odata.id"] =
                    "/redfish/v1/TaskService/Tasks";
                asyncResp->res.jsonValue["Name"] = "Task Collection";
                asyncResp->res.jsonValue["Description"] = "Task Collection";
                asyncResp->res.jsonValue["Members@odata.count"] =
                    task::tasks.size();
                nlohmann::json& members = asyncResp->res.jsonValue["Members"];
                members = nlohmann::json::array();

                for (const std::shared_ptr<task::TaskData>& task : task::tasks)
                {
                    if (task == nullptr)
                    {
                        continue; // shouldn't be possible
                    }
                    nlohmann::json::object_t member;
                    member["@odata.id"] =
                        boost::urls::format("/redfish/v1/TaskService/Tasks/{}",
                                            std::to_string(task->index));
                    members.emplace_back(std::move(member));
                }
            });
}

inline void requestRoutesTaskService(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/TaskService/")
        .privileges(redfish::privileges::getTaskService)
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp) {
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }
                asyncResp->res.jsonValue["@odata.type"] = json_util::odataType("TaskService");
                asyncResp->res.jsonValue["@odata.id"] =
                    "/redfish/v1/TaskService";
                asyncResp->res.jsonValue["Name"] = "Task Service";
                asyncResp->res.jsonValue["Description"] = "Task Collection";
                asyncResp->res.jsonValue["Id"] = "TaskService";
                asyncResp->res.jsonValue["DateTime"] =
                    redfish::time_utils::getDateTimeOffsetNow().first;
                asyncResp->res.jsonValue["CompletedTaskOverWritePolicy"] =
                    task_service::OverWritePolicy::Oldest;

                asyncResp->res.jsonValue["LifeCycleEventOnTaskStateChange"] =
                    true;

                asyncResp->res.jsonValue["Status"]["State"] =
                    resource::State::Enabled;
                asyncResp->res.jsonValue["ServiceEnabled"] = true;
                asyncResp->res.jsonValue["Tasks"]["@odata.id"] =
                    "/redfish/v1/TaskService/Tasks";
            });
}

inline void requestRoutesTaskDelete(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/TaskService/Tasks/<str>/")
        .privileges(redfish::privileges::deleteTask)
        .methods(boost::beast::http::verb::delete_)(
            std::bind_front(handleTaskDelete, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/TaskService/TaskMonitors/<str>")
        .privileges(redfish::privileges::deleteTask)
        .methods(boost::beast::http::verb::delete_)(
            std::bind_front(handleTaskDeleteMonitor, std::ref(app)));
}
} // namespace redfish
