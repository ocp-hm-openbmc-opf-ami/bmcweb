#pragma once

#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/url/format.hpp>
#include <sdbusplus/bus/match.hpp>
#include "utils/dbus_utils.hpp"
#include <sdbusplus/bus.hpp>
#include "dbus_utility.hpp"

#include <chrono>
#include <memory>
#include <ranges>
#include <variant>
#include <ctime>
#include <iostream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <unistd.h>
static constexpr const char* taskService = "xyz.openbmc_project.RedfishPreserve";
static constexpr const char* taskInterface = "xyz.openbmc_project.RFPreserve.RedfishPreserve";
static constexpr const char* taskObject = "/xyz/openbmc_project/RedfishPreserve/taskHandle";
static constexpr const char* taskCreateInterface = "xyz.openbmc_project.RFPreserve.RFPmethod";

namespace redfish
{
namespace taskservice
{

using PropertyValue =
    std::variant<uint8_t, uint16_t, uint32_t, uint64_t, int, std::string>;

/**
 * Func give current system date time in string format
 *
 * @param[in] 
 * @param[in]
 */
inline std::string getCurrentDateTime(void)
{
  const int bufferSize = 40;
  auto now = std::chrono::system_clock::now();
  std::time_t now_c = std::chrono::system_clock::to_time_t(now);
  char *buffer = new char[bufferSize];
  std::snprintf(buffer, bufferSize, "%s", std::ctime(&now_c));
  std::string strbuffer(buffer);
  delete[] buffer;
  return strbuffer;
}

/**
 * Func convert system time date to epoch time
 *
 * @param[in] timeStamp - Current BMC Time in string format
 * @param[in]
 */
inline time_t timeStamptoepoch(std::string& timeStamp)
{
   if(timeStamp.empty())
   {
       return (time_t)0;
   }

   if (!timeStamp.empty() && timeStamp[timeStamp.length() - 1] == '\n') {
        timeStamp.pop_back();
   }
   std::tm tm_struct = {};
   std::istringstream ss(timeStamp);
   ss >> std::get_time(&tm_struct, "%a %b %d %H:%M:%S %Y");
   if (ss.fail())
    {
        return (time_t)0;
    }
    return std::mktime(&tm_struct);
}

/**
 * Func create Task Service on D-Bus
 *
 * @param[in] timeStamp - type of task
 * @param[in] index - task index
 */
inline const std::string createTaskService(std::string type, int index) 
{
    std::string value;
    const char* methodCall = "TaskCreate";
    try
    {
        auto bus = sdbusplus::bus::new_default_system();
        auto method = bus.new_method_call(taskService, 
                taskObject, taskCreateInterface, methodCall);
        method.append(type, index);
        auto reply = bus.call(method);
        reply.read(value);
     }
    catch (const std::exception& e)
    {
        BMCWEB_LOG_ERROR("Error creating task service: {}", e.what());
    }
    return value;
}

/**
 * Func delete Task Service on D-Bus
 *
 * @param[in] index - task index
 */

inline int deleteTaskService(size_t index) 
{
    int value;
    std::string delTask = "Task_" + std::to_string(index);
    const char* methodCall = "TaskDelete";
    try
    {
        BMCWEB_LOG_DEBUG("Deleting Task Service : {}", delTask.c_str());
        auto bus = sdbusplus::bus::new_default_system();
        auto method = bus.new_method_call(taskService, taskObject, 
                                        taskCreateInterface, methodCall);
        method.append(delTask);
        auto reply = bus.call(method);
        reply.read(value);
     }
    catch (const std::exception& e)
    {
        BMCWEB_LOG_ERROR("Error deleting task service: {}", e.what());
    }
    return value;
}

/**
 * Func get property value on D-Bus
 *
 * @param[in] propertyName - dbus property name
 */
inline std::string getTaskState(const std::string& objPath)
{
    PropertyValue value{};
    constexpr const char* dbuspropertyInterface = "org.freedesktop.DBus.Properties";

    try 
    {
        auto bus = sdbusplus::bus::new_default_system();
        auto method = bus.new_method_call(taskService, objPath.c_str(),
                                        dbuspropertyInterface, "Get");
        method.append("xyz.openbmc_project.RFPreserve.RedfishPreserve", "TaskState");
        auto reply = bus.call(method);
        reply.read(value);
    }
    catch (const std::exception& e)
    {
        BMCWEB_LOG_ERROR("Error getting task property: {}", e.what());
    }
    
    return std::get<std::string>(value);
}

/**
 * Func get property value on D-Bus
 *
 * @param[in] propertyName - dbus property name
 */

inline void setServiceProperty(std::string& objPath, 
                    std::string property, std::string value)
{
    sdbusplus::asio::setProperty(
            *crow::connections::systemBus, taskService, objPath,
            taskInterface, property, value,
            [&](const boost::system::error_code& ec) {
                if (ec)
                {
                    BMCWEB_LOG_ERROR("D-Bus responses error: {}", ec);
                    return;
                }
    });
}

/**
 * Func set Task message on D-Bus
 *
 * @param[in] message - dbus property name
 * @param[in] index  - index of task
 */

inline void setTaskMessage(std::string message, size_t index)
{
    std::string taskObjPath = "/xyz/openbmc_project/Task/task_" 
                                            + std::to_string(index);
    setServiceProperty(taskObjPath, 
    "TaskMessage", 
    message);
}

/**
 * Func set Task state on D-Bus
 *
 * @param[in] state - state of task
 * @param[in] index  - index of task
 */

inline void setTaskState(std::string state, size_t index)
{
    std::string taskObjPath = "/xyz/openbmc_project/Task/task_" 
                                                + std::to_string(index);
    setServiceProperty(taskObjPath, 
    "TaskState", 
    "xyz.openbmc_project.RFPreserve.RedfishPreserve.State." + state);

    if(state == "Completed" || state == "Exception" 
        || state == "Killed" || state == "Cancelled")
    {
        BMCWEB_LOG_DEBUG("Setting End Time for Task Index : {} \r\n", index);
        setServiceProperty(taskObjPath, 
        "EndTime",
        ""+getCurrentDateTime());
        syslog(LOG_INFO, "Task %zu state changed to %s\n", 
            index, state.c_str());
    }
}

/**
 * Func set Task status on D-Bus
 *
 * @param[in] status - status of task
 * @param[in] index  - index of task
 */

inline void setTaskStatus(std::string status, size_t index)
{
    std::string taskObjPath = "/xyz/openbmc_project/Task/task_" 
                                            + std::to_string(index);
    setServiceProperty(taskObjPath, 
    "TaskStatus", 
    "xyz.openbmc_project.RFPreserve.RedfishPreserve.Health." + status);
}

} // namespace task
} // namespace redfish
