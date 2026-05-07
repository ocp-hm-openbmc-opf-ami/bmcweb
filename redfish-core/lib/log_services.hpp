// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
// SPDX-FileCopyrightText: Copyright 2018 Intel Corporation
#pragma once

#include "app.hpp"
#include "dbus_utility.hpp"
#include "error_messages.hpp"
#include "ethernet.hpp"
#include "event_service.hpp"
#include "generated/enums/log_entry.hpp"
#include "generated/enums/log_service.hpp"
#include "gzfile.hpp"
#include "http_utility.hpp"
#include "human_sort.hpp"
#include "log_error.hpp"
#include "multipart_parser.hpp"
#include "query.hpp"
#include "registries.hpp"
#include "registries/base_message_registry.hpp"
#include "registries/openbmc_message_registry.hpp"
#include "registries/privilege_registry.hpp"
#include "system_utils.hpp"
#include "task.hpp"
#include "task_messages.hpp"
#include "utils/dbus_event_log_entry.hpp"
#include "utils/dbus_utils.hpp"
#include "utils/json_utils.hpp"
#include "utils/time_utils.hpp"

#include <systemd/sd-id128.h>
#include <tinyxml2.h>
#include <unistd.h>

#include <boost/beast/http/verb.hpp>
#include <boost/container/flat_map.hpp>
#include <boost/system/linux_error.hpp>
#include <boost/url/format.hpp>
#include <sdbusplus/asio/property.hpp>
#include <sdbusplus/unpack_properties.hpp>

#include <array>
#include <charconv>
#include <cstddef>
#include <filesystem>
#include <iterator>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <variant>

namespace redfish
{

constexpr const char* crashdumpObject = "com.intel.crashdump";
constexpr const char* crashdumpPath = "/com/intel/crashdump";
constexpr const char* intelcrashdumpInterface = "com.intel.crashdump";
constexpr const char* amdcrashdumpObject = "com.amd.crashdump";
constexpr const char* amdcrashdumpPath = "/com/amd/crashdump";
constexpr const char* crashdumpInterface = "com.amd.crashdump";
constexpr const char* crashdumpconfigInterface =
    "com.amd.crashdump.Configuration";
constexpr const char* deleteAllInterface =
    "xyz.openbmc_project.Collection.DeleteAll";
constexpr const char* crashdumpOnDemandInterface =
    "com.intel.crashdump.OnDemand";
constexpr const char* crashdumpTelemetryInterface =
    "com.intel.crashdump.Telemetry";

// Rsyslog Feature changes
std::string syslogFileName("");

std::string syslogCacertFileName = "rsyslog_cacert.pem";
std::string syslogServerCRTFileName = "rsyslog_server.crt";
std::string syslogServerKeyFileName = "rsyslog_server.key";
namespace fs = std::filesystem;
fs::path syslogCertsPath = "/etc/ssl/certs/rsyslog/";

fs::path syslogCACERTFilePath = syslogCertsPath / syslogCacertFileName;
fs::path syslogServerCRTFilePath = syslogCertsPath / syslogServerCRTFileName;
fs::path syslogServerKeyFilePath = syslogCertsPath / syslogServerKeyFileName;

std::string syslogCACERTFile(syslogCACERTFilePath);
std::string syslogServerCRTFile(syslogServerCRTFilePath);
std::string syslogServerKeyFile(syslogServerKeyFilePath);

constexpr const char* syslogServicePath = "xyz.openbmc_project.Syslog.Config";
constexpr const char* syslogObjectPath =
    "/xyz/openbmc_project/logging/config/remote";
constexpr const char* syslogInterface = "xyz.openbmc_project.Network.Client";

using PropertyValue = std::variant<uint8_t, uint16_t, uint64_t, std::string,
                                   std::vector<std::string>, bool>;

enum class DumpCreationProgress
{
    DUMP_CREATE_SUCCESS,
    DUMP_CREATE_FAILED,
    DUMP_CREATE_INPROGRESS
};

inline std::string timeFormat(std::string timestamp)
{
    std::size_t dot = timestamp.find_first_of('.');
    std::size_t plus = timestamp.find_first_of('+');
    if (dot != std::string::npos && plus != std::string::npos)
    {
        timestamp.erase(dot, plus - dot);
    }
    return timestamp;
}

inline std::string translateSeverityDbusToRedfish(const std::string& s)
{
    if ((s == "xyz.openbmc_project.Logging.Entry.Level.Alert") ||
        (s == "xyz.openbmc_project.Logging.Entry.Level.Critical") ||
        (s == "xyz.openbmc_project.Logging.Entry.Level.Emergency") ||
        (s == "xyz.openbmc_project.Logging.Entry.Level.Error"))
    {
        return "Critical";
    }
    if ((s == "xyz.openbmc_project.Logging.Entry.Level.Debug") ||
        (s == "xyz.openbmc_project.Logging.Entry.Level.Informational") ||
        (s == "xyz.openbmc_project.Logging.Entry.Level.Notice"))
    {
        return "OK";
    }
    if (s == "xyz.openbmc_project.Logging.Entry.Level.Warning")
    {
        return "Warning";
    }
    if (s == "xyz.openbmc_project.Logging.Entry.Level.NotApplicable")
    {
        return "NotApplicable";
    }
    return "";
}

inline std::optional<bool> getProviderNotifyAction(const std::string& notify)
{
    std::optional<bool> notifyAction;
    if (notify == "xyz.openbmc_project.Logging.Entry.Notify.Notify")
    {
        notifyAction = true;
    }
    else if (notify == "xyz.openbmc_project.Logging.Entry.Notify.Inhibit")
    {
        notifyAction = false;
    }

    return notifyAction;
}

const PropertyValue getCrashdumpConfig(
    const std::string& processName, const std::string& objectPath,
    const std::string& interfaceName, const std::string& propertyName)
{
    PropertyValue value;

    auto b = sdbusplus::bus::new_default_system();
    auto method = b.new_method_call(processName.c_str(), objectPath.c_str(),
                                    "org.freedesktop.DBus.Properties", "Get");
    method.append(interfaceName, propertyName);
    auto reply = b.call(method);
    reply.read(value);
    return value;
}

std::string getRecoveryMode(uint16_t value)
{
    if (value == 2)
        return "WarmReset";
    else if (value == 1)
        return "ColdReset";
    else
        return "None";
}

uint16_t getrecoverydata(std::string value)
{
    if (value == "WarmReset")
        return 2;
    else if (value == "ColdReset")
        return 1;
    else if (value == "None")
        return 0;
    else
        return 3;
}

std::string getDumpPath(std::string_view dumpType)
{
    std::string dbusDumpPath = "/xyz/openbmc_project/dump/";
    std::ranges::transform(dumpType, std::back_inserter(dbusDumpPath),
                           bmcweb::asciiToLower);

    return dbusDumpPath;
}

inline bool getUniqueEntryID(const std::string& logEntry, std::string& entryID,
                             const bool firstEntry = true)
{
    static time_t prevTs = 0;
    static int index = 0;
    if (firstEntry)
    {
        prevTs = 0;
    }

    // Get the entry timestamp
    std::time_t curTs = 0;
    std::tm timeStruct = {};
    std::istringstream entryStream(logEntry);
    if (entryStream >> std::get_time(&timeStruct, "%Y-%m-%dT%H:%M:%S"))
    {
        curTs = std::mktime(&timeStruct);
    }
    // If the timestamp isn't unique, increment the index
    if (curTs == prevTs)
    {
        index++;
    }
    else
    {
        // Otherwise, reset it
        index = 0;
    }
    // Save the timestamp
    prevTs = curTs;

    entryID = std::to_string(curTs);
    if (index > 0)
    {
        entryID += "_" + std::to_string(index);
    }
    return true;
}

inline bool getRedfishLogFiles(
    std::vector<std::filesystem::path>& redfishLogFiles)
{
    static const std::filesystem::path redfishLogDir = "/var/log";
    static const std::string redfishLogFilename = "redfish";

    // Loop through the directory looking for redfish log files
    for (const std::filesystem::directory_entry& dirEnt :
         std::filesystem::directory_iterator(redfishLogDir))
    {
        // If we find a redfish log file, save the path
        std::string filename = dirEnt.path().filename();
        if (filename.starts_with(redfishLogFilename))
        {
            redfishLogFiles.emplace_back(redfishLogDir / filename);
        }
    }
    // As the log files rotate, they are appended with a ".#" that is higher for
    // the older logs. Since we don't expect more than 10 log files, we
    // can just sort the list to get them in order from newest to oldest
    std::ranges::sort(redfishLogFiles);

    return !redfishLogFiles.empty();
}

log_entry::OriginatorTypes mapDbusOriginatorTypeToRedfish(
    const std::string& originatorType)
{
    if (originatorType ==
        "xyz.openbmc_project.Common.OriginatedBy.OriginatorTypes.Client")
    {
        return log_entry::OriginatorTypes::Client;
    }
    if (originatorType ==
        "xyz.openbmc_project.Common.OriginatedBy.OriginatorTypes.Internal")
    {
        return log_entry::OriginatorTypes::Internal;
    }
    if (originatorType ==
        "xyz.openbmc_project.Common.OriginatedBy.OriginatorTypes.SupportingService")
    {
        return log_entry::OriginatorTypes::SupportingService;
    }
    return log_entry::OriginatorTypes::Invalid;
}

inline void parseDumpEntryFromDbusObject(
    const dbus::utility::ManagedObjectType::value_type& object,
    std::string& dumpStatus, uint64_t& size, uint64_t& timestampUs,
    std::string& originatorId, log_entry::OriginatorTypes& originatorType,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    for (const auto& interfaceMap : object.second)
    {
        if (interfaceMap.first == "xyz.openbmc_project.Common.Progress")
        {
            for (const auto& propertyMap : interfaceMap.second)
            {
                if (propertyMap.first == "Status")
                {
                    const auto* status =
                        std::get_if<std::string>(&propertyMap.second);
                    if (status == nullptr)
                    {
                        messages::internalError(asyncResp->res);
                        break;
                    }
                    dumpStatus = *status;
                }
            }
        }
        else if (interfaceMap.first == "xyz.openbmc_project.Dump.Entry")
        {
            for (const auto& propertyMap : interfaceMap.second)
            {
                if (propertyMap.first == "Size")
                {
                    const auto* sizePtr =
                        std::get_if<uint64_t>(&propertyMap.second);
                    if (sizePtr == nullptr)
                    {
                        messages::internalError(asyncResp->res);
                        break;
                    }
                    size = *sizePtr;
                    break;
                }
            }
        }
        else if (interfaceMap.first == "xyz.openbmc_project.Time.EpochTime")
        {
            for (const auto& propertyMap : interfaceMap.second)
            {
                if (propertyMap.first == "Elapsed")
                {
                    const uint64_t* usecsTimeStamp =
                        std::get_if<uint64_t>(&propertyMap.second);
                    if (usecsTimeStamp == nullptr)
                    {
                        messages::internalError(asyncResp->res);
                        break;
                    }
                    timestampUs = *usecsTimeStamp;
                    break;
                }
            }
        }
        else if (interfaceMap.first ==
                 "xyz.openbmc_project.Common.OriginatedBy")
        {
            for (const auto& propertyMap : interfaceMap.second)
            {
                if (propertyMap.first == "OriginatorId")
                {
                    const std::string* id =
                        std::get_if<std::string>(&propertyMap.second);
                    if (id == nullptr)
                    {
                        messages::internalError(asyncResp->res);
                        break;
                    }
                    originatorId = *id;
                }

                if (propertyMap.first == "OriginatorType")
                {
                    const std::string* type =
                        std::get_if<std::string>(&propertyMap.second);
                    if (type == nullptr)
                    {
                        messages::internalError(asyncResp->res);
                        break;
                    }

                    originatorType = mapDbusOriginatorTypeToRedfish(*type);
                    if (originatorType == log_entry::OriginatorTypes::Invalid)
                    {
                        messages::internalError(asyncResp->res);
                        break;
                    }
                }
            }
        }
    }
}

static std::string getDumpEntriesPath(const std::string& dumpType)
{
    std::string entriesPath;

    if (dumpType == "BMC")
    {
        entriesPath =
            std::format("/redfish/v1/Managers/{}/LogServices/Dump/Entries/",
                        BMCWEB_REDFISH_MANAGER_URI_NAME);
    }
    else if (dumpType == "FaultLog")
    {
        entriesPath =
            std::format("/redfish/v1/Managers/{}/LogServices/FaultLog/Entries/",
                        BMCWEB_REDFISH_MANAGER_URI_NAME);
    }
    else if (dumpType == "System")
    {
        entriesPath =
            std::format("/redfish/v1/Systems/{}/LogServices/Dump/Entries/",
                        BMCWEB_REDFISH_SYSTEM_URI_NAME);
    }
    else
    {
        BMCWEB_LOG_ERROR("getDumpEntriesPath() invalid dump type: {}",
                         dumpType);
    }

    // Returns empty string on error
    return entriesPath;
}

inline void getDumpEntryCollection(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& dumpType)
{
    std::string entriesPath = getDumpEntriesPath(dumpType);
    if (entriesPath.empty())
    {
        messages::internalError(asyncResp->res);
        return;
    }

    sdbusplus::message::object_path path("/xyz/openbmc_project/dump");
    dbus::utility::getManagedObjects(
        "xyz.openbmc_project.Dump.Manager", path,
        [asyncResp, entriesPath,
         dumpType](const boost::system::error_code& ec,
                   const dbus::utility::ManagedObjectType& objects) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("DumpEntry resp_handler got error {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }

            // Remove ending slash
            std::string odataIdStr = entriesPath;
            if (!odataIdStr.empty())
            {
                odataIdStr.pop_back();
            }

            asyncResp->res.jsonValue["@odata.type"] =
                json_util::odataType("LogEntryCollection");
            asyncResp->res.jsonValue["@odata.id"] = std::move(odataIdStr);
            asyncResp->res.jsonValue["Name"] = dumpType + " Dump Entries";
            asyncResp->res.jsonValue["Description"] =
                "Collection of " + dumpType + " Dump Entries";

            nlohmann::json::array_t entriesArray;
            std::string dumpEntryPath = getDumpPath(dumpType) + "/entry/";

            dbus::utility::ManagedObjectType resp(objects);
            std::ranges::sort(resp, [](const auto& l, const auto& r) {
                return AlphanumLess<std::string>()(l.first.filename(),
                                                   r.first.filename());
            });

            for (auto& object : resp)
            {
                if (object.first.str.find(dumpEntryPath) == std::string::npos)
                {
                    continue;
                }
                uint64_t timestampUs = 0;
                uint64_t size = 0;
                std::string dumpStatus;
                std::string originatorId;
                log_entry::OriginatorTypes originatorType =
                    log_entry::OriginatorTypes::Internal;
                nlohmann::json::object_t thisEntry;

                std::string entryID = object.first.filename();
                if (entryID.empty())
                {
                    continue;
                }

                parseDumpEntryFromDbusObject(object, dumpStatus, size,
                                             timestampUs, originatorId,
                                             originatorType, asyncResp);

                if (dumpStatus !=
                        "xyz.openbmc_project.Common.Progress.OperationStatus.Completed" &&
                    !dumpStatus.empty())
                {
                    // Dump status is not Complete, no need to enumerate
                    continue;
                }

                thisEntry["@odata.type"] = json_util::odataType("LogEntry");
                thisEntry["@odata.id"] = entriesPath + entryID;
                thisEntry["Id"] = entryID;
                thisEntry["EntryType"] = "Event";
                thisEntry["Name"] = dumpType + " Dump Entry";
                thisEntry["Description"] = dumpType + " Dump Entry";
                thisEntry["Created"] = timeFormat(
                    redfish::time_utils::getDateTimeUintUs(timestampUs));

                if (!originatorId.empty())
                {
                    thisEntry["Originator"] = originatorId;
                    thisEntry["OriginatorType"] = originatorType;
                }

                if (dumpType == "BMC")
                {
                    thisEntry["DiagnosticDataType"] = "Manager";
                    thisEntry["AdditionalDataURI"] =
                        entriesPath + entryID + "/attachment";
                    thisEntry["AdditionalDataSizeBytes"] = size;
                }
                else if (dumpType == "System")
                {
                    thisEntry["DiagnosticDataType"] = "OEM";
                    thisEntry["OEMDiagnosticDataType"] = "System";
                    thisEntry["AdditionalDataURI"] =
                        entriesPath + entryID + "/attachment";
                    thisEntry["AdditionalDataSizeBytes"] = size;
                }
                entriesArray.emplace_back(std::move(thisEntry));
            }
            asyncResp->res.jsonValue["Members@odata.count"] =
                entriesArray.size();
            asyncResp->res.jsonValue["Members"] = std::move(entriesArray);
        });
}

inline void getDumpEntryById(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& entryID, const std::string& dumpType)
{
    std::string entriesPath = getDumpEntriesPath(dumpType);
    if (entriesPath.empty())
    {
        messages::internalError(asyncResp->res);
        return;
    }

    sdbusplus::message::object_path path("/xyz/openbmc_project/dump");
    dbus::utility::getManagedObjects(
        "xyz.openbmc_project.Dump.Manager", path,
        [asyncResp, entryID, dumpType,
         entriesPath](const boost::system::error_code& ec,
                      const dbus::utility::ManagedObjectType& resp) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("DumpEntry resp_handler got error {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }

            bool foundDumpEntry = false;
            std::string dumpEntryPath = getDumpPath(dumpType) + "/entry/";

            for (const auto& objectPath : resp)
            {
                if (objectPath.first.str != dumpEntryPath + entryID)
                {
                    continue;
                }

                foundDumpEntry = true;
                uint64_t timestampUs = 0;
                uint64_t size = 0;
                std::string dumpStatus;
                std::string originatorId;
                log_entry::OriginatorTypes originatorType =
                    log_entry::OriginatorTypes::Internal;

                parseDumpEntryFromDbusObject(objectPath, dumpStatus, size,
                                             timestampUs, originatorId,
                                             originatorType, asyncResp);

                if (dumpStatus !=
                        "xyz.openbmc_project.Common.Progress.OperationStatus.Completed" &&
                    !dumpStatus.empty())
                {
                    // Dump status is not Complete
                    // return not found until status is changed to Completed
                    messages::resourceNotFound(asyncResp->res,
                                               dumpType + " dump", entryID);
                    return;
                }

                asyncResp->res.jsonValue["@odata.type"] =
                    json_util::odataType("LogEntry");
                asyncResp->res.jsonValue["@odata.id"] = entriesPath + entryID;
                asyncResp->res.jsonValue["Id"] = entryID;
                asyncResp->res.jsonValue["EntryType"] = "Event";
                asyncResp->res.jsonValue["Name"] = dumpType + " Dump Entry";
                asyncResp->res.jsonValue["Description"] =
                    dumpType + " Dump Entry";
                asyncResp->res.jsonValue["Created"] = timeFormat(
                    redfish::time_utils::getDateTimeUintUs(timestampUs));

                if (!originatorId.empty())
                {
                    asyncResp->res.jsonValue["Originator"] = originatorId;
                    asyncResp->res.jsonValue["OriginatorType"] = originatorType;
                }

                if (dumpType == "BMC")
                {
                    asyncResp->res.jsonValue["DiagnosticDataType"] = "Manager";
                    asyncResp->res.jsonValue["AdditionalDataURI"] =
                        entriesPath + entryID + "/attachment";
                    asyncResp->res.jsonValue["AdditionalDataSizeBytes"] = size;
                }
                else if (dumpType == "System")
                {
                    asyncResp->res.jsonValue["DiagnosticDataType"] = "OEM";
                    asyncResp->res.jsonValue["OEMDiagnosticDataType"] =
                        "System";
                    asyncResp->res.jsonValue["AdditionalDataURI"] =
                        entriesPath + entryID + "/attachment";
                    asyncResp->res.jsonValue["AdditionalDataSizeBytes"] = size;
                }
            }
            if (!foundDumpEntry)
            {
                BMCWEB_LOG_WARNING("Can't find Dump Entry {}", entryID);
                messages::resourceNotFound(asyncResp->res, dumpType + " dump",
                                           entryID);
                return;
            }
        });
}

void deleteDumpEntry(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                     const std::string& entryID, const std::string& dumpType)
{
    auto respHandler = [asyncResp,
                        entryID](const boost::system::error_code& ec) {
        BMCWEB_LOG_DEBUG("Dump Entry doDelete callback: Done");
        if (ec)
        {
            if (ec.value() == EBADR)
            {
                messages::resourceNotFound(asyncResp->res, "LogEntry", entryID);
                return;
            }
            BMCWEB_LOG_ERROR(
                "Dump (DBus) doDelete respHandler got error {} entryID={}", ec,
                entryID);
            messages::internalError(asyncResp->res);
            return;
        }
    };

    crow::connections::systemBus->async_method_call(
        respHandler, "xyz.openbmc_project.Dump.Manager",
        std::format("{}/entry/{}", getDumpPath(dumpType), entryID),
        "xyz.openbmc_project.Object.Delete", "Delete");
}
bool checkSizeLimit(int fd, crow::Response& res)
{
    long long int size = lseek(fd, 0, SEEK_END);
    if (size <= 0)
    {
        BMCWEB_LOG_ERROR("Failed to get size of file, lseek() returned {}",
                         size);
        messages::internalError(res);
        return false;
    }

    // Arbitrary max size of 20MB to accommodate BMC dumps
    constexpr long long int maxFileSize = 20LL * 1024LL * 1024LL;
    if (size > maxFileSize)
    {
        BMCWEB_LOG_ERROR("File size {} exceeds maximum allowed size of {}",
                         size, maxFileSize);
        messages::internalError(res);
        return false;
    }
    off_t rc = lseek(fd, 0, SEEK_SET);
    if (rc < 0)
    {
        BMCWEB_LOG_ERROR("Failed to reset file offset to 0");
        messages::internalError(res);
        return false;
    }
    return true;
}
inline void downloadEntryCallback(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& entryID, const std::string& downloadEntryType,
    const boost::system::error_code& ec,
    const sdbusplus::message::unix_fd& unixfd)
{
    if (ec.value() == EBADR)
    {
        messages::resourceNotFound(asyncResp->res, "EntryAttachment", entryID);
        return;
    }
    if (ec)
    {
        BMCWEB_LOG_ERROR("DBUS response error: {}", ec);
        messages::internalError(asyncResp->res);
        return;
    }

    // Make sure we know how to process the retrieved entry attachment
    if ((downloadEntryType != "BMC") && (downloadEntryType != "System"))
    {
        BMCWEB_LOG_ERROR("downloadEntryCallback() invalid entry type: {}",
                         downloadEntryType);
        messages::internalError(asyncResp->res);
    }

    int fd = -1;
    fd = dup(unixfd);
    if (fd < 0)
    {
        BMCWEB_LOG_ERROR("Failed to open file");
        messages::internalError(asyncResp->res);
        return;
    }
    if (!checkSizeLimit(fd, asyncResp->res))
    {
        close(fd);
        return;
    }
    if (downloadEntryType == "System")
    {
        if (!asyncResp->res.openFd(fd, bmcweb::EncodingType::Base64))
        {
            messages::internalError(asyncResp->res);
            close(fd);
            return;
        }
        asyncResp->res.addHeader(
            boost::beast::http::field::content_transfer_encoding, "Base64");
        asyncResp->res.addHeader(boost::beast::http::field::content_type,
                                 "application/octet-stream");
        return;
    }
    if (!asyncResp->res.openFd(fd))
    {
        messages::internalError(asyncResp->res);
        close(fd);
        return;
    }
    asyncResp->res.addHeader(boost::beast::http::field::content_type,
                             "application/octet-stream");
}

inline void downloadDumpEntry(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& entryID, const std::string& dumpType)
{
    if (dumpType != "BMC")
    {
        BMCWEB_LOG_WARNING("Can't find Dump Entry {}", entryID);
        messages::resourceNotFound(asyncResp->res, dumpType + " dump", entryID);
        return;
    }

    std::string dumpEntryPath =
        std::format("{}/entry/{}", getDumpPath(dumpType), entryID);

    auto downloadDumpEntryHandler =
        [asyncResp, entryID,
         dumpType](const boost::system::error_code& ec,
                   const sdbusplus::message::unix_fd& unixfd) {
            downloadEntryCallback(asyncResp, entryID, dumpType, ec, unixfd);
        };

    crow::connections::systemBus->async_method_call(
        std::move(downloadDumpEntryHandler), "xyz.openbmc_project.Dump.Manager",
        dumpEntryPath, "xyz.openbmc_project.Dump.Entry", "GetFileHandle");
}

inline void downloadEventLogEntry(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& systemName, const std::string& entryID,
    const std::string& dumpType)
{
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

    std::string entryPath =
        sdbusplus::message::object_path("/xyz/openbmc_project/logging/entry") /
        entryID;

    dbus::utility::getProperty<std::map<std::string, std::string>>(
        "xyz.openbmc_project.Logging", entryPath,
        "xyz.openbmc_project.Logging.Entry", "AdditionalData",
        [asyncResp, dumpType,
         entryID](const boost::system::error_code& ec,
                  const std::map<std::string, std::string>& additionalData) {
            if (ec.value() == EBADR)
            {
                messages::resourceNotFound(asyncResp->res, "LogEntry", entryID);
                return;
            }
            if (ec)
            {
                BMCWEB_LOG_DEBUG(
                    "Got DBUS response error while getting AdditionalData in {}",
                    dumpType);
                return;
            }
            nlohmann::json jsonData = nlohmann::json::object();
            for (const auto& [key, value] : additionalData)
            {
                BMCWEB_LOG_DEBUG("AdditionalData: {}={}", key, value);
                jsonData[key] = value;
            }
            asyncResp->res.addHeader(boost::beast::http::field::content_type,
                                     "application/octet-stream");
            asyncResp->res.addHeader(
                boost::beast::http::field::content_disposition, "attachment");
            asyncResp->res.jsonValue = jsonData;
        });
}

inline void downloadSELEntry(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& managerId, const std::string& entryID,
    const std::string& dumpType)
{
    std::string entryPath =
        sdbusplus::message::object_path("/xyz/openbmc_project/logging/ipmi") /
        entryID;
    BMCWEB_LOG_DEBUG("Manager ID = {}", managerId);
    dbus::utility::getProperty<std::map<std::string, std::string>>(
        "xyz.openbmc_project.Logging", entryPath,
        "xyz.openbmc_project.Logging.Entry", "AdditionalData",
        [asyncResp, dumpType,
         entryID](const boost::system::error_code& ec,
                  const std::map<std::string, std::string>& additionalData) {
            if (ec.value() == EBADR)
            {
                messages::resourceNotFound(asyncResp->res, "LogEntry", entryID);
                return;
            }
            if (ec)
            {
                BMCWEB_LOG_DEBUG(
                    "Got DBUS response error while getting AdditionalData in {}",
                    dumpType);
                return;
            }
            nlohmann::json jsonData = nlohmann::json::object();
            for (const auto& [key, value] : additionalData)
            {
                BMCWEB_LOG_DEBUG("AdditionalData: {}={}", key, value);
                jsonData[key] = value;
            }
            asyncResp->res.addHeader(boost::beast::http::field::content_type,
                                     "application/octet-stream");
            asyncResp->res.addHeader(
                boost::beast::http::field::content_disposition, "attachment");
            asyncResp->res.jsonValue = jsonData;
        });
}

inline DumpCreationProgress mapDbusStatusToDumpProgress(
    const std::string& status)
{
    if (status ==
            "xyz.openbmc_project.Common.Progress.OperationStatus.Failed" ||
        status == "xyz.openbmc_project.Common.Progress.OperationStatus.Aborted")
    {
        return DumpCreationProgress::DUMP_CREATE_FAILED;
    }
    if (status ==
        "xyz.openbmc_project.Common.Progress.OperationStatus.Completed")
    {
        return DumpCreationProgress::DUMP_CREATE_SUCCESS;
    }
    return DumpCreationProgress::DUMP_CREATE_INPROGRESS;
}

inline DumpCreationProgress getDumpCompletionStatus(
    const dbus::utility::DBusPropertiesMap& values)
{
    for (const auto& [key, val] : values)
    {
        if (key == "Status")
        {
            const std::string* value = std::get_if<std::string>(&val);
            if (value == nullptr)
            {
                BMCWEB_LOG_ERROR("Status property value is null");
                return DumpCreationProgress::DUMP_CREATE_FAILED;
            }
            return mapDbusStatusToDumpProgress(*value);
        }
    }
    return DumpCreationProgress::DUMP_CREATE_INPROGRESS;
}

inline std::string getDumpEntryPath(const std::string& dumpPath)
{
    if (dumpPath == "/xyz/openbmc_project/dump/bmc/entry")
    {
        return std::format("/redfish/v1/Managers/{}/LogServices/Dump/Entries/",
                           BMCWEB_REDFISH_MANAGER_URI_NAME);
    }
    if (dumpPath == "/xyz/openbmc_project/dump/system/entry")
    {
        return std::format("/redfish/v1/Systems/{}/LogServices/Dump/Entries/",
                           BMCWEB_REDFISH_SYSTEM_URI_NAME);
    }
    return "";
}

inline void createDumpTaskCallback(
    task::Payload&& payload,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const sdbusplus::message::object_path& createdObjPath)
{
    const std::string dumpPath = createdObjPath.parent_path().str;
    const std::string dumpId = createdObjPath.filename();

    std::string dumpEntryPath = getDumpEntryPath(dumpPath);

    if (dumpEntryPath.empty())
    {
        BMCWEB_LOG_ERROR("Invalid dump type received");
        messages::internalError(asyncResp->res);
        return;
    }

    crow::connections::systemBus->async_method_call(
        [asyncResp, payload = std::move(payload), createdObjPath,
         dumpEntryPath{std::move(dumpEntryPath)},
         dumpId](const boost::system::error_code& ec,
                 const std::string& introspectXml) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("Introspect call failed with error: {}",
                                 ec.message());
                messages::internalError(asyncResp->res);
                return;
            }

            // Check if the created dump object has implemented Progress
            // interface to track dump completion. If yes, fetch the "Status"
            // property of the interface, modify the task state accordingly.
            // Else, return task completed.
            tinyxml2::XMLDocument doc;

            doc.Parse(introspectXml.data(), introspectXml.size());
            tinyxml2::XMLNode* pRoot = doc.FirstChildElement("node");
            if (pRoot == nullptr)
            {
                BMCWEB_LOG_ERROR("XML document failed to parse");
                messages::internalError(asyncResp->res);
                return;
            }
            tinyxml2::XMLElement* interfaceNode =
                pRoot->FirstChildElement("interface");

            bool isProgressIntfPresent = false;
            while (interfaceNode != nullptr)
            {
                const char* thisInterfaceName =
                    interfaceNode->Attribute("name");
                if (thisInterfaceName != nullptr)
                {
                    if (thisInterfaceName ==
                        std::string_view("xyz.openbmc_project.Common.Progress"))
                    {
                        interfaceNode =
                            interfaceNode->NextSiblingElement("interface");
                        continue;
                    }
                    isProgressIntfPresent = true;
                    break;
                }
                interfaceNode = interfaceNode->NextSiblingElement("interface");
            }

            std::shared_ptr<task::TaskData> task = task::TaskData::createTask(
                [createdObjPath, dumpEntryPath, dumpId, isProgressIntfPresent](
                    const boost::system::error_code& ec2,
                    sdbusplus::message_t& msg,
                    const std::shared_ptr<task::TaskData>& taskData) {
                    if (ec2)
                    {
                        BMCWEB_LOG_ERROR("{}: Error in creating dump",
                                         createdObjPath.str);
                        taskData->messages.emplace_back(
                            messages::internalError());
                        taskData->state = "Cancelled";
                        return task::completed;
                    }

                    if (isProgressIntfPresent)
                    {
                        dbus::utility::DBusPropertiesMap values;
                        std::string prop;
                        msg.read(prop, values);

                        DumpCreationProgress dumpStatus =
                            getDumpCompletionStatus(values);
                        if (dumpStatus ==
                            DumpCreationProgress::DUMP_CREATE_FAILED)
                        {
                            BMCWEB_LOG_ERROR("{}: Error in creating dump",
                                             createdObjPath.str);
                            taskData->state = "Cancelled";
                            return task::completed;
                        }

                        if (dumpStatus ==
                            DumpCreationProgress::DUMP_CREATE_INPROGRESS)
                        {
                            BMCWEB_LOG_DEBUG(
                                "{}: Dump creation task is in progress",
                                createdObjPath.str);
                            return !task::completed;
                        }
                    }

                    nlohmann::json retMessage = messages::success();
                    taskData->messages.emplace_back(retMessage);

                    boost::urls::url url =
                        boost::urls::format("{}{}", dumpEntryPath, dumpId);

                    std::string headerLoc = "Location: ";
                    headerLoc += url.buffer();

                    taskData->payload->httpHeaders.emplace_back(
                        std::move(headerLoc));

                    BMCWEB_LOG_DEBUG("{}: Dump creation task completed",
                                     createdObjPath.str);
                    taskData->state = "Completed";
                    return task::completed;
                },
                "type='signal',interface='org.freedesktop.DBus.Properties',"
                "member='PropertiesChanged',path='" +
                    createdObjPath.str + "'");

            // The task timer is set to max time limit within which the
            // requested dump will be collected.
            task->startTimer(std::chrono::minutes(6));
            task->populateResp(asyncResp->res);
            task->payload.emplace(payload);
        },
        "xyz.openbmc_project.Dump.Manager", createdObjPath,
        "org.freedesktop.DBus.Introspectable", "Introspect");
}

void createDump(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                const crow::Request& req, const std::string& dumpType)
{
    std::string dumpPath = getDumpEntriesPath(dumpType);
    if (dumpPath.empty())
    {
        messages::internalError(asyncResp->res);
        return;
    }

    std::optional<std::string> diagnosticDataType;
    std::optional<std::string> oemDiagnosticDataType;

    if (!redfish::json_util::readJsonAction(
            req, asyncResp->res, "DiagnosticDataType", diagnosticDataType,
            "OEMDiagnosticDataType", oemDiagnosticDataType))
    {
        return;
    }

    if (dumpType == "System")
    {
        if (!oemDiagnosticDataType || !diagnosticDataType)
        {
            BMCWEB_LOG_ERROR(
                "CreateDump action parameter 'DiagnosticDataType'/'OEMDiagnosticDataType' value not found!");
            messages::actionParameterMissing(
                asyncResp->res, "CollectDiagnosticData",
                "DiagnosticDataType & OEMDiagnosticDataType");
            return;
        }
        if (*diagnosticDataType != "OEM")
        {
            BMCWEB_LOG_ERROR("Wrong parameter values passed");
            messages::internalError(asyncResp->res);
            return;
        }
        dumpPath = std::format("/redfish/v1/Systems/{}/LogServices/Dump/",
                               BMCWEB_REDFISH_SYSTEM_URI_NAME);
    }
    else if (dumpType == "BMC")
    {
        if (!diagnosticDataType)
        {
            BMCWEB_LOG_ERROR(
                "CreateDump action parameter 'DiagnosticDataType' not found!");
            messages::actionParameterMissing(
                asyncResp->res, "CollectDiagnosticData", "DiagnosticDataType");
            return;
        }
        if (*diagnosticDataType != "Manager")
        {
            BMCWEB_LOG_ERROR(
                "Wrong parameter value passed for 'DiagnosticDataType'");
            messages::internalError(asyncResp->res);
            return;
        }
        dumpPath = std::format("/redfish/v1/Managers/{}/LogServices/Dump/",
                               BMCWEB_REDFISH_MANAGER_URI_NAME);
    }
    else
    {
        BMCWEB_LOG_ERROR("CreateDump failed. Unknown dump type");
        messages::internalError(asyncResp->res);
        return;
    }

    std::vector<std::pair<std::string, std::variant<std::string, uint64_t>>>
        createDumpParamVec;

    if (req.session != nullptr)
    {
        createDumpParamVec.emplace_back(
            "xyz.openbmc_project.Dump.Create.CreateParameters.OriginatorId",
            req.session->clientIp);
        createDumpParamVec.emplace_back(
            "xyz.openbmc_project.Dump.Create.CreateParameters.OriginatorType",
            "xyz.openbmc_project.Common.OriginatedBy.OriginatorTypes.Client");
    }

    crow::connections::systemBus->async_method_call(
        [asyncResp, payload(task::Payload(req)),
         dumpPath](const boost::system::error_code& ec,
                   const sdbusplus::message_t& msg,
                   const sdbusplus::message::object_path& objPath) mutable {
            if (ec)
            {
                BMCWEB_LOG_ERROR("CreateDump resp_handler got error {}", ec);
                const sd_bus_error* dbusError = msg.get_error();
                if (dbusError == nullptr)
                {
                    /* With the upstream fix of sdbuplus (commit
                     * https://github.com/openbmc/sdbusplus/commit/9ed557ee627e4b4b43086dfb98acd8e8201d718d):
                     * we can remove the EIO workaround*/
                    if (ec.value() == EIO)
                    {
                        messages::resourceInUse(asyncResp->res);
                        return;
                    }
                    messages::internalError(asyncResp->res);
                    return;
                }

                BMCWEB_LOG_ERROR("CreateDump DBus error: {} and error msg: {}",
                                 dbusError->name, dbusError->message);
                if (std::string_view(
                        "xyz.openbmc_project.Common.Error.NotAllowed") ==
                    dbusError->name)
                {
                    messages::resourceInStandby(asyncResp->res);
                    return;
                }
                if (std::string_view(
                        "xyz.openbmc_project.Dump.Create.Error.Disabled") ==
                    dbusError->name)
                {
                    messages::serviceDisabled(asyncResp->res, dumpPath);
                    return;
                }
                if (std::string_view(
                        "xyz.openbmc_project.Common.Error.Unavailable") ==
                    dbusError->name)
                {
                    messages::resourceInUse(asyncResp->res);
                    return;
                }
                if (std::string_view(
                        "xyz.openbmc_project.Dump.Create.Error.QuotaExceeded") ==
                    dbusError->name)
                {
                    messages::dumpQuotaExceeded(asyncResp->res);
                    return;
                }
                // Other Dbus errors such as:
                // xyz.openbmc_project.Common.Error.InvalidArgument &
                // org.freedesktop.DBus.Error.InvalidArgs are all related to
                // the dbus call that is made here in the bmcweb
                // implementation and has nothing to do with the client's
                // input in the request. Hence, returning internal error
                // back to the client.
                messages::internalError(asyncResp->res);
                return;
            }
            BMCWEB_LOG_DEBUG("Dump Created. Path: {}", objPath.str);
            createDumpTaskCallback(std::move(payload), asyncResp, objPath);
        },
        "xyz.openbmc_project.Dump.Manager", getDumpPath(dumpType),
        "xyz.openbmc_project.Dump.Create", "CreateDump", createDumpParamVec);
}

void clearDump(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
               const std::string& dumpType)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("clearDump resp_handler got error {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }
            messages::success(asyncResp->res);
        },
        "xyz.openbmc_project.Dump.Manager", getDumpPath(dumpType),
        "xyz.openbmc_project.Collection.DeleteAll", "DeleteAll");
}

inline void parseCrashdumpParameters(
    const dbus::utility::DBusPropertiesMap& params, std::string& filename,
    std::string& timestamp, std::string& logfile)
{
    const std::string* filenamePtr = nullptr;
    const std::string* timestampPtr = nullptr;
    const std::string* logfilePtr = nullptr;

    const bool success = sdbusplus::unpackPropertiesNoThrow(
        dbus_utils::UnpackErrorPrinter(), params, "Timestamp", timestampPtr,
        "Filename", filenamePtr, "Log", logfilePtr);

    if (!success)
    {
        return;
    }

    if (filenamePtr != nullptr)
    {
        filename = *filenamePtr;
    }

    if (timestampPtr != nullptr)
    {
        timestamp = *timestampPtr;
    }

    if (logfilePtr != nullptr)
    {
        logfile = *logfilePtr;
    }
}

inline void requestRoutesSystemLogServiceCollection(App& app)
{
    /**
     * Functions triggers appropriate requests on DBus
     */
    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/LogServices/")
        .privileges(redfish::privileges::getLogServiceCollection)
        .methods(
            boost::beast::http::verb::
                get)([&app](const crow::Request& req,
                            const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                            const std::string& systemName) {
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
            if (!system_utils::validateSystemName(asyncResp, systemName))
            {
                return;
            }

            // Collections don't include the static data added by SubRoute
            // because it has a duplicate entry for members
            asyncResp->res.jsonValue["@odata.type"] =
                json_util::odataType("LogServiceCollection");
            asyncResp->res.jsonValue["@odata.id"] =
                std::format("/redfish/v1/Systems/{}/LogServices",
                            BMCWEB_REDFISH_SYSTEM_URI_NAME);
            asyncResp->res.jsonValue["Name"] = "System Log Services Collection";
            asyncResp->res.jsonValue["Description"] =
                "Collection of LogServices for this Computer System";
            nlohmann::json& logServiceArray =
                asyncResp->res.jsonValue["Members"];
            logServiceArray = nlohmann::json::array();
            nlohmann::json::object_t eventLog;
            eventLog["@odata.id"] =
                std::format("/redfish/v1/Systems/{}/LogServices/EventLog",
                            BMCWEB_REDFISH_SYSTEM_URI_NAME);
            logServiceArray.emplace_back(std::move(eventLog));

#if (defined(ONETREE_MSCCRAID)) || (defined(ONETREE_BRCMRAID))
            nlohmann::json::object_t raid;
            raid["@odata.id"] =
                std::format("/redfish/v1/Systems/{}/LogServices/Raid",
                            BMCWEB_REDFISH_SYSTEM_URI_NAME);
            logServiceArray.emplace_back(std::move(raid));
#endif

#ifdef ONETREE_NVIDIASIPACK
            nlohmann::json::object_t debugToken;
            debugToken["@odata.id"] =
                "/redfish/v1/Systems/system/LogServices/DebugTokenService";
            logServiceArray.emplace_back(std::move(debugToken));
#endif
            if constexpr (BMCWEB_REDFISH_DUMP_LOG)
            {
                nlohmann::json::object_t dumpLog;
                dumpLog["@odata.id"] =
                    std::format("/redfish/v1/Systems/{}/LogServices/Dump",
                                BMCWEB_REDFISH_SYSTEM_URI_NAME);
                logServiceArray.emplace_back(std::move(dumpLog));
            }

            if constexpr (BMCWEB_REDFISH_CPU_LOG)
            {
                nlohmann::json::object_t crashdump;
                crashdump["@odata.id"] =
                    std::format("/redfish/v1/Systems/{}/LogServices/Crashdump",
                                BMCWEB_REDFISH_SYSTEM_URI_NAME);
                logServiceArray.emplace_back(std::move(crashdump));
            }

            if constexpr (BMCWEB_REDFISH_HOST_LOGGER)
            {
                nlohmann::json::object_t hostlogger;
                hostlogger["@odata.id"] =
                    std::format("/redfish/v1/Systems/{}/LogServices/HostLogger",
                                BMCWEB_REDFISH_SYSTEM_URI_NAME);
                logServiceArray.emplace_back(std::move(hostlogger));
            }
            nlohmann::json::object_t syslog;
            syslog["@odata.id"] =
                std::format("/redfish/v1/Systems/{}/LogServices/Syslog",
                            BMCWEB_REDFISH_SYSTEM_URI_NAME);
            logServiceArray.emplace_back(std::move(syslog));

            asyncResp->res.jsonValue["Members@odata.count"] =
                logServiceArray.size();
            constexpr std::array<std::string_view, 1> interfaces = {
                "xyz.openbmc_project.State.Boot.PostCode"};
            dbus::utility::getSubTreePaths(
                "/", 0, interfaces,
                [asyncResp](const boost::system::error_code& ec,
                            const dbus::utility::MapperGetSubTreePathsResponse&
                                subtreePath) {
                    if (ec)
                    {
                        BMCWEB_LOG_ERROR("{}", ec);
                        return;
                    }

                    for (const auto& pathStr : subtreePath)
                    {
                        if (pathStr.find("PostCode") != std::string::npos)
                        {
                            nlohmann::json& logServiceArrayLocal =
                                asyncResp->res.jsonValue["Members"];
                            nlohmann::json::object_t member;
                            member["@odata.id"] = std::format(
                                "/redfish/v1/Systems/{}/LogServices/PostCodes",
                                BMCWEB_REDFISH_SYSTEM_URI_NAME);

                            logServiceArrayLocal.emplace_back(
                                std::move(member));

                            asyncResp->res.jsonValue["Members@odata.count"] =
                                logServiceArrayLocal.size();
                            return;
                        }
                    }
                });
        });
}

inline void requestRoutesEventLogService(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/LogServices/EventLog/")
        .privileges(redfish::privileges::getLogService)
        .methods(
            boost::beast::http::verb::
                get)([&app](const crow::Request& req,
                            const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                            const std::string& systemName) {
            if (!redfish::setUpRedfishRoute(app, req, asyncResp))
            {
                return;
            }
            if (!system_utils::validateSystemName(asyncResp, systemName))
            {
                return;
            }
            asyncResp->res.jsonValue["@odata.id"] =
                std::format("/redfish/v1/Systems/{}/LogServices/EventLog",
                            BMCWEB_REDFISH_SYSTEM_URI_NAME);
            asyncResp->res.jsonValue["@odata.type"] =
                json_util::odataType("LogService");
            asyncResp->res.jsonValue["Name"] = "Event Log Service";
            asyncResp->res.jsonValue["Description"] =
                "System Event Log Service";
            asyncResp->res.jsonValue["Id"] = "EventLog";
            asyncResp->res.jsonValue["OverWritePolicy"] =
                log_service::OverWritePolicy::WrapsWhenFull;
            asyncResp->res.jsonValue["MaxNumberOfRecords"] = 1250;

            auto [dateTime,
                  offsetStr] = redfish::time_utils::getLocalDateTimeOffset();
            asyncResp->res.jsonValue["DateTime"] = dateTime;
            asyncResp->res.jsonValue["DateTimeLocalOffset"] = offsetStr;
            asyncResp->res.jsonValue["Entries"]["@odata.id"] = std::format(
                "/redfish/v1/Systems/{}/LogServices/EventLog/Entries",
                BMCWEB_REDFISH_SYSTEM_URI_NAME);
            asyncResp->res
                .jsonValue["Actions"]["#LogService.ClearLog"]["target"]

                = std::format(
                    "/redfish/v1/Systems/{}/LogServices/EventLog/Actions/LogService.ClearLog",
                    BMCWEB_REDFISH_SYSTEM_URI_NAME);
        });
}

inline void handleSystemsLogServicesEventLogActionsClearPost(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& systemName)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (!system_utils::validateSystemName(asyncResp, systemName))
    {
        return;
    }

    // Clear the EventLog by deleting the log files
    std::vector<std::filesystem::path> redfishLogFiles;
    if (getRedfishLogFiles(redfishLogFiles))
    {
        for (const std::filesystem::path& file : redfishLogFiles)
        {
            std::error_code ec;
            std::filesystem::remove(file, ec);
        }
    }

    // Reload rsyslog so it knows to start new log files
    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("Failed to reload rsyslog: {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }
            messages::success(asyncResp->res);
        },
        "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager", "ReloadUnit", "rsyslog.service",
        "replace");
}

inline void requestRoutesJournalEventLogClear(App& app)
{
    BMCWEB_ROUTE(
        app,
        "/redfish/v1/Systems/<str>/LogServices/EventLog/Actions/LogService.ClearLog/")
        .privileges({{"ConfigureComponents"}})
        .methods(boost::beast::http::verb::post)(std::bind_front(
            handleSystemsLogServicesEventLogActionsClearPost, std::ref(app)));
}

inline LogParseError fillMessageEntry(const std::string& logEntry,
                                      std::string& messageID, std::string& msg)
{
    // The redfish log format is "<MessageId>,<MessageArgs>"
    size_t pos = logEntry.find_first_of(",:");
    // Checking the MessageID without Arguments.
    if (pos == std::string::npos)
    {
        // Initially considering whole logEntry as MessageID.
        messageID = logEntry;
        // Get the Message from the MessageRegistry
        const registries::Message* message = registries::getMessage(messageID);
        if (message == nullptr)
        {
            return LogParseError::messageIdNotInRegistry;
        }
        msg = redfish::registries::fillMessageArgs(
            std::span<const std::string_view>{}, message->message);
        if (msg.empty())
        {
            return LogParseError::parseFailed;
        }
        return LogParseError::success;
    }
    // Checking the MessageID with Arguments.
    char foundChar = logEntry[pos];
    std::string_view entry(logEntry);
    // Use split to separate the entry into its fields
    std::vector<std::string> logEntryFields;
    // Checking MessageID seperated by Comma(,), usually from dbus.
    if (foundChar == ',')
    {
        bmcweb::split(logEntryFields, entry, ',');
        auto logEntryIter = logEntryFields.begin();
        if (logEntryIter == logEntryFields.end())
        {
            return LogParseError::parseFailed;
        }
        messageID = *logEntryIter;
        // Get the Message from the MessageRegistry
        const registries::Message* message = registries::getMessage(messageID);
        logEntryIter++;
        if (message == nullptr)
        {
            return LogParseError::messageIdNotInRegistry;
        }
        std::vector<std::string_view> messageArgs(logEntryIter,
                                                  logEntryFields.end());
        messageArgs.resize(message->numberOfArgs);
        msg =
            redfish::registries::fillMessageArgs(messageArgs, message->message);
        if (msg.empty())
        {
            return LogParseError::parseFailed;
        }
    }
    // Checking MessageID with Colon(:), usually when entries are created from
    // session create method.
    else if (foundChar == ':')
    {
        bmcweb::split(logEntryFields, entry, ':');
        // We need at least a MessageId to be valid
        auto logEntryIter = logEntryFields.begin();
        if (logEntryIter == logEntryFields.end())
        {
            return LogParseError::parseFailed;
        }
        std::string& messageKey = *logEntryIter;
        // MessageID to be formated with Major & Minor Version.
        // TODO This RegistryName should be fetched dynamically instead of
        // hardcoded.
        const std::string& registryName = "OpenBMC";
        const registries::Header* header = nullptr;
        header = &registries::openbmc::header;
        messageID =
            std::format("{}.{}.{}.{}", header->registryPrefix,
                        header->versionMajor, header->versionMinor, messageKey);
        const registries::Message* message = registries::getMessageFromRegistry(
            messageKey,
            redfish::registries::getRegistryFromPrefix(registryName));
        logEntryIter++;
        if (message == nullptr)
        {
            return LogParseError::messageIdNotInRegistry;
        }
        std::vector<std::string_view> messageArgs(logEntryIter,
                                                  logEntryFields.end());
        messageArgs.resize(message->numberOfArgs);
        msg =
            redfish::registries::fillMessageArgs(messageArgs, message->message);
        if (msg.empty())
        {
            return LogParseError::parseFailed;
        }
    }
    return LogParseError::success;
}

static LogParseError fillEventLogEntryJson(
    const std::string& logEntryID, const std::string& logEntry,
    nlohmann::json::object_t& logEntryJson)
{
    // The redfish log format is "<Timestamp> <MessageId>,<MessageArgs>"
    // First get the Timestamp
    size_t space = logEntry.find_first_of(' ');
    if (space == std::string::npos)
    {
        return LogParseError::parseFailed;
    }
    std::string timestamp = logEntry.substr(0, space);
    // Then get the log contents
    size_t entryStart = logEntry.find_first_not_of(' ', space);
    if (entryStart == std::string::npos)
    {
        return LogParseError::parseFailed;
    }
    std::string_view entry(logEntry);
    entry.remove_prefix(entryStart);
    // Use split to separate the entry into its fields
    std::vector<std::string> logEntryFields;
    bmcweb::split(logEntryFields, entry, ',');
    // We need at least a MessageId to be valid
    auto logEntryIter = logEntryFields.begin();
    if (logEntryIter == logEntryFields.end())
    {
        return LogParseError::parseFailed;
    }
    std::string& messageID = *logEntryIter;
    // Get the Message from the MessageRegistry
    const registries::Message* message = registries::getMessage(messageID);

    logEntryIter++;
    if (message == nullptr)
    {
        BMCWEB_LOG_WARNING("Log entry not found in registry: {}", logEntry);
        return LogParseError::messageIdNotInRegistry;
    }

    std::vector<std::string_view> messageArgs(logEntryIter,
                                              logEntryFields.end());
    messageArgs.resize(message->numberOfArgs);

    std::string msg =
        redfish::registries::fillMessageArgs(messageArgs, message->message);
    if (msg.empty())
    {
        return LogParseError::parseFailed;
    }

    // Get the Created time from the timestamp. The log timestamp is in RFC3339
    // format which matches the Redfish format except for the fractional seconds
    // between the '.' and the '+', so just remove them.
    std::size_t dot = timestamp.find_first_of('.');
    std::size_t plus = timestamp.find_first_of('+');
    if (dot != std::string::npos && plus != std::string::npos)
    {
        timestamp.erase(dot, plus - dot);
    }

    // Fill in the log entry with the gathered data
    logEntryJson["@odata.type"] = json_util::odataType("LogEntry");
    logEntryJson["@odata.id"] = boost::urls::format(
        "/redfish/v1/Systems/{}/LogServices/EventLog/Entries/{}",
        BMCWEB_REDFISH_SYSTEM_URI_NAME, logEntryID);
    logEntryJson["Name"] = "System Event Log Entry";
    logEntryJson["Description"] = "EventLog " + logEntryID;
    logEntryJson["Id"] = logEntryID;
    logEntryJson["Message"] = std::move(msg);
    logEntryJson["MessageId"] = std::move(messageID);
    logEntryJson["MessageArgs"] = messageArgs;
    logEntryJson["EntryType"] = "Event";
    logEntryJson["Severity"] = message->messageSeverity;
    logEntryJson["Created"] = std::move(timestamp);
    return LogParseError::success;
}

inline void fillEventLogLogEntryFromPropertyMap(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const dbus::utility::DBusPropertiesMap& resp,
    nlohmann::json& objectToFillOut)
{
    std::optional<DbusEventLogEntry> optEntry =
        fillDbusEventLogEntryFromPropertyMap(resp);

    if (!optEntry.has_value())
    {
        messages::internalError(asyncResp->res);
        return;
    }
    DbusEventLogEntry entry = optEntry.value();

    std::string Id = std::to_string(entry.Id);
    objectToFillOut["@odata.id"] = boost::urls::format(
        "/redfish/v1/Systems/{}/LogServices/EventLog/Entries/{}",
        BMCWEB_REDFISH_SYSTEM_URI_NAME, Id);
    objectToFillOut["Name"] = "System Event Log Entry";
    objectToFillOut["Id"] = Id;
    objectToFillOut["Description"] = "EventLog " + Id;
    std::string msgID, msgForm;
    LogParseError status = fillMessageEntry(entry.Message, msgID, msgForm);
    if (status != LogParseError::success)
    {
        objectToFillOut["Message"] = entry.Message;
    }
    else
    {
        objectToFillOut["MessageId"] = std::move(msgID);
        objectToFillOut["Message"] = std::move(msgForm);
    }
    objectToFillOut["Resolved"] = entry.Resolved;
    std::optional<bool> notifyAction =
        getProviderNotifyAction(entry.ServiceProviderNotify);
    if (notifyAction)
    {
        objectToFillOut["ServiceProviderNotified"] = *notifyAction;
    }
    if ((entry.Resolution != nullptr) && !entry.Resolution->empty())
    {
        objectToFillOut["Resolution"] = *entry.Resolution;
    }
    objectToFillOut["EntryType"] = "Event";
    std::string severity = translateSeverityDbusToRedfish(entry.Severity);
    if ((!severity.empty()) && (severity != "NotApplicable"))
    {
        objectToFillOut["Severity"] = severity;
    }
    objectToFillOut["Created"] = entry.Timestamp;
    objectToFillOut["Modified"] = entry.UpdateTimestamp;
    if (entry.Path != nullptr)
    {
        objectToFillOut["AdditionalDataURI"] = boost::urls::format(
            "/redfish/v1/Systems/{}/LogServices/EventLog/Entries/{}/attachment",
            BMCWEB_REDFISH_SYSTEM_URI_NAME, std::to_string(entry.Id));
    }
}

inline void afterLogEntriesGetManagedObjects(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const boost::system::error_code& ec,
    const dbus::utility::ManagedObjectType& resp)
{
    if (ec)
    {
        // TODO Handle for specific error code
        BMCWEB_LOG_ERROR("getLogEntriesIfaceData resp_handler got error {}",
                         ec);
        messages::internalError(asyncResp->res);
        return;
    }
    nlohmann::json::array_t entriesArray;
    std::string logEntryOdata = json_util::odataType("LogEntry");
    std::string timeZone =
        crow::utility::getTimeZone(crow::utility::localTimeZone);
    for (const auto& objectPath : resp)
    {
        dbus::utility::DBusPropertiesMap propsFlattened;
        auto isEntry =
            std::ranges::find_if(objectPath.second, [](const auto& object) {
                return object.first == "xyz.openbmc_project.Logging.Entry";
            });
        if (isEntry == objectPath.second.end())
        {
            continue;
        }
        for (const auto& interfaceMap : objectPath.second)
        {
            for (const auto& propertyMap : interfaceMap.second)
            {
                propsFlattened.emplace_back(propertyMap.first,
                                            propertyMap.second);
            }
        }
        auto& entry = entriesArray.emplace_back();
        fillEventLogLogEntryFromPropertyMap(asyncResp, propsFlattened, entry);
        entry["@odata.type"] = logEntryOdata; // common for all entries
        entry["Created"] = timeFormat(
            redfish::time_utils::getDateTimeUintMs(entry["Created"], timeZone));
        entry["Modified"] = timeFormat(redfish::time_utils::getDateTimeUintMs(
            entry["Modified"], timeZone));
    }

    std::ranges::sort(entriesArray, [](const nlohmann::json& left,
                                       const nlohmann::json& right) {
        return std::stoi(left["Id"].get<std::string>()) <=
               std::stoi(right["Id"].get<std::string>());
    });
    asyncResp->res.jsonValue["Members@odata.count"] = entriesArray.size();
    asyncResp->res.jsonValue["Members"] = std::move(entriesArray);
}

inline void fillSELEntryFromPropertyMap(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const dbus::utility::DBusPropertiesMap& resp,
    nlohmann::json& objectToFillOut)
{
    std::optional<DbusEventLogEntry> optEntry =
        fillDbusEventLogEntryFromPropertyMap(resp);

    if (!optEntry.has_value())
    {
        messages::internalError(asyncResp->res);
        return;
    }
    DbusEventLogEntry entry = optEntry.value();

    objectToFillOut["@odata.type"] = json_util::odataType("LogEntry");
    objectToFillOut["@odata.id"] = boost::urls::format(
        "/redfish/v1/Managers/{}/LogServices/SEL/Entries/{}",
        BMCWEB_REDFISH_MANAGER_URI_NAME, std::to_string(entry.Id));
    objectToFillOut["Name"] = "Managers SEL Log Entry";
    objectToFillOut["Id"] = std::to_string(entry.Id);
    objectToFillOut["Description"] =
        "SEL Log Entry " + std::to_string(entry.Id);
    std::string msgID, msgForm;
    LogParseError status = fillMessageEntry(entry.Message, msgID, msgForm);
    if (status != LogParseError::success)
    {
        objectToFillOut["Message"] = entry.Message;
    }
    else
    {
        objectToFillOut["MessageId"] = std::move(msgID);
        objectToFillOut["Message"] = std::move(msgForm);
    }
    objectToFillOut["Resolved"] = entry.Resolved;
    std::optional<bool> notifyAction =
        getProviderNotifyAction(entry.ServiceProviderNotify);
    if (notifyAction)
    {
        objectToFillOut["ServiceProviderNotified"] = *notifyAction;
    }
    if ((entry.Resolution != nullptr) && !entry.Resolution->empty())
    {
        objectToFillOut["Resolution"] = *entry.Resolution;
    }
    objectToFillOut["EntryType"] = "SEL";
    std::string severity = translateSeverityDbusToRedfish(entry.Severity);
    if ((!severity.empty()) && (severity != "NotApplicable"))
    {
        objectToFillOut["Severity"] = severity;
    }
    objectToFillOut["Created"] = std::move(
        timeFormat(redfish::time_utils::getDateTimeUintMs(entry.Timestamp)));
    objectToFillOut["Modified"] = std::move(timeFormat(
        redfish::time_utils::getDateTimeUintMs(entry.UpdateTimestamp)));
    if (entry.Path != nullptr)
    {
        objectToFillOut["AdditionalDataURI"] = boost::urls::format(
            "/redfish/v1/Managers/{}/LogServices/SEL/Entries/{}/attachment",
            BMCWEB_REDFISH_MANAGER_URI_NAME, std::to_string(entry.Id));
    }
}

inline void afterSELLogEntriesGetManagedObjects(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const boost::system::error_code& ec,
    const dbus::utility::ManagedObjectType& resp)
{
    if (ec)
    {
        // TODO Handle for specific error code
        BMCWEB_LOG_ERROR("getLogEntriesIfaceData resp_handler got error {}",
                         ec);
        messages::internalError(asyncResp->res);
        return;
    }
    nlohmann::json::array_t entriesArray;
    for (const auto& objectPath : resp)
    {
        dbus::utility::DBusPropertiesMap propsFlattened;
        auto isEntry =
            std::ranges::find_if(objectPath.second, [](const auto& object) {
                return object.first == "xyz.openbmc_project.Logging.Entry";
            });
        if (isEntry == objectPath.second.end())
        {
            continue;
        }
        for (const auto& interfaceMap : objectPath.second)
        {
            for (const auto& propertyMap : interfaceMap.second)
            {
                propsFlattened.emplace_back(propertyMap.first,
                                            propertyMap.second);
            }
        }
        fillSELEntryFromPropertyMap(asyncResp, propsFlattened,
                                    entriesArray.emplace_back());
    }

    std::ranges::sort(entriesArray, [](const nlohmann::json& left,
                                       const nlohmann::json& right) {
        return std::stoi(left["Id"].get<std::string>()) <=
               std::stoi(right["Id"].get<std::string>());
    });
    asyncResp->res.jsonValue["Members@odata.count"] = entriesArray.size();
    asyncResp->res.jsonValue["Members"] = std::move(entriesArray);
}

inline void getSELEntryCollection(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    // Collections don't include the static data added by SubRoute
    // because it has a duplicate entry for members
    asyncResp->res.jsonValue["@odata.type"] =
        json_util::odataType("LogEntryCollection");
    asyncResp->res.jsonValue["@odata.id"] =
        std::format("/redfish/v1/Managers/{}/LogServices/SEL/Entries",
                    BMCWEB_REDFISH_MANAGER_URI_NAME);
    asyncResp->res.jsonValue["Name"] = "System Event Log Entries";
    asyncResp->res.jsonValue["Description"] =
        "Collection of Manager SEL Log Entries";

    // DBus implementation of EventLog/Entries
    // Make call to Logging Service to find all log entry objects
    sdbusplus::message::object_path path("/xyz/openbmc_project/logging/ipmi");
    dbus::utility::getManagedObjects(
        "xyz.openbmc_project.Logging", path,
        [asyncResp](const boost::system::error_code& ec,
                    const dbus::utility::ManagedObjectType& resp) {
            afterSELLogEntriesGetManagedObjects(asyncResp, ec, resp);
        });
}

inline void handleSystemsLogServiceEventLogLogEntryCollection(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& systemName)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    query_param::QueryCapabilities capabilities = {
        .canDelegateTop = true,
        .canDelegateSkip = true,
    };
    query_param::Query delegatedQuery;
    if (!redfish::setUpRedfishRouteWithDelegation(app, req, asyncResp,
                                                  delegatedQuery, capabilities))
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

    size_t top = delegatedQuery.top.value_or(query_param::Query::maxTop);
    size_t skip = delegatedQuery.skip.value_or(0);

    // Collections don't include the static data added by SubRoute
    // because it has a duplicate entry for members
    asyncResp->res.jsonValue["@odata.type"] =
        json_util::odataType("LogEntryCollection");
    asyncResp->res.jsonValue["@odata.id"] =
        std::format("/redfish/v1/Systems/{}/LogServices/EventLog/Entries",
                    BMCWEB_REDFISH_SYSTEM_URI_NAME);
    asyncResp->res.jsonValue["Name"] = "System Event Log Entries";
    asyncResp->res.jsonValue["Description"] =
        "Collection of System Event Log Entries";

    nlohmann::json& logEntryArray = asyncResp->res.jsonValue["Members"];
    logEntryArray = nlohmann::json::array();
    // Go through the log files and create a unique ID for each
    // entry
    std::vector<std::filesystem::path> redfishLogFiles;
    getRedfishLogFiles(redfishLogFiles);
    uint64_t entryCount = 0;
    std::string logEntry;

    // Oldest logs are in the last file, so start there and loop
    // backwards
    for (auto it = redfishLogFiles.rbegin(); it < redfishLogFiles.rend(); it++)
    {
        std::ifstream logStream(*it);
        if (!logStream.is_open())
        {
            continue;
        }

        // Reset the unique ID on the first entry
        bool firstEntry = true;
        while (std::getline(logStream, logEntry))
        {
            std::string idStr;
            if (!getUniqueEntryID(logEntry, idStr, firstEntry))
            {
                continue;
            }
            firstEntry = false;

            nlohmann::json::object_t bmcLogEntry;
            LogParseError status =
                fillEventLogEntryJson(idStr, logEntry, bmcLogEntry);
            if (status == LogParseError::messageIdNotInRegistry)
            {
                continue;
            }
            if (status != LogParseError::success)
            {
                messages::internalError(asyncResp->res);
                return;
            }

            entryCount++;
            // Handle paging using skip (number of entries to skip from the
            // start) and top (number of entries to display)
            if (entryCount <= skip || entryCount > skip + top)
            {
                continue;
            }

            logEntryArray.emplace_back(std::move(bmcLogEntry));
        }
    }
    asyncResp->res.jsonValue["Members@odata.count"] = entryCount;
    if (skip + top < entryCount)
    {
        asyncResp->res.jsonValue["Members@odata.nextLink"] =
            boost::urls::format(
                "/redfish/v1/Systems/{}/LogServices/EventLog/Entries?$skip={}",
                BMCWEB_REDFISH_SYSTEM_URI_NAME, std::to_string(skip + top));
    }
}

inline void requestRoutesJournalEventLogEntryCollection(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/LogServices/EventLog/Entries/")
        .privileges(redfish::privileges::getLogEntryCollection)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleSystemsLogServiceEventLogLogEntryCollection, std::ref(app)));
}
inline void handleSystemsLogServiceEventLogEntriesGet(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& systemName, const std::string& param)
{
    asyncResp->res.clearHeader(boost::beast::http::field::allow);
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
    if (!system_utils::validateSystemName(asyncResp, systemName))
    {
        return;
    }
    if (!membersResponseGet(asyncResp, param, "LogEntryCollection"))
    {
        return;
    }
    asyncResp->res.addHeader("Allow", "GET");
    const std::string& targetID = param;

    // Go through the log files and check the unique ID for each
    // entry to find the target entry
    std::vector<std::filesystem::path> redfishLogFiles;
    getRedfishLogFiles(redfishLogFiles);
    std::string logEntry;

    // Oldest logs are in the last file, so start there and loop
    // backwards
    for (auto it = redfishLogFiles.rbegin(); it < redfishLogFiles.rend(); it++)
    {
        std::ifstream logStream(*it);
        if (!logStream.is_open())
        {
            continue;
        }

        // Reset the unique ID on the first entry
        bool firstEntry = true;
        while (std::getline(logStream, logEntry))
        {
            std::string idStr;
            if (!getUniqueEntryID(logEntry, idStr, firstEntry))
            {
                continue;
            }
            firstEntry = false;

            if (idStr == targetID)
            {
                nlohmann::json::object_t bmcLogEntry;
                LogParseError status =
                    fillEventLogEntryJson(idStr, logEntry, bmcLogEntry);
                if (status != LogParseError::success)
                {
                    messages::internalError(asyncResp->res);
                    return;
                }

                asyncResp->res.jsonValue.update(bmcLogEntry);
                return;
            }
        }
    }
    // Requested ID was not found
    messages::resourceNotFound(asyncResp->res, "LogEntry", targetID);
}

inline void requestRoutesJournalEventLogEntry(App& app)
{
    BMCWEB_ROUTE(
        app, "/redfish/v1/Systems/<str>/LogServices/EventLog/Entries/<str>/")
        .privileges(redfish::privileges::getLogEntry)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleSystemsLogServiceEventLogEntriesGet, std::ref(app)));

    BMCWEB_ROUTE(app,
                 "/redfish/v1/Systems/<str>/LogServices/EventLog/Entries/<str>")
        .methods(boost::beast::http::verb::post,
                 boost::beast::http::verb::patch, boost::beast::http::verb::put,
                 boost::beast::http::verb::delete_)(
            [&app](const crow::Request& /* req */,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& /* systemName */,
                   const std::string& param) {
                asyncResp->res.clearHeader(boost::beast::http::field::allow);
                if (!membersResponseGet(asyncResp, param, "LogEntryCollection"))
                {
                    return;
                }
                asyncResp->res.addHeader("Allow", "GET");
                messages::operationNotAllowed(asyncResp->res);
            });
}
inline void dBusEventLogEntryCollection(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    // Collections don't include the static data added by SubRoute
    // because it has a duplicate entry for members
    asyncResp->res.jsonValue["@odata.type"] =
        json_util::odataType("LogEntryCollection");
    asyncResp->res.jsonValue["@odata.id"] =
        std::format("/redfish/v1/Systems/{}/LogServices/EventLog/Entries",
                    BMCWEB_REDFISH_SYSTEM_URI_NAME);
    asyncResp->res.jsonValue["Name"] = "System Event Log Entries";
    asyncResp->res.jsonValue["Description"] =
        "Collection of System Event Log Entries";

    // DBus implementation of EventLog/Entries
    // Make call to Logging Service to find all log entry objects
    sdbusplus::message::object_path path("/xyz/openbmc_project/logging/entry");
    dbus::utility::getManagedObjects(
        "xyz.openbmc_project.Logging", path,
        [asyncResp](const boost::system::error_code& ec,
                    const dbus::utility::ManagedObjectType& resp) {
            afterLogEntriesGetManagedObjects(asyncResp, ec, resp);
        });
}

inline void requestRoutesDBusEventLogEntryCollection(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/LogServices/EventLog/Entries/")
        .privileges(redfish::privileges::getLogEntryCollection)
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& systemName) {
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
                if (!system_utils::validateSystemName(asyncResp, systemName))
                {
                    return;
                }
                dBusEventLogEntryCollection(asyncResp);
            });
}

inline void handleLogServicesSELEntryGet(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& managerId, const std::string& entryID)
{
    asyncResp->res.clearHeader(boost::beast::http::field::allow);
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
    {
        messages::resourceNotFound(asyncResp->res, "Managers", managerId);
        return;
    }
    if (!membersResponseGet(asyncResp, entryID, "LogEntryCollection"))
    {
        return;
    }
    asyncResp->res.addHeader("Allow", "GET, PATCH, DELETE");
    // DBus implementation of EventLog/Entries
    // Make call to Logging Service to find all log entry objects
    dbus::utility::getAllProperties(
        "xyz.openbmc_project.Logging",
        "/xyz/openbmc_project/logging/ipmi/" + entryID, "",
        [asyncResp, entryID](const boost::system::error_code& ec,
                             const dbus::utility::DBusPropertiesMap& resp) {
            if (ec.value() == EBADR)
            {
                messages::resourceNotFound(asyncResp->res, "LogEntry", entryID);
                return;
            }
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "SEL LogEntry (DBus) resp_handler got error {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }
            fillSELEntryFromPropertyMap(asyncResp, resp,
                                        asyncResp->res.jsonValue);
        });
}

inline void handleLogServicesSELEntryDelete(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& managerId, const std::string& entryID)
{
    asyncResp->res.clearHeader(boost::beast::http::field::allow);
    std::string entryId = entryID;
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
    {
        messages::resourceNotFound(asyncResp->res, "Managers", managerId);
        return;
    }
    if (!membersResponseGet(asyncResp, entryID, "LogEntryCollection"))
    {
        return;
    }
    dbus::utility::escapePathForDbus(entryId);

    // Process response from Logging service.
    auto respHandler = [asyncResp,
                        entryID](const boost::system::error_code& ec) {
        if (ec)
        {
            if (ec.value() == EIO)
            {
                messages::resourceNotFound(asyncResp->res, "LogEntry", entryID);
                return;
            }
            // TODO Handle for specific error code
            BMCWEB_LOG_ERROR(
                "EventLogEntry (DBus) doDelete respHandler got error {}", ec);
            asyncResp->res.result(
                boost::beast::http::status::internal_server_error);
            return;
        }

        messages::success(asyncResp->res);
    };

    // Make call to Logging service to request Delete Log
    crow::connections::systemBus->async_method_call(
        respHandler, "xyz.openbmc_project.Logging",
        "/xyz/openbmc_project/logging/ipmi",
        "xyz.openbmc_project.Collection.DeleteLogType", "DeleteLogType", "ipmi",
        static_cast<uint32_t>(std::stoi(entryID)));
}

inline void handleLogServicesSELEntryPatch(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& managerId, const std::string& entryID)
{
    asyncResp->res.clearHeader(boost::beast::http::field::allow);
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
    {
        messages::resourceNotFound(asyncResp->res, "Managers", managerId);
        return;
    }
    if (!membersResponseGet(asyncResp, entryID, "LogEntryCollection"))
    {
        return;
    }
    // Process response from Logging service.
    std::optional<bool> resolved;

    if (!json_util::readJsonPatch( //
            req, asyncResp->res,   //
            "Resolved", resolved   //
            ))
    {
        return;
    }
    BMCWEB_LOG_DEBUG("Set Resolved");

    setDbusProperty(asyncResp, "Resolved", "xyz.openbmc_project.Logging",
                    "/xyz/openbmc_project/logging/ipmi/" + entryID,
                    "xyz.openbmc_project.Logging.Entry", "Resolved",
                    resolved.value_or(false));
}

inline void dBusEventLogEntryGet(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp, std::string entryID)
{
    dbus::utility::escapePathForDbus(entryID);

    // DBus implementation of EventLog/Entries
    // Make call to Logging Service to find all log entry objects
    dbus::utility::getAllProperties(
        "xyz.openbmc_project.Logging",
        "/xyz/openbmc_project/logging/entry/" + entryID, "",
        [asyncResp, entryID](const boost::system::error_code& ec,
                             const dbus::utility::DBusPropertiesMap& resp) {
            if (ec.value() == EBADR)
            {
                messages::resourceNotFound(asyncResp->res, "LogEntry", entryID);
                return;
            }
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "Event LogEntry (DBus) resp_handler got error {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }
            fillEventLogLogEntryFromPropertyMap(asyncResp, resp,
                                                asyncResp->res.jsonValue);
            asyncResp->res.jsonValue["@odata.type"] =
                json_util::odataType("LogEntry");
            std::string timeZone =
                crow::utility::getTimeZone(crow::utility::localTimeZone);
            asyncResp->res.jsonValue["Created"] =
                timeFormat(redfish::time_utils::getDateTimeUintMs(
                    asyncResp->res.jsonValue["Created"], timeZone));
            asyncResp->res.jsonValue["Modified"] =
                timeFormat(redfish::time_utils::getDateTimeUintMs(
                    asyncResp->res.jsonValue["Modified"], timeZone));
        });
}

inline void dBusEventLogEntryPatch(
    const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& entryId)
{
    std::optional<bool> resolved;
    std::optional<std::string> created;
    std::optional<std::string> entryType;
    std::optional<std::string> id;
    std::optional<std::string> modified;
    std::optional<std::string> severity;
    if (!json_util::readJsonPatch(  //
            req, asyncResp->res,    //
            "Resolved", resolved,   //
            "Created", created,     //
            "EntryType", entryType, //
            "Id", id,               //
            "Modified", modified,   //
            "Severity", severity    //
            ))
    {
        return;
    }
    bool isInValid = false;
    if (created)
    {
        isInValid = true;
        messages::propertyNotWritable(asyncResp->res, "Created");
    }
    if (entryType)
    {
        isInValid = true;
        messages::propertyNotWritable(asyncResp->res, "EntryType");
    }
    if (id)
    {
        isInValid = true;
        messages::propertyNotWritable(asyncResp->res, "Id");
    }
    if (modified)
    {
        isInValid = true;
        messages::propertyNotWritable(asyncResp->res, "Modified");
    }
    if (severity)
    {
        isInValid = true;
        messages::propertyNotWritable(asyncResp->res, "Severity");
    }
    if (isInValid == true)
    {
        return;
    }
    BMCWEB_LOG_DEBUG("Set Resolved");

    setDbusProperty(asyncResp, "Resolved", "xyz.openbmc_project.Logging",
                    "/xyz/openbmc_project/logging/entry/" + entryId,
                    "xyz.openbmc_project.Logging.Entry", "Resolved",
                    resolved.value_or(false));
}

inline void dBusEntryDelete(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                            std::string logType, std::string entryID)
{
    dbus::utility::escapePathForDbus(entryID);

    // Process response from Logging service.
    auto respHandler = [asyncResp,
                        entryID](const boost::system::error_code& ec) {
        BMCWEB_LOG_DEBUG("Log Entry (DBus) doDelete callback: Done");
        if (ec)
        {
            if (ec.value() == EIO)
            {
                messages::resourceNotFound(asyncResp->res, "LogEntry", entryID);
                return;
            }
            // TODO Handle for specific error code
            BMCWEB_LOG_ERROR(
                "Log Entry (DBus) doDelete respHandler got error {}", ec);
            asyncResp->res.result(
                boost::beast::http::status::internal_server_error);
            return;
        }

        messages::success(asyncResp->res);
    };

    // Make call to Logging service to request Delete Log
    crow::connections::systemBus->async_method_call(
        respHandler, "xyz.openbmc_project.Logging",
        "/xyz/openbmc_project/logging/ipmi",
        "xyz.openbmc_project.Collection.DeleteLogType", "DeleteLogType",
        logType, static_cast<uint32_t>(std::stoi(entryID)));
}

inline void handleLogServicesSELClearLogPost(
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
    dBusEntryDelete(asyncResp, "ipmi", "0");
}

inline void requestRoutesDBusEventLogEntry(App& app)
{
    BMCWEB_ROUTE(
        app, "/redfish/v1/Systems/<str>/LogServices/EventLog/Entries/<str>/")
        .privileges(redfish::privileges::getLogEntry)
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& systemName, const std::string& entryId) {
                asyncResp->res.clearHeader(boost::beast::http::field::allow);

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
                if (!system_utils::validateSystemName(asyncResp, systemName))
                {
                    return;
                }
                if (!membersResponseGet(asyncResp, entryId,
                                        "LogEntryCollection"))
                {
                    return;
                }
                asyncResp->res.addHeader("Allow", "GET, PATCH, DELETE");
                dBusEventLogEntryGet(asyncResp, entryId);
            });

    BMCWEB_ROUTE(
        app, "/redfish/v1/Systems/<str>/LogServices/EventLog/Entries/<str>/")
        .privileges(redfish::privileges::patchLogEntry)
        .methods(boost::beast::http::verb::patch)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& systemName, const std::string& entryId) {
                asyncResp->res.clearHeader(boost::beast::http::field::allow);

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
                if (!system_utils::validateSystemName(asyncResp, systemName))
                {
                    return;
                }
                if (!membersResponseGet(asyncResp, entryId,
                                        "LogEntryCollection"))
                {
                    return;
                }
                dbus::utility::getAllProperties(
                    "xyz.openbmc_project.Logging",
                    "/xyz/openbmc_project/logging/entry/" + entryId, "",
                    [asyncResp, entryId, req](
                        const boost::system::error_code& ec,
                        [[maybe_unused]] const dbus::utility::DBusPropertiesMap&
                            resp) {
                        if (ec.value() == EBADR)
                        {
                            messages::resourceNotFound(
                                asyncResp->res, "EventLogEntry", entryId);
                            return;
                        }
                        dBusEventLogEntryPatch(req, asyncResp, entryId);
                    });
            });

    BMCWEB_ROUTE(
        app, "/redfish/v1/Systems/<str>/LogServices/EventLog/Entries/<str>/")
        .privileges(redfish::privileges::deleteLogEntry)

        .methods(boost::beast::http::verb::delete_)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& systemName, const std::string& param) {
                asyncResp->res.clearHeader(boost::beast::http::field::allow);

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
                if (!system_utils::validateSystemName(asyncResp, systemName))
                {
                    return;
                }
                if (!membersResponseGet(asyncResp, param, "LogEntryCollection"))
                {
                    return;
                }
                dBusEntryDelete(asyncResp, "default", param);
            });

    BMCWEB_ROUTE(
        app, "/redfish/v1/Systems/<str>/LogServices/EventLog/Entries/<str>/")
        .privileges(redfish::privileges::getLogEntry)
        .methods(boost::beast::http::verb::post)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   [[maybe_unused]] const std::string& systemName,
                   [[maybe_unused]] const std::string& entryId) {
                asyncResp->res.clearHeader(boost::beast::http::field::allow);
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }
                if (!membersResponseGet(asyncResp, entryId,
                                        "LogEntryCollection"))
                {
                    return;
                }
                dbus::utility::getAllProperties(
                    "xyz.openbmc_project.Logging",
                    "/xyz/openbmc_project/logging/entry/" + entryId, "",
                    [asyncResp, entryId](
                        const boost::system::error_code& ec,
                        [[maybe_unused]] const dbus::utility::DBusPropertiesMap&
                            resp) {
                        if (ec.value() == EBADR)
                        {
                            messages::resourceNotFound(
                                asyncResp->res, "EventLogEntry", entryId);
                            return;
                        }
                        asyncResp->res.addHeader("Allow", "GET, PATCH, DELETE");
                        messages::operationNotAllowed(asyncResp->res);
                        return;
                    });
            });
}

constexpr const char* hostLoggerFolderPath = "/var/log/console";

inline bool getHostLoggerFiles(
    const std::string& hostLoggerFilePath,
    std::vector<std::filesystem::path>& hostLoggerFiles)
{
    std::error_code ec;
    std::filesystem::directory_iterator logPath(hostLoggerFilePath, ec);
    if (ec)
    {
        BMCWEB_LOG_WARNING("{}", ec.message());
        return false;
    }
    for (const std::filesystem::directory_entry& it : logPath)
    {
        std::string filename = it.path().filename();
        // Prefix of each log files is "log". Find the file and save the
        // path
        if (filename.starts_with("log"))
        {
            hostLoggerFiles.emplace_back(it.path());
        }
    }
    // As the log files rotate, they are appended with a ".#" that is higher for
    // the older logs. Since we start from oldest logs, sort the name in
    // descending order.
    std::sort(hostLoggerFiles.rbegin(), hostLoggerFiles.rend(),
              AlphanumLess<std::string>());

    return true;
}

inline bool getHostLoggerEntries(
    const std::vector<std::filesystem::path>& hostLoggerFiles, uint64_t skip,
    uint64_t top, std::vector<std::string>& logEntries, size_t& logCount)
{
    GzFileReader logFile;

    // Go though all log files and expose host logs.
    for (const std::filesystem::path& it : hostLoggerFiles)
    {
        if (!logFile.gzGetLines(it.string(), skip, top, logEntries, logCount))
        {
            BMCWEB_LOG_ERROR("fail to expose host logs");
            return false;
        }
    }
    // Get lastMessage from constructor by getter
    std::string lastMessage = logFile.getLastMessage();
    if (!lastMessage.empty())
    {
        logCount++;
        if (logCount > skip && logCount <= (skip + top))
        {
            logEntries.push_back(lastMessage);
        }
    }
    return true;
}
inline void handleBMCLogServicesCollectionGet(
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

    // Collections don't include the static data added by SubRoute
    // because it has a duplicate entry for members
    asyncResp->res.jsonValue["@odata.type"] =
        json_util::odataType("LogServiceCollection");
    asyncResp->res.jsonValue["@odata.id"] = boost::urls::format(
        "/redfish/v1/Managers/{}/LogServices", BMCWEB_REDFISH_MANAGER_URI_NAME);
    asyncResp->res.jsonValue["Name"] = "Open BMC Log Services Collection";
    asyncResp->res.jsonValue["Description"] =
        "Collection of LogServices for this Manager";
    nlohmann::json& logServiceArray = asyncResp->res.jsonValue["Members"];
    logServiceArray = nlohmann::json::array();

    if constexpr (BMCWEB_REDFISH_BMC_JOURNAL)
    {
        nlohmann::json::object_t journal;
        journal["@odata.id"] =
            boost::urls::format("/redfish/v1/Managers/{}/LogServices/Journal",
                                BMCWEB_REDFISH_MANAGER_URI_NAME);
        logServiceArray.emplace_back(std::move(journal));
    }
    nlohmann::json::object_t sel;
    sel["@odata.id"] =
        boost::urls::format("/redfish/v1/Managers/{}/LogServices/SEL",
                            BMCWEB_REDFISH_MANAGER_URI_NAME);
    logServiceArray.emplace_back(std::move(sel));
    asyncResp->res.jsonValue["Members@odata.count"] = logServiceArray.size();

    if constexpr (BMCWEB_REDFISH_DUMP_LOG)
    {
        constexpr std::array<std::string_view, 1> interfaces = {
            "xyz.openbmc_project.Collection.DeleteAll"};
        dbus::utility::getSubTreePaths(
            "/xyz/openbmc_project/dump", 0, interfaces,
            [asyncResp](const boost::system::error_code& ec,
                        const dbus::utility::MapperGetSubTreePathsResponse&
                            subTreePaths) {
                if (ec)
                {
                    BMCWEB_LOG_ERROR(
                        "handleBMCLogServicesCollectionGet respHandler got error {}",
                        ec);
                    // Assume that getting an error simply means there are no
                    // dump LogServices. Return without adding any error
                    // response.
                    return;
                }

                nlohmann::json& logServiceArrayLocal =
                    asyncResp->res.jsonValue["Members"];

                for (const std::string& path : subTreePaths)
                {
                    if (path == "/xyz/openbmc_project/dump/bmc")
                    {
                        nlohmann::json::object_t member;
                        member["@odata.id"] = boost::urls::format(
                            "/redfish/v1/Managers/{}/LogServices/Dump",
                            BMCWEB_REDFISH_MANAGER_URI_NAME);
                        logServiceArrayLocal.emplace_back(std::move(member));
                    }
                    else if (path == "/xyz/openbmc_project/dump/faultlog")
                    {
                        nlohmann::json::object_t member;
                        member["@odata.id"] = boost::urls::format(
                            "/redfish/v1/Managers/{}/LogServices/FaultLog",
                            BMCWEB_REDFISH_MANAGER_URI_NAME);
                        logServiceArrayLocal.emplace_back(std::move(member));
                    }
                }

                asyncResp->res.jsonValue["Members@odata.count"] =
                    logServiceArrayLocal.size();
            });
    }
}

inline void requestRoutesBMCLogServiceCollection(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Managers/<str>/LogServices/")
        .privileges(redfish::privileges::getLogServiceCollection)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleBMCLogServicesCollectionGet, std::ref(app)));
}

inline void getDumpServiceInfo(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& dumpType)
{
    std::string dumpPath;
    log_service::OverWritePolicy overWritePolicy =
        log_service::OverWritePolicy::Invalid;
    bool collectDiagnosticDataSupported = false;

    if (dumpType == "BMC")
    {
        dumpPath = std::format("/redfish/v1/Managers/{}/LogServices/Dump",
                               BMCWEB_REDFISH_MANAGER_URI_NAME);
        overWritePolicy = log_service::OverWritePolicy::WrapsWhenFull;
        collectDiagnosticDataSupported = true;
    }
    else if (dumpType == "FaultLog")
    {
        dumpPath = std::format("/redfish/v1/Managers/{}/LogServices/FaultLog",
                               BMCWEB_REDFISH_MANAGER_URI_NAME);
        overWritePolicy = log_service::OverWritePolicy::Unknown;
        collectDiagnosticDataSupported = false;
    }
    else if (dumpType == "System")
    {
        dumpPath = std::format("/redfish/v1/Systems/{}/LogServices/Dump",
                               BMCWEB_REDFISH_SYSTEM_URI_NAME);
        overWritePolicy = log_service::OverWritePolicy::WrapsWhenFull;
        collectDiagnosticDataSupported = true;
    }
    else if (dumpType == "SEL")
    {
        dumpPath = std::format("/redfish/v1/Managers/{}/LogServices/SEL",
                               BMCWEB_REDFISH_MANAGER_URI_NAME);
        overWritePolicy = log_service::OverWritePolicy::WrapsWhenFull;
        collectDiagnosticDataSupported = false;
        asyncResp->res.jsonValue["MaxNumberOfRecords"] = 1250;
    }
    else
    {
        BMCWEB_LOG_ERROR("getDumpServiceInfo() invalid dump type: {}",
                         dumpType);
        messages::internalError(asyncResp->res);
        return;
    }

    asyncResp->res.jsonValue["@odata.id"] = dumpPath;
    asyncResp->res.jsonValue["@odata.type"] =
        json_util::odataType("LogService");
    asyncResp->res.jsonValue["Name"] = "Dump LogService";
    asyncResp->res.jsonValue["Description"] = dumpType + " Dump LogService";
    asyncResp->res.jsonValue["Id"] = std::filesystem::path(dumpPath).filename();
    asyncResp->res.jsonValue["OverWritePolicy"] = overWritePolicy;

    if (overWritePolicy == log_service::OverWritePolicy::WrapsWhenFull &&
        dumpType != "SEL")
    {
        asyncResp->res.jsonValue["MaxNumberOfRecords"] = 150;
    }

    auto [dateTime, offsetStr] = redfish::time_utils::getLocalDateTimeOffset();
    asyncResp->res.jsonValue["DateTime"] = dateTime;
    asyncResp->res.jsonValue["DateTimeLocalOffset"] = offsetStr;

    asyncResp->res.jsonValue["Entries"]["@odata.id"] = dumpPath + "/Entries";

    if (collectDiagnosticDataSupported)
    {
        asyncResp->res.jsonValue["Actions"]["#LogService.CollectDiagnosticData"]
                                ["target"] =
            dumpPath + "/Actions/LogService.CollectDiagnosticData";
    }

    constexpr std::array<std::string_view, 1> interfaces = {deleteAllInterface};
    dbus::utility::getSubTreePaths(
        "/xyz/openbmc_project/dump", 0, interfaces,
        [asyncResp, dumpType, dumpPath](
            const boost::system::error_code& ec,
            const dbus::utility::MapperGetSubTreePathsResponse& subTreePaths) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("getDumpServiceInfo respHandler got error {}",
                                 ec);
                // Assume that getting an error simply means there are no dump
                // LogServices. Return without adding any error response.
                return;
            }
            std::string dbusDumpPath = getDumpPath(dumpType);
            for (const std::string& path : subTreePaths)
            {
                if (path == dbusDumpPath)
                {
                    asyncResp->res.jsonValue["Actions"]["#LogService.ClearLog"]
                                            ["target"] =
                        dumpPath + "/Actions/LogService.ClearLog";
                    break;
                }
            }
        });
}

inline void handleLogServicesDumpServiceGet(
    crow::App& app, const std::string& dumpType, const crow::Request& req,
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

    getDumpServiceInfo(asyncResp, dumpType);
}

inline void handleLogServicesSELServiceGet(
    crow::App& app, const std::string& dumpType, const crow::Request& req,
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

    getDumpServiceInfo(asyncResp, dumpType);
    asyncResp->res
        .jsonValue["Actions"]["#LogService.ClearLog"]["target"] = std::format(
        "/redfish/v1/Managers/{}/LogServices/SEL/Actions/LogService.ClearLog",
        BMCWEB_REDFISH_MANAGER_URI_NAME);
}

inline void handleLogServicesDumpServiceComputerSystemGet(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (chassisId != BMCWEB_REDFISH_SYSTEM_URI_NAME)
    {
        messages::resourceNotFound(asyncResp->res, "ComputerSystem", chassisId);
        return;
    }
    getDumpServiceInfo(asyncResp, "System");
}

inline void handleLogServicesSELEntriesCollectionGet(
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
    getSELEntryCollection(asyncResp);
}

inline void handleLogServicesDumpEntriesCollectionGet(
    crow::App& app, const std::string& dumpType, const crow::Request& req,
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
    getDumpEntryCollection(asyncResp, dumpType);
}

inline void handleLogServicesDumpEntriesCollectionComputerSystemGet(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (chassisId != BMCWEB_REDFISH_SYSTEM_URI_NAME)
    {
        messages::resourceNotFound(asyncResp->res, "ComputerSystem", chassisId);
        return;
    }
    getDumpEntryCollection(asyncResp, "System");
}

inline void handleLogServicesDumpEntryGet(
    crow::App& app, const std::string& dumpType, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& managerId, const std::string& dumpId)
{
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
    if (!membersResponseGet(asyncResp, dumpId, "LogEntryCollection"))
    {
        return;
    }
    asyncResp->res.addHeader("Allow", "GET, DELETE");
    getDumpEntryById(asyncResp, dumpId, dumpType);
}

inline void handleLogServicesDumpEntryComputerSystemGet(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId, const std::string& dumpId)
{
    asyncResp->res.clearHeader(boost::beast::http::field::allow);
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (chassisId != BMCWEB_REDFISH_SYSTEM_URI_NAME)
    {
        messages::resourceNotFound(asyncResp->res, "ComputerSystem", chassisId);
        return;
    }
    if (!membersResponseGet(asyncResp, dumpId, "LogEntryCollection"))
    {
        return;
    }
    asyncResp->res.addHeader("Allow", "GET, DELETE");
    getDumpEntryById(asyncResp, dumpId, "System");
}

inline void handleLogServicesDumpEntryDelete(
    crow::App& app, const std::string& dumpType, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& managerId, const std::string& dumpId)
{
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
    if (!membersResponseGet(asyncResp, dumpId, "LogEntryCollection"))
    {
        return;
    }
    deleteDumpEntry(asyncResp, dumpId, dumpType);
}

inline void handleLogServicesDumpEntryPost(
    crow::App& app, [[maybe_unused]] const std::string& dumpType,
    const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& managerId, const std::string& entryID)
{
    asyncResp->res.clearHeader(boost::beast::http::field::allow);
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (!membersResponseGet(asyncResp, entryID, "LogEntryCollection"))
    {
        return;
    }
    if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
    {
        messages::resourceNotFound(asyncResp->res, "Manager", managerId);
        return;
    }

    std::string entriesPath = getDumpEntriesPath(dumpType);
    if (entriesPath.empty())
    {
        messages::internalError(asyncResp->res);
        return;
    }

    sdbusplus::message::object_path path("/xyz/openbmc_project/dump");
    dbus::utility::getManagedObjects(
        "xyz.openbmc_project.Dump.Manager", path,
        [asyncResp, entryID, dumpType,
         entriesPath](const boost::system::error_code& ec,
                      const dbus::utility::ManagedObjectType& resp) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("DumpEntry resp_handler got error {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }

            bool foundDumpEntry = false;
            std::string dumpEntryPath = getDumpPath(dumpType) + "/entry/";

            for (const auto& objectPath : resp)
            {
                if (objectPath.first.str != dumpEntryPath + entryID)
                {
                    continue;
                }

                foundDumpEntry = true;
            }
            if (!foundDumpEntry)
            {
                BMCWEB_LOG_WARNING("Can't find Dump Entry {}", entryID);
                messages::resourceNotFound(asyncResp->res, dumpType + " dump",
                                           entryID);
                return;
            }
            else
            {
                asyncResp->res.addHeader("Allow", "GET, DELETE");
                messages::operationNotAllowed(asyncResp->res);
                return;
            }
        });
}

inline void handleLogServicesDumpEntryComputerSystemDelete(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId, const std::string& dumpId)
{
    asyncResp->res.clearHeader(boost::beast::http::field::allow);
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (chassisId != BMCWEB_REDFISH_SYSTEM_URI_NAME)
    {
        messages::resourceNotFound(asyncResp->res, "ComputerSystem", chassisId);
        return;
    }
    if (!membersResponseGet(asyncResp, dumpId, "LogEntryCollection"))
    {
        return;
    }
    deleteDumpEntry(asyncResp, dumpId, "System");
}

inline void handleLogServicesSELEntryDownloadGet(
    crow::App& app, const std::string& dumpType, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& managerId, const std::string& entryID)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    std::string_view Accept = req.getHeaderValue("Accept");
    if (Accept.find("text/html, */*") == std::string::npos &&
        Accept.find("text/html, */*;q=0.8") == std::string::npos &&
        Accept.find("*/*") == std::string::npos &&
        Accept.find("application/json") == std::string::npos)
    {
        asyncResp->res.result(boost::beast::http::status::bad_request);
        return;
    }
    downloadSELEntry(asyncResp, managerId, entryID, dumpType);
}

inline void handleLogServicesDumpEntryDownloadGet(
    crow::App& app, const std::string& dumpType, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& managerId, const std::string& dumpId)
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
    downloadDumpEntry(asyncResp, dumpId, dumpType);
}

inline void handleDBusEventLogEntryDownloadGet(
    crow::App& app, const std::string& dumpType, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& systemName, const std::string& entryID)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    std::string_view Accept = req.getHeaderValue("Accept");
    if (Accept.find("text/html, */*") == std::string::npos &&
        Accept.find("text/html, */*;q=0.8") == std::string::npos &&
        Accept.find("*/*") == std::string::npos &&
        Accept.find("application/json") == std::string::npos)
    {
        asyncResp->res.result(boost::beast::http::status::bad_request);
        return;
    }
    downloadEventLogEntry(asyncResp, systemName, entryID, dumpType);
}

inline void handleLogServicesDumpCollectDiagnosticDataPost(
    crow::App& app, const std::string& dumpType, const crow::Request& req,
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

    createDump(asyncResp, req, dumpType);
}

inline void handleLogServicesDumpCollectDiagnosticDataComputerSystemPost(
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
    if (!system_utils::validateSystemName(asyncResp, systemName))
    {
        return;
    }
    createDump(asyncResp, req, "System");
}

inline void handleLogServicesDumpClearLogPost(
    crow::App& app, const std::string& dumpType, const crow::Request& req,
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
    clearDump(asyncResp, dumpType);
}

inline void handleLogServicesDumpClearLogComputerSystemPost(
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
    if (!system_utils::validateSystemName(asyncResp, systemName))
    {
        return;
    }
    clearDump(asyncResp, "System");
}

inline void handleLogServicesDumpConfigGet(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    dbus::utility::getAllProperties(
        amdcrashdumpObject, amdcrashdumpPath, crashdumpconfigInterface,
        [asyncResp](const boost::system::error_code& ec,
                    const dbus::utility::DBusPropertiesMap& propertiesList) {
            if (ec)
            {
                if (ec.value() != EBADR)
                {
                    BMCWEB_LOG_ERROR("DBUS response error for Asset {}",
                                     ec.value());
                }
                return;
            }

            const uint16_t* apmlretries = nullptr;
            const bool* harvestppin = nullptr;
            const bool* harvestucodeversion = nullptr;
            const uint16_t* systemrecovery = nullptr;
            const bool* mcaPollingEn = nullptr;
            const uint16_t* mcaPollingPeriod = nullptr;
            const bool* dramCeccPollingEn = nullptr;
            const uint16_t* dramCeccPollingPeriod = nullptr;
            const bool* pcieAerPollingEn = nullptr;
            const uint16_t* pcieAerPollingPeriod = nullptr;

            const bool success = sdbusplus::unpackPropertiesNoThrow(
                dbus_utils::UnpackErrorPrinter(), propertiesList, "apmlRetries",
                apmlretries, "harvestPpin", harvestppin, "harvestuCodeVersion",
                harvestucodeversion, "systemRecovery", systemrecovery,
                "McaPollingEn", mcaPollingEn, "McaPollingPeriod",
                mcaPollingPeriod, "DramCeccPollingEn", dramCeccPollingEn,
                "DramCeccPollingPeriod", dramCeccPollingPeriod,
                "PcieAerPollingEn", pcieAerPollingEn, "PcieAerPollingPeriod",
                pcieAerPollingPeriod);

            if (!success)
            {
                messages::internalError(asyncResp->res);
                return;
            }

            asyncResp->res.jsonValue["Oem"]["Ami"]["@odata.type"] =
                json_util::odataType("AmiADDCConfiguration");

            if (apmlretries != nullptr)
            {
                asyncResp->res
                    .jsonValue["Oem"]["Ami"]["Configuration"]["Retry"] =
                    *apmlretries;
            }

            if (harvestppin != nullptr)
            {
                asyncResp->res
                    .jsonValue["Oem"]["Ami"]["Configuration"]["HarvestPPIN"] =
                    *harvestppin;
            }

            if (harvestucodeversion != nullptr)
            {
                asyncResp->res
                    .jsonValue["Oem"]["Ami"]["Configuration"]["HarvestUCode"] =
                    *harvestucodeversion;
            }

            if (systemrecovery != nullptr)
            {
                std::string value = getRecoveryMode(*systemrecovery);
                asyncResp->res
                    .jsonValue["Oem"]["Ami"]["Configuration"]["RecoverMode"] =
                    value;
            }

            if (mcaPollingEn != nullptr)
            {
                asyncResp->res
                    .jsonValue["Oem"]["Ami"]["Configuration"]["McaPollingEn"] =
                    *mcaPollingEn;
            }

            if (mcaPollingPeriod != nullptr)
            {
                asyncResp->res.jsonValue["Oem"]["Ami"]["Configuration"]
                                        ["McaPollingPeriod"] =
                    *mcaPollingPeriod;
            }

            if (dramCeccPollingEn != nullptr)
            {
                asyncResp->res.jsonValue["Oem"]["Ami"]["Configuration"]
                                        ["DramCeccPollingEn"] =
                    *dramCeccPollingEn;
            }

            if (dramCeccPollingPeriod != nullptr)
            {
                asyncResp->res.jsonValue["Oem"]["Ami"]["Configuration"]
                                        ["DramCeccPollingPeriod"] =
                    *dramCeccPollingPeriod;
            }

            if (pcieAerPollingEn != nullptr)
            {
                asyncResp->res.jsonValue["Oem"]["Ami"]["Configuration"]
                                        ["PcieAerPollingEn"] =
                    *pcieAerPollingEn;
            }

            if (pcieAerPollingPeriod != nullptr)
            {
                asyncResp->res.jsonValue["Oem"]["Ami"]["Configuration"]
                                        ["PcieAerPollingPeriod"] =
                    *pcieAerPollingPeriod;
            }
        });
}

inline void requestRoutesBMCDumpService(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Managers/<str>/LogServices/Dump/")
        .privileges(redfish::privileges::getLogService)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleLogServicesDumpServiceGet, std::ref(app), "BMC"));
}

inline void requestRoutesBMCDumpEntryCollection(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Managers/<str>/LogServices/Dump/Entries/")
        .privileges(redfish::privileges::getLogEntryCollection)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleLogServicesDumpEntriesCollectionGet, std::ref(app), "BMC"));
}

inline void requestRoutesBMCDumpEntry(App& app)
{
    BMCWEB_ROUTE(app,
                 "/redfish/v1/Managers/<str>/LogServices/Dump/Entries/<str>/")
        .privileges(redfish::privileges::getLogEntry)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleLogServicesDumpEntryGet, std::ref(app), "BMC"));

    BMCWEB_ROUTE(app,
                 "/redfish/v1/Managers/<str>/LogServices/Dump/Entries/<str>/")
        .privileges(redfish::privileges::deleteLogEntry)
        .methods(boost::beast::http::verb::delete_)(std::bind_front(
            handleLogServicesDumpEntryDelete, std::ref(app), "BMC"));

    BMCWEB_ROUTE(app,
                 "/redfish/v1/Managers/<str>/LogServices/Dump/Entries/<str>/")
        .privileges(redfish::privileges::getLogEntry)
        .methods(boost::beast::http::verb::patch,
                 boost::beast::http::verb::post)(std::bind_front(
            handleLogServicesDumpEntryPost, std::ref(app), "BMC"));
}

inline void requestRoutesBMCDumpEntryDownload(App& app)
{
    BMCWEB_ROUTE(
        app,
        "/redfish/v1/Managers/<str>/LogServices/Dump/Entries/<str>/attachment/")
        .privileges(redfish::privileges::getLogEntry)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleLogServicesDumpEntryDownloadGet, std::ref(app), "BMC"));
}
inline void requestRoutesBMCSELService(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Managers/<str>/LogServices/SEL/")
        .privileges(redfish::privileges::getLogService)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleLogServicesSELServiceGet, std::ref(app), "SEL"));
}

inline void requestRoutesBMCSELEntryCollection(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Managers/<str>/LogServices/SEL/Entries/")
        .privileges(redfish::privileges::getLogEntryCollection)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleLogServicesSELEntriesCollectionGet, std::ref(app)));
}

inline void requestRoutesBMCSELEntry(App& app)
{
    BMCWEB_ROUTE(app,
                 "/redfish/v1/Managers/<str>/LogServices/SEL/Entries/<str>/")
        .privileges(redfish::privileges::getLogEntry)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleLogServicesSELEntryGet, std::ref(app)));

    BMCWEB_ROUTE(app,
                 "/redfish/v1/Managers/<str>/LogServices/SEL/Entries/<str>/")
        .privileges(redfish::privileges::patchLogEntry)
        .methods(boost::beast::http::verb::patch)(
            std::bind_front(handleLogServicesSELEntryPatch, std::ref(app)));

    BMCWEB_ROUTE(app,
                 "/redfish/v1/Managers/<str>/LogServices/SEL/Entries/<str>/")
        .privileges(redfish::privileges::deleteLogEntry)
        .methods(boost::beast::http::verb::delete_)(
            std::bind_front(handleLogServicesSELEntryDelete, std::ref(app)));

    BMCWEB_ROUTE(app,
                 "/redfish/v1/Managers/<str>/LogServices/SEL/Entries/<str>/")
        .methods(boost::beast::http::verb::post)(
            [&app](const crow::Request& /* req */,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& /* chassisId */,
                   const std::string& entryID) {
                asyncResp->res.clearHeader(boost::beast::http::field::allow);
                if (!membersResponseGet(asyncResp, entryID,
                                        "LogEntryCollection"))
                {
                    return;
                }
                asyncResp->res.addHeader("Allow", "GET, PATCH, DELETE");
                messages::operationNotAllowed(asyncResp->res);
            });
}

inline void requestRoutesBMCSELClear(App& app)
{
    BMCWEB_ROUTE(
        app,
        "/redfish/v1/Managers/<str>/LogServices/SEL/Actions/LogService.ClearLog/")
        .privileges(redfish::privileges::postLogService)
        .methods(boost::beast::http::verb::post)(
            std::bind_front(handleLogServicesSELClearLogPost, std::ref(app)));
}

inline void requestRoutesBMCSELEntryDownload(App& app)
{
    BMCWEB_ROUTE(
        app,
        "/redfish/v1/Managers/<str>/LogServices/SEL/Entries/<str>/attachment/")
        .privileges(redfish::privileges::getLogEntry)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleLogServicesSELEntryDownloadGet, std::ref(app), "BMC"));
}

inline void requestRoutesBMCDumpCreate(App& app)
{
    BMCWEB_ROUTE(
        app,
        "/redfish/v1/Managers/<str>/LogServices/Dump/Actions/LogService.CollectDiagnosticData/")
        .privileges(redfish::privileges::postLogService)
        .methods(boost::beast::http::verb::post)(
            std::bind_front(handleLogServicesDumpCollectDiagnosticDataPost,
                            std::ref(app), "BMC"));
}

inline void requestRoutesBMCDumpClear(App& app)
{
    BMCWEB_ROUTE(
        app,
        "/redfish/v1/Managers/<str>/LogServices/Dump/Actions/LogService.ClearLog/")
        .privileges(redfish::privileges::postLogService)
        .methods(boost::beast::http::verb::post)(std::bind_front(
            handleLogServicesDumpClearLogPost, std::ref(app), "BMC"));
}

inline void requestRoutesDBusEventLogEntryDownload(App& app)
{
    BMCWEB_ROUTE(
        app,
        "/redfish/v1/Systems/<str>/LogServices/EventLog/Entries/<str>/attachment/")
        .privileges(redfish::privileges::getLogEntry)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleDBusEventLogEntryDownloadGet, std::ref(app), "System"));
}

inline void requestRoutesFaultLogDumpService(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Managers/<str>/LogServices/FaultLog/")
        .privileges(redfish::privileges::getLogService)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleLogServicesDumpServiceGet, std::ref(app), "FaultLog"));
}

inline void requestRoutesFaultLogDumpEntryCollection(App& app)
{
    BMCWEB_ROUTE(app,
                 "/redfish/v1/Managers/<str>/LogServices/FaultLog/Entries/")
        .privileges(redfish::privileges::getLogEntryCollection)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleLogServicesDumpEntriesCollectionGet,
                            std::ref(app), "FaultLog"));
}

inline void requestRoutesFaultLogDumpEntry(App& app)
{
    BMCWEB_ROUTE(
        app, "/redfish/v1/Managers/<str>/LogServices/FaultLog/Entries/<str>/")
        .privileges(redfish::privileges::getLogEntry)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleLogServicesDumpEntryGet, std::ref(app), "FaultLog"));

    BMCWEB_ROUTE(
        app, "/redfish/v1/Managers/<str>/LogServices/FaultLog/Entries/<str>/")
        .privileges(redfish::privileges::deleteLogEntry)
        .methods(boost::beast::http::verb::delete_)(std::bind_front(
            handleLogServicesDumpEntryDelete, std::ref(app), "FaultLog"));

    BMCWEB_ROUTE(
        app, "/redfish/v1/Managers/<str>/LogServices/FaultLog/Entries/<str>/")
        .privileges(redfish::privileges::getLogEntry)
        .methods(boost::beast::http::verb::patch,
                 boost::beast::http::verb::post)(std::bind_front(
            handleLogServicesDumpEntryPost, std::ref(app), "FaultLog"));
}

inline void requestRoutesFaultLogDumpClear(App& app)
{
    BMCWEB_ROUTE(
        app,
        "/redfish/v1/Managers/<str>/LogServices/FaultLog/Actions/LogService.ClearLog/")
        .privileges(redfish::privileges::postLogService)
        .methods(boost::beast::http::verb::post)(std::bind_front(
            handleLogServicesDumpClearLogPost, std::ref(app), "FaultLog"));
}

inline void requestRoutesSystemDumpService(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/LogServices/Dump/")
        .privileges(redfish::privileges::getLogService)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleLogServicesDumpServiceComputerSystemGet, std::ref(app)));
}

inline void requestRoutesSystemDumpEntryCollection(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/LogServices/Dump/Entries/")
        .privileges(redfish::privileges::getLogEntryCollection)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleLogServicesDumpEntriesCollectionComputerSystemGet,
            std::ref(app)));
}

inline void requestRoutesSystemDumpEntry(App& app)
{
    BMCWEB_ROUTE(app,
                 "/redfish/v1/Systems/<str>/LogServices/Dump/Entries/<str>/")
        .privileges(redfish::privileges::getLogEntry)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleLogServicesDumpEntryComputerSystemGet, std::ref(app)));

    BMCWEB_ROUTE(app,
                 "/redfish/v1/Systems/<str>/LogServices/Dump/Entries/<str>/")
        .privileges(redfish::privileges::deleteLogEntry)
        .methods(boost::beast::http::verb::delete_)(std::bind_front(
            handleLogServicesDumpEntryComputerSystemDelete, std::ref(app)));

    BMCWEB_ROUTE(app,
                 "/redfish/v1/Systems/<str>/LogServices/Dump/Entries/<str>/")
        .methods(boost::beast::http::verb::post,
                 boost::beast::http::verb::patch,
                 boost::beast::http::verb::put)(
            [&app](const crow::Request& /* req */,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& /* chassisId */,
                   const std::string& dumpId) {
                asyncResp->res.clearHeader(boost::beast::http::field::allow);
                if (!membersResponseGet(asyncResp, dumpId,
                                        "LogEntryCollection"))
                {
                    return;
                }
                asyncResp->res.addHeader("Allow", "GET, DELETE");
                messages::operationNotAllowed(asyncResp->res);
            });
}

inline void requestRoutesSystemDumpCreate(App& app)
{
    BMCWEB_ROUTE(
        app,
        "/redfish/v1/Systems/<str>/LogServices/Dump/Actions/LogService.CollectDiagnosticData/")
        .privileges(redfish::privileges::postLogService)
        .methods(boost::beast::http::verb::post)(std::bind_front(
            handleLogServicesDumpCollectDiagnosticDataComputerSystemPost,
            std::ref(app)));
}

inline void requestRoutesSystemDumpClear(App& app)
{
    BMCWEB_ROUTE(
        app,
        "/redfish/v1/Systems/<str>/LogServices/Dump/Actions/LogService.ClearLog/")
        .privileges(redfish::privileges::postLogService)
        .methods(boost::beast::http::verb::post)(std::bind_front(
            handleLogServicesDumpClearLogComputerSystemPost, std::ref(app)));
}

inline void requestRoutesCrashdumpService(App& app)
{
    // Note: Deviated from redfish privilege registry for GET & HEAD
    // method for security reasons.
    /**
     * Functions triggers appropriate requests on DBus
     */
    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/LogServices/Crashdump/")
        // This is incorrect, should be:
        //.privileges(redfish::privileges::getLogService)
        .privileges({{"Login"}})
        .methods(
            boost::beast::http::verb::
                get)([&app](const crow::Request& req,
                            const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                            const std::string& systemName) {
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
            if (!system_utils::validateSystemName(asyncResp, systemName))
            {
                return;
            }

            // Copy over the static data to include the entries added by
            // SubRoute
            asyncResp->res.jsonValue["@odata.id"] =
                std::format("/redfish/v1/Systems/{}/LogServices/Crashdump",
                            BMCWEB_REDFISH_SYSTEM_URI_NAME);
            asyncResp->res.jsonValue["@odata.type"] =
                json_util::odataType("LogService");
            asyncResp->res.jsonValue["Name"] = "Open BMC Oem Crashdump Service";
            asyncResp->res.jsonValue["Description"] = "Oem Crashdump Service";
            asyncResp->res.jsonValue["Id"] = "Crashdump";
            asyncResp->res.jsonValue["OverWritePolicy"] =
                log_service::OverWritePolicy::WrapsWhenFull;
#ifdef ONETREE_BHS
            asyncResp->res.jsonValue["MaxNumberOfRecords"] = 1;
#else
            asyncResp->res.jsonValue["MaxNumberOfRecords"] = 150;
#endif

            auto [dateTime,
                  offsetStr] = redfish::time_utils::getLocalDateTimeOffset();
            asyncResp->res.jsonValue["DateTime"] = dateTime;
            asyncResp->res.jsonValue["DateTimeLocalOffset"] = offsetStr;

            asyncResp->res.jsonValue["Entries"]["@odata.id"] = std::format(
                "/redfish/v1/Systems/{}/LogServices/Crashdump/Entries",
                BMCWEB_REDFISH_SYSTEM_URI_NAME);
            asyncResp->res.jsonValue["Actions"]["#LogService.ClearLog"]
                                    ["target"] = std::format(
                "/redfish/v1/Systems/{}/LogServices/Crashdump/Actions/LogService.ClearLog",
                BMCWEB_REDFISH_SYSTEM_URI_NAME);
            asyncResp->res
                .jsonValue["Actions"]["#LogService.CollectDiagnosticData"]
                          ["target"] = std::format(
                "/redfish/v1/Systems/{}/LogServices/Crashdump/Actions/LogService.CollectDiagnosticData",
                BMCWEB_REDFISH_SYSTEM_URI_NAME);

            handleLogServicesDumpConfigGet(asyncResp);
        });

    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/LogServices/Crashdump/")
        .privileges({{"ConfigureManager"}})
        .methods(boost::beast::http::verb::patch)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& systemName) {
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
                if (!system_utils::validateSystemName(asyncResp, systemName))
                {
                    return;
                }

                BMCWEB_LOG_DEBUG("doPatch...");

                std::optional<uint16_t> apmlretries;
                std::optional<std::string> systemrecovery;
                std::optional<bool> harvestppin;
                std::optional<bool> harvestucodeversion;
                std::optional<bool> dramCeccPollingEn;
                std::optional<uint16_t> dramCeccPollingPeriod;
                std::optional<bool> mcaPollingEn;
                std::optional<uint16_t> mcaPollingPeriod;
                std::optional<bool> pcieAerPollingEn;
                std::optional<uint16_t> pcieAerPollingPeriod;

                if (!json_util::readJsonPatch(                               //
                        req, asyncResp->res,                                 //
                        "Oem/Ami/Configuration/Retry", apmlretries,          //
                        "Oem/Ami/Configuration/HarvestPPIN", harvestppin,    //
                        "Oem/Ami/Configuration/HarvestUCode",
                        harvestucodeversion,                                 //
                        "Oem/Ami/Configuration/RecoverMode", systemrecovery, //
                        "Oem/Ami/Configuration/DramCeccPollingEn",
                        dramCeccPollingEn,                                   //
                        "Oem/Ami/Configuration/DramCeccPollingPeriod",
                        dramCeccPollingPeriod,                               //
                        "Oem/Ami/Configuration/McaPollingEn", mcaPollingEn,  //
                        "Oem/Ami/Configuration/McaPollingPeriod",
                        mcaPollingPeriod,                                    //
                        "Oem/Ami/Configuration/PcieAerPollingEn",
                        pcieAerPollingEn,                                    //
                        "Oem/Ami/Configuration/PcieAerPollingPeriod",
                        pcieAerPollingPeriod                                 //
                        ))
                {
                    BMCWEB_LOG_DEBUG("doPatch: Invalid request body");
                    return;
                }

                if (apmlretries)
                {
                    if (*apmlretries <= 100)
                    {
                        setDbusProperty(asyncResp, "Retry", "com.amd.crashdump",
                                        sdbusplus::message::object_path(
                                            "/com/amd/crashdump"),
                                        "com.amd.crashdump.Configuration",
                                        "apmlRetries", *apmlretries);
                    }
                    else
                    {
                        messages::propertyValueNotInList(asyncResp->res,
                                                         *apmlretries, "Retry");
                        return;
                    }
                }

                if (harvestppin)
                {
                    setDbusProperty(
                        asyncResp, "HarvestPPIN", "com.amd.crashdump",
                        sdbusplus::message::object_path("/com/amd/crashdump"),
                        "com.amd.crashdump.Configuration", "harvestPpin",
                        *harvestppin);
                }

                if (harvestucodeversion)
                {
                    setDbusProperty(
                        asyncResp, "HarvestUCode", "com.amd.crashdump",
                        sdbusplus::message::object_path("/com/amd/crashdump"),
                        "com.amd.crashdump.Configuration",
                        "harvestuCodeVersion", *harvestucodeversion);
                }

                if (systemrecovery)
                {
                    uint16_t value = getrecoverydata(*systemrecovery);

                    if (value < 3)
                    {
                        setDbusProperty(asyncResp, "RecoveryMode",
                                        "com.amd.crashdump",
                                        sdbusplus::message::object_path(
                                            "/com/amd/crashdump"),
                                        "com.amd.crashdump.Configuration",
                                        "systemRecovery", value);
                    }
                    else
                    {
                        messages::propertyValueNotInList(
                            asyncResp->res, *systemrecovery, "RecoveryMode");
                        return;
                    }
                }

                if (dramCeccPollingEn)
                {
                    setDbusProperty(
                        asyncResp, "DramCeccPollingEn", "com.amd.crashdump",
                        sdbusplus::message::object_path("/com/amd/crashdump"),
                        "com.amd.crashdump.Configuration", "DramCeccPollingEn",
                        *dramCeccPollingEn);
                }

                if (dramCeccPollingPeriod)
                {
                    auto value = getCrashdumpConfig(
                        amdcrashdumpObject, amdcrashdumpPath,
                        crashdumpconfigInterface, "DramCeccPollingEn");
                    auto dramCeccEnable = std::get<bool>(value);
                    if (dramCeccEnable)
                    {
                        setDbusProperty(
                            asyncResp, "DramCeccPollingPeriod",
                            "com.amd.crashdump",
                            sdbusplus::message::object_path(
                                "/com/amd/crashdump"),
                            "com.amd.crashdump.Configuration",
                            "DramCeccPollingPeriod", *dramCeccPollingPeriod);
                    }
                    else
                    {
                        messages::propertyMissing(asyncResp->res,
                                                  "DramCeccPollingEn");
                        return;
                    }
                }

                if (mcaPollingEn)
                {
                    setDbusProperty(
                        asyncResp, "McaPollingEn", "com.amd.crashdump",
                        sdbusplus::message::object_path("/com/amd/crashdump"),
                        "com.amd.crashdump.Configuration", "McaPollingEn",
                        *mcaPollingEn);
                }

                if (mcaPollingPeriod)
                {
                    auto value = getCrashdumpConfig(
                        amdcrashdumpObject, amdcrashdumpPath,
                        crashdumpconfigInterface, "McaPollingEn");
                    auto mcaPollEnable = std::get<bool>(value);
                    if (mcaPollEnable)
                    {
                        setDbusProperty(asyncResp, "McaPollingPeriod",
                                        "com.amd.crashdump",
                                        sdbusplus::message::object_path(
                                            "/com/amd/crashdump"),
                                        "com.amd.crashdump.Configuration",
                                        "McaPollingPeriod", *mcaPollingPeriod);
                    }
                    else
                    {
                        messages::propertyMissing(asyncResp->res,
                                                  "McaPollingEn");
                        return;
                    }
                }

                if (pcieAerPollingEn)
                {
                    setDbusProperty(
                        asyncResp, "PcieAerPollingEn", "com.amd.crashdump",
                        sdbusplus::message::object_path("/com/amd/crashdump"),
                        "com.amd.crashdump.Configuration", "PcieAerPollingEn",
                        *pcieAerPollingEn);
                }

                if (pcieAerPollingPeriod)
                {
                    auto value = getCrashdumpConfig(
                        amdcrashdumpObject, amdcrashdumpPath,
                        crashdumpconfigInterface, "PcieAerPollingEn");
                    auto pcieAerPollEnable = std::get<bool>(value);
                    if (pcieAerPollEnable)
                    {
                        setDbusProperty(
                            asyncResp, "PcieAerPollingPeriod",
                            "com.amd.crashdump",
                            sdbusplus::message::object_path(
                                "/com/amd/crashdump"),
                            "com.amd.crashdump.Configuration",
                            "PcieAerPollingPeriod", *pcieAerPollingPeriod);
                    }
                    else
                    {
                        messages::propertyMissing(asyncResp->res,
                                                  "PcieAerPollingEn");
                        return;
                    }
                }
            });
}

void inline requestRoutesCrashdumpClear(App& app)
{
    BMCWEB_ROUTE(
        app,
        "/redfish/v1/Systems/<str>/LogServices/Crashdump/Actions/LogService.ClearLog/")
        // This is incorrect, should be:
        .privileges(redfish::privileges::postLogService)
        .methods(boost::beast::http::verb::post)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& systemName) {
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
                if (!system_utils::validateSystemName(asyncResp, systemName))
                {
                    return;
                }
                crow::connections::systemBus->async_method_call(
                    [asyncResp](const boost::system::error_code& ec,
                                const std::string&) {
                        if (ec)
                        {
                            messages::internalError(asyncResp->res);
                            return;
                        }
                        messages::success(asyncResp->res);
                    },
                    crashdumpObject, crashdumpPath, deleteAllInterface,
                    "DeleteAll");
            });
}

inline void logCrashdumpEntry(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& logID, nlohmann::json& logEntryJson)
{
    auto getStoredLogCallback =
        [asyncResp, logID,
         &logEntryJson](const boost::system::error_code& ec,
                        const dbus::utility::DBusPropertiesMap& params) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("failed to get log ec: {}", ec.message());
                if (ec.value() ==
                    boost::system::linux_error::bad_request_descriptor)
                {
                    messages::resourceNotFound(asyncResp->res, "LogEntry",
                                               logID);
                }
                else
                {
                    messages::internalError(asyncResp->res);
                }
                return;
            }

            std::string timestamp{};
            std::string filename{};
            std::string logfile{};
            parseCrashdumpParameters(params, filename, timestamp, logfile);

            if (filename.empty() || timestamp.empty())
            {
                messages::resourceNotFound(asyncResp->res, "LogEntry", logID);
                return;
            }

            std::string crashdumpURI =
                std::format(
                    "/redfish/v1/Systems/{}/LogServices/Crashdump/Entries/",
                    BMCWEB_REDFISH_SYSTEM_URI_NAME) +
                logID + "/" + filename;
            nlohmann::json::object_t logEntry;
            logEntry["@odata.type"] = json_util::odataType("LogEntry");
            logEntry["@odata.id"] = boost::urls::format(
                "/redfish/v1/Systems/{}/LogServices/Crashdump/Entries/{}",
                BMCWEB_REDFISH_SYSTEM_URI_NAME, logID);
            logEntry["Name"] = "CPU Crashdump";
            logEntry["Id"] = logID;
            logEntry["EntryType"] = log_entry::LogEntryType::Oem;
            logEntry["AdditionalDataURI"] = std::move(crashdumpURI);
            logEntry["DiagnosticDataType"] = "OEM";
            logEntry["OEMDiagnosticDataType"] = "PECICrashdump";
            logEntry["Created"] = timeFormat(timestamp);

            // If logEntryJson references an array of LogEntry resources
            // ('Members' list), then push this as a new entry, otherwise set it
            // directly
            if (logEntryJson.is_array())
            {
                logEntryJson.push_back(logEntry);
                asyncResp->res.jsonValue["Members@odata.count"] =
                    logEntryJson.size();
            }
            else
            {
                logEntryJson.update(logEntry);
            }
        };
    dbus::utility::getAllProperties(
        crashdumpObject, crashdumpPath + std::string("/") + logID,
        intelcrashdumpInterface, std::move(getStoredLogCallback));
}

inline void requestRoutesCrashdumpEntryCollection(App& app)
{
    // Note: Deviated from redfish privilege registry for GET & HEAD
    // method for security reasons.
    /**
     * Functions triggers appropriate requests on DBus
     */
    BMCWEB_ROUTE(app,
                 "/redfish/v1/Systems/<str>/LogServices/Crashdump/Entries/")
        // This is incorrect, should be.
        //.privileges(redfish::privileges::postLogEntryCollection)
        .privileges({{"Login"}})
        .methods(
            boost::beast::http::verb::
                get)([&app](const crow::Request& req,
                            const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                            const std::string& systemName) {
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
            if (!system_utils::validateSystemName(asyncResp, systemName))
            {
                return;
            }

            constexpr std::array<std::string_view, 1> interfaces = {
                intelcrashdumpInterface};
            dbus::utility::getSubTreePaths(
                "/", 0, interfaces,
                [asyncResp](const boost::system::error_code& ec,
                            const std::vector<std::string>& resp) {
                    if (ec)
                    {
                        if (ec.value() !=
                            boost::system::errc::no_such_file_or_directory)
                        {
                            BMCWEB_LOG_DEBUG("failed to get entries ec: {}",
                                             ec.message());
                            messages::internalError(asyncResp->res);
                            return;
                        }
                    }
                    asyncResp->res.jsonValue["@odata.type"] =
                        json_util::odataType("LogEntryCollection");
                    asyncResp->res.jsonValue["@odata.id"] = std::format(
                        "/redfish/v1/Systems/{}/LogServices/Crashdump/Entries",
                        BMCWEB_REDFISH_SYSTEM_URI_NAME);
                    asyncResp->res.jsonValue["Name"] =
                        "Open BMC Crashdump Entries";
                    asyncResp->res.jsonValue["Description"] =
                        "Collection of Crashdump Entries";
                    asyncResp->res.jsonValue["Members"] =
                        nlohmann::json::array();
                    asyncResp->res.jsonValue["Members@odata.count"] = 0;

                    for (const std::string& path : resp)
                    {
                        const sdbusplus::message::object_path objPath(path);
                        // Get the log ID
                        std::string logID = objPath.filename();
                        if (logID.empty())
                        {
                            continue;
                        }
                        // Add the log entry to the array
                        logCrashdumpEntry(asyncResp, logID,
                                          asyncResp->res.jsonValue["Members"]);
                    }
                });
        });
}

inline void requestRoutesCrashdumpEntry(App& app)
{
    // Note: Deviated from redfish privilege registry for GET & HEAD
    // method for security reasons.

    BMCWEB_ROUTE(
        app, "/redfish/v1/Systems/<str>/LogServices/Crashdump/Entries/<str>/")
        // this is incorrect, should be
        // .privileges(redfish::privileges::getLogEntry)
        .privileges(redfish::privileges::getLogEntry)
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& systemName, const std::string& param) {
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
                if (!system_utils::validateSystemName(asyncResp, systemName))
                {
                    return;
                }
                const std::string& logID = param;
                logCrashdumpEntry(asyncResp, logID, asyncResp->res.jsonValue);
            });
}

inline void requestRoutesCrashdumpFile(App& app)
{
    // Note: Deviated from redfish privilege registry for GET & HEAD
    // method for security reasons.
    BMCWEB_ROUTE(
        app,
        "/redfish/v1/Systems/<str>/LogServices/Crashdump/Entries/<str>/<str>/")
        .privileges(redfish::privileges::getLogEntry)
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& systemName, const std::string& logID,
                   const std::string& fileName) {
                // Do not call getRedfishRoute here since the crashdump file is
                // not a Redfish resource.

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
                if (!system_utils::validateSystemName(asyncResp, systemName))
                {
                    return;
                }

                auto getStoredLogCallback =
                    [asyncResp, logID, fileName,
                     url(boost::urls::url(req.url()))](
                        const boost::system::error_code& ec,
                        const std::vector<std::pair<
                            std::string, dbus::utility::DbusVariantType>>&
                            resp) {
                        if (ec)
                        {
                            BMCWEB_LOG_DEBUG("failed to get log ec: {}",
                                             ec.message());
                            messages::internalError(asyncResp->res);
                            return;
                        }

                        std::string dbusFilename{};
                        std::string dbusTimestamp{};
                        std::string dbusFilepath{};

                        parseCrashdumpParameters(resp, dbusFilename,
                                                 dbusTimestamp, dbusFilepath);

                        if (dbusFilename.empty() || dbusTimestamp.empty() ||
                            dbusFilepath.empty())
                        {
                            messages::resourceNotFound(asyncResp->res,
                                                       "LogEntry", logID);
                            return;
                        }

                        // Verify the file name parameter is correct
                        if (fileName != dbusFilename)
                        {
                            messages::resourceNotFound(asyncResp->res,
                                                       "LogEntry", logID);
                            return;
                        }

                        if (asyncResp->res.openFile(dbusFilepath) !=
                            crow::OpenCode::Success)
                        {
                            messages::resourceNotFound(asyncResp->res,
                                                       "LogEntry", logID);
                            return;
                        }

                        // Configure this to be a file download when accessed
                        // from a browser
                        asyncResp->res.addHeader(
                            boost::beast::http::field::content_disposition,
                            "attachment");
                    };
                dbus::utility::getAllProperties(
                    crashdumpObject, crashdumpPath + std::string("/") + logID,
                    intelcrashdumpInterface, std::move(getStoredLogCallback));
            });
}

enum class OEMDiagnosticType
{
    onDemand,
    telemetry,
    invalid,
};

inline OEMDiagnosticType getOEMDiagnosticType(std::string_view oemDiagStr)
{
    if (oemDiagStr == "OnDemand")
    {
        return OEMDiagnosticType::onDemand;
    }
    if (oemDiagStr == "Telemetry")
    {
        return OEMDiagnosticType::telemetry;
    }

    return OEMDiagnosticType::invalid;
}

inline void requestRoutesCrashdumpCollect(App& app)
{
    // Note: Deviated from redfish privilege registry for GET & HEAD
    // method for security reasons.
    BMCWEB_ROUTE(
        app,
        "/redfish/v1/Systems/<str>/LogServices/Crashdump/Actions/LogService.CollectDiagnosticData/")
        .privileges(redfish::privileges::postLogService)
        .methods(boost::beast::http::verb::post)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& systemName) {
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
                if (!system_utils::validateSystemName(asyncResp, systemName))
                {
                    return;
                }

                std::string diagnosticDataType;
                std::string oemDiagnosticDataType;
                if (!redfish::json_util::readJsonAction(               //
                        req, asyncResp->res,                           //
                        "DiagnosticDataType", diagnosticDataType,      //
                        "OEMDiagnosticDataType", oemDiagnosticDataType //
                        ))
                {
                    return;
                }

                bool reqValid = true;
                if (diagnosticDataType != "OEM")
                {
                    BMCWEB_LOG_ERROR(
                        "Only OEM DiagnosticDataType supported for Crashdump");
                    messages::actionParameterValueNotInList(
                        asyncResp->res, diagnosticDataType,
                        "DiagnosticDataType", "CollectDiagnosticData");
                    reqValid = false;
                }

                OEMDiagnosticType oemDiagType =
                    getOEMDiagnosticType(oemDiagnosticDataType);

                std::string iface;
                std::string method;
                std::string taskMatchStr;
                if (oemDiagType == OEMDiagnosticType::onDemand)
                {
                    iface = crashdumpOnDemandInterface;
                    method = "GenerateOnDemandLog";
                    taskMatchStr =
                        "type='signal',"
                        "interface='org.freedesktop.DBus.Properties',"
                        "member='PropertiesChanged',"
                        "arg0namespace='com.intel.crashdump'";
                }
                else if (oemDiagType == OEMDiagnosticType::telemetry)
                {
                    iface = crashdumpTelemetryInterface;
                    method = "GenerateTelemetryLog";
                    taskMatchStr =
                        "type='signal',"
                        "interface='org.freedesktop.DBus.Properties',"
                        "member='PropertiesChanged',"
                        "arg0namespace='com.intel.crashdump'";
                }
                else
                {
                    BMCWEB_LOG_ERROR("Unsupported OEMDiagnosticDataType: {}",
                                     oemDiagnosticDataType);
                    messages::actionParameterValueNotInList(
                        asyncResp->res, oemDiagnosticDataType,
                        "OEMDiagnosticDataType", "CollectDiagnosticData");
                    reqValid = false;
                }

                if (!reqValid)
                {
                    return;
                }

                auto collectCrashdumpCallback =
                    [asyncResp, payload(task::Payload(req)),
                     taskMatchStr](const boost::system::error_code& ec,
                                   const std::string&) mutable {
                        if (ec)
                        {
                            if (ec.value() ==
                                boost::system::errc::operation_not_supported)
                            {
                                messages::resourceInStandby(asyncResp->res);
                            }
                            else if (ec.value() == boost::system::errc::
                                                       device_or_resource_busy)
                            {
                                messages::serviceTemporarilyUnavailable(
                                    asyncResp->res, "60");
                            }
                            else if (ec.value() == EHOSTUNREACH)
                            {
                                messages::actionNotSupported(
                                    asyncResp->res, "CollectDiagnosticData");
                            }
                            else
                            {
                                messages::internalError(asyncResp->res);
                            }
                            return;
                        }
                        std::shared_ptr<task::TaskData> task =
                            task::TaskData::createTask(
                                [](const boost::system::error_code& ec2,
                                   sdbusplus::message_t&,
                                   const std::shared_ptr<task::TaskData>&
                                       taskData) {
                                    if (!ec2)
                                    {
                                        taskData->messages.emplace_back(
                                            messages::taskCompletedOK(
                                                std::to_string(
                                                    taskData->index)));
                                        taskData->state = "Completed";
                                    }
                                    return task::completed;
                                },
                                taskMatchStr);

                        task->startTimer(std::chrono::minutes(30));
                        task->populateResp(asyncResp->res);
                        task->payload.emplace(std::move(payload));
                        task->state = "Running";
                    };

                crow::connections::systemBus->async_method_call(
                    std::move(collectCrashdumpCallback), crashdumpObject,
                    crashdumpPath, iface, method);
            });
}

/**
 * DBusLogServiceActionsClear class supports POST method for ClearLog action.
 */
inline void requestRoutesDBusLogServiceActionsClear(App& app)
{
    /**
     * Function handles POST method request.
     * The Clear Log actions does not require any parameter.The action deletes
     * all entries found in the Entries collection for this Log Service.
     */

    BMCWEB_ROUTE(
        app,
        "/redfish/v1/Systems/<str>/LogServices/EventLog/Actions/LogService.ClearLog/")
        .privileges(redfish::privileges::postLogService)
        .methods(boost::beast::http::verb::post)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& systemName) {
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
                if (!system_utils::validateSystemName(asyncResp, systemName))
                {
                    return;
                }
                dBusEntryDelete(asyncResp, "default", "0");
            });
}

// Rsyslog feature changes
template <typename T>
void setSyslogCertificatePatch(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& propertyName, const std::optional<T>& propertyValue)
{
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, syslogServicePath, syslogObjectPath,
        syslogInterface, propertyName, *propertyValue,
        [asyncResp](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-Bus responses error: {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }
            messages::success(asyncResp->res);
        });
}

void handleSyslogCertificatePatch(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& systemName)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (!system_utils::validateSystemName(asyncResp, systemName))
    {
        return;
    }
    std::optional<uint16_t> filesize;
    std::optional<uint16_t> remoteserverport;
    std::optional<bool> rotatecount;
    std::optional<std::string> remotelogserver;
    std::optional<std::string> porttype;

    std::optional<nlohmann::json> oem;

    if (!json_util::readJsonPatch(req, asyncResp->res, "Oem", oem))
    {
        BMCWEB_LOG_DEBUG("Syslog Service doPatch: Invalid request body");
        return;
    }

    if (oem)
    {
        std::optional<nlohmann::json> ami;
        if (!json_util::readJson(*oem, asyncResp->res, "Ami", ami))
        {
            return;
        }
        if (ami)
        {
            std::optional<nlohmann::json> syslog;
            if (!json_util::readJson(*ami, asyncResp->res, "SysLog", syslog))
            {
                return;
            }

            if (syslog)
            {
                std::optional<nlohmann::json> configuration;
                if (!json_util::readJson(*syslog, asyncResp->res,
                                         "Configuration", configuration))
                {
                    return;
                }
                if (configuration)
                {
                    std::size_t configuration_size =
                        configuration.value().size();
                    if (configuration_size == 0)
                    {
                        messages::propertyNotWritable(asyncResp->res,
                                                      "Configuration");
                        return;
                    }

                    if (!json_util::readJson(                     //
                            *configuration, asyncResp->res,       //
                            "RemoteServerPort", remoteserverport, //
                            "RemoteLogServer", remotelogserver,   //
                            "PortType", porttype, "FileSize", filesize,
                            "RotateCount", rotatecount))
                    {
                        return;
                    }
                    if (remoteserverport)
                    {
                        if (remoteserverport >= 0 && remoteserverport <= 65535)
                        {
                            setSyslogCertificatePatch(asyncResp, "Port",
                                                      remoteserverport);
                        }
                        else
                        {
                            messages::propertyValueOutOfRange(
                                asyncResp->res, *remoteserverport, "Port");
                            return;
                        }
                    }
                    if (remotelogserver)
                    {
                        const std::string& ipAddress = *remotelogserver;

                        if (!ip_util::isValidIPv4Addr(
                                ipAddress,
                                ip_util::Type::IP4_ADDRESS)) // checking the
                                                             // IPv4 Address
                        {
                            messages::invalidip(asyncResp->res, "Address",
                                                ipAddress);
                        }
                        setSyslogCertificatePatch(asyncResp, "Address",
                                                  remotelogserver);
                    }

                    if (porttype)
                    {
                        std::optional<std::string> portvalue;
                        if (porttype == "TCP" || porttype == "Tcp")
                        {
                            portvalue =
                                "xyz.openbmc_project.Network.Client.TransportProtocol.TCP";
                        }
                        else if (porttype == "UDP" || porttype == "Udp")
                        {
                            portvalue =
                                "xyz.openbmc_project.Network.Client.TransportProtocol.UDP";
                        }

                        if (porttype == "TCP" || porttype == "Tcp" ||
                            porttype == "UDP" || porttype == "Udp")
                        {
                            setSyslogCertificatePatch(
                                asyncResp, "TransportProtocol", portvalue);
                        }
                        else
                        {
                            messages::actionParameterValueNotInList(
                                asyncResp->res, *portvalue, "TCP", "UDP");
                            return;
                        }
                    }
                    if (rotatecount)
                    {
                        setSyslogCertificatePatch(asyncResp, "RotateCount",
                                                  rotatecount);
                    }
                    if (filesize)
                    {
                        if (filesize >= 0 && filesize <= 65535)
                        {
                            setSyslogCertificatePatch(asyncResp, "FileSize",
                                                      filesize);
                        }
                        else
                        {
                            messages::propertyValueOutOfRange(
                                asyncResp->res, *filesize, "FileSize");
                            return;
                        }
                    }
                }
            }
        }
    }
}

void getSyslogCertificates(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    bool isSyslogCACERT = true;
    bool isSyslogServerKey = true;
    bool isSyslogServerCRT = true;

    /* Syslog Certificate */

    BMCWEB_LOG_DEBUG("Syslog CACERT Context file= {}",
                     syslogCACERTFile.c_str());
    BMCWEB_LOG_DEBUG("Syslog CRT Context file= {}",
                     syslogServerCRTFile.c_str());
    BMCWEB_LOG_DEBUG("Syslog Key Context file=  {}",
                     syslogServerKeyFile.c_str());

    isSyslogCACERT = ensureOpensslKeyPresentAndValid(syslogCACERTFile);
    asyncResp->res
        .jsonValue["Oem"]["Ami"]["SysLog"]["Configuration"]["IsCACERTExist"] =
        isSyslogCACERT;
    isSyslogServerCRT = ensureOpensslKeyPresentAndValid(syslogServerCRTFile);

    asyncResp->res.jsonValue["Oem"]["Ami"]["SysLog"]["Configuration"]
                            ["IsServerCRTExist"] = isSyslogServerCRT;
    isSyslogServerKey = ensureOpensslKeyPresentAndValid(syslogServerKeyFile);

    asyncResp->res.jsonValue["Oem"]["Ami"]["SysLog"]["Configuration"]
                            ["IsServerKeyExist"] = isSyslogServerKey;

    if (isSyslogCACERT)
    {
        std::string syslogCACERTModifiedDate =
            modifiedDateTime(syslogCACERTFile);
        asyncResp->res.jsonValue["Oem"]["Ami"]["SysLog"]["Configuration"]
                                ["SyslogCACERTModifiedDate"] =
            syslogCACERTModifiedDate;
    }
    if (isSyslogServerCRT)
    {
        std::string syslogCACERTModifiedDate =
            modifiedDateTime(syslogServerCRTFile);
        asyncResp->res.jsonValue["Oem"]["Ami"]["SysLog"]["Configuration"]
                                ["SyslogserverCRTModifiedDate"] =
            syslogCACERTModifiedDate;
    }
    if (isSyslogServerKey)
    {
        std::string syslogCACERTModifiedDate =
            modifiedDateTime(syslogServerKeyFile);
        asyncResp->res.jsonValue["Oem"]["Ami"]["SysLog"]["Configuration"]
                                ["SyslogServerKeyModifiedDate"] =
            syslogCACERTModifiedDate;
    }
}

void handleSyslogCertificateGet(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& systemName)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (!system_utils::validateSystemName(asyncResp, systemName))
    {
        return;
    }
    dbus::utility::getAllProperties(
        syslogServicePath, syslogObjectPath, syslogInterface,
        [asyncResp](const boost::system::error_code& ec,
                    const dbus::utility::DBusPropertiesMap& propertiesList) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("DBus response error for Version: {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }
            const std::string* remoteLogServer = nullptr;
            const uint16_t* remoteServerPort = nullptr;
            const std::string* transportProtocol = nullptr;
            const bool* rotateCount = nullptr;
            const uint16_t* fileSize = nullptr;

            const bool success = sdbusplus::unpackPropertiesNoThrow(
                dbus_utils::UnpackErrorPrinter(), propertiesList, "Address",
                remoteLogServer, "Port", remoteServerPort, "RotateCount",
                rotateCount, "FileSize", fileSize, "TransportProtocol",
                transportProtocol);

            if (!success)
            {
                messages::internalError(asyncResp->res);
                return;
            }
            asyncResp->res.jsonValue["@odata.id"] =
                std::format("/redfish/v1/Systems/{}/LogServices/Syslog",
                            BMCWEB_REDFISH_SYSTEM_URI_NAME);
            asyncResp->res.jsonValue["@odata.type"] =
                json_util::odataType("LogService");
            asyncResp->res.jsonValue["Oem"]["Ami"]["@odata.type"] =
                json_util::odataType("AmiSyslog");
            asyncResp->res.jsonValue["Actions"]["Oem"]["Ami"]
                                    ["#Rsyslog.RemoteServerCertificateUpload"]
                                    ["target"] = std::format(
                "/redfish/v1/Systems/{}/LogServices/Syslog/Actions/Oem/Ami/Rsyslog.RemoteServerCertificateUpload",
                BMCWEB_REDFISH_SYSTEM_URI_NAME);
            asyncResp->res.jsonValue["Name"] = "OpenBMC Oem Syslog Service";
            asyncResp->res.jsonValue["Description"] = "Oem Syslog Service";
            asyncResp->res.jsonValue["Id"] = "Syslog";
            if (remoteLogServer != nullptr)
            {
                asyncResp->res.jsonValue["Oem"]["Ami"]["SysLog"]
                                        ["Configuration"]["RemoteLogServer"] =
                    *remoteLogServer;
            }
            if (remoteServerPort != nullptr)
            {
                asyncResp->res.jsonValue["Oem"]["Ami"]["SysLog"]
                                        ["Configuration"]["RemoteServerPort"] =
                    *remoteServerPort;
            }
            if (transportProtocol != nullptr)
            {
                std::string porttype = " ";
                if (*transportProtocol ==
                    "xyz.openbmc_project.Network.Client.TransportProtocol.TCP")
                {
                    porttype = "TCP";
                }
                else if (
                    *transportProtocol ==
                    "xyz.openbmc_project.Network.Client.TransportProtocol.UDP")
                {
                    porttype = "UDP";
                }
                else
                {
                    messages::internalError(asyncResp->res);
                    return;
                }
                asyncResp->res.jsonValue["Oem"]["Ami"]["SysLog"]
                                        ["Configuration"]["PortType"] =
                    porttype;
            }
            if (rotateCount != nullptr)
            {
                asyncResp->res.jsonValue["Oem"]["Ami"]["SysLog"]
                                        ["Configuration"]["RotateCount"] =
                    *rotateCount;
            }
            if (fileSize != nullptr)
            {
                asyncResp->res.jsonValue["Oem"]["Ami"]["SysLog"]
                                        ["Configuration"]["FileSize"] =
                    *fileSize;
            }
        });
    getSyslogCertificates(asyncResp);
}

void uploadSyslogFile(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                      std::string_view body, const std::string& fileName)
{
    fs::create_directories(syslogCertsPath);

    if (fileName == syslogCacertFileName)
    {
        std::filesystem::path path = syslogCACERTFilePath;
        std::ofstream out(path, std::ofstream::out | std::ofstream::binary |
                                    std::ofstream::trunc);
        out << body;
        if (out.bad())
        {
            messages::internalError(asyncResp->res);
            return;
        }
        else
        {
            messages::success(asyncResp->res);
        }
        out.close();
    }
    else if (fileName == syslogServerCRTFileName)
    {
        std::filesystem::path path = syslogServerCRTFilePath;
        std::ofstream out(path, std::ofstream::out | std::ofstream::binary |
                                    std::ofstream::trunc);
        out << body;
        if (out.bad())
        {
            messages::internalError(asyncResp->res);
            return;
        }
        else
        {
            messages::success(asyncResp->res);
        }
        out.close();
    }
    else if (fileName == syslogServerKeyFileName)
    {
        std::filesystem::path path = syslogServerKeyFilePath;
        std::ofstream out(path, std::ofstream::out | std::ofstream::binary |
                                    std::ofstream::trunc);
        out << body;
        if (out.bad())
        {
            messages::internalError(asyncResp->res);
            return;
        }
        else
        {
            messages::success(asyncResp->res);
        }
        out.close();
    }
}

void readSyslogContext(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                       const MultipartParser& parser,
                       const std::string& configurationType)
{
    const std::string* uploadData = nullptr;
    for (const FormPart& formpart : parser.mime_fields)
    {
        boost::beast::http::fields::const_iterator it =
            formpart.fields.find("Content-Disposition");
        if (it == formpart.fields.end())
        {
            BMCWEB_LOG_ERROR("Couldn't find Content-Disposition");
            return;
        }
        // The construction parameters of param_list must start with `;`
        size_t index = it->value().find(';');
        if (index == std::string::npos)
        {
            continue;
        }

        for (const auto& param :
             boost::beast::http::param_list{it->value().substr(index)})
        {
            if (param.second.empty())
            {
                continue;
            }
            else
            {
                syslogFileName = param.second;
                BMCWEB_LOG_DEBUG("Read Syslog Original files Name {}",
                                 syslogFileName);
                if (syslogFileName.substr(
                        syslogFileName.find_last_of(".") + 1) == "crt")
                {
                    uploadData = &(formpart.content);
                    syslogFileName = configurationType + "_server.crt";
                }
                else if (syslogFileName.substr(
                             syslogFileName.find_last_of(".") + 1) == "pem")
                {
                    uploadData = &(formpart.content);
                    syslogFileName = configurationType + "_cacert.pem";
                }
                else if (syslogFileName.substr(
                             syslogFileName.find_last_of(".") + 1) == "key")
                {
                    uploadData = &(formpart.content);
                    syslogFileName = configurationType + "_server.key";
                }
                else
                {
                    messages::propertyValueTypeError(
                        asyncResp->res, syslogFileName, "InValid Format");
                }
                BMCWEB_LOG_DEBUG("Read Syslog Renamed files Name {}",
                                 syslogFileName);
            }
        }
    }

    if (uploadData == nullptr)
    {
        messages::propertyMissing(asyncResp->res,
                                  "Syslog Certificates Missing");
        return;
    }
    uploadSyslogFile(asyncResp, *uploadData, syslogFileName);
}

void handleSyslogCertificateUploadAction(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& systemName)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (!system_utils::validateSystemName(asyncResp, systemName))
    {
        return;
    }
    std::string_view contentType = req.getHeaderValue("Content-Type");
    BMCWEB_LOG_DEBUG("doPost: contentType= ", contentType);
    if (contentType.starts_with("multipart/form-data"))
    {
        MultipartParser parser;
        ParserError ec = parser.parse(req);
        if (ec != ParserError::PARSER_SUCCESS)
        {
            // handle error
            BMCWEB_LOG_ERROR("Syslog Certificate parse failed, ec :",
                             static_cast<int>(ec));
            messages::internalError(asyncResp->res);
            return;
        }
        dbus::utility::getProperty<std::string>(
            syslogServicePath, syslogObjectPath, syslogInterface,
            "TransportProtocol",
            [asyncResp, parser](const boost::system::error_code& ec2,
                                const std::string& transportProtocol) {
                std::string porttype;
                if (ec2)
                {
                    BMCWEB_LOG_ERROR("DBus response error for Version: {}",
                                     ec2);
                    messages::internalError(asyncResp->res);
                    return;
                }
                if (transportProtocol ==
                    "xyz.openbmc_project.Network.Client.TransportProtocol.TCP")
                {
                    porttype = "TCP";
                }
                else if (
                    transportProtocol ==
                    "xyz.openbmc_project.Network.Client.TransportProtocol.UDP")
                {
                    porttype = "UDP";
                }
                else
                {
                    messages::internalError(asyncResp->res);
                    return;
                }
                if (porttype == "TCP")
                {
                    readSyslogContext(asyncResp, parser, "rsyslog");
                }
                else
                {
                    messages::propertyValueTypeError(asyncResp->res, porttype,
                                                     "InValid Port Type");
                    return;
                }
            });
    }
    else
    {
        BMCWEB_LOG_ERROR("InValid Content Type");
        return;
    }
}

inline void requestRoutesSystemRsyslog(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/LogServices/Syslog")
        .privileges(redfish::privileges::getLogService)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleSyslogCertificateGet, std::ref(app)));

    BMCWEB_ROUTE(
        app,
        "/redfish/v1/Systems/<str>/LogServices/Syslog/Actions/Oem/Ami/Rsyslog.RemoteServerCertificateUpload")
        .privileges(redfish::privileges::postLogService)
        .methods(boost::beast::http::verb::post)(std::bind_front(
            handleSyslogCertificateUploadAction, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/LogServices/Syslog")
        .privileges(redfish::privileges::patchLogEntry)
        .methods(boost::beast::http::verb::patch)(
            std::bind_front(handleSyslogCertificatePatch, std::ref(app)));
}
} // namespace redfish
