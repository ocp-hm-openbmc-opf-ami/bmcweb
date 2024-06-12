/*
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
*/
#pragma once
#include "dbus_utility.hpp"
#include "error_messages.hpp"
#include "event_service_store.hpp"
#include "http_client.hpp"
#include "kafka_manager.hpp"
#include "metric_report.hpp"
#include "ossl_random.hpp"
#include "persistent_data.hpp"
#include "registries.hpp"
#include "registries_selector.hpp"
#include "str_utility.hpp"
#include "utility.hpp"
#include "utils/json_utils.hpp"
#include "utils/time_utils.hpp"

#include <sys/inotify.h>

#include <boost/asio/io_context.hpp>
#include <boost/container/flat_map.hpp>
#include <boost/url/format.hpp>
#include <boost/url/url_view_base.hpp>
#include <sdbusplus/bus/match.hpp>
#include <snmp.hpp>
#include <snmp_notification.hpp>

#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <memory>
#include <ranges>
#include <span>

namespace redfish
{

using ReadingsObjType =
    std::vector<std::tuple<std::string, std::string, double, int32_t>>;

static constexpr const char* eventFormatType = "Event";
static constexpr const char* metricReportFormatType = "MetricReport";

static constexpr const char* subscriptionTypeSSE = "SSE";
static constexpr const char* eventServiceFile =
    "/var/lib/bmcweb/eventservice_config.json";

static std::function<void(const std::string&)> retryExhaustCallback =
    [](const std::string&) {};

static constexpr const uint8_t maxNoOfSubscriptions = 20;
static constexpr const uint8_t maxNoOfSSESubscriptions = 10;

using EventLogObjectsType =
    std::tuple<std::string, std::string, std::string, std::string, std::string,
               std::vector<std::string>>;

using Value =
    std::variant<bool, uint8_t, int16_t, uint16_t, int32_t, uint32_t, int64_t,
                 uint64_t, double, std::string, std::vector<uint8_t>,
                 std::vector<uint16_t>, std::vector<uint32_t>,
                 std::vector<std::string>>;

using ObjectType =
    boost::container::flat_map<std::string,
                               boost::container::flat_map<std::string, Value>>;

namespace registries
{
static const Message*
    getMsgFromRegistry(const std::string& messageKey,
                       const std::span<const MessageEntry>& registry)
{
    std::span<const MessageEntry>::iterator messageIt = std::ranges::find_if(
        registry, [&messageKey](const MessageEntry& messageEntry) {
        return messageKey == messageEntry.first;
    });
    if (messageIt != registry.end())
    {
        return &messageIt->second;
    }

    return nullptr;
}

static const Message* formatMessage(std::string messageID)
{
    // Find the right registry and check it for the MessageKey
    const std::string&   registryName="OpenBMC";
    std::string  messageKey=messageID;
    messageKey.erase(std::remove(messageKey.begin(), messageKey.end(), ' '), messageKey.end());
    return getMsgFromRegistry(messageKey, getRegistryFromPrefix(registryName));
}
} // namespace registries

namespace event_log
{
inline bool getUniqueEntryID(const std::string& logEntry, std::string& entryID)
{
    static time_t prevTs = 0;
    static int index = 0;

    // Get the entry timestamp
    std::time_t curTs = 0;
    std::tm timeStruct = {};
    std::istringstream entryStream(logEntry);
    if (entryStream >> std::get_time(&timeStruct, "%Y-%m-%dT%H:%M:%S"))
    {
        curTs = std::mktime(&timeStruct);
        if (curTs == -1)
        {
            return false;
        }
    }
    // If the timestamp isn't unique, increment the index
    index = (curTs == prevTs) ? index + 1 : 0;

    // Save the timestamp
    prevTs = curTs;

    entryID = std::to_string(curTs);
    if (index > 0)
    {
        entryID += "_" + std::to_string(index);
    }
    return true;
}

inline int getEventLogParams(const std::string& logEntry,
                             std::string& messageID,
                             std::vector<std::string>& messageArgs)
{
    size_t colonPos = logEntry.find(':');
    if (colonPos == std::string::npos)
    {
       messageID=logEntry;
    }
    else
    {
    messageID = logEntry.substr(0, colonPos);
    messageArgs.push_back(logEntry.substr(colonPos + 1));
    }
    return 0;
}

inline void getRegistryAndMessageKey(const std::string& messageID,
                                     std::string& registryName,
                                     std::string& messageKey)
{
   registryName="OpenBMC";
   messageKey=messageID;
   messageKey.erase(std::remove(messageKey.begin(), messageKey.end(), ' '), messageKey.end());
}

inline int formatEventLogEntry(const std::string& logEntryID,
                               const std::string& messageID,
                               const std::span<std::string_view> messageArgs,
                               std::string timestamp,
                               const std::string& customText,
                               nlohmann::json& logEntryJson)
{
    // Get the Message from the MessageRegistry
    const registries::Message* message = registries::formatMessage(messageID);

    if (message == nullptr)
    {
        return -1;
    }

    std::string msg = redfish::registries::fillMessageArgs(messageArgs,
                                                           message->message);
    if (msg.empty())
    {
        return -1;
    }

    // Get the Created time from the timestamp. The log timestamp is in
    // RFC3339 format which matches the Redfish format except for the
    // fractional seconds between the '.' and the '+', so just remove them.
    std::size_t dot = timestamp.find_first_of('.');
    std::size_t plus = timestamp.find_first_of('+', dot);
    if (dot != std::string::npos && plus != std::string::npos)
    {
        timestamp.erase(dot, plus - dot);
    }

    // Fill in the log entry with the gathered data
    logEntryJson["EventId"] = logEntryID;
    logEntryJson["EventType"] = "Event";
    logEntryJson["Severity"] = message->messageSeverity;
    logEntryJson["Message"] = std::move(msg);
    logEntryJson["MessageId"] = messageID;
    logEntryJson["MessageArgs"] = messageArgs;
    logEntryJson["EventTimestamp"] = std::move(timestamp);
    logEntryJson["Context"] = customText;
    return 0;
}

} // namespace event_log

inline bool isFilterQuerySpecialChar(char c)
{
    switch (c)
    {
        case '(':
        case ')':
        case '\'':
            return true;
        default:
            return false;
    }
}

inline bool
    readSSEQueryParams(std::string sseFilter, std::string& formatType,
                       std::vector<std::string>& messageIds,
                       std::vector<std::string>& registryPrefixes,
                       std::vector<std::string>& metricReportDefinitions)
{
    auto remove = std::ranges::remove_if(sseFilter, isFilterQuerySpecialChar);
    sseFilter.erase(std::ranges::begin(remove), sseFilter.end());

    std::vector<std::string> result;

    // NOLINTNEXTLINE
    bmcweb::split(result, sseFilter, ' ');

    BMCWEB_LOG_DEBUG("No of tokens in SEE query: {}", result.size());

    constexpr uint8_t divisor = 4;
    constexpr uint8_t minTokenSize = 3;
    if (result.size() % divisor != minTokenSize)
    {
        BMCWEB_LOG_ERROR("Invalid SSE filter specified.");
        return false;
    }

    for (std::size_t i = 0; i < result.size(); i += divisor)
    {
        const std::string& key = result[i];
        const std::string& op = result[i + 1];
        const std::string& value = result[i + 2];

        if ((i + minTokenSize) < result.size())
        {
            const std::string& separator = result[i + minTokenSize];
            // SSE supports only "or" and "and" in query params.
            if ((separator != "or") && (separator != "and"))
            {
                BMCWEB_LOG_ERROR(
                    "Invalid group operator in SSE query parameters");
                return false;
            }
        }

        // SSE supports only "eq" as per spec.
        if (op != "eq")
        {
            BMCWEB_LOG_ERROR(
                "Invalid assignment operator in SSE query parameters");
            return false;
        }

        BMCWEB_LOG_DEBUG("{} : {}", key, value);
        if (key == "EventFormatType")
        {
            formatType = value;
        }
        else if (key == "MessageId")
        {
            messageIds.push_back(value);
        }
        else if (key == "RegistryPrefix")
        {
            registryPrefixes.push_back(value);
        }
        else if (key == "MetricReportDefinition")
        {
            metricReportDefinitions.push_back(value);
        }
        else
        {
            BMCWEB_LOG_ERROR("Invalid property({})in SSE filter query.", key);
            return false;
        }
    }
    return true;
}

inline boost::system::error_code subRetryHandler(unsigned int respCode)
{
    // Allow all response codes because we want to surface Listener
    // issue to the client
    BMCWEB_LOG_DEBUG("Received {} response from Listener", respCode);
    return boost::system::errc::make_error_code(boost::system::errc::success);
}

constexpr unsigned int subReadBodyLimit = 4 * 1024 * 1024; // 4MB
inline crow::ConnectionPolicy getSubPolicy()
{
    return {.maxRetryAttempts = 1,
            .requestByteLimit = subReadBodyLimit,
            .maxConnections = 20,
            .retryPolicyAction = "TerminateAfterRetries",
            .retryIntervalSecs = std::chrono::seconds(30),
            .invalidResp = subRetryHandler};
}

class Subscription : public persistent_data::UserSubscription
{
  public:
    Subscription(const Subscription&) = delete;
    Subscription& operator=(const Subscription&) = delete;
    Subscription(Subscription&&) = delete;
    Subscription& operator=(Subscription&&) = delete;

    Subscription(const boost::urls::url_view_base& url,
                 boost::asio::io_context& ioc) :
        policy(std::make_shared<crow::ConnectionPolicy>(getSubPolicy()))
    {
        destinationUrl = url;
        client.emplace(ioc, policy);
        // Subscription constructor
        policy->invalidResp = retryRespHandler;
    }

    explicit Subscription(
        std::shared_ptr<crow::sse_socket::Connection>& connIn) :
        policy(std::make_shared<crow::ConnectionPolicy>(getSubPolicy())),
        sseConn(connIn)
    {
        // Subscription constructor
        policy->invalidResp = retryRespHandler;
    }

    ~Subscription() = default;

    void getSseConnection(std::shared_ptr<crow::sse_socket::Connection>& connPtr)
    {
	connPtr = sseConn;
	return;
    }

    bool sendEvent(std::string&& msg)
    {
        if (subscriptionType == "SNMPTrap")
        {
            return true; // Don't need send SNMPTrap event.
        }
        persistent_data::EventServiceConfig eventServiceConfig =
            persistent_data::EventServiceStore::getInstance()
                .getEventServiceConfig();
        if (!eventServiceConfig.enabled)
        {
            return false;
        }

        // For Suspended subscriptions, State is set to "Disabled". So
        // stop sending events to that subscription.
        if (state == "Disabled")
        {
            BMCWEB_LOG_DEBUG(
                "Subscription is suspended, so not sending events.");
            return false;
        }

        // A connection pool will be created if one does not already exist
        if (client)
        {
            std::function<void(crow::Response&)> sendEventCallback =
                [subId(id), retryPolicy(retryPolicy),
                 retryExhaustCallback(retryExhaustCallback)](
                    crow::Response& res) {
                if (res.result() == boost::beast::http::status::bad_gateway)
                {
                    // Response is going to have bad_gateway result if the event
                    // listener was not able to receive the event even after
                    // multiple retries. This response is received only when
                    // retry policy is Suspend after retires or Terminate after
                    // reties.
                    retryExhaustCallback(subId);
                }
            };

            client->sendDataWithCallback(
                std::move(msg), destinationUrl, verifyCertificate, httpHeaders,
                boost::beast::http::verb::post, sendEventCallback);
            return true;
        }

        if (sseConn != nullptr)
        {
            sseConn->sendEvent(std::to_string(eventSeqNum), msg);
        }
        return true;
    }

    bool sendSNMPTrap(uint32_t eventId, std::string timestamp, std::string sev,
                      std::string& msg)
    {
        persistent_data::EventServiceConfig eventServiceConfig =
            persistent_data::EventServiceStore::getInstance()
                .getEventServiceConfig();
        if (!eventServiceConfig.enabled)
        {
            return false;
        }
        phosphor::network::snmp::sendTrap<
            phosphor::network::snmp::OBMCErrorNotification>(
            static_cast<uint32_t>(eventId), timestamp, sev, std::move(msg));
        eventSeqNum++;
        return true;
    }

    void filterAndsendSNMPTrap(
        const std::vector<EventLogObjectsType>& eventRecords)
    {
        for (const EventLogObjectsType& logEntry : eventRecords)
        {
            const std::string& idStr = std::get<0>(logEntry);
            const std::string& messageID = std::get<2>(logEntry);
            const std::string& registryName = std::get<3>(logEntry);
            const std::string& messageKey = std::get<4>(logEntry);
            const std::vector<std::string>& messageArgs = std::get<5>(logEntry);

            if (!registryPrefixes.empty())
            {
                auto obj = std::find(registryPrefixes.begin(),
                                     registryPrefixes.end(), registryName);
                if (obj == registryPrefixes.end())
                {
                    continue;
                }
            }
            if (!registryMsgIds.empty())
            {
                auto obj = std::find(registryMsgIds.begin(),
                                     registryMsgIds.end(), messageKey);
                if (obj == registryMsgIds.end())
                {
                    continue;
                }
            }
            std::vector<std::string_view> messageArgsView(messageArgs.begin(),
                                                          messageArgs.end());

            const registries::Message* message =
                registries::formatMessage(messageID);
            if (message == nullptr)
            {
                continue;
            }

            std::string msg = redfish::registries::fillMessageArgs(
                messageArgsView, message->message);
            if (msg.empty())
            {
                continue;
            }
            std::string messageSeverity{message->messageSeverity};
            this->sendSNMPTrap(static_cast<uint32_t>(eventSeqNum), idStr,
                               messageSeverity == "Ok"         ? "Ok"
                               : messageSeverity == "Warning"  ? "Warning"
                               : messageSeverity == "Critical" ? "Critical"
                                                               : "Ok",
                               msg);
        }
    }

    bool sendTestEventLog()
    {
        nlohmann::json logEntryArray;
        logEntryArray.push_back({});
        nlohmann::json& logEntryJson = logEntryArray.back();

        logEntryJson["EventId"] = "TestID";
        logEntryJson["EventType"] = "Event";
        logEntryJson["Severity"] = "OK";
        logEntryJson["Message"] = "Generated test event";
        logEntryJson["MessageId"] = "OpenBMC.0.2.TestEventLog";
        logEntryJson["MessageArgs"] = nlohmann::json::array();
        logEntryJson["EventTimestamp"] =
            redfish::time_utils::getDateTimeOffsetNow().first;
        logEntryJson["Context"] = customText;

        nlohmann::json msg;
        msg["@odata.type"] = "#Event.v1_4_0.Event";
        msg["Id"] = std::to_string(eventSeqNum);
        msg["Name"] = "Event Log";
        msg["Events"] = logEntryArray;

        std::string strMsg = msg.dump(2, ' ', true,
                                      nlohmann::json::error_handler_t::replace);
        return sendEvent(std::move(strMsg));
    }

    bool sendTestSNMPTrap()
    {
        std::string timestamp =
            redfish::time_utils::getDateTimeOffsetNow().first;
        std::tm timeStruct = {};
        std::istringstream entryStream(timestamp);
        if (!(entryStream >> std::get_time(&timeStruct, "%Y-%m-%dT%H:%M:%S")))
        {
            return false;
        }
        std::stringstream ss;
        ss << std::put_time(&timeStruct, "%Y-%m-%d %H:%M:%S");
        std::string timeString = ss.str();
        std::string msg{"Generated test event"};
        this->sendSNMPTrap(static_cast<uint32_t>(eventSeqNum), timeString, "Ok",
                           msg);
        return true;
    }

    void filterAndSendEventLogs(
        const std::vector<EventLogObjectsType>& eventRecords)
    {
        nlohmann::json logEntryArray;
        for (const EventLogObjectsType& logEntry : eventRecords)
        {
            const std::string& idStr = std::get<0>(logEntry);
            const std::string& timestamp = std::get<1>(logEntry);
            const std::string& messageID = std::get<2>(logEntry);
            const std::string& registryName = std::get<3>(logEntry);
            const std::string& messageKey = std::get<4>(logEntry);
            const std::vector<std::string>& messageArgs = std::get<5>(logEntry);

            // If registryPrefixes list is empty, don't filter events
            // send everything.
            if (!registryPrefixes.empty())
            {
                auto obj = std::ranges::find(registryPrefixes, registryName);
                if (obj == registryPrefixes.end())
                {
                    continue;
                }
            }

            // If registryMsgIds list is empty, don't filter events
            // send everything.
            if (!registryMsgIds.empty())
            {
                auto obj = std::ranges::find(registryMsgIds, messageKey);
                if (obj == registryMsgIds.end())
                {
                    continue;
                }
            }

            std::vector<std::string_view> messageArgsView(messageArgs.begin(),
                                                          messageArgs.end());

            logEntryArray.push_back({});
            nlohmann::json& bmcLogEntry = logEntryArray.back();
            if (event_log::formatEventLogEntry(idStr, messageID,
                                               messageArgsView, timestamp,
                                               customText, bmcLogEntry) != 0)
            {
                BMCWEB_LOG_DEBUG("Read eventLog entry failed");
                continue;
            }
        }

        if (logEntryArray.empty())
        {
            BMCWEB_LOG_DEBUG("No log entries available to be transferred.");
            return;
        }

        nlohmann::json msg;
        msg["@odata.type"] = "#Event.v1_4_0.Event";
        msg["Id"] = std::to_string(eventSeqNum);
        msg["Name"] = "Event Log";
        msg["Events"] = logEntryArray;
        std::string strMsg = msg.dump(2, ' ', true,
                                      nlohmann::json::error_handler_t::replace);
        sendEvent(std::move(strMsg));
        eventSeqNum++;
    }

    void filterAndSendReports(const std::string& reportId,
                              const telemetry::TimestampReadings& var)
    {
        boost::urls::url mrdUri = boost::urls::format(
            "/redfish/v1/TelemetryService/MetricReportDefinitions/{}",
            reportId);

        // Empty list means no filter. Send everything.
        if (!metricReportDefinitions.empty())
        {
            if (std::ranges::find(metricReportDefinitions, mrdUri.buffer()) ==
                metricReportDefinitions.end())
            {
                return;
            }
        }

        nlohmann::json msg;
        if (!telemetry::fillReport(msg, reportId, var))
        {
            BMCWEB_LOG_ERROR("Failed to fill the MetricReport for DBus "
                             "Report with id {}",
                             reportId);
            return;
        }

        // Context is set by user during Event subscription and it must be
        // set for MetricReport response.
        if (!customText.empty())
        {
            msg["Context"] = customText;
        }

        std::string strMsg = msg.dump(2, ' ', true,
                                      nlohmann::json::error_handler_t::replace);
        sendEvent(std::move(strMsg));
    }

    void updateRetryConfig(uint32_t retryAttempts,
                           uint32_t retryTimeoutInterval)
    {
        if (policy == nullptr)
        {
            BMCWEB_LOG_DEBUG("Retry policy was nullptr, ignoring set");
            return;
        }
        policy->maxRetryAttempts = retryAttempts;
        policy->retryIntervalSecs = std::chrono::seconds(retryTimeoutInterval);
    }

    uint64_t getEventSeqNum() const
    {
        return eventSeqNum;
    }

    void setSubscriptionId(const std::string& id2)
    {
        BMCWEB_LOG_DEBUG("Subscription ID: {}", id2);
        subId = id2;
    }

    std::string getSubscriptionId()
    {
        return subId;
    }

    std::optional<std::string> getSubscriptionId(
        const std::shared_ptr<crow::sse_socket::Connection>& connPtr)
    {
        if (sseConn != nullptr && connPtr == sseConn)
        {
            BMCWEB_LOG_DEBUG("{} conn matched, subId: {}", __FUNCTION__, subId);
            return subId;
        }

        return std::nullopt;
    }

  private:
    std::string subId;
    uint64_t eventSeqNum = 1;
    boost::urls::url host;
    std::shared_ptr<crow::ConnectionPolicy> policy;
    std::shared_ptr<crow::sse_socket::Connection> sseConn = nullptr;
    std::optional<crow::HttpClient> client;
    std::string path;
    std::string uriProto;

    // As per DMTF Redfish EventDestination schema, if 'VerifyCertificate'
    // is not supported by service, It shall be assumed 'false'. So setting
    // this value to false default till EventService add support it.
    bool verifyCertificate = false;

    // Check used to indicate what response codes are valid as part of our retry
    // policy.  2XX is considered acceptable
    static boost::system::error_code retryRespHandler(unsigned int respCode)
    {
        BMCWEB_LOG_DEBUG(
            "Checking response code validity for SubscriptionEvent");
        if ((respCode < 200) || (respCode >= 300))
        {
            return boost::system::errc::make_error_code(
                boost::system::errc::result_out_of_range);
        }

        // Return 0 if the response code is valid
        return boost::system::errc::make_error_code(
            boost::system::errc::success);
    }
};

class EventServiceManager
{
  private:
    bool serviceEnabled = false;
    uint32_t retryAttempts = 0;
    uint32_t retryTimeoutInterval = 0;

   
    size_t noOfEventLogSubscribers{0};
    size_t noOfMetricReportSubscribers{0};
    std::shared_ptr<sdbusplus::bus::match_t> matchTelemetryMonitor;
    std::shared_ptr<sdbusplus::bus::match_t> matchEventLog;
    boost::container::flat_map<std::string, std::shared_ptr<Subscription>>
        subscriptionsMap;

    uint64_t eventId{1};

    boost::asio::io_context& ioc;

  public:
    EventServiceManager(const EventServiceManager&) = delete;
    EventServiceManager& operator=(const EventServiceManager&) = delete;
    EventServiceManager(EventServiceManager&&) = delete;
    EventServiceManager& operator=(EventServiceManager&&) = delete;
    ~EventServiceManager() = default;

    explicit EventServiceManager(boost::asio::io_context& iocIn) : ioc(iocIn)
    {
        // Set Lambda for DeliveryRetry attempts exhaust
        retryExhaustCallback = [](const std::string& id) {
            std::shared_ptr<Subscription> subValue =
                EventServiceManager::getInstance().getSubscription(id);
            if (subValue == nullptr)
            {
                return;
            }
            if (subValue->retryPolicy == "TerminateAfterRetries")
            {
                // As per spec, Subscription should be deleted in this case.
                BMCWEB_LOG_DEBUG("Deleting Terminated Subscription: {}", id);
                EventServiceManager::getInstance().deleteSubscription(id);
            }
            else if (subValue->retryPolicy == "SuspendRetries")
            {
                // As per spec, Subscription state should be set to disabled in
                // this case.
                BMCWEB_LOG_DEBUG(
                    "Setting state to Disabled for Suspended Subscription: {}",
                    id);
                subValue->state = "Disabled";
                EventServiceManager::getInstance().updateSubscription(id);
            }
            // Other case, do nothing
        };

        // Load config from persist store.
        initConfig();
        redfish::KafkaManager::getInstance(&ioc);
    }

    static EventServiceManager&
        getInstance(boost::asio::io_context* ioc = nullptr)
    {
        static EventServiceManager handler(*ioc);
        return handler;
    }

    void initConfig()
    {
        loadOldBehavior();

        persistent_data::EventServiceConfig eventServiceConfig =
            persistent_data::EventServiceStore::getInstance()
                .getEventServiceConfig();

        serviceEnabled = eventServiceConfig.enabled;
        retryAttempts = eventServiceConfig.retryAttempts;
        retryTimeoutInterval = eventServiceConfig.retryTimeoutInterval;

        for (const auto& it : persistent_data::EventServiceStore::getInstance()
                                  .subscriptionsConfigMap)
        {
            std::shared_ptr<persistent_data::UserSubscription> newSub =
                it.second;

            boost::system::result<boost::urls::url> url =
                boost::urls::parse_absolute_uri(newSub->destinationUrl);

            if (!url)
            {
                BMCWEB_LOG_ERROR(
                    "Failed to validate and split destination url");
                continue;
            }
            std::shared_ptr<Subscription> subValue =
                std::make_shared<Subscription>(*url, ioc);

            subValue->id = newSub->id;
            subValue->destinationUrl = newSub->destinationUrl;
            subValue->protocol = newSub->protocol;
            subValue->retryPolicy = newSub->retryPolicy;
            subValue->customText = newSub->customText;
            subValue->eventFormatType = newSub->eventFormatType;
            subValue->subscriptionType = newSub->subscriptionType;
            subValue->registryMsgIds = newSub->registryMsgIds;
            subValue->registryPrefixes = newSub->registryPrefixes;
            subValue->resourceTypes = newSub->resourceTypes;
            subValue->httpHeaders = newSub->httpHeaders;
            subValue->metricReportDefinitions = newSub->metricReportDefinitions;
            subValue->state = newSub->state;
            subValue->owner = newSub->owner;

            if (subValue->id.empty())
            {
                BMCWEB_LOG_ERROR("Failed to add subscription");
            }
            subscriptionsMap.insert(std::pair(subValue->id, subValue));

            updateNoOfSubscribersCount();

            // Update retry configuration.
            subValue->updateRetryConfig(retryAttempts, retryTimeoutInterval);
        }
    }

    static void loadOldBehavior()
    {
        std::ifstream eventConfigFile(eventServiceFile);
        if (!eventConfigFile.good())
        {
            BMCWEB_LOG_DEBUG("Old eventService config not exist");
            return;
        }
        auto jsonData = nlohmann::json::parse(eventConfigFile, nullptr, false);
        if (jsonData.is_discarded())
        {
            BMCWEB_LOG_ERROR("Old eventService config parse error.");
            return;
        }

        for (const auto& item : jsonData.items())
        {
            if (item.key() == "Configuration")
            {
                persistent_data::EventServiceStore::getInstance()
                    .getEventServiceConfig()
                    .fromJson(item.value());
            }
            else if (item.key() == "Subscriptions")
            {
                for (const auto& elem : item.value())
                {
                    std::shared_ptr<persistent_data::UserSubscription>
                        newSubscription =
                            persistent_data::UserSubscription::fromJson(elem,
                                                                        true);
                    if (newSubscription == nullptr)
                    {
                        BMCWEB_LOG_ERROR("Problem reading subscription "
                                         "from old persistent store");
                        continue;
                    }

                    std::uniform_int_distribution<uint32_t> dist(0);
                    bmcweb::OpenSSLGenerator gen;

                    std::string id;

                    int retry = 3;
                    while (retry != 0)
                    {
                        id = std::to_string(dist(gen));
                        if (gen.error())
                        {
                            retry = 0;
                            break;
                        }
                        newSubscription->id = id;
                        auto inserted =
                            persistent_data::EventServiceStore::getInstance()
                                .subscriptionsConfigMap.insert(
                                    std::pair(id, newSubscription));
                        if (inserted.second)
                        {
                            break;
                        }
                        --retry;
                    }

                    if (retry <= 0)
                    {
                        BMCWEB_LOG_ERROR(
                            "Failed to generate random number from old "
                            "persistent store");
                        continue;
                    }
                }
            }

            persistent_data::getConfig().writeData();
            std::error_code ec;
            std::filesystem::remove(eventServiceFile, ec);
            if (ec)
            {
                BMCWEB_LOG_DEBUG(
                    "Failed to remove old event service file.  Ignoring");
            }
            else
            {
                BMCWEB_LOG_DEBUG("Remove old eventservice config");
            }
        }
    }

    void persistSubscriptionData() const
    {
        persistent_data::EventServiceStore::getInstance()
            .eventServiceConfig.enabled = serviceEnabled;
        persistent_data::EventServiceStore::getInstance()
            .eventServiceConfig.retryAttempts = retryAttempts;
        persistent_data::EventServiceStore::getInstance()
            .eventServiceConfig.retryTimeoutInterval = retryTimeoutInterval;

        persistent_data::getConfig().writeData();
    }

    void setEventServiceConfig(const persistent_data::EventServiceConfig& cfg)
    {
        bool updateConfig = false;
        bool updateRetryCfg = false;

        if (serviceEnabled != cfg.enabled)
        {
            serviceEnabled = cfg.enabled;
            if (serviceEnabled && noOfMetricReportSubscribers != 0U)
            {
                registerMetricReportSignal();
            }
            else
            {
                unregisterMetricReportSignal();
            }
            updateConfig = true;
        }

        if (retryAttempts != cfg.retryAttempts)
        {
            retryAttempts = cfg.retryAttempts;
            updateConfig = true;
            updateRetryCfg = true;
        }

        if (retryTimeoutInterval != cfg.retryTimeoutInterval)
        {
            retryTimeoutInterval = cfg.retryTimeoutInterval;
            updateConfig = true;
            updateRetryCfg = true;
        }

        if (updateConfig)
        {
            persistSubscriptionData();
        }

        if (updateRetryCfg)
        {
            // Update the changed retry config to all subscriptions
            for (const auto& it :
                 EventServiceManager::getInstance().subscriptionsMap)
            {
                Subscription& entry = *it.second;
                entry.updateRetryConfig(retryAttempts, retryTimeoutInterval);
            }
        }
    }

    void updateNoOfSubscribersCount()
    {
        size_t eventLogSubCount = 0;
        size_t metricReportSubCount = 0;
        for (const auto& it : subscriptionsMap)
        {
            std::shared_ptr<Subscription> entry = it.second;
            if (entry->eventFormatType == eventFormatType)
            {
                eventLogSubCount++;
            }
            else if (entry->eventFormatType == metricReportFormatType)
            {
                metricReportSubCount++;
            }
        }

        noOfEventLogSubscribers = eventLogSubCount;
        if (noOfMetricReportSubscribers != metricReportSubCount)
        {
            noOfMetricReportSubscribers = metricReportSubCount;
            if (noOfMetricReportSubscribers != 0U)
            {
                registerMetricReportSignal();
            }
            else
            {
                unregisterMetricReportSignal();
            }
        }
    }

    std::shared_ptr<Subscription> getSubscription(const std::string& id)
    {
        auto obj = subscriptionsMap.find(id);
        if (obj == subscriptionsMap.end())
        {
            BMCWEB_LOG_ERROR("No subscription exist with ID:{}", id);
            return nullptr;
        }
        std::shared_ptr<Subscription> subValue = obj->second;
        return subValue;
    }

    void addSubscription(const std::shared_ptr<Subscription>& subValue,
                         std::string& id, const bool updateFile = true)
    {
        std::uniform_int_distribution<uint32_t> dist(0);
        bmcweb::OpenSSLGenerator gen;

        int retry = 3;
        while (retry != 0)
        {
            if (id.empty())
            {
                id = std::to_string(dist(gen));
                if (gen.error())
                {
                    retry = 0;
                    break;
                }
            }
            auto inserted = subscriptionsMap.insert(std::pair(id, subValue));
            if (inserted.second)
            {
                break;
            }
            --retry;
        }

        if (retry <= 0)
        {
            BMCWEB_LOG_ERROR("Failed to generate random number");
            return;
        }

        subValue->id = id;
        std::shared_ptr<persistent_data::UserSubscription> newSub =
            std::make_shared<persistent_data::UserSubscription>();
        newSub->id = id;
        newSub->destinationUrl = subValue->destinationUrl;
        newSub->protocol = subValue->protocol;
        newSub->retryPolicy = subValue->retryPolicy;
        newSub->customText = subValue->customText;
        newSub->eventFormatType = subValue->eventFormatType;
        newSub->subscriptionType = subValue->subscriptionType;
        newSub->registryMsgIds = subValue->registryMsgIds;
        newSub->registryPrefixes = subValue->registryPrefixes;
        newSub->resourceTypes = subValue->resourceTypes;
        newSub->httpHeaders = subValue->httpHeaders;
        newSub->metricReportDefinitions = subValue->metricReportDefinitions;
        newSub->state = subValue->state;
        newSub->owner = subValue->owner;

        persistent_data::EventServiceStore::getInstance()
            .subscriptionsConfigMap.emplace(newSub->id, newSub);

        updateNoOfSubscribersCount();

        if (updateFile)
        {
            persistSubscriptionData();
        }

    
        // Update retry configuration.
        subValue->updateRetryConfig(retryAttempts, retryTimeoutInterval);

        // Set Subscription ID for back trace
        subValue->setSubscriptionId(id);

        /* Log event for subscription addition */
        std::string severity = "xyz.openbmc_project.Logging.Entry.Level.Informational";
        auto bus = sdbusplus::bus::new_default_system();
        sdbusplus::message::message m = bus.new_method_call("xyz.openbmc_project.Logging", "/xyz/openbmc_project/logging",
                  "xyz.openbmc_project.Logging.Create", "Create" );
        std::string journalMsg = "EventSubscriptionAdded:" + id;

           // Append the arguments to the method call
            m.append(journalMsg, severity, std::map<std::string, std::string>());
            try
            {
                bus.call(m);
            }
            catch (const sdbusplus::exception_t& e)
            {
                std::cerr << "Failed to create log entry: " << e.what() << std::endl;
            }

        return;
    }

    bool isSubscriptionExist(const std::string& id)
    {
        auto obj = subscriptionsMap.find(id);
        return obj != subscriptionsMap.end();
    }

    void deleteSubscription(const std::string& id)
    {
        auto obj = subscriptionsMap.find(id);
        std::shared_ptr<crow::sse_socket::Connection> sseConnPtr = NULL;
        if (obj != subscriptionsMap.end())
        {
	       std::shared_ptr<Subscription> entry = obj->second;
	       if (entry->subscriptionType == subscriptionTypeSSE)
	        {
		       entry->getSseConnection(sseConnPtr);
	        }	

            subscriptionsMap.erase(obj);
            auto obj2 = persistent_data::EventServiceStore::getInstance()
                            .subscriptionsConfigMap.find(id);
            persistent_data::EventServiceStore::getInstance()
                .subscriptionsConfigMap.erase(obj2);
            updateNoOfSubscribersCount();
            persistSubscriptionData();

            /* Log event for subscription delete. */
           std::string severity = "xyz.openbmc_project.Logging.Entry.Level.Informational";
            auto bus = sdbusplus::bus::new_default_system();
            sdbusplus::message::message m = bus.new_method_call("xyz.openbmc_project.Logging", "/xyz/openbmc_project/logging",
                  "xyz.openbmc_project.Logging.Create", "Create" );
            std::string journalMsg = "EventSubscriptionRemoved:" + id;

            // Append the arguments to the method call
            m.append(journalMsg, severity, std::map<std::string, std::string>());
            try
            {
                bus.call(m);
            }
            catch (const sdbusplus::exception_t& e)
            {
                std::cerr << "Failed to create log entry: " << e.what() << std::endl;
            }
        }
        if(sseConnPtr)
        {
            sseConnPtr->close("subscription deleted");
        }	
    }

    void deleteSseSubscription(
        const std::shared_ptr<crow::sse_socket::Connection>& thisConn)
    {
        for (auto it = subscriptionsMap.begin(); it != subscriptionsMap.end();)
        {
            std::shared_ptr<Subscription> entry = it->second;
            if (entry->subscriptionType == subscriptionTypeSSE)
            {
                std::optional<std::string> id =
                    entry->getSubscriptionId(thisConn);
                if (id)
                {
                    deleteSubscription(*id);
                    return;
                }
            }
            it++;
        }
    }

    void updateSubscription(const std::string& id) const
    {
        persistSubscriptionData();

        /* Log event for subscription update. */
        std::string severity = "xyz.openbmc_project.Logging.Entry.Level.Informational";
        auto bus = sdbusplus::bus::new_default_system();
        sdbusplus::message::message m = bus.new_method_call("xyz.openbmc_project.Logging", "/xyz/openbmc_project/logging",
                  "xyz.openbmc_project.Logging.Create", "Create" );

         std::string journalMsg = "EventSubscriptionUpdated:" + id;
 
        // Append the arguments to the method call
        m.append(journalMsg, severity, std::map<std::string, std::string>());
        try
        {
            bus.call(m);
        }
        catch (const sdbusplus::exception_t& e)
        {
            std::cerr << "Failed to create log entry: " << e.what() << std::endl;
        }
    }

    size_t getNumberOfSubscriptions() const
    {
        return subscriptionsMap.size();
    }

    size_t getNumberOfSSESubscriptions() const
    {
        auto size = std::ranges::count_if(
            subscriptionsMap,
            [](const std::pair<std::string, std::shared_ptr<Subscription>>&
                   entry) {
            return (entry.second->subscriptionType == subscriptionTypeSSE);
        });
        return static_cast<size_t>(size);
    }

    std::vector<std::string> getAllIDs()
    {
        std::vector<std::string> idList;
        for (const auto& it : subscriptionsMap)
        {
            idList.emplace_back(it.first);
        }
        return idList;
    }

    bool sendTestEventLog()
    {
        bool snmpNotified = false;
        for (const auto& it : subscriptionsMap)
        {
            std::shared_ptr<Subscription> entry = it.second;
            if (entry->protocol == "SNMPv1" || entry->protocol == "SNMPv2c" ||
                entry->protocol == "SNMPv3")
            {
                if (!snmpNotified)
                {
                    if (entry->sendTestSNMPTrap())
                    {
                        snmpNotified = true;
                    }
                }
                continue;
            }

            if (!entry->sendTestEventLog())
            {
                return false;
            }
        }
        return true;
    }

    void sendEvent(nlohmann::json eventMessage, const std::string& origin,
                   const std::string& resType)
    {
        std::string msg;
        if (!serviceEnabled || (noOfEventLogSubscribers == 0U))
        {
            BMCWEB_LOG_DEBUG("EventService disabled or no Subscriptions.");
            return;
        }
        if (eventMessage.contains("Message") &&
            eventMessage["Message"].is_string())
        {
            msg = eventMessage["Message"].get<std::string>();
        }
        nlohmann::json eventRecord = nlohmann::json::array();

        eventMessage["EventId"] = eventId;
        // MemberId is 0 : since we are sending one event record.
        eventMessage["MemberId"] = 0;
        eventMessage["EventTimestamp"] =
            redfish::time_utils::getDateTimeOffsetNow().first;
        eventMessage["OriginOfCondition"] = origin;

        eventRecord.emplace_back(std::move(eventMessage));

        bool snmpNotified = false;

        for (const auto& it : subscriptionsMap)
        {
            std::shared_ptr<Subscription> entry = it.second;
            bool isSubscribed = false;
            // Search the resourceTypes list for the subscription.
            // If resourceTypes list is empty, don't filter events
            // send everything.
            if (!entry->resourceTypes.empty())
            {
                for (const auto& resource : entry->resourceTypes)
                {
                    if (resType == resource)
                    {
                        BMCWEB_LOG_INFO(
                            "ResourceType {} found in the subscribed list",
                            resource);
                        isSubscribed = true;
                        break;
                    }
                }
            }
            else // resourceTypes list is empty.
            {
                isSubscribed = true;
            }

            if (entry->subscriptionType == "SNMPTrap")
            {
                if (!snmpNotified)
                {
                    std::string timestamp =
                        redfish::time_utils::getDateTimeOffsetNow().first;
                    std::tm timeStruct = {};
                    std::istringstream entryStream(timestamp);
                    if (!(entryStream >>
                          std::get_time(&timeStruct, "%Y-%m-%dT%H:%M:%S")))
                    {
                        continue;
                    }
                    std::stringstream ss;
                    ss << std::put_time(&timeStruct, "%Y-%m-%d %H:%M:%S");
                    std::string timeString = ss.str();
                    entry->sendSNMPTrap(static_cast<uint32_t>(eventId),
                                        timeString, "Ok", msg);
                    snmpNotified = true;
                    eventId++;
                }
                continue;
            }

            if (isSubscribed)
            {
                nlohmann::json msgJson;

                msgJson["@odata.type"] = "#Event.v1_4_0.Event";
                msgJson["Name"] = "Event Log";
                msgJson["Id"] = eventId;
                msgJson["Events"] = eventRecord;

                std::string strMsg = msgJson.dump(
                    2, ' ', true, nlohmann::json::error_handler_t::replace);
                entry->sendEvent(std::move(strMsg));
                eventId++; // increment the eventId
            }
            else
            {
                BMCWEB_LOG_INFO("Not subscribed to this resource");
            }
        }
    }


    void readEventLogsFromDbus(const std::string& logEntry , std::string& timestampStr)
    {
         std::vector<EventLogObjectsType> eventRecords;
         std::vector<std::string> messageArgs;
         std::string idStr,messageID,registryName,messageKey;

        //convert time to human readable format
        long long millisec = std::stoll(timestampStr); 
        auto time_point = std::chrono::system_clock::time_point(
        std::chrono::milliseconds(millisec));

        // Convert time_point to std::tm (local time)
        std::time_t time = std::chrono::system_clock::to_time_t(time_point);
        std::tm tm = *std::localtime(&time);

        // Extract milliseconds
        auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_point.time_since_epoch()) % 1000;

        // Format ISO 8601 string
         std::ostringstream oss;
         oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
	     std::string timestamp=oss.str();
            
        event_log::getUniqueEntryID(logEntry, idStr);
            
        event_log::getEventLogParams(logEntry, messageID,messageArgs);
           
        event_log::getRegistryAndMessageKey(messageID, registryName, messageKey);
           
        eventRecords.emplace_back(idStr, timestamp, messageID, registryName,
                                      messageKey, messageArgs);

        if (eventRecords.empty())
        {
            // No Records to send
            BMCWEB_LOG_DEBUG("No log entries available to be transferred.");
            return;
        }
        bool snmpNotified = false;
        for (const auto& it : subscriptionsMap)
        {
            std::shared_ptr<Subscription> entry = it.second;
            std::string prot = entry->protocol;
            if (entry->eventFormatType == "Event")
            {
                if (prot != "SNMPv1" && prot != "SNMPv2c" && prot != "SNMPv3")
                {
                    entry->filterAndSendEventLogs(eventRecords);
                    break;
                }
                else if (!snmpNotified)
                {
                    entry->filterAndsendSNMPTrap(eventRecords);
                    snmpNotified = true;
                    break;
                }
            }
        }
    } 

   static  void readEventLogsLambda(sdbusplus::message_t& msg)
    {
        sdbusplus::message::object_path path;
        ObjectType object;
        try
        {
            msg.read(path, object);
        }
        catch (const sdbusplus::exception_t& e)
        {
            std::cerr << "Failed to read message" << e.what();
            return;
        }

       auto findType = object.find("xyz.openbmc_project.Logging.Entry");
       if (findType != object.end())
       {
           std::string messages,timestampStr;
           uint64_t timestamp ;

           auto property_Msg = findType->second.find("Message");
           auto property_Time = findType->second.find("Timestamp");
           if (property_Msg != findType->second.end() && property_Time!= findType->second.end())
           {
                if (std::holds_alternative<std::string>(property_Msg->second))
                {
                    messages = std::get<std::string>(property_Msg->second);
                }
            
                if (std::holds_alternative<uint64_t>(property_Time->second))
                {
                    timestamp = std::get<uint64_t>(property_Time->second);
                    timestampStr = std::to_string(timestamp);
                }  
                 EventServiceManager::getInstance().readEventLogsFromDbus(messages,timestampStr);
            }
        }
   
    }                       

    static void startEventLogMonitor()
    {
        
       std::string matchStr1 = "type='signal',member='InterfacesAdded',path='/xyz/openbmc_project/logging'";
       try
       {

        EventServiceManager::getInstance().matchEventLog = std::make_shared<sdbusplus::bus::match_t>(
         *crow::connections::systemBus,matchStr1,readEventLogsLambda);
       
       }
       catch(const std::exception& e)
       {
            std::cerr<<"bmcweb::error in signal "<<e.what()<<"\n";
       }
    }
    static void getReadingsForReport(sdbusplus::message_t& msg)
    {
        if (msg.is_method_error())
        {
            BMCWEB_LOG_ERROR("TelemetryMonitor Signal error");
            return;
        }

        sdbusplus::message::object_path path(msg.get_path());
        std::string id = path.filename();
        if (id.empty())
        {
            BMCWEB_LOG_ERROR("Failed to get Id from path");
            return;
        }

        std::string interface;
        dbus::utility::DBusPropertiesMap props;
        std::vector<std::string> invalidProps;
        msg.read(interface, props, invalidProps);

        auto found = std::ranges::find_if(
            props, [](const auto& x) { return x.first == "Readings"; });
        if (found == props.end())
        {
            BMCWEB_LOG_INFO("Failed to get Readings from Report properties");
            return;
        }

        const telemetry::TimestampReadings* readings =
            std::get_if<telemetry::TimestampReadings>(&found->second);
        if (readings == nullptr)
        {
            BMCWEB_LOG_INFO("Failed to get Readings from Report properties");
            return;
        }

        for (const auto& it :
             EventServiceManager::getInstance().subscriptionsMap)
        {
            Subscription& entry = *it.second;
            if (entry.eventFormatType == metricReportFormatType)
            {
                entry.filterAndSendReports(id, *readings);
            }
        }
    }

    void unregisterMetricReportSignal()
    {
        if (matchTelemetryMonitor)
        {
            BMCWEB_LOG_DEBUG("Metrics report signal - Unregister");
            matchTelemetryMonitor.reset();
            matchTelemetryMonitor = nullptr;
        }
    }

    void registerMetricReportSignal()
    {
        if (!serviceEnabled || matchTelemetryMonitor)
        {
            BMCWEB_LOG_DEBUG("Not registering metric report signal.");
            return;
        }

        BMCWEB_LOG_DEBUG("Metrics report signal - Register");
        std::string matchStr = "type='signal',member='PropertiesChanged',"
                               "interface='org.freedesktop.DBus.Properties',"
                               "arg0=xyz.openbmc_project.Telemetry.Report";

        matchTelemetryMonitor = std::make_shared<sdbusplus::bus::match_t>(
            *crow::connections::systemBus, matchStr, getReadingsForReport);
    }
};

} // namespace redfish
