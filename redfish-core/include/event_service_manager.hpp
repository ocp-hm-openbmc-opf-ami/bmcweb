// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
// SPDX-FileCopyrightText: Copyright 2020 Intel Corporation
#pragma once
#include "dbus_log_watcher.hpp"
#include "dbus_singleton.hpp"
#include "dbus_utility.hpp"
#include "error_messages.hpp"
#include "event_log.hpp"
#include "event_matches_filter.hpp"
#include "event_service_store.hpp"
#include "filesystem_log_watcher.hpp"
#include "kafka_manager.hpp"
#include "metric_report.hpp"
#include "ossl_random.hpp"
#include "persistent_data.hpp"
#include "subscription.hpp"
#include "utility.hpp"
#include "utils/dbus_event_log_entry.hpp"
#include "utils/json_utils.hpp"
#include "utils/time_utils.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/container/flat_map.hpp>
#include <boost/url/format.hpp>
#include <boost/url/url_view_base.hpp>

#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <format>
#include <fstream>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace redfish
{

static constexpr const char* eventFormatType = "Event";
static constexpr const char* metricReportFormatType = "MetricReport";

static constexpr const char* eventServiceFile =
    "/var/lib/bmcweb/eventservice_config.json";

static std::function<void(const std::string&)> retryExhaustCallback =
    [](const std::string&) {};

using Value = std::variant<bool, uint8_t, int16_t, uint16_t, int32_t, uint32_t,
                           int64_t, uint64_t, double, std::string,
                           std::vector<uint8_t>, std::vector<uint16_t>,
                           std::vector<uint32_t>, std::vector<std::string>>;

using ObjectType =
    boost::container::flat_map<std::string,
                               boost::container::flat_map<std::string, Value>>;

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

inline bool readSSEQueryParams(
    std::string sseFilter, std::string& formatType,
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

class EventServiceManager
{
  private:
    bool serviceEnabled = false;
    uint32_t retryAttempts = 0;
    uint32_t retryTimeoutInterval = 0;

    size_t noOfEventLogSubscribers{0};
    size_t noOfMetricReportSubscribers{0};
    std::optional<DbusEventLogMonitor> dbusEventLogMonitor;
    std::optional<DbusTelemetryMonitor> matchTelemetryMonitor;
    std::optional<FilesystemLogWatcher> filesystemLogMonitor;
    std::shared_ptr<sdbusplus::bus::match_t> matchEventLog;
    boost::container::flat_map<std::string, std::shared_ptr<Subscription>>
        subscriptionsMap;

    uint64_t eventId{1};

    struct Event
    {
        std::string id;
        nlohmann::json message;
    };
    constexpr static size_t maxMessages = 200;
    boost::circular_buffer<Event> messages{maxMessages};

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
            if (subValue->userSub->retryPolicy == "TerminateAfterRetries")
            {
                // As per spec, Subscription should be deleted in this case.
                BMCWEB_LOG_DEBUG("Deleting Terminated Subscription: {}", id);
                EventServiceManager::getInstance().deleteSubscription(id);
            }
            else if (subValue->userSub->retryPolicy == "SuspendRetries")
            {
                // As per spec, Subscription state should be set to disabled in
                // this case.
                BMCWEB_LOG_DEBUG(
                    "Setting state to Disabled for Suspended Subscription: {}",
                    id);
                subValue->userSub->state = "Disabled";
                EventServiceManager::getInstance().updateSubscription(id);
            }
            // Other case, do nothing
        };

        // Load config from persist store.
        initConfig();
        redfish::KafkaManager::getInstance(&ioc);
    }

    static EventServiceManager& getInstance(
        boost::asio::io_context* ioc = nullptr)
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
                std::make_shared<Subscription>(newSub, *url, ioc);

            std::string id = subValue->userSub->id;
            subValue->deleter = [id]() {
                EventServiceManager::getInstance().deleteSubscription(id);
            };

            subscriptionsMap.emplace(id, subValue);

            updateNoOfSubscribersCount();

            // Update retry configuration.
            subValue->updateRetryConfig(retryAttempts, retryTimeoutInterval);

            // schedule a heartbeat if sendHeartbeat was set to true
            if (subValue->userSub->sendHeartbeat)
            {
                subValue->scheduleNextHeartbeatEvent();
            }
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

        const nlohmann::json::object_t* obj =
            jsonData.get_ptr<const nlohmann::json::object_t*>();
        if (obj == nullptr)
        {
            return;
        }
        for (const auto& item : *obj)
        {
            if (item.first == "Configuration")
            {
                persistent_data::EventServiceStore::getInstance()
                    .getEventServiceConfig()
                    .fromJson(item.second);
            }
            else if (item.first == "Subscriptions")
            {
                for (const auto& elem : item.second)
                {
                    std::optional<persistent_data::UserSubscription>
                        newSubscription =
                            persistent_data::UserSubscription::fromJson(elem,
                                                                        true);
                    if (!newSubscription)
                    {
                        BMCWEB_LOG_ERROR("Problem reading subscription "
                                         "from old persistent store");
                        continue;
                    }
                    persistent_data::UserSubscription& newSub =
                        *newSubscription;

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
                        newSub.id = id;
                        auto inserted =
                            persistent_data::EventServiceStore::getInstance()
                                .subscriptionsConfigMap.insert(std::pair(
                                    id, std::make_shared<
                                            persistent_data::UserSubscription>(
                                            newSub)));
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

    void updateSubscriptionData() const
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

        if (serviceEnabled)
        {
            if (noOfEventLogSubscribers > 0U)
            {
                if constexpr (BMCWEB_REDFISH_DBUS_LOG)
                {
                    if (!dbusEventLogMonitor)
                    {
                        if constexpr (
                            BMCWEB_EXPERIMENTAL_REDFISH_DBUS_LOG_SUBSCRIPTION)
                        {
                            dbusEventLogMonitor.emplace();
                        }
                    }
                }
                else
                {
                    if (!filesystemLogMonitor)
                    {
                        filesystemLogMonitor.emplace(ioc);
                    }
                }
            }
            else
            {
                dbusEventLogMonitor.reset();
            }

            if (noOfMetricReportSubscribers > 0U)
            {
                if (!matchTelemetryMonitor)
                {
                    matchTelemetryMonitor.emplace();
                }
            }
            else
            {
                matchTelemetryMonitor.reset();
            }
        }
        else
        {
            matchTelemetryMonitor.reset();
            dbusEventLogMonitor.reset();
            filesystemLogMonitor.reset();
        }

        if (serviceEnabled != cfg.enabled)
        {
            serviceEnabled = cfg.enabled;
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
            updateSubscriptionData();
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
            if (entry->userSub->eventFormatType == eventFormatType)
            {
                eventLogSubCount++;
            }
            else if (entry->userSub->eventFormatType == metricReportFormatType)
            {
                metricReportSubCount++;
            }
        }

        noOfEventLogSubscribers = eventLogSubCount;
        if (eventLogSubCount > 0U)
        {
            if constexpr (BMCWEB_REDFISH_DBUS_LOG)
            {
                if (!dbusEventLogMonitor &&
                    BMCWEB_EXPERIMENTAL_REDFISH_DBUS_LOG_SUBSCRIPTION)
                {
                    dbusEventLogMonitor.emplace();
                }
            }
            else
            {
                if (!filesystemLogMonitor)
                {
                    filesystemLogMonitor.emplace(ioc);
                }
            }
        }
        else
        {
            dbusEventLogMonitor.reset();
            filesystemLogMonitor.reset();
        }
        noOfMetricReportSubscribers = metricReportSubCount;
        if (metricReportSubCount > 0U)
        {
            if (!matchTelemetryMonitor)
            {
                matchTelemetryMonitor.emplace();
            }
        }
        else
        {
            matchTelemetryMonitor.reset();
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

    void addSubscriptionInternal(const std::shared_ptr<Subscription>& subValue,
                                 std::string& id)
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
            if (subValue->userSub->subscriptionType == subscriptionTypeSSE)
            {
                subValue->userSub->customText = "Event_Sub_" + id;
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

        // subValue->id = id;

        // Set Subscription ID for back trace
        subValue->userSub->id = id;

        persistent_data::EventServiceStore::getInstance()
            .subscriptionsConfigMap.emplace(id, subValue->userSub);

        updateNoOfSubscribersCount();

        // Update retry configuration.
        subValue->updateRetryConfig(retryAttempts, retryTimeoutInterval);

        /* Log event for subscription addition */
        std::string severity =
            "xyz.openbmc_project.Logging.Entry.Level.Informational";
        auto bus = sdbusplus::bus::new_default_system();
        sdbusplus::message::message m = bus.new_method_call(
            "xyz.openbmc_project.Logging", "/xyz/openbmc_project/logging",
            "xyz.openbmc_project.Logging.Create", "Create");
        std::string journalMsg = "EventSubscriptionAdded:" + id;

        // Append the arguments to the method call
        m.append(journalMsg, severity, std::map<std::string, std::string>());
        try
        {
            bus.call(m);
        }
        catch (const sdbusplus::exception_t& e)
        {
            std::cerr << "Failed to create log entry: " << e.what()
                      << std::endl;
        }

        return;
    }

    void addSSESubscription(const std::shared_ptr<Subscription>& subValue,
                            std::string_view lastEventId, std::string& id)
    {
        addSubscriptionInternal(subValue, id);
        if (!lastEventId.empty())
        {
            BMCWEB_LOG_INFO("Attempting to find message for last id {}",
                            lastEventId);
            boost::circular_buffer<Event>::iterator lastEvent =
                std::find_if(messages.begin(), messages.end(),
                             [&lastEventId](const Event& event) {
                                 return event.id == lastEventId;
                             });
            // Can't find a matching ID
            if (lastEvent == messages.end())
            {
                nlohmann::json msg = messages::eventBufferExceeded();
                // If the buffer overloaded, send all messages.
                subValue->sendEventToSubscriber(msg);
                lastEvent = messages.begin();
            }
            else
            {
                // Skip the last event the user already has
                lastEvent++;
            }
            for (boost::circular_buffer<Event>::const_iterator event =
                     lastEvent;
                 lastEvent != messages.end(); lastEvent++)
            {
                subValue->sendEventToSubscriber(event->message);
            }
        }
        return;
    }

    void addPushSubscription(const std::shared_ptr<Subscription>& subValue,
                             std::string& id)
    {
        addSubscriptionInternal(subValue, id);

        subValue->deleter = [id]() {
            EventServiceManager::getInstance().deleteSubscription(id);
        };
        updateSubscriptionData();
        return;
    }

    bool isSubscriptionExist(const std::string& id)
    {
        auto obj = subscriptionsMap.find(id);
        return obj != subscriptionsMap.end();
    }

    bool isDuplicateDestination(const std::string& destUrl)
    {
        for (const auto& [id, subscription] : subscriptionsMap)
        {
            if (!subscription || !subscription->userSub)
            {
                continue;
            }

            std::string existingDest =
                subscription->userSub->destinationUrl.buffer();

            if (existingDest == destUrl)
            {
                return true;
            }
        }

        return false;
    }

    bool deleteSubscription(const std::string& id)
    {
        auto obj = subscriptionsMap.find(id);
        std::shared_ptr<crow::sse_socket::Connection> sseConnPtr = NULL;
        if (obj == subscriptionsMap.end())
        {
            BMCWEB_LOG_WARNING("Could not find subscription with id {}", id);
            return false;
        }
        std::shared_ptr<Subscription> entry = obj->second;
        if (entry->userSub->subscriptionType == subscriptionTypeSSE)
        {
            entry->getSseConnection(sseConnPtr);
        }
        subscriptionsMap.erase(obj);
        auto& event = persistent_data::EventServiceStore::getInstance();
        auto persistentObj = event.subscriptionsConfigMap.find(id);
        if (persistentObj == event.subscriptionsConfigMap.end())
        {
            BMCWEB_LOG_ERROR("Subscription wasn't in persistent data");
            return true;
        }
        persistent_data::EventServiceStore::getInstance()
            .subscriptionsConfigMap.erase(persistentObj);
        updateNoOfSubscribersCount();
        updateSubscriptionData();

        /* Log event for subscription delete. */
        std::string severity =
            "xyz.openbmc_project.Logging.Entry.Level.Informational";
        auto bus = sdbusplus::bus::new_default_system();
        sdbusplus::message::message m = bus.new_method_call(
            "xyz.openbmc_project.Logging", "/xyz/openbmc_project/logging",
            "xyz.openbmc_project.Logging.Create", "Create");
        std::string journalMsg = "EventSubscriptionRemoved:" + id;

        // Append the arguments to the method call
        m.append(journalMsg, severity, std::map<std::string, std::string>());
        try
        {
            bus.call(m);
            std::string timestampStr = std::to_string(std::time(nullptr));
            int32_t sensorType = 0;
            readEventLogsFromDbus(journalMsg, timestampStr, sensorType);
        }
        catch (const sdbusplus::exception_t& e)
        {
            std::cerr << "Failed to create log entry: " << e.what()
                      << std::endl;
        }
        if (sseConnPtr)
        {
            sseConnPtr->close("subscription deleted");
        }
        return true;
    }

    void deleteSseSubscription(
        const std::shared_ptr<crow::sse_socket::Connection>& thisConn)
    {
        for (auto it = subscriptionsMap.begin(); it != subscriptionsMap.end();)
        {
            std::shared_ptr<Subscription> entry = it->second;
            if (entry->userSub->subscriptionType == subscriptionTypeSSE)
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
        updateSubscriptionData();

        /* Log event for subscription update. */
        std::string severity =
            "xyz.openbmc_project.Logging.Entry.Level.Informational";
        auto bus = sdbusplus::bus::new_default_system();
        sdbusplus::message::message m = bus.new_method_call(
            "xyz.openbmc_project.Logging", "/xyz/openbmc_project/logging",
            "xyz.openbmc_project.Logging.Create", "Create");

        std::string journalMsg = "EventSubscriptionUpdated:" + id;

        // Append the arguments to the method call
        m.append(journalMsg, severity, std::map<std::string, std::string>());
        try
        {
            bus.call(m);
        }
        catch (const sdbusplus::exception_t& e)
        {
            std::cerr << "Failed to create log entry: " << e.what()
                      << std::endl;
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
                return (entry.second->userSub->subscriptionType ==
                        subscriptionTypeSSE);
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

    bool sendTestEventLog(TestEvent& testEvent)
    {
        bool snmpNotified = false;
        for (const auto& it : subscriptionsMap)
        {
            std::shared_ptr<Subscription> entry = it.second;
            if (entry->userSub->protocol == "SNMPv1" ||
                entry->userSub->protocol == "SNMPv2c" ||
                entry->userSub->protocol == "SNMPv3")
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
            if (!testEvent.eventId)
            {
                testEvent.eventId = std::to_string(eventId);
            }
            if (!entry->sendTestEventLog(testEvent))
            {
                return false;
            }
        }
        return true;
    }

    static void sendEventsToSubs(
        const std::vector<EventLogObjectsType>& eventRecords)
    {
        for (const auto& it :
             EventServiceManager::getInstance().subscriptionsMap)
        {
            Subscription& entry = *it.second;
            entry.filterAndSendEventLogs(eventRecords);
        }
    }

    static void sendTelemetryReportToSubs(
        const std::string& reportId, const telemetry::TimestampReadings& var)
    {
        for (const auto& it :
             EventServiceManager::getInstance().subscriptionsMap)
        {
            Subscription& entry = *it.second;
            entry.filterAndSendReports(reportId, var);
        }
    }

    void sendEvent(nlohmann::json eventMessage, std::string_view origin,
                   std::string_view resType)
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

        eventMessage["EventId"] = eventId;
        // MemberId is 0 : since we are sending one event record.
        eventMessage["MemberId"] = "0";
        eventMessage["EventTimestamp"] =
            redfish::time_utils::getDateTimeOffsetNow().first;
        eventMessage["OriginOfCondition"] = origin;

        messages.push_back(Event(std::to_string(eventId), eventMessage));

        bool snmpNotified = false;

        for (auto& it : subscriptionsMap)
        {
            std::shared_ptr<Subscription>& entry = it.second;
            if (!eventMatchesFilter(*entry->userSub, eventMessage, resType))
            {
                BMCWEB_LOG_DEBUG("Filter didn't match");
                continue;
            }
            nlohmann::json::array_t eventRecord;
            eventRecord.emplace_back(eventMessage);
            nlohmann::json msgJson;
            msgJson["@odata.type"] = json_util::odataType("Event");
            msgJson["Name"] = "Event Log";
            msgJson["Id"] = eventId;
            msgJson["Events"] = std::move(eventRecord);
            std::string strMsg = msgJson.dump(
                2, ' ', true, nlohmann::json::error_handler_t::replace);
            entry->sendEventToSubscriber(std::move(strMsg));

            if (entry->userSub->subscriptionType == "SNMPTrap")
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
        }
        eventId++; // increment the eventId
    }

    void readEventLogsFromDbus(const std::string& logEntry,
                               std::string& timestampStr,
                               const int32_t& sensorType)
    {
        std::vector<EventLogObjectsType> eventRecords;
        std::vector<std::string> messageArgs;
        std::string idStr, messageID, registryName, messageKey;

        // convert time to human readable format
        long long millisec = std::stoll(timestampStr);
        auto time_point = std::chrono::system_clock::time_point(
            std::chrono::milliseconds(millisec));

        // Convert time_point to std::tm (local time)
        std::time_t time = std::chrono::system_clock::to_time_t(time_point);
        std::tm tm = *std::localtime(&time);

        // Extract milliseconds
        auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(
                          time_point.time_since_epoch()) %
                      1000;

        // Format ISO 8601 string
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
        std::string timestamp = oss.str();

        event_log::getUniqueEntryID(logEntry, idStr);

        event_log::getDbusEventLogParams(logEntry, messageID, messageArgs);

        getRegistryAndMessageKey(messageID, registryName, messageKey);

        eventRecords.emplace_back(idStr, timestamp, messageID, messageArgs,
                                  registryName, messageKey, sensorType);

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
            std::string prot = entry->userSub->protocol;
            if (entry->userSub->eventFormatType == "Event")
            {
                if (prot != "SNMPv1" && prot != "SNMPv2c" && prot != "SNMPv3")
                {
                    if (messageID != "EventSubscriptionRemoved" &&
                        messageID != "EventSubscriptionAdded")
                    {
                        entry->filterAndSendEventLogs(eventRecords);
                    }
                    // break;
                }
                else if (!snmpNotified)
                {
                    entry->filterAndsendSNMPTrap(eventRecords);
                    snmpNotified = true;
                    // break;
                }
            }
        }
    }

    static void readEventLogsLambda(sdbusplus::message_t& msg)
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
        if (findType == object.end())
        {
            std::cerr << "Logging entry not found!" << std::endl;
            return;
        }

        std::string messages, timestampStr;
        uint64_t timestamp = 0;

        auto property_Msg = findType->second.find("Message");
        auto property_Time = findType->second.find("Timestamp");

        //  Fetch Message
        if (property_Msg != findType->second.end() &&
            std::holds_alternative<std::string>(property_Msg->second))
        {
            messages = std::get<std::string>(property_Msg->second);
        }

        //  Fetch Timestamp
        if (property_Time != findType->second.end() &&
            std::holds_alternative<uint64_t>(property_Time->second))
        {
            timestamp = std::get<uint64_t>(property_Time->second);
            timestampStr = std::to_string(timestamp);
        }

        sdbusplus::asio::getProperty<std::map<std::string, std::string>>(
            *crow::connections::systemBus,
            "xyz.openbmc_project.Logging",       // D-Bus service name
            path.str.c_str(),                    // Object path
            "xyz.openbmc_project.Logging.Entry", // Interface
            "AdditionalData",                    // Property name
            [messages, timestampStr](const boost::system::error_code& ec,
                                     const std::map<std::string, std::string>&
                                         additionalData) mutable {
                if (ec)
                {
                    BMCWEB_LOG_ERROR("Failed to get AdditionalData: {}", ec);
                    return;
                }

                int32_t sensorType = 0; // Default value if not found
                std::string sensorPath;
                std::optional<std::string> redfishMsgId;
                std::optional<std::string> redfishMsgArgs;

                // Extract SENSOR_TYPE, SENSOR_PATH, REDFISH_MESSAGE_ID and
                // REDFISH_MESSAGE_ARGS from AdditionalData

                auto itSensorType = additionalData.find("SENSOR_TYPE");
                if (itSensorType != additionalData.end())
                {
                    sensorType = std::stoi(itSensorType->second);
                }

                auto itSensorPath = additionalData.find("SENSOR_PATH");
                if (itSensorPath != additionalData.end())
                {
                    sensorPath = itSensorPath->second;
                }

                auto itMsgId = additionalData.find("REDFISH_MESSAGE_ID");
                if (itMsgId != additionalData.end())
                {
                    redfishMsgId = itMsgId->second;
                }

                auto itMsgArgs = additionalData.find("REDFISH_MESSAGE_ARGS");
                if (itMsgArgs != additionalData.end())
                {
                    redfishMsgArgs = itMsgArgs->second;
                }
                // Fallback Logic: infer sensor type from path when metadata
                // doesn’t provide SENSOR_TYPE.
                if (sensorType == 0 && !sensorPath.empty())
                {
                    if (sensorPath.find("/temperature/") != std::string::npos)
                    {
                        sensorType = 1;
                    }
                    else if (sensorPath.find("/voltage/") != std::string::npos)
                    {
                        sensorType = 2;
                    }
                    else if (sensorPath.find("/current/") != std::string::npos)
                    {
                        sensorType = 3;
                    }
                    else if (sensorPath.find("/fan") != std::string::npos)
                    {
                        sensorType = 4;
                    }
                }

                std::string logEntry = messages;
                if (!redfishMsgId)
                {
                    // Some phosphor-logging threshold entries already encode a
                    // full MessageId plus args separated by commas (no
                    // REDFISH_MESSAGE_ID/ARGS provided). Normalize that into
                    // MessageId + MessageArgs so downstream parsing succeeds.
                    size_t commaPos = messages.find(',');
                    if (commaPos != std::string::npos &&
                        messages.find("SensorThreshold") != std::string::npos)
                    {
                        redfishMsgId = messages.substr(0, commaPos);
                        redfishMsgArgs = messages.substr(commaPos + 1);
                    }
                }
                if (redfishMsgId)
                {
                    size_t lastDot = redfishMsgId->rfind('.');
                    if (lastDot != std::string::npos)
                    {
                        *redfishMsgId = redfishMsgId->substr(lastDot + 1);
                    }
                    logEntry = *redfishMsgId;
                    if (redfishMsgArgs && !redfishMsgArgs->empty())
                    {
                        // Use colon separator to match getDbusEventLogParams()
                        // parsing logic
                        logEntry += ":";
                        logEntry += *redfishMsgArgs;
                    }
                }
                EventServiceManager::getInstance().readEventLogsFromDbus(
                    logEntry, timestampStr, sensorType);
            });
    }

    static void startdbusEventLogMonitor()
    {
        std::string matchStr1 =
            "type='signal',member='InterfacesAdded',path_namespace='/xyz/openbmc_project/logging'";
        try
        {
            EventServiceManager::getInstance().matchEventLog =
                std::make_shared<sdbusplus::bus::match_t>(
                    *crow::connections::systemBus, matchStr1,
                    readEventLogsLambda);
        }
        catch (const std::exception& e)
        {
            std::cerr << "bmcweb::error in signal " << e.what() << "\n";
        }
    }

    // Below Function is to log events in dbus for propertychange operations
    void propertyModifiedEventLog(nlohmann::json::object_t& propertyModified,
                                  nlohmann::json::object_t& propertyOriginal,
                                  const std::string& URI)
    {
        std::string arg1;
        std::string arg2 = URI;
        std::string arg3;
        std::string arg4;
        bool firstModified = true; // To track if it's the first key
        bool firstOriginal = true;
        if (propertyModified.size() > 0)
        {
            for (const auto& [key, value] : propertyModified)
            {
                if (!firstModified)
                {
                    arg1 += ", "; // Add a comma before the next key
                    arg4 += ", ";
                }

                arg1 += key;

                // Handle value type (string, boolean, or array of strings)
                if (value.is_string())
                {
                    arg4 += value.get<std::string>();
                }
                else if (value.is_boolean())
                {
                    arg4 += value.get<bool>() ? "true" : "false";
                }
                else if (value.is_number_integer())
                {
                    arg4 += std::to_string(value.get<uint64_t>());
                }
                else if (value.is_number_float())
                {
                    arg4 += std::to_string(value.get<double>());
                }
                else if (value.is_array())
                {
                    std::string arrayStr = "[";
                    bool firstInArray = true;
                    for (const auto& item : value)
                    {
                        if (!firstInArray)
                        {
                            arrayStr += ", ";
                        }
                        if (item.is_string())
                        {
                            arrayStr += item.get<std::string>();
                        }
                        firstInArray = false;
                    }
                    arrayStr += "]";
                    arg4 += arrayStr;
                }
                else if (value.is_null())
                {
                    arg4 += "null";
                }
                else if (value.is_object())
                {
                    arg4 += "{object}"; // Or serialize the object
                }

                firstModified = false;

                auto it = propertyOriginal.find(key);
                if (it != propertyOriginal.end())
                {
                    if (!firstOriginal)
                    {
                        arg3 += ", "; // Add a comma before the next key
                    }
                    if (it->second.is_string())
                    {
                        arg3 += it->second.get<std::string>();
                    }
                    else if (it->second.is_boolean())
                    {
                        arg3 += it->second.get<bool>() ? "true" : "false";
                    }
                    else if (it->second.is_number_integer())
                    {
                        arg3 += std::to_string(it->second.get<uint64_t>());
                    }
                    else if (it->second.is_number_float())
                    {
                        arg3 += std::to_string(it->second.get<double>());
                    }
                    else if (it->second.is_array())
                    {
                        std::string arrayStr = "[";
                        bool firstInArray = true;
                        for (const auto& item : it->second)
                        {
                            if (!firstInArray)
                            {
                                arrayStr += ", ";
                            }
                            if (item.is_string())
                            {
                                arrayStr += item.get<std::string>();
                            }
                            firstInArray = false;
                        }
                        arrayStr += "]";
                        arg3 += arrayStr;
                    }
                    else if (it->second.is_null())
                    {
                        arg3 += "null";
                    }
                    else if (it->second.is_object())
                    {
                        arg3 += "{object}"; // Or serialize the object
                    }

                    firstOriginal = false;
                }
            }
        }

        std::string severity =
            "xyz.openbmc_project.Logging.Entry.Level.Informational";
        auto bus = sdbusplus::bus::new_default_system();
        sdbusplus::message::message m = bus.new_method_call(
            "xyz.openbmc_project.Logging", "/xyz/openbmc_project/logging",
            "xyz.openbmc_project.Logging.Create", "Create");
        std::string journalMsg =
            "ResourceModified:" + arg1 + "," + arg2 + "," + arg3 + "," + arg4;

        // Append the arguments to the method call
        m.append(journalMsg, severity, std::map<std::string, std::string>());
        try
        {
            bus.call(m);
        }
        catch (const sdbusplus::exception_t& e)
        {
            std::cerr << "Failed to create log entry: " << e.what()
                      << std::endl;
        }
    }

    // Below Function is to log events in dbus for resource creation and
    // deletion
    void resourceCreationDeletion(const std::string& eventLogMessageId)
    {
        std::string severity =
            "xyz.openbmc_project.Logging.Entry.Level.Informational";
        auto bus = sdbusplus::bus::new_default_system();
        sdbusplus::message::message m = bus.new_method_call(
            "xyz.openbmc_project.Logging", "/xyz/openbmc_project/logging",
            "xyz.openbmc_project.Logging.Create", "Create");
        std::string journalMsg = eventLogMessageId;

        // Append the arguments to the method call
        m.append(journalMsg, severity, std::map<std::string, std::string>());
        try
        {
            bus.call(m);
        }
        catch (const sdbusplus::exception_t& e)
        {
            std::cerr << "Failed to create log entry: " << e.what()
                      << std::endl;
        }
    }
    void alertSystem(const std::string& managerMessageID)
    {
        std::string severity =
            "xyz.openbmc_project.Logging.Entry.Level.Informational";
        auto bus = sdbusplus::bus::new_default_system();
        sdbusplus::message::message m = bus.new_method_call(
            "xyz.openbmc_project.Logging", "/xyz/openbmc_project/logging",
            "xyz.openbmc_project.Logging.Create", "Create");
        std::string journalMsg = managerMessageID;

        // Append the arguments to the method call
        m.append(journalMsg, severity, std::map<std::string, std::string>());
        try
        {
            bus.call(m);
        }
        catch (const sdbusplus::exception_t& e)
        {
            std::cerr << "Failed to create log entry: " << e.what()
                      << std::endl;
        }
    }
};

} // namespace redfish
