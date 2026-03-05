/*
Copyright (c) 2020 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include "subscription.hpp"

#include "dbus_singleton.hpp"
#include "event_log.hpp"
#include "event_logs_object_type.hpp"
#include "event_matches_filter.hpp"
#include "event_service_manager.hpp"
#include "event_service_store.hpp"
#include "filter_expr_executor.hpp"
#include "heartbeat_messages.hpp"
#include "http_client.hpp"
#include "http_response.hpp"
#include "logging.hpp"
#include "metric_report.hpp"
#include "registries.hpp"
#include "server_sent_event.hpp"
#include "ssl_key_handler.hpp"
#include "utils/time_utils.hpp"

#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast/http/field.hpp>
#include <boost/beast/http/fields.hpp>
#include <boost/beast/http/verb.hpp>
#include <boost/system/errc.hpp>
#include <boost/url/format.hpp>
#include <boost/url/url_view_base.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <format>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace redfish
{

Subscription::Subscription(
    std::shared_ptr<persistent_data::UserSubscription> userSubIn,
    const boost::urls::url_view_base& url, boost::asio::io_context& ioc) :
    userSub{std::move(userSubIn)},
    policy(std::make_shared<crow::ConnectionPolicy>()), hbTimer(ioc)
{
    userSub->destinationUrl = url;
    client.emplace(ioc, policy);
    // Subscription constructor
    policy->invalidResp = retryRespHandler;
}

Subscription::Subscription(
    std::shared_ptr<crow::sse_socket::Connection>& connIn) :
    userSub{std::make_shared<persistent_data::UserSubscription>()},
    policy(std::make_shared<crow::ConnectionPolicy>(getSubPolicy())),
    sseConn(connIn), hbTimer(crow::connections::systemBus->get_io_context())
{
    // Subscription constructor
    policy->invalidResp = retryRespHandler;
}

void Subscription::resHandler(const crow::Response& res)
{
    BMCWEB_LOG_DEBUG("Response handled with return code: {}", res.resultInt());
    if (!client)
    {
        BMCWEB_LOG_ERROR(
            "Http client wasn't filled but http client callback was called.");
        return;
    }
    if (userSub->retryPolicy != "TerminateAfterRetries")
    {
        return;
    }
    if (client->isTerminated())
    {
        hbTimer.cancel();
        if (deleter)
        {
            BMCWEB_LOG_INFO("Subscription {} is deleted after MaxRetryAttempts",
                            userSub->id);
            deleter();
        }
    }
}

void Subscription::getSseConnection(
    std::shared_ptr<crow::sse_socket::Connection>& connPtr)
{
    connPtr = sseConn;
    return;
}

void Subscription::sendHeartbeatEvent()
{
    // send the heartbeat message
    nlohmann::json eventMessage = messages::redfishServiceFunctional();
    std::string heartEventId = std::to_string(eventSeqNum);
    eventMessage["EventId"] = heartEventId;
    eventMessage["EventTimestamp"] = time_utils::getDateTimeOffsetNow().first;
    eventMessage["OriginOfCondition"] =
        std::format("/redfish/v1/EventService/Subscriptions/{}", userSub->id);
    eventMessage["MemberId"] = "0";
    nlohmann::json::array_t eventRecord;
    eventRecord.emplace_back(std::move(eventMessage));
    nlohmann::json msgJson;
    msgJson["@odata.type"] = json_util::odataType("Event");
    msgJson["Name"] = "Heartbeat";
    msgJson["Id"] = heartEventId;
    msgJson["Events"] = std::move(eventRecord);
    std::string strMsg =
        msgJson.dump(2, ' ', true, nlohmann::json::error_handler_t::replace);
    sendEventToSubscriber(std::move(strMsg));
    eventSeqNum++;
}

void Subscription::scheduleNextHeartbeatEvent()
{
    hbTimer.expires_after(std::chrono::minutes(userSub->hbIntervalMinutes));
    hbTimer.async_wait(
        std::bind_front(&Subscription::onHbTimeout, this, weak_from_this()));
}

void Subscription::heartbeatParametersChanged()
{
    hbTimer.cancel();
    if (userSub->sendHeartbeat)
    {
        scheduleNextHeartbeatEvent();
    }
}

void Subscription::onHbTimeout(const std::weak_ptr<Subscription>& weakSelf,
                               const boost::system::error_code& ec)
{
    if (ec == boost::asio::error::operation_aborted)
    {
        BMCWEB_LOG_DEBUG("heartbeat timer async_wait is aborted");
        return;
    }
    if (ec == boost::system::errc::operation_canceled)
    {
        BMCWEB_LOG_DEBUG("heartbeat timer async_wait canceled");
        return;
    }
    if (ec)
    {
        BMCWEB_LOG_CRITICAL("heartbeat timer async_wait failed: {}", ec);
        return;
    }
    std::shared_ptr<Subscription> self = weakSelf.lock();
    if (!self)
    {
        BMCWEB_LOG_CRITICAL("onHbTimeout failed on Subscription");
        return;
    }
    // Timer expired.
    sendHeartbeatEvent();
    // reschedule heartbeat timer
    scheduleNextHeartbeatEvent();
}

bool Subscription::sendEventToSubscriber(std::string&& msg)
{
    if (userSub->subscriptionType == "SNMPTrap")
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
    if (userSub->state == "Disabled")
    {
        BMCWEB_LOG_DEBUG("Subscription is suspended, so not sending events.");
        return false;
    }

    if (client)
    {
        boost::beast::http::fields httpHeadersCopy(userSub->httpHeaders);
        httpHeadersCopy.set(boost::beast::http::field::content_type,
                            "application/json");
        std::function<void(crow::Response&)> sendEventCallback =
            [subId(userSub->id), retryPolicy(userSub->retryPolicy),
             retryExhaustCallback(retryExhaustCallback)](crow::Response& res) {
                if (res.result() == boost::beast::http::status::bad_gateway)
                {
                    // Response is going to have bad_gateway result if the
                    // event listener was not able to receive the event even
                    // after multiple retries. This response is received
                    // only when retry policy is Suspend after retires or
                    // Terminate after reties.
                    retryExhaustCallback(subId);
                }
            };

        client->sendDataWithCallback(
            std::move(msg), userSub->destinationUrl,
            static_cast<ensuressl::VerifyCertificate>(
                userSub->verifyCertificate),
            httpHeadersCopy, boost::beast::http::verb::post,
            std::bind_front(&Subscription::resHandler, this));
        return true;
    }

    if (sseConn != nullptr)
    {
        sseConn->sendSseEvent(std::to_string(eventSeqNum), msg);
    }
    return true;
}
bool Subscription::sendSNMPTrap(uint32_t eventId, std::string timestamp,
                                std::string sev, std::string& msg)
{
    persistent_data::EventServiceConfig eventServiceConfig =
        persistent_data::EventServiceStore::getInstance()
            .getEventServiceConfig();
    if (!eventServiceConfig.enabled)
    {
        return false;
    }
    try
    {
        phosphor::network::snmp::sendTrap<
            phosphor::network::snmp::OBMCErrorNotification>(
            static_cast<uint32_t>(eventId), timestamp, sev, std::move(msg));
        eventSeqNum++;
        return true;
    }
    catch (const sdbusplus::exception_t& e)
    {
        BMCWEB_LOG_ERROR("Exception during SNMP trap send: {}", e.what());
        return false;
    }
}

void Subscription::filterAndsendSNMPTrap(
    const std::vector<EventLogObjectsType>& eventRecords)
{
    nlohmann::json::array_t logEntryArray;
    for (const EventLogObjectsType& logEntry : eventRecords)
    {
        const std::string& idStr = logEntry.id;
        const std::string& messageID = logEntry.messageId;
        const std::string& registryName = logEntry.registryName;
        const std::string& messageKey = logEntry.messageKey;
        const std::vector<std::string>& messageArgs = logEntry.messageArgs;

        if (!userSub->registryPrefixes.empty())
        {
            auto obj = std::find(userSub->registryPrefixes.begin(),
                                 userSub->registryPrefixes.end(), registryName);
            if (obj == userSub->registryPrefixes.end())
            {
                continue;
            }
        }
        if (!userSub->registryMsgIds.empty())
        {
            auto obj = std::find(userSub->registryMsgIds.begin(),
                                 userSub->registryMsgIds.end(), messageKey);
            if (obj == userSub->registryMsgIds.end())
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

bool Subscription::sendTestEventLog(TestEvent& testEvent)
{
    nlohmann::json::array_t logEntryArray;
    nlohmann::json& logEntryJson = logEntryArray.emplace_back();

    if (testEvent.eventGroupId)
    {
        logEntryJson["EventGroupId"] = *testEvent.eventGroupId;
    }

    if (testEvent.eventId)
    {
        logEntryJson["EventId"] = *testEvent.eventId;
    }

    if (testEvent.eventTimestamp)
    {
        logEntryJson["EventTimestamp"] = *testEvent.eventTimestamp;
    }
    else
    {
        logEntryJson["EventTimestamp"] =
            redfish::time_utils::getDateTimeOffsetNow().first;
    }

    if (testEvent.originOfCondition)
    {
        logEntryJson["OriginOfCondition"]["@odata.id"] =
            *testEvent.originOfCondition;
    }
    else
    {
        logEntryJson["OriginOfCondition"]["@odata.id"] =
            "/redfish/v1/EventService/Actions/EventService.SubmitTestEvent";
    }

    if (testEvent.severity)
    {
        logEntryJson["Severity"] = *testEvent.severity;
    }
    else
    {
        logEntryJson["Severity"] = "OK";
    }

    if (testEvent.message)
    {
        logEntryJson["Message"] = *testEvent.message;
    }
    else
    {
        logEntryJson["Message"] = "SubmitTestEvent Action has been triggered";
    }

    if (testEvent.resolution)
    {
        logEntryJson["Resolution"] = *testEvent.resolution;
    }

    if (testEvent.messageId)
    {
        logEntryJson["MessageId"] = *testEvent.messageId;
    }

    if (testEvent.messageArgs)
    {
        logEntryJson["MessageArgs"] = *testEvent.messageArgs;
    }
    else
    {
        logEntryJson["MessageArgs"] = {*testEvent.eventId};
    }

    // MemberId is 0 : since we are sending one event record.
    logEntryJson["MemberId"] = "0";
    //  Adding EventType property as "Other" since it is deprecated but a
    //  required property
    logEntryJson["EventType"] = "Other";
    logEntryJson["Context"] = "Test_Event_Subcription";

    nlohmann::json msg;
    msg["@odata.type"] = json_util::odataType("Event");
    msg["Id"] = std::to_string(eventSeqNum);
    msg["Name"] = "Event Log";
    msg["Events@odata.count"] = logEntryArray.size();
    msg["Events"] = std::move(logEntryArray);
    msg["Context"] = "Test_Event_Subcription";

    std::string strMsg =
        msg.dump(2, ' ', true, nlohmann::json::error_handler_t::replace);
    return sendEventToSubscriber(std::move(strMsg));
}

bool Subscription::sendTestSNMPTrap()
{
    std::string timestamp = redfish::time_utils::getDateTimeOffsetNow().first;
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

    try
    {
        this->sendSNMPTrap(static_cast<uint32_t>(eventSeqNum), timeString, "Ok",
                           msg);
    }
    catch (const std::exception& e)
    {
        BMCWEB_LOG_ERROR("bmcweb: Exception in sendSNMPTrap: ");
        return false;
    }
    return true;
}

void Subscription::filterAndSendEventLogs(
    const std::vector<EventLogObjectsType>& eventRecords)
{
    nlohmann::json::array_t logEntryArray;
    for (const EventLogObjectsType& logEntry : eventRecords)
    {
        BMCWEB_LOG_DEBUG("Processing logEntry: {}, {} '{}'", logEntry.id,
                         logEntry.timestamp, logEntry.messageId);
        std::vector<std::string_view> messageArgsView(
            logEntry.messageArgs.begin(), logEntry.messageArgs.end());
        std::string origin = getOrigin(logEntry.sensorType);
        std::string memberId = std::to_string(eventSeqNum);

        nlohmann::json::object_t bmcLogEntry;
        if (event_log::formatEventLogEntry(
                logEntry.id, logEntry.messageId, messageArgsView,
                logEntry.timestamp, userSub->customText, origin, memberId,
                logEntry.registryName, bmcLogEntry) != 0)
        {
            BMCWEB_LOG_DEBUG("Read eventLog entry failed");
            continue;
        }

        if (!eventMatchesFilter(*userSub, bmcLogEntry, ""))
        {
            BMCWEB_LOG_DEBUG("Read eventLog entry failed");
            continue;
        }

        if (filter)
        {
            if (!memberMatches(bmcLogEntry, *filter))
            {
                BMCWEB_LOG_DEBUG("Filter didn't match");
                continue;
            }
        }

        logEntryArray.emplace_back(std::move(bmcLogEntry));
    }

    if (logEntryArray.empty())
    {
        BMCWEB_LOG_DEBUG("No log entries available to be transferred.");
        return;
    }

    nlohmann::json msg;
    msg["@odata.type"] = json_util::odataType("Event");
    msg["Id"] = std::to_string(eventSeqNum);
    msg["Name"] = "Event Log";
    msg["Context"] = userSub->customText;
    msg["Events@odata.count"] = logEntryArray.size();
    msg["Events"] = std::move(logEntryArray);
    std::string strMsg =
        msg.dump(2, ' ', true, nlohmann::json::error_handler_t::replace);
    sendEventToSubscriber(std::move(strMsg));
    eventSeqNum++;
}

void Subscription::filterAndSendReports(const std::string& reportId,
                                        const telemetry::TimestampReadings& var)
{
    boost::urls::url mrdUri = boost::urls::format(
        "/redfish/v1/TelemetryService/MetricReportDefinitions/{}", reportId);

    // Empty list means no filter. Send everything.
    if (!userSub->metricReportDefinitions.empty())
    {
        if (std::ranges::find(userSub->metricReportDefinitions,
                              mrdUri.buffer()) ==
            userSub->metricReportDefinitions.end())
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
    if (!userSub->customText.empty())
    {
        msg["Context"] = userSub->customText;
    }

    std::string strMsg =
        msg.dump(2, ' ', true, nlohmann::json::error_handler_t::replace);
    sendEventToSubscriber(std::move(strMsg));
}

void Subscription::updateRetryConfig(uint32_t retryAttempts,
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

uint64_t Subscription::getEventSeqNum() const
{
    return eventSeqNum;
}

std::optional<std::string> Subscription::getSubscriptionId(
    const std::shared_ptr<crow::sse_socket::Connection>& connPtr)
{
    if (sseConn != nullptr && connPtr == sseConn)
    {
        BMCWEB_LOG_DEBUG("{} conn matched, subId: {}", __FUNCTION__,
                         userSub->id);
        return userSub->id;
    }

    return std::nullopt;
}

boost::system::error_code Subscription::retryRespHandler(unsigned int respCode)
{
    BMCWEB_LOG_DEBUG("Checking response code validity for SubscriptionEvent");
    if ((respCode < 200) || (respCode >= 300))
    {
        return boost::system::errc::make_error_code(
            boost::system::errc::result_out_of_range);
    }

    // Return 0 if the response code is valid
    return boost::system::errc::make_error_code(boost::system::errc::success);
}
std::string Subscription::getOrigin(const int& sensorTypeCode)
{
    if (sensorTypeCode == 24 || sensorTypeCode == 5)
    {
        return "/redfish/v1/Chassis/AC_Baseboard";
    }
    else if (sensorTypeCode == 1 || sensorTypeCode == 4)
    {
        return "/redfish/v1/Chassis/AC_Baseboard/ThermalSubsystem";
    }
    else if (sensorTypeCode == 2 || sensorTypeCode == 3 ||
             sensorTypeCode == 8 || sensorTypeCode == 9)
    {
        return "/redfish/v1/Chassis/AC_Baseboard/Power";
    }
    else if (sensorTypeCode == 15 || sensorTypeCode == 18 ||
             sensorTypeCode == 29 || sensorTypeCode == 30 ||
             sensorTypeCode == 31 || sensorTypeCode == 32 ||
             sensorTypeCode == 34)
    {
        return "/redfish/v1/Systems/system";
    }
    else if (sensorTypeCode == 12)
    {
        return "/redfish/v1/Systems/system/Memory";
    }
    else if (sensorTypeCode == 7)
    {
        return "/redfish/v1/Systems/system/Processors";
    }
    else if (sensorTypeCode == 6 || sensorTypeCode == 10 ||
             sensorTypeCode == 11 || sensorTypeCode == 13 ||
             sensorTypeCode == 14 || sensorTypeCode == 16 ||
             sensorTypeCode == 17 || sensorTypeCode == 19 ||
             sensorTypeCode == 20 || sensorTypeCode == 21 ||
             sensorTypeCode == 22 || sensorTypeCode == 23 ||
             sensorTypeCode == 25 || sensorTypeCode == 26 ||
             sensorTypeCode == 27 || sensorTypeCode == 28 ||
             sensorTypeCode == 33 || sensorTypeCode == 35 ||
             sensorTypeCode == 36 || sensorTypeCode == 37 ||
             sensorTypeCode == 38 || sensorTypeCode == 39 ||
             sensorTypeCode == 40 || sensorTypeCode == 41 ||
             sensorTypeCode == 42 || sensorTypeCode == 43 ||
             sensorTypeCode == 44)
    {
        return "/redfish/v1/Managers/bmc";
    }
    else
    {
        return "/redfish/v1";
    }
}

} // namespace redfish
