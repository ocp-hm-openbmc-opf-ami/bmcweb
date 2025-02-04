/*
// Copyright (c) 2022 Intel Corporation
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
#include "ossl_random.hpp"

#include <errno.h>
#include <sys/inotify.h>

#include <boost/asio/io_context.hpp>
#include <boost/container/flat_map.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/error_condition.hpp>
#include <boost/system/generic_category.hpp>
#include <boost/system/result.hpp>
#include <boost/url/grammar/error.hpp>
#include <boost/url/parse.hpp>
#include <boost/url/url_view.hpp>
#include <certificate_service.hpp>
#include <dbus_utility.hpp>
#include <error_messages.hpp>
#include <event_service_store.hpp>
#include <http/utility.hpp>
#include <http_client.hpp>
#include <persistent_data.hpp>
#include <sdbusplus/bus/match.hpp>
#include <utils/json_utils.hpp>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <memory>
#include <span>

namespace redfish
{

struct KafkaConfig
{
    std::string mainBroker;
    std::vector<std::string> additionalBrokers;
    std::string topic;
    uint32_t schemaId;
    uint32_t sInterval;
    std::string certUri;
    std::string context;
};

static constexpr const char* kafkaConfigFile =
    "/var/lib/bmcweb/kafka_config.json";
constexpr int initConfigMaxNumOfRetries = 10;
constexpr int initConfigTimeoutInSeconds = 5;

class KafkaManager : public std::enable_shared_from_this<KafkaManager>
{
  private:
    boost::asio::io_context& ioc;
    bool configTimerStarted = false;
    int numOfRetries = 0;
    KafkaManager(boost::asio::io_context& iocIn) : ioc(iocIn)
    {
        // Load config from persist store.
        initConfig();
    }

    boost::container::flat_map<std::string, KafkaConfig> subscriptionsMap;
    bool configPmtResourceError;

    bool parseAndValidateDestination(const std::string& dest,
                                     std::shared_ptr<bmcweb::AsyncResp> aResp,
                                     std::string_view fieldName,
                                     std::string& authority)
    {
        constexpr const char* defaultScheme = "ssl://";
        boost::system::result<boost::urls::url_view> url =
            boost::urls::parse_uri(dest);

        if (!url)
        {
            int ec = url.error().value();
            if ((ec ==
                 static_cast<int>(boost::urls::grammar::error::need_more)) ||
                (ec == static_cast<int>(boost::urls::grammar::error::mismatch)))
            {
                // need_more appears when destination=hostname.
                // mismatch appears when destination=IPv4/IPv6(:port).
                // Appending scheme string to the beginning resolves both.
                std::string destWithScheme = defaultScheme + dest;
                return parseAndValidateDestination(destWithScheme, aResp,
                                                   fieldName, authority);
            }
            else
            {
                BMCWEB_LOG_WARNING("Failed to parse URL {}: {}", dest,
                                   url.error());
                messages::propertyValueFormatError(aResp->res, dest, fieldName);
                return false;
            }
        }

        if (!url->has_authority())
        {
            std::string destWithScheme = defaultScheme + dest;
            return parseAndValidateDestination(destWithScheme, aResp, fieldName,
                                               authority);
        }

        if (url->scheme() != "ssl")
        {
            BMCWEB_LOG_WARNING("Invalid scheme for URL: {}", dest);
            messages::propertyValueFormatError(aResp->res, dest, fieldName);
            return false;
        }

        if (url->host_type() == boost::urls::host_type::none)
        {
            BMCWEB_LOG_WARNING("Invalid host data for URL: {}", dest);
            messages::propertyValueFormatError(aResp->res, dest, fieldName);
            return false;
        }

        authority = url->encoded_authority();
        return true;
    }

    bool validateTopic(const std::string& topic,
                       std::shared_ptr<bmcweb::AsyncResp> aResp)
    {
        constexpr size_t maxTopicLength = 249;

        if (topic.size() > maxTopicLength)
        {
            BMCWEB_LOG_WARNING("Kafka topic is too long");
            messages::propertyValueFormatError(aResp->res, topic, "KafkaTopic");
            return false;
        }

        ssize_t validCount = std::count_if(topic.begin(), topic.end(),
                                           [](unsigned char c) {
            return (std::isalnum(c) || (c == '-') || (c == '_') || (c == '.'));
        });

        if (validCount != static_cast<ssize_t>(topic.size()))
        {
            BMCWEB_LOG_WARNING("Invalid Kafka topic: {}", topic);
            messages::propertyValueFormatError(aResp->res, topic, "KafkaTopic");
            return false;
        }

        return true;
    }

    bool validateInterval(const uint32_t intervalMs,
                          std::shared_ptr<bmcweb::AsyncResp> aResp)
    {
        constexpr uint32_t minIntervalMs = 1000;

        if (intervalMs < minIntervalMs)
        {
            BMCWEB_LOG_WARNING("Invalid streaming intervalMs: {}", intervalMs);
            messages::propertyValueFormatError(aResp->res, intervalMs,
                                               "StreamingRateMs");
            return false;
        }

        return true;
    }

    bool validateSchemaId(const uint32_t schemaId,
                          std::shared_ptr<bmcweb::AsyncResp> aResp)
    {
        if (schemaId > std::numeric_limits<int32_t>::max())
        {
            BMCWEB_LOG_WARNING("Invalid schema ID value: {}", schemaId);
            messages::propertyValueFormatError(aResp->res, schemaId,
                                               "AvroSchemaId");
            return false;
        }

        return true;
    }

    void getCertificate(
        const KafkaConfig& subData,
        std::function<void(const boost::system::error_code&,
                           std::optional<std::string>)>&& callback)
    {
        constexpr std::string_view uriBase =
            "/redfish/v1/Managers/bmc/Truststore/Certificates/";

        if (!subData.certUri.starts_with(uriBase))
        {
            BMCWEB_LOG_ERROR("Invalid URI: {}", subData.certUri);
            callback(boost::system::errc::make_error_code(
                         boost::system::errc::bad_address),
                     std::nullopt);
            return;
        }

        std::string certId = subData.certUri.substr(uriBase.size());
        std::string objPath =
            sdbusplus::message::object_path(certs::authorityObjectPath) /
            certId;

        dbus::utility::getProperty<std::string>(
            certs::authorityServiceName, objPath, certs::certPropIntf,
            "CertificateString",
            [callback(std::move(callback))](const boost::system::error_code& ec,
                                            const std::string& certString) {
                if (ec)
                {
                    callback(ec, std::nullopt);
                    return;
                }

                callback(ec, certString);
            });
    }

  public:
    KafkaManager(const KafkaManager&) = delete;
    KafkaManager& operator=(const KafkaManager&) = delete;
    KafkaManager(KafkaManager&&) = delete;
    KafkaManager& operator=(KafkaManager&&) = delete;
    ~KafkaManager() = default;

    static KafkaManager& getInstance(boost::asio::io_context* iocIn = nullptr)
    {
        static KafkaManager handler(*iocIn);
        return handler;
    }

    inline std::string genSubscriptionId()
    {
        std::uniform_int_distribution<uint32_t> dist(0);
        bmcweb::OpenSSLGenerator gen;
        std::string id;

        id = std::to_string(dist(gen));
        if (gen.error())
        {
            BMCWEB_LOG_ERROR("Failed to generate random number");
            return "";
        }

        return id;
    }

    inline void readJsonAndAddToMap(const nlohmann::json& j)
    {
        KafkaConfig subData;
        std::string subId;

        for (const auto& element : j.items())
        {
            if (element.key() == "Id")
            {
                const std::string* value =
                    element.value().get_ptr<const std::string*>();
                if (value == nullptr)
                {
                    continue;
                }
                subId = *value;
            }
            if (element.key() == "Destination")
            {
                const std::string* value =
                    element.value().get_ptr<const std::string*>();
                if (value == nullptr)
                {
                    continue;
                }
                subData.mainBroker = *value;
            }
            if (element.key() == "Context")
            {
                const std::string* value =
                    element.value().get_ptr<const std::string*>();
                if (value == nullptr)
                {
                    continue;
                }
                subData.context = *value;
            }
            if (element.key() == "KafkaTopic")
            {
                const std::string* value =
                    element.value().get_ptr<const std::string*>();
                if (value == nullptr)
                {
                    continue;
                }
                subData.topic = *value;
            }
            else if (element.key() == "AdditionalDestinations")
            {
                const auto& obj = element.value();
                for (const auto& val : obj.items())
                {
                    const std::string* value =
                        val.value().get_ptr<const std::string*>();
                    if (value == nullptr)
                    {
                        continue;
                    }
                    subData.additionalBrokers.emplace_back(*value);
                }
            }
            else if (element.key() == "AvroSchemaId")
            {
                const uint64_t* value =
                    element.value().get_ptr<const uint64_t*>();
                if ((value == nullptr) ||
                    (*value > std::numeric_limits<uint32_t>::max()))
                {
                    continue;
                }
                subData.schemaId = static_cast<uint32_t>(*value);
            }
            else if (element.key() == "StreamingRateMs")
            {
                const uint64_t* value =
                    element.value().get_ptr<const uint64_t*>();
                if ((value == nullptr) ||
                    (*value > std::numeric_limits<uint32_t>::max()))
                {
                    continue;
                }
                subData.sInterval = static_cast<uint32_t>(*value);
            }
            else if (element.key() == "CertificateUri")
            {
                const std::string* value =
                    element.value().get_ptr<const std::string*>();
                if ((value == nullptr))
                {
                    continue;
                }
                subData.certUri = *value;
            }
        }

        if (subId.empty())
        {
            BMCWEB_LOG_ERROR("Failed to subscription ID.");
            return;
        }

        // TODO: The following needs to be changed for 2 reasons:
        // 1) Async callbacks don't work properly at this particular stage of
        //    service lifetime. There needs to be one request sent to BMC in
        //    order to enter callbacks. Otherwise they'll fail after timeout.
        // 2) There's no proper synchronization mechanism between this and the
        //    PMT service. For now it is assumed that subscriptions are still
        //    present on the latter, but this might not be true.
        auto afterCertGet = [this, subId,
                             subData](const boost::system::error_code& ec,
                                      std::optional<std::string> certString) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("Failed to get certificate from {}: {}",
                                 subData.certUri, ec);
                return;
            }

            std::vector<std::string> brokers;
            brokers.push_back(subData.mainBroker);
            brokers.insert(brokers.end(), subData.additionalBrokers.begin(),
                           subData.additionalBrokers.end());

            crow::connections::systemBus->async_method_call(
                [this, subId, subData](const boost::system::error_code& ec2,
                                       const bool result) {
                if (ec2)
                {
                    configPmtResourceError = true;
                    BMCWEB_LOG_ERROR(
                        "Failed to subscribe for Kafka streaming.");
                    return;
                }
                if (!result)
                {
                    BMCWEB_LOG_ERROR("PMT failed to add streaming destination");
                    return;
                }
                subscriptionsMap.insert(std::pair(subId, subData));
            },
                "xyz.openbmc_project.Pmt", "/xyz/openbmc_project/Pmt",
                "xyz.openbmc_project.Pmt.StreamingDestination",
                "UpdateStreamingDestination", subId, brokers, subData.topic,
                subData.schemaId, subData.sInterval, *certString);
        };

        getCertificate(subData, std::move(afterCertGet));

        return;
    }

    void initConfigErrorCheck()
    {
        if (configTimerStarted)
        {
            return;
        }

        if (initConfigMaxNumOfRetries <= numOfRetries)
        {
            BMCWEB_LOG_ERROR(
                "Kafka config initialization fail. Exceeded number of retries.");
            return;
        }

        configTimerStarted = true;
        static boost::asio::steady_timer timeout(ioc);
        timeout.expires_after(std::chrono::seconds(initConfigTimeoutInSeconds));

        timeout.async_wait([this](const boost::system::error_code& ec) {
            configTimerStarted = false;
            numOfRetries++;
            if (ec == boost::asio::error::operation_aborted)
            {
                // completed.
                return;
            }
            if (configPmtResourceError)
            {
                BMCWEB_LOG_ERROR(
                    "Kafka config was not initialized due to PMT unavailability, retrying.");
                initConfig();
            }
        });
    }

    void initConfig()
    {
        std::ifstream cfgFile(kafkaConfigFile);
        configPmtResourceError = false;
        if (!cfgFile.good())
        {
            BMCWEB_LOG_DEBUG("Kafka config file not exist");
            return;
        }
        auto jsonData = nlohmann::json::parse(cfgFile, nullptr, false);
        if (jsonData.is_discarded())
        {
            BMCWEB_LOG_ERROR("Kafka config file parse error.");
            return;
        }

        subscriptionsMap.clear();
        for (const auto& item : jsonData.items())
        {
            if (item.key() == "Subscriptions")
            {
                for (const auto& elem : item.value())
                {
                    readJsonAndAddToMap(elem);
                }
            }
        }

        initConfigErrorCheck();
    }

    inline void WriteToFile()
    {
        std::ofstream cfgFile(kafkaConfigFile);
        if (!cfgFile.good())
        {
            BMCWEB_LOG_DEBUG("Kafka config file not exist");
            return;
        }
        nlohmann::json data;
        nlohmann::json& subscriptions = data["Subscriptions"];

        for (const auto& it : subscriptionsMap)
        {
            KafkaConfig subData = it.second;
            std::string subId = it.first;
            subscriptions.push_back({
                {"Id", subId},
                {"Destination", subData.mainBroker},
                {"Context", subData.context},
                {"KafkaTopic", subData.topic},
                {"AdditionalDestinations", subData.additionalBrokers},
                {"AvroSchemaId", subData.schemaId},
                {"StreamingRateMs", subData.sInterval},
                {"CertificateUri", subData.certUri},
            });
        }
        cfgFile << data;
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

    /**
     * @brief Handles the delete request for Kafka protocol
     *
     * @param[in] subId  Subscription Id to be removed
     * @param[out] aResp  Shared pointer for completing asynchronous calls.
     *
     * @return None.
     */
    inline void getSubscription(const std::string& subId,
                                std::shared_ptr<bmcweb::AsyncResp> aResp)
    {
        BMCWEB_LOG_DEBUG("Kafka subscription GET request.");

        auto obj = subscriptionsMap.find(subId);
        if (obj == subscriptionsMap.end())
        {
            aResp->res.result(boost::beast::http::status::not_found);
            return;
        }

        KafkaConfig subData = obj->second;

        std::string refLink = "/redfish/v1/EventService/Subscriptions/" + subId;
        aResp->res.jsonValue["@odata.type"] =
            "#EventDestination.v1_9_0.EventDestination";
        aResp->res.jsonValue["@odata.id"] =
            "/redfish/v1/EventService/Subscriptions/" + subId;
        aResp->res.jsonValue["Id"] = subId;
        aResp->res.jsonValue["Name"] = "Event Destination " + subId;
        aResp->res.jsonValue["SubscriptionType"] = "OEM";
        aResp->res.jsonValue["OEMSubscriptionType"] = "Kafka";
        aResp->res.jsonValue["Protocol"] = "OEM";
        aResp->res.jsonValue["OEMProtocol"] = "Avro";
        aResp->res.jsonValue["Oem"]["@odata.id"] = refLink + "#/Oem";
        aResp->res.jsonValue["Oem"]["@odata.type"] = "#OemEventDestination.Oem";
        aResp->res.jsonValue["Oem"]["Intel"]["@odata.id"] = refLink +
                                                            "#/Oem/Intel";
        aResp->res.jsonValue["Oem"]["Intel"]["@odata.type"] =
            "#OemEventDestination.Intel";
        nlohmann::json& kafkaObj =
            aResp->res.jsonValue["Oem"]["Intel"]["Kafka"];
        nlohmann::json& brokerArray = kafkaObj["AdditionalDestinations"];
        brokerArray = nlohmann::json::array();

        aResp->res.jsonValue["Destination"] = subData.mainBroker;
        aResp->res.jsonValue["Context"] = subData.context;
        kafkaObj["@odata.id"] = refLink + "#/Oem/Intel/Kafka";
        kafkaObj["@odata.type"] = "#OemEventDestination.Kafka";
        kafkaObj["KafkaTopic"] = subData.topic;
        kafkaObj["AvroSchemaId"] = subData.schemaId;
        kafkaObj["StreamingRateMs"] = subData.sInterval;
        kafkaObj["CertificateUri"] = subData.certUri;
        for (const std::string& entry : subData.additionalBrokers)
        {
            brokerArray.push_back(entry);
        }
        aResp->res.result(boost::beast::http::status::ok);
        return;
    }
    /**
     * @brief Handles the Oem request which support Kafka protocol
     *
     * @param[in] oemObject Oem Object passed in request
     * @param[in] dest  KafkaBroker passed as destination in request
     * @param[in] aResp     Shared pointer for completing asynchronous calls.
     *
     * @return None.
     */
    inline void createSubscription(nlohmann::json& oemObject,
                                   const std::string& dest,
                                   std::optional<std::string> context,
                                   std::shared_ptr<bmcweb::AsyncResp> aResp)
    {
        BMCWEB_LOG_DEBUG("Kafka subscription CREATE request.");
        nlohmann::json kafkaObj;
        nlohmann::json intelObj;

        std::string mainBroker;
        if (!parseAndValidateDestination(dest, aResp, "Destination",
                                         mainBroker))
        {
            return;
        }

        if (!json_util::readJson(oemObject, aResp->res, "Intel", intelObj))
        {
            return;
        }

        if (!json_util::readJson(intelObj, aResp->res, "Kafka", kafkaObj))
        {
            return;
        }

        KafkaConfig subData;
        std::optional<std::vector<std::string>> addDest;
        if (!json_util::readJson(kafkaObj, aResp->res, "AdditionalDestinations",
                                 addDest, "KafkaTopic", subData.topic,
                                 "AvroSchemaId", subData.schemaId,
                                 "StreamingRateMs", subData.sInterval,
                                 "CertificateUri", subData.certUri))
        {
            return;
        }

        if (!validateTopic(subData.topic, aResp) ||
            !validateInterval(subData.sInterval, aResp) ||
            !validateSchemaId(subData.schemaId, aResp))
        {
            return;
        }

        subData.mainBroker = mainBroker;

        if (context)
        {
            subData.context = *context;
        }

        if (addDest)
        {
            for (const auto& entry : *addDest)
            {
                std::string subBroker;
                if (!parseAndValidateDestination(
                        entry, aResp, "AdditionalDestinations", subBroker))
                {
                    return;
                }
                subData.additionalBrokers.emplace_back(subBroker);
            }
        }

        std::string subId = genSubscriptionId();
        if (subId.empty())
        {
            BMCWEB_LOG_ERROR("Failed to generate random number.");
            messages::internalError(aResp->res);
            return;
        }

        auto afterCertGet = [this, aResp, subId,
                             subData](const boost::system::error_code& ec,
                                      std::optional<std::string> certString) {
            if (ec)
            {
                if (ec == boost::system::error_condition(
                              EBADR, boost::system::generic_category()))
                {
                    BMCWEB_LOG_ERROR("CA certificate wasn't found under {}",
                                     subData.certUri);
                    messages::resourceNotFound(aResp->res, "CA Certificate",
                                               subData.certUri);
                }
                else
                {
                    BMCWEB_LOG_ERROR("Error on getting certificate: {}", ec);
                    messages::internalError(aResp->res);
                }
                return;
            }

            std::vector<std::string> brokers;
            brokers.push_back(subData.mainBroker);
            brokers.insert(brokers.end(), subData.additionalBrokers.begin(),
                           subData.additionalBrokers.end());

            std::erase_if(brokers,
                          [](const auto& broker) { return broker.empty(); });
            if (brokers.empty())
            {
                BMCWEB_LOG_ERROR(
                    "Empty Kafka Brokers Destinations while creating a subscription.");
                messages::propertyValueFormatError(aResp->res, "<empty>",
                                                   "Destination");
                return;
            }

            crow::connections::systemBus->async_method_call(
                [this, aResp, subId, subData, certString](
                    const boost::system::error_code& ec2, const bool result) {
                if (ec2)
                {
                    BMCWEB_LOG_ERROR(
                        "Failed to subscribe for Kafka streaming.");
                    messages::internalError(aResp->res);
                    return;
                }

                if (!result)
                {
                    BMCWEB_LOG_ERROR("PMT failed to add streaming destination");
                    messages::internalError(aResp->res);
                    return;
                }

                subscriptionsMap.insert(std::pair(subId, subData));
                WriteToFile();
                messages::success(aResp->res);
            },
                "xyz.openbmc_project.Pmt", "/xyz/openbmc_project/Pmt",
                "xyz.openbmc_project.Pmt.StreamingDestination",
                "AddStreamingDestination", subId, brokers, subData.topic,
                subData.schemaId, subData.sInterval, *certString);
        };

        getCertificate(subData, std::move(afterCertGet));

        return;
    }

    /**
     * @brief Handles the delete request for Kafka protocol
     *
     * @param[in] subId  Subscription Id to be removed
     * @param[out] aResp  Shared pointer for completing asynchronous calls.
     *
     * @return None.
     */
    inline void deleteSubscription(const std::string& subId,
                                   std::shared_ptr<bmcweb::AsyncResp> aResp)
    {
        BMCWEB_LOG_DEBUG("Kafka subscription DELETE request.");

        auto obj = subscriptionsMap.find(subId);
        if (obj == subscriptionsMap.end())
        {
            aResp->res.result(boost::beast::http::status::not_found);
            return;
        }

        crow::connections::systemBus->async_method_call(
            [this, aResp, subId](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("No kafka subscription found");
                aResp->res.result(boost::beast::http::status::not_found);
                return;
            }
            subscriptionsMap.erase(subId);
            WriteToFile();
            messages::success(aResp->res);
            aResp->res.result(boost::beast::http::status::ok);
        },
            "xyz.openbmc_project.Pmt", "/xyz/openbmc_project/Pmt",
            "xyz.openbmc_project.Pmt.StreamingDestination",
            "RemoveStreamingDestination", subId);

        return;
    }

    /**
     * @brief Handles the  Kafka subscription patch request
     *
     * @param[in] req     Request body passed in patch.
     * @param[in] aResp   Shared pointer for completing asynchronous calls.
     *
     * @return None.
     */
    inline void updateSubscription(const crow::Request& req,
                                   const std::string& subId,
                                   std::shared_ptr<bmcweb::AsyncResp> aResp)
    {
        BMCWEB_LOG_DEBUG("Kafka subscription UPDATE request.");

        auto obj = subscriptionsMap.find(subId);
        if (obj == subscriptionsMap.end())
        {
            aResp->res.result(boost::beast::http::status::not_found);
            return;
        }

        KafkaConfig subData = obj->second;

        std::optional<std::string> dest;
        std::optional<nlohmann::json> oemObject;
        std::optional<std::string> context;
        if (!json_util::readJsonPatch(req, aResp->res, "Destination", dest,
                                      "Context", context, "Oem", oemObject))
        {
            return;
        }
        if (!dest && !oemObject && !context)
        {
            BMCWEB_LOG_ERROR("Kafka subscription Patch - Invalid body.");
            aResp->res.result(boost::beast::http::status::not_found);
            return;
        }

        nlohmann::json kafkaObj;
        if (!json_util::readJson(*oemObject, aResp->res, "Intel", kafkaObj))
        {
            return;
        }

        if (dest)
        {
            std::string mainBroker;
            if (!parseAndValidateDestination(*dest, aResp, "Destination",
                                             mainBroker))
            {
                return;
            }
            subData.mainBroker = mainBroker;
        }

        if (context)
        {
            subData.context = *context;
        }

        std::optional<std::vector<std::string>> addDest;
        std::optional<std::string> topic;
        std::optional<uint32_t> schemaId;
        std::optional<uint32_t> streamRate;
        std::optional<std::string> certUri;

        if (!json_util::readJson(kafkaObj, aResp->res, "AdditionalDestinations",
                                 addDest, "KafkaTopic", topic, "AvroSchemaId",
                                 schemaId, "StreamingRateMs", streamRate,
                                 "CertificateUri", certUri))
        {
            return;
        }

        if (addDest)
        {
            for (const auto& entry : *addDest)
            {
                std::string subBroker;
                if (!parseAndValidateDestination(
                        entry, aResp, "AdditionalDestinations", subBroker))
                {
                    return;
                }
                subData.additionalBrokers.emplace_back(subBroker);
            }
        }

        if (topic)
        {
            if (!validateTopic(*topic, aResp))
            {
                return;
            }
            subData.topic = *topic;
        }

        if (schemaId)
        {
            if (!validateSchemaId(*schemaId, aResp))
            {
                return;
            }
            subData.schemaId = *schemaId;
        }

        if (streamRate)
        {
            if (!validateInterval(*streamRate, aResp))
            {
                return;
            }
            subData.sInterval = *streamRate;
        }

        if (certUri)
        {
            subData.certUri = *certUri;
        }

        auto afterCertGet = [this, aResp, subId,
                             subData](const boost::system::error_code& ec,
                                      std::optional<std::string> certString) {
            if (ec)
            {
                if (ec == boost::system::error_condition(
                              EBADR, boost::system::generic_category()))
                {
                    BMCWEB_LOG_ERROR("CA certificate wasn't found under {}",
                                     subData.certUri);
                    messages::resourceNotFound(aResp->res, "CA Certificate",
                                               subData.certUri);
                }
                else
                {
                    BMCWEB_LOG_ERROR("Error on getting certificate: {}", ec);
                    messages::internalError(aResp->res);
                }
                return;
            }

            std::vector<std::string> brokers;
            brokers.push_back(subData.mainBroker);
            brokers.insert(brokers.end(), subData.additionalBrokers.begin(),
                           subData.additionalBrokers.end());

            std::erase_if(brokers,
                          [](const auto& broker) { return broker.empty(); });
            if (brokers.empty())
            {
                BMCWEB_LOG_ERROR(
                    "Empty Kafka Brokers Destinations while updating a subscription.");
                messages::propertyValueFormatError(aResp->res, "<empty>",
                                                   "Destination");
                return;
            }

            subscriptionsMap.erase(subId);

            crow::connections::systemBus->async_method_call(
                [this, aResp, subId, subData, certString](
                    const boost::system::error_code& ec2, const bool result) {
                if (ec2)
                {
                    BMCWEB_LOG_ERROR("Failed to update Kafka subscription.");
                    messages::internalError(aResp->res);
                    return;
                }

                if (!result)
                {
                    BMCWEB_LOG_ERROR(
                        "PMT failed to update streaming destination");
                    messages::internalError(aResp->res);
                    return;
                }

                subscriptionsMap.insert(std::pair(subId, subData));
                WriteToFile();
                messages::success(aResp->res);
            },
                "xyz.openbmc_project.Pmt", "/xyz/openbmc_project/Pmt",
                "xyz.openbmc_project.Pmt.StreamingDestination",
                "UpdateStreamingDestination", subId, brokers, subData.topic,
                subData.schemaId, subData.sInterval, *certString);
        };

        getCertificate(subData, std::move(afterCertGet));

        return;
    }
};
} // namespace redfish
