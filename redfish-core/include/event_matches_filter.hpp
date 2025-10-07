#pragma once

#include "generated/enums/log_entry.hpp"
#include "logging.hpp"
#include "persistent_data.hpp"
#include "str_utility.hpp"

#include <nlohmann/json.hpp>

#include <ranges>
#include <string>
#include <string_view>
#include <vector>

namespace redfish
{

inline void getRegistryAndMessageKey(const std::string& messageID,
                                     std::string& registryName,
                                     std::string& messageKey)
{
    size_t pos = messageID.find_last_of('.'); // Find the last comma
    std::string lastValue = (pos != std::string::npos) ? messageID.substr(pos + 1) : messageID; // Extract last value
    size_t pos1 = messageID.find(".");	
    if (pos != std::string::npos) {
        registryName = (pos1 != std::string::npos) ? messageID.substr(0, pos1) : messageID;
        messageKey = lastValue;
    }
    else
    {
        registryName = "OpenBMC";
        messageKey = messageID;
    }
    messageKey.erase(std::remove(messageKey.begin(), messageKey.end(), ' '),
                     messageKey.end());
}

inline bool eventMatchesFilter(const persistent_data::UserSubscription& userSub,
                               const nlohmann::json::object_t& eventMessage,
                               std::string_view resType)
{
    // If resourceTypes list is empty, assume all
    if (!userSub.resourceTypes.empty())
    {
        // Search the resourceTypes list for the subscription.
        auto resourceTypeIndex = std::ranges::find_if(
            userSub.resourceTypes, [resType](const std::string& rtEntry) {
                return rtEntry == resType;
            });
        if (resourceTypeIndex == userSub.resourceTypes.end())
        {
            BMCWEB_LOG_DEBUG("Not subscribed to this resource");
            return false;
        }
        BMCWEB_LOG_DEBUG("ResourceType {} found in the subscribed list",
                         resType);
    }

    // If registryPrefixes list is empty, don't filter events
    // send everything.
    if (!userSub.registryPrefixes.empty())
    {
        auto eventJson = eventMessage.find("MessageId");
        if (eventJson == eventMessage.end())
        {
            return false;
        }
        const std::string* messageId =
            eventJson->second.get_ptr<const std::string*>();
        if (messageId == nullptr)
        {
            BMCWEB_LOG_ERROR("MessageId wasn't a string???");
            return false;
        }
        std::string registry;
        std::string messageKey;
        getRegistryAndMessageKey(*messageId, registry, messageKey);
        auto obj = std::ranges::find(userSub.registryPrefixes, registry);
        if (obj == userSub.registryPrefixes.end())
        {
            return false;
        }
    }
    if (!userSub.originResources.empty())
    {
        auto eventJson = eventMessage.find("OriginOfCondition");
        if (eventJson == eventMessage.end())
        {
            return false;
        }
        const std::string* originOfCondition =
            eventJson->second.get_ptr<const std::string*>();
        if (originOfCondition == nullptr)
        {
            BMCWEB_LOG_ERROR("OriginOfCondition wasn't a string???");
            return false;
        }
        auto obj =
            std::ranges::find(userSub.originResources, *originOfCondition);

        if (obj == userSub.originResources.end())
        {
            return false;
        }
    }

    // If registryMsgIds list is empty, assume all
    if (!userSub.registryMsgIds.empty())
    {
        auto eventJson = eventMessage.find("MessageId");
        if (eventJson == eventMessage.end())
        {
            return false;
        }
        const std::string* messageId =
            eventJson->second.get_ptr<const std::string*>();
        if (messageId == nullptr)
        {
            BMCWEB_LOG_ERROR("EventType wasn't a string???");
            return false;
        }
        std::string registry;
        std::string messageKey;
        getRegistryAndMessageKey(*messageId, registry, messageKey);
        auto obj = std::ranges::find(
            userSub.registryMsgIds, std::format("{}.{}", registry, messageKey));
        if (obj == userSub.registryMsgIds.end())
        {
            return false;
        }
    }
    return true;
}

} // namespace redfish
