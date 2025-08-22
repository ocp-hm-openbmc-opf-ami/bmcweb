// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#include "registries.hpp"

#include "registries_selector.hpp"
#include "str_utility.hpp"

#include <algorithm>
#include <cstring>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace redfish::registries
{

const Message* getMessageFromRegistry(const std::string& messageKey,
                                      std::span<const MessageEntry> registry)
{
    std::span<const MessageEntry>::iterator messageIt = std::ranges::find_if(
        registry, [&messageKey](const MessageEntry& messageEntry) {
            return std::strcmp(messageEntry.first, messageKey.c_str()) == 0;
        });
    if (messageIt != registry.end())
    {
        return &messageIt->second;
    }

    return nullptr;
}

const Message* getMessage(std::string_view messageID)
{
    // Redfish MessageIds are in the form
    // RegistryName.MajorVersion.MinorVersion.MessageKey, so parse it to find
    // the right Message
    std::vector<std::string> fields;
    fields.reserve(4);
    bmcweb::split(fields, messageID, '.');

    if (fields.size() != 4)
    {
        return nullptr;
    }

    const std::string& registryName = fields[0];
    const std::string& messageKey = fields[3];

    // Find the right registry and check it for the MessageKey
    return getMessageFromRegistry(messageKey,
                                  getRegistryFromPrefix(registryName));
}

const Message* formatMessage(std::string messageID)
{
    // Find the right registry and check it for the MessageKey
    size_t pos = messageID.find_last_of('.'); // Find the last comma
    std::string lastValue = (pos != std::string::npos) ? messageID.substr(pos + 1) : messageID; // Extract last value
	size_t pos1 = messageID.find(".");	
	std::string registryName;
	if (pos != std::string::npos) {
		registryName = (pos1 != std::string::npos) ? messageID.substr(0, pos1) : messageID;
        std::string messageKey = lastValue;
		messageKey.erase(std::remove(messageKey.begin(), messageKey.end(), ' '),
                     messageKey.end());
		return getMessageFromRegistry(messageKey, getRegistryFromPrefix(registryName));
	}
	else
	{
        registryName = "OpenBMC";
        std::string messageKey = messageID;
        messageKey.erase(std::remove(messageKey.begin(), messageKey.end(), ' '),
                     messageKey.end());
        return getMessageFromRegistry(messageKey, getRegistryFromPrefix(registryName));
    }
}

} // namespace redfish::registries
