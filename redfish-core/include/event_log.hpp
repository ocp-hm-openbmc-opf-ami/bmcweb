#pragma once

#include <nlohmann/json.hpp>

#include <span>
#include <string>
#include <string_view>

namespace redfish
{

namespace event_log
{

bool getUniqueEntryID(const std::string& logEntry, std::string& entryID);

int getEventLogParams(const std::string& logEntry, std::string& timestamp,
                      std::string& messageID,
                      std::vector<std::string>& messageArgs);

int getDbusEventLogParams(const std::string& logEntry, std::string& messageID,
                          std::vector<std::string>& messageArgs);

int formatEventLogEntry(
    const std::string& logEntryID, const std::string& messageID,
    std::span<std::string_view> messageArgs, std::string timestamp,
    const std::string& customText, const std::string& origin,
    const std::string& memberId, const std::string& registryName, nlohmann::json::object_t& logEntryJson);

} // namespace event_log

} // namespace redfish
