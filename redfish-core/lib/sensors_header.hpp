#pragma once

namespace redfish
{
namespace sensors
{
constexpr std::string_view powerNodeStr;
constexpr std::string_view thermalNodeStr;
void handleSensorGet(App& app, const crow::Request& req,
                     const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                     const std::string& chassisId, const std::string& sensorId);
void getSensorFromDbus(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                       const std::string& sensorPath,
                       const ::dbus::utility::MapperGetObject& mapperResponse);
void getSensorReading(const std::string& sensorPath,
                      std::function<void(const std::string&)> callback);
} // namespace sensors
} // namespace redfish
