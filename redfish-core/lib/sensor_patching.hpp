#pragma once

#include <app.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/container/flat_map.hpp>
#include <boost/range/algorithm/replace_copy_if.hpp>
#include <dbus_singleton.hpp>
#include <dbus_utility.hpp>
#include <registries/privilege_registry.hpp>
#include <sdbusplus/asio/property.hpp>
#include <utils/json_utils.hpp>

#include <cmath>
#include <utility>
#include <variant>

namespace redfish
{

/**
 * @brief Entry point for overriding sensor values of given sensor
 *
 * @param sensorAsyncResp   response object
 * @param overrideMap   Collections of sensors to be updated
 */
inline void
    setSensor(const std::shared_ptr<SensorsAsyncResp>& sensorAsyncResp,
              std::unordered_map<std::string, std::pair<double, std::string>>&
                  overrideMap)
{
    auto getChassisSensorListCb = [sensorAsyncResp, overrideMap](
                                      const std::shared_ptr<
                                          std::set<std::string>>& sensorsList) {
        // Match sensor names in the PATCH request to those managed by the
        // chassis node
        const std::shared_ptr<std::set<std::string>> sensorNames =
            std::make_shared<std::set<std::string>>();
        for (const auto& item : overrideMap)
        {
            const auto& sensor = item.first;
            if (!findSensorNameUsingSensorPath(sensor, *sensorsList,
                                               *sensorNames))
            {
                BMCWEB_LOG_INFO("Unable to find memberId {}", item.first);
                messages::resourceNotFound(sensorAsyncResp->asyncResp->res,
                                           item.second.second, item.first);
                return;
            }
        }
        // Get the connection to which the memberId belongs
        auto getObjectsWithConnectionCb = [sensorAsyncResp, overrideMap](
                                              const std::set<
                                                  std::string>& /*connections*/,
                                              const std::set<std::pair<
                                                  std::string, std::string>>&
                                                  objectsWithConnection) {
            if (objectsWithConnection.size() != overrideMap.size())
            {
                BMCWEB_LOG_INFO(
                    "Unable to find all objects with proper connection {} requested {}",
                    objectsWithConnection.size(), overrideMap.size());
                messages::resourceNotFound(
                    sensorAsyncResp->asyncResp->res,
                    sensorAsyncResp->chassisSubNode ==
                            sensor_utils::chassisSubNodeToString(
                                sensor_utils::ChassisSubNode::thermalNode)
                        ? "Temperatures"
                        : "Voltages",
                    "Count");
                return;
            }
            for (const auto& item : objectsWithConnection)
            {
                sdbusplus::message::object_path path(item.first);
                std::string sensorName = path.filename();
                if (sensorName.empty())
                {
                    messages::internalError(sensorAsyncResp->asyncResp->res);
                    return;
                }

                const auto& iterator = overrideMap.find(sensorName);
                if (iterator == overrideMap.end())
                {
                    BMCWEB_LOG_INFO("Unable to find sensor object {}",
                                    item.first);
                    messages::internalError(sensorAsyncResp->asyncResp->res);
                    return;
                }
                crow::connections::systemBus->async_method_call(
                    [sensorAsyncResp](const boost::system::error_code ec) {
                        if (ec)
                        {
                            BMCWEB_LOG_DEBUG(
                                "setOverrideValueStatus DBUS error: {}", ec);
                            messages::internalError(
                                sensorAsyncResp->asyncResp->res);
                            return;
                        }
                    },
                    item.second, item.first, "org.freedesktop.DBus.Properties",
                    "Set", "xyz.openbmc_project.Sensor.Value", "Value",
                    std::variant<double>(iterator->second.first));
            }
        };
        // Get object with connection for the given sensor name
        getObjectsWithConnection(sensorAsyncResp, sensorNames,
                                 std::move(getObjectsWithConnectionCb));
    };
    // get full sensor list for the given chassisId and cross verify the sensor.
    getChassis(sensorAsyncResp->asyncResp, sensorAsyncResp->chassisId,
               sensorAsyncResp->chassisSubNode, sensorAsyncResp->types,
               std::move(getChassisSensorListCb));
}

inline void requestRoutesSensorPatching(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Chassis/<str>/Sensors/<str>/")
        .privileges(redfish::privileges::patchSensor)
        .methods(boost::beast::http::verb::patch)(
            [](const crow::Request& req,
               const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
               const std::string& chassisName, const std::string&) {

                asyncResp->res.clearHeader(boost::beast::http::field::allow);
                asyncResp->res.addHeader("Allow", "GET, PATCH");

                crow::connections::systemBus->async_method_call(
                [asyncResp, chassisName,
                 req](const boost::system::error_code ec_,
                      const std::vector<std::string>& chassisPaths) {
                    if (ec_)

                    {
                        BMCWEB_LOG_ERROR(
                            "D-Bus call error while validating chassis ID");
                        asyncResp->res.result(
                            boost::beast::http::status::internal_server_error);
                        return;
                    }

                    // Extract valid chassis IDs from the D-Bus paths
                    bool isValid = false;
                    for (const std::string& objpath : chassisPaths)
                    {
                        std::size_t lastPos = objpath.rfind('/');
                        if (lastPos != std::string::npos)
                        {
                            std::string extractedChassisId =
                                objpath.substr(lastPos + 1);
                            std::cerr
                                << "extractedChassisId: " << extractedChassisId
                                << "\n";
                            std::cerr << "chassisId: " << chassisName << "\n";

                            if (extractedChassisId == chassisName)
                            {
                                isValid = true;
                                break;
                            }
                        }
                    }

                    if (!isValid)
                    {
                        messages::resourceNotFound(asyncResp->res, chassisName,
                                                   "chassisId");
                        return;
                    }
                    else
                    {
                        std::unordered_map<std::string,
                                           std::pair<double, std::string>>
                            overrideMap;
                        std::string memberId;
                        double value = 0;

                        auto sensorsAsyncResp =
                            std::make_shared<SensorsAsyncResp>(
                                asyncResp, chassisName,
                                sensors::dbus::sensorPaths,
                                sensors::sensorsNodeStr);

                        if (!json_util::readJsonPatch( //
                                req, sensorsAsyncResp->asyncResp->res, //
                                "Id", memberId, //
                                "Reading", value //
                                ))
                        {
                            return;
                        }

                        std::pair<std::string, std::string> nameType =
                            redfish::sensor_utils::splitSensorNameAndType(
                                memberId);
                        overrideMap.emplace(nameType.second,
                                            std::make_pair(value, "Reading"));
                        setSensor(sensorsAsyncResp, overrideMap);
                    }
                },
                "xyz.openbmc_project.ObjectMapper",
                "/xyz/openbmc_project/object_mapper",
                "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths",
                "/xyz/openbmc_project/inventory", 0,
                std::array<const char*, 2>{
                    "xyz.openbmc_project.Inventory.Item.Board",
                    "xyz.openbmc_project.Inventory.Item.Chassis"});
            });
}
} // namespace redfish
