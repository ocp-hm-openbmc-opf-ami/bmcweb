// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
// SPDX-FileCopyrightText: Copyright 2018 Intel Corporation
#pragma once

#include "app.hpp"
#include "dbus_singleton.hpp"
#include "dbus_utility.hpp"
#include "generated/enums/redundancy.hpp"
#include "generated/enums/resource.hpp"
#include "query.hpp"
#include "registries/privilege_registry.hpp"
#include "str_utility.hpp"
#include "utils/dbus_utils.hpp"
#include "utils/json_utils.hpp"
#include "utils/query_param.hpp"
#include "utils/sensor_utils.hpp"

#include <boost/system/error_code.hpp>
#include <boost/url/format.hpp>
#include <sdbusplus/asio/property.hpp>
#include <sdbusplus/unpack_properties.hpp>

#include <array>
#include <cmath>
#include <iterator>
#include <limits>
#include <map>
#include <ranges>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

using SensorCallback =
    std::function<void(const std::vector<std::string>& stringState)>;

namespace redfish
{

namespace sensors
{

// clang-format off
namespace dbus
{
constexpr auto powerPaths = std::to_array<std::string_view>({
    "/xyz/openbmc_project/sensors/power"
});

constexpr auto getSensorPaths(){
    if constexpr(BMCWEB_REDFISH_NEW_POWERSUBSYSTEM_THERMALSUBSYSTEM){
    return std::to_array<std::string_view>({
        "/xyz/openbmc_project/sensors/power",
        "/xyz/openbmc_project/sensors/frequency",
        "/xyz/openbmc_project/sensors/current",
        "/xyz/openbmc_project/sensors/airflow",
	"/xyz/openbmc_project/sensors/count",
        "/xyz/openbmc_project/sensors/humidity",
        "/xyz/openbmc_project/sensors/voltage",
        "/xyz/openbmc_project/sensors/fan_tach",
        "/xyz/openbmc_project/sensors/temperature",
        "/xyz/openbmc_project/sensors/fan_pwm",
        "/xyz/openbmc_project/sensors/altitude",
        "/xyz/openbmc_project/sensors/energy",
        "/xyz/openbmc_project/sensors/utilization",
	    "/xyz/openbmc_project/sensors/cpu",
        "/xyz/openbmc_project/sensors/bmcfirmwarehealth",
        "/xyz/openbmc_project/sensors/acpidevice",
        "/xyz/openbmc_project/sensors/acpisystem",
        "/xyz/openbmc_project/sensors/battery",
        "/xyz/openbmc_project/sensors/chassisstate",
        "/xyz/openbmc_project/sensors/os",
        "/xyz/openbmc_project/sensors/watchdog",
	    "/xyz/openbmc_project/sensors/logging",
        "/xyz/openbmc_project/sensors/flowrate",
        "/xyz/openbmc_project/sensors/tach",
        "/xyz/openbmc_project/sensors/pwm",
        "/xyz/openbmc_project/sensors/hours",
        "/xyz/openbmc_project/sensors/pressurekpa",
        "/xyz/openbmc_project/sensors/discrete",
	"/xyz/openbmc_project/sensors/count/"});
    } else {
      return  std::to_array<std::string_view>({"/xyz/openbmc_project/sensors/power",
        "/xyz/openbmc_project/sensors/current",
        "/xyz/openbmc_project/sensors/count",
        "/xyz/openbmc_project/sensors/airflow",
        "/xyz/openbmc_project/sensors/humidity",
        "/xyz/openbmc_project/sensors/temperature",
        "/xyz/openbmc_project/sensors/chassisstate",
        "/xyz/openbmc_project/sensors/battery",
        "/xyz/openbmc_project/sensors/acpidevice",
        "/xyz/openbmc_project/sensors/utilization",
        "/xyz/openbmc_project/sensors/powerunit",
        "/xyz/openbmc_project/sensors/acpisystem",
        "/xyz/openbmc_project/sensors/powersupply",
        "/xyz/openbmc_project/sensors/os"
        });
}
}

constexpr auto sensorPaths = getSensorPaths();

constexpr auto thermalPaths = std::to_array<std::string_view>({
    "/xyz/openbmc_project/sensors/fan_tach",
    "/xyz/openbmc_project/sensors/temperature",
    "/xyz/openbmc_project/sensors/fan_pwm"
});

} // namespace dbus
// clang-format on

constexpr std::string_view powerNodeStr = sensor_utils::chassisSubNodeToString(
    sensor_utils::ChassisSubNode::powerNode);
constexpr std::string_view sensorsNodeStr =
    sensor_utils::chassisSubNodeToString(
        sensor_utils::ChassisSubNode::sensorsNode);
constexpr std::string_view thermalNodeStr =
    sensor_utils::chassisSubNodeToString(
        sensor_utils::ChassisSubNode::thermalNode);

using sensorPair =
    std::pair<std::string_view, std::span<const std::string_view>>;
static constexpr std::array<sensorPair, 3> paths = {
    {{sensors::powerNodeStr, dbus::powerPaths},
     {sensors::sensorsNodeStr, dbus::sensorPaths},
     {sensors::thermalNodeStr, dbus::thermalPaths}}};

} // namespace sensors

/**
 * SensorsAsyncResp
 * Gathers data needed for response processing after async calls are done
 */
class SensorsAsyncResp
{
  public:
    using DataCompleteCb = std::function<void(
        const boost::beast::http::status status,
        const std::map<std::string, std::string>& uriToDbus)>;

    struct SensorData
    {
        std::string name;
        std::string uri;
        std::string dbusPath;
    };

    SensorsAsyncResp(const std::shared_ptr<bmcweb::AsyncResp>& asyncRespIn,
                     const std::string& chassisIdIn,
                     std::span<const std::string_view> typesIn,
                     std::string_view subNode) :
        asyncResp(asyncRespIn), chassisId(chassisIdIn), types(typesIn),
        chassisSubNode(subNode), efficientExpand(false)
    {}

    // Store extra data about sensor mapping and return it in callback
    SensorsAsyncResp(const std::shared_ptr<bmcweb::AsyncResp>& asyncRespIn,
                     const std::string& chassisIdIn,
                     std::span<const std::string_view> typesIn,
                     std::string_view subNode,
                     DataCompleteCb&& creationComplete) :
        asyncResp(asyncRespIn), chassisId(chassisIdIn), types(typesIn),
        chassisSubNode(subNode), efficientExpand(false),
        metadata{std::vector<SensorData>()},
        dataComplete{std::move(creationComplete)}
    {}

    // sensor collections expand
    SensorsAsyncResp(const std::shared_ptr<bmcweb::AsyncResp>& asyncRespIn,
                     const std::string& chassisIdIn,
                     std::span<const std::string_view> typesIn,
                     const std::string_view& subNode, bool efficientExpandIn) :
        asyncResp(asyncRespIn), chassisId(chassisIdIn), types(typesIn),
        chassisSubNode(subNode), efficientExpand(efficientExpandIn)
    {}

    ~SensorsAsyncResp()
    {
        if (asyncResp->res.result() ==
            boost::beast::http::status::internal_server_error)
        {
            // Reset the json object to clear out any data that made it in
            // before the error happened todo(ed) handle error condition with
            // proper code
            asyncResp->res.jsonValue = nlohmann::json::object();
        }

        if (dataComplete && metadata)
        {
            std::map<std::string, std::string> map;
            if (asyncResp->res.result() == boost::beast::http::status::ok)
            {
                for (auto& sensor : *metadata)
                {
                    map.emplace(sensor.uri, sensor.dbusPath);
                }
            }
            dataComplete(asyncResp->res.result(), map);
        }
    }

    SensorsAsyncResp(const SensorsAsyncResp&) = delete;
    SensorsAsyncResp(SensorsAsyncResp&&) = delete;
    SensorsAsyncResp& operator=(const SensorsAsyncResp&) = delete;
    SensorsAsyncResp& operator=(SensorsAsyncResp&&) = delete;

    void addMetadata(const nlohmann::json& sensorObject,
                     const std::string& dbusPath)
    {
        if (metadata)
        {
            metadata->emplace_back(SensorData{
                sensorObject["Name"], sensorObject["@odata.id"], dbusPath});
        }
    }

    void updateUri(const std::string& name, const std::string& uri)
    {
        if (metadata)
        {
            for (auto& sensor : *metadata)
            {
                if (sensor.name == name)
                {
                    sensor.uri = uri;
                }
            }
        }
    }

    const std::shared_ptr<bmcweb::AsyncResp> asyncResp;
    const std::string chassisId;
    const std::span<const std::string_view> types;
    const std::string chassisSubNode;
    const bool efficientExpand;

  private:
    std::optional<std::vector<SensorData>> metadata;
    DataCompleteCb dataComplete;
};
using InventoryItem = sensor_utils::InventoryItem;
/**
 * @brief Get objects with connection necessary for sensors
 * @param SensorsAsyncResp Pointer to object holding response data
 * @param sensorNames Sensors retrieved from chassis
 * @param callback Callback for processing gathered connections
 */
template <typename Callback>
void getObjectsWithConnection(
    const std::shared_ptr<SensorsAsyncResp>& sensorsAsyncResp,
    const std::shared_ptr<std::set<std::string>>& sensorNames,
    Callback&& callback)
{
    BMCWEB_LOG_DEBUG("getObjectsWithConnection enter");
    const std::string path = "/xyz/openbmc_project/sensors";
    constexpr std::array<std::string_view, 1> interfaces = {
        "xyz.openbmc_project.Sensor.Value"};

    // Make call to ObjectMapper to find all sensors objects
    dbus::utility::getSubTree(
        path, 2, interfaces,
        [callback = std::forward<Callback>(callback), sensorsAsyncResp,
         sensorNames](const boost::system::error_code& ec,
                      const dbus::utility::MapperGetSubTreeResponse& subtree) {
            // Response handler for parsing objects subtree
            BMCWEB_LOG_DEBUG("getObjectsWithConnection resp_handler enter");
            if (ec)
            {
                messages::internalError(sensorsAsyncResp->asyncResp->res);
                BMCWEB_LOG_ERROR(
                    "getObjectsWithConnection resp_handler: Dbus error {}", ec);
                return;
            }

            BMCWEB_LOG_DEBUG("Found {} subtrees", subtree.size());

            // Make unique list of connections only for requested sensor types
            // and found in the chassis
            std::set<std::string> connections;
            std::set<std::pair<std::string, std::string>> objectsWithConnection;

            BMCWEB_LOG_DEBUG("sensorNames list count: {}", sensorNames->size());
            for (const std::string& tsensor : *sensorNames)
            {
                BMCWEB_LOG_DEBUG("Sensor to find: {}", tsensor);
            }

            for (const std::pair<std::string,
                                 std::vector<std::pair<
                                     std::string, std::vector<std::string>>>>&
                     object : subtree)
            {
                if (sensorNames->find(object.first) != sensorNames->end())
                {
                    for (const std::pair<std::string, std::vector<std::string>>&
                             objData : object.second)
                    {
                        BMCWEB_LOG_DEBUG("Adding connection: {}",
                                         objData.first);
                        connections.insert(objData.first);
                        objectsWithConnection.insert(
                            std::make_pair(object.first, objData.first));
                    }
                }
            }
            BMCWEB_LOG_DEBUG("Found {} connections", connections.size());
            callback(std::move(connections), std::move(objectsWithConnection));
            BMCWEB_LOG_DEBUG("getObjectsWithConnection resp_handler exit");
        });
    BMCWEB_LOG_DEBUG("getObjectsWithConnection exit");
}

/**
 * @brief Create connections necessary for sensors
 * @param SensorsAsyncResp Pointer to object holding response data
 * @param sensorNames Sensors retrieved from chassis
 * @param callback Callback for processing gathered connections
 */
template <typename Callback>
void getConnections(const std::shared_ptr<SensorsAsyncResp>& sensorsAsyncResp,
                    const std::shared_ptr<std::set<std::string>>& sensorNames,
                    Callback&& callback)
{
    auto objectsWithConnectionCb =
        [callback = std::forward<Callback>(callback)](
            const std::set<std::string>& connections,
            const std::set<std::pair<std::string, std::string>>&
            /*objectsWithConnection*/) { callback(connections); };
    getObjectsWithConnection(sensorsAsyncResp, sensorNames,
                             std::move(objectsWithConnectionCb));
}

/**
 * @brief Shrinks the list of sensors for processing
 * @param SensorsAysncResp  The class holding the Redfish response
 * @param allSensors  A list of all the sensors associated to the
 * chassis element (i.e. baseboard, front panel, etc...)
 * @param activeSensors A list that is a reduction of the incoming
 * allSensors list.  Eliminate Thermal sensors when a Power request is
 * made, and eliminate Power sensors when a Thermal request is made.
 */
inline void reduceSensorList(
    crow::Response& res, std::string_view chassisSubNode,
    std::span<const std::string_view> sensorTypes,
    const std::vector<std::string>* allSensors,
    const std::shared_ptr<std::set<std::string>>& activeSensors)
{
    if ((allSensors == nullptr) || (activeSensors == nullptr))
    {
        messages::resourceNotFound(res, chassisSubNode,
                                   chassisSubNode == sensors::thermalNodeStr
                                       ? "Temperatures"
                                       : "Voltages");

        return;
    }
    if (allSensors->empty())
    {
        // Nothing to do, the activeSensors object is also empty
        return;
    }

    for (std::string_view type : sensorTypes)
    {
        for (const std::string& sensor : *allSensors)
        {
            if (sensor.starts_with(type))
            {
                activeSensors->emplace(sensor);
            }
        }
    }
}

/*
 *Populates the top level collection for a given subnode.  Populates
 *SensorCollection, Power, or Thermal schemas.
 *
 * */
inline void populateChassisNode(nlohmann::json& jsonValue,
                                std::string_view chassisSubNode)
{
    if (chassisSubNode == sensors::thermalNodeStr)
    {
        jsonValue["@odata.type"] = json_util::odataType("Thermal");
        jsonValue["Fans"] = nlohmann::json::array();
        jsonValue["Temperatures"] = nlohmann::json::array();
        jsonValue["Id"] = chassisSubNode;
    }
    else if (chassisSubNode == sensors::sensorsNodeStr)
    {
        jsonValue["@odata.type"] = "#SensorCollection.SensorCollection";
        jsonValue["Description"] = "Collection of Sensors for this Chassis";
        jsonValue["Members"] = nlohmann::json::array();
        jsonValue["Members@odata.count"] = 0;
    }

    if (chassisSubNode != sensors::powerNodeStr)
    {
        jsonValue["Name"] = chassisSubNode;
    }
}

/**
 * @brief Retrieves requested chassis sensors and redundancy data from DBus .
 * @param SensorsAsyncResp   Pointer to object holding response data
 * @param callback  Callback for next step in gathered sensor processing
 */
template <typename Callback>
void getChassis(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                std::string_view chassisId, std::string_view chassisSubNode,
                std::span<const std::string_view> sensorTypes,
                Callback&& callback)
{
    BMCWEB_LOG_DEBUG("getChassis enter");
    constexpr std::array<std::string_view, 2> interfaces = {
        "xyz.openbmc_project.Inventory.Item.Board",
        "xyz.openbmc_project.Inventory.Item.Chassis"};

    // Get the Chassis Collection
    dbus::utility::getSubTreePaths(
        "/xyz/openbmc_project/inventory", 0, interfaces,
        [callback = std::forward<Callback>(callback), asyncResp,
         chassisIdStr{std::string(chassisId)},
         chassisSubNode{std::string(chassisSubNode)},
         sensorTypes](const boost::system::error_code& ec,
                      const dbus::utility::MapperGetSubTreePathsResponse&
                          chassisPaths) mutable {
            BMCWEB_LOG_DEBUG("getChassis respHandler enter");
            if (ec)
            {
                BMCWEB_LOG_ERROR("getChassis respHandler DBUS error: {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }
            const std::string* chassisPath = nullptr;
            for (const std::string& chassis : chassisPaths)
            {
                sdbusplus::message::object_path path(chassis);
                std::string chassisName = path.filename();
                if (chassisName.empty())
                {
                    BMCWEB_LOG_ERROR("Failed to find '/' in {}", chassis);
                    continue;
                }
                if (chassisName == chassisIdStr)
                {
                    chassisPath = &chassis;
                    break;
                }
            }
            if (chassisPath == nullptr)
            {
                messages::resourceNotFound(asyncResp->res, "Chassis",
                                           chassisIdStr);
                return;
            }
            populateChassisNode(asyncResp->res.jsonValue, chassisSubNode);

            if (chassisSubNode != sensors::powerNodeStr)
            {
                asyncResp->res.jsonValue["@odata.id"] = boost::urls::format(
                    "/redfish/v1/Chassis/{}/{}", chassisIdStr, chassisSubNode);
            }

            // Get the list of all sensors for this Chassis element
            std::string sensorPath = *chassisPath + "/all_sensors";
            dbus::utility::getAssociationEndPoints(
                sensorPath, [asyncResp, chassisSubNode, sensorTypes,
                             callback = std::forward<Callback>(callback)](
                                const boost::system::error_code& ec2,
                                const dbus::utility::MapperEndPoints&
                                    nodeSensorList) mutable {
                    if (ec2)
                    {
                        if (ec2.value() != EBADR)
                        {
                            messages::internalError(asyncResp->res);
                            return;
                        }
                    }
                    const std::shared_ptr<std::set<std::string>>
                        culledSensorList =
                            std::make_shared<std::set<std::string>>();
                    reduceSensorList(asyncResp->res, chassisSubNode,
                                     sensorTypes, &nodeSensorList,
                                     culledSensorList);
                    BMCWEB_LOG_DEBUG("Finishing with {}",
                                     culledSensorList->size());
                    callback(culledSensorList);
                });
        });
    BMCWEB_LOG_DEBUG("getChassis exit");
}

inline void getPsuState(InventoryItem* inventoryItem)
{
    if (inventoryItem != nullptr)
    {
        size_t strPos = (inventoryItem->name).find_last_of('_');
        dbus::utility::getAllProperties(
            "xyz.openbmc_project.PSUSensor",
            "/xyz/openbmc_project/sensors/voltage/" +
                inventoryItem->name.substr(strPos + 1) + "_Input_Voltage",
            "",
            [inventoryItem](
                const boost::system::error_code& ec,
                const ::dbus::utility::DBusPropertiesMap& valuesDict) {
                if (ec)
                {
                    return;
                }
                bool connected = false;
                double value;
                for (const auto& [valueName, valueVariant] : valuesDict)
                {
                    if (valueName == "Functional")
                    {
                        connected = std::get<bool>(valueVariant);
                    }
                    if (valueName == "Value")
                    {
                        value = std::get<double>(valueVariant);
                    }
                }
                if (connected)
                {
                    if (value > 0)
                    {
                        inventoryItem->psuState = "Enabled";
                    }
                    else
                    {
                        inventoryItem->psuState = "UnavailableOffline";
                    }
                }
                else
                {
                    inventoryItem->psuState = "Disabled";
                }
            });
    }
    else
    {
        inventoryItem->psuState = "Disabled";
    }
}

inline void sensorState(uint16_t value, std::string objPath,
                        std::string_view sensorType,
                        const SensorCallback callback)
{
    uint16_t position = 0;
    std::vector<uint16_t> positions;
    std::map<std::string, std::string> type = {
        {"cpu", "Cpustatus"},
        {"watchdog", "watchdog"},
        {"acpisystem", "ACPISystem"},
        {"powersupply", "Powersupply"},
        {"powerunit", "Powerunit"},
        {"os", "OSCritical"},
        {"acpidevice", "ACPIDevice"},
        {"battery", "Battery"},
        {"bmcfirmwarehealth", "BMCFirwareHealth"},
        {"chassisstate", "Digital"},
        {"discrete", "APISensor"},
        {"discrete", "APISensor2"},
        {"discrete", "APISensor3"},
        {"discrete", "APISensor4"},
        {"discrete", "APISensor5"},
        {"discrete", "APISensor6"},
        {"discrete", "APISensor7"},
        {"discrete", "APISensor8"},
        {"discrete", "APISensor9"},
        {"discrete", "APISensor10"}};
    auto it = type.find(std::string(sensorType));
    if (it != type.end())
    {
        while (value > 0)
        {
            if (value & 1)
            {
                positions.push_back(position);
            }
            value >>= 1;
            position++;
        }
        std::string interFace =
            "xyz.openbmc_project.Configuration." + it->second;
        auto asyncCallback =
            [positions,
             callback](const boost::system::error_code ec,
                       const std::variant<std::vector<std::string>>& state) {
                if (ec)
                {
                    // BMCWEB_LOG_DEBUG << "DBUS response error " << ec;
                    BMCWEB_LOG_DEBUG("DBUS response error {}", ec);
                    return;
                }
                if (auto* stateVector =
                        std::get_if<std::vector<std::string>>(&state))
                {
                    if (!stateVector->empty())
                    {
                        std::vector<std::string> stateSensor;
                        for (auto& itr : positions)
                        {
                            stateSensor.push_back(stateVector->at(itr));
                        }
                        callback(stateSensor);
                    }
                }
            };
        crow::connections::systemBus->async_method_call(
            asyncCallback, "xyz.openbmc_project.EntityManager", objPath,
            "org.freedesktop.DBus.Properties", "Get", interFace, "State");
    }
}

/**
 * @brief Builds a json sensor representation of a sensor.
 * @param sensorName  The name of the sensor to be built
 * @param sensorType  The type (temperature, fan_tach, etc) of the sensor to
 * build
 * @param chassisSubNode The subnode (thermal, sensor, etc) of the sensor
 * @param interfacesDict  A dictionary of the interfaces and properties of said
 * interfaces to be built from
 * @param sensorJson  The json object to fill
 * @param inventoryItem D-Bus inventory item associated with the sensor.  Will
 * be nullptr if no associated inventory item was found.
 */
inline void objectInterfacesToJson(
    const std::string& sensorName, const std::string& sensorType,
    const sensor_utils::ChassisSubNode chassisSubNode,
    const dbus::utility::DBusInterfacesMap& interfacesDict,
    nlohmann::json& sensorJson, InventoryItem* inventoryItem)
{
    for (const auto& [interface, valuesDict] : interfacesDict)
    {
        sensor_utils::objectPropertiesToJson(
            sensorName, sensorType, chassisSubNode, valuesDict, sensorJson,
            inventoryItem);
    }
    BMCWEB_LOG_DEBUG("Added sensor {}", sensorName);
}

inline void populateFanRedundancy(
    const std::shared_ptr<SensorsAsyncResp>& sensorsAsyncResp)
{
    constexpr std::array<std::string_view, 1> interfaces = {
        "xyz.openbmc_project.Control.FanRedundancy"};
    dbus::utility::getSubTree(
        "/xyz/openbmc_project/control", 2, interfaces,
        [sensorsAsyncResp](
            const boost::system::error_code& ec,
            const dbus::utility::MapperGetSubTreeResponse& resp) {
            if (ec)
            {
                return; // don't have to have this interface
            }
            for (const std::pair<std::string, dbus::utility::MapperServiceMap>&
                     pathPair : resp)
            {
                const std::string& path = pathPair.first;
                const dbus::utility::MapperServiceMap& objDict =
                    pathPair.second;
                if (objDict.empty())
                {
                    continue; // this should be impossible
                }

                const std::string& owner = objDict.begin()->first;
                dbus::utility::getAssociationEndPoints(
                    path + "/chassis",
                    [path, owner, sensorsAsyncResp](
                        const boost::system::error_code& ec2,
                        const dbus::utility::MapperEndPoints& endpoints) {
                        if (ec2)
                        {
                            return; // if they don't have an association we
                                    // can't tell what chassis is
                        }
                        auto found = std::ranges::find_if(
                            endpoints,
                            [sensorsAsyncResp](const std::string& entry) {
                                return entry.find(
                                           sensorsAsyncResp->chassisId) !=
                                       std::string::npos;
                            });

                        if (found == endpoints.end())
                        {
                            return;
                        }
                        dbus::utility::getAllProperties(
                            owner, path,
                            "xyz.openbmc_project.Control.FanRedundancy",
                            [path, sensorsAsyncResp](
                                const boost::system::error_code& ec3,
                                const dbus::utility::DBusPropertiesMap& ret) {
                                if (ec3)
                                {
                                    return; // don't have to have this
                                            // interface
                                }

                                const uint8_t* allowedFailures = nullptr;
                                const std::vector<std::string>* collection =
                                    nullptr;
                                const std::string* status = nullptr;

                                const bool success =
                                    sdbusplus::unpackPropertiesNoThrow(
                                        dbus_utils::UnpackErrorPrinter(), ret,
                                        "AllowedFailures", allowedFailures,
                                        "Collection", collection, "Status",
                                        status);

                                if (!success)
                                {
                                    messages::internalError(
                                        sensorsAsyncResp->asyncResp->res);
                                    return;
                                }

                                if (allowedFailures == nullptr ||
                                    collection == nullptr || status == nullptr)
                                {
                                    BMCWEB_LOG_ERROR(
                                        "Invalid redundancy interface");
                                    messages::internalError(
                                        sensorsAsyncResp->asyncResp->res);
                                    return;
                                }

                                sdbusplus::message::object_path objectPath(
                                    path);
                                std::string name = objectPath.filename();
                                if (name.empty())
                                {
                                    // this should be impossible
                                    messages::internalError(
                                        sensorsAsyncResp->asyncResp->res);
                                    return;
                                }
                                std::ranges::replace(name, '_', ' ');

                                std::string health;

                                if (status->ends_with("Full"))
                                {
                                    health = "OK";
                                }
                                else if (status->ends_with("Degraded"))
                                {
                                    health = "Warning";
                                }
                                else
                                {
                                    health = "Critical";
                                }
                                nlohmann::json::array_t redfishCollection;
                                const auto& fanRedfish =
                                    sensorsAsyncResp->asyncResp->res
                                        .jsonValue["Fans"];
                                for (const std::string& item : *collection)
                                {
                                    sdbusplus::message::object_path itemPath(
                                        item);
                                    std::string itemName = itemPath.filename();
                                    if (itemName.empty())
                                    {
                                        continue;
                                    }
                                    /*
                                    todo(ed): merge patch that fixes the names
                                    std::replace(itemName.begin(),
                                                 itemName.end(), '_', ' ');*/
                                    auto schemaItem = std::ranges::find_if(
                                        fanRedfish,
                                        [itemName](const nlohmann::json& fan) {
                                            return fan["Name"] == itemName;
                                        });
                                    if (schemaItem != fanRedfish.end())
                                    {
                                        nlohmann::json::object_t collectionId;
                                        collectionId["@odata.id"] =
                                            (*schemaItem)["@odata.id"];
                                        redfishCollection.emplace_back(
                                            std::move(collectionId));
                                    }
                                    else
                                    {
                                        BMCWEB_LOG_ERROR(
                                            "failed to find fan in schema");
                                        messages::internalError(
                                            sensorsAsyncResp->asyncResp->res);
                                        return;
                                    }
                                }

                                size_t minNumNeeded =
                                    collection->empty()
                                        ? 0
                                        : collection->size() - *allowedFailures;
                                nlohmann::json& jResp =
                                    sensorsAsyncResp->asyncResp->res
                                        .jsonValue["Redundancy"];

                                nlohmann::json::object_t redundancy;
                                boost::urls::url url = boost::urls::format(
                                    "/redfish/v1/Chassis/{}/{}",
                                    sensorsAsyncResp->chassisId,
                                    sensorsAsyncResp->chassisSubNode);
                                url.set_fragment(
                                    ("/Redundancy"_json_pointer / jResp.size())
                                        .to_string());
                                redundancy["@odata.id"] = std::move(url);
                                redundancy["@odata.type"] =
                                    json_util::odataType("Redundancy");
                                redundancy["MinNumNeeded"] = minNumNeeded;
                                redundancy["Mode"] =
                                    redundancy::RedundancyType::NPlusM;
                                redundancy["Name"] = name;
                                redundancy["RedundancySet"] = redfishCollection;
                                redundancy["Status"]["Health"] = health;
                                redundancy["Status"]["State"] =
                                    resource::State::Enabled;

                                jResp.emplace_back(std::move(redundancy));
                            });
                    });
            }
        });
}

inline void sortJSONResponse(
    const std::shared_ptr<SensorsAsyncResp>& sensorsAsyncResp)
{
    nlohmann::json& response = sensorsAsyncResp->asyncResp->res.jsonValue;
    std::array<std::string, 2> sensorHeaders{"Temperatures", "Fans"};
    if (sensorsAsyncResp->chassisSubNode == sensors::powerNodeStr)
    {
        sensorHeaders = {"Voltages", "PowerSupplies"};
    }
    for (const std::string& sensorGroup : sensorHeaders)
    {
        nlohmann::json::iterator entry = response.find(sensorGroup);
        if (entry == response.end())
        {
            continue;
        }
        nlohmann::json::array_t* arr =
            entry->get_ptr<nlohmann::json::array_t*>();
        if (arr == nullptr)
        {
            continue;
        }
        json_util::sortJsonArrayByKey(*arr, "Name");
        // add the index counts to the end of each entry
        size_t count = 0;
        for (nlohmann::json& sensorJson : *entry)
        {
            nlohmann::json::iterator odata = sensorJson.find("@odata.id");
            if (odata == sensorJson.end())
            {
                continue;
            }
            std::string* value = odata->get_ptr<std::string*>();
            if (value != nullptr)
            {
                *value += "/" + std::to_string(count);
                sensorJson["MemberId"] = std::to_string(count);
                count++;
                sensorsAsyncResp->updateUri(sensorJson["Name"], *value);
            }
        }
    }
}

/**
 * @brief Finds the inventory item with the specified object path.
 * @param inventoryItems D-Bus inventory items associated with sensors.
 * @param invItemObjPath D-Bus object path of inventory item.
 * @return Inventory item within vector, or nullptr if no match found.
 */
inline InventoryItem* findInventoryItem(
    const std::shared_ptr<std::vector<InventoryItem>>& inventoryItems,
    const std::string& invItemObjPath)
{
    for (InventoryItem& inventoryItem : *inventoryItems)
    {
        if (inventoryItem.objectPath == invItemObjPath)
        {
            return &inventoryItem;
        }
    }
    return nullptr;
}

/**
 * @brief Finds the inventory item associated with the specified sensor.
 * @param inventoryItems D-Bus inventory items associated with sensors.
 * @param sensorObjPath D-Bus object path of sensor.
 * @return Inventory item within vector, or nullptr if no match found.
 */
inline InventoryItem* findInventoryItemForSensor(
    const std::shared_ptr<std::vector<InventoryItem>>& inventoryItems,
    const std::string& sensorObjPath)
{
    for (InventoryItem& inventoryItem : *inventoryItems)
    {
        if (inventoryItem.sensors.contains(sensorObjPath))
        {
            return &inventoryItem;
        }
    }
    return nullptr;
}

/**
 * @brief Finds the inventory item associated with the specified led path.
 * @param inventoryItems D-Bus inventory items associated with sensors.
 * @param ledObjPath D-Bus object path of led.
 * @return Inventory item within vector, or nullptr if no match found.
 */
inline InventoryItem* findInventoryItemForLed(
    std::vector<InventoryItem>& inventoryItems, const std::string& ledObjPath)
{
    for (InventoryItem& inventoryItem : inventoryItems)
    {
        if (inventoryItem.ledObjectPath == ledObjPath)
        {
            return &inventoryItem;
        }
    }
    return nullptr;
}

/**
 * @brief Adds inventory item and associated sensor to specified vector.
 *
 * Adds a new InventoryItem to the vector if necessary.  Searches for an
 * existing InventoryItem with the specified object path.  If not found, one is
 * added to the vector.
 *
 * Next, the specified sensor is added to the set of sensors associated with the
 * InventoryItem.
 *
 * @param inventoryItems D-Bus inventory items associated with sensors.
 * @param invItemObjPath D-Bus object path of inventory item.
 * @param sensorObjPath D-Bus object path of sensor
 */
inline void addInventoryItem(
    const std::shared_ptr<std::vector<InventoryItem>>& inventoryItems,
    const std::string& invItemObjPath, const std::string& sensorObjPath)
{
    // Look for inventory item in vector
    InventoryItem* inventoryItem =
        findInventoryItem(inventoryItems, invItemObjPath);

    // If inventory item doesn't exist in vector, add it
    if (inventoryItem == nullptr)
    {
        inventoryItems->emplace_back(invItemObjPath);
        inventoryItem = &(inventoryItems->back());
    }

    // Add sensor to set of sensors associated with inventory item
    inventoryItem->sensors.emplace(sensorObjPath);
}

/**
 * @brief Stores D-Bus data in the specified inventory item.
 *
 * Finds D-Bus data in the specified map of interfaces.  Stores the data in the
 * specified InventoryItem.
 *
 * This data is later used to provide sensor property values in the JSON
 * response.
 *
 * @param inventoryItem Inventory item where data will be stored.
 * @param interfacesDict Map containing D-Bus interfaces and their properties
 * for the specified inventory item.
 */
inline void storeInventoryItemData(
    InventoryItem& inventoryItem,
    const dbus::utility::DBusInterfacesMap& interfacesDict)
{
    // Get properties from Inventory.Item interface

    for (const auto& [interface, values] : interfacesDict)
    {
        if (interface == "xyz.openbmc_project.Inventory.Item")
        {
            for (const auto& [name, dbusValue] : values)
            {
                if (name == "Present")
                {
                    const bool* value = std::get_if<bool>(&dbusValue);
                    if (value != nullptr)
                    {
                        inventoryItem.isPresent = *value;
                    }
                }
            }
        }
        // Check if Inventory.Item.PowerSupply interface is present

        if (interface == "xyz.openbmc_project.Inventory.Item.PowerSupply")
        {
            inventoryItem.isPowerSupply = true;
        }

        // Get properties from Inventory.Decorator.Asset interface
        if (interface == "xyz.openbmc_project.Inventory.Decorator.Asset")
        {
            for (const auto& [name, dbusValue] : values)
            {
                if (name == "Manufacturer")
                {
                    const std::string* value =
                        std::get_if<std::string>(&dbusValue);
                    if (value != nullptr)
                    {
                        inventoryItem.manufacturer = *value;
                    }
                }
                if (name == "Model")
                {
                    const std::string* value =
                        std::get_if<std::string>(&dbusValue);
                    if (value != nullptr)
                    {
                        inventoryItem.model = *value;
                    }
                }
                if (name == "SerialNumber")
                {
                    const std::string* value =
                        std::get_if<std::string>(&dbusValue);
                    if (value != nullptr)
                    {
                        inventoryItem.serialNumber = *value;
                    }
                }
                if (name == "PartNumber")
                {
                    const std::string* value =
                        std::get_if<std::string>(&dbusValue);
                    if (value != nullptr)
                    {
                        inventoryItem.partNumber = *value;
                    }
                }
            }
        }

        if (interface ==
            "xyz.openbmc_project.State.Decorator.OperationalStatus")
        {
            for (const auto& [name, dbusValue] : values)
            {
                if (name == "Functional")
                {
                    const bool* value = std::get_if<bool>(&dbusValue);
                    if (value != nullptr)
                    {
                        inventoryItem.isFunctional = *value;
                    }
                }
            }
        }
    }
}

inline void StorePSUmonitorItemData(InventoryItem* inventoryItem)
{
    crow::connections::systemBus->async_method_call(
        [inventoryItem](
            const boost::system::error_code ec2,
            const std::vector<std::pair<
                std::string, std::variant<uint8_t, uint16_t, std::string,
                                          std::vector<std::string>>>>&
                propertiesList) {
            if (ec2)
            {
                return;
            }
            for (const std::pair<std::string,
                                 std::variant<uint8_t, uint16_t, std::string,
                                              std::vector<std::string>>>&
                     property : propertiesList)
            {
                const std::string& propertyName = property.first;
                if (propertyName == "FirmwareVersion")
                {
                    const std::string* value =
                        std::get_if<std::string>(&property.second);
                    if (value != nullptr)
                    {
                        inventoryItem->firmwareVersion = *value;
                    }
                }
                if (propertyName == "InputNominalVoltageType")
                {
                    const std::string* value =
                        std::get_if<std::string>(&property.second);
                    if (value != nullptr)
                    {
                        inventoryItem->nominalVoltageType = *value;
                    }
                }
                if (propertyName == "PlugType")
                {
                    const std::string* value =
                        std::get_if<std::string>(&property.second);
                    if (value != nullptr)
                    {
                        inventoryItem->plugType = *value;
                    }
                }
                if (propertyName == "PowerSupplyType")
                {
                    const std::string* value =
                        std::get_if<std::string>(&property.second);
                    if (value != nullptr)
                    {
                        inventoryItem->powerSupplyType = *value;
                    }
                }
                if (propertyName == "SparePartNumber")
                {
                    const std::string* value =
                        std::get_if<std::string>(&property.second);
                    if (value != nullptr)
                    {
                        inventoryItem->sparePartNumber = *value;
                    }
                }
                if (propertyName == "PowerCapacityWatts")
                {
                    const uint16_t* value =
                        std::get_if<uint16_t>(&property.second);
                    if (value != nullptr)
                    {
                        inventoryItem->powerCapacityWatts = *value;
                    }
                }
                if (propertyName == "EfficiencyRatings")
                {
                    const std::string* value =
                        std::get_if<std::string>(&property.second);
                    if (value != nullptr)
                    {
                        try
                        {
                            int value1 = std::stoi(*value);
                            inventoryItem->efficiencyRatings =
                                static_cast<uint16_t>(value1);
                        }
                        catch (const std::exception& e)
                        {}
                    }
                }
                if (propertyName == "OutputRails")
                {
                    const auto& propertyValue = property.second;
                    if (std::holds_alternative<std::vector<std::string>>(
                            propertyValue))
                    {
                        const std::vector<std::string>& vectorValue =
                            std::get<std::vector<std::string>>(propertyValue);
                        for (const std::string& element : vectorValue)
                        {
                            if (element == "12v")
                            {
                                inventoryItem->outputRails[12] =
                                    "StorageDevice";
                            }
                            if (element == "1.8v")
                            {
                                inventoryItem->outputRails[1.8] = "SystemBoard";
                            }
                            if (element == "3v")
                            {
                                inventoryItem->outputRails[3] = "SystemBoard";
                            }
                            if (element == "5v")
                            {
                                inventoryItem->outputRails[5] = "SystemBoard";
                            }
                        }
                    }
                }
            }
        },
        "xyz.openbmc_project.Power.PSUMonitor",
        "/xyz/openbmc_project/inventory/system/powersupply",
        "org.freedesktop.DBus.Properties", "GetAll",
        "xyz.openbmc_project.PsuStatus");
}

/**
 * @brief Gets D-Bus data for inventory items associated with sensors.
 *
 * Uses the specified connections (services) to obtain D-Bus data for inventory
 * items associated with sensors.  Stores the resulting data in the
 * inventoryItems vector.
 *
 * This data is later used to provide sensor property values in the JSON
 * response.
 *
 * Finds the inventory item data asynchronously.  Invokes callback when data has
 * been obtained.
 *
 * The callback must have the following signature:
 *   @code
 *   callback(void)
 *   @endcode
 *
 * This function is called recursively, obtaining data asynchronously from one
 * connection in each call.  This ensures the callback is not invoked until the
 * last asynchronous function has completed.
 *
 * @param sensorsAsyncResp Pointer to object holding response data.
 * @param inventoryItems D-Bus inventory items associated with sensors.
 * @param invConnections Connections that provide data for the inventory items.
 * implements ObjectManager.
 * @param callback Callback to invoke when inventory data has been obtained.
 * @param invConnectionsIndex Current index in invConnections.  Only specified
 * in recursive calls to this function.
 */
template <typename Callback>
void getInventoryItemsData(
    const std::shared_ptr<SensorsAsyncResp>& sensorsAsyncResp,
    const std::shared_ptr<std::vector<InventoryItem>>& inventoryItems,
    const std::shared_ptr<std::set<std::string>>& invConnections,
    Callback&& callback, size_t invConnectionsIndex = 0)
{
    BMCWEB_LOG_DEBUG("getInventoryItemsData enter");

    // If no more connections left, call callback
    if (invConnectionsIndex >= invConnections->size())
    {
        callback();
        BMCWEB_LOG_DEBUG("getInventoryItemsData exit");
        return;
    }

    // Get inventory item data from current connection
    auto it = invConnections->begin();
    std::advance(it, invConnectionsIndex);
    if (it != invConnections->end())
    {
        const std::string& invConnection = *it;

        // Get all object paths and their interfaces for current connection
        sdbusplus::message::object_path path("/xyz/openbmc_project/inventory");
        dbus::utility::getManagedObjects(
            invConnection, path,
            [sensorsAsyncResp, inventoryItems, invConnections,
             callback = std::forward<Callback>(callback), invConnectionsIndex](
                const boost::system::error_code& ec,
                const dbus::utility::ManagedObjectType& resp) mutable {
                BMCWEB_LOG_DEBUG("getInventoryItemsData respHandler enter");
                if (ec)
                {
                    BMCWEB_LOG_ERROR(
                        "getInventoryItemsData respHandler DBus error {}", ec);
                    messages::internalError(sensorsAsyncResp->asyncResp->res);
                    return;
                }

                // Loop through returned object paths
                for (const auto& objDictEntry : resp)
                {
                    const std::string& objPath =
                        static_cast<const std::string&>(objDictEntry.first);

                    // If this object path is one of the specified inventory
                    // items
                    InventoryItem* inventoryItem =
                        findInventoryItem(inventoryItems, objPath);
                    if (inventoryItem != nullptr)
                    {
                        // Store inventory data in InventoryItem
                        storeInventoryItemData(*inventoryItem,
                                               objDictEntry.second);
                        StorePSUmonitorItemData(inventoryItem);
                        getPsuState(inventoryItem);
                    }
                }

                // Recurse to get inventory item data from next connection
                getInventoryItemsData(sensorsAsyncResp, inventoryItems,
                                      invConnections, std::move(callback),
                                      invConnectionsIndex + 1);

                BMCWEB_LOG_DEBUG("getInventoryItemsData respHandler exit");
            });
    }

    BMCWEB_LOG_DEBUG("getInventoryItemsData exit");
}

/**
 * @brief Gets connections that provide D-Bus data for inventory items.
 *
 * Gets the D-Bus connections (services) that provide data for the inventory
 * items that are associated with sensors.
 *
 * Finds the connections asynchronously.  Invokes callback when information has
 * been obtained.
 *
 * The callback must have the following signature:
 *   @code
 *   callback(std::shared_ptr<std::set<std::string>> invConnections)
 *   @endcode
 *
 * @param sensorsAsyncResp Pointer to object holding response data.
 * @param inventoryItems D-Bus inventory items associated with sensors.
 * @param callback Callback to invoke when connections have been obtained.
 */
template <typename Callback>
void getInventoryItemsConnections(
    const std::shared_ptr<SensorsAsyncResp>& sensorsAsyncResp,
    const std::shared_ptr<std::vector<InventoryItem>>& inventoryItems,
    Callback&& callback)
{
    BMCWEB_LOG_DEBUG("getInventoryItemsConnections enter");

    const std::string path = "/xyz/openbmc_project/inventory";
    constexpr std::array<std::string_view, 4> interfaces = {
        "xyz.openbmc_project.Inventory.Item",
        "xyz.openbmc_project.Inventory.Item.PowerSupply",
        "xyz.openbmc_project.Inventory.Decorator.Asset",
        "xyz.openbmc_project.State.Decorator.OperationalStatus"};

    // Make call to ObjectMapper to find all inventory items
    dbus::utility::getSubTree(
        path, 0, interfaces,
        [callback = std::forward<Callback>(callback), sensorsAsyncResp,
         inventoryItems](
            const boost::system::error_code& ec,
            const dbus::utility::MapperGetSubTreeResponse& subtree) mutable {
            // Response handler for parsing output from GetSubTree
            BMCWEB_LOG_DEBUG("getInventoryItemsConnections respHandler enter");
            if (ec)
            {
                messages::internalError(sensorsAsyncResp->asyncResp->res);
                BMCWEB_LOG_ERROR(
                    "getInventoryItemsConnections respHandler DBus error {}",
                    ec);
                return;
            }

            // Make unique list of connections for desired inventory items
            std::shared_ptr<std::set<std::string>> invConnections =
                std::make_shared<std::set<std::string>>();

            // Loop through objects from GetSubTree
            for (const std::pair<std::string,
                                 std::vector<std::pair<
                                     std::string, std::vector<std::string>>>>&
                     object : subtree)
            {
                // Check if object path is one of the specified inventory items
                const std::string& objPath = object.first;
                if (findInventoryItem(inventoryItems, objPath) != nullptr)
                {
                    // Store all connections to inventory item
                    for (const std::pair<std::string, std::vector<std::string>>&
                             objData : object.second)
                    {
                        const std::string& invConnection = objData.first;
                        invConnections->insert(invConnection);
                    }
                }
            }

            callback(invConnections);
            BMCWEB_LOG_DEBUG("getInventoryItemsConnections respHandler exit");
        });
    BMCWEB_LOG_DEBUG("getInventoryItemsConnections exit");
}

/**
 * @brief Gets associations from sensors to inventory items.
 *
 * Looks for ObjectMapper associations from the specified sensors to related
 * inventory items. Then finds the associations from those inventory items to
 * their LEDs, if any.
 *
 * Finds the inventory items asynchronously.  Invokes callback when information
 * has been obtained.
 *
 * The callback must have the following signature:
 *   @code
 *   callback(std::shared_ptr<std::vector<InventoryItem>> inventoryItems)
 *   @endcode
 *
 * @param sensorsAsyncResp Pointer to object holding response data.
 * @param sensorNames All sensors within the current chassis.
 * implements ObjectManager.
 * @param callback Callback to invoke when inventory items have been obtained.
 */
template <typename Callback>
void getInventoryItemAssociations(
    const std::shared_ptr<SensorsAsyncResp>& sensorsAsyncResp,
    const std::shared_ptr<std::set<std::string>>& sensorNames,
    Callback&& callback)
{
    BMCWEB_LOG_DEBUG("getInventoryItemAssociations enter");

    // Call GetManagedObjects on the ObjectMapper to get all associations
    sdbusplus::message::object_path path("/");
    dbus::utility::getManagedObjects(
        "xyz.openbmc_project.ObjectMapper", path,
        [callback = std::forward<Callback>(callback), sensorsAsyncResp,
         sensorNames](const boost::system::error_code& ec,
                      const dbus::utility::ManagedObjectType& resp) mutable {
            BMCWEB_LOG_DEBUG("getInventoryItemAssociations respHandler enter");
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "getInventoryItemAssociations respHandler DBus error {}",
                    ec);
                messages::internalError(sensorsAsyncResp->asyncResp->res);
                return;
            }

            // Create vector to hold list of inventory items
            std::shared_ptr<std::vector<InventoryItem>> inventoryItems =
                std::make_shared<std::vector<InventoryItem>>();

            // Loop through returned object paths
            std::string sensorAssocPath;
            sensorAssocPath.reserve(128); // avoid memory allocations
            for (const auto& objDictEntry : resp)
            {
                const std::string& objPath =
                    static_cast<const std::string&>(objDictEntry.first);

                // If path is inventory association for one of the specified
                // sensors
                for (const std::string& sensorName : *sensorNames)
                {
                    sensorAssocPath = sensorName;
                    sensorAssocPath += "/inventory";
                    if (objPath == sensorAssocPath)
                    {
                        // Get Association interface for object path
                        for (const auto& [interface, values] :
                             objDictEntry.second)
                        {
                            if (interface == "xyz.openbmc_project.Association")
                            {
                                for (const auto& [valueName, value] : values)
                                {
                                    if (valueName == "endpoints")
                                    {
                                        const std::vector<std::string>*
                                            endpoints = std::get_if<
                                                std::vector<std::string>>(
                                                &value);
                                        if ((endpoints != nullptr) &&
                                            !endpoints->empty())
                                        {
                                            // Add inventory item to vector
                                            const std::string& invItemPath =
                                                endpoints->front();
                                            addInventoryItem(inventoryItems,
                                                             invItemPath,
                                                             sensorName);
                                        }
                                    }
                                }
                            }
                        }
                        break;
                    }
                }
            }

            // Now loop through the returned object paths again, this time to
            // find the leds associated with the inventory items we just found
            std::string inventoryAssocPath;
            inventoryAssocPath.reserve(128); // avoid memory allocations
            for (const auto& objDictEntry : resp)
            {
                const std::string& objPath =
                    static_cast<const std::string&>(objDictEntry.first);

                for (InventoryItem& inventoryItem : *inventoryItems)
                {
                    inventoryAssocPath = inventoryItem.objectPath;
                    inventoryAssocPath += "/leds";
                    if (objPath == inventoryAssocPath)
                    {
                        for (const auto& [interface, values] :
                             objDictEntry.second)
                        {
                            if (interface == "xyz.openbmc_project.Association")
                            {
                                for (const auto& [valueName, value] : values)
                                {
                                    if (valueName == "endpoints")
                                    {
                                        const std::vector<std::string>*
                                            endpoints = std::get_if<
                                                std::vector<std::string>>(
                                                &value);
                                        if ((endpoints != nullptr) &&
                                            !endpoints->empty())
                                        {
                                            // Add inventory item to vector
                                            // Store LED path in inventory item
                                            const std::string& ledPath =
                                                endpoints->front();
                                            inventoryItem.ledObjectPath =
                                                ledPath;
                                        }
                                    }
                                }
                            }
                        }

                        break;
                    }
                }
            }
            callback(inventoryItems);
            BMCWEB_LOG_DEBUG("getInventoryItemAssociations respHandler exit");
        });

    BMCWEB_LOG_DEBUG("getInventoryItemAssociations exit");
}

/**
 * @brief Gets D-Bus data for inventory item leds associated with sensors.
 *
 * Uses the specified connections (services) to obtain D-Bus data for inventory
 * item leds associated with sensors.  Stores the resulting data in the
 * inventoryItems vector.
 *
 * This data is later used to provide sensor property values in the JSON
 * response.
 *
 * Finds the inventory item led data asynchronously.  Invokes callback when data
 * has been obtained.
 *
 * The callback must have the following signature:
 *   @code
 *   callback()
 *   @endcode
 *
 * This function is called recursively, obtaining data asynchronously from one
 * connection in each call.  This ensures the callback is not invoked until the
 * last asynchronous function has completed.
 *
 * @param sensorsAsyncResp Pointer to object holding response data.
 * @param inventoryItems D-Bus inventory items associated with sensors.
 * @param ledConnections Connections that provide data for the inventory leds.
 * @param callback Callback to invoke when inventory data has been obtained.
 * @param ledConnectionsIndex Current index in ledConnections.  Only specified
 * in recursive calls to this function.
 */
template <typename Callback>
void getInventoryLedData(
    const std::shared_ptr<SensorsAsyncResp>& sensorsAsyncResp,
    const std::shared_ptr<std::vector<InventoryItem>>& inventoryItems,
    const std::shared_ptr<std::map<std::string, std::string>>& ledConnections,
    Callback&& callback, size_t ledConnectionsIndex = 0)
{
    BMCWEB_LOG_DEBUG("getInventoryLedData enter");

    // If no more connections left, call callback
    if (ledConnectionsIndex >= ledConnections->size())
    {
        callback();
        BMCWEB_LOG_DEBUG("getInventoryLedData exit");
        return;
    }

    // Get inventory item data from current connection
    auto it = ledConnections->begin();
    std::advance(it, ledConnectionsIndex);
    if (it != ledConnections->end())
    {
        const std::string& ledPath = (*it).first;
        const std::string& ledConnection = (*it).second;
        // Response handler for Get State property
        auto respHandler =
            [sensorsAsyncResp, inventoryItems, ledConnections, ledPath,
             callback = std::forward<Callback>(callback),
             ledConnectionsIndex](const boost::system::error_code& ec,
                                  const std::string& state) mutable {
                BMCWEB_LOG_DEBUG("getInventoryLedData respHandler enter");
                if (ec)
                {
                    BMCWEB_LOG_ERROR(
                        "getInventoryLedData respHandler DBus error {}", ec);
                    messages::internalError(sensorsAsyncResp->asyncResp->res);
                    return;
                }

                BMCWEB_LOG_DEBUG("Led state: {}", state);
                // Find inventory item with this LED object path
                InventoryItem* inventoryItem =
                    findInventoryItemForLed(*inventoryItems, ledPath);
                if (inventoryItem != nullptr)
                {
                    // Store LED state in InventoryItem
                    if (state.ends_with("On"))
                    {
                        inventoryItem->ledState = sensor_utils::LedState::ON;
                    }
                    else if (state.ends_with("Blink"))
                    {
                        inventoryItem->ledState = sensor_utils::LedState::BLINK;
                    }
                    else if (state.ends_with("Off"))
                    {
                        inventoryItem->ledState = sensor_utils::LedState::OFF;
                    }
                    else
                    {
                        inventoryItem->ledState =
                            sensor_utils::LedState::UNKNOWN;
                    }
                }

                // Recurse to get LED data from next connection
                getInventoryLedData(sensorsAsyncResp, inventoryItems,
                                    ledConnections, std::move(callback),
                                    ledConnectionsIndex + 1);

                BMCWEB_LOG_DEBUG("getInventoryLedData respHandler exit");
            };

        // Get the State property for the current LED
        dbus::utility::getProperty<std::string>(
            ledConnection, ledPath, "xyz.openbmc_project.Led.Physical", "State",
            std::move(respHandler));
    }

    BMCWEB_LOG_DEBUG("getInventoryLedData exit");
}

/**
 * @brief Gets LED data for LEDs associated with given inventory items.
 *
 * Gets the D-Bus connections (services) that provide LED data for the LEDs
 * associated with the specified inventory items.  Then gets the LED data from
 * each connection and stores it in the inventory item.
 *
 * This data is later used to provide sensor property values in the JSON
 * response.
 *
 * Finds the LED data asynchronously.  Invokes callback when information has
 * been obtained.
 *
 * The callback must have the following signature:
 *   @code
 *   callback()
 *   @endcode
 *
 * @param sensorsAsyncResp Pointer to object holding response data.
 * @param inventoryItems D-Bus inventory items associated with sensors.
 * @param callback Callback to invoke when inventory items have been obtained.
 */
template <typename Callback>
void getInventoryLeds(
    const std::shared_ptr<SensorsAsyncResp>& sensorsAsyncResp,
    const std::shared_ptr<std::vector<InventoryItem>>& inventoryItems,
    Callback&& callback)
{
    BMCWEB_LOG_DEBUG("getInventoryLeds enter");

    const std::string path = "/xyz/openbmc_project";
    constexpr std::array<std::string_view, 1> interfaces = {
        "xyz.openbmc_project.Led.Physical"};

    // Make call to ObjectMapper to find all inventory items
    dbus::utility::getSubTree(
        path, 0, interfaces,
        [callback = std::forward<Callback>(callback), sensorsAsyncResp,
         inventoryItems](
            const boost::system::error_code& ec,
            const dbus::utility::MapperGetSubTreeResponse& subtree) mutable {
            // Response handler for parsing output from GetSubTree
            BMCWEB_LOG_DEBUG("getInventoryLeds respHandler enter");
            if (ec)
            {
                messages::internalError(sensorsAsyncResp->asyncResp->res);
                BMCWEB_LOG_ERROR("getInventoryLeds respHandler DBus error {}",
                                 ec);
                return;
            }

            // Build map of LED object paths to connections
            std::shared_ptr<std::map<std::string, std::string>> ledConnections =
                std::make_shared<std::map<std::string, std::string>>();

            // Loop through objects from GetSubTree
            for (const std::pair<std::string,
                                 std::vector<std::pair<
                                     std::string, std::vector<std::string>>>>&
                     object : subtree)
            {
                // Check if object path is LED for one of the specified
                // inventory items
                const std::string& ledPath = object.first;
                if (findInventoryItemForLed(*inventoryItems, ledPath) !=
                    nullptr)
                {
                    // Add mapping from ledPath to connection
                    const std::string& connection =
                        object.second.begin()->first;
                    (*ledConnections)[ledPath] = connection;
                    BMCWEB_LOG_DEBUG("Added mapping {} -> {}", ledPath,
                                     connection);
                }
            }

            getInventoryLedData(sensorsAsyncResp, inventoryItems,
                                ledConnections, std::move(callback));
            BMCWEB_LOG_DEBUG("getInventoryLeds respHandler exit");
        });
    BMCWEB_LOG_DEBUG("getInventoryLeds exit");
}

/**
 * @brief Gets D-Bus data for Power Supply Attributes such as EfficiencyPercent
 *
 * Uses the specified connections (services) (currently assumes just one) to
 * obtain D-Bus data for Power Supply Attributes. Stores the resulting data in
 * the inventoryItems vector. Only stores data in Power Supply inventoryItems.
 *
 * This data is later used to provide sensor property values in the JSON
 * response.
 *
 * Finds the Power Supply Attributes data asynchronously.  Invokes callback
 * when data has been obtained.
 *
 * The callback must have the following signature:
 *   @code
 *   callback(std::shared_ptr<std::vector<InventoryItem>> inventoryItems)
 *   @endcode
 *
 * @param sensorsAsyncResp Pointer to object holding response data.
 * @param inventoryItems D-Bus inventory items associated with sensors.
 * @param psAttributesConnections Connections that provide data for the Power
 *        Supply Attributes
 * @param callback Callback to invoke when data has been obtained.
 */
template <typename Callback>
void getPowerSupplyAttributesData(
    const std::shared_ptr<SensorsAsyncResp>& sensorsAsyncResp,
    const std::shared_ptr<std::vector<InventoryItem>>& inventoryItems,
    const std::map<std::string, std::string>& psAttributesConnections,
    Callback&& callback)
{
    BMCWEB_LOG_DEBUG("getPowerSupplyAttributesData enter");

    if (psAttributesConnections.empty())
    {
        BMCWEB_LOG_DEBUG("Can't find PowerSupplyAttributes, no connections!");
        callback(inventoryItems);
        return;
    }

    // Assuming just one connection (service) for now
    auto it = psAttributesConnections.begin();

    const std::string& psAttributesPath = (*it).first;
    const std::string& psAttributesConnection = (*it).second;

    // Response handler for Get DeratingFactor property
    auto respHandler = [sensorsAsyncResp, inventoryItems,
                        callback = std::forward<Callback>(callback)](
                           const boost::system::error_code& ec,
                           uint32_t value) mutable {
        BMCWEB_LOG_DEBUG("getPowerSupplyAttributesData respHandler enter");
        if (ec)
        {
            BMCWEB_LOG_ERROR(
                "getPowerSupplyAttributesData respHandler DBus error {}", ec);
            messages::internalError(sensorsAsyncResp->asyncResp->res);
            return;
        }

        BMCWEB_LOG_DEBUG("PS EfficiencyPercent value: {}", value);
        // Store value in Power Supply Inventory Items
        for (InventoryItem& inventoryItem : *inventoryItems)
        {
            if (inventoryItem.isPowerSupply)
            {
                inventoryItem.powerSupplyEfficiencyPercent =
                    static_cast<int>(value);
            }
        }

        BMCWEB_LOG_DEBUG("getPowerSupplyAttributesData respHandler exit");
        callback(inventoryItems);
    };

    // Get the DeratingFactor property for the PowerSupplyAttributes
    // Currently only property on the interface/only one we care about
    dbus::utility::getProperty<uint32_t>(
        psAttributesConnection, psAttributesPath,
        "xyz.openbmc_project.Control.PowerSupplyAttributes", "DeratingFactor",
        std::move(respHandler));

    BMCWEB_LOG_DEBUG("getPowerSupplyAttributesData exit");
}

/**
 * @brief Gets the Power Supply Attributes such as EfficiencyPercent
 *
 * Gets the D-Bus connection (service) that provides Power Supply Attributes
 * data. Then gets the Power Supply Attributes data from the connection
 * (currently just assumes 1 connection) and stores the data in the inventory
 * item.
 *
 * This data is later used to provide sensor property values in the JSON
 * response. DeratingFactor on D-Bus is mapped to EfficiencyPercent on Redfish.
 *
 * Finds the Power Supply Attributes data asynchronously. Invokes callback
 * when information has been obtained.
 *
 * The callback must have the following signature:
 *   @code
 *   callback(std::shared_ptr<std::vector<InventoryItem>> inventoryItems)
 *   @endcode
 *
 * @param sensorsAsyncResp Pointer to object holding response data.
 * @param inventoryItems D-Bus inventory items associated with sensors.
 * @param callback Callback to invoke when data has been obtained.
 */
template <typename Callback>
void getPowerSupplyAttributes(
    const std::shared_ptr<SensorsAsyncResp>& sensorsAsyncResp,
    const std::shared_ptr<std::vector<InventoryItem>>& inventoryItems,
    Callback&& callback)
{
    BMCWEB_LOG_DEBUG("getPowerSupplyAttributes enter");

    // Only need the power supply attributes when the Power Schema
    if (sensorsAsyncResp->chassisSubNode != sensors::powerNodeStr)
    {
        BMCWEB_LOG_DEBUG("getPowerSupplyAttributes exit since not Power");
        callback(inventoryItems);
        return;
    }

    constexpr std::array<std::string_view, 1> interfaces = {
        "xyz.openbmc_project.Control.PowerSupplyAttributes"};

    // Make call to ObjectMapper to find the PowerSupplyAttributes service
    dbus::utility::getSubTree(
        "/xyz/openbmc_project", 0, interfaces,
        [callback = std::forward<Callback>(callback), sensorsAsyncResp,
         inventoryItems](
            const boost::system::error_code& ec,
            const dbus::utility::MapperGetSubTreeResponse& subtree) mutable {
            // Response handler for parsing output from GetSubTree
            BMCWEB_LOG_DEBUG("getPowerSupplyAttributes respHandler enter");
            if (ec)
            {
                messages::internalError(sensorsAsyncResp->asyncResp->res);
                BMCWEB_LOG_ERROR(
                    "getPowerSupplyAttributes respHandler DBus error {}", ec);
                return;
            }
            if (subtree.empty())
            {
                BMCWEB_LOG_DEBUG("Can't find Power Supply Attributes!");
                callback(inventoryItems);
                return;
            }

            // Currently we only support 1 power supply attribute, use this for
            // all the power supplies. Build map of object path to connection.
            // Assume just 1 connection and 1 path for now.
            std::map<std::string, std::string> psAttributesConnections;

            if (subtree[0].first.empty() || subtree[0].second.empty())
            {
                BMCWEB_LOG_DEBUG("Power Supply Attributes mapper error!");
                callback(inventoryItems);
                return;
            }

            const std::string& psAttributesPath = subtree[0].first;
            const std::string& connection = subtree[0].second.begin()->first;

            if (connection.empty())
            {
                BMCWEB_LOG_DEBUG("Power Supply Attributes mapper error!");
                callback(inventoryItems);
                return;
            }

            psAttributesConnections[psAttributesPath] = connection;
            BMCWEB_LOG_DEBUG("Added mapping {} -> {}", psAttributesPath,
                             connection);

            getPowerSupplyAttributesData(sensorsAsyncResp, inventoryItems,
                                         psAttributesConnections,
                                         std::move(callback));
            BMCWEB_LOG_DEBUG("getPowerSupplyAttributes respHandler exit");
        });
    BMCWEB_LOG_DEBUG("getPowerSupplyAttributes exit");
}

/**
 * @brief Gets inventory items associated with sensors.
 *
 * Finds the inventory items that are associated with the specified sensors.
 * Then gets D-Bus data for the inventory items, such as presence and VPD.
 *
 * This data is later used to provide sensor property values in the JSON
 * response.
 *
 * Finds the inventory items asynchronously.  Invokes callback when the
 * inventory items have been obtained.
 *
 * The callback must have the following signature:
 *   @code
 *   callback(std::shared_ptr<std::vector<InventoryItem>> inventoryItems)
 *   @endcode
 *
 * @param sensorsAsyncResp Pointer to object holding response data.
 * @param sensorNames All sensors within the current chassis.
 * implements ObjectManager.
 * @param callback Callback to invoke when inventory items have been obtained.
 */
template <typename Callback>
inline void getInventoryItems(
    const std::shared_ptr<SensorsAsyncResp>& sensorsAsyncResp,
    const std::shared_ptr<std::set<std::string>>& sensorNames,
    Callback&& callback)
{
    BMCWEB_LOG_DEBUG("getInventoryItems enter");
    auto getInventoryItemAssociationsCb =
        [sensorsAsyncResp, callback = std::forward<Callback>(callback)](
            const std::shared_ptr<std::vector<InventoryItem>>&
                inventoryItems) mutable {
            BMCWEB_LOG_DEBUG("getInventoryItemAssociationsCb enter");
            auto getInventoryItemsConnectionsCb =
                [sensorsAsyncResp, inventoryItems,
                 callback = std::forward<Callback>(callback)](
                    const std::shared_ptr<std::set<std::string>>&
                        invConnections) mutable {
                    BMCWEB_LOG_DEBUG("getInventoryItemsConnectionsCb enter");
                    auto getInventoryItemsDataCb =
                        [sensorsAsyncResp, inventoryItems,
                         callback =
                             std::forward<Callback>(callback)]() mutable {
                            BMCWEB_LOG_DEBUG("getInventoryItemsDataCb enter");

                            auto getInventoryLedsCb =
                                [sensorsAsyncResp, inventoryItems,
                                 callback = std::forward<Callback>(
                                     callback)]() mutable {
                                    BMCWEB_LOG_DEBUG(
                                        "getInventoryLedsCb enter");
                                    // Find Power Supply Attributes and get the
                                    // data
                                    getPowerSupplyAttributes(
                                        sensorsAsyncResp, inventoryItems,
                                        std::move(callback));
                                    BMCWEB_LOG_DEBUG("getInventoryLedsCb exit");
                                };

                            // Find led connections and get the data
                            getInventoryLeds(sensorsAsyncResp, inventoryItems,
                                             std::move(getInventoryLedsCb));
                            BMCWEB_LOG_DEBUG("getInventoryItemsDataCb exit");
                        };

                    // Get inventory item data from connections
                    getInventoryItemsData(sensorsAsyncResp, inventoryItems,
                                          invConnections,
                                          std::move(getInventoryItemsDataCb));
                    BMCWEB_LOG_DEBUG("getInventoryItemsConnectionsCb exit");
                };

            // Get connections that provide inventory item data
            getInventoryItemsConnections(
                sensorsAsyncResp, inventoryItems,
                std::move(getInventoryItemsConnectionsCb));
            BMCWEB_LOG_DEBUG("getInventoryItemAssociationsCb exit");
        };

    // Get associations from sensors to inventory items
    getInventoryItemAssociations(sensorsAsyncResp, sensorNames,
                                 std::move(getInventoryItemAssociationsCb));
    BMCWEB_LOG_DEBUG("getInventoryItems exit");
}

/**
 * @brief Returns JSON PowerSupply object for the specified inventory item.
 *
 * Searches for a JSON PowerSupply object that matches the specified inventory
 * item.  If one is not found, a new PowerSupply object is added to the JSON
 * array.
 *
 * Multiple sensors are often associated with one power supply inventory item.
 * As a result, multiple sensor values are stored in one JSON PowerSupply
 * object.
 *
 * @param powerSupplyArray JSON array containing Redfish PowerSupply objects.
 * @param inventoryItem Inventory item for the power supply.
 * @param chassisId Chassis that contains the power supply.
 * @return JSON PowerSupply object for the specified inventory item.
 */
inline nlohmann::json& getPowerSupply(nlohmann::json& powerSupplyArray,
                                      const InventoryItem& inventoryItem,
                                      const std::string& chassisId)
{
    std::string nameS;
    nameS.resize(inventoryItem.name.size());
    std::ranges::replace_copy(inventoryItem.name, nameS.begin(), '_', ' ');
    // Check if matching PowerSupply object already exists in JSON array
    for (nlohmann::json& powerSupply : powerSupplyArray)
    {
        nlohmann::json::iterator nameIt = powerSupply.find("Name");
        if (nameIt == powerSupply.end())
        {
            continue;
        }
        const std::string* name = nameIt->get_ptr<std::string*>();
        if (name == nullptr)
        {
            continue;
        }
        if (powerSupply["Id"] == inventoryItem.name)
        {
            return powerSupply;
        }
    }

    // Add new PowerSupply object to JSON array
    powerSupplyArray.push_back({});
    nlohmann::json railValues, inputRanges, efficiencyRatings;
    nlohmann::json& powerSupply = powerSupplyArray.back();

#ifdef ONETREE_AMD_CHALUPA
    {
        boost::urls::url url =
            boost::urls::format("/redfish/v1/Chassis/{}/Power", chassisId);
        url.set_fragment(("/PowerSupplies"_json_pointer).to_string());
    }
#endif
    powerSupply["@odata.id"] =
        "/redfish/v1/Chassis/" + chassisId + "/PowerSubsystem/PowerSupplies/" +
        inventoryItem.name;
    powerSupply["@odata.type"] = json_util::odataType("PowerSupply");
    powerSupply["Id"] = inventoryItem.name;

    std::string escaped;
    escaped.resize(inventoryItem.name.size());
    std::ranges::replace_copy(inventoryItem.name, escaped.begin(), '_', ' ');
    powerSupply["Name"] = std::move(escaped);
    powerSupply["Description"] = "Power Supply Information";
    powerSupply["Manufacturer"] = inventoryItem.manufacturer;
    powerSupply["Model"] = inventoryItem.model;
    powerSupply["PartNumber"] = inventoryItem.partNumber;
    powerSupply["SerialNumber"] = inventoryItem.serialNumber;
    powerSupply["FirmwareVersion"] = inventoryItem.firmwareVersion;
    powerSupply["PlugType"] = inventoryItem.plugType;
    powerSupply["PowerSupplyType"] = inventoryItem.powerSupplyType;
    powerSupply["SparePartNumber"] = inventoryItem.sparePartNumber;
    powerSupply["PowerCapacityWatts"] = inventoryItem.powerCapacityWatts;
    for (const auto& rail : inventoryItem.outputRails)
    {
        railValues["NominalVoltage"] = rail.first;
        railValues["PhysicalContext"] = rail.second;
        powerSupply["OutputRails"].push_back(railValues);
    }
    if (inventoryItem.efficiencyRatings > 100)
    {
        efficiencyRatings["EfficiencyPercent"] = 0;
    }
    else
    {
        efficiencyRatings["EfficiencyPercent"] =
            inventoryItem.efficiencyRatings;
    }
    powerSupply["EfficiencyRatings"].push_back(efficiencyRatings);
    inputRanges["NominalVoltageType"] = inventoryItem.nominalVoltageType;
    powerSupply["InputRanges"].push_back(inputRanges);
    powerSupply["Status"]["State"] = inventoryItem.psuState;
    sensor_utils::setLedState(powerSupply, &inventoryItem);

    powerSupply["Status"]["State"] =
        sensor_utils::getState(&inventoryItem, true);
    const char* health = inventoryItem.isFunctional ? "OK" : "Critical";
    powerSupply["Status"]["Health"] = health;
    return powerSupply;
}

/**
 * @brief Gets the values of the specified sensors.
 *
 * Stores the results as JSON in the SensorsAsyncResp.
 *
 * Gets the sensor values asynchronously.  Stores the results later when the
 * information has been obtained.
 *
 * The sensorNames set contains all requested sensors for the current chassis.
 *
 * To minimize the number of DBus calls, the DBus method
 * org.freedesktop.DBus.ObjectManager.GetManagedObjects() is used to get the
 * values of all sensors provided by a connection (service).
 *
 * The connections set contains all the connections that provide sensor values.
 *
 * The InventoryItem vector contains D-Bus inventory items associated with the
 * sensors.  Inventory item data is needed for some Redfish sensor properties.
 *
 * @param SensorsAsyncResp Pointer to object holding response data.
 * @param sensorNames All requested sensors within the current chassis.
 * @param connections Connections that provide sensor values.
 * implements ObjectManager.
 * @param inventoryItems Inventory items associated with the sensors.
 */
inline void getSensorData(
    const std::shared_ptr<SensorsAsyncResp>& sensorsAsyncResp,
    const std::shared_ptr<std::set<std::string>>& sensorNames,
    const std::set<std::string>& connections,
    const std::shared_ptr<std::vector<InventoryItem>>& inventoryItems)
{
    BMCWEB_LOG_DEBUG("getSensorData enter");
    // Get managed objects from all services exposing sensors
    for (const std::string& connection : connections)
    {
        sdbusplus::message::object_path sensorPath(
            "/xyz/openbmc_project/sensors");
        dbus::utility::getManagedObjects(
            connection, sensorPath,
            [sensorsAsyncResp, sensorNames,
             inventoryItems](const boost::system::error_code& ec,
                             const dbus::utility::ManagedObjectType& resp) {
                BMCWEB_LOG_DEBUG("getManagedObjectsCb enter");
                if (ec)
                {
                    BMCWEB_LOG_ERROR("getManagedObjectsCb DBUS error: {}", ec);
                    messages::internalError(sensorsAsyncResp->asyncResp->res);
                    return;
                }
                auto chassisSubNode = sensor_utils::chassisSubNodeFromString(
                    sensorsAsyncResp->chassisSubNode);
                // Go through all objects and update response with sensor data
                for (const auto& objDictEntry : resp)
                {
                    const std::string& objPath =
                        static_cast<const std::string&>(objDictEntry.first);
                    BMCWEB_LOG_DEBUG("getManagedObjectsCb parsing object {}",
                                     objPath);

                    std::vector<std::string> split;
                    // Reserve space for
                    // /xyz/openbmc_project/sensors/<name>/<subname>
                    split.reserve(6);
                    // NOLINTNEXTLINE
                    bmcweb::split(split, objPath, '/');
                    if (split.size() < 6)
                    {
                        BMCWEB_LOG_ERROR("Got path that isn't long enough {}",
                                         objPath);
                        continue;
                    }
                    // These indexes aren't intuitive, as split puts an empty
                    // string at the beginning
                    const std::string& sensorType = split[4];
                    const std::string& sensorName = split[5];
                    BMCWEB_LOG_DEBUG("sensorName {} sensorType {}", sensorName,
                                     sensorType);
                    if (sensorNames->find(objPath) == sensorNames->end())
                    {
                        BMCWEB_LOG_DEBUG("{} not in sensor list ", sensorName);
                        continue;
                    }

                    // Find inventory item (if any) associated with sensor
                    InventoryItem* inventoryItem =
                        findInventoryItemForSensor(inventoryItems, objPath);

                    const std::string& sensorSchema =
                        sensorsAsyncResp->chassisSubNode;

                    nlohmann::json* sensorJson = nullptr;
                    std::string checkPowersupply;

                    if (sensorSchema == sensors::sensorsNodeStr &&
                        !sensorsAsyncResp->efficientExpand)
                    {
                        std::string sensorId =
                            redfish::sensor_utils::getSensorId(sensorName,
                                                               sensorType);

                        sensorsAsyncResp->asyncResp->res
                            .jsonValue["@odata.id"] = boost::urls::format(
                            "/redfish/v1/Chassis/{}/{}/{}",
                            sensorsAsyncResp->chassisId,
                            sensorsAsyncResp->chassisSubNode, sensorId);
                        sensorJson =
                            &(sensorsAsyncResp->asyncResp->res.jsonValue);
                    }
                    else
                    {
                        std::string fieldName;
                        if (sensorsAsyncResp->efficientExpand)
                        {
                            fieldName = "Members";
                        }
                        else if (sensorType == "temperature")
                        {
                            fieldName = "Temperatures";
                        }
                        else if (sensorType == "fan" ||
                                 sensorType == "fan_tach" ||
                                 sensorType == "fan_pwm")
                        {
                            fieldName = "Fans";
                        }
                        else if (sensorType == "voltage")
                        {
                            fieldName = "Voltages";
                        }
                        else if (sensorType == "power")
                        {
                            if (sensorName == "total_power")
                            {
                                fieldName = "PowerControl";
                            }
                            else if ((inventoryItem != nullptr) &&
                                     (inventoryItem->isPowerSupply))
                            {
                                if (inventoryItem->name ==
                                    std::string(sensorsAsyncResp->asyncResp->res
                                                    .jsonValue["Id"]))
                                {
                                    fieldName = "PowerSupplies";
                                    checkPowersupply = "PowerSupplies";
                                }
                                else
                                {
                                    continue;
                                }
                            }
                            else
                            {
                                // Other power sensors are in SensorCollection
                                continue;
                            }
                        }
                        else
                        {
                            BMCWEB_LOG_ERROR(
                                "Unsure how to handle sensorType {}",
                                sensorType);
                            continue;
                        }

                        nlohmann::json& tempArray =
                            sensorsAsyncResp->asyncResp->res
                                .jsonValue[fieldName];
                        if (fieldName == "PowerControl")
                        {
                            if (tempArray.empty())
                            {
                                // Put multiple "sensors" into a single
                                // PowerControl. Follows MemberId naming and
                                // naming in power.hpp.
                                nlohmann::json::object_t power;
                                boost::urls::url url = boost::urls::format(
                                    "/redfish/v1/Chassis/{}/{}",
                                    sensorsAsyncResp->chassisId,
                                    sensorsAsyncResp->chassisSubNode);
                                url.set_fragment(
                                    (""_json_pointer / fieldName / "0")
                                        .to_string());
                                power["@odata.id"] = std::move(url);
                                tempArray.emplace_back(std::move(power));
                            }
                            sensorJson = &(tempArray.back());
                        }
                        else if (fieldName == "PowerSupplies")
                        {
                            if (inventoryItem != nullptr)
                            {
                                sensorJson = &(getPowerSupply(
                                    tempArray, *inventoryItem,
                                    sensorsAsyncResp->chassisId));
                            }
                        }
                        else if (fieldName == "Members")
                        {
                            std::string sensorId =
                                redfish::sensor_utils::getSensorId(sensorName,
                                                                   sensorType);

                            nlohmann::json::object_t member;
                            member["@odata.id"] = boost::urls::format(
                                "/redfish/v1/Chassis/{}/{}/{}",
                                sensorsAsyncResp->chassisId,
                                sensorsAsyncResp->chassisSubNode, sensorId);
                            tempArray.emplace_back(std::move(member));
                            sensorJson = &(tempArray.back());
                        }
                        else
                        {
                            nlohmann::json::object_t member;
                            boost::urls::url url = boost::urls::format(
                                "/redfish/v1/Chassis/{}/{}",
                                sensorsAsyncResp->chassisId,
                                sensorsAsyncResp->chassisSubNode);
                            url.set_fragment(
                                (""_json_pointer / fieldName).to_string());
                            member["@odata.id"] = std::move(url);
                            tempArray.emplace_back(std::move(member));
                            sensorJson = &(tempArray.back());
                        }
                    }

                    if (sensorJson != nullptr)
                    {
                        if ((sensorJson != nullptr) &&
                            (checkPowersupply != "PowerSupplies"))
                        {
                            objectInterfacesToJson(sensorName, sensorType,
                                                   chassisSubNode,
                                                   objDictEntry.second,
                                                   *sensorJson, inventoryItem);
                        }
                        std::string path = "/xyz/openbmc_project/sensors/";
                        path += sensorType;
                        path += "/";
                        path += sensorName;
                        sensorsAsyncResp->addMetadata(*sensorJson, path);
                    }
                }

                if (sensorsAsyncResp.use_count() == 1)
                {
                    if (sensorsAsyncResp->chassisSubNode ==
                        sensors::powerNodeStr)
                    {
                        // nlohmann::json& tempArray =
                        // sensorsAsyncResp->asyncResp->res.jsonValue
                        if (sensorsAsyncResp->asyncResp->res
                                .jsonValue["PowerSupplies"] != nullptr)
                        {
                            sensorsAsyncResp->asyncResp->res.jsonValue =
                                sensorsAsyncResp->asyncResp->res
                                    .jsonValue["PowerSupplies"][0];
                        }
                        else
                        {
                            sensorsAsyncResp->asyncResp->res
                                .jsonValue["PowerSupplies"] =
                                nlohmann::json::array();
                        }
                    }
                    sortJSONResponse(sensorsAsyncResp);
                    if (chassisSubNode ==
                            sensor_utils::ChassisSubNode::sensorsNode &&
                        sensorsAsyncResp->efficientExpand)
                    {
                        sensorsAsyncResp->asyncResp->res
                            .jsonValue["Members@odata.count"] =
                            sensorsAsyncResp->asyncResp->res
                                .jsonValue["Members"]
                                .size();
                    }
                    else if (chassisSubNode ==
                             sensor_utils::ChassisSubNode::thermalNode)
                    {
                        populateFanRedundancy(sensorsAsyncResp);
                    }
                }
                BMCWEB_LOG_DEBUG("getManagedObjectsCb exit");
            });
    }
    BMCWEB_LOG_DEBUG("getSensorData exit");
}

inline void processSensorList(
    const std::shared_ptr<SensorsAsyncResp>& sensorsAsyncResp,
    const std::shared_ptr<std::set<std::string>>& sensorNames)
{
    auto getConnectionCb = [sensorsAsyncResp, sensorNames](
                               const std::set<std::string>& connections) {
        BMCWEB_LOG_DEBUG("getConnectionCb enter");
        auto getInventoryItemsCb =
            [sensorsAsyncResp, sensorNames, connections](
                const std::shared_ptr<std::vector<InventoryItem>>&
                    inventoryItems) mutable {
                BMCWEB_LOG_DEBUG("getInventoryItemsCb enter");
                // Get sensor data and store results in JSON
                getSensorData(sensorsAsyncResp, sensorNames, connections,
                              inventoryItems);
                BMCWEB_LOG_DEBUG("getInventoryItemsCb exit");
            };

        // Get inventory items associated with sensors
        getInventoryItems(sensorsAsyncResp, sensorNames,
                          std::move(getInventoryItemsCb));

        BMCWEB_LOG_DEBUG("getConnectionCb exit");
    };

    // Get set of connections that provide sensor values
    getConnections(sensorsAsyncResp, sensorNames, std::move(getConnectionCb));
}

/**
 * @brief Entry point for retrieving sensors data related to requested
 *        chassis.
 * @param SensorsAsyncResp   Pointer to object holding response data
 */
inline void getChassisData(
    const std::shared_ptr<SensorsAsyncResp>& sensorsAsyncResp)
{
    BMCWEB_LOG_DEBUG("getChassisData enter");
    auto getChassisCb =
        [sensorsAsyncResp](
            const std::shared_ptr<std::set<std::string>>& sensorNames) {
            BMCWEB_LOG_DEBUG("getChassisCb enter");
            processSensorList(sensorsAsyncResp, sensorNames);
            BMCWEB_LOG_DEBUG("getChassisCb exit");
        };
    // SensorCollection doesn't contain the Redundancy property
    //   if (sensorsAsyncResp->chassisSubNode != sensors::sensorsNodeStr)
    //   {
    //       sensorsAsyncResp->asyncResp->res.jsonValue["Redundancy"] =
    //           nlohmann::json::array();
    //   }
    // Get set of sensors in chassis
    getChassis(sensorsAsyncResp->asyncResp, sensorsAsyncResp->chassisId,
               sensorsAsyncResp->chassisSubNode, sensorsAsyncResp->types,
               std::move(getChassisCb));
    BMCWEB_LOG_DEBUG("getChassisData exit");
}

/**
 * @brief Find the requested sensorName in the list of all sensors supplied by
 * the chassis node
 *
 * @param sensorName   The sensor name supplied in the PATCH request
 * @param sensorsList  The list of sensors managed by the chassis node
 * @param sensorsModified  The list of sensors that were found as a result of
 *                         repeated calls to this function
 */
inline bool findSensorNameUsingSensorPath(
    std::string_view sensorName, const std::set<std::string>& sensorsList,
    std::set<std::string>& sensorsModified)
{
    for (const auto& chassisSensor : sensorsList)
    {
        sdbusplus::message::object_path path(chassisSensor);
        std::string thisSensorName = path.filename();
        if (thisSensorName.empty())
        {
            continue;
        }
        if (thisSensorName == sensorName)
        {
            sensorsModified.emplace(chassisSensor);
            return true;
        }
    }
    return false;
}

/**
 * @brief Entry point for overriding sensor values of given sensor
 *
 * @param sensorAsyncResp   response object
 * @param allCollections   Collections extract from sensors' request patch info
 * @param chassisSubNode   Chassis Node for which the query has to happen
 */
inline void setSensorsOverride(
    const std::shared_ptr<SensorsAsyncResp>& sensorAsyncResp,
    std::unordered_map<std::string, std::vector<nlohmann::json::object_t>>&
        allCollections)
{
    BMCWEB_LOG_INFO("setSensorsOverride for subNode{}",
                    sensorAsyncResp->chassisSubNode);

    std::string_view propertyValueName;
    std::unordered_map<std::string, std::pair<double, std::string>> overrideMap;
    std::string memberId;
    double value = 0.0;
    for (auto& collectionItems : allCollections)
    {
        if (collectionItems.first == "Temperatures")
        {
            propertyValueName = "ReadingCelsius";
        }
        else if (collectionItems.first == "Fans")
        {
            propertyValueName = "Reading";
        }
        else
        {
            propertyValueName = "ReadingVolts";
        }
        for (auto& item : collectionItems.second)
        {
            if (!json_util::readJsonObject(                //
                    item, sensorAsyncResp->asyncResp->res, //
                    "MemberId", memberId,                  //
                    propertyValueName, value               //
                    ))
            {
                return;
            }
            overrideMap.emplace(memberId,
                                std::make_pair(value, collectionItems.first));
        }
    }

    auto getChassisSensorListCb = [sensorAsyncResp, overrideMap,
                                   propertyValueNameStr =
                                       std::string(propertyValueName)](
                                      const std::shared_ptr<
                                          std::set<std::string>>& sensorsList) {
        // Match sensor names in the PATCH request to those managed by the
        // chassis node
        const std::shared_ptr<std::set<std::string>> sensorNames =
            std::make_shared<std::set<std::string>>();
        for (const auto& item : overrideMap)
        {
            const auto& sensor = item.first;
            std::pair<std::string, std::string> sensorNameType =
                redfish::sensor_utils::splitSensorNameAndType(sensor);
            if (!findSensorNameUsingSensorPath(sensorNameType.second,
                                               *sensorsList, *sensorNames))
            {
                BMCWEB_LOG_INFO("Unable to find memberId {}", item.first);
                messages::resourceNotFound(sensorAsyncResp->asyncResp->res,
                                           item.second.second, item.first);
                return;
            }
        }
        // Get the connection to which the memberId belongs
        auto getObjectsWithConnectionCb = [sensorAsyncResp, overrideMap,
                                           propertyValueNameStr](
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
                    sensorAsyncResp->chassisSubNode == sensors::thermalNodeStr
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
                std::string id = redfish::sensor_utils::getSensorId(
                    sensorName, path.parent_path().filename());

                const auto& iterator = overrideMap.find(id);
                if (iterator == overrideMap.end())
                {
                    BMCWEB_LOG_INFO("Unable to find sensor object{}",
                                    item.first);
                    messages::internalError(sensorAsyncResp->asyncResp->res);
                    return;
                }
                setDbusProperty(sensorAsyncResp->asyncResp,
                                propertyValueNameStr, item.second, item.first,
                                "xyz.openbmc_project.Sensor.Value", "Value",
                                iterator->second.first);
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

/**
 * @brief Retrieves mapping of Redfish URIs to sensor value property to D-Bus
 * path of the sensor.
 *
 * Function builds valid Redfish response for sensor query of given chassis and
 * node. It then builds metadata about Redfish<->D-Bus correlations and provides
 * it to caller in a callback.
 *
 * @param chassis   Chassis for which retrieval should be performed
 * @param node  Node (group) of sensors. See sensor_utils::node for supported
 * @param mapComplete   Callback to be called with retrieval result
 */
template <typename Callback>
inline void retrieveUriToDbusMap(
    const std::string& chassis, const std::string& node, Callback&& mapComplete)
{
    decltype(sensors::paths)::const_iterator pathIt =
        std::find_if(sensors::paths.cbegin(), sensors::paths.cend(),
                     [&node](auto&& val) { return val.first == node; });
    if (pathIt == sensors::paths.cend())
    {
        BMCWEB_LOG_ERROR("Wrong node provided : {}", node);
        std::map<std::string, std::string> noop;
        mapComplete(boost::beast::http::status::bad_request, noop);
        return;
    }

    auto asyncResp = std::make_shared<bmcweb::AsyncResp>();
    auto callback =
        [asyncResp, mapCompleteCb = std::forward<Callback>(mapComplete)](
            const boost::beast::http::status status,
            const std::map<std::string, std::string>& uriToDbus) {
            mapCompleteCb(status, uriToDbus);
        };

    auto resp = std::make_shared<SensorsAsyncResp>(
        asyncResp, chassis, pathIt->second, node, std::move(callback));
    getChassisData(resp);
}

namespace sensors
{

inline void getChassisCallback(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    std::string_view chassisId, std::string_view chassisSubNode,
    const std::shared_ptr<std::set<std::string>>& sensorNames)
{
    BMCWEB_LOG_DEBUG("getChassisCallback enter ");

    nlohmann::json& entriesArray = asyncResp->res.jsonValue["Members"];
    for (const std::string& sensor : *sensorNames)
    {
        BMCWEB_LOG_DEBUG("Adding sensor: {}", sensor);

        sdbusplus::message::object_path path(sensor);
        std::string sensorName = path.filename();
        if (sensorName.empty())
        {
            BMCWEB_LOG_ERROR("Invalid sensor path: {}", sensor);
            messages::internalError(asyncResp->res);
            return;
        }
        std::string type = path.parent_path().filename();
        std::string id = redfish::sensor_utils::getSensorId(sensorName, type);

        nlohmann::json::object_t member;
        member["@odata.id"] = boost::urls::format(
            "/redfish/v1/Chassis/{}/{}/{}", chassisId, chassisSubNode, id);

        entriesArray.emplace_back(std::move(member));
    }

    asyncResp->res.jsonValue["Members@odata.count"] = entriesArray.size();
#ifndef ONETREE_PSM
    asyncResp->res.jsonValue["Oem"]["Ami"]["Threshold"]["@odata.id"] =
        boost::urls::format("/redfish/v1/Chassis/{}/Sensors/Oem/Ami/Threshold",
                            chassisId);
#endif
    BMCWEB_LOG_DEBUG("getChassisCallback exit");
}

inline void handleSensorCollectionGet(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    query_param::QueryCapabilities capabilities = {
        .canDelegateExpandLevel = 1,
    };
    query_param::Query delegatedQuery;
    if (!redfish::setUpRedfishRouteWithDelegation(app, req, asyncResp,
                                                  delegatedQuery, capabilities))
    {
        return;
    }

    if (delegatedQuery.expandType != query_param::ExpandType::None)
    {
        // we perform efficient expand.
        auto sensorsAsyncResp = std::make_shared<SensorsAsyncResp>(
            asyncResp, chassisId, sensors::dbus::sensorPaths,
            sensors::sensorsNodeStr,
            /*efficientExpand=*/true);
        getChassisData(sensorsAsyncResp);

        BMCWEB_LOG_DEBUG(
            "SensorCollection doGet exit via efficient expand handler");
        return;
    }

    // We get all sensors as hyperlinkes in the chassis (this
    // implies we reply on the default query parameters handler)
    getChassis(asyncResp, chassisId, sensors::sensorsNodeStr, dbus::sensorPaths,
               std::bind_front(sensors::getChassisCallback, asyncResp,
                               chassisId, sensors::sensorsNodeStr));
}

inline void handleSensorThreshCollectionGet(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId)
{
    BMCWEB_LOG_DEBUG("Sensor Thresh Collections");

    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    auto respHandler = [asyncResp, chassisId](
                           const std::optional<std::string>& chassisPath) {
        if (!chassisPath)
        {
            messages::resourceNotFound(asyncResp->res, "Chassis", chassisId);
            return;
        }
        asyncResp->res.jsonValue["@odata.id"] = boost::urls::format(
            "/redfish/v1/Chassis/{}/Sensors/Oem/Ami/Threshold", chassisId);
        asyncResp->res.jsonValue["@odata.type"] =
            "#ThresholdSensorCollection.ThresholdSensorCollection";
        asyncResp->res.jsonValue["Description"] =
            "Collection of Threshold Sensors of this Chassis";
        asyncResp->res.jsonValue["Name"] = "Threshold Sensors";
        nlohmann::json& sensorPathList = asyncResp->res.jsonValue["Members"];
        sensorPathList = nlohmann::json::array();
        std::string chassisSensorPath = *chassisPath + "/all_sensors";
        ::dbus::utility::getAssociationEndPoints(
            chassisSensorPath,
            [asyncResp, chassisId, &sensorPathList](
                const boost::system::error_code& ec1,
                const ::dbus::utility::MapperEndPoints& sensorList) {
                if (ec1 || sensorList.empty())
                {
                    // no associations is not an error
                    return;
                }
                std::array<std::string, 2> interfaces = {
                    "xyz.openbmc_project.Sensor.Threshold.Warning",
                    "xyz.openbmc_project.Sensor.Threshold.Critical"};
                crow::connections::systemBus->async_method_call(
                    [asyncResp, chassisId, sensorList, &sensorPathList](
                        const boost::system::error_code ec,
                        const std::vector<std::string>& ifaceList) {
                        if (ec || ifaceList.empty())
                        {
                            BMCWEB_LOG_DEBUG(
                                "Error in querying GetSubTreePaths with Object Mapper. {}",
                                ec);
                            //    messages::internalError(asyncResp->res);
                            return;
                        }

                        std::unordered_set<std::string> sensorSet(
                            sensorList.begin(), sensorList.end());

                        for (const std::string& objpath : ifaceList)
                        {
                            // Check if objpath exists in SensorList if
                            if (sensorSet.find(objpath) == sensorSet.end())
                            {
                                continue;
                            }
                            std::size_t lastSlashPos = objpath.rfind('/');
                            std::size_t secondLastSlashPos =
                                objpath.rfind('/', lastSlashPos - 1);

                            if (lastSlashPos == std::string::npos ||
                                secondLastSlashPos == std::string::npos ||
                                (objpath.size() <= lastSlashPos + 1))
                            {
                                BMCWEB_LOG_ERROR(
                                    "Failed to parse object path: {}", objpath);
                                continue;
                            }

                            std::string sensorType = objpath.substr(
                                secondLastSlashPos + 1,
                                (lastSlashPos - secondLastSlashPos) - 1);
                            std::string sensorName =
                                objpath.substr(lastSlashPos + 1);

                            if (sensorType == "fan_tach")
                            {
                                sensorType = "fantach";
                            }
                            std::string sensorTypeName =
                                sensorType + "_" + sensorName;

                            sensorPathList.push_back(
                                {"@odata.id",
                                 boost::urls::format(
                                     "/redfish/v1/Chassis/{}/Sensors/Oem/Ami/Threshold/{}",
                                     chassisId, sensorTypeName)});
                        }
                        asyncResp->res.jsonValue["Members@odata.count"] =
                            sensorPathList.size();
                    },
                    "xyz.openbmc_project.ObjectMapper",
                    "/xyz/openbmc_project/object_mapper",
                    "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths", "/",
                    0, interfaces);
            });
    };
    redfish::chassis_utils::getValidChassisPath(asyncResp, chassisId,
                                                std::move(respHandler));
}

inline void getSensorFromDbus(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& sensorPath,
    const ::dbus::utility::MapperGetObject& mapperResponse)
{
    if (mapperResponse.size() != 1)
    {
        messages::internalError(asyncResp->res);
        return;
    }
    const auto& valueIface = *mapperResponse.begin();
    const std::string& connectionName = valueIface.first;
    BMCWEB_LOG_DEBUG("Looking up {}", connectionName);
    BMCWEB_LOG_DEBUG("Path {}", sensorPath);
    sdbusplus::message::object_path path(sensorPath);
    std::string name = path.filename();
    path = path.parent_path();
    std::string type = path.filename();
    std::set<std::string> discreteSensorTypes = {
        "cpu",          "watchdog",  "acpisystem",
        "powersupply",  "powerunit", "os",
        "acpidevice",   "battery",   "bmcfirmwarehealth",
        "chassisstate", "discrete"};
    ::dbus::utility::getAllProperties(
        connectionName, sensorPath, "",
        [asyncResp, sensorPath, name, type, discreteSensorTypes](
            const boost::system::error_code& ec,
            const ::dbus::utility::DBusPropertiesMap& valuesDict) {
            if (ec)
            {
                messages::internalError(asyncResp->res);
                return;
            }
            if (discreteSensorTypes.count(type) > 0)
            {
                uint16_t pass = 0;
                for (const auto& [valueName, valueVariant] : valuesDict)
                {
                    const uint16_t* value;
                    std::string endPoint;
                    if (valueName == "Associations")
                    {
                        if (std::holds_alternative<std::vector<std::tuple<
                                std::string, std::string, std::string>>>(
                                valueVariant))
                        {
                            // Get the vector of tuples
                            const auto& tupleVector =
                                std::get<std::vector<std::tuple<
                                    std::string, std::string, std::string>>>(
                                    valueVariant);
                            for (const auto& tuple : tupleVector)
                            {
                                endPoint = std::get<2>(tuple);
                                pass++;
                            }
                        }
                    }
                    else if (valueName == "State")
                    {
                        value = std::get_if<uint16_t>(&valueVariant);
                        pass++;
                    }
                    if (pass == 2)
                    {
                        asyncResp->res.jsonValue["@odata.type"] =
                            json_util::odataType("Sensor");
                        std::string nameSensor = name;
                        std::replace(nameSensor.begin(), nameSensor.end(), '_',
                                     ' ');
                        asyncResp->res.jsonValue["Name"] = nameSensor;
                        asyncResp->res.jsonValue["Id"] = type + '_' + name;
                        asyncResp->res.jsonValue["Description"] =
                            "Sensor Information";
                        if (*value != 0)
                        {
                            std::string objPath =
                                endPoint + "/" + std::string(name);
                            sensorState(
                                *value, objPath, type,
                                [asyncResp](const std::vector<std::string>&
                                                stringState) {
                                    nlohmann::json stateArray =
                                        nlohmann::json::array();
                                    for (auto& itr : stringState)
                                    {
                                        stateArray.push_back(itr);
                                    }
                                    asyncResp->res
                                        .jsonValue["Oem"]["Ami"]["States"] =
                                        stateArray;
                                    asyncResp->res.jsonValue["Oem"]["Ami"]
                                                            ["ReadingType"] =
                                        "Discrete";
                                });
                        }
                        else
                        {
                            asyncResp->res.jsonValue["Oem"]["Ami"]["States"] =
                                nullptr;
                        }
                        asyncResp->res.jsonValue["Oem"]["Ami"]["@odata.type"] =
                            json_util::odataType("AMISensor");
                        asyncResp->res.jsonValue["Status"]["State"] =
                            sensor_utils::getState(nullptr, true);
                        asyncResp->res.jsonValue["Status"]["Health"] =
                            sensor_utils::getHealth(asyncResp->res.jsonValue,
                                                    valuesDict, nullptr);
                    }
                }
            }
            else
            {
                sensor_utils::objectPropertiesToJson(
                    name, type, sensor_utils::ChassisSubNode::sensorsNode,
                    valuesDict, asyncResp->res.jsonValue, nullptr);
            }
        });
}

inline void handleSensorThreshGet(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId, const std::string& sensorId)
{
    asyncResp->res.clearHeader(boost::beast::http::field::allow);
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (!membersResponseGet(asyncResp, sensorId, "ThresholdSensorCollection"))
    {
        return;
    }
    asyncResp->res.addHeader("Allow", "GET, PATCH");

    auto respHandler = [asyncResp, chassisId, sensorId](
                           const std::optional<std::string>& chassisPath) {
        if (!chassisPath)
        {
            messages::resourceNotFound(asyncResp->res, "Chassis", chassisId);
            return;
        }
        std::pair<std::string, std::string> nameType =
            redfish::sensor_utils::splitSensorNameAndType(sensorId);
        if (nameType.first.empty() || nameType.second.empty())
        {
            messages::resourceNotFound(asyncResp->res, sensorId, "Sensor");
            return;
        }

        constexpr std::array<std::string_view, 3> interfaces = {
            "xyz.openbmc_project.Sensor.Value",
            "xyz.openbmc_project.Sensor.State",
            "xyz.openbmc_project.Association.Definitions"};
        std::string sensorPath = "/xyz/openbmc_project/sensors/" +
                                 nameType.first + '/' + nameType.second;
        ::dbus::utility::getDbusObject(
            sensorPath, interfaces,
            [asyncResp, sensorId, chassisId,
             sensorPath](const boost::system::error_code& ec,
                         const ::dbus::utility::MapperGetObject& subtree) {
                if (ec == boost::system::errc::io_error)
                {
                    BMCWEB_LOG_WARNING("Sensor not found from getSensorPaths");
                    messages::resourceNotFound(asyncResp->res, sensorId,
                                               "Sensor");
                    return;
                }
                if (ec)
                {
                    messages::internalError(asyncResp->res);
                    BMCWEB_LOG_ERROR(
                        "Sensor getSensorPaths resp_handler: Dbus error {}",
                        ec);
                    return;
                }
                asyncResp->res.jsonValue["@odata.id"] = boost::urls::format(
                    "/redfish/v1/Chassis/{}/Sensors/Oem/Ami/Threshold/{}",
                    chassisId, sensorId);
                getSensorFromDbus(asyncResp, sensorPath, subtree);
            });
    };

    redfish::chassis_utils::getValidChassisPath(asyncResp, chassisId,
                                                std::move(respHandler));
}

inline void setSensorThreshold(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    std::string& sensorType, std::string& sensorName,
    const double thresholdValue, std::string& threshold, std::string& objEnd)
{
    std::string service;
    std::string interface;
    std::string property;
    std::string Objpath;

    std::replace(sensorName.begin(), sensorName.end(), ' ', '_');

    std::array<std::string, 3> interfacesList = {
        "xyz.openbmc_project.Sensor.Threshold.Warning",
        "xyz.openbmc_project.Sensor.Threshold.Critical",
        "xyz.openbmc_project.Sensor.Threshold.NonRecoverable"};

    crow::connections::systemBus->async_method_call(
        [asyncResp, &service, &Objpath, threshold, &interface, sensorName,
         &property, objEnd, thresholdValue, sensorType](
            const boost::system::error_code ec,
            std::map<std::string,
                     std::map<std::string, std::vector<std::string>>>& resp) {
            if (ec)
            {
                return; // don't have to have this interface
            }
            std::string objectPath;
            for (const auto& pathPair : resp)
            {
                Objpath = pathPair.first;
                size_t pos = Objpath.find_last_of('/');
                if (pos == std::string::npos)
                {
                    return;
                }
                std::string last_string;
                last_string = Objpath;
                if (pos != std::string::npos)
                {
                    last_string.erase(0, pos + 1);
                }

                if (sensorName == last_string)
                {
                    const auto& objDict = pathPair.second;
                    if (objDict.empty())
                    {
                        continue;
                    }
                    service = objDict.begin()->first;
                    objectPath = Objpath;
                }
            }

            if (threshold == "LowerCaution")
            {
                interface = "xyz.openbmc_project.Sensor.Threshold.Warning";
                property = "WarningLow";
            }
            else if (threshold == "LowerCritical")
            {
                interface = "xyz.openbmc_project.Sensor.Threshold.Critical";
                property = "CriticalLow";
            }
            else if (threshold == "UpperCaution")
            {
                interface = "xyz.openbmc_project.Sensor.Threshold.Warning";
                property = "WarningHigh";
            }
            else if (threshold == "UpperCritical")
            {
                interface = "xyz.openbmc_project.Sensor.Threshold.Critical";
                property = "CriticalHigh";
            }
            else if (threshold == "UpperFatal")
            {
                interface =
                    "xyz.openbmc_project.Sensor.Threshold.NonRecoverable";
                property = "NonRecoverableHigh";
            }
            else if (threshold == "LowerFatal")
            {
                interface =
                    "xyz.openbmc_project.Sensor.Threshold.NonRecoverable";
                property = "NonRecoverableLow";
            }
            else
            {
                messages::propertyUnknown(asyncResp->res, threshold);
                return;
            }

            ::dbus::utility::getProperty<double>(
                service, objectPath, "xyz.openbmc_project.Sensor.Value",
                "Value",
                [asyncResp, thresholdValue, threshold](
                    const boost::system::error_code& ec1, double sensorValue) {
                    if (ec1)
                    {
                        BMCWEB_LOG_ERROR("Error while getting progress");
                        messages::internalError(asyncResp->res);
                        return;
                    }

                    if (threshold == "LowerCaution" ||
                        threshold == "LowerCritical" ||
                        threshold == "LowerFatal")
                    {
                        if (sensorValue > thresholdValue)
                        {
                            asyncResp->res.jsonValue["Status"] = "Asserted";
                            BMCWEB_LOG_DEBUG("Sensor Asserted successfully");
                        }
                        else
                        {
                            asyncResp->res.jsonValue["Status"] = "Deasserted";
                            BMCWEB_LOG_DEBUG("Sensor Deasserted successfully");
                        }
                    }
                    if (threshold == "UpperCaution" ||
                        threshold == "UpperCritical" ||
                        threshold == "UpperFatal")
                    {
                        if (sensorValue < thresholdValue)
                        {
                            asyncResp->res.jsonValue["Status"] = "Asserted";
                            BMCWEB_LOG_DEBUG("Sensor Asserted successfully");
                        }
                        else
                        {
                            asyncResp->res.jsonValue["Status"] = "Deasserted";
                            BMCWEB_LOG_DEBUG("Sensor Deasserted successfully");
                        }
                    }
                });

            sdbusplus::asio::setProperty(
                *crow::connections::systemBus, service, objectPath, interface,
                property, thresholdValue,
                [asyncResp](const boost::system::error_code& ec2) {
                    if (ec2)
                    {
                        messages::internalError(asyncResp->res);
                        return;
                    }
                    // messages::success(asyncResp->res);
                });
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTree",
        "/xyz/openbmc_project/sensors", 0, interfacesList);
}

inline void handleSensorThreshPatch(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId, const std::string& sensorId)
{
    asyncResp->res.clearHeader(boost::beast::http::field::allow);
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (!membersResponseGet(asyncResp, sensorId, "ThresholdSensorCollection"))
    {
        return;
    }
    std::pair<std::string, std::string> nameType =
        redfish::sensor_utils::splitSensorNameAndType(sensorId);
    if (nameType.first.empty() || nameType.second.empty())
    {
        messages::resourceNotFound(asyncResp->res, sensorId, "Sensor");
        return;
    }

    constexpr std::array<std::string_view, 3> interfaces = {
        "xyz.openbmc_project.Sensor.Value", "xyz.openbmc_project.Sensor.State",
        "xyz.openbmc_project.Association.Definitions"};
    std::string sensorPath = "/xyz/openbmc_project/sensors/" + nameType.first +
                             '/' + nameType.second;
    ::dbus::utility::getDbusObject(
        sensorPath, interfaces,
        [asyncResp, sensorId](const boost::system::error_code& ec,
                              const ::dbus::utility::MapperGetObject&) {
            if (ec == boost::system::errc::io_error)
            {
                BMCWEB_LOG_WARNING("Sensor not found from getSensorPaths");
                messages::resourceNotFound(asyncResp->res, sensorId, "Sensor");
                return;
            }
            if (ec)
            {
                messages::internalError(asyncResp->res);
                BMCWEB_LOG_ERROR(
                    "Sensor getSensorPaths resp_handler: Dbus error {}", ec);
                return;
            }
        });

    std::string sensorType = nameType.first;
    std::string objectNameEnd = nameType.second;
    std::string sensorName = nameType.second;
    std::replace(sensorName.begin(), sensorName.end(), '_', ' ');

    std::optional<double> lowerCaution;
    std::optional<double> lowerCritical;
    std::optional<double> upperCaution;
    std::optional<double> upperCritical;
    std::optional<double> upperFatal;
    std::optional<double> lowerFatal;
    std::string threshold;

    if (!json_util::readJsonPatch(                     //
            req, asyncResp->res,                       //
            "Thresholds/LowerCaution", lowerCaution,   //
            "Thresholds/LowerCritical", lowerCritical, //
            "Thresholds/UpperCaution", upperCaution,   //
            "Thresholds/UpperCritical", upperCritical, //
            "Thresholds/UpperFatal", upperFatal,       //
            "Thresholds/LowerFatal", lowerFatal        //
            ))
    {
        return;
    }

    asyncResp->res.jsonValue = {
        {"@odata.type", "#SensorThreshold.v1_0_0.SensorThreshold"},
        {"@odata.id", "/redfish/v1/Chassis/" + chassisId + "/" +
                          "Sensors/Oem/Ami/Threshold/" + sensorId},
        {"Id", sensorId + " Sensor Threshold"},
        {"Name", sensorName}};

    if (lowerCaution)
    {
        threshold = "LowerCaution";
        setSensorThreshold(asyncResp, sensorType, sensorName, *lowerCaution,
                           threshold, objectNameEnd);
    }
    if (lowerCritical)
    {
        threshold = "LowerCritical";
        setSensorThreshold(asyncResp, sensorType, sensorName, *lowerCritical,
                           threshold, objectNameEnd);
    }
    if (upperCaution)
    {
        threshold = "UpperCaution";
        setSensorThreshold(asyncResp, sensorType, sensorName, *upperCaution,
                           threshold, objectNameEnd);
    }
    if (upperCritical)
    {
        threshold = "UpperCritical";
        setSensorThreshold(asyncResp, sensorType, sensorName, *upperCritical,
                           threshold, objectNameEnd);
    }
    if (upperFatal)
    {
        threshold = "UpperFatal";
        setSensorThreshold(asyncResp, sensorType, sensorName, *upperFatal,
                           threshold, objectNameEnd);
    }
    if (lowerFatal)
    {
        threshold = "LowerFatal";
        setSensorThreshold(asyncResp, sensorType, sensorName, *lowerFatal,
                           threshold, objectNameEnd);
    }
}

inline void filterThresholdSensors(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId, const std::string& sensorId)
{
    std::array<std::string, 2> interfaces = {
        "xyz.openbmc_project.Sensor.Threshold.Warning",
        "xyz.openbmc_project.Sensor.Threshold.Critical"};

    std::pair<std::string, std::string> nameType =
        redfish::sensor_utils::splitSensorNameAndType(sensorId);
    if (nameType.first.empty() || nameType.second.empty())
    {
        messages::resourceNotFound(asyncResp->res, sensorId, "Sensor");
        return;
    }

    crow::connections::systemBus->async_method_call(
        [asyncResp, chassisId,
         sensorId /*, &result*/](const boost::system::error_code ec,
                                 const std::vector<std::string>& ifaceList) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG(
                    "Error in querying GetSubTreePaths with Object Mapper. {}",
                    ec);
                messages::internalError(asyncResp->res);
                return;
            }
            for (const std::string& objpath : ifaceList)
            {
                std::size_t lastSlashPos = objpath.rfind('/');
                std::size_t secondLastSlashPos =
                    objpath.rfind('/', lastSlashPos - 1);

                std::string sensorType =
                    objpath.substr(secondLastSlashPos + 1,
                                   lastSlashPos - secondLastSlashPos - 1);
                std::string sensorName = objpath.substr(lastSlashPos + 1);

                std::string sensorTypeName =
                    redfish::sensor_utils::getSensorId(sensorName, sensorType);

                if (sensorTypeName == sensorId)
                {
                    asyncResp->res.jsonValue["Oem"]["Ami"]["SensorThreshold"]
                                            ["@odata.id"] = boost::urls::format(
                        "/redfish/v1/Chassis/{}/Sensors/Oem/Ami/Threshold/{}",
                        chassisId, sensorId);
                    return;
                }
                else
                {
                    continue;
                }
            }
            return;
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths",
        "/xyz/openbmc_project/sensors/", 0, interfaces);
    return;
}

inline bool valideSensorWithConfFile(const std::string& sensorId)
{
    std::ifstream inputFile("/etc/sensor-reader-conf/configuredsensors");
    if (inputFile.is_open())
    {
        std::string sensorNameSearch, fileLine;
        size_t pos = sensorId.find('_');
        if (pos != std::string::npos)
        {
            sensorNameSearch = sensorId.substr(pos + 1);
            bool found = false;
            while (std::getline(inputFile, fileLine))
            {
                if (fileLine.find(sensorNameSearch) != std::string::npos)
                {
                    found = true;
                    break;
                }
            }
            inputFile.close();
            return found;
        }
        inputFile.close();
    }
    return false;
}

inline void getSensorReading(const std::string& sensorPath,
                             std::function<void(const std::string&)> callback)
{
    constexpr std::array<std::string_view, 3> interfaces = {
        "xyz.openbmc_project.Sensor.Value", "xyz.openbmc_project.Sensor.State",
        "xyz.openbmc_project.Association.Definitions"};
    ::dbus::utility::getDbusObject(
        sensorPath, interfaces,
        [callback,
         sensorPath](const boost::system::error_code& ec,
                     const ::dbus::utility::MapperGetObject& subtree) {
            if (ec)
            {
                callback("nan");
                return;
            }
            std::string service = subtree.begin()->first;

            ::dbus::utility::getProperty<double>(
                service, sensorPath, "xyz.openbmc_project.Sensor.Value",
                "Value",
                [callback](boost::system::error_code ec1, double value) {
                    if (ec1)
                    {
                        callback("nan");
                        return;
                    }
                    callback(std::to_string(value));
                });
        });
}

inline void handleSensorGet(App& app, const crow::Request& req,
                            const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                            const std::string& chassisId,
                            const std::string& sensorId)
{
    asyncResp->res.clearHeader(boost::beast::http::field::allow);

    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (!membersResponseGet(asyncResp, sensorId, "SensorCollection"))
    {
        return;
    }
    asyncResp->res.addHeader("Allow", "GET");

    auto respHandler = [asyncResp, chassisId, sensorId](
                           const std::optional<std::string>& chassisPath) {
        if (!chassisPath)
        {
            messages::resourceNotFound(asyncResp->res, "Chassis", chassisId);
            return;
        }
        // Proceed with sensor retrieval after chassis validation
        BMCWEB_LOG_DEBUG(
            "Chassis ID is valid. Proceeding with sensor retrieval.");
        std::pair<std::string, std::string> nameType =
            redfish::sensor_utils::splitSensorNameAndType(sensorId);
        std::string sensorPath = "/xyz/openbmc_project/sensors/" +
                                 nameType.first + '/' + nameType.second;
        if (nameType.first.empty() || nameType.second.empty())
        {
            messages::resourceNotFound(asyncResp->res, sensorId, "Sensor");
            return;
        }
        if (valideSensorWithConfFile(sensorId))
        {
            getSensorReading(sensorPath, [asyncResp, chassisId, sensorId](
                                             const std::string& reading) {
                if (reading != "nan")
                {
                    asyncResp->res.jsonValue["Oem"]["Ami"]
                                            ["@odata.id"] = boost::urls::format(
                        "/redfish/v1/Chassis/{}/Sensors/{}/Oem/SensorHistory",
                        chassisId, sensorId);
                }
            });
        }
        filterThresholdSensors(asyncResp, chassisId, sensorId);

        BMCWEB_LOG_DEBUG("Sensor doGet enter");
        constexpr std::array<std::string_view, 3> interfaces = {
            "xyz.openbmc_project.Sensor.Value",
            "xyz.openbmc_project.Sensor.State",
            "xyz.openbmc_project.Association.Definitions"};
        // Get a list of all of the sensors that implement Sensor.Value
        // and get the path and service name associated with the sensor
        ::dbus::utility::getDbusObject(
            sensorPath, interfaces,
            [asyncResp, sensorId, chassisId,
             sensorPath](const boost::system::error_code& ec,
                         const ::dbus::utility::MapperGetObject& subtree) {
                BMCWEB_LOG_DEBUG("respHandler1 enter");
                if (ec == boost::system::errc::io_error)
                {
                    BMCWEB_LOG_WARNING("Sensor not found from getSensorPaths");
                    messages::resourceNotFound(asyncResp->res, sensorId,
                                               "Sensor");
                    return;
                }
                if (ec)
                {
                    messages::internalError(asyncResp->res);
                    BMCWEB_LOG_ERROR(
                        "Sensor getSensorPaths resp_handler: Dbus error {}",
                        ec);
                    return;
                }
                asyncResp->res.jsonValue["@odata.id"] = boost::urls::format(
                    "/redfish/v1/Chassis/{}/Sensors/{}", chassisId, sensorId);
                getSensorFromDbus(asyncResp, sensorPath, subtree);
                BMCWEB_LOG_DEBUG("respHandler1 exit");
            });
    };
    redfish::chassis_utils::getValidChassisPath(asyncResp, chassisId,
                                                std::move(respHandler));
}

inline void handleSensorPost(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId, const std::string& sensorId)
{
    asyncResp->res.clearHeader(boost::beast::http::field::allow);
    if (!membersResponseGet(asyncResp, sensorId, "SensorCollection"))
    {
        return;
    }
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    crow::connections::systemBus->async_method_call(
        [asyncResp, chassisId,
         sensorId](const boost::system::error_code ec_,
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
                        << "extractedChassisId: " << extractedChassisId << "\n";
                    std::cerr << "chassisId: " << chassisId << "\n";

                    if (extractedChassisId == chassisId)
                    {
                        isValid = true;
                        break;
                    }
                }
            }
            if (!isValid)
            {
                messages::resourceNotFound(asyncResp->res, "chassisId",
                                           chassisId);
                return;
            }

            // Proceed with sensor retrieval after chassis validation
            std::pair<std::string, std::string> nameType =
                redfish::sensor_utils::splitSensorNameAndType(sensorId);
            std::string sensorPath = "/xyz/openbmc_project/sensors/" +
                                     nameType.first + '/' + nameType.second;
            if (nameType.first.empty() || nameType.second.empty())
            {
                messages::resourceNotFound(asyncResp->res, sensorId, "Sensor");
                return;
            }
            else
            {
                constexpr std::array<std::string_view, 3> interfaces = {
                    "xyz.openbmc_project.Sensor.Value",
                    "xyz.openbmc_project.Sensor.State",
                    "xyz.openbmc_project.Association.Definitions"};
                ::dbus::utility::getDbusObject(
                    sensorPath, interfaces,
                    [asyncResp, sensorId](
                        const boost::system::error_code& ec,
                        const ::dbus::utility::MapperGetObject& /*subtree*/) {
                        if (ec == boost::system::errc::io_error)
                        {
                            messages::resourceNotFound(asyncResp->res, sensorId,
                                                       "Sensor");
                            return;
                        }
                        if (ec)
                        {
                            BMCWEB_LOG_ERROR(
                                "Sensor getSensorPaths resp_handler: Dbus error {}",
                                ec);
                            messages::internalError(asyncResp->res);
                            return;
                        }
                        else
                        {
                            messages::operationNotAllowed(asyncResp->res);
                            return;
                        }
                    });
            }
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths",
        "/xyz/openbmc_project/inventory", 0,
        std::array<const char*, 2>{
            "xyz.openbmc_project.Inventory.Item.Board",
            "xyz.openbmc_project.Inventory.Item.Chassis"});
}

inline void handleSensorHistoryGet(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId, const std::string& sensorId)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    std::pair<std::string, std::string> nameType =
        redfish::sensor_utils::splitSensorNameAndType(sensorId);
    if (valideSensorWithConfFile(sensorId))
    {
        std::string sensorPath = "/xyz/openbmc_project/sensors/" +
                                 nameType.first + '/' + nameType.second;
        getSensorReading(sensorPath, [asyncResp, chassisId, sensorId,
                                      nameType](const std::string& reading) {
            if (reading == "nan")
            {
                messages::resourceNotFound(asyncResp->res, sensorId, "Sensor");
                return;
            }
            if (nameType.first.empty() || nameType.second.empty())
            {
                messages::resourceNotFound(asyncResp->res, sensorId, "Sensor");
                return;
            }
            std::string sensorName = nameType.second;
            std::replace(sensorName.begin(), sensorName.end(), '_', ' ');
            asyncResp->res.jsonValue["@odata.id"] = boost::urls::format(
                "/redfish/v1/Chassis/{}/Sensors/{}/Oem/SensorHistory",
                chassisId, sensorId);

            asyncResp->res.jsonValue = {
                {"@odata.type", "#SensorHistory.v1_0_0.SensorHistory"},
                {"@odata.id", "/redfish/v1/Chassis/" + chassisId + "/" +
                                  "Sensors/" + sensorId + "/Oem/SensorHistory"},
                {"Id", sensorId + " Sensor History"},
                {"Name", sensorName},
                {"SensorName", sensorName}};

            crow::connections::systemBus->async_method_call(
                [asyncResp](const boost::system::error_code ec,
                            const std::vector<
                                std::pair<std::string, std::variant<uint64_t>>>&
                                propertiesList) {
                    if (ec)
                    {
                        messages::internalError(asyncResp->res);
                        BMCWEB_LOG_ERROR(
                            "Sensor patchSensorHistory Interval Dbus error {}",
                            ec);
                        return;
                    }

                    for (const std::pair<std::string, std::variant<uint64_t>>&
                             property : propertiesList)
                    {
                        const std::string& propertyName = property.first;
                        if ((propertyName.find("Interval") !=
                             std::string::npos) ||
                            (propertyName.find("TimeFrame") !=
                             std::string::npos))
                        {
                            const uint64_t* value =
                                std::get_if<uint64_t>(&property.second);
                            if (value != nullptr)
                            {
                                asyncResp->res.jsonValue[propertyName] = *value;
                            }
                        }
                    }
                },
                "xyz.openbmc_project.SensorReader",
                "/xyz/openbmc_project/SensorReader/History",
                "org.freedesktop.DBus.Properties", "GetAll",
                "xyz.openbmc_project.SensorReader.History.Read");

            crow::connections::systemBus->async_method_call(
                [asyncResp, chassisId,
                 sensorId](const boost::system::error_code ec,
                           const std::vector<std::pair<uint64_t, double>>&
                               historyResp) {
                    if (ec)
                    {
                        messages::internalError(asyncResp->res);
                        BMCWEB_LOG_ERROR(
                            "Sensor patchSensorHistory Interval Dbus error {}",
                            ec);
                        return;
                    }

                    nlohmann::json& historyArray =
                        asyncResp->res.jsonValue["SensorReadings"];
                    uint16_t sensorCount = 0;
                    for (const std::pair<uint64_t, double>& property :
                         historyResp)
                    {
                        const uint64_t time = property.first;
                        const double value = property.second;

                        nlohmann::json historyItem;
                        historyItem["@odata.id"] =
                            "/redfish/v1/Chassis/" + chassisId + "/" +
                            "Sensors/" + sensorId + "/Oem/SensorHistory" +
                            "#/SensorReadings/" + std::to_string(sensorCount++);
                        historyItem["@odata.type"] = "#OemSensorHistory.v1_0_0";
                        historyItem["Time"] = time;
                        historyItem["Value"] = value;
                        historyArray.push_back(historyItem);
                    }
                    asyncResp->res.jsonValue["SensorReadingsCount"] =
                        sensorCount;
                },
                "xyz.openbmc_project.SensorReader",
                "/xyz/openbmc_project/SensorReader/History",
                "xyz.openbmc_project.SensorReader.History.Read", "Read",
                (nameType.second));
        });
    }
    else
    {
        messages::resourceNotFound(asyncResp->res, sensorId, "Sensor");
        return;
    }
}
inline void handleSensorHistorypatch(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId, const std::string& sensorId)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    std::pair<std::string, std::string> nameType =
        redfish::sensor_utils::splitSensorNameAndType(sensorId);
    if (valideSensorWithConfFile(sensorId))
    {
        std::string sensorPath = "/xyz/openbmc_project/sensors/" +
                                 nameType.first + '/' + nameType.second;
        getSensorReading(sensorPath, [asyncResp, chassisId, sensorId,
                                      &req](const std::string& reading) {
            if (reading == "nan")
            {
                messages::resourceNotFound(asyncResp->res, sensorId, "Sensor");
                return;
            }
            BMCWEB_LOG_DEBUG(
                "Handling sensor history for Chassis ID: {} Sensor ID:",
                chassisId, sensorId);
            std::optional<uint64_t> interval;
            std::optional<uint64_t> timeFrame;
            if (!json_util::readJsonPatch( //
                    req, asyncResp->res,   //
                    "Interval", interval,  //
                    "TimeFrame", timeFrame //
                    ))
            {
                return;
            }
            if (interval)
            {
                crow::connections::systemBus->async_method_call(
                    [asyncResp, interval](const boost::system::error_code ec) {
                        if (ec)
                        {
                            messages::internalError(asyncResp->res);
                            BMCWEB_LOG_ERROR(
                                "Sensor patchSensorHistory Interval Dbus error {}",
                                ec);
                            return;
                        }
                    },
                    "xyz.openbmc_project.SensorReader",
                    "/xyz/openbmc_project/SensorReader/History",
                    "org.freedesktop.DBus.Properties", "Set",
                    "xyz.openbmc_project.SensorReader.History.Read", "Interval",
                    std::variant<uint64_t>(*interval));
            }
            if (timeFrame)
            {
                crow::connections::systemBus->async_method_call(
                    [asyncResp, timeFrame](const boost::system::error_code ec) {
                        if (ec)
                        {
                            messages::internalError(asyncResp->res);
                            BMCWEB_LOG_ERROR(
                                "Sensor patchSensorHistory Interval Dbus error {}",
                                ec);
                            return;
                        }
                    },
                    "xyz.openbmc_project.SensorReader",
                    "/xyz/openbmc_project/SensorReader/History",
                    "org.freedesktop.DBus.Properties", "Set",
                    "xyz.openbmc_project.SensorReader.History.Read",
                    "TimeFrame", std::variant<uint64_t>(*timeFrame));
            }
        });
    }
    else
    {
        messages::resourceNotFound(asyncResp->res, sensorId, "Sensor");
        return;
    }
}
} // namespace sensors

inline void requestRoutesSensorCollection(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Chassis/<str>/Sensors/")
        .privileges(redfish::privileges::getSensorCollection)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(sensors::handleSensorCollectionGet, std::ref(app)));
}

inline void requestRoutesSensorThreshCollection(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Chassis/<str>/Sensors/Oem/Ami/Threshold/")
        .privileges(redfish::privileges::getSensorThreshCollection)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            sensors::handleSensorThreshCollectionGet, std::ref(app)));
}

inline void requestRoutesSensorThresh(App& app)
{
    BMCWEB_ROUTE(app,
                 "/redfish/v1/Chassis/<str>/Sensors/Oem/Ami/Threshold/<str>/")
        .privileges(redfish::privileges::getSensorThresh)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(sensors::handleSensorThreshGet, std::ref(app)));

    BMCWEB_ROUTE(app,
                 "/redfish/v1/Chassis/<str>/Sensors/Oem/Ami/Threshold/<str>/")
        .privileges(redfish::privileges::patchSensorThresh)
        .methods(boost::beast::http::verb::patch)(
            std::bind_front(sensors::handleSensorThreshPatch, std::ref(app)));

    BMCWEB_ROUTE(app,
                 "/redfish/v1/Chassis/<str>/Sensors/Oem/Ami/Threshold/<str>/")
        .methods(boost::beast::http::verb::post, boost::beast::http::verb::put,
                 boost::beast::http::verb::delete_)(
            [](const crow::Request& req,
               const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
               const std::string& /* chassisName */,
               const std::string& sensorId) {
                asyncResp->res.clearHeader(boost::beast::http::field::allow);
                if (!membersResponseGet(asyncResp, sensorId,
                                        "ThresholdSensorCollection"))
                {
                    return;
                }
                asyncResp->res.addHeader("Allow", "GET, PATCH");
                if (req.method() == boost::beast::http::verb::delete_)
                {
                    messages::resourceCannotBeDeleted(asyncResp->res);
                    return;
                }
                messages::operationNotAllowed(asyncResp->res);
            });
}

inline void requestRoutesSensor(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Chassis/<str>/Sensors/<str>/")
        .privileges(redfish::privileges::getSensor)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(sensors::handleSensorGet, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Chassis/<str>/Sensors/<str>/")
        .privileges(redfish::privileges::getSensor)
        .methods(boost::beast::http::verb::post,
                 boost::beast::http::verb::patch, boost::beast::http::verb::put,
                 boost::beast::http::verb::delete_)(
            std::bind_front(sensors::handleSensorPost, std::ref(app)));
}

inline void requestRoutesSensorHistory(App& app)
{
    BMCWEB_ROUTE(app,
                 "/redfish/v1/Chassis/<str>/Sensors/<str>/Oem/SensorHistory")
        .privileges(redfish::privileges::getSensor)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(sensors::handleSensorHistoryGet, std::ref(app)));

    BMCWEB_ROUTE(app,
                 "/redfish/v1/Chassis/<str>/Sensors/<str>/Oem/SensorHistory")
        .privileges(redfish::privileges::patchSensor)
        .methods(boost::beast::http::verb::patch)(
            std::bind_front(sensors::handleSensorHistorypatch, std::ref(app)));
}

} // namespace redfish
