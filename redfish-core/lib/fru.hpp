#pragma once

#include "app.hpp"
#include "query.hpp"
#include "registries/privilege_registry.hpp"
#include "utils/json_utils.hpp"

#include <boost/url/format.hpp>

#include <memory>
#include <optional>
#include <string>

namespace redfish
{

// Chassis interfaces
constexpr const std::array<std::string_view, 2> chassisInterfaces = {
    "xyz.openbmc_project.Inventory.Item.Board",
    "xyz.openbmc_project.Inventory.Item.Chassis"};

// FRU interfaces
constexpr const std::array<std::string_view, 1> fruInterfaces = {
    "xyz.openbmc_project.FruDevice"};

// Map of FRU D-Bus property to Redfish property name
constexpr const std::array<std::pair<std::string_view, std::string_view>, 13>
    fruPropertyMap = {{
        {"BOARD_FRU_VERSION_ID", "BoardVersion"},
        {"PRODUCT_VERSION", "ProductVersion"},
        {"BOARD_MANUFACTURER", "BoardMfg"},
        {"PRODUCT_MANUFACTURER", "ProductManufacturer"},
        {"BOARD_PRODUCT_NAME", "BoardProduct"},
        {"PRODUCT_PRODUCT_NAME", "ProductName"},
        {"BOARD_PART_NUMBER", "BoardPartNumber"},
        {"PRODUCT_PART_NUMBER", "ProductPartNumber"},
        {"BOARD_SERIAL_NUMBER", "BoardSerialNumber"},
        {"PRODUCT_SERIAL_NUMBER", "ProductSerialNumber"},
        {"BOARD_LANGUAGE_CODE", "BoardLanguageCode"},
        {"PRODUCT_LANGUAGE_CODE", "ProductLanguageCode"},
        {"BOARD_MANUFACTURE_DATE", "BoardMfgDate"},
    }};

/* check the existence of the instance and set response */
inline void setFruCollection(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId, const boost::system::error_code& ec,
    const dbus::utility::MapperGetSubTreePathsResponse& subtreePaths)
{
    if (ec)
    {
        BMCWEB_LOG_ERROR("DBUS response error {}", ec);
        messages::internalError(asyncResp->res);
        return;
    }
    const bool chassisFound = std::ranges::any_of(
        subtreePaths, [&chassisId](const std::string& path) {
            return sdbusplus::message::object_path(path).filename() ==
                   chassisId;
        });

    if (!chassisFound)
    {
        messages::resourceNotFound(asyncResp->res, "Chassis", chassisId);
        return;
    }
    else
    {
        asyncResp->res.jsonValue["@odata.type"] =
            json_util::odataType("AmiChassisFRUCollection");
        asyncResp->res.jsonValue["@odata.id"] = boost::urls::format(
            "/redfish/v1/Chassis/{}/Oem/Ami/FRU", chassisId);
        asyncResp->res.jsonValue["Description"] =
            "Resource Collection of FRU instances";
        asyncResp->res.jsonValue["Name"] = "FRUCollection";

        dbus::utility::getSubTreePaths(
            "/xyz/openbmc_project/FruDevice", 1, fruInterfaces,
            [asyncResp, chassisId](
                const boost::system::error_code& errCode,
                const dbus::utility::MapperGetSubTreePathsResponse& fruPaths) {
                if (errCode)
                {
                    // do not add err msg in redfish response, because this is
                    // not mandatory property
                    BMCWEB_LOG_ERROR("DBUS error: no matched iface:{}",
                                     errCode);
                    return;
                }

                nlohmann::json& entriesArray =
                    asyncResp->res.jsonValue["Members"];

                for (const auto& fruPath : fruPaths)
                {
                    std::string fruName =
                        sdbusplus::message::object_path(fruPath).filename();
                    if (fruName.empty())
                    {
                        BMCWEB_LOG_ERROR("Invalid fru object path:{}", fruPath);
                        continue;
                    }
                    entriesArray.push_back(
                        {{"@odata.id",
                          boost::urls::format(
                              "/redfish/v1/Chassis/{}/Oem/Ami/FRU/{}",
                              chassisId, fruName)}});
                } // object path loop

                asyncResp->res.jsonValue["Members@odata.count"] =
                    entriesArray.size();
            });
    }
}

inline void setFru(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId, const std::string& fruName,
    const boost::system::error_code& ec,
    const dbus::utility::MapperGetSubTreePathsResponse& subtreePaths)
{
    if (ec)
    {
        BMCWEB_LOG_ERROR("DBUS response error {}", ec);
        messages::internalError(asyncResp->res);
        return;
    }

    // Check chassis existence
    const bool chassisFound = std::ranges::any_of(
        subtreePaths, [&chassisId](const std::string& path) {
            return sdbusplus::message::object_path(path).filename() ==
                   chassisId;
        });

    if (!chassisFound)
    {
        messages::resourceNotFound(asyncResp->res, "Chassis", chassisId);
        return;
    }

    // fruName is the last path component
    const std::string fruPath =
        std::string("/xyz/openbmc_project/FruDevice/") + fruName;

    dbus::utility::getAllProperties(
        "xyz.openbmc_project.FruDevice", fruPath,
        "xyz.openbmc_project.FruDevice",
        [asyncResp, chassisId,
         fruName](const boost::system::error_code error_code,
                  const dbus::utility::DBusPropertiesMap& dbus_data) {
            if (error_code)
            {
                BMCWEB_LOG_ERROR("D-Bus response error:{}", error_code);
                if (error_code.value() == EBADR)
                {
                    messages::resourceNotFound(asyncResp->res, "FRU", fruName);
                }
                else
                {
                    messages::internalError(asyncResp->res);
                }
                return;
            }

            asyncResp->res.jsonValue["@odata.id"] = boost::urls::format(
                "/redfish/v1/Chassis/{}/Oem/Ami/FRU/{}", chassisId, fruName);
            asyncResp->res.jsonValue["@odata.type"] =
                json_util::odataType("AmiChassisFRU");
            asyncResp->res.jsonValue["Name"] = fruName;
            asyncResp->res.jsonValue["Description"] = "FRU Device Information";
            asyncResp->res.jsonValue["Id"] = fruName;

            for (const auto& [propName, propValue] : dbus_data)
            {
                auto it = std::ranges::find_if(
                    fruPropertyMap, [&propName](const auto& entry) {
                        return entry.first == propName;
                    });
                if (it != fruPropertyMap.end())
                {
                    const std::string* val =
                        std::get_if<std::string>(&propValue);
                    if (val != nullptr)
                    {
                        asyncResp->res.jsonValue[it->second] = *val;
                    }
                }
            }
        });
}

inline void postFru(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId, const std::string& fruName,
    const boost::system::error_code& ec,
    const dbus::utility::MapperGetSubTreePathsResponse& subtreePaths)
{
    if (ec)
    {
        BMCWEB_LOG_ERROR("DBUS response error {}", ec);
        messages::internalError(asyncResp->res);
        return;
    }
    const bool chassisFound = std::ranges::any_of(
        subtreePaths, [&chassisId](const std::string& path) {
            return sdbusplus::message::object_path(path).filename() ==
                   chassisId;
        });

    if (!chassisFound)
    {
        messages::resourceNotFound(asyncResp->res, "Chassis", chassisId);
        return;
    }
    else
    {
        dbus::utility::getSubTreePaths(
            "/xyz/openbmc_project/FruDevice", 2, fruInterfaces,
            [asyncResp, fruName](
                const boost::system::error_code& errCode,
                const dbus::utility::MapperGetSubTreePathsResponse& fruPaths) {
                if (errCode)
                {
                    messages::internalError(asyncResp->res);
                    BMCWEB_LOG_ERROR(
                        "FRU getfruPaths resp_handler: Dbus error {}", errCode);
                    return;
                }

                const bool fruFound = std::ranges::any_of(
                    fruPaths, [&fruName](const std::string& path) {
                        return sdbusplus::message::object_path(path)
                                   .filename() == fruName;
                    });
                if (!fruFound)
                {
                    BMCWEB_LOG_ERROR("Could not find object path for fru:{}",
                                     fruName);
                    messages::resourceNotFound(asyncResp->res, "FRU", fruName);
                    return;
                }
                else
                {
                    asyncResp->res.addHeader("Allow", "GET");
                    messages::operationNotAllowed(asyncResp->res);
                    return;
                }
            });
    }
}

inline void handleFruCollectionOperationNotAllowed(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& /*chassisId*/)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    asyncResp->res.clearHeader(boost::beast::http::field::allow);
    asyncResp->res.addHeader("Allow", "GET");
    messages::operationNotAllowed(asyncResp->res);
}

inline void handleFruCollectionGet(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId)
{
    asyncResp->res.clearHeader(boost::beast::http::field::allow);
    asyncResp->res.addHeader("Allow", "GET");

    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    dbus::utility::getSubTreePaths(
        "/xyz/openbmc_project/inventory", 0, chassisInterfaces,
        std::bind_front(setFruCollection, asyncResp, chassisId));

    return;
}

inline void handleFruGet(App& app, const crow::Request& req,
                         const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                         const std::string& chassisId,
                         const std::string& fruName)
{
    asyncResp->res.clearHeader(boost::beast::http::field::allow);

    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (!membersResponseGet(asyncResp, fruName, "ChassisFRUCollection"))
    {
        return;
    }
    asyncResp->res.addHeader("Allow", "GET");

    dbus::utility::getSubTreePaths(
        "/xyz/openbmc_project/inventory", 0, chassisInterfaces,
        std::bind_front(setFru, asyncResp, chassisId, fruName));

    return;
}

inline void requestRoutesFru(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Chassis/<str>/Oem/Ami/FRU/<str>/")
        .privileges(redfish::privileges::getFru)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleFruGet, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Chassis/<str>/Oem/Ami/FRU/<str>/")
        .privileges(redfish::privileges::getFru)
        .methods(boost::beast::http::verb::post,
                 boost::beast::http::verb::patch,
                 boost::beast::http::verb::delete_)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& chassisId, const std::string& fruName) {
                asyncResp->res.clearHeader(boost::beast::http::field::allow);
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }
                if (!membersResponseGet(asyncResp, fruName,
                                        "ChassisFRUCollection"))
                {
                    return;
                }

                dbus::utility::getSubTreePaths(
                    "/xyz/openbmc_project/inventory", 0, chassisInterfaces,
                    std::bind_front(postFru, asyncResp, chassisId, fruName));

                return;
            });
}

inline void requestRoutesFruCollection(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Chassis/<str>/Oem/Ami/FRU/")
        .privileges(redfish::privileges::getFruCollection)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleFruCollectionGet, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Chassis/<str>/Oem/Ami/FRU/")
        .privileges(redfish::privileges::getFruCollection)
        .methods(boost::beast::http::verb::post,
                 boost::beast::http::verb::patch,
                 boost::beast::http::verb::delete_)(std::bind_front(
            handleFruCollectionOperationNotAllowed, std::ref(app)));
}
} // namespace redfish
