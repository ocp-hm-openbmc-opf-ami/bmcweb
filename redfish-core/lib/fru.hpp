#pragma once

#include "app.hpp"
#include "query.hpp"
#include "registries/privilege_registry.hpp"

#include <boost/url/format.hpp>

#include <memory>
#include <optional>
#include <string>

namespace redfish
{

using GetSubTreeType = std::vector<
    std::pair<std::string,
              std::vector<std::pair<std::string, std::vector<std::string>>>>>;
using PropertiesType =
    boost::container::flat_map<std::string, dbus::utility::DbusVariantType>;

inline void
    handleFruCollectionGet(App& app, const crow::Request& req,
                           const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                           const std::string& chassisId)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    asyncResp->res.jsonValue["@odata.type"] =
        "#AMIChassisFRUCollection.AMIChassisFRUCollection";
    asyncResp->res.jsonValue["@odata.id"] =
        boost::urls::format("/redfish/v1/Chassis/{}/FRU", chassisId);
    asyncResp->res.jsonValue["Description"] =
        "Resource Collection of FRU instances";
    asyncResp->res.jsonValue["Name"] = "FRUCollection";

    crow::connections::systemBus->async_method_call(
        [asyncResp, chassisId](
            const boost::system::error_code ec,
            const std::vector<std::pair<
                std::string,
                std::vector<std::pair<std::string, std::vector<std::string>>>>>&
                subtree) {
            if (ec)
            {
                // do not add err msg in redfish response, becaues this is not
                //     mandatory property
                BMCWEB_LOG_ERROR("DBUS error: no matched iface:{}", ec);
                return;
            }

            nlohmann::json& entriesArray = asyncResp->res.jsonValue["Members"];

            for (const auto& fruobject : subtree)
            {
                std::string fru = fruobject.first;
                std::size_t lastPos = fru.rfind("/");

                if (lastPos == std::string::npos || lastPos + 1 >= fru.size())
                {
                    BMCWEB_LOG_ERROR("Invalid fru object path:{}", fru);
                    messages::internalError(asyncResp->res);
                    return;
                }

                std::string fruName = fru.substr(lastPos + 1);
                entriesArray.push_back(
                    {{"@odata.id", "/redfish/v1/Chassis/" + chassisId + "/" +
                                       "FRU" + "/" + fruName}});

            } // object path loop

            asyncResp->res.jsonValue["Members@odata.count"] =
                entriesArray.size();
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTree",
        "/xyz/openbmc_project/FruDevice", 1,
        std::array<const char*, 1>{"xyz.openbmc_project.FruDevice"});

    return;
}

inline void handleFruGet(App& app, const crow::Request& req,
                         const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                         const std::string& chassisId,
                         const std::string& fruName)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    asyncResp->res.jsonValue["@odata.id"] = boost::urls::format(
        "/redfish/v1/Chassis/{}/FRU/{}", chassisId, fruName);
    asyncResp->res.jsonValue["@odata.type"] =
        "#AMIChassisFRU.v1_0_0.AMIChassisFRU";
    asyncResp->res.jsonValue["Name"] = fruName;

    crow::connections::systemBus->async_method_call(
        [asyncResp, fruName](const boost::system::error_code ec,
                             const GetSubTreeType& subtree) {
            if (ec)
            {
                messages::internalError(asyncResp->res);
                BMCWEB_LOG_ERROR("FRU getfruPaths resp_handler: Dbus error {}",
                                 ec);
                return;
            }

            GetSubTreeType::const_iterator it = std::find_if(
                subtree.begin(), subtree.end(),
                [fruName](
                    const std::pair<
                        std::string,
                        std::vector<std::pair<
                            std::string, std::vector<std::string>>>>& object) {
                    std::string_view fru = object.first;
                    std::size_t lastPos = fru.rfind("/");
                    if (lastPos == std::string::npos ||
                        lastPos + 1 >= fru.size())
                    {
                        BMCWEB_LOG_ERROR("Invalid fru path:{}", fru);
                        return false;
                    }
                    std::string_view name = fru.substr(lastPos + 1);

                    return name == fruName;
                });

            if (it == subtree.end())
            {
                BMCWEB_LOG_ERROR("Could not find object path for fru:{}",
                                 fruName);
                messages::resourceNotFound(asyncResp->res, "fru", fruName);
                return;
            }

            const std::string fruPath = (*it).first;

            BMCWEB_LOG_DEBUG("Found fru object path for fru{}:{}", fruName,
                             fruPath);

            crow::connections::systemBus->async_method_call(
                [asyncResp](const boost::system::error_code error_code,
                            const PropertiesType& dbus_data) {
                    if (error_code)
                    {
                        BMCWEB_LOG_ERROR("D-Bus response error:{}", error_code);
                        messages::internalError(asyncResp->res);
                        return;
                    }

                    std::vector<std::string> Fru_Objectdata;

                    for (const auto& property : dbus_data)
                    {
                        std::string res = "";
                        if ((property.first == "BOARD_FRU_VERSION_ID") ||
                            (property.first == "PRODUCT_VERSION"))
                        {
                            const std::string* version =
                                std::get_if<std::string>(&property.second);

                            if (property.first == "BOARD_FRU_VERSION_ID")
                            {
                                res = "Board Version  : " + *version;
                                Fru_Objectdata.emplace_back(res);
                            }

                            else
                            {
                                res = "Product Version  : " + *version;
                                Fru_Objectdata.emplace_back(res);
                            }
                        }

                        else if ((property.first == "BOARD_MANUFACTURER") ||
                                 (property.first == "PRODUCT_MANUFACTURER"))
                        {
                            const std::string* manufacturer =
                                std::get_if<std::string>(&property.second);
                            if (property.first == "BOARD_MANUFACTURER")
                            {
                                res = "Board Mfg  : " + *manufacturer;
                                Fru_Objectdata.emplace_back(res);
                            }
                            else
                            {
                                res = "Product Manufacturer  : " +
                                      *manufacturer;
                                Fru_Objectdata.emplace_back(res);
                            }
                        }
                        else if ((property.first == "BOARD_PRODUCT_NAME") ||
                                 (property.first == "PRODUCT_PRODUCT_NAME"))
                        {
                            const std::string* product_name =
                                std::get_if<std::string>(&property.second);

                            if (property.first == "BOARD_PRODUCT_NAME")
                            {
                                res = "Board Product  : " + *product_name;
                                Fru_Objectdata.emplace_back(res);
                            }
                            else
                            {
                                res = "Product Name  : " + *product_name;
                                Fru_Objectdata.emplace_back(res);
                            }
                        }

                        else if ((property.first == "BOARD_PART_NUMBER") ||
                                 (property.first == "PRODUCT_PART_NUMBER"))
                        {
                            const std::string* part_number =
                                std::get_if<std::string>(&property.second);
                            if (property.first == "BOARD_PART_NUMBER")
                            {
                                res = "Board Part Number  : " + *part_number;
                                Fru_Objectdata.emplace_back(res);
                            }
                            else
                            {
                                res = "Product Part Number  : " + *part_number;
                                Fru_Objectdata.emplace_back(res);
                            }
                        }

                        else if ((property.first == "BOARD_SERIAL_NUMBER") ||
                                 (property.first == "PRODUCT_SERIAL_NUMBER"))
                        {
                            const std::string* serial_number =
                                std::get_if<std::string>(&property.second);
                            if (property.first == "BOARD_SERIAL_NUMBER")
                            {
                                res = "Board Serial  : " + *serial_number;
                                Fru_Objectdata.emplace_back(res);
                            }
                            else
                            {
                                res = "Product Serial  : " + *serial_number;
                                Fru_Objectdata.emplace_back(res);
                            }
                        }

                        else if ((property.first == "BOARD_LANGUAGE_CODE") ||
                                 (property.first == "PRODUCT_LANGUAGE_CODE"))
                        {
                            const std::string* language_code =
                                std::get_if<std::string>(&property.second);
                            if (property.first == "BOARD_LANGUAGE_CODE")
                            {
                                res = "Board language code  : " +
                                      *language_code;
                                Fru_Objectdata.emplace_back(res);
                            }
                            else
                            {
                                res = "Product language code  : " +
                                      *language_code;
                                Fru_Objectdata.emplace_back(res);
                            }
                        }
                        else if (property.first == "BOARD_MANUFACTURE_DATE")
                        {
                            const std::string* mfg_date =
                                std::get_if<std::string>(&property.second);
                            res = "Board Mfg Date  : " + *mfg_date;
                            Fru_Objectdata.emplace_back(res);
                        }

                    } // property loop end

                    asyncResp->res.jsonValue["FRU Device Description"] =
                        Fru_Objectdata;
                },
                "xyz.openbmc_project.FruDevice", fruPath,
                "org.freedesktop.DBus.Properties", "GetAll",
                "xyz.openbmc_project.FruDevice");
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTree",
        "/xyz/openbmc_project/FruDevice", 2,
        std::array<const char*, 1>{"xyz.openbmc_project.FruDevice"});

    return;
}

inline void requestRoutesFru(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Chassis/<str>/FRU/<str>")
        .privileges(redfish::privileges::getFru)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleFruGet, std::ref(app)));
}

inline void requestRoutesFruCollection(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Chassis/<str>/FRU/")
        .privileges(redfish::privileges::getFruCollection)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleFruCollectionGet, std::ref(app)));
}
} // namespace redfish
