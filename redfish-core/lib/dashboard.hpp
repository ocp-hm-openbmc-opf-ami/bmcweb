#pragma once

#include "app.hpp"
#include "error_messages.hpp"
#include "http_request.hpp"
#include "http_response.hpp"
#include "query.hpp"
#include "registries/privilege_registry.hpp"
#include "utility.hpp"
#include "utils/json_utils.hpp"
#include "managers.hpp"
#include "led.hpp"
#include "systems.hpp"

#include <boost/url/format.hpp>

#include <ranges>
#include <string>

namespace redfish
{

inline void getEventLogSeverityCounts(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    std::map<std::string, uint16_t> severityCount;

    sdbusplus::message::object_path path("/xyz/openbmc_project/logging/entry");
    dbus::utility::getManagedObjects(
        "xyz.openbmc_project.Logging", path,
        [asyncResp, severityCount = std::move(severityCount)](
            const boost::system::error_code& ec,
            const dbus::utility::ManagedObjectType& resp) mutable
        {
            if (ec)
            {
                BMCWEB_LOG_ERROR("EventLog Count Failed: {}", ec);
                return;
            }

            for (const auto& [objPath, interfaces] : resp)
            {
                for (const auto& [interfaceName, properties] : interfaces)
                {
                    if (interfaceName != "xyz.openbmc_project.Logging.Entry")
                    {
                        continue;
                    }

                    for (const auto& [propName, propValue] : properties)
                    {
                        if (propName == "Severity")
                        {
                            const auto* severity = std::get_if<std::string>(&propValue);
                            if (severity != nullptr)
                            {
                                severityCount[*severity]++;
                            }
                            break;
                        }
                    }

                    break; // found the entry interface; no need to check others
                }
            }

            nlohmann::json& severityJson = asyncResp->res.jsonValue["SeverityCounts"];
            uint16_t critical = 0, warning = 0, ok = 0;
            for (const auto& [sev, count] : severityCount)
            {

                if (translateSeverityDbusToRedfish(sev) == "Critical")
                {
                    critical += count;
                }
                else if (translateSeverityDbusToRedfish(sev) == "OK")
                {
                    ok += count;
                }
                else if (translateSeverityDbusToRedfish(sev) == "Warning")
                {
                    warning += count;
                }
            }
            severityJson["Critical"] = std::move(critical);
            severityJson["OK"] = std::move(ok);
            severityJson["Warning"] = std::move(warning);
        });
}


inline void getDateTime ( const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    dbus::utility::getProperty<std::string>(
        "org.freedesktop.timedate1", "/org/freedesktop/timedate1",
        "org.freedesktop.timedate1", "Timezone",
        [asyncResp](const boost::system::error_code& ec,
                    const std::string& property) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("DBUS response error for TimeZoneName");
                return;
            }

            asyncResp->res.jsonValue["TimeZoneName"] = property;
            getCurrentDateTimeValue(asyncResp, property);
        });
}

inline void getSeverInfo(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    constexpr std::array<std::string_view, 1> interfaces{
        "xyz.openbmc_project.Inventory.Item.Board"};

    dbus::utility::getSubTreePaths(
        "/xyz/openbmc_project/inventory", 0, interfaces,
        [asyncResp](const boost::system::error_code& ec,
                    const dbus::utility::MapperGetSubTreePathsResponse& chassisList) {
            
            if (ec)
            {
                // No chassis paths found — bail out immediately
                BMCWEB_LOG_ERROR("Chassis Name not found - {}", ec);
                return;
            }

            auto foundPtr = std::make_shared<bool>(false);

            for (const auto& chassis : chassisList)
            {
                BMCWEB_LOG_DEBUG("Checking chassis path: {}", chassis);

                dbus::utility::getAllProperties(
                    "xyz.openbmc_project.EntityManager", chassis,
                    "xyz.openbmc_project.Inventory.Decorator.Asset",
                    [asyncResp, chassis, foundPtr](const boost::system::error_code& propEc,
                                                   const dbus::utility::DBusPropertiesMap& properties) {
                        if (*foundPtr)
                            return;

                        if (propEc)
                        {
                            BMCWEB_LOG_DEBUG("No Asset interface at {}", chassis);
                            return;
                        }

                        *foundPtr = true;
                        BMCWEB_LOG_INFO("Found Asset interface at {}", chassis);

                        const std::string* partNumber = nullptr;
                        const std::string* serialNumber = nullptr;
                        const std::string* manufacturer = nullptr;
                        const std::string* model = nullptr;
                        const std::string* subModel = nullptr;

                        const bool success = sdbusplus::unpackPropertiesNoThrow(
                            dbus_utils::UnpackErrorPrinter(), properties,
                            "PartNumber", partNumber,
                            "SerialNumber", serialNumber,
                            "Manufacturer", manufacturer,
                            "Model", model,
                            "SubModel", subModel);

                        if (!success)
                        {
                            BMCWEB_LOG_ERROR("Chassis Properties not found");
                            return;
                        }
                        if (partNumber)
                            asyncResp->res.jsonValue["PartNumber"] = *partNumber;
                        if (serialNumber)
                            asyncResp->res.jsonValue["SerialNumber"] = *serialNumber;
                        if (manufacturer)
                            asyncResp->res.jsonValue["Manufacturer"] = *manufacturer;
                        if (model)
                            asyncResp->res.jsonValue["Model"] = *model;
                        if (subModel)
                            asyncResp->res.jsonValue["SubModel"] = *subModel;
                    });
            }
        });
}

inline void OverviewPage (App& /*app*/, const crow::Request& /*req*/,
                      const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    asyncResp->res.jsonValue["@odata.id"] = "/redfish/v1/Oem/Ami/Dashboard";
    //Date and Time Info
    getDateTime(asyncResp);

    //System Info
    getSeverInfo(asyncResp);

    //Firmware Info

    //Network Info

    //Event Info
    getEventLogSeverityCounts(asyncResp);

    //Inventory and LED Info
    getSystemLocationIndicatorActive(asyncResp);
    getPhysicalLedState(asyncResp);
    getHostState(asyncResp);

    //erase led odataType
    asyncResp->res.jsonValue["Oem"]["Ami"]["PhysicalLED"].erase("@odata.type");

}

inline void requestRoutesDashboard (App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Oem/Ami/Dashboard")
        .privileges(redfish::privileges::privilegeSetLogin)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(OverviewPage, std::ref(app)));
}

} // namespace redfish
