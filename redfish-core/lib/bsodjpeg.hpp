#include "log_services.hpp"

#include <fstream>
#include <iterator>
#include <vector>

namespace redfish
{
std::string inputImagePath = "/etc/bsod/screenShotBSOD.jpeg";
uint16_t State = 0;

inline void getBsodjpeg(std::shared_ptr<bmcweb::AsyncResp> asyncResp)
{
    std::ifstream imageFile(inputImagePath, std::ios::binary);

    if (!imageFile)
    {
        BMCWEB_LOG_DEBUG("Failed to open image file.");
        asyncResp->res.jsonValue["Image"] = "Image File is  not Created";
        return;
    }

    if (fs::is_empty(inputImagePath)) // Checking Created File is empty or not
    {
        messages::internalError(asyncResp->res);
        return;
    }

    imageFile.seekg(0, std::ios::end);
    std::streampos fileSize = imageFile.tellg();
    imageFile.seekg(0, std::ios::beg);

    std::vector<unsigned char> imageData(static_cast<size_t>(fileSize));
    imageFile.read(reinterpret_cast<char*>(imageData.data()),
                   static_cast<int>(fileSize));
    imageFile.close();

    std::string_view strdata(reinterpret_cast<char*>(imageData.data()),
                             imageData.size());
    std::string output = crow::utility::base64encode(strdata);
    asyncResp->res.jsonValue["Image"] = output;
}

inline void requestRoutesBsodjpeg(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Managers/bmc/Oem/OpenBmc/Jpeg")
        .privileges({{"Login"}, {"ConfigureComponents"}})
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp) {
        if (!redfish::setUpRedfishRoute(app, req, asyncResp))
        {
            return;
        }
        asyncResp->res.jsonValue["@odata.id"] =
            "/redfish/v1/Managers/bmc/Oem/OpenBmc/Jpeg";
        asyncResp->res.jsonValue["@odata.type"] = "#Jpeg_v1_0_0.Jpeg";
        getBsodjpeg(asyncResp);
    });
}

inline void requestRoutesDeleteBsodjpeg(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Managers/bmc/Oem/OpenBmc/Jpeg")
        .privileges({{"Login"}, {"ConfigureComponents"}})
        .methods(boost::beast::http::verb::delete_)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp) {
        if (!redfish::setUpRedfishRoute(app, req, asyncResp))
        {
            return;
        }

        if (fs::exists(inputImagePath))
        {
            if (fs::remove(inputImagePath))
            {
                crow::connections::systemBus->async_method_call(
                    [asyncResp](const boost::system::error_code ec) {
                    if (ec)
                    {
                        BMCWEB_LOG_ERROR("DBUS response error {}", ec);
                        messages::internalError(asyncResp->res);
                        return;
                    }
                    messages::success(asyncResp->res);
                }, "xyz.openbmc_project.OSSStatusSensor",
                    "/xyz/openbmc_project/sensors/os/OS_Stop_Status",
                    "org.freedesktop.DBus.Properties", "Set",
                    "xyz.openbmc_project.Sensor.State", "State",
                    dbus::utility::DbusVariantType(State));
            }
        }
        else
        {
            messages::internalError(asyncResp->res);
            return;
        }
    });
}

inline void requestRoutesTriggerBsodjpeg(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Managers/bmc/Oem/OpenBmc/Jpeg")
        .privileges({{"Login"}, {"ConfigureComponents"}})
        .methods(boost::beast::http::verb::post)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp) {
        if (!redfish::setUpRedfishRoute(app, req, asyncResp))
        {
            return;
        }
        if (fs::exists(inputImagePath))
        {
            crow::connections::systemBus->async_method_call(
                [asyncResp](const boost::system::error_code ec) {
                if (ec)
                {
                    BMCWEB_LOG_ERROR("DBUS response error {}", ec);
                    messages::internalError(asyncResp->res);
                    return;
                }
            }, "xyz.openbmc_project.OSSStatusSensor",
                "/xyz/openbmc_project/sensors/os/OS_Stop_Status",
                "org.freedesktop.DBus.Properties", "Set",
                "xyz.openbmc_project.Sensor.State", "State",
                dbus::utility::DbusVariantType(State));
        }
        uint8_t netfn = 0x0a;
        uint8_t lun = 0x00;
        uint8_t cmdno = 0x44;
        std::vector<uint8_t> commandData = {0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
                                            0x00, 0x41, 0x0,  0x04, 0x20, 0x0,
                                            0x6f, 0x01, 0xff, 0xf};

        auto bus = sdbusplus::bus::new_default_system();

        const char* serviceName = "xyz.openbmc_project.Ipmi.Host";
        const char* objectPath = "/xyz/openbmc_project/Ipmi";
        const char* interfaceName = "xyz.openbmc_project.Ipmi.Server";
        const char* methodName = "execute";

        std::vector<std::pair<std::string, std::variant<std::string, uint64_t>>>
            options;

        auto methodCall = bus.new_method_call(serviceName, objectPath,
                                              interfaceName, methodName);
        methodCall.append(netfn, lun, cmdno, commandData, options);
        auto response = bus.call(methodCall);
        if (response.is_method_error())
        {
            BMCWEB_LOG_ERROR("DBUS Method Call Failed");
            messages::internalError(asyncResp->res);
            return;
        }
        else
        {
            messages::success(asyncResp->res);
        }
    });
}

} // namespace redfish
