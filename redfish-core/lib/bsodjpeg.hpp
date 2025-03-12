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
        asyncResp->res.jsonValue["Id"] = "Jpeg";
        asyncResp->res.jsonValue["Name"] = "Jpeg Image";
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
                        messages::success(asyncResp->res);
                    }
                }
                else
                {
                    messages::resourceNotFound(asyncResp->res, "Jpeg", "Image");
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
                int32_t dbuspropertyvalue = 1;
                crow::connections::systemBus->async_method_call(
                    [asyncResp](const boost::system::error_code& ec,
                                const std::string& response) {
                        if (ec)
                        {
                            messages::internalError(asyncResp->res);
                            return;
                        }
                        if (response != "Success")
                        {
                            messages::internalError(asyncResp->res);
                            return;
                        }
                        messages::success(asyncResp->res);
                    },
                    "xyz.openbmc_project.Kvm", "/xyz/openbmc_project/Kvm",
                    "xyz.openbmc_project.Kvm.Screenshot", "TriggerScreenshot",
                    dbuspropertyvalue);
            });
}

} // namespace redfish
