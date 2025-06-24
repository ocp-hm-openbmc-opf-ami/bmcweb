#pragma once

#include "app.hpp"
#include "dbus_utility.hpp"
#include "error_messages.hpp"
#include "managers.hpp"
#include "registries/privilege_registry.hpp"
#include "utils/dbus_utils.hpp"
#include "utils/json_utils.hpp"

#include <sdbusplus/asio/property.hpp>
#include <sdbusplus/unpack_properties.hpp>

#include <array>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace redfish
{
inline void getLicenseKey(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code ec,
                    const std::string licenseKey) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("Get License Key DBUS response error: {}", ec);
                return;
            }
            asyncResp->res.jsonValue["LicenseKey"] = licenseKey;
        },
        "xyz.openbmc_project.License", "/xyz/openbmc_project/License",
        "xyz.openbmc_project.License.LicenseControl", "GetLicenseKey");
}

inline void getGlobalLicenseValidity(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code ec,
                    const int64_t globalLicenseValidity) {
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "Get GlobalLicense Validity DBUS response error: {}", ec);
                return;
            }
            asyncResp->res.jsonValue["GlobalLicenseValidity"] =
                globalLicenseValidity;
        },
        "xyz.openbmc_project.License", "/xyz/openbmc_project/License",
        "xyz.openbmc_project.License.LicenseControl", "GlobalLicenseValidity");
}

inline void
    getServicesUpCountDays(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code ec,
                    const int64_t servicesUpCountDays) {
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "Get Services UpCount Days DBUS response error: {}", ec);
                return;
            }
            asyncResp->res.jsonValue["ServicesUpCountDays"] =
                servicesUpCountDays;
        },
        "xyz.openbmc_project.License", "/xyz/openbmc_project/License",
        "xyz.openbmc_project.License.LicenseControl", "ServicesUpCountDays");
}

inline void getAlertMessage(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    dbus::utility::getProperty<std::string>(
        "xyz.openbmc_project.License", "/xyz/openbmc_project/License",
        "xyz.openbmc_project.License.LicenseControl", "AlertMessage",
        [asyncResp](const boost::system::error_code& ec,
                    const std::string alertMessage) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("Alert message DBUS response error {}", ec);
                return;
            }

            BMCWEB_LOG_DEBUG("Alert Message: {}", alertMessage);

            asyncResp->res.jsonValue["AlertMessage"] = alertMessage;
        });
}

inline void
    getUserAlertCount(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    dbus::utility::getProperty<uint32_t>(
        "xyz.openbmc_project.License",
        "/xyz/openbmc_project/License",
        "xyz.openbmc_project.License.LicenseControl", "UserAlertCount",
        [asyncResp](const boost::system::error_code& ec,
                    const uint32_t userAlertCount) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("User Alert Count DBUS response error {}", ec);
                return;
            }

            BMCWEB_LOG_DEBUG("User Alert Count {}", userAlertCount);

            asyncResp->res.jsonValue["UserAlertCount"] = userAlertCount;
        });
}

inline void
    handleLicenseControlGet(App& app, const crow::Request& req,
                            const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    asyncResp->res.jsonValue["@odata.id"] =
        "/redfish/v1/Oem/Ami/LicenseControl";
    asyncResp->res.jsonValue["@odata.type"] = json_util::odataType("AmiLicenseControl");
    asyncResp->res.jsonValue["Name"] = "License Control";
    asyncResp->res.jsonValue["Id"] = "License Control";

    getLicenseKey(asyncResp);
    getGlobalLicenseValidity(asyncResp);
    getServicesUpCountDays(asyncResp);
    getAlertMessage(asyncResp);
    getUserAlertCount(asyncResp);
}

inline void
    setUserAlertCount(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                      const uint32_t userAlertCount)
{
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, "xyz.openbmc_project.License",
        "/xyz/openbmc_project/License",
        "xyz.openbmc_project.License.LicenseControl", "UserAlertCount",
        userAlertCount,
        [asyncResp, userAlertCount](const boost::system::error_code& ec,
                                    sdbusplus::message_t& msg) {
            if (ec)
            {
                const sd_bus_error* dbusError = msg.get_error();
                if ((dbusError != nullptr) &&
                    (dbusError->name ==
                     std::string_view(
                         "xyz.openbmc_project.Common.Error.InvalidArgument")))
                {
                    std::string_view userAlertCountview =
                        std::to_string(userAlertCount);
                    BMCWEB_LOG_WARNING(
                        "Error Occurred in updating the property UserAlertCount");
                    messages::propertyValueOutOfRange(
                        asyncResp->res, userAlertCountview, "UserAlertCount");
                    return;
                }

                BMCWEB_LOG_ERROR("Set UserAlertCount DBUS response error {}",
                                 ec);
                messages::internalError(asyncResp->res);
                return;
            }
            BMCWEB_LOG_DEBUG("User Alert Count set successfully done");
        });
}

inline void handleLicenseControlPatch(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    std::optional<uint32_t> userAlertCount;

    if (!json_util::readJsonPatch( //
            req, asyncResp->res, //
            "UserAlertCount", userAlertCount //
            ))
    {
        return;
    }

    if (userAlertCount)
    {
        setUserAlertCount(asyncResp, userAlertCount.value());
    }
}

inline void uploadLicenseKeyFile(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp, std::string_view body)
{
    if (fs::exists("/tmp/license-control"))
    {
        fs::remove_all("/tmp/license-control");
    }

    fs::create_directory("/tmp/license-control");
    std::filesystem::path path = "/tmp/license-control/output.key";
    std::ofstream out(path, std::ofstream::out | std::ofstream::binary |
                                std::ofstream::trunc);
    out << body;
    if (out.bad())
    {
        messages::internalError(asyncResp->res);
        return;
    }

    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code& ec, bool& result) {
            if (ec)
            {
                messages::internalError(asyncResp->res);
                return;
            }

            if (!result)
            {
                std::cerr << "bef invalidFileContent " << std::endl;
                messages::invalidFileContent(asyncResp->res, "output.key");
                return;
            }
            asyncResp->res.result(boost::beast::http::status::no_content);
        },
        "xyz.openbmc_project.License", "/xyz/openbmc_project/License",
        "xyz.openbmc_project.License.LicenseControl", "AddLicenseKey");
}

// Function to check if a given string has the ".key" extension

bool hasKeyExtension(const std::string& str)
{
    const std::string extension = ".key";
    if (str.size() >= extension.size() &&
        str.compare(str.size() - extension.size(), extension.size(),
                    extension) == 0)
    {
        return true;
    }
    return false;
}

inline void
    readMultipartContext(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                         const MultipartParser& parser)
{
    const std::string* uploadData = nullptr;

    for (const FormPart& formpart : parser.mime_fields)
    {
        boost::beast::http::fields::const_iterator it =
            formpart.fields.find("Content-Disposition");
        if (it == formpart.fields.end())
        {
            BMCWEB_LOG_ERROR("Couldn't find Content-Disposition");
            return;
        }

        BMCWEB_LOG_INFO("Parsing value {}", it->value());

        // The construction parameters of param_list must start with `;`
        size_t index = it->value().find(';');
        if (index == std::string::npos)
        {
            continue;
        }
        for (const auto& param :
             boost::beast::http::param_list{it->value().substr(index)})
        {
            if (param.first == "filename" && !hasKeyExtension(param.second))
            {
                messages::invalidLicenseKeyFileFormat(asyncResp->res,
                                                      param.second);
                return;
            }

            if (param.first != "name" || param.second.empty())
            {
                continue;
            }
            else if (param.second == "LicenseKeyFile")
            {
                uploadData = &(formpart.content);
            }
        }
    }

    if (uploadData == nullptr)
    {
        BMCWEB_LOG_ERROR("Upload data is NULL");
        messages::propertyMissing(asyncResp->res, "LicenseKeyFile");
        return;
    }

    uploadLicenseKeyFile(asyncResp, *uploadData);
}

inline void handleLicenseControlPost(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    std::string_view contentType = req.getHeaderValue("Content-Type");

    BMCWEB_LOG_DEBUG("doPost: contentType= {}", contentType);

    if (boost::iequals(contentType, "application/octet-stream"))
    {
        uploadLicenseKeyFile(asyncResp, req.body());
    }
    else if (contentType.starts_with("multipart/form-data"))
    {
        MultipartParser parser;

        ParserError ec = parser.parse(req);
        if (ec != ParserError::PARSER_SUCCESS)
        {
            // handle error
            BMCWEB_LOG_ERROR("MIME parse failed, ec : {}",
                             static_cast<int>(ec));
            messages::internalError(asyncResp->res);
            return;
        }
        readMultipartContext(asyncResp, parser);
    }
    else
    {
        BMCWEB_LOG_DEBUG("Bad content type specified:{}", contentType);
        messages::unrecognizedRequestBody(asyncResp->res);
        asyncResp->res.result(boost::beast::http::status::bad_request);
    }
}

inline void requestRoutesLicenseControl(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Oem/Ami/LicenseControl/")
        .privileges(redfish::privileges::getLicenseControl)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleLicenseControlGet, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Oem/Ami/LicenseControl/")
        .privileges(redfish::privileges::postLicenseControl)
        .methods(boost::beast::http::verb::post)(
            std::bind_front(handleLicenseControlPost, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Oem/Ami/LicenseControl/")
        .privileges(redfish::privileges::patchLicenseControl)
        .methods(boost::beast::http::verb::patch)(
            std::bind_front(handleLicenseControlPatch, std::ref(app)));
}
} // namespace redfish
