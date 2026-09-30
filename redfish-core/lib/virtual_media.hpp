// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
// SPDX-FileCopyrightText: Copyright 2018 Intel Corporation
#pragma once

#include "account_service.hpp"
#include "app.hpp"
#include "async_resp.hpp"
#include "credential_pipe.hpp"
#include "dbus_utility.hpp"
#include "generated/enums/virtual_media.hpp"
#include "logging.hpp"
#include "query.hpp"
#include "registries/privilege_registry.hpp"
#include "system_utils.hpp"
#include "utils/json_utils.hpp"
#include "websocket.hpp"

#include <boost/url/format.hpp>
#include <boost/url/url_view.hpp>
#include <boost/url/url_view_base.hpp>
#include <dbus_singleton.hpp>
#include <sdbusplus/bus/match.hpp>

#include <array>
#include <ranges>
#include <regex>
#include <string_view>

#define POWER_SAVE_MODE_ENABLE 1
#define POWER_SAVE_MODE_DISABLE 0

namespace redfish
{

enum class VmMode
{
    Invalid,
    Legacy,
    Proxy
};

static constexpr const char* legacyMode = "Legacy";
static constexpr const char* proxyMode = "Proxy";
static constexpr const char* rmediaServiceName =
    "xyz.openbmc_project.VirtualMedia";
static constexpr const char* rmediaInterfaceName =
    "xyz.openbmc_project.VirtualMedia.Reconnect";
static constexpr const char* rmediaObjPath =
    "/xyz/openbmc_project/VirtualMedia";

static constexpr const char* rmedia1ServiceName =
    "xyz.openbmc_project.VirtualMedia1";
static constexpr const char* rmedia1ObjPath =
    "/xyz/openbmc_project/VirtualMedia1";

inline bool validateImageUrl(const std::string& url)
{
    std::string::size_type start = url.find("://") + 3;
    std::string::size_type colonPos = url.find(':', start);

    std::string address, path;

    if (url[start] == '[') // IPv6 address
    {
        std::string::size_type bracketEnd = url.find(']', start);
        address = url.substr(start + 1, bracketEnd - start - 1);
        path = url.substr(bracketEnd + 2); // Skip ']' and ':'
    }
    else                                   // IPv4 or FQDN
    {
        address = url.substr(start, colonPos - start);
        path = url.substr(colonPos + 1);
    }

    // Regular expression to match the allowed characters
    const std::regex pathPattern(R"(^[a-zA-Z0-9/_\\.-]+$)");

    // Regular expression to validate FQDN
    const std::regex fqdnPattern(R"(^([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,6}$)");

    boost::system::error_code ec;
    boost::asio::ip::address addr = boost::asio::ip::make_address(address, ec);

    if (ec)
    {
        if (!std::regex_match(address, fqdnPattern))
        {
            std::cerr << "Error: " << address
                      << " is not a valid IP address or FQDN." << std::endl;
            return false;
        }
    }

    else
    {
        if (addr.is_v4() &&
            !ip_util::isValidIPv4Addr(
                address,
                ip_util::Type::IP4_ADDRESS)) // checking the IPv4 Address
        {
            std::cerr << "Error: Address = " << address
                      << " is not a valid IPv4 address." << std::endl;
            return false;
        }

        else if (addr.is_v6() &&
                 !ip_util::validateIPv6address(
                     address,
                     ip_util::Type::IP6_ADDRESS)) // checking the IPv6 Address
        {
            std::cerr << "Error: Address = " << address
                      << " is not a valid IPv6 address." << std::endl;
            return false;
        }
    }

    if (path.length() > 256)
    {
        std::cerr << "Error: Path = " << path << "exceeds 256 characters."
                  << std::endl;
        return false;
    }

    if (!std::regex_match(path, pathPattern))
    {
        std::cerr
            << "Error: Path = " << path
            << "contains invalid characters. Allowed characters are alpha-numeric, '/', '\\', '_', '.' and '-'."
            << std::endl;
        return false;
    }

    return true;
}

inline void powerSaveMode(int mode)
{
    BMCWEB_LOG_DEBUG("USB Power Save Mode Set: %d", mode);
    crow::connections::systemBus->async_method_call(
        [mode](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("Failed to Set PowerSaveMode: ");
            }
        },
        "xyz.openbmc_project.Settings", "/xyz/openbmc_project/logging/settings",
        "xyz.openbmc_project.USB", "SetUSBPowerSaveMode", mode);
}

static std::string getModeName(bool isLegacy)
{
    if (isLegacy)
    {
        return legacyMode;
    }
    return proxyMode;
}

inline VmMode parseObjectPathAndGetMode(
    const sdbusplus::message::object_path& itemPath, const std::string& resName)
{
    std::string thisPath = itemPath.filename();
    BMCWEB_LOG_DEBUG("Filename: {}, ThisPath: {}", itemPath.str, thisPath);

    if (thisPath.empty())
    {
        return VmMode::Invalid;
    }

    if (thisPath != resName)
    {
        return VmMode::Invalid;
    }

    auto mode = itemPath.parent_path();
    auto type = mode.parent_path();

    if (mode.filename().empty() || type.filename().empty())
    {
        return VmMode::Invalid;
    }

    if (type.filename() != "VirtualMedia" && type.filename() != "VirtualMedia1")
    {
        return VmMode::Invalid;
    }
    std::string modeStr = mode.filename();
    if (modeStr == "Legacy")
    {
        return VmMode::Legacy;
    }
    if (modeStr == "Proxy")
    {
        return VmMode::Proxy;
    }
    return VmMode::Invalid;
}

using CheckItemHandler =
    std::function<void(const std::string& service, const std::string& resName,
                       const std::shared_ptr<bmcweb::AsyncResp>&,
                       const std::pair<sdbusplus::message::object_path,
                                       dbus::utility::DBusInterfacesMap>&)>;

inline void findAndParseObject(
    const std::string& service, const std::string& resName,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& name, CheckItemHandler&& handler)
{
    std::string path;
    if (name == "system1")
    {
        path = "/xyz/openbmc_project/VirtualMedia1";
    }
    else
    {
        path = "/xyz/openbmc_project/VirtualMedia";
    }
    dbus::utility::getManagedObjects(
        service, path,
        [service, resName, asyncResp, handler = std::move(handler)](
            const boost::system::error_code& ec,
            const dbus::utility::ManagedObjectType& subtree) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("DBUS response error");

                return;
            }

            for (const auto& item : subtree)
            {
                VmMode mode = parseObjectPathAndGetMode(item.first, resName);
                if (mode != VmMode::Invalid)
                {
                    handler(service, resName, asyncResp, item);
                    return;
                }
            }

            BMCWEB_LOG_DEBUG("Parent item not found");
            messages::resourceNotFound(asyncResp->res, "VirtualMedia", resName);
        });
}

inline void findAndParsePostObject(
    const std::string& service, const std::string& resName,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& name, CheckItemHandler&& handler)
{
    std::string path;
    if (name == "system1")
    {
        path = "/xyz/openbmc_project/VirtualMedia1";
    }
    else
    {
        path = "/xyz/openbmc_project/VirtualMedia";
    }
    dbus::utility::getManagedObjects(
        service, path,
        [service, resName, asyncResp, handler = std::move(handler)](
            const boost::system::error_code& ec,
            const dbus::utility::ManagedObjectType& subtree) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("DBUS response error");

                return;
            }

            for (const auto& item : subtree)
            {
                VmMode mode = parseObjectPathAndGetMode(item.first, resName);
                if (mode != VmMode::Invalid)
                {
                    asyncResp->res.addHeader("Allow", "GET, PATCH");
                    messages::operationNotAllowed(asyncResp->res);
                    return;
                }
                else
                {
                    messages::resourceNotFound(asyncResp->res, "VirtualMedia",
                                               resName);
                    return;
                }
            }
        });
    return;
}

/**
 * @brief Function parses getManagedObject response, finds item, makes generic
 *        validation and invokes callback handler on this item.
 *
 */
inline void findItemAndRunHandler(
    const std::shared_ptr<bmcweb::AsyncResp>& aResp, const std::string& name,
    const std::string& resName, CheckItemHandler&& handler,
    const crow::Request& req)
{
    if (system_utils::isDualHostEnabled())
    {
        // For dual node, accept system and system1
        if (name != "system" && name != "system1")
        {
            messages::resourceNotFound(aResp->res, "ComputerSystem", name);
            return;
        }
    }
    else
    {
        if (name != "system")
        {
            messages::resourceNotFound(aResp->res, "ComputerSystem", name);
            return;
        }
    }

    std::string path;
    if (name == "system1")
    {
        path = "/xyz/openbmc_project/VirtualMedia1";
    }
    else
    {
        path = "/xyz/openbmc_project/VirtualMedia";
    }

    if (req.session->username != "root")
    {
        auto result = find(req.session->userGroups.begin(),
                           req.session->userGroups.end(), "media");
        if (result == end(req.session->userGroups))
        {
            BMCWEB_LOG_ERROR("Unable to get access ");
            messages::resourceAtUriUnauthorized(
                aResp->res, req.url(), "Insufficient privileges to access ");
            return;
        }
    }

    crow::connections::systemBus->async_method_call(
        [aResp, resName, handler = std::move(handler),
         name](const boost::system::error_code ec,
               const dbus::utility::MapperGetObject& getObjectType) mutable {
            if (ec)
            {
                BMCWEB_LOG_ERROR("ObjectMapper::GetObject call failed: {}", ec);
                aResp->res.result(boost::beast::http::status::not_found);

                return;
            }

            if (getObjectType.empty())
            {
                BMCWEB_LOG_ERROR("ObjectMapper : No Service found");
                aResp->res.result(boost::beast::http::status::not_found);

                return;
            }

            std::string service = getObjectType.begin()->first;
            BMCWEB_LOG_DEBUG("GetObjectType: {}", service);

            findAndParseObject(service, resName, aResp, name,
                               std::move(handler));
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetObject", path,
        std::array<const char*, 0>());
}

/**
 * @brief Function extracts transfer protocol name from URI.
 */
inline std::string getTransferProtocolTypeFromUri(const std::string& imageUri)
{
    boost::system::result<boost::urls::url_view> url =
        boost::urls::parse_uri(imageUri);
    if (!url)
    {
        return "None";
    }
    std::string_view scheme = url->scheme();
    if (scheme == "smb")
    {
        return "CIFS";
    }
    if (scheme == "https")
    {
        return "HTTPS";
    }
    if (scheme == "nfs")
    {
        return "NFS";
    }

    return "None";
}

inline void getRmediareconnectValues(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& name)
{
    std::string path;
    if (name == "system1")
    {
        path = "/xyz/openbmc_project/VirtualMedia1";
    }
    else
    {
        path = "/xyz/openbmc_project/VirtualMedia";
    }

    std::string serviceName =
        (name == "system1") ? rmedia1ServiceName : rmediaServiceName;

    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code& ec,
                    const std::tuple<uint32_t, uint32_t>& result) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("DBUS response error");
                return;
            }
            asyncResp->res.jsonValue["Oem"]["Ami"]["RetryCount"] =
                std::get<0>(result);

            asyncResp->res.jsonValue["Oem"]["Ami"]["RetryInterval"] =
                std::get<1>(result);
        },
        serviceName, path, rmediaInterfaceName, "GetAll");
}

/**
 * @brief Read all known properties from VM object interfaces
 */
inline void vmParseInterfaceObject(
    const dbus::utility::DBusInterfacesMap& interfaces,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    for (const auto& [interface, values] : interfaces)
    {
        if (interface == "xyz.openbmc_project.VirtualMedia.MountPoint")
        {
            for (const auto& [property, value] : values)
            {
                if (property == "EndpointId")
                {
                    const std::string* endpointIdValue =
                        std::get_if<std::string>(&value);
                    if (endpointIdValue == nullptr)
                    {
                        continue;
                    }
                    if (!endpointIdValue->empty())
                    {
                        // Proxy mode
                        asyncResp->res
                            .jsonValue["Oem"]["OpenBMC"]["WebSocketEndpoint"] =
                            *endpointIdValue;
                        asyncResp->res.jsonValue["TransferProtocolType"] =
                            "OEM";
                    }
                }
                if (property == "ImageURL")
                {
                    const std::string* imageUrlValue =
                        std::get_if<std::string>(&value);
                    if (imageUrlValue != nullptr && !imageUrlValue->empty())
                    {
                        std::filesystem::path filePath = *imageUrlValue;
                        if (!filePath.has_filename())
                        {
                            // this will handle https share, which not
                            // necessarily has to have filename given.
                            asyncResp->res.jsonValue["ImageName"] = "";
                        }
                        else
                        {
                            asyncResp->res.jsonValue["ImageName"] =
                                filePath.filename();
                        }

                        asyncResp->res.jsonValue["Image"] = *imageUrlValue;
                        asyncResp->res.jsonValue["TransferProtocolType"] =
                            getTransferProtocolTypeFromUri(*imageUrlValue);

                        asyncResp->res.jsonValue["ConnectedVia"] =
                            virtual_media::ConnectedVia::URI;
                    }
                }
                if (property == "UserName")
                {
                    const std::string* userNameValue =
                        std::get_if<std::string>(&value);
                    if (userNameValue != nullptr && !userNameValue->empty())
                    {
                        asyncResp->res.jsonValue["UserName"] = *userNameValue;
                    }
                }
                if (property == "WriteProtected")
                {
                    const bool* writeProtectedValue = std::get_if<bool>(&value);
                    if (writeProtectedValue != nullptr)
                    {
                        asyncResp->res.jsonValue["WriteProtected"] =
                            *writeProtectedValue;
                    }
                }
            }
        }
        if (interface == "xyz.openbmc_project.VirtualMedia.Process")
        {
            for (const auto& [property, value] : values)
            {
                if (property == "Active")
                {
                    const bool* activeValue = std::get_if<bool>(&value);
                    if (activeValue == nullptr)
                    {
                        BMCWEB_LOG_DEBUG("Value Active not found");
                        return;
                    }
                    asyncResp->res.jsonValue["Inserted"] = *activeValue;

                    if (*activeValue)
                    {
                        asyncResp->res.jsonValue["ConnectedVia"] =
                            virtual_media::ConnectedVia::Applet;
                    }
                }
            }
        }
    }
}

inline void getBackedUpImageUrl(
    const std::string& resName,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& name)
{
    std::string ObjPath;
    if (name == "system1")
    {
        ObjPath = "/xyz/openbmc_project/VirtualMedia1";
    }
    else
    {
        ObjPath = "/xyz/openbmc_project/VirtualMedia";
    }
    std::string serviceName =
        (name == "system1") ? rmedia1ServiceName : rmediaServiceName;

    if (resName == "Slot_2" || resName == "Slot_3")
    {
        crow::connections::systemBus->async_method_call(
            [asyncResp, resName](const boost::system::error_code& ec,
                                 const std::variant<std::string>& imageUrl) {
                if (ec)
                {
                    BMCWEB_LOG_DEBUG("Failed to get backup image URL");
                    return;
                }

                const std::string* urlValue =
                    std::get_if<std::string>(&imageUrl);
                if (urlValue != nullptr)
                {
                    asyncResp->res.jsonValue["Oem"]["Ami"]["BackupImageURL"] =
                        *urlValue;
                }
                else
                {
                    asyncResp->res.jsonValue["Oem"]["Ami"]["BackupImageURL"] =
                        "";
                }
            },
            serviceName, ObjPath, "org.freedesktop.DBus.Properties", "Get",
            "xyz.openbmc_project.VirtualMedia.BackupImageURL", resName);
    }
}

/**
 * @brief Fill template for Virtual Media Item.
 */
inline nlohmann::json vmItemTemplate(const std::string& name,
                                     const std::string& resName)
{
    nlohmann::json item;
    item["@odata.id"] = boost::urls::format(
        "/redfish/v1/Systems/{}/VirtualMedia/{}", name, resName);

    item["@odata.type"] = json_util::odataType("VirtualMedia");
    item["Name"] = "Virtual Removable Media";
    item["Description"] = "Virtual Removable Media";
    item["Id"] = resName;
    item["WriteProtected"] = true;
    item["ConnectedVia"] = virtual_media::ConnectedVia::NotConnected;
    item["MediaTypes"] = nlohmann::json::array_t({"CD", "USBStick"});
    item["TransferMethod"] = virtual_media::TransferMethod::Stream;
    item["Oem"]["OpenBMC"]["@odata.type"] =
        json_util::odataType("OpenBMCVirtualMedia", "VirtualMedia");
    item["Oem"]["OpenBMC"]["@odata.id"] = boost::urls::format(
        "/redfish/v1/Systems/{}/VirtualMedia/{}#/Oem/OpenBMC", name, resName);

    item["Oem"]["Ami"]["@odata.type"] = json_util::odataType("AmiVirtualMedia");
    item["Oem"]["Ami"]["@odata.id"] = boost::urls::format(
        "/redfish/v1/Systems/{}/VirtualMedia/{}#/Oem/Ami", name, resName);
    return item;
}

/**
 *  @brief Fills collection data
 */
inline void getVmResourceList(std::shared_ptr<bmcweb::AsyncResp> asyncResp,
                              const std::string& service,
                              const std::string& name)
{
    BMCWEB_LOG_DEBUG("Get available Virtual Media resources.");
    std::string objPath;
    if (name == "system1")
    {
        objPath = "/xyz/openbmc_project/VirtualMedia1";
    }
    else
    {
        objPath = "/xyz/openbmc_project/VirtualMedia";
    }

    dbus::utility::getManagedObjects(
        service, objPath,
        [name, asyncResp{std::move(asyncResp)}](
            const boost::system::error_code& ec,
            const dbus::utility::ManagedObjectType& subtree) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("DBUS response error");
                return;
            }
            nlohmann::json& members = asyncResp->res.jsonValue["Members"];
            members = nlohmann::json::array();

            for (const auto& object : subtree)
            {
                nlohmann::json item;
                std::string path = object.first.filename();
                if (path.empty() || path == "Local")
                {
                    continue;
                }

                item["@odata.id"] = boost::urls::format(
                    "/redfish/v1/Systems/{}/VirtualMedia/{}", name, path);
                members.emplace_back(std::move(item));
            }
            asyncResp->res.jsonValue["Members@odata.count"] = members.size();
        });
}

inline void afterGetVmData(
    const std::string& name, const std::string& /*service*/,
    const std::string& resName,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::pair<sdbusplus::message::object_path,
                    dbus::utility::DBusInterfacesMap>& item)
{
    VmMode mode = parseObjectPathAndGetMode(item.first, resName);
    if (mode == VmMode::Invalid)
    {
        return;
    }

    asyncResp->res.jsonValue = vmItemTemplate(name, resName);
    getBackedUpImageUrl(resName, asyncResp, name);

    // Check if dbus path is Legacy type
    if (mode == VmMode::Legacy)
    {
        asyncResp->res.jsonValue["Actions"]["#VirtualMedia.InsertMedia"]
                                ["target"] = boost::urls::format(
            "/redfish/v1/Systems/{}/VirtualMedia/{}/Actions/VirtualMedia.InsertMedia",
            name, resName);
        getRmediareconnectValues(asyncResp, name);
    }

    vmParseInterfaceObject(item.second, asyncResp);

    asyncResp->res.jsonValue["Actions"]["#VirtualMedia.EjectMedia"]
                            ["target"] = boost::urls::format(
        "/redfish/v1/Systems/{}/VirtualMedia/{}/Actions/VirtualMedia.EjectMedia",
        name, resName);
}

/**
 *  @brief Fills data for specific resource
 */
inline void getVmData(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                      const std::string& service, const std::string& name,
                      const std::string& resName)
{
    BMCWEB_LOG_DEBUG("Get Virtual Media resource data.");

    findAndParseObject(service, resName, asyncResp, name,
                       std::bind_front(afterGetVmData, name));
}

inline void getVmPostData(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                          const std::string& service, const std::string& name,
                          const std::string& resName)
{
    findAndParsePostObject(service, resName, asyncResp, name,
                           std::bind_front(afterGetVmData, name));
}

/**
 * @brief Transfer protocols supported for InsertMedia action.
 *
 */
enum class TransferProtocol
{
    https,
    smb,
    nfs,
    invalid
};

/**
 * @brief Function extracts transfer protocol type from URI.
 *
 */
inline std::optional<TransferProtocol> getTransferProtocolFromUri(
    const boost::urls::url_view_base& imageUri)
{
    std::string_view scheme = imageUri.scheme();
    if (scheme == "smb")
    {
        return TransferProtocol::smb;
    }
    if (scheme == "https")
    {
        return TransferProtocol::https;
    }
    if (scheme == "nfs")
    {
        return TransferProtocol::nfs;
    }
    if (!scheme.empty())
    {
        return TransferProtocol::invalid;
    }

    return {};
}

/**
 * @brief Function convert transfer protocol from string param.
 *
 */
inline std::optional<TransferProtocol> getTransferProtocolFromParam(
    const std::optional<std::string>& transferProtocolType)
{
    if (!transferProtocolType)
    {
        return {};
    }

    if (*transferProtocolType == "CIFS")
    {
        return TransferProtocol::smb;
    }

    if (*transferProtocolType == "NFS")
    {
        return TransferProtocol::nfs;
    }

    if (*transferProtocolType == "HTTPS")
    {
        return TransferProtocol::https;
    }

    return TransferProtocol::invalid;
}

/**
 * @brief Function extends URI with transfer protocol type.
 *
 */
inline std::string getUriWithTransferProtocol(
    const std::string& imageUri, const TransferProtocol& transferProtocol)
{
    if (transferProtocol == TransferProtocol::smb)
    {
        return "smb://" + imageUri;
    }

    if (transferProtocol == TransferProtocol::nfs)
    {
        return "nfs://" + imageUri;
    }

    if (transferProtocol == TransferProtocol::https)
    {
        return "https://" + imageUri;
    }

    return imageUri;
}

inline void setUserName(std::shared_ptr<bmcweb::AsyncResp> asyncResp,
                        const std::string& userName, const std::string& name,
                        const std::string& systemName)
{
    sdbusplus::message::object_path path;

    std::string serviceName =
        (systemName == "system1") ? rmedia1ServiceName : rmediaServiceName;

    if (name == "Slot_0" || name == "Slot_1")
    {
        if (systemName == "system")
        {
            path = sdbusplus::message::object_path(
                "/xyz/openbmc_project/VirtualMedia/Proxy");
        }
        else if (systemName == "system1")
        {
            path = sdbusplus::message::object_path(
                "/xyz/openbmc_project/VirtualMedia1/Proxy");
        }
    }
    else if (name == "Slot_2" || name == "Slot_3")
    {
        if (systemName == "system")
        {
            path = sdbusplus::message::object_path(
                "/xyz/openbmc_project/VirtualMedia/Legacy");
        }
        else if (systemName == "system1")
        {
            path = sdbusplus::message::object_path(
                "/xyz/openbmc_project/VirtualMedia1/Legacy");
        }
    }

    path /= name;
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, serviceName, path,
        "xyz.openbmc_project.VirtualMedia.MountPoint", "UserName", userName,
        [asyncResp](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("Failed to set UserName property: {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }
        });
}

struct InsertMediaActionParams
{
    std::optional<std::string> imageUrl;
    std::optional<std::string> userName;
    std::optional<std::string> password;
    std::optional<std::string> transferMethod;
    std::optional<std::string> transferProtocolType;
    std::optional<bool> writeProtected = true;
    std::optional<bool> inserted;
};

/**
 * @brief holder for dbus signal matchers
 */
struct MatchWrapper
{
    void stop()
    {
        timer->cancel();
        matcher = std::nullopt;
    }

    std::optional<sdbusplus::bus::match::match> matcher{};
    std::optional<boost::asio::steady_timer> timer;
};

/**
 * @brief Function starts waiting for signal completion
 */
static inline std::shared_ptr<MatchWrapper> doListenForCompletion(
    const std::string& name, const std::string& objectPath,
    const std::string& action, bool legacy,
    std::shared_ptr<bmcweb::AsyncResp> asyncResp, std::string userName,
    const std::string& systemName)

{
    BMCWEB_LOG_DEBUG("Start Listening for completion : {}", action);
    std::string matcherString = sdbusplus::bus::match::rules::type::signal();

    std::string interface =
        std::string("xyz.openbmc_project.VirtualMedia.") + getModeName(legacy);

    matcherString += sdbusplus::bus::match::rules::interface(interface);
    matcherString += sdbusplus::bus::match::rules::member("Completion");

    if (systemName == "system1")
    {
        matcherString += sdbusplus::bus::match::rules::sender(
            "xyz.openbmc_project.VirtualMedia1");
    }
    else
    {
        matcherString += sdbusplus::bus::match::rules::sender(
            "xyz.openbmc_project.VirtualMedia");
    }
    matcherString += sdbusplus::bus::match::rules::path(objectPath);

    auto matchWrapper = std::make_shared<MatchWrapper>();
    auto matchHandler = [asyncResp = std::move(asyncResp), name, action,
                         objectPath, matchWrapper, userName,
                         systemName](sdbusplus::message::message& m) {
        int errorCode = 0;
        try
        {
            BMCWEB_LOG_INFO("Completion signal from {} has been received",
                            m.get_path());

            m.read(errorCode);
            switch (errorCode)
            {
                case 0: // success
                    BMCWEB_LOG_INFO("Signal received: Success");
                    setUserName(asyncResp, userName, name, systemName);
                    messages::success(asyncResp->res);
                    break;
                case EPERM:
                    BMCWEB_LOG_ERROR("Signal received: EPERM");
                    messages::actionParameterValueError(
                        asyncResp->res, "UserName/Password", "InsertMedia");
                    break;
                case 2:
                    BMCWEB_LOG_ERROR("Signal received: ENOENT ");
                    messages::invalidImagePath(asyncResp->res);
                    break;

                case EBUSY:
                    BMCWEB_LOG_ERROR("Signal received: EAGAIN");
                    messages::resourceInUse(asyncResp->res);
                    break;
                case 34:
                    BMCWEB_LOG_ERROR("Signal received: ERANGE ");
                    messages::invalidImageSize(asyncResp->res);
                    break;
                case 111:
                    BMCWEB_LOG_ERROR("Signal received: ECONNREFUSED ");
                    messages::remoteServiceConnectionRefused(asyncResp->res);
                    break;
                case 113:
                    BMCWEB_LOG_ERROR("Signal received: EHOSTUNREACH  ");
                    messages::invalidIPAddress(asyncResp->res);
                    break;
                case 71:
                    BMCWEB_LOG_ERROR("Signal received: EPROTO    ");
                    messages::virtualMediaHttpsTransferFailed(asyncResp->res);
                    break;
                case 110:
                    BMCWEB_LOG_ERROR("Signal received: ETIMEDOUT  ");
                    messages::remoteServiceTimeout(asyncResp->res);
                    break;
                default:
                    BMCWEB_LOG_ERROR("Signal received: Other: {}", errorCode);
                    messages::operationFailed(asyncResp->res);
                    break;
            }
        }
        catch (sdbusplus::exception::SdBusError& e)
        {
            BMCWEB_LOG_ERROR("{}", e.what());
        }
        // postpone matcher deletion after callback finishes
        boost::asio::post(
            crow::connections::systemBus->get_io_context(),
            [name, matchWrapper = matchWrapper]()

            {
                BMCWEB_LOG_DEBUG("Removing matcher for {} node.", name);
                matchWrapper->stop();
            });
    };
    matchWrapper->timer.emplace(crow::connections::systemBus->get_io_context());

    // Safety valve. Clean itself after 3 minutes without signal
    matchWrapper->timer->expires_after(std::chrono::minutes(3));
    matchWrapper->timer->async_wait(
        [matchWrapper](const boost::system::error_code& ec) {
            if (ec != boost::asio::error::operation_aborted)
            {
                BMCWEB_LOG_DEBUG("Timer expired! Signal did not come");
                matchWrapper->matcher = std::nullopt;
                return;
            }
        });

    matchWrapper->matcher.emplace(*crow::connections::systemBus, matcherString,
                                  matchHandler);
    return matchWrapper;
}

/**
 * @brief Function transceives data with dbus directly.
 *
 * All BMC state properties will be retrieved before sending reset request.
 */
inline void doMountVmLegacy(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& service, const std::string& name,
    const std::string& imageUrl, bool rw, std::string&& userName,
    std::string&& password, const std::string& sessionId,
    const std::string& systemName)
{
    std::string userNameCopy = userName;
    int fd = -1;
    dbus::utility::DbusVariantType unixFd = -1;
    std::shared_ptr<CredentialsPipe> secretPipe;
    if (!userName.empty() || !password.empty())
    {
        // Payload must contain data + NULL delimiters
        constexpr const size_t secretLimit = 1024;
        if (userName.size() + password.size() + 2 > secretLimit)
        {
            BMCWEB_LOG_ERROR("Credentials too long to handle");
            messages::unrecognizedRequestBody(asyncResp->res);
            return;
        }
        // Open pipe
        secretPipe = std::make_shared<CredentialsPipe>(
            crow::connections::systemBus->get_io_context());
        fd = secretPipe->releaseFd();

        // Pass secret over pipe
        secretPipe->asyncWrite(
            std::move(userName), std::move(password),
            [asyncResp,
             secretPipe](const boost::system::error_code& ec, std::size_t) {
                if (ec)
                {
                    BMCWEB_LOG_ERROR("Failed to pass secret: {}", ec);
                    messages::internalError(asyncResp->res);
                }
            });
    }

    std::string objectPath;
    if (systemName == "system1")
    {
        objectPath = "/xyz/openbmc_project/VirtualMedia1/Legacy/" + name;
        BMCWEB_LOG_DEBUG("Mounting Virtual Media on system1 in Legacy mode");
    }
    else
    {
        objectPath = "/xyz/openbmc_project/VirtualMedia/Legacy/" + name;
        BMCWEB_LOG_DEBUG("Mounting Virtual Media in Legacy mode");
    }
    const std::string action = "VirtualMedia.InsertMedia";
    auto wrapper =
        doListenForCompletion(name, objectPath, action, true, asyncResp,
                              std::move(userNameCopy), systemName);

    if (imageUrl.find("nfs://") != 0)
    {
        unixFd = dbus::utility::DbusVariantType(
            std::in_place_type<sdbusplus::message::unix_fd>, fd);
    }

    crow::connections::systemBus->async_method_call(
        [asyncResp, secretPipe, name, action, wrapper, objectPath, sessionId,
         systemName](const boost::system::error_code& ec, bool success) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("Bad D-Bus request error: {}", ec);
                if (ec == boost::system::errc::device_or_resource_busy)
                {
                    messages::resourceInUse(asyncResp->res);
                }
                else if (ec == boost::system::errc::permission_denied)
                {
                    messages::accessDenied(
                        asyncResp->res,
                        boost::urls::format(
                            "/redfish/v1/Systems/{}/VirtualMedia/{}/Actions/{}",
                            systemName, name, action));
                }
                else
                {
                    messages::internalError(asyncResp->res);
                }
                wrapper->stop();
                return;
            }
            if (!success)
            {
                messages::resourceInUse(asyncResp->res);
            }
        },
        service, objectPath, "xyz.openbmc_project.VirtualMedia.Legacy", "Mount",
        imageUrl, rw, unixFd, sessionId);
}

/**
 * @brief Function validate parameters of insert media request.
 *
 */
inline void validateParams(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                           const std::string& service,
                           const std::string& resName,
                           InsertMediaActionParams& actionParams,
                           const crow::Request& req, const std::string& name)
{
    BMCWEB_LOG_DEBUG("Validation started");
    // required param imageUrl must not be empty
    if (!actionParams.imageUrl)
    {
        BMCWEB_LOG_ERROR("Request action parameter Image is empty.");

        boost::urls::url urlObj = boost::urls::format(
            "/redfish/v1/Systems/{}/VirtualMedia/{}/Actions/{}", resName, name,
            "VirtualMedia.InsertMedia");
        std::string Url = urlObj.buffer();
        messages::actionParameterMissing(asyncResp->res, Url, "Image");
        return;
    }

    // optional param inserted must be true
    if (actionParams.inserted && !*actionParams.inserted)
    {
        BMCWEB_LOG_ERROR(
            "Request action optional parameter Inserted must be true.");

        messages::actionParameterNotSupported(asyncResp->res, "Inserted",
                                              "InsertMedia");

        return;
    }
    // required to check for correct Mediatype format for param imageUrl
    else if (actionParams.imageUrl)
    {
        // Parse the URI
        boost::system::result<boost::urls::url_view> url =
            boost::urls::parse_uri(*actionParams.imageUrl);
        if (!url)
        {
            messages::actionParameterValueFormatError(
                asyncResp->res, *actionParams.imageUrl, "Image", "InsertMedia");
            return;
        }
        // Validate host
        std::string host = url->host();
        static const std::regex ipv4Pattern(R"(^(\d{1,3}\.){3}\d{1,3}$)");
        static const std::regex ipv6Pattern(R"(^\[?[0-9a-fA-F:]+\]?$)");
        static const std::regex domainPattern(
            R"(^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$)");

        if (!std::regex_match(host, ipv4Pattern) &&
            !std::regex_match(host, ipv6Pattern) &&
            !std::regex_match(host, domainPattern))
        {
            BMCWEB_LOG_ERROR("Invalid host in URI", host);
            messages::propertyValueFormatError(asyncResp->res,
                                               *actionParams.imageUrl, "Image");
            return;
        }
        // Validate path and extension
        std::string path = url->path();
        std::string::size_type Index = path.rfind('.');
        if (Index == std::string::npos)
        {
            BMCWEB_LOG_ERROR("No file extension found in path");
            messages::propertyValueFormatError(asyncResp->res,
                                               *actionParams.imageUrl, "Image");
            return;
        }
        std::string MediaType = path.substr(Index);
        std::transform(MediaType.begin(), MediaType.end(), MediaType.begin(),
                       ::tolower);
        if ((MediaType != ".iso") && (MediaType != ".ima") &&
            (MediaType != ".img") && (MediaType != ".nrg") &&
            (MediaType != ".vhd") && (MediaType != ".vmdk"))
        {
            BMCWEB_LOG_ERROR("Invalid Media format", MediaType);
            messages::propertyValueFormatError(asyncResp->res,
                                               *actionParams.imageUrl, "Image");
            return;
        }
        std::optional<TransferProtocol> uriTransferProtocolType =
            getTransferProtocolFromUri(*url);

        std::optional<TransferProtocol> paramTransferProtocolType =
            getTransferProtocolFromParam(actionParams.transferProtocolType);

        // ImageUrl does not contain valid protocol type
        if (uriTransferProtocolType &&
            *uriTransferProtocolType == TransferProtocol::invalid)
        {
            BMCWEB_LOG_ERROR("Request action parameter ImageUrl must "
                             "contain specified protocol type from list: "
                             "(smb, nfs, https).");

            messages::resourceAtUriInUnknownFormat(asyncResp->res, *url);

            return;
        }

        if (!paramTransferProtocolType)
        {
            messages::actionParameterMissing(asyncResp->res, "InsertMedia",
                                             "TransferProtocolType");
            return;
        }

        // transferProtocolType should contain value from list
        if (paramTransferProtocolType &&
            *paramTransferProtocolType == TransferProtocol::invalid)
        {
            BMCWEB_LOG_ERROR("Request action parameter TransferProtocolType "
                             "must be provided with value from list: "
                             "(CIFS, HTTPS).");

            messages::propertyValueNotInList(
                asyncResp->res, actionParams.transferProtocolType.value_or(""),
                "TransferProtocolType");
            return;
        }

        // valid transfer protocol not provided either with URI nor param
        if (!uriTransferProtocolType && !paramTransferProtocolType)
        {
            BMCWEB_LOG_ERROR("Request action parameter ImageUrl must "
                             "contain specified protocol type or param "
                             "TransferProtocolType must be provided.");

            messages::resourceAtUriInUnknownFormat(asyncResp->res, *url);

            return;
        }

        // valid transfer protocol provided both with URI and param
        if (paramTransferProtocolType && uriTransferProtocolType)
        {
            // check if protocol is the same for URI and param
            if (*paramTransferProtocolType != *uriTransferProtocolType)
            {
                BMCWEB_LOG_ERROR("Request action parameter "
                                 "TransferProtocolType must  contain the "
                                 "same protocol type as protocol type "
                                 "provided with param imageUrl.");

                messages::actionParameterValueTypeError(
                    asyncResp->res,
                    actionParams.transferProtocolType.value_or(""),
                    "TransferProtocolType", "InsertMedia");

                return;
            }
        }

        if (actionParams.transferProtocolType == "NFS" &&
            !validateImageUrl(*actionParams.imageUrl))
        {
            messages::actionParameterValueFormatError(
                asyncResp->res, *actionParams.imageUrl, "Image", "InsertMedia");
            return;
        }

        // validation passed, add protocol to URI if needed
        if (!uriTransferProtocolType && paramTransferProtocolType)
        {
            actionParams.imageUrl = getUriWithTransferProtocol(
                *actionParams.imageUrl, *paramTransferProtocolType);
        }

        if (actionParams.transferProtocolType)
        {
            if ((*actionParams.transferProtocolType == "NFS" &&
                 actionParams.imageUrl->find("nfs://[") == 0) ||
                (*actionParams.transferProtocolType == "CIFS" &&
                 actionParams.imageUrl->find("smb://[") == 0))
            {
                std::size_t startBracket = actionParams.imageUrl->find('[');
                auto endBracket =
                    actionParams.imageUrl->find(']', startBracket);
                auto colon = actionParams.imageUrl->find(':', endBracket);

                if (endBracket != std::string::npos && colon == endBracket + 1)
                {
                    std::string ipv6 = actionParams.imageUrl->substr(
                        startBracket + 1, endBracket - (startBracket + 1));
                    std::string path = actionParams.imageUrl->substr(colon + 1);

                    if (*actionParams.transferProtocolType == "NFS")
                    {
                        *actionParams.imageUrl = "nfs://" + ipv6 + ":" + path;
                    }
                    else
                    {
                        *actionParams.imageUrl = "smb://" + ipv6 + path;
                    }
                }
                else
                {
                    BMCWEB_LOG_ERROR("{} URL format invalid: {}",
                                     *actionParams.transferProtocolType,
                                     *actionParams.imageUrl);
                    messages::propertyValueFormatError(
                        asyncResp->res, *actionParams.imageUrl, "Image");
                    return;
                }
            }
        }
    }
    // optional param transferMethod must be stream
    if (actionParams.transferMethod &&
        (*actionParams.transferMethod != "Stream"))
    {
        BMCWEB_LOG_ERROR("Request action optional parameter "
                         "TransferMethod must be Stream.");

        messages::actionParameterNotSupported(asyncResp->res, "TransferMethod",
                                              "InsertMedia");

        return;
    }

    // validate the Username and Password for CIFS

    if (actionParams.transferProtocolType == "CIFS" ||
        actionParams.transferProtocolType == "HTTPS")
    {
        if (!actionParams.userName || actionParams.userName == "")

        {
            BMCWEB_LOG_ERROR("Request action parameter UserName is Missing.");

            messages::actionParameterMissing(asyncResp->res, "InsertMedia",
                                             "UserName");

            return;
        }
        if (!actionParams.password || actionParams.password == "")

        {
            BMCWEB_LOG_ERROR("Request action parameter Password is Missing.");

            messages::actionParameterMissing(asyncResp->res, "InsertMedia",
                                             "Password");

            return;
        }
    }

    // validate that Username and Password are NOT provided for NFS
    if (actionParams.transferProtocolType == "NFS")
    {
        if (actionParams.userName.has_value() ||
            actionParams.password.has_value())
        {
            BMCWEB_LOG_ERROR(
                "Request: Username/Password not supported for NFS");
            messages::actionParameterNotSupported(
                asyncResp->res, "UserName/Password", "InsertMedia");
            return;
        }
    }
    if (!actionParams.userName)
    {
        actionParams.userName = "";
    }

    if (!actionParams.password)
    {
        actionParams.password = "";
    }
    std::string sessionId;
    std::string uniqueId = req.session->uniqueId;
    if (persistent_data::sessionMap.find(uniqueId) !=
        persistent_data::sessionMap.end())
    {
        sessionId = "session_" +
                    std::to_string(persistent_data::sessionMap[uniqueId]);
    }

    doMountVmLegacy(asyncResp, service, resName, *actionParams.imageUrl,
                    !(actionParams.writeProtected.value_or(false)),
                    std::move(*actionParams.userName),
                    std::move(*actionParams.password), sessionId, name);
}

/**
 * @brief Function transceives data with dbus directly.
 *
 * All BMC state properties will be retrieved before sending reset request.
 */
inline void doEjectAction(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                          const std::string& service, const std::string& name,
                          const std::string& systemName, bool legacy)
{
    const std::string vmMode = getModeName(legacy);
    std::string objectPath;
    if (systemName == "system1")
    {
        objectPath = "/xyz/openbmc_project/VirtualMedia1/" + vmMode + "/" +
                     name;
    }
    else
    {
        objectPath = "/xyz/openbmc_project/VirtualMedia/" + vmMode + "/" + name;
    }
    const std::string ifaceName = "xyz.openbmc_project.VirtualMedia." + vmMode;
    std::string action = "VirtualMedia.Eject";

    auto wrapper = doListenForCompletion(name, objectPath, action, legacy,
                                         asyncResp, "", systemName);

    crow::connections::systemBus->async_method_call(
        [asyncResp, name, action, objectPath, wrapper,
         systemName](const boost::system::error_code ec, bool success) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("Bad D-Bus request error: {}", ec);
                if (ec == boost::system::errc::device_or_resource_busy)
                {
                    messages::resourceInUse(asyncResp->res);
                }
                else if (ec == boost::system::errc::permission_denied)
                {
                    messages::accessDenied(
                        asyncResp->res,
                        boost::urls::format(
                            "/redfish/v1/Systems/{}/VirtualMedia/{}/Actions/{}",
                            systemName, name, action));
                }
                else
                {
                    messages::internalError(asyncResp->res);
                }
                wrapper->stop();
                return;
            }

            if (!success)
            {
                messages::operationFailed(asyncResp->res);
                wrapper->stop();
            }
        },
        service, objectPath, ifaceName, "Unmount");
}

inline void handleSystemsVirtualMediaActionInsertPost(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& name, const std::string& resName)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    constexpr std::string_view action = "VirtualMedia.InsertMedia";

    if (!system_utils::validateSystemName(asyncResp, name))
    {
        return;
    }

    if ((resName == "Slot_0") || (resName == "Slot_1"))
    {
        messages::resourceNotFound(asyncResp->res, "Virtual Media", resName);
        return;
    }
    if (req.session->username != "root")
    {
        auto result = find(req.session->userGroups.begin(),
                           req.session->userGroups.end(), "media");
        if (result == end(req.session->userGroups))
        {
            BMCWEB_LOG_ERROR("Unable to get access ");
            messages::resourceAtUriUnauthorized(
                asyncResp->res, req.url(),
                "Insufficient privileges to access ");
            return;
        }
    }
    InsertMediaActionParams actionParams;

    asyncResp->res.clearHeader(boost::beast::http::field::allow);
    asyncResp->res.addHeader("Allow", "POST");

    // Read obligatory parameters (url of image)
    if (!json_util::readJsonAction(                                   //
            req, asyncResp->res,                                      //
            "Image", actionParams.imageUrl,                           //
            "WriteProtected", actionParams.writeProtected,            //
            "UserName", actionParams.userName,                        //
            "Password", actionParams.password,                        //
            "Inserted", actionParams.inserted,                        //
            "TransferMethod", actionParams.transferMethod,            //
            "TransferProtocolType", actionParams.transferProtocolType //
            ))
    {
        return;
    }

    std::string objPath, service, vmObjectPath;

    if (name == "system1")
    {
        objPath = "/xyz/openbmc_project/VirtualMedia1/Legacy/" + resName;
        service = "xyz.openbmc_project.VirtualMedia1";
        vmObjectPath = "/xyz/openbmc_project/VirtualMedia1";
    }
    else
    {
        objPath = "/xyz/openbmc_project/VirtualMedia/Legacy/" + resName;
        service = "xyz.openbmc_project.VirtualMedia";
        vmObjectPath = "/xyz/openbmc_project/VirtualMedia";
    }
    dbus::utility::getProperty<bool>(
        service, objPath, "xyz.openbmc_project.VirtualMedia.Process", "Active",
        [asyncResp, action, actionParams, &req, resName, name,
         vmObjectPath](const boost::system::error_code& ec1, bool present) {
            BMCWEB_LOG_DEBUG("handleSystemsVirtualMediaActionInsertPost ");
            if (ec1)
            {
                if (ec1.value() != EBADR)
                {
                    messages::internalError(asyncResp->res);
                }
                return;
            }
            if (present)
            {
                messages::resourceAlreadyExists(asyncResp->res, "Slot ",
                                                resName, "can't insert");
                return;
            }
            else if (!present)
            {
                dbus::utility::getDbusObject(
                    vmObjectPath, {},
                    [&req, asyncResp, action, actionParams, resName,
                     vmObjectPath, name](const boost::system::error_code& ec,
                                         const dbus::utility::MapperGetObject&
                                             getObjectType) mutable {
                        if (ec)
                        {
                            BMCWEB_LOG_ERROR(
                                "ObjectMapper::GetObject call failed: {}", ec);
                            messages::resourceNotFound(asyncResp->res, action,
                                                       resName);
                            return;
                        }

                        std::string service = getObjectType.begin()->first;
                        BMCWEB_LOG_DEBUG("GetObjectType: {}", service);

                        dbus::utility::getManagedObjects(
                            service, vmObjectPath,
                            [&req, service, resName, action, actionParams,
                             asyncResp,
                             name](const boost::system::error_code& ec2,
                                   const dbus::utility::ManagedObjectType&
                                       subtree) mutable {
                                if (ec2)
                                {
                                    // Not possible in proxy mode
                                    BMCWEB_LOG_DEBUG("InsertMedia not "
                                                     "allowed in proxy mode");
                                    messages::resourceNotFound(asyncResp->res,
                                                               action, resName);

                                    return;
                                }
                                for (const auto& object : subtree)
                                {
                                    VmMode mode = parseObjectPathAndGetMode(
                                        object.first, resName);
                                    if (mode == VmMode::Legacy)
                                    {
                                        validateParams(asyncResp, service,
                                                       resName, actionParams,
                                                       req, name);

                                        return;
                                    }
                                }
                                BMCWEB_LOG_DEBUG("Parent item not found");
                                messages::resourceNotFound(
                                    asyncResp->res, "VirtualMedia", resName);
                            });
                    });
            }
        });
}

inline void handleSystemsVirtualMediaActionEject(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& name, const std::string& resName)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    constexpr std::string_view action = "VirtualMedia.EjectMedia";

    if (!system_utils::validateSystemName(asyncResp, name))
    {
        return;
    }

    if (req.session->username != "root")
    {
        auto result = find(req.session->userGroups.begin(),
                           req.session->userGroups.end(), "media");
        if (result == end(req.session->userGroups))
        {
            BMCWEB_LOG_ERROR("Unable to get access ");
            messages::resourceAtUriUnauthorized(
                asyncResp->res, req.url(),
                "Insufficient privileges to access ");
            return;
        }
    }
    std::string objectPathStr, vmService;
    if (resName == "Slot_2" || resName == "Slot_3")
    {
        if (name == "system1")
        {
            vmService = "xyz.openbmc_project.VirtualMedia1";
            objectPathStr =
                std::string("/xyz/openbmc_project/VirtualMedia1/Legacy/") +
                std::string(resName);
        }
        else
        {
            vmService = "xyz.openbmc_project.VirtualMedia";
            objectPathStr =
                std::string("/xyz/openbmc_project/VirtualMedia/Legacy/") +
                std::string(resName);
        }
    }
    else
    {
        if (name == "system1")
        {
            vmService = "xyz.openbmc_project.VirtualMedia1";
            objectPathStr =
                std::string("/xyz/openbmc_project/VirtualMedia1/Proxy/") +
                std::string(resName);
        }
        else
        {
            vmService = "xyz.openbmc_project.VirtualMedia";
            objectPathStr =
                std::string("/xyz/openbmc_project/VirtualMedia/Proxy/") +
                std::string(resName);
        }
    }
    std::string objectPath = std::move(objectPathStr);

    dbus::utility::getProperty<bool>(
        *crow::connections::systemBus, vmService, objectPath,
        "xyz.openbmc_project.VirtualMedia.Process", "Active",
        [asyncResp, action, resName, name,
         objectPath](const boost::system::error_code& ec1, bool ejectState) {
            if (ec1)
            {
                BMCWEB_LOG_ERROR("GetProperty call failed: {}", ec1);
                messages::internalError(asyncResp->res);
                return;
            }

            if (!ejectState)
            {
                messages::actionNotSupported(
                    asyncResp->res,
                    std::format("in {} does not contain any Media to Eject",
                                resName));
                return;
            }
            else
            {
                dbus::utility::getDbusObject(
                    objectPath, {},
                    [asyncResp, action, resName, name](
                        const boost::system::error_code& ec2,
                        const dbus::utility::MapperGetObject& getObjectType) {
                        if (ec2)
                        {
                            BMCWEB_LOG_ERROR(
                                "ObjectMapper::GetObject call failed: {}", ec2);
                            messages::internalError(asyncResp->res);

                            return;
                        }
                        std::string service = getObjectType.begin()->first;
                        BMCWEB_LOG_DEBUG("GetObjectType: {}", service);

                        std::string path;
                        if (name == "system1")
                        {
                            path = "/xyz/openbmc_project/VirtualMedia1";
                        }
                        else
                        {
                            path = "/xyz/openbmc_project/VirtualMedia";
                        }
                        dbus::utility::getManagedObjects(
                            service, path,
                            [resName, service, action, asyncResp,
                             name](const boost::system::error_code& ec,
                                   const dbus::utility::ManagedObjectType&
                                       subtree) {
                                if (ec)
                                {
                                    BMCWEB_LOG_ERROR(
                                        "ObjectMapper : No Service found");
                                    messages::resourceNotFound(asyncResp->res,
                                                               action, resName);
                                    return;
                                }

                                for (const auto& object : subtree)
                                {
                                    VmMode mode = parseObjectPathAndGetMode(
                                        object.first, resName);
                                    if (mode != VmMode::Invalid)
                                    {
                                        doEjectAction(asyncResp, service,
                                                      resName, name,
                                                      mode == VmMode::Legacy);
                                        return;
                                    }
                                }
                                BMCWEB_LOG_DEBUG("Parent item not found");
                                messages::resourceNotFound(
                                    asyncResp->res, "VirtualMedia", resName);
                            });
                    });
            }
        });
}

inline void handleSystemsVirtualMediaCollectionGet(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& name)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    if (!system_utils::validateSystemName(asyncResp, name))
    {
        return;
    }

    asyncResp->res.jsonValue["@odata.type"] =
        "#VirtualMediaCollection.VirtualMediaCollection";
    asyncResp->res.jsonValue["Name"] = "Virtual Media Services";
    asyncResp->res.jsonValue["Description"] =
        "The Collection for Virtual Media Services";
    asyncResp->res.jsonValue["@odata.id"] =
        boost::urls::format("/redfish/v1/Systems/{}/VirtualMedia", name);

    std::string path;
    if (name == "system1")
    {
        path = "/xyz/openbmc_project/VirtualMedia1";
    }
    else
    {
        path = "/xyz/openbmc_project/VirtualMedia";
    }

    dbus::utility::getDbusObject(
        path, {},
        [asyncResp, name](const boost::system::error_code& ec,
                          const dbus::utility::MapperGetObject& getObjectType) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("ObjectMapper::GetObject call failed: {}", ec);
                messages::resourceNotFound(asyncResp->res, "VirtualMedia",
                                           name);
                return;
            }
            std::string service = getObjectType.begin()->first;
            BMCWEB_LOG_DEBUG("GetObjectType: {}", service);

            getVmResourceList(asyncResp, service, name);
        });
}

inline void handleVirtualMediaGet(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& name, const std::string& resName)
{
    asyncResp->res.clearHeader(boost::beast::http::field::allow);

    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (!system_utils::validateSystemName(asyncResp, name))
    {
        return;
    }

    if (!membersResponseGet(asyncResp, resName, "VirtualMediaCollection"))
    {
        return;
    }

    if (resName == "Slot_0" || resName == "Slot_1")
    {
        asyncResp->res.addHeader("Allow", "GET");
    }
    else
    {
        asyncResp->res.addHeader("Allow", "GET, PATCH");
    }

    if (req.session->username != "root")
    {
        auto result = find(req.session->userGroups.begin(),
                           req.session->userGroups.end(), "media");
        if (result == end(req.session->userGroups))
        {
            BMCWEB_LOG_ERROR("Unable to get access ");
            messages::insufficientPrivilege(asyncResp->res);
            return;
        }
    }

    std::string path;
    if (name == "system1")
    {
        path = "/xyz/openbmc_project/VirtualMedia1";
    }
    else
    {
        path = "/xyz/openbmc_project/VirtualMedia";
    }
    dbus::utility::getDbusObject(
        path, {},
        [asyncResp, name,
         resName](const boost::system::error_code& ec,
                  const dbus::utility::MapperGetObject& getObjectType) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("ObjectMapper::GetObject call failed: {}", ec);
                messages::internalError(asyncResp->res);

                return;
            }
            std::string service = getObjectType.begin()->first;
            BMCWEB_LOG_DEBUG("GetObjectType: {}", service);

            getVmData(asyncResp, service, name, resName);
        });
}

inline void handleVirtualMediaValueGet(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& name, const std::string& resName)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    asyncResp->res.clearHeader(boost::beast::http::field::allow);

    if (!system_utils::validateSystemName(asyncResp, name))
    {
        return;
    }

    if (resName == "Slot_2" || resName == "Slot_3")
    {
        asyncResp->res.addHeader("Allow", "POST");
        messages::operationNotAllowed(asyncResp->res);
        return;
    }
    else
    {
        messages::resourceNotFound(asyncResp->res, "Virtual Media", resName);
        return;
    }
}

inline void handleVirtualmediaPatch(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& name, const std::string& resName)
{
    asyncResp->res.clearHeader(boost::beast::http::field::allow);

    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    if (!system_utils::validateSystemName(asyncResp, name))
    {
        return;
    }

    if (resName.empty())
    {
        messages::resourceNotFound(asyncResp->res, "Virtual Media", resName);
        return;
    }
    if (!membersResponseGet(asyncResp, resName, "VirtualMediaCollection"))
    {
        return;
    }

    std::string path;
    if (name == "system1")
    {
        path = "/xyz/openbmc_project/VirtualMedia1";
    }
    else
    {
        path = "/xyz/openbmc_project/VirtualMedia";
    }
    std::string serviceName =
        (name == "system1") ? rmedia1ServiceName : rmediaServiceName;

    dbus::utility::getManagedObjects(
        serviceName, path,
        [asyncResp, resName, &req, serviceName,
         path](const boost::system::error_code& ec,
               const dbus::utility::ManagedObjectType& slot) {
            if (ec)
            {
                messages::internalError(asyncResp->res);
                return;
            }
            const auto slotIt = std::ranges::find_if(
                slot,
                [resName](const std::pair<sdbusplus::message::object_path,
                                          dbus::utility::DBusInterfacesMap>&
                              slotName) {
                    return resName == slotName.first.filename();
                });
            if (slotIt == slot.end())
            {
                messages::resourceNotFound(asyncResp->res, "ManagerAccount",
                                           resName);
                return;
            }
            if (resName == "Slot_0" || resName == "Slot_1")
            {
                asyncResp->res.addHeader("Allow", "GET");
                asyncResp->res.result(
                    boost::beast::http::status::method_not_allowed);
                messages::operationNotAllowed(asyncResp->res);
                return;
            }
            std::optional<nlohmann::json> oem;
            if (!json_util::readJsonPatch(req, asyncResp->res, "Oem", oem))
            {
                return;
            }
            if (oem)
            {
                std::optional<nlohmann::json> amiBmc;

                if (!json_util::readJson(*oem, asyncResp->res, "Ami", amiBmc))
                {
                    return;
                }
                if (amiBmc)
                {
                    std::optional<uint32_t> retryCount;
                    std::optional<uint32_t> retryInterval;
                    bool retryFlag = true;

                    if (!json_util::readJson(*amiBmc, asyncResp->res,
                                             "RetryCount", retryCount,
                                             "RetryInterval", retryInterval))
                    {
                        return;
                    }
                    if (retryCount < 3 || retryCount > 6)
                    {
                        retryFlag = false;
                        messages::propertyValueOutOfRange(
                            asyncResp->res, std::to_string(*retryCount),
                            "RetryCount");
                    }
                    if (retryInterval < 15 || retryInterval > 30)
                    {
                        retryFlag = false;
                        messages::propertyValueOutOfRange(
                            asyncResp->res, std::to_string(*retryInterval),
                            "RetryInterval");
                    }
                    if (retryFlag)
                    {
                        crow::connections::systemBus->async_method_call(
                            [asyncResp](const boost::system::error_code ec,
                                        std::string& ret) {
                                if (ec)
                                {
                                    BMCWEB_LOG_ERROR("Error patching {}", ec);
                                    messages::internalError(asyncResp->res);
                                    return;
                                }
                                if (ret == "Success")
                                {
                                    messages::success(asyncResp->res);
                                }
                            },
                            serviceName, path, rmediaInterfaceName, "SetAll",
                            *retryCount, *retryInterval);
                    }
                }
            }
        });
}

inline void insertMediaCheckMode(
    [[maybe_unused]] const std::string& service,
    [[maybe_unused]] const std::string& resName,
    const std::shared_ptr<bmcweb::AsyncResp>& aResp,
    const std::pair<sdbusplus::message::object_path,
                    dbus::utility::DBusInterfacesMap>& item)
{
    auto mode = item.first.parent_path();
    auto type = mode.parent_path();
    // Check if dbus path is Legacy type
    if (mode.filename() == legacyMode)
    {
        BMCWEB_LOG_DEBUG(
            "InsertMedia only allowed with POST method in legacy mode");
        aResp->res.clearHeader(boost::beast::http::field::allow);
        aResp->res.addHeader("Allow", "POST");
        messages::operationNotAllowed(aResp->res);
        return;
    }
    // Check if dbus path is Proxy type
    if (mode.filename() == proxyMode)
    {
        // Not possible in proxy mode
        BMCWEB_LOG_DEBUG("InsertMedia not allowed in proxy mode");
        aResp->res.result(boost::beast::http::status::not_found);
    }
}

inline void requestNBDVirtualMediaRoutes(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/VirtualMedia/<str>/Actions/"
                      "VirtualMedia.InsertMedia")
        .privileges(redfish::privileges::getVirtualMedia)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleVirtualMediaValueGet, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/VirtualMedia/<str>/Actions/"
                      "VirtualMedia.InsertMedia")
        .privileges(redfish::privileges::patchVirtualMedia)
        .methods(boost::beast::http::verb::patch)(
            []([[maybe_unused]] const crow::Request& req,
               const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
               const std::string& name, const std::string& resName) {
                if ((resName == "Slot_0") || (resName == "Slot_1"))
                {
                    messages::resourceNotFound(asyncResp->res, "Virtual Media",
                                               resName);
                    return;
                }
                findItemAndRunHandler(asyncResp, name, resName,
                                      insertMediaCheckMode, req);
            });
    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/VirtualMedia/<str>/Actions/"
                      "VirtualMedia.InsertMedia")
        .privileges(redfish::privileges::putVirtualMedia)
        .methods(boost::beast::http::verb::put)(
            []([[maybe_unused]] const crow::Request& req,
               const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
               const std::string& name, const std::string& resName) {
                if ((resName == "Slot_0") || (resName == "Slot_1"))
                {
                    messages::resourceNotFound(asyncResp->res, "Virtual Media",
                                               resName);
                    return;
                }
                findItemAndRunHandler(asyncResp, name, resName,
                                      insertMediaCheckMode, req);
            });
    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/VirtualMedia/<str>/Actions/"
                      "VirtualMedia.InsertMedia")
        .privileges(redfish::privileges::deleteVirtualMedia)
        .methods(boost::beast::http::verb::delete_)(
            []([[maybe_unused]] const crow::Request& req,
               const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
               const std::string& name, const std::string& resName) {
                if ((resName == "Slot_0") || (resName == "Slot_1"))
                {
                    messages::resourceNotFound(asyncResp->res, "Virtual Media",
                                               resName);
                    return;
                }
                findItemAndRunHandler(asyncResp, name, resName,
                                      insertMediaCheckMode, req);
            });
    BMCWEB_ROUTE(
        app,
        "/redfish/v1/Systems/<str>/VirtualMedia/<str>/Actions/VirtualMedia.InsertMedia")
        .privileges(redfish::privileges::postVirtualMedia)
        .methods(boost::beast::http::verb::post)(std::bind_front(
            handleSystemsVirtualMediaActionInsertPost, std::ref(app)));

    BMCWEB_ROUTE(
        app,
        "/redfish/v1/Systems/<str>/VirtualMedia/<str>/Actions/VirtualMedia.EjectMedia")
        .privileges(redfish::privileges::postVirtualMedia)
        .methods(boost::beast::http::verb::post)(std::bind_front(
            handleSystemsVirtualMediaActionEject, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/VirtualMedia/")
        .privileges(redfish::privileges::getVirtualMediaCollection)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleSystemsVirtualMediaCollectionGet, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/VirtualMedia/<str>/")
        .privileges(redfish::privileges::getVirtualMedia)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleVirtualMediaGet, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/VirtualMedia/<str>/")
        .privileges(redfish::privileges::patchVirtualMedia)
        .methods(boost::beast::http::verb::patch)(
            std::bind_front(handleVirtualmediaPatch, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/VirtualMedia/<str>/")
        .privileges(redfish::privileges::getVirtualMedia)
        .methods(boost::beast::http::verb::post,
                 boost::beast::http::verb::delete_)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& name, const std::string& resName) {
                asyncResp->res.clearHeader(boost::beast::http::field::allow);
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }
                if (!membersResponseGet(asyncResp, resName,
                                        "VirtualMediaCollection"))
                {
                    return;
                }
                if (!system_utils::validateSystemName(asyncResp, name))
                {
                    return;
                }
                // Block POST and DELETE for specific slots
                if (resName == "Slot_0" || resName == "Slot_1" ||
                    resName == "Slot_2" || resName == "Slot_3")
                {
                    // Explicitly state allowed methods (none in this case)
                    asyncResp->res.clearHeader(
                        boost::beast::http::field::allow);
                    messages::operationNotAllowed(asyncResp->res);
                    asyncResp->res.result(
                        boost::beast::http::status::method_not_allowed);
                    return;
                }
                std::string path;
                if (name == "system1")
                {
                    path = "/xyz/openbmc_project/VirtualMedia1";
                }
                else
                {
                    path = "/xyz/openbmc_project/VirtualMedia";
                }
                dbus::utility::getDbusObject(
                    path, {},
                    [asyncResp, name, resName](
                        const boost::system::error_code& ec,
                        const dbus::utility::MapperGetObject& getObjectType) {
                        if (ec)
                        {
                            BMCWEB_LOG_ERROR(
                                "ObjectMapper::GetObject call failed: {}", ec);
                            messages::internalError(asyncResp->res);

                            return;
                        }
                        std::string service = getObjectType.begin()->first;
                        BMCWEB_LOG_DEBUG("GetObjectType: {}", service);

                        getVmPostData(asyncResp, service, name, resName);
                    });
            });
}

} // namespace redfish
