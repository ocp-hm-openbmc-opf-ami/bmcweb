// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#pragma once

#include "dbus_utility.hpp"
#include "error_messages.hpp"
#include "http_request.hpp"
#include "http_response.hpp"
#include "logging.hpp"
#include "routing/baserule.hpp"
#include "utils/dbus_utils.hpp"
#include "utils/ip_utils.hpp"

#include <boost/url/format.hpp>
#include <sdbusplus/unpack_properties.hpp>

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace crow
{
// Cache structure for user properties
struct UserPropertiesCache
{
    std::string userRole;
    bool remoteUser = false;
    std::optional<bool> passwordExpired;
    std::optional<std::vector<std::string>> userGroups;
    bool isValid = false;
};

// Static cache storage
static UserPropertiesCache cachedUserProperties;

// Populate session with user information.
inline bool
    populateUserInfo(persistent_data::UserSession& session,
                     const dbus::utility::DBusPropertiesMap& userInfoMap)
{
    std::string userRole;
    bool remoteUser = false;
    std::optional<bool> passwordExpired;
    std::optional<std::vector<std::string>> userGroups;

    const bool success = sdbusplus::unpackPropertiesNoThrow(
        redfish::dbus_utils::UnpackErrorPrinter(), userInfoMap, "UserPrivilege",
        userRole, "RemoteUser", remoteUser, "UserPasswordExpired",
        passwordExpired, "UserGroups", userGroups);

    if (!success)
    {
        if (cachedUserProperties.isValid)
        {
            userRole = cachedUserProperties.userRole;
            remoteUser = cachedUserProperties.remoteUser;
            passwordExpired = cachedUserProperties.passwordExpired;
            userGroups = cachedUserProperties.userGroups;
        }
        else
        {
            BMCWEB_LOG_ERROR("No cached user properties available");
            return false;
        }
    }
    else
    {
        cachedUserProperties.userRole = userRole;
        cachedUserProperties.remoteUser = remoteUser;
        cachedUserProperties.passwordExpired = passwordExpired;
        cachedUserProperties.userGroups = userGroups;
        cachedUserProperties.isValid = true;
    }

    if (!remoteUser && (!passwordExpired || !userGroups))
    {
        BMCWEB_LOG_ERROR(
            "Missing UserPasswordExpired or UserGroups property for local user");
        return false;
    }

    session.userRole = userRole;
    BMCWEB_LOG_DEBUG("userName = {} userRole = {}", session.username, userRole);
    // Set isConfigureSelfOnly based on D-Bus results.  This
    // ignores the results from both pamAuthenticateUser and the
    // value from any previous use of this session.
    session.isConfigureSelfOnly = passwordExpired.value_or(false);

    session.userGroups.clear();
    if (userGroups)
    {
        session.userGroups.swap(*userGroups);
    }

    return true;
}

inline bool
    isUserPrivileged(Request& req,
                     const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                     BaseRule& rule)
{
    if (req.session == nullptr)
    {
        return false;
    }
    // Get the user's privileges from the role
    redfish::Privileges userPrivileges =
        redfish::getUserPrivileges(*req.session);

    // Modify privileges if isConfigureSelfOnly.
    if (req.session->isConfigureSelfOnly)
    {
        // Remove all privileges except ConfigureSelf
        userPrivileges =
            userPrivileges.intersection(redfish::Privileges{"ConfigureSelf"});
        BMCWEB_LOG_DEBUG("Operation limited to ConfigureSelf");
    }

    if (!rule.checkPrivileges(userPrivileges))
    {
        asyncResp->res.result(boost::beast::http::status::forbidden);
        if (req.session->isConfigureSelfOnly)
        {
            redfish::messages::passwordChangeRequired(
                asyncResp->res,
                boost::urls::format("/redfish/v1/AccountService/Accounts/{}",
                                    req.session->username));
        }
        return false;
    }

    req.userRole = req.session->userRole;
    return true;
}

inline bool afterGetUserInfoValidate(
    Request& req, const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    BaseRule& rule, const dbus::utility::DBusPropertiesMap& userInfoMap)
{
    if (!populateUserInfo(*req.session, userInfoMap))
    {
        BMCWEB_LOG_DEBUG("Failed to populate user information; Insufficient Privilege");
        redfish::messages::insufficientPrivilege(asyncResp->res);
        return false;
    }
    else if (req.session == nullptr)
    {
        BMCWEB_LOG_ERROR("Failed to populate user information");
        asyncResp->res.result(
            boost::beast::http::status::internal_server_error);
        return false;
    }

    if (!isUserPrivileged(req, asyncResp, rule))
    {
        // User is not privileged
        // Only add insufficientPrivilege error when it's not ConfigureSelfOnly
        if (req.session && !req.session->isConfigureSelfOnly)
        {
            BMCWEB_LOG_ERROR("Insufficient Privilege");
            redfish::messages::insufficientPrivilege(asyncResp->res);
        }

        return false;
    }

    return true;
}

template <typename CallbackFn>
void requestUserInfo(const std::string& username,
                     const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,  const boost::asio::ip::address& serverIp,
                     CallbackFn&& callback)
{

    std::string ipStr = redfish::ip_util::extractIPv4FromMappedIPv6(serverIp);

    crow::connections::systemBus->async_method_call(
        [asyncResp, callback = std::forward<CallbackFn>(callback), serverIp](
            const boost::system::error_code& ec,
            const dbus::utility::DBusPropertiesMap& userInfoMap) mutable {
        if (ec)
        {
            BMCWEB_LOG_DEBUG("GetUserInfo Dbus failed...");
            asyncResp->res.result(
                boost::beast::http::status::internal_server_error);
            return;
        }
        callback(userInfoMap);
        },
        "xyz.openbmc_project.User.Manager", "/xyz/openbmc_project/user",
        "xyz.openbmc_project.User.Manager", "GetUserInfo", username, ipStr);
}

template <typename CallbackFn>
void validatePrivilege(const std::shared_ptr<Request>& req,
                       const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                       BaseRule& rule, CallbackFn&& callback)
{
    if (req->session == nullptr)
    {
        return;
    }

    requestUserInfo(
        req->session->username, asyncResp, req->serverIPAddress,
        [req, asyncResp, &rule, callback = std::forward<CallbackFn>(callback)](
            const dbus::utility::DBusPropertiesMap& userInfoMap) mutable {
        if (afterGetUserInfoValidate(*req, asyncResp, rule, userInfoMap))
        {
            callback();
        }
        });
}

template <typename CallbackFn>
void getUserInfo(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                 const std::string& username,
                 std::shared_ptr<persistent_data::UserSession>& session, const boost::asio::ip::address& serverIp,
                 CallbackFn&& callback)
{
    requestUserInfo(
        username, asyncResp, serverIp,
        [asyncResp, session, callback = std::forward<CallbackFn>(callback)](
            const dbus::utility::DBusPropertiesMap& userInfoMap) {
        if (!populateUserInfo(*session, userInfoMap))
        {
            BMCWEB_LOG_ERROR("Failed to populate user information");
            asyncResp->res.result(
                boost::beast::http::status::internal_server_error);
            return;
        }
        callback();
        });
}

} // namespace crow
