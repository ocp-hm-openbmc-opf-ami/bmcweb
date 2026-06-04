// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#pragma once

#include "dbus_singleton.hpp"
#include "logging.hpp"

#include <sdbusplus/bus.hpp>

#include <functional>
#include <map>
#include <string>
#include <variant>
#include <vector>

namespace crow
{
namespace user_info_utils
{

using UserInfoVariant =
    std::variant<bool, std::string, std::vector<std::string>>;
using UserInfoMap = std::map<std::string, UserInfoVariant>;

inline std::string getRole(const std::string& role)
{
    if (role == "priv-admin")
    {
        return "Administrator";
    }
    if (role == "priv-operator")
    {
        return "Operator";
    }
    if (role == "priv-user")
    {
        return "ReadOnly";
    }
    return "";
}

struct UserInfoData
{
    std::string userPrivilege;
    std::string roleId;
    std::string userType;
    bool remoteUser = false;
};

inline UserInfoData parseUserInfoMap(const UserInfoMap& infoMap)
{
    UserInfoData data;

    auto privIt = infoMap.find("UserPrivilege");
    if (privIt != infoMap.end() &&
        std::holds_alternative<std::string>(privIt->second))
    {
        data.userPrivilege = std::get<std::string>(privIt->second);
        data.roleId = getRole(data.userPrivilege);
    }

    auto remoteIt = infoMap.find("RemoteUser");
    if (remoteIt != infoMap.end())
    {
        if (const auto* val = std::get_if<bool>(&remoteIt->second))
        {
            data.remoteUser = *val;
        }
    }

    auto typeIt = infoMap.find("UserType");
    if (typeIt != infoMap.end() &&
        std::holds_alternative<std::string>(typeIt->second))
    {
        data.userType = std::get<std::string>(typeIt->second);
    }

    return data;
}

template <typename CallbackFn>
inline void getUserInfo(const std::string& user, const std::string& ipAddr,
                        CallbackFn&& callback)
{
    crow::connections::systemBus->async_method_call(
        [callback = std::forward<CallbackFn>(callback)](
            const boost::system::error_code& ec, const UserInfoMap& infoMap) {
            UserInfoData data;
            if (ec)
            {
                BMCWEB_LOG_ERROR("GetUserInfo D-Bus call failed: {}",
                                 ec.message());
                callback(data);
                return;
            }
            data = parseUserInfoMap(infoMap);
            callback(data);
        },
        "xyz.openbmc_project.User.Manager", "/xyz/openbmc_project/user",
        "xyz.openbmc_project.User.Manager", "GetUserInfo", user, ipAddr);
}

} // namespace user_info_utils
} // namespace crow
