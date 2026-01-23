// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
// SPDX-FileCopyrightText: Copyright 2018 Intel Corporation
#pragma once

#include "app.hpp"
#include "boost_formatters.hpp"
#include "certificate_service.hpp"
#include "dbus_utility.hpp"
#include "error_messages.hpp"
#include "generated/enums/account_service.hpp"
#include "persistent_data.hpp"
#include "query.hpp"
#include "registries/privilege_registry.hpp"
#include "sessions.hpp"
#include "utils/collection.hpp"
#include "utils/dbus_utils.hpp"
#include "utils/json_utils.hpp"
#include "multipart_parser.hpp"
#include "utils/ip_utils.hpp"

#include <boost/url/format.hpp>
#include <boost/url/url.hpp>
#include <sdbusplus/asio/property.hpp>
#include <sdbusplus/unpack_properties.hpp>
#include <nlohmann/json.hpp>

#include <array>
#include <memory>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <vector>
#include <utility>
#include <variant>
#include <unordered_set>

#include <event_service_manager.hpp>


#if BMCWEB_AMI_REP_MACRO
    #include "ext/include/ami_errors.hpp"
#endif

namespace redfish
{

constexpr const char* ldapConfigObjectName =
    "/xyz/openbmc_project/user/ldap/openldap";
constexpr const char* adConfigObject =
    "/xyz/openbmc_project/user/ldap/active_directory";

constexpr const char* rootUserDbusPath = "/xyz/openbmc_project/user/";
constexpr const char* ldapRootObject = "/xyz/openbmc_project/user/ldap";
constexpr const char* ldapDbusService = "xyz.openbmc_project.Ldap.Config";
constexpr const char* snmpUserDbusPath = "/xyz/openbmc_project/snmp/UserManager";
constexpr const char* ldapConfigInterface =
    "xyz.openbmc_project.User.Ldap.Config";
constexpr const char* ldapCreateInterface =
    "xyz.openbmc_project.User.Ldap.Create";
constexpr const char* ldapEnableInterface = "xyz.openbmc_project.Object.Enable";
constexpr const char* ldapPrivMapperInterface =
    "xyz.openbmc_project.User.PrivilegeMapper";

/*
    RADIUS Variable
 */
const std::string radisuDBusService = "xyz.openbmc_project.Radius.Config";
const std::string radiusConfigObjectPath =
    "/xyz/openbmc_project/user/Radius/Config";
const std::string radiusRoleMapObjectPath =
    "/xyz/openbmc_project/user/Radius/role_map";
const std::string radiusConfigInterface =
    "xyz.openbmc_project.User.Radius.Config";
const std::string radiusRoleMapInterface =
    "xyz.openbmc_project.User.Radius.role_map";

namespace fs = std::filesystem;

inline std::string caCertFile = (fs::path("/etc/ssl/certs/") / "radius_ca.pem").string();
inline std::string clientCertFile = (fs::path("/etc/ssl/certs/") / "radius_client.pem").string();
inline std::string privateKeyFile = (fs::path("/etc/ssl/certs/") / "radius_key.pem").string();

struct LDAPRoleMapData
{
    std::string groupName;
    std::string privilege;
};

struct LDAPConfigData
{
    std::string uri;
    std::string bindDN;
    std::string baseDN;
    std::string searchScope;
    std::string serverType;
    bool serviceEnabled = false;
    std::string userNameAttribute;
    std::string groupAttribute;
    std::vector<std::pair<std::string, LDAPRoleMapData>> groupRoleList;
};

struct RadiusPatchParams
{
    std::optional<bool> enabled;
    std::optional<bool> enabledEapTLS;
    std::optional<std::string> password;
    std::optional<std::string> host;
    std::optional<int32_t> port;
    std::optional<std::string> groupName1;
    std::optional<std::string> groupName2;
    std::optional<std::string> groupName3;
    std::optional<std::string> privilege1;
    std::optional<std::string> privilege2;
    std::optional<std::string> privilege3;
};

inline size_t accountsCompletedOperations = 0;
inline size_t accountsTotalOperations = 0;
inline nlohmann::json::object_t propertyModified;
inline nlohmann::json::object_t propertyOriginal;

inline std::string getRoleIdFromPrivilege(std::string_view role)
{
    if (role == "priv-admin")
    {
        return "Administrator";
    }
    if (role == "priv-user")
    {
        return "ReadOnly";
    }
    if (role == "priv-operator")
    {
        return "Operator";
    }
    return "";
}
inline std::string getPrivilegeFromRoleId(std::string_view role)
{
    if (role.empty())
    {
        return "";
    }
    if (role == "Administrator")
    {
        return "priv-admin";
    }
    if (role == "ReadOnly")
    {
        return "priv-user";
    }
    if (role == "Operator")
    {
        return "priv-operator";
    }
    return ""; // If the role is invalid, return empty.
}

inline std::string getModeFromAccessMode(std::string mode)
{
    if (mode == "ReadOnly")
    {
        return "ro";
    }
    if (mode == "ReadWrite")
    {
        return "rw";
    }
    return "";
}

inline std::string getAccessModeFromMode(std::string mode)
{
    if (mode == "ro")
    {
        return "ReadOnly";
    }
    if (mode == "rw")
    {
        return "ReadWrite";
    }
    return "";
}

inline void setSMTPMailId(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,const std::string& username,
                        const std::string& SMTPMailId)
{
    std::cerr<<"SMTPMailId value in setSMTPMailId function: " << SMTPMailId << std::endl;
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus,"xyz.openbmc_project.User.Manager", 
        "/xyz/openbmc_project/user/" + username,
        "xyz.openbmc_project.User.Attributes", "SMTPMailID" , SMTPMailId,
        [asyncResp](const boost::system::error_code& ec){
        if (ec)
        {
            BMCWEB_LOG_DEBUG("DBUS response error {}", ec);
            return;
        }
    });
}

inline void populateOEMAMIChannelInfo(std::vector<std::string> userPrivileges, std::vector<uint8_t> userChannelAccess, const std::shared_ptr<bmcweb::AsyncResp>& asyncResp, const crow::Request& req)
{

    const std::string serverIp = redfish::ip_util::extractIPv4FromMappedIPv6(req.serverIPAddress);
    std::string thisUser;
    if (req.session)
    {
        thisUser = req.session->username;
    }

    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code ec1,
            const std::map<std::string, dbus::utility::DbusVariantType>& userInfo) {

                if (ec1)
                {
                    messages::internalError(asyncResp->res);
                    return;
                }

                auto userPrivilegeIter = userInfo.find("UserPrivilege");
                if (userPrivilegeIter != userInfo.end())
                {
                    const std::string* userPrivilegePtr = std::get_if<std::string>(&userPrivilegeIter->second);
                    if (userPrivilegePtr != nullptr)
                    {
                        std::string_view userPrivilegesView  = *userPrivilegePtr;
                        std::string role = getRoleIdFromPrivilege(userPrivilegesView);
                        asyncResp->res.jsonValue["Oem"] ["Ami"] ["WebRoleId"]= role;
                    }
                }
                else
                {
                    messages::internalError(asyncResp->res);
                    return;
                }

            },
            "xyz.openbmc_project.User.Manager",
            "/xyz/openbmc_project/user",
            "xyz.openbmc_project.User.Manager", "GetUserInfo", thisUser, serverIp
        );

    crow::connections::systemBus->async_method_call(
        [asyncResp, userPrivileges, userChannelAccess](const boost::system::error_code& ec,
                   const std::map<uint8_t, std::string>& channelMap) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("D-Bus Method GetChannelInterfaceMap Response Error: {}", ec);
                return;
            }

            if (userPrivileges.size() != channelMap.size() ||
                userChannelAccess.size() != channelMap.size())
            {
                BMCWEB_LOG_DEBUG("Mismatch in sizes: UserPrivileges = {}, UserChannelAccess = {}, ChannelInterfaceMap = {}",
                                 userPrivileges.size(), userChannelAccess.size(), channelMap.size());
                return;
            }

            try
            {
                nlohmann::json channelPrivileges = nlohmann::json::array();
                size_t i = 0;
                for (const auto& [channel, interface] : channelMap)
                {
                    nlohmann::json entry;
                    entry["ChannelId"] = channel;
                    std::string_view channelPriv = userPrivileges[i];
                    entry["ChannelPrivilege"] = getRoleIdFromPrivilege(channelPriv);
                    entry["ChannelAccess"] = static_cast<bool>(userChannelAccess[i]);
                    channelPrivileges.push_back(std::move(entry));
                    ++i;
                }

                asyncResp->res.jsonValue["Oem"]["Ami"]["ChannelPrivileges"] = std::move(channelPrivileges);
            }
            catch (const std::exception& e)
            {
                BMCWEB_LOG_ERROR("Exception in populateOEMAMIChannelInfo: {}", e.what());
                messages::internalError(asyncResp->res);
                return;
            }

        },
        "xyz.openbmc_project.User.Manager", // Service
        "/xyz/openbmc_project/user", // Object path
        "xyz.openbmc_project.User.AccountPolicy", // Interface
        "GetChannelInterfaceMap" // Method name
    );
}

/**
 * @brief Maps user group names retrieved from D-Bus object to
 * Account Types.
 *
 * @param[in] userGroups List of User groups
 * @param[out] res AccountTypes populated
 *
 * @return true in case of success, false if UserGroups contains
 * invalid group name(s).
 */
inline bool translateUserGroup(const std::vector<std::string>& userGroups,
                               crow::Response& res)
{
    std::vector<std::string> accountTypes;
    for (const auto& userGroup : userGroups)
    {
        if (userGroup == "redfish")
        {
            accountTypes.emplace_back("Redfish");
            accountTypes.emplace_back("WebUI");
        }
        else if (userGroup == "ipmi")
        {
            accountTypes.emplace_back("IPMI");
        }
        else if (userGroup == "ssh")
        {
            accountTypes.emplace_back("ManagerConsole");
        }
        else if (userGroup == "hostconsole")
        {
            // The hostconsole group controls who can access the host console
            // port via ssh and websocket.
            accountTypes.emplace_back("HostConsole");
        }
        else if (userGroup == "web")
        {
            // 'web' is one of the valid groups in the UserGroups property of
            // the user account in the D-Bus object. This group is currently not
            // doing anything, and is considered to be equivalent to 'redfish'.
            // 'redfish' user group is mapped to 'Redfish'and 'WebUI'
            // AccountTypes, so do nothing here...
        }
        else if (userGroup == "media")
        {
            accountTypes.emplace_back("VirtualMedia");
        }
        else if (userGroup == "snmp")
        {
            accountTypes.emplace_back("SNMP");
        }
        else if (userGroup == "redfish-hostiface")
        {
            accountTypes.emplace_back("Redfish");
        }
        else
        {
            // Invalid user group name. Caller throws an exception.
            return false;
        }
    }

    res.jsonValue["AccountTypes"] = std::move(accountTypes);
    return true;
}

/* Creating the same functionality of translateUserGroup with some
changes for PATCH function of accounts instance URI to avoid problems
during LF sync */

inline std::tuple<bool, std::vector<std::string>> translateUserGroupGet(const std::vector<std::string>& userGroups)
{
    std::vector<std::string> accountTypes;
    for (const auto& userGroup : userGroups)
    {
        if (userGroup == "redfish")
        {
            accountTypes.emplace_back("Redfish");
            accountTypes.emplace_back("WebUI");
        }
        else if (userGroup == "ipmi")
        {
            accountTypes.emplace_back("IPMI");
        }
        else if (userGroup == "ssh")
        {
            accountTypes.emplace_back("ManagerConsole");
        }
        else if (userGroup == "hostconsole")
        {
            // The hostconsole group controls who can access the host console
            // port via ssh and websocket.
            accountTypes.emplace_back("HostConsole");
        }
        else if (userGroup == "web")
        {
            // 'web' is one of the valid groups in the UserGroups property of
            // the user account in the D-Bus object. This group is currently not
            // doing anything, and is considered to be equivalent to 'redfish'.
            // 'redfish' user group is mapped to 'Redfish'and 'WebUI'
            // AccountTypes, so do nothing here...
        }
        else if (userGroup == "media")
        {
            accountTypes.emplace_back("VirtualMedia");
        }
        else if (userGroup == "snmp")
        {
            accountTypes.emplace_back("SNMP");
        }
        else
        {
            // Invalid user group name. Caller throws an exception.
            return std::make_tuple(false, accountTypes);
        }
    }

   return std::make_tuple(true, accountTypes);
}

/**
 * @brief Builds User Groups from the Account Types
 *
 * @param[in] asyncResp Async Response
 * @param[in] accountTypes List of Account Types
 * @param[out] userGroups List of User Groups mapped from Account Types
 *
 * @return true if Account Types mapped to User Groups, false otherwise.
 */
inline bool getUserGroupFromAccountType(
    crow::Response& res, const std::vector<std::string>& accountTypes,
    std::vector<std::string>& userGroups)
{
    // Need both Redfish and WebUI Account Types to map to 'redfish' User Group
    bool redfishType = false;
    bool webUIType = false;

    for (const auto& accountType : accountTypes)
    {
        if (accountType == "Redfish")
        {
            redfishType = true;
        }
        else if (accountType == "WebUI")
        {
            webUIType = true;
        }
        else if (accountType == "IPMI")
        {
            userGroups.emplace_back("ipmi");
        }
        else if (accountType == "HostConsole")
        {
            userGroups.emplace_back("hostconsole");
        }
        else if (accountType == "ManagerConsole")
        {
            userGroups.emplace_back("ssh");
        }
        else if (accountType == "VirtualMedia")
        {
            userGroups.emplace_back("media");
        }
        else if (accountType == "SNMP")
        {
            userGroups.emplace_back("snmp");
        }
        else if (accountType == "HostInterfaces")
        {
            userGroups.emplace_back("HostInterfaces");
        }
        else
        {
            // Invalid Account Type
            messages::propertyValueNotInList(res, "AccountTypes", accountType);
            return false;
        }
    }

    // Both  Redfish and WebUI Account Types are needed to PATCH
    if (redfishType ^ webUIType)
    {
        BMCWEB_LOG_ERROR(
            "Missing Redfish or WebUI Account Type to set redfish User Group");
        messages::strictAccountTypes(res, "AccountTypes");
        return false;
    }

    if (redfishType && webUIType)
    {
        userGroups.emplace_back("redfish");
    }

    return true;
}

/**
 * @brief Sets UserGroups property of the user based on the Account Types
 *
 * @param[in] accountTypes List of User Account Types
 * @param[in] asyncResp Async Response
 * @param[in] dbusObjectPath D-Bus Object Path
 * @param[in] userSelf true if User is updating OWN Account Types
 */
inline void patchAccountTypes(
    const std::vector<std::string>& accountTypes,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& dbusObjectPath, bool userSelf,
    std::function<void(bool)> completionHandler)
{
    // Check if User is disabling own Redfish Account Type
    accountsTotalOperations++;
    if (userSelf &&
        (accountTypes.cend() ==
         std::find(accountTypes.cbegin(), accountTypes.cend(), "Redfish")))
    {
        BMCWEB_LOG_ERROR(
            "User disabling OWN Redfish Account Type is not allowed");
        messages::strictAccountTypes(asyncResp->res, "AccountTypes");
        completionHandler(false);
        return;
    }

    std::vector<std::string> updatedUserGroups;
    if (!getUserGroupFromAccountType(asyncResp->res, accountTypes,
                                     updatedUserGroups))
    {
        // Problem in mapping Account Types to User Groups, Error already
        // logged.
        completionHandler(false);
        return;
    }
    setDbusProperty(asyncResp, "AccountTypes",
                    "xyz.openbmc_project.User.Manager", dbusObjectPath,
                    "xyz.openbmc_project.User.Attributes", "UserGroups",
                    updatedUserGroups);

    propertyModified["AccountTypes"] = updatedUserGroups;
    completionHandler(true);
}

inline void userErrorMessageHandler(
    const sd_bus_error* e, const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& newUser, const std::string& username)
{
    if (e == nullptr)
    {
        messages::internalError(asyncResp->res);
        return;
    }

    const char* errorMessage = e->name;
    if (strcmp(errorMessage,
               "xyz.openbmc_project.User.Common.Error.UserNameExists") == 0)
    {
        messages::resourceAlreadyExists(asyncResp->res, "ManagerAccount",
                                        "UserName", newUser);
    }
    else if (strcmp(errorMessage, "xyz.openbmc_project.User.Common.Error."
                                  "UserNameDoesNotExist") == 0)
    {
        messages::resourceNotFound(asyncResp->res, "ManagerAccount", username);
    }
    else if ((strcmp(errorMessage,
                     "xyz.openbmc_project.Common.Error.InvalidArgument") ==
              0) ||
             (strcmp(
                  errorMessage,
                  "xyz.openbmc_project.User.Common.Error.UserNameGroupFail") ==
              0))
    {
        messages::propertyValueFormatError(asyncResp->res, newUser, "UserName");
    }
    else if (strcmp(errorMessage,
                    "xyz.openbmc_project.User.Common.Error.NoResource") == 0)
    {
        messages::createLimitReachedForResource(asyncResp->res);
    }
    else
    {
        BMCWEB_LOG_ERROR("DBUS response error {}", errorMessage);
        messages::internalError(asyncResp->res);
    }
}

inline void partialPatchResult(
    const std::shared_ptr<int>& successCount,
    const std::shared_ptr<int>& pendingCount,
    const std::shared_ptr<int>& totalCount,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    --(*pendingCount);
    if (*pendingCount == 0)
    {
        if (*successCount == 0)
        {
            // All properties are invalid.
            asyncResp->res.result(boost::beast::http::status::bad_request);
        }
        else if (*successCount < *totalCount)
        {
            // Partial patch success.
            asyncResp->res.result(boost::beast::http::status::ok);
        }
    }
}

inline void parseLDAPConfigData(nlohmann::json& jsonResponse,
                                const LDAPConfigData& confData,
                                const std::string& ldapType)
{
    nlohmann::json::object_t ldap;
    ldap["ServiceEnabled"] = confData.serviceEnabled;
    nlohmann::json::array_t serviceAddresses;
    serviceAddresses.emplace_back(confData.uri);
    ldap["ServiceAddresses"] = std::move(serviceAddresses);

    nlohmann::json::object_t authentication;
    authentication["AuthenticationType"] =
        account_service::AuthenticationTypes::UsernameAndPassword;
    authentication["Username"] = confData.bindDN;
    authentication["Password"] = nullptr;
    ldap["Authentication"] = std::move(authentication);

    nlohmann::json::object_t ldapService;
    nlohmann::json::object_t searchSettings;
    nlohmann::json::array_t baseDistinguishedNames;
    baseDistinguishedNames.emplace_back(confData.baseDN);

    searchSettings["BaseDistinguishedNames"] =
        std::move(baseDistinguishedNames);
    searchSettings["UsernameAttribute"] = confData.userNameAttribute;
    searchSettings["GroupsAttribute"] = confData.groupAttribute;
    ldapService["SearchSettings"] = std::move(searchSettings);
    ldap["LDAPService"] = std::move(ldapService);

    nlohmann::json::array_t roleMapArray;
    for (const auto& obj : confData.groupRoleList)
    {
        BMCWEB_LOG_DEBUG("Pushing the data groupName={}", obj.second.groupName);

        nlohmann::json::object_t remoteGroup;
        remoteGroup["RemoteGroup"] = obj.second.groupName;
        remoteGroup["LocalRole"] = getRoleIdFromPrivilege(obj.second.privilege);
        roleMapArray.emplace_back(std::move(remoteGroup));
    }

    ldap["RemoteRoleMapping"] = std::move(roleMapArray);

    jsonResponse[ldapType].update(ldap);
}

/**
 *  @brief validates given JSON input and then calls appropriate method to
 * create, to delete or to set Rolemapping object based on the given input.
 *
 */
inline void handleRoleMapPatch(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::vector<std::pair<std::string, LDAPRoleMapData>>& roleMapObjData,
    const std::string& serverType,
    std::vector<std::variant<nlohmann::json::object_t, std::nullptr_t>>& input,
    const std::shared_ptr<int>& successCount,
    const std::shared_ptr<int>& pendingCount,
    const std::shared_ptr<int>& totalCount)
{
    for (size_t i = 0; i < input.size(); ++i)
    {
        for (size_t j = i + 1; j < input.size(); ++j)
        {
            if (input[i].index() == 0 && input[j].index() == 0)
            {
                // !obj.empty() --> skip comparison between empty objects
                if (!std::get<nlohmann::json::object_t>(input[i]).empty() &&
                    std::get<nlohmann::json::object_t>(input[i]) ==
                    std::get<nlohmann::json::object_t>(input[j]))
                {
                    messages::propertyValueConflict(asyncResp->res,
                                                    "RemoteRoleMapping",
                                                    "RemoteGroupRemoteGroup");
                    partialPatchResult(successCount, pendingCount, totalCount, asyncResp);
                    return;
                }
            }
        }
    }
    for (size_t index = 0; index < input.size(); index++)
    {
        std::variant<nlohmann::json::object_t, std::nullptr_t>& thisJson =
            input[index];
        nlohmann::json::object_t* obj =
            std::get_if<nlohmann::json::object_t>(&thisJson);
        if (obj == nullptr)
        {
            // delete the existing object
            if (index < roleMapObjData.size())
            {
                if (input.size() != roleMapObjData.size())
                {
                    messages::propertyValueConflict(
                        asyncResp->res, "RemoteRoleMapping",
                        "RemoteGroup");
                    partialPatchResult(successCount, pendingCount, totalCount, asyncResp);
                    return;
                }
                crow::connections::systemBus->async_method_call(
                    [asyncResp, roleMapObjData, serverType,
                     index, successCount,
                     pendingCount, totalCount](const boost::system::error_code& ec) {
                        if (ec)
                        {
                            BMCWEB_LOG_ERROR("DBUS response error: {}", ec);
                            messages::propertyValueFormatError(
                                asyncResp->res, "Missing", "Invalid");

                            partialPatchResult(successCount, pendingCount, totalCount, asyncResp);
                            return;
                        }
                        asyncResp->res
                            .jsonValue[serverType]["RemoteRoleMapping"][index] =
                            nullptr;
                    },
                    ldapDbusService, roleMapObjData[index].first,
                    "xyz.openbmc_project.Object.Delete", "Delete");
            }
            else
            {
                BMCWEB_LOG_ERROR("Can't delete the object");
                messages::propertyValueTypeError(
                    asyncResp->res, "null",
                    "RemoteRoleMapping/" + std::to_string(index));
                partialPatchResult(successCount, pendingCount, totalCount, asyncResp);
                return;
            }
        }
        else if (obj->empty())
        {
            // Don't do anything for the empty objects,parse next json
            // eg {"RemoteRoleMapping",[{}]}
        }
        else
        {
            // update/create the object
            std::optional<std::string> remoteGroup;
            std::optional<std::string> localRole;

            if (!json_util::readJsonObject(     //
                    *obj, asyncResp->res,       //
                    "RemoteGroup", remoteGroup, //
                    "LocalRole", localRole      //
                    ))
            {
                continue;
            }

            // Update existing RoleMapping Object
            if (index < roleMapObjData.size())
            {
                BMCWEB_LOG_DEBUG("Update Role Map Object");
                bool allDuplicate = false;
                // Check for duplicate RemoteGroup in roleMapObjData
                for (const auto& [path, data] : roleMapObjData)
                {
                    if (remoteGroup && *remoteGroup == data.groupName)
                    {
                        std::string currentLocalRole = getRoleIdFromPrivilege(data.privilege);
                        if (localRole && *localRole == currentLocalRole)
                        {
                            BMCWEB_LOG_DEBUG("Duplicate RemoteGroup: {} found",
                                         *remoteGroup);
                            allDuplicate = true;
                        }
                        else
                        {
                            allDuplicate = false;
                        }
                    }
                }
                if (allDuplicate)
                {
                    continue;
                }

                // If "RemoteGroup" info is provided
                if (remoteGroup)
                {
                    sdbusplus::asio::setProperty(
                        *crow::connections::systemBus, ldapDbusService,
                        roleMapObjData[index].first,
                        "xyz.openbmc_project.User.PrivilegeMapperEntry",
                        "GroupName", *remoteGroup,
                        [asyncResp, roleMapObjData, serverType, index,
                         remoteGroup, successCount,
                         pendingCount, totalCount](const boost::system::error_code& ec,
                                      const sdbusplus::message_t& msg) {
                            if (ec)
                            {
                                const sd_bus_error* dbusError = msg.get_error();
                                if ((dbusError != nullptr) &&
                                    (dbusError->name ==
                                     std::string_view(
                                         "xyz.openbmc_project.Common.Error.InvalidArgument")))
                                {
                                    BMCWEB_LOG_WARNING(
                                        "DBUS response error: {}", ec);
                                    messages::propertyValueIncorrect(
                                        asyncResp->res, "RemoteGroup",
                                        *remoteGroup);
                                    partialPatchResult(successCount, pendingCount, totalCount, asyncResp);
                                    return;
                                }
                                messages::internalError(asyncResp->res);
                                partialPatchResult(successCount, pendingCount, totalCount, asyncResp);
                                return;
                            }
                            asyncResp->res
                                .jsonValue[serverType]["RemoteRoleMapping"]
                                          [index]["RemoteGroup"] = *remoteGroup;
                        });
                }

                // If "LocalRole" info is provided
                if (localRole)
                {
                    std::string priv = getPrivilegeFromRoleId(*localRole);
                    if (priv.empty())
                    {
                        messages::propertyValueNotInList(
                            asyncResp->res, *localRole,
                            std::format("RemoteRoleMapping/{}/LocalRole",
                                        index));
                        partialPatchResult(successCount, pendingCount, totalCount, asyncResp);
                        return;
                    }
                    sdbusplus::asio::setProperty(
                        *crow::connections::systemBus, ldapDbusService,
                        roleMapObjData[index].first,
                        "xyz.openbmc_project.User.PrivilegeMapperEntry",
                        "Privilege", priv,
                        [asyncResp, roleMapObjData, serverType, index,
                         localRole, successCount,
                         pendingCount, totalCount](const boost::system::error_code& ec,
                                    const sdbusplus::message_t& msg) {
                            if (ec)
                            {
                                const sd_bus_error* dbusError = msg.get_error();
                                if ((dbusError != nullptr) &&
                                    (dbusError->name ==
                                     std::string_view(
                                         "xyz.openbmc_project.Common.Error.InvalidArgument")))
                                {
                                    BMCWEB_LOG_WARNING(
                                        "DBUS response error: {}", ec);
                                    messages::propertyValueIncorrect(
                                        asyncResp->res, "LocalRole",
                                        *localRole);
                                    partialPatchResult(successCount, pendingCount, totalCount, asyncResp);
                                    return;
                                }
                                messages::internalError(asyncResp->res);
                                partialPatchResult(successCount, pendingCount, totalCount, asyncResp);
                                return;
                            }
                            asyncResp->res
                                .jsonValue[serverType]["RemoteRoleMapping"]
                                          [index]["LocalRole"] = *localRole;
                        });
                }
            }
            // Create a new RoleMapping Object.
            else
            {
                BMCWEB_LOG_DEBUG(
                    "setRoleMappingProperties: Creating new Object");
                std::string pathString =
                    "RemoteRoleMapping/" + std::to_string(index);

                if (!localRole)
                {
                    messages::propertyMissing(asyncResp->res,
                                              pathString + "/LocalRole");
                    continue;
                }
                if (!remoteGroup)
                {
                    messages::propertyMissing(asyncResp->res,
                                              pathString + "/RemoteGroup");
                    continue;
                }

                std::string dbusObjectPath;
                if (serverType == "ActiveDirectory")
                {
                    dbusObjectPath = adConfigObject;
                }
                else if (serverType == "LDAP")
                {
                    dbusObjectPath = ldapConfigObjectName;
                }

                BMCWEB_LOG_DEBUG("Remote Group={},LocalRole={}", *remoteGroup,
                                 *localRole);

                crow::connections::systemBus->async_method_call(
                    [asyncResp, serverType, localRole,
                     remoteGroup, successCount,
                     pendingCount, totalCount](const boost::system::error_code& ec) {
                        if (ec)
                        {
                            BMCWEB_LOG_ERROR("DBUS response error: {}", ec);
                            // messages::internalError(asyncResp->res);
                            if (localRole.has_value())
                            {
                                messages::propertyValueIncorrect(
                                    asyncResp->res, "LocalRole", *localRole);
                            }
                            if (remoteGroup.has_value())
                            {
                                messages::propertyValueIncorrect(asyncResp->res,
                                                                 "RemoteGroup",
                                                                 *remoteGroup);
                            }
                            partialPatchResult(successCount, pendingCount, totalCount, asyncResp);
                            return;
                        }
                        else
                        {
                            nlohmann::json& remoteRoleJson =
                                asyncResp->res
                                    .jsonValue[serverType]["RemoteRoleMapping"];
                            nlohmann::json::object_t roleMapEntry;
                            roleMapEntry["LocalRole"] = *localRole;
                            roleMapEntry["RemoteGroup"] = *remoteGroup;
                            remoteRoleJson.emplace_back(std::move(roleMapEntry));
                            partialPatchResult(successCount, pendingCount, totalCount, asyncResp);
                        }
                    },
                    ldapDbusService, dbusObjectPath, ldapPrivMapperInterface,
                    "Create", *remoteGroup,
                    getPrivilegeFromRoleId(std::move(*localRole)));
            }
        }
    }

    ++(*successCount);
    partialPatchResult(successCount, pendingCount, totalCount, asyncResp);
}

/**
 * Function that retrieves all properties for LDAP config object
 * into JSON
 */
template <typename CallbackFunc>
inline void getLDAPConfigData(const std::string& ldapType,
                              CallbackFunc&& callback)
{
    constexpr std::array<std::string_view, 2> interfaces = {
        ldapEnableInterface, ldapConfigInterface};

    dbus::utility::getDbusObject(
        ldapConfigObjectName, interfaces,
        [callback = std::forward<CallbackFunc>(callback),
         ldapType](const boost::system::error_code& ec,
                   const dbus::utility::MapperGetObject& resp) mutable {
            if (ec || resp.empty())
            {
                BMCWEB_LOG_WARNING(
                    "DBUS response error during getting of service name: {}",
                    ec);
                LDAPConfigData empty{};
                callback(false, empty, ldapType);
                return;
            }
            std::string service = resp.begin()->first;
            sdbusplus::message::object_path path(ldapRootObject);
            dbus::utility::getManagedObjects(
                service, path,
                [callback, ldapType](const boost::system::error_code& ec2,
                                     const dbus::utility::ManagedObjectType&
                                         ldapObjects) mutable {
                    LDAPConfigData confData{};
                    if (ec2)
                    {
                        callback(false, confData, ldapType);
                        BMCWEB_LOG_WARNING("D-Bus responses error: {}", ec2);
                        return;
                    }

                    std::string ldapDbusType;
                    std::string searchString;

                    if (ldapType == "LDAP")
                    {
                        ldapDbusType =
                            "xyz.openbmc_project.User.Ldap.Config.Type.OpenLdap";
                        searchString = "openldap";
                    }
                    else if (ldapType == "ActiveDirectory")
                    {
                        ldapDbusType =
                            "xyz.openbmc_project.User.Ldap.Config.Type.ActiveDirectory";
                        searchString = "active_directory";
                    }
                    else
                    {
                        BMCWEB_LOG_ERROR(
                            "Can't get the DbusType for the given type={}",
                            ldapType);
                        callback(false, confData, ldapType);
                        return;
                    }

                    std::string ldapEnableInterfaceStr = ldapEnableInterface;
                    std::string ldapConfigInterfaceStr = ldapConfigInterface;

                    for (auto it = ldapObjects.rbegin(); it != ldapObjects.rend(); ++it)
                    {
                        const auto& object = *it;
                        // let's find the object whose ldap type is equal to the
                        // given type
                        if (object.first.str.find(searchString) ==
                            std::string::npos)
                        {
                            continue;
                        }

                        for (const auto& interface : object.second)
                        {
                            if (interface.first == ldapEnableInterfaceStr)
                            {
                                // rest of the properties are string.
                                for (const auto& property : interface.second)
                                {
                                    if (property.first == "Enabled")
                                    {
                                        const bool* value =
                                            std::get_if<bool>(&property.second);
                                        if (value == nullptr)
                                        {
                                            continue;
                                        }
                                        confData.serviceEnabled = *value;
                                        break;
                                    }
                                }
                            }
                            else if (interface.first == ldapConfigInterfaceStr)
                            {
                                for (const auto& property : interface.second)
                                {
                                    const std::string* strValue =
                                        std::get_if<std::string>(
                                            &property.second);
                                    if (strValue == nullptr)
                                    {
                                        continue;
                                    }
                                    if (property.first == "LDAPServerURI")
                                    {
                                        confData.uri = *strValue;
                                    }
                                    else if (property.first == "LDAPBindDN")
                                    {
                                        confData.bindDN = *strValue;
                                    }
                                    else if (property.first == "LDAPBaseDN")
                                    {
                                        confData.baseDN = *strValue;
                                    }
                                    else if (property.first ==
                                             "LDAPSearchScope")
                                    {
                                        confData.searchScope = *strValue;
                                    }
                                    else if (property.first ==
                                             "GroupNameAttribute")
                                    {
                                        confData.groupAttribute = *strValue;
                                    }
                                    else if (property.first ==
                                             "UserNameAttribute")
                                    {
                                        confData.userNameAttribute = *strValue;
                                    }
                                    else if (property.first == "LDAPType")
                                    {
                                        confData.serverType = *strValue;
                                    }
                                }
                            }
                            else if (
                                interface.first ==
                                "xyz.openbmc_project.User.PrivilegeMapperEntry")
                            {
                                LDAPRoleMapData roleMapData{};
                                for (const auto& property : interface.second)
                                {
                                    const std::string* strValue =
                                        std::get_if<std::string>(
                                            &property.second);

                                    if (strValue == nullptr)
                                    {
                                        continue;
                                    }

                                    if (property.first == "GroupName")
                                    {
                                        roleMapData.groupName = *strValue;
                                    }
                                    else if (property.first == "Privilege")
                                    {
                                        roleMapData.privilege = *strValue;
                                    }
                                }

                                confData.groupRoleList.emplace_back(
                                    object.first.str, roleMapData);
                            }
                        }
                    }
                    callback(true, confData, ldapType);
                });
        });
}

inline std::string modifiedDateTime(const std::string& filepath)
{
    // Check if the file exists before accessing its timestamp
    if (!std::filesystem::exists(filepath))
    {
        std::cerr << "Error: File does not exist: " << filepath << std::endl;
        return "FileNotFound";
    }

    try
    {
        std::filesystem::file_time_type ftime = std::filesystem::last_write_time(filepath);
        auto sys_time = std::chrono::file_clock::to_sys(ftime);
        auto time_t = std::chrono::system_clock::to_time_t(sys_time);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(sys_time.time_since_epoch()) % 1000;

        std::tm* tm = std::localtime(&time_t);
        std::ostringstream oss;
        oss << std::put_time(tm, "%Y-%m-%dT%H:%M:%S");
        oss << '.' << std::setw(3) << std::setfill('0') << ms.count();

        // Calculate and format timezone offset
        std::time_t gmt_time = std::mktime(tm);
        int offset = static_cast<int>(std::difftime(time_t, gmt_time));
        int hours = offset / 3600;
        int minutes = (offset % 3600) / 60;
        oss << (hours >= 0 ? '+' : '-') << std::setw(2) << std::setfill('0') << std::abs(hours)
            << ':' << std::setw(2) << std::setfill('0') << std::abs(minutes);

        std::string str = oss.str();
        return str;
    }
    catch (const std::filesystem::filesystem_error& e)
    {
        return "Error";
    }
}


inline bool ensureOpensslKeyPresentAndValid(const std::string& filepath)
{

    bool certValid = false;

    // Check if the file exists
    if (!std::filesystem::exists(filepath))
    {
        std::cerr << "Error: File does not exist: " << filepath << std::endl;
        return false;
    }

    FILE* file = fopen(filepath.c_str(), "r");
    if (file != nullptr)
    {
        certValid = true;
        std::cerr << "File is accessible and valid." << std::endl;
        fclose(file);  // Don't forget to close the file after checking
    }
    else
    {
        std::cerr << "Error opening file: " << filepath << std::endl;
    }

    return certValid;
}


inline void getRADIUSConfigData(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    bool isCAFileUsed = false;
    bool isPrivateKeyUsed = false;
    bool isClientCertUsed = false;

    dbus::utility::getAllProperties(
        radisuDBusService, radiusConfigObjectPath, radiusConfigInterface,
        [asyncResp, &isCAFileUsed, &isPrivateKeyUsed, &isClientCertUsed]
        (const boost::system::error_code& ec,
         const dbus::utility::DBusPropertiesMap& propertiesList)
        {
            if (ec)
            {
                BMCWEB_LOG_ERROR("getRADIUSConfigData: Failed to get properties from DBus. Error: {}", ec.message());
                messages::internalError(asyncResp->res);
                return;
            }

            bool enable = true;
            const std::string* host = nullptr;
            const int32_t* port = nullptr;
            bool enableEapTLS = false;

            const bool success = sdbusplus::unpackPropertiesNoThrow(
                dbus_utils::UnpackErrorPrinter(), propertiesList,
                "Enable", enable,
                "IP", host,
                "PortNumber", port,
                "EnableEapTLS", enableEapTLS);

            if (!success)
            {
                BMCWEB_LOG_ERROR("getRADIUSConfigData: Failed to unpack DBus properties");
                messages::internalError(asyncResp->res);
                return;
            }

            asyncResp->res.jsonValue["ServiceEnabled"] = enable;
            asyncResp->res.jsonValue["Oem"]["Ami"]["RADIUS"]["EnableEapTLS"] = enableEapTLS;

            if (host != nullptr)
            {
                asyncResp->res.jsonValue["Oem"]["Ami"]["RADIUS"]["ServiceAddress"] = *host;
            }

            asyncResp->res.jsonValue["Oem"]["Ami"]["RADIUS"]["Secret"] = nullptr;

            if (port != nullptr)
            {
                asyncResp->res.jsonValue["Oem"]["Ami"]["RADIUS"]["ServicePort"] = *port;
            }

            // File checks
            isCAFileUsed = ensureOpensslKeyPresentAndValid(caCertFile);
            isClientCertUsed = ensureOpensslKeyPresentAndValid(clientCertFile);
            isPrivateKeyUsed = ensureOpensslKeyPresentAndValid(privateKeyFile);

            asyncResp->res.jsonValue["Oem"]["Ami"]["RADIUS"]["isCAFilePresent"] = isCAFileUsed;
            asyncResp->res.jsonValue["Oem"]["Ami"]["RADIUS"]["isClientCertPresent"] = isClientCertUsed;
            asyncResp->res.jsonValue["Oem"]["Ami"]["RADIUS"]["isPrivateKeyPresent"] = isPrivateKeyUsed;

            // Modified dates
            std::string caModifiedDate = modifiedDateTime(caCertFile);
            std::string clientModifiedDate = modifiedDateTime(clientCertFile);
            std::string keyModifiedDate = modifiedDateTime(privateKeyFile);

            if (caModifiedDate != "FileNotFound" && caModifiedDate != "Error")
            {
                asyncResp->res.jsonValue["Oem"]["Ami"]["RADIUS"]["CAFileModifiedDate"] = caModifiedDate;
            }

            if (clientModifiedDate != "FileNotFound" && clientModifiedDate != "Error")
            {
                asyncResp->res.jsonValue["Oem"]["Ami"]["RADIUS"]["ClientFileModifiedDate"] = clientModifiedDate;
            }

            if (keyModifiedDate != "FileNotFound" && keyModifiedDate != "Error")
            {
                asyncResp->res.jsonValue["Oem"]["Ami"]["RADIUS"]["PrivateKeyFileModifiedDate"] = keyModifiedDate;
            }

        });
}


inline void getRADIUSRoleMap(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    dbus::utility::getAllProperties(
        radisuDBusService, radiusRoleMapObjectPath, radiusRoleMapInterface,
        [asyncResp](const boost::system::error_code& ec,
                    const dbus::utility::DBusPropertiesMap& propertiesList) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("getRADIUSRoleMap: Can't get "
                                 "radiusRoleMapInterface ");
                messages::internalError(asyncResp->res);
                return;
            }

            BMCWEB_LOG_DEBUG("Got {}properties for getRADIUSRoleMap",
                             propertiesList.size());

            const std::string* GroupName1 = nullptr;
            const std::string* GroupName2 = nullptr;
            const std::string* GroupName3 = nullptr;
            const std::string* Privilege1 = nullptr;
            const std::string* Privilege2 = nullptr;
            const std::string* Privilege3 = nullptr;

            const bool success = sdbusplus::unpackPropertiesNoThrow(
                dbus_utils::UnpackErrorPrinter(), propertiesList, "GroupName1",
                GroupName1, "GroupName2", GroupName2, "GroupName3", GroupName3,
                "Privilege1", Privilege1, "Privilege2", Privilege2,
                "Privilege3", Privilege3);

            if (!success)
            {
                messages::internalError(asyncResp->res);
                return;
            }

            if (GroupName1 != nullptr)
            {
                asyncResp->res.jsonValue["Oem"]["Ami"]["RADIUS"]["GroupName1"] =
                    *GroupName1;
            }
            if (GroupName2 != nullptr)
            {
                asyncResp->res.jsonValue["Oem"]["Ami"]["RADIUS"]["GroupName2"] =
                    *GroupName2;
            }
            if (GroupName3 != nullptr)
            {
                asyncResp->res.jsonValue["Oem"]["Ami"]["RADIUS"]["GroupName3"] =
                    *GroupName3;
            }
            if (Privilege1 != nullptr)
            {
                std::string role = getRoleIdFromPrivilege(*Privilege1);

                asyncResp->res.jsonValue["Oem"]["Ami"]["RADIUS"]["Privilege1"] =
                    role;
            }
            if (Privilege2 != nullptr)
            {
                std::string role = getRoleIdFromPrivilege(*Privilege2);
                asyncResp->res.jsonValue["Oem"]["Ami"]["RADIUS"]["Privilege2"] =
                    role;
            }
            if (Privilege3 != nullptr)
            {
                std::string role = getRoleIdFromPrivilege(*Privilege3);
                asyncResp->res.jsonValue["Oem"]["Ami"]["RADIUS"]["Privilege3"] =
                    role;
            }
        });
}

inline void setSNMPEnableDisable(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const bool& propertyValue, const std::string& userName)
{
    sdbusplus::message::object_path tempObjPath(rootUserDbusPath);
    tempObjPath /= userName;
    const std::string userPath(tempObjPath);

    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, "xyz.openbmc_project.User.Manager",
        userPath, "xyz.openbmc_project.User.Attributes", "SNMPAccessEnableStatus",
        propertyValue,
        [asyncResp, userName](const boost::system::error_code& ec1) {
            if (ec1)
            {
                BMCWEB_LOG_ERROR("Failed to set SNMPAccessEnableStatus for {}: {}", userName, ec1.message());
                messages::internalError(asyncResp->res);
                return;
            }
        });
}

inline void handleSNMPUserPatch(
    const std::shared_ptr<bmcweb::AsyncResp> asyncResp, std::string snmpObject,
    std::string propertyName, std::string propertyValue)
{
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, "xyz.openbmc_project.Snmp.Conf", snmpObject,
        "xyz.openbmc_project.Snmp.UserManager", propertyName, propertyValue,
        [asyncResp](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-Bus responses error: {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }
        });
}

inline void handleRadiusConfigRolemMapPatch(
    const std::shared_ptr<bmcweb::AsyncResp> aResp, std::string radiusObject,
    std::string radiusInterface, std::string propertyName,
    std::string propertyValue)
{
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, radisuDBusService, radiusObject,
        radiusInterface, propertyName, propertyValue,
        [aResp](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-Bus responses error: {}", ec);
                messages::internalError(aResp->res);
                return;
            }
            messages::success(aResp->res);
        });
}

inline void setRadiusEnable(const std::shared_ptr<bmcweb::AsyncResp>& aResp,
                            std::string propertyName, bool& propertyValue)
{
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, radisuDBusService,
        radiusConfigObjectPath, radiusConfigInterface, propertyName, propertyValue,
        [aResp](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-Bus responses error: {}", ec);
                messages::internalError(aResp->res);
                return;
            }
            messages::success(aResp->res);
        });
}

/**
 * @brief updates the LDAP server address and updates the
          json response with the new value.
 * @param serviceAddressList address to be updated.
 * @param asyncResp pointer to the JSON response
 * @param ldapServerElementName Type of LDAP
 server(openLDAP/ActiveDirectory)
 */

inline void handleServiceAddressPatch(
    const std::vector<std::string>& serviceAddressList,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& ldapServerElementName,
    const std::string& ldapConfigObject,
    const std::shared_ptr<int>& successCount,
    const std::shared_ptr<int>& pendingCount,
    const std::shared_ptr<int>& totalCount)
{
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, ldapDbusService, ldapConfigObject,
        ldapConfigInterface, "LDAPServerURI", serviceAddressList.front(),
        [asyncResp, ldapServerElementName, serviceAddressList,
         successCount, pendingCount, totalCount](
            const boost::system::error_code& ec, sdbusplus::message_t& msg) {
            if (ec)
            {
                const sd_bus_error* dbusError = msg.get_error();
                if ((dbusError != nullptr) &&
                    (dbusError->name ==
                     std::string_view(
                         "xyz.openbmc_project.Common.Error.InvalidArgument")))
                {
                    BMCWEB_LOG_WARNING(
                        "Error Occurred in updating the service address");
                    messages::propertyValueIncorrect(
                        asyncResp->res, "ServiceAddresses",
                        serviceAddressList.front());
                }
                else
                {
                    messages::internalError(asyncResp->res);
                }
            }
            else
            {
                std::vector<std::string> modifiedserviceAddressList = {
                    serviceAddressList.front()};
                asyncResp->res
                    .jsonValue[ldapServerElementName]["ServiceAddresses"] =
                    modifiedserviceAddressList;
                if ((serviceAddressList).size() > 1)
                {
                    messages::propertyValueModified(asyncResp->res,
                                                    "ServiceAddresses",
                                                    serviceAddressList.front());
                }
                else
                {
                    BMCWEB_LOG_DEBUG("Updated the service address");
                    ++(*successCount);
                }
            }

            partialPatchResult(successCount, pendingCount, totalCount, asyncResp);
        });
}
/**
 * @brief updates the LDAP Bind DN and updates the
          json response with the new value.
 * @param username name of the user which needs to be updated.
 * @param asyncResp pointer to the JSON response
 * @param ldapServerElementName Type of LDAP
 server(openLDAP/ActiveDirectory)
 */

inline void handleUserNamePatch(
    const std::string& username,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& ldapServerElementName,
    const std::string& ldapConfigObject,
    const std::shared_ptr<int>& successCount,
    const std::shared_ptr<int>& pendingCount,
    const std::shared_ptr<int>& totalCount)
{
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, ldapDbusService, ldapConfigObject,
        ldapConfigInterface, "LDAPBindDN", username,
        [asyncResp, username, ldapServerElementName,
         successCount, pendingCount, totalCount](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("Error occurred in updating the username");
                messages::internalError(asyncResp->res);
            }
            else
            {
                asyncResp->res.jsonValue[ldapServerElementName]["Authentication"]
                                        ["Username"] = username;
                BMCWEB_LOG_DEBUG("Updated the username");
                ++(*successCount);
            }

            partialPatchResult(successCount, pendingCount, totalCount, asyncResp);
        });
    // setDbusProperty(asyncResp,
    //               ldapServerElementName + "/Authentication/Username",
    //             ldapDbusService, ldapConfigObject, ldapConfigInterface,
    //           "LDAPBindDN", username);
}

/**
 * @brief updates the LDAP password
 * @param password : ldap password which needs to be updated.
 * @param asyncResp pointer to the JSON response
 * @param ldapServerElementName Type of LDAP
 *        server(openLDAP/ActiveDirectory)
 */

inline void handlePasswordPatch(
    const std::string& password,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& ldapServerElementName,
    const std::string& ldapConfigObject,
    const std::shared_ptr<int>& successCount,
    const std::shared_ptr<int>& pendingCount,
    const std::shared_ptr<int>& totalCount)
{
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, ldapDbusService, ldapConfigObject,
        ldapConfigInterface, "LDAPBindDNPassword", password,
        [asyncResp, password, ldapServerElementName,
         successCount, pendingCount, totalCount](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("Error occurred in updating the password");
                messages::internalError(asyncResp->res);
            }
            else
            {
                asyncResp->res.jsonValue[ldapServerElementName]["Authentication"]
                                        ["Password"] = "";
                BMCWEB_LOG_DEBUG("Updated the password");
                ++(*successCount);
            }

            partialPatchResult(successCount, pendingCount, totalCount, asyncResp);
        });
}

/**
 * @brief updates the LDAP BaseDN and updates the
          json response with the new value.
 * @param baseDNList baseDN list which needs to be updated.
 * @param asyncResp pointer to the JSON response
 * @param ldapServerElementName Type of LDAP
 server(openLDAP/ActiveDirectory)
 */

inline void handleBaseDNPatch(
    const std::vector<std::string>& baseDNList,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& ldapServerElementName,
    const std::string& ldapConfigObject,
    const std::shared_ptr<int>& successCount,
    const std::shared_ptr<int>& pendingCount,
    const std::shared_ptr<int>& totalCount)
{
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, ldapDbusService, ldapConfigObject,
        ldapConfigInterface, "LDAPBaseDN", baseDNList.front(),
        [asyncResp, baseDNList, ldapServerElementName,
         successCount, pendingCount, totalCount](const boost::system::error_code& ec,
                                const sdbusplus::message_t& msg) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("Error Occurred in Updating the base DN");
                const sd_bus_error* dbusError = msg.get_error();
                if ((dbusError != nullptr) &&
                    (dbusError->name ==
                     std::string_view(
                         "xyz.openbmc_project.Common.Error.InvalidArgument")))
                {
                    messages::propertyValueIncorrect(asyncResp->res,
                                                     "BaseDistinguishedNames",
                                                     baseDNList.front());
                }
                else
                {
                    messages::internalError(asyncResp->res);
                }
            }
            else
            {
                auto& serverTypeJson =
                    asyncResp->res.jsonValue[ldapServerElementName];
                auto& searchSettingsJson =
                    serverTypeJson["LDAPService"]["SearchSettings"];
                std::vector<std::string> modifiedBaseDNList = {baseDNList.front()};
                searchSettingsJson["BaseDistinguishedNames"] = modifiedBaseDNList;
                if (baseDNList.size() > 1)
                {
                    messages::propertyValueModified(asyncResp->res,
                                                    "BaseDistinguishedNames",
                                                    baseDNList.front());
                }
                else
                {
                    BMCWEB_LOG_DEBUG("Updated the base DN");
                    ++(*successCount);
                }
            }

            partialPatchResult(successCount, pendingCount, totalCount, asyncResp);
        });
}
/**
 * @brief updates the LDAP user name attribute and updates the
          json response with the new value.
 * @param userNameAttribute attribute to be updated.
 * @param asyncResp pointer to the JSON response
 * @param ldapServerElementName Type of LDAP
 server(openLDAP/ActiveDirectory)
 */

inline void handleUserNameAttrPatch(
    const std::string& userNameAttribute,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& ldapServerElementName,
    const std::string& ldapConfigObject,
    const std::shared_ptr<int>& successCount,
    const std::shared_ptr<int>& pendingCount,
    const std::shared_ptr<int>& totalCount)
{
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, ldapDbusService, ldapConfigObject,
        ldapConfigInterface, "UserNameAttribute", userNameAttribute,
        [asyncResp, userNameAttribute, ldapServerElementName,
         successCount, pendingCount, totalCount](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("Error Occurred in Updating the "
                                 "username attribute");
                messages::internalError(asyncResp->res);
            }
            else
            {
                auto& serverTypeJson =
                    asyncResp->res.jsonValue[ldapServerElementName];
                auto& searchSettingsJson =
                    serverTypeJson["LDAPService"]["SearchSettings"];
                searchSettingsJson["UsernameAttribute"] = userNameAttribute;
                BMCWEB_LOG_DEBUG("Updated the user name attr.");
                ++(*successCount);
            }

            partialPatchResult(successCount, pendingCount, totalCount, asyncResp);
        });
}
/**
 * @brief updates the LDAP group attribute and updates the
          json response with the new value.
 * @param groupsAttribute attribute to be updated.
 * @param asyncResp pointer to the JSON response
 * @param ldapServerElementName Type of LDAP
 server(openLDAP/ActiveDirectory)
 */

inline void handleGroupNameAttrPatch(
    const std::string& groupsAttribute,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& ldapServerElementName,
    const std::string& ldapConfigObject,
    const std::shared_ptr<int>& successCount,
    const std::shared_ptr<int>& pendingCount,
    const std::shared_ptr<int>& totalCount)
{
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, ldapDbusService, ldapConfigObject,
        ldapConfigInterface, "GroupNameAttribute", groupsAttribute,
        [asyncResp, groupsAttribute, ldapServerElementName,
         successCount, pendingCount, totalCount](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("Error Occurred in Updating the "
                                 "groupname attribute");
                messages::internalError(asyncResp->res);
            }
            else
            {
                auto& serverTypeJson =
                    asyncResp->res.jsonValue[ldapServerElementName];
                auto& searchSettingsJson =
                    serverTypeJson["LDAPService"]["SearchSettings"];
                searchSettingsJson["GroupsAttribute"] = groupsAttribute;
                BMCWEB_LOG_DEBUG("Updated the groupname attr");
                ++(*successCount);
            }

            partialPatchResult(successCount, pendingCount, totalCount, asyncResp);
        });
}
/**
 * @brief updates the LDAP service enable and updates the
          json response with the new value.
 * @param input JSON data.
 * @param asyncResp pointer to the JSON response
 * @param ldapServerElementName Type of LDAP
 server(openLDAP/ActiveDirectory)
 */

inline void handleServiceEnablePatch(
    bool serviceEnabled, const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& ldapServerElementName,
    const std::string& ldapConfigObject,
    const std::shared_ptr<int>& successCount,
    const std::shared_ptr<int>& pendingCount,
    const std::shared_ptr<int>& totalCount)
{
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, ldapDbusService, ldapConfigObject,
        ldapEnableInterface, "Enabled", serviceEnabled,
        [asyncResp, serviceEnabled,
         ldapServerElementName,
         successCount, pendingCount, totalCount](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG(
                    "Error Occurred in Updating the service enable");
                messages::conflictOnPropertyPatch(asyncResp->res,
                                                  "ServiceEnabled", "true");
            }
            else
            {
                 asyncResp->res.jsonValue[ldapServerElementName]["ServiceEnabled"] =
                     serviceEnabled;
                BMCWEB_LOG_DEBUG("Updated Service enable = {}", serviceEnabled);
                ++(*successCount);
            }

            partialPatchResult(successCount, pendingCount, totalCount, asyncResp);
        });
}

struct AuthMethods
{
    std::optional<bool> basicAuth;
    std::optional<bool> cookie;
    std::optional<bool> sessionToken;
    std::optional<bool> xToken;
    std::optional<bool> tls;
};

inline void handleAuthMethodsPatch(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const AuthMethods& auth)
{
    persistent_data::AuthConfigMethods& authMethodsConfig =
        persistent_data::SessionStore::getInstance().getAuthMethodsConfig();

    if (auth.basicAuth)
    {
        if constexpr (!BMCWEB_BASIC_AUTH)
        {
            messages::actionNotSupported(
                asyncResp->res,
                "Setting BasicAuth when basic-auth feature is disabled");
            return;
        }

        authMethodsConfig.basic = *auth.basicAuth;
    }

    if (auth.cookie)
    {
        if constexpr (!BMCWEB_COOKIE_AUTH)
        {
            messages::actionNotSupported(
                asyncResp->res,
                "Setting Cookie when cookie-auth feature is disabled");
            return;
        }
        authMethodsConfig.cookie = *auth.cookie;
    }

    if (auth.sessionToken)
    {
        if constexpr (!BMCWEB_SESSION_AUTH)
        {
            messages::actionNotSupported(
                asyncResp->res,
                "Setting SessionToken when session-auth feature is disabled");
            return;
        }
        authMethodsConfig.sessionToken = *auth.sessionToken;
    }

    if (auth.xToken)
    {
        if constexpr (!BMCWEB_XTOKEN_AUTH)
        {
            messages::actionNotSupported(
                asyncResp->res,
                "Setting XToken when xtoken-auth feature is disabled");
            return;
        }
        authMethodsConfig.xtoken = *auth.xToken;
    }

    if (auth.tls)
    {
        if constexpr (!BMCWEB_MUTUAL_TLS_AUTH)
        {
            messages::actionNotSupported(
                asyncResp->res,
                "Setting TLS when mutual-tls-auth feature is disabled");
            return;
        }
        authMethodsConfig.tls = *auth.tls;
    }

    if (!authMethodsConfig.basic && !authMethodsConfig.cookie &&
        !authMethodsConfig.sessionToken && !authMethodsConfig.xtoken &&
        !authMethodsConfig.tls)
    {
        // Do not allow user to disable everything
        messages::actionNotSupported(asyncResp->res,
                                     "of disabling all available methods");
        return;
    }

    persistent_data::SessionStore::getInstance().updateAuthMethodsConfig(
        authMethodsConfig);
    // Save configuration immediately
    persistent_data::getConfig().writeData();

    // messages::success(asyncResp->res);
    // asyncResp->res.result(boost::beast::http::status::no_content);
}

/**
 * @brief Get the required values from the given JSON, validates the
 *        value and create the LDAP config object.
 * @param input JSON data
 * @param asyncResp pointer to the JSON response
 * @param serverType Type of LDAP server(openLDAP/ActiveDirectory)
 */

struct LdapPatchParams
{
    std::optional<std::string> authType;
    std::optional<std::vector<std::string>> serviceAddressList;
    std::optional<bool> serviceEnabled;
    std::optional<std::vector<std::string>> baseDNList;
    std::optional<std::string> userNameAttribute;
    std::optional<std::string> groupsAttribute;
    std::optional<std::string> userName;
    std::optional<std::string> password;
    std::optional<
        std::vector<std::variant<nlohmann::json::object_t, std::nullptr_t>>>
        remoteRoleMapData;
    bool hasValue() const
    {
        return authType.has_value() || serviceAddressList.has_value() ||
               serviceEnabled.has_value() || baseDNList.has_value() ||
               userNameAttribute.has_value() || groupsAttribute.has_value() ||
               userName.has_value() || password.has_value() ||
               remoteRoleMapData.has_value();
    }
};

inline void handleLDAPPatch(LdapPatchParams&& input,
                            const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                            const std::string& serverType)
{
    std::string dbusObjectPath;
    if (serverType == "ActiveDirectory")
    {
        dbusObjectPath = adConfigObject;
    }
    else if (serverType == "LDAP")
    {
        dbusObjectPath = ldapConfigObjectName;
        if ((input.baseDNList.has_value() ||
             input.userNameAttribute.has_value() ||
             input.serviceAddressList.has_value()) &&
            (!input.userName || !input.password))
        {
            messages::propertyMissing(asyncResp->res, "Username");
	    messages::propertyMissing(asyncResp->res, "Password");
            return;
        }
    }
    else
    {
        BMCWEB_LOG_ERROR("serverType wasn't AD or LDAP but was {}????",
                         serverType);
        return;
    }

    if (input.authType && *input.authType != "UsernameAndPassword")
    {
        messages::propertyValueNotInList(asyncResp->res, *input.authType,
                                         "AuthenticationType");
        return;
    }

    if (input.serviceAddressList)
    {
        if (input.serviceAddressList->empty())
        {
            messages::propertyValueNotInList(
                asyncResp->res, *input.serviceAddressList, "ServiceAddress");
            return;
        }
    }
    if (input.baseDNList)
    {
        if (input.baseDNList->empty())
        {
            messages::propertyValueNotInList(asyncResp->res, *input.baseDNList,
                                             "BaseDistinguishedNames");
            return;
        }
    }

    // nothing to update, then return
    if (!input.userName && !input.password && !input.serviceAddressList &&
        !input.baseDNList && !input.userNameAttribute &&
        !input.groupsAttribute && !input.serviceEnabled &&
        !input.remoteRoleMapData)
    {
        return;
    }

    // Get the existing resource first then keep modifying
    // whenever any property gets updated.
    getLDAPConfigData(serverType, [asyncResp, input = std::move(input),
                                   dbusObjectPath = std::move(dbusObjectPath)](
                                      bool success,
                                      const LDAPConfigData& confData,
                                      const std::string& serverT) mutable {
        if (!success)
        {
            messages::internalError(asyncResp->res);
            return;
        }

        if (input.serviceEnabled)
        {
            if (!*input.serviceEnabled && !confData.serviceEnabled)
            {
                messages::serviceDisabled(asyncResp->res, serverT + " Service Disabled");
                asyncResp->res.result(boost::beast::http::status::bad_request);
                return;
            }
        }
        else if (!confData.serviceEnabled)
        {
            messages::serviceDisabled(asyncResp->res, serverT + " Service Disabled");
            asyncResp->res.result(boost::beast::http::status::bad_request);
            return;
        }

        auto successCount = std::make_shared<int>(0);
        auto pendingCount = std::make_shared<int>(0);
        auto totalCount = std::make_shared<int>(0);

        parseLDAPConfigData(asyncResp->res.jsonValue, confData, serverT);
        if (confData.serviceEnabled)
        {
            // Disable the service first and update the rest of
            // the properties.
            ++(*pendingCount);
            ++(*totalCount);
            handleServiceEnablePatch(false, asyncResp,
                                    serverT, dbusObjectPath,
                                    successCount, pendingCount, totalCount);
        }

        if (input.serviceAddressList)
        {
            ++(*pendingCount);
            ++(*totalCount);
            handleServiceAddressPatch(*input.serviceAddressList, asyncResp,
                                      serverT, dbusObjectPath,
                                      successCount, pendingCount, totalCount);
        }
        if (input.userName)
        {
            ++(*pendingCount);
            ++(*totalCount);
            handleUserNamePatch(*input.userName, asyncResp, serverT,
                                dbusObjectPath, successCount, pendingCount, totalCount);
        }
        if (input.password)
        {
            ++(*pendingCount);
            ++(*totalCount);
            handlePasswordPatch(*input.password, asyncResp, serverT,
                                dbusObjectPath, successCount, pendingCount, totalCount);
        }
        if (input.baseDNList)
        {
            ++(*pendingCount);
            ++(*totalCount);
            handleBaseDNPatch(*input.baseDNList, asyncResp, serverT,
                              dbusObjectPath, successCount, pendingCount, totalCount);
        }
        if (input.userNameAttribute)
        {
            ++(*pendingCount);
            ++(*totalCount);
            handleUserNameAttrPatch(*input.userNameAttribute, asyncResp,
                                    serverT, dbusObjectPath,
                                    successCount, pendingCount, totalCount);
        }
        if (input.groupsAttribute)
        {
            ++(*pendingCount);
            ++(*totalCount);
            handleGroupNameAttrPatch(*input.groupsAttribute, asyncResp, serverT,
                                     dbusObjectPath, successCount, pendingCount, totalCount);
        }
        if (input.serviceEnabled)
        {
            // if user has given the value as true then enable
            // the service. if user has given false then no-op
            // as service is already stopped.
            if (*input.serviceEnabled)
            {
                ++(*pendingCount);
                ++(*totalCount);
                handleServiceEnablePatch(*input.serviceEnabled, asyncResp,
                                         serverT, dbusObjectPath,
                                         successCount, pendingCount, totalCount);
            }
        }
        else
        {
            // if user has not given the service enabled value
            // then revert it to the same state as it was
            // before.
            ++(*pendingCount);
            ++(*totalCount);
            handleServiceEnablePatch(confData.serviceEnabled, asyncResp,
                                     serverT, dbusObjectPath,
                                     successCount, pendingCount, totalCount);
        }

        if (input.remoteRoleMapData)
        {
            ++(*pendingCount);
            ++(*totalCount);
            handleRoleMapPatch(asyncResp, confData.groupRoleList, serverT,
                                *input.remoteRoleMapData, successCount,
                                pendingCount, totalCount);
        }
    });
}

struct UserUpdateParams
{
    std::string username;
    std::optional<std::string> password;
    std::optional<bool> enabled;
    std::optional<std::string> roleId;
    std::optional<bool> locked;
    std::optional<std::vector<std::string>> accountTypes;
    bool userSelf;
    std::shared_ptr<persistent_data::UserSession> session;
    std::string dbusObjectPath;
    std::optional<bool> passwordChangeRequired;
};

inline void setErrorMessageId(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& messageId,
    const boost::urls::url_view_base& arg)
{
    auto& msgArray = asyncResp->res.jsonValue["error"]["@Message.ExtendedInfo"];

    bool alreadySet = false;
    if (msgArray.is_array())
    {
        for (const auto& msg : msgArray)
        {
            auto it = msg.find("MessageId");
            if (it != msg.end() && it->is_string())
            {
                const std::string& id = *it;
                if (id.find(messageId) != std::string::npos)
                {
                    alreadySet = true;
                    break;
                }
            }
        }
    }

    if (!alreadySet)
    {
        // Example handling based on messageId content
        if (messageId.find("AccessDenied") != std::string::npos)
        {
            messages::accessDenied(asyncResp->res, boost::urls::format(arg));
        }
        else
        {
            BMCWEB_LOG_DEBUG("Unknown MessageId: {}", messageId);
        }
    }
}

inline void afterVerifyUserExists(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const UserUpdateParams& params,
    std::function<void(bool)> completionHandler, int rc)
{
    if (rc <= 0)
    {
        messages::resourceNotFound(asyncResp->res, "ManagerAccount",
                                   params.username);
        completionHandler(false);
        return;
    }

    if (params.password)
    {
        accountsTotalOperations++;

        int pamrc=pamAuthenticateUser(params.username,*params.password,
                                    std::nullopt,boost::asio::ip::address(),false);
        if ((pamrc==PAM_NEW_AUTHTOK_REQD))
        {
            BMCWEB_LOG_ERROR("Need to provide new Password");
            messages::passwordResetFailed(asyncResp->res);
            completionHandler(false);
            return;
        }

        int retval = pamUpdatePassword(params.username, *params.password);
        if (retval == PAM_USER_UNKNOWN)
        {
            messages::resourceNotFound(asyncResp->res, "ManagerAccount",
                                       params.username);
            completionHandler(false);
            return;
        }
        else if (retval == PAM_AUTHTOK_ERR)
        {
            // If password is invalid
            messages::propertyValueFormatError(asyncResp->res, nullptr,
                                               "Password");
            BMCWEB_LOG_ERROR("pamUpdatePassword Failed");
            completionHandler(false);
            return;
        }
        else if (retval != PAM_SUCCESS)
        {
            messages::passwordResetFailed(asyncResp->res);
            completionHandler(false);
            return;
        }
        propertyModified["Password"] = "*****";
        completionHandler(true);

    }

    if (params.enabled)
    {
        // Don't process if an error already occurred
        if (asyncResp->res.result() != boost::beast::http::status::ok)
        {
            return;
        }
        accountsTotalOperations++;
        setDbusProperty(
            asyncResp, "Enabled", "xyz.openbmc_project.User.Manager",
            params.dbusObjectPath, "xyz.openbmc_project.User.Attributes",
            "UserEnabled", *params.enabled);

        propertyModified["Enabled"] = *params.enabled;
        completionHandler(true);
    }

    if ((params.username == "root") && params.roleId)
    {
        BMCWEB_LOG_ERROR("Not allowed to change Channel Privileges for root user !!");
        const std::string& arg =
            "redfish/v1/AccountService/Accounts/" + params.username;
        setErrorMessageId(asyncResp, "AccessDenied", boost::urls::format(arg));
        completionHandler(false);
        return;
    }

    if (params.locked)
    {
        // Don't process if an error already occurred
        if (asyncResp->res.result() != boost::beast::http::status::ok)
        {
            return;
        }
        accountsTotalOperations++;
        // admin can unlock the account which is locked by
        // successive authentication failures but admin should
        // not be allowed to lock an account.
        if (*params.locked)
        {
            messages::propertyValueNotInList(asyncResp->res, "true", "Locked");
            completionHandler(false);
            return;
        }
        setDbusProperty(asyncResp, "Locked", "xyz.openbmc_project.User.Manager",
                        params.dbusObjectPath,
                        "xyz.openbmc_project.User.Attributes",
                        "UserLockedForFailedAttempt", *params.locked);

        propertyModified["Locked"] = *params.locked;
        completionHandler(true);
    }

    // Only process accountTypes/roleId if needed and no error occurred
    if (params.accountTypes || params.roleId)
    {
        // Don't process if an error already occurred
        if (asyncResp->res.result() != boost::beast::http::status::ok)
        {
            return;
        }

        // Need to fetch current user's RoleId to determine validation logic
        sdbusplus::asio::getProperty<std::vector<std::string>>(
            *crow::connections::systemBus,
            "xyz.openbmc_project.User.Manager",
            params.dbusObjectPath,
            "xyz.openbmc_project.User.Attributes",
            "UserPrivilege",
            [asyncResp, params, completionHandler](const boost::system::error_code& ec,
                                                        const std::vector<std::string>& userPrivileges) {
                // Check if an error has already occurred (e.g., password validation failed)
                // This must be checked BEFORE any processing to avoid incrementing counters
                if (asyncResp->res.result() != boost::beast::http::status::ok)
                {
                    return;
                }
                
                if (ec)
                {
                    BMCWEB_LOG_ERROR("Failed to get UserPrivilege: {}", ec.message());
                    messages::internalError(asyncResp->res);
                    completionHandler(false);
                    return;
                }

                if (userPrivileges.empty())
                {
                    BMCWEB_LOG_ERROR("UserPrivilege is empty");
                    messages::internalError(asyncResp->res);
                    completionHandler(false);
                    return;
                }

                if (params.accountTypes && !params.roleId)
                {
                    std::string_view currentPrivilege = userPrivileges.front();
                    std::string currentRoleId = getRoleIdFromPrivilege(currentPrivilege);

                    // If user is Administrator, allow any AccountTypes
                    if (currentRoleId == "Administrator")
                    {
                        patchAccountTypes(*params.accountTypes, asyncResp,
                                        params.dbusObjectPath, params.userSelf, completionHandler);
                    }
                    else
                    {
                        // For non-admin users, AccountTypes must NOT contain HostConsole or ManagerConsole
                        if (std::find(params.accountTypes->begin(), params.accountTypes->end(), "HostConsole") != params.accountTypes->end() ||
                            std::find(params.accountTypes->begin(), params.accountTypes->end(), "ManagerConsole") != params.accountTypes->end())
                        {
                            messages::propertyValueConflict(asyncResp->res, currentRoleId, "AccountTypes");
                            completionHandler(false);
                            return;
                        }
                        else
                        {
                            patchAccountTypes(*params.accountTypes, asyncResp,
                                        params.dbusObjectPath, params.userSelf, completionHandler);
                        }
                    }
                }
                else if (params.accountTypes && params.roleId == "Administrator")
                {
                    // If RoleId is Administrator, allow any AccountTypes                    
                    patchAccountTypes(*params.accountTypes, asyncResp,
                                    params.dbusObjectPath, params.userSelf, completionHandler);
                }
                else if (params.accountTypes && params.roleId != "Administrator")
                {
                    // For non-admin users, AccountTypes must NOT contain HostConsole or ManagerConsole
                    if (std::find(params.accountTypes->begin(), params.accountTypes->end(), "HostConsole") != params.accountTypes->end() ||
                        std::find(params.accountTypes->begin(), params.accountTypes->end(), "ManagerConsole") != params.accountTypes->end())
                    {
                        messages::propertyValueConflict(asyncResp->res, params.roleId.value_or(""), "AccountTypes");
                        completionHandler(false);
                        return;
                    }
                    else
                    {
                        patchAccountTypes(*params.accountTypes, asyncResp,
                                    params.dbusObjectPath, params.userSelf, completionHandler);
                    }
                }
            });
    }

    if (params.passwordChangeRequired)
    {
        // Don't process if an error already occurred
        if (asyncResp->res.result() != boost::beast::http::status::ok)
        {
            return;
        }
        std::optional<bool> passwordChangeRequired =
            params.passwordChangeRequired;
        if (params.username != "root")
        {
            accountsTotalOperations++;
            crow::connections::systemBus->async_method_call(
                [asyncResp,
                 passwordChangeRequired, completionHandler](const boost::system::error_code ec) {
                    if (ec)
                    {
                        completionHandler(false);
                        return;
                    }
                },
                "xyz.openbmc_project.User.Manager", "/xyz/openbmc_project/user",
                "xyz.openbmc_project.User.Manager", "SetPasswordExpired",
                params.username, *passwordChangeRequired);

            propertyModified["PasswordChangeRequired"] = *passwordChangeRequired;
            completionHandler(true);
        }
        else
        {
            BMCWEB_LOG_DEBUG("Not able to change PasswordChangeRequired for root user");
            const std::string& arg =
                "redfish/v1/AccountService/Accounts/" + params.username;
            messages::accessDenied(asyncResp->res, boost::urls::format(arg));
            completionHandler(false);
            return;
        }
    }
}

inline void updateUserProperties(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& username, const std::optional<std::string>& password,
    const std::optional<bool>& enabled,
    const std::optional<std::string>& roleId, const std::optional<bool>& locked,
    const std::optional<std::vector<std::string>>& accountTypes, bool userSelf,
    const std::shared_ptr<persistent_data::UserSession>& session,
    const std::optional<bool>& passwordChangeRequired,
    std::function<void(bool)> completionHandler)
{
    sdbusplus::message::object_path tempObjPath(rootUserDbusPath);
    tempObjPath /= username;
    std::string dbusObjectPath(tempObjPath);



    UserUpdateParams params{username,       password,
                            enabled,        roleId,
                            locked,         accountTypes,
                            userSelf,       session,
                            dbusObjectPath, passwordChangeRequired};

    dbus::utility::checkDbusPathExists(
        dbusObjectPath,
        std::bind_front(afterVerifyUserExists, asyncResp, std::move(params), completionHandler));
}

inline void handleAccountServiceHead(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/AccountService/AccountService.json>; rel=describedby");
}

inline void getClientCertificates(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const nlohmann::json::json_pointer& keyLocation)
{
    boost::urls::url url(
        "/redfish/v1/AccountService/MultiFactorAuth/ClientCertificate/Certificates");
    std::array<std::string_view, 1> interfaces = {
        "xyz.openbmc_project.Certs.Certificate"};
    std::string path = "/xyz/openbmc_project/certs/authority/truststore";

    collection_util::getCollectionToKey(asyncResp, url, interfaces, path,
                                        keyLocation);
}

inline void handleAccountServiceClientCertificatesInstanceHead(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& /*id*/)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/Certificate/Certificate.json>; rel=describedby");
}

inline void handleAccountServiceClientCertificatesInstanceGet(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp, const std::string& id)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    BMCWEB_LOG_DEBUG("ClientCertificate Certificate ID={}", id);
    const boost::urls::url certURL = boost::urls::format(
        "/redfish/v1/AccountService/MultiFactorAuth/ClientCertificate/Certificates/{}",
        id);
    std::string objPath =
        sdbusplus::message::object_path(certs::authorityObjectPath) / id;
    getCertificateProperties(
        asyncResp, objPath,
        "xyz.openbmc_project.Certs.Manager.Authority.Truststore", id, certURL,
        "Client Certificate");
}

inline void handleAccountServiceClientCertificatesHead(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/CertificateCollection/CertificateCollection.json>; rel=describedby");
}

inline void handleAccountServiceClientCertificatesGet(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    asyncResp->res.jsonValue["@odata.id"] =
        "/redfish/v1/AccountService/MultiFactorAuth/ClientCertificate/Certificates";
    asyncResp->res.jsonValue["@odata.type"] =
        "#CertificateCollection.CertificateCollection";
    asyncResp->res.jsonValue["Name"] = "Client Certificate Collection";
    asyncResp->res.jsonValue["Description"] =
        "A Collection of Client Certificate instances";
    getClientCertificates(asyncResp, "/Members"_json_pointer);
}

using account_service::CertificateMappingAttribute;
using persistent_data::MTLSCommonNameParseMode;
inline CertificateMappingAttribute getCertificateMapping(
    MTLSCommonNameParseMode parse)
{
    switch (parse)
    {
        case MTLSCommonNameParseMode::CommonName:
        {
            return CertificateMappingAttribute::CommonName;
        }
        break;
        case MTLSCommonNameParseMode::Whole:
        {
            return CertificateMappingAttribute::Whole;
        }
        break;
        case MTLSCommonNameParseMode::UserPrincipalName:
        {
            return CertificateMappingAttribute::UserPrincipalName;
        }
        break;

        case MTLSCommonNameParseMode::Meta:
        {
            if constexpr (BMCWEB_META_TLS_COMMON_NAME_PARSING)
            {
                return CertificateMappingAttribute::CommonName;
            }
        }
        break;
        default:
        {
            return CertificateMappingAttribute::Invalid;
        }
        break;
    }
}

inline void handleAccountServiceGet(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    if (req.session == nullptr)
    {
        messages::internalError(asyncResp->res);
        return;
    }

    const persistent_data::AuthConfigMethods& authMethodsConfig =
        persistent_data::SessionStore::getInstance().getAuthMethodsConfig();

    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/AccountService/AccountService.json>; rel=describedby");

    nlohmann::json& json = asyncResp->res.jsonValue;
    json["@odata.id"] = "/redfish/v1/AccountService";
    json["@odata.type"] = json_util::odataType("AccountService");
    json["Id"] = "AccountService";
    json["Name"] = "Account Service";
    json["Description"] = "Account Service";
    json["ServiceEnabled"] = true;
    json["MaxPasswordLength"] = 20;
    json["Accounts"]["@odata.id"] = "/redfish/v1/AccountService/Accounts";
    json["Roles"]["@odata.id"] = "/redfish/v1/AccountService/Roles";
    json["AdditionalExternalAccountProviders"]["@odata.id"] =
        "/redfish/v1/AccountService/ExternalAccountProviders";
    if(!BMCWEB_AMI_PSM_MACRO){
    json["HTTPBasicAuth"] = authMethodsConfig.basic
                                ? account_service::BasicAuthState::Enabled
                                : account_service::BasicAuthState::Disabled;

    nlohmann::json::array_t allowed;
    allowed.emplace_back(account_service::BasicAuthState::Enabled);
    allowed.emplace_back(account_service::BasicAuthState::Disabled);
    json["HTTPBasicAuth@Redfish.AllowableValues"] = std::move(allowed);
    }
    nlohmann::json::object_t clientCertificate;
    clientCertificate["Enabled"] = authMethodsConfig.tls;
    clientCertificate["RespondToUnauthenticatedClients"] =
        !authMethodsConfig.tlsStrict;

    using account_service::CertificateMappingAttribute;

    CertificateMappingAttribute mapping =
        getCertificateMapping(authMethodsConfig.mTLSCommonNameParsingMode);
    if (mapping == CertificateMappingAttribute::Invalid)
    {
        messages::internalError(asyncResp->res);
    }
    else
    {
        clientCertificate["CertificateMappingAttribute"] = mapping;
    }
    nlohmann::json::object_t certificates;
    certificates["@odata.id"] =
        "/redfish/v1/AccountService/MultiFactorAuth/ClientCertificate/Certificates";
    certificates["@odata.type"] =
        "#CertificateCollection.CertificateCollection";
    clientCertificate["Certificates"] = std::move(certificates);
    if(!BMCWEB_AMI_PSM_MACRO){
    json["MultiFactorAuth"]["ClientCertificate"] = std::move(clientCertificate);
    }
    getClientCertificates(
        asyncResp,
        "/MultiFactorAuth/ClientCertificate/Certificates/Members"_json_pointer);

    json["Oem"]["OpenBMC"]["@odata.type"] = json_util::odataType("OpenBMCAccountService", "AccountService");
    json["Oem"]["OpenBMC"]["@odata.id"] =
        "/redfish/v1/AccountService#/Oem/OpenBMC";
    json["Oem"]["OpenBMC"]["AuthMethods"]["BasicAuth"] =
        authMethodsConfig.basic;
    json["Oem"]["OpenBMC"]["AuthMethods"]["SessionToken"] =
        authMethodsConfig.sessionToken;
    json["Oem"]["OpenBMC"]["AuthMethods"]["XToken"] = authMethodsConfig.xtoken;
    json["Oem"]["OpenBMC"]["AuthMethods"]["Cookie"] = authMethodsConfig.cookie;
    json["Oem"]["OpenBMC"]["AuthMethods"]["TLS"] = authMethodsConfig.tls;

    // /redfish/v1/AccountService/LDAP/Certificates is something only
    // ConfigureManager can access then only display when the user has
    // permissions ConfigureManager
    Privileges effectiveUserPrivileges =
        redfish::getUserPrivileges(*req.session);

    if (isOperationAllowedWithPrivileges({{"ConfigureManager"}},
                                         effectiveUserPrivileges))
    {
        asyncResp->res.jsonValue["LDAP"]["Certificates"]["@odata.id"] =
            "/redfish/v1/AccountService/LDAP/Certificates";
    }
    dbus::utility::getAllProperties(
        "xyz.openbmc_project.User.Manager", "/xyz/openbmc_project/user",
        "xyz.openbmc_project.User.AccountPolicy",
        [asyncResp](const boost::system::error_code& ec,
                    const dbus::utility::DBusPropertiesMap& propertiesList) {
            if (ec)
            {
                messages::internalError(asyncResp->res);
                return;
            }

            BMCWEB_LOG_DEBUG("Got {} properties for AccountService",
                             propertiesList.size());

            const uint8_t* minPasswordLength = nullptr;
            const uint32_t* accountUnlockTimeout = nullptr;
            const uint16_t* maxLoginAttemptBeforeLockout = nullptr;
            const uint8_t* rememberOldPasswordTimes = nullptr;
            const std::string* passwordPolicyComplexity = nullptr;

            const bool success = sdbusplus::unpackPropertiesNoThrow(
                dbus_utils::UnpackErrorPrinter(), propertiesList,
                "MinPasswordLength", minPasswordLength, "AccountUnlockTimeout",
                accountUnlockTimeout, "MaxLoginAttemptBeforeLockout",
                maxLoginAttemptBeforeLockout, "RememberOldPasswordTimes",
                rememberOldPasswordTimes, "PasswordPolicyComplexity",
                passwordPolicyComplexity);

            if (!success)
            {
                messages::internalError(asyncResp->res);
                return;
            }

            if (minPasswordLength != nullptr)
            {
                asyncResp->res.jsonValue["MinPasswordLength"] =
                    *minPasswordLength;
            }

            if (accountUnlockTimeout != nullptr)
            {
                asyncResp->res.jsonValue["AccountLockoutDuration"] =
                    *accountUnlockTimeout;
            }

            if (maxLoginAttemptBeforeLockout != nullptr)
            {
                asyncResp->res.jsonValue["AccountLockoutThreshold"] =
                    *maxLoginAttemptBeforeLockout;
            }

            if ((rememberOldPasswordTimes != nullptr) && (!BMCWEB_AMI_PSM_MACRO))
            {
                asyncResp->res
                    .jsonValue["Oem"]["OpenBMC"]["RememberOldPasswordTimes"] =
                    *rememberOldPasswordTimes;
            }

            if ((passwordPolicyComplexity != nullptr) && (!BMCWEB_AMI_PSM_MACRO))
            {
                asyncResp->res
                    .jsonValue["Oem"]["OpenBMC"]["PasswordPolicyComplexity"] =
                    *passwordPolicyComplexity;
            }
        });

    auto callback = [asyncResp](bool success, const LDAPConfigData& confData,
                                const std::string& ldapType) {
        if (!success)
        {
            return;
        }
        parseLDAPConfigData(asyncResp->res.jsonValue, confData, ldapType);
    };

    getLDAPConfigData("LDAP", callback);
    getLDAPConfigData("ActiveDirectory", callback);
}

inline void handleCertificateMappingAttributePatch(
    crow::Response& res, const std::string& certMapAttribute)
{
    MTLSCommonNameParseMode parseMode =
        persistent_data::getMTLSCommonNameParseMode(certMapAttribute);
    if (parseMode == MTLSCommonNameParseMode::Invalid)
    {
        messages::propertyValueNotInList(res, "CertificateMappingAttribute",
                                         certMapAttribute);
        return;
    }

    persistent_data::AuthConfigMethods& authMethodsConfig =
        persistent_data::SessionStore::getInstance().getAuthMethodsConfig();
    authMethodsConfig.mTLSCommonNameParsingMode = parseMode;
}

inline void handleRespondToUnauthenticatedClientsPatch(
    App& app, const crow::Request& req, crow::Response& res,
    bool respondToUnauthenticatedClients)
{
    if (req.session != nullptr)
    {
        // Sanity check.  If the user isn't currently authenticated with mutual
        // TLS, they very likely are about to permanently lock themselves out.
        // Make sure they're using mutual TLS before allowing locking.
        if (req.session->sessionType != persistent_data::SessionType::MutualTLS)
        {
            messages::propertyValueExternalConflict(
                res,
                "MultiFactorAuth/ClientCertificate/RespondToUnauthenticatedClients",
                respondToUnauthenticatedClients);
            return;
        }
    }

    persistent_data::AuthConfigMethods& authMethodsConfig =
        persistent_data::SessionStore::getInstance().getAuthMethodsConfig();

    // Change the settings
    authMethodsConfig.tlsStrict = !respondToUnauthenticatedClients;

    // Write settings to disk
    persistent_data::getConfig().writeData();

    // Trigger a reload, to apply the new settings to new connections
    app.loadCertificate();
}

inline void handleExternalProviderGet(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    if (req.session == nullptr)
    {
        messages::internalError(asyncResp->res);
        return;
    }

    nlohmann::json& json = asyncResp->res.jsonValue;
    json["@odata.id"] = "/redfish/v1/AccountService/ExternalAccountProviders";
    json["@odata.type"] =
        "#ExternalAccountProviderCollection.ExternalAccountProviderCollection";
    json["Name"] = "External Accounts Provider Collection";
    json["Description"] = "Collection for External Accounts Provider";
    nlohmann::json& memberArray = json["Members"];
    nlohmann::json::object_t member;
    member["@odata.id"] = boost::urls::format(
        "/redfish/v1/AccountService/ExternalAccountProviders/RADIUS");
    memberArray.push_back(std::move(member));

    json["Members@odata.count"] = memberArray.size();
}

inline void uploadRadiusSSLFile(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                                std::string_view body, const std::string& fileName)
{
    std::string filePath = "/etc/ssl/certs/" + fileName;
    std::filesystem::path path(filePath);

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out)
    {
        messages::internalError(asyncResp->res);
        BMCWEB_LOG_ERROR("Failed to open file: {}", filePath);
        return;
    }

    out.write(reinterpret_cast<const char*>(body.data()),
              static_cast<std::streamsize>(body.size()));
    out.close();

    if (out.bad())
    {
        messages::internalError(asyncResp->res);
        BMCWEB_LOG_ERROR("Error writing file: {}", filePath);
        return;
    }
    asyncResp->res.result(boost::beast::http::status::no_content);

}

inline void readRadiusSSLContext(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                                 const MultipartParser& parser)
{
    bool fileUploaded = false;
    std::string SSLFileName ="";

    for (const FormPart& formpart : parser.mime_fields)
    {
        auto it = formpart.fields.find("Content-Disposition");
        if (it == formpart.fields.end())
        {
            continue;
        }

        size_t index = it->value().find(';');
        if (index == std::string::npos)
        {
            continue;
        }

        std::string_view dispositionParams = it->value().substr(index);
        std::string fieldName;

        for (const auto& param : boost::beast::http::param_list{dispositionParams})
        {
            if (param.first == "name")
            {
                fieldName = std::string(param.second);
            }
            else if (param.first == "filename" && !param.second.empty())
            {
                SSLFileName = param.second;

                if (SSLFileName.substr(SSLFileName.find_last_of('.') + 1) != "pem")
                {
                    messages::actionParameterValueFormatError(
                        asyncResp->res, SSLFileName, fieldName, "RADIUS.SSLCertificateUpload");
                    return;
                }
            }
        }

        if (!fieldName.empty())
        {
            if (formpart.content.empty())
            {
                #if BMCWEB_AMI_REP_MACRO
                {
                    messages::invalidFileContent(asyncResp->res, SSLFileName);
                    return;
                }
                #else
                {
                    messages::invalidLicense(asyncResp->res);
                    return;
                }
                #endif
            }
            std::string fileName = fieldName + ".pem";
            uploadRadiusSSLFile(asyncResp, formpart.content, fileName);
            fileUploaded = true;
        }
    }

    if (!fileUploaded)
    {
        #if BMCWEB_AMI_REP_MACRO
        {
            messages::invalidFileContent(asyncResp->res, SSLFileName);
            return;
        }
        #else
        {
            messages::invalidLicense(asyncResp->res);
            return;
        }
        #endif
    }
}

inline void handleRadiusSSLCertificateUploadAction(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    std::string_view contentType = req.getHeaderValue("Content-Type");
    BMCWEB_LOG_DEBUG("doPost: contentType= ", contentType);
    if (contentType.starts_with("multipart/form-data"))
    {
        MultipartParser parser;
        ParserError ec = parser.parse(req);
        if (ec != ParserError::PARSER_SUCCESS)
        {
            // handle error
            BMCWEB_LOG_ERROR("SSL Certificate parse failed, ec :",
                             static_cast<int>(ec));
            messages::internalError(asyncResp->res);
            return;
        }

        sdbusplus::asio::getProperty<bool>(
            *crow::connections::systemBus,
            radisuDBusService,
            radiusConfigObjectPath,
            radiusConfigInterface,
            "Enable", // Fetching Enable property
            [asyncResp, parser](const boost::system::error_code& ec1, bool Enable)
            {
                if (ec1)
                {
                    BMCWEB_LOG_DEBUG("DBUS response error for Enable {}", ec1);
                    return;
                }

                // Validate the Enable property
                if (!Enable)
                {
                    BMCWEB_LOG_ERROR("RADIUS service is disabled, skipping SSL upload handling");
                    messages::configurationConflict(asyncResp->res, "Enable", "disabled");
                    return;
                }

                // Fetch EnableEapTLS property only if Enable is true
                sdbusplus::asio::getProperty<bool>(
                    *crow::connections::systemBus,
                    radisuDBusService,
                    radiusConfigObjectPath,
                    radiusConfigInterface,
                    "EnableEapTLS", // Fetching EnableEapTLS property
                    [asyncResp, parser, Enable](const boost::system::error_code& ec2, bool EnableEapTLS)
                    {
                        if (ec2)
                        {
                            BMCWEB_LOG_DEBUG("DBUS response error for EnableEapTLS {}", ec2);
                            return;
                        }

                        // Validate EnableEapTLS if Enable is true
                        if (!EnableEapTLS)
                        {
                            BMCWEB_LOG_ERROR("EAP-TLS is disabled, skipping SSL upload handling");
                            messages::configurationConflict(asyncResp->res, "EnableEapTLS", "disabled");
                            return;
                        }

                        // Proceed with reading SSL context if both Enable and EnableEapTLS are true
                        readRadiusSSLContext(asyncResp, parser);
                    });
            });
    }
}

inline void
    handleAccountRadiusGet(App& app, const crow::Request& req,
                           const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    if (req.session == nullptr)
    {
        messages::internalError(asyncResp->res);
        return;
    }

    nlohmann::json& json = asyncResp->res.jsonValue;

    json["@odata.id"] =
        "/redfish/v1/AccountService/ExternalAccountProviders/RADIUS";
    json["@odata.type"] = json_util::odataType("ExternalAccountProvider");
    json["AccountProviderType"] = "OEM";
    json["Oem"]["Ami"]["@odata.type"] = json_util::odataType("AMIExternalAccountProvider", "Ami");
    json["Id"] = "RADIUS";
    json["Name"] = "RADIUS Settings";
    json["Description"] = "RADIUS server settings";
    json["Oem"]["Ami"]["Actions"]["#AMIExternalAccountProvider.v1_0_0.Ami"] = {
        {"target", "/redfish/v1/AccountService/ExternalAccountProviders/Actions/Oem/Ami/RADIUS.SSLCertificateUpload"}};

    getRADIUSConfigData(asyncResp);
    getRADIUSRoleMap(asyncResp);
}
inline void handleAccountRadiusPatch(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    RadiusPatchParams radiusObject;
    bool anyPropertyPatched = false;

    // clang-format off
    std::optional<nlohmann::json> oem;

    if (!json_util::readJsonPatch(
            req, asyncResp->res, "Oem", oem, "ServiceEnabled", radiusObject.enabled))
    {
        BMCWEB_LOG_DEBUG("Radius Service doPatch: Invalid request body");
        return;
    }

    if (oem)
    {
        std::optional<nlohmann::json> ami;
        std::size_t oem_size = oem.value().size();
        if (oem_size == 0)
        {
            messages::propertyNotWritable(asyncResp->res, "Oem");
            // Do not return here, allow partial patch
        }

        if (!json_util::readJson(*oem, asyncResp->res, "Ami", ami))
        {
            // Do not return here, allow partial patch
        }

        if(ami)
        {
            std::optional<nlohmann::json> radius;
            std::size_t ami_size = ami.value().size();
            if (ami_size == 0)
            {
                messages::propertyNotWritable(asyncResp->res, "Ami");
                // Do not return here, allow partial patch
            }

            if (!json_util::readJson(*ami, asyncResp->res, "RADIUS", radius))
            {
                // Do not return here, allow partial patch
            }

            if(radius)
            {
                std::size_t radius_size = radius.value().size();
                if (radius_size == 0)
                {
                    messages::propertyNotWritable(asyncResp->res, "RADIUS");
                    // Do not return here, allow partial patch
                }

                if (!json_util::readJson(
                *radius, asyncResp->res,
                "EnableEapTLS", radiusObject.enabledEapTLS,
                "ServiceAddress", radiusObject.host,
                "Secret", radiusObject.password,
                "ServicePort", radiusObject.port,
                "GroupName1", radiusObject.groupName1,
                "GroupName2", radiusObject.groupName2,
                "GroupName3", radiusObject.groupName3,
                "Privilege1", radiusObject.privilege1,
                "Privilege2", radiusObject.privilege2,
                "Privilege3", radiusObject.privilege3))
                {
                    // Do not return here, allow partial patch
                }
                // clang-format on

                if (radiusObject.host)
                {
                    if (radiusObject.host != "")
                    {
                        const std::string& ipAddress = *radiusObject.host;
                        if (!ip_util::isValidIPv4Addr(
                                *radiusObject.host,
                                ip_util::Type::IP4_ADDRESS)) // checking the
                                                             // IPv4 Address
                        {
                            messages::invalidip(asyncResp->res,
                                                "ServiceAddress", ipAddress);
                        }
                        else
                        {
                            handleRadiusConfigRolemMapPatch(
                                asyncResp, radiusConfigObjectPath,
                                radiusConfigInterface, "IP",
                                *radiusObject.host);
                            anyPropertyPatched = true;
                        }
                    }
                    else
                    {
                        messages::propertyValueEmpty(asyncResp->res,
                                                     *radiusObject.host,
                                                     "ServiceAddress");
                    }
                }
                if (radiusObject.password)
                {
                    if (radiusObject.password != "")
                    {
                        handleRadiusConfigRolemMapPatch(
                            asyncResp, radiusConfigObjectPath,
                            radiusConfigInterface, "Password",
                            *radiusObject.password);
                        anyPropertyPatched = true;
                    }
                    else
                    {
                        messages::propertyValueEmpty(
                            asyncResp->res, *radiusObject.password, "Secret");
                    }
                }
                if (radiusObject.port && *radiusObject.port >= 0 &&
                    *radiusObject.port <= 65535)
                {
                    sdbusplus::asio::setProperty(
                        *crow::connections::systemBus, radisuDBusService,
                        radiusConfigObjectPath, radiusConfigInterface,
                        "PortNumber", *radiusObject.port,
                        [asyncResp](const boost::system::error_code& ec) {
                            if (ec)
                            {
                                BMCWEB_LOG_ERROR("D-Bus responses error: {}",
                                                 ec);
                                messages::internalError(asyncResp->res);
                                return;
                            }
                            messages::success(asyncResp->res);
                            BMCWEB_LOG_DEBUG("Patch port Success");
                        });
                    anyPropertyPatched = true;
                }
                if (radiusObject.groupName1)
                {
                    handleRadiusConfigRolemMapPatch(
                        asyncResp, radiusRoleMapObjectPath,
                        radiusRoleMapInterface, "GroupName1",
                        *radiusObject.groupName1);
                    anyPropertyPatched = true;
                }
                if (radiusObject.groupName2)
                {
                    handleRadiusConfigRolemMapPatch(
                        asyncResp, radiusRoleMapObjectPath,
                        radiusRoleMapInterface, "GroupName2",
                        *radiusObject.groupName2);
                    anyPropertyPatched = true;
                }
                if (radiusObject.groupName3)
                {
                    handleRadiusConfigRolemMapPatch(
                        asyncResp, radiusRoleMapObjectPath,
                        radiusRoleMapInterface, "GroupName3",
                        *radiusObject.groupName3);
                    anyPropertyPatched = true;
                }
                if (radiusObject.privilege1)
                {
                    if (!radiusObject.privilege1->empty())
                    {
                        // Map privilege to a role ID
                        std::string roleId =
                            getPrivilegeFromRoleId(*radiusObject.privilege1);

                        if (!roleId.empty())
                        {
                            // Process valid privilege
                            handleRadiusConfigRolemMapPatch(
                                asyncResp, radiusRoleMapObjectPath,
                                radiusRoleMapInterface, "Privilege1", roleId);
                            anyPropertyPatched = true;
                        }
                        else
                        {
                            // Handle invalid privilege
                            messages::propertyValueNotInList(
                                asyncResp->res, *radiusObject.privilege1,
                                "Privilege1");
                        }
                    }
                    else
                    {
                        // Handle empty privilege
                        messages::propertyValueEmpty(asyncResp->res,
                                                     *radiusObject.privilege1,
                                                     "Privilege1");
                    }
                }

                if (radiusObject.privilege2)
                {
                    if (!radiusObject.privilege2->empty())
                    {
                        // Map privilege to a role ID
                        std::string roleId =
                            getPrivilegeFromRoleId(*radiusObject.privilege2);

                        if (!roleId.empty())
                        {
                            // Process valid privilege
                            handleRadiusConfigRolemMapPatch(
                                asyncResp, radiusRoleMapObjectPath,
                                radiusRoleMapInterface, "Privilege2", roleId);
                            anyPropertyPatched = true;
                        }
                        else
                        {
                            // Handle invalid privilege
                            messages::propertyValueNotInList(
                                asyncResp->res, *radiusObject.privilege2,
                                "Privilege2");
                        }
                    }
                    else
                    {
                        // Handle empty privilege
                        messages::propertyValueEmpty(asyncResp->res,
                                                     *radiusObject.privilege2,
                                                     "Privilege2");
                    }
                }
                if (radiusObject.privilege3)
                {
                    if (!radiusObject.privilege3->empty())
                    {
                        // Map privilege to a role ID
                        std::string roleId =
                            getPrivilegeFromRoleId(*radiusObject.privilege3);

                        if (!roleId.empty())
                        {
                            // Process valid privilege
                            handleRadiusConfigRolemMapPatch(
                                asyncResp, radiusRoleMapObjectPath,
                                radiusRoleMapInterface, "Privilege3", roleId);
                            anyPropertyPatched = true;
                        }
                        else
                        {
                            // Handle invalid privilege
                            messages::propertyValueNotInList(
                                asyncResp->res, *radiusObject.privilege3,
                                "Privilege3");
                        }
                    }
                    else
                    {
                        // Handle empty privilege
                        messages::propertyValueEmpty(asyncResp->res,
                                                     *radiusObject.privilege3,
                                                     "Privilege3");
                    }
                }
                if(radiusObject.enabledEapTLS.has_value())
                {
                    setRadiusEnable(asyncResp, "EnableEapTLS", *radiusObject.enabledEapTLS);
                    anyPropertyPatched = true;
                }
            }
        }
    }

    if (radiusObject.enabled.has_value())
    {
        // Enable or disable the RADIUS service based on the value of "ServiceEnabled"
        setRadiusEnable(asyncResp, "Enable", *radiusObject.enabled);
        anyPropertyPatched = true;
    }
    else
    {
        BMCWEB_LOG_DEBUG("ServiceEnabled field missing or invalid");
    }

    // If any property was patched, set response to 200 OK
    if (anyPropertyPatched)
    {
        asyncResp->res.result(boost::beast::http::status::ok);
    }
    else
    {
        // If nothing was patched, keep the default error handling
        asyncResp->res.result(boost::beast::http::status::bad_request);
    }
}

inline void getSNMPAccessStatus(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                                 const std::string& username,
                                 std::function<void(bool)> callback)
{
    sdbusplus::message::object_path tempObjPath(rootUserDbusPath);
    tempObjPath /= username;

    const std::string userPath(tempObjPath);

    sdbusplus::asio::getProperty<bool>(
        *crow::connections::systemBus,
        "xyz.openbmc_project.User.Manager",
        userPath,
        "xyz.openbmc_project.User.Attributes",
        "SNMPAccessEnableStatus",
        [callback, asyncResp, username](const boost::system::error_code& ec, const bool& fetchedStatus) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("Failed to get SNMPAccessEnableStatus for user {}: {}",
                                 username, ec.message());
                messages::internalError(asyncResp->res);
                callback(false);
                return;
            }
            callback(fetchedStatus);
        });
}

inline void handleAccountSnmpPatch(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                                    const std::string& username,
                                    std::optional<bool> hasSNMP,
                                    std::optional<std::string> algorithm,
                                    std::optional<std::string> encryption,
                                    std::optional<std::string> accessMode,
                                    std::optional<std::string> password)
{
    sdbusplus::message::object_path tempObjPath(snmpUserDbusPath);
    tempObjPath /= username;
    const std::string objPath(tempObjPath);

    sdbusplus::message::object_path tempUserObjPath(rootUserDbusPath);
    tempUserObjPath /= username;
    const std::string userPath(tempUserObjPath);

    boost::urls::url objUserPath = boost::urls::format("{}", userPath);

    sdbusplus::message::object_path path("/xyz/openbmc_project/snmp/UserManager");

    dbus::utility::getManagedObjects(
        "xyz.openbmc_project.Snmp.Conf", path,
        [asyncResp, objUserPath, username, hasSNMP, algorithm, encryption, accessMode, password, userPath, objPath](const boost::system::error_code& ec,
                                  const dbus::utility::ManagedObjectType& resp)
        {
            if (ec)
            {
                BMCWEB_LOG_ERROR("DBus error in getManagedObjects: {}", ec.message());
                messages::internalError(asyncResp->res);
                return;
            }

            std::string snmpUserPath = "/xyz/openbmc_project/snmp/UserManager/" + username;
            bool hasSNMPuserPath = false; // Initialize inside the callback

            for (const auto& objectPath : resp)
            {
                if (objectPath.first == snmpUserPath)
                {
                    hasSNMPuserPath = true;
                    break;
                }
            }

            if (hasSNMPuserPath)
            {
                // If SNMP is disabled
                if (hasSNMP && !*hasSNMP)
                {
                    if ((algorithm && *algorithm != "default_algorithm") ||
                        (encryption && *encryption != "default_encryption") ||
                        (accessMode && *accessMode != "read-write"))
                    {
                        nlohmann::json hasSNMPJson = nlohmann::json(*hasSNMP);
                        messages::propertyValueExternalConflict(asyncResp->res, "SNMPAccessEnableStatus", hasSNMPJson);
                        return;
                    }
                    else
                    {
                        setSNMPEnableDisable(asyncResp, *hasSNMP, username);
                        return;
                    }
                }

                // If hasSNMP is true and currentSNMPAccessEnableStatus is true, skip setSNMPEnableDisable
                bool currentSNMPAccessEnableStatus = false;
                getSNMPAccessStatus(asyncResp, username, [&currentSNMPAccessEnableStatus](bool status) {
                    std::cout << "SNMP access is " << (status ? "enabled" : "disabled") << std::endl;
                    currentSNMPAccessEnableStatus = status;
                });

                if (hasSNMP)
                {
                    if (*hasSNMP && currentSNMPAccessEnableStatus == true)
                    {
                        BMCWEB_LOG_INFO("SNMP enablement conflict for user {}", username);
                    }
                    else
                    {
                        // If SNMPAccessEnableStatus is false, update the SNMP access
                        setSNMPEnableDisable(asyncResp, *hasSNMP, username);
                    }
                }

                // Handle SNMP user patch for Algorithm, Encryption, and Access Mode
                if (algorithm && *algorithm != "default_algorithm")
                {
                    handleSNMPUserPatch(asyncResp, objPath, "Algorithm", *algorithm);
                }

                if (encryption && *encryption != "default_encryption")
                {
                    handleSNMPUserPatch(asyncResp, objPath, "Encryption", *encryption);
                }

                if (accessMode && *accessMode != "read-write")
                {
                    std::string mode = getModeFromAccessMode(*accessMode);
                    handleSNMPUserPatch(asyncResp, objPath, "ReadWritePermission", mode);
                }

                return;
            }
            else
            {
                if (hasSNMP && !*hasSNMP)
                {
                    if ((algorithm && !algorithm->empty() && *algorithm != "default_algorithm") ||
                        (encryption && !encryption->empty() && *encryption != "default_encryption") ||
                        (accessMode && !accessMode->empty() && *accessMode != "read-write"))
                    {
                        nlohmann::json hasSNMPJson = nlohmann::json(*hasSNMP);
                        messages::propertyValueExternalConflict(asyncResp->res, "SNMPAccessEnableStatus", hasSNMPJson);
                        return;
                    }
                    else
                    {
                        setSNMPEnableDisable(asyncResp, *hasSNMP, username);
                        return;
                    }
                }

                if (hasSNMP && *hasSNMP)
                {
                    bool isMissing = false;
                    if (password && *password == "dummy_password")
                    {
                        isMissing = true;
                        messages::propertyMissing(asyncResp->res, "Password");
                    }
                    if (accessMode && *accessMode == "read-write")
                    {
                        isMissing = true;
                        messages::propertyMissing(asyncResp->res, "Access Mode");
                    }
                    if (algorithm && *algorithm == "default_algorithm")
                    {
                        isMissing = true;
                        messages::propertyMissing(asyncResp->res, "Algorithm");
                    }
                    if (encryption && *encryption == "default_encryption")
                    {
                        isMissing = true;
                        messages::propertyMissing(asyncResp->res, "Encryption");
                    }

                    if (isMissing)
                    {
                        return;
                    }

                    std::string mode;
                    if (accessMode)
                    {
                        mode = getModeFromAccessMode(*accessMode);
                    }

                    // Set SNMPAccessEnableStatus on the user
                    sdbusplus::asio::setProperty(
                        *crow::connections::systemBus, "xyz.openbmc_project.User.Manager",
                        objUserPath.c_str(), "xyz.openbmc_project.User.Attributes", "SNMPAccessEnableStatus",
                        hasSNMP.value(),
                        [asyncResp, username, password, algorithm, encryption, mode](const boost::system::error_code& ec1)
                        {
                            if (ec1)
                            {
                                BMCWEB_LOG_ERROR("Failed to set SNMPAccessEnableStatus for {}: {}", username, ec1.message());
                                messages::internalError(asyncResp->res);
                                return;
                            }

                            crow::connections::systemBus->async_method_call(
                                [asyncResp](const boost::system::error_code& ec2)
                                {
                                    if (ec2)
                                    {
                                        BMCWEB_LOG_ERROR("SNMP user creation failed: {}", ec2.message());
                                        messages::internalError(asyncResp->res);
                                        return;
                                    }
                                },
                                "xyz.openbmc_project.Snmp.Conf",
                                "/xyz/openbmc_project/snmp/UserManager",
                                "xyz.openbmc_project.Snmp.UserManager.Create",
                                "Client", username, *password, *encryption, *algorithm, mode);
                        });

                    return;
                }
            }
        });
}

inline void handleAccountServicePatch(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    std::optional<uint32_t> unlockTimeout;
    std::optional<uint16_t> lockoutThreshold;
    std::optional<uint8_t> minPasswordLength;
    std::optional<uint16_t> maxPasswordLength;
    LdapPatchParams ldapObject;
    std::optional<std::string> certificateMappingAttribute;
    std::optional<bool> respondToUnauthenticatedClients;
    LdapPatchParams activeDirectoryObject;
    AuthMethods auth;
    std::optional<std::string> httpBasicAuth;
    std::optional<std::string> passwordcomplexity;
    std::optional<uint8_t> RememberOldPasswordTimes;
    std::optional<std::string> vId;
    std::optional<bool> serviceEnable;
    // clang-format off
    if (!json_util::readJsonPatch(
            req, asyncResp->res, //
            "AccountLockoutDuration", unlockTimeout, //
            "AccountLockoutThreshold", lockoutThreshold, //
            "ActiveDirectory/Authentication/AuthenticationType", activeDirectoryObject.authType, //
            "ActiveDirectory/Authentication/Password", activeDirectoryObject.password, //
            "ActiveDirectory/Authentication/Username", activeDirectoryObject.userName, //
            "ActiveDirectory/LDAPService/SearchSettings/BaseDistinguishedNames", activeDirectoryObject.baseDNList, //
            "ActiveDirectory/LDAPService/SearchSettings/GroupsAttribute", activeDirectoryObject.groupsAttribute, //
            "ActiveDirectory/LDAPService/SearchSettings/UsernameAttribute", activeDirectoryObject.userNameAttribute, //
            "ActiveDirectory/RemoteRoleMapping", activeDirectoryObject.remoteRoleMapData, //
            "ActiveDirectory/ServiceAddresses", activeDirectoryObject.serviceAddressList, //
            "ActiveDirectory/ServiceEnabled", activeDirectoryObject.serviceEnabled, //
            "MultiFactorAuth/ClientCertificate/CertificateMappingAttribute", certificateMappingAttribute, //
            "MultiFactorAuth/ClientCertificate/RespondToUnauthenticatedClients", respondToUnauthenticatedClients, //
            "LDAP/Authentication/AuthenticationType", ldapObject.authType, //
            "LDAP/Authentication/Password", ldapObject.password, //
            "LDAP/Authentication/Username", ldapObject.userName, //
            "LDAP/LDAPService/SearchSettings/BaseDistinguishedNames", ldapObject.baseDNList, //
            "LDAP/LDAPService/SearchSettings/GroupsAttribute", ldapObject.groupsAttribute, //
            "LDAP/LDAPService/SearchSettings/UsernameAttribute", ldapObject.userNameAttribute, //
            "LDAP/RemoteRoleMapping", ldapObject.remoteRoleMapData, //
            "LDAP/ServiceAddresses", ldapObject.serviceAddressList, //
            "LDAP/ServiceEnabled", ldapObject.serviceEnabled, //
            "MaxPasswordLength", maxPasswordLength, //
            "MinPasswordLength", minPasswordLength, //
            "Oem/OpenBMC/AuthMethods/BasicAuth", auth.basicAuth, //
            "Oem/OpenBMC/AuthMethods/Cookie", auth.cookie, //
            "Oem/OpenBMC/AuthMethods/SessionToken", auth.sessionToken, //
            "Oem/OpenBMC/AuthMethods/TLS", auth.tls, //
            "Oem/OpenBMC/AuthMethods/XToken", auth.xToken, //
            "HTTPBasicAuth", httpBasicAuth, //
            "Oem/OpenBMC/PasswordPolicyComplexity",passwordcomplexity, //
            "Oem/OpenBMC/RememberOldPasswordTimes",RememberOldPasswordTimes, "Id", vId, //
            "ServiceEnabled", serviceEnable //
            ))
    {
        return;
    }
    // clang-format on

    if (httpBasicAuth)
    {
        if (*httpBasicAuth == "Enabled")
        {
            auth.basicAuth = true;
        }
        else if (*httpBasicAuth == "Disabled")
        {
            auth.basicAuth = false;
        }
        else
        {
            messages::propertyValueNotInList(asyncResp->res, "HttpBasicAuth",
                                             *httpBasicAuth);
        }
    }

    if (vId)
    {
        messages::propertyNotWritable(asyncResp->res, "Id");
        asyncResp->res.result(boost::beast::http::status::bad_request);
        return;
    }

    if (serviceEnable)
    {
        messages::propertyNotWritable(asyncResp->res, "ServiceEnabled");
        asyncResp->res.result(boost::beast::http::status::bad_request);
        return;
    }

    if (respondToUnauthenticatedClients)
    {
        handleRespondToUnauthenticatedClientsPatch(
            app, req, asyncResp->res, *respondToUnauthenticatedClients);
    }

    if (certificateMappingAttribute)
    {
        handleCertificateMappingAttributePatch(asyncResp->res,
                                               *certificateMappingAttribute);
    }

    if (minPasswordLength)
    {
        sdbusplus::asio::setProperty(
            *crow::connections::systemBus, "xyz.openbmc_project.User.Manager",
            "/xyz/openbmc_project/user",
            "xyz.openbmc_project.User.AccountPolicy", "MinPasswordLength",
            *minPasswordLength,
            [asyncResp](const boost::system::error_code& ec) {
                if (ec)
                {
                    messages::internalError(asyncResp->res);
                    return;
                }
                messages::success(asyncResp->res);
            });
    }

    if (maxPasswordLength)
    {
        messages::propertyNotWritable(asyncResp->res, "MaxPasswordLength");
    }

    if (passwordcomplexity)
    {
        crow::connections::systemBus->async_method_call(
            [asyncResp,
             passwordcomplexity](const boost::system::error_code ec) {
                if (ec)
                {
                    messages::internalError(asyncResp->res);
                    return;
                }
                messages::success(asyncResp->res);
            },
            "xyz.openbmc_project.User.Manager", "/xyz/openbmc_project/user",
            "org.freedesktop.DBus.Properties", "Set",
            "xyz.openbmc_project.User.AccountPolicy",
            "PasswordPolicyComplexity",
            std::variant<std::string>(*passwordcomplexity));
    }

    if (RememberOldPasswordTimes)
    {
        uint8_t rememberRange = RememberOldPasswordTimes.value();
        crow::connections::systemBus->async_method_call(
            [asyncResp, rememberRange](const boost::system::error_code ec) {
                if (ec)
                {
                    messages::internalError(asyncResp->res);
                    return;
                }
                if (rememberRange > 5)
                {
                    std::string RemebrOldPasswdTimes =
                        std::to_string(rememberRange);
                    std::string_view RembrOldPasswdView(RemebrOldPasswdTimes);
                    messages::propertyValueOutOfRange(
                        asyncResp->res, RembrOldPasswdView,
                        "RememberOldPasswordTimes");
                    return;
                }
                messages::success(asyncResp->res);
            },
            "xyz.openbmc_project.User.Manager", "/xyz/openbmc_project/user",
            "org.freedesktop.DBus.Properties", "Set",
            "xyz.openbmc_project.User.AccountPolicy",
            "RememberOldPasswordTimes",
            std::variant<uint8_t>(*RememberOldPasswordTimes));
    }

    if (ldapObject.baseDNList)
    {
        if (ldapObject.baseDNList->at(0).length() > 253 || ldapObject.baseDNList->at(0).length() < 4)
        {
            messages::propertyValueOutOfRange(asyncResp->res, *ldapObject.baseDNList,
                    "BaseDistinguishedNames");
            return;
        }
    }

    if (activeDirectoryObject.hasValue())
    {
        handleLDAPPatch(std::move(activeDirectoryObject), asyncResp,
                        "ActiveDirectory");
    }

    if (ldapObject.hasValue())
    {
        handleLDAPPatch(std::move(ldapObject), asyncResp, "LDAP");
    }

    handleAuthMethodsPatch(asyncResp, auth);

    if (unlockTimeout)
    {
        // Account will be locked permanently after the N number of failed login
        // attempts if we set unlockTimeout value to be 0.
        /*if (unlockTimeout.value() == 0)
        {
            BMCWEB_LOG_INFO("Unlock timeout value must be greater than zero");
            messages::propertyValueNotInList(asyncResp->res, "unlockTimeout",
                                             "AccountLockoutDuration");
            return;
        }*/
        sdbusplus::asio::setProperty(
            *crow::connections::systemBus, "xyz.openbmc_project.User.Manager",
            "/xyz/openbmc_project/user",
            "xyz.openbmc_project.User.AccountPolicy", "AccountUnlockTimeout",
            *unlockTimeout, [asyncResp](const boost::system::error_code& ec) {
                if (ec)
                {
                    messages::internalError(asyncResp->res);
                    return;
                }
                messages::success(asyncResp->res);
            });
    }
    if (lockoutThreshold)
    {
        sdbusplus::asio::setProperty(
            *crow::connections::systemBus, "xyz.openbmc_project.User.Manager",
            "/xyz/openbmc_project/user",
            "xyz.openbmc_project.User.AccountPolicy",
            "MaxLoginAttemptBeforeLockout", *lockoutThreshold,
            [asyncResp](const boost::system::error_code& ec) {
                if (ec)
                {
                    messages::internalError(asyncResp->res);
                    return;
                }
                messages::success(asyncResp->res);
            });
    }
}

inline void handleAccountCollectionHead(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/ManagerAccountCollection.json>; rel=describedby");
}

inline void handleAccountCollectionGet(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    if (req.session == nullptr)
    {
        messages::internalError(asyncResp->res);
        return;
    }

    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/ManagerAccountCollection.json>; rel=describedby");

    asyncResp->res.jsonValue["@odata.id"] =
        "/redfish/v1/AccountService/Accounts";
    asyncResp->res.jsonValue["@odata.type"] = "#ManagerAccountCollection."
                                              "ManagerAccountCollection";
    asyncResp->res.jsonValue["Name"] = "Accounts Collection";
    asyncResp->res.jsonValue["Description"] = "BMC User Accounts";

    Privileges effectiveUserPrivileges =
        redfish::getUserPrivileges(*req.session);

    std::string thisUser;
    if (req.session)
    {
        thisUser = req.session->username;
    }
    sdbusplus::message::object_path path("/xyz/openbmc_project/user");
    dbus::utility::getManagedObjects(
        "xyz.openbmc_project.User.Manager", path,
        [asyncResp, req, thisUser, effectiveUserPrivileges](
            const boost::system::error_code& ec,
            const dbus::utility::ManagedObjectType& users) {
            if (ec)
            {
                messages::internalError(asyncResp->res);
                return;
            }

            bool userCanSeeAllAccounts =
                effectiveUserPrivileges.isSupersetOf({"ConfigureUsers"});

            bool userCanSeeSelf =
                effectiveUserPrivileges.isSupersetOf({"ConfigureSelf"});

            nlohmann::json& memberArray = asyncResp->res.jsonValue["Members"];
            memberArray = nlohmann::json::array();

            const std::string serverIp = redfish::ip_util::extractIPv4FromMappedIPv6(req.serverIPAddress);
            for (const auto& userpath : users)
            {
                std::string user = userpath.first.filename();
                if (user.empty())
                {
                    messages::internalError(asyncResp->res);
                    BMCWEB_LOG_ERROR("Invalid firmware ID");

                    return;
                }

                crow::connections::systemBus->async_method_call(
                    [asyncResp, thisUser, userCanSeeAllAccounts, userCanSeeSelf,
                     user, &memberArray](
                        const boost::system::error_code ec1,
                        const std::map<std::string,
                                       dbus::utility::DbusVariantType>&
                            userInfo) {
                        if (ec1)
                        {
                            BMCWEB_LOG_ERROR("GetUserInfo failed");
                            messages::internalError(asyncResp->res);
                            return;
                        }
                        const std::vector<std::string>* userGroupPtr = nullptr;
                        auto userInfoIter = userInfo.find("UserGroups");
                        if (userInfoIter != userInfo.end())
                        {
                            userGroupPtr =
                                std::get_if<std::vector<std::string>>(
                                    &userInfoIter->second);
                        }
                        if (userGroupPtr == nullptr)
                        {
                            BMCWEB_LOG_ERROR("User Group not found");
                            sdbusplus::message::object_path tempObjPath(rootUserDbusPath);
                            tempObjPath /= user;
                            const std::string userPath(tempObjPath);
                            dbus::utility::getProperty<std::vector<std::string>>(
                                "xyz.openbmc_project.User.Manager", userPath,
                                "xyz.openbmc_project.User.Attributes", "UserGroups",
                                [asyncResp, thisUser, userCanSeeAllAccounts, userCanSeeSelf,
                                    user, &memberArray](const boost::system::error_code& ec,
                                                 const std::vector<std::string>& list) {
                                    if (ec)
                                    {
                                        messages::internalError(asyncResp->res);
                                        return;
                                    }
                                    std::vector<std::string> userGroupPtr = list;
                                    auto found = std::find_if(
                                        userGroupPtr.begin(), userGroupPtr.end(),
                                        [](const auto& group) {
                                            return (group == "redfish-hostiface") ? true
                                                                                : false;
                                        });
                                    if (found == userGroupPtr.end())
                                    {
                                        if (userCanSeeAllAccounts || (thisUser == user && userCanSeeSelf))
                                        {
                                            memberArray.push_back(
                                                {{"@odata.id",
                                                "/redfish/v1/AccountService/Accounts/" +
                                                    user}});
                                        }
                                    }
                                    else
                                    {
                                        BMCWEB_LOG_DEBUG("Add the HostInterface User in Accounts Collection");
                                        memberArray.push_back(
                                        {{"@odata.id",
                                        "/redfish/v1/AccountService/Accounts/" + user}});
                                    }
                                    asyncResp->res.jsonValue["Members@odata.count"] =
                                        memberArray.size();
                                });
                        }
                        else
                        {
                            // If the host interface user found, then
                            // skip that user and don't add in response.
                            auto found = std::find_if(
                                userGroupPtr->begin(), userGroupPtr->end(),
                                [](const auto& group) {
                                    return (group == "redfish-hostiface") ? true
                                                                        : false;
                                });
                            if (found == userGroupPtr->end())
                            {
                                // As clarified by Redfish here:
                                // https://redfishforum.com/thread/281/manageraccountcollection-change-allows-account-enumeration
                                // Users without ConfigureUsers, only
                                // see their own account. Users with
                                // ConfigureUsers, see all accounts.
                                if (userCanSeeAllAccounts ||
                                    (thisUser == user && userCanSeeSelf))
                                {
                                    memberArray.push_back(
                                        {{"@odata.id",
                                        "/redfish/v1/AccountService/Accounts/" +
                                            user}});
                                }
                            }
                            else
                            {
                                BMCWEB_LOG_DEBUG("Add the HostInterface User in Accounts Collection");
                                memberArray.push_back(
                                {{"@odata.id",
                                "/redfish/v1/AccountService/Accounts/" + user}});
                            }
                            asyncResp->res.jsonValue["Members@odata.count"] =
                                memberArray.size();
                        }
                    },
                    "xyz.openbmc_project.User.Manager",
                    "/xyz/openbmc_project/user",
                    "xyz.openbmc_project.User.Manager", "GetUserInfo", user, serverIp);
            }
            asyncResp->res.jsonValue["Members@odata.count"] =
                memberArray.size();
        });

}

inline void processAfterCreateUser(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& username, const std::string& password,
    const boost::system::error_code& ec, sdbusplus::message_t& m,
    std::optional<bool> passwordChangeRequired)
{
    if (ec)
    {
        userErrorMessageHandler(m.get_error(), asyncResp, username, "");
        return;
    }
    // Ensure password update is successful
    if (pamUpdatePassword(username, password) != PAM_SUCCESS)
    {
        // If password update fails, delete the created user
        sdbusplus::message::object_path tempObjPath(rootUserDbusPath);
        tempObjPath /= username;
        const std::string userPath(tempObjPath);
        crow::connections::systemBus->async_method_call(
            [asyncResp](const boost::system::error_code& ec3) {
                if (ec3)
                {
                    messages::internalError(asyncResp->res);
                    return;
                }
                // Password format error message
                messages::propertyValueFormatError(asyncResp->res, nullptr,
                                                   "Password");
            },
            "xyz.openbmc_project.User.Manager", userPath,
            "xyz.openbmc_project.Object.Delete", "Delete");

        BMCWEB_LOG_ERROR("pamUpdatePassword Failed");
        return;
    }

    // Handle password change requirement
    if (username != "root" && passwordChangeRequired)
    {
        crow::connections::systemBus->async_method_call(
            [asyncResp](const boost::system::error_code& ec4) {
                if (ec4)
                {
                    return;  // Ignore failure
                }
            },
            "xyz.openbmc_project.User.Manager", "/xyz/openbmc_project/user",
            "xyz.openbmc_project.User.Manager", "SetPasswordExpired", username,
            *passwordChangeRequired);
    }

    asyncResp->res.result(boost::beast::http::status::no_content);
    asyncResp->res.addHeader("Location",
                             "/redfish/v1/AccountService/Accounts/" + username);
    std::string eventLogMessageId = "ResourceAdded:/redfish/v1/AccountService/Accounts/" + username;
    EventServiceManager::getInstance().resourceCreationDeletion(eventLogMessageId);
}

inline void processAfterGetAllGroups(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& username, const std::string& password,
    std::optional<std::string> roleIdJson, bool enabled,
    std::optional<std::vector<std::string>> accountTypes,
    const std::vector<std::string>& allGroupsList,
    std::optional<bool> passwordChangeRequired,
    std::optional<std::string> algorithm,
    std::optional<std::string> encryption,
    std::optional<std::string> accessMode,
    std::optional<bool> hasSNMP, std::vector<std::string> dbusChannelPrivileges, 
    std::vector<uint8_t> dbusChannelAccess, std::optional<std::string> smtpMailId)
{
    std::vector<std::string> userGroups;
    std::vector<std::string> accountTypeUserGroups;

    // Convert account types to groups
    if (accountTypes &&
        !getUserGroupFromAccountType(asyncResp->res, *accountTypes, accountTypeUserGroups))
    {
        return;
    }

    if(username == "root") // Do not allow to create a user with the username root
    {
        messages::propertyValueIncorrect(asyncResp->res, "UserName", nlohmann::json(username));
        return;
    }

    // Translate roleId to privilege
    std::string roleId = roleIdJson.value_or("");
    if (!roleId.empty())
    {
        const std::string priv = getPrivilegeFromRoleId(roleId);
        if (priv.empty())
        {
            messages::propertyValueNotInList(asyncResp->res, roleId, "RoleId");
            return;
        }
        roleId = priv;
    }

    auto addGroupsToUser = [&](std::vector<std::string>& targetGroups) {
        for (const std::string& group : allGroupsList)
        {
            // Filter by account types if specified
            if (!accountTypeUserGroups.empty() &&
                std::find(accountTypeUserGroups.begin(), accountTypeUserGroups.end(), group) == accountTypeUserGroups.end())
            {
                continue;
            }

            // Only admin can have hostconsole & managerconsole access
            if ((group == "hostconsole" || group == "ssh") && roleId != "priv-admin")
            {
                if (!accountTypeUserGroups.empty())
                {
                    std::string_view accountTypeName = (group == "hostconsole") ? "HostConsole" : "ManagerConsole";
                    BMCWEB_LOG_ERROR("Only administrator can get {} access", accountTypeName);
                    messages::propertyValueConflict(asyncResp->res, accountTypeName,
                                                    "Administrator privilege required for this Account Type.");
                    return false;
                }
                continue;
            }
            else
            {
                targetGroups.emplace_back(group);
            }
        }
        // Ensure specified account types match final groups
        if (!accountTypeUserGroups.empty() && accountTypeUserGroups.size() != targetGroups.size())
        {
            messages::internalError(asyncResp->res);
            return false;
        }

        return true;
    };

    // Case 1: Creating user with SNMP access
    if (!roleId.empty() && encryption && algorithm && accessMode && hasSNMP.value_or(false))
    {
        if (!addGroupsToUser(userGroups))
        {
            return;
        }

        crow::connections::systemBus->async_method_call(
            [=](const boost::system::error_code& ec2, sdbusplus::message_t& m) {
                if (ec2)
                {
                    BMCWEB_LOG_ERROR("Error creating user {}: {}", username, ec2.message());
                    messages::internalError(asyncResp->res);
                    return;
                }
                processAfterCreateUser(asyncResp, username, password, ec2, m, passwordChangeRequired);
                std::string userPath = "/xyz/openbmc_project/user/" + username;

                sdbusplus::asio::setProperty(
                    *crow::connections::systemBus,
                    "xyz.openbmc_project.User.Manager", userPath,
                    "xyz.openbmc_project.User.Attributes", "SNMPAccessEnableStatus",
                    hasSNMP.value(),
                    [=](const boost::system::error_code& ec1) {
                        if (ec1)
                        {
                            BMCWEB_LOG_ERROR("Failed to set SNMPAccessEnableStatus for {}: {}", username, ec1.message());
                            messages::internalError(asyncResp->res);
                            return;
                        }
                        crow::connections::systemBus->async_method_call(
                            [=](const boost::system::error_code& ec) {
                                if (ec)
                                {
                                    BMCWEB_LOG_ERROR("SNMP Client method failed: {}", ec.message());
                                    messages::internalError(asyncResp->res);
                                    return;
                                }
                                BMCWEB_LOG_INFO("SNMP user successfully created.");
                            },
                            "xyz.openbmc_project.Snmp.Conf",
                            "/xyz/openbmc_project/snmp/UserManager",
                            "xyz.openbmc_project.Snmp.UserManager.Create",
                            "Client", username, password, *encryption, *algorithm, *accessMode);
                    });
            },
            "xyz.openbmc_project.User.Manager", "/xyz/openbmc_project/user",
            "xyz.openbmc_project.User.Manager", "CreateUser",
            username, userGroups, dbusChannelPrivileges, dbusChannelAccess, enabled);
    }
    // Case 2: Regular user creation without SNMP
    else if (!roleId.empty() && !encryption && !algorithm && !accessMode)
    {
        if (!addGroupsToUser(userGroups))
        {
            return;
        }

        crow::connections::systemBus->async_method_call(
            [=](const boost::system::error_code& ec1, sdbusplus::message_t& m1) {
                processAfterCreateUser(asyncResp, username, password, ec1, m1, passwordChangeRequired);
            },
            "xyz.openbmc_project.User.Manager", "/xyz/openbmc_project/user",
            "xyz.openbmc_project.User.Manager", "CreateUser",
            username, userGroups, dbusChannelPrivileges, dbusChannelAccess, enabled);
    }

    //setting SMTPMailID if provided during user creation
    if (smtpMailId.has_value())
    {
        setSMTPMailId(asyncResp, username, *smtpMailId);
    }
}

inline void validateChannelPrivilegesCreateUser(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& username, const std::string& password,
    std::optional<std::string> roleIdJson, bool enabled,
    std::optional<std::vector<std::string>> accountTypes,
    std::optional<bool> passwordChangeRequired,
    std::optional<std::string> algorithm, std::optional<std::string> encryption,
    std::optional<std::string> accessMode,
    std::optional<bool> hasSNMP, nlohmann::json userChannelPrivileges,
    std::optional<std::string> smtpMailId)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp, username, password, roleIdJson, enabled,
            accountTypes, passwordChangeRequired, algorithm, encryption, accessMode, hasSNMP, userChannelPrivileges, smtpMailId](const boost::system::error_code& ec, const std::map<uint8_t, std::string>& channelMap) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("D-Bus Method GetChannelInterfaceMap Response Error: {}", ec);
                return;
            }

            bool validChannelPrivFlag = true;
            std::vector<std::string> dbusChannelPrivileges;
            std::vector<uint8_t> dbusChannelAccess;
            const std::set<std::string> validChannelPrivileges = {
                "Administrator",
                "Operator",
                "ReadOnly"
            };
            nlohmann::json channelIds = nlohmann::json::array();
            nlohmann::json defaultChannelId = 0;
            bool defaultChannelFlag = false;
            for (const auto& [channel, interface] : channelMap)
            {
                if (!defaultChannelFlag)
                {
                    defaultChannelId = channel;
                    defaultChannelFlag = true;
                }

                channelIds.push_back(channel);
            }
            if (!userChannelPrivileges.is_array())
            {
                messages::propertyValueError(asyncResp->res, "ChannelPrivileges");
                validChannelPrivFlag = false;
            }
            else
            {
                if (channelIds.size() > userChannelPrivileges.size())
                {
                    messages::arraySizeTooShort(asyncResp->res, "#/Oem/Ami/ChannelPrivileges", channelIds.size());
                    validChannelPrivFlag = false;
                }
                else if (channelIds.size() < userChannelPrivileges.size())
                {
                    messages::arraySizeTooLong(asyncResp->res, "#/Oem/Ami/ChannelPrivileges", channelIds.size());
                    validChannelPrivFlag = false;
                }
                else
                {
                    std::unordered_set<int> uniqueChannelIds;
                    for (std::size_t i = 0; i < userChannelPrivileges.size(); ++i)
                    {
                        const auto& entry = userChannelPrivileges[i];

                        if (!entry.contains("ChannelId"))
                        {
                            messages::createFailedMissingReqProperties(asyncResp->res, "#/Oem/Ami/ChannelPrivileges/" + std::to_string(i) + "/ChannelId");
                            validChannelPrivFlag = false;
                        }
                        else if (!entry["ChannelId"].is_number())
                        {
                            messages::propertyValueError(asyncResp->res, "#/Oem/Ami/ChannelPrivileges/" + std::to_string(i) + "/ChannelId");
                            validChannelPrivFlag = false;
                        }
                        else if (std::find(channelIds.begin(), channelIds.end(), entry["ChannelId"]) == channelIds.end())
                        {
                            messages::propertyValueOutOfRange(asyncResp->res, entry["ChannelId"], "#/Oem/Ami/ChannelPrivileges/" + std::to_string(i) + "/ChannelId");
                            validChannelPrivFlag = false;
                        }

                        int channelId = entry["ChannelId"].get<int>();
                        if (!uniqueChannelIds.insert(channelId).second)
                        {
                            messages::propertyDuplicate(asyncResp->res, "#/Oem/Ami/ChannelPrivileges/" + std::to_string(i) + "/ChannelId");
                            validChannelPrivFlag = false;
                        }

                        if (!entry.contains("ChannelPrivilege"))
                        {
                            messages::createFailedMissingReqProperties(asyncResp->res, "#/Oem/Ami/ChannelPrivileges/" + std::to_string(i) + "/ChannelPrivilege");
                            validChannelPrivFlag = false;
                        }
                        else if (!entry["ChannelPrivilege"].is_string())
                        {
                            messages::propertyValueError(asyncResp->res, "#/Oem/Ami/ChannelPrivileges/" + std::to_string(i) + "/ChannelPrivilege");
                            validChannelPrivFlag = false;
                        }
                        else if (validChannelPrivileges.find(entry["ChannelPrivilege"]) == validChannelPrivileges.end())
                        {
                            messages::propertyValueNotInList(asyncResp->res, entry["ChannelPrivilege"], "#/Oem/Ami/ChannelPrivileges/" + std::to_string(i) + "/ChannelPrivilege");
                            validChannelPrivFlag = false;
                        }
                        if (!entry.contains("ChannelAccess"))
                        {
                            messages::createFailedMissingReqProperties(asyncResp->res, "#/Oem/Ami/ChannelPrivileges/" + std::to_string(i) + "/ChannelAccess");
                            validChannelPrivFlag = false;
                        }
                        else if (!entry["ChannelAccess"].is_boolean())
                        {
                            messages::propertyValueError(asyncResp->res, "#/Oem/Ami/ChannelPrivileges/" + std::to_string(i) + "/ChannelAccess");
                            validChannelPrivFlag = false;
                        }
                        if (entry.contains("ChannelId") && entry["ChannelId"] == defaultChannelId)
                        {
                            if (entry.contains("ChannelPrivilege") && entry["ChannelPrivilege"] != roleIdJson)
                            {
                                messages::propertyValueConflict(asyncResp->res, "RoleId", "#/Oem/Ami/ChannelPrivileges/" + std::to_string(i) + "/ChannelPrivilege");
                                validChannelPrivFlag = false;
                            }
                        }
                    }
                    if(validChannelPrivFlag)
                    {
                        for (const auto& [channel, interface] : channelMap)
                        {
                            for (const auto& entry : userChannelPrivileges)
                            {
                                // Use auto for get<> result if the compiler is being strict
                                auto channelId = entry["ChannelId"].get<uint8_t>();
                                if (channelId == channel)
                                {
                                    std::string_view channelPriv = entry["ChannelPrivilege"].get<std::string>();
                                    std::string dbusChannelPriv = getPrivilegeFromRoleId(channelPriv);
                                    bool channelAccess = entry["ChannelAccess"].get<bool>();

                                    dbusChannelPrivileges.emplace_back(dbusChannelPriv);
                                    dbusChannelAccess.emplace_back(static_cast<uint8_t>(channelAccess));
                                    break;
                                }
                            }
                        }

                        for (const auto& priv : dbusChannelPrivileges)
                        {
                            std::cout << "Privilege: " << priv << std::endl;
                        }

                        for (const auto& access : dbusChannelAccess)
                        {
                            std::cout << "Access: " << static_cast<int>(access) << std::endl;
                        }

                        // User doesn't exist, proceed with user creation
                        dbus::utility::getProperty<std::vector<std::string>>(
                            "xyz.openbmc_project.User.Manager", "/xyz/openbmc_project/user",
                            "xyz.openbmc_project.User.Manager", "AllGroups",
                            [asyncResp, username, password, roleIdJson, enabled,
                            accountTypes, passwordChangeRequired, algorithm, encryption, accessMode, hasSNMP, dbusChannelPrivileges, dbusChannelAccess, smtpMailId]
                            (const boost::system::error_code& ec1, const std::vector<std::string>& allGroupsList) {
                                if (ec1) {
                                    BMCWEB_LOG_DEBUG("D-Bus response error {}", ec1);
                                    messages::internalError(asyncResp->res);
                                    return;
                                }
                                if (allGroupsList.empty()) {
                                    messages::internalError(asyncResp->res);
                                    return;
                                }

                                processAfterGetAllGroups(asyncResp, username, password, roleIdJson,
                                    enabled, accountTypes, allGroupsList,
                                    passwordChangeRequired,
                                    algorithm, encryption, accessMode, hasSNMP, dbusChannelPrivileges, dbusChannelAccess, smtpMailId);
                            }
                        );
                    }
                }
            }
        },
        "xyz.openbmc_project.User.Manager", // Service
        "/xyz/openbmc_project/user", // Object path
        "xyz.openbmc_project.User.AccountPolicy", // Interface
        "GetChannelInterfaceMap" // Method name
    );
}

inline void handleAccountCollectionPost(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    std::string username;
    std::string password;
    std::string roleIdJson;
    std::optional<bool> enabledJson;
    std::optional<std::vector<std::string>> accountTypes;
    std::optional<bool> passwordChangeRequired = false;
    std::optional<std::string> algorithm;
    std::optional<std::string> encryption;
    std::optional<std::string> accessMode;
    std::optional<std::string> smtpMailId;
    nlohmann::json oemObj;
    std::optional<bool> hasSNMP;

    if (!json_util::readJsonPatch(
            req, asyncResp->res,
            "UserName", username,
            "Password", password,
            "RoleId", roleIdJson,
            "Enabled", enabledJson,
            "AccountTypes", accountTypes,
            "PasswordChangeRequired", passwordChangeRequired,
            "Oem", oemObj))
    {
        BMCWEB_LOG_ERROR("Failed to read required fields from JSON");
        return;
    }

    std::string user_name(username);

    if (!std::regex_match(user_name.c_str(),
                                std::regex("^[a-zA-Z_][a-zA-Z0-9_.]{0,15}$")))
    {
         BMCWEB_LOG_ERROR("username:{} is not valid",username);
         messages::propertyValueFormatError(asyncResp->res, username,
                                                   "UserName");
         return;
    }


    bool enabled = enabledJson.value_or(true);
    if (oemObj.is_object())
    {
        nlohmann::json ami;
        std::size_t oemObj_size = oemObj.size();
        if (oemObj_size == 0)
        {
            messages::propertyNotWritable(asyncResp->res, "Oem");
            return;
        }
        if (!json_util::readJson(oemObj, asyncResp->res, "Ami", ami))
        {
            return;
        }

        if (ami.is_object())
        {
            std::optional<nlohmann::json> snmp;
            nlohmann::json userChannelPrivileges;
            std::optional<nlohmann::json> smtp;

            std::size_t ami_size = ami.size();
            if (ami_size == 0)
            {
                messages::propertyNotWritable(asyncResp->res, "Ami");
                return;
            }
            if (!json_util::readJson(ami, asyncResp->res, "ChannelPrivileges", userChannelPrivileges, "SNMP", snmp, "SMTP", smtp))
            {
                BMCWEB_LOG_DEBUG("ChannelPrivileges/SNMP/SMTP attribute is missing in Oem -> Ami attribute. \n");
            }

            if (snmp)
            {
                if (snmp->empty())
                {
                    messages::propertyNotWritable(asyncResp->res, "SNMP");
                    return;
                }
                if (!json_util::readJson(*snmp, asyncResp->res,
                                         "Algorithm", algorithm,
                                         "Encryption", encryption,
                                         "Access", accessMode,
                                         "SNMPAccessEnableStatus", hasSNMP))
                {
                    return;
                }
                if (!hasSNMP.has_value())
                {
                    messages::propertyMissing(asyncResp->res, "SNMPAccessEnableStatus");
                    return;
                }
                if (accessMode && !accessMode->empty())
                {
                    std::string mode = getModeFromAccessMode(*accessMode);
                    if (mode.empty())
                    {
                        messages::propertyValueNotInList(asyncResp->res, *accessMode, "Access");
                        return;
                    }
                    accessMode = mode;
                }
                if (encryption && !encryption->empty())
                {
                    if (*encryption != "AES" && *encryption != "DES")
                    {
                        messages::propertyValueNotInList(asyncResp->res, *encryption, "Encryption");
                        return;
                    }
                }
                if (algorithm && !algorithm->empty())
                {
                    if (*algorithm != "SHA-224" && *algorithm != "SHA-256" &&
                        *algorithm != "SHA-512" && *algorithm != "SHA-384")
                    {
                        messages::propertyValueNotInList(asyncResp->res, *algorithm, "Algorithm");
                        return;
                    }
                }

                if ((accessMode || encryption || algorithm) && hasSNMP.has_value() && hasSNMP.value() == false)
                {
                    nlohmann::json hasSNMPJson = nlohmann::json(*hasSNMP);
                    messages::propertyValueIncorrect(asyncResp->res, "SNMPAccessEnableStatus", hasSNMPJson);
                    return;
                }
            }
            if(smtp)
            {
                if (smtp->empty())
                {
                    messages::propertyNotWritable(asyncResp->res, "SMTP");
                    return;
                }
                if (!json_util::readJson(*smtp, asyncResp->res,
                                         "SMTPMailId", smtpMailId))
                {
                    return;
                }
                if (!smtpMailId.has_value())
                {
                    messages::propertyMissing(asyncResp->res, "SMTPMailId");
                    return;
                }
            }
            if (userChannelPrivileges.is_array() && !userChannelPrivileges.empty())
            {
                validateChannelPrivilegesCreateUser(asyncResp, username, password, roleIdJson,
                    enabled, accountTypes, passwordChangeRequired,
                    algorithm, encryption, accessMode, hasSNMP, userChannelPrivileges, smtpMailId);
            }
        }
    }

}

inline void fetchSnmpUserData(const std::string& accountName, const std::shared_ptr<bmcweb::AsyncResp>& asyncResp) {


    sdbusplus::message::object_path tempObjPath(snmpUserDbusPath);
    tempObjPath /= accountName;
    const std::string objPath(tempObjPath);

    const boost::urls::url objSNMPPath = boost::urls::format("{}", objPath);

    dbus::utility::getAllProperties(
        "xyz.openbmc_project.Snmp.Conf", objSNMPPath.data(), "xyz.openbmc_project.Snmp.UserManager",
        [asyncResp](const boost::system::error_code& ec,
            const dbus::utility::DBusPropertiesMap& propertiesList) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("Error fetching DBus properties: {}", ec.message());
                return;
            }

            const std::string* algorithm = nullptr;
            const std::string* encryption = nullptr;
            const std::string* permission = nullptr;

            const bool success = sdbusplus::unpackPropertiesNoThrow(
                dbus_utils::UnpackErrorPrinter(), propertiesList,
                "Algorithm", algorithm,
                "Encryption", encryption,
                "ReadWritePermission", permission);

            if (!success)
            {
                BMCWEB_LOG_ERROR("Failed to unpack properties for SNMP user data.");
                messages::internalError(asyncResp->res);
                return;
            }

            if (algorithm != nullptr)
            {
                asyncResp->res.jsonValue["Oem"]["Ami"]["SNMP"]["Algorithm"] = *algorithm;
            }

            if (encryption != nullptr)
            {
                asyncResp->res.jsonValue["Oem"]["Ami"]["SNMP"]["Encryption"] = *encryption;
            }

            if (permission != nullptr)
            {
                std::string mode = getAccessModeFromMode(*permission);
                if (mode.empty())
                {
                    messages::propertyValueNotInList(asyncResp->res, *permission, "Access");
                    return;
                }
                asyncResp->res.jsonValue["Oem"]["Ami"]["SNMP"]["Access"] = mode;
            }

        });
}

inline void handleAccountHead(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& accountName)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (accountName == "root")
    {
        //remove the delete method from allow header
        asyncResp->res.clearHeader(boost::beast::http::field::allow);
        asyncResp->res.addHeader(boost::beast::http::field::allow, "GET, HEAD, PATCH");
    }
    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/ManagerAccount/ManagerAccount.json>; rel=describedby");
}

inline void handleAccountGet(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& accountName)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (membersResponsePost(req, asyncResp, accountName) ==
        membersResponse::postNotAllowed)
    {
        return;
    }
    asyncResp->res.addHeader("Allow", "GET, HEAD, PATCH, DELETE");
    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/ManagerAccount/ManagerAccount.json>; rel=describedby");

    if constexpr (BMCWEB_INSECURE_DISABLE_AUTH)
    {
        // If authentication is disabled, there are no user accounts
        messages::resourceNotFound(asyncResp->res, "ManagerAccount",
                                   accountName);
        return;
    }

    if (req.session == nullptr)
    {
        messages::internalError(asyncResp->res);
        return;
    }
    if (accountName == "root")
    {
        //remove the delete method from allow header
        asyncResp->res.clearHeader(boost::beast::http::field::allow);
        asyncResp->res.addHeader(boost::beast::http::field::allow, "GET, HEAD, PATCH");
    }
    
    // Check privileges before making D-Bus call
    bool hasPrivilege = false;
    if (req.session->username == accountName)
    {
        hasPrivilege = true;
    }
    else
    {
        // At this point we've determined that the user is trying to
        // access a user that isn't them.  We need to verify that they
        // have permissions to access other users, so re-run the auth
        // check with the same permissions, minus ConfigureSelf.
        Privileges effectiveUserPrivileges =
            redfish::getUserPrivileges(*req.session);
        Privileges requiredPermissionsToChangeNonSelf = {"ConfigureUsers",
                                                         "ConfigureManager"};
        if (effectiveUserPrivileges.isSupersetOf(
                requiredPermissionsToChangeNonSelf))
        {
            hasPrivilege = true;
        }
    }
    
    if (!hasPrivilege)
    {
        BMCWEB_LOG_DEBUG("GET Account denied access");
        messages::insufficientPrivilege(asyncResp->res);
        return;
    }

    sdbusplus::message::object_path path("/xyz/openbmc_project/user");
    dbus::utility::getManagedObjects(
        "xyz.openbmc_project.User.Manager", path,
        [asyncResp,
         accountName, req](const boost::system::error_code& ec,
                      const dbus::utility::ManagedObjectType& users) {
            if (ec)
            {
                messages::internalError(asyncResp->res);
                return;
            }
            const auto userIt = std::ranges::find_if(
                users,
                [accountName](
                    const std::pair<sdbusplus::message::object_path,
                                    dbus::utility::DBusInterfacesMap>& user) {
                    return accountName == user.first.filename();
                });

            if (userIt == users.end())
            {
                messages::resourceNotFound(asyncResp->res, "ManagerAccount",
                                           accountName);
                return;
            }

            asyncResp->res.jsonValue["@odata.type"] = json_util::odataType("ManagerAccount");
            asyncResp->res.jsonValue["Name"] = "User Account";
            asyncResp->res.jsonValue["Description"] = "User Account";
            asyncResp->res.jsonValue["Password"] = nullptr;
            asyncResp->res.jsonValue["StrictAccountTypes"] = true;

            for (const auto& interface : userIt->second)
            {
                if (interface.first == "xyz.openbmc_project.User.Attributes")
                {
                    const bool* userEnabled = nullptr;
                    const bool* userLocked = nullptr;
                    const bool* userPasswordExpired = nullptr;
                    const std::vector<std::string>* userGroups = nullptr;
                    std::vector<std::string> userPrivileges;
                    std::vector<uint8_t> userChannelAccess;
                    const bool* snmpAccessEnableStatus = nullptr;
                    const std::string* smtpMailId = nullptr;
                    const bool success = sdbusplus::unpackPropertiesNoThrow(
                        dbus_utils::UnpackErrorPrinter(), interface.second,
                        "UserEnabled", userEnabled, "UserChannelAccess", userChannelAccess,
                        "UserLockedForFailedAttempt", userLocked,
                        "UserPrivilege", userPrivileges, "UserPasswordExpired",
                        userPasswordExpired, "UserGroups", userGroups, 
                        "SNMPAccessEnableStatus", snmpAccessEnableStatus,
                        "SMTPMailID" , smtpMailId);
                    if (!success)
                    {
                        messages::internalError(asyncResp->res);
                        return;
                    }

                    if (userEnabled == nullptr)
                    {
                        BMCWEB_LOG_ERROR("UserEnabled wasn't a bool");
                        messages::internalError(asyncResp->res);
                        return;
                    }
                    asyncResp->res.jsonValue["Enabled"] = *userEnabled;

                    if (userLocked == nullptr)
                    {
                        BMCWEB_LOG_ERROR("UserLockedForF"
                                         "ailedAttempt "
                                         "wasn't a bool");
                        messages::internalError(asyncResp->res);
                        return;
                    }

                    asyncResp->res.jsonValue["Locked"] = *userLocked;
                    nlohmann::json::array_t allowed;
                    // can only unlock accounts
                    allowed.emplace_back("false");
                    asyncResp->res.jsonValue["Locked@Redfish.AllowableValues"] =
                        std::move(allowed);

                    if (!userPrivileges.empty())
                    {
                        std::string_view defaultUserPrivilege = userPrivileges.front();
                        std::string role = getRoleIdFromPrivilege(defaultUserPrivilege);
                        asyncResp->res.jsonValue["RoleId"] = role;
                        nlohmann::json& roleEntry =
                            asyncResp->res.jsonValue["Links"]["Role"];
                        roleEntry["@odata.id"] = boost::urls::format(
                            "/redfish/v1/AccountService/Roles/{}", role);
                    }
                    else // handle empty case
                    {

                        BMCWEB_LOG_DEBUG("UserPrivilege wasn't a vector of strings");
                        messages::internalError(asyncResp->res);
                        return;
                    }

                    if (userPasswordExpired == nullptr)
                    {
                        BMCWEB_LOG_ERROR("UserPasswordExpired wasn't a bool");
                        messages::internalError(asyncResp->res);
                        return;
                    }
                    asyncResp->res.jsonValue["PasswordChangeRequired"] =
                        *userPasswordExpired;

                    if (userGroups == nullptr)
                    {
                        BMCWEB_LOG_ERROR("userGroups wasn't a string vector");
                        messages::internalError(asyncResp->res);
                        return;
                    }

                    if (!translateUserGroup(*userGroups, asyncResp->res))
                    {
                        BMCWEB_LOG_ERROR("userGroups mapping failed");
                        messages::internalError(asyncResp->res);
                        return;
                    }

                    asyncResp->res.jsonValue["Oem"]["Ami"]["@odata.type"]= json_util::odataType("AmiManagerAccount", "ManagerAccount");

                    populateOEMAMIChannelInfo(userPrivileges, userChannelAccess, asyncResp, req);

                    if (snmpAccessEnableStatus == nullptr)
                    {
                        BMCWEB_LOG_ERROR("SNMPAccessEnableStatus wasn't a bool");
                        messages::internalError(asyncResp->res);
                        return;
                    }
                    asyncResp->res.jsonValue["Oem"]["Ami"]["SNMP"]["SNMPAccessEnableStatus"] = *snmpAccessEnableStatus;

                    if (*snmpAccessEnableStatus) {
                        fetchSnmpUserData(accountName, asyncResp);
                    }

                    if (smtpMailId == nullptr)
                    {
                        BMCWEB_LOG_ERROR("SMTPMailId wasn't a string");
                        messages::internalError(asyncResp->res);
                        return;
                    }
                    asyncResp->res.jsonValue["Oem"]["Ami"]["SMTP"]["SMTPMailId"] = *smtpMailId;
                        
                }
            }

            asyncResp->res.jsonValue["@odata.id"] = boost::urls::format(
                "/redfish/v1/AccountService/Accounts/{}", accountName);
            asyncResp->res.jsonValue["Id"] = accountName;
            asyncResp->res.jsonValue["UserName"] = accountName;
        });
}

inline void handleAccountDelete(App& app, const crow::Request& req,
                    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                    const std::string& username)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (membersResponsePost(req, asyncResp, username) ==
        membersResponse::postNotAllowed)
    {
        return;
    }
    if constexpr (BMCWEB_INSECURE_DISABLE_AUTH)
    {
        messages::resourceNotFound(asyncResp->res, "ManagerAccount", username);
        return;
    }

    sdbusplus::message::object_path tempObjPath(rootUserDbusPath);
    tempObjPath /= username;
    const std::string userPath(tempObjPath);

    sdbusplus::message::object_path tempObjPathSnmp(snmpUserDbusPath);
    tempObjPathSnmp /= username;
    const std::string userSNMPPath(tempObjPathSnmp);

  // Check if the username is "root"
    if (username == "root")
    {
        //remove the delete method from allow header
        asyncResp->res.addHeader(boost::beast::http::field::allow, "GET, HEAD, PATCH");
        messages::resourceCannotBeDeleted(asyncResp->res);
        return;
    }

    sdbusplus::message::object_path path("/xyz/openbmc_project/snmp/UserManager");

    dbus::utility::getManagedObjects(
        "xyz.openbmc_project.Snmp.Conf", path,
        [asyncResp, username, userPath, userSNMPPath](const boost::system::error_code& ec,
                    const dbus::utility::ManagedObjectType& resp)
        {
            bool hasSNMPuserPath = false;

            if (!ec)
            {
                for (const auto& objectPath : resp)
                {
                    if (objectPath.first == "/xyz/openbmc_project/snmp/UserManager/" + username)
                    {
                        hasSNMPuserPath = true;
                        break;
                    }
                }
            }

            auto deleteUserManagerAccount = [asyncResp, username, userPath]() {
                crow::connections::systemBus->async_method_call(
                    [asyncResp, username](const boost::system::error_code& ec) {
                        if (ec)
                        {
                            messages::resourceNotFound(asyncResp->res, "ManagerAccount", username);
                            return;
                        }

                        messages::accountRemoved(asyncResp->res);
                        std::string eventLogMessageId =
                            "ResourceRemoved:/redfish/v1/AccountService/Accounts/" + username;
                        EventServiceManager::getInstance().resourceCreationDeletion(eventLogMessageId);
                    },
                    "xyz.openbmc_project.User.Manager", userPath,
                    "xyz.openbmc_project.Object.Delete", "Delete");
            };

            if (hasSNMPuserPath)
            {
                crow::connections::systemBus->async_method_call(
                    [asyncResp, username, deleteUserManagerAccount](const boost::system::error_code& ec) {
                        if (ec)
                        {
                            messages::resourceNotFound(asyncResp->res, "ManagerAccount", username);
                            return;
                        }

                        deleteUserManagerAccount();
                    },
                    "xyz.openbmc_project.Snmp.Conf", userSNMPPath,
                    "xyz.openbmc_project.Object.Delete", "Delete");
            }
            else
            {
                // No SNMP user, proceed directly
                deleteUserManagerAccount();
            }
        });
}

inline void validateChannelPrivilegesUpdateUser(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp, const std::string& userName,
    const std::string& originalRoleId, std::optional<const std::string> modifiedRoleId, nlohmann::json userChannelPrivileges,
    std::optional<std::vector<std::string>> accountTypes)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp, userName, originalRoleId, modifiedRoleId, userChannelPrivileges,accountTypes](const boost::system::error_code& ec, const std::map<uint8_t, std::string>& channelMap) {
            // Check if an error has already occurred before processing
            if (asyncResp->res.result() != boost::beast::http::status::ok)
            {
                BMCWEB_LOG_ERROR("Skipping channel privileges update - error already set, status: {}", 
                    static_cast<unsigned>(asyncResp->res.result()));
                return;
            }
            
            if (ec)
            {
                BMCWEB_LOG_DEBUG("D-Bus Method GetChannelInterfaceMap Response Error: {}", ec);
                return;
            }
            sdbusplus::message::object_path tempObjPath(rootUserDbusPath);
            tempObjPath /= userName;
            const std::string userPath(tempObjPath);
            sdbusplus::asio::getProperty<std::vector<std::string>>(
            *crow::connections::systemBus,
            "xyz.openbmc_project.User.Manager",
            userPath,
            "xyz.openbmc_project.User.Attributes", "UserGroups",
            [asyncResp, userName, originalRoleId, modifiedRoleId, userChannelPrivileges, channelMap, accountTypes](const boost::system::error_code& ec1, const std::vector<std::string>& userGroups) {
                // Check if an error has already occurred before processing
                if (asyncResp->res.result() != boost::beast::http::status::ok)
                {
                    BMCWEB_LOG_ERROR("Skipping UserGroups processing in channel privileges - error already set, status: {}", 
                        static_cast<unsigned>(asyncResp->res.result()));
                    return;
                }
                
                if (ec1)
                {
                    BMCWEB_LOG_DEBUG("D-Bus response error {}", ec1);
                    return;
                }

            bool validChannelPrivFlag = true;
            std::vector<std::string> dbusChannelPrivileges;
            std::vector<uint8_t> dbusChannelAccess;
            const std::set<std::string> validChannelPrivileges = {
                "Administrator",
                "Operator",
                "ReadOnly"
            };
            nlohmann::json channelIds = nlohmann::json::array();
            nlohmann::json defaultChannelId = 0;
            bool defaultChannelFlag = false;
            for (const auto& [channel, interface] : channelMap)
            {
                if (!defaultChannelFlag)
                {
                    defaultChannelId = channel;
                    defaultChannelFlag = true;
                }

                channelIds.push_back(channel);
            }
            if (!userChannelPrivileges.is_array())
            {
                messages::propertyValueError(asyncResp->res, "ChannelPrivileges");
                validChannelPrivFlag = false;
            }
            else
            {
                if (channelIds.size() > userChannelPrivileges.size())
                {
                    messages::arraySizeTooShort(asyncResp->res, "#/Oem/Ami/ChannelPrivileges", channelIds.size());
                    validChannelPrivFlag = false;
                }
                else if (channelIds.size() < userChannelPrivileges.size())
                {
                    messages::arraySizeTooLong(asyncResp->res, "#/Oem/Ami/ChannelPrivileges", channelIds.size());
                    validChannelPrivFlag = false;
                }
                else
                {
                    std::unordered_set<int> uniqueChannelIds;
                    for (std::size_t i = 0; i < userChannelPrivileges.size(); ++i)
                    {
                        const auto& entry = userChannelPrivileges[i];

                        if (!entry.contains("ChannelId"))
                        {
                            messages::createFailedMissingReqProperties(asyncResp->res, "#/Oem/Ami/ChannelPrivileges/" + std::to_string(i) + "/ChannelId");
                            validChannelPrivFlag = false;
                        }
                        else if (!entry["ChannelId"].is_number())
                        {
                            messages::propertyValueError(asyncResp->res, "#/Oem/Ami/ChannelPrivileges/" + std::to_string(i) + "/ChannelId");
                            validChannelPrivFlag = false;
                        }
                        else if (std::find(channelIds.begin(), channelIds.end(), entry["ChannelId"]) == channelIds.end())
                        {
                            messages::propertyValueOutOfRange(asyncResp->res, entry["ChannelId"], "#/Oem/Ami/ChannelPrivileges/" + std::to_string(i) + "/ChannelId");
                            validChannelPrivFlag = false;
                        }
                        int channelId = entry["ChannelId"].get<int>();
                        if (!uniqueChannelIds.insert(channelId).second)
                        {
                            messages::propertyDuplicate(asyncResp->res, "#/Oem/Ami/ChannelPrivileges/" + std::to_string(i) + "/ChannelId");
                            validChannelPrivFlag = false;
                        }
                        if (!entry.contains("ChannelPrivilege"))
                        {
                            messages::createFailedMissingReqProperties(asyncResp->res, "#/Oem/Ami/ChannelPrivileges/" + std::to_string(i) + "/ChannelPrivilege");
                            validChannelPrivFlag = false;
                        }
                        else if (!entry["ChannelPrivilege"].is_string())
                        {
                            messages::propertyValueError(asyncResp->res, "#/Oem/Ami/ChannelPrivileges/" + std::to_string(i) + "/ChannelPrivilege");
                            validChannelPrivFlag = false;
                        }
                        else if (validChannelPrivileges.find(entry["ChannelPrivilege"]) == validChannelPrivileges.end())
                        {
                            messages::propertyValueNotInList(asyncResp->res, entry["ChannelPrivilege"], "#/Oem/Ami/ChannelPrivileges/" + std::to_string(i) + "/ChannelPrivilege");
                            validChannelPrivFlag = false;
                        }
                        if (!entry.contains("ChannelAccess"))
                        {
                            messages::createFailedMissingReqProperties(asyncResp->res, "#/Oem/Ami/ChannelPrivileges/" + std::to_string(i) + "/ChannelAccess");
                            validChannelPrivFlag = false;
                        }
                        else if (!entry["ChannelAccess"].is_boolean())
                        {
                            messages::propertyValueError(asyncResp->res, "#/Oem/Ami/ChannelPrivileges/" + std::to_string(i) + "/ChannelAccess");
                            validChannelPrivFlag = false;
                        }
                        if (entry.contains("ChannelId") && entry["ChannelId"] == defaultChannelId)
                        {
                            if (entry.contains("ChannelPrivilege") && ((modifiedRoleId && entry["ChannelPrivilege"] != *modifiedRoleId) || (!modifiedRoleId && entry["ChannelPrivilege"] != originalRoleId))) // If the default Channel Privilege doesn't match the Current RoleId or the Desired RoleId, we need to throw error.
                            {
                                messages::propertyValueConflict(asyncResp->res, "RoleId", "#/Oem/Ami/ChannelPrivileges/" + std::to_string(i) + "/ChannelPrivilege");
                                validChannelPrivFlag = false;
                            }
                        }

                        if (accountTypes)
                        {
                            std::string roleToValidate;
                            if (modifiedRoleId)
                            {
                                roleToValidate = *modifiedRoleId;
                            }
                            else
                            {
                                roleToValidate = originalRoleId;
                            }

                            if (roleToValidate != "Administrator")
                            {
                                // For non-admin users, AccountTypes must NOT contain
                                // HostConsole or ManagerConsole.
                                const auto& types = *accountTypes;
                                bool hasHostConsole = (std::find(types.begin(), types.end(), "HostConsole") != types.end());
                                bool hasManagerConsole = (std::find(types.begin(), types.end(), "ManagerConsole") != types.end());
                                if (hasHostConsole || hasManagerConsole)
                                {
                                    messages::propertyValueConflict(asyncResp->res, roleToValidate, "AccountTypes");
                                    return;
                                }
                            }
                        }
                        else
                        {
                            BMCWEB_LOG_ERROR("AccountTypes not provided for validation.");
                            BMCWEB_LOG_ERROR("Validating AccountTypes for non-admin user based on UserGroups");
                            for (const auto& groups : userGroups)
                            {
                                if ((groups == "hostconsole") || (groups == "ssh"))
                                {
                                    // For non-admin users, presence of these account types is forbidden.
                                    std::string roleToValidate;
                                    if (modifiedRoleId)
                                    {
                                        roleToValidate = *modifiedRoleId;
                                    }
                                    else
                                    {
                                        roleToValidate = originalRoleId;
                                    }

                                    if (roleToValidate != "Administrator")
                                    {
                                        messages::propertyValueConflict(asyncResp->res, roleToValidate, "AccountTypes");
                                        return;
                                    }
                                }
                            }
                        }

                    }

                    if(validChannelPrivFlag)
                    {
                        BMCWEB_LOG_DEBUG("Going to populate dbusChannelPrivileges & dbusChannelAccess");
                        for (const auto& [channel, interface] : channelMap)
                        {
                            for (const auto& entry : userChannelPrivileges)
                            {
                                // Use auto for get<> result if the compiler is being strict
                                auto channelId = entry["ChannelId"].get<uint8_t>();
                                if (channelId == channel)
                                {
                                    std::string_view channelPriv = entry["ChannelPrivilege"].get<std::string>();
                                    std::string dbusChannelPriv = getPrivilegeFromRoleId(channelPriv);
                                    bool channelAccess = entry["ChannelAccess"].get<bool>();

                                    dbusChannelPrivileges.emplace_back(dbusChannelPriv);
                                    dbusChannelAccess.emplace_back(static_cast<uint8_t>(channelAccess));
                                    break;
                                }
                            }
                        }

                        for (const auto& priv : dbusChannelPrivileges)
                        {
                            std::cout << "Privilege: " << priv << std::endl;
                        }

                        for (const auto& access : dbusChannelAccess)
                        {
                            std::cout << "Access: " << static_cast<int>(access) << std::endl;
                        }

                        sdbusplus::message::object_path tempObjPath(rootUserDbusPath);
                        tempObjPath /= userName;
                        const std::string userPath(tempObjPath);

                        sdbusplus::asio::setProperty(
                            *crow::connections::systemBus, "xyz.openbmc_project.User.Manager",
                            userPath, "xyz.openbmc_project.User.Attributes", "UserPrivilege",
                            dbusChannelPrivileges,
                            [asyncResp, userName, userPath, dbusChannelAccess](const boost::system::error_code& ec1)
                            {
                                if (ec1)
                                {
                                    BMCWEB_LOG_DEBUG("Failed to set UserPrivilege for {} : {}", userName, ec1.message());
                                    return;
                                }

                                sdbusplus::asio::setProperty(
                                    *crow::connections::systemBus, "xyz.openbmc_project.User.Manager",
                                    userPath, "xyz.openbmc_project.User.Attributes", "UserChannelAccess",
                                    dbusChannelAccess,
                                    [asyncResp, userName](const boost::system::error_code& ec2)
                                    {
                                        if (ec2)
                                        {
                                            BMCWEB_LOG_DEBUG("Failed to set UserChannelAccess for {} : {}", userName, ec2.message());
                                            return;
                                        }
                                    }
                                );
                            }
                        );
                    }
                }
            }
        });
        },
        "xyz.openbmc_project.User.Manager", // Service
        "/xyz/openbmc_project/user", // Object path
        "xyz.openbmc_project.User.AccountPolicy", // Interface
        "GetChannelInterfaceMap" // Method name
    );
}

inline void handleSNMPOEMProperties(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                                    const std::string& originalRoleId, const std::optional<const std::string>& modifiedRoleId,
                                    std::optional<nlohmann::json> oemObj,
                                    std::optional<std::string> algorithm,
                                    std::optional<std::string> encryption,
                                    std::optional<std::string> accessMode,
                                    std::optional<std::string> smtpMailId,
                                    std::optional<bool>& hasSNMP,
                                    const std::string& username,
                                    std::optional<std::string> password,
                                    std::optional<std::vector<std::string>> accountTypes)
{
    std::optional<nlohmann::json> ami;

    if (!oemObj || oemObj->empty())
    {
        messages::propertyNotWritable(asyncResp->res, "Oem");
        return;
    }
    if (!json_util::readJson(*oemObj, asyncResp->res, "Ami", ami))
    {
        return;
    }

    if (!ami || ami->empty())
    {
        messages::propertyNotWritable(asyncResp->res, "Ami");
        return;
    }

    std::optional<nlohmann::json> snmp;
    std::optional<nlohmann::json> channelPrivileges;
    std::optional<nlohmann::json> smtp;
   
    if (!json_util::readJson( *ami, asyncResp->res, "ChannelPrivileges" , channelPrivileges, "SNMP", snmp, "SMTP", smtp))
    {
        return;
    }
    if(channelPrivileges)
    {
        if (username == "root")
        {
            BMCWEB_LOG_DEBUG("Not allowed to change Channel Privileges for root user !!");
            const std::string& arg =
                "redfish/v1/AccountService/Accounts/" + username;
            setErrorMessageId(asyncResp, "AccessDenied", boost::urls::format(arg));
            return;
        }

        nlohmann::json userChannelPrivileges = *channelPrivileges;
        validateChannelPrivilegesUpdateUser(asyncResp, username, originalRoleId, modifiedRoleId, userChannelPrivileges, accountTypes);
    }
    if (snmp && snmp->is_object() && snmp->empty())
    {
        messages::propertyNotWritable(asyncResp->res, "SNMP");
        return;
    }
    if (snmp && snmp->is_object() && !snmp->empty())
    {
        if (!json_util::readJson(*snmp, asyncResp->res,
                                "Algorithm", algorithm,
                                "Encryption", encryption,
                                "Access", accessMode,
                                "SNMPAccessEnableStatus", hasSNMP))
        {
            BMCWEB_LOG_DEBUG("Failed to read SNMP properties from SNMP JSON:");
            return;
        }

        // Use default values for missing fields
        std::string defaultAlgorithm = "default_algorithm";
        std::string defaultEncryption = "default_encryption";
        std::string defaultAccessMode = "read-write";
        std::string updatedPassword = "dummy_password";

        if (!algorithm)
        {
            std::cerr << "[bmcweb] Algorithm not passed. Using default: " << defaultAlgorithm << std::endl;
            algorithm = defaultAlgorithm;
        }
        else if (algorithm && !algorithm->empty() && *algorithm != "SHA-224" && *algorithm != "SHA-256" &&
            *algorithm != "SHA-512" && *algorithm != "SHA-384")
        {
            messages::propertyValueNotInList(asyncResp->res, *algorithm, "Algorithm");
            return;
        }

        if (!encryption)
        {
            encryption = defaultEncryption;
        }
        else if (encryption && !encryption->empty() && *encryption != "AES" && *encryption != "DES")
        {
            messages::propertyValueNotInList(asyncResp->res, *encryption, "Encryption");
            return;
        }

        if (!accessMode)
        {
            accessMode = defaultAccessMode;
        }
        else if (accessMode && !accessMode->empty())
        {
            std::string mode = getModeFromAccessMode(*accessMode);
            if (mode.empty())
            {
                messages::propertyValueNotInList(asyncResp->res, *accessMode, "AccessMode");
                return;
            }
        }

        if (!password)
        {
            password = updatedPassword;
        }
        else
        {
            BMCWEB_LOG_INFO("SNMP Password is provided for user: {}", username);
        }

        // Call to fetch current SNMPAccessEnableStatus and proceed with logic
        getSNMPAccessStatus(asyncResp, username, [asyncResp, username, hasSNMP, algorithm, encryption, accessMode, password](bool currentSNMPAccessEnableStatus) {

            // Check if an error has already occurred before processing
            if (asyncResp->res.result() != boost::beast::http::status::ok)
            {
                BMCWEB_LOG_ERROR("Skipping SNMP processing - error already set, status: {}", 
                    static_cast<unsigned>(asyncResp->res.result()));
                return;
            }

            if (hasSNMP && !*hasSNMP && currentSNMPAccessEnableStatus == false)
            {
                // Clear the body before setting 204
                auto* body = asyncResp->res.body();
                if (body != nullptr)
                {
                    const_cast<std::string*>(body)->clear();
                }
                // Send No Content response as no change is required
                asyncResp->res.result(boost::beast::http::status::no_content);
                return;
            }

            handleAccountSnmpPatch(asyncResp, username, hasSNMP, algorithm, encryption, accessMode, password);
        });
    }
    if(smtp && smtp->is_object() && !smtp->empty())
    {
        if (!json_util::readJson(*smtp, asyncResp->res,
                                "SMTPMailId", smtpMailId))
        {
            BMCWEB_LOG_DEBUG("Failed to read SMTP properties from SMTP JSON");
            return;
        }
        if (!smtpMailId.has_value())
        {
            messages::propertyMissing(asyncResp->res, "SMTPMailId");
            return;
        }
        BMCWEB_LOG_DEBUG("handleSNMPOEMProperties: SMTPMailId parsed: {}", *smtpMailId);
        setSMTPMailId(asyncResp, username, *smtpMailId);
    }
}

inline void handleAccountPatch(App& app, const crow::Request& req,
                       const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                       const std::string& username)
{
    accountsTotalOperations = 0;
    accountsCompletedOperations = 0;
    propertyModified.clear();
    propertyOriginal.clear();

    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (membersResponsePost(req, asyncResp, username) ==
        membersResponse::postNotAllowed)
    {
        return;
    }
    if constexpr (BMCWEB_INSECURE_DISABLE_AUTH)
    {
        // If authentication is disabled, there are no user accounts
        messages::resourceNotFound(asyncResp->res, "ManagerAccount", username);
        return;
    }

    if (req.session == nullptr)
    {
        messages::internalError(asyncResp->res);
        return;
    }

    if (username == "root")

    {
        //remove the delete method from allow header
        asyncResp->res.addHeader(boost::beast::http::field::allow, "GET, HEAD, PATCH");
    }

    sdbusplus::message::object_path path("/xyz/openbmc_project/user");
    dbus::utility::getManagedObjects(
        "xyz.openbmc_project.User.Manager", path,
        [asyncResp, username, req](const boost::system::error_code& ec,
                              const dbus::utility::ManagedObjectType& users) {
            if (ec)
            {
                messages::internalError(asyncResp->res);
                return;
            }

            const auto userIt = std::find_if(
                users.begin(), users.end(),
                [username](
                    const std::pair<sdbusplus::message::object_path,
                                    dbus::utility::DBusInterfacesMap>& user) {
                    return username == user.first.filename();
                });
            if (userIt == users.end())
            {
                asyncResp->res.clear();
                messages::resourceNotFound(asyncResp->res, "ManagerAccount",
                                           username);
                return;
            }

            for (const auto& interface : userIt->second)
            {
                if (interface.first == "xyz.openbmc_project.User.Attributes")
                {
                    for (const auto& property : interface.second)
                    {
                        if (property.first == "UserGroups")
                        {
                            const std::vector<std::string>* userGroups =
                                std::get_if<std::vector<std::string>>(
                                    &property.second);
                            if (userGroups == nullptr)
                            {
                                BMCWEB_LOG_ERROR(
                                    "userGroups wasn't a string vector");
                                messages::internalError(asyncResp->res);
                                return;
                            }
                            else if(std::find(userGroups->begin(),userGroups->end(),"redfish-hostiface")!=userGroups->end())
                            {

                                asyncResp->res.clearHeader(boost::beast::http::field::allow);
                                asyncResp->res.addHeader("Allow", "GET, DELETE");
                                messages::operationNotAllowed(asyncResp->res);
                                return;
                            }
                        }
                    }

                }

            }

            auto hasError = std::make_shared<bool>(false);

            nlohmann::json body;
            body = nlohmann::json::parse(req.body());

            auto completionHandler = [asyncResp, hasError, username, body](bool success)
            {
                // Always increment completed operations counter, regardless of success/failure
                accountsCompletedOperations++;
                
                if (!success)
                {
                    *hasError = true;
                }
                
                if (accountsCompletedOperations == accountsTotalOperations)
                {
                    if (!(*hasError) && accountsTotalOperations == body.size())
                    {
                        EventServiceManager::getInstance().propertyModifiedEventLog(propertyModified, propertyOriginal, "/redfish/v1/AccountService/Accounts/" + username);
                    }
                    
                    // All async operations complete - now check final status
                    // If all succeeded (status is still 200 OK), change to 204 No Content
                    // Otherwise, preserve the error response set by the operations
                    if (asyncResp->res.result() == boost::beast::http::status::ok)
                    {
                        asyncResp->res.result(boost::beast::http::status::no_content);
                    }
                }
            };

            bool userSelf = (username == req.session->username);

            Privileges effectiveUserPrivileges =
                redfish::getUserPrivileges(*req.session);
            Privileges configureUsers = {"ConfigureUsers"};
            bool userHasConfigureUsers =
                effectiveUserPrivileges.isSupersetOf(configureUsers);

            std::optional<std::string> newUserName;
            std::optional<std::string> password;
            std::optional<bool> enabled;
            std::optional<std::string> roleId;
            std::optional<bool> locked;
            std::optional<std::vector<std::string>> accountTypes;
            std::optional<bool> passwordChangeRequired;
            std::optional<std::string> algorithm;
            std::optional<std::string> encryption;
            std::optional<std::string> accessMode;
            std::optional<bool> hasSNMP;
            std::optional<nlohmann::json> oemObj;
            std::string originalRoleId;
            std::optional<std::string> smtpMailId;
            
            if (userHasConfigureUsers)
            {
                if (!json_util::readJsonPatch(
                        req, asyncResp->res,
                        "UserName", newUserName,
                        "Password", password,
                        "RoleId", roleId,
                        "Enabled", enabled,
                        "Locked", locked,
                        "AccountTypes", accountTypes,
                        "PasswordChangeRequired", passwordChangeRequired,
                        "Oem", oemObj
                        ))
                {
                    return;
                }
            }
            else
            {
                // ConfigureSelf accounts can only modify their own account
                if (!userSelf)
                {
                    messages::insufficientPrivilege(asyncResp->res);
                    return;
                }

                // ConfigureSelf accounts can only modify their password
                if (!json_util::readJsonPatch(req, asyncResp->res, "Password", password))
                {
                    BMCWEB_LOG_DEBUG("User with ConfigureSelf attempting to modify restricted properties.");
                    asyncResp->res.clear();  //clear unknown properties response
                    messages::insufficientPrivilege(asyncResp->res);
                    return;
                }
            }

            const std::string& password_ref = password ? *password : "";

            for (const auto& interface : userIt->second)
            {
                if (interface.first == "xyz.openbmc_project.User.Attributes")
                {
                    const bool* userEnabled = nullptr;
                    const bool* userLocked = nullptr;
                    // const std::string* userPrivPtr = nullptr;
                    std::vector<std::string> userPrivileges;
                    std::vector<uint8_t> userChannelAccess;
                    const bool* userPasswordExpired = nullptr;
                    const std::vector<std::string>* userGroups = nullptr;

                    const bool success = sdbusplus::unpackPropertiesNoThrow(
                        dbus_utils::UnpackErrorPrinter(), interface.second,
                        "UserEnabled", userEnabled,
                        "UserLockedForFailedAttempt", userLocked,
                        "UserPrivilege", userPrivileges, "UserChannelAccess", userChannelAccess,
                        "UserPasswordExpired", userPasswordExpired,
                        "UserGroups", userGroups);
                    if (!success)
                    {
                        messages::internalError(asyncResp->res);
                        return;
                    }

                    if (userEnabled == nullptr)
                    {
                        BMCWEB_LOG_ERROR("UserEnabled wasn't a bool");
                        propertyOriginal["Enabled"] = nullptr;

                    }
                    else
                    {
                        propertyOriginal["Enabled"] = *userEnabled;
                    }

                    if (userLocked == nullptr)
                    {
                        BMCWEB_LOG_ERROR("UserLockedForF"
                                         "ailedAttempt "
                                         "wasn't a bool");
                        propertyOriginal["Locked"] = nullptr;
                    }
                    else
                    {
                        propertyOriginal["Locked"] = *userLocked;
                    }

                    if (!userPrivileges.empty())
                    {
                        std::string_view defaultUserPrivilege = userPrivileges.front();
                        std::string role = getRoleIdFromPrivilege(defaultUserPrivilege);

                        if (role.empty())
                        {
                            BMCWEB_LOG_DEBUG("Invalid user role");
                            messages::internalError(asyncResp->res);
                            return;
                        }
                        else
                        {
                            originalRoleId = role;
                        }
                        propertyOriginal["RoleId"] = role;
                    }
                    else // handle empty case
                    {

                        BMCWEB_LOG_DEBUG("UserPrivilege wasn't a vector of strings");
                        propertyOriginal["RoleId"] = nullptr;
                    }

                    if (userPasswordExpired == nullptr)
                    {
                        BMCWEB_LOG_ERROR("UserPasswordExpired wasn't a bool");
                        propertyOriginal["PasswordChangeRequired"] = nullptr;
                    }
                    else
                    {
                        propertyOriginal["PasswordChangeRequired"] =
                        *userPasswordExpired;
                    }

                    if (userGroups == nullptr)
                    {
                        BMCWEB_LOG_ERROR("userGroups wasn't a string vector");
                        propertyOriginal["AccountTypes"] = nullptr;

                    }
                    else
                    {
                        auto [ret, convertedAccountTypes] = translateUserGroupGet(*userGroups);
                        if (!ret)
                        {
                            BMCWEB_LOG_ERROR("userGroups mapping failed");
                            messages::internalError(asyncResp->res);
                            return;
                        }
                        else
                        {
                            propertyOriginal["AccountTypes"] = std::move(convertedAccountTypes);

                        }
                    }
                }
            }
            propertyOriginal["Username"] = username;
            propertyOriginal["Password"] = "*****";

            if (username != "root" && body.contains("RoleId")) // For any non root user, RoleId alone cannot be patched, we need to combine it along with the ChannelPrivileges  attribute
            {
                std::string_view roleIdView = body.at("RoleId").get_ref<const std::string&>();
                const std::string priv = getPrivilegeFromRoleId(roleIdView);
                if (priv.empty())
                {
                    messages::propertyValueNotInList(asyncResp->res, roleId ? nlohmann::json(*roleId) : nlohmann::json(nullptr), "RoleId");
                    return;
                }

                // Check if Oem → Ami → ChannelPrivileges is missing
                if (!body.contains("Oem") || !body["Oem"].contains("Ami") || !body["Oem"]["Ami"].contains("ChannelPrivileges"))
                {
                    messages::propertyMissing(asyncResp->res, "#/Oem/Ami/ChannelPrivileges");
                    return;
                }
            }

            // if user name is not provided in the patch method or if it
            // matches the user name in the URI, then we are treating it as
            // updating user properties other then username. If username
            // provided doesn't match the URI, then we are treating this as
            // user rename request.
            if (!newUserName || (newUserName.value() == username) )
            {
                updateUserProperties(asyncResp, username, password, enabled, roleId,
                     locked, accountTypes, userSelf, req.session,
                     passwordChangeRequired, completionHandler);

                if (oemObj) 
                {
                    std::string mutableUser = username;

                    // Handle SNMP properties, ensure errors are propagated if any
                    handleSNMPOEMProperties(asyncResp, originalRoleId, roleId, oemObj, algorithm, encryption, accessMode, 
                                                    smtpMailId, hasSNMP, mutableUser, password, accountTypes);
                }

                // Async operations will complete and call completionHandler
                // Final status check moved to completionHandler
                return;

            }

            if (password)
            {
                if (pamUpdatePassword(username, *password) != PAM_SUCCESS)
                {
                    messages::propertyValueFormatError(asyncResp->res, nullptr,
                                                    "Password");
                    return;
                }
            }

            crow::connections::systemBus->async_method_call(
                [asyncResp, username,
                password(std::move(password)),
                roleId(std::move(roleId)), originalRoleId, enabled,
                newUserRaw = *newUserName,
                locked, userSelf, req,
                accountTypes(std::move(accountTypes)),
                passwordChangeRequired, completionHandler,
                oemObj,
                algorithm(std::move(algorithm)),
                encryption(std::move(encryption)),
                accessMode(std::move(accessMode)),
                smtpMailId(std::move(smtpMailId)),                
                hasSNMP](
                    const boost::system::error_code& ec,
                    sdbusplus::message_t& m)
            {
                std::string newUser = newUserRaw;

                if (ec)
                {
                    userErrorMessageHandler(m.get_error(), asyncResp, newUser, username);
                    return;
                }

                propertyModified["Username"] = newUser;

                updateUserProperties(asyncResp, newUser, password, enabled, roleId,
                                    locked, accountTypes, userSelf, req.session,
                                    passwordChangeRequired, completionHandler);

                if (oemObj)
                {
                    std::optional<bool> hasSNMPCopy = hasSNMP;

                    handleSNMPOEMProperties(asyncResp, originalRoleId, roleId, oemObj, algorithm, encryption,
                                            accessMode, smtpMailId, hasSNMPCopy, newUser, password, accountTypes);
                }

                // Async operations will complete and call completionHandler
                // Final status check moved to completionHandler
                return;
            },
            "xyz.openbmc_project.User.Manager", "/xyz/openbmc_project/user",
            "xyz.openbmc_project.User.Manager", "RenameUser", username, *newUserName);
        });
}

inline void requestAccountServiceRoutes(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/AccountService/")
        .privileges(redfish::privileges::headAccountService)
        .methods(boost::beast::http::verb::head)(
            std::bind_front(handleAccountServiceHead, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/AccountService/")
        .privileges(redfish::privileges::getAccountService)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleAccountServiceGet, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/AccountService/")
        .privileges(redfish::privileges::patchAccountService)
        .methods(boost::beast::http::verb::patch)(
            std::bind_front(handleAccountServicePatch, std::ref(app)));

    BMCWEB_ROUTE(
        app,
        "/redfish/v1/AccountService/MultiFactorAuth/ClientCertificate/Certificates/")
        .privileges(redfish::privileges::headCertificateCollection)
        .methods(boost::beast::http::verb::head)(std::bind_front(
            handleAccountServiceClientCertificatesHead, std::ref(app)));

    BMCWEB_ROUTE(
        app,
        "/redfish/v1/AccountService/MultiFactorAuth/ClientCertificate/Certificates/")
        .privileges(redfish::privileges::getCertificateCollection)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleAccountServiceClientCertificatesGet, std::ref(app)));

    BMCWEB_ROUTE(
        app,
        "/redfish/v1/AccountService/MultiFactorAuth/ClientCertificate/Certificates/<str>/")
        .privileges(redfish::privileges::headCertificate)
        .methods(boost::beast::http::verb::head)(std::bind_front(
            handleAccountServiceClientCertificatesInstanceHead, std::ref(app)));

    BMCWEB_ROUTE(
        app,
        "/redfish/v1/AccountService/MultiFactorAuth/ClientCertificate/Certificates/<str>/")
        .privileges(redfish::privileges::getCertificate)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleAccountServiceClientCertificatesInstanceGet, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/AccountService/Accounts/")
        .privileges(redfish::privileges::headManagerAccountCollection)
        .methods(boost::beast::http::verb::head)(
            std::bind_front(handleAccountCollectionHead, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/AccountService/Accounts/")
        .privileges(redfish::privileges::getManagerAccountCollection)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleAccountCollectionGet, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/AccountService/Accounts/")
        .privileges(redfish::privileges::postManagerAccountCollection)
        .methods(boost::beast::http::verb::post)(
            std::bind_front(handleAccountCollectionPost, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/AccountService/Accounts/<str>/")
        .methods(boost::beast::http::verb::post, boost::beast::http::verb::put)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& accountName) {
                membersResponse result =
                    membersResponsePost(req, asyncResp, accountName);
                if (result == membersResponse::postAllowed)
                {
                    handleAccountCollectionPost(app, req, asyncResp);
                    return;
                }
                else if (result == membersResponse::postNotAllowed)
                {
                    return;
                }
                asyncResp->res.addHeader("Allow", "GET, HEAD, PATCH, DELETE");
                messages::operationNotAllowed(asyncResp->res);
            });

    BMCWEB_ROUTE(app, "/redfish/v1/AccountService/Accounts/<str>/")
        .privileges(redfish::privileges::headManagerAccount)
        .methods(boost::beast::http::verb::head)(
            std::bind_front(handleAccountHead, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/AccountService/Accounts/<str>/")
        .privileges(redfish::privileges::getManagerAccount)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleAccountGet, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/AccountService/Accounts/<str>/")
        // TODO this privilege should be using the generated endpoints, but
        // because of the special handling of ConfigureSelf, it's not able to
        // yet
        .privileges({{"ConfigureUsers"}, {"ConfigureSelf"}})
        .methods(boost::beast::http::verb::patch)(
            std::bind_front(handleAccountPatch, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/AccountService/Accounts/<str>/")
        .privileges(redfish::privileges::deleteManagerAccount)
        .methods(boost::beast::http::verb::delete_)(
            std::bind_front(handleAccountDelete, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/AccountService/ExternalAccountProviders/")
        .privileges(redfish::privileges::getAccountService)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleExternalProviderGet, std::ref(app)));

    BMCWEB_ROUTE(app,
                 "/redfish/v1/AccountService/ExternalAccountProviders/RADIUS/")
        .privileges(redfish::privileges::headAccountService)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleAccountRadiusGet, std::ref(app)));

    BMCWEB_ROUTE(app,
                 "/redfish/v1/AccountService/ExternalAccountProviders/RADIUS/")
        .privileges(redfish::privileges::patchManagerAccountCollection)
        .methods(boost::beast::http::verb::patch)(
            std::bind_front(handleAccountRadiusPatch, std::ref(app)));
    BMCWEB_ROUTE(
        app,
        "/redfish/v1/AccountService/ExternalAccountProviders/Actions/Oem/Ami/RADIUS.SSLCertificateUpload")
        .privileges(redfish::privileges::privilegeSetConfigureUsers)
        .methods(boost::beast::http::verb::post)(
            std::bind_front(handleRadiusSSLCertificateUploadAction, std::ref(app)));
}

} // namespace redfish
