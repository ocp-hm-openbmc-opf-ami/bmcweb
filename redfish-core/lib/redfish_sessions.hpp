// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
// SPDX-FileCopyrightText: Copyright 2018 Intel Corporation
#pragma once

#include "account_service.hpp"
#include "app.hpp"
#include "cookies.hpp"
#include "error_messages.hpp"
#include "http/utility.hpp"
#include "persistent_data.hpp"
#include "query.hpp"
#include "registries/privilege_registry.hpp"
#include "sdbusplus/unpack_properties.hpp"
#include "utils/json_utils.hpp"

#include <boost/url/format.hpp>

#include <string>
#include <vector>

namespace redfish
{

constexpr const char* SessionManagerService =
    "xyz.openbmc_project.SessionManager";
constexpr const char* SessionManagerObj = "/xyz/openbmc_project/SessionManager";
std::vector<std::string> SessionInterfaces = {
    "xyz.openbmc_project.SessionManager.Kvm",
    "xyz.openbmc_project.SessionManager.Vmedia",
    "xyz.openbmc_project.SessionManager.Web",
    "xyz.openbmc_project.SessionManager.Ssh"};
std::vector<std::string> SessionProperties = {
    "KvmSessionInfo", "VmediaSessionInfo", "WebSessionInfo", "SshSessionInfo"};
constexpr const char* DBUS_PROPERTY_IFACE = "org.freedesktop.DBus.Properties";

using sessionInfo = std::tuple<uint8_t, std::string, std::string, uint8_t,
                               uint8_t, uint8_t, std::string>;

using sessionRet = std::vector<sessionInfo>;
using propertyValue = std::variant<std::vector<sessionInfo>>;

using privPropertyValue = std::variant<uint8_t, uint16_t, uint64_t, std::string,
                                       std::vector<std::string>, bool>;

inline std::string getRolePrivilege(std::string user)
{
    using VariantType =
        std::variant<bool, std::string, std::vector<std::string>>;

    auto bus = sdbusplus::bus::new_default();
    auto getuser_info_path = bus.new_method_call(
        "xyz.openbmc_project.User.Manager", "/xyz/openbmc_project/user",
        "xyz.openbmc_project.User.Manager", "GetUserInfo");
    getuser_info_path.append(user);

    auto user_info = bus.call(getuser_info_path);
    std::map<std::string, VariantType> infoDetailes;
    user_info.read(infoDetailes);

    auto it = infoDetailes.find("UserPrivilege");
    if (it != infoDetailes.end())
    {
        // Use std::get_if to check and get the value if it is a string
        if (auto value = std::get_if<std::string>(&it->second))
        {
            std::string privileage_value = *value;
            return privileage_value;
        }
    }
    else
    {
        std::cout << "UserPrivilege not found" << std::endl;
    }
    return "";
}

std::string getRole(std::string role)
{
    if (role == "priv-admin")
        return "Administrator";
    else if (role == "priv-operator")
        return "Operator";
    else if (role == "priv-user")
        return "Readonly";
    else
        return "";
}

const propertyValue getSessiondata(const std::string& interface,
                                   const std::string& propertyName)
{
    propertyValue value;
    auto b = sdbusplus::bus::new_default_system();
    auto method = b.new_method_call(SessionManagerService, SessionManagerObj,
                                    DBUS_PROPERTY_IFACE, "Get");
    method.append(interface, propertyName);
    auto reply = b.call(method);
    reply.read(value);
    return value;
}
uint16_t getBmcwebPort()
{
    PropertyValue property;
    uint16_t portNumber;
    try
    {
        // Create a D-Bus connection
        auto bus = sdbusplus::bus::new_default_system();

        // Prepare the D-Bus method call
        auto method =
            bus.new_method_call("xyz.openbmc_project.Control.Service.Manager",
                                "/xyz/openbmc_project/control/service/bmcweb",
                                "org.freedesktop.DBus.Properties", "Get");

        // Append interface and property name to the method call
        method.append("xyz.openbmc_project.Control.Service.SocketAttributes",
                      "Port");

        auto reply = bus.call(method);

        reply.read(property);

        if (auto val = std::get_if<uint16_t>(&property))
        {
            portNumber = *val;
        }
        else
        {
            std::cerr << "Property is not of type uint16_t" << std::endl;
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error retrieving port number from D-Bus: " << e.what()
                  << std::endl;
    }

    return portNumber;
}

inline void fillSessionObject(crow::Response& res,
                              const persistent_data::UserSession& session)
{
    res.jsonValue["Id"] = session.uniqueId;
    res.jsonValue["UserName"] = session.username;
    res.jsonValue["Oem"]["AMI_WebSession"]["UserId"] = session.userId;
    nlohmann::json::array_t roles;

    auto value = getRolePrivilege(session.username);

    roles.emplace_back(getRole(value));

    res.jsonValue["Roles"] = std::move(roles);
    res.jsonValue["@odata.id"] = boost::urls::format(
        "/redfish/v1/SessionService/Sessions/{}", session.uniqueId);
    res.jsonValue["@odata.type"] = json_util::odataType("Session");
    res.jsonValue["Name"] = "User Session";
    res.jsonValue["Description"] = "Manager User Session";
    res.jsonValue["ClientOriginIPAddress"] = session.clientIp;
    res.jsonValue["SessionType"] = session.AMIsessionType;
    res.jsonValue["Oem"]["AMI_WebSession"]["@odata.id"] = boost::urls::format(
        "/redfish/v1/SessionService/Sessions/{}#/Oem/AMI_WebSession",
        session.uniqueId);
    res.jsonValue["Oem"]["AMI_WebSession"]["@odata.type"] = json_util::odataType("AMIWebSession", "WebSession");
    res.jsonValue["Oem"]["AMI_WebSession"]["KvmActive"] =
        static_cast<bool>(session.kvmConnections);
    res.jsonValue["Oem"]["AMI_WebSession"]["VmActive"] =
        nlohmann::json::array();
    res.jsonValue["Oem"]["AMI_WebSession"]["MountType"] = "";
    for (const bool status : session.vmNbdActive)
    {
        res.jsonValue["Oem"]["AMI_WebSession"]["VmActive"].push_back(status);
    }
    if (session.clientId)
    {
        res.jsonValue["Context"] = *session.clientId;
    }

    std::string creationMessageId = "ResourceAdded:/redfish/v1/SessionService/Sessions/" + session.uniqueId;
    EventServiceManager::getInstance().resourceCreationDeletion(creationMessageId);
}

inline std::string getSessionType(int sessionType)
{
    if (sessionType == 0)
        return "KVM";
    else if (sessionType == 1)
        return "WEB";
    else if (sessionType == 2)
        return "VMEDIA";
    else if (sessionType == 3)
        return "SSH";
    else
        return "";
}

inline std::string getprivilege(int priv)
{
    if (priv == 1)
        return "Callback";
    else if (priv == 2)
        return "User";
    else if (priv == 3)
        return "Operator";
    else if (priv == 4)
        return "Administrator";
    else if (priv == 5)
        return "OEM Proprietary";
    else
        return "";
}

inline void getSessionInfo(std::shared_ptr<bmcweb::AsyncResp> asyncResp,
                           const std::string& interface,
                           const std::string& propertyName,
                           std::string sessionId, bool& found)
{
    size_t Pos = sessionId.find('_');
    std::string num = sessionId.substr(Pos + 1);
    int SessId = std::stoi(num);

    propertyValue value;
    auto b = sdbusplus::bus::new_default_system();
    auto method = b.new_method_call(SessionManagerService, SessionManagerObj,
                                    DBUS_PROPERTY_IFACE, "Get");
    method.append(interface, propertyName);
    auto reply = b.call(method);
    reply.read(value);

    if (std::holds_alternative<sessionRet>(value))
    {
        sessionRet& vec = std::get<sessionRet>(value);
        for (const auto& tuple : vec)
        {
            int id;
            std::string IpAddess;
            std::string userName;
            int SessionType;
            int privilege;
            int UserId;
            std::string additionalConfigValue;
            std::tie(id, IpAddess, userName, SessionType, privilege, UserId,
                     additionalConfigValue) = tuple;
            if (SessId == id)
            {
                found = true;
                asyncResp->res.jsonValue["Id"] = sessionId;
                asyncResp->res.jsonValue["UserName"] = userName;
                asyncResp->res.jsonValue["@odata.id"] =
                    "/redfish/v1/SessionService/"
                    "Sessions/" +
                    sessionId;
		asyncResp->res.jsonValue["@odata.type"] = json_util::odataType("Session");
                asyncResp->res.jsonValue["Name"] = "User Session";
                asyncResp->res.jsonValue["Description"] =
                    "Manager User Session";
                asyncResp->res.jsonValue["ClientOriginIPAddress"] = IpAddess;
                if (SessionType == 2)
                {
                    asyncResp->res
                        .jsonValue["Oem"]["AMI_WebSession"]["MountType"] =
                        additionalConfigValue;
                }
                else
                {
                    asyncResp->res
                        .jsonValue["Oem"]["AMI_WebSession"]["MountType"] = "";
                }
                asyncResp->res.jsonValue["SessionType"] =
                    getSessionType(SessionType);
                nlohmann::json::array_t roles;
                roles.emplace_back(getprivilege(privilege));
                asyncResp->res.jsonValue["Roles"] = std::move(roles);
                asyncResp->res.jsonValue["Oem"]["AMI_WebSession"]["UserId"] =
                    UserId;
            }
        }
    }
}

inline void handleSessionHead(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& /*sessionId*/)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    asyncResp->res.clearHeader(boost::beast::http::field::allow);
    asyncResp->res.addHeader("Allow", "GET,DELETE,HEAD");
    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/Session/Session.json>; rel=describedby");
}

inline void handleSessionGet(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& sessionId)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    if(sessionId == "Members")
    {
        messages::operationNotAllowed(asyncResp->res);
        return;
    }

    asyncResp->res.clearHeader(boost::beast::http::field::allow);
    asyncResp->res.addHeader("Allow", "GET,DELETE,HEAD");
    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/Session/Session.json>; rel=describedby");

    // Note that control also reaches here via doPost and doDelete.
    auto session =
        persistent_data::SessionStore::getInstance().getSessionByUid(sessionId);

    if (session)
    {
        fillSessionObject(asyncResp->res, *session);
        return;
    }

    bool found = false;
    // Session management
    if (sessionId.find("session_") != std::string::npos)
    {
        for (size_t i = 0; i < SessionInterfaces.size(); ++i)
        {
            getSessionInfo(asyncResp, SessionInterfaces[i],
                           SessionProperties[i], sessionId, found);
        }
        // Session details found
        if (found == true)
            return;
    }

    // Check the IPMI sessions and get session info
    std::array<std::string, 1> interfaces = {
        "xyz.openbmc_project.Ipmi.SessionInfo"};
    crow::connections::systemBus->async_method_call(
        [asyncResp,
         sessionId](const boost::system::error_code ec,
                    const dbus::utility::MapperGetSubTreeResponse& subtree) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG(
                    "Error in querying GetSubTree with Object Mapper. {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }
            if (subtree.size() == 0)
            {
                BMCWEB_LOG_DEBUG("Can't find  Session Info Attributes!");
                messages::resourceNotFound(asyncResp->res, "Session",
                                           sessionId);
                return;
            }
            bool ipmiSessionFound = false;
            std::string ipmiSessionService;
            std::string ipmiSessionInfPath;
            for (const auto& [ipmiSessionPath, object] : subtree)
            {
                if (ipmiSessionPath.empty() || object.empty())
                {
                    BMCWEB_LOG_DEBUG("Session Info Attributes mapper error!");
                    continue;
                }
                if (!boost::ends_with(ipmiSessionPath, sessionId))
                {
                    continue;
                }
                ipmiSessionFound = true;
                ipmiSessionService = object[0].first;
                ipmiSessionInfPath = ipmiSessionPath;
                break;
            }
            if (!ipmiSessionFound)
            {
                messages::resourceNotFound(asyncResp->res, "Session",
                                           sessionId);
                return;
            }
            if (ipmiSessionService.empty())
            {
                BMCWEB_LOG_DEBUG("Session Info Attributes mapper error!");
                messages::internalError(asyncResp->res);
                return;
            }
            crow::connections::systemBus->async_method_call(
                [asyncResp, sessionId](
                    const boost::system::error_code ec2,
                    const std::vector<std::pair<
                        std::string, std::variant<std::monostate, std::string,
                                                  uint32_t>>>& properties) {
                    if (ec2)
                    {
                        BMCWEB_LOG_DEBUG(
                            "Error in querying Session Info State property {}",
                            ec2);
                        messages::internalError(asyncResp->res);
                        return;
                    }
                    std::string userName = "";
                    uint32_t remoteIpAddr;
                    try
                    {
                        sdbusplus::unpackProperties(properties, "Username",
                                                    userName, "RemoteIPAddr",
                                                    remoteIpAddr);
                        asyncResp->res.jsonValue["Id"] = sessionId;
                        asyncResp->res.jsonValue["UserName"] = userName;
                        asyncResp->res.jsonValue["@odata.id"] =
                            "/redfish/v1/SessionService/"
                            "Sessions/" +
                            sessionId;
			asyncResp->res.jsonValue["@odata.type"] = json_util::odataType("Session");
                        asyncResp->res.jsonValue["Name"] = "User Session";
                        asyncResp->res.jsonValue["Description"] =
                            "Manager User Session";
                        struct in_addr ipAddr;
                        ipAddr.s_addr = remoteIpAddr;
                        asyncResp->res.jsonValue["ClientOriginIPAddress"] =
                            inet_ntoa(ipAddr);
                        asyncResp->res.jsonValue["SessionType"] = "IPMI";
                    }
                    catch (
                        const sdbusplus::exception::UnpackPropertyError& error)
                    {
                        BMCWEB_LOG_ERROR("{}", error.what());
                        messages::internalError(asyncResp->res);
                        return;
                    }
                    return;
                },
                ipmiSessionService, ipmiSessionInfPath,
                "org.freedesktop.DBus.Properties", "GetAll",
                "xyz.openbmc_project.Ipmi.SessionInfo");
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTree", "/", 0, interfaces);
}

inline void handleSessionDelete(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& sessionId)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    std::string deletionMessageId = "ResourceRemoved:/redfish/v1/SessionService/Sessions/" + sessionId;

    asyncResp->res.clearHeader(boost::beast::http::field::allow);
    asyncResp->res.addHeader("Allow", "GET,DELETE,HEAD");
    if (sessionId.find('_') != std::string::npos)
    {
        size_t Pos = sessionId.find('_');
        std::string num = sessionId.substr(Pos + 1);
        int SessId = std::stoi(num);
        int sessType;
        bool found = false;

        // Fetching sessionType with sessionId
        for (size_t i = 0; i < SessionInterfaces.size(); ++i)
        {
            propertyValue data =
                getSessiondata(SessionInterfaces[i], SessionProperties[i]);
            if (std::holds_alternative<sessionRet>(data))
            {
                sessionRet& vec = std::get<sessionRet>(data);
                for (const auto& tuple : vec)
                {
                    uint8_t id = std::get<0>(tuple);
                    uint8_t SessionType = std::get<3>(tuple);
                    if (SessId == id)
                    {
                        sessType = SessionType;
                        found = true;
                        break;
                    }
                }
            }
            if (found)
            {
                break;
            }
        }

        if (!found)
        {
            messages::resourceNotFound(asyncResp->res, "Session", sessionId);
            return;
        }

        // Unregister session
        crow::connections::systemBus->async_method_call(
            [asyncResp, sessType, SessId,
             req](const boost::system::error_code& ec, bool value) {
                if (ec)
                {
                    BMCWEB_LOG_DEBUG("Failed to unRegister: {}", ec);
                    messages::internalError(asyncResp->res);
                    return;
                }
                if (value)
                {
                    if (sessType == 1)
                    {
                        auto session =
                            persistent_data::SessionStore::getInstance()
                                .getSessionByUid(
                                    persistent_data::getUniqueIdFromSessionID(
                                        static_cast<uint8_t>(SessId)));
                        // If session type is Web, clear the session cookies
                        if (session)
                        {
                            if (req.session != nullptr &&
                                req.session->uniqueId ==
                                    (persistent_data::getUniqueIdFromSessionID(
                                        static_cast<uint8_t>(SessId))) &&
                                session->cookieAuth)
                            {
                                bmcweb::clearSessionCookies(asyncResp->res);
                            }
                            persistent_data::SessionStore::getInstance()
                                .removeSession(session);
                        }
                    }
                    asyncResp->res.result(
                        boost::beast::http::status::no_content);
                    return;
                }
            },
            SessionManagerService, SessionManagerObj,
            "xyz.openbmc_project.SessionManager", "SessionUnregister",
            static_cast<uint8_t>(SessId), static_cast<uint8_t>(sessType), 1);
            
        EventServiceManager::getInstance().resourceCreationDeletion(deletionMessageId);
        return;
    }

    auto session =
        persistent_data::SessionStore::getInstance().getSessionByUid(sessionId);

    // Perform a proper ConfigureSelf authority check.  If a
    // session is being used to DELETE some other user's session,
    // then the ConfigureSelf privilege does not apply.  In that
    // case, perform the authority check again without the user's
    // ConfigureSelf privilege.
    if (session)
    {
        if (session->username != req.session->username)
        {
            Privileges effectiveUserPrivileges =
                redfish::getUserPrivileges(*req.session);

            if (!effectiveUserPrivileges.isSupersetOf({"ConfigureUsers"}))
            {
                messages::insufficientPrivilege(asyncResp->res);
                return;
            }
        }

        if (req.session != nullptr && req.session->uniqueId == sessionId &&
            session->cookieAuth)
        {
            bmcweb::clearSessionCookies(asyncResp->res);
        }

        persistent_data::SessionStore::getInstance().removeSession(session);
        asyncResp->res.result(boost::beast::http::status::no_content);
        EventServiceManager::getInstance().resourceCreationDeletion(deletionMessageId);
        return;
    }

    // Check is it IPMI session and delete that session
    std::array<std::string, 1> interfaces = {
        "xyz.openbmc_project.Ipmi.SessionInfo"};
    crow::connections::systemBus->async_method_call(
        [asyncResp, sessionId](const boost::system::error_code ec,
                               const std::vector<std::string>& ifaceList) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG(
                    "Error in querying GetSubTreePaths with Object Mapper. {}",
                    ec);
                messages::internalError(asyncResp->res);
                return;
            }
            if (ifaceList.size() == 0)
            {
                BMCWEB_LOG_DEBUG("Can't find  Session Info Attributes!");
                return;
            }
            bool ipmiSessionFound = false;
            for (const std::string& ipmiSessionPath : ifaceList)
            {
                if (!boost::ends_with(ipmiSessionPath, sessionId))
                {
                    continue;
                }
                ipmiSessionFound = true;
                break;
            }
            if (ipmiSessionFound)
            {
                BMCWEB_LOG_DEBUG(
                    "Deleting IPMI session from Redfish is not allowed.");
                messages::actionNotSupported(
                    asyncResp->res, "deleting IPMI session from Redfish");
                return;
            }
            messages::resourceNotFound(asyncResp->res, "Session", sessionId);
            return;
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths", "/", 0,
        interfaces);
    
    EventServiceManager::getInstance().resourceCreationDeletion(deletionMessageId);
}

inline nlohmann::json getSessionCollectionMembers()
{
    auto& store = persistent_data::SessionStore::getInstance();
    const std::vector<std::string> sessionIds = store.getAllUniqueIds();
    const auto& sessions = store.getSessions();

    nlohmann::json ret = nlohmann::json::array();

    for (const std::string& uid : sessionIds)
    {
        std::shared_ptr<persistent_data::UserSession> session = nullptr;

        for (const auto& s : sessions)
        {
            if (s && s->uniqueId == uid)
            {
                session = s;
                break;
            }
        }

        if (session == nullptr)
        {
            continue;
        }

        if (session->AMIsessionType != "Redfish")
        {
            continue;
        }
        nlohmann::json::object_t sessionJson;
        sessionJson["@odata.id"] =
            boost::urls::format("/redfish/v1/SessionService/Sessions/{}", uid);
        ret.emplace_back(std::move(sessionJson));
    }

    return ret;
}

inline void getSessions(std::shared_ptr<bmcweb::AsyncResp> asyncResp,
                        std::string interface, std::string Property,
                        nlohmann::json& members)
{
    dbus::utility::getProperty<std::vector<sessionInfo>>(
        *crow::connections::systemBus, SessionManagerService, SessionManagerObj,
        interface, Property,
        [asyncResp, &members](const boost::system::error_code ec,
                              const std::vector<sessionInfo>& Sessions) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("DBus response error:{}", ec);
                return;
            }
            std::vector<uint8_t> sessionIds;
            for (const auto& tuple : Sessions)
            {
                uint8_t sessionId = std::get<0>(tuple);
                sessionIds.push_back(sessionId);
            }

            for (uint64_t value : sessionIds)
            {
                members.push_back(
                    {{"@odata.id",
                      "/redfish/v1/SessionService/Sessions/session_" +
                          std::to_string(value)}});
            }
        });
}

inline void handleSessionCollectionHead(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/SessionCollection.json>; rel=describedby");
}

inline void handleSessionCollectionGet(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/SessionCollection.json>; rel=describedby");

    asyncResp->res.jsonValue["Members"] = getSessionCollectionMembers();
    asyncResp->res.jsonValue["@odata.type"] =
        "#SessionCollection.SessionCollection";
    asyncResp->res.jsonValue["@odata.id"] =
        "/redfish/v1/SessionService/Sessions";
    asyncResp->res.jsonValue["Name"] = "Session Collection";
    asyncResp->res.jsonValue["Description"] = "Session Collection";

    // Collect IPMI sessions information
    std::array<std::string, 1> interfaces = {
        "xyz.openbmc_project.Ipmi.SessionInfo"};
    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code ec,
                    const std::vector<std::string>& ifaceList) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG(
                    "Error in querying GetSubTreePaths with Object Mapper. {}",
                    ec);
                messages::internalError(asyncResp->res);
                return;
            }
            if (ifaceList.size() == 0)
            {
                BMCWEB_LOG_DEBUG("Can't find  Session Info Attributes!");
                return;
            }
            for (const std::string& ipmiSessionPath : ifaceList)
            {
                std::filesystem::path filePath(ipmiSessionPath);
                std::string ipmiSessionID =
                    filePath.has_filename() ? filePath.filename() : "";
                if (!ipmiSessionID.empty() && ipmiSessionID != "0")
                {
                    asyncResp->res.jsonValue["Members"].push_back(
                        {{"@odata.id", "/redfish/v1/SessionService/Sessions/" +
                                           ipmiSessionID}});
                }
            }
            asyncResp->res.jsonValue["Members@odata.count"] =
                asyncResp->res.jsonValue["Members"].size();
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths", "/", 0,
        interfaces);

    nlohmann::json& members = asyncResp->res.jsonValue["Members"];
    for (size_t i = 0; i < SessionInterfaces.size(); ++i)
    {
        getSessions(asyncResp, SessionInterfaces[i], SessionProperties[i],
                    members);
    }
    asyncResp->res.jsonValue["Members@odata.count"] = members.size();
}

inline void handleSessionCollectionMembersGet(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    asyncResp->res.jsonValue = getSessionCollectionMembers();
}

inline void processAfterSessionCreation(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const crow::Request& req, const std::string& username,
    std::shared_ptr<persistent_data::UserSession>& session)
{
    asyncResp->res.addHeader("X-XSS-Protection", "1; mode=block");
    // When session is created by webui-vue give it session cookies as a
    // non-standard Redfish extension. This is needed for authentication for
    // WebSockets-based functionality.
    if (!req.getHeaderValue("X-Requested-With").empty())
    {
        bmcweb::setSessionCookies(asyncResp->res, *session);
    }
    else
    {
        asyncResp->res.addHeader("X-Auth-Token", session->sessionToken);
    }
    asyncResp->res.addHeader(
        "Location", "/redfish/v1/SessionService/Sessions/" + session->uniqueId);
    if (session->isConfigureSelfOnly)
    {
        messages::passwordChangeRequired(
            asyncResp->res,
            boost::urls::format("/redfish/v1/AccountService/Accounts/{}",
                                session->username));
    }
    asyncResp->res.result(boost::beast::http::status::created);
    session->AMIsessionType = "Redfish";
    crow::getUserInfo(asyncResp, username, session, [asyncResp, session]() {
        fillSessionObject(asyncResp->res, *session);
    });
    
}

inline void handleSessionCollectionPost(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    std::string username;
    std::string password;
    std::optional<std::string> clientId;
    std::optional<std::string> token;
    if (!json_util::readJsonPatch( //
            req, asyncResp->res,   //
            "UserName", username,  //
            "Password", password,  //
            "Token", token,        //
            "Context", clientId    //
            ))
    {
        return;
    }
    if (password.empty() || username.empty() ||
        asyncResp->res.result() != boost::beast::http::status::ok)
    {
        if (username.empty())
        {
            messages::resourceAtUriUnauthorized(asyncResp->res, req.url(),
                                                "Invalid username ");
        }

        if (password.empty())
        {
            messages::resourceAtUriUnauthorized(asyncResp->res, req.url(),
                                                "Invalid Password ");
        }

        return;
    }

    int pamrc = pamAuthenticateUser(username, password, token,req.ipAddress);
    bool isConfigureSelfOnly = pamrc == PAM_NEW_AUTHTOK_REQD;
    if ((pamrc != PAM_SUCCESS) && !isConfigureSelfOnly)
    {
        messages::resourceAtUriUnauthorized(asyncResp->res, req.url(),
                                            "Invalid username or password");
        return;
    }

    // User is authenticated - create session
    std::shared_ptr<persistent_data::UserSession> session =
        persistent_data::SessionStore::getInstance().generateUserSession(
            username, req.ipAddress, clientId,
            persistent_data::SessionType::Session, isConfigureSelfOnly,
            "Redfish");
    bool maxSessionReached =
        persistent_data::SessionStore::getInstance().getRedfishSessionReached();
    if (session == nullptr && maxSessionReached == true)
    {
        messages::sessionLimitExceeded(asyncResp->res);
        return;
    }
    else if (session == nullptr)
    {
        messages::internalError(asyncResp->res);
        return;
    }
    processAfterSessionCreation(asyncResp, req, username, session);
}

inline void handleSessionServiceHead(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/SessionService/SessionService.json>; rel=describedby");
}
inline void handleSessionServiceGet(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)

{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    asyncResp->res.addHeader(
        boost::beast::http::field::link,
        "</redfish/v1/JsonSchemas/SessionService/SessionService.json>; rel=describedby");
    
    asyncResp->res.jsonValue["@odata.type"] = json_util::odataType("SessionService");
    asyncResp->res.jsonValue["@odata.id"] = "/redfish/v1/SessionService";
    asyncResp->res.jsonValue["Name"] = "Session Service";
    asyncResp->res.jsonValue["Id"] = "SessionService";
    asyncResp->res.jsonValue["Description"] = "Session Service";
    // asyncResp->res.jsonValue["SessionTimeout"] =
    //     persistent_data::SessionStore::getInstance().getTimeoutInSeconds();
    asyncResp->res.jsonValue["ServiceEnabled"] = true;
    asyncResp->res.jsonValue["Oem"]["Ami"]["KvmMaxSession"] =
        persistent_data::SessionStore::getInstance().loadMaxSession(
            "start-ipkvm");
    asyncResp->res.jsonValue["Oem"]["Ami"]["VmMaxSession"] =
        persistent_data::SessionStore::getInstance().loadMaxSession(
            "xyz.openbmc_project.VirtualMedia");
    asyncResp->res.jsonValue["Oem"]["Ami"]["SshMaxSession"] =
        persistent_data::SessionStore::getInstance().loadMaxSession("dropbear");
    asyncResp->res.jsonValue["Oem"]["Ami"]["WebMaxSession"] =
        persistent_data::SessionStore::getInstance().loadMaxSession("web");
    asyncResp->res.jsonValue["Oem"]["Ami"]["RedfishMaxSession"] =
        persistent_data::SessionStore::getInstance().loadMaxSession("redfish");

    asyncResp->res.jsonValue["Sessions"]["@odata.id"] =
        "/redfish/v1/SessionService/Sessions";
    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code ec,
                    const std::variant<uint64_t>& value) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("failed to get property Value  ", ec);
                return;
            }

            const uint64_t* s = std::get_if<uint64_t>(&value);
            asyncResp->res.jsonValue["SessionTimeout"] = *s;
        },
        "xyz.openbmc_project.Control.Service.Manager",
        "/xyz/openbmc_project/control/service/bmcweb",
        "org.freedesktop.DBus.Properties", "Get",
        "xyz.openbmc_project.Control.Service.Attributes", "SessionTimeOut");

    uint16_t bmcwebPort = getBmcwebPort();
    if (bmcwebPort)
    {
        asyncResp->res.jsonValue["Oem"]["Ami"]["BMCwebPort"] = bmcwebPort;
    }
    else
    {
        BMCWEB_LOG_DEBUG("failed to get property Value");
        return;
    }

    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code ec,
                    const std::variant<uint64_t>& value) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("failed to get property Value  ", ec);
                return;
            }

            const uint64_t* s = std::get_if<uint64_t>(&value);
            asyncResp->res.jsonValue["Oem"]["Ami"]["@odata.id"] =
                "/redfish/v1/SessionService#/Oem/Ami";
            asyncResp->res.jsonValue["Oem"]["Ami"]["@odata.type"] = json_util::odataType("AMISessionService", "Ami");
            asyncResp->res.jsonValue["Oem"]["Ami"]["KVMSessionTimeout"] = *s;
        },
        "xyz.openbmc_project.Control.Service.Manager",
        "/xyz/openbmc_project/control/service/start_2dipkvm",
        "org.freedesktop.DBus.Properties", "Get",
        "xyz.openbmc_project.Control.Service.Attributes", "SessionTimeOut");

    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code ec,
                    const std::variant<uint16_t>& value) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("failed to get property Value  ", ec);
                return;
            }
            const uint16_t* s = std::get_if<uint16_t>(&value);
            asyncResp->res.jsonValue["Oem"]["Ami"]["@odata.id"] =
                "/redfish/v1/SessionService#/Oem/Ami";
	    asyncResp->res.jsonValue["Oem"]["Ami"]["@odata.type"] = json_util::odataType("AMISessionService", "Ami");
	    asyncResp->res.jsonValue["Oem"]["Ami"]["KVMPort"] = *s;
        },
        "xyz.openbmc_project.Control.Service.Manager",
        "/xyz/openbmc_project/control/service/start_2dipkvm",
        "org.freedesktop.DBus.Properties", "Get",
        "xyz.openbmc_project.Control.Service.SocketAttributes", "Port");
}

inline void handleSessionServicePatch(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    std::optional<uint64_t> sessionTimeout;
    std::optional<nlohmann::json> oem;
    if (!json_util::readJsonPatch(            //
            req, asyncResp->res,              //
            "SessionTimeout", sessionTimeout, //
            "Oem", oem                        //
            ))
    {
        return;
    }

    if (sessionTimeout)
    {
        // The minimum & maximum allowed values for session timeout
        // are 30 seconds and 86400 seconds respectively as per the
        // session service schema mentioned at
        // https://redfish.dmtf.org/schemas/v1/SessionService.v1_1_7.json

        if (*sessionTimeout <= 86400 && *sessionTimeout >= 30)
        {
            crow::connections::systemBus->async_method_call(
                [asyncResp,
                 sessionTimeout](const boost::system::error_code ec) {
                    if (ec)
                    {
                        messages::internalError(asyncResp->res);
                        return;
                    }
                    messages::success(asyncResp->res);
                },
                "xyz.openbmc_project.Control.Service.Manager",
                "/xyz/openbmc_project/control/service/bmcweb",
                "org.freedesktop.DBus.Properties", "Set",
                "xyz.openbmc_project.Control.Service.Attributes",
                "SessionTimeOut", std::variant<uint64_t>(*sessionTimeout));
        }
        else
        {
            messages::propertyValueNotInList(asyncResp->res, *sessionTimeout,
                                             "SessionTimeOut");
        }
    }

    if (oem)
    {
        std::optional<nlohmann::json> ami;

        if (!json_util::readJson(     //
                *oem, asyncResp->res, //
                "Ami", ami            //
                ))
        {
            return;
        }
        if (ami)
        {
            std::optional<uint64_t> kvmSessionTimeout;
            std::optional<uint16_t> bmcwebPort;
            std::optional<uint16_t> kvmPort;
            if (!json_util::readJson(*ami, asyncResp->res, "KVMSessionTimeout",
                                     kvmSessionTimeout, "BMCwebPort",
                                     bmcwebPort, "KVMPort", kvmPort))
            {
                return;
            }

	     if (kvmSessionTimeout)
            {
                if (*kvmSessionTimeout <= 86400 && *kvmSessionTimeout >= 30)
                {
                crow::connections::systemBus->async_method_call(
                    [asyncResp, kvmSessionTimeout](const boost::system::error_code ec) {
                        if (ec)
                        {
                            BMCWEB_LOG_ERROR("Error patching {}", ec);
                            messages::internalError(asyncResp->res);
                            return;
                        }
                        messages::success(asyncResp->res);
                    },
                    "xyz.openbmc_project.Control.Service.Manager",
                    "/xyz/openbmc_project/control/service/start_2dipkvm",
                    "org.freedesktop.DBus.Properties", "Set",
                    "xyz.openbmc_project.Control.Service.Attributes",
                    "SessionTimeOut",
                    std::variant<uint64_t>(*kvmSessionTimeout));
               }
               else
               {
                    messages::propertyValueNotInList(asyncResp->res, std::to_string(*kvmSessionTimeout),
                                             "KVMSessionTimeout");
               }
           }

            if (bmcwebPort)
            {
                crow::connections::systemBus->async_method_call(
                    [asyncResp](const boost::system::error_code ec) {
                        if (ec)
                        {
                            BMCWEB_LOG_ERROR("Error patching {}", ec);
                            messages::internalError(asyncResp->res);
                            return;
                        }
                        messages::success(asyncResp->res);
                    },
                    "xyz.openbmc_project.Control.Service.Manager",
                    "/xyz/openbmc_project/control/service/bmcweb",
                    "org.freedesktop.DBus.Properties", "Set",
                    "xyz.openbmc_project.Control.Service.SocketAttributes",
                    "Port", std::variant<uint16_t>(*bmcwebPort));
            }

            if (kvmPort)
            {
                uint16_t bmcweb_Port = getBmcwebPort();
                if (kvmPort != bmcweb_Port)
                {
                    crow::connections::systemBus->async_method_call(
                        [asyncResp](const boost::system::error_code ec) {
                            if (ec)
                            {
                                BMCWEB_LOG_ERROR("Error patching {}", ec);
                                messages::internalError(asyncResp->res);
                                return;
                            }
                            messages::success(asyncResp->res);
                        },
                        "xyz.openbmc_project.Control.Service.Manager",
                        "/xyz/openbmc_project/control/service/start_2dipkvm",
                        "org.freedesktop.DBus.Properties", "Set",
                        "xyz.openbmc_project.Control.Service.SocketAttributes",
                        "Port", std::variant<uint16_t>(*kvmPort));
                }
                else
                {
                    messages::resourceInUse(asyncResp->res);
                    return;
                }
            }
        }
    }
}

inline void requestRoutesSession(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/SessionService/Sessions/<str>/")
        .privileges(redfish::privileges::headSession)
        .methods(boost::beast::http::verb::head)(
            std::bind_front(handleSessionHead, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/SessionService/Sessions/<str>/")
        .privileges(redfish::privileges::getSession)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleSessionGet, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/SessionService/Sessions/<str>/")
        .privileges(redfish::privileges::deleteSession)
        .methods(boost::beast::http::verb::delete_)(
            std::bind_front(handleSessionDelete, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/SessionService/Sessions/<str>/")
        .methods(boost::beast::http::verb::post,
                 boost::beast::http::verb::patch)(
            [&app](const crow::Request& req,
               const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
               const std::string& sessionId) {
                asyncResp->res.clearHeader(boost::beast::http::field::allow);
                asyncResp->res.addHeader("Allow", "GET,DELETE,HEAD");
                if (sessionId.find('_') != std::string::npos)
                {
                    size_t Pos = sessionId.find('_');
                    std::string num = sessionId.substr(Pos + 1);
                    int SessId = std::stoi(num);
                    bool found = false;

                    // Fetching sessionType with sessionId
                    for (size_t i = 0; i < SessionInterfaces.size(); ++i)
                    {
                        propertyValue data = getSessiondata(
                            SessionInterfaces[i], SessionProperties[i]);
                        if (std::holds_alternative<sessionRet>(data))
                        {
                            sessionRet& vec = std::get<sessionRet>(data);
                            for (const auto& tuple : vec)
                            {
                                uint8_t id = std::get<0>(tuple);

                                if (SessId == id)
                                {
                                    found = true;
                                    break;
                                }
                            }
                        }
                        if (found)
                        {
                            messages::operationNotAllowed(asyncResp->res);
                            return;
                        }
                    }
                }
                else if(sessionId == "Members" )
                {
                    if (req.method() == boost::beast::http::verb::post)
                    {
                        handleSessionCollectionPost(app, req, asyncResp);
                    }
                    else
                    {
                        messages::operationNotAllowed(asyncResp->res);
                    }
                }
                else
                {
                    messages::resourceNotFound(asyncResp->res, "Session",
                                           sessionId);
                }
            });

    BMCWEB_ROUTE(app, "/redfish/v1/SessionService/Sessions/")
        .privileges(redfish::privileges::headSessionCollection)
        .methods(boost::beast::http::verb::head)(
            std::bind_front(handleSessionCollectionHead, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/SessionService/Sessions/")
        .privileges(redfish::privileges::getSessionCollection)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleSessionCollectionGet, std::ref(app)));

    // Note, the next two routes technically don't match the privilege
    // registry given the way login mechanisms work.  The base privilege
    // registry lists this endpoint as requiring login privilege, but because
    // this is the endpoint responsible for giving the login privilege, and it
    // is itself its own route, it needs to not require Login
    BMCWEB_ROUTE(app, "/redfish/v1/SessionService/Sessions/")
        .privileges({})
        .methods(boost::beast::http::verb::post)(
            std::bind_front(handleSessionCollectionPost, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/SessionService/")
        .privileges(redfish::privileges::headSessionService)
        .methods(boost::beast::http::verb::head)(
            std::bind_front(handleSessionServiceHead, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/SessionService/")
        .privileges(redfish::privileges::getSessionService)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleSessionServiceGet, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/SessionService/")
        .privileges(redfish::privileges::patchSessionService)
        .methods(boost::beast::http::verb::patch)(
            std::bind_front(handleSessionServicePatch, std::ref(app)));
}

} // namespace redfish
