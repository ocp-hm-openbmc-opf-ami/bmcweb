// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#pragma once

#include "app.hpp"
#include "cookies.hpp"
#include "error_messages.hpp"
#include "http_request.hpp"
#include "http_response.hpp"
#include "multipart_parser.hpp"
#include "pam_authenticate.hpp"
#include "webassets.hpp"

#include <boost/container/flat_set.hpp>

#include <random>
#include <variant>

namespace crow
{

namespace login_routes
{

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

inline std::string getRolePrivilege(std::string user, std::string ipAddr)
{
    using VariantType =
        std::variant<bool, std::string, std::vector<std::string>>;

    auto bus = sdbusplus::bus::new_default();
    auto getuser_info_path = bus.new_method_call(
        "xyz.openbmc_project.User.Manager", "/xyz/openbmc_project/user",
        "xyz.openbmc_project.User.Manager", "GetUserInfo");
    getuser_info_path.append(user, ipAddr);

    auto user_info = bus.call(getuser_info_path);
    std::map<std::string, VariantType> infoDetailes;
    user_info.read(infoDetailes);

    auto it = infoDetailes.find("UserPrivilege");
    if (it != infoDetailes.end())
    {
        const auto& var = it->second;
        if (std::holds_alternative<std::string>(var))
        {
            std::string privilege = std::get<std::string>(var);
            return privilege;
        }
        else
        {
            BMCWEB_LOG_DEBUG("UserPrivilege is not a string type.\n");
        }
    }
    else
    {
        BMCWEB_LOG_DEBUG("UserPrivilege not found in GetUserInfo Output.\n");
    }
    return "";
}

inline bool getRemoteUserInfo(std::string user, std::string ipAddr)
{
    using VariantType =
        std::variant<bool, std::string, std::vector<std::string>>;

    auto bus = sdbusplus::bus::new_default();
    auto getuser_info_path = bus.new_method_call(
        "xyz.openbmc_project.User.Manager", "/xyz/openbmc_project/user",
        "xyz.openbmc_project.User.Manager", "GetUserInfo");
    getuser_info_path.append(user, ipAddr);

    auto user_info = bus.call(getuser_info_path);
    std::map<std::string, VariantType> infoDetails;
    user_info.read(infoDetails);

    auto it = infoDetails.find("RemoteUser");
    if (it != infoDetails.end())
    {
        if (auto value = std::get_if<bool>(&it->second))
        {
            BMCWEB_LOG_DEBUG("RemoteUser for user {}: {}", user, *value);
            return *value;
        }
        else
        {
            BMCWEB_LOG_ERROR("RemoteUser found for user {} but not of type bool.", user);
        }
    }
    else
    {
        BMCWEB_LOG_ERROR("RemoteUser not found in user info for user: {}", user);
    }

    return false; // Default fallback
}

inline void handleLogin(const crow::Request& req,
                        const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    MultipartParser parser;
    std::string_view contentType = req.getHeaderValue("content-type");
    std::string_view username;
    std::string_view password;

    // This object needs to be declared at this scope so the strings
    // within it are not destroyed before we can use them
    nlohmann::json loginCredentials;
    // Check if auth was provided by a payload
    if (contentType.starts_with("application/json"))
    {
        loginCredentials = nlohmann::json::parse(req.body(), nullptr, false);
        if (loginCredentials.is_discarded())
        {
            BMCWEB_LOG_DEBUG("Bad json in request");
            asyncResp->res.result(boost::beast::http::status::bad_request);
            return;
        }

        // check for username/password in the root object
        // THis method is how intel APIs authenticate
        nlohmann::json::iterator userIt = loginCredentials.find("username");
        nlohmann::json::iterator passIt = loginCredentials.find("password");
        if (userIt != loginCredentials.end() &&
            passIt != loginCredentials.end())
        {
            const std::string* userStr = userIt->get_ptr<const std::string*>();
            const std::string* passStr = passIt->get_ptr<const std::string*>();
            if (userStr != nullptr && passStr != nullptr)
            {
                username = *userStr;
                password = *passStr;
            }
        }
        else
        {
            // Openbmc appears to push a data object that contains the
            // same keys (username and password), attempt to use that
            auto dataIt = loginCredentials.find("data");
            if (dataIt != loginCredentials.end())
            {
                // Some apis produce an array of value ["username",
                // "password"]
                if (dataIt->is_array())
                {
                    if (dataIt->size() == 2)
                    {
                        nlohmann::json::iterator userIt2 = dataIt->begin();
                        nlohmann::json::iterator passIt2 = dataIt->begin() + 1;
                        if (userIt2 != dataIt->end() &&
                            passIt2 != dataIt->end())
                        {
                            const std::string* userStr =
                                userIt2->get_ptr<const std::string*>();
                            const std::string* passStr =
                                passIt2->get_ptr<const std::string*>();
                            if (userStr != nullptr && passStr != nullptr)
                            {
                                username = *userStr;
                                password = *passStr;
                            }
                        }
                    }
                }
                else if (dataIt->is_object())
                {
                    nlohmann::json::iterator userIt2 = dataIt->find("username");
                    nlohmann::json::iterator passIt2 = dataIt->find("password");
                    if (userIt2 != dataIt->end() && passIt2 != dataIt->end())
                    {
                        const std::string* userStr =
                            userIt2->get_ptr<const std::string*>();
                        const std::string* passStr =
                            passIt2->get_ptr<const std::string*>();
                        if (userStr != nullptr && passStr != nullptr)
                        {
                            username = *userStr;
                            password = *passStr;
                        }
                    }
                }
            }
        }
    }
    else if (contentType.starts_with("multipart/form-data"))
    {
        ParserError ec = parser.parse(req);
        if (ec != ParserError::PARSER_SUCCESS)
        {
            // handle error
            BMCWEB_LOG_ERROR("MIME parse failed, ec : {}",
                             static_cast<int>(ec));
            asyncResp->res.result(boost::beast::http::status::bad_request);
            return;
        }

        for (const FormPart& formpart : parser.mime_fields)
        {
            boost::beast::http::fields::const_iterator it =
                formpart.fields.find("Content-Disposition");
            if (it == formpart.fields.end())
            {
                BMCWEB_LOG_ERROR("Couldn't find Content-Disposition");
                asyncResp->res.result(boost::beast::http::status::bad_request);
                continue;
            }

            BMCWEB_LOG_INFO("Parsing value {}", it->value());

            if (it->value() == "form-data; name=\"username\"")
            {
                username = formpart.content;
            }
            else if (it->value() == "form-data; name=\"password\"")
            {
                password = formpart.content;
            }
            else
            {
                BMCWEB_LOG_INFO("Extra format, ignore it.{}", it->value());
            }
        }
    }
    else
    {
        // check if auth was provided as a headers
        username = req.getHeaderValue("username");
        password = req.getHeaderValue("password");
    }

    if (!username.empty() && !password.empty())
    {
        int pamrc = pamAuthenticateUser(username, password, std::nullopt,req.ipAddress);
        bool isConfigureSelfOnly = pamrc == PAM_NEW_AUTHTOK_REQD;
        if (pamrc == PAM_MAXTRIES)
        {
            // return the API error code as Locked 423
            asyncResp->res.result(boost::beast::http::status::locked);
        }
        else if ((pamrc != PAM_SUCCESS) && !isConfigureSelfOnly)
        {
            asyncResp->res.result(boost::beast::http::status::unauthorized);
        }
        else
        {
            auto session =
                persistent_data::SessionStore::getInstance()
                    .generateUserSession(username, req.ipAddress, std::nullopt,
                                         persistent_data::SessionType::Session,
                                         isConfigureSelfOnly, "WebUI");
            std::string ipAddr   =  redfish::ip_util::extractIPv4FromMappedIPv6(req.serverIPAddress);

            if (session && session->userRole.empty())
            {
                std::string username = session->username;
                std::string userPath = "/xyz/openbmc_project/user/" + session->username;
                try
                {
                    auto bus = sdbusplus::bus::new_default_system();

                    // Prepare the GetUserInfo method call
                    auto method = bus.new_method_call(
                        "xyz.openbmc_project.User.Manager",         // Service name
                        "/xyz/openbmc_project/user",                // Object path
                        "xyz.openbmc_project.User.Manager",         // Interface
                        "GetUserInfo");                             // Method

                    method.append(username, ipAddr);

                    // Call the method
                    auto reply = bus.call(method);

                    // Expected return type: a{sv}
                    using VariantType = std::variant<bool, std::string, std::vector<std::string>>;
                    std::map<std::string, VariantType> result;

                    reply.read(result);

                    auto it = result.find("UserPrivilege");
                    if (it != result.end())
                    {
                        const auto& var = it->second;
                        if (std::holds_alternative<std::string>(var))
                        {
                            std::string privilege = std::get<std::string>(var);
                            session->userRole = privilege;
                            BMCWEB_LOG_ERROR("Fetched userRole from D-Bus: {}", session->userRole);
                        }
                        else
                        {
                            BMCWEB_LOG_DEBUG("UserPrivilege is not a string type.\n");
                            redfish::messages::insufficientPrivilege(asyncResp->res);
                            return;
                        }
                    }
                    else
                    {
                        BMCWEB_LOG_DEBUG("UserPrivilege not found in GetUserInfo Output.\n");
                        redfish::messages::insufficientPrivilege(asyncResp->res);
                        return;
                    }
                }
                catch (const sdbusplus::exception::SdBusError& e)
                {
                    BMCWEB_LOG_ERROR("Failed to get UserPrivilege from D-Bus: {}", e.what());
                }
            }

            bool maxSessionReached =
                persistent_data::SessionStore::getInstance()
                    .getWebSessionReached();
            if (session == nullptr && maxSessionReached == true)
            {
                redfish::messages::sessionLimitExceeded(asyncResp->res);
                return;
            }

            bmcweb::setSessionCookies(asyncResp->res, *session);

            // if content type is json, assume json token
            asyncResp->res.jsonValue["token"] = session->sessionToken;

            int userId = session->userId;
            bool result;
            uint8_t sessionId = 0;
            uint8_t sessionType = 1;

            std::unordered_map<std::string, uint8_t> roleToPriv = {
                {"Callback", 1},
                {"priv-user", 2},
                {"priv-operator", 3},
                {"OEM Proprietary", 5}};
            uint8_t priv = roleToPriv.contains(session->userRole)
                            ? roleToPriv[session->userRole]
                            : 4;

            auto b = sdbusplus::bus::new_default_system();
            auto method = b.new_method_call(
                "xyz.openbmc_project.SessionManager",
                "/xyz/openbmc_project/SessionManager",
                "xyz.openbmc_project.SessionManager", "SessionRegister");
            method.append(sessionId, session->clientIp, session->username, sessionType,
                        priv, static_cast<uint8_t>(userId), "");
            try
            {
                auto reply = b.call(method);
                reply.read(result);

                if (!result)
                {
                    BMCWEB_LOG_DEBUG("back-end return false while call method ");
                    return;
                }
            }
            catch (const sdbusplus::exception::SdBusError& e)
            {
                BMCWEB_LOG_ERROR("D-Bus call failed: {}", e.what());
                return;
            }

            // Get session ID
            auto bus = sdbusplus::bus::new_default_system();
            auto m = bus.new_method_call("xyz.openbmc_project.SessionManager",
                                        "/xyz/openbmc_project/SessionManager",
                                        "org.freedesktop.DBus.Properties", "Get");

            m.append("xyz.openbmc_project.SessionManager.Web", "WebSessionInfo");
            try
            {
                sdbusplus::message::message r = bus.call(m);

                std::variant<
                    std::vector<std::tuple<uint8_t, std::string, std::string, uint8_t,
                                        uint8_t, uint8_t, std::string>>>
                    val;
                r.read(val);

                auto sessionArray = std::get<
                    std::vector<std::tuple<uint8_t, std::string, std::string, uint8_t,
                                        uint8_t, uint8_t, std::string>>>(val);

                if (!sessionArray.empty())
                {
                    auto lastSession = sessionArray.back();
                    uint8_t sessionId = std::get<0>(lastSession);
                    persistent_data::sessionMap[session->uniqueId] = sessionId;
                    asyncResp->res.jsonValue["Session_ID"] =
                        "session_" + std::to_string(std::get<0>(lastSession));
                }
                else
                {
                    BMCWEB_LOG_ERROR("No active session found!");
                }
            }
            catch (const sdbusplus::exception::SdBusError& e)
            {
                BMCWEB_LOG_ERROR("Failed to fetch WebSessionInfo from D-Bus: {}",
                                e.what());
                return;
            }

            // For User Privilege 
            std::string roleId;
            std::string user(username);
            auto value = getRolePrivilege(user, ipAddr);
            roleId = getRole(value);
            asyncResp->res.jsonValue["RoleId"] = roleId;

            // For Remote User
            bool isRemote = getRemoteUserInfo(user, ipAddr);
            asyncResp->res.jsonValue["RemoteUser"] = isRemote;

#if (BMCWEB_AMI_2FA_MACRO)
#if (BMCWEB_AMI_REP_MACRO)
            dbus::utility::getProperty<bool>(
                "xyz.openbmc_project.User.Manager",
                "/xyz/openbmc_project/user/" + user,
                "xyz.openbmc_project.User.Attributes", "TwoFacEnableStatus",
                [asyncResp](const boost::system::error_code& ec,
                            bool ServiceEnabled) {
                    if (ec)
                    {
                        //  asyncResp->res.result(
                        //      boost::beast::http::status::internal_server_error);
                        return;
                    }
                    asyncResp->res.jsonValue["TwoFacEnableStatus"] =
                        ServiceEnabled;
                });
#else
            asyncResp->res.jsonValue["TwoFacEnableStatus"] = "N/A";
#endif
#endif
        }
    }
    else
    {
        BMCWEB_LOG_DEBUG("Couldn't interpret password");
        asyncResp->res.result(boost::beast::http::status::bad_request);
    }

}

inline void handleLogout(const crow::Request& req,
                         const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    const auto& session = req.session;

    if (session != nullptr)
    {
        asyncResp->res.jsonValue["data"] =
            "User '" + session->username + "' logged out";
        asyncResp->res.jsonValue["message"] = "200 OK";
        asyncResp->res.jsonValue["status"] = "ok";

        std::string uniqueId = session->uniqueId;
        uint8_t sessionType = 1;
        auto it = persistent_data::sessionMap.find(uniqueId);

        if (it != persistent_data::sessionMap.end())
        {
            uint8_t sessionId = it->second;

        crow::connections::systemBus->async_method_call(
        [asyncResp,session,it](const boost::system::error_code ec,bool success) {
	    if (ec)
            {
            BMCWEB_LOG_ERROR("handleLogout D-Bus call failed: {}", ec.message());
            redfish::messages::internalError(asyncResp->res);
               return;
            }
            if(!success)
            {
               BMCWEB_LOG_ERROR("handleLogout: SessionUnregister returned false");
               redfish::messages::internalError(asyncResp->res);
               return;
            }
            BMCWEB_LOG_INFO("SessionUnregister succeeded");
	    persistent_data::sessionMap.erase(it);
            bmcweb::clearSessionCookies(asyncResp->res);
            persistent_data::SessionStore::getInstance().removeSession(session);
            },
            "xyz.openbmc_project.SessionManager", "/xyz/openbmc_project/SessionManager",
            "xyz.openbmc_project.SessionManager", "SessionUnregister",
             sessionId,
             sessionType,
             1);
        }
    }
}
void generateOTP (const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                     const std::string& username)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code& ec, bool response) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("DBUS response error {}", ec);
                return;
            }
            if (!response)
            {

                asyncResp->res.jsonValue["error"] = "Failed to generate OTP code";
                asyncResp->res.result(boost::beast::http::status::bad_request);
            }
        },
        "xyz.openbmc_project.User.Manager",
        "/xyz/openbmc_project/user",
        "xyz.openbmc_project.User.Manager",
        "OTPGeneration", username);
}

void checkSMTPMailId(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                     std::string username, bool smtpDisabled = false)
{
    dbus::utility::getProperty<std::string>(
        "xyz.openbmc_project.User.Manager", "/xyz/openbmc_project/user/" + username,
        "xyz.openbmc_project.User.Attributes", "SMTPMailID",
        [asyncResp, username, smtpDisabled](const boost::system::error_code& ec,
                        const std::string& SMTPMailId) {
            if (ec)
            {
                BMCWEB_LOG_DEBUG("DBUS response error {}", ec);
                return;
            }
            if (SMTPMailId.empty() && smtpDisabled)
            {
                asyncResp->res.jsonValue["error"] =
                    "The user does not have an SMTP mail ID and SMTP server configured";
                asyncResp->res.result(boost::beast::http::status::bad_request);
                return;
            }
            else if (SMTPMailId.empty() && !smtpDisabled)
            {
                asyncResp->res.jsonValue["error"] =
                    "SMTP Mail ID is not configured for user";
                asyncResp->res.result(boost::beast::http::status::bad_request);
                return;
            }
            else if (!SMTPMailId.empty() && smtpDisabled)
            {
                asyncResp->res.jsonValue["error"] =
                    "SMTP Server is not configured";
                asyncResp->res.result(boost::beast::http::status::bad_request);
                return;
            }
            generateOTP(asyncResp, username);
        });
}

inline void handleGenerateOTP(const crow::Request& req,
                            const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    std::string_view contentType = req.getHeaderValue("content-type");
    std::string username;
    nlohmann::json loginCredentials;

    if (contentType.starts_with("application/json"))
    {
        loginCredentials = nlohmann::json::parse(req.body(), nullptr, false);
        if (loginCredentials.is_discarded())
        {
            BMCWEB_LOG_DEBUG("Bad json in request");
            asyncResp->res.result(boost::beast::http::status::bad_request);
            return;
        }
        nlohmann::json::iterator userIt = loginCredentials.find("username");

        if (userIt != loginCredentials.end())
        {
            const std::string* userStr = userIt->get_ptr<const std::string*>();
   
            if (userStr != nullptr)
            {
                username = *userStr;
            }
        }
    }
    else
    {
        // check if auth was provided as a headers
        username = req.getHeaderValue("username");
    }

    if (!username.empty())
    {
        sdbusplus::message::object_path path("/xyz/openbmc_project/user");
        dbus::utility::getManagedObjects(
            "xyz.openbmc_project.User.Manager", path,
            [asyncResp, username,
             &req](const boost::system::error_code& ec,
                   const dbus::utility::ManagedObjectType& users) {
                if (ec)
                {
                    BMCWEB_LOG_DEBUG("DBUS response error {}", ec);
                    return;
                }
                const auto userIt = std::ranges::find_if(
                    users,
                    [username](
                        const std::pair<sdbusplus::message::object_path,
                                        dbus::utility::DBusInterfacesMap>&
                            user) {
                        return username == user.first.filename();
                    });
                if (userIt == users.end())
                {
                    std::ostringstream oss;
                    oss << "Username " << username << " Not Found";
                    asyncResp->res.jsonValue["error"] = oss.str();
                    asyncResp->res.result(
                        boost::beast::http::status::not_found);
                    return;
                }
                else
                {
                    dbus::utility::getProperty<bool>(
                    "xyz.openbmc_project.mail", "/xyz/openbmc_project/mail/alert",
                    "xyz.openbmc_project.mail.alert.primary", "Enable",
                    [asyncResp,username](const boost::system::error_code& ec,
                                    const bool primarySMTPEnable) {
                        if (ec)
                        {
                            BMCWEB_LOG_ERROR("DBUS response error {}", ec);
                            return;
                        }
                        if (primarySMTPEnable)
                        {
                            checkSMTPMailId(asyncResp, username);
                        }   
                        else
                        {
                            dbus::utility::getProperty<bool>(
                            "xyz.openbmc_project.mail", "/xyz/openbmc_project/mail/alert",
                            "xyz.openbmc_project.mail.alert.secondary", "Enable",
                            [asyncResp, username](const boost::system::error_code& ec,
                                            const bool secondarySMTPEnable) {
                                if (ec)
                                {
                                    BMCWEB_LOG_ERROR("DBUS response error {}", ec);
                                    return;
                                }
                                if (!secondarySMTPEnable)
                                {
                                    BMCWEB_LOG_ERROR("SMTP servers disabled, checking mail configuration");
                                    checkSMTPMailId(asyncResp, username, true);
                                }
                                else
                                {
                                    checkSMTPMailId(asyncResp, username);
                                }
                                
                            });

                        } 
                    });
                }
            });
    }
    else
    {
        asyncResp->res.jsonValue["error"] = "Couldn't interpret UserName";
        asyncResp->res.result(boost::beast::http::status::bad_request);
    }
}

inline void handleValidateOTP(const crow::Request& req,
                            const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
        std::string_view contentType = req.getHeaderValue("content-type");
        std::string username;
        std::string verificationcode;
        std::string password;

        nlohmann::json loginCredentials;
       
        if (contentType.starts_with("application/json"))
        {
            loginCredentials = nlohmann::json::parse(req.body(), nullptr, false);
            if (loginCredentials.is_discarded())
            {
                BMCWEB_LOG_DEBUG("Bad json in request");
                asyncResp->res.result(boost::beast::http::status::bad_request);
                return;
            }

            nlohmann::json::iterator userIt = loginCredentials.find("username");
            nlohmann::json::iterator verificationcodeIt =
                loginCredentials.find("verificationcode");
            nlohmann::json::iterator passwordIt =
                loginCredentials.find("password");
    
            if (userIt != loginCredentials.end() &&
                verificationcodeIt != loginCredentials.end() && passwordIt != loginCredentials.end())
            {
                const std::string* userStr = userIt->get_ptr<const std::string*>();
                const std::string* verificationcodeStr =
                    verificationcodeIt->get_ptr<const std::string*>();
                const std::string* passwordStr =
                    passwordIt->get_ptr<const std::string*>();
    
                if (userStr != nullptr && verificationcodeStr != nullptr && passwordStr != nullptr)
                {
                    username = *userStr;
                    verificationcode = *verificationcodeStr;
                    password = *passwordStr;
                }
            }
        }
        else
        {
            username = req.getHeaderValue("username");
            verificationcode = req.getHeaderValue("verificationcode");
            password = req.getHeaderValue("password");
        }
    
        if (!username.empty() && !verificationcode.empty() && !password.empty())
        {
              crow::connections::systemBus->async_method_call(
                [asyncResp](const boost::system::error_code& ec, bool response) {
                    if (ec)
                    {
                        BMCWEB_LOG_DEBUG("DBUS response error {}", ec);
                        return;
                    }
                    if (!response)
                    {
                        asyncResp->res.jsonValue["error"] = "Failed to validate OTP code";
                        asyncResp->res.result(boost::beast::http::status::bad_request);
                    }
                },
                "xyz.openbmc_project.User.Manager",
                "/xyz/openbmc_project/user",
                "xyz.openbmc_project.User.Manager",
                "OTPValidationPasswordUpdate", username , verificationcode ,password); 
        }
        else
        {
            asyncResp->res.jsonValue["error"] = "Required properties are missing from the request";
            asyncResp->res.result(boost::beast::http::status::bad_request);
        }
}
inline void requestRoutes(App& app)
{
    BMCWEB_ROUTE(app, "/login")
        .methods(boost::beast::http::verb::post)(handleLogin);

    BMCWEB_ROUTE(app, "/logout")
        .methods(boost::beast::http::verb::post)(handleLogout);

    BMCWEB_ROUTE(app, "/generate_otp")
        .methods(boost::beast::http::verb::post)(handleGenerateOTP);
        
    BMCWEB_ROUTE(app, "/validate_otp")
        .methods(boost::beast::http::verb::post)(handleValidateOTP);
}
} // namespace login_routes
} // namespace crow
