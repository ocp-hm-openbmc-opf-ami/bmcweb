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

namespace crow
{

namespace login_routes
{

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

            if (session && session->userRole.empty())
            {
                std::string userPath = "/xyz/openbmc_project/user/" + session->username;
                try
                {
                    auto bus = sdbusplus::bus::new_default_system();
                    auto method = bus.new_method_call(
                        "xyz.openbmc_project.User.Manager",
                        userPath.c_str(),
                        "org.freedesktop.DBus.Properties",
                        "Get");

                    method.append("xyz.openbmc_project.User.Attributes", "UserPrivilege");

                    auto reply = bus.call(method);

                    std::variant<std::string> value;
                    reply.read(value);
                    session->userRole = std::get<std::string>(value);

                    BMCWEB_LOG_INFO("Fetched userRole from D-Bus: {}", session->userRole);
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
            
	    std::unordered_map<std::string, uint8_t> roleToPriv = {{"Callback", 1},{"priv-user", 2},{"priv-operator", 3},{"OEM Proprietary", 5}};
            uint8_t priv = roleToPriv.contains(session->userRole) ? roleToPriv[session->userRole] : 4;

            auto b = sdbusplus::bus::new_default_system();
            auto method = b.new_method_call("xyz.openbmc_project.SessionManager", "/xyz/openbmc_project/SessionManager",
                                            "xyz.openbmc_project.SessionManager", "SessionRegister");
            method.append(sessionId, session->clientIp, session->username, sessionType, priv, static_cast<uint8_t>(userId), "");
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
            auto m =
                bus.new_method_call("xyz.openbmc_project.SessionManager",
                                    "/xyz/openbmc_project/SessionManager",
                                    "org.freedesktop.DBus.Properties", "Get");

            m.append("xyz.openbmc_project.SessionManager.Web",
                     "WebSessionInfo");
	 try
	  {
            sdbusplus::message::message r = bus.call(m);

            std::variant<
                std::vector<std::tuple<uint8_t, std::string, std::string,
                                       uint8_t, uint8_t, uint8_t, std::string>>>
                val;
            r.read(val);

            auto sessionArray = std::get<std::vector<
                std::tuple<uint8_t, std::string, std::string, uint8_t, uint8_t,
                           uint8_t, std::string>>>(val);

            if (!sessionArray.empty())
            {
                auto lastSession = sessionArray.back();
                uint8_t sessionId = std::get<0>(lastSession);
                persistent_data::sessionMap[session->uniqueId] = sessionId;
                asyncResp->res.jsonValue["Session_ID"] = "session_" + std::to_string(std::get<0>(lastSession));
            }
            else
            {
                BMCWEB_LOG_ERROR("No active session found!");
            }
	  }
            catch (const sdbusplus::exception::SdBusError& e)
           {
                   BMCWEB_LOG_ERROR("Failed to fetch WebSessionInfo from D-Bus: {}", e.what());
                return;
           }
	 
#if (BMCWEB_AMI_2FA_MACRO)
#if (BMCWEB_AMI_REP_MACRO)
            std::string user(username);
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

inline void requestRoutes(App& app)
{
    BMCWEB_ROUTE(app, "/login")
        .methods(boost::beast::http::verb::post)(handleLogin);

    BMCWEB_ROUTE(app, "/logout")
        .methods(boost::beast::http::verb::post)(handleLogout);
}
} // namespace login_routes
} // namespace crow
