// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#pragma once

#include <security/pam_appl.h>
#include <systemd/sd-journal.h>

#include <dbus_utility.hpp>

#include <cstring>
#include <memory>
#include <span>
#include <string_view>
#include <variant>

struct PasswordData
{
    struct Response
    {
        std::string_view prompt;
        std::string value;
    };

    std::vector<Response> responseData;

    int addPrompt(std::string_view prompt, std::string_view value)
    {
        if (value.size() + 1 > PAM_MAX_MSG_SIZE)
        {
            BMCWEB_LOG_ERROR("value length error", prompt);
            return PAM_CONV_ERR;
        }
        responseData.emplace_back(prompt, std::string(value));
        return PAM_SUCCESS;
    }

    int makeResponse(const pam_message& msg, pam_response& response)
    {
      
        switch (msg.msg_style)
        {
            case PAM_PROMPT_ECHO_ON:
                break;
            case PAM_PROMPT_ECHO_OFF:
            {
                std::string prompt(msg.msg);
                auto iter = std::ranges::find_if(
                    responseData, [&prompt](const Response& data) {
                        return prompt.starts_with(data.prompt);
                    });
                if (iter == responseData.end())
                {
                    return PAM_CONV_ERR;
                }
                response.resp = strdup(iter->value.c_str());
                return PAM_SUCCESS;
            }
            break;
            case PAM_ERROR_MSG:
            {
                BMCWEB_LOG_ERROR("Pam error {}", msg.msg);
            }
            break;
            case PAM_TEXT_INFO:
            {
                BMCWEB_LOG_ERROR("Pam info {}", msg.msg);
            }
            break;
            default:
            {
                return PAM_CONV_ERR;
            }
        }
        return PAM_SUCCESS;
    }
};

// function used to get user input
inline int pamFunctionConversation(int numMsg, const struct pam_message** msgs,
                                   struct pam_response** resp, void* appdataPtr)
{
    if ((appdataPtr == nullptr) || (msgs == nullptr) || (resp == nullptr))
    {
        return PAM_CONV_ERR;
    }

    if (numMsg <= 0 || numMsg >= PAM_MAX_NUM_MSG)
    {
        return PAM_CONV_ERR;
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    PasswordData* appPass = reinterpret_cast<PasswordData*>(appdataPtr);
    auto msgCount = static_cast<size_t>(numMsg);
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays)
    auto responseArrPtr = std::make_unique<pam_response[]>(msgCount);
    auto responses = std::span(responseArrPtr.get(), msgCount);
    auto messagePtrs = std::span(msgs, msgCount);
    for (size_t i = 0; i < msgCount; ++i)
    {
        const pam_message& msg = *(messagePtrs[i]);

        pam_response& response = responses[i];
        response.resp_retcode = 0;
        response.resp = nullptr;

        int r = appPass->makeResponse(msg, response);
        if (r != PAM_SUCCESS)
        {
            return r;
        }
    }

    *resp = responseArrPtr.release();
    return PAM_SUCCESS;
}

// checking the UserLockedForFailedAttempt, if it is true then
// pam_athenticate will return PAM_MAXTRIES

static bool pamMaxtriescheck(std::string& userName)
{
    const char* userNameStr = userName.c_str();
    std::string objPath = "/xyz/openbmc_project/user/";
    std::variant<bool> lockedUserValue;
    bool UserMaxtriesReached;
    objPath += userNameStr;

    try
    {
        sdbusplus::message::message getlockedUser =
            crow::connections::systemBus->new_method_call(
                "xyz.openbmc_project.User.Manager", objPath.c_str(), 
                "org.freedesktop.DBus.Properties", "Get");
        getlockedUser.append("xyz.openbmc_project.User.Attributes", 
                            "UserLockedForFailedAttempt");

        sdbusplus::message::message getlockedUserResp =
            crow::connections::systemBus->call(getlockedUser);
        getlockedUserResp.read(lockedUserValue);
    }
    catch (sdbusplus::exception_t&)
    {
        return false;
    }
    UserMaxtriesReached = std::get<bool>(lockedUserValue);
    if (UserMaxtriesReached == true)
    {
        return true;
    }
    return false;
}

/**
 * @brief Attempt username/password authentication via PAM.
 * @param username The provided username aka account name.
 * @param password The provided password.
 * @param token The provided MFA token.
 * @returns PAM error code or PAM_SUCCESS for success. */
inline int pamAuthenticateUser(std::string_view username,
                               std::string_view password,
                               std::optional<std::string> token, 
                               const boost::asio::ip::address &ip = boost::asio::ip::address(),
                               bool serviceWebserver = true)
{
    std::string userStr(username);
    PasswordData data;
    const std::string serviceType = serviceWebserver ? "webserver" : "web-silent";

    if (int ret = data.addPrompt("Password: ", password); ret != PAM_SUCCESS)
    {
        return ret;
    }
    if (token)
    {
        if (int ret = data.addPrompt("Verification code: ", *token);
            ret != PAM_SUCCESS)
        {
            return ret;
        }
    }
    const struct pam_conv localConversation = {pamFunctionConversation, &data};
    pam_handle_t* localAuthHandle = nullptr; // this gets set by pam_start

    bool pamMaxerror;

    int retval = pam_start(serviceType.c_str(), userStr.c_str(), &localConversation,
                           &localAuthHandle);
    if (retval != PAM_SUCCESS)
    {
        return retval;
    }

    retval = pam_authenticate(localAuthHandle,
                              PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK);
    if (retval != PAM_SUCCESS)
    {
        if (serviceWebserver)
        {
            std::string severity = "xyz.openbmc_project.Logging.Entry.Level.Warning";
            auto bus = sdbusplus::bus::new_default_system();
            sdbusplus::message::message m = bus.new_method_call("xyz.openbmc_project.Logging", "/xyz/openbmc_project/logging",
                    "xyz.openbmc_project.Logging.Create", "Create" );
            std::string journalMsg = "InvalidLoginAttempted:HTTPS";

            m.append(journalMsg, severity, std::map<std::string, std::string>());
            try
            {
                bus.call(m);
            }
            catch (const sdbusplus::exception_t& e)
            {
                std::cerr << "Failed to create log entry: " << e.what() << std::endl;
            }

            sd_journal_send("MESSAGE= %s", "Invalid login attempted on HTTPS",
                            "PRIORITY=%i", LOG_WARNING, "REDFISH_MESSAGE_ID=%s",
                            "OpenBMC.0.1.InvalidLoginAttempted",
                            "REDFISH_MESSAGE_ARGS=%s", "HTTPS", NULL);
        }
        pam_end(localAuthHandle, PAM_SUCCESS); // ignore retval

        pamMaxerror = pamMaxtriescheck(userStr);
        if (pamMaxerror == true)
        {
            return PAM_MAXTRIES;
        }
        return retval;
    }

    if (!ip.is_unspecified())
    {
        auto ipaddr = ip.to_string();
        if (ip.is_v6() && ip.to_v6().is_v4_mapped())
        {
            ipaddr = boost::asio::ip::make_address_v4(boost::asio::ip::v4_mapped,ip.to_v6()).to_string();
        }
        retval = pam_set_item(localAuthHandle, PAM_RHOST, ipaddr.c_str());
        if (retval != PAM_SUCCESS)
        {
            pam_end(localAuthHandle, PAM_SUCCESS); // ignore retval
            return retval;
        }
    }

    /* check that the account is healthy */
    retval = pam_acct_mgmt(localAuthHandle, PAM_DISALLOW_NULL_AUTHTOK);
    if (retval != PAM_SUCCESS)
    {
        pam_end(localAuthHandle, PAM_SUCCESS); // ignore retval
        return retval;
    }

    return pam_end(localAuthHandle, PAM_SUCCESS);
}

inline int pamUpdatePassword(const std::string& username,
                             const std::string& password)
{
    BMCWEB_LOG_ERROR("pamUpdatePassword: Starting for user {}", username);
    PasswordData data;
    if (int ret = data.addPrompt("New password: ", password);
        ret != PAM_SUCCESS)
    {
        BMCWEB_LOG_ERROR("pamUpdatePassword: addPrompt 'New password' failed with ret={}", ret);
        return ret;
    }

    if (int ret = data.addPrompt("Retype new password: ", password);
        ret != PAM_SUCCESS)
    {
         BMCWEB_LOG_ERROR("pamUpdatePassword: addPrompt 'Retype new password' failed with ret={}", ret);
         return ret;
    }
    const struct pam_conv localConversation = {pamFunctionConversation, &data};
    pam_handle_t* localAuthHandle = nullptr; // this gets set by pam_start

    int retval = pam_start("webserver", username.c_str(), &localConversation,
                           &localAuthHandle);

    if (retval != PAM_SUCCESS)
    {
        BMCWEB_LOG_ERROR("pamUpdatePassword: pam_start failed with retval={}", retval);
        return retval;
    }

    retval = pam_chauthtok(localAuthHandle, PAM_SILENT);
    if (retval != PAM_SUCCESS)
    {
        if (retval == PAM_AUTHTOK_RECOVERY_ERR)
        {
            BMCWEB_LOG_ERROR("pamUpdatePassword: Password corruption detected, retval={}", retval);
        }
        else
        {
            BMCWEB_LOG_ERROR("pamUpdatePassword: pam_chauthtok failed with retval={}", retval);
        }
        pam_end(localAuthHandle, PAM_SUCCESS);
        return retval;
    }

    BMCWEB_LOG_ERROR("pamUpdatePassword: Success for user {}", username);
    return pam_end(localAuthHandle, PAM_SUCCESS);
}
