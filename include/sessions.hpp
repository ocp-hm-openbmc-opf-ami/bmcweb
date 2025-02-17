// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#pragma once

#include "logging.hpp"
#include "ossl_random.hpp"
#include "utility.hpp"
#include "utils/ip_utils.hpp"

#include <nlohmann/json.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/message.hpp>

#include <algorithm>
#include <csignal>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <vector>

namespace persistent_data
{

// entropy: 20 characters, 62 possibilities.  log2(62^20) = 119 bits of
// entropy.  OWASP recommends at least 64
// https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-entropy
constexpr std::size_t sessionTokenSize = 20;

enum class SessionType
{
    None,
    Basic,
    Session,
    Cookie,
    MutualTLS
};

struct UserSession
{
    std::string uniqueId;
    std::string sessionToken;
    std::string username;
    std::string csrfToken;
    std::optional<std::string> clientId;
    std::string clientIp;
    std::string AMIsessionType;
    std::chrono::time_point<std::chrono::steady_clock> lastUpdated;
    SessionType sessionType{SessionType::None};
    bool cookieAuth = false;
    bool isConfigureSelfOnly = false;
    std::string userRole;
    std::vector<std::string> userGroups;
    int userId;
    // Use counter since one user can have multiple kvm connections
    int kvmConnections = 0;
    // currently there is only 2 nbd slots
    std::array<bool, 2> vmNbdActive = {false, false};

    // There are two sources of truth for isConfigureSelfOnly:
    //  1. When pamAuthenticateUser() returns PAM_NEW_AUTHTOK_REQD.
    //  2. D-Bus User.Manager.GetUserInfo property UserPasswordExpired.
    // These should be in sync, but the underlying condition can change at any
    // time.  For example, a password can expire or be changed outside of
    // bmcweb.  The value stored here is updated at the start of each
    // operation and used as the truth within bmcweb.

    /**
     * @brief Fills object with data from UserSession's JSON representation
     *
     * This replaces nlohmann's from_json to ensure no-throw approach
     *
     * @param[in] j   JSON object from which data should be loaded
     *
     * @return a shared pointer if data has been loaded properly, nullptr
     * otherwise
     */
    static std::shared_ptr<UserSession>
        fromJson(const nlohmann::json::object_t& j)
    {
        std::shared_ptr<UserSession> userSession =
            std::make_shared<UserSession>();
        for (const auto& element : j)
        {
            const std::string* thisValue =
                element.second.get_ptr<const std::string*>();
            if (thisValue == nullptr)
            {
                BMCWEB_LOG_ERROR("Error reading persistent store.  Property {} "
                                 "was not of type string",
                                 element.first);
                continue;
            }
            if (element.first == "unique_id")
            {
                userSession->uniqueId = *thisValue;
            }
            else if (element.first == "session_token")
            {
                userSession->sessionToken = *thisValue;
            }
            else if (element.first == "csrf_token")
            {
                userSession->csrfToken = *thisValue;
            }
            else if (element.first == "username")
            {
                userSession->username = *thisValue;
            }
            else if (element.first == "client_id")
            {
                userSession->clientId = *thisValue;
            }
            else if (element.first == "client_ip")
            {
                userSession->clientIp = *thisValue;
            }

            else
            {
                BMCWEB_LOG_ERROR(
                    "Got unexpected property reading persistent file: {}",
                    element.first);
                continue;
            }
        }
        // If any of these fields are missing, we can't restore the session, as
        // we don't have enough information.  These 4 fields have been present
        // in every version of this file in bmcwebs history, so any file, even
        // on upgrade, should have these present
        if (userSession->uniqueId.empty() || userSession->username.empty() ||
            userSession->sessionToken.empty() || userSession->csrfToken.empty())
        {
            BMCWEB_LOG_DEBUG("Session missing required security "
                             "information, refusing to restore");
            return nullptr;
        }

        // For now, sessions that were persisted through a reboot get their idle
        // timer reset.  This could probably be overcome with a better
        // understanding of wall clock time and steady timer time, possibly
        // persisting values with wall clock time instead of steady timer, but
        // the tradeoffs of all the corner cases involved are non-trivial, so
        // this is done temporarily
        userSession->lastUpdated = std::chrono::steady_clock::now();
        userSession->sessionType = SessionType::Session;

        return userSession;
    }
};

enum class MTLSCommonNameParseMode
{
    Invalid = 0,
    // This section approximately matches Redfish AccountService
    // CertificateMappingAttribute,  plus bmcweb defined OEM ones.
    // Note, IDs in this enum must be maintained between versions, as they are
    // persisted to disk
    Whole = 1,
    CommonName = 2,
    UserPrincipalName = 3,

    // Intentional gap for future DMTF-defined enums

    // OEM parsing modes for various OEMs
    Meta = 100,
};

inline MTLSCommonNameParseMode getMTLSCommonNameParseMode(std::string_view name)
{
    if (name == "CommonName")
    {
        return MTLSCommonNameParseMode::CommonName;
    }
    if (name == "Whole")
    {
        // Not yet supported
        // return MTLSCommonNameParseMode::Whole;
    }
    if (name == "UserPrincipalName")
    {
        // Not yet supported
        // return MTLSCommonNameParseMode::UserPrincipalName;
    }
    if constexpr (BMCWEB_META_TLS_COMMON_NAME_PARSING)
    {
        if (name == "Meta")
        {
            return MTLSCommonNameParseMode::Meta;
        }
    }
    return MTLSCommonNameParseMode::Invalid;
}

struct AuthConfigMethods
{
    // Authentication paths
    bool basic = BMCWEB_BASIC_AUTH;
    bool sessionToken = BMCWEB_SESSION_AUTH;
    bool xtoken = BMCWEB_XTOKEN_AUTH;
    bool cookie = BMCWEB_COOKIE_AUTH;
    bool tls = BMCWEB_MUTUAL_TLS_AUTH;

    // Whether or not unauthenticated TLS should be accepted
    // true = reject connections if mutual tls is not provided
    // false = allow connection, and allow user to use other auth method
    // Always default to false, because root certificates will not
    // be provisioned at startup
    bool tlsStrict = false;

    MTLSCommonNameParseMode mTLSCommonNameParsingMode =
        getMTLSCommonNameParseMode(
            BMCWEB_MUTUAL_TLS_COMMON_NAME_PARSING_DEFAULT);

    void fromJson(const nlohmann::json::object_t& j)
    {
        for (const auto& element : j)
        {
            const bool* value = element.second.get_ptr<const bool*>();
            if (value != nullptr)
            {
                if (element.first == "XToken")
                {
                    xtoken = *value;
                }
                else if (element.first == "Cookie")
                {
                    cookie = *value;
                }
                else if (element.first == "SessionToken")
                {
                    sessionToken = *value;
                }
                else if (element.first == "BasicAuth")
                {
                    basic = *value;
                }
                else if (element.first == "TLS")
                {
                    tls = *value;
                }
                else if (element.first == "TLSStrict")
                {
                    tlsStrict = *value;
                }
            }
            const uint64_t* intValue =
                element.second.get_ptr<const uint64_t*>();
            if (intValue != nullptr)
            {
                if (element.first == "MTLSCommonNameParseMode")
                {
                    if (*intValue <= 2 || *intValue == 100)
                    {
                        mTLSCommonNameParsingMode =
                            static_cast<MTLSCommonNameParseMode>(*intValue);
                    }
                    else
                    {
                        BMCWEB_LOG_ERROR(
                            "Json value of {} was out of range of the enum.  Ignoring",
                            *intValue);
                    }
                }
            }
        }
    }
};

class SessionStore
{
  public:
    std::shared_ptr<UserSession> generateUserSession(
        std::string_view username, const boost::asio::ip::address& clientIp,
        const std::optional<std::string>& clientId, SessionType sessionType,
        bool isConfigureSelfOnly = false,
        std::string sessionTypeString = "Redfish")
    {
        // Count the number of active sessions of the specific type
        size_t activeWebUISessions = 1;
        size_t activeRedfishSessions = 1;
        webSessionReached = false;
        redfishSessionReached = false;

        // Iterate through all sessions to count WebUI and Redfish sessions
        for (const auto& session : authTokens)
        {
            if (session.second->AMIsessionType == "WebUI")
            {
                activeWebUISessions++;
            }
            else if (session.second->AMIsessionType == "Redfish")
            {
                activeRedfishSessions++;
            }
        }

        // Check if the total session count exceeds the limit
        if (activeWebUISessions > maxWebuiSessions &&
            sessionTypeString == "WebUI")
        {
            BMCWEB_LOG_ERROR(
                "Maximum WebUI sessions reached, cannot create new session.");
            webSessionReached = true;
            return nullptr;
        }

        if (activeRedfishSessions > maxRedfishSessions &&
            sessionTypeString == "Redfish")
        {
            BMCWEB_LOG_ERROR(
                "Maximum Redfish sessions reached, cannot create new session.");
            redfishSessionReached = true;
            return nullptr;
        }

        // Only need csrf tokens for cookie based auth, token doesn't matter
        std::string sessionToken =
            bmcweb::getRandomIdOfLength(sessionTokenSize);
        std::string csrfToken = bmcweb::getRandomIdOfLength(sessionTokenSize);
        std::string uniqueId = bmcweb::getRandomIdOfLength(10);
        //
        if (sessionToken.empty() || csrfToken.empty() || uniqueId.empty())
        {
            BMCWEB_LOG_ERROR("Failed to generate session tokens");
            return nullptr;
        }

        // Increment the UserId for each new session
        static int currentUserId = 1;
        int userId = currentUserId++;

        std::string AMIsessionType = sessionTypeString;

        auto session = std::make_shared<UserSession>(UserSession{
            uniqueId,
            sessionToken,
            std::string(username),
            csrfToken,
            clientId,
            redfish::ip_util::toString(clientIp),
            AMIsessionType,
            std::chrono::steady_clock::now(),
            sessionType,
            false,
            isConfigureSelfOnly,
            "",
            {},
            userId});
        auto it = authTokens.emplace(sessionToken, session);
        // Only need to write to disk if session isn't about to be destroyed.
        needWrite = sessionType != SessionType::Basic &&
                    sessionType != SessionType::MutualTLS;
        return it.first->second;
    }

    std::shared_ptr<UserSession> loginSessionByToken(std::string_view token)
    {
        applySessionTimeouts();
        if (token.size() != sessionTokenSize)
        {
            return nullptr;
        }
        auto sessionIt = authTokens.find(std::string(token));
        if (sessionIt == authTokens.end())
        {
            return nullptr;
        }
        std::shared_ptr<UserSession> userSession = sessionIt->second;
        userSession->lastUpdated = std::chrono::steady_clock::now();
        return userSession;
    }

    std::shared_ptr<UserSession> getSessionByUid(std::string_view uid)
    {
        applySessionTimeouts();
        // TODO(Ed) this is inefficient
        auto sessionIt = authTokens.begin();
        while (sessionIt != authTokens.end())
        {
            if (sessionIt->second->uniqueId == uid)
            {
                return sessionIt->second;
            }
            sessionIt++;
        }
        return nullptr;
    }

    void removeSession(const std::shared_ptr<UserSession>& session)
    {
        authTokens.erase(session->sessionToken);
        session->kvmConnections = 0;
        needWrite = true;
    }

    std::vector<std::string> getAllUniqueIds()
    {
        //applySessionTimeouts();
        std::vector<std::string> ret;
        ret.reserve(authTokens.size());
        for (auto& session : authTokens)
        {
            ret.push_back(session.second->uniqueId);
        }
        return ret;
    }

    std::vector<std::string> getUniqueIdsBySessionType(SessionType type)
    {
        applySessionTimeouts();

        std::vector<std::string> ret;
        ret.reserve(authTokens.size());

        for (auto& session : authTokens)
        {
            if (type == session.second->sessionType)
            {
                ret.push_back(session.second->uniqueId);
            }
        }
        return ret;
    }

    std::vector<std::shared_ptr<UserSession>> getSessions()
    {
        std::vector<std::shared_ptr<UserSession>> sessions;
        sessions.reserve(authTokens.size());
        for (auto& session : authTokens)
        {
            sessions.push_back(session.second);
        }
        return sessions;
    }

    void removeSessionsByUsername(std::string_view username)
    {
        std::erase_if(authTokens, [username](const auto& value) {
            if (value.second == nullptr)
            {
                return false;
            }
            return value.second->username == username;
        });
    }

    void removeSessionsByUsernameExceptSession(
        std::string_view username, const std::shared_ptr<UserSession>& session)
    {
        std::erase_if(authTokens, [username, session](const auto& value) {
            if (value.second == nullptr)
            {
                return false;
            }

            return value.second->username == username &&
                   value.second->uniqueId != session->uniqueId;
        });
    }

    void updateAuthMethodsConfig(const AuthConfigMethods& config)
    {
        bool isTLSchanged = (authMethodsConfig.tls != config.tls);
        authMethodsConfig = config;
        needWrite = true;
        if (isTLSchanged)
        {
            // recreate socket connections with new settings
            std::raise(SIGHUP);
        }
    }

    AuthConfigMethods& getAuthMethodsConfig()
    {
        return authMethodsConfig;
    }

    bool needsWrite() const
    {
        return needWrite;
    }
    int64_t getTimeoutInSeconds() const
    {
        return std::chrono::seconds(timeoutInSeconds).count();
    }
    std::chrono::time_point<std::chrono::steady_clock>
        getTimeSinceLastTimeoutInSeconds() const
    {
        return lastTimeoutUpdate;
    }

    void updateSessionTimeout(std::chrono::seconds newTimeoutInSeconds)
    {
        timeoutInSeconds = newTimeoutInSeconds;
        needWrite = true;
    }
    void updatelastSessionTime()
    {
        auto timeNow = std::chrono::steady_clock::now();
        lastTimeoutUpdate = timeNow;
    }


    std::size_t getMaxWebuiSessions()
    {
        return maxWebuiSessions;
    }

    bool getRedfishSessionReached()
    {
        return redfishSessionReached;
    }
    bool getWebSessionReached()
    {
        return webSessionReached;
    }

    static SessionStore& getInstance()
    {
        static SessionStore sessionStore;
        return sessionStore;
    }

    void applySessionTimeouts()
    {
        auto timeNow = std::chrono::steady_clock::now();
        if (timeNow - lastTimeoutUpdate > std::chrono::seconds(1))
        {
            lastTimeoutUpdate = timeNow;
            auto authTokensIt = authTokens.begin();
            while (authTokensIt != authTokens.end())
            {
                if (timeNow - authTokensIt->second->lastUpdated >=
                    timeoutInSeconds)
                {
                    authTokensIt = authTokens.erase(authTokensIt);

                    needWrite = true;
                }
                else
                {
                    authTokensIt++;
                }
            }
        }
    }

    void initializeDbus()
    {
        auto bus = sdbusplus::bus::new_default();
        // Create the matcher to listen for property changes on the session
        // timeout
        sessionTimeoutMatcher = std::make_unique<sdbusplus::bus::match_t>(
            bus,
            "interface='org.freedesktop.DBus.Properties',type='signal',"
            "member='PropertiesChanged',"
            "path='/xyz/openbmc_project/control/service/bmcweb'",
            [this](sdbusplus::message_t& msg) {
            handleSessionTimeoutPropertyChanged(msg);
            });
    }

    // Handle session timeout property change
    void handleSessionTimeoutPropertyChanged(sdbusplus::message_t& msg)
    {
        std::string interfaceName;
        std::map<std::string, std::variant<bool, uint16_t, uint64_t>>
            properties;

        msg.read(interfaceName, properties);
        auto it = properties.find("SessionTimeOut");
        if (it != properties.end())
        {
            auto timeoutValue = std::get_if<uint64_t>(&it->second);
            if (*timeoutValue > 0)
            {
                updateSessionTimeout(std::chrono::seconds(*timeoutValue));
            }
        }
    }

    // Fetching Maxsession values from srvcfg.json
    std::size_t loadMaxSession(std::string ServiceName)
    {
        std::string filePath = "/etc/srvcfg-manager/srvcfg.json";
        std::ifstream file(filePath);
        if (!file.is_open())
        {
            BMCWEB_LOG_ERROR("Error opening config file: {}", filePath);
            return 0;
        }

        nlohmann::json config;

        file >> config;

        // Now, find the service and retrieve the max_session_limit
        try
        {
            for (const auto& service : config["services"])
            {
                if (service["name"] == ServiceName)
                {
                    std::size_t value = service["max_session_limit"];
                    return value;
                }
                else if (ServiceName == "redfish" && service["name"] == "bmcweb")
                {
                    std::size_t value = service["redfish_max_session_limit"];
                    return value;
                }
                else if (ServiceName == "web" && service["name"] == "bmcweb")
                {
                    std::size_t value = service["web_max_session_limit"];
                    return value;
                }
            }
        }
        catch (const nlohmann::json::exception& e)
        {
            BMCWEB_LOG_ERROR("Error accessing JSON: {}", e.what());
        }
        return 0;
    }

    SessionStore(const SessionStore&) = delete;
    SessionStore& operator=(const SessionStore&) = delete;
    SessionStore(SessionStore&&) = delete;
    SessionStore& operator=(const SessionStore&&) = delete;
    ~SessionStore() = default;

    std::unordered_map<std::string, std::shared_ptr<UserSession>,
                        std::hash<std::string>, bmcweb::ConstantTimeCompare>
        authTokens;

    std::chrono::time_point<std::chrono::steady_clock> lastTimeoutUpdate;
    bool needWrite{false};
    std::chrono::seconds timeoutInSeconds;
    std::size_t maxRedfishSessions = loadMaxSession("redfish");
    std::size_t maxWebuiSessions = loadMaxSession("web");
    bool redfishSessionReached = false;
    bool webSessionReached = false;
    AuthConfigMethods authMethodsConfig;

  private:
    SessionStore() : timeoutInSeconds(1800)
    {

        initializeDbus(); // Initialize D-Bus matchers
    }
    std::unique_ptr<sdbusplus::bus::match_t> sessionTimeoutMatcher;
};

} // namespace persistent_data
