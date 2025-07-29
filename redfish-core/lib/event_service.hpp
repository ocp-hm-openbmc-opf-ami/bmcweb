// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
// SPDX-FileCopyrightText: Copyright 2020 Intel Corporation
#pragma once
#include "app.hpp"
#include "event_service_manager.hpp"
#include "generated/enums/event_service.hpp"
#include "http/utility.hpp"
#include "logging.hpp"
#include "multipart_parser.hpp"
#include "query.hpp"
#include "registries.hpp"
#include "registries/privilege_registry.hpp"
#include "registries_selector.hpp"
#include "snmp_trap_event_clients.hpp"
#include "utils/json_utils.hpp"

#include <stdlib.h>

#include <boost/beast/http/fields.hpp>
#include <boost/system/error_code.hpp>
#include <boost/url/parse.hpp>
#include <sdbusplus/unpack_properties.hpp>
#include <utils/dbus_utils.hpp>

#include <charconv>
#include <memory>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <vector>

namespace redfish
{

static constexpr const std::array<const char*, 2> supportedEvtFormatTypes = {
    eventFormatType, metricReportFormatType};
static constexpr const std::array<const char*, 4> supportedRegPrefixes = {
    "Base", "OpenBMC", "TaskEvent", "HeartbeatEvent"};
static constexpr const std::array<const char*, 3> supportedRetryPolicies = {
    "TerminateAfterRetries", "SuspendRetries", "RetryForever"};

static constexpr const std::array<const char*, 2> supportedResourceTypes = {
    "Task", "Heartbeat"};

// SMTP TSL Support

/* Primary SSL Support Keys */
std::string primaryCacertFileName = "primary_cacert.pem";
std::string primaryServerCRTFileName = "primary_server.crt";
std::string primaryServerKeyFileName = "primary_server.key";
namespace fs = std::filesystem;
fs::path certsPath = "/etc/ssl/certs/";
fs::path privatePath = "/etc/ssl/private/";

fs::path primaryCACERTFilePath = certsPath / primaryCacertFileName;
fs::path primaryServerCRTFilePath = certsPath / primaryServerCRTFileName;
fs::path primaryserverKeyFilePath = privatePath / primaryServerKeyFileName;

std::string sslPrimaryCACERTFile(primaryCACERTFilePath);
std::string sslPrimaryServerCRTFile(primaryServerCRTFilePath);
std::string sslPrimaryServerKeyFile(primaryserverKeyFilePath);

/* Secondary SSL Support Keys */

std::string secondaryCacertFileName = "secondary_cacert.pem";
std::string secondaryServerCRTFileName = "secondary_server.crt";
std::string secondaryServerKeyFileName = "secondary_server.key";

fs::path secodaryCACERTFilePath = certsPath / secondaryCacertFileName;
fs::path secodaryServerCRTFilePath = certsPath / secondaryServerCRTFileName;
fs::path secodaryServerKeyFilePath = privatePath / secondaryServerKeyFileName;

std::string sslSecondaryCACERTFile(secodaryCACERTFilePath);
std::string sslSecondaryServerCRTFile(secodaryServerCRTFilePath);
std::string sslSecondaryServerKeyFile(secodaryServerKeyFilePath);

std::string SSLFileName("");
const char* commandLine("systemctl restart mail-alert-manager.service");

constexpr const char* snmpProtocolSevrice = "xyz.openbmc_project.Snmp.Conf";
constexpr const char* snmpProtocolObject = "/xyz/openbmc_project/snmp/SnmpUtils";
constexpr const char* snmpProtocolInterface =
    "xyz.openbmc_project.Snmp.SnmpUtils";
constexpr const char* snmpProtocolProp = "SnmpTrapStatus";

/* Flag for successfully setting SNMP property */
bool anySuccess = false;
bool anyFailure = false;

/*smtp interface*/
std::string interfacePrimary = "xyz.openbmc_project.mail.alert.primary";
std::string interfaceSecondary = "xyz.openbmc_project.mail.alert.secondary";

inline size_t snmpCompletedOperations = 0;

/* Holds SMTP configuration parameters for patching.*/ 
struct SmtpPatchParams
{
    std::optional<bool> authentication;
    std::optional<bool> enable;
    std::optional<std::string> host;
    std::optional<std::string> password;
    std::optional<uint16_t> port;
    std::optional<std::vector<std::string>> recipient;
    std::optional<std::string> sender;
    std::optional<bool> tlsenable;
    std::optional<std::string> username;
    
    bool hasValue() const
    {
        return authentication.has_value() || enable.has_value() ||
               host.has_value() || password.has_value() ||
               port.has_value() || recipient.has_value() ||
               sender.has_value() || tlsenable.has_value() ||
               username.has_value();
    }
};

using PropertyValue = std::variant<uint8_t, uint16_t, uint64_t, std::string,
                                   std::vector<std::string>, bool>;

const PropertyValue getSnmpProtocol()
{
    PropertyValue value;
    auto b = sdbusplus::bus::new_default_system();
    auto method = b.new_method_call(snmpProtocolSevrice, snmpProtocolObject,
                                    "org.freedesktop.DBus.Properties", "Get");
    method.append(snmpProtocolInterface, snmpProtocolProp);
    auto reply = b.call(method);
    reply.read(value);
    return value;
}

/**
 * @brief Retrieves SMTP configuration params
 *
 * @param[in] aResp  Shared pointer for generating response message.
 *
 * @return None.
 */
inline void getSmtpConfig(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                          std::string interfaces, std::string configuration)
{
    dbus::utility::getAllProperties(
        "xyz.openbmc_project.mail", "/xyz/openbmc_project/mail/alert",
        interfaces,
        [asyncResp, configuration](
            const boost::system::error_code& ec,
            const dbus::utility::DBusPropertiesMap& propertiesList) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("GetSMTPconfig: Can't get "
                                 "alertMailIface ");
                messages::internalError(asyncResp->res);
                return;
            }

            BMCWEB_LOG_DEBUG("Got {}properties for SmtpConfig",
                             propertiesList.size());

            bool authentication = true;
            bool enable = true;
            const std::string* host = nullptr;
            const std::string* password = nullptr;
            const uint16_t* port = nullptr;
            const std::vector<std::string>* recipient = nullptr;
            const std::string* sender = nullptr;
            bool TLSEnable = true;
            const std::string* username = nullptr;

            const bool success = sdbusplus::unpackPropertiesNoThrow(
                dbus_utils::UnpackErrorPrinter(), propertiesList,
                "Authentication", authentication, "Enable", enable, "Host",
                host, "Password", password, "Port", port, "Recipient",
                recipient, "Sender", sender, "TLSEnable", TLSEnable, "UserName",
                username);

            if (!success)
            {
                messages::internalError(asyncResp->res);
                return;
            }
            asyncResp->res.jsonValue["Oem"]["OpenBmc"]["SMTP"]["@odata.type"] =
                "#AMIEventService.SMTP";
            asyncResp->res.jsonValue["Oem"]["OpenBmc"]["SMTP"][configuration]
                                    ["Authentication"] = authentication;

            asyncResp->res
                .jsonValue["Oem"]["OpenBmc"]["SMTP"][configuration]["Enable"] =
                enable;

            if (host != nullptr)
            {
                asyncResp->res.jsonValue["Oem"]["OpenBmc"]["SMTP"]
                                        [configuration]["Host"] = *host;
            }
            if (username != nullptr)
            {
                asyncResp->res.jsonValue["Oem"]["OpenBmc"]["SMTP"]
                                        [configuration]["UserName"] = *username;
            }
            if (password != nullptr)
            {
                asyncResp->res.jsonValue["Oem"]["OpenBmc"]["SMTP"]
                                        [configuration]["Password"] = *password;
            }

            if (port != nullptr)
            {
                asyncResp->res.jsonValue["Oem"]["OpenBmc"]["SMTP"]
                                        [configuration]["Port"] = *port;
            }
            if (recipient != nullptr)
            {
                asyncResp->res.jsonValue["Oem"]["OpenBmc"]["SMTP"]
                                        [configuration]["Recipient"] =
                    *recipient;
            }
            if (sender != nullptr)
            {
                asyncResp->res.jsonValue["Oem"]["OpenBmc"]["SMTP"]
                                        [configuration]["Sender"] = *sender;
            }

            asyncResp->res.jsonValue["Oem"]["OpenBmc"]["SMTP"][configuration]
                                    ["TLSEnable"] = TLSEnable;
        });
}

inline std::string modifiedDateTime(const std::string& filepath)
{
    /* Modified date and time */

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
    //std::tm* gmt_tm = std::gmtime(&gmt_time);
    int offset = static_cast<int>(std::difftime(time_t, gmt_time));
    int hours = offset / 3600;
    int minutes = (offset % 3600) / 60;
    oss << (hours >= 0 ? '+' : '-') << std::setw(2) << std::setfill('0') << std::abs(hours)
        << ':' << std::setw(2) << std::setfill('0') << std::abs(minutes);

    std::string str = oss.str();
    return str;
}
inline bool ensureOpensslKeyPresentAndValid(const std::string& filepath)
{
    bool certValid = false;

    std::cerr << "Checking certs in file path " << filepath.c_str() << "\n";

    FILE* file = fopen(filepath.c_str(), "r");
    std::cerr << "Checking error logic" << "\n";
    if (file != nullptr)
    {
        certValid = true;
    }
    std::cerr << "Checking exits logic" << certValid << "\n";
    return certValid;
}

inline void
    getSmtpSSLCertificates(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    bool isPrimaryCACERT = true;
    bool isPrimaryServerKey = true;
    bool isPrimaryServerCRT = true;
    bool isSecondrayCACERT = true;
    bool isSecondrayServerKey = true;
    bool isSecondrayServerCRT = true;

    /* Primary SSL */

    std::cerr << "SSL Primary CACERT Context file= "
              << sslPrimaryCACERTFile.c_str() << "\n";
    std::cerr << "SSL Primary CRT Context file= "
              << sslPrimaryServerCRTFile.c_str() << "\n";
    std::cerr << "SSL Primary Key Context file= "
              << sslPrimaryServerKeyFile.c_str() << "\n";

    isPrimaryCACERT = ensureOpensslKeyPresentAndValid(sslPrimaryCACERTFile);
    asyncResp->res.jsonValue["Oem"]["OpenBmc"]["SMTP"]["PrimaryConfiguration"]
                            ["isCACERTExist"] = isPrimaryCACERT;
    isPrimaryServerCRT =
        ensureOpensslKeyPresentAndValid(sslPrimaryServerCRTFile);

    asyncResp->res.jsonValue["Oem"]["OpenBmc"]["SMTP"]["PrimaryConfiguration"]
                            ["isServerCRTExist"] = isPrimaryServerCRT;
    isPrimaryServerKey =
        ensureOpensslKeyPresentAndValid(sslPrimaryServerKeyFile);

    asyncResp->res.jsonValue["Oem"]["OpenBmc"]["SMTP"]["PrimaryConfiguration"]
                            ["isServerKeyExist"] = isPrimaryServerKey;

    if (isPrimaryCACERT)
    {
        std::string primaryCACERTModifiedDate =
            modifiedDateTime(sslPrimaryCACERTFile);

        std::cerr << "Modified date and time for Primary CACERT "
                  << primaryCACERTModifiedDate << "\n";

        asyncResp->res
            .jsonValue["Oem"]["OpenBmc"]["SMTP"]["PrimaryConfiguration"]
                      ["primaryCACERTModifiedDate"] = primaryCACERTModifiedDate;
    }
    if (isPrimaryServerCRT)
    {
        std::string primaryCACERTModifiedDate =
            modifiedDateTime(sslPrimaryServerCRTFile);

        std::cerr << "Modified date and time for Primary CACERT "
                  << primaryCACERTModifiedDate << "\n";

        asyncResp->res
            .jsonValue["Oem"]["OpenBmc"]["SMTP"]["PrimaryConfiguration"]
                      ["primaryserverCRTModifiedDate"] =
            primaryCACERTModifiedDate;
    }
    if (isPrimaryServerKey)
    {
        std::string primaryCACERTModifiedDate =
            modifiedDateTime(sslPrimaryServerKeyFile);

        std::cerr << "Modified date and time for Primary CACERT "
                  << primaryCACERTModifiedDate << "\n";

        asyncResp->res
            .jsonValue["Oem"]["OpenBmc"]["SMTP"]["PrimaryConfiguration"]
                      ["primaryServerKeyModifiedDate"] =
            primaryCACERTModifiedDate;
    }

    /* Secondary SSL */

    std::cerr << "SSL Secondary CACERT Context file= "
              << sslSecondaryCACERTFile.c_str() << "\n";
    std::cerr << "SSL Secondary CRT Context file= "
              << sslSecondaryServerCRTFile.c_str() << "\n";
    std::cerr << "SSL Secondary Key Context file= "
              << sslSecondaryServerKeyFile.c_str() << "\n";

    isSecondrayCACERT = ensureOpensslKeyPresentAndValid(sslSecondaryCACERTFile);
    asyncResp->res.jsonValue["Oem"]["OpenBmc"]["SMTP"]["SecondaryConfiguration"]
                            ["isCACERTExist"] = isSecondrayCACERT;
    isSecondrayServerKey =
        ensureOpensslKeyPresentAndValid(sslSecondaryServerKeyFile);

    asyncResp->res.jsonValue["Oem"]["OpenBmc"]["SMTP"]["SecondaryConfiguration"]
                            ["isServerKeyExist"] = isSecondrayServerKey;
    isSecondrayServerCRT =
        ensureOpensslKeyPresentAndValid(sslSecondaryServerCRTFile);

    asyncResp->res.jsonValue["Oem"]["OpenBmc"]["SMTP"]["SecondaryConfiguration"]
                            ["isServerCRTExist"] = isSecondrayServerCRT;

    if (isSecondrayCACERT)
    {
        std::string modifiedDate = modifiedDateTime(sslSecondaryCACERTFile);

        std::cerr << "Modified date and time for Primary CACERT "
                  << modifiedDate << "\n";

        asyncResp->res
            .jsonValue["Oem"]["OpenBmc"]["SMTP"]["SecondaryConfiguration"]
                      ["secondaryCACERTModifiedDate"] = modifiedDate;
    }
    if (isSecondrayServerCRT)
    {
        std::string modifiedDate = modifiedDateTime(sslSecondaryServerCRTFile);

        std::cerr << "Modified date and time for Primary CACERT "
                  << modifiedDate << "\n";

        asyncResp->res
            .jsonValue["Oem"]["OpenBmc"]["SMTP"]["SecondaryConfiguration"]
                      ["secondaryserverCRTModifiedDate"] = modifiedDate;
    }
    if (isSecondrayServerKey)
    {
        std::string modifiedDate = modifiedDateTime(sslSecondaryServerKeyFile);

        std::cerr << "Modified date and time for Primary CACERT "
                  << modifiedDate << "\n";

        asyncResp->res
            .jsonValue["Oem"]["OpenBmc"]["SMTP"]["SecondaryConfiguration"]
                      ["secondaryServerKeyModifiedDate"] = modifiedDate;
    }
}

inline void uploadSSLFile(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                          std::string_view body, const std::string& fileName)
{
    if (fileName == primaryCacertFileName)
    {
        std::filesystem::path path = primaryCACERTFilePath;
        std::ofstream out(path, std::ofstream::out | std::ofstream::binary |
                                    std::ofstream::trunc);
        out << body;
        out.close();
        std::cout << out.rdbuf();
        std::cerr << "Read SSl files " << out.rdbuf() << "\n";
        if (out.bad())
        {
            messages::internalError(asyncResp->res);
            return;
        }
        else
        {
            int systemRet = system(commandLine);
            if (systemRet == -1)
            {
                std::cerr << "Failed to restart the service " << systemRet
                          << "\n";
            }
            else
                messages::success(asyncResp->res);
        }
    }
    else if (fileName == primaryServerCRTFileName)
    {
        std::filesystem::path path = primaryServerCRTFilePath;
        std::ofstream out(path, std::ofstream::out | std::ofstream::binary |
                                    std::ofstream::trunc);
        out << body;
        out.close();
        std::cout << out.rdbuf();
        std::cerr << "Read SSl files " << out.rdbuf() << "\n";
        if (out.bad())
        {
            messages::internalError(asyncResp->res);
            return;
        }
        else
        {
            int systemRet = system(commandLine);
            if (systemRet == -1)
            {
                std::cerr << "Failed to restart the service " << systemRet
                          << "\n";
            }
            else
                messages::success(asyncResp->res);
        }
    }
    else if (fileName == primaryServerKeyFileName)
    {
        std::filesystem::path path = primaryserverKeyFilePath;
        std::ofstream out(path, std::ofstream::out | std::ofstream::binary |
                                    std::ofstream::trunc);
        out << body;
        out.close();
        std::cout << out.rdbuf();
        std::cerr << "Read SSl files " << out.rdbuf() << "\n";
        if (out.bad())
        {
            messages::internalError(asyncResp->res);
            return;
        }
        else
        {
            int systemRet = system(commandLine);
            if (systemRet == -1)
            {
                std::cerr << "Failed to restart the service " << systemRet
                          << "\n";
            }
            else
                messages::success(asyncResp->res);
        }
    }
    else if (fileName == secondaryCacertFileName)
    {
        std::filesystem::path path = secodaryCACERTFilePath;
        std::ofstream out(path, std::ofstream::out | std::ofstream::binary |
                                    std::ofstream::trunc);
        out << body;
        out.close();
        std::cout << out.rdbuf();
        std::cerr << "Read SSl files " << out.rdbuf() << "\n";
        if (out.bad())
        {
            messages::internalError(asyncResp->res);
            return;
        }
        else
        {
            int systemRet = system(commandLine);
            if (systemRet == -1)
            {
                std::cerr << "Failed to restart the service " << systemRet
                          << "\n";
            }
            else
                messages::success(asyncResp->res);
        }
    }
    else if (fileName == secondaryServerCRTFileName)
    {
        std::filesystem::path path = secodaryServerCRTFilePath;
        std::ofstream out(path, std::ofstream::out | std::ofstream::binary |
                                    std::ofstream::trunc);
        out << body;
        out.close();
        std::cout << out.rdbuf();
        std::cerr << "Read SSl files " << out.rdbuf() << "\n";
        if (out.bad())
        {
            messages::internalError(asyncResp->res);
            return;
        }
        else
        {
            int systemRet = system(commandLine);
            if (systemRet == -1)
            {
                std::cerr << "Failed to restart the service " << systemRet
                          << "\n";
            }
            else
                messages::success(asyncResp->res);
        }
    }
    else if (fileName == secondaryServerKeyFileName)
    {
        std::filesystem::path path = secodaryServerKeyFilePath;
        std::ofstream out(path, std::ofstream::out | std::ofstream::binary |
                                    std::ofstream::trunc);
        out << body;
        out.close();
        std::cout << out.rdbuf();
        std::cerr << "Read SSl files " << out.rdbuf() << "\n";
        if (out.bad())
        {
            messages::internalError(asyncResp->res);
            return;
        }
        else
        {
            int systemRet = system(commandLine);
            if (systemRet == -1)
            {
                std::cerr << "Failed to restart the service " << systemRet
                          << "\n";
            }
            else
                messages::success(asyncResp->res);
        }
    }
    else
    {
        messages::propertyValueEmpty(asyncResp->res,
                                     "SSL Key Certificate is not empty",
                                     "/etc/ssl/certs/");
    }
}

inline void readSSLContext(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                           const MultipartParser& parser,
                           const std::string& configurationType)
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
        BMCWEB_LOG_INFO("Parsing value", it->value());

        // The construction parameters of param_list must start with `;`
        size_t index = it->value().find(';');
        BMCWEB_LOG_INFO("Parsing value", index);
        if (index == std::string::npos)
        {
            continue;
        }

        for (const auto& param :
             boost::beast::http::param_list{it->value().substr(index)})
        {
            if (param.second.empty())
            {
                continue;
            }
            else
            {
                SSLFileName = param.second;
                std::cerr << "Read SSl Original files Name " << SSLFileName
                          << "\n";
                if (SSLFileName.substr(SSLFileName.find_last_of(".") + 1) ==
                    "crt")
                {
                    uploadData = &(formpart.content);
                    SSLFileName = configurationType + "_server.crt";
                }
                else if (SSLFileName.substr(
                             SSLFileName.find_last_of(".") + 1) == "pem")
                {
                    uploadData = &(formpart.content);
                    SSLFileName = configurationType + "_cacert.pem";
                }
                else if (SSLFileName.substr(
                             SSLFileName.find_last_of(".") + 1) == "key")
                {
                    uploadData = &(formpart.content);
                    SSLFileName = configurationType + "_server.key";
                }
                else
                    messages::propertyValueTypeError(
                        asyncResp->res, SSLFileName, "InValid Format");

                std::cerr << "Read SSl Rename files Name " << SSLFileName
                          << "\n";
            }
        }
    }

    if (uploadData == nullptr)
    {
        messages::propertyMissing(asyncResp->res, "SSL Certificates Missing");
        return;
    }
    uploadSSLFile(asyncResp, *uploadData, SSLFileName);
}

inline void handleSSLCertificatePrimaryUploadAction(
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
        readSSLContext(asyncResp, parser, "primary");
    }
}

inline void handleSSLCertificateSecondaryUploadAction(
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
        readSSLContext(asyncResp, parser, "secondary");
    }
}

bool validateMsgId(std::string messageId)
{
    std::string msgPrefix;
    std::string msgSuffix;
    std::size_t pos = messageId.find('.');
    std::size_t posLast = messageId.find_last_of('.');
    if (pos != std::string::npos && posLast != std::string::npos &&
        pos != posLast)
    {
        msgPrefix = messageId.substr(0, pos);
        msgSuffix = messageId.substr(posLast + 1);
        msgSuffix.erase(
            0, msgSuffix.find_first_not_of(' ')); // Remove leading spaces
        msgSuffix.erase(
            msgSuffix.find_last_not_of(' ') + 1); // Remove trailing spaces
    }
    else
    {
        return false;
    }

    const std::span<const redfish::registries::MessageEntry> registry =
        redfish::registries::getRegistryFromPrefix(msgPrefix);

    if (std::any_of(registry.begin(), registry.end(),
                    [&msgSuffix](
                        const redfish::registries::MessageEntry& messageEntry) {
                        BMCWEB_LOG_DEBUG(
                            "msgSuffix : {}, messageEntry.first : {}",
                            msgSuffix, messageEntry.first);
                        return msgSuffix == messageEntry.first;
                    }))
    {
        return true;
    }
    return false; // No matcing found the Message Entry
}

inline void handleauthenticationpatch(
    const std::shared_ptr<bmcweb::AsyncResp> aResp, std::string interfaces,
    std::string property, bool& authentication)
{
    dbus::utility::getProperty<std::string>(
        "xyz.openbmc_project.mail", "/xyz/openbmc_project/mail/alert",
        interfaces, "UserName",
        [aResp, interfaces, property, authentication](
            const boost::system::error_code ec1, const std::string& username) {
            if (ec1)
            {
                messages::internalError(aResp->res);
                return;
            }
            dbus::utility::getProperty<std::string>(
                "xyz.openbmc_project.mail", "/xyz/openbmc_project/mail/alert",
                interfaces, "Password",
                [aResp, interfaces, property, authentication,
                 username](const boost::system::error_code ec2,
                           const std::string& password) {
                    if (ec2)
                    {
                        messages::internalError(aResp->res);
                        return;
                    }
                    if (username.empty() && password.empty())
                    {
                        anyFailure = true;
                        messages::propertyValueEmpty(aResp->res, username,
                                                     "UserName and Password");
                        return;
                    }
                    else if (username.empty())
                    {
                        anyFailure = true;
                        messages::propertyValueEmpty(aResp->res, username,
                                                     "UserName");
                        return;
                    }
                    else if (password.empty())
                    {
                        anyFailure = true;
                        messages::propertyValueEmpty(aResp->res, password,
                                                     "Password");
                        return;
                    }
                    else
                    {
                        sdbusplus::asio::setProperty(
                            *crow::connections::systemBus,
                            "xyz.openbmc_project.mail",
                            "/xyz/openbmc_project/mail/alert", interfaces,
                            property, authentication,
                            [aResp](const boost::system::error_code& ec) {
                                if (ec)
                                {
                                    BMCWEB_LOG_ERROR(
                                        "D-Bus responses error: {}", ec);
                                    messages::internalError(aResp->res);
                                    return;
                                }
                                anySuccess = true;
                                BMCWEB_LOG_DEBUG(
                                    "Patch Authentication2 SUCESS");
                            });
                    }
                });
        });
}

bool isValidPort(uint16_t port)
{
    // These port's are not allowed to use 0,20,21,22,23,80,161,443,546 this are
    // reserved port's
    return (port >= 1 && port != 20 && port != 21 && port != 22 && port != 23 &&
            port != 80 && port != 161 && port != 443 && port != 546);
}

/* Retrieves a D-Bus property value from the SMTP interface. */
const PropertyValue getSMTPProperty(const std::string& interface,
                                    const std::string& propertyName)
{
    PropertyValue value;
    auto b = sdbusplus::bus::new_default_system();
    auto method = b.new_method_call("xyz.openbmc_project.mail", 
                                    "/xyz/openbmc_project/mail/alert",
                                    "org.freedesktop.DBus.Properties", "Get");
    method.append(interface, propertyName);
    
    auto reply = b.call(method);
    reply.read(value);
    return value;
}

/* Sets a D-Bus property on the SMTP interface asynchronously */
template <typename T>
inline void setSMTPProperty(const std::shared_ptr<bmcweb::AsyncResp>& aResp,
                            const std::string& interface,
                            const std::string& propertyName,
                            const T& propertyValue)
{
    try
    {
        auto bus = sdbusplus::bus::new_default();
        auto method = bus.new_method_call(
            "xyz.openbmc_project.mail",
            "/xyz/openbmc_project/mail/alert",
            "org.freedesktop.DBus.Properties",
            "Set");

        method.append(interface, propertyName, std::variant<T>(propertyValue));

        auto reply = bus.call(method);
        anySuccess = true;
        BMCWEB_LOG_DEBUG("SetSMTPProperty: Successfully set {}", propertyName);
    }
    catch (const sdbusplus::exception::exception& e)
    {
        BMCWEB_LOG_ERROR("SetSMTPProperty: Failed to set {}: {}", propertyName, e.what());
        messages::internalError(aResp->res);
    }
}

/* Applies SMTP patch parameters to the specified configuration (Primary/Secondary). */
inline void handleSmtpPatch(SmtpPatchParams&& input,
                            const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                            const std::string& configType)
{
    const std::string& interface = (configType == "Primary") ? 
                                    interfacePrimary : interfaceSecondary;

    if (input.port)
    {
        if (!isValidPort(*input.port))
        {
            anyFailure = true;
            messages::propertyValueIncorrect(asyncResp->res,
                        "Port", *input.port);
        }
        else
        {
            setSMTPProperty(asyncResp, interface,
                    "Port", *input.port);
        }
    }

    if (input.recipient)
    {
        if (input.recipient->size() > 4)
        {
            anyFailure = true;
            messages::arraySizeTooLong(asyncResp->res,
                        "Recipient", 4);
        }
        else
        {
            setSMTPProperty(asyncResp, interface,
                    "Recipient", *input.recipient);
        }
    }

    if (input.authentication)
    {
        if (*input.authentication)
        {
            if (input.username && input.password)
            {
                if (input.username->empty() && input.password->empty())
                {
                    anyFailure = true;
                    messages::propertyValueEmpty(asyncResp->res, 
                                *input.username, "UserName and Password");
                }
                else if (input.username->empty())
                {
                    anyFailure = true;
                    messages::propertyValueEmpty(asyncResp->res, 
                                *input.username, "UserName");
                }
                else if (input.password->empty())
                {
                    anyFailure = true;
                    messages::propertyValueEmpty(asyncResp->res, 
                                *input.password, "Password");
                }
                else
                {
                    setSMTPProperty(asyncResp, interface,
                            "Authentication", *input.authentication);
                }
            }
            else
            {
                handleauthenticationpatch(asyncResp, interface,
                        "Authentication", *input.authentication);
            }
        }
        else
        {
            setSMTPProperty(asyncResp, interface,
                    "Authentication", *input.authentication);
        }
    }

    if (input.username)
    {
        if (input.username->empty())
        {
            auto value = getSMTPProperty(interface, "Authentication");
            bool serviceEnabled = std::get<bool>(value);
            if (serviceEnabled)
            {
                anyFailure = true;
                messages::propertyValueEmpty(asyncResp->res,
                            *input.username,"UserName");
            }
            else
            {
                setSMTPProperty(asyncResp, interface,
                        "UserName", *input.username);
            }
        }
        else
        {
            setSMTPProperty(asyncResp, interface,
                    "UserName", *input.username);
        }
    }

    if (input.password)
    {
        if (input.password->empty())
        {
            auto value = getSMTPProperty(interface, "Authentication");
            bool serviceEnabled = std::get<bool>(value);
            if (serviceEnabled)
            {
                anyFailure = true;
                messages::propertyValueEmpty(asyncResp->res,
                            *input.password, "Password");
            }
            else
            {
                setSMTPProperty(asyncResp, interface,
                        "Password", *input.password);
            }
        }
        else
        {
            setSMTPProperty(asyncResp, interface,
                    "Password", *input.password);
        }
    }

    if (input.tlsenable)
    {
        const std::string& cacertFile = (configType == "Primary") ? 
                                        sslPrimaryCACERTFile : sslSecondaryCACERTFile;
        const std::string& serverKeyFile = (configType == "Primary") ? 
                                            sslPrimaryServerKeyFile : sslSecondaryServerKeyFile;
        const std::string& serverCrtFile = (configType == "Primary") ? 
                                            sslPrimaryServerCRTFile : sslSecondaryServerCRTFile;

        if (*input.tlsenable)
        {
            bool isCACERT = ensureOpensslKeyPresentAndValid(cacertFile);
            bool isServerKey = ensureOpensslKeyPresentAndValid(serverKeyFile);
            bool isServerCRT = ensureOpensslKeyPresentAndValid(serverCrtFile);

            if (!isCACERT)
            {
                anyFailure = true;
                messages::propertyValueEmpty(asyncResp->res,
                            configType + " CACERT is missing", cacertFile);
            }
            else if (!isServerKey)
            {
                anyFailure = true;
                messages::propertyValueEmpty(asyncResp->res,
                            configType + " Server Key is missing", serverKeyFile);
            }
            else if (!isServerCRT)
            {
                anyFailure = true;
                messages::propertyValueEmpty(asyncResp->res,
                            configType + " Server CRT is missing", serverCrtFile);
            }
            else
            {
                setSMTPProperty(asyncResp, interface,
                        "TLSEnable", *input.tlsenable);
            }
        }
        else
        {
            setSMTPProperty(asyncResp, interface,
                    "TLSEnable", *input.tlsenable);
        }
    }

    if (input.enable)
    {
        setSMTPProperty(asyncResp, interface,
                "Enable", *input.enable);
    }

    if (input.host)
    {
        setSMTPProperty(asyncResp, interface,
                "Host", *input.host);
    }

    if (input.sender)
    {
        setSMTPProperty(asyncResp, interface,
                "Sender", *input.sender);
    }
}

void getEventServiceInfo(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    asyncResp->res.jsonValue["@odata.id"] = "/redfish/v1/EventService";
            asyncResp->res.jsonValue["@odata.type"] = json_util::odataType("EventService");
            asyncResp->res.jsonValue["Id"] = "EventService";
            asyncResp->res.jsonValue["Name"] = "Event Service";
            asyncResp->res.jsonValue["Description"] = "Event Service";
            asyncResp->res.jsonValue["ServerSentEventUri"] =
                "/redfish/v1/EventService/SSE";

            asyncResp->res.jsonValue["Subscriptions"]["@odata.id"] =
                "/redfish/v1/EventService/Subscriptions";
            asyncResp->res.jsonValue["Actions"]["#EventService.SubmitTestEvent"]
                                    ["target"] =
                "/redfish/v1/EventService/Actions/EventService.SubmitTestEvent";
            asyncResp->res.jsonValue["Actions"]["#EventService.SubmitTestEvent"]
                                    ["@Redfish.ActionInfo"] =
                boost::urls::format(
                    "/redfish/v1/EventService/SubmitTestEventActionInfo");

            const persistent_data::EventServiceConfig eventServiceConfig =
                persistent_data::EventServiceStore::getInstance()
                    .getEventServiceConfig();

            asyncResp->res.jsonValue["Status"]["State"] =
                (eventServiceConfig.enabled ? "Enabled" : "Disabled");
            asyncResp->res.jsonValue["ServiceEnabled"] =
                eventServiceConfig.enabled;
            asyncResp->res.jsonValue["DeliveryRetryAttempts"] =
                eventServiceConfig.retryAttempts;
            asyncResp->res.jsonValue["DeliveryRetryIntervalSeconds"] =
                eventServiceConfig.retryTimeoutInterval;
            asyncResp->res.jsonValue["EventFormatTypes"] =
                supportedEvtFormatTypes;
            asyncResp->res.jsonValue["RegistryPrefixes"] = supportedRegPrefixes;
            asyncResp->res.jsonValue["ResourceTypes"] = supportedResourceTypes;

            nlohmann::json::object_t supportedSSEFilters;
            supportedSSEFilters["EventFormatType"] = true;
            supportedSSEFilters["MessageId"] = true;
            supportedSSEFilters["MetricReportDefinition"] = true;
            supportedSSEFilters["RegistryPrefix"] = true;
            supportedSSEFilters["OriginResource"] = false;
            supportedSSEFilters["ResourceType"] = false;

            asyncResp->res.jsonValue["SSEFilterPropertiesSupported"] =
                std::move(supportedSSEFilters);
            getSmtpConfig(asyncResp, "xyz.openbmc_project.mail.alert.primary",
                          "PrimaryConfiguration");
            getSmtpConfig(asyncResp, "xyz.openbmc_project.mail.alert.secondary",
                          "SecondaryConfiguration");
            getSmtpSSLCertificates(asyncResp);

            asyncResp->res.jsonValue["Oem"]["OpenBmc"]["SMTP"]
                                    ["PrimaryConfiguration"]["@odata.type"] =
                "#AMIEventService.PrimaryConfiguration";
            asyncResp->res.jsonValue["Oem"]["OpenBmc"]["SMTP"]
                                    ["SecondaryConfiguration"]["@odata.type"] =
                "#AMIEventService.SecondaryConfiguration";

            asyncResp->res
                .jsonValue["Oem"]["OpenBmc"]["SMTP"]["PrimaryConfiguration"]
                          ["Actions"]["#AMIEventService.PrimaryConfiguration"]
                          ["target"] =
                "/redfish/v1/EventService/Actions/Oem/Ami/SMTP.PrimarySSLCertificateUpload";
            asyncResp->res
                .jsonValue["Oem"]["OpenBmc"]["SMTP"]["SecondaryConfiguration"]
                          ["Actions"]["#AMIEventService.SecondaryConfiguration"]
                          ["target"] =
                "/redfish/v1/EventService/Actions/Oem/Ami/SMTP.SecondarySSLCertificateUpload";
}

inline void getEventServiceSubscriptionIdInfo(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& param)
{
    std::shared_ptr<Subscription> subValue =
        EventServiceManager::getInstance().getSubscription(param);
    const std::string& id = param;

    if (param.starts_with("snmp"))
    {
        getSnmpTrapClient(asyncResp, param);
        //return;
    }
    else
    {
         if (subValue == nullptr)
        {
            // Lookup in Kafka subscriptions
            KafkaManager::getInstance().getSubscription(param,
                                                        asyncResp);
            return;
        }
        asyncResp->res.jsonValue["@odata.type"] =
        "#EventDestination.v1_14_1.EventDestination";
        asyncResp->res.jsonValue["Protocol"] =
            event_destination::EventDestinationProtocol::Redfish;
        asyncResp->res.jsonValue["@odata.id"] = boost::urls::format(
            "/redfish/v1/EventService/Subscriptions/{}", id);
        asyncResp->res.jsonValue["Id"] = id;
        asyncResp->res.jsonValue["Name"] = "Event Destination " + id;
        asyncResp->res.jsonValue["Destination"] =
            subValue->userSub->destinationUrl;
        asyncResp->res.jsonValue["SubscriptionType"] =
            subValue->userSub->subscriptionType;
        asyncResp->res.jsonValue["EventFormatType"] =
            subValue->userSub->eventFormatType;
    }

    asyncResp->res.jsonValue["Context"] =
        ((subValue != nullptr) && !subValue->userSub->customText.empty()) ? subValue->userSub->customText : "Event_Sub_" + id;
    asyncResp->res.jsonValue["HttpHeaders"] =
        nlohmann::json::array();
    asyncResp->res.jsonValue["RegistryPrefixes"] =
        subValue->userSub->registryPrefixes;
    asyncResp->res.jsonValue["ResourceTypes"] =
        subValue->userSub->resourceTypes;
    asyncResp->res.jsonValue["MessageIds"] =
        subValue->userSub->registryMsgIds;
    asyncResp->res.jsonValue["DeliveryRetryPolicy"] =
        subValue->userSub->retryPolicy;
    asyncResp->res.jsonValue["SendHeartbeat"] =
        subValue->userSub->sendHeartbeat;
    asyncResp->res.jsonValue["HeartbeatIntervalMinutes"] =
        subValue->userSub->hbIntervalMinutes;
    asyncResp->res.jsonValue["VerifyCertificate"] =
        subValue->userSub->verifyCertificate;
    asyncResp->res.jsonValue["Status"]["Health"] = "OK";
    asyncResp->res.jsonValue["Status"]["State"] =
        subValue->userSub->state;

    nlohmann::json::array_t mrdJsonArray;
    for (const auto& mdrUri :
            subValue->userSub->metricReportDefinitions)
    {
        nlohmann::json::object_t mdr;
        mdr["@odata.id"] = mdrUri;
        mrdJsonArray.emplace_back(std::move(mdr));
    }
    asyncResp->res.jsonValue["MetricReportDefinitions"] =
        mrdJsonArray;

}

inline void requestRoutesEventService(App& app)
{
BMCWEB_ROUTE(app, "/redfish/v1/EventService/")
        .privileges(redfish::privileges::getEventService)
        .methods(
            boost::beast::http::verb::
                get)([&app](
                         const crow::Request& req,
                         const std::shared_ptr<bmcweb::AsyncResp>& asyncResp) {
            if (!redfish::setUpRedfishRoute(app, req, asyncResp))
            {
                return;
            }
            getEventServiceInfo(asyncResp);
        });

    BMCWEB_ROUTE(app, "/redfish/v1/EventService/")
        .privileges(redfish::privileges::patchEventService)
        .methods(boost::beast::http::verb::
                     patch)([&app](const crow::Request& req,
                                   const std::shared_ptr<bmcweb::AsyncResp>&
                                       asyncResp) {
            if (!redfish::setUpRedfishRoute(app, req, asyncResp))
            {
                return;
            }
            
            anySuccess = false;
            anyFailure = false;
            std::optional<bool> serviceEnabled;
            std::optional<uint32_t> retryAttemps;
            std::optional<uint32_t> retryInterval;
            SmtpPatchParams primarySmtpConfig;
            SmtpPatchParams secondarySmtpConfig;

            if (!json_util::readJsonPatch( //
                    req, asyncResp->res, //
                    "ServiceEnabled", serviceEnabled, //
                    "DeliveryRetryAttempts", retryAttemps, //
                    "DeliveryRetryIntervalSeconds", retryInterval, //
                    "Oem/OpenBmc/SMTP/PrimaryConfiguration/Authentication", primarySmtpConfig.authentication, //
                    "Oem/OpenBmc/SMTP/PrimaryConfiguration/Enable", primarySmtpConfig.enable,
                    "Oem/OpenBmc/SMTP/PrimaryConfiguration/Host", primarySmtpConfig.host,
                    "Oem/OpenBmc/SMTP/PrimaryConfiguration/Password", primarySmtpConfig.password,
                    "Oem/OpenBmc/SMTP/PrimaryConfiguration/Port", primarySmtpConfig.port,
                    "Oem/OpenBmc/SMTP/PrimaryConfiguration/Recipient", primarySmtpConfig.recipient,
                    "Oem/OpenBmc/SMTP/PrimaryConfiguration/Sender", primarySmtpConfig.sender,
                    "Oem/OpenBmc/SMTP/PrimaryConfiguration/TLSEnable", primarySmtpConfig.tlsenable,
                    "Oem/OpenBmc/SMTP/PrimaryConfiguration/UserName", primarySmtpConfig.username,
                    "Oem/OpenBmc/SMTP/SecondaryConfiguration/Authentication", secondarySmtpConfig.authentication,
                    "Oem/OpenBmc/SMTP/SecondaryConfiguration/Enable", secondarySmtpConfig.enable,
                    "Oem/OpenBmc/SMTP/SecondaryConfiguration/Host", secondarySmtpConfig.host,
                    "Oem/OpenBmc/SMTP/SecondaryConfiguration/Password", secondarySmtpConfig.password,
                    "Oem/OpenBmc/SMTP/SecondaryConfiguration/Port", secondarySmtpConfig.port,
                    "Oem/OpenBmc/SMTP/SecondaryConfiguration/Recipient", secondarySmtpConfig.recipient,
                    "Oem/OpenBmc/SMTP/SecondaryConfiguration/Sender", secondarySmtpConfig.sender,
                    "Oem/OpenBmc/SMTP/SecondaryConfiguration/TLSEnable", secondarySmtpConfig.tlsenable,
                    "Oem/OpenBmc/SMTP/SecondaryConfiguration/UserName", secondarySmtpConfig.username
                    ))
            {
                return;
            }

            persistent_data::EventServiceConfig eventServiceConfig =
                persistent_data::EventServiceStore::getInstance()
                    .getEventServiceConfig();

            if (serviceEnabled)
            {
                eventServiceConfig.enabled = *serviceEnabled;
            }

            if (retryAttemps)
            {
                // Supported range [1-3]
                if ((*retryAttemps < 1) || (*retryAttemps > 3))
                {
                    anyFailure = true;
                    messages::queryParameterOutOfRange(
                        asyncResp->res, std::to_string(*retryAttemps),
                        "DeliveryRetryAttempts", "[1-3]");
                }
                else
                {
                    eventServiceConfig.retryAttempts = *retryAttemps;
                }
            }

            if (retryInterval)
            {
                // Supported range [5 - 180]
                if ((*retryInterval < 5) || (*retryInterval > 180))
                {
                    anyFailure = true;
                    messages::queryParameterOutOfRange(
                        asyncResp->res, std::to_string(*retryInterval),
                        "DeliveryRetryIntervalSeconds", "[5-180]");
                }
                else
                {
                    eventServiceConfig.retryTimeoutInterval = *retryInterval;
                }
            }

            /* handle primary and secondary SMPT configuration */
            if(primarySmtpConfig.hasValue())
            {
                handleSmtpPatch(std::move(primarySmtpConfig),asyncResp,"Primary");
            }
            if(secondarySmtpConfig.hasValue())
            {
                handleSmtpPatch(std::move(secondarySmtpConfig),asyncResp,"Secondary");
            }
            
            if (anyFailure && !anySuccess)
            {
                asyncResp->res.result(boost::beast::http::status::bad_request);
                return;
            }
            else
            {
                EventServiceManager::getInstance().setEventServiceConfig(
                    eventServiceConfig);
                getEventServiceInfo(asyncResp);
                asyncResp->res.result(boost::beast::http::status::ok);
                return;
            }
        });
}

inline void handleSubmitTestEventActionGet(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    asyncResp->res.jsonValue["@odata.type"] = json_util::odataType("ActionInfo");
    asyncResp->res.jsonValue["@odata.id"] = boost::urls::format(
        "/redfish/v1/EventService/SubmitTestEventActionInfo");
    asyncResp->res.jsonValue["Name"] = "SubmitTestEvent Action Info";
    asyncResp->res.jsonValue["Id"] = "SubmitTestEventActionInfo";
    nlohmann::json::object_t MessageId;
    MessageId["DataType"] = "String";
    MessageId["Name"] = "MessageId";
    MessageId["Required"] = true;
    nlohmann::json::object_t EventId;
    EventId["DataType"] = "String";
    EventId["Name"] = "EventId";
    EventId["Required"] = false;
    nlohmann::json::object_t EventTimestamp;
    EventTimestamp["DataType"] = "String";
    EventTimestamp["Name"] = "EventTimestamp";
    EventTimestamp["Required"] = false;
    nlohmann::json::object_t MessageArgs;
    MessageArgs["DataType"] = "StringArray";
    MessageArgs["Name"] = "MessageArgs";
    MessageArgs["Required"] = false;
    nlohmann::json::object_t OriginOfCondition;
    OriginOfCondition["DataType"] = "String";
    OriginOfCondition["Name"] = "OriginOfCondition";
    OriginOfCondition["Required"] = false;
    nlohmann::json::object_t Message;
    Message["DataType"] = "String";
    Message["Name"] = "Message";
    Message["Required"] = false;
    nlohmann::json::object_t EventGroupId;
    EventGroupId["DataType"] = "Number";
    EventGroupId["Name"] = "EventGroupId";
    EventGroupId["Required"] = false;
    nlohmann::json::object_t Severity;
    Severity["DataType"] = "String";
    Severity["Name"] = "Severity";
    Severity["Required"] = false;
    nlohmann::json::array_t parameters;
    parameters.push_back(std::move(MessageId));
    parameters.push_back(std::move(EventId));
    parameters.push_back(std::move(EventTimestamp));
    parameters.push_back(std::move(MessageArgs));
    parameters.push_back(std::move(OriginOfCondition));
    parameters.push_back(std::move(Message));
    parameters.push_back(std::move(EventGroupId));
    parameters.push_back(std::move(Severity));
    asyncResp->res.jsonValue["Parameters"] = std::move(parameters);
}

inline const registries::Header* getRegistryHeader(std::string registry)
{
    if (registry == "Base")
    {
        return &registries::base::header;
    }
    if (registry == "OpenBMC")
    {
        return &registries::openbmc::header;
    }
    if (registry == "TaskEvent")
    {
        return &registries::task_event::header;
    }
    return &registries::openbmc::header;
}

inline void requestRoutesSubmitTestEvent(App& app)
{
    BMCWEB_ROUTE(
        app, "/redfish/v1/EventService/Actions/EventService.SubmitTestEvent/")
        .privileges(redfish::privileges::postEventService)
        .methods(boost::beast::http::verb::post)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp) {
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }
                TestEvent testEvent;
                // clang-format off
                
                if (!json_util::readJsonAction(
                        req, asyncResp->res,
                        "EventGroupId", testEvent.eventGroupId,
                        "EventId", testEvent.eventId,
                        "EventTimestamp", testEvent.eventTimestamp,
                        "Message", testEvent.message,
                        "MessageArgs", testEvent.messageArgs,
                        "MessageId", testEvent.messageId,
                        "OriginOfCondition", testEvent.originOfCondition,
                        "Resolution", testEvent.resolution,
                        "Severity", testEvent.severity))
                {
                    return;
                }
                if (testEvent.messageId.has_value())
                {
                     if(!validateMsgId(testEvent.messageId.value()))
                    {
                    messages::propertyValueNotInList(asyncResp->res,*testEvent.messageId, "MessageId");
                    return;
                    }
                }
                // clang-format on
                if (!EventServiceManager::getInstance().sendTestEventLog(
                        testEvent))
                {
                    messages::serviceDisabled(asyncResp->res,
                                              "/redfish/v1/EventService/");
                    return;
                }
                asyncResp->res.result(boost::beast::http::status::no_content);
            });

    BMCWEB_ROUTE(app, "/redfish/v1/EventService/SubmitTestEventActionInfo/")
        .privileges(redfish::privileges::getActionInfo)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleSubmitTestEventActionGet, std::ref(app)));
}

inline void requestRoutesSSLEvent(App& app)
{
    BMCWEB_ROUTE(
        app,
        "/redfish/v1/EventService/Actions/Oem/Ami/SMTP.PrimarySSLCertificateUpload")
        .privileges(redfish::privileges::postEventService)
        .methods(boost::beast::http::verb::post)(std::bind_front(
            handleSSLCertificatePrimaryUploadAction, std::ref(app)));
    BMCWEB_ROUTE(
        app,
        "/redfish/v1/EventService/Actions/Oem/Ami/SMTP.SecondarySSLCertificateUpload")
        .privileges(redfish::privileges::postEventService)
        .methods(boost::beast::http::verb::post)(std::bind_front(
            handleSSLCertificateSecondaryUploadAction, std::ref(app)));
}

inline void doSubscriptionCollection(
    const boost::system::error_code& ec,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const dbus::utility::ManagedObjectType& resp)
{
    if (ec)
    {
        // This is an optional process so just return if it isn't there
        BMCWEB_LOG_DEBUG("EventService: The SNMP service is not enabled");
        return;
    }
    nlohmann::json& memberArray = asyncResp->res.jsonValue["Members"];
    for (const auto& objpath : resp)
    {
        sdbusplus::message::object_path path(objpath.first);
        const std::string snmpId = path.filename();
        if (snmpId.empty())
        {
            BMCWEB_LOG_ERROR("The SNMP client ID is wrong");
            messages::internalError(asyncResp->res);
            return;
        }

        getSnmpSubscriptionList(asyncResp, snmpId, memberArray);
    }
}
inline std::string removeProtocol(const std::string& url)
{
    std::regex pattern("^.+://");
    return std::regex_replace(url, pattern, "");
}

inline void requestRoutesEventDestinationCollection(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/EventService/Subscriptions/")
        .privileges(redfish::privileges::getEventDestinationCollection)
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp) {
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }
                asyncResp->res.jsonValue["@odata.type"] =
                    "#EventDestinationCollection.EventDestinationCollection";
                asyncResp->res.jsonValue["@odata.id"] =
                    "/redfish/v1/EventService/Subscriptions";
                asyncResp->res.jsonValue["Name"] =
                    "Event Destination Collections";
                asyncResp->res.jsonValue["Description"] =
                    "Event Destination Collections";

                nlohmann::json& memberArray =
                    asyncResp->res.jsonValue["Members"];

                std::vector<std::string> subscripIds =
                    EventServiceManager::getInstance().getAllIDs();
                memberArray = nlohmann::json::array();
                asyncResp->res.jsonValue["Members@odata.count"] =
                    subscripIds.size();

                for (const std::string& id : subscripIds)
                {
                    if (id.starts_with("snmp"))
                    {
                        continue;
                    }
                    nlohmann::json::object_t member;
                    member["@odata.id"] = boost::urls::format(
                        "/redfish/v1/EventService/Subscriptions/{}" + id);
                    memberArray.emplace_back(std::move(member));
                }

                // Fill in Kafka subscriptions
                std::vector<std::string> kafkaIds =
                    KafkaManager::getInstance().getAllIDs();
                asyncResp->res.jsonValue["Members@odata.count"] =
                    subscripIds.size() + kafkaIds.size();
                for (const std::string& id : kafkaIds)
                {
                    memberArray.push_back(
                        {{"@odata.id",
                          "/redfish/v1/EventService/Subscriptions/" + id}});
                }

                crow::connections::systemBus->async_method_call(
                    [asyncResp](const boost::system::error_code& ec,
                                const dbus::utility::ManagedObjectType& resp) {
                        doSubscriptionCollection(ec, asyncResp, resp);
                    },
                    "xyz.openbmc_project.Network.SNMP",
                    "/xyz/openbmc_project/network/snmp/manager",
                    "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");
            });

    BMCWEB_ROUTE(app, "/redfish/v1/EventService/Subscriptions/")
        .privileges(redfish::privileges::postEventDestinationCollection)
        .methods(
            boost::beast::http::verb::
                post)([&app](
                          const crow::Request& req,
                          const std::shared_ptr<bmcweb::AsyncResp>& asyncResp) {
            if (!redfish::setUpRedfishRoute(app, req, asyncResp))
            {
                return;
            }
            if (EventServiceManager::getInstance().getNumberOfSubscriptions() >=
                maxNoOfSubscriptions)
            {
                messages::eventSubscriptionLimitExceeded(asyncResp->res);
                return;
            }
            std::string destUrl;
            std::string protocol;
            std::optional<bool> verifyCertificate;
            std::optional<std::string> vId;
            std::optional<std::string> context;
            std::optional<std::string> subscriptionType;
            std::optional<std::string> eventFormatType2;
            std::optional<std::string> retryPolicy;
            std::optional<bool> sendHeartbeat;
            std::optional<uint64_t> hbIntervalMinutes;
            std::optional<std::vector<std::string>> msgIds;
            std::optional<std::vector<std::string>> regPrefixes;
            std::optional<std::vector<std::string>> originResources;
            std::optional<std::vector<std::string>> resTypes;
            std::optional<std::vector<nlohmann::json::object_t>> headers;
            std::optional<std::vector<nlohmann::json::object_t>> mrdJsonArray;
            std::optional<nlohmann::json> oemObj;
            std::optional<std::string> oemsnmpcommunitystring;
            if (!json_util::readJsonPatch( //
                    req, asyncResp->res, //
                    "Destination", destUrl, //
                    "Context", context, //
                    "Protocol", protocol, //
                    "SubscriptionType", subscriptionType, //
                    "EventFormatType", eventFormatType2, //
                    "HeartbeatIntervalMinutes", hbIntervalMinutes, //
                    "HttpHeaders", headers, //
                    "RegistryPrefixes", regPrefixes, //
                    "MessageIds", msgIds, //
                    "OriginResources", originResources, //
                    "Id", vId, //
                    "DeliveryRetryPolicy", retryPolicy, //
                    "MetricReportDefinitions", mrdJsonArray, //
                    "ResourceTypes", resTypes, //
                    "SendHeartbeat", sendHeartbeat, //
                    "VerifyCertificate", verifyCertificate, //
                    "Oem/OpenBmc/CommunityString", oemsnmpcommunitystring, //
                    "Oem", oemObj //
                    ))
            {
                return;
            }

            if(protocol.empty())
            {
                messages::propertyValueEmpty(asyncResp->res, protocol, "Protocol");
                return;
            }

            if (vId)
            {
                messages::propertyNotWritable(asyncResp->res, "Id");
                asyncResp->res.result(boost::beast::http::status::bad_request);
                return;
            }

            if (protocol == "Oem")
            {
                // Handle to support Kafka streaming support
                KafkaManager::getInstance().createSubscription(
                    *oemObj, destUrl, context, asyncResp);
                return;
            }

            // https://stackoverflow.com/questions/417142/what-is-the-maximum-length-of-a-url-in-different-browsers
            static constexpr const uint16_t maxDestinationSize = 2000;
            if (destUrl.size() > maxDestinationSize)
            {
                messages::stringValueTooLong(asyncResp->res, "Destination",
                                             maxDestinationSize);
                return;
            }

            if (regPrefixes && msgIds)
            {
                if (!regPrefixes->empty() && !msgIds->empty())
                {
                    messages::propertyValueConflict(
                        asyncResp->res, "MessageIds", "RegistryPrefixes");
                    return;
                }
            }

            boost::system::result<boost::urls::url> url =
                boost::urls::parse_absolute_uri(destUrl);
            if (!url)
            {
                BMCWEB_LOG_WARNING(
                    "Failed to validate and split destination url");
                messages::propertyValueFormatError(asyncResp->res, destUrl,
                                                    "Destination");
                return;
            }

            if (url)
            {
                std::string destIp = removeProtocol(destUrl);
                size_t atPos = destIp.find('@');
                if (atPos != std::string::npos)
                {
                    destIp = destIp.substr(atPos + 1);
                }
                if (destIp.front() == '[' && destIp.back() == ']')
                {
                    destIp = destIp.substr(
                        1, destIp.size() - 2); // Remove brackets for IPv6
                }
                size_t lastColon = destIp.rfind(':');
                if (lastColon != std::string::npos)
                {
                    std::string possiblePort = destIp.substr(lastColon + 1);
                    if (std::all_of(possiblePort.begin(), possiblePort.end(),
                                    ::isdigit))
                    {
                        destIp = destIp.substr(0, lastColon);
                    }
                }
                size_t slashPos = destIp.rfind('/');
                if (slashPos)
                {
                    destIp = destIp.substr(0, slashPos);
                }

                std::string ip = destIp;
                boost::system::error_code ec;
                boost::asio::ip::make_address(ip, ec);
                if (ec)
                {
                    messages::propertyValueFormatError(asyncResp->res, destUrl,
                                                       "Destination");
                    return;
                }
            }

            url->normalize();

            // port_number returns zero if it is not a valid representable port
            if (url->has_port() && url->port_number() == 0)
            {
                BMCWEB_LOG_WARNING("{} is an invalid port in destination url",
                                   url->port());
                messages::propertyValueFormatError(asyncResp->res, destUrl,
                                                   "Destination");
                return;
            }

            crow::utility::setProtocolDefaults(*url, protocol);
            crow::utility::setPortDefaults(*url);

            if (url->path().empty())
            {
                url->set_path("/");
            }

            if (protocol != "SNMPv3" && url->has_userinfo())
            {
                messages::propertyValueFormatError(asyncResp->res, destUrl,
                                                   "Destination");
                return;
            }

            /* if (protocol == "SNMPv2c")
             {
                if (context)
                 {
                     messages::propertyValueConflict(asyncResp->res, "Context",
                                                     "Protocol");
                     return;
                 }
                 if (eventFormatType2)
                 {
                     messages::propertyValueConflict(asyncResp->res,
                                                     "EventFormatType",
             "Protocol"); return;
                 }
                 if (retryPolicy)
                 {
                     messages::propertyValueConflict(asyncResp->res,
             "RetryPolicy", "Protocol"); return;
                 }
                 if (sendHeartbeat)
                 {
                    messages::propertyValueConflict(
                        asyncResp->res, "SendHeartbeat", "Protocol");
                    return;
                 }
                 if (hbIntervalMinutes)
                 {
                    messages::propertyValueConflict(
                        asyncResp->res, "HeartbeatIntervalMinutes", "Protocol");
                    return;
                 }
                 if (msgIds)
                 {
                     messages::propertyValueConflict(asyncResp->res,
             "MessageIds", "Protocol"); return;
                 }
                 if (regPrefixes)
                 {
                     messages::propertyValueConflict(asyncResp->res,
                                                     "RegistryPrefixes",
             "Protocol"); return;
                 }
                 if (resTypes)
                 {
                     messages::propertyValueConflict(asyncResp->res,
             "ResourceTypes", "Protocol"); return;
                 }
                 if (headers)
                 {
                     messages::propertyValueConflict(asyncResp->res,
             "HttpHeaders", "Protocol"); return;
                 }
                 if (mrdJsonArray)
                 {
                     messages::propertyValueConflict(
                         asyncResp->res, "MetricReportDefinitions", "Protocol");
                     return;
                 }
                 if (url->scheme() != "snmp")
                 {
                     messages::propertyValueConflict(asyncResp->res,
             "Destination", "Protocol"); return;
                 }
                 if (*subscriptionType == "RedfishEvent")
                 {
                     messages::propertyValueConflict(asyncResp->res,
                                                     "SubscriptionType",
             "Protocol"); return;
                 }
                 addSnmpTrapClient(asyncResp, url->host_address(),
                                   url->port_number());
                 return;
             }*/

            if (req.session == nullptr || req.session->username.empty())
            {
                BMCWEB_LOG_ERROR("Request Session Undefined");
                messages::noValidSession(asyncResp->res);
                return;
            }

            std::shared_ptr<Subscription> subValue =
                std::make_shared<Subscription>(
                    std::make_shared<persistent_data::UserSubscription>(), *url,
                    app.ioContext());

            subValue->userSub->destinationUrl = *url;
            subValue->userSub->owner = req.session->username;

            if (subscriptionType)
            {
                if ((protocol == "Redfish" &&
                     *subscriptionType != "RedfishEvent") ||
                    (protocol == "SNMPv2c" &&
                     *subscriptionType != "SNMPTrap") ||
                    (protocol == "SNMPv3" && *subscriptionType != "SNMPTrap") ||
                    (protocol == "SNMPv1" && *subscriptionType != "SNMPTrap"))
                {
                    messages::propertyValueNotInList(
                        asyncResp->res, *subscriptionType, "SubscriptionType");
                    return;
                }
                subValue->userSub->subscriptionType = *subscriptionType;
            }
            else
            {
                if (protocol == "SNMPv1" || protocol == "SNMPv2c" ||
                    protocol == "SNMPv3")
                {
                    subValue->userSub->subscriptionType = "SNMPTrap";
                }
                else
                {
                    subValue->userSub->subscriptionType =
                        "RedfishEvent"; // Default
                }
            }

            if ((protocol != "Redfish") && (protocol != "SNMPv2c") &&
                (protocol != "SNMPv3") && (protocol != "SNMPv1"))
            {
                messages::propertyValueNotInList(asyncResp->res, protocol,
                                                 "Protocol");
                return;
            }
            subValue->userSub->protocol = protocol;


            if (verifyCertificate)
            {
                subValue->userSub->verifyCertificate = *verifyCertificate;
            }

            if (eventFormatType2)
            {
                if (protocol == "SNMPv2c" || protocol == "SNMPv3" ||
                    protocol == "SNMPv1")
                {
                    if (*eventFormatType2 != "Event")
                    {
                        messages::propertyValueNotInList(asyncResp->res,
                                                         *eventFormatType2,
                                                         "EventFormatType");
                        return;
                    }
                    subValue->userSub->eventFormatType = *eventFormatType2;
                }
                else
                {
                    if (std::ranges::find(supportedEvtFormatTypes,
                                          *eventFormatType2) ==
                        supportedEvtFormatTypes.end())
                    {
                        messages::propertyValueNotInList(asyncResp->res,
                                                         *eventFormatType2,
                                                         "EventFormatType");
                        return;
                    }
                    subValue->userSub->eventFormatType = *eventFormatType2;
                }
            }
            else
            {
                // If not specified, use default "Event"
                subValue->userSub->eventFormatType = "Event";
            }

            if (context)
            {
                // This value is selected arbitrarily.
                constexpr const size_t maxContextSize = 256;
                if (context->size() > maxContextSize)
                {
                    messages::stringValueTooLong(asyncResp->res, "Context",
                                                 maxContextSize);
                    return;
                }
                subValue->userSub->customText = *context;
            }

            if (headers)
            {
                size_t cumulativeLen = 0;

                for (const nlohmann::json::object_t& headerChunk : *headers)
                {
                    for (const auto& item : headerChunk)
                    {
                        const std::string* value =
                            item.second.get_ptr<const std::string*>();
                        if (value == nullptr)
                        {
                            messages::propertyValueFormatError(
                                asyncResp->res, item.second,
                                "HttpHeaders/" + item.first);
                            return;
                        }
                        // Adding a new json value is the size of the key, +
                        // the size of the value + 2 * 2 quotes for each, +
                        // the colon and space between. example:
                        // "key": "value"
                        cumulativeLen += item.first.size() + value->size() + 6;
                        // This value is selected to mirror http_connection.hpp
                        constexpr const uint16_t maxHeaderSizeED = 8096;
                        if (cumulativeLen > maxHeaderSizeED)
                        {
                            messages::arraySizeTooLong(
                                asyncResp->res, "HttpHeaders", maxHeaderSizeED);
                            return;
                        }
                        subValue->userSub->httpHeaders.set(item.first, *value);
                    }
                }
            }

            if (regPrefixes)
            {
                for (const std::string& it : *regPrefixes)
                {
                    if (std::ranges::find(supportedRegPrefixes, it) ==
                        supportedRegPrefixes.end())
                    {
                        messages::propertyValueNotInList(asyncResp->res, it,
                                                         "RegistryPrefixes");
                        return;
                    }
                }
                subValue->userSub->registryPrefixes = *regPrefixes;
            }

            if (originResources)
            {
                subValue->userSub->originResources = *originResources;
            }

            if (resTypes)
            {
                for (const std::string& it : *resTypes)
                {
                    if (std::ranges::find(supportedResourceTypes, it) ==
                        supportedResourceTypes.end())
                    {
                        messages::propertyValueNotInList(asyncResp->res, it,
                                                         "ResourceTypes");
                        return;
                    }
                }
                subValue->userSub->resourceTypes = *resTypes;
            }

            if (msgIds)
            {
                std::vector<std::string> registryPrefix;

                // If no registry prefixes are mentioned, consider all
                // supported prefixes
                if (subValue->userSub->registryPrefixes.empty())
                {
                    registryPrefix.assign(supportedRegPrefixes.begin(),
                                          supportedRegPrefixes.end());
                }
                else
                {
                    registryPrefix = subValue->userSub->registryPrefixes;
                }

                for (const std::string& id : *msgIds)
                {
                    bool validId = false;

                    // Check for Message ID in each of the selected Registry
                    for (const std::string& it : registryPrefix)
                    {
                        const std::span<const redfish::registries::MessageEntry>
                            registry =
                                redfish::registries::getRegistryFromPrefix(it);

                        if (std::ranges::any_of(
                                registry,
                                [&id](const redfish::registries::MessageEntry&
                                          messageEntry) {
                                    return id == messageEntry.first;
                                }))
                        {
                            validId = true;
                            break;
                        }
                    }

                    if (!validId)
                    {
                        messages::propertyValueNotInList(asyncResp->res, id,
                                                         "MessageIds");
                        return;
                    }
                }

                subValue->userSub->registryMsgIds = *msgIds;
            }

            if (retryPolicy)
            {
                if (std::ranges::find(supportedRetryPolicies, *retryPolicy) ==
                    supportedRetryPolicies.end())
                {
                    messages::propertyValueNotInList(
                        asyncResp->res, *retryPolicy, "DeliveryRetryPolicy");
                    return;
                }
                subValue->userSub->retryPolicy = *retryPolicy;
            }
            else
            {
                // Default "TerminateAfterRetries"
                subValue->userSub->retryPolicy = "TerminateAfterRetries";
            }

            if (sendHeartbeat)
            {
                subValue->userSub->sendHeartbeat = *sendHeartbeat;
            }
            if (hbIntervalMinutes)
            {
                if (*hbIntervalMinutes < 1 || *hbIntervalMinutes > 65535)
                {
                    messages::propertyValueOutOfRange(
                        asyncResp->res, *hbIntervalMinutes,
                        "HeartbeatIntervalMinutes");
                    return;
                }
                subValue->userSub->hbIntervalMinutes = *hbIntervalMinutes;
            }

            if (mrdJsonArray)
            {
                for (nlohmann::json::object_t& mrdObj : *mrdJsonArray)
                {
                    std::string mrdUri;

                    if (!json_util::readJsonObject( //
                            mrdObj, asyncResp->res, //
                            "@odata.id", mrdUri //
                            ))

                    {
                        return;
                    }
                    subValue->userSub->metricReportDefinitions.emplace_back(
                        mrdUri);
                }
            }

            // Default is Enabled, when subscription is suspended, this will
            // be set to "Disabled" state.
            subValue->userSub->state = "Enabled";

            if (protocol == "SNMPv2c" || protocol == "SNMPv3" ||
                protocol == "SNMPv1")
            {
                auto subId = std::make_shared<std::string>();
                snmpCompletedOperations = 0;
                auto snmpCompletionHandler = [asyncResp, subId, oemsnmpcommunitystring, protocol](bool success)
                {
                    if (success)
                    {
                        snmpCompletedOperations++;
                    }
                    // As of now two snmpcompletedoperations for SNMPV1 and SNMPV2 and one snmpcompletedoperations for SNMPv3. In Future if new dbus call are added for these protocols please increment the values of snmpcompletedoperations.
                    if ((oemsnmpcommunitystring && (snmpCompletedOperations == 2)) || (protocol == "SNMPv3" && (snmpCompletedOperations == 1)))
                    {
                        getEventServiceSubscriptionIdInfo(asyncResp,*subId);
                        asyncResp->res.result(boost::beast::http::status::created);
                    }
                };
                auto value = getSnmpProtocol();
                auto protocolStatus = std::get<bool>(value);
                if (!protocolStatus)
                {
                    messages::serviceDisabled(asyncResp->res, "SNMP");
                    return;
                }
                if(protocol == "SNMPv2c" || protocol == "SNMPv1" )
                {
                    std::string hostaddress = url->host_address();
                    uint16_t portnumber = url->port_number();
                    std::string user_name = url->user();
                    if(oemsnmpcommunitystring)
                    {
                        //validatecommunitystring(asyncResp, *oemsnmpcommunitystring);
                        sdbusplus::message::object_path path("/xyz/openbmc_project/snmp/CommunityStrManager/" + *oemsnmpcommunitystring);
                        dbus::utility::getProperty<std::string>(
                            "xyz.openbmc_project.Snmp.Conf", path,
                            "xyz.openbmc_project.Snmp.CommunityStrManager", "CommunityString",
                            [asyncResp, oemsnmpcommunitystring, hostaddress, portnumber, protocol, user_name, subValue, subId, snmpCompletionHandler](const boost::system::error_code& ec, std::string communitystring) {
                            if (ec)
                            {
                                BMCWEB_LOG_ERROR("no communitystring object path avaliable");
                                messages::propertyValueNotInList(asyncResp->res, *oemsnmpcommunitystring, "Oem/OpenBmc/CommunityString");
                                asyncResp->res.result(boost::beast::http::status::bad_request);
                                return;
                            }
                            else if (communitystring.empty()){
                                messages::propertyValueNotInList(asyncResp->res, *oemsnmpcommunitystring, "Oem/OpenBmc/CommunityString");
                                asyncResp->res.result(boost::beast::http::status::bad_request);
                                return;
                            }
                            else
                            {
                                snmpCompletionHandler(true);
                                addSnmpTrapClient(asyncResp, hostaddress,
                                    portnumber, protocol, user_name,
                                    subValue, *oemsnmpcommunitystring, subId, snmpCompletionHandler);
                            }
                        });
                    }
                    else
                    {
                        messages::propertyMissing(asyncResp->res, 
                                            "Oem/OpenBmc/CommunityString");
                        return;
                    }
                }
                else
                {
                    if (protocol == "SNMPv3" && url->has_userinfo() == false)
                    {
                        BMCWEB_LOG_DEBUG("Missing UserName in Destination");
                        messages::propertyValueFormatError(asyncResp->res, destUrl,
                                                        "Destination");
                        return;
                    }
                    addSnmpTrapClient(asyncResp, url->host_address(),
                                    url->port_number(), protocol, url->user(),
                                    subValue, *oemsnmpcommunitystring, subId, snmpCompletionHandler);                    
                }
                return;
            }

            std::string id;
            EventServiceManager::getInstance().addPushSubscription(
                subValue, id);

            getEventServiceSubscriptionIdInfo(asyncResp,id);
            asyncResp->res.result(boost::beast::http::status::created);
            asyncResp->res.addHeader(
                "Location", "/redfish/v1/EventService/Subscriptions/" + id);

            // schedule a heartbeat
            if (subValue->userSub->sendHeartbeat)
            {
                subValue->scheduleNextHeartbeatEvent();
            }
        });
}

bool isConfigureManagerOrSelf(const crow::Request& req,
                              const std::shared_ptr<Subscription>& subValue)
{
    Privileges effectiveUserPrivileges =
        redfish::getUserPrivileges(*req.session);
    bool isConfigureManager =
        effectiveUserPrivileges.isSupersetOf({"ConfigureManager"});

    if (!isConfigureManager)
    {
        // If the user does not have Configure manager privilege
        // then the user must be an Operator (i.e. Configure
        // Components and Self)
        // We need to ensure that the User is the actual owner of
        // the Subscription being patched
        // This also supports backward compatibility as subscription
        // owner would be empty which would not be equal to current
        // user, enabling only Admin to be able to patch the
        // Subscription

        if (req.session == nullptr || req.session->username.empty())
        {
            BMCWEB_LOG_ERROR(
                "Insufficient Privilege. Request Session Undefined");
            return false;
        }

        if (subValue->userSub->owner != req.session->username)
        {
            BMCWEB_LOG_ERROR(
                "Insufficient Privilege. User is not the owner of this Subscription");
            return false;
        }
    }
    return true;
}

inline bool validAuthProtocol(std::optional<std::string> authProtocol)
{
    if (authProtocol == "SHA-256" || authProtocol == "SHA-384" ||
        authProtocol == "SHA-512" || authProtocol == "SHA")
        return true;
    else
        return false;
}

inline void requestRoutesEventDestination(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/EventService/Subscriptions/<str>/")
        .privileges(redfish::privileges::getEventDestination)
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& param) {
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }

                getEventServiceSubscriptionIdInfo(asyncResp,param);
            });
    BMCWEB_ROUTE(app, "/redfish/v1/EventService/Subscriptions/<str>/")
        .privileges(redfish::privileges::patchEventDestination)
        .methods(boost::beast::http::verb::patch)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& param) {
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }
                std::shared_ptr<Subscription> subValue =
                    EventServiceManager::getInstance().getSubscription(param);
                if (subValue == nullptr && !param.starts_with("snmp"))
                {
                    // Lookup in Kafka subscriptions
                    KafkaManager::getInstance().updateSubscription(req, param,
                                                                   asyncResp);
                    return;
                }

                if (!isConfigureManagerOrSelf(req, subValue))
                {
                    messages::insufficientPrivilege(asyncResp->res);
                    return;
                }

                std::optional<std::string> context;
                std::optional<std::string> retryPolicy;
                std::optional<bool> sendHeartbeat;
                std::optional<uint64_t> hbIntervalMinutes;
                std::optional<bool> verifyCertificate;
                std::optional<std::vector<nlohmann::json::object_t>> headers;

                if (!json_util::readJsonPatch( //
                        req, asyncResp->res, //
                        "Context", context, //
                        "DeliveryRetryPolicy", retryPolicy, //
                        "HeartbeatIntervalMinutes", hbIntervalMinutes, //
                        "HttpHeaders", headers, //
                        "SendHeartbeat", sendHeartbeat, //
                        "VerifyCertificate", verifyCertificate //
                        ))
                {
                    return;
                }

                std::string_view snmpTrapId = param.substr(4);
                sdbusplus::message::object_path snmpPath =
                    sdbusplus::message::object_path(
                        "/xyz/openbmc_project/network/snmp/manager/" +
                        std::string(snmpTrapId));
                if (context)
                {
                    subValue->userSub->customText = *context;
                }

                if (headers)
                {
                    boost::beast::http::fields fields;
                    for (const nlohmann::json::object_t& headerChunk : *headers)
                    {
                        for (const auto& it : headerChunk)
                        {
                            const std::string* value =
                                it.second.get_ptr<const std::string*>();
                            if (value == nullptr)
                            {
                                messages::propertyValueFormatError(
                                    asyncResp->res, it.second,
                                    "HttpHeaders/" + it.first);
                                return;
                            }
                            fields.set(it.first, *value);
                        }
                    }
                    subValue->userSub->httpHeaders = std::move(fields);
                }

                if (retryPolicy)
                {
                    if (std::ranges::find(supportedRetryPolicies,
                                          *retryPolicy) ==
                        supportedRetryPolicies.end())
                    {
                        messages::propertyValueNotInList(asyncResp->res,
                                                         *retryPolicy,
                                                         "DeliveryRetryPolicy");
                        return;
                    }
                    subValue->userSub->retryPolicy = *retryPolicy;
                }

                if (sendHeartbeat)
                {
                    subValue->userSub->sendHeartbeat = *sendHeartbeat;
                }
                if (hbIntervalMinutes)
                {
                    if (*hbIntervalMinutes < 1 || *hbIntervalMinutes > 65535)
                    {
                        messages::propertyValueOutOfRange(
                            asyncResp->res, *hbIntervalMinutes,
                            "HeartbeatIntervalMinutes");
                        return;
                    }
                    subValue->userSub->hbIntervalMinutes = *hbIntervalMinutes;
                }

                if (hbIntervalMinutes || sendHeartbeat)
                {
                    // if Heartbeat interval or send heart were changed, cancel
                    // the heartbeat timer if running and start a new heartbeat
                    // if needed
                    subValue->heartbeatParametersChanged();
                }

                if (verifyCertificate)
                {
                    subValue->userSub->verifyCertificate = *verifyCertificate;
                }

                EventServiceManager::getInstance().updateSubscription(param);
                getEventServiceSubscriptionIdInfo(asyncResp,param);
                asyncResp->res.result(boost::beast::http::status::ok);
            });
    BMCWEB_ROUTE(app, "/redfish/v1/EventService/Subscriptions/<str>/")
        .privileges(redfish::privileges::deleteEventDestination)
        .methods(boost::beast::http::verb::delete_)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& param) {
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }

                if (param.starts_with("snmp"))
                {
                    deleteSnmpTrapClient(asyncResp, param);
                    EventServiceManager::getInstance().deleteSubscription(
                        param);
                    return;
                }

                std::shared_ptr<Subscription> subValue =
                    EventServiceManager::getInstance().getSubscription(param);
                if (subValue == nullptr)
                {
                    // Lookup in Kafka subscription.
                    KafkaManager::getInstance().deleteSubscription(param,
                                                                   asyncResp);
                    return;
                }

                if (!isConfigureManagerOrSelf(req, subValue))
                {
                    messages::insufficientPrivilege(asyncResp->res);
                    return;
                }

                if(EventServiceManager::getInstance().deleteSubscription(param))
		{
		    asyncResp->res.result(boost::beast::http::status::no_content);
		}
		else
		{
		    messages::resourceNotFound(asyncResp->res, "Subscriptions", param);
		}
            });
}

} // namespace redfish
