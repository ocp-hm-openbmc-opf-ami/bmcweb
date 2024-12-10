// Copyright (c) 2020 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include "dbus_utility.hpp"
#include "event_service.hpp"

#include <system_error>

namespace redfish
{
static constexpr const char* pefAlertSensorNumberIface =
    "xyz.openbmc_project.pef.alert.SensorNumber";
static constexpr const char* pefConfIface =
    "xyz.openbmc_project.pef.PEFConfInfo";

using GetSubTreeType = std::vector<
    std::pair<std::string,
              std::vector<std::pair<std::string, std::vector<std::string>>>>>;
inline void getFilterEnable(const std::shared_ptr<bmcweb::AsyncResp>& aResp)
{
    crow::connections::systemBus->async_method_call(
        [aResp](const boost::system::error_code ec,
                const GetSubTreeType& subtreeLocal) {
        if (ec || subtreeLocal.empty())
        {
            BMCWEB_LOG_ERROR("GetFilterEnable: Error");
            messages::internalError(aResp->res);
            return;
        }
        if (subtreeLocal[0].second.size() != 1)
        {
            // invalid mapper response, should never happen
            BMCWEB_LOG_ERROR("GetPefAlertSensorNumberIface: Mapper Error");
            messages::internalError(aResp->res);
            return;
        }
        const std::string& path = subtreeLocal[0].first;
        const std::string& owner = subtreeLocal[0].second[0].first;

        crow::connections::systemBus->async_method_call(
            [path, owner, aResp](const boost::system::error_code ec2,
                                 std::vector<uint8_t>& resp) {
            if (ec2)
            {
                BMCWEB_LOG_ERROR("GetPefAlert: Can't get "
                                 "pefAlertSensorNumberIface ",
                                 path);
                messages::internalError(aResp->res);
                return;
            }
            const std::vector<uint8_t>* filterEnable = &resp;
            if (filterEnable == nullptr)
            {
                BMCWEB_LOG_ERROR("Field Illegal FilterEnable");
                messages::internalError(aResp->res);
                return;
            }
            aResp->res.jsonValue["FilterEnable"] = *filterEnable;
        },
            owner, path, pefAlertSensorNumberIface, "GetFilterEnable");
    },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTree", "/", 0,
        std::array<const char*, 1>{pefAlertSensorNumberIface});
}

inline void setFilterEnable(const std::shared_ptr<bmcweb::AsyncResp>& aResp,
                            std::vector<uint8_t>& filterEnable)
{
    crow::connections::systemBus->async_method_call(
        [aResp, filterEnable](const boost::system::error_code ec,
                              const GetSubTreeType& subtreeLocal) {
        if (ec || subtreeLocal.empty())
        {
            BMCWEB_LOG_ERROR("SetFilterEnable: Error");
            messages::internalError(aResp->res);
            return;
        }
        if (subtreeLocal[0].second.size() != 1)
        {
            // invalid mapper response, should never happen
            BMCWEB_LOG_ERROR("GetPefAlertSensorNumberIface: Mapper Error");
            messages::internalError(aResp->res);
            return;
        }
        const std::string& path = subtreeLocal[0].first;
        const std::string& owner = subtreeLocal[0].second[0].first;

        crow::connections::systemBus->async_method_call(
            [aResp, filterEnable](const boost::system::error_code ec2) {
            if (ec2)
            {
                BMCWEB_LOG_ERROR("Set Property SetFilterEnable: Set Error");
                messages::internalError(aResp->res);
                return;
            }
        }, owner, path, pefAlertSensorNumberIface, "SetFilterEnable",
            std::vector<uint8_t>{filterEnable});
    },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTree", "/", 0,
        std::array<const char*, 1>{pefAlertSensorNumberIface});
}

inline void getPefConfParam(const std::shared_ptr<bmcweb::AsyncResp>& aResp)
{
    crow::connections::systemBus->async_method_call(
        [aResp](const boost::system::error_code ec,
                const GetSubTreeType& subtreeLocal) {
        if (ec || subtreeLocal.empty())
        {
            BMCWEB_LOG_ERROR("GetPefConfParam: Error");
            messages::internalError(aResp->res);
            return;
        }
        if (subtreeLocal[0].second.size() != 1)
        {
            // invalid mapper response, should never happen
            BMCWEB_LOG_ERROR("pefConfIface: Mapper Error");
            messages::internalError(aResp->res);
            return;
        }
        const std::string& path = subtreeLocal[0].first;
        const std::string& owner = subtreeLocal[0].second[0].first;

        crow::connections::systemBus->async_method_call(
            [path, owner,
             aResp](const boost::system::error_code ec2,
                    const std::vector<
                        std::pair<std::string, dbus::utility::DbusVariantType>>&
                        propertiesList) {
            if (ec2)
            {
                BMCWEB_LOG_ERROR("GetBootCount: Can't get "
                                 "pefConfIface ",
                                 path);
                messages::internalError(aResp->res);
                return;
            }

            for (const std::pair<std::string, dbus::utility::DbusVariantType>&
                     property : propertiesList)
            {
                if (property.first == "PEFActionGblControl")
                {
                    const uint8_t* value =
                        std::get_if<uint8_t>(&property.second);
                    if (value != nullptr)
                    {
                        aResp->res.jsonValue["PEFActionGblControl"] = *value;
                    }
                }
            }
        },
            owner, path, "org.freedesktop.DBus.Properties", "GetAll",
            pefConfIface);
    },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTree", "/", 0,
        std::array<const char*, 1>{pefConfIface});
}

inline void setPefConfParam(const std::shared_ptr<bmcweb::AsyncResp>& aResp,
                            const std::optional<uint8_t>& pefActionGblControl)
{
    crow::connections::systemBus->async_method_call(
        [aResp, pefActionGblControl](const boost::system::error_code ec,
                                     const GetSubTreeType& subtreeLocal) {
        if (ec || subtreeLocal.empty())
        {
            BMCWEB_LOG_ERROR("SetPefConfParam: Error");
            messages::internalError(aResp->res);
            return;
        }
        if (subtreeLocal[0].second.size() != 1)
        {
            // invalid mapper response, should never happen
            BMCWEB_LOG_ERROR("SetPefConf: Mapper Error");
            messages::internalError(aResp->res);
            return;
        }
        const std::string& path = subtreeLocal[0].first;
        const std::string& owner = subtreeLocal[0].second[0].first;

        if (pefActionGblControl)
        {
            crow::connections::systemBus->async_method_call(
                [aResp,
                 pefActionGblControl](const boost::system::error_code ec2) {
                if (ec2)
                {
                    BMCWEB_LOG_ERROR("SetPefActionGblControl: Set Error");
                    messages::internalError(aResp->res);
                    return;
                }
            },
                owner, path, "org.freedesktop.DBus.Properties", "Set",
                pefConfIface, "PEFActionGblControl",
                dbus::utility::DbusVariantType(*pefActionGblControl));
        }
    },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTree", "/", 0,
        std::array<const char*, 1>{pefConfIface});
}

void getEventEntries(const std::shared_ptr<bmcweb::AsyncResp>& aResp,
                     nlohmann::json& entriesArray)
{
    std::cerr << "PEF getEventEntries: " << std::endl;
    crow::connections::systemBus->async_method_call(
        [aResp, &entriesArray](const boost::system::error_code ec,
                               const std::vector<std::string>& storageList) {
        if (ec)
        {
            BMCWEB_LOG_ERROR("Volume mapper call error");
            return;
        }

        for (const std::string& objpath : storageList)
        {
            std::cerr << "PEF getEventEntries inside for: " << std::endl;
            std::size_t lastPos = objpath.rfind('/');
            if (lastPos == std::string::npos || (objpath.size() <= lastPos + 1))
            {
                BMCWEB_LOG_ERROR("Failed to find '/' in ", objpath);
                continue;
            }
            entriesArray.push_back(
                {{"@odata.id",
                  "/redfish/v1/PefService/" + objpath.substr(lastPos + 1)}});
            std::cerr << "PEF getEventEntries entry details : " << objpath;
        }
        aResp->res.jsonValue["Members@odata.count"] = entriesArray.size();
    },

        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths",
        "/xyz/openbmc_project/PefAlertManager/EventFilterTable/", 0,
        std::array<const char*, 1>{"xyz.openbmc_project.pef.EventFilterTable"});
}

inline void getEventSeverity(const std::shared_ptr<bmcweb::AsyncResp>& aResp,
                             const std::string entryValue)
{
    sdbusplus::asio::getProperty<uint8_t>(
        *crow::connections::systemBus, "xyz.openbmc_project.pef.alert.manager",
        "/xyz/openbmc_project/PefAlertManager/EventFilterTable/" + entryValue,
        "xyz.openbmc_project.pef.EventFilterTable", "EventSeverity",
        [aResp](const boost::system::error_code& ec, uint8_t eventValue) {
        if (ec)
        {
            BMCWEB_LOG_ERROR("D-BUS response error on EventSeverity Get{}", ec);
            messages::internalError(aResp->res);
            return;
        }
        if (eventValue == 2)
        {
            aResp->res.jsonValue["EventSeverity"] = "Information";
        }
        else if (eventValue == 4)
        {
            aResp->res.jsonValue["EventSeverity"] = "OK";
        }
        else if (eventValue == 8)
        {
            aResp->res.jsonValue["EventSeverity"] = "Warning";
        }
        else if (eventValue == 10)
        {
            aResp->res.jsonValue["EventSeverity"] = "Critical";
        }
        else if (eventValue == 30)
        {
            aResp->res.jsonValue["EventSeverity"] = "All";
        }
        else
            aResp->res.jsonValue["EventSeverity"] = nullptr;
    });
}

inline void setEventSeverity(const std::shared_ptr<bmcweb::AsyncResp>& aResp,
                             const std::optional<uint8_t>& eventId,
                             const std::string entryValue)
{
    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, "xyz.openbmc_project.pef.alert.manager",
        "/xyz/openbmc_project/PefAlertManager/EventFilterTable/" + entryValue,
        "xyz.openbmc_project.pef.EventFilterTable", "EventSeverity", *eventId,
        [aResp](const boost::system::error_code& ec) {
        if (ec)
        {
            BMCWEB_LOG_ERROR("D-Bus responses error: {}", ec);
            messages::internalError(aResp->res);
            return;
        }
    });
}

const PropertyValue getSmtpEnable(const std::string& interfaceName)
{
    PropertyValue value{};
    auto b = sdbusplus::bus::new_default_system();
    auto method = b.new_method_call("xyz.openbmc_project.mail",
                                    "/xyz/openbmc_project/mail/alert",
                                    dbusPropertyInterface, "Get");

    method.append(interfaceName, "Enable");
    auto reply = b.call(method);
    reply.read(value);
    return value;
}

inline void requestRoutesPefService(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/PefService/")
        .privileges({{"Login"}, {"ConfigureComponents"}})
        .methods(boost::beast::http::verb::get)(
            [](const crow::Request&,
               const std::shared_ptr<bmcweb::AsyncResp>& aResp) {
        aResp->res.jsonValue = {
            {"@odata.type", "#PefService.v1_0_0.PefService"},
            {"@odata.id", "/redfish/v1/PefService"},
            {"Id", "Pef Service"},
            {"Name", "Pef Service"},
            {"Description", "Pef Service Collections"}};
        aResp->res.jsonValue["Actions"]["#PefService.SendAlertMail"]["target"] =
            "/redfish/v1/PefService/Actions/"
            "PefService.SendAlertMail/";
        aResp->res
            .jsonValue["Actions"]["#PefService.SendAlertSNMPTrap"]["target"] =
            "/redfish/v1/PefService/Actions/"
            "PefService.SendAlertSNMPTrap/";
        nlohmann::json& entriesntrollerArray = aResp->res.jsonValue["Members"];
        entriesntrollerArray = nlohmann::json::array();

        getEventEntries(aResp, entriesntrollerArray);
        getFilterEnable(aResp);
        getPefConfParam(aResp);
    });

    BMCWEB_ROUTE(app, "/redfish/v1/PefService/")
        .privileges({{"Login"}, {"ConfigureComponents"}})
        .methods(boost::beast::http::verb::patch)(
            [](const crow::Request& req,
               const std::shared_ptr<bmcweb::AsyncResp>& aResp) {
        std::optional<std::vector<uint8_t>> filterEnable;
        std::optional<uint8_t> pefActionGblControl;

        if (!json_util::readJsonPatch(req, aResp->res, "FilterEnable",
                                      filterEnable, "PEFActionGblControl",
                                      pefActionGblControl))
        {
            return;
        }
        if (filterEnable)
        {
            setFilterEnable(aResp, *filterEnable);
        }
        if (pefActionGblControl)
        {
            setPefConfParam(aResp, pefActionGblControl);
        }
	messages::success(aResp->res);
    });

    BMCWEB_ROUTE(app, "/redfish/v1/PefService/<str>")
        .privileges({{"Login"}, {"ConfigureComponents"}})
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& entryId) {
        if (!redfish::setUpRedfishRoute(app, req, asyncResp))
        {
            return;
        }
       crow::connections::systemBus->async_method_call(
            [asyncResp, entryId](const boost::system::error_code ec,
                         const std::vector<std::string>& storageList) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("D-Bus call error while validating event entry");
                asyncResp->res.result(boost::beast::http::status::internal_server_error);
                return;
            }

            // Loop through the event entries and check if the requested entryId is valid
            bool isValid = false;
            for (const std::string& objpath : storageList)
            {
                std::size_t lastPos = objpath.rfind('/');
                if (lastPos != std::string::npos && objpath.substr(lastPos + 1) == entryId)
                {
                    isValid = true;
                    break;
                }
            }

            if (!isValid)
            {
                messages::resourceNotFound(asyncResp->res, "PefService", entryId);
                return;
            }
            else
            {
                    asyncResp->res.jsonValue = {
                    {"@odata.type", "#PefEntry.v1_0_0.PefEntry"},
                    {"@odata.id", "/redfish/v1/PefService/" + entryId},
                    {"Id", entryId},
                    {"Name", "Pef Service Entry"}};
                   getEventSeverity(asyncResp, entryId);
            }
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths",
        "/xyz/openbmc_project/PefAlertManager/EventFilterTable/", 0,
        std::array<const char*, 1>{"xyz.openbmc_project.pef.EventFilterTable"});
    });

    BMCWEB_ROUTE(app, "/redfish/v1/PefService/<str>")
        .privileges({{"Login"}, {"ConfigureComponents"}})
        .methods(boost::beast::http::verb::patch)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& entryId) {
        std::optional<std::string> eventSeverity;
        if (!json_util::readJsonPatch(req, asyncResp->res, "EventSeverity",
                                      eventSeverity))
        {
            return;
        }

        if (eventSeverity)
        {
            if (eventSeverity == "Information")
            {
                setEventSeverity(asyncResp, 2, entryId);
            }
            else if (eventSeverity == "OK")
            {
                setEventSeverity(asyncResp, 4, entryId);
            }
            else if (eventSeverity == "Warning")
            {
                setEventSeverity(asyncResp, 8, entryId);
            }
            else if (eventSeverity == "Critical")
            {
                setEventSeverity(asyncResp, 10, entryId);
            }
            else if (eventSeverity == "All")
            {
                setEventSeverity(asyncResp, 30, entryId);
            }
            else
            {
                messages::propertyValueNotInList(
                    asyncResp->res, "EventSeverity", *eventSeverity);
            }
        }
	messages::success(asyncResp->res);
    });

    BMCWEB_ROUTE(app,
                 "/redfish/v1/PefService/Actions/PefService.SendAlertMail/")
        .privileges({{"Login"}, {"ConfigureComponents"}})
        .methods(boost::beast::http::verb::post)(
            [](const crow::Request& req,
               const std::shared_ptr<bmcweb::AsyncResp>& aResp) {
        std::string subject;
        std::string mailBuf;
        std::optional<std::string> vId;

        if (!json_util::readJsonPatch(req, aResp->res, "Subject", subject,
                                      "MailContent", mailBuf, "Id", vId))
        {
            return;
        }
        if (vId)
        {
            messages::propertyNotWritable(aResp->res, "Id");
            aResp->res.result(boost::beast::http::status::bad_request);
            return;
        }
        auto primaryvalue =
            getSmtpEnable("xyz.openbmc_project.mail.alert.primary");
        auto primaryconfiguration = std::get<bool>(primaryvalue);

        auto secondaryvalue =
            getSmtpEnable("xyz.openbmc_project.mail.alert.secondary");
        auto secondaryconfiguration = std::get<bool>(secondaryvalue);

        if (!primaryconfiguration && !secondaryconfiguration)
        {
            messages::serviceDisabled(
                aResp->res,
                "Primary Configuration and secondary configuration");
            aResp->res.result(boost::beast::http::status::bad_request);
            return;
        }
        else
        {
            crow::connections::systemBus->async_method_call(
                [subject, mailBuf, aResp](const boost::system::error_code ec1,
                                          const std::uint16_t& response) {
                if (ec1)
                {
                    BMCWEB_LOG_ERROR("SendMail: Can't get "
                                     "alertMailIface ");
                    messages::internalError(aResp->res);
                    return;
                }
                else if (response == 65535)
                {
                    messages::internalError(aResp->res);
                    return;
                }
                else if (response == 65534)
                {
                    messages::insufficientPrivilege(aResp->res);
                    return;
                }
                else
                {
                    messages::success(aResp->res);
                }
            },
                "xyz.openbmc_project.mail", "/xyz/openbmc_project/mail/alert",
                "xyz.openbmc_project.mail.alert", "SendMail", subject, mailBuf);
        }
    });
}

inline void requestRoutesSendTrap(App& app)
{
    BMCWEB_ROUTE(app,
                 "/redfish/v1/PefService/Actions/PefService.SendAlertSNMPTrap/")
        .privileges({{"Login"}, {"ConfigureComponents"}})
        .methods(boost::beast::http::verb::post)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& aResp) {
        if (!redfish::setUpRedfishRoute(app, req, aResp))
        {
            return;
        }
        crow::connections::systemBus->async_method_call(
            [aResp](const boost::system::error_code& ec1) {
            if (ec1)
            {
                BMCWEB_LOG_ERROR("SendMail: Can't get "
                                 "alertMailIface ");
                messages::internalError(aResp->res);
                return;
            }
            else
            {
                sdbusplus::message::object_path path(
                    "/xyz/openbmc_project/network/snmp/manager");
                dbus::utility::getManagedObjects(
                    "xyz.openbmc_project.Network.SNMP", path,
                    [aResp](const boost::system::error_code& ec2,
                            const dbus::utility::ManagedObjectType& resp) {
                    if (ec2)
                    {
                        BMCWEB_LOG_WARNING("D-Bus responses error: {}", ec2);
                        return;
                    }
                    sdbusplus::asio::getProperty<bool>(
                        *crow::connections::systemBus,
                        "xyz.openbmc_project.Snmp", "/xyz/openbmc_project/Snmp",
                        "xyz.openbmc_project.Snmp.SnmpUtils", "SnmpTrapStatus",
                        [aResp, resp](const boost::system::error_code& ec,
                                      bool protocolEnabled) {
                        if (ec)
                        {
                            BMCWEB_LOG_ERROR(
                                "D-BUS response error on SnmpTrapStatus Get{}",
                                ec);
                            messages::internalError(aResp->res);
                            return;
                        }
                        else if (!protocolEnabled)
                        {
                            messages::serviceDisabled(aResp->res,
                                                      "SNMP Service Disabled");
                            return;
                            return;
                        }
                        else if (resp.size() == 0)
                        {
                            messages::internalError(aResp->res);
                            return;
                        }
                        messages::success(aResp->res);
                    });
                });
            }
        }, "xyz.openbmc_project.Snmp", "/xyz/openbmc_project/Snmp",
            "xyz.openbmc_project.Snmp.SnmpUtils", "SendSNMPTrap");
    });
}

} // namespace redfish
