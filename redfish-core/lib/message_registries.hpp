/*
// Copyright (c) 2019 Intel Corporation
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
*/
#pragma once

#include "app.hpp"
#include "query.hpp"
#include "registries.hpp"
#include "registries/base_message_registry.hpp"
#include "registries/nm_message_registry.hpp"
#include "registries/openbmc_message_registry.hpp"
#include "registries/privilege_registry.hpp"
#include "registries/resource_event_message_registry.hpp"
#include "registries/task_event_message_registry.hpp"
#include "registries/telemetry_message_registry.hpp"
#include "registries/privilege_mapping.hpp"


#include <boost/url/format.hpp>

#include <array>

namespace redfish
{

inline void handleMessageRegistryFileCollectionGet(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    // Collections don't include the static data added by SubRoute
    // because it has a duplicate entry for members

    asyncResp->res.jsonValue["@odata.type"] =
        "#MessageRegistryFileCollection.MessageRegistryFileCollection";
    asyncResp->res.jsonValue["@odata.id"] = "/redfish/v1/Registries";
    asyncResp->res.jsonValue["Name"] = "MessageRegistryFile Collection";
    asyncResp->res.jsonValue["Description"] =
        "Collection of MessageRegistryFiles";

    nlohmann::json& members = asyncResp->res.jsonValue["Members"];
    for (const char* memberName :
         std::to_array({"Base", "TaskEvent", "NodeManager", "ResourceEvent", "OpenBMC", "Telemetry", "PrivilegeRegistry"}))
    {
        nlohmann::json::object_t member;
        member["@odata.id"] = boost::urls::format("/redfish/v1/Registries/{}",
                                                  memberName);
        members.emplace_back(std::move(member));
    }
    asyncResp->res.jsonValue["Members@odata.count"] = (asyncResp->res.jsonValue["Members"]).size();
}

inline void requestRoutesMessageRegistryFileCollection(App& app)
{
    /**
     * Functions triggers appropriate requests on DBus
     */
    BMCWEB_ROUTE(app, "/redfish/v1/Registries/")
        .privileges(redfish::privileges::getMessageRegistryFileCollection)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleMessageRegistryFileCollectionGet, std::ref(app)));
}
inline void fillPrivilegeRegistry(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const registries::Header* header
    )
{
    //asyncResp->res.jsonValue["@Redfish.Copyright"] = header->copyright;
    asyncResp->res.jsonValue["@odata.type"] = header->type;
    asyncResp->res.jsonValue["Id"] = header->id;
    asyncResp->res.jsonValue["Name"] = header->name;
    //asyncResp->res.jsonValue["Language"] = header->language;
    //asyncResp->res.jsonValue["Description"] = header->description;
    //asyncResp->res.jsonValue["RegistryPrefix"] = header->registryPrefix;
    //asyncResp->res.jsonValue["RegistryVersion"] = header->registryVersion;
    //asyncResp->res.jsonValue["OwningEntity"] = header->owningEntity;

    nlohmann::json& privilegeObj = asyncResp->res.jsonValue["PrivilegesUsed"];
    privilegeObj = nlohmann::json::array();

    for (const char* privilegeItem : registries::PrivilegeRegistry::PrivilegesUsed) {
        if (privilegeItem == nullptr) {
            break;
        }
        privilegeObj.push_back(privilegeItem);
    }

    nlohmann::json& oemPrivileges = asyncResp->res.jsonValue["OEMPrivilegesUsed"];
    oemPrivileges = nlohmann::json::array();

    for(const char* OemprivilegeItem : registries::PrivilegeRegistry::OEMprivilegesUsed) {
		    if (OemprivilegeItem == nullptr) {
            break;
        }
        oemPrivileges.push_back(OemprivilegeItem);
     }

    nlohmann::json& mappings = asyncResp->res.jsonValue["Mappings"];
    for (const auto& entity : registries::PrivilegeRegistry::entities) {
        std::string entityName = entity.first;
        const auto& operationMaps = entity.second;

        nlohmann::json mappingObj = nlohmann::json::object();
        mappingObj["Entity"] = entityName;
        mappingObj["OperationMap"] = nlohmann::json::object();


        for (const auto& operation : operationMaps) {
            const std::string& method = operation.first;
            const auto& privileges = operation.second;

            mappingObj["OperationMap"][method] = nlohmann::json::array();
            for (const auto& privilege : privileges) {
                mappingObj["OperationMap"][method].push_back({
                    {"Privilege", nlohmann::json::array({privilege})}
                    });
            }
        }

        mappings.push_back(mappingObj);
    }

    for (const auto& entity : registries::PrivilegeRegistry::OEMentities) {
        std::string entityName = entity.first;
        const auto& operationMaps = entity.second;

        nlohmann::json oemPrivilegesObj = nlohmann::json::object();
        oemPrivilegesObj["Entity"] = entityName;
        oemPrivilegesObj["OperationMap"] = nlohmann::json::object();

        for (const auto& operation : operationMaps) {

            const std::string& method = operation.first;
            const auto& privileges = operation.second;
            oemPrivilegesObj["OperationMap"][method] = nlohmann::json::array();

            for (const auto& privilege : privileges) {
                oemPrivilegesObj["OperationMap"][method].push_back({
                     {"Privilege", nlohmann::json::array({privilege})}
                     });
            }
        }

        mappings.push_back(oemPrivilegesObj);
    }
}

inline void handleMessageRoutesMessageRegistryFileGet(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& registry)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    const registries::Header* header = nullptr;
    std::string dmtf = "DMTF ";
    std::vector<const registries::MessageEntry*> registryEntries;
    int registryVal = 0;

    size_t pos = registry.find('.');
    std::string registryName;
    if (pos != std::string::npos) {
        // Retrieve the substring before the first full stop
        registryName = registry.substr(0, pos);
    }
    std::string Val;
    if (registry == "Base" || registryName == "Base")
    {
        header = &registries::base::header;
        Val= header->id;
        if(registry == "Base"){
                registryVal = 0;
        }
        else if (registry == Val + ".json")
        {
                for (const registries::MessageEntry& entry : registries::base::registry)
                {
                        registryEntries.emplace_back(&entry);
                }
                registryVal = 1;
        }
        else
        {
            messages::resourceNotFound(asyncResp->res, "MessageRegistryFile",
                                    registry);
            return;
        }
    }
    else if (registry == "TaskEvent" || registryName == "TaskEvent")
    {
        header = &registries::task_event::header;
        Val= header->id;
        if(registry == "TaskEvent"){
                registryVal = 0;
        }
        else if (registry == Val + ".json")
        {
                for (const registries::MessageEntry& entry : registries::task_event::registry)
                {
                        registryEntries.emplace_back(&entry);
                }
                registryVal = 1;
        }
        else
        {
            messages::resourceNotFound(asyncResp->res, "MessageRegistryFile",
                                    registry);
            return;
        }
    }
    else if (registry == "OpenBMC" || registryName == "OpenBMC")
    {
        header = &registries::openbmc::header;
        Val= header->id;
        if(registry == "OpenBMC"){
                dmtf.clear();
                registryVal = 0;
        }
        else if (registry == Val + ".json")
        {
                for (const registries::MessageEntry& entry : registries::openbmc::registry)
                {
                        registryEntries.emplace_back(&entry);
                }
                registryVal = 1;
        }
        else
        {
            messages::resourceNotFound(asyncResp->res, "MessageRegistryFile",
                                    registry);
            return;
        }
    }
    else if (registry == "NodeManager" || registryName == "NodeManager")
    {
        header = &registries::nm::header;
        Val= header->id;
        if(registry == "NodeManager"){
                dmtf.clear();
                registryVal = 0;
        }
        else if (registry == Val + ".json")
        {
                for (const registries::MessageEntry& entry : registries::nm::registry)
                {
                        registryEntries.emplace_back(&entry);
                }
                registryVal = 1;
        }
        else
        {
            messages::resourceNotFound(asyncResp->res, "MessageRegistryFile",
                                    registry);
            return;
        }
    }
    else if (registry == "ResourceEvent" || registryName == "ResourceEvent")
    {
        header = &registries::resource_event::header;
        Val= header->id;
        if(registry == "ResourceEvent"){
                registryVal = 0;
        }
        else if (registry == Val + ".json")
        {
                for (const registries::MessageEntry& entry : registries::resource_event::registry)
                {
                        registryEntries.emplace_back(&entry);
                }
                registryVal = 1;
        }
        else
        {
            messages::resourceNotFound(asyncResp->res, "MessageRegistryFile",
                                    registry);
            return;
        }
    }
    else if (registry == "Telemetry" || registryName == "Telemetry")
    {
        header = &registries::telemetry::header;
         Val= header->id;
        if(registry == "Telemetry"){
                registryVal = 0;
        }
        else if (registry == Val + ".json")
        {
                for (const registries::MessageEntry& entry : registries::telemetry::registry)
                {
                        registryEntries.emplace_back(&entry);
                }
                registryVal = 1;
        }
        else
        {
            messages::resourceNotFound(asyncResp->res, "MessageRegistryFile",
                                    registry);
            return;
        }
    }
    else if (registry == "PrivilegeRegistry" || registry.find("PrivilegeRegistry") != std::string::npos)
    {
        header = &registries::PrivilegeRegistry::header;
        Val= header->id;
        if(registry == "PrivilegeRegistry"){
                registryVal = 0;
        }
        else if (registry == Val + ".json")
        {

           fillPrivilegeRegistry(asyncResp ,header);
           return;

        }
        else
        {
            messages::resourceNotFound(asyncResp->res, "MessageRegistryFile",
                                    registry);
            return;
        }
    }
    else
    {
        messages::resourceNotFound(asyncResp->res, "MessageRegistryFile",
                                   registry);
        return;
    }
    if (registryVal == 0)
    {
        asyncResp->res.jsonValue["@odata.id"] =
            boost::urls::format("/redfish/v1/Registries/{}", registry);
        asyncResp->res.jsonValue["@odata.type"] =
            "#MessageRegistryFile.v1_1_0.MessageRegistryFile";
        asyncResp->res.jsonValue["Name"] = registry + " Message Registry File";
        asyncResp->res.jsonValue["Description"] = dmtf + registry +
                                              " Message Registry File Location";
        asyncResp->res.jsonValue["Id"] = header->registryPrefix;
        asyncResp->res.jsonValue["Registry"] = header->id;
        nlohmann::json::array_t languages;
        languages.emplace_back(header->language);
        asyncResp->res.jsonValue["Languages@odata.count"] = languages.size();
        asyncResp->res.jsonValue["Languages"] = std::move(languages);
        nlohmann::json::array_t locationMembers;
        nlohmann::json::object_t location;
        location["Language"] = header->language;
    location["Uri"] = "/redfish/v1/Registries/" + Val + ".json";

        locationMembers.emplace_back(std::move(location));
        asyncResp->res.jsonValue["Location@odata.count"] = locationMembers.size();
        asyncResp->res.jsonValue["Location"] = std::move(locationMembers);
    }
    if(registryVal == 1){
        std::cerr << "Enter in registryVal == 1 " << std::endl;
        asyncResp->res.jsonValue["@Redfish.Copyright"] = header->copyright;
        asyncResp->res.jsonValue["@odata.type"] = header->type;
        asyncResp->res.jsonValue["Id"] = header->id;
        asyncResp->res.jsonValue["Name"] = header->name;
        asyncResp->res.jsonValue["Language"] = header->language;
        asyncResp->res.jsonValue["Description"] = header->description;
        asyncResp->res.jsonValue["RegistryPrefix"] = header->registryPrefix;
        asyncResp->res.jsonValue["RegistryVersion"] = header->registryVersion;
        asyncResp->res.jsonValue["OwningEntity"] = header->owningEntity;

        nlohmann::json& messageObj = asyncResp->res.jsonValue["Messages"];

        // Go through the Message Registry and populate each Message
        for (const registries::MessageEntry* message : registryEntries)
        {
            nlohmann::json& obj = messageObj[message->first];
            obj["Description"] = message->second.description;
            obj["Message"] = message->second.message;
            obj["Severity"] = message->second.messageSeverity;
            obj["MessageSeverity"] = message->second.messageSeverity;
            obj["NumberOfArgs"] = message->second.numberOfArgs;
            obj["Resolution"] = message->second.resolution;
            if (message->second.numberOfArgs > 0)
            {
                nlohmann::json& messageParamArray = obj["ParamTypes"];
                messageParamArray = nlohmann::json::array();
                for (const char* str : message->second.paramTypes)
                {
                   if (str == nullptr)
                   {
                       break;
                   }
                   messageParamArray.push_back(str);
                }
             }
         }
    }

}

inline void requestRoutesMessageRegistryFile(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Registries/<str>/")
        .privileges(redfish::privileges::getMessageRegistryFile)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleMessageRoutesMessageRegistryFileGet, std::ref(app)));
}

} // namespace redfish
