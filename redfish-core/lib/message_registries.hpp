// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
// SPDX-FileCopyrightText: Copyright 2019 Intel Corporation
#pragma once

#include "app.hpp"
#include "query.hpp"
#include "registries.hpp"
#include "registries/base_message_registry.hpp"
#include "registries/certificate_service_message_registry.hpp"
#include "registries/heartbeat_event_message_registry.hpp"
#include "registries/license_message_registry.hpp"
#include "registries/nm_message_registry.hpp"
#include "registries/openbmc_message_registry.hpp"
#include "registries/privilege_mapping.hpp"
#include "registries/privilege_registry.hpp"
#include "registries/resource_event_message_registry.hpp"
#include "registries/task_event_message_registry.hpp"
#include "registries/telemetry_message_registry.hpp"

#ifdef ONETREE_RTP
#include "ext/include/registries/ami_certificate_service_message_registry.hpp"
#include "ext/include/registries/ami_privilege_mapping.hpp"
#endif

#if (BMCWEB_AMI_CONTROLS_MACRO)
#include "ext/include/registries/amioem_controls_privilege_mapping.hpp"
#endif

#ifdef ONETREE_ACD
#include "ext/include/registries/acd_service_message_registry.hpp"
#endif

#include <boost/url/format.hpp>

#include <array>
#include <format>

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
    static constexpr const auto registryFiles = std::to_array(
        {"Base", "TaskEvent", "License", "NodeManager", "ResourceEvent",
         "OpenBMC", "Telemetry", "PrivilegeRegistry", "HeartbeatEvent",
         "CertificateService", "AmiOneTree"});
    for (const char* memberName : registryFiles)
    {
        nlohmann::json::object_t member;
        member["@odata.id"] =
            boost::urls::format("/redfish/v1/Registries/{}", memberName);
        members.emplace_back(std::move(member));
    }

#ifdef ONETREE_ACD
    {
        nlohmann::json::object_t acdMember;
        acdMember["@odata.id"] = boost::urls::url("/redfish/v1/Registries/ACD");
        members.emplace_back(std::move(acdMember));
    }
#endif

    asyncResp->res.jsonValue["Members@odata.count"] = members.size();
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

/**
 * @brief Helper function to populate privilege mappings for entities
 *
 * @param mappings Reference to the mappings JSON array
 * @param entities Map of entity names to their operation maps
 */
template <typename EntityMapType>
inline void addEntitiesToMappings(nlohmann::json& mappings,
                                  const EntityMapType& entities)
{
    for (const auto& entity : entities)
    {
        std::string entityName = entity.first;
        const auto& operationMaps = entity.second;

        nlohmann::json entityObj = nlohmann::json::object();
        entityObj["Entity"] = entityName;
        entityObj["OperationMap"] = nlohmann::json::object();

        for (const auto& operation : operationMaps)
        {
            const std::string& method = operation.first;
            const auto& privileges = operation.second;
            entityObj["OperationMap"][method] = nlohmann::json::array();

            for (const auto& privilege : privileges)
            {
                entityObj["OperationMap"][method].push_back(
                    {{"Privilege", nlohmann::json::array({privilege})}});
            }
        }

        mappings.push_back(entityObj);
    }
}

inline void fillPrivilegeRegistry(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const registries::Header* header)
{
    // asyncResp->res.jsonValue["@Redfish.Copyright"] = header->copyright;
    std::vector<std::string> split;
    bmcweb::split(split, header->type, '.');
    asyncResp->res.jsonValue["@odata.type"] = json_util::odataType(split[2]);
    asyncResp->res.jsonValue["Id"] =
        std::format("{}.{}.{}.{}", header->registryPrefix, header->versionMajor,
                    header->versionMinor, header->versionPatch);
    asyncResp->res.jsonValue["Name"] = header->name;
    // asyncResp->res.jsonValue["Language"] = header->language;
    // asyncResp->res.jsonValue["Description"] = header->description;
    // asyncResp->res.jsonValue["RegistryPrefix"] = header->registryPrefix;
    // asyncResp->res.jsonValue["RegistryVersion"] = header->registryVersion;
    // asyncResp->res.jsonValue["OwningEntity"] = header->owningEntity;

    nlohmann::json& privilegeObj = asyncResp->res.jsonValue["PrivilegesUsed"];
    privilegeObj = nlohmann::json::array();

    for (const char* privilegeItem :
         registries::PrivilegeRegistry::PrivilegesUsed)
    {
        if (privilegeItem == nullptr)
        {
            break;
        }
        privilegeObj.push_back(privilegeItem);
    }

    nlohmann::json& oemPrivileges =
        asyncResp->res.jsonValue["OEMPrivilegesUsed"];
    oemPrivileges = nlohmann::json::array();

    for (const char* OemprivilegeItem :
         registries::PrivilegeRegistry::OEMprivilegesUsed)
    {
        if (OemprivilegeItem == nullptr)
        {
            break;
        }
        oemPrivileges.push_back(OemprivilegeItem);
    }

    nlohmann::json& mappings = asyncResp->res.jsonValue["Mappings"];
    for (const auto& entity : registries::PrivilegeRegistry::entities)
    {
        std::string entityName = entity.first;
        const auto& operationMaps = entity.second;

        nlohmann::json mappingObj = nlohmann::json::object();
        mappingObj["Entity"] = entityName;
        mappingObj["OperationMap"] = nlohmann::json::object();

        for (const auto& operation : operationMaps)
        {
            const std::string& method = operation.first;
            const auto& privileges = operation.second;

            mappingObj["OperationMap"][method] = nlohmann::json::array();
            for (const auto& privilege : privileges)
            {
                mappingObj["OperationMap"][method].push_back(
                    {{"Privilege", nlohmann::json::array({privilege})}});
            }
        }

        // Check for PropertyOverrides for this entity
        const auto propertyOverrideIt =
            registries::PrivilegeRegistry::propertyOverrides.find(entityName);
        if (propertyOverrideIt !=
            registries::PrivilegeRegistry::propertyOverrides.end())
        {
            mappingObj["PropertyOverrides"] = nlohmann::json::array();
            for (const auto& propOverride : propertyOverrideIt->second)
            {
                nlohmann::json propOverrideObj = nlohmann::json::object();
                propOverrideObj["Targets"] = propOverride.targets;
                propOverrideObj["OperationMap"] = nlohmann::json::object();
                for (const auto& op : propOverride.operationMap)
                {
                    const std::string& opMethod = op.first;
                    const auto& privileges = op.second;
                    propOverrideObj["OperationMap"][opMethod] =
                        nlohmann::json::array();
                    for (const auto& privilege : privileges)
                    {
                        propOverrideObj["OperationMap"][opMethod].push_back(
                            {{"Privilege",
                              nlohmann::json::array({privilege})}});
                    }
                }
                mappingObj["PropertyOverrides"].push_back(propOverrideObj);
            }
        }

        mappings.push_back(mappingObj);
    }

    // Add OEM entities
    addEntitiesToMappings(mappings, registries::PrivilegeRegistry::OEMentities);

#ifdef ONETREE_RTP
    // Add AMI-specific entities to PrivilegeRegistry
    addEntitiesToMappings(
        mappings, redfish::registries::AMIPrivilegeMapping::AMIEntities);
#endif

#if (BMCWEB_AMI_CONTROLS_MACRO)
    // Add AMI-specific Controls entities to PrivilegeRegistry
    addEntitiesToMappings(
        mappings,
        redfish::registries::AMIPrivilegeMapping::AMIOemControlsEntities);
#endif
}

inline void handleMessageRoutesMessageRegistryFileGet(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& registry)
{
    asyncResp->res.clearHeader(boost::beast::http::field::allow);

    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (!membersResponseGet(asyncResp, registry,
                            "MessageRegistryFileCollection"))
    {
        return;
    }
    asyncResp->res.addHeader("Allow", "GET");
    const registries::Header* header = nullptr;
    std::string dmtf = "DMTF ";
    std::vector<const registries::MessageEntry*> registryEntries;
    bool registryVal = false;

    size_t pos = registry.find('.');
    std::string registryName;
    if (pos != std::string::npos)
    {
        // Retrieve the substring before the first full stop
        registryName = registry.substr(0, pos);
    }
    std::string Val;
    if (registry == "Base" || registryName == "Base")
    {
        header = &registries::base::header;
        Val = std::format("{}.{}.{}.{}", header->registryPrefix,
                          header->versionMajor, header->versionMinor,
                          header->versionPatch);
        if (registry == "Base")
        {
            registryVal = false;
        }
        else if (registry == Val + ".json")
        {
            for (const registries::MessageEntry& entry :
                 registries::base::registry)
            {
                registryEntries.emplace_back(&entry);
            }
            registryVal = true;
        }
        else
        {
            messages::resourceNotFound(asyncResp->res, "MessageRegistryFile",
                                       registry);
            return;
        }
    }
    else if (registry == "License" || registryName == "License")
    {
        header = &registries::license::header;
        Val = std::format("{}.{}.{}.{}", header->registryPrefix,
                          header->versionMajor, header->versionMinor,
                          header->versionPatch);
        if (registry == "License")
        {
            registryVal = false;
        }
        else if (registry == Val + ".json")
        {
            for (const registries::MessageEntry& entry :
                 registries::license::registry)
            {
                registryEntries.emplace_back(&entry);
            }
            registryVal = true;
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
        Val = std::format("{}.{}.{}.{}", header->registryPrefix,
                          header->versionMajor, header->versionMinor,
                          header->versionPatch);
        if (registry == "TaskEvent")
        {
            registryVal = false;
        }
        else if (registry == Val + ".json")
        {
            for (const registries::MessageEntry& entry :
                 registries::task_event::registry)
            {
                registryEntries.emplace_back(&entry);
            }
            registryVal = true;
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
        Val = std::format("{}.{}.{}.{}", header->registryPrefix,
                          header->versionMajor, header->versionMinor,
                          header->versionPatch);
        if (registry == "OpenBMC")
        {
            dmtf.clear();
            registryVal = false;
        }
        else if (registry == Val + ".json")
        {
            for (const registries::MessageEntry& entry :
                 registries::openbmc::registry)
            {
                registryEntries.emplace_back(&entry);
            }
            registryVal = true;
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
        Val = std::format("{}.{}.{}.{}", header->registryPrefix,
                          header->versionMajor, header->versionMinor,
                          header->versionPatch);
        if (registry == "NodeManager")
        {
            dmtf.clear();
            registryVal = false;
        }
        else if (registry == Val + ".json")
        {
            for (const registries::MessageEntry& entry :
                 registries::nm::registry)
            {
                registryEntries.emplace_back(&entry);
            }
            registryVal = true;
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
        Val = std::format("{}.{}.{}.{}", header->registryPrefix,
                          header->versionMajor, header->versionMinor,
                          header->versionPatch);
        if (registry == "ResourceEvent")
        {
            registryVal = false;
        }
        else if (registry == Val + ".json")
        {
            for (const registries::MessageEntry& entry :
                 registries::resource_event::registry)
            {
                registryEntries.emplace_back(&entry);
            }
            registryVal = true;
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
        Val = std::format("{}.{}.{}.{}", header->registryPrefix,
                          header->versionMajor, header->versionMinor,
                          header->versionPatch);
        if (registry == "Telemetry")
        {
            registryVal = false;
        }
        else if (registry == Val + ".json")
        {
            for (const registries::MessageEntry& entry :
                 registries::telemetry::registry)
            {
                registryEntries.emplace_back(&entry);
            }
            registryVal = true;
        }
        else
        {
            messages::resourceNotFound(asyncResp->res, "MessageRegistryFile",
                                       registry);
            return;
        }
    }
    else if (registry == "HeartbeatEvent" || registryName == "HeartbeatEvent")
    {
        header = &registries::heartbeat_event::header;
        Val = std::format("{}.{}.{}.{}", header->registryPrefix,
                          header->versionMajor, header->versionMinor,
                          header->versionPatch);
        if (registry == "HeartbeatEvent")
        {
            registryVal = false;
        }
        else if (registry == Val + ".json")
        {
            for (const registries::MessageEntry& entry :
                 registries::telemetry::registry)
            {
                registryEntries.emplace_back(&entry);
            }
            registryVal = true;
        }
        else
        {
            messages::resourceNotFound(asyncResp->res, "MessageRegistryFile",
                                       registry);
            return;
        }
    }
    else if (registry == "PrivilegeRegistry" ||
             registry.find("PrivilegeRegistry") != std::string::npos)
    {
        header = &registries::PrivilegeRegistry::header;
        Val = "Redfish_1.5.0_PrivilegeRegistry";
        if (registry == "PrivilegeRegistry")
        {
            registryVal = false;
        }
        else if (registry == Val + ".json")
        {
            fillPrivilegeRegistry(asyncResp, header);
            return;
        }
        else
        {
            messages::resourceNotFound(asyncResp->res, "MessageRegistryFile",
                                       registry);
            return;
        }
    }
    else if (registry == "CertificateService" ||
             registryName == "CertificateService")
    {
        header = &registries::certificate::header;
        Val = std::format("{}.{}.{}.{}", header->registryPrefix,
                          header->versionMajor, header->versionMinor,
                          header->versionPatch);
        if (registry == "CertificateService")
        {
            registryVal = false;
        }
        else if (registry == Val + ".json")
        {
            for (const registries::MessageEntry& entry :
                 registries::certificate::registry)
            {
                registryEntries.emplace_back(&entry);
            }
#ifdef ONETREE_RTP
            header = &registries::ami::certificate::header;
            for (const registries::MessageEntry& entry :
                 registries::ami::certificate::registry)
            {
                registryEntries.emplace_back(&entry);
            }
#endif
            registryVal = true;
        }
        else
        {
            messages::resourceNotFound(asyncResp->res, "MessageRegistryFile",
                                       registry);
            return;
        }
    }
#ifdef ONETREE_ACD
    else if (registry == "ACD" || registryName == "ACD")
    {
        header = &registries::acd::header;
        dmtf.clear();

        Val = std::format("{}.{}.{}.{}", header->registryPrefix,
                          header->versionMajor, header->versionMinor,
                          header->versionPatch);
        if (registry == "ACD")
        {
            registryVal = false;
        }
        else if (registry == Val + ".json")
        {
            for (const registries::MessageEntry& entry :
                 registries::acd::registry)
            {
                registryEntries.emplace_back(&entry);
            }
            registryVal = true;
        }
        else
        {
            messages::resourceNotFound(asyncResp->res, "MessageRegistryFile",
                                       registry);
            return;
        }
    }
#endif
    else if (registry == "AmiOneTree" || registryName == "AmiOneTree")
    {
        header = &registries::amionetree::header;
        dmtf.clear();
        Val = std::format("{}.{}.{}.{}", header->registryPrefix,
                          header->versionMajor, header->versionMinor,
                          header->versionPatch);
        if (registry == "AmiOneTree")
        {
            registryVal = false;
        }
        else if (registry == Val + ".json")
        {
            for (const registries::MessageEntry& entry :
                 registries::amionetree::registry)
            {
                registryEntries.emplace_back(&entry);
            }
            registryVal = true;
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
    if (!registryVal)
    {
        asyncResp->res.jsonValue["@odata.id"] =
            boost::urls::format("/redfish/v1/Registries/{}", registry);
        asyncResp->res.jsonValue["@odata.type"] =
            json_util::odataType("MessageRegistryFile");
        asyncResp->res.jsonValue["Name"] = registry + " Message Registry File";
        asyncResp->res.jsonValue["Description"] =
            dmtf + registry + " Message Registry File Location";
        asyncResp->res.jsonValue["Id"] = header->registryPrefix;
        if (registry != "PrivilegeRegistry")
        {
            asyncResp->res.jsonValue["Registry"] =
                std::format("{}.{}.{}", header->registryPrefix,
                            header->versionMajor, header->versionMinor);
        }
        else
        {
            asyncResp->res.jsonValue["Registry"] =
                "Redfish_1.5.0_PrivilegeRegistry";
        }
        nlohmann::json::array_t languages;
        languages.emplace_back(header->language);
        asyncResp->res.jsonValue["Languages@odata.count"] = languages.size();
        asyncResp->res.jsonValue["Languages"] = std::move(languages);
        nlohmann::json::array_t locationMembers;
        nlohmann::json::object_t location;
        location["Language"] = header->language;
        location["Uri"] = "/redfish/v1/Registries/" + Val + ".json";

        locationMembers.emplace_back(std::move(location));
        asyncResp->res.jsonValue["Location@odata.count"] =
            locationMembers.size();
        asyncResp->res.jsonValue["Location"] = std::move(locationMembers);
    }
    if (registryVal)
    {
        std::vector<std::string> split;
        bmcweb::split(split, header->type, '.');
        asyncResp->res.jsonValue["@Redfish.Copyright"] = header->copyright;
        asyncResp->res.jsonValue["@odata.type"] =
            json_util::odataType(split[2]);
        asyncResp->res.jsonValue["Id"] = std::format(
            "{}.{}.{}.{}", header->registryPrefix, header->versionMajor,
            header->versionMinor, header->versionPatch);
        asyncResp->res.jsonValue["Name"] = header->name;
        asyncResp->res.jsonValue["Language"] = header->language;
        asyncResp->res.jsonValue["Description"] = header->description;
        asyncResp->res.jsonValue["RegistryPrefix"] = header->registryPrefix;
        asyncResp->res.jsonValue["RegistryVersion"] =
            std::format("{}.{}.{}", header->versionMajor, header->versionMinor,
                        header->versionPatch);
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

    BMCWEB_ROUTE(app, "/redfish/v1/Registries/<str>/")
        .privileges(redfish::privileges::getMessageRegistryFile)
        .methods(
            boost::beast::http::verb::post, boost::beast::http::verb::patch,
            boost::beast::http::verb::delete_,
            boost::beast::http::verb::
                put)([&app](const crow::Request& req,
                            const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                            const std::string& registry) {
            asyncResp->res.clearHeader(boost::beast::http::field::allow);
            if (!redfish::setUpRedfishRoute(app, req, asyncResp))
            {
                return;
            }
            if (!membersResponseGet(asyncResp, registry,
                                    "MessageRegistryFileCollection"))
            {
                return;
            }
            size_t pos = registry.find('.');
            std::string registryName;
            if (pos != std::string::npos)
            {
                // Retrieve the substring before the first full stop
                registryName = registry.substr(0, pos);
            }
            std::string Val;
            static constexpr const auto registryFiles = std::to_array(
                {"Base", "TaskEvent", "License", "NodeManager", "ResourceEvent",
                 "OpenBMC", "Telemetry", "PrivilegeRegistry", "HeartbeatEvent",
                 "CertificateService", "Ami"});
            for (const char* memberName : registryFiles)
            {
                if (registry == memberName || registryName == memberName)
                {
                    asyncResp->res.addHeader("Allow", "GET");
                    messages::operationNotAllowed(asyncResp->res);
                    return;
                }
            }

#ifdef ONETREE_ACD
            if (registry == "ACD" || registryName == "ACD")
            {
                asyncResp->res.addHeader("Allow", "GET");
                messages::operationNotAllowed(asyncResp->res);
                return;
            }
#endif

#ifdef ONETREE_RTP
            sdbusplus::asio::getAllProperties(
                *crow::connections::systemBus,
                "xyz.openbmc_project.OOBInventoryConfig",
                "/xyz/openbmc_project/OOBInventoryConfig",
                "xyz.openbmc_project.OobBiosConfigInventory.OobBiosConfigInventory",
                [asyncResp, registry](
                    const boost::system::error_code& ec,
                    const std::vector<
                        std::pair<std::string, dbus::utility::DbusVariantType>>&
                        properties) {
                    if (ec)
                    {
                        messages::resourceNotFound(
                            asyncResp->res, "MessageRegistryFile", registry);
                        return;
                    }

                    // Extract properties from the response
                    std::string registryVersion;
                    std::vector<std::string> languageInfo;

                    for (const auto& [key, value] : properties)
                    {
                        if (key == "BiosAttributeRegistryVersion")
                        {
                            const std::string* strValue =
                                std::get_if<std::string>(&value);
                            if (strValue)
                            {
                                registryVersion = *strValue;
                            }
                        }
                        else if (key == "LanguageInfo")
                        {
                            const std::vector<std::string>* vecValue =
                                std::get_if<std::vector<std::string>>(&value);
                            if (vecValue)
                            {
                                languageInfo = *vecValue;
                            }
                        }
                    }

                    if (registryVersion.empty())
                    {
                        messages::resourceNotFound(
                            asyncResp->res, "MessageRegistryFile", registry);
                        return;
                    }

                    if (registry == registryVersion)
                    {
                        asyncResp->res.addHeader("Allow", "GET");
                        messages::operationNotAllowed(asyncResp->res);
                        return;
                    }

                    // Check for .json file variant
                    if (registry.ends_with(".json"))
                    {
                        if (languageInfo.empty())
                        {
                            BMCWEB_LOG_ERROR("languages not available");
                            messages::resourceNotFound(asyncResp->res,
                                                       "MessageRegistryFile",
                                                       registry);
                            return;
                        }

                        bool registryFound = false;

                        // Parse registryVersion:
                        // "BiosAttributeRegistry0ACQZ.0.72.0" Extract:
                        // registryId = "BiosAttributeRegistry0ACQZ", version =
                        // "0.72.0"

                        size_t dotPos = registryVersion.find('.');
                        std::string registryId =
                            registryVersion.substr(0, dotPos);
                        std::string version =
                            registryVersion.substr(dotPos + 1);

                        for (const auto& language : languageInfo)
                        {
                            std::string expectedFilename =
                                registryId + "." + language + "." + version +
                                ".json";
                            if (expectedFilename == registry)
                            {
                                registryFound = true;
                                break;
                            }
                        }

                        if (registryFound)
                        {
                            asyncResp->res.addHeader("Allow", "GET");
                            messages::operationNotAllowed(asyncResp->res);
                            return;
                        }
                        else
                        {
                            messages::resourceNotFound(asyncResp->res,
                                                       "MessageRegistryFile",
                                                       registry);
                            return;
                        }
                    }
                    else
                    {
                        messages::resourceNotFound(
                            asyncResp->res, "MessageRegistryFile", registry);
                        return;
                    }
                });
#else
            messages::resourceNotFound(asyncResp->res, "MessageRegistryFile",
                                       registry);
            return;
#endif
        });
}

} // namespace redfish
