#pragma once

#include "app.hpp"
#include "query.hpp"
#include "registries/privilege_registry.hpp"
#include "utils/sw_utils.hpp"

#include <boost/url/format.hpp>

namespace redfish
{

/*baseBIOSTable
map{attributeName,struct{attributeType,readonlyStatus,displayname,
              description,menuPath,current,default,
              array{struct{optionstring,optionvalue}}}}
*/

using BiosBaseTableType = boost::container::flat_map<
    std::string,
    std::tuple<
        std::string, bool, std::string, std::string, std::string,
        std::variant<int64_t, std::string>, std::variant<int64_t, std::string>,
        std::vector<std::tuple<std::string, std::variant<int64_t, std::string>,
                               std::string>>>>;

using BiosBaseTableItemType = std::pair<
    std::string,
    std::tuple<
        std::string, bool, std::string, std::string, std::string,
        std::variant<int64_t, std::string>, std::variant<int64_t, std::string>,
        std::vector<std::tuple<std::string, std::variant<int64_t, std::string>,
                               std::string>>>>;

using OptionsItemType =
    std::tuple<std::string, std::variant<int64_t, std::string>, std::string>;

using PendingAttributesType = boost::container::flat_map<
    std::string, std::tuple<std::string, std::variant<int64_t, std::string>>>;

using PendingAttributesItemType =
    std::pair<std::string,
              std::tuple<std::string, std::variant<int64_t, std::string>>>;

enum BiosBaseTableIndex
{
    biosBaseAttrType = 0,
    biosBaseReadonlyStatus,
    biosBaseDisplayName,
    biosBaseDescription,
    biosBaseMenuPath,
    biosBaseCurrValue,
    biosBaseDefaultValue,
    biosBaseOptions
};
enum OptionsItemIndex
{
    optItemType = 0,
    optItemValue,
    optItemText
};

enum PendingAttributesIndex
{
    pendingAttrType = 0,
    pendingAttrValue
};
static std::string mapAttrTypeToRedfish(const std::string_view typeDbus)
{
    std::string ret;
    if (typeDbus == "xyz.openbmc_project.BIOSConfig."
                    "Manager.AttributeType.String")
    {
        ret = "String";
    }
    else if (typeDbus == "xyz.openbmc_project.BIOSConfig."
                         "Manager.AttributeType.Integer")
    {
        ret = "Integer";
    }
    else if (typeDbus == "xyz.openbmc_project.BIOSConfig."
                         "Manager.AttributeType.Enumeration")
    {
        ret = "Enumeration";
    }
    else
    {
        ret = "UNKNOWN";
    }

    return ret;
}

static std::string mapBoundTypeToRedfish(const std::string_view typeDbus)
{
    std::string ret;
    if (typeDbus ==
        "xyz.openbmc_project.BIOSConfig.Manager.BoundType.ScalarIncrement")
    {
        ret = "ScalarIncrement";
    }
    else if (typeDbus ==
             "xyz.openbmc_project.BIOSConfig.Manager.BoundType.LowerBound")
    {
        ret = "LowerBound";
    }
    else if (typeDbus ==
             "xyz.openbmc_project.BIOSConfig.Manager.BoundType.UpperBound")
    {
        ret = "UpperBound";
    }
    else if (typeDbus ==
             "xyz.openbmc_project.BIOSConfig.Manager.BoundType.MinStringLength")
    {
        ret = "MinStringLength";
    }
    else if (typeDbus ==
             "xyz.openbmc_project.BIOSConfig.Manager.BoundType.MaxStringLength")
    {
        ret = "MaxStringLength";
    }
    else if (typeDbus ==
             "xyz.openbmc_project.BIOSConfig.Manager.BoundType.OneOf")
    {
        ret = "OneOf";
    }
    else
    {
        ret = "UNKNOWN";
    }

    return ret;
}

/**
 * BiosService class supports handle get method for bios.
 */
inline void
    handleBiosServiceGet(crow::App& app, const crow::Request& req,
                         const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                         const std::string& systemName)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if constexpr (BMCWEB_EXPERIMENTAL_REDFISH_MULTI_COMPUTER_SYSTEM)
    {
        // Option currently returns no systems.  TBD
        messages::resourceNotFound(asyncResp->res, "ComputerSystem",
                                   systemName);
        return;
    }
    if (systemName != BMCWEB_REDFISH_SYSTEM_URI_NAME)
    {
        messages::resourceNotFound(asyncResp->res, "ComputerSystem",
                                   systemName);
        return;
    }
    asyncResp->res.jsonValue["@odata.id"] = std::format(
        "/redfish/v1/Systems/{}/Bios", BMCWEB_REDFISH_SYSTEM_URI_NAME);
    asyncResp->res.jsonValue["@odata.type"] = "#Bios.v1_2_0.Bios";
    asyncResp->res.jsonValue["Name"] = "BIOS Configuration";
    asyncResp->res.jsonValue["Description"] = "BIOS Configuration Service";
    asyncResp->res.jsonValue["Id"] = "BIOS";
    asyncResp->res.jsonValue["Actions"]["#Bios.ResetBios"]["target"] =
        std::format("/redfish/v1/Systems/{}/Bios/Actions/Bios.ResetBios",
                    BMCWEB_REDFISH_SYSTEM_URI_NAME);

    asyncResp->res.jsonValue["Actions"]["#Bios.ChangePassword"] = {
        {"target", "/redfish/v1/Systems/system/Bios/Actions/"
                   "Bios.ChangePassword"}};

    asyncResp->res.jsonValue["Settings"]["@odata.id"] =
            "/redfish/v1/Systems/system/Bios/Settings";

    // Get the ActiveSoftwareImage and SoftwareImages
    sw_util::populateSoftwareInformation(asyncResp, sw_util::biosPurpose, "",
                                         true);

    asyncResp->res.jsonValue["@Redfish.Settings"] = {
        {"@odata.type", "#Settings.v1_3_0.Settings"},
        {"SettingsObject",
         {{"@odata.id", "/redfish/v1/Systems/system/Bios/Settings"}}}};
    asyncResp->res.jsonValue["AttributeRegistry"] = "BiosAttributeRegistry";
    asyncResp->res.jsonValue["Attributes"] = nlohmann::json::object();

    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code ec,
                    const dbus::utility::MapperGetObject& getObjectType) {
        if (ec)
        {
            BMCWEB_LOG_ERROR("ObjectMapper::GetObject call failed: {}", ec);
            messages::internalError(asyncResp->res);

            return;
        }

        if (getObjectType.empty())
        {
            BMCWEB_LOG_ERROR("getObjectType is empty.");
            messages::internalError(asyncResp->res);

            return;
        }

        const std::string& service = getObjectType.begin()->first;

        crow::connections::systemBus->async_method_call(
            [asyncResp](const boost::system::error_code ec2,
                        const std::variant<BiosBaseTableType>& retBiosTable) {
            if (ec2)
            {
                BMCWEB_LOG_ERROR("getBiosAttributes DBUS error: {}", ec2);
                messages::internalError(asyncResp->res);
                return;
            }
            const BiosBaseTableType* baseBiosTable =
                std::get_if<BiosBaseTableType>(&retBiosTable);
            nlohmann::json& attributesJson =
                asyncResp->res.jsonValue["Attributes"];
            if (baseBiosTable == nullptr)
            {
                BMCWEB_LOG_ERROR("baseBiosTable is empty");
                messages::internalError(asyncResp->res);
                return;
            }
            for (const BiosBaseTableItemType& item : *baseBiosTable)
            {
                const std::string& key = item.first;
                const std::string& itemType =
                    std::get<biosBaseAttrType>(item.second);
                std::string attrType = mapAttrTypeToRedfish(itemType);
                if (attrType == "String" || attrType == "Enumeration")
                {
                    const std::string* currValue = std::get_if<std::string>(
                        &std::get<biosBaseCurrValue>(item.second));
                    attributesJson.emplace(
                        key, currValue != nullptr ? *currValue : "");
                }
                else if (attrType == "Integer")
                {
                    const int64_t* currValue = std::get_if<int64_t>(
                        &std::get<biosBaseCurrValue>(item.second));
                    attributesJson.emplace(
                        key, currValue != nullptr ? *currValue : 0);
                }
                else
                {
                    BMCWEB_LOG_ERROR("Unsupported attribute type.");
                }
            }
        },
            service, "/xyz/openbmc_project/bios_config/manager",
            "org.freedesktop.DBus.Properties", "Get",
            "xyz.openbmc_project.BIOSConfig.Manager", "BaseBIOSTable");
    },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetObject",
        "/xyz/openbmc_project/bios_config/manager",
        std::array<const char*, 0>());
}

inline void requestRoutesBiosService(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/Bios/")
        .privileges(redfish::privileges::getBios)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleBiosServiceGet, std::ref(app)));
}

/**
 * BiosChangePassword class supports handle POST method for change bios
 * password. The class retrieves and sends data directly to D-Bus.
 */
inline void requestRoutesBiosChangePassword(App& app)
{
    BMCWEB_ROUTE(app,
                 "/redfish/v1/Systems/system/Bios/Actions/Bios.ChangePassword/")
        .privileges(redfish::privileges::postBios)
        .methods(boost::beast::http::verb::post)(
            [](const crow::Request& req,
               const std::shared_ptr<bmcweb::AsyncResp>& asyncResp) {
        std::string currentPassword, newPassword, userName;
        if (!json_util::readJsonPatch(
                req, asyncResp->res, "NewPassword", newPassword, "OldPassword",
                currentPassword, "PasswordName", userName))
        {
            return;
        }
        if (currentPassword.empty())
        {
            messages::actionParameterUnknown(asyncResp->res, "ChangePassword",
                                             "OldPassword");
            return;
        }
        if (newPassword.empty())
        {
            messages::actionParameterUnknown(asyncResp->res, "ChangePassword",
                                             "NewPassword");
            return;
        }
        if (userName.empty())
        {
            messages::actionParameterUnknown(asyncResp->res, "ChangePassword",
                                             "PasswordName");
            return;
        }

        // In Intel BIOS, we are not supporting user password in BIOS setup
        if (userName == "UserPassword")
        {
            messages::actionParameterUnknown(asyncResp->res, "ChangePassword",
                                             "PasswordName");
            return;
        }

        crow::connections::systemBus->async_method_call(
            [asyncResp](const boost::system::error_code ec) {
            if (ec)
            {
                BMCWEB_LOG_CRITICAL("Failed in doPost(BiosChangePassword) {}",
                                    ec);
                messages::internalError(asyncResp->res);
                return;
            }
        },
            "xyz.openbmc_project.BIOSConfigManager",
            "/xyz/openbmc_project/bios_config/password",
            "xyz.openbmc_project.BIOSConfig.Password", "ChangePassword",
            userName, currentPassword, newPassword);
    });
}

/**
 * BiosSettings class supports handle GET/PATCH method for
 * BIOS configuration pending settings.
 */
inline void requestRoutesBiosSettings(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Systems/system/Bios/Settings")
        .privileges(redfish::privileges::getBios)
        .methods(boost::beast::http::verb::get)(
            [](const crow::Request&,
               const std::shared_ptr<bmcweb::AsyncResp>& asyncResp) {
        asyncResp->res.jsonValue["@odata.id"] =
            "/redfish/v1/Systems/system/Bios/Settings";
        asyncResp->res.jsonValue["@odata.type"] = "#Bios.v1_1_0.Bios";
        asyncResp->res.jsonValue["Name"] = "Bios Settings Version 1";
        asyncResp->res.jsonValue["Id"] = "BiosSettingsV1";
        asyncResp->res.jsonValue["AttributeRegistry"] = "BiosAttributeRegistry";

        crow::connections::systemBus->async_method_call(
            [asyncResp](const boost::system::error_code ec,
                        const dbus::utility::MapperGetObject& getObjectType) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("ObjectMapper::GetObject call failed: {}", ec);
                messages::internalError(asyncResp->res);

                return;
            }

            if (getObjectType.empty())
            {
                BMCWEB_LOG_ERROR("getObjectType is empty.");
                messages::internalError(asyncResp->res);

                return;
            }

            std::string service = getObjectType.begin()->first;

            crow::connections::systemBus->async_method_call(
                [asyncResp](const boost::system::error_code ec2,
                            const std::variant<PendingAttributesType>&
                                retPendingAttributes) {
                if (ec2)
                {
                    BMCWEB_LOG_ERROR("getBiosSettings DBUS error: {}", ec2);
                    messages::resourceNotFound(
                        asyncResp->res, "Systems/system/Bios", "Settings");
                    return;
                }

                const PendingAttributesType* pendingAttributes =
                    std::get_if<PendingAttributesType>(&retPendingAttributes);
                nlohmann::json& attributesJson =
                    asyncResp->res.jsonValue["Attributes"];
                attributesJson = nlohmann::json::object();
                if (pendingAttributes == nullptr)
                {
                    BMCWEB_LOG_ERROR("pendingAttributes is empty");
                    messages::internalError(asyncResp->res);
                    return;
                }

                for (const PendingAttributesItemType& pendingAttributesItem :
                     *pendingAttributes)
                {
                    const std::string& biosAttrType =
                        std::get<pendingAttrType>(pendingAttributesItem.second);

                    std::string itemType = mapAttrTypeToRedfish(biosAttrType);

                    if (itemType == "String" || itemType == "Enumeration")
                    {
                        const std::string* currValue = std::get_if<std::string>(
                            &std::get<pendingAttrValue>(
                                pendingAttributesItem.second));

                        if (!currValue)
                        {
                            BMCWEB_LOG_ERROR(
                                "No string data in pending attributes item data");
                            messages::internalError(asyncResp->res);
                            return;
                        }
                        attributesJson.emplace(pendingAttributesItem.first,
                                               *currValue);
                    }
                    else if (itemType == "Integer")
                    {
                        const int64_t* currValue =
                            std::get_if<int64_t>(&std::get<pendingAttrValue>(
                                pendingAttributesItem.second));

                        if (!currValue)
                        {
                            BMCWEB_LOG_ERROR(
                                "No int64_t data in pending attributes item data");
                            messages::internalError(asyncResp->res);
                            return;
                        }

                        attributesJson.emplace(pendingAttributesItem.first,
                                               *currValue);
                    }
                    else
                    {
                        BMCWEB_LOG_ERROR("Unsupported attribute type.");
                        messages::internalError(asyncResp->res);
                        return;
                    }
                }
            },
                service, "/xyz/openbmc_project/bios_config/manager",
                "org.freedesktop.DBus.Properties", "Get",
                "xyz.openbmc_project.BIOSConfig.Manager", "PendingAttributes");
        },
            "xyz.openbmc_project.ObjectMapper",
            "/xyz/openbmc_project/object_mapper",
            "xyz.openbmc_project.ObjectMapper", "GetObject",
            "/xyz/openbmc_project/bios_config/manager",
            std::array<const char*, 0>());
    });

    BMCWEB_ROUTE(app, "/redfish/v1/Systems/system/Bios/Settings")
        .privileges(redfish::privileges::patchBios)
        .methods(boost::beast::http::verb::patch)(
            [](const crow::Request& req,
               const std::shared_ptr<bmcweb::AsyncResp>& asyncResp) {
        nlohmann::json inpJson;

        if (!redfish::json_util::readJsonPatch(req, asyncResp->res, "data",
                                               inpJson))
        {
            BMCWEB_LOG_ERROR("No 'data' in req!");
            return;
        }

        if (inpJson.empty())
        {
            messages::invalidObject(asyncResp->res,
                                    boost::urls::format("data"));
            BMCWEB_LOG_ERROR("No input in req!");
            return;
        }

        crow::connections::systemBus->async_method_call(
            [asyncResp,
             inpJson](const boost::system::error_code ec,
                      const dbus::utility::MapperGetObject& getObjectType) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("ObjectMapper::GetObject call failed: {}", ec);
                messages::internalError(asyncResp->res);

                return;
            }

            if (getObjectType.empty())
            {
                BMCWEB_LOG_ERROR("getObjectType is empty.");
                messages::internalError(asyncResp->res);

                return;
            }

            std::string service = getObjectType.begin()->first;

            crow::connections::systemBus->async_method_call(
                [asyncResp,
                 inpJson](const boost::system::error_code ec2,
                          const std::variant<BiosBaseTableType>& retBiosTable) {
                if (ec2)
                {
                    BMCWEB_LOG_ERROR("getBiosAttributes DBUS error: {}", ec2);
                    messages::internalError(asyncResp->res);
                    return;
                }

                const BiosBaseTableType* baseBiosTable =
                    std::get_if<BiosBaseTableType>(&retBiosTable);

                if (baseBiosTable == nullptr)
                {
                    BMCWEB_LOG_ERROR("baseBiosTable is empty.");
                    messages::internalError(asyncResp->res);
                    return;
                }

                PendingAttributesType pendingAttributes{};

                for (const nlohmann::detail::iteration_proxy_value<
                         nlohmann::detail::iter_impl<
                             const nlohmann::basic_json<>>>& attributes :
                     inpJson.items())
                {
                    BiosBaseTableType::const_iterator knobIter =
                        baseBiosTable->find(attributes.key());
                    if (knobIter == baseBiosTable->end())
                    {
                        BMCWEB_LOG_ERROR("Cannot find {} in baseBiosTable",
                                         attributes.key());
                        messages::propertyValueNotInList(
                            asyncResp->res, attributes.key(), "data");
                        return;
                    }

                    const std::string& itemType =
                        std::get<biosBaseAttrType>(knobIter->second);
                    std::string attrType = mapAttrTypeToRedfish(itemType);

                    if (attrType == "String" || attrType == "Enumeration")
                    {
                        std::string val = attributes.value();

                        pendingAttributes.emplace(
                            attributes.key(), std::make_tuple(itemType, val));
                    }
                    else if (attrType == "Integer")
                    {
                        pendingAttributes.emplace(
                            attributes.key(),
                            std::make_tuple(itemType, static_cast<int64_t>(
                                                          attributes.value())));
                    }
                    else
                    {
                        BMCWEB_LOG_ERROR("UNKNOWN attrType == {}", itemType);
                        messages::internalError(asyncResp->res);

                        return;
                    }
                }

                if (pendingAttributes.empty())
                {
                    BMCWEB_LOG_ERROR("pendingAttributes is empty.");
                    messages::invalidObject(asyncResp->res,
                                            boost::urls::format("data"));
                }

                crow::connections::systemBus->async_method_call(
                    [asyncResp](const boost::system::error_code ec3) {
                    if (ec3 == boost::system::errc::io_error)
                    {
                        BMCWEB_LOG_ERROR(
                            "Invalid input data passed while patching Bios/Setting");
                        messages::invalidObject(asyncResp->res,
                                                boost::urls::format("data"));
                        return;
                    }
                    if (ec3)
                    {
                        BMCWEB_LOG_ERROR("doPatch resp_handler got error {}",
                                         ec3);
                        messages::internalError(asyncResp->res);
                        return;
                    }

                    messages::success(asyncResp->res);
                },
                    "xyz.openbmc_project.BIOSConfigManager",
                    "/xyz/openbmc_project/bios_config/manager",
                    "org.freedesktop.DBus.Properties", "Set",
                    "xyz.openbmc_project.BIOSConfig.Manager",
                    "PendingAttributes",
                    std::variant<PendingAttributesType>(pendingAttributes));
            },
                service, "/xyz/openbmc_project/bios_config/manager",
                "org.freedesktop.DBus.Properties", "Get",
                "xyz.openbmc_project.BIOSConfig.Manager", "BaseBIOSTable");
        },
            "xyz.openbmc_project.ObjectMapper",
            "/xyz/openbmc_project/object_mapper",
            "xyz.openbmc_project.ObjectMapper", "GetObject",
            "/xyz/openbmc_project/bios_config/manager",
            std::array<const char*, 0>());
    });
}
/**
 * BiosAttributeRegistry class supports handle get method for BIOS attribute
 * registry.
 */
inline void requestRoutesBiosAttributeRegistry(App& app)
{
    BMCWEB_ROUTE(
        app,
        "/redfish/v1/Registries/BiosAttributeRegistry/BiosAttributeRegistry/")
        .privileges(redfish::privileges::getBios)
        .methods(boost::beast::http::verb::get)(
            [](const crow::Request&,
               const std::shared_ptr<bmcweb::AsyncResp>& asyncResp) {
        asyncResp->res.jsonValue["@odata.id"] =
            "/redfish/v1/Registries/BiosAttributeRegistry/"
            "BiosAttributeRegistry";
        asyncResp->res.jsonValue["@odata.type"] =
            "#AttributeRegistry.v1_3_2.AttributeRegistry";
        asyncResp->res.jsonValue["Name"] = "Bios Attribute Registry";
        asyncResp->res.jsonValue["Id"] = "BiosAttributeRegistry";
        asyncResp->res.jsonValue["RegistryVersion"] = "1.0.0";
        asyncResp->res.jsonValue["Language"] = "en";
        asyncResp->res.jsonValue["OwningEntity"] = "OpenBMC";
        asyncResp->res.jsonValue["RegistryEntries"]["Attributes"] =
            nlohmann::json::array();

        crow::connections::systemBus->async_method_call(
            [asyncResp](const boost::system::error_code ec,
                        const dbus::utility::MapperGetObject& getObjectType) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("ObjectMapper::GetObject call failed: {}", ec);
                messages::internalError(asyncResp->res);

                return;
            }

            if (getObjectType.empty())
            {
                BMCWEB_LOG_ERROR("getObjectType is empty.");
                messages::internalError(asyncResp->res);

                return;
            }

            std::string service = getObjectType.begin()->first;

            crow::connections::systemBus->async_method_call(
                [asyncResp](
                    const boost::system::error_code ec2,
                    const std::variant<BiosBaseTableType>& retBiosTable) {
                if (ec2)
                {
                    BMCWEB_LOG_ERROR("getBiosAttributeRegistry DBUS error: {}",
                                     ec2);
                    messages::resourceNotFound(asyncResp->res,
                                               "Registries/Bios", "Bios");
                    return;
                }
                const BiosBaseTableType* baseBiosTable =
                    std::get_if<BiosBaseTableType>(&retBiosTable);
                nlohmann::json& attributeArray =
                    asyncResp->res.jsonValue["RegistryEntries"]["Attributes"];
                if (baseBiosTable == nullptr)
                {
                    BMCWEB_LOG_ERROR("baseBiosTable == nullptr");
                    messages::internalError(asyncResp->res);
                    return;
                }
                for (const BiosBaseTableItemType& item : *baseBiosTable)
                {
                    const std::string& itemType =
                        std::get<biosBaseAttrType>(item.second);
                    std::string attrType = mapAttrTypeToRedfish(itemType);
                    if (attrType == "UNKNOWN")
                    {
                        BMCWEB_LOG_ERROR("UNKNOWN attrType == {}", itemType);
                        continue;
                    }
                    nlohmann::json attributeItem;
                    attributeItem["AttributeName"] = item.first;
                    attributeItem["Type"] = attrType;
                    attributeItem["ReadOnly"] =
                        std::get<biosBaseReadonlyStatus>(item.second);
                    attributeItem["DisplayName"] =
                        std::get<biosBaseDisplayName>(item.second);
                    attributeItem["HelpText"] =
                        std::get<biosBaseDescription>(item.second);
                    attributeItem["MenuPath"] =
                        std::get<biosBaseMenuPath>(item.second);

                    if (attrType == "String" || attrType == "Enumeration")
                    {
                        const std::string* currValue = std::get_if<std::string>(
                            &std::get<biosBaseCurrValue>(item.second));

                        if (!currValue)
                        {
                            BMCWEB_LOG_ERROR(
                                "Unable to get currValue, no std::string data in BIOS attributes item data");
                            continue;
                        }

                        const std::string* defValue = std::get_if<std::string>(
                            &std::get<biosBaseDefaultValue>(item.second));

                        if (!defValue)
                        {
                            BMCWEB_LOG_ERROR(
                                "Unable to get defValue, no std::string data in BIOS attributes item data");
                            continue;
                        }

                        attributeItem["CurrentValue"] =
                            currValue != nullptr ? *currValue : "";
                        attributeItem["DefaultValue"] =
                            defValue != nullptr ? *defValue : "";
                    }
                    else if (attrType == "Integer")
                    {
                        const int64_t* currValue = std::get_if<int64_t>(
                            &std::get<biosBaseCurrValue>(item.second));

                        if (!currValue)
                        {
                            BMCWEB_LOG_ERROR(
                                "Unable to get currValue, no int64_t data in BIOS attributes item data");
                            continue;
                        }

                        const int64_t* defValue = std::get_if<int64_t>(
                            &std::get<biosBaseDefaultValue>(item.second));

                        if (!defValue)
                        {
                            BMCWEB_LOG_ERROR(
                                "Unable to get defValue, no int64_t data in BIOS attributes item data");
                            continue;
                        }

                        attributeItem["CurrentValue"] =
                            currValue != nullptr ? *currValue : 0;
                        attributeItem["DefaultValue"] =
                            defValue != nullptr ? *defValue : 0;
                    }
                    else
                    {
                        BMCWEB_LOG_ERROR("UNKNOWN attrType == {}", itemType);
                        continue;
                    }

                    nlohmann::json optionsArray = nlohmann::json::array();
                    const std::vector<OptionsItemType>& optionsVector =
                        std::get<biosBaseOptions>(item.second);
                    for (const OptionsItemType& optItem : optionsVector)
                    {
                        nlohmann::json optItemJson;
                        const std::string& strOptItemType =
                            std::get<optItemType>(optItem);
                        std::string optItemTypeRedfish =
                            mapBoundTypeToRedfish(strOptItemType);
                        if (optItemTypeRedfish == "UNKNOWN")
                        {
                            BMCWEB_LOG_ERROR("UNKNOWN optItemTypeRedfish == {}",
                                             strOptItemType);
                            continue;
                        }
                        if (optItemTypeRedfish == "OneOf")
                        {
                            const std::string* currValue =
                                std::get_if<std::string>(
                                    &std::get<optItemValue>(optItem));

                            if (!currValue)
                            {
                                BMCWEB_LOG_ERROR(
                                    "Unable to get currValue, no std::string data in option item value");
                                continue;
                            }

                            optItemJson["ValueDisplayName"] =
                                std::get<optItemText>(optItem);
                            optItemJson["ValueName"] =
                                currValue != nullptr ? *currValue : "";
                        }
                        else
                        {
                            const int64_t* currValue = std::get_if<int64_t>(
                                &std::get<optItemValue>(optItem));

                            if (!currValue)
                            {
                                BMCWEB_LOG_ERROR(
                                    "Unable to get currValue, no int64_t data in option item value");
                                continue;
                            }

                            optItemJson["ValueDisplayName"] =
                                currValue != nullptr ? *currValue : 0;
                            optItemJson["ValueName"] =
                                currValue != nullptr ? *currValue : 0;
                        }

                        optionsArray.push_back(optItemJson);

                        if (optionsArray.empty())
                        {
                            BMCWEB_LOG_ERROR("optionsArray is empty");
                            continue;
                        }
                    }

                    attributeItem["Value"] = optionsArray;
                    attributeArray.push_back(attributeItem);
                }
            },
                service, "/xyz/openbmc_project/bios_config/manager",
                "org.freedesktop.DBus.Properties", "Get",
                "xyz.openbmc_project.BIOSConfig.Manager", "BaseBIOSTable");
        },
            "xyz.openbmc_project.ObjectMapper",
            "/xyz/openbmc_project/object_mapper",
            "xyz.openbmc_project.ObjectMapper", "GetObject",
            "/xyz/openbmc_project/bios_config/manager",
            std::array<const char*, 0>());
    });
}

/**
 * BiosReset class supports handle POST method for Reset bios.
 * The class retrieves and sends data directly to D-Bus.
 *
 * Function handles POST method request.
 * Analyzes POST body message before sends Reset request data to D-Bus.
 */
inline void
    handleBiosResetPost(crow::App& app, const crow::Request& req,
                        const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                        const std::string& systemName)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    if constexpr (BMCWEB_EXPERIMENTAL_REDFISH_MULTI_COMPUTER_SYSTEM)
    {
        // Option currently returns no systems.  TBD
        messages::resourceNotFound(asyncResp->res, "ComputerSystem",
                                   systemName);
        return;
    }

    if (systemName != BMCWEB_REDFISH_SYSTEM_URI_NAME)
    {
        messages::resourceNotFound(asyncResp->res, "ComputerSystem",
                                   systemName);
        return;
    }

    std::string resetFlag =
        "xyz.openbmc_project.BIOSConfig.Manager.ResetFlag.FactoryDefaults";

    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code& ec) {
        if (ec)
        {
            BMCWEB_LOG_ERROR("doPost bios reset got error: {}", ec);
            messages::internalError(asyncResp->res);
            return;
        }
    },
        "xyz.openbmc_project.BIOSConfigManager",
        "/xyz/openbmc_project/bios_config/manager",
        "org.freedesktop.DBus.Properties", "Set",
        "xyz.openbmc_project.BIOSConfig.Manager", "ResetBIOSSettings",
        std::variant<std::string>(resetFlag));
}

inline void requestRoutesBiosReset(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/Bios/Actions/Bios.ResetBios/")
        .privileges(redfish::privileges::postBios)
        .methods(boost::beast::http::verb::post)(
            std::bind_front(handleBiosResetPost, std::ref(app)));
}

} // namespace redfish
