// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#pragma once

#include "app.hpp"
#include "query.hpp"
#include "registries/privilege_registry.hpp"
#include "utils/sw_utils.hpp"

// Validate multi-host vs single-host system name
#include "system_utils.hpp"

#include <boost/url/format.hpp>

namespace redfish
{

namespace bios
{
/**
 * BiosConfig Manager Dbus info
 */
constexpr const char* biosConfigObj =
    "/xyz/openbmc_project/bios_config/manager";
constexpr const char* biosConfigIface =
    "xyz.openbmc_project.BIOSConfig.Manager";

using GetObjectType =
    std::vector<std::pair<std::string, std::vector<std::string>>>;
/**
 * BiosService DBus types
 */
using BaseBIOSTable = boost::container::flat_map<
    std::string,
    std::tuple<
        std::string, bool, std::string, std::string, std::string,
        std::variant<int64_t, std::string, bool>,
        std::variant<int64_t, std::string, bool>,
        std::vector<std::tuple<std::string, std::variant<int64_t, std::string>,
                               std::string>>>>;

using BaseBIOSTableItem = std::pair<
    std::string,
    std::tuple<
        std::string, bool, std::string, std::string, std::string,
        std::variant<int64_t, std::string, bool>,
        std::variant<int64_t, std::string, bool>,
        std::vector<std::tuple<std::string, std::variant<int64_t, std::string>,
                               std::string>>>>;

using PendingAttrType = boost::container::flat_map<
    std::string,
    std::tuple<std::string, std::variant<int64_t, std::string, bool>>>;

using PendingAttrItemType = std::pair<
    std::string,
    std::tuple<std::string, std::variant<int64_t, std::string, bool>>>;

using AttrBoundType =
    std::tuple<std::string, std::variant<int64_t, std::string>, std::string>;

enum BaseBiosTableIndex
{
    baseBiosAttrType = 0,
    baseBiosReadonlyStatus,
    baseBiosDisplayName,
    baseBiosDescription,
    baseBiosMenuPath,
    baseBiosCurrValue,
    baseBiosDefaultValue,
    baseBiosBoundValues
};

enum BaseBiosBoundIndex
{
    baseBiosBoundType = 0,
    baseBiosBoundValue
};

enum BiosPendingAttributesIndex
{
    biosPendingAttrType = 0,
    biosPendingAttrValue
};

/**
 *@brief Translates Base BIOS Table attribute type from DBUS property value to
 *Redfish string type.
 *
 *@param[in] attrType The DBUS BIOS attribute type value
 *
 *@return Returns as a string, the attribute type required for Redfish.
 *If attribute type didn't match, then returns 'UNKNOWN' string.
 */
static std::string getBiosAttrType(const std::string& attrType)
{
    std::string type;
    if (attrType ==
        "xyz.openbmc_project.BIOSConfig.Manager.AttributeType.Enumeration")
    {
        type = "Enumeration";
    }
    else if (attrType ==
             "xyz.openbmc_project.BIOSConfig.Manager.AttributeType.String")
    {
        type = "String";
    }
    else if (attrType ==
             "xyz.openbmc_project.BIOSConfig.Manager.AttributeType.Password")
    {
        type = "Password";
    }
    else if (attrType ==
             "xyz.openbmc_project.BIOSConfig.Manager.AttributeType.Integer")
    {
        type = "Integer";
    }
    else if (attrType ==
             "xyz.openbmc_project.BIOSConfig.Manager.AttributeType.Boolean")
    {
        type = "Boolean";
    }
    else
    {
        type = "UNKNOWN";
    }

    return type;
}

/**
 *@brief Translates Base BIOS Table attribute bound value type from DBUS
 *property value to Redfish string type.
 *
 *@param[in] attrType The DBUS BIOS Bound value attribute type value
 *
 *@return Returns as a string, the attribute bound value type required for
 *Redfish. If attribute type didn't match, then returns 'UNKNOWN' string.
 */
static std::string getBiosBoundValType(const std::string& boundValType)
{
    std::string type;
    if (boundValType ==
        "xyz.openbmc_project.BIOSConfig.Manager.BoundType.ScalarIncrement")
    {
        type = "ScalarIncrement";
    }
    else if (boundValType ==
             "xyz.openbmc_project.BIOSConfig.Manager.BoundType.LowerBound")
    {
        type = "LowerBound";
    }
    else if (boundValType ==
             "xyz.openbmc_project.BIOSConfig.Manager.BoundType.UpperBound")
    {
        type = "UpperBound";
    }
    else if (boundValType ==
             "xyz.openbmc_project.BIOSConfig.Manager.BoundType.OneOf")
    {
        type = "OneOf";
    }
    else
    {
        type = "UNKNOWN";
    }

    return type;
}

/**
 *@brief Translates Reset BIOS to Default Settings status type from DBUS
 *property value to Redfish string type.
 *
 *@param[in] biosMode The DBUS BIOS Reset BIOS to Default Setting status value
 *
 *@return Returns as a string, the Reset BIOS Settings to default type required
 *for Redfish. If attribute type didn't match, then returns 'UNKNOWN' string.
 */
static std::string getBiosDefaultSettingsMode(const std::string& biosMode)
{
    std::string mode;
    if (biosMode == "xyz.openbmc_project.BIOSConfig.Manager.ResetFlag.NoAction")
    {
        mode = "NoAction";
    }
    else if (biosMode ==
             "xyz.openbmc_project.BIOSConfig.Manager.ResetFlag.FactoryDefaults")
    {
        mode = "FactoryDefaults";
    }
    else if (biosMode == "xyz.openbmc_project.BIOSConfig.Manager.ResetFlag."
                         "FailSafeDefaults")
    {
        mode = "FailSafeDefaults";
    }
    else
    {
        mode = "UNKNOWN";
    }
    return mode;
}

/**
 *@brief Reads the Reset BIOS Settings to default property.
 *
 * @param[in,out]   asyncResp   Async HTTP response.
 *
 * @return None.
 */
static void getResetBiosSettings(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    BMCWEB_LOG_DEBUG("Get Reset Bios Settings to Defaults Pending Status");
    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code ec,

                    const GetObjectType& objType) {
            if (ec || objType.empty())
            {
                BMCWEB_LOG_ERROR("GetObject for path biosConfigObj");
                messages::internalError(asyncResp->res);
                return;
            }

            const std::string& biosService = objType.begin()->first;
            crow::connections::systemBus->async_method_call(
                [asyncResp](
                    const boost::system::error_code ec1,
                    const std::variant<std::string>& resetBiosSettingsMode) {
                    if (ec1)
                    {
                        BMCWEB_LOG_DEBUG(
                            "DBUS response error for "
                            "Get Reset BIOS setting to default status.");
                        messages::internalError(asyncResp->res);
                        return;
                    }
                    const std::string* value =
                        std::get_if<std::string>(&resetBiosSettingsMode);
                    if (value == nullptr)
                    {
                        BMCWEB_LOG_DEBUG(
                            "Null value returned for Reset BIOS Settings status");
                        messages::internalError(asyncResp->res);
                        return;
                    }

                    std::string biosMode = getBiosDefaultSettingsMode(*value);

                    if (biosMode == "NoAction")
                    {
                        asyncResp->res.jsonValue["ResetBiosToDefaultsPending"] =
                            false;
                    }
                    else if ((biosMode == "FactoryDefaults") ||
                             (biosMode == "FailSafeDefaults"))
                    {
                        asyncResp->res.jsonValue["ResetBiosToDefaultsPending"] =
                            true;
                    }
                    else
                    {
                        BMCWEB_LOG_DEBUG("Invalid Reset BIOS Settings Status");
                        messages::internalError(asyncResp->res);
                        return;
                    }
                },
                biosService, biosConfigObj, "org.freedesktop.DBus.Properties",
                "Get", biosConfigIface, "ResetBIOSSettings");
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetObject", biosConfigObj,
        std::array<const char*, 1>{biosConfigIface});
}

/**
 *@brief Reads the BIOS Base Table DBUS property and update the Bios Attributes
 *response.
 *
 * @param[in,out]   asyncResp   Async HTTP response.
 *
 * @return None.
 */
static void getBiosAttributes(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code ec,
                    const GetObjectType& objType) {
            if (ec || objType.empty())
            {
                BMCWEB_LOG_ERROR("GetObject for path biosConfigObj");
                messages::internalError(asyncResp->res);
                return;
            }

            const std::string& biosService = objType.begin()->first;

            crow::connections::systemBus->async_method_call(
                [asyncResp](
                    const boost::system::error_code ec1,
                    const std::variant<BaseBIOSTable>& baseBiosTableResp) {
                    if (ec1)
                    {
                        BMCWEB_LOG_ERROR(
                            "Get BaseBIOSTable DBus response error");
                        messages::internalError(asyncResp->res);
                        return;
                    }
                    const BaseBIOSTable* baseBiosTable =
                        std::get_if<BaseBIOSTable>(&baseBiosTableResp);

                    nlohmann::json& attributesJson =
                        asyncResp->res.jsonValue["Attributes"];
                    if (baseBiosTable == nullptr)
                    {
                        BMCWEB_LOG_ERROR("Empty BaseBIOSTable");
                        messages::internalError(asyncResp->res);
                        return;
                    }
                    for (const BaseBIOSTableItem& attrIt : *baseBiosTable)
                    {
                        const std::string& attr = attrIt.first;

                        // read the attribute type at 0th field and convert from
                        // dbus to string format
                        std::string attrType = getBiosAttrType(std::string(
                            std::get<BaseBiosTableIndex::baseBiosAttrType>(
                                attrIt.second)));
                        if ((attrType == "String") ||
                            (attrType == "Enumeration"))
                        {
                            // read the current value of attribute at 5th field
                            const std::string* attrCurrValue =
                                std::get_if<std::string>(
                                    &std::get<
                                        BaseBiosTableIndex::baseBiosCurrValue>(
                                        attrIt.second));
                            if (attrCurrValue != nullptr)
                            {
                                attributesJson.emplace(attr, *attrCurrValue);
                            }
                            else
                            {
                                attributesJson.emplace(attr, std::string(""));
                            }
                        }
                        else if ((attrType == "Integer") ||
                                 (attrType == "Boolean"))
                        {
                            // read the current value of attribute at 5th field
                            const int64_t* attrCurrValue = std::get_if<int64_t>(
                                &std::get<
                                    BaseBiosTableIndex::baseBiosCurrValue>(
                                    attrIt.second));
                            if (attrCurrValue != nullptr)
                            {
                                if (attrType == "Boolean")
                                {
                                    if (*attrCurrValue)
                                    {
                                        attributesJson.emplace(attr, true);
                                    }
                                    else
                                    {
                                        attributesJson.emplace(attr, false);
                                    }
                                }
                                else
                                {
                                    attributesJson.emplace(attr,
                                                           *attrCurrValue);
                                }
                            }
                            else
                            {
                                if (attrType == "Boolean")
                                {
                                    attributesJson.emplace(attr, false);
                                }
                                else
                                {
                                    attributesJson.emplace(attr, 0);
                                }
                            }
                        }
                        else
                        {
                            BMCWEB_LOG_ERROR("Attribute type not supported");
                        }
                    }
                },
                biosService, biosConfigObj, "org.freedesktop.DBus.Properties",
                "Get", biosConfigIface, "BaseBIOSTable");
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetObject", biosConfigObj,
        std::array<const char*, 1>{biosConfigIface});
}

/**
 *@brief Reads the BIOS Pending Attributes, which are updated by oob the user
 * and update the Bios Settings Attributes response.
 *
 * @param[in,out]   asyncResp   Async HTTP response.
 *
 * @return None.
 */
static void getBiosSettingsAttr(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp](const boost::system::error_code ec,
                    const GetObjectType& objType) {
            if (ec || objType.empty())
            {
                BMCWEB_LOG_ERROR("GetObject for path biosConfigObj");
                messages::internalError(asyncResp->res);
                return;
            }
            const std::string& biosService = objType.begin()->first;
            crow::connections::systemBus->async_method_call(
                [asyncResp](
                    const boost::system::error_code ec1,
                    const std::variant<PendingAttrType>& pendingAttrsResp) {
                    if (ec1)
                    {
                        BMCWEB_LOG_ERROR(
                            "Get PendingAttributes DBus response error");
                        messages::internalError(asyncResp->res);
                        return;
                    }

                    const PendingAttrType* pendingAttrs =
                        std::get_if<PendingAttrType>(&pendingAttrsResp);

                    nlohmann::json& attributesJson =
                        asyncResp->res.jsonValue["Attributes"];
                    if (pendingAttrs == nullptr)
                    {
                        BMCWEB_LOG_ERROR("Empty Pending Attributes");
                        messages::internalError(asyncResp->res);
                        return;
                    }

                    for (const PendingAttrItemType& attrIt : *pendingAttrs)
                    {
                        const std::string& attr = attrIt.first;

                        // read the attribute type at 0th field and convert from
                        // dbus to string format
                        std::string attrType = getBiosAttrType(std::string(
                            std::get<BiosPendingAttributesIndex::
                                         biosPendingAttrType>(attrIt.second)));
                        if ((attrType == "String") ||
                            (attrType == "Enumeration"))
                        {
                            // read the current value of attribute at 1st field
                            const std::string* attrCurrValue =
                                std::get_if<std::string>(
                                    &std::get<BiosPendingAttributesIndex::
                                                  biosPendingAttrValue>(
                                        attrIt.second));
                            if (attrCurrValue != nullptr)
                            {
                                attributesJson.emplace(attr, *attrCurrValue);
                            }
                            else
                            {
                                attributesJson.emplace(attr, std::string(""));
                            }
                        }
                        else if ((attrType == "Integer") ||
                                 (attrType == "Boolean"))
                        {
                            // read the current value of attribute at 1st field
                            const int64_t* attrCurrValue = std::get_if<int64_t>(
                                &std::get<BiosPendingAttributesIndex::
                                              biosPendingAttrValue>(
                                    attrIt.second));
                            if (attrCurrValue != nullptr)
                            {
                                if (attrType == "Boolean")
                                {
                                    if (*attrCurrValue)
                                    {
                                        attributesJson.emplace(attr, true);
                                    }
                                    else
                                    {
                                        attributesJson.emplace(attr, false);
                                    }
                                }
                                else
                                {
                                    attributesJson.emplace(attr,
                                                           *attrCurrValue);
                                }
                            }
                            else
                            {
                                if (attrType == "Boolean")
                                {
                                    attributesJson.emplace(attr, false);
                                }
                                else
                                {
                                    attributesJson.emplace(attr, 0);
                                }
                            }
                        }
                        else
                        {
                            BMCWEB_LOG_ERROR("Attribute type not supported");
                        }
                    }
                },
                biosService, biosConfigObj, "org.freedesktop.DBus.Properties",
                "Get", biosConfigIface, "PendingAttributes");
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetObject", biosConfigObj,
        std::array<const char*, 1>{biosConfigIface});
}

/**
 *@brief Updates the BIOS Pending Attributes DBUS property, which are requested
 *by the oob user.
 *
 * @param[in,out]   asyncResp   Async HTTP response.
 *
 * @return None.
 */
static void setBiosPendingAttr(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const nlohmann::json& pendingAttrJson)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp, pendingAttrJson](const boost::system::error_code ec,
                                     const GetObjectType& objType) {
            if (ec || objType.empty())
            {
                BMCWEB_LOG_ERROR("GetObject for path biosConfigObj");
                messages::internalError(asyncResp->res);
                return;
            }
            const std::string& biosService = objType.begin()->first;
            crow::connections::systemBus->async_method_call(
                [asyncResp, pendingAttrJson, biosService](
                    const boost::system::error_code ec1,
                    const std::variant<BaseBIOSTable>& baseBiosTableResp) {
                    if (ec1)
                    {
                        BMCWEB_LOG_ERROR(
                            "Get BaseBIOSTable DBus response error");
                        messages::internalError(asyncResp->res);
                        return;
                    }

                    const BaseBIOSTable* baseBiosTable =
                        std::get_if<BaseBIOSTable>(&baseBiosTableResp);

                    if (baseBiosTable == nullptr)
                    {
                        BMCWEB_LOG_ERROR("Empty BaseBIOSTable");
                        messages::internalError(asyncResp->res);
                        return;
                    }

                    PendingAttrType pendingAttrs{};
                    for (const auto& pendingAttrIt : pendingAttrJson.items())
                    {
                        // Check whether the requested attribute is available
                        // inside BaseBIOSTable or not
                        auto attrIt = baseBiosTable->find(pendingAttrIt.key());
                        if (attrIt == baseBiosTable->end())
                        {
                            BMCWEB_LOG_ERROR("Not Found Attribute ");
                            messages::propertyValueNotInList(
                                asyncResp->res, pendingAttrIt.key(),
                                "Attributes");
                            return;
                        }

                        // read the attribute type at 0th field and convert from
                        // dbus to string format
                        std::string attrItType =
                            std::get<BaseBiosTableIndex::baseBiosAttrType>(
                                attrIt->second);
                        std::string attrType = getBiosAttrType(attrItType);
                        if ((attrType == "String") ||
                            (attrType == "Enumeration"))
                        {
                            std::string attrReqVal = pendingAttrIt.value();
                            // read the bound values for the attribute
                            const std::vector<AttrBoundType> boundValues =
                                std::get<
                                    BaseBiosTableIndex::baseBiosBoundValues>(
                                    attrIt->second);
                            auto found = std::find_if(
                                boundValues.begin(), boundValues.end(),
                                [attrReqVal](
                                    const AttrBoundType& boundValueIt) {
                                    // read the bound value type at 0th field
                                    // and convert from dbus to string format
                                    std::string boundValType =
                                        getBiosBoundValType(std::string(
                                            std::get<BaseBiosBoundIndex::
                                                         baseBiosBoundType>(
                                                boundValueIt)));

                                    if (boundValType == "OneOf")
                                    {
                                        // read the bound value  at 1st field
                                        // for each entry
                                        const std::string* currBoundVal =
                                            std::get_if<std::string>(
                                                &std::get<
                                                    BaseBiosBoundIndex::
                                                        baseBiosBoundValue>(
                                                    boundValueIt));
                                        if (currBoundVal == nullptr)
                                        {
                                            BMCWEB_LOG_ERROR(
                                                "Bound Value not found");
                                            return false;
                                        }

                                        return (attrReqVal == *currBoundVal)
                                                   ? true
                                                   : false;
                                    }
                                    else
                                    {
                                        return false;
                                    }
                                });

                            if (found == boundValues.end())
                            {
                                BMCWEB_LOG_ERROR(
                                    "Requested Attribute Value invalid");
                                messages::internalError(asyncResp->res);
                                return;
                            }
                            pendingAttrs.insert(std::make_pair(
                                pendingAttrIt.key(),
                                std::make_tuple(attrItType, attrReqVal)));
                        }
                        else if (attrType == "Boolean")
                        {
                            int64_t attrReqVal = static_cast<int64_t>(
                                pendingAttrIt.value().get<bool>());
                            // read the bound values for the attribute
                            const std::vector<AttrBoundType> boundValues =
                                std::get<
                                    BaseBiosTableIndex::baseBiosBoundValues>(
                                    attrIt->second);

                            auto found = std::find_if(
                                boundValues.begin(), boundValues.end(),
                                [attrReqVal](
                                    const AttrBoundType& boundValueIt) {
                                    // read the bound value type at 0th field
                                    // and convert from dbus to string format
                                    std::string boundValType =
                                        getBiosBoundValType(std::string(
                                            std::get<BaseBiosBoundIndex::
                                                         baseBiosBoundType>(
                                                boundValueIt)));
                                    if (boundValType == "OneOf")
                                    {
                                        // read the bound value  at 1st field
                                        // for each entry
                                        const int64_t* currBoundVal =
                                            std::get_if<int64_t>(
                                                &std::get<
                                                    BaseBiosBoundIndex::
                                                        baseBiosBoundValue>(
                                                    boundValueIt));
                                        if (currBoundVal == nullptr)
                                        {
                                            BMCWEB_LOG_ERROR(
                                                "Bound Value not found");
                                            return false;
                                        }
                                        return (attrReqVal == *currBoundVal)
                                                   ? true
                                                   : false;
                                    }
                                    else
                                    {
                                        return false;
                                    }
                                });

                            if (found == boundValues.end())
                            {
                                BMCWEB_LOG_ERROR(
                                    "Requested Attribute Value invalid");
                                messages::internalError(asyncResp->res);
                                return;
                            }
                            pendingAttrs.insert(std::make_pair(
                                pendingAttrIt.key(),
                                std::make_tuple(attrItType, attrReqVal)));
                        }
                        else if (attrType == "Integer")
                        {
                            int64_t attrReqVal = pendingAttrIt.value();
                            pendingAttrs.emplace(
                                pendingAttrIt.key(),
                                std::make_tuple(attrItType, attrReqVal));
                        }
                        else
                        {
                            BMCWEB_LOG_ERROR("Unknown Attribute Type");
                            messages::internalError(asyncResp->res);
                            return;
                        }
                    }

                    if (pendingAttrs.empty())
                    {
                        BMCWEB_LOG_ERROR("PendingAttributes empty");
                        messages::invalidObject(
                            asyncResp->res, boost::urls::format("Attributes"));
                    }

                    crow::connections::systemBus->async_method_call(
                        [asyncResp](const boost::system::error_code ec2) {
                            if (ec2)
                            {
                                BMCWEB_LOG_ERROR(
                                    "Set PendingAttributes failed ");
                                messages::internalError(asyncResp->res);
                                return;
                            }

                            messages::success(asyncResp->res);
                        },
                        biosService, biosConfigObj,
                        "org.freedesktop.DBus.Properties", "Set",
                        biosConfigIface, "PendingAttributes",
                        std::variant<PendingAttrType>(pendingAttrs));
                },
                biosService, biosConfigObj, "org.freedesktop.DBus.Properties",
                "Get", biosConfigIface, "BaseBIOSTable");
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetObject", biosConfigObj,
        std::array<const char*, 1>{biosConfigIface});
}
/**
 *@brief Reads the BIOS Base Table DBUS property and update the Bios Attribute
 *Registry response.
 *
 * @param[in,out]   asyncResp   Async HTTP response.
 *
 * @return None.
 */

} // namespace bios

/**
 * BiosService class supports handle get method for bios.
 */
inline void handleBiosServiceGet(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& systemName)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    asyncResp->res.jsonValue["@odata.id"] =
        boost::urls::format("/redfish/v1/Systems/{}/Bios", systemName);
    asyncResp->res.jsonValue["@odata.type"] = json_util::odataType("Bios");
    asyncResp->res.jsonValue["Name"] = "BIOS Configuration";
    asyncResp->res.jsonValue["Description"] = "BIOS Configuration Service";
    asyncResp->res.jsonValue["Id"] = "BIOS";
    asyncResp->res.jsonValue["Actions"]["#Bios.ResetBios"] = {
        {"target", boost::urls::format(
                       "/redfish/v1/Systems/{}/Bios/Actions/Bios.ResetBios",
                       systemName)}};
    asyncResp->res.jsonValue["Actions"]["#Bios.ChangePassword"] = {
        {"target",
         boost::urls::format(
             "/redfish/v1/Systems/{}/Bios/Actions/Bios.ChangePassword",
             systemName)}};
    asyncResp->res.jsonValue["@Redfish.Settings"]["@odata.type"] =
        json_util::odataType("Settings");
    asyncResp->res.jsonValue["@Redfish.Settings"]["SettingsObject"] = {
        {"@odata.id", boost::urls::format(
                          "/redfish/v1/Systems/{}/Bios/Settings", systemName)}};
    // Get the ActiveSoftwareImage and SoftwareImages
    sw_util::populateSoftwareInformation(asyncResp, sw_util::biosPurpose, "",
                                         true);
    asyncResp->res.jsonValue["Attributes"] = nlohmann::json({});
    // Get the BIOS Attributes
    bios::getBiosAttributes(asyncResp);
    // Get the ResetBiosToDefaultsPending
    bios::getResetBiosSettings(asyncResp);
}
inline void requestRoutesBiosService(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/Bios/")
        .privileges(redfish::privileges::getBios)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleBiosServiceGet, std::ref(app)));
}
/**
 * BiosSetting class supports handle patch method for Bios Settings.
 */
inline void handleBiosSettingsPatch(
    const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& systemName [[maybe_unused]])
{
    nlohmann::json pendingAttrJson;
    if (!redfish::json_util::readJsonPatch( //
            req, asyncResp->res,            //
            "Attributes", pendingAttrJson   //
            ))
    {
        BMCWEB_LOG_ERROR("No 'Attributes' found");
        return;
    }
    if (pendingAttrJson.empty())
    {
        messages::invalidObject(asyncResp->res,
                                boost::urls::format("Attributes"));
        BMCWEB_LOG_ERROR("No input in req!");
        return;
    }
    // Update the Pending Atttributes
    bios::setBiosPendingAttr(asyncResp, pendingAttrJson);
}
/**
 * BiosSetting class supports handle get method for Bios Settings.
 */
inline void handleBiosSettingsGet(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& systemName)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    asyncResp->res.jsonValue["@odata.id"] =
        boost::urls::format("/redfish/v1/Systems/{}/Bios/Settings", systemName);
    asyncResp->res.jsonValue["@odata.type"] = json_util::odataType("Bios");
    asyncResp->res.jsonValue["Name"] = "BIOS Configuration";
    asyncResp->res.jsonValue["Description"] = "BIOS Settings";
    asyncResp->res.jsonValue["Id"] = "BIOS_Settings";
    asyncResp->res.jsonValue["Attributes"] = nlohmann::json({});
    // get the BIOS Attributes
    bios::getBiosSettingsAttr(asyncResp);
}
inline void requestRoutesBiosSettings(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/Bios/Settings/")
        .privileges(redfish::privileges::getBios)
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleBiosSettingsGet, std::ref(app)));

    BMCWEB_ROUTE(app, "/redfish/v1/Systems/<str>/Bios/Settings/")
        .privileges(redfish::privileges::patchBios)
        .methods(boost::beast::http::verb::patch)(handleBiosSettingsPatch);
}
/**
 * BiosChangePassword class supports handle POST method for change bios
 * password. The class retrieves and sends data directly to D-Bus.
 */
inline void requestRoutesBiosChangePassword(App& app)
{
    BMCWEB_ROUTE(app,
                 "/redfish/v1/Systems/<str>/Bios/Actions/Bios.ChangePassword/")
        .privileges(redfish::privileges::postBios)
        .methods(boost::beast::http::verb::post)(
            [](const crow::Request& req,
               const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
               const std::string& systemName) {
                if (!system_utils::validateSystemName(asyncResp, systemName))
                {
                    return;
                }
                std::string currentPassword, newPassword, userName;
                if (!json_util::readJsonPatch(          //
                        req, asyncResp->res,            //
                        "NewPassword", newPassword,     //
                        "OldPassword", currentPassword, //
                        "PasswordName", userName        //
                        ))
                {
                    return;
                }
                if (currentPassword.empty())
                {
                    messages::actionParameterUnknown(
                        asyncResp->res, "ChangePassword", "OldPassword");
                    return;
                }
                if (newPassword.empty())
                {
                    messages::actionParameterUnknown(
                        asyncResp->res, "ChangePassword", "NewPassword");
                    return;
                }
                if (userName.empty())
                {
                    messages::actionParameterUnknown(
                        asyncResp->res, "ChangePassword", "PasswordName");
                    return;
                }
                // In Intel BIOS, we are not supporting user password in BIOS
                // setup
                if (userName == "UserPassword")
                {
                    messages::actionParameterUnknown(
                        asyncResp->res, "ChangePassword", "PasswordName");
                    return;
                }
                crow::connections::systemBus->async_method_call(
                    [asyncResp](const boost::system::error_code ec) {
                        if (ec)
                        {
                            BMCWEB_LOG_CRITICAL(
                                "Failed in doPost(BiosChangePassword) {}", ec);
                            messages::internalError(asyncResp->res);
                            return;
                        }
                    },
                    "xyz.openbmc_project.BIOSConfigPassword",
                    "/xyz/openbmc_project/bios_config/password",
                    "xyz.openbmc_project.BIOSConfig.Password", "ChangePassword",
                    userName, currentPassword, newPassword);
            });
}

/**
 * BiosReset class supports handle POST method for Reset bios.
 * The class retrieves and sends data directly to D-Bus.
 *
 * Function handles POST method request.
 * Analyzes POST body message before sends Reset request data to D-Bus.
 */
inline void handleBiosResetPost(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& systemName)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    if (!system_utils::validateSystemName(asyncResp, systemName))
    {
        return;
    }

    if (!req.body().empty() && req.body() != "{}")
    {
        nlohmann::json jsonBody = nlohmann::json::parse(req.body());
        std::string key = jsonBody.begin().key();
        auto actionUrl = boost::urls::format(
            "/redfish/v1/Systems/{}/Bios/Actions/Bios.ResetBios/", systemName);
        std::string actionTarget(actionUrl.buffer());
        messages::actionParameterUnknown(asyncResp->res, actionTarget, key);
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
/**
 * BiosAttributeRegistry class supports handle get method for Bios Attribute
 * Registry.
 */

} // namespace redfish
