#pragma once

#include "app.hpp"
#include "query.hpp"
#include "registries/privilege_registry.hpp"
#include "utils/sw_utils.hpp"

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
 *@brief Translates Base BIOS Table attribute type from Redfish string type to
 *DBUS property value.
 *
 *@param[in] attrType The Redfish BIOS attribute string type value
 *
 *@return Returns as a string, the attribute type required for DBUS.
 *If attribute type didn't match, then returns 'UNKNOWN' string.
 */
static std::string getDbusBiosAttrType(const std::string& attrType)
{
    std::string type;
    if (attrType == "Enumeration")
    {
        type =
            "xyz.openbmc_project.BIOSConfig.Manager.AttributeType.Enumeration";
    }
    else if (attrType == "String")
    {
        type = "xyz.openbmc_project.BIOSConfig.Manager.AttributeType.String";
    }
    else if (attrType == "Password")
    {
        type = "xyz.openbmc_project.BIOSConfig.Manager.AttributeType.Password";
    }
    else if (attrType == "Integer")
    {
        type = "xyz.openbmc_project.BIOSConfig.Manager.AttributeType.Integer";
    }
    else if (attrType == "Boolean")
    {
        type = "xyz.openbmc_project.BIOSConfig.Manager.AttributeType.Boolean";
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
 *@brief sets the Reset BIOS Settings to default property.
 *
 * @param[in]       ResetBiosToDefaultsPending    Reset BIOS Settings to Default
 *status
 * @param[in,out]   asyncResp   Async HTTP response.
 *
 * @return None.
 */
static void
    setResetBiosSettings(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                         const bool& resetBiosToDefaultsPending)
{
    BMCWEB_LOG_DEBUG("Set Reset Bios Settings to Defaults Pending Status");

    crow::connections::systemBus->async_method_call(
        [asyncResp, resetBiosToDefaultsPending](
            const boost::system::error_code ec, const GetObjectType& objType) {
        if (ec || objType.empty())
        {
            BMCWEB_LOG_ERROR("GetObject for path biosConfigObj");
            messages::internalError(asyncResp->res);
            return;
        }
        const std::string& biosService = objType.begin()->first;
        std::string biosMode;
        if (resetBiosToDefaultsPending)
        {
            biosMode = "xyz.openbmc_project.BIOSConfig.Manager.ResetFlag."
                       "FactoryDefaults";
        }
        else
        {
            biosMode =
                "xyz.openbmc_project.BIOSConfig.Manager.ResetFlag.NoAction";
        }
        crow::connections::systemBus->async_method_call(
            [asyncResp](const boost::system::error_code ec1) {
            if (ec1)
            {
                BMCWEB_LOG_DEBUG("DBUS response error for "
                                 "Set Reset BIOS setting to default status.");
                messages::internalError(asyncResp->res);
                return;
            }
            messages::success(asyncResp->res);
        }, biosService, biosConfigObj, "org.freedesktop.DBus.Properties", "Set",
            biosConfigIface, "ResetBIOSSettings",
            std::variant<std::string>(biosMode));
    },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetObject", biosConfigObj,
        std::array<const char*, 1>{biosConfigIface});
}

/**
 *@brief Reads the Reset BIOS Settings to default property.
 *
 * @param[in,out]   asyncResp   Async HTTP response.
 *
 * @return None.
 */
static void
    getResetBiosSettings(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
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
                BMCWEB_LOG_DEBUG("DBUS response error for "
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
                asyncResp->res.jsonValue["ResetBiosToDefaultsPending"] = false;
            }
            else if ((biosMode == "FactoryDefaults") ||
                     (biosMode == "FailSafeDefaults"))
            {
                asyncResp->res.jsonValue["ResetBiosToDefaultsPending"] = true;
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
static void
    getBiosAttributes(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
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
            [asyncResp](const boost::system::error_code ec1,
                        const std::variant<BaseBIOSTable>& baseBiosTableResp) {
            if (ec1)
            {
                BMCWEB_LOG_ERROR("Get BaseBIOSTable DBus response error");
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
                std::string attrType = getBiosAttrType(
                    std::string(std::get<BaseBiosTableIndex::baseBiosAttrType>(
                        attrIt.second)));
                if ((attrType == "String") || (attrType == "Enumeration"))
                {
                    // read the current value of attribute at 5th field
                    const std::string* attrCurrValue = std::get_if<std::string>(
                        &std::get<BaseBiosTableIndex::baseBiosCurrValue>(
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
                else if ((attrType == "Integer") || (attrType == "Boolean"))
                {
                    // read the current value of attribute at 5th field
                    const int64_t* attrCurrValue = std::get_if<int64_t>(
                        &std::get<BaseBiosTableIndex::baseBiosCurrValue>(
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
                            attributesJson.emplace(attr, *attrCurrValue);
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
 *@brief Validates the requested BIOS Base Table JSON with the required
 *attribute format.
 *
 * @param[in]      attrJson    BIOS Attribute JSON
 * @param[in,out]   asyncResp   Async HTTP response.
 *
 * @return Returns as a bool flag, true if attribute json is in valid format,
 * or else returns false.
 */
static bool isValidAttrJson(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                            const nlohmann::json& attrJson)
{
    std::vector<std::string> keys{
        "AttributeName", "CurrentValue", "DefaultValue",
        "DisplayName",   "Description",  "MenuPath",
        "ReadOnly",      "Type",         "Values"};
    std::vector<std::string> boundKeys{"LowerBound", "UpperBound",
                                       "ScalarIncrement"};

    for (const auto& key : keys)
    {
        if (!attrJson.contains(key))
        {
            if (key == "Values")
            {
                // If Type is Integer, then check for the bound values
                if (attrJson[keys.at(7)] == "Integer")
                {
                    for (const auto& boundKey : boundKeys)
                    {
                        if (!attrJson.contains(boundKey))
                        {
                            messages::propertyMissing(asyncResp->res, boundKey);
                            BMCWEB_LOG_ERROR(
                                "Required propery missing in req!");
                            return false;
                        }
                    }
                }
                else
                {
                    messages::propertyMissing(asyncResp->res, key);
                    BMCWEB_LOG_ERROR("Required propery missing in req!");
                    return false;
                }
            }
        }
    }
    if (attrJson[keys.at(0)] == "")
    {
        messages::propertyValueIncorrect(asyncResp->res, keys.at(0), "empty");
        BMCWEB_LOG_ERROR("AttributeName is not valid in req!");
        return false;
    }
    return true;
}

/**
 *@brief Sets the BIOS Base Table DBUS property with requested BIOS default
 *attributes.
 *
 * @param[in]      baseBiosTableJson BIOS Base Table default Attribute details
 * @param[in,out]   asyncResp   Async HTTP response.
 *
 * @return Returns None.
 */
static void fillBiosTable(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                          const std::vector<nlohmann::json>& baseBiosTableJson)
{
    BaseBIOSTable baseBiosTable;
    for (const nlohmann::json& attrJson : baseBiosTableJson)
    {
        // Check all the fields are present
        if (!isValidAttrJson(asyncResp, attrJson))
        {
            BMCWEB_LOG_ERROR("Req attributes are missing!");
            return;
        }
        std::string attr;
        std::string attrDispName;
        std::string attrDescr;
        std::string attrMenuPath;
        std::string attrType;
        bool attrReadOnly;
        std::vector<std::tuple<std::string, std::variant<int64_t, std::string>,
                               std::string>>
            attrValues;

        attr = attrJson["AttributeName"].get<std::string>();
        attrDispName = attrJson["DisplayName"].get<std::string>();
        attrDescr = attrJson["Description"].get<std::string>();
        attrMenuPath = attrJson["MenuPath"].get<std::string>();
        attrType = attrJson["Type"].get<std::string>();
        attrReadOnly = attrJson["ReadOnly"].get<bool>();
        if ((attrType == "String") || (attrType == "Enumeration"))
        {
            std::string currVal = attrJson["CurrentValue"].get<std::string>();
            std::string defaultVal =
                attrJson["DefaultValue"].get<std::string>();

            // read and update the bound values
            for (const auto& value :
                 attrJson["Values"].get<std::vector<std::string>>())
            {
                attrValues.emplace_back(std::make_tuple(
                    "xyz.openbmc_project.BIOSConfig.Manager.BoundType.OneOf",
                    value, ""));
            }
            attrType = getDbusBiosAttrType(attrType);
            baseBiosTable.insert(std::make_pair(
                attr, std::make_tuple(attrType, attrReadOnly, attrDispName,
                                      attrDescr, attrMenuPath, currVal,
                                      defaultVal, attrValues)));
        }
        else if (attrType == "Integer")
        {
            int64_t currVal = attrJson["CurrentValue"].get<int64_t>();
            int64_t defaultVal = attrJson["DefaultValue"].get<int64_t>();

            // read and update the bound values
            attrValues.emplace_back(std::make_tuple(
                "xyz.openbmc_project.BIOSConfig.Manager.BoundType.LowerBound",
                attrJson["LowerBound"].get<int64_t>(), ""));
            attrValues.emplace_back(std::make_tuple(
                "xyz.openbmc_project.BIOSConfig.Manager.BoundType.UpperBound",
                attrJson["UpperBound"].get<int64_t>(), ""));
            attrValues.emplace_back(std::make_tuple(
                "xyz.openbmc_project.BIOSConfig.Manager.BoundType."
                "ScalarIncrement",
                attrJson["ScalarIncrement"].get<int64_t>(), ""));

            attrType = getDbusBiosAttrType(attrType);
            baseBiosTable.insert(std::make_pair(
                attr, std::make_tuple(attrType, attrReadOnly, attrDispName,
                                      attrDescr, attrMenuPath, currVal,
                                      defaultVal, attrValues)));
        }
        else if (attrType == "Boolean")
        {
            // for Boolean type, BaseBIOSTable DBus method will expect the data
            // in the int64_t type
            int64_t currVal =
                static_cast<int64_t>(attrJson["CurrentValue"].get<bool>());
            int64_t defaultVal =
                static_cast<int64_t>(attrJson["DefaultValue"].get<bool>());
            // read and update the bound values
            for (const auto& value :
                 attrJson["Values"].get<std::vector<bool>>())
            {
                attrValues.emplace_back(std::make_tuple(
                    "xyz.openbmc_project.BIOSConfig.Manager.BoundType.OneOf",
                    (value == true ? 1 : 0), ""));
            }
            attrType = getDbusBiosAttrType(attrType);
            baseBiosTable.insert(std::make_pair(
                attr, std::make_tuple(attrType, attrReadOnly, attrDispName,
                                      attrDescr, attrMenuPath, currVal,
                                      defaultVal, attrValues)));
        }
        else
        {
            messages::propertyValueIncorrect(asyncResp->res, "Type", "UNKNOWN");
            BMCWEB_LOG_ERROR("Attribute Type is not valid in req!");
            return;
        }
    }

    if (baseBiosTable.empty())
    {
        BMCWEB_LOG_ERROR("Base Bios Table empty");
        messages::invalidObject(asyncResp->res,
                                boost::urls::format("Attributes"));
    }

    crow::connections::systemBus->async_method_call(
        [asyncResp, baseBiosTable](const boost::system::error_code ec) {
        if (ec)
        {
            BMCWEB_LOG_DEBUG("Error occurred in setting BaseBIOSTable");
            messages::internalError(asyncResp->res);
            return;
        }

        messages::success(asyncResp->res);
    }, "xyz.openbmc_project.BIOSConfigManager",
        "/xyz/openbmc_project/bios_config/manager",
        "org.freedesktop.DBus.Properties", "Set",
        "xyz.openbmc_project.BIOSConfig.Manager", "BaseBIOSTable",
        std::variant<BaseBIOSTable>(baseBiosTable));
}

/**
 *@brief Reads the BIOS Pending Attributes, which are updated by oob the user
 * and update the Bios Settings Attributes response.
 *
 * @param[in,out]   asyncResp   Async HTTP response.
 *
 * @return None.
 */
static void
    getBiosSettingsAttr(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
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
            [asyncResp](const boost::system::error_code ec1,
                        const std::variant<PendingAttrType>& pendingAttrsResp) {
            if (ec1)
            {
                BMCWEB_LOG_ERROR("Get PendingAttributes DBus response error");
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
                    std::get<BiosPendingAttributesIndex::biosPendingAttrType>(
                        attrIt.second)));
                if ((attrType == "String") || (attrType == "Enumeration"))
                {
                    // read the current value of attribute at 1st field
                    const std::string* attrCurrValue = std::get_if<std::string>(
                        &std::get<
                            BiosPendingAttributesIndex::biosPendingAttrValue>(
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
                else if ((attrType == "Integer") || (attrType == "Boolean"))
                {
                    // read the current value of attribute at 1st field
                    const int64_t* attrCurrValue = std::get_if<int64_t>(
                        &std::get<
                            BiosPendingAttributesIndex::biosPendingAttrValue>(
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
                            attributesJson.emplace(attr, *attrCurrValue);
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
static void
    setBiosPendingAttr(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
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
                BMCWEB_LOG_ERROR("Get BaseBIOSTable DBus response error");
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
                        asyncResp->res, pendingAttrIt.key(), "Attributes");
                    return;
                }

                // read the attribute type at 0th field and convert from
                // dbus to string format
                std::string attrItType =
                    std::get<BaseBiosTableIndex::baseBiosAttrType>(
                        attrIt->second);
                std::string attrType = getBiosAttrType(attrItType);
                if ((attrType == "String") || (attrType == "Enumeration"))
                {
                    std::string attrReqVal = pendingAttrIt.value();
                    // read the bound values for the attribute
                    const std::vector<AttrBoundType> boundValues =
                        std::get<BaseBiosTableIndex::baseBiosBoundValues>(
                            attrIt->second);
                    auto found = std::find_if(
                        boundValues.begin(), boundValues.end(),
                        [attrReqVal](const AttrBoundType& boundValueIt) {
                        // read the bound value type at 0th field
                        // and convert from dbus to string format
                        std::string boundValType =
                            getBiosBoundValType(std::string(
                                std::get<BaseBiosBoundIndex::baseBiosBoundType>(
                                    boundValueIt)));

                        if (boundValType == "OneOf")
                        {
                            // read the bound value  at 1st field
                            // for each entry
                            const std::string* currBoundVal =
                                std::get_if<std::string>(
                                    &std::get<
                                        BaseBiosBoundIndex::baseBiosBoundValue>(
                                        boundValueIt));
                            if (currBoundVal == nullptr)
                            {
                                BMCWEB_LOG_ERROR("Bound Value not found");
                                return false;
                            }

                            return (attrReqVal == *currBoundVal) ? true : false;
                        }
                        else
                        {
                            return false;
                        }
                    });

                    if (found == boundValues.end())
                    {
                        BMCWEB_LOG_ERROR("Requested Attribute Value invalid");
                        messages::internalError(asyncResp->res);
                        return;
                    }
                    pendingAttrs.insert(std::make_pair(
                        pendingAttrIt.key(),
                        std::make_tuple(attrItType, attrReqVal)));
                }
                else if (attrType == "Boolean")
                {
                    int64_t attrReqVal =
                        static_cast<int64_t>(pendingAttrIt.value().get<bool>());
                    // read the bound values for the attribute
                    const std::vector<AttrBoundType> boundValues =
                        std::get<BaseBiosTableIndex::baseBiosBoundValues>(
                            attrIt->second);

                    auto found = std::find_if(
                        boundValues.begin(), boundValues.end(),
                        [attrReqVal](const AttrBoundType& boundValueIt) {
                        // read the bound value type at 0th field
                        // and convert from dbus to string format
                        std::string boundValType =
                            getBiosBoundValType(std::string(
                                std::get<BaseBiosBoundIndex::baseBiosBoundType>(
                                    boundValueIt)));
                        if (boundValType == "OneOf")
                        {
                            // read the bound value  at 1st field
                            // for each entry
                            const int64_t* currBoundVal = std::get_if<int64_t>(
                                &std::get<
                                    BaseBiosBoundIndex::baseBiosBoundValue>(
                                    boundValueIt));
                            if (currBoundVal == nullptr)
                            {
                                BMCWEB_LOG_ERROR("Bound Value not found");
                                return false;
                            }
                            return (attrReqVal == *currBoundVal) ? true : false;
                        }
                        else
                        {
                            return false;
                        }
                    });

                    if (found == boundValues.end())
                    {
                        BMCWEB_LOG_ERROR("Requested Attribute Value invalid");
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
                messages::invalidObject(asyncResp->res,
                                        boost::urls::format("Attributes"));
            }

            crow::connections::systemBus->async_method_call(
                [asyncResp](const boost::system::error_code ec2) {
                if (ec2)
                {
                    BMCWEB_LOG_ERROR("Set PendingAttributes failed ");
                    messages::internalError(asyncResp->res);
                    return;
                }

                messages::success(asyncResp->res);
            }, biosService, biosConfigObj, "org.freedesktop.DBus.Properties",
                "Set", biosConfigIface, "PendingAttributes",
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
 * BiosService class supports handle put method for bios.
 */
inline void
    handleBiosServicePut(const crow::Request& req,
                         const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    crow::connections::systemBus->async_method_call(
        [req,
         asyncResp](const boost::system::error_code ec,
                    const std::map<std::string, dbus::utility::DbusVariantType>&
                        userInfo) {
        if (ec)
        {
            BMCWEB_LOG_ERROR("GetUserInfo failed");
            messages::internalError(asyncResp->res);
            return;
        }

        const std::vector<std::string>* userGroupPtr = nullptr;
        auto userInfoIter = userInfo.find("UserGroups");
        if (userInfoIter != userInfo.end())
        {
            userGroupPtr =
                std::get_if<std::vector<std::string>>(&userInfoIter->second);
        }

        if (userGroupPtr == nullptr)
        {
            BMCWEB_LOG_ERROR("User Group not found");
            messages::internalError(asyncResp->res);
            return;
        }
        auto found = std::find_if(userGroupPtr->begin(), userGroupPtr->end(),
                                  [](const auto& group) {
            return (group == "redfish-hostiface") ? true : false;
        });
        // Only Host Iface (redfish-hostiface) group user should
        // perform PUT operations
        if (found == userGroupPtr->end())
        {
            BMCWEB_LOG_ERROR("Not Sufficient Privilege");
            messages::insufficientPrivilege(asyncResp->res);
            return;
        }
        std::vector<nlohmann::json> baseBiosTableJson;
        if (!redfish::json_util::readJsonAction(
                req, asyncResp->res, "Attributes", baseBiosTableJson))
        {
            BMCWEB_LOG_ERROR("No 'Attributes' found");
            messages::unrecognizedRequestBody(asyncResp->res);
            return;
        }
        if (baseBiosTableJson.empty())
        {
            messages::invalidObject(asyncResp->res,
                                    boost::urls::format("Attributes"));
            BMCWEB_LOG_ERROR("No input in req!");
            return;
        }

        // Set the BaseBIOSTable
        bios::fillBiosTable(asyncResp, baseBiosTableJson);
    },
        "xyz.openbmc_project.User.Manager", "/xyz/openbmc_project/user",
        "xyz.openbmc_project.User.Manager", "GetUserInfo",
        req.session->username);
}
/**
 * BiosService class supports handle patch method for bios.
 */
inline void
    handleBiosServicePatch(const crow::Request& req,
                           const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    std::optional<bool> resetBiosToDefaultsPending;
    if (!json_util::readJsonPatch(req, asyncResp->res,
                                  "ResetBiosToDefaultsPending",
                                  resetBiosToDefaultsPending))
    {
        BMCWEB_LOG_ERROR("No 'ResetBiosToDefaultsPending' found");
        return;
    }
    if (resetBiosToDefaultsPending)
    {
        // set the ResetBiosToDefaultsPending
        bios::setResetBiosSettings(asyncResp, *resetBiosToDefaultsPending);
    }
}
/**
 * BiosService class supports handle get method for bios.
 */
inline void
    handleBiosServiceGet(const crow::Request&,
                         const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    asyncResp->res.jsonValue["@odata.id"] = "/redfish/v1/Systems/system/Bios";
    asyncResp->res.jsonValue["@odata.type"] = "#Bios.v1_2_0.Bios";
    asyncResp->res.jsonValue["Name"] = "BIOS Configuration";
    asyncResp->res.jsonValue["Description"] = "BIOS Configuration Service";
    asyncResp->res.jsonValue["Id"] = "BIOS";
    asyncResp->res.jsonValue["Actions"]["#Bios.ResetBios"] = {
        {"target", "/redfish/v1/Systems/system/Bios/Actions/Bios.ResetBios"}};
    asyncResp->res.jsonValue["Actions"]["#Bios.ChangePassword"] = {
        {"target", "/redfish/v1/Systems/system/Bios/Actions/"
                   "Bios.ChangePassword"}};
    asyncResp->res.jsonValue["@Redfish.Settings"]["@odata.type"] =
        "#Settings.v1_2_2.Settings";
    asyncResp->res.jsonValue["@Redfish.Settings"]["SettingsObject"] = {
        {"@odata.id", "/redfish/v1/Systems/system/Bios/Settings"}};
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
    BMCWEB_ROUTE(app, "/redfish/v1/Systems/system/Bios/")
        .privileges(redfish::privileges::getBios)
        .methods(boost::beast::http::verb::get)(handleBiosServiceGet);
    BMCWEB_ROUTE(app, "/redfish/v1/Systems/system/Bios/")
        .privileges(redfish::privileges::patchBios)
        .methods(boost::beast::http::verb::patch)(handleBiosServicePatch);
    BMCWEB_ROUTE(app, "/redfish/v1/Systems/system/Bios/")
        .privileges(redfish::privileges::putBios)
        .methods(boost::beast::http::verb::put)(handleBiosServicePut);
}
/**
 * BiosSetting class supports handle patch method for Bios Settings.
 */
inline void
    handleBiosSettingsPatch(const crow::Request& req,
                            const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    nlohmann::json pendingAttrJson;
    if (!redfish::json_util::readJsonPatch(req, asyncResp->res, "Attributes",
                                           pendingAttrJson))
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
inline void
    handleBiosSettingsGet(const crow::Request&,
                          const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    asyncResp->res.jsonValue["@odata.id"] =
        "/redfish/v1/Systems/system/Bios/Settings";
    asyncResp->res.jsonValue["@odata.type"] = "#Bios.v1_1_0.Bios";
    asyncResp->res.jsonValue["Name"] = "BIOS Configuration";
    asyncResp->res.jsonValue["Description"] = "BIOS Settings";
    asyncResp->res.jsonValue["Id"] = "BIOS_Settings";
    asyncResp->res.jsonValue["Attributes"] = nlohmann::json({});
    // get the BIOS Attributes
    bios::getBiosSettingsAttr(asyncResp);
}
inline void requestRoutesBiosSettings(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Systems/system/Bios/Settings")
        .privileges(redfish::privileges::getBios)
        .methods(boost::beast::http::verb::get)(handleBiosSettingsGet);
    BMCWEB_ROUTE(app, "/redfish/v1/Systems/system/Bios/Settings")
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
        }, "xyz.openbmc_project.BIOSConfigPassword",
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
inline void
    handleBiosResetPost(crow::App& app, const crow::Request& req,
                        const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                        const std::string& systemName)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    if (!req.body().empty() && req.body() != "{}")
    {
        nlohmann::json jsonBody = nlohmann::json::parse(req.body());
        std::string key = jsonBody.begin().key();
        messages::actionParameterUnknown(asyncResp->res, "/redfish/v1/Systems/system/Bios/Actions/Bios.ResetBios/", key);
        return;
    }

    /*if constexpr (bmcwebEnableMultiHost)
    {
        // Option currently returns no systems.  TBD
        messages::resourceNotFound(asyncResp->res, "ComputerSystem",
                                   systemName);
        return;
    }*/

    if (systemName != "system")
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
    }, "xyz.openbmc_project.BIOSConfigManager",
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
