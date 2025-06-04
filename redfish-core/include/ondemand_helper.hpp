/*
// Copyright (c) 2022 Intel Corporation
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

/**
 * This file contains all error codes for OnDemand dbus-responses and OnDemand
 * helper functions.
 */

#pragma once

namespace redfish
{

enum class OnDemandResponseCode
{
    ondemandFailure = 0,
    ondemandSuccess,
    ondemandMethodInProgress,
    ondemandUnableToOpenFd
};
inline void fillOnDemandOemObject(std::shared_ptr<bmcweb::AsyncResp> asyncResp,
                                  const std::string& processorId)
{
    crow::connections::systemBus->async_method_call(
        [asyncResp,
         processorId](boost::system::error_code ec,
                      const dbus::utility::MapperGetSubTreeResponse& subtree) {
            if (ec)
            {
                return;
            }
            for (const auto& [objectPath, serviceMap] : subtree)
            {
                // Ignore any configs without ending with desired cpu name
                if (!objectPath.ends_with(processorId) || serviceMap.empty())
                {
                    continue;
                }
                asyncResp->res.jsonValue["Name"] = processorId;
                asyncResp->res.jsonValue["Id"] = processorId;
                nlohmann::json& oem = asyncResp->res.jsonValue["Oem"];
                nlohmann::json& oemIntel = oem["Intel"];
                oemIntel["@odata.type"] = json_util::odataType("OemProcessor", "Processor");
                oemIntel["MeteringFeature"]["@odata.id"] =
                    "/redfish/v1/Systems/system/Processors/" + processorId +
                    "/Oem/Intel/MeteringFeature";
                oemIntel["StateFeature"]["@odata.id"] =
                    "/redfish/v1/Systems/system/Processors/" + processorId +
                    "/Oem/Intel/StateFeature";
                oemIntel["ProvisionFeature"]["@odata.id"] =
                    "/redfish/v1/Systems/system/Processors/" + processorId +
                    "/Oem/Intel/ProvisionFeature";
                oemIntel["DynamicFeature"]["@odata.id"] =
                    "/redfish/v1/Systems/system/Processors/" + processorId +
                    "/Oem/Intel/DynamicFeature";

                dbus::utility::getProperty<std::string>(
                    "xyz.openbmc_project.SpecialMode",
                    "/xyz/openbmc_project/security/special_mode",
                    "xyz.openbmc_project.Security.SpecialMode", "SpecialMode",
                    [asyncResp, &oemIntel,
                     processorId](const boost::system::error_code error,
                                  const std::string& specialModeStr) {
                        if (error)
                        {
                            BMCWEB_LOG_DEBUG("DBUS response error {}", error);
                            return;
                        }
                        if (specialModeStr.ends_with("ValidationUnsecure"))
                        {
                            oemIntel["UnsignedMeteringFeature"]["@odata.id"] =
                                "/redfish/v1/Systems/system/Processors/" +
                                processorId +
                                "/Oem/Intel/UnsignedMeteringFeature";
                        }
                    });
            }
            return;
        },
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTree",
        "/xyz/openbmc_project/ondemand", 0,
        std::array<const std::string, 1>{
            "xyz.openbmc_project.CPU.FeatureEnable"});
}

} // namespace redfish
