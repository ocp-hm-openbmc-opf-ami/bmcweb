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

#pragma once

#include "ondemand_helper.hpp"
#include "registries.hpp"
#include "registries/base_message_registry.hpp"
#include "registries/openbmc_message_registry.hpp"
#include "task.hpp"

#include <app.hpp>
#include <dbus_utility.hpp>

namespace redfish
{
namespace ondemand
{
static const std::string ondemandService = "xyz.openbmc_project.ondemand";
static const std::string ondemandPath = "/xyz/openbmc_project/ondemand/";
static const std::string stateDataInterface =
    "xyz.openbmc_project.CPU.StateData";
static const std::string meterDataInterface =
    "xyz.openbmc_project.CPU.MeteredData";
static const std::string featureEnableInterfaceName =
    "xyz.openbmc_project.CPU.FeatureEnable";

class Fd
{
  private:
    std::optional<int> fd;

  public:
    Fd() = default;
    explicit Fd(int fdIn) : fd(fdIn) {}
    Fd(const Fd&) = delete;
    Fd(Fd&& other)
    {
        std::swap(fd, other.fd);
    }

    ~Fd()
    {
        reset();
    }

    Fd& operator=(const Fd&) = delete;
    Fd& operator=(Fd&& other)
    {
        reset();
        std::swap(fd, other.fd);
        return *this;
    }

    void reset()
    {
        if (fd)
        {
            ::close(*fd);
            fd.reset();
        }
    }

    explicit operator bool() const
    {
        return static_cast<bool>(fd);
    }
    int operator*() const
    {
        return *fd;
    }
};

struct ondemandData
{
    int fd;
    bool fdStatus;
    bool methodSuccess;
    bool signalResponseSuccess;
    std::shared_ptr<task::TaskData> task;
};
boost::container::flat_map<std::string, ondemandData> ondemandList;

inline void
    getCPUMeterState(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                     const std::string& processorId,
                     const std::string& reqFeature,
                     const std::string& featureData)
{
    asyncResp->res.jsonValue["@odata.type"] =
        "#MeterStateFeature.v1_0_0.MeterStateFeature";
    asyncResp->res.jsonValue["@odata.id"] =
        "/redfish/v1/Systems/system/Processors/" + processorId + "/Oem/Intel/" +
        reqFeature;
    asyncResp->res.jsonValue["FeatureAuthDevice"]["@odata.id"] =
        "/redfish/v1/Systems/system/Processors/" + processorId;
    asyncResp->res.jsonValue["Name"] = reqFeature;
    asyncResp->res.jsonValue["Id"] = processorId + reqFeature;

    if (!featureData.empty())
    {
        std::string ondemandListIdentifier = processorId + reqFeature;
        ondemandData ondemandObject = ondemandList[ondemandListIdentifier];
        if (ondemandObject.signalResponseSuccess)
        {
            asyncResp->res.jsonValue["FeatureStatus"] = "Enabled";
        }
        else
        {
            asyncResp->res.jsonValue["FeatureStatus"] = "Disabled";
        }
        asyncResp->res.jsonValue["FeatureData"] = featureData;
    }
    else
    {
        asyncResp->res.jsonValue["FeatureStatus"] = "Disabled";
        asyncResp->res.jsonValue["FeatureData"] = "";
    }
}

inline void
    getCPUProvisionDynamic(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                           const std::string& processorId,
                           const std::string& reqFeature,
                           const bool featureEnabled)
{
    asyncResp->res.jsonValue["@odata.type"] =
        "#ProvisionDynamicFeature.v1_0_0.ProvisionDynamicFeature";
    asyncResp->res.jsonValue["@odata.id"] =
        "/redfish/v1/Systems/system/Processors/" + processorId + "/Oem/Intel/" +
        reqFeature;
    asyncResp->res.jsonValue["FeatureAuthDevice"]["@odata.id"] =
        "/redfish/v1/Systems/system/Processors/" + processorId;
    asyncResp->res.jsonValue["Name"] = reqFeature;
    asyncResp->res.jsonValue["Id"] = processorId + reqFeature;

    if (featureEnabled)
    {
        asyncResp->res.jsonValue["FeatureStatus"] = "Enabled";
        asyncResp->res.jsonValue["FeatureAuthLicense"]["@odata.id"] =
            "/redfish/v1/LicenseService/Licenses/" +
            std::string((reqFeature == "ProvisionFeature") ? "ProvisionLicense"
                                                           : "DynamicLicense") +
            processorId;
    }
    else
    {
        asyncResp->res.jsonValue["FeatureStatus"] = "Disabled";
    }
}

inline void
    createMeterStateData(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                         const std::string& processorId,
                         const std::string& reqFeature)
{
    std::string ondemandListIdentifier = processorId + reqFeature;
    std::string signalMatchStr, method, obj, iface;
    bool isUnsigned = false;

    if (reqFeature == "MeteringFeature")
    {
        method = "GetMeteredData";
        obj = ondemandPath + processorId + "/metered_data";
        iface = meterDataInterface;
        signalMatchStr = "type='signal',interface='";
        signalMatchStr += iface;
        signalMatchStr += "',member='";
        signalMatchStr += "GetMeteredDataComplete";
        signalMatchStr += "', path='";
        signalMatchStr += obj;
        signalMatchStr += "'";
    }
    else if (reqFeature == "UnsignedMeteringFeature")
    {
        isUnsigned = true;
        method = "GetMeteredData";
        obj = ondemandPath + processorId + "/metered_data";
        iface = meterDataInterface;
        signalMatchStr = "type='signal',interface='";
        signalMatchStr += iface;
        signalMatchStr += "',member='";
        signalMatchStr += "GetMeteredDataComplete";
        signalMatchStr += "', path='";
        signalMatchStr += obj;
        signalMatchStr += "'";
    }
    else if (reqFeature == "StateFeature")
    {
        method = "GetStateData";
        obj = ondemandPath + processorId + "/state_data";
        iface = stateDataInterface;
        signalMatchStr = "type='signal',interface='";
        signalMatchStr += iface;
        signalMatchStr += "',member='";
        signalMatchStr += "GetStateDataComplete";
        signalMatchStr += "', path='";
        signalMatchStr += obj;
        signalMatchStr += "'";
    }
    else
    {
        messages::resourceNotFound(asyncResp->res, "OnDemandFeature",
                                   reqFeature);
        return;
    }
    auto createFeaureTaskCallback =
        [asyncResp, ondemandListIdentifier, signalMatchStr, processorId,
         reqFeature](const boost::system::error_code ec,
                     std::tuple<sdbusplus::message::unix_fd, int> response) {
        if (ec)
        {
            messages::internalError(asyncResp->res);
            return;
        }
        int ondemandResponse = std::get<1>(response);
        if (ondemandResponse ==
            static_cast<int>(redfish::OnDemandResponseCode::ondemandSuccess))
        {
            int fdDup = dup(std::get<0>(response));
            if (fdDup == -1)
            {
                getCPUMeterState(asyncResp, processorId, reqFeature, "");
                return;
            }

            std::shared_ptr<task::TaskData> task = task::TaskData::createTask(
                [ondemandListIdentifier](
                    boost::system::error_code err, sdbusplus::message_t& msg,
                    const std::shared_ptr<task::TaskData>& taskData) {
                auto ondemandListObj =
                    ondemandList.find(ondemandListIdentifier);
                if (!err)
                {
                    taskData->messages.emplace_back(messages::taskCompletedOK(
                        std::to_string(taskData->index)));
                    taskData->state = "Completed";
                    int onDemandSignalResponse = static_cast<int>(
                        redfish::OnDemandResponseCode::ondemandFailure);
                    msg.read(onDemandSignalResponse);
                    if (ondemandListObj != ondemandList.end())
                    {
                        ondemandListObj->second.fdStatus = true;
                        ondemandListObj->second.methodSuccess = true;
                        if (onDemandSignalResponse ==
                            static_cast<int>(
                                redfish::OnDemandResponseCode::ondemandSuccess))
                        {
                            ondemandListObj->second.signalResponseSuccess =
                                true;
                        }
                    }
                }
                else
                {
                    if (ondemandListObj != ondemandList.end())
                    {
                        ondemandListObj->second.fdStatus = true;
                    }
                }
                return task::completed;
            },
                signalMatchStr);
            task->startTimer(std::chrono::minutes(1));
            task->populateResp(asyncResp->res);

            task->state = "Pending";

            ondemandData ondemandVal = {fdDup, false, false, false, task};
            ondemandList[ondemandListIdentifier] = ondemandVal;

            return;
        }
        else if (ondemandResponse ==
                 static_cast<int>(
                     redfish::OnDemandResponseCode::ondemandMethodInProgress))
        {
            messages::serviceTemporarilyUnavailable(asyncResp->res, "60");
            return;
        }
        else
        {
            messages::internalError(asyncResp->res);
            return;
        }
    };

    crow::connections::systemBus->async_method_call(
        std::move(createFeaureTaskCallback), ondemandService, obj, iface,
        method, isUnsigned);
}

inline void
    readMeterStateData(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                       Fd fd, const std::string& processorId,
                       const std::string& reqFeature)
{
    std::vector<char> data;
    std::array<char, 1024> chunk;
    long long int rc = 0;
    if (lseek(*fd, 0, SEEK_SET) == -1)
    {
        getCPUMeterState(asyncResp, processorId, reqFeature, "");
        return;
    }
    while ((rc = read(*fd, chunk.data(), chunk.max_size())) > 0)
    {
        data.insert(std::end(data), std::begin(chunk), std::begin(chunk) + rc);
    }
    // TODO: Uncomment the below pieces of code when file size is confirmed from
    // backend constexpr int maxFileSize = 4096;   //4KB
    if (data.size() == 0 /*|| data.size() > maxFileSize*/ || rc != 0)
    {
        getCPUMeterState(asyncResp, processorId, reqFeature, "");
    }
    else
    {
        getCPUMeterState(asyncResp, processorId, reqFeature,
                         std::string(data.cbegin(), data.cend()));
    }
}

inline void getMeterStateFeatureData(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& processorId, const std::string& reqFeature)

{
    auto ondemandObject = ondemandList.find(processorId + reqFeature);
    if (ondemandObject == ondemandList.end())
    {
        createMeterStateData(asyncResp, processorId, reqFeature);
    }
    else
    {
        if (!ondemandObject->second.fdStatus)
        {
            ondemandObject->second.task->populateResp(asyncResp->res);
            return;
        }
        Fd fd{ondemandObject->second.fd};
        if (!ondemandObject->second.methodSuccess)
        {
            getCPUMeterState(asyncResp, processorId, reqFeature, "");
            ondemandList.erase(ondemandObject);
            return;
        }

        readMeterStateData(asyncResp, std::move(fd), processorId, reqFeature);
        ondemandList.erase(ondemandObject);
    }
}

inline void getProvisionDyamicFeatureData(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& objectPath, const std::string& processorId,
    const std::string& reqFeature)
{
    std::string method;
    if (reqFeature == "ProvisionFeature")
    {
        method = "GetProvisionState";
    }
    else
    {
        method = "GetFeatureState";
    }

    crow::connections::systemBus->async_method_call(
        [asyncResp, processorId, reqFeature,
         method](const boost::system::error_code ec, bool featureEnabled) {
        if (ec)
        {
            messages::internalError(asyncResp->res);
            return;
        }
        getCPUProvisionDynamic(asyncResp, processorId, reqFeature,
                               featureEnabled);
    },
        ondemandService, objectPath, featureEnableInterfaceName, method);
}
} // namespace ondemand

inline void requestRoutesMeterStateData(App& app)
{
    BMCWEB_ROUTE(app,
                 "/redfish/v1/Systems/system/Processors/<str>/Oem/Intel/<str>")
        .privileges(redfish::privileges::privilegeSetConfigureComponents)
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& processorId,
                   const std::string& reqFeature) {
        if (!redfish::setUpRedfishRoute(app, req, asyncResp))
        {
            return;
        }
        if (reqFeature.empty())
        {
            messages::internalError(asyncResp->res);
            return;
        }
        crow::connections::systemBus->async_method_call(
            [&req, asyncResp, processorId, reqFeature](
                boost::system::error_code ec,
                const dbus::utility::MapperGetSubTreeResponse& subtree) {
            if (ec)
            {
                BMCWEB_LOG_WARNING("D-Bus error: {}, {}", ec, ec.message());
                messages::internalError(asyncResp->res);
                return;
            }
            for (const auto& [objectPath, serviceMap] : subtree)
            {
                // Ignore any configs without ending with desired cpu name
                if (!objectPath.ends_with(processorId) || serviceMap.empty())
                {
                    continue;
                }
                if ((reqFeature == "MeteringFeature") ||
                    (reqFeature == "UnsignedMeteringFeature") ||
                    (reqFeature == "StateFeature"))
                {
                    ondemand::getMeterStateFeatureData(asyncResp, processorId,
                                                       reqFeature);
                }
                else if ((reqFeature == "ProvisionFeature") ||
                         (reqFeature == "DynamicFeature"))
                {
                    ondemand::getProvisionDyamicFeatureData(
                        asyncResp, objectPath, processorId, reqFeature);
                }
                else
                {
                    break;
                }
                return;
            }
            messages::resourceNotFound(asyncResp->res, "OnDemandFeature",
                                       reqFeature);
        },
            "xyz.openbmc_project.ObjectMapper",
            "/xyz/openbmc_project/object_mapper",
            "xyz.openbmc_project.ObjectMapper", "GetSubTree",
            "/xyz/openbmc_project/ondemand", 0,
            std::array<const std::string, 1>{
                "xyz.openbmc_project.CPU.FeatureEnable"});
    });
}

} // namespace redfish
