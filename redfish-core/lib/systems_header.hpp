#pragma once

#include "system_utils.hpp"

#include <string>

namespace redfish
{

// Service name constants for dual-node support
static constexpr const char* virtualMediaServiceNameNode0 =
    "xyz_2eopenbmc_project_2eVirtualMedia";
static constexpr const char* kvmServiceNameNode0 = "start_2dipkvm";
static constexpr const char* watchdogServiceNameNode0 =
    "xyz_2eopenbmc_project_2eWatchdog_2ehost0";

static constexpr const char* virtualMediaServiceNameNode1 =
    "xyz_2eopenbmc_project_2eVirtualMedia1";
static constexpr const char* kvmServiceNameNode1 = "start_2dipkvm1";
static constexpr const char* watchdogServiceNameNode1 =
    "xyz_2eopenbmc_project_2eWatchdog_2ehost1";

// Common utility functions for service name resolution
inline std::string getVirtualMediaServiceName(const std::string& systemName)
{
    if (system_utils::isDualHostEnabled())
    {
        if (systemName == "system1")
        {
            return virtualMediaServiceNameNode1;
        }
        return virtualMediaServiceNameNode0;
    }
    return virtualMediaServiceNameNode0;
}

inline std::string getKvmServiceName(const std::string& systemName)
{
    if (system_utils::isDualHostEnabled())
    {
        if (systemName == "system1")
        {
            return kvmServiceNameNode1;
        }
        return kvmServiceNameNode0;
    }
    return kvmServiceNameNode0;
}

inline std::string getWatchdogServiceName(const std::string& systemName)
{
    if (system_utils::isDualHostEnabled())
    {
        if (systemName == "system1")
        {
            return watchdogServiceNameNode1;
        }
        return watchdogServiceNameNode0;
    }
    return watchdogServiceNameNode0;
}

// Forward declarations
void getMemorySummary(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                      const std::string& service, const std::string& path);

void getComputerSystem(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp);
void getProvisioningStatus(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp);
void afterGetUUID(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                  const boost::system::error_code& ec,
                  const dbus::utility::DBusPropertiesMap& properties);
void afterGetInventory(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                       const boost::system::error_code& ec,
                       const dbus::utility::DBusPropertiesMap& propertiesList);
void afterGetAssetTag(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                      const boost::system::error_code& ec,
                      const std::string& value);
void afterPortRequest(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const boost::system::error_code& ec,
    const std::vector<std::tuple<std::string, std::string, bool>>& socketData);
void getHostState(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                  const std::string& systemType);
void getBootProperties(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp);
void getBootOverrideSource(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp);
void getBootOverrideType(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp);
void getBootProgress(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp);
void getBootProgressLastStateTime(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp);
void getCPLDBootProgress(const std::shared_ptr<bmcweb::AsyncResp>& aResp);
void getHostWatchdogTimer(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                          const std::string& systemName);
void getPowerRestorePolicy(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp);
void getStopBootOnFault(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp);
void getAutomaticRetryPolicy(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp);
void getLastResetTime(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                      const std::string& systemType);
void getTrustedModuleRequiredToBoot(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp);
void getPowerMode(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp);
void getIdlePowerSaver(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp);
void getSerialConsoleSshStatus(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp);
void getKvmConfig(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                  const std::string& systemName);
void getVirtualMediaConfig(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                           const std::string& systemName);
void setBootModeOrSource(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                         const std::optional<std::string>& bootSource);
void setBootType(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                 const std::optional<std::string>& bootType);
void setBootEnable(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::optional<std::string>& bootEnable);
void setAssetTag(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                 const std::string& assetTag);
void setWDTProperties(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                      const std::optional<bool> wdtEnable,
                      const std::optional<std::string>& wdtTimeOutAction,
                      const std::string& systemName);
void setAutomaticRetryAttempts(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const uint32_t retryAttempts);
void setAutomaticRetry(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                       const std::string& automaticRetryConfig);
void setTrustedModuleRequiredToBoot(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& bootTrustedModuleRequired);
void setStopBootOnFault(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                        const std::string& stopBootOnFault);
void setPowerRestorePolicy(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                           std::string_view policy);
void setPowerMode(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                  const std::string& pmode);
void setIdlePowerSaver(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                       const std::optional<bool> ipsEnable,
                       const std::optional<uint8_t> ipsEnterUtil,
                       const std::optional<uint64_t> ipsEnterTime,
                       const std::optional<uint8_t> ipsExitUtil,
                       const std::optional<uint64_t> ipsExitTime);
void handleComputerSystemCollectionGet(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp);
void handleComputerSystemGet(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& systemName);
void handleComputerSystemPostDelete(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& systemName);
} // namespace redfish
