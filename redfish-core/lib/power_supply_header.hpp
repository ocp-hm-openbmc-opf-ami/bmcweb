#pragma once

namespace redfish
{
    void handlePowerSupplyGet(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& chassisId, const std::string& powerSupplyId);
    
    void getValidPowerSupplyPath(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& powerSupplyId,
    std::function<void(const std::string& powerSupplyPath)>&& callback);
}