#pragma once

namespace redfish
{
    void handleUpdateServiceFirmwareInventoryGet(
        App& app, const crow::Request& req,
        const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
        const std::string& managerId);
}

