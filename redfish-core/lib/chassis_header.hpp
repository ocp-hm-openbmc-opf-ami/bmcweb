#pragma once


namespace redfish
{
    void
    handleChassisGet(App& app, const crow::Request& req,
                     const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                     const std::string& chassisId);
    inline bool ishandleChassisGetSubTree = false;
    void handleChassisPatch(App& app, const crow::Request& req,
		    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
		    const std::string& param);
    
}
