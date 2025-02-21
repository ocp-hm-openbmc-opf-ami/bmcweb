#pragma once
#include <boost/date_time.hpp>

namespace redfish
{
    bool ishandleManagersInstanceGet = false;
    void handleManagersInstanceGet(
        App& app, const crow::Request& req,
        const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
        const std::string& managerId);
}
