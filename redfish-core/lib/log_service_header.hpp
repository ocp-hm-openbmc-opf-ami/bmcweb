#pragma once
#include "generated/enums/log_entry.hpp"


namespace redfish
{
   std::string getDumpPath(std::string_view dumpType);
   void deleteDumpEntry(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
		   const std::string& entryID,
		   const std::string& dumpType);
   void clearDump(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
		   const std::string& dumpType);
   log_entry::OriginatorTypes mapDbusOriginatorTypeToRedfish(const std::string& originatorType);
   bool checkSizeLimit(int fd, crow::Response& res);
   void createDump(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const crow::Request& req, const std::string& dumpType);
}
