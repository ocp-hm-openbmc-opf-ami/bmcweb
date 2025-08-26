
#pragma once
#include "log_error.hpp"

//int alphanumComp(std::string_view, std::string_view);

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
   std::string timeFormat(std::string timestamp);
   LogParseError fillMessageEntry(const std::string& logEntry, std::string& msgID, std::string& msg);

// A generic template type compatible with std::less that can be used on generic
// containers (set, map, etc)
//template <class Type>
//struct AlphanumLess
//{
//    bool operator()(const Type& left, const Type& right) const
//    {
//        return alphanumComp(left, right) < 0;
//    }
//};
}
