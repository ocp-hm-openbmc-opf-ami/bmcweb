#include "app.hpp"
#include "redfish.hpp"

#include <boost/asio/io_context.hpp>

#include <memory>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace redfish
{
namespace
{
using ::testing::EndsWith;

TEST(Redfish, PathsShouldValidate)
{
    auto io = std::make_shared<boost::asio::io_context>();
    crow::App app(io);

    RedfishService redfish(app);

    app.validate();

    for (const std::string* route : app.getRoutes())
    {
        ASSERT_NE(route, nullptr);
        // OEM and action routes may not end with trailing slash
        if (route->find("/Oem/") == std::string::npos &&
            route->find("/Actions/") == std::string::npos)
        {
            EXPECT_THAT(*route, EndsWith("/"));
        }
    }
}

} // namespace
} // namespace redfish
