// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
// clang-format off
#include "async_resp.hpp"
#include "dbus_singleton.hpp"
#include "http_response.hpp"
#include "human_sort.hpp"
#include "utils/json_utils.hpp"

#include "power_subsystem.hpp"
// clang-format on

#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>
#include <sdbusplus/asio/connection.hpp>

#include <memory>
#include <optional>
#include <string>

#include <gtest/gtest.h>

namespace redfish
{
namespace
{

constexpr const char* chassisId = "ChassisId";
constexpr const char* validChassisPath = "ChassisPath";

void assertPowerSubsystemCollectionGet(crow::Response& res)
{
    nlohmann::json& json = res.jsonValue;
    EXPECT_EQ(json["@odata.type"], "#PowerSubsystem.v1_1_0.PowerSubsystem");
    EXPECT_EQ(json["Name"], "Power Subsystem");
    EXPECT_EQ(json["Id"], "PowerSubsystem");
    EXPECT_EQ(json["@odata.id"],
              "/redfish/v1/Chassis/ChassisId/PowerSubsystem");
    EXPECT_EQ(json["Status"]["State"], "Enabled");
    EXPECT_EQ(json["Status"]["Health"], "OK");
}

TEST(PowerSubsystemCollectionTest,
     PowerSubsystemCollectionStaticAttributesAreExpected)
{
    // doPowerSubsystemCollection issues fire-and-forget async D-Bus calls via
    // crow::connections::systemBus.  Without a valid (non-null) pointer those
    // calls dereference nullptr and crash.  We create a real connection backed
    // by an io_context that is never driven, so the D-Bus callbacks never
    // fire.  The test only verifies the static JSON fields that are set
    // synchronously before any D-Bus call is made.
    boost::asio::io_context io;
    sdbusplus::asio::connection conn(io);
    crow::connections::systemBus = &conn;

    auto shareAsyncResp = std::make_shared<bmcweb::AsyncResp>();
    shareAsyncResp->res.setCompleteRequestHandler(
        assertPowerSubsystemCollectionGet);
    doPowerSubsystemCollection(
        shareAsyncResp, chassisId,
        std::make_optional<std::string>(validChassisPath));

    crow::connections::systemBus = nullptr;
}

} // namespace
} // namespace redfish
