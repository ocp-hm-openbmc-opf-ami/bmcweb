// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

// clang-format off
#include "async_resp.hpp"
#include "dbus_singleton.hpp"
#include "http_response.hpp"
#include "utils/json_utils.hpp"
#include "fan.hpp"
#include "thermal_subsystem.hpp"
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

void assertThermalCollectionGet(crow::Response& res)
{
    nlohmann::json& json = res.jsonValue;
    EXPECT_EQ(json["@odata.type"], "#ThermalSubsystem.v1_0_0.ThermalSubsystem");
    EXPECT_EQ(json["Name"], "Thermal Subsystem");
    EXPECT_EQ(json["Id"], "ThermalSubsystem");
    EXPECT_EQ(json["@odata.id"],
              "/redfish/v1/Chassis/ChassisId/ThermalSubsystem");
    EXPECT_EQ(json["Status"]["State"], "Enabled");
    EXPECT_EQ(json["Status"]["Health"], "OK");
}

TEST(ThermalSubsystemCollectionTest,
     ThermalSubsystemCollectionStaticAttributesAreExpected)
{
    // doThermalSubsystemCollection triggers async D-Bus calls via
    // crow::connections::systemBus (via fan.hpp).  Without a valid pointer
    // those calls dereference nullptr and crash.  We create a real connection
    // backed by an io_context that is never driven so the callbacks never
    // fire; only the static JSON fields (which the test asserts) are set
    // synchronously.
    boost::asio::io_context io;
    sdbusplus::asio::connection conn(io);
    crow::connections::systemBus = &conn;

    auto shareAsyncResp = std::make_shared<bmcweb::AsyncResp>();
    shareAsyncResp->res.setCompleteRequestHandler(assertThermalCollectionGet);
    doThermalSubsystemCollection(
        shareAsyncResp, chassisId,
        std::make_optional<std::string>(validChassisPath));

    crow::connections::systemBus = nullptr;
}

} // namespace
} // namespace redfish
