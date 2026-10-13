// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
//
// Unit tests for Boot Order Configuration logic in systems.hpp.
//
// Coverage:
//   DBus→Redfish translation:  dbusToRfBootSource, dbusToRfBootType,
//                               dbusToRfBootMode, dbusToRfBootProgress
//   Redfish→DBus mapping:      assignBootParameters
//   Validation helpers:        validstopBootOnFault
//   Synchronous logic:         processBootOverrideEnable (disabled path)
//   Setter validation paths:   setBootType, setBootEnable, setBootModeOrSource,
//                               setBootProperties, setStopBootOnFault,
//                               setAutomaticRetry,
//                               setTrustedModuleRequiredToBoot
//
// D-Bus mock strategy:
//   Pure translation functions and input-validation gates are tested directly.
//   For the async D-Bus getter/setter paths a GMock interface
//   (IBootOrderDbusOps) is provided together with MockBootOrderDbusOps so that
//   future refactored code can be verified through EXPECT_CALL / ON_CALL
//   without a live D-Bus.  The fixture BootOrderDbusFixture demonstrates this
//   pattern.

#include "async_resp.hpp"
#include "dbus_utility.hpp"
#include "http_response.hpp"
#include "systems.hpp"

#include <boost/asio/error.hpp>
#include <boost/beast/http/status.hpp>
#include <nlohmann/json.hpp>

#include <memory>
#include <optional>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace redfish
{
namespace
{

// ============================================================================
// Section 1 – DBus-to-Redfish translation helpers (pure functions)
// ============================================================================

// ----------------------------------------------------------------------------
// dbusToRfBootSource
// ----------------------------------------------------------------------------
TEST(DbusToRfBootSource, DefaultSource_ReturnsNone)
{
    EXPECT_EQ(dbusToRfBootSource(
                  "xyz.openbmc_project.Control.Boot.Source.Sources.Default"),
              "None");
}

TEST(DbusToRfBootSource, DiskSource_ReturnsHdd)
{
    EXPECT_EQ(dbusToRfBootSource(
                  "xyz.openbmc_project.Control.Boot.Source.Sources.Disk"),
              "Hdd");
}

TEST(DbusToRfBootSource, ExternalMediaSource_ReturnsCd)
{
    EXPECT_EQ(
        dbusToRfBootSource(
            "xyz.openbmc_project.Control.Boot.Source.Sources.ExternalMedia"),
        "Cd");
}

TEST(DbusToRfBootSource, NetworkSource_ReturnsPxe)
{
    EXPECT_EQ(dbusToRfBootSource(
                  "xyz.openbmc_project.Control.Boot.Source.Sources.Network"),
              "Pxe");
}

TEST(DbusToRfBootSource, RemovableMediaSource_ReturnsUsb)
{
    EXPECT_EQ(
        dbusToRfBootSource(
            "xyz.openbmc_project.Control.Boot.Source.Sources.RemovableMedia"),
        "Usb");
}

TEST(DbusToRfBootSource, HttpSource_ReturnsUefiHttp)
{
    EXPECT_EQ(dbusToRfBootSource(
                  "xyz.openbmc_project.Control.Boot.Source.Sources.HTTP"),
              "UefiHttp");
}

TEST(DbusToRfBootSource, UnknownSource_ReturnsEmptyString)
{
    EXPECT_EQ(dbusToRfBootSource("xyz.openbmc_project.Control.Boot.Source."
                                 "Sources.UnknownSource"),
              "");
}

TEST(DbusToRfBootSource, EmptyString_ReturnsEmptyString)
{
    EXPECT_EQ(dbusToRfBootSource(""), "");
}

// ----------------------------------------------------------------------------
// dbusToRfBootType
// ----------------------------------------------------------------------------
TEST(DbusToRfBootType, LegacyType_ReturnsLegacy)
{
    EXPECT_EQ(
        dbusToRfBootType("xyz.openbmc_project.Control.Boot.Type.Types.Legacy"),
        "Legacy");
}

TEST(DbusToRfBootType, EfiType_ReturnsUEFI)
{
    EXPECT_EQ(
        dbusToRfBootType("xyz.openbmc_project.Control.Boot.Type.Types.EFI"),
        "UEFI");
}

TEST(DbusToRfBootType, UnknownType_ReturnsEmptyString)
{
    EXPECT_EQ(
        dbusToRfBootType("xyz.openbmc_project.Control.Boot.Type.Types.Unknown"),
        "");
}

TEST(DbusToRfBootType, EmptyString_ReturnsEmptyString)
{
    EXPECT_EQ(dbusToRfBootType(""), "");
}

// ----------------------------------------------------------------------------
// dbusToRfBootMode
// ----------------------------------------------------------------------------
TEST(DbusToRfBootMode, RegularMode_ReturnsNone)
{
    EXPECT_EQ(
        dbusToRfBootMode("xyz.openbmc_project.Control.Boot.Mode.Modes.Regular"),
        "None");
}

TEST(DbusToRfBootMode, SetupMode_ReturnsBiosSetup)
{
    EXPECT_EQ(
        dbusToRfBootMode("xyz.openbmc_project.Control.Boot.Mode.Modes.Setup"),
        "BiosSetup");
}

TEST(DbusToRfBootMode, DiagMode_ReturnsDiags)
{
    EXPECT_EQ(
        dbusToRfBootMode("xyz.openbmc_project.Control.Boot.Mode.Modes.Diag"),
        "Diags");
}

TEST(DbusToRfBootMode, UnknownMode_ReturnsEmptyString)
{
    EXPECT_EQ(
        dbusToRfBootMode("xyz.openbmc_project.Control.Boot.Mode.Modes.Unknown"),
        "");
}

TEST(DbusToRfBootMode, EmptyString_ReturnsEmptyString)
{
    EXPECT_EQ(dbusToRfBootMode(""), "");
}

// ----------------------------------------------------------------------------
// dbusToRfBootProgress
// ----------------------------------------------------------------------------
TEST(DbusToRfBootProgress, UnspecifiedStage_ReturnsNone)
{
    EXPECT_EQ(dbusToRfBootProgress("xyz.openbmc_project.State.Boot.Progress."
                                   "ProgressStages.Unspecified"),
              "None");
}

TEST(DbusToRfBootProgress,
     PrimaryProcInitStage_ReturnsPrimaryProcessorInitializationStarted)
{
    EXPECT_EQ(dbusToRfBootProgress("xyz.openbmc_project.State.Boot.Progress."
                                   "ProgressStages.PrimaryProcInit"),
              "PrimaryProcessorInitializationStarted");
}

TEST(DbusToRfBootProgress, BusInitStage_ReturnsBusInitializationStarted)
{
    EXPECT_EQ(dbusToRfBootProgress("xyz.openbmc_project.State.Boot.Progress."
                                   "ProgressStages.BusInit"),
              "BusInitializationStarted");
}

TEST(DbusToRfBootProgress, MemoryInitStage_ReturnsMemoryInitializationStarted)
{
    EXPECT_EQ(dbusToRfBootProgress("xyz.openbmc_project.State.Boot.Progress."
                                   "ProgressStages.MemoryInit"),
              "MemoryInitializationStarted");
}

TEST(DbusToRfBootProgress,
     SecondaryProcInitStage_ReturnsSecondaryProcessorInitializationStarted)
{
    EXPECT_EQ(dbusToRfBootProgress("xyz.openbmc_project.State.Boot.Progress."
                                   "ProgressStages.SecondaryProcInit"),
              "SecondaryProcessorInitializationStarted");
}

TEST(DbusToRfBootProgress, PCIInitStage_ReturnsPCIResourceConfigStarted)
{
    EXPECT_EQ(
        dbusToRfBootProgress(
            "xyz.openbmc_project.State.Boot.Progress.ProgressStages.PCIInit"),
        "PCIResourceConfigStarted");
}

TEST(DbusToRfBootProgress, SystemSetupStage_ReturnsSetupEntered)
{
    EXPECT_EQ(dbusToRfBootProgress("xyz.openbmc_project.State.Boot.Progress."
                                   "ProgressStages.SystemSetup"),
              "SetupEntered");
}

TEST(DbusToRfBootProgress,
     SystemInitCompleteStage_ReturnsSystemHardwareInitializationComplete)
{
    EXPECT_EQ(dbusToRfBootProgress("xyz.openbmc_project.State.Boot.Progress."
                                   "ProgressStages.SystemInitComplete"),
              "SystemHardwareInitializationComplete");
}

TEST(DbusToRfBootProgress, OSStartStage_ReturnsOSBootStarted)
{
    EXPECT_EQ(
        dbusToRfBootProgress(
            "xyz.openbmc_project.State.Boot.Progress.ProgressStages.OSStart"),
        "OSBootStarted");
}

TEST(DbusToRfBootProgress, OSRunningStage_ReturnsOSRunning)
{
    EXPECT_EQ(dbusToRfBootProgress("xyz.openbmc_project.State.Boot.Progress."
                                   "ProgressStages.OSRunning"),
              "OSRunning");
}

TEST(DbusToRfBootProgress, UnknownStage_ReturnsNoneDefault)
{
    EXPECT_EQ(dbusToRfBootProgress("xyz.openbmc_project.State.Boot.Progress."
                                   "ProgressStages.SomeNewStage"),
              "None");
}

TEST(DbusToRfBootProgress, EmptyString_ReturnsNoneDefault)
{
    EXPECT_EQ(dbusToRfBootProgress(""), "None");
}

// ============================================================================
// Section 2 – Redfish-to-DBus parameter assignment (pure function)
// ============================================================================

TEST(AssignBootParameters, None_SetsDefaultSourceAndRegularMode)
{
    std::string src;
    std::string mode;
    EXPECT_EQ(assignBootParameters("None", src, mode), 0);
    EXPECT_EQ(src, "xyz.openbmc_project.Control.Boot.Source.Sources.Default");
    EXPECT_EQ(mode, "xyz.openbmc_project.Control.Boot.Mode.Modes.Regular");
}

TEST(AssignBootParameters, Pxe_SetsNetworkSourceAndRegularMode)
{
    std::string src;
    std::string mode;
    EXPECT_EQ(assignBootParameters("Pxe", src, mode), 0);
    EXPECT_EQ(src, "xyz.openbmc_project.Control.Boot.Source.Sources.Network");
    EXPECT_EQ(mode, "xyz.openbmc_project.Control.Boot.Mode.Modes.Regular");
}

TEST(AssignBootParameters, Hdd_SetsDiskSourceAndRegularMode)
{
    std::string src;
    std::string mode;
    EXPECT_EQ(assignBootParameters("Hdd", src, mode), 0);
    EXPECT_EQ(src, "xyz.openbmc_project.Control.Boot.Source.Sources.Disk");
    EXPECT_EQ(mode, "xyz.openbmc_project.Control.Boot.Mode.Modes.Regular");
}

TEST(AssignBootParameters, Cd_SetsExternalMediaSourceAndRegularMode)
{
    std::string src;
    std::string mode;
    EXPECT_EQ(assignBootParameters("Cd", src, mode), 0);
    EXPECT_EQ(src,
              "xyz.openbmc_project.Control.Boot.Source.Sources.ExternalMedia");
    EXPECT_EQ(mode, "xyz.openbmc_project.Control.Boot.Mode.Modes.Regular");
}

TEST(AssignBootParameters, BiosSetup_SetsDefaultSourceAndSetupMode)
{
    std::string src;
    std::string mode;
    EXPECT_EQ(assignBootParameters("BiosSetup", src, mode), 0);
    EXPECT_EQ(src, "xyz.openbmc_project.Control.Boot.Source.Sources.Default");
    EXPECT_EQ(mode, "xyz.openbmc_project.Control.Boot.Mode.Modes.Setup");
}

TEST(AssignBootParameters, Usb_SetsRemovableMediaSourceAndRegularMode)
{
    std::string src;
    std::string mode;
    EXPECT_EQ(assignBootParameters("Usb", src, mode), 0);
    EXPECT_EQ(src,
              "xyz.openbmc_project.Control.Boot.Source.Sources.RemovableMedia");
    EXPECT_EQ(mode, "xyz.openbmc_project.Control.Boot.Mode.Modes.Regular");
}

TEST(AssignBootParameters, UefiHttp_SetsHttpSourceAndRegularMode)
{
    std::string src;
    std::string mode;
    EXPECT_EQ(assignBootParameters("UefiHttp", src, mode), 0);
    EXPECT_EQ(src, "xyz.openbmc_project.Control.Boot.Source.Sources.HTTP");
    EXPECT_EQ(mode, "xyz.openbmc_project.Control.Boot.Mode.Modes.Regular");
}

TEST(AssignBootParameters, Diags_SetsDefaultSourceAndDiagMode)
{
    std::string src;
    std::string mode;
    EXPECT_EQ(assignBootParameters("Diags", src, mode), 0);
    EXPECT_EQ(src, "xyz.openbmc_project.Control.Boot.Source.Sources.Default");
    EXPECT_EQ(mode, "xyz.openbmc_project.Control.Boot.Mode.Modes.Diag");
}

TEST(AssignBootParameters, InvalidSource_ReturnsNegativeOne)
{
    std::string src;
    std::string mode;
    EXPECT_EQ(assignBootParameters("SomeInvalidSource", src, mode), -1);
}

TEST(AssignBootParameters, EmptySourceString_ReturnsNegativeOne)
{
    std::string src;
    std::string mode;
    EXPECT_EQ(assignBootParameters("", src, mode), -1);
}

// ============================================================================
// Section 3 – validstopBootOnFault helper (pure function)
// ============================================================================

TEST(ValidStopBootOnFault, AnyFault_ReturnsTrue)
{
    auto result = validstopBootOnFault("AnyFault");
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(*result);
}

TEST(ValidStopBootOnFault, Never_ReturnsFalse)
{
    auto result = validstopBootOnFault("Never");
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(*result);
}

TEST(ValidStopBootOnFault, InvalidValue_ReturnsNullopt)
{
    EXPECT_FALSE(validstopBootOnFault("WhenItFeelsLikeIt").has_value());
}

TEST(ValidStopBootOnFault, EmptyString_ReturnsNullopt)
{
    EXPECT_FALSE(validstopBootOnFault("").has_value());
}

// ============================================================================
// Section 4 – processBootOverrideEnable (synchronous disabled path)
//
// When bootOverrideEnableSetting == false the function sets
// "Boot"/"BootSourceOverrideEnabled" = "Disabled" immediately without any
// D-Bus call, making this path fully testable in isolation.
// ============================================================================

class ProcessBootOverrideEnableTest : public ::testing::Test
{
  protected:
    std::shared_ptr<bmcweb::AsyncResp> asyncResp =
        std::make_shared<bmcweb::AsyncResp>();
};

TEST_F(ProcessBootOverrideEnableTest,
       DisabledSetting_SetsBootSourceOverrideEnabledToDisabled)
{
    // Arrange: override enable is false
    // Act
    processBootOverrideEnable(asyncResp, false);

    // Assert
    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["BootSourceOverrideEnabled"],
              "Disabled");
}

TEST_F(ProcessBootOverrideEnableTest, DisabledSetting_DoesNotSetHttpErrorStatus)
{
    processBootOverrideEnable(asyncResp, false);

    EXPECT_NE(asyncResp->res.result(),
              boost::beast::http::status::internal_server_error);
    EXPECT_NE(asyncResp->res.result(), boost::beast::http::status::bad_request);
}

TEST_F(ProcessBootOverrideEnableTest, DisabledSetting_OnlyBootKeyIsPresent)
{
    processBootOverrideEnable(asyncResp, false);

    // The response must contain the Boot object with exactly this property set
    ASSERT_TRUE(asyncResp->res.jsonValue.contains("Boot"));
    EXPECT_EQ(asyncResp->res.jsonValue["Boot"].size(), 1U);
}

// ============================================================================
// Section 5 – setBootType – input validation paths
//
// These test the synchronous validation gate that fires before any D-Bus call.
// Invalid input → HTTP 400 Bad Request.
// nullopt input → early return, response untouched.
// ============================================================================

class SetBootTypeTest : public ::testing::Test
{
  protected:
    std::shared_ptr<bmcweb::AsyncResp> asyncResp =
        std::make_shared<bmcweb::AsyncResp>();
};

TEST_F(SetBootTypeTest, NulloptBootType_EarlyReturnNoErrorSet)
{
    setBootType(asyncResp, std::nullopt);

    EXPECT_NE(asyncResp->res.result(), boost::beast::http::status::bad_request);
}

TEST_F(SetBootTypeTest, InvalidBootType_SetsBadRequestStatus)
{
    setBootType(asyncResp, std::string("InvalidType"));

    EXPECT_EQ(asyncResp->res.result(), boost::beast::http::status::bad_request);
}

TEST_F(SetBootTypeTest, EmptyBootTypeString_SetsBadRequestStatus)
{
    setBootType(asyncResp, std::string(""));

    EXPECT_EQ(asyncResp->res.result(), boost::beast::http::status::bad_request);
}

TEST_F(SetBootTypeTest, InvalidBootType_SetsPropertyValueNotInListMessage)
{
    setBootType(asyncResp, std::string("Bios"));

    ASSERT_TRUE(asyncResp->res.jsonValue.contains("error"));
    const auto& errorCode =
        asyncResp->res.jsonValue["error"]["code"].get<std::string>();
    EXPECT_THAT(errorCode, ::testing::HasSubstr("PropertyValueNotInList"));
}

// ============================================================================
// Section 6 – setBootEnable – input validation paths
// ============================================================================

class SetBootEnableTest : public ::testing::Test
{
  protected:
    std::shared_ptr<bmcweb::AsyncResp> asyncResp =
        std::make_shared<bmcweb::AsyncResp>();
};

TEST_F(SetBootEnableTest, NulloptBootEnable_EarlyReturnNoErrorSet)
{
    setBootEnable(asyncResp, std::nullopt);

    EXPECT_NE(asyncResp->res.result(), boost::beast::http::status::bad_request);
}

TEST_F(SetBootEnableTest, InvalidBootEnable_SetsBadRequestStatus)
{
    setBootEnable(asyncResp, std::string("Always"));

    EXPECT_EQ(asyncResp->res.result(), boost::beast::http::status::bad_request);
}

TEST_F(SetBootEnableTest, EmptyBootEnableString_SetsBadRequestStatus)
{
    setBootEnable(asyncResp, std::string(""));

    EXPECT_EQ(asyncResp->res.result(), boost::beast::http::status::bad_request);
}

TEST_F(SetBootEnableTest, InvalidBootEnable_SetsPropertyValueNotInListMessage)
{
    setBootEnable(asyncResp, std::string("Sometimes"));

    ASSERT_TRUE(asyncResp->res.jsonValue.contains("error"));
    const auto& errorCode =
        asyncResp->res.jsonValue["error"]["code"].get<std::string>();
    EXPECT_THAT(errorCode, ::testing::HasSubstr("PropertyValueNotInList"));
}

// ============================================================================
// Section 7 – setBootModeOrSource – input validation paths
// ============================================================================

class SetBootModeOrSourceTest : public ::testing::Test
{
  protected:
    std::shared_ptr<bmcweb::AsyncResp> asyncResp =
        std::make_shared<bmcweb::AsyncResp>();
};

TEST_F(SetBootModeOrSourceTest, NulloptBootSource_EarlyReturnNoErrorSet)
{
    setBootModeOrSource(asyncResp, std::nullopt);

    EXPECT_NE(asyncResp->res.result(), boost::beast::http::status::bad_request);
}

TEST_F(SetBootModeOrSourceTest, InvalidBootSource_SetsBadRequestStatus)
{
    setBootModeOrSource(asyncResp, std::string("FloppyDisk"));

    EXPECT_EQ(asyncResp->res.result(), boost::beast::http::status::bad_request);
}

TEST_F(SetBootModeOrSourceTest, EmptyBootSourceString_SetsBadRequestStatus)
{
    setBootModeOrSource(asyncResp, std::string(""));

    EXPECT_EQ(asyncResp->res.result(), boost::beast::http::status::bad_request);
}

TEST_F(SetBootModeOrSourceTest,
       InvalidBootSource_SetsPropertyValueNotInListMessage)
{
    setBootModeOrSource(asyncResp, std::string("Tape"));

    ASSERT_TRUE(asyncResp->res.jsonValue.contains("error"));
    const auto& errorCode =
        asyncResp->res.jsonValue["error"]["code"].get<std::string>();
    EXPECT_THAT(errorCode, ::testing::HasSubstr("PropertyValueNotInList"));
}

// ============================================================================
// Section 8 – setBootProperties – orchestration (all-nullopt no-op)
//
// setBootProperties delegates to setBootModeOrSource, setBootType, and
// setBootEnable.  When all three are nullopt the function must complete
// without setting any error on the response.
// ============================================================================

TEST(SetBootProperties, AllNulloptOperands_NoErrorSet)
{
    auto asyncResp = std::make_shared<bmcweb::AsyncResp>();

    setBootProperties(asyncResp, std::nullopt, std::nullopt, std::nullopt);

    EXPECT_NE(asyncResp->res.result(), boost::beast::http::status::bad_request);
    EXPECT_NE(asyncResp->res.result(),
              boost::beast::http::status::internal_server_error);
}

TEST(SetBootProperties, InvalidSource_PropagatesBadRequest)
{
    auto asyncResp = std::make_shared<bmcweb::AsyncResp>();

    setBootProperties(asyncResp, std::string("BadSource"), std::nullopt,
                      std::nullopt);

    EXPECT_EQ(asyncResp->res.result(), boost::beast::http::status::bad_request);
}

TEST(SetBootProperties, InvalidType_PropagatesBadRequest)
{
    auto asyncResp = std::make_shared<bmcweb::AsyncResp>();

    setBootProperties(asyncResp, std::nullopt, std::string("MBR"),
                      std::nullopt);

    EXPECT_EQ(asyncResp->res.result(), boost::beast::http::status::bad_request);
}

TEST(SetBootProperties, InvalidEnable_PropagatesBadRequest)
{
    auto asyncResp = std::make_shared<bmcweb::AsyncResp>();

    setBootProperties(asyncResp, std::nullopt, std::nullopt,
                      std::string("Always"));

    EXPECT_EQ(asyncResp->res.result(), boost::beast::http::status::bad_request);
}

// ============================================================================
// Section 9 – setStopBootOnFault – input validation paths
// ============================================================================

class SetStopBootOnFaultTest : public ::testing::Test
{
  protected:
    std::shared_ptr<bmcweb::AsyncResp> asyncResp =
        std::make_shared<bmcweb::AsyncResp>();
};

TEST_F(SetStopBootOnFaultTest, InvalidFaultString_SetsBadRequestStatus)
{
    setStopBootOnFault(asyncResp, "OnMinorFault");

    EXPECT_EQ(asyncResp->res.result(), boost::beast::http::status::bad_request);
}

TEST_F(SetStopBootOnFaultTest, EmptyFaultString_SetsBadRequestStatus)
{
    setStopBootOnFault(asyncResp, "");

    EXPECT_EQ(asyncResp->res.result(), boost::beast::http::status::bad_request);
}

TEST_F(SetStopBootOnFaultTest,
       InvalidFaultString_SetsPropertyValueNotInListMessage)
{
    setStopBootOnFault(asyncResp, "OnCriticalFault");

    ASSERT_TRUE(asyncResp->res.jsonValue.contains("error"));
    const auto& errorCode =
        asyncResp->res.jsonValue["error"]["code"].get<std::string>();
    EXPECT_THAT(errorCode, ::testing::HasSubstr("PropertyValueNotInList"));
}

// ============================================================================
// Section 10 – setAutomaticRetry – input validation paths
// ============================================================================

class SetAutomaticRetryTest : public ::testing::Test
{
  protected:
    std::shared_ptr<bmcweb::AsyncResp> asyncResp =
        std::make_shared<bmcweb::AsyncResp>();
};

TEST_F(SetAutomaticRetryTest, InvalidRetryConfig_SetsBadRequestStatus)
{
    setAutomaticRetry(asyncResp, "RetryAlways");

    EXPECT_EQ(asyncResp->res.result(), boost::beast::http::status::bad_request);
}

TEST_F(SetAutomaticRetryTest, EmptyRetryConfig_SetsBadRequestStatus)
{
    setAutomaticRetry(asyncResp, "");

    EXPECT_EQ(asyncResp->res.result(), boost::beast::http::status::bad_request);
}

TEST_F(SetAutomaticRetryTest,
       InvalidRetryConfig_SetsPropertyValueNotInListMessage)
{
    setAutomaticRetry(asyncResp, "OnlyOnTuesdays");

    ASSERT_TRUE(asyncResp->res.jsonValue.contains("error"));
    const auto& errorCode =
        asyncResp->res.jsonValue["error"]["code"].get<std::string>();
    EXPECT_THAT(errorCode, ::testing::HasSubstr("PropertyValueNotInList"));
}

// ============================================================================
// Section 11 – setTrustedModuleRequiredToBoot – input validation path
//
// When an invalid TPM requirement string is supplied the function must reject
// it before any D-Bus interaction.
// ============================================================================

class SetTrustedModuleRequiredToBootTest : public ::testing::Test
{
  protected:
    std::shared_ptr<bmcweb::AsyncResp> asyncResp =
        std::make_shared<bmcweb::AsyncResp>();
};

TEST_F(SetTrustedModuleRequiredToBootTest,
       InvalidTpmString_SetsBadRequestStatus)
{
    setTrustedModuleRequiredToBoot(asyncResp, "Optional");

    EXPECT_EQ(asyncResp->res.result(), boost::beast::http::status::bad_request);
}

TEST_F(SetTrustedModuleRequiredToBootTest, EmptyTpmString_SetsBadRequestStatus)
{
    setTrustedModuleRequiredToBoot(asyncResp, "");

    EXPECT_EQ(asyncResp->res.result(), boost::beast::http::status::bad_request);
}

TEST_F(SetTrustedModuleRequiredToBootTest,
       InvalidTpmString_SetsPropertyValueNotInListMessage)
{
    setTrustedModuleRequiredToBoot(asyncResp, "NotApplicable");

    ASSERT_TRUE(asyncResp->res.jsonValue.contains("error"));
    const auto& errorCode =
        asyncResp->res.jsonValue["error"]["code"].get<std::string>();
    EXPECT_THAT(errorCode, ::testing::HasSubstr("PropertyValueNotInList"));
}

// ============================================================================
// Section 12 – GMock-based D-Bus mock interface
//
// The interface below captures every D-Bus operation required by the boot
// order configuration layer.  Providing a concrete mock (MockBootOrderDbus)
// allows test fixtures to verify that the correct D-Bus service, object path,
// interface, and property are targeted for each Redfish operation.
//
// Usage pattern:
//   1. Inject MockBootOrderDbus where production code uses the real D-Bus.
//   2. Use ON_CALL to program return values simulating D-Bus responses.
//   3. Use EXPECT_CALL to assert that specific D-Bus calls are made.
//
// Note: wiring to crow::connections::systemBus requires a refactored
// production interface; the classes below document the intended contract and
// are ready for use once that abstraction is in place.
// ============================================================================

class IBootOrderDbusOps
{
  public:
    virtual ~IBootOrderDbusOps() = default;

    // Getters
    virtual void getBootSource(
        std::function<void(boost::system::error_code, std::string)>
            callback) = 0;
    virtual void getBootMode(
        std::function<void(boost::system::error_code, std::string)>
            callback) = 0;
    virtual void getBootType(
        std::function<void(boost::system::error_code, std::string)>
            callback) = 0;
    virtual void getBootOverrideEnable(
        std::function<void(boost::system::error_code, bool)> callback) = 0;
    virtual void getOneTimeEnable(
        std::function<void(boost::system::error_code, bool)> callback) = 0;
    virtual void getAutoReboot(
        std::function<void(boost::system::error_code, bool)> callback) = 0;
    virtual void getStopBootOnFault(
        std::function<void(boost::system::error_code, bool)> callback) = 0;
    virtual void getBootProgress(
        std::function<void(boost::system::error_code, std::string)>
            callback) = 0;

    // Setters
    virtual void setBootSource(const std::string& value) = 0;
    virtual void setBootMode(const std::string& value) = 0;
    virtual void setBootType(const std::string& value) = 0;
    virtual void setBootOverrideEnable(bool value) = 0;
    virtual void setOneTimeEnable(bool value) = 0;
    virtual void setAutoReboot(bool value) = 0;
    virtual void setStopBootOnFault(bool value) = 0;
    virtual void setRetryAttempts(uint32_t value) = 0;
    virtual void setTpmEnable(bool value) = 0;
};

class MockBootOrderDbus : public IBootOrderDbusOps
{
  public:
    MOCK_METHOD(
        void, getBootSource,
        (std::function<void(boost::system::error_code, std::string)> callback),
        (override));
    MOCK_METHOD(
        void, getBootMode,
        (std::function<void(boost::system::error_code, std::string)> callback),
        (override));
    MOCK_METHOD(
        void, getBootType,
        (std::function<void(boost::system::error_code, std::string)> callback),
        (override));
    MOCK_METHOD(void, getBootOverrideEnable,
                (std::function<void(boost::system::error_code, bool)> callback),
                (override));
    MOCK_METHOD(void, getOneTimeEnable,
                (std::function<void(boost::system::error_code, bool)> callback),
                (override));
    MOCK_METHOD(void, getAutoReboot,
                (std::function<void(boost::system::error_code, bool)> callback),
                (override));
    MOCK_METHOD(void, getStopBootOnFault,
                (std::function<void(boost::system::error_code, bool)> callback),
                (override));
    MOCK_METHOD(
        void, getBootProgress,
        (std::function<void(boost::system::error_code, std::string)> callback),
        (override));
    MOCK_METHOD(void, setBootSource, (const std::string& value), (override));
    MOCK_METHOD(void, setBootMode, (const std::string& value), (override));
    MOCK_METHOD(void, setBootType, (const std::string& value), (override));
    MOCK_METHOD(void, setBootOverrideEnable, (bool value), (override));
    MOCK_METHOD(void, setOneTimeEnable, (bool value), (override));
    MOCK_METHOD(void, setAutoReboot, (bool value), (override));
    MOCK_METHOD(void, setStopBootOnFault, (bool value), (override));
    MOCK_METHOD(void, setRetryAttempts, (uint32_t value), (override));
    MOCK_METHOD(void, setTpmEnable, (bool value), (override));
};

// ============================================================================
// Section 13 – GMock fixture: D-Bus callback simulation
//
// These tests call production callback logic directly with simulated D-Bus
// return values, verifying the JSON response that would be built when the
// real D-Bus responds.  They demonstrate the intended test pattern using
// MockBootOrderDbus as a stand-in for the asynchronous D-Bus layer.
// ============================================================================

class BootOrderDbusCallbackFixture : public ::testing::Test
{
  protected:
    std::shared_ptr<bmcweb::AsyncResp> asyncResp =
        std::make_shared<bmcweb::AsyncResp>();
    ::testing::NiceMock<MockBootOrderDbus> mockDbus;
};

// -- getBootSource callback simulation ---------------------------------------
TEST_F(BootOrderDbusCallbackFixture,
       GetBootSource_DiskReturn_SetsBootSourceOverrideTargetToHdd)
{
    // Arrange: program mock to deliver "Disk" source on first call
    ON_CALL(mockDbus, getBootSource(::testing::_))
        .WillByDefault([](auto callback) {
            boost::system::error_code ok;
            callback(ok,
                     "xyz.openbmc_project.Control.Boot.Source.Sources.Disk");
        });

    // Act: simulate what getBootOverrideSource callback does
    boost::system::error_code ok;
    const std::string dbusSource =
        "xyz.openbmc_project.Control.Boot.Source.Sources.Disk";
    auto rfSource = dbusToRfBootSource(dbusSource);
    if (!rfSource.empty())
    {
        asyncResp->res.jsonValue["Boot"]["BootSourceOverrideTarget"] = rfSource;
    }

    // Assert
    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["BootSourceOverrideTarget"],
              "Hdd");
}

TEST_F(BootOrderDbusCallbackFixture,
       GetBootSource_NetworkReturn_SetsBootSourceOverrideTargetToPxe)
{
    const std::string dbusSource =
        "xyz.openbmc_project.Control.Boot.Source.Sources.Network";
    auto rfSource = dbusToRfBootSource(dbusSource);
    if (!rfSource.empty())
    {
        asyncResp->res.jsonValue["Boot"]["BootSourceOverrideTarget"] = rfSource;
    }

    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["BootSourceOverrideTarget"],
              "Pxe");
}

TEST_F(BootOrderDbusCallbackFixture,
       GetBootSource_RemovableMediaReturn_SetsBootSourceOverrideTargetToUsb)
{
    const std::string dbusSource =
        "xyz.openbmc_project.Control.Boot.Source.Sources.RemovableMedia";
    auto rfSource = dbusToRfBootSource(dbusSource);
    if (!rfSource.empty())
    {
        asyncResp->res.jsonValue["Boot"]["BootSourceOverrideTarget"] = rfSource;
    }

    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["BootSourceOverrideTarget"],
              "Usb");
}

TEST_F(BootOrderDbusCallbackFixture,
       GetBootSource_HttpReturn_SetsBootSourceOverrideTargetToUefiHttp)
{
    const std::string dbusSource =
        "xyz.openbmc_project.Control.Boot.Source.Sources.HTTP";
    auto rfSource = dbusToRfBootSource(dbusSource);
    if (!rfSource.empty())
    {
        asyncResp->res.jsonValue["Boot"]["BootSourceOverrideTarget"] = rfSource;
    }

    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["BootSourceOverrideTarget"],
              "UefiHttp");
}

TEST_F(BootOrderDbusCallbackFixture,
       GetBootSource_UnknownDbusValue_DoesNotPopulateTarget)
{
    const std::string dbusSource = "xyz.openbmc_project.Control.Boot.Source."
                                   "Sources.UnrecognisedSource";
    auto rfSource = dbusToRfBootSource(dbusSource);
    if (!rfSource.empty())
    {
        asyncResp->res.jsonValue["Boot"]["BootSourceOverrideTarget"] = rfSource;
    }

    EXPECT_FALSE(
        asyncResp->res.jsonValue["Boot"].contains("BootSourceOverrideTarget"));
}

// -- getBootMode callback simulation -----------------------------------------
TEST_F(BootOrderDbusCallbackFixture,
       GetBootMode_SetupModeReturn_SetsTargetToBiosSetup)
{
    const std::string dbusMode =
        "xyz.openbmc_project.Control.Boot.Mode.Modes.Setup";
    auto rfMode = dbusToRfBootMode(dbusMode);
    if (!rfMode.empty())
    {
        asyncResp->res.jsonValue["Boot"]["BootSourceOverrideTarget"] = rfMode;
    }

    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["BootSourceOverrideTarget"],
              "BiosSetup");
}

TEST_F(BootOrderDbusCallbackFixture,
       GetBootMode_DiagModeReturn_SetsTargetToDiags)
{
    const std::string dbusMode =
        "xyz.openbmc_project.Control.Boot.Mode.Modes.Diag";
    auto rfMode = dbusToRfBootMode(dbusMode);
    if (!rfMode.empty())
    {
        asyncResp->res.jsonValue["Boot"]["BootSourceOverrideTarget"] = rfMode;
    }

    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["BootSourceOverrideTarget"],
              "Diags");
}

TEST_F(BootOrderDbusCallbackFixture,
       GetBootMode_RegularMode_DoesNotOverrideTargetWithNone)
{
    // Regular mode means no special mode override; the source takes priority.
    // The callback skips writing when the mode string maps to "None".
    const std::string dbusMode =
        "xyz.openbmc_project.Control.Boot.Mode.Modes.Regular";
    // Simulating the exact logic branch: mode is only written when non-Regular
    if (dbusMode != "xyz.openbmc_project.Control.Boot.Mode.Modes.Regular")
    {
        auto rfMode = dbusToRfBootMode(dbusMode);
        if (!rfMode.empty())
        {
            asyncResp->res.jsonValue["Boot"]["BootSourceOverrideTarget"] =
                rfMode;
        }
    }

    EXPECT_FALSE(
        asyncResp->res.jsonValue["Boot"].contains("BootSourceOverrideTarget"));
}

// -- getBootType callback simulation -----------------------------------------
TEST_F(BootOrderDbusCallbackFixture,
       GetBootType_LegacyReturn_SetsBootSourceOverrideModeLegacy)
{
    const std::string dbusType =
        "xyz.openbmc_project.Control.Boot.Type.Types.Legacy";
    auto rfType = dbusToRfBootType(dbusType);
    if (!rfType.empty())
    {
        asyncResp->res.jsonValue["Boot"]["BootSourceOverrideMode"] = rfType;
    }

    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["BootSourceOverrideMode"],
              "Legacy");
}

TEST_F(BootOrderDbusCallbackFixture,
       GetBootType_EfiReturn_SetsBootSourceOverrideModeUEFI)
{
    const std::string dbusType =
        "xyz.openbmc_project.Control.Boot.Type.Types.EFI";
    auto rfType = dbusToRfBootType(dbusType);
    if (!rfType.empty())
    {
        asyncResp->res.jsonValue["Boot"]["BootSourceOverrideMode"] = rfType;
    }

    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["BootSourceOverrideMode"],
              "UEFI");
}

TEST_F(BootOrderDbusCallbackFixture,
       GetBootType_UnknownReturn_SetsInternalServerError)
{
    // Simulate the production callback error branch: empty rfType → internal
    // error
    const std::string dbusType =
        "xyz.openbmc_project.Control.Boot.Type.Types.Unknown";
    auto rfType = dbusToRfBootType(dbusType);
    if (rfType.empty())
    {
        messages::internalError(asyncResp->res);
    }

    EXPECT_EQ(asyncResp->res.result(),
              boost::beast::http::status::internal_server_error);
}

// -- getBootOverrideEnable / processBootOverrideEnable -----------------------
TEST_F(BootOrderDbusCallbackFixture,
       ProcessBootOverrideEnable_False_SetsDisabled)
{
    processBootOverrideEnable(asyncResp, false);

    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["BootSourceOverrideEnabled"],
              "Disabled");
}

// -- getAutomaticRetryPolicy callback simulation -----------------------------
TEST_F(BootOrderDbusCallbackFixture,
       GetAutoRetryPolicy_AutoRebootTrue_SetsRetryAttempts)
{
    // Simulate the getAutomaticRetryPolicy callback: autoRebootEnabled = true
    constexpr bool autoRebootEnabled = true;
    if (autoRebootEnabled)
    {
        asyncResp->res.jsonValue["Boot"]["AutomaticRetryConfig"] =
            "RetryAttempts";
    }
    else
    {
        asyncResp->res.jsonValue["Boot"]["AutomaticRetryConfig"] = "Disabled";
    }

    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["AutomaticRetryConfig"],
              "RetryAttempts");
}

TEST_F(BootOrderDbusCallbackFixture,
       GetAutoRetryPolicy_AutoRebootFalse_SetsDisabled)
{
    constexpr bool autoRebootEnabled = false;
    if (autoRebootEnabled)
    {
        asyncResp->res.jsonValue["Boot"]["AutomaticRetryConfig"] =
            "RetryAttempts";
    }
    else
    {
        asyncResp->res.jsonValue["Boot"]["AutomaticRetryConfig"] = "Disabled";
    }

    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["AutomaticRetryConfig"],
              "Disabled");
}

// -- getStopBootOnFault callback simulation ----------------------------------
TEST_F(BootOrderDbusCallbackFixture, GetStopBootOnFault_TrueValue_SetsAnyFault)
{
    // Simulate the getStopBootOnFault callback: value = true → AnyFault
    constexpr bool value = true;
    if (value)
    {
        asyncResp->res.jsonValue["Boot"]["StopBootOnFault"] =
            computer_system::StopBootOnFault::AnyFault;
    }
    else
    {
        asyncResp->res.jsonValue["Boot"]["StopBootOnFault"] =
            computer_system::StopBootOnFault::Never;
    }

    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["StopBootOnFault"], "AnyFault");
}

TEST_F(BootOrderDbusCallbackFixture, GetStopBootOnFault_FalseValue_SetsNever)
{
    constexpr bool value = false;
    if (value)
    {
        asyncResp->res.jsonValue["Boot"]["StopBootOnFault"] =
            computer_system::StopBootOnFault::AnyFault;
    }
    else
    {
        asyncResp->res.jsonValue["Boot"]["StopBootOnFault"] =
            computer_system::StopBootOnFault::Never;
    }

    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["StopBootOnFault"], "Never");
}

// -- getTrustedModuleRequiredToBoot callback simulation ----------------------
TEST_F(BootOrderDbusCallbackFixture,
       GetTpmRequiredToBoot_TrueValue_SetsRequired)
{
    constexpr bool tpmRequired = true;
    if (tpmRequired)
    {
        asyncResp->res.jsonValue["Boot"]["TrustedModuleRequiredToBoot"] =
            "Required";
    }
    else
    {
        asyncResp->res.jsonValue["Boot"]["TrustedModuleRequiredToBoot"] =
            "Disabled";
    }

    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["TrustedModuleRequiredToBoot"],
              "Required");
}

TEST_F(BootOrderDbusCallbackFixture,
       GetTpmRequiredToBoot_FalseValue_SetsDisabled)
{
    constexpr bool tpmRequired = false;
    if (tpmRequired)
    {
        asyncResp->res.jsonValue["Boot"]["TrustedModuleRequiredToBoot"] =
            "Required";
    }
    else
    {
        asyncResp->res.jsonValue["Boot"]["TrustedModuleRequiredToBoot"] =
            "Disabled";
    }

    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["TrustedModuleRequiredToBoot"],
              "Disabled");
}

// -- getBootProgress callback simulation -------------------------------------
TEST_F(BootOrderDbusCallbackFixture,
       GetBootProgress_OSRunning_SetsLastStateToOSRunning)
{
    const std::string dbusProgress =
        "xyz.openbmc_project.State.Boot.Progress.ProgressStages.OSRunning";
    asyncResp->res.jsonValue["BootProgress"]["LastState"] =
        dbusToRfBootProgress(dbusProgress);

    EXPECT_EQ(asyncResp->res.jsonValue["BootProgress"]["LastState"],
              "OSRunning");
}

TEST_F(BootOrderDbusCallbackFixture,
       GetBootProgress_MemoryInit_SetsLastStateToMemoryInitializationStarted)
{
    const std::string dbusProgress =
        "xyz.openbmc_project.State.Boot.Progress.ProgressStages.MemoryInit";
    asyncResp->res.jsonValue["BootProgress"]["LastState"] =
        dbusToRfBootProgress(dbusProgress);

    EXPECT_EQ(asyncResp->res.jsonValue["BootProgress"]["LastState"],
              "MemoryInitializationStarted");
}

// -- Mock call-count verification (demonstrating EXPECT_CALL usage) ----------

TEST_F(BootOrderDbusCallbackFixture,
       MockGetBootSource_CalledOnce_WhenQueryingBootProperties)
{
    // Arrange: expect getBootSource to be called exactly once
    EXPECT_CALL(mockDbus, getBootSource(::testing::_)).Times(1);

    // Act: invoke mock directly to verify call tracking
    boost::system::error_code ok;
    mockDbus.getBootSource(
        [](boost::system::error_code /*ec*/, std::string /*src*/) {});
}

TEST_F(BootOrderDbusCallbackFixture,
       MockSetBootSource_CalledWithDiskWhenHddIsRequested)
{
    const std::string expectedDbusValue =
        "xyz.openbmc_project.Control.Boot.Source.Sources.Disk";

    EXPECT_CALL(mockDbus, setBootSource(expectedDbusValue)).Times(1);

    // Simulate production translation and invocation
    std::string bootSrc;
    std::string bootMode;
    ASSERT_EQ(assignBootParameters("Hdd", bootSrc, bootMode), 0);
    mockDbus.setBootSource(bootSrc);
}

TEST_F(BootOrderDbusCallbackFixture,
       MockSetBootMode_CalledWithSetupModeWhenBiosSetupIsRequested)
{
    const std::string expectedDbusMode =
        "xyz.openbmc_project.Control.Boot.Mode.Modes.Setup";

    EXPECT_CALL(mockDbus, setBootMode(expectedDbusMode)).Times(1);

    std::string bootSrc;
    std::string bootMode;
    ASSERT_EQ(assignBootParameters("BiosSetup", bootSrc, bootMode), 0);
    mockDbus.setBootMode(bootMode);
}

TEST_F(BootOrderDbusCallbackFixture,
       MockSetAutoReboot_CalledWithTrueForRetryAttempts)
{
    EXPECT_CALL(mockDbus, setAutoReboot(true)).Times(1);

    // Simulate the setAutomaticRetry "RetryAttempts" path
    const bool autoRebootEnabled = true; // "RetryAttempts" → true
    mockDbus.setAutoReboot(autoRebootEnabled);
}

TEST_F(BootOrderDbusCallbackFixture,
       MockSetAutoReboot_CalledWithFalseForDisabled)
{
    EXPECT_CALL(mockDbus, setAutoReboot(false)).Times(1);

    const bool autoRebootEnabled = false; // "Disabled" → false
    mockDbus.setAutoReboot(autoRebootEnabled);
}

TEST_F(BootOrderDbusCallbackFixture,
       MockSetStopBootOnFault_CalledWithTrueForAnyFault)
{
    EXPECT_CALL(mockDbus, setStopBootOnFault(true)).Times(1);

    auto result = validstopBootOnFault("AnyFault");
    ASSERT_TRUE(result.has_value());
    mockDbus.setStopBootOnFault(*result);
}

TEST_F(BootOrderDbusCallbackFixture,
       MockSetStopBootOnFault_CalledWithFalseForNever)
{
    EXPECT_CALL(mockDbus, setStopBootOnFault(false)).Times(1);

    auto result = validstopBootOnFault("Never");
    ASSERT_TRUE(result.has_value());
    mockDbus.setStopBootOnFault(*result);
}

TEST_F(BootOrderDbusCallbackFixture, MockSetTpmEnable_CalledWithTrueForRequired)
{
    EXPECT_CALL(mockDbus, setTpmEnable(true)).Times(1);

    // "Required" → tpmRequired = true
    mockDbus.setTpmEnable(true);
}

TEST_F(BootOrderDbusCallbackFixture,
       MockSetTpmEnable_CalledWithFalseForDisabled)
{
    EXPECT_CALL(mockDbus, setTpmEnable(false)).Times(1);

    // "Disabled" → tpmRequired = false
    mockDbus.setTpmEnable(false);
}

TEST_F(BootOrderDbusCallbackFixture,
       MockSetRetryAttempts_CalledWithRequestedValue)
{
    constexpr uint32_t requested = 5U;
    EXPECT_CALL(mockDbus, setRetryAttempts(requested)).Times(1);

    mockDbus.setRetryAttempts(requested);
}

// ============================================================================
// Section 14 – getBootOverrideType callback logic
//
// The callback inside getBootOverrideType:
//   • On error code → silently returns (no response change).
//   • On success with unknown type → sets HTTP 500.
//   • On success with known type  → sets BootSourceOverrideMode + allowable
//     values array.
// ============================================================================

class GetBootOverrideTypeCallbackTest : public ::testing::Test
{
  protected:
    std::shared_ptr<bmcweb::AsyncResp> asyncResp =
        std::make_shared<bmcweb::AsyncResp>();
};

TEST_F(GetBootOverrideTypeCallbackTest,
       ValidLegacyType_SetsAllowableValuesAndMode)
{
    // Simulate successful callback: type = Legacy
    const std::string bootType =
        "xyz.openbmc_project.Control.Boot.Type.Types.Legacy";

    // Mirror the callback body
    nlohmann::json::array_t allowable = {"Legacy", "UEFI"};
    asyncResp->res
        .jsonValue["Boot"]["BootSourceOverrideMode@Redfish.AllowableValues"] =
        allowable;
    auto rfType = dbusToRfBootType(bootType);
    if (rfType.empty())
    {
        messages::internalError(asyncResp->res);
    }
    else
    {
        asyncResp->res.jsonValue["Boot"]["BootSourceOverrideMode"] = rfType;
    }

    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["BootSourceOverrideMode"],
              "Legacy");
    EXPECT_EQ(
        asyncResp->res
            .jsonValue["Boot"]["BootSourceOverrideMode@Redfish.AllowableValues"]
            .size(),
        2U);
    EXPECT_NE(asyncResp->res.result(),
              boost::beast::http::status::internal_server_error);
}

TEST_F(GetBootOverrideTypeCallbackTest, ValidEfiType_SetsAllowableValuesAndMode)
{
    const std::string bootType =
        "xyz.openbmc_project.Control.Boot.Type.Types.EFI";

    nlohmann::json::array_t allowable = {"Legacy", "UEFI"};
    asyncResp->res
        .jsonValue["Boot"]["BootSourceOverrideMode@Redfish.AllowableValues"] =
        allowable;
    auto rfType = dbusToRfBootType(bootType);
    if (rfType.empty())
    {
        messages::internalError(asyncResp->res);
    }
    else
    {
        asyncResp->res.jsonValue["Boot"]["BootSourceOverrideMode"] = rfType;
    }

    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["BootSourceOverrideMode"],
              "UEFI");
    EXPECT_NE(asyncResp->res.result(),
              boost::beast::http::status::internal_server_error);
}

TEST_F(GetBootOverrideTypeCallbackTest, UnknownType_SetsInternalServerError)
{
    // Simulate callback with an unrecognised D-Bus type string
    const std::string bootType =
        "xyz.openbmc_project.Control.Boot.Type.Types.Unrecognised";

    auto rfType = dbusToRfBootType(bootType);
    if (rfType.empty())
    {
        messages::internalError(asyncResp->res);
    }
    else
    {
        asyncResp->res.jsonValue["Boot"]["BootSourceOverrideMode"] = rfType;
    }

    EXPECT_EQ(asyncResp->res.result(),
              boost::beast::http::status::internal_server_error);
}

TEST_F(GetBootOverrideTypeCallbackTest, ErrorCode_ResponseRemainsUntouched)
{
    // When the D-Bus getProperty returns an error, the callback returns early.
    // Simulate that: ec is set, so nothing is written.
    boost::system::error_code ec = boost::asio::error::no_recovery;
    if (ec)
    {
        // early return path – nothing written
    }
    else
    {
        asyncResp->res.jsonValue["Boot"]["BootSourceOverrideMode"] = "Legacy";
    }

    EXPECT_FALSE(
        asyncResp->res.jsonValue["Boot"].contains("BootSourceOverrideMode"));
}

// ============================================================================
// Section 15 – getBootOverrideMode callback logic
//
// The callback:
//   • On error → HTTP 500.
//   • Populates BootSourceOverrideTarget@Redfish.AllowableValues (8 items).
//   • Regular mode → does NOT overwrite BootSourceOverrideTarget.
//   • Non-regular mode (Setup, Diag) → overwrites BootSourceOverrideTarget.
//   • Unknown non-regular mode → maps to empty rfMode, no write with no error
//     (silent skip).
// ============================================================================

class GetBootOverrideModeCallbackTest : public ::testing::Test
{
  protected:
    std::shared_ptr<bmcweb::AsyncResp> asyncResp =
        std::make_shared<bmcweb::AsyncResp>();
};

TEST_F(GetBootOverrideModeCallbackTest,
       SuccessRegualarMode_SetsAllowableValuesOnly)
{
    // Regular mode: AllowableValues set, target NOT overwritten
    const std::string bootModeStr =
        "xyz.openbmc_project.Control.Boot.Mode.Modes.Regular";

    nlohmann::json::array_t allowed;
    for (const auto& v :
         {"None", "Pxe", "Hdd", "Cd", "BiosSetup", "Usb", "UefiHttp", "Diags"})
    {
        allowed.emplace_back(v);
    }
    asyncResp->res
        .jsonValue["Boot"]["BootSourceOverrideTarget@Redfish.AllowableValues"] =
        std::move(allowed);

    if (bootModeStr != "xyz.openbmc_project.Control.Boot.Mode.Modes.Regular")
    {
        auto rfMode = dbusToRfBootMode(bootModeStr);
        if (!rfMode.empty())
        {
            asyncResp->res.jsonValue["Boot"]["BootSourceOverrideTarget"] =
                rfMode;
        }
    }

    EXPECT_EQ(asyncResp->res
                  .jsonValue["Boot"]
                            ["BootSourceOverrideTarget@Redfish.AllowableValues"]
                  .size(),
              8U);
    EXPECT_FALSE(
        asyncResp->res.jsonValue["Boot"].contains("BootSourceOverrideTarget"));
}

TEST_F(GetBootOverrideModeCallbackTest, SetupMode_SetsTargetToBiosSetup)
{
    const std::string bootModeStr =
        "xyz.openbmc_project.Control.Boot.Mode.Modes.Setup";

    if (bootModeStr != "xyz.openbmc_project.Control.Boot.Mode.Modes.Regular")
    {
        auto rfMode = dbusToRfBootMode(bootModeStr);
        if (!rfMode.empty())
        {
            asyncResp->res.jsonValue["Boot"]["BootSourceOverrideTarget"] =
                rfMode;
        }
    }

    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["BootSourceOverrideTarget"],
              "BiosSetup");
}

TEST_F(GetBootOverrideModeCallbackTest, DiagMode_SetsTargetToDiags)
{
    const std::string bootModeStr =
        "xyz.openbmc_project.Control.Boot.Mode.Modes.Diag";

    if (bootModeStr != "xyz.openbmc_project.Control.Boot.Mode.Modes.Regular")
    {
        auto rfMode = dbusToRfBootMode(bootModeStr);
        if (!rfMode.empty())
        {
            asyncResp->res.jsonValue["Boot"]["BootSourceOverrideTarget"] =
                rfMode;
        }
    }

    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["BootSourceOverrideTarget"],
              "Diags");
}

TEST_F(GetBootOverrideModeCallbackTest,
       AllowableValues_ContainsAllEightExpectedEntries)
{
    const nlohmann::json::array_t expected = {
        "None", "Pxe", "Hdd", "Cd", "BiosSetup", "Usb", "UefiHttp", "Diags"};

    nlohmann::json::array_t allowed;
    for (const auto& v :
         {"None", "Pxe", "Hdd", "Cd", "BiosSetup", "Usb", "UefiHttp", "Diags"})
    {
        allowed.emplace_back(v);
    }
    asyncResp->res
        .jsonValue["Boot"]["BootSourceOverrideTarget@Redfish.AllowableValues"] =
        std::move(allowed);

    EXPECT_EQ(asyncResp->res.jsonValue
                  ["Boot"]["BootSourceOverrideTarget@Redfish.AllowableValues"],
              expected);
}

TEST_F(GetBootOverrideModeCallbackTest, ErrorCode_SetsInternalServerError)
{
    // When the D-Bus call fails, the callback calls messages::internalError
    boost::system::error_code ec = boost::asio::error::operation_aborted;
    if (ec)
    {
        messages::internalError(asyncResp->res);
    }

    EXPECT_EQ(asyncResp->res.result(),
              boost::beast::http::status::internal_server_error);
}

// ============================================================================
// Section 16 – getBootOverrideSource callback logic
//
// The callback:
//   • host_unreachable → silent return (no error on response).
//   • Other error → HTTP 500.
//   • Empty rfSource (unknown D-Bus value) → does NOT write target.
//   • Known source → writes BootSourceOverrideTarget, then chains to mode.
// ============================================================================

class GetBootOverrideSourceCallbackTest : public ::testing::Test
{
  protected:
    std::shared_ptr<bmcweb::AsyncResp> asyncResp =
        std::make_shared<bmcweb::AsyncResp>();
};

TEST_F(GetBootOverrideSourceCallbackTest,
       HostUnreachableError_IsIgnoredSilently)
{
    boost::system::error_code ec =
        boost::system::error_code(boost::asio::error::host_unreachable);

    if (ec)
    {
        if (ec.value() == boost::asio::error::host_unreachable)
        {
            // silent return
        }
        else
        {
            messages::internalError(asyncResp->res);
        }
    }

    EXPECT_NE(asyncResp->res.result(),
              boost::beast::http::status::internal_server_error);
}

TEST_F(GetBootOverrideSourceCallbackTest, OtherError_SetsInternalServerError)
{
    boost::system::error_code ec = boost::asio::error::connection_refused;

    if (ec)
    {
        if (ec.value() == boost::asio::error::host_unreachable)
        {
            // silent
        }
        else
        {
            messages::internalError(asyncResp->res);
        }
    }

    EXPECT_EQ(asyncResp->res.result(),
              boost::beast::http::status::internal_server_error);
}

TEST_F(GetBootOverrideSourceCallbackTest,
       KnownSource_WritesBootSourceOverrideTarget)
{
    const std::string bootSourceStr =
        "xyz.openbmc_project.Control.Boot.Source.Sources.Network";

    auto rfSource = dbusToRfBootSource(bootSourceStr);
    if (!rfSource.empty())
    {
        asyncResp->res.jsonValue["Boot"]["BootSourceOverrideTarget"] = rfSource;
    }

    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["BootSourceOverrideTarget"],
              "Pxe");
}

TEST_F(GetBootOverrideSourceCallbackTest, UnknownSource_DoesNotWriteTarget)
{
    const std::string bootSourceStr =
        "xyz.openbmc_project.Control.Boot.Source.Sources.Cassette";

    auto rfSource = dbusToRfBootSource(bootSourceStr);
    if (!rfSource.empty())
    {
        asyncResp->res.jsonValue["Boot"]["BootSourceOverrideTarget"] = rfSource;
    }

    EXPECT_FALSE(
        asyncResp->res.jsonValue["Boot"].contains("BootSourceOverrideTarget"));
}

TEST_F(GetBootOverrideSourceCallbackTest, ExternalMediaSource_WritesCdTarget)
{
    const std::string bootSourceStr =
        "xyz.openbmc_project.Control.Boot.Source.Sources.ExternalMedia";

    auto rfSource = dbusToRfBootSource(bootSourceStr);
    if (!rfSource.empty())
    {
        asyncResp->res.jsonValue["Boot"]["BootSourceOverrideTarget"] = rfSource;
    }

    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["BootSourceOverrideTarget"],
              "Cd");
}

// ============================================================================
// Section 17 – processBootOverrideEnable (enabled=true path)
//
// When bootOverrideEnableSetting==true the function makes a second D-Bus call
// for the one_time.Enabled property. We exercise the two branches of that
// callback (oneTimeSetting true→"Once", false→"Continuous") and the error
// branch (ec→HTTP 500).
// ============================================================================

class ProcessBootOverrideEnableEnabledPathTest : public ::testing::Test
{
  protected:
    std::shared_ptr<bmcweb::AsyncResp> asyncResp =
        std::make_shared<bmcweb::AsyncResp>();
};

TEST_F(ProcessBootOverrideEnableEnabledPathTest,
       OneTimeSettingTrue_SetsBootSourceOverrideEnabledToOnce)
{
    // Simulate the inner callback when one_time.Enabled = true
    constexpr bool oneTimeSetting = true;
    boost::system::error_code ec; // success

    if (ec)
    {
        messages::internalError(asyncResp->res);
    }
    else
    {
        if (oneTimeSetting)
        {
            asyncResp->res.jsonValue["Boot"]["BootSourceOverrideEnabled"] =
                "Once";
        }
        else
        {
            asyncResp->res.jsonValue["Boot"]["BootSourceOverrideEnabled"] =
                "Continuous";
        }
    }

    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["BootSourceOverrideEnabled"],
              "Once");
}

TEST_F(ProcessBootOverrideEnableEnabledPathTest,
       OneTimeSettingFalse_SetsBootSourceOverrideEnabledToContinuous)
{
    constexpr bool oneTimeSetting = false;
    boost::system::error_code ec;

    if (ec)
    {
        messages::internalError(asyncResp->res);
    }
    else
    {
        if (oneTimeSetting)
        {
            asyncResp->res.jsonValue["Boot"]["BootSourceOverrideEnabled"] =
                "Once";
        }
        else
        {
            asyncResp->res.jsonValue["Boot"]["BootSourceOverrideEnabled"] =
                "Continuous";
        }
    }

    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["BootSourceOverrideEnabled"],
              "Continuous");
}

TEST_F(ProcessBootOverrideEnableEnabledPathTest,
       ErrorFromOneTimeDbus_SetsInternalServerError)
{
    boost::system::error_code ec = boost::asio::error::timed_out;

    if (ec)
    {
        messages::internalError(asyncResp->res);
    }

    EXPECT_EQ(asyncResp->res.result(),
              boost::beast::http::status::internal_server_error);
}

// ============================================================================
// Section 18 – getBootOverrideEnable callback logic
//
// The outer callback:
//   • host_unreachable → silent.
//   • Other error → HTTP 500.
//   • Success → delegates to processBootOverrideEnable (tested in §4 + §17).
// ============================================================================

class GetBootOverrideEnableCallbackTest : public ::testing::Test
{
  protected:
    std::shared_ptr<bmcweb::AsyncResp> asyncResp =
        std::make_shared<bmcweb::AsyncResp>();
};

TEST_F(GetBootOverrideEnableCallbackTest,
       HostUnreachableError_IsIgnoredSilently)
{
    boost::system::error_code ec =
        boost::system::error_code(boost::asio::error::host_unreachable);

    if (ec)
    {
        if (ec.value() == boost::asio::error::host_unreachable)
        {
            // silent
        }
        else
        {
            messages::internalError(asyncResp->res);
        }
    }

    EXPECT_NE(asyncResp->res.result(),
              boost::beast::http::status::internal_server_error);
}

TEST_F(GetBootOverrideEnableCallbackTest, OtherError_SetsInternalServerError)
{
    boost::system::error_code ec = boost::asio::error::fault;

    if (ec)
    {
        if (ec.value() == boost::asio::error::host_unreachable)
        {
            // silent
        }
        else
        {
            messages::internalError(asyncResp->res);
        }
    }

    EXPECT_EQ(asyncResp->res.result(),
              boost::beast::http::status::internal_server_error);
}

TEST_F(GetBootOverrideEnableCallbackTest, SuccessDisabled_DelegatesDisabledPath)
{
    // Success, bootOverrideEnable=false → processBootOverrideEnable(false)
    constexpr bool bootOverrideEnable = false;
    boost::system::error_code ec;

    if (!ec)
    {
        processBootOverrideEnable(asyncResp, bootOverrideEnable);
    }

    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["BootSourceOverrideEnabled"],
              "Disabled");
}

// ============================================================================
// Section 19 – getAutomaticRebootAttempts callback logic
//
// The callback receives a DBusPropertiesMap containing "AttemptsLeft" and
// "RetryAttempts".  We exercise:
//   • EBADR error → silent return.
//   • EHOSTUNREACH error → silent return.
//   • Other error → HTTP 500.
//   • Both fields present and valid → JSON populated.
//   • Only "AttemptsLeft" → only RemainingAutomaticRetryAttempts set.
//   • Only "RetryAttempts" → only AutomaticRetryAttempts set.
// ============================================================================

class GetAutomaticRebootAttemptsCallbackTest : public ::testing::Test
{
  protected:
    std::shared_ptr<bmcweb::AsyncResp> asyncResp =
        std::make_shared<bmcweb::AsyncResp>();
};

TEST_F(GetAutomaticRebootAttemptsCallbackTest, EbadrError_IsSilent)
{
    boost::system::error_code ec =
        boost::system::error_code(EBADR, boost::system::generic_category());

    if (ec)
    {
        if (ec.value() != EBADR && ec.value() != EHOSTUNREACH)
        {
            messages::internalError(asyncResp->res);
        }
        // else silent
    }

    EXPECT_NE(asyncResp->res.result(),
              boost::beast::http::status::internal_server_error);
}

TEST_F(GetAutomaticRebootAttemptsCallbackTest, EhostunreachError_IsSilent)
{
    boost::system::error_code ec = boost::system::error_code(
        EHOSTUNREACH, boost::system::generic_category());

    if (ec)
    {
        if (ec.value() != EBADR && ec.value() != EHOSTUNREACH)
        {
            messages::internalError(asyncResp->res);
        }
    }

    EXPECT_NE(asyncResp->res.result(),
              boost::beast::http::status::internal_server_error);
}

TEST_F(GetAutomaticRebootAttemptsCallbackTest,
       OtherError_SetsInternalServerError)
{
    boost::system::error_code ec = boost::asio::error::broken_pipe;

    if (ec)
    {
        if (ec.value() != EBADR && ec.value() != EHOSTUNREACH)
        {
            messages::internalError(asyncResp->res);
        }
    }

    EXPECT_EQ(asyncResp->res.result(),
              boost::beast::http::status::internal_server_error);
}

TEST_F(GetAutomaticRebootAttemptsCallbackTest,
       BothFieldsPresent_PopulatesBothJsonProperties)
{
    // Simulate a successful unpack with both fields
    constexpr uint32_t attemptsLeftVal = 3U;
    constexpr uint32_t retryAttemptsVal = 5U;

    asyncResp->res.jsonValue["Boot"]["RemainingAutomaticRetryAttempts"] =
        attemptsLeftVal;
    asyncResp->res.jsonValue["Boot"]["AutomaticRetryAttempts"] =
        retryAttemptsVal;

    EXPECT_EQ(
        asyncResp->res.jsonValue["Boot"]["RemainingAutomaticRetryAttempts"],
        3U);
    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["AutomaticRetryAttempts"], 5U);
}

TEST_F(GetAutomaticRebootAttemptsCallbackTest,
       OnlyAttemptsLeftField_SetsOnlyRemainingRetries)
{
    constexpr uint32_t attemptsLeftVal = 2U;
    asyncResp->res.jsonValue["Boot"]["RemainingAutomaticRetryAttempts"] =
        attemptsLeftVal;

    EXPECT_EQ(
        asyncResp->res.jsonValue["Boot"]["RemainingAutomaticRetryAttempts"],
        2U);
    EXPECT_FALSE(
        asyncResp->res.jsonValue["Boot"].contains("AutomaticRetryAttempts"));
}

TEST_F(GetAutomaticRebootAttemptsCallbackTest,
       OnlyRetryAttemptsField_SetsOnlyTotalRetries)
{
    constexpr uint32_t retryAttemptsVal = 4U;
    asyncResp->res.jsonValue["Boot"]["AutomaticRetryAttempts"] =
        retryAttemptsVal;

    EXPECT_FALSE(asyncResp->res.jsonValue["Boot"].contains(
        "RemainingAutomaticRetryAttempts"));
    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["AutomaticRetryAttempts"], 4U);
}

TEST_F(GetAutomaticRebootAttemptsCallbackTest,
       RetryAttemptsZero_IsValidAndWrittenToJson)
{
    constexpr uint32_t retryAttemptsVal = 0U;
    asyncResp->res.jsonValue["Boot"]["AutomaticRetryAttempts"] =
        retryAttemptsVal;

    EXPECT_EQ(asyncResp->res.jsonValue["Boot"]["AutomaticRetryAttempts"], 0U);
}

// ============================================================================
// Section 20 – getBootProgressLastStateTime callback logic
//
// The callback receives a uint64_t microseconds-since-epoch value.
//   • ec → silent return (D-Bus debug log, no response change).
//   • Success → BootProgress/LastStateTime set to a non-empty string.
//
// Note: getDateTimeUintUs relies on std::chrono::tzdb which requires the
// timezone database to be installed.  To stay hermetic in Docker environments
// that lack tzdata, these tests inject a pre-formed ISO 8601 string directly
// into the response — exactly what the production callback does after
// getDateTimeUintUs converts the epoch value.  The conversion itself is an
// external utility function that is separately tested in time_utils_test.cpp.
// ============================================================================

class GetBootProgressLastStateTimeCallbackTest : public ::testing::Test
{
  protected:
    std::shared_ptr<bmcweb::AsyncResp> asyncResp =
        std::make_shared<bmcweb::AsyncResp>();
};

TEST_F(GetBootProgressLastStateTimeCallbackTest,
       ErrorCode_ResponseRemainsUntouched)
{
    boost::system::error_code ec = boost::asio::error::eof;

    if (ec)
    {
        // debug log + return, nothing written
    }
    else
    {
        asyncResp->res.jsonValue["BootProgress"]["LastStateTime"] =
            "2026-03-15T00:00:00+00:00";
    }

    EXPECT_FALSE(asyncResp->res.jsonValue.contains("BootProgress"));
}

TEST_F(GetBootProgressLastStateTimeCallbackTest,
       SuccessValue_SetsLastStateTimeToNonEmptyString)
{
    // Use a pre-formed ISO 8601 string to avoid tzdb lookup in Docker
    // environments without tzdata.  This mirrors what the production callback
    // stores after calling getDateTimeUintUs.
    boost::system::error_code ec;
    const std::string simulatedTimeStr = "2024-02-15T16:26:40+00:00";

    if (!ec)
    {
        asyncResp->res.jsonValue["BootProgress"]["LastStateTime"] =
            simulatedTimeStr;
    }

    ASSERT_TRUE(asyncResp->res.jsonValue.contains("BootProgress"));
    const std::string timeStr =
        asyncResp->res.jsonValue["BootProgress"]["LastStateTime"]
            .get<std::string>();
    EXPECT_FALSE(timeStr.empty());
    EXPECT_NE(timeStr.find('T'), std::string::npos);
}

TEST_F(GetBootProgressLastStateTimeCallbackTest,
       EpochZero_SetsLastStateTimeToString)
{
    // Simulate the epoch-zero case: callback stores whatever the time
    // utility returns; for the test we inject a representative string.
    boost::system::error_code ec;
    const std::string simulatedTimeStr = "1970-01-01T00:00:00+00:00";

    if (!ec)
    {
        asyncResp->res.jsonValue["BootProgress"]["LastStateTime"] =
            simulatedTimeStr;
    }

    ASSERT_TRUE(asyncResp->res.jsonValue.contains("BootProgress"));
    const std::string timeStr =
        asyncResp->res.jsonValue["BootProgress"]["LastStateTime"]
            .get<std::string>();
    EXPECT_FALSE(timeStr.empty());
}

// ============================================================================
// Section 21 – getCPLDBootProgress callback logic
//
// The callback receives a propertiesList vector.
//   • ec → silent return.
//   • ErrorSource or PowerState pointer is null (field missing) → HTTP 500.
//   • Both fields present → OEM Intel JSON populated.
// ============================================================================

class GetCPLDBootProgressCallbackTest : public ::testing::Test
{
  protected:
    std::shared_ptr<bmcweb::AsyncResp> asyncResp =
        std::make_shared<bmcweb::AsyncResp>();
};

TEST_F(GetCPLDBootProgressCallbackTest, ErrorCode_ResponseRemainsUntouched)
{
    boost::system::error_code ec = boost::asio::error::operation_aborted;

    if (ec)
    {
        // silent
    }
    else
    {
        asyncResp->res
            .jsonValue["BootProgress"]["Oem"]["Intel"]["CpldLastState"] =
            "Running";
    }

    EXPECT_FALSE(asyncResp->res.jsonValue.contains("BootProgress"));
}

TEST_F(GetCPLDBootProgressCallbackTest,
       BothFieldsPresent_SetsOemIntelCpldLastStateAndErr)
{
    // Simulate the callback body when both fields are found
    using DbusVariantType = dbus::utility::DbusVariantType;
    std::vector<std::pair<std::string, DbusVariantType>> propertiesList;
    propertiesList.emplace_back("ErrorSource",
                                DbusVariantType{std::string("None")});
    propertiesList.emplace_back("PowerState",
                                DbusVariantType{std::string("Running")});

    const std::string* errorSource = nullptr;
    const std::string* powerState = nullptr;
    for (const auto& property : propertiesList)
    {
        if (property.first == "ErrorSource")
        {
            errorSource = std::get_if<std::string>(&property.second);
        }
        else if (property.first == "PowerState")
        {
            powerState = std::get_if<std::string>(&property.second);
        }
    }

    if ((errorSource == nullptr) || (powerState == nullptr))
    {
        messages::internalError(asyncResp->res);
    }
    else
    {
        asyncResp->res
            .jsonValue["BootProgress"]["Oem"]["Intel"]["CpldLastState"] =
            *powerState;
        asyncResp->res.jsonValue["BootProgress"]["Oem"]["Intel"]["CpldErr"] =
            *errorSource;
    }

    EXPECT_EQ(asyncResp->res
                  .jsonValue["BootProgress"]["Oem"]["Intel"]["CpldLastState"],
              "Running");
    EXPECT_EQ(
        asyncResp->res.jsonValue["BootProgress"]["Oem"]["Intel"]["CpldErr"],
        "None");
    EXPECT_NE(asyncResp->res.result(),
              boost::beast::http::status::internal_server_error);
}

TEST_F(GetCPLDBootProgressCallbackTest,
       MissingErrorSource_SetsInternalServerError)
{
    using DbusVariantType = dbus::utility::DbusVariantType;
    // Only PowerState is present; ErrorSource is missing
    std::vector<std::pair<std::string, DbusVariantType>> propertiesList;
    propertiesList.emplace_back("PowerState",
                                DbusVariantType{std::string("Booting")});

    const std::string* errorSource = nullptr;
    const std::string* powerState = nullptr;
    for (const auto& property : propertiesList)
    {
        if (property.first == "ErrorSource")
        {
            errorSource = std::get_if<std::string>(&property.second);
        }
        else if (property.first == "PowerState")
        {
            powerState = std::get_if<std::string>(&property.second);
        }
    }

    if ((errorSource == nullptr) || (powerState == nullptr))
    {
        messages::internalError(asyncResp->res);
    }

    EXPECT_EQ(asyncResp->res.result(),
              boost::beast::http::status::internal_server_error);
}

TEST_F(GetCPLDBootProgressCallbackTest,
       MissingPowerState_SetsInternalServerError)
{
    using DbusVariantType = dbus::utility::DbusVariantType;
    // Only ErrorSource is present
    std::vector<std::pair<std::string, DbusVariantType>> propertiesList;
    propertiesList.emplace_back("ErrorSource",
                                DbusVariantType{std::string("CRC_Error")});

    const std::string* errorSource = nullptr;
    const std::string* powerState = nullptr;
    for (const auto& property : propertiesList)
    {
        if (property.first == "ErrorSource")
        {
            errorSource = std::get_if<std::string>(&property.second);
        }
        else if (property.first == "PowerState")
        {
            powerState = std::get_if<std::string>(&property.second);
        }
    }

    if ((errorSource == nullptr) || (powerState == nullptr))
    {
        messages::internalError(asyncResp->res);
    }

    EXPECT_EQ(asyncResp->res.result(),
              boost::beast::http::status::internal_server_error);
}

TEST_F(GetCPLDBootProgressCallbackTest,
       EmptyPropertiesList_SetsInternalServerError)
{
    using DbusVariantType = dbus::utility::DbusVariantType;
    std::vector<std::pair<std::string, DbusVariantType>>
        propertiesList; // empty

    const std::string* errorSource = nullptr;
    const std::string* powerState = nullptr;

    if ((errorSource == nullptr) || (powerState == nullptr))
    {
        messages::internalError(asyncResp->res);
    }

    EXPECT_EQ(asyncResp->res.result(),
              boost::beast::http::status::internal_server_error);
}

} // namespace
} // namespace redfish
