// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
// SPDX-FileCopyrightText: Copyright 2019 Intel Corporation
#pragma once

#include "app.hpp"
#include "async_resp.hpp"
#include "dbus_utility.hpp"
#include "generated/enums/chassis.hpp"
#include "redfish_util.hpp"
#include "utils/json_utils.hpp"

#include <boost/algorithm/string/predicate.hpp>
#include <sdbusplus/asio/property.hpp>

namespace redfish
{
/**
 * @brief Retrieves identify led group properties over dbus
 *
 * @param[in] asyncResp     Shared pointer for generating response message.
 *
 * @return None.
 */
// TODO (Gunnar): Remove IndicatorLED after enough time has passed
inline void getIndicatorLedState(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    BMCWEB_LOG_DEBUG("Get led groups");
    dbus::utility::getProperty<bool>(
        "xyz.openbmc_project.LED.GroupManager",
        "/xyz/openbmc_project/led/groups/enclosure_identify_blink",
        "xyz.openbmc_project.Led.Group", "Asserted",
        [asyncResp](const boost::system::error_code& ec, const bool blinking) {
            // Some systems may not have enclosure_identify_blink object so
            // proceed to get enclosure_identify state.
            if (ec == boost::system::errc::invalid_argument)
            {
                BMCWEB_LOG_DEBUG(
                    "Get identity blinking LED failed, mismatch in property type");
                messages::internalError(asyncResp->res);
                return;
            }

            // Blinking ON, no need to check enclosure_identify assert.
            if (!ec && blinking)
            {
                asyncResp->res.jsonValue["IndicatorLED"] =
                    chassis::IndicatorLED::Blinking;
                return;
            }

            dbus::utility::getProperty<bool>(
                "xyz.openbmc_project.LED.GroupManager",
                "/xyz/openbmc_project/led/groups/enclosure_identify",
                "xyz.openbmc_project.Led.Group", "Asserted",
                [asyncResp](const boost::system::error_code& ec2,
                            const bool ledOn) {
                    if (ec2 == boost::system::errc::invalid_argument)
                    {
                        BMCWEB_LOG_DEBUG(
                            "Get enclosure identity led failed, mismatch in property type");
                        messages::internalError(asyncResp->res);
                        return;
                    }

                    if (ec2)
                    {
                        return;
                    }

                    if (ledOn)
                    {
                        asyncResp->res.jsonValue["IndicatorLED"] =
                            chassis::IndicatorLED::Lit;
                    }
                    else
                    {
                        asyncResp->res.jsonValue["IndicatorLED"] =
                            chassis::IndicatorLED::Off;
                    }
                });
        });
}

/**
 * @brief Sets identify led group properties
 *
 * @param[in] asyncResp     Shared pointer for generating response message.
 * @param[in] ledState  LED state passed from request
 *
 * @return None.
 */
// TODO (Gunnar): Remove IndicatorLED after enough time has passed
inline void setIndicatorLedState(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& ledState)
{
    BMCWEB_LOG_DEBUG("Set led groups");
    bool ledOn = false;
    bool ledBlinkng = false;

    if (ledState == "Lit")
    {
        ledOn = true;
    }
    else if (ledState == "Blinking")
    {
        ledBlinkng = true;
    }
    else if (ledState != "Off")
    {
        messages::propertyValueNotInList(asyncResp->res, ledState,
                                         "IndicatorLED");
        return;
    }

    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, "xyz.openbmc_project.LED.GroupManager",
        "/xyz/openbmc_project/led/groups/enclosure_identify_blink",
        "xyz.openbmc_project.Led.Group", "Asserted", ledBlinkng,
        [asyncResp, ledOn,
         ledBlinkng](const boost::system::error_code& ec) mutable {
            if (ec)
            {
                // Some systems may not have enclosure_identify_blink object so
                // Lets set enclosure_identify state to true if Blinking is
                // true.
                if (ledBlinkng)
                {
                    ledOn = true;
                }
            }
            setDbusProperty(
                asyncResp, "IndicatorLED",
                "xyz.openbmc_project.LED.GroupManager",
                sdbusplus::message::object_path(
                    "/xyz/openbmc_project/led/groups/enclosure_identify"),
                "xyz.openbmc_project.Led.Group", "Asserted", ledBlinkng);
        });
}

/**
 * @brief Retrieves identify system led group properties over dbus
 *
 * @param[in] asyncResp     Shared pointer for generating response message.
 *
 * @return None.
 */
inline void getSystemLocationIndicatorActive(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    BMCWEB_LOG_DEBUG("Get LocationIndicatorActive");
    dbus::utility::getProperty<bool>(
        "xyz.openbmc_project.LED.GroupManager",
        "/xyz/openbmc_project/led/groups/enclosure_identify_blink",
        "xyz.openbmc_project.Led.Group", "Asserted",
        [asyncResp](const boost::system::error_code& ec, const bool blinking) {
            // Some systems may not have enclosure_identify_blink object so
            // proceed to get enclosure_identify state.
            if (ec == boost::system::errc::invalid_argument)
            {
                BMCWEB_LOG_DEBUG(
                    "Get identity blinking LED failed, mismatch in property type");
                messages::internalError(asyncResp->res);
                return;
            }

            // Blinking ON, no need to check enclosure_identify assert.
            if (!ec && blinking)
            {
                asyncResp->res.jsonValue["LocationIndicatorActive"] = true;
                return;
            }

            dbus::utility::getProperty<bool>(
                "xyz.openbmc_project.LED.GroupManager",
                "/xyz/openbmc_project/led/groups/enclosure_identify",
                "xyz.openbmc_project.Led.Group", "Asserted",
                [asyncResp](const boost::system::error_code& ec2,
                            const bool ledOn) {
                    if (ec2 == boost::system::errc::invalid_argument)
                    {
                        BMCWEB_LOG_DEBUG(
                            "Get enclosure identity led failed, mismatch in property type");
                        messages::internalError(asyncResp->res);
                        return;
                    }

                    if (ec2)
                    {
                        return;
                    }

                    asyncResp->res.jsonValue["LocationIndicatorActive"] = ledOn;
                });
        });
}

/**
 * @brief Sets identify system led group properties
 *
 * @param[in] asyncResp     Shared pointer for generating response message.
 * @param[in] ledState  LED state passed from request
 *
 * @return None.
 */
inline void setSystemLocationIndicatorActive(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp, const bool ledState)
{
    BMCWEB_LOG_DEBUG("Set LocationIndicatorActive");

    sdbusplus::asio::setProperty(
        *crow::connections::systemBus, "xyz.openbmc_project.LED.GroupManager",
        "/xyz/openbmc_project/led/groups/enclosure_identify_blink",
        "xyz.openbmc_project.Led.Group", "Asserted", ledState,
        [asyncResp, ledState](const boost::system::error_code& ec) {
            if (ec)
            {
                // Some systems may not have enclosure_identify_blink object so
                // lets set enclosure_identify state also if
                // enclosure_identify_blink failed
                setDbusProperty(
                    asyncResp, "LocationIndicatorActive",
                    "xyz.openbmc_project.LED.GroupManager",
                    sdbusplus::message::object_path(
                        "/xyz/openbmc_project/led/groups/enclosure_identify"),
                    "xyz.openbmc_project.Led.Group", "Asserted", ledState);
            }
        });
}

inline void setPhysicalLedState(const std::shared_ptr<bmcweb::AsyncResp>& aResp,
                                const std::string& led,
                                const std::string& state)
{
    if (!state.compare("On"))
    {
        aResp->res.jsonValue["Oem"]["Ami"]["PhysicalLED"][led] = "On";
    }
    else if (!state.compare("Blink"))
    {
        aResp->res.jsonValue["Oem"]["Ami"]["PhysicalLED"][led] = "Blinking";
    }
    else if (!state.compare("Off"))
    {
        aResp->res.jsonValue["Oem"]["Ami"]["PhysicalLED"][led] = "Off";
    }
    else
    {
        aResp->res.jsonValue["Oem"]["Ami"]["PhysicalLED"][led] = "Unknown";
    }
}

inline void getPhysicalLedState(const std::shared_ptr<bmcweb::AsyncResp>& aResp)
{
    BMCWEB_LOG_DEBUG("Get Physical Led");
    aResp->res.jsonValue["Oem"]["Ami"]["PhysicalLED"]["@odata.type"] =
        json_util::odataType("OpenBMCComputerSystem", "PhysicalLED");

    dbus::utility::getProperty<bool>(
        "xyz.openbmc_project.LED.GroupManager",
        "/xyz/openbmc_project/led/groups/status_critical",
        "xyz.openbmc_project.Led.Group", "Asserted",
        [aResp](const boost::system::error_code ec, const bool amberLedState) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("Get Physical State Amber Led: DBus Error",
                                 ec);
                return;
            }
            if (!amberLedState)
            {
                dbus::utility::getProperty<bool>(
                    "xyz.openbmc_project.LED.GroupManager",
                    "/xyz/openbmc_project/led/groups/status_non_critical",
                    "xyz.openbmc_project.Led.Group", "Asserted",
                    [aResp](const boost::system::error_code ec1,
                            const bool amberLedState1) {
                        if (ec1)
                        {
                            BMCWEB_LOG_ERROR(
                                "Get Physical State Amber Led: DBus Error",
                                ec1);
                            return;
                        }
                        std::string amberLed = amberLedState1 ? "Blink" : "Off";
                        setPhysicalLedState(aResp, "AmberLED", amberLed);
                    });
            }
            else
            {
                setPhysicalLedState(aResp, "AmberLED", "On");
            }
        });
    dbus::utility::getProperty<bool>(
        "xyz.openbmc_project.LED.GroupManager",
        "/xyz/openbmc_project/led/groups/status_degraded",
        "xyz.openbmc_project.Led.Group", "Asserted",
        [aResp](const boost::system::error_code ec, const bool greenLedState) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("Get Physical State Green Led: DBus Error",
                                 ec);
                return;
            }
            if (!greenLedState)
            {
                dbus::utility::getProperty<bool>(
                    "xyz.openbmc_project.LED.GroupManager",
                    "/xyz/openbmc_project/led/groups/status_ok",
                    "xyz.openbmc_project.Led.Group", "Asserted",
                    [aResp](const boost::system::error_code ec1,
                            const bool greenLedState1) {
                        if (ec1)
                        {
                            BMCWEB_LOG_ERROR(
                                "Get Physical State Green Led: DBus Error",
                                ec1);
                            return;
                        }
                        std::string greenLed = greenLedState1 ? "Blink" : "Off";
                        setPhysicalLedState(aResp, "GreenLED", greenLed);
                    });
            }
            else
            {
                setPhysicalLedState(aResp, "GreenLED", "On");
            }
        });

    dbus::utility::getProperty<bool>(
        "xyz.openbmc_project.LED.GroupManager",
        "/xyz/openbmc_project/led/groups/enclosure_identify_blink",
        "xyz.openbmc_project.Led.Group", "Asserted",
        [aResp](const boost::system::error_code& ec, const bool blueLedState) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("Get Physical State Blue Led: DBus Error", ec);
                return;
            }
            std::string SolidblueLed = blueLedState ? "Blink" : "Off";
            setPhysicalLedState(aResp, "BlueLED", SolidblueLed);
        });
}
} // namespace redfish
