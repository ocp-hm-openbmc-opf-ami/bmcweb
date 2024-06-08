/*
// Copyright (c) 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/
#pragma once

#include "app.hpp"
#include "async_resp.hpp"
#include "dbus_utility.hpp"
#include "redfish_util.hpp"

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
inline void
    getIndicatorLedState(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    BMCWEB_LOG_DEBUG("Get led groups");
    sdbusplus::asio::getProperty<bool>(
        *crow::connections::systemBus, "xyz.openbmc_project.LED.GroupManager",
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
            asyncResp->res.jsonValue["IndicatorLED"] = "Blinking";
            return;
        }

        sdbusplus::asio::getProperty<bool>(
            *crow::connections::systemBus,
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
                asyncResp->res.jsonValue["IndicatorLED"] = "Lit";
            }
            else
            {
                asyncResp->res.jsonValue["IndicatorLED"] = "Off";
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
inline void
    setIndicatorLedState(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
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
            asyncResp, "xyz.openbmc_project.LED.GroupManager",
            sdbusplus::message::object_path(
                "/xyz/openbmc_project/led/groups/enclosure_identify"),
            "xyz.openbmc_project.Led.Group", "Asserted", "IndicatorLED",
            ledBlinkng);
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
    sdbusplus::asio::getProperty<bool>(
        *crow::connections::systemBus, "xyz.openbmc_project.LED.GroupManager",
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

        sdbusplus::asio::getProperty<bool>(
            *crow::connections::systemBus,
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
                asyncResp, "xyz.openbmc_project.LED.GroupManager",
                sdbusplus::message::object_path(
                    "/xyz/openbmc_project/led/groups/enclosure_identify"),
                "xyz.openbmc_project.Led.Group", "Asserted",
                "LocationIndicatorActive", ledState);
        }
    });
}

inline void setPhysicalLedState(const std::shared_ptr<bmcweb::AsyncResp>& aResp,
                                const std::string& led,
                                const std::string& state)
{
    if (boost::ends_with(state, "On"))
    {
        aResp->res.jsonValue["Oem"]["OpenBmc"]["PhysicalLED"][led] = "On";
    }
    else if (boost::ends_with(state, "Blink"))
    {
        aResp->res.jsonValue["Oem"]["OpenBmc"]["PhysicalLED"][led] = "Blinking";
    }
    else if (boost::ends_with(state, "Off"))
    {
        aResp->res.jsonValue["Oem"]["OpenBmc"]["PhysicalLED"][led] = "Off";
    }
    else
    {
        aResp->res.jsonValue["Oem"]["OpenBmc"]["PhysicalLED"][led] = "Unknown";
    }
}

inline void getPhysicalLedState(const std::shared_ptr<bmcweb::AsyncResp>& aResp)
{
    BMCWEB_LOG_DEBUG("Get Physical Led");
    aResp->res.jsonValue["Oem"]["OpenBmc"]["PhysicalLED"]["@odata.type"] =
        "#OemComputerSystem.PhysicalLED";

    sdbusplus::asio::getProperty<std::string>(
        *crow::connections::systemBus,
        "xyz.openbmc_project.LED.Controller.status_amber",
        "/xyz/openbmc_project/led/physical/status_amber",
        "xyz.openbmc_project.Led.Physical", "State",
        [aResp](const boost::system::error_code ec,
                const std::string& amberLedState) {
        if (ec)
        {
            BMCWEB_LOG_ERROR("Get Physical State Amber Led: DBus Error", ec);
            messages::internalError(aResp->res);
            return;
        }
        setPhysicalLedState(aResp, "AmberLED", amberLedState);
    });

    sdbusplus::asio::getProperty<std::string>(
        *crow::connections::systemBus,
        "xyz.openbmc_project.LED.Controller.status_green",
        "/xyz/openbmc_project/led/physical/status_green",
        "xyz.openbmc_project.Led.Physical", "State",
        [aResp](const boost::system::error_code ec,
                const std::string& greenLedState) {
        if (ec)
        {
            BMCWEB_LOG_ERROR("Get Physical State Green Led: DBus Error", ec);
            messages::internalError(aResp->res);
            return;
        }
        setPhysicalLedState(aResp, "GreenLED", greenLedState);
    });

    sdbusplus::asio::getProperty<std::string>(
        *crow::connections::systemBus,
        "xyz.openbmc_project.LED.Controller.status_susack",
        "/xyz/openbmc_project/led/physical/status_susack",
        "xyz.openbmc_project.Led.Physical", "State",
        [aResp](const boost::system::error_code ec,
                const std::string& susackLedState) {
        if (ec)
        {
            BMCWEB_LOG_ERROR("Get Physical State Susack Led: DBus Error", ec);
            messages::internalError(aResp->res);
            return;
        }
        setPhysicalLedState(aResp, "SusackLED", susackLedState);
    });
}
} // namespace redfish
