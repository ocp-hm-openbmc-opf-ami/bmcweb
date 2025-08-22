// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#pragma once
#include "registries/base_message_registry.hpp"
#include "registries/heartbeat_event_message_registry.hpp"
#include "registries/openbmc_message_registry.hpp"
#include "registries/task_event_message_registry.hpp"
#include "registries/security_message_registry.hpp"
#include "registries/ipmi_message_registry.hpp"
#include "registries/eventlog_message_registry.hpp"
#include "registries/task_message_registry.hpp"
#include "registries/ami_message_registry.hpp"

#include <span>
#include <string_view>

namespace redfish::registries
{
inline std::span<const MessageEntry>
    getRegistryFromPrefix(std::string_view registryName)
{
    if (task_event::header.registryPrefix == registryName)
    {
        return {task_event::registry};
    }
    if (openbmc::header.registryPrefix == registryName)
    {
        return {openbmc::registry};
    }
    if (heartbeat_event::header.registryPrefix == registryName)
    {
        return {heartbeat_event::registry};
    }
    if (base::header.registryPrefix == registryName)
    {
        return {base::registry};
    }
    if (security::header.registryPrefix == registryName)
    {
        return {security::registry};
    }
	if (ipmi::header.registryPrefix == registryName)
    {
        return {ipmi::registry};
    }
    if (task::header.registryPrefix == registryName)
    {
        return {task::registry};
    }
	if (eventlog::header.registryPrefix == registryName)
    {
        return {eventlog::registry};
    }
    if (ami::header.registryPrefix == registryName)
    {
        return {ami::registry};
    }
    return {openbmc::registry};
}
} // namespace redfish::registries
