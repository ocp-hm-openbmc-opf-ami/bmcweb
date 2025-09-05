// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#pragma once
#include "registries/base_message_registry.hpp"
#include "registries/heartbeat_event_message_registry.hpp"
#include "registries/openbmc_message_registry.hpp"
#include "registries/task_event_message_registry.hpp"

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
    return {openbmc::registry};
}

inline const Header* resolveHeader(std::string_view registryPrefix)
{
    if (registryPrefix == base::header.registryPrefix)
    {
        return &base::header;
    }
    if (registryPrefix == heartbeat_event::header.registryPrefix)
    {
        return &heartbeat_event::header;
    }
    if (registryPrefix == openbmc::header.registryPrefix)
    {
        return &openbmc::header;
    }
    if (registryPrefix == task_event::header.registryPrefix)
    {
        return &task_event::header;
    }

    return nullptr; // Unknown registry
}

} // namespace redfish::registries
