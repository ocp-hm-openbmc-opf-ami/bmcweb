/*
// Copyright (c) 2020 Intel Corporation
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
#include <registries.hpp>

namespace redfish::registries::bios
{
const Header header = {
    "Copyright 2020 OpenBMC. All rights reserved.",
    "#MessageRegistry.v1_4_0.MessageRegistry",
    "BiosAttributeRegistry.1.0.0",
    "Bios Attribute Registry",
    "en",
    "This registry defines the messages for bios attribute registry.",
    "BiosAttributeRegistry",
    "1.0.0",
    "OpenBMC",
};
// BiosAttributeRegistry registry is not defined in DMTF, We should use
// OEM defined registries for this purpose.
// Below link is wrong - We need to define OEM registries and use
// appropriate data here.
constexpr const char* url =
    "https://redfish.dmtf.org/registries/BiosAttributeRegistry.1.0.0.json";

constexpr std::array<MessageEntry, 0> registry = {};
} // namespace redfish::registries::bios
