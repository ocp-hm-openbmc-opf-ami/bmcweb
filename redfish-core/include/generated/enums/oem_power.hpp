#pragma once
#include <nlohmann/json.hpp>

namespace oem_power
{
// clang-format off

enum class PowerLimitStorage{
    Invalid,
    Volatile,
    Persistent,
};

NLOHMANN_JSON_SERIALIZE_ENUM(PowerLimitStorage, {
    {PowerLimitStorage::Invalid, "Invalid"},
    {PowerLimitStorage::Volatile, "Volatile"},
    {PowerLimitStorage::Persistent, "Persistent"},
});

}
// clang-format on
