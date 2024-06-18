#pragma once
#include <nlohmann/json.hpp>

namespace cups_policy
{
// clang-format off

enum class PolicyStorage{
    Invalid,
    Volatile,
    Persistent,
};

NLOHMANN_JSON_SERIALIZE_ENUM(PolicyStorage, {
    {PolicyStorage::Invalid, "Invalid"},
    {PolicyStorage::Volatile, "Volatile"},
    {PolicyStorage::Persistent, "Persistent"},
});

}
// clang-format on
