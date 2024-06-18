#pragma once
#include <nlohmann/json.hpp>

namespace cups_service
{
// clang-format off

enum class LoadFactorConfiguration{
    Invalid,
    Dynamic,
    Static,
};

NLOHMANN_JSON_SERIALIZE_ENUM(LoadFactorConfiguration, {
    {LoadFactorConfiguration::Invalid, "Invalid"},
    {LoadFactorConfiguration::Dynamic, "Dynamic"},
    {LoadFactorConfiguration::Static, "Static"},
});

}
// clang-format on
