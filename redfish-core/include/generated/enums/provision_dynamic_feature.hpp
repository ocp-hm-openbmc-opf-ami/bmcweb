#pragma once
#include <nlohmann/json.hpp>

namespace provision_dynamic_feature
{
// clang-format off

enum class FeatureStatusValues{
    Invalid,
    Enabled,
    Disabled,
};

NLOHMANN_JSON_SERIALIZE_ENUM(FeatureStatusValues, {
    {FeatureStatusValues::Invalid, "Invalid"},
    {FeatureStatusValues::Enabled, "Enabled"},
    {FeatureStatusValues::Disabled, "Disabled"},
});

}
// clang-format on
