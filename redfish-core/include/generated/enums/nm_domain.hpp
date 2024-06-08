#pragma once
#include <nlohmann/json.hpp>

namespace nm_domain
{
// clang-format off

enum class ControlKnob{
    Invalid,
    AcpiPstate,
    HwpmPerfBias,
    HwpmPerfPreference,
    HwpmPerfPreferenceOverride,
    ProchotRatio,
    TurboRatioLimit,
};

NLOHMANN_JSON_SERIALIZE_ENUM(ControlKnob, {
    {ControlKnob::Invalid, "Invalid"},
    {ControlKnob::AcpiPstate, "AcpiPstate"},
    {ControlKnob::HwpmPerfBias, "HwpmPerfBias"},
    {ControlKnob::HwpmPerfPreference, "HwpmPerfPreference"},
    {ControlKnob::HwpmPerfPreferenceOverride, "HwpmPerfPreferenceOverride"},
    {ControlKnob::ProchotRatio, "ProchotRatio"},
    {ControlKnob::TurboRatioLimit, "TurboRatioLimit"},
});

}
// clang-format on
