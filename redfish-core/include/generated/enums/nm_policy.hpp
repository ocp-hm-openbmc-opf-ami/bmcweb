#pragma once
#include <nlohmann/json.hpp>

namespace nm_policy
{
// clang-format off

enum class NmState{
    Invalid,
    Disabled,
    Suspended,
    Pending,
    Ready,
    Triggered,
    Selected,
};

enum class PolicyType{
    Invalid,
    PowerPolicy,
    PerformancePolicy,
};

enum class PolicyStorage{
    Invalid,
    Volatile,
    Persistent,
};

enum class CorrectionType{
    Invalid,
    Auto,
    NonAggressive,
    Aggressive,
};

enum class LimitException{
    Invalid,
    HardPowerOff,
    LogEventOnly,
    NoAction,
    Oem,
};

enum class ControlKnob{
    Invalid,
    AcpiPstate,
    TurboRatioLimit,
    ProchotRatio,
    HwpmPerfPreference,
    HwpmPerfBias,
    HwpmPerfPreferenceOverride,
};

NLOHMANN_JSON_SERIALIZE_ENUM(NmState, {
    {NmState::Invalid, "Invalid"},
    {NmState::Disabled, "Disabled"},
    {NmState::Suspended, "Suspended"},
    {NmState::Pending, "Pending"},
    {NmState::Ready, "Ready"},
    {NmState::Triggered, "Triggered"},
    {NmState::Selected, "Selected"},
});

NLOHMANN_JSON_SERIALIZE_ENUM(PolicyType, {
    {PolicyType::Invalid, "Invalid"},
    {PolicyType::PowerPolicy, "PowerPolicy"},
    {PolicyType::PerformancePolicy, "PerformancePolicy"},
});

NLOHMANN_JSON_SERIALIZE_ENUM(PolicyStorage, {
    {PolicyStorage::Invalid, "Invalid"},
    {PolicyStorage::Volatile, "Volatile"},
    {PolicyStorage::Persistent, "Persistent"},
});

NLOHMANN_JSON_SERIALIZE_ENUM(CorrectionType, {
    {CorrectionType::Invalid, "Invalid"},
    {CorrectionType::Auto, "Auto"},
    {CorrectionType::NonAggressive, "NonAggressive"},
    {CorrectionType::Aggressive, "Aggressive"},
});

NLOHMANN_JSON_SERIALIZE_ENUM(LimitException, {
    {LimitException::Invalid, "Invalid"},
    {LimitException::HardPowerOff, "HardPowerOff"},
    {LimitException::LogEventOnly, "LogEventOnly"},
    {LimitException::NoAction, "NoAction"},
    {LimitException::Oem, "Oem"},
});

NLOHMANN_JSON_SERIALIZE_ENUM(ControlKnob, {
    {ControlKnob::Invalid, "Invalid"},
    {ControlKnob::AcpiPstate, "AcpiPstate"},
    {ControlKnob::TurboRatioLimit, "TurboRatioLimit"},
    {ControlKnob::ProchotRatio, "ProchotRatio"},
    {ControlKnob::HwpmPerfPreference, "HwpmPerfPreference"},
    {ControlKnob::HwpmPerfBias, "HwpmPerfBias"},
    {ControlKnob::HwpmPerfPreferenceOverride, "HwpmPerfPreferenceOverride"},
});

}
// clang-format on
