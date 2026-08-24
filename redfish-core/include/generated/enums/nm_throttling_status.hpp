#pragma once
#include <nlohmann/json.hpp>

namespace nm_throttling_status
{
// clang-format off

enum class ThrottlingSource{
    Invalid,
    ACTotalPlatformDomain,
    CPUSubsystem,
    MemorySubsystem,
    PCISubsystem,
    DCTotalPlatformDomain,
    SmaRTCLST,
};

enum class ThrottlingReason{
    Invalid,
    AlwaysOn,
    InletAirTemperature,
    MissingReadingsTimeout,
    TimeAfterHostReset,
    GPIO,
    CPUUtilization,
    Host Reset,
    OCWarning,
    OTWarning,
    UVFault,
};

enum class ThrottlingMethod{
    Invalid,
    PowerLimit,
    ACPIPstate,
    ACPThreads,
    TurboRatioLimit,
    PROCHOT,
};

enum class ThrottlingSource{
    Invalid,
    ACTotalPlatformDomain,
    CPUSubsystem,
    MemorySubsystem,
    PCISubsystem,
    DCTotalPlatformDomain,
    Performance,
    SmaRTCLST,
};

enum class Source{
    Invalid,
    ACTotalPlatformPower,
    CPUSubsystem,
    MemorySubsystem,
    PCIe,
    DCTotalPlatformPower,
    CPUPerformance,
    SmaRTCLST,
};

enum class Reason{
    Invalid,
    AlwaysOn,
    InletTemperature,
    MissingReadingsTimeout,
    TimeAfterHostReset,
    GPIO,
    CPUUtilization,
    HostReset,
    Overcurrent,
    Overtemperature,
    Undervoltage,
};

enum class Method{
    Invalid,
    PowerLimit,
    TurboRatioLimit,
    PROCHOT,
    HwpmPerfPreference,
    HwpmPerfPreferenceMin,
    HwpmPerfPreferenceMax,
    HwpmPerfPreferenceEpp,
    HwpmPerfBias,
    HwpmPerfPreferenceOverride,
    SmaRTEvent,
};

NLOHMANN_JSON_SERIALIZE_ENUM(ThrottlingSource, {
    {ThrottlingSource::Invalid, "Invalid"},
    {ThrottlingSource::ACTotalPlatformDomain, "ACTotalPlatformDomain"},
    {ThrottlingSource::CPUSubsystem, "CPUSubsystem"},
    {ThrottlingSource::MemorySubsystem, "MemorySubsystem"},
    {ThrottlingSource::PCISubsystem, "PCISubsystem"},
    {ThrottlingSource::DCTotalPlatformDomain, "DCTotalPlatformDomain"},
    {ThrottlingSource::SmaRTCLST, "SmaRTCLST"},
});

NLOHMANN_JSON_SERIALIZE_ENUM(ThrottlingReason, {
    {ThrottlingReason::Invalid, "Invalid"},
    {ThrottlingReason::AlwaysOn, "AlwaysOn"},
    {ThrottlingReason::InletAirTemperature, "InletAirTemperature"},
    {ThrottlingReason::MissingReadingsTimeout, "MissingReadingsTimeout"},
    {ThrottlingReason::TimeAfterHostReset, "TimeAfterHostReset"},
    {ThrottlingReason::GPIO, "GPIO"},
    {ThrottlingReason::CPUUtilization, "CPUUtilization"},
    {ThrottlingReason::Host Reset, "Host Reset"},
    {ThrottlingReason::OCWarning, "OCWarning"},
    {ThrottlingReason::OTWarning, "OTWarning"},
    {ThrottlingReason::UVFault, "UVFault"},
});

NLOHMANN_JSON_SERIALIZE_ENUM(ThrottlingMethod, {
    {ThrottlingMethod::Invalid, "Invalid"},
    {ThrottlingMethod::PowerLimit, "PowerLimit"},
    {ThrottlingMethod::ACPIPstate, "ACPIPstate"},
    {ThrottlingMethod::ACPThreads, "ACPThreads"},
    {ThrottlingMethod::TurboRatioLimit, "TurboRatioLimit"},
    {ThrottlingMethod::PROCHOT, "PROCHOT"},
});

NLOHMANN_JSON_SERIALIZE_ENUM(ThrottlingSource, {
    {ThrottlingSource::Invalid, "Invalid"},
    {ThrottlingSource::ACTotalPlatformDomain, "ACTotalPlatformDomain"},
    {ThrottlingSource::CPUSubsystem, "CPUSubsystem"},
    {ThrottlingSource::MemorySubsystem, "MemorySubsystem"},
    {ThrottlingSource::PCISubsystem, "PCISubsystem"},
    {ThrottlingSource::DCTotalPlatformDomain, "DCTotalPlatformDomain"},
    {ThrottlingSource::Performance, "Performance"},
    {ThrottlingSource::SmaRTCLST, "SmaRTCLST"},
});

NLOHMANN_JSON_SERIALIZE_ENUM(Source, {
    {Source::Invalid, "Invalid"},
    {Source::ACTotalPlatformPower, "ACTotalPlatformPower"},
    {Source::CPUSubsystem, "CPUSubsystem"},
    {Source::MemorySubsystem, "MemorySubsystem"},
    {Source::PCIe, "PCIe"},
    {Source::DCTotalPlatformPower, "DCTotalPlatformPower"},
    {Source::CPUPerformance, "CPUPerformance"},
    {Source::SmaRTCLST, "SmaRTCLST"},
});

NLOHMANN_JSON_SERIALIZE_ENUM(Reason, {
    {Reason::Invalid, "Invalid"},
    {Reason::AlwaysOn, "AlwaysOn"},
    {Reason::InletTemperature, "InletTemperature"},
    {Reason::MissingReadingsTimeout, "MissingReadingsTimeout"},
    {Reason::TimeAfterHostReset, "TimeAfterHostReset"},
    {Reason::GPIO, "GPIO"},
    {Reason::CPUUtilization, "CPUUtilization"},
    {Reason::HostReset, "HostReset"},
    {Reason::Overcurrent, "Overcurrent"},
    {Reason::Overtemperature, "Overtemperature"},
    {Reason::Undervoltage, "Undervoltage"},
});

NLOHMANN_JSON_SERIALIZE_ENUM(Method, {
    {Method::Invalid, "Invalid"},
    {Method::PowerLimit, "PowerLimit"},
    {Method::TurboRatioLimit, "TurboRatioLimit"},
    {Method::PROCHOT, "PROCHOT"},
    {Method::HwpmPerfPreference, "HwpmPerfPreference"},
    {Method::HwpmPerfPreferenceMin, "HwpmPerfPreferenceMin"},
    {Method::HwpmPerfPreferenceMax, "HwpmPerfPreferenceMax"},
    {Method::HwpmPerfPreferenceEpp, "HwpmPerfPreferenceEpp"},
    {Method::HwpmPerfBias, "HwpmPerfBias"},
    {Method::HwpmPerfPreferenceOverride, "HwpmPerfPreferenceOverride"},
    {Method::SmaRTEvent, "SmaRTEvent"},
});

}
// clang-format on
