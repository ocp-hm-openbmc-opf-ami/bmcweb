// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#pragma once
/****************************************************************
 * This header contains definitions for AMI custom Redfish messages.
 ***************************************************************/
#include "registries.hpp"

#include <array>

// clang-format off

namespace redfish::registries::amionetree
{
const Header header = {
    "Copyright 2023 Ami. All rights reserved.",
    "#MessageRegistry.v1_4_0.MessageRegistry",
    1,
    0,
    0,
    "Ami Custom Message Registry",
    "en",
    "This registry defines the Ami custom messages.",
    "AmiOneTree",
    "Ami",
};
constexpr std::array registry =
{
    MessageEntry{
        "invalidImageSize",
        {
            "Indicates that the image provided is invalid or the image size is less than the required minimum size.",
            "The image provided is invalid or the image size is less than 600KB.",
            "Critical",
            0,
            {},
            "Ensure that the image is valid with size greater than 600KB and resubmit the request.",
        }},
    MessageEntry{
        "dumpQuotaExceeded",
        {
            "Indicates that the maximum number of dump records has been reached or the dump storage is full.",
            "The dump cannot be created because either the MaxNumberOfRecords (150) has been reached or the available dump storage (1024 KB) is insufficient.",
            "Critical",
            0,
            {},
            "Delete existing dump files to free space, then retry the request.",
        }},
    MessageEntry{
        "FirmwareUpdateFailed",
        {
            "The firmware image validation timed out.",
            "This may be due to an invalid firmware image or D-Bus service unavailability.",
            "Warning",
            0,
            {},
            "The firmware image may be invalid or the D-Bus service is currently unavailable. Please check the format and try again later.",
        }},
    MessageEntry{
        "PasswordCorruption",
        {
            "Indicates that the password authentication token is corrupted in the system.",
            "Password authentication token corruption detected. The system encountered an internal error while processing the password.",
            "Critical",
            0,
            {},
            "Contact the system administrator. The password storage may be corrupted and require system maintenance.",
        }},
    // ================================================================
    // IPMI 2.0 Table 42-3 Sensor-Specific Offset Coverage (added)
    // ================================================================

    // Physical Security / Platform Security Violation (sensor type 0x06)
    MessageEntry{
        "PlatformSecurityModeViolation",
        {
            "Indicates that a secure mode violation attempt has been detected.",
            "Platform Security Violation: Secure mode violation attempted on %1 Sensor.",
            "Warning",
            1,
            {"string"},
            "Verify physical access controls and audit recent activity.",
        }},
    MessageEntry{
        "PlatformPasswordUserViolation",
        {
            "Indicates a pre-boot user password violation attempt.",
            "Platform Security Violation: Pre-boot user password violation on %1 Sensor.",
            "Warning",
            1,
            {"string"},
            "Check BIOS audit log and verify authorized user access.",
        }},
    MessageEntry{
        "PlatformPasswordSetupViolation",
        {
            "Indicates a pre-boot setup password violation attempt.",
            "Platform Security Violation: Pre-boot setup password violation on %1 Sensor.",
            "Warning",
            1,
            {"string"},
            "Check BIOS audit log and verify authorized administrator access.",
        }},
    MessageEntry{
        "PlatformPasswordNetworkViolation",
        {
            "Indicates a pre-boot network boot password violation attempt.",
            "Platform Security Violation: Pre-boot network boot password violation on %1 Sensor.",
            "Warning",
            1,
            {"string"},
            "Verify network boot credentials and audit recent boot attempts.",
        }},
    MessageEntry{
        "PlatformPasswordOtherViolation",
        {
            "Indicates an other pre-boot password violation attempt.",
            "Platform Security Violation: Other pre-boot password violation on %1 Sensor.",
            "Warning",
            1,
            {"string"},
            "Investigate BIOS audit log for unauthorized access attempts.",
        }},
    MessageEntry{
        "PlatformPasswordOOBViolation",
        {
            "Indicates an out-of-band access password violation attempt.",
            "Platform Security Violation: Out-of-band password violation on %1 Sensor.",
            "Warning",
            1,
            {"string"},
            "Verify BMC management network credentials and review audit logs.",
        }},

    // Processor (sensor type 0x07)
    MessageEntry{
        "ProcessorIERR",
        {
            "Indicates that the processor has signalled an internal error (IERR).",
            "Processor %1 Sensor reported an Internal Error (IERR).",
            "Critical",
            1,
            {"string"},
            "Reseat or replace the affected processor.",
        }},
    MessageEntry{
        "ProcessorFRB1",
        {
            "Indicates a processor FRB1 / BIST failure.",
            "Processor %1 Sensor FRB1/BIST failure.",
            "Critical",
            1,
            {"string"},
            "Reseat or replace the affected processor.",
        }},
    MessageEntry{
        "ProcessorFRB2",
        {
            "Indicates a processor FRB2 / Hang in POST failure.",
            "Processor %1 Sensor FRB2/Hang in POST failure.",
            "Critical",
            1,
            {"string"},
            "Reseat or replace the affected processor.",
        }},
    MessageEntry{
        "ProcessorFRB3",
        {
            "Indicates a processor FRB3 / Initialization failure.",
            "Processor %1 Sensor FRB3/Initialization failure.",
            "Critical",
            1,
            {"string"},
            "Reseat or replace the affected processor.",
        }},
    MessageEntry{
        "ProcessorConfigurationError",
        {
            "Indicates a processor configuration error.",
            "Processor %1 Sensor configuration error detected.",
            "Critical",
            1,
            {"string"},
            "Verify processor compatibility and check BIOS configuration.",
        }},
    MessageEntry{
        "ProcessorSMBIOSUncorrectable",
        {
            "Indicates an SM BIOS uncorrectable processor complex error.",
            "Processor %1 Sensor SM BIOS reported uncorrectable error.",
            "Critical",
            1,
            {"string"},
            "Replace the affected processor and review system logs.",
        }},
    MessageEntry{
        "ProcessorDisabled",
        {
            "Indicates that a processor has been disabled.",
            "Processor %1 Sensor has been disabled.",
            "Warning",
            1,
            {"string"},
            "Check BIOS settings or hardware faults that may have disabled the processor.",
        }},
    MessageEntry{
        "ProcessorTerminatorPresence",
        {
            "Indicates that a processor terminator has been detected.",
            "Processor terminator presence detected at %1 Sensor.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "ProcessorAutomaticThrottle",
        {
            "Indicates that a processor has been automatically throttled.",
            "Processor %1 Sensor automatically throttled.",
            "Warning",
            1,
            {"string"},
            "Check thermal conditions and power capping settings.",
        }},
    MessageEntry{
        "ProcessorMachineCheckUncorrectable",
        {
            "Indicates a processor uncorrectable machine check exception.",
            "Processor %1 Sensor reported an uncorrectable machine check exception.",
            "Critical",
            1,
            {"string"},
            "Replace the affected processor and inspect platform logs.",
        }},
    MessageEntry{
        "ProcessorMachineCheckCorrectable",
        {
            "Indicates a processor correctable machine check exception.",
            "Processor %1 Sensor reported a correctable machine check exception.",
            "Warning",
            1,
            {"string"},
            "Monitor the processor; replace if errors persist.",
        }},

    // Power Supply (sensor type 0x08)
    MessageEntry{
        "PowerSupplyACOutOfRange",
        {
            "Indicates that a power supply input is lost or out of range.",
            "Power supply %1 Sensor AC input lost or out of range.",
            "Critical",
            1,
            {"string"},
            "Verify input power source and replace the power supply if required.",
        }},
    MessageEntry{
        "PowerSupplyACOutOfRangeButPresent",
        {
            "Indicates that a power supply input is out of range but still present.",
            "Power supply %1 Sensor AC input out of range but present.",
            "Warning",
            1,
            {"string"},
            "Verify input voltage and check power source quality.",
        }},

    // Power Unit (sensor type 0x09)
    MessageEntry{
        "PowerUnit240VAPowerDown",
        {
            "Indicates a 240VA Power Down has been initiated by the power unit.",
            "Power unit %1 Sensor initiated 240VA Power Down.",
            "Critical",
            1,
            {"string"},
            "Inspect power distribution and overcurrent protection.",
        }},
    MessageEntry{
        "PowerUnitInterlockPowerDown",
        {
            "Indicates a Power Unit interlock power down.",
            "Power unit %1 Sensor initiated interlock power down.",
            "Warning",
            1,
            {"string"},
            "Check that chassis interlocks are properly engaged.",
        }},
    MessageEntry{
        "PowerUnitSoftPowerControlFailure",
        {
            "Indicates a Power Unit soft power control failure.",
            "Power unit %1 Sensor soft power control failure.",
            "Critical",
            1,
            {"string"},
            "Inspect BMC and power management firmware.",
        }},
    MessageEntry{
        "PowerUnitFailureDetected",
        {
            "Indicates a Power Unit failure has been detected.",
            "Power unit %1 Sensor failure detected.",
            "Critical",
            1,
            {"string"},
            "Replace the failed power unit.",
        }},
    MessageEntry{
        "PowerUnitPredictiveFailure",
        {
            "Indicates a Power Unit predictive failure.",
            "Power unit %1 Sensor predictive failure.",
            "Warning",
            1,
            {"string"},
            "Plan replacement of the power unit at the next maintenance window.",
        }},

    // Memory (sensor type 0x0C)
    MessageEntry{
        "MemoryScrubFailed",
        {
            "Indicates a memory scrub operation has failed.",
            "Memory %1 Sensor scrub operation failed.",
            "Warning",
            1,
            {"string"},
            "Check memory health; replace the DIMM if errors persist.",
        }},
    MessageEntry{
        "MemoryDeviceDisabled",
        {
            "Indicates a memory device has been disabled.",
            "Memory %1 Sensor device disabled.",
            "Warning",
            1,
            {"string"},
            "Verify DIMM configuration and replace failed module if required.",
        }},
    MessageEntry{
        "MemoryDIMMPresence",
        {
            "Indicates that a memory DIMM presence has been detected.",
            "Memory %1 Sensor DIMM presence detected.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "MemoryConfigurationError",
        {
            "Indicates a memory configuration error.",
            "Memory %1 Sensor configuration error detected.",
            "Critical",
            1,
            {"string"},
            "Verify DIMM population rules and BIOS memory settings.",
        }},
    MessageEntry{
        "MemorySparingSpare",
        {
            "Indicates that a memory sparing event has occurred.",
            "Memory %1 Sensor sparing activated.",
            "Warning",
            1,
            {"string"},
            "Plan replacement of the spared DIMM.",
        }},
    MessageEntry{
        "MemoryAutomaticThrottle",
        {
            "Indicates that memory has been automatically throttled.",
            "Memory %1 Sensor automatically throttled.",
            "Warning",
            1,
            {"string"},
            "Check memory thermals and airflow.",
        }},
    MessageEntry{
        "MemoryCriticalOvertemperature",
        {
            "Indicates that memory has reached a critical overtemperature state.",
            "Memory %1 Sensor critical overtemperature.",
            "Critical",
            1,
            {"string"},
            "Check cooling and ambient temperature; reduce load if necessary.",
        }},

    // Drive Slot (sensor type 0x0D)
    MessageEntry{
        "DriveSlotDrivePresence",
        {
            "Indicates that a drive has been detected in a drive slot.",
            "Drive slot %1 Sensor drive presence detected.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "DriveSlotPredictiveFailure",
        {
            "Indicates a drive predictive failure.",
            "Drive slot %1 Sensor predictive failure.",
            "Warning",
            1,
            {"string"},
            "Plan replacement of the affected drive.",
        }},
    MessageEntry{
        "DriveSlotHotSpare",
        {
            "Indicates that a hot spare drive is active.",
            "Drive slot %1 Sensor hot spare active.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "DriveSlotConsistencyCheck",
        {
            "Indicates that a drive consistency check is in progress.",
            "Drive slot %1 Sensor consistency or parity check in progress.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "DriveSlotInCriticalArray",
        {
            "Indicates that a drive is in a critical array state.",
            "Drive slot %1 Sensor is in a critical array state.",
            "Warning",
            1,
            {"string"},
            "Verify the array configuration and replace any failed drives.",
        }},
    MessageEntry{
        "DriveSlotInFailedArray",
        {
            "Indicates that a drive is in a failed array state.",
            "Drive slot %1 Sensor is in a failed array state.",
            "Critical",
            1,
            {"string"},
            "Replace failed drives and restore the array from backup if necessary.",
        }},
    MessageEntry{
        "DriveSlotRebuildActive",
        {
            "Indicates that a drive rebuild or remap is in progress.",
            "Drive slot %1 Sensor rebuild/remap in progress.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "DriveSlotRebuildAborted",
        {
            "Indicates that a drive rebuild or remap has been aborted.",
            "Drive slot %1 Sensor rebuild/remap aborted.",
            "Warning",
            1,
            {"string"},
            "Investigate cause of abort and restart the rebuild if appropriate.",
        }},

    // POST Memory Resize (sensor type 0x0E)
    MessageEntry{
        "POSTMemoryResize",
        {
            "Indicates a POST memory resize event.",
            "POST memory resize event on %1 Sensor.",
            "OK",
            1,
            {"string"},
            "None.",
        }},

    // System Firmware (sensor type 0x0F)
    MessageEntry{
        "BIOSHang",
        {
            "Indicates that the system firmware has hung.",
            "System firmware (BIOS) hang detected. POST code %1%2.",
            "Critical",
            2,
            {"string", "string"},
            "Capture POST code data and investigate the cause of the hang.",
        }},

    // Event Logging Disabled (sensor type 0x10)
    MessageEntry{
        "EventLogCorrectableMemoryErrorDisabled",
        {
            "Indicates correctable memory error logging has been disabled.",
            "Correctable memory error logging disabled on %1 Sensor.",
            "Warning",
            1,
            {"string"},
            "Re-enable correctable memory error logging when possible.",
        }},
    MessageEntry{
        "EventLogEventTypeDisabled",
        {
            "Indicates that event type logging has been disabled.",
            "Event type logging disabled on %1 Sensor.",
            "Warning",
            1,
            {"string"},
            "Re-enable event type logging when possible.",
        }},
    MessageEntry{
        "EventLogAllDisabled",
        {
            "Indicates that all event logging has been disabled.",
            "All event logging disabled on %1 Sensor.",
            "Warning",
            1,
            {"string"},
            "Re-enable event logging when possible.",
        }},
    MessageEntry{
        "EventLogSELFull",
        {
            "Indicates that the SEL is full.",
            "System Event Log is full.",
            "Warning",
            0,
            {},
            "Clear the SEL or archive existing entries.",
        }},
    MessageEntry{
        "EventLogSELAlmostFull",
        {
            "Indicates that the SEL is almost full.",
            "System Event Log is almost full.",
            "Warning",
            0,
            {},
            "Clear the SEL or archive existing entries.",
        }},

    // System Event (sensor type 0x12)
    MessageEntry{
        "SystemReconfigured",
        {
            "Indicates that the system has been reconfigured.",
            "System has been reconfigured.",
            "OK",
            0,
            {},
            "None.",
        }},
    MessageEntry{
        "SystemBootOEMEvent",
        {
            "Indicates that an OEM system boot event occurred.",
            "OEM system boot event reported (OEM data: %1%2).",
            "OK",
            2,
            {"string", "string"},
            "None.",
        }},
    MessageEntry{
        "SystemHardwareFailure",
        {
            "Indicates an undetermined system hardware failure.",
            "Undetermined system hardware failure detected.",
            "Critical",
            0,
            {},
            "Investigate platform hardware and review BMC and BIOS logs.",
        }},
    MessageEntry{
        "SystemAuxLogEntryAdded",
        {
            "Indicates that an auxiliary log entry has been added.",
            "Auxiliary log %1.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "SystemPEFAction",
        {
            "Indicates that a Platform Event Filter (PEF) action has been triggered.",
            "Platform Event Filter action triggered (action bits: %1).",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "SystemTimestampClockSync",
        {
            "Indicates that the timestamp clock has been synchronized.",
            "Timestamp clock synchronized.",
            "OK",
            0,
            {},
            "None.",
        }},

    // Critical Interrupt (sensor type 0x13)
    MessageEntry{
        "BusTimeout",
        {
            "Indicates that a bus timeout has been detected.",
            "Bus timeout detected on %1 Sensor.",
            "Critical",
            1,
            {"string"},
            "Inspect bus connections and bus master devices.",
        }},
    MessageEntry{
        "IOChannelCheckNMI",
        {
            "Indicates an I/O channel check NMI has been detected.",
            "I/O channel check NMI detected on %1 Sensor.",
            "Critical",
            1,
            {"string"},
            "Inspect I/O subsystem and recent device changes.",
        }},
    MessageEntry{
        "SoftwareNMI",
        {
            "Indicates a software-generated NMI.",
            "Software NMI detected on %1 Sensor.",
            "Warning",
            1,
            {"string"},
            "Investigate OS and software triggering the NMI.",
        }},
    MessageEntry{
        "EISAFailSafeTimeout",
        {
            "Indicates an EISA fail-safe timeout.",
            "EISA fail-safe timeout detected on %1 Sensor.",
            "Critical",
            1,
            {"string"},
            "Inspect EISA bus devices.",
        }},
    MessageEntry{
        "BusCorrectableError",
        {
            "Indicates a correctable bus error.",
            "Bus correctable error detected on %1 Sensor.",
            "Warning",
            1,
            {"string"},
            "Monitor the bus; replace devices if errors persist.",
        }},
    MessageEntry{
        "BusUncorrectableError",
        {
            "Indicates an uncorrectable bus error.",
            "Bus uncorrectable error detected on %1 Sensor.",
            "Critical",
            1,
            {"string"},
            "Inspect bus connections and devices for failure.",
        }},
    MessageEntry{
        "FatalNMI",
        {
            "Indicates a fatal NMI has been detected.",
            "Fatal NMI detected on %1 Sensor.",
            "Critical",
            1,
            {"string"},
            "Investigate platform hardware and review system logs.",
        }},
    MessageEntry{
        "BusFatalError",
        {
            "Indicates a fatal bus error.",
            "Bus fatal error detected on %1 Sensor.",
            "Critical",
            1,
            {"string"},
            "Inspect bus connections and devices for failure.",
        }},
    MessageEntry{
        "BusDegraded",
        {
            "Indicates a bus is operating in a degraded state.",
            "Bus degraded on %1 Sensor.",
            "Warning",
            1,
            {"string"},
            "Inspect bus connections and devices for failure.",
        }},

    // Button / Switch (sensor type 0x14)
    MessageEntry{
        "SleepButtonPressed",
        {
            "Indicates that the sleep button has been pressed.",
            "Sleep button pressed.",
            "OK",
            0,
            {},
            "None.",
        }},
    MessageEntry{
        "FRULatchOpen",
        {
            "Indicates that a FRU latch has been opened.",
            "FRU %1 Sensor latch open.",
            "Warning",
            1,
            {"string"},
            "Close the FRU latch.",
        }},
    MessageEntry{
        "FRUServiceRequest",
        {
            "Indicates that a FRU service request button has been pressed.",
            "FRU %1 Sensor service request.",
            "OK",
            1,
            {"string"},
            "None.",
        }},

    // Chip Set (sensor type 0x19)
    MessageEntry{
        "ChipSetSoftPowerControlFailure",
        {
            "Indicates a chip set soft power control failure.",
            "Chip set soft power control failure on %1 Sensor.",
            "Critical",
            1,
            {"string"},
            "Inspect platform power control circuitry.",
        }},
    MessageEntry{
        "ChipSetThermalTrip",
        {
            "Indicates a chip set thermal trip.",
            "Chip set thermal trip on %1 Sensor.",
            "Critical",
            1,
            {"string"},
            "Inspect platform cooling and reduce load.",
        }},

    // Cable / Interconnect (sensor type 0x1B)
    MessageEntry{
        "CableConnected",
        {
            "Indicates that a cable or interconnect is connected.",
            "Cable/Interconnect %1 Sensor connected.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "CableIncorrectConfig",
        {
            "Indicates an incorrect cable or interconnect configuration.",
            "Cable/Interconnect %1 Sensor incorrectly configured.",
            "Warning",
            1,
            {"string"},
            "Verify cable routing per platform documentation.",
        }},

    // System Boot / Restart Initiated (sensor type 0x1D)
    MessageEntry{
        "SystemBootPowerUp",
        {
            "Indicates that a system boot was initiated by power up.",
            "System boot initiated by power up (cause: %1, channel: %2).",
            "OK",
            2,
            {"string", "string"},
            "None.",
        }},
    MessageEntry{
        "SystemBootHardReset",
        {
            "Indicates that a system boot was initiated by hard reset.",
            "System boot initiated by hard reset (cause: %1, channel: %2).",
            "OK",
            2,
            {"string", "string"},
            "None.",
        }},
    MessageEntry{
        "SystemBootWarmReset",
        {
            "Indicates that a system boot was initiated by warm reset.",
            "System boot initiated by warm reset (cause: %1, channel: %2).",
            "OK",
            2,
            {"string", "string"},
            "None.",
        }},
    MessageEntry{
        "SystemBootUserRequestedPXE",
        {
            "Indicates a user-requested PXE boot.",
            "User-requested PXE boot initiated (cause: %1, channel: %2).",
            "OK",
            2,
            {"string", "string"},
            "None.",
        }},
    MessageEntry{
        "SystemBootDiagnostic",
        {
            "Indicates an automatic boot to a diagnostic.",
            "Automatic boot to diagnostic initiated (cause: %1, channel: %2).",
            "OK",
            2,
            {"string", "string"},
            "None.",
        }},
    MessageEntry{
        "SystemBootOSHardReset",
        {
            "Indicates that the OS initiated a hard reset.",
            "OS-initiated hard reset (cause: %1, channel: %2).",
            "OK",
            2,
            {"string", "string"},
            "None.",
        }},
    MessageEntry{
        "SystemBootOSWarmReset",
        {
            "Indicates that the OS initiated a warm reset.",
            "OS-initiated warm reset (cause: %1, channel: %2).",
            "OK",
            2,
            {"string", "string"},
            "None.",
        }},
    MessageEntry{
        "SystemBootRestart",
        {
            "Indicates a system restart.",
            "System restart initiated (cause: %1, channel: %2).",
            "OK",
            2,
            {"string", "string"},
            "None.",
        }},

    // Boot Error (sensor type 0x1E)
    MessageEntry{
        "BootErrorNoBootableMedia",
        {
            "Indicates that no bootable media was found.",
            "Boot error: No bootable media found.",
            "Warning",
            0,
            {},
            "Insert bootable media or verify boot order.",
        }},
    MessageEntry{
        "BootErrorNonBootableDiskette",
        {
            "Indicates a non-bootable diskette was left in the drive.",
            "Boot error: Non-bootable diskette in drive.",
            "Warning",
            0,
            {},
            "Remove non-bootable diskette.",
        }},
    MessageEntry{
        "BootErrorPXEServerNotFound",
        {
            "Indicates that no PXE server responded.",
            "Boot error: PXE server not found.",
            "Warning",
            0,
            {},
            "Verify PXE server configuration and network connectivity.",
        }},
    MessageEntry{
        "BootErrorInvalidBootSector",
        {
            "Indicates an invalid boot sector was detected.",
            "Boot error: Invalid boot sector.",
            "Warning",
            0,
            {},
            "Repair or replace the boot media.",
        }},
    MessageEntry{
        "BootErrorTimeout",
        {
            "Indicates a timeout waiting for user boot selection.",
            "Boot error: Timeout waiting for user boot selection.",
            "Warning",
            0,
            {},
            "Restart the system and provide a boot selection.",
        }},

    // Base OS Boot / Installation Status (sensor type 0x1F)
    MessageEntry{
        "OSBootCompletedA",
        {
            "Indicates that an A: drive boot has completed.",
            "OS boot completed from A: drive.",
            "OK",
            0,
            {},
            "None.",
        }},
    MessageEntry{
        "OSBootCompletedC",
        {
            "Indicates that a C: drive boot has completed.",
            "OS boot completed from C: drive.",
            "OK",
            0,
            {},
            "None.",
        }},
    MessageEntry{
        "OSBootCompletedPXE",
        {
            "Indicates that a PXE boot has completed.",
            "OS boot completed via PXE.",
            "OK",
            0,
            {},
            "None.",
        }},
    MessageEntry{
        "OSBootCompletedDiagnostic",
        {
            "Indicates that a diagnostic boot has completed.",
            "Diagnostic boot completed.",
            "OK",
            0,
            {},
            "None.",
        }},
    MessageEntry{
        "OSBootCompletedCDROM",
        {
            "Indicates that a CD-ROM boot has completed.",
            "OS boot completed from CD-ROM.",
            "OK",
            0,
            {},
            "None.",
        }},
    MessageEntry{
        "OSBootCompletedROM",
        {
            "Indicates that a ROM boot has completed.",
            "OS boot completed from ROM.",
            "OK",
            0,
            {},
            "None.",
        }},
    MessageEntry{
        "OSBootCompleted",
        {
            "Indicates that the OS boot has completed.",
            "OS boot completed.",
            "OK",
            0,
            {},
            "None.",
        }},
    MessageEntry{
        "OSInstallationStarted",
        {
            "Indicates that the OS or hypervisor installation has started.",
            "OS/Hypervisor installation started.",
            "OK",
            0,
            {},
            "None.",
        }},

    // OS Stop / Shutdown (sensor type 0x20)
    MessageEntry{
        "OSLoadCriticalStop",
        {
            "Indicates a critical stop during OS load.",
            "Critical stop during OS load/initialization.",
            "Critical",
            0,
            {},
            "Investigate the OS load failure.",
        }},
    MessageEntry{
        "OSGracefulStop",
        {
            "Indicates a graceful OS stop.",
            "OS gracefully stopped.",
            "OK",
            0,
            {},
            "None.",
        }},
    MessageEntry{
        "OSGracefulShutdown",
        {
            "Indicates a graceful OS shutdown.",
            "OS gracefully shut down.",
            "OK",
            0,
            {},
            "None.",
        }},
    MessageEntry{
        "OSShutdownByPEF",
        {
            "Indicates a soft shutdown initiated by Platform Event Filter.",
            "Soft shutdown initiated by Platform Event Filter.",
            "Warning",
            0,
            {},
            "Investigate the triggering event filter.",
        }},
    MessageEntry{
        "OSAgentNotResponding",
        {
            "Indicates that the OS management agent is not responding.",
            "OS management agent not responding.",
            "Warning",
            0,
            {},
            "Verify the OS management agent is running.",
        }},

    // Slot / Connector (sensor type 0x21)
    MessageEntry{
        "SlotIdentifyStatus",
        {
            "Indicates that a slot identify status has been asserted.",
            "Slot %1 Sensor identify status asserted.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "SlotDeviceInstalled",
        {
            "Indicates that a device has been installed in a slot.",
            "Slot %1 Sensor device installed.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "SlotReadyForInstall",
        {
            "Indicates that a slot is ready for device installation.",
            "Slot %1 Sensor ready for device installation.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "SlotReadyForRemoval",
        {
            "Indicates that a slot is ready for device removal.",
            "Slot %1 Sensor ready for device removal.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "SlotPowerOff",
        {
            "Indicates that a slot has been powered off.",
            "Slot %1 Sensor power off.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "SlotRemovalRequest",
        {
            "Indicates a slot device removal request.",
            "Slot %1 Sensor device removal request.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "SlotInterlockAsserted",
        {
            "Indicates that a slot interlock has been asserted.",
            "Slot %1 Sensor interlock asserted.",
            "Warning",
            1,
            {"string"},
            "Verify the slot interlock is engaged.",
        }},
    MessageEntry{
        "SlotDisabled",
        {
            "Indicates that a slot has been disabled.",
            "Slot %1 Sensor disabled.",
            "Warning",
            1,
            {"string"},
            "Investigate the cause for the slot being disabled.",
        }},
    MessageEntry{
        "SlotSpareDeviceHolder",
        {
            "Indicates that a slot holds a spare device.",
            "Slot %1 Sensor holds a spare device.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "SlotOffboardPresence",
        {
            "Indicates an offboard slot or connector presence.",
            "Offboard slot/connector %1 Sensor presence detected.",
            "OK",
            1,
            {"string"},
            "None.",
        }},

    // System ACPI Power State (sensor type 0x22)
    MessageEntry{
        "ACPIPowerStateS0G0",
        {
            "Indicates the system has entered ACPI S0/G0 (Working) state.",
            "System entered ACPI S0/G0 (Working) state.",
            "OK",
            0,
            {},
            "None.",
        }},
    MessageEntry{
        "ACPIPowerStateS1",
        {
            "Indicates the system has entered ACPI S1 state.",
            "System entered ACPI S1 state.",
            "OK",
            0,
            {},
            "None.",
        }},
    MessageEntry{
        "ACPIPowerStateS2",
        {
            "Indicates the system has entered ACPI S2 state.",
            "System entered ACPI S2 state.",
            "OK",
            0,
            {},
            "None.",
        }},
    MessageEntry{
        "ACPIPowerStateS3",
        {
            "Indicates the system has entered ACPI S3 (Suspend to RAM) state.",
            "System entered ACPI S3 (Suspend to RAM) state.",
            "OK",
            0,
            {},
            "None.",
        }},
    MessageEntry{
        "ACPIPowerStateS4",
        {
            "Indicates the system has entered ACPI S4 (Suspend to Disk) state.",
            "System entered ACPI S4 (Suspend to Disk) state.",
            "OK",
            0,
            {},
            "None.",
        }},
    MessageEntry{
        "ACPIPowerStateS5",
        {
            "Indicates the system has entered ACPI S5/G2 (Soft Off) state.",
            "System entered ACPI S5/G2 (Soft Off) state.",
            "OK",
            0,
            {},
            "None.",
        }},
    MessageEntry{
        "ACPIPowerStateS4S5",
        {
            "Indicates the system has entered ACPI S4/S5 Soft Off state.",
            "System entered ACPI S4/S5 Soft Off state.",
            "OK",
            0,
            {},
            "None.",
        }},
    MessageEntry{
        "ACPIPowerStateG3",
        {
            "Indicates the system has entered ACPI G3 (Mechanical Off) state.",
            "System entered ACPI G3 (Mechanical Off) state.",
            "OK",
            0,
            {},
            "None.",
        }},
    MessageEntry{
        "ACPIPowerStateSleeping",
        {
            "Indicates the system is sleeping in ACPI S1/S2/S3 state.",
            "System sleeping in ACPI S1/S2/S3 state.",
            "OK",
            0,
            {},
            "None.",
        }},
    MessageEntry{
        "ACPIPowerStateG1Sleep",
        {
            "Indicates the system has entered ACPI G1 Sleeping state.",
            "System entered ACPI G1 Sleeping state.",
            "OK",
            0,
            {},
            "None.",
        }},
    MessageEntry{
        "ACPIPowerStateS5Override",
        {
            "Indicates the system has entered ACPI S5 by override.",
            "System entered ACPI S5 by override.",
            "OK",
            0,
            {},
            "None.",
        }},
    MessageEntry{
        "ACPIPowerStateLegacyOn",
        {
            "Indicates the system is in legacy ON state.",
            "System in legacy ON state.",
            "OK",
            0,
            {},
            "None.",
        }},
    MessageEntry{
        "ACPIPowerStateLegacyOff",
        {
            "Indicates the system is in legacy OFF state.",
            "System in legacy OFF state.",
            "OK",
            0,
            {},
            "None.",
        }},
    MessageEntry{
        "ACPIPowerStateUnknown",
        {
            "Indicates the system ACPI power state is unknown.",
            "System ACPI power state unknown.",
            "Warning",
            0,
            {},
            "Verify ACPI state reporting.",
        }},

    // Platform Alert (sensor type 0x24)
    MessageEntry{
        "PlatformGeneratedPage",
        {
            "Indicates that a platform-generated page alert has been sent.",
            "Platform generated page alert on %1 Sensor.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "PlatformGeneratedLANAlert",
        {
            "Indicates that a platform-generated LAN alert has been sent.",
            "Platform generated LAN alert on %1 Sensor.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "PlatformGeneratedTrap",
        {
            "Indicates that a platform event trap has been generated.",
            "Platform event trap generated on %1 Sensor.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "PlatformGeneratedSNMPTrap",
        {
            "Indicates that an SNMP trap has been generated by the platform.",
            "Platform generated SNMP trap on %1 Sensor.",
            "OK",
            1,
            {"string"},
            "None.",
        }},

    // Entity Presence (sensor type 0x25)
    MessageEntry{
        "EntityPresenceDetected",
        {
            "Indicates that an entity presence has been detected.",
            "Entity %1 Sensor presence detected.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "EntityAbsent",
        {
            "Indicates that an entity is absent.",
            "Entity %1 Sensor absent.",
            "Warning",
            1,
            {"string"},
            "Verify entity installation.",
        }},
    MessageEntry{
        "EntityDisabled",
        {
            "Indicates that an entity has been disabled.",
            "Entity %1 Sensor disabled.",
            "Warning",
            1,
            {"string"},
            "Verify the entity is intended to be disabled.",
        }},

    // LAN (sensor type 0x27)
    MessageEntry{
        "LanRestored",
        {
            "Indicates that LAN heartbeat has been restored.",
            "LAN heartbeat restored on %1 Sensor.",
            "OK",
            1,
            {"string"},
            "None.",
        }},

    // Management Subsystem Health (sensor type 0x28)
    MessageEntry{
        "ManagementSensorAccessDegraded",
        {
            "Indicates degraded or unavailable sensor access.",
            "Management sensor access degraded on %1 Sensor.",
            "Warning",
            1,
            {"string"},
            "Verify management controller and sensor health.",
        }},
    MessageEntry{
        "ManagementControllerAccessDegraded",
        {
            "Indicates degraded or unavailable management controller access.",
            "Management controller access degraded on %1 Sensor.",
            "Warning",
            1,
            {"string"},
            "Verify management controller health.",
        }},
    MessageEntry{
        "ManagementControllerOffline",
        {
            "Indicates that a management controller is offline.",
            "Management controller %1 Sensor offline.",
            "Critical",
            1,
            {"string"},
            "Verify management controller health and connectivity.",
        }},
    MessageEntry{
        "ManagementControllerUnavailable",
        {
            "Indicates that a management controller is unavailable.",
            "Management controller %1 Sensor unavailable.",
            "Critical",
            1,
            {"string"},
            "Verify management controller health and connectivity.",
        }},
    MessageEntry{
        "ManagementSensorFailure",
        {
            "Indicates that a management sensor has failed.",
            "Management sensor failure detected on %1 Sensor.",
            "Warning",
            1,
            {"string"},
            "Replace or recalibrate the sensor.",
        }},
    MessageEntry{
        "ManagementFRUFailure",
        {
            "Indicates that a management FRU has failed.",
            "Management FRU failure detected on %1 Sensor.",
            "Warning",
            1,
            {"string"},
            "Replace the affected FRU.",
        }},

    // Battery (sensor type 0x29)
    MessageEntry{
        "BatteryPresence",
        {
            "Indicates that a battery presence has been detected.",
            "Battery %1 Sensor presence detected.",
            "OK",
            1,
            {"string"},
            "None.",
        }},

    // Session Audit (sensor type 0x2A)
    MessageEntry{
        "SessionActivated",
        {
            "Indicates that a session has been activated.",
            "Session activated for user ID %1 on channel %2.",
            "OK",
            2,
            {"string", "string"},
            "None.",
        }},
    MessageEntry{
        "SessionDeactivated",
        {
            "Indicates that a session has been deactivated.",
            "Session deactivated for user ID %1 on channel %2 (cause: %3).",
            "OK",
            3,
            {"string", "string", "string"},
            "None.",
        }},
    MessageEntry{
        "SessionInvalidPassword",
        {
            "Indicates that an invalid username or password was used.",
            "Invalid login attempted for user ID %1 on channel %2.",
            "Warning",
            2,
            {"string", "string"},
            "Review audit logs for unauthorized access attempts.",
        }},
    MessageEntry{
        "SessionPasswordDisable",
        {
            "Indicates that a user account was disabled due to invalid password attempts.",
            "User account disabled due to invalid password attempts for user ID %1 on channel %2.",
            "Warning",
            2,
            {"string", "string"},
            "Review audit logs and re-enable the account if appropriate.",
        }},

    // Version Change (sensor type 0x2B)
    MessageEntry{
        "VersionHardwareChange",
        {
            "Indicates that a hardware change has been detected.",
            "Hardware change detected on %1 Sensor.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "VersionFirmwareChange",
        {
            "Indicates that a firmware or software change has been detected.",
            "Firmware/Software change detected on %1 Sensor.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "VersionHardwareIncompatibility",
        {
            "Indicates a hardware incompatibility.",
            "Hardware incompatibility detected on %1 Sensor.",
            "Critical",
            1,
            {"string"},
            "Verify hardware compatibility per platform documentation.",
        }},
    MessageEntry{
        "VersionFirmwareIncompatibility",
        {
            "Indicates a firmware or software incompatibility.",
            "Firmware/Software incompatibility detected on %1 Sensor.",
            "Critical",
            1,
            {"string"},
            "Verify firmware versions per platform documentation.",
        }},
    MessageEntry{
        "VersionUnsupportedHardware",
        {
            "Indicates an invalid or unsupported hardware version.",
            "Unsupported hardware version detected on %1 Sensor.",
            "Critical",
            1,
            {"string"},
            "Replace with supported hardware.",
        }},
    MessageEntry{
        "VersionUnsupportedFirmware",
        {
            "Indicates an invalid or unsupported firmware version.",
            "Unsupported firmware version detected on %1 Sensor.",
            "Critical",
            1,
            {"string"},
            "Update to a supported firmware version.",
        }},
    MessageEntry{
        "VersionHardwareChangeSuccess",
        {
            "Indicates a hardware change has been detected with a successful change.",
            "Hardware change successful on %1 Sensor.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "VersionFirmwareChangeSuccess",
        {
            "Indicates a firmware or software change has been detected with a successful change.",
            "Firmware/Software change successful on %1 Sensor.",
            "OK",
            1,
            {"string"},
            "None.",
        }},

    // FRU State (sensor type 0x2C)
    MessageEntry{
        "FRUNotInstalled",
        {
            "Indicates that a FRU is not installed.",
            "FRU %1 Sensor not installed.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "FRUInactive",
        {
            "Indicates that a FRU is inactive.",
            "FRU %1 Sensor inactive.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "FRUActivationRequested",
        {
            "Indicates that a FRU activation has been requested.",
            "FRU %1 Sensor activation requested.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "FRUActivationInProgress",
        {
            "Indicates that a FRU activation is in progress.",
            "FRU %1 Sensor activation in progress.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "FRUActive",
        {
            "Indicates that a FRU is active.",
            "FRU %1 Sensor active.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "FRUDeactivationRequested",
        {
            "Indicates that a FRU deactivation has been requested.",
            "FRU %1 Sensor deactivation requested.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "FRUDeactivationInProgress",
        {
            "Indicates that a FRU deactivation is in progress.",
            "FRU %1 Sensor deactivation in progress.",
            "OK",
            1,
            {"string"},
            "None.",
        }},
    MessageEntry{
        "FRUCommunicationLost",
        {
            "Indicates that communication with a FRU has been lost.",
            "FRU %1 Sensor communication lost.",
            "Warning",
            1,
            {"string"},
            "Verify FRU connectivity and reseat if required.",
        }},
    MessageEntry{
        "InvalidIPAddress",
        {
            "Indicates that the  server IP address specified in the Image URI is invalid.",
            "The server IP address specified in the Image URI is not valid.",
            "Warning",
            0,
            {},
            "Provide a valid IP address in the Image URI and retry the operation",
        }},
    MessageEntry{
        "InvalidImagePath",
        {
            "Indicates that the image path specified in the Image URI is invalid or the file does not exist on the remote server.",
            "The virtual media image path specified in the Image URI is invalid or the file does not exist on the remote server.",
            "Warning",
            0,
            {},
            "Verify the image path and ensure the file exists on the remote server.",
        }},
        MessageEntry{
            "RemoteServiceConnectionRefused",
            {
                "Indicates that the connection to the remote service was refused.",
                "The connection to remote service was refused. Ensure the target service NFS/CIFS/HTTPS is running.",
                "Warning",
                0,
                {},
                "Verify the remote service is running and reachable.",
            }},
        MessageEntry{
            "VirtualMediaHttpsTransferFailed",
            {
                "Indicates that the virtual media image transfer using HTTPS failed.",
                "The virtual media image transfer using HTTPS failed. This may be due to an invalid image path, invalid server IP address , authentication failure,  or remote service unavailability.",
                "Warning",
                0,
                {},
                "Verify the image path, server address , credentials, and ensure taht remote HTTPS service is reachable, then retry the operation."
            }},
         MessageEntry{
            "RemoteServiceTimeout",
            {
                "Indicates that the connection to the remote service timed out.",
                "The connection to the remote service  timed out.",
                "Critical",
                0,
                {},
                "Verify the remote server is reachable and retry the operation."
            }},
};

enum class Index
{
    invalidImageSize = 0,
    dumpQuotaExceeded = 1,
    firmwareUpdateFailed = 2,
    passwordCorruption = 3,
    platformSecurityModeViolation = 4,
    platformPasswordUserViolation = 5,
    platformPasswordSetupViolation = 6,
    platformPasswordNetworkViolation = 7,
    platformPasswordOtherViolation = 8,
    platformPasswordOOBViolation = 9,
    processorIERR = 10,
    processorFRB1 = 11,
    processorFRB2 = 12,
    processorFRB3 = 13,
    processorConfigurationError = 14,
    processorSMBIOSUncorrectable = 15,
    processorDisabled = 16,
    processorTerminatorPresence = 17,
    processorAutomaticThrottle = 18,
    processorMachineCheckUncorrectable = 19,
    processorMachineCheckCorrectable = 20,
    powerSupplyACOutOfRange = 21,
    powerSupplyACOutOfRangeButPresent = 22,
    powerUnit240VAPowerDown = 23,
    powerUnitInterlockPowerDown = 24,
    powerUnitSoftPowerControlFailure = 25,
    powerUnitFailureDetected = 26,
    powerUnitPredictiveFailure = 27,
    memoryScrubFailed = 28,
    memoryDeviceDisabled = 29,
    memoryDIMMPresence = 30,
    memoryConfigurationError = 31,
    memorySparingSpare = 32,
    memoryAutomaticThrottle = 33,
    memoryCriticalOvertemperature = 34,
    driveSlotDrivePresence = 35,
    driveSlotPredictiveFailure = 36,
    driveSlotHotSpare = 37,
    driveSlotConsistencyCheck = 38,
    driveSlotInCriticalArray = 39,
    driveSlotInFailedArray = 40,
    driveSlotRebuildActive = 41,
    driveSlotRebuildAborted = 42,
    pOSTMemoryResize = 43,
    bIOSHang = 44,
    eventLogCorrectableMemoryErrorDisabled = 45,
    eventLogEventTypeDisabled = 46,
    eventLogAllDisabled = 47,
    eventLogSELFull = 48,
    eventLogSELAlmostFull = 49,
    systemReconfigured = 50,
    systemBootOEMEvent = 51,
    systemHardwareFailure = 52,
    systemAuxLogEntryAdded = 53,
    systemPEFAction = 54,
    systemTimestampClockSync = 55,
    busTimeout = 56,
    iOChannelCheckNMI = 57,
    softwareNMI = 58,
    eISAFailSafeTimeout = 59,
    busCorrectableError = 60,
    busUncorrectableError = 61,
    fatalNMI = 62,
    busFatalError = 63,
    busDegraded = 64,
    sleepButtonPressed = 65,
    fRULatchOpen = 66,
    fRUServiceRequest = 67,
    chipSetSoftPowerControlFailure = 68,
    chipSetThermalTrip = 69,
    cableConnected = 70,
    cableIncorrectConfig = 71,
    systemBootPowerUp = 72,
    systemBootHardReset = 73,
    systemBootWarmReset = 74,
    systemBootUserRequestedPXE = 75,
    systemBootDiagnostic = 76,
    systemBootOSHardReset = 77,
    systemBootOSWarmReset = 78,
    systemBootRestart = 79,
    bootErrorNoBootableMedia = 80,
    bootErrorNonBootableDiskette = 81,
    bootErrorPXEServerNotFound = 82,
    bootErrorInvalidBootSector = 83,
    bootErrorTimeout = 84,
    oSBootCompletedA = 85,
    oSBootCompletedC = 86,
    oSBootCompletedPXE = 87,
    oSBootCompletedDiagnostic = 88,
    oSBootCompletedCDROM = 89,
    oSBootCompletedROM = 90,
    oSBootCompleted = 91,
    oSInstallationStarted = 92,
    oSLoadCriticalStop = 93,
    oSGracefulStop = 94,
    oSGracefulShutdown = 95,
    oSShutdownByPEF = 96,
    oSAgentNotResponding = 97,
    slotIdentifyStatus = 98,
    slotDeviceInstalled = 99,
    slotReadyForInstall = 100,
    slotReadyForRemoval = 101,
    slotPowerOff = 102,
    slotRemovalRequest = 103,
    slotInterlockAsserted = 104,
    slotDisabled = 105,
    slotSpareDeviceHolder = 106,
    slotOffboardPresence = 107,
    aCPIPowerStateS0G0 = 108,
    aCPIPowerStateS1 = 109,
    aCPIPowerStateS2 = 110,
    aCPIPowerStateS3 = 111,
    aCPIPowerStateS4 = 112,
    aCPIPowerStateS5 = 113,
    aCPIPowerStateS4S5 = 114,
    aCPIPowerStateG3 = 115,
    aCPIPowerStateSleeping = 116,
    aCPIPowerStateG1Sleep = 117,
    aCPIPowerStateS5Override = 118,
    aCPIPowerStateLegacyOn = 119,
    aCPIPowerStateLegacyOff = 120,
    aCPIPowerStateUnknown = 121,
    platformGeneratedPage = 122,
    platformGeneratedLANAlert = 123,
    platformGeneratedTrap = 124,
    platformGeneratedSNMPTrap = 125,
    entityPresenceDetected = 126,
    entityAbsent = 127,
    entityDisabled = 128,
    lanRestored = 129,
    managementSensorAccessDegraded = 130,
    managementControllerAccessDegraded = 131,
    managementControllerOffline = 132,
    managementControllerUnavailable = 133,
    managementSensorFailure = 134,
    managementFRUFailure = 135,
    batteryPresence = 136,
    sessionActivated = 137,
    sessionDeactivated = 138,
    sessionInvalidPassword = 139,
    sessionPasswordDisable = 140,
    versionHardwareChange = 141,
    versionFirmwareChange = 142,
    versionHardwareIncompatibility = 143,
    versionFirmwareIncompatibility = 144,
    versionUnsupportedHardware = 145,
    versionUnsupportedFirmware = 146,
    versionHardwareChangeSuccess = 147,
    versionFirmwareChangeSuccess = 148,
    fRUNotInstalled = 149,
    fRUInactive = 150,
    fRUActivationRequested = 151,
    fRUActivationInProgress = 152,
    fRUActive = 153,
    fRUDeactivationRequested = 154,
    fRUDeactivationInProgress = 155,
    fRUCommunicationLost = 156,
    invalidIPAddress = 157,
    invalidImagePath = 158,
    remoteServiceConnectionRefused = 159,
    virtualMediaHttpsTransferFailed = 160,
    remoteServiceTimeout = 161,
};
} // namespace redfish::registries::amionetree
 