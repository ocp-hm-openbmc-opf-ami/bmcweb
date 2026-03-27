// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#include "redfish.hpp"

#include "bmcweb_config.h"

#include "account_service.hpp"
#include "aggregation_service.hpp"
#include "app.hpp"
#include "bios.hpp"
#include "cable.hpp"
#include "certificate_service.hpp"
#include "chassis.hpp"
#include "cups_service.hpp"
#include "dashboard.hpp"
#include "environment_metrics.hpp"
#include "ethernet.hpp"
#include "event_service.hpp"
#include "eventservice_sse.hpp"
#include "fabric_adapters.hpp"
#include "fan.hpp"
#include "fips_manager.hpp"
#include "fru.hpp"
#include "hypervisor_system.hpp"
#include "license_control.hpp"
#include "log_services.hpp"
#include "manager_diagnostic_data.hpp"
#include "manager_logservices_journal.hpp"
#include "managers.hpp"
#include "memory.hpp"
#include "message_registries.hpp"
#include "metadata.hpp"
#include "metric_report.hpp"
#include "metric_report_definition.hpp"
#include "network_protocol.hpp"
#include "node-manager/domains_collection.hpp"
#include "node-manager/node_manager.hpp"
#include "node-manager/policies_collection.hpp"
#include "node-manager/power.hpp"
#include "node-manager/throttling_status.hpp"
#include "node-manager/triggers.hpp"
#include "odata.hpp"
#include "pcie.hpp"
#include "pcie_slots.hpp"
#include "pef_service.hpp"
#include "power.hpp"
#include "power_subsystem.hpp"
#include "power_supply.hpp"
#include "processor.hpp"
#include "redfish_sessions.hpp"
#include "redfish_v1.hpp"
#include "roles.hpp"
#include "sensors.hpp"
#include "service_root.hpp"
#include "storage.hpp"
#include "systems.hpp"
#include "systems_logservices_hostlogger.hpp"
#include "systems_logservices_postcodes.hpp"
#include "task.hpp"
#include "telemetry_service.hpp"
#include "thermal.hpp"
#include "thermal_metrics.hpp"
#include "thermal_subsystem.hpp"
#include "trigger.hpp"
#include "update_service.hpp"
#include "utils/json_utils.hpp"
#include "virtual_media.hpp"

#ifndef ONETREE_EVB_NUVOTON_NPCM845
#include "bsodjpeg.hpp"
#endif

#ifdef ONETREE_NIC
#include "ext/src/nic.hpp"
#endif

#if BMCWEB_AMI_CXL_MACRO
#include "ext/src/cxl.hpp"
#endif

#ifdef ONETREE_RTP
#include "ext/src/rep.hpp"
#endif

#ifdef ONETREE_RM
#include "ext/src/rm.hpp"
#endif

#ifdef ONETREE_PSM
#include "ext/src/psm.hpp"
#endif

#if BMCWEB_AMI_THERMALEQUIPMENT_MACRO
#include "ext/src/thermal_equipment.hpp"
#endif

#if BMCWEB_AMI_CONTROLS_MACRO
#include "ext/src/controls/controls.hpp"
#endif

#ifdef ONETREE_BRCMRAID
#include "ext/lib/brcm/storage_brcm.hpp"
#endif

#ifdef ONETREE_MSCCRAID
#include "ext/lib/mscc/storage_mscc.hpp"
#endif

#ifdef ONETREE_BRCMRAID8
#include "ext/lib/brcm/sl8_brcm.hpp"
#endif

#ifdef ONETREE_NVME
#include "ext/lib/nvme/storage_nvme.hpp"
#endif

#ifdef ONETREE_NVIDIASIPACK
#include "ext/cper/src/cper.hpp"
#include "ext/dot/src/dot.hpp"
#include "ext/sbmr/src/sbmr.hpp"
#include "ext/spdm/src/spdm.hpp"
#include "ext/src/auxreset.hpp"
#include "ext/src/erot_dump.hpp"
#include "ext/src/reset.hpp"
#endif

#ifdef ONETREE_GPGPU
#include "ext/src/gpgpu.hpp"
#endif

#if (defined(ONETREE_BRCMRAID)) || (defined(ONETREE_MSCCRAID)) ||              \
    (defined(ONETREE_NVME)) || (defined(ONETREE_BRCMRAID8)) ||                 \
    (defined(ONETREE_RTP))
#include "ext/include/storage_ext.hpp"
#endif

#if (defined(ONETREE_MSCCRAID)) || (defined(ONETREE_BRCMRAID)) ||              \
    (defined(ONETREE_BRCMRAID8))
#include "ext/include/log_services_ext.hpp"
#endif

#ifdef ONETREE_BRCMPCIESW
#include "redfish-core/lib/ext/pciesw/oem_pcie_switch.hpp"
#endif

#ifdef ONETREE_ACD
#include "ext/lib/acd/acd_service.hpp"
#endif

#ifdef ONETREE_ASD
#include "ext/lib/asd/asd_service.hpp"
#endif

#if BMCWEB_AMI_REDEBUG_MACRO
#include "ext/lib/redebugserv/redebugserv.hpp"
#endif

#ifdef ONETREE_RM
#include "ext/src/rm.hpp"
#endif

#ifdef ONETREE_PSM
#include "ext/src/psm.hpp"
#endif

#ifdef ONETREE_RPC
#include "ext/src/rackpowercontroller.hpp"
#endif

#ifdef ONETREE_ARM_SBMR
#include "ext/src/arm_redfish.hpp"
#endif

namespace redfish
{

RedfishService::RedfishService(App& app)
{
    // init schemaVersionMap
    json_util::initSchemaVersionMap();
#ifdef ONETREE_ACD
    redfish::ami::core::resource::requestRoutesACDService(app);
#endif

#ifdef ONETREE_ASD
    redfish::ami::core::resource::requestRoutesASDService(app);
#endif

#if BMCWEB_AMI_REDEBUG_MACRO
    redfish::ami::core::resource::requestRoutesReDebugService(app);
#endif

    requestRoutesMetadata(app);
    requestRoutesOdata(app);
    requestRoutesDashboard(app);

#if ONETREE_RM
    redfish::rm::registerRmRoutes(app);
#endif
    requestRoutesNodeManagerService(app);
    requestRoutesNodeManagerDomains(app);
    requestRoutesNodeManagerPolicies(app);
    requestRoutesNodeManagerThrottlingStatus(app);
    requestRoutesNodeManagerTriggers(app);

    requestAccountServiceRoutes(app);
    if constexpr (BMCWEB_REDFISH_AGGREGATION)
    {
        requestRoutesAggregationService(app);
        requestRoutesAggregationSourceCollection(app);
        requestRoutesAggregationSource(app);
    }
    requestRoutesRoles(app);
    requestRoutesRoleCollection(app);
    requestRoutesServiceRoot(app);
    requestRoutesNetworkProtocol(app);
    requestRoutesSession(app);
    requestEthernetInterfacesRoutes(app);
#if (!defined(ONETREE_RM))
    if constexpr (BMCWEB_REDFISH_ALLOW_DEPRECATED_POWER_THERMAL)
    {
        requestRoutesThermal(app);
        requestRoutesPower(app);
    }
#endif
#ifdef ONETREE_AMD_CHALUPA
    {
        requestRoutesPower(app);
    }
#endif
    if constexpr (BMCWEB_REDFISH_NEW_POWERSUBSYSTEM_THERMALSUBSYSTEM)
    {
        requestRoutesEnvironmentMetrics(app);
        requestRoutesPowerSubsystem(app);
        requestRoutesPowerSupply(app);
        requestRoutesPowerSupplyCollection(app);
        requestRoutesThermalMetrics(app);
        requestRoutesThermalSubsystem(app);
        requestRoutesFan(app);
        requestRoutesFanCollection(app);
    }
    requestRoutesManagerCollection(app);
    requestRoutesManager(app);
    requestRoutesManagerSerialInterface(app);
    requestRoutesSerialConsoleLog(app);
    requestRoutesManagerResetAction(app);
    requestRoutesManagerResetActionInfo(app);
    requestRoutesManagerResetToDefaults(app);
    requestRoutesManagerDiagnosticData(app);
#ifndef ONETREE_EVB_NUVOTON_NPCM845
    requestRoutesBsodjpeg(app);
    requestRoutesDeleteBsodjpeg(app);
    requestRoutesTriggerBsodjpeg(app);
#endif
    requestRoutesChassisCollection(app);
    requestRoutesChassis(app);
    requestRoutesChassisResetAction(app);
    requestRoutesChassisResetActionInfo(app);
    requestRoutesChassisDrive(app);
    requestRoutesChassisDriveName(app);
#if (!defined(ONETREE_RM))
    requestRoutesUpdateService(app);
#endif
    // requestRoutesStorageCollection(app);
    // requestRoutesStorage(app);

    requestRoutesCable(app);
    requestRoutesCableCollection(app);

    requestRoutesFru(app);
    requestRoutesFruCollection(app);

    requestRoutesSystemLogServiceCollection(app);
    requestRoutesEventLogService(app);
    requestRoutesSystemsLogServicesPostCode(app);
    // manager SEL for getting IPMI SEL entry

    requestRoutesBMCSELService(app);
    requestRoutesBMCSELEntryCollection(app);
    requestRoutesBMCSELClear(app);
    requestRoutesBMCSELEntry(app);
    requestRoutesBMCSELEntryDownload(app);
    if constexpr (BMCWEB_REDFISH_DUMP_LOG)
    {
        requestRoutesSystemDumpService(app);
        requestRoutesSystemDumpEntryCollection(app);
        requestRoutesSystemDumpEntry(app);
        requestRoutesSystemDumpCreate(app);
        requestRoutesSystemDumpClear(app);

        requestRoutesBMCDumpService(app);
        requestRoutesBMCDumpEntryCollection(app);
        requestRoutesBMCDumpEntry(app);
        requestRoutesBMCDumpEntryDownload(app);
        requestRoutesBMCDumpCreate(app);
        requestRoutesBMCDumpClear(app);

        requestRoutesFaultLogDumpService(app);
        requestRoutesFaultLogDumpEntryCollection(app);
        requestRoutesFaultLogDumpEntry(app);
        requestRoutesFaultLogDumpClear(app);
    }

    requestRoutesBMCLogServiceCollection(app);

    if constexpr (BMCWEB_REDFISH_BMC_JOURNAL)
    {
        requestRoutesBMCJournalLogService(app);
    }

    if constexpr (BMCWEB_REDFISH_CPU_LOG)
    {
        requestRoutesCrashdumpService(app);
        requestRoutesCrashdumpEntryCollection(app);
        requestRoutesCrashdumpEntry(app);
        requestRoutesCrashdumpFile(app);
        requestRoutesCrashdumpClear(app);
        requestRoutesCrashdumpCollect(app);
    }

    requestRoutesSystemRsyslog(app);

    requestRoutesProcessorCollection(app);
    requestRoutesProcessor(app);
    requestRoutesOperatingConfigCollection(app);
    requestRoutesOperatingConfig(app);
    requestRoutesMemoryCollection(app);
    requestRoutesMemory(app);

#ifndef ONETREE_PSM
    requestRoutesSystems(app);
#endif

    requestRoutesBiosService(app);
    requestRoutesBiosReset(app);
    requestRoutesBiosSettings(app);
    // requestRoutesBiosAttributeRegistry(app);
    // requestRoutesBiosAttrRegistryService(app);
    requestRoutesBiosChangePassword(app);

    if constexpr (BMCWEB_VM_NBDPROXY)
    {
        requestNBDVirtualMediaRoutes(app);
    }

    if constexpr (BMCWEB_REDFISH_DBUS_LOG)
    {
        requestRoutesDBusLogServiceActionsClear(app);
        requestRoutesDBusEventLogEntryCollection(app);
        requestRoutesDBusEventLogEntry(app);
        requestRoutesDBusEventLogEntryDownload(app);
    }
    else
    {
        requestRoutesJournalEventLogEntryCollection(app);
        requestRoutesJournalEventLogEntry(app);
        requestRoutesJournalEventLogClear(app);
    }

    if constexpr (BMCWEB_REDFISH_HOST_LOGGER)
    {
        requestRoutesSystemsLogServiceHostlogger(app);
    }

    requestRoutesMessageRegistryFileCollection(app);
    requestRoutesMessageRegistryFile(app);
    // requestRoutesMessageRegistry(app);

    requestRoutesCertificateService(app);
    requestRoutesHTTPSCertificate(app);
    requestRoutesLDAPCertificate(app);
    requestRoutesTrustStoreCertificate(app);

    requestRoutesSystemPCIeFunctionCollection(app);
    requestRoutesSystemPCIeFunction(app);
    requestRoutesSystemPCIeDeviceCollection(app);
    requestRoutesSystemPCIeDevice(app);
#ifndef ONETREE_PSM
    requestRoutesPCIeSlots(app);
#endif
    requestRoutesSensorCollection(app);
    requestRoutesSensor(app);
    requestRoutesSensorHistory(app);

    requestRoutesSensorThreshCollection(app);
    requestRoutesSensorThresh(app);

    requestRoutesCupsService(app);
    requestRoutesCupsSensors(app);

    requestRoutesTaskDelete(app);
    requestRoutesTaskMonitor(app);
    requestRoutesTaskService(app);
    requestRoutesTaskCollection(app);
    requestRoutesTask(app);
#if (!defined(ONETREE_RM))
    requestRoutesEventService(app);
#endif
    requestRoutesEventServiceSse(app);
    requestRoutesEventDestinationCollection(app);
    requestRoutesEventDestination(app);
    requestRoutesFabricAdapters(app);
    requestRoutesFabricAdapterCollection(app);
    requestRoutesSubmitTestEvent(app);
    requestRoutesSSLEvent(app);

    if constexpr (BMCWEB_HYPERVISOR_COMPUTER_SYSTEM)
    {
        requestRoutesHypervisorSystems(app);
    }

    requestRoutesTelemetryService(app);
    requestRoutesMetricReportDefinitionCollection(app);
    requestRoutesMetricReportDefinition(app);
    requestRoutesMetricReportCollection(app);
    requestRoutesMetricReport(app);
    requestRoutesTriggerCollection(app);
    requestRoutesTrigger(app);

#if (!defined(ONETREE_AMD_CHALUPA) || !defined(ONETREE_EVB_NUVOTON_NPCM845) || \
     !defined(ONETREE_ASPEED_SDK_LAYER))
    // FIPS Enablement
    requestFipsManagerRoutes(app);
#endif

    // License Control
#ifdef ONETREE_LICENSE
    requestRoutesLicenseControl(app);
#endif

    requestRoutesPefService(app);
    requestRoutesSendTrap(app);

    // All Extention packs routing table added here
#ifdef ONETREE_RTP
    registerRepRoutes(app);
#endif

#if BMCWEB_AMI_THERMALEQUIPMENT_MACRO
    registerThermalEquipmentRoutes(app);
#endif

#if BMCWEB_AMI_CONTROLS_MACRO
    registerOemAMIControlsRoutes(app);
#endif

#ifdef ONETREE_NIC
    registerNicRoutes(app);
#endif

#if BMCWEB_AMI_CXL_MACRO
    registerCxlRoutes(app);
#endif

#ifdef ONETREE_PSM
    redfish::psm::registerPsmRoutes(app);
#endif
#ifdef ONETREE_RPC
    registerRackPowerControllerRoutes(app);
#endif

#ifdef ONETREE_GPGPU
    registerGpgpuRoutes(app);
#endif

#if (defined(ONETREE_NVME)) || (defined(ONETREE_MSCCRAID)) ||                  \
    (defined(ONETREE_BRCMRAID)) || (defined(ONETREE_BRCMRAID8)) ||             \
    (defined(ONETREE_RTP))
    {
        redfish::ext::core::resource::requestStorageCollectionRoutes(app);
        redfish::ext::core::resource::requestRoutesStorage(app);
    }
#else
    {
        requestRoutesStorageCollection(app);
        requestRoutesStorage(app);
    }
#endif

#if (defined(ONETREE_MSCCRAID)) || (defined(ONETREE_BRCMRAID)) ||              \
    (defined(ONETREE_BRCMRAID8))
    requestRoutesRaidLog(app);
#endif

#ifdef ONETREE_NVME
    requestRoutesNvme(app);
#endif
#ifdef ONETREE_MSCCRAID
    requestRoutesMSCCStorageDevices(app);
#endif
#ifdef ONETREE_BRCMRAID
    requestRoutesBRCMStorageDevices(app);
    requestRaidPostCall(app);
#endif
#ifdef ONETREE_BRCMRAID8
    requestRoutesSl8StorageDevices(app);
    requestRaidPostCall(app);
#endif
#ifdef ONETREE_BRCMPCIESW
    requestRoutesPcieSwitchCollection(app);
    requestRoutesPcieSwitchInstanceCollection(app);
    requestRoutesPcieSwitchPortsCollection(app);
    requestRoutesPcieSwitchPortsInstanceCollection(app);
    requestRoutesPcieSwitchRefresh(app);
    requestRoutesPcieSwitchCoreDump(app);
    requestRoutesPcieSwitchTraseBuffer(app);
    requestRoutesPcieSwitchFWUpdate(app);
#endif
#ifdef ONETREE_NVIDIASIPACK
    registerSbmrRoutes(app);
    registerSpdmRoutes(app);
    registerDotRoutes(app);
    registerCperRoutes(app);
    registerResetRoutes(app);
    registerErotDumpRoutes(app);
    registerAuxResetRoutes(app);
#endif

#ifdef ONETREE_PSM
    redfish::psm::registerPsmRoutes(app);
#endif
#ifdef ONETREE_ARM_SBMR
    registerSystemExtensionRoutes(app);
#endif
    // Note, this must be the last route registered
    requestRoutesRedfish(app);
}

} // namespace redfish
