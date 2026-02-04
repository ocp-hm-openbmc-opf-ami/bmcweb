// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#include "redfish.hpp"

#include "amiconfig.h"
#include "bmcweb_config.h"

#include "account_service.hpp"
#include "aggregation_service.hpp"
#include "app.hpp"
#include "bios.hpp"
#include "cable.hpp"
#include "certificate_service.hpp"
#include "chassis.hpp"
#include "cups_service.hpp"
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
#include "sensor_patching.hpp"
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
#include "virtual_media.hpp"
#include "utils/json_utils.hpp"
#include "dashboard.hpp"

#if (!BMCWEB_ARBEL_NUVOTON_MACRO)
#include "bsodjpeg.hpp"
#endif

#if BMCWEB_AMI_NIC_MACRO
#include "ext/src/nic.hpp"
#endif

#if BMCWEB_AMI_CXL_MACRO
#include "ext/src/cxl.hpp"
#endif

#if BMCWEB_AMI_REP_MACRO
#include "ext/src/rep.hpp"
#endif

#if BMCWEB_AMI_RM_MACRO
#include "ext/src/rm.hpp"
#endif

#if BMCWEB_AMI_PSM_MACRO
#include "ext/src/psm.hpp"
#endif

#if BMCWEB_AMI_THERMALEQUIPMENT_MACRO
#include "ext/src/thermal_equipment.hpp"
#endif

#if BMCWEB_AMI_CONTROLS_MACRO
#include "ext/src/controls/controls.hpp"
#endif

#if BMCWEB_AMI_RAIDBRCM_MACRO
#include "ext/lib/brcm/storage_brcm.hpp"
#endif

#if BMCWEB_AMI_RAIDMSCC_MACRO
#include "ext/lib/mscc/storage_mscc.hpp"
#endif

#if BMCWEB_AMI_SL8_MACRO
#include "ext/lib/brcm/sl8_brcm.hpp"
#endif

#if BMCWEB_AMI_NVME_MACRO
#include "ext/lib/nvme/storage_nvme.hpp"
#endif

#if BMCWEB_SPDM_URIS_MACRO
#include "ext/spdm/src/spdm.hpp"
#endif

#if BMCWEB_GPGPU_URIS_MACRO
#include "ext/src/gpgpu.hpp"
#endif

#if BMCWEB_CPER_URIS_MACRO
#include "ext/cper/src/cper.hpp"
#endif

#if (BMCWEB_AMI_RAIDBRCM_MACRO) || (BMCWEB_AMI_RAIDMSCC_MACRO) ||              \
    (BMCWEB_AMI_NVME_MACRO) || (BMCWEB_AMI_SL8_MACRO) || (BMCWEB_AMI_REP_MACRO)
#include "ext/include/storage_ext.hpp"
#endif

#if (BMCWEB_AMI_RAIDMSCC_MACRO) || (BMCWEB_AMI_RAIDBRCM_MACRO) || (BMCWEB_AMI_SL8_MACRO)
#include "ext/include/log_services_ext.hpp"
#endif

#if BMCWEB_AMI_PCIESW_MACRO
#include "redfish-core/lib/ext/pciesw/oem_pcie_switch.hpp"
#endif

#if BMCWEB_AMI_ACD_MACRO
#include "ext/lib/acd/acd_service.hpp"
#endif

#if BMCWEB_AMI_ASD_MACRO
#include "ext/lib/asd/asd_service.hpp"
#endif

#if BMCWEB_AMI_REDEBUG_MACRO
#include "ext/lib/redebugserv/redebugserv.hpp"
#endif

#if BMCWEB_SBMR_EXT_MACRO
#include "ext/sbmr/src/sbmr.hpp"
#endif

#if BMCWEB_DOT_URIS_MACRO
#include "ext/dot/src/dot.hpp"
#endif

#if BMCWEB_NVIDIA_RESET_URIS_MACRO
#include "ext/src/reset.hpp"
#endif

#if BMCWEB_NVIDIA_EROT_DUMP_MACRO
#include "ext/src/erot_dump.hpp"
#endif

#if BMCWEB_AMI_RM_MACRO
#include "ext/src/rm.hpp"
#endif

#if BMCWEB_AMI_PSM_MACRO
#include "ext/src/psm.hpp"
#endif

#if BMCWEB_NVIDIA_AUX_RESET_URIS_MACRO
#include "ext/src/auxreset.hpp"
#endif

#if BMCWEB_ARM_SBMR_MACRO
#include "ext/src/arm_redfish.hpp"
#endif

namespace redfish
{

RedfishService::RedfishService(App& app)
{
    //init schemaVersionMap
    json_util::initSchemaVersionMap();
#if BMCWEB_AMI_ACD_MACRO
    redfish::ami::core::resource::requestRoutesACDService(app);
#endif

#if BMCWEB_AMI_ASD_MACRO
    redfish::ami::core::resource::requestRoutesASDService(app);
#endif

#if BMCWEB_AMI_REDEBUG_MACRO
    redfish::ami::core::resource::requestRoutesReDebugService(app);
#endif

    requestRoutesMetadata(app);
    requestRoutesOdata(app);
    requestRoutesDashboard(app);

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
    if constexpr (BMCWEB_REDFISH_ALLOW_DEPRECATED_POWER_THERMAL)
    {
        requestRoutesThermal(app);
        requestRoutesPower(app);
    }
#if (BMCWEB_CHALUPA_AMD_MACRO)
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
    #if (!BMCWEB_ARBEL_NUVOTON_MACRO)
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
    requestRoutesUpdateService(app);
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

    requestRoutesAcpiService(app);
    requestRoutesAcpiEntryCollection(app);
    requestRoutesAcpiEntry(app);
    requestRoutesAcpiFile(app);
    requestRoutesSystemRsyslog(app);

    requestRoutesProcessorCollection(app);
    requestRoutesProcessor(app);
    requestRoutesOperatingConfigCollection(app);
    requestRoutesOperatingConfig(app);
    requestRoutesMemoryCollection(app);
    requestRoutesMemory(app);

    #if (!BMCWEB_AMI_PSM_MACRO)
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
    #if (!BMCWEB_AMI_PSM_MACRO)
    requestRoutesPCIeSlots(app);
    #endif
    requestRoutesSensorCollection(app);
    requestRoutesSensor(app);
    requestRoutesSensorPatching(app);
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
    requestRoutesEventService(app);
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

#if (!BMCWEB_CHALUPA_AMD_MACRO && !BMCWEB_ARBEL_NUVOTON_MACRO && !BMCWEB_AST2700_EVB_MACRO)
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
#if BMCWEB_AMI_REP_MACRO
    registerRepRoutes(app);
#endif

#if BMCWEB_AMI_THERMALEQUIPMENT_MACRO
    registerThermalEquipmentRoutes(app);
#endif

#if BMCWEB_AMI_CONTROLS_MACRO
    registerOemAMIControlsRoutes(app);
#endif

#if BMCWEB_AMI_NIC_MACRO
    registerNicRoutes(app);
#endif

#if BMCWEB_AMI_CXL_MACRO
    registerCxlRoutes(app);
#endif

#if BMCWEB_AMI_RM_MACRO
    redfish::rm::registerRmRoutes(app);
#endif
#if BMCWEB_AMI_PSM_MACRO
    redfish::psm::registerPsmRoutes(app);
#endif

#if BMCWEB_GPGPU_URIS_MACRO
    registerGpgpuRoutes(app);
#endif

#if (BMCWEB_AMI_NVME_MACRO) || (BMCWEB_AMI_RAIDMSCC_MACRO) ||                  \
    (BMCWEB_AMI_RAIDBRCM_MACRO) || (BMCWEB_AMI_SL8_MACRO) || (BMCWEB_AMI_REP_MACRO)
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

#if (BMCWEB_AMI_RAIDMSCC_MACRO) || (BMCWEB_AMI_RAIDBRCM_MACRO) || (BMCWEB_AMI_SL8_MACRO)
    requestRoutesRaidLog(app);
#endif

#if BMCWEB_AMI_NVME_MACRO
    requestRoutesNvme(app);
#endif
#if BMCWEB_AMI_RAIDMSCC_MACRO
    requestRoutesMSCCStorageDevices(app);
#endif
#if BMCWEB_AMI_RAIDBRCM_MACRO
    requestRoutesBRCMStorageDevices(app);
    requestRaidPostCall(app);
#endif
#if BMCWEB_AMI_SL8_MACRO
    requestRoutesSl8StorageDevices(app);
    requestRaidPostCall(app);
#endif
#if BMCWEB_AMI_PCIESW_MACRO
    requestRoutesPcieSwitchCollection(app);
    requestRoutesPcieSwitchInstanceCollection(app);
    requestRoutesPcieSwitchPortsCollection(app);
    requestRoutesPcieSwitchPortsInstanceCollection(app);
    requestRoutesPcieSwitchRefresh(app);
    requestRoutesPcieSwitchCoreDump(app);
    requestRoutesPcieSwitchTraseBuffer(app);
    requestRoutesPcieSwitchFWUpdate(app);
#endif
#if BMCWEB_SBMR_EXT_MACRO
    registerSbmrRoutes(app);
#endif
#if BMCWEB_SPDM_URIS_MACRO
    registerSpdmRoutes(app);
#endif
#if BMCWEB_DOT_URIS_MACRO
    registerDotRoutes(app);
#endif
#if BMCWEB_CPER_URIS_MACRO
    registerCperRoutes(app);
#endif
#if BMCWEB_NVIDIA_RESET_URIS_MACRO
    registerResetRoutes(app);
#endif
#if BMCWEB_NVIDIA_EROT_DUMP_MACRO
    registerErotDumpRoutes(app);
#endif
#if BMCWEB_AMI_RM_MACRO
    redfish::rm::registerRmRoutes(app);
#endif
#if BMCWEB_AMI_PSM_MACRO
    redfish::psm::registerPsmRoutes(app);
#endif
#if BMCWEB_NVIDIA_AUX_RESET_URIS_MACRO
    registerAuxResetRoutes(app);
#endif
#if BMCWEB_ARM_SBMR_MACRO
    registerSystemExtensionRoutes(app);
#endif
    // Note, this must be the last route registered
    requestRoutesRedfish(app);
}

} // namespace redfish
