#include "webserver_run.hpp"

#include "bmcweb_config.h"

#include "app.hpp"
#include "dbus_monitor.hpp"
#include "dbus_singleton.hpp"
#include "event_service_manager.hpp"
#include "google/google_service_root.hpp"
#include "hostname_monitor.hpp"
#include "ibm/management_console_rest.hpp"
#include "image_upload.hpp"
#include "kvm_websocket.hpp"
#include "logging.hpp"
#include "login_routes.hpp"
#include "obmc_console.hpp"
#include "openbmc_dbus_rest.hpp"
#include "redfish.hpp"
#if (BMCWEB_AMI_REP_MACRO) || (BMCWEB_AMI_NIC_MACRO)
#include <redfish/ami/extension/service.hpp>
#include <redfish_v1.hpp>
#include <boost/dll/import.hpp>
#endif
#include "redfish_aggregator.hpp"
#include "user_monitor.hpp"
#include "vm_websocket.hpp"
#include "webassets.hpp"

#include <boost/asio/io_context.hpp>
#include <sdbusplus/asio/connection.hpp>

#include <memory>

int run()
{
    auto io = std::make_shared<boost::asio::io_context>();
    App app(io);

    sdbusplus::asio::connection systemBus(*io);
    crow::connections::systemBus = &systemBus;

    // Static assets need to be initialized before Authorization, because auth
    // needs to build the whitelist from the static routes

    if constexpr (BMCWEB_STATIC_HOSTING)
    {
        crow::webassets::requestRoutes(app);
    }

    if constexpr (BMCWEB_KVM)
    {
        crow::obmc_kvm::requestRoutes(app);
    }

    if constexpr (BMCWEB_REDFISH)
    {
        redfish::RedfishService redfish(app);
#if (BMCWEB_AMI_REP_MACRO) || (BMCWEB_AMI_NIC_MACRO)        
if constexpr (BMCWEB_AMI_NIC) {
        try
        {
              // Create AMI Redfish extension service and initialize Config
               boost::dll::import_symbol<redfish::ami::extension::Service<crow::App>>(
                   "/usr/lib/redfish/core/libnic.so.1", "service",
                   boost::dll::load_mode::rtld_lazy | boost::dll::load_mode::rtld_global)
                   ->requestRoutes(app);
        }
        catch (const std::system_error& e)
        {
            std::cerr << e.what() << std::endl;
        }
}
if constexpr (BMCWEB_AMI_REP)
{        try
        {
	      BMCWEB_LOG_ERROR("Inside BMCWEB_ENABLE_AMI_REP");
              // Create AMI Redfish extension service and initialize Config
               boost::dll::import_symbol<redfish::ami::extension::Service<crow::App>>(
                   "/usr/lib/redfish/core/libami.so.1", "service",
                   boost::dll::load_mode::rtld_lazy | boost::dll::load_mode::rtld_global)
                   ->requestRoutes(app);
        }
        catch (const std::system_error& e)
        {
            std::cerr << e.what() << std::endl;
        }
}

        // Note, this must be the last route registered
        redfish::requestRoutesRedfish(app); 

        // Create EventServiceManager instance and initialize Config
        redfish::EventServiceManager::getInstance(&*io);

        //Initialize config JSON file for SSDP service , /home/root/bmcweb_persistent_data.json
        persistent_data::getConfig().readData();
#endif        

        if constexpr (BMCWEB_REDFISH_AGGREGATION)
        {
            // Create RedfishAggregator instance and initialize Config
            redfish::RedfishAggregator::getInstance(&*io);
        }
    }

    if constexpr (BMCWEB_REST)
    {
        crow::dbus_monitor::requestRoutes(app);
        crow::image_upload::requestRoutes(app);
        crow::openbmc_mapper::requestRoutes(app);
    }

    if constexpr (BMCWEB_HOST_SERIAL_SOCKET)
    {
        crow::obmc_console::requestRoutes(app);
    }

    crow::obmc_vm::requestRoutes(app);

    if constexpr (BMCWEB_IBM_MANAGEMENT_CONSOLE)
    {
        crow::ibm_mc::requestRoutes(app);
    }

    if constexpr (BMCWEB_GOOGLE_API)
    {
        crow::google_api::requestRoutes(app);
    }

    crow::login_routes::requestRoutes(app);

    if constexpr (BMCWEB_REDFISH_DBUS_LOG)
    {
        auto eventServiceManager = std::make_unique<redfish::EventServiceManager>(*io);
        eventServiceManager->startEventLogMonitor();
    }

    if constexpr (!BMCWEB_INSECURE_DISABLE_SSL)
    {
        BMCWEB_LOG_INFO("Start Hostname Monitor Service...");
        crow::hostname_monitor::registerHostnameSignal();
    }

    bmcweb::registerUserRemovedSignal();

    app.run();
    io->run();

    crow::connections::systemBus = nullptr;

    return 0;
}
