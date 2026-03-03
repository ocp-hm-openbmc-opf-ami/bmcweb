// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#pragma once
#include "app.hpp"
#include "async_resp.hpp"
#include "system_utils.hpp"
#include "websocket.hpp"

#include <sys/socket.h>

#include <boost/container/flat_map.hpp>
#include <registries/privilege_registry.hpp>

namespace crow
{
namespace obmc_kvm
{

std::vector<std::string> csrfTokenlist;

using PropertyValue = std::variant<uint8_t, uint16_t, std::string,
                                   std::vector<std::string>, bool>;

using KvmSessionInfoEntry = std::tuple<uint8_t, std::string, std::string, uint8_t, uint8_t, uint8_t, std::string>;
using KvmSessionInfoType = std::vector<KvmSessionInfoEntry>;

uint16_t getPortNumberFromDBus()
{

    PropertyValue property;
    uint16_t portNumber = 5900; // Default port number
    try
    {
        // Create a D-Bus connection
        auto bus = sdbusplus::bus::new_default_system();

        // Prepare the D-Bus method call
        auto method = bus.new_method_call(
            "xyz.openbmc_project.Control.Service.Manager",
            "/xyz/openbmc_project/control/service/start_2dipkvm",
            "org.freedesktop.DBus.Properties", "Get");

        // Append interface and property name to the method call
        method.append("xyz.openbmc_project.Control.Service.SocketAttributes",
                      "Port");

        auto reply = bus.call(method);

        reply.read(property);

        if (auto val = std::get_if<uint16_t>(&property))
        {
            portNumber = *val;
        }
        else
        {
            std::cerr << "Property is not of type uint16_t" << std::endl;
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error retrieving port number from D-Bus: " << e.what()
                  << std::endl;
    }

    return portNumber;
}

uint16_t getActiveKVMSessionsFromDBus()
{
    KvmSessionInfoType sessionCounts;
    try
    {
        auto bus = sdbusplus::bus::new_default_system();

        // Prepare the D-Bus method call
        auto method =
            bus.new_method_call("xyz.openbmc_project.SessionManager",
                                "/xyz/openbmc_project/SessionManager",
                                "org.freedesktop.DBus.Properties", "Get");

        // Append interface and property name to the method call
        method.append("xyz.openbmc_project.SessionManager.Kvm",
                      "KvmSessionInfo");

        auto reply = bus.call(method);

        std::variant<KvmSessionInfoType> result;
        reply.read(result);

        sessionCounts = std::get<KvmSessionInfoType>(result);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error retrieving Active KVM sessions from D-Bus: "
                  << e.what() << std::endl;
    }
    return static_cast<uint16_t>(sessionCounts.size());
}

class KvmSession : public std::enable_shared_from_this<KvmSession>
{
  public:
    explicit KvmSession(crow::websocket::Connection& connIn, const std::uint16_t portIn = 5900) :
        conn(connIn), hostSocket(conn.getIoContext()),
        timeoutInSeconds(
            persistent_data::SessionStore::getInstance().getTimeoutInSeconds())
    {
        uint16_t port = (portIn == 5900) ? getPortNumberFromDBus() : portIn;
        boost::asio::ip::tcp::endpoint endpoint(
            boost::asio::ip::make_address("127.0.0.1"), port);
        hostSocket.async_connect(
            endpoint, [this, &connIn](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "conn:{}, Couldn't connect to KVM socket port: {}",
                    logPtr(&conn), ec);
                if (ec != boost::asio::error::operation_aborted)
                {
                    connIn.close("Error in connecting to KVM port");
                }
                return;
            }

            doRead();
        });
        startTimeoutTimer(); // Invoke the timer function when the KVM WebSocket
                             // is opened.
    }

    void onMessage(const std::string& data)
    {
        if (data.length() > inputBuffer.capacity())
        {
            BMCWEB_LOG_ERROR("conn:{}, Buffer overrun when writing {} bytes",
                             logPtr(&conn), data.length());
            conn.close("Buffer overrun");
            return;
        }

        BMCWEB_LOG_DEBUG("conn:{}, Read {} bytes from websocket", logPtr(&conn),
                         data.size());
        size_t copied = boost::asio::buffer_copy(
            inputBuffer.prepare(data.size()), boost::asio::buffer(data));
        BMCWEB_LOG_DEBUG("conn:{}, Committing {} bytes from websocket",
                         logPtr(&conn), copied);
        inputBuffer.commit(copied);

        BMCWEB_LOG_DEBUG("conn:{}, inputbuffer size {}", logPtr(&conn),
                         inputBuffer.size());
        doWrite();
        lastActivityTime = persistent_data::SessionStore::getInstance()
                               .getTimeSinceLastTimeoutInSeconds();
    }

    ~KvmSession()
    {
        stopTimeoutTimer();
    }

  protected:
    void doRead()
    {
        std::size_t bytes = outputBuffer.capacity() - outputBuffer.size();
        BMCWEB_LOG_DEBUG("conn:{}, Reading {} from kvm socket", logPtr(&conn),
                         bytes);
        hostSocket.async_read_some(
            outputBuffer.prepare(outputBuffer.capacity() - outputBuffer.size()),
            [this, weak(weak_from_this())](const boost::system::error_code& ec,
                                           std::size_t bytesRead) {
            auto self = weak.lock();
            if (self == nullptr)
            {
                return;
            }
            BMCWEB_LOG_DEBUG("conn:{}, read done.  Read {} bytes",
                             logPtr(&conn), bytesRead);
            if (ec)
            {
                BMCWEB_LOG_ERROR(
                    "conn:{}, Couldn't read from KVM socket port: {}",
                    logPtr(&conn), ec);
                if (ec != boost::asio::error::operation_aborted)
                {
                    conn.close("Error in connecting to KVM port");
                }
                return;
            }

            outputBuffer.commit(bytesRead);
            std::string_view payload(
                static_cast<const char*>(outputBuffer.data().data()),
                bytesRead);
            BMCWEB_LOG_DEBUG("conn:{}, Sending payload size {}", logPtr(&conn),
                             payload.size());
            conn.sendBinary(payload);
            outputBuffer.consume(bytesRead);

            // closing KVM when web session deleted
            if (!conn.session->kvmConnections)
            {
                closeWebSocket();
            }
            doRead();
        });
    }

    void doWrite()
    {
        if (doingWrite)
        {
            BMCWEB_LOG_DEBUG("conn:{}, Already writing.  Bailing out",
                             logPtr(&conn));
            return;
        }
        if (inputBuffer.size() == 0)
        {
            BMCWEB_LOG_DEBUG("conn:{}, inputBuffer empty.  Bailing out",
                             logPtr(&conn));
            return;
        }

        doingWrite = true;
        hostSocket.async_write_some(
            inputBuffer.data(),
            [this, weak(weak_from_this())](const boost::system::error_code& ec,
                                           std::size_t bytesWritten) {
            auto self = weak.lock();
            if (self == nullptr)
            {
                return;
            }
            BMCWEB_LOG_DEBUG("conn:{}, Wrote {}bytes", logPtr(&conn),
                             bytesWritten);
            doingWrite = false;
            inputBuffer.consume(bytesWritten);

            if (ec == boost::asio::error::eof)
            {
                conn.close("KVM socket port closed");
                return;
            }
            if (ec)
            {
                BMCWEB_LOG_ERROR("conn:{}, Error in KVM socket write {}",
                                 logPtr(&conn), ec);
                if (ec != boost::asio::error::operation_aborted)
                {
                    conn.close("Error in reading to host port");
                }
                return;
            }

            persistent_data::SessionStore::getInstance()
                .updatelastSessionTime();
            doWrite();
        });
    }

    void startTimeoutTimer()
    {
        if (!timerRunning) // Check if the timer is not already running
        {
            timerRunning = true;
            lastActivityTime =
                persistent_data::SessionStore::getInstance()
                    .getTimeSinceLastTimeoutInSeconds(); // Get the current time
                                                         // and store it in
                                                         // lastActivityTime

            // Start a new thread (timeoutTimer) to handle the timeout logic
            timeoutTimer = std::thread([this]() {
                while (timerRunning)
                {
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    // Get the timeout value from the persistent data store
                    int64_t timeoutValue =
                        persistent_data::SessionStore::getInstance()
                            .getTimeoutInSeconds();
                    timeoutInSeconds = std::chrono::seconds(
                        timeoutValue);      // Convert the timeout value to
                                            // std::chrono::seconds and update
                                            // timeoutInSeconds
                    applySessionTimeouts(); // Call the function to apply
                                            // session timeouts
                }
            });
        }
    }

    void stopTimeoutTimer()
    {
        if (timerRunning)         // Check if the timer is currently running
        {
            timerRunning = false; // Set the flag to indicate that the timer is
                                  // no longer running
            if (timeoutTimer.joinable()) // Check if the thread associated with
                                         // the timeoutTimer is joinable
            {
                timeoutTimer.join(); // If it's joinable, join (wait for) the
                                     // thread to finish its execution
            }
        }
    }

    void applySessionTimeouts()
    {
        auto timeNow = std::chrono::steady_clock::now();
        int64_t timeoutValue =
            persistent_data::SessionStore::getInstance().getTimeoutInSeconds();
        timeoutInSeconds = std::chrono::seconds(timeoutValue);
        if (timeNow - lastActivityTime >=
            timeoutInSeconds) // This condition checks if the time elapsed since
                              // the last activity in the KVM session is greater
                              // than or equal to the configured timeout. If
                              // true, it means that the session has been
                              // inactive for the specified timeout duration.
        {
            closeWebSocket();
        }
    }

    void closeWebSocket()
    {
        conn.close("Session timeout");
    }

    crow::websocket::Connection& conn;
    boost::asio::ip::tcp::socket hostSocket;
    boost::beast::flat_static_buffer<1024UL * 50UL> outputBuffer;
    boost::beast::flat_static_buffer<1024UL> inputBuffer;
    bool doingWrite{false};
    std::atomic<bool> timerRunning{false};
    std::thread timeoutTimer;
    std::chrono::time_point<std::chrono::steady_clock> lastActivityTime;
    std::chrono::seconds timeoutInSeconds;
};

using SessionMap = boost::container::flat_map<crow::websocket::Connection*,
                                              std::shared_ptr<KvmSession>>;
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static SessionMap sessions;

inline void requestRoutes(App& app)
{
    const uint maxSessions = redfish::system_utils::isDualHostEnabled() ? 4 : 2;
    sessions.reserve(maxSessions);

    BMCWEB_ROUTE(app, "/kvm/0")
        .websocket()
        .privileges(redfish::privileges::privilegeSetConfigureManager)
        .onopen([maxSessions](crow::websocket::Connection& conn) {
        BMCWEB_LOG_DEBUG("Connection {} opened", logPtr(&conn));

            sessions[&conn] = std::make_shared<KvmSession>(conn);
            conn.session->kvmConnections++;

            if (!redfish::system_utils::isDualHostEnabled())
            {
                if (conn.session->cookieAuth == 1)
                {
                    auto it =
                        std::find(csrfTokenlist.begin(), csrfTokenlist.end(),
                                  conn.session->csrfToken);
                    if (it != csrfTokenlist.end())
                    {
                        csrfTokenlist.push_back(conn.session->csrfToken);
                        conn.close(
                            "Already a session is running in this browser");
                        return;
                    }
                    else
                    {
                        csrfTokenlist.push_back(conn.session->csrfToken);
                    }
                }
            }
        if (getActiveKVMSessionsFromDBus() >= maxSessions)
        {
            conn.close("Max sessions are already connected");
            return;
        }

    })
        .onclose([](crow::websocket::Connection& conn, const std::string&) {
            if (!redfish::system_utils::isDualHostEnabled())
            {
                if (conn.session->cookieAuth == 1)
                {
                    auto it =
                        std::find(csrfTokenlist.rbegin(), csrfTokenlist.rend(),
                                  conn.session->csrfToken);
                    if (it != csrfTokenlist.rend())
                    {
                        csrfTokenlist.erase(std::next(it).base());
                    }
                }
            }
        sessions.erase(&conn);
        conn.session->kvmConnections--;
    })
        .onmessage([](crow::websocket::Connection& conn,
                      const std::string& data, bool) {
        if (sessions[&conn])
        {
            sessions[&conn]->onMessage(data);
        }
    });

    if (redfish::system_utils::isDualHostEnabled())
    {
        BMCWEB_ROUTE(app, "/kvm/1")
            .websocket()
            .privileges(redfish::privileges::privilegeSetConfigureManager)
            .onopen([maxSessions](crow::websocket::Connection& conn) {
                BMCWEB_LOG_DEBUG("Connection {} opened", logPtr(&conn));

        const std::uint16_t port = 5901;
        sessions[&conn] = std::make_shared<KvmSession>(conn, port);
        conn.session->kvmConnections++;

        if (getActiveKVMSessionsFromDBus() >= maxSessions)
        {
            conn.close("Max sessions are already connected");
            return;
        }

    })
        .onclose([](crow::websocket::Connection& conn, const std::string&) {
        sessions.erase(&conn);
        conn.session->kvmConnections--;
    })
        .onmessage([](crow::websocket::Connection& conn,
                      const std::string& data, bool) {
        if (sessions[&conn])
        {
            sessions[&conn]->onMessage(data);
        }
    });
    }
}

} // namespace obmc_kvm
} // namespace crow
