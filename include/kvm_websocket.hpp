#pragma once
#include "app.hpp"
#include "async_resp.hpp"
#include "websocket.hpp"

#include <sys/socket.h>

#include <boost/container/flat_map.hpp>
#include <registries/privilege_registry.hpp>

namespace crow
{
namespace obmc_kvm
{

static constexpr const uint maxSessions = 1;
int kvmActiveStatus = 0;

class KvmSession : public std::enable_shared_from_this<KvmSession>
{
  public:
    explicit KvmSession(crow::websocket::Connection& connIn) :
        conn(connIn), hostSocket(conn.getIoContext()),
        timeoutInSeconds(
            persistent_data::SessionStore::getInstance().getTimeoutInSeconds())
    {
        boost::asio::ip::tcp::endpoint endpoint(
            boost::asio::ip::make_address("127.0.0.1"), 5900);
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
    sessions.reserve(maxSessions);

    BMCWEB_ROUTE(app, "/kvm/0")
        .websocket()
        .privileges(redfish::privileges::privilegeSetConfigureManager)
        .onopen([](crow::websocket::Connection& conn) {
        BMCWEB_LOG_DEBUG("Connection {} opened", logPtr(&conn));

        if (sessions.size() == maxSessions)
        {
            conn.close("Max sessions are already connected");
            return;
        }

        sessions[&conn] = std::make_shared<KvmSession>(conn);
        conn.session->kvmConnections++;
        kvmActiveStatus = 1;
    })
        .onclose([](crow::websocket::Connection& conn, const std::string&) {
        sessions.erase(&conn);
        conn.session->kvmConnections--;
        kvmActiveStatus = 0;
    })
        .onmessage([](crow::websocket::Connection& conn,
                      const std::string& data, bool) {
        if (sessions[&conn])
        {
            sessions[&conn]->onMessage(data);
        }
    });
    BMCWEB_ROUTE(app, "/kvm/kvmActiveStatus")
        .privileges({{"ConfigureComponents", "ConfigureManager"}})
        .methods(boost::beast::http::verb::get)(
            [](const crow::Request& req,
               const std::shared_ptr<bmcweb::AsyncResp>& ares) {
        if (req.session == nullptr)
        {
            BMCWEB_LOG_DEBUG("Internal Server Error");
            return;
        }
        ares->res.jsonValue["kvmActiveStatus"] = kvmActiveStatus;
    });
}

} // namespace obmc_kvm
} // namespace crow
