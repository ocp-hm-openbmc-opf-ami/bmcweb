// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#pragma once

#include "baserule.hpp"
#include "privilegeparametertraits.hpp"
#include "server_sent_event.hpp"

#include <functional>

namespace crow
{

class SseSocketRule :
    public BaseRule,
    public PrivilegeParameterTraits<SseSocketRule>
{
    using self_t = SseSocketRule;

  public:
    explicit SseSocketRule(const std::string& ruleIn) : BaseRule(ruleIn)
    {
        isUpgrade = true;
        // Clear GET handler
        methodsBitfield = 0;
    }

    void validate() override {}

    void handle(const Request& /*req*/,
                const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                const std::vector<std::string>& /*params*/) override
    {
        BMCWEB_LOG_ERROR(
            "Handle called on websocket rule.  This should never happen");
        asyncResp->res.result(
            boost::beast::http::status::internal_server_error);
    }

    void handleUpgrade(const Request& req,
                       const std::shared_ptr<bmcweb::AsyncResp>& /*asyncResp*/,
                       boost::asio::ip::tcp::socket&& adaptor) override
    {
        std::shared_ptr<
            crow::sse_socket::ConnectionImpl<boost::asio::ip::tcp::socket>>
            myConnection = std::make_shared<
                crow::sse_socket::ConnectionImpl<boost::asio::ip::tcp::socket>>(
                req, std::move(adaptor), openHandler, closeHandler);
        myConnection->start();
    }
    void handleUpgrade(const Request& req,
                       const std::shared_ptr<bmcweb::AsyncResp>& /*asyncResp*/,
                       boost::asio::ssl::stream<boost::asio::ip::tcp::socket>&&
                           adaptor) override
    {
        std::shared_ptr<crow::sse_socket::ConnectionImpl<
            boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>>
            myConnection = std::make_shared<crow::sse_socket::ConnectionImpl<
                boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>>(
                req, std::move(adaptor), openHandler, closeHandler);
        myConnection->start();
    }

    template <typename Func>
    self_t& onopen(Func f)
    {
        openHandler = f;
        return *this;
    }

    template <typename Func>
    self_t& onclose(Func f)
    {
        closeHandler = f;
        return *this;
    }

  private:
    std::function<void(std::shared_ptr<crow::sse_socket::Connection>&,
                       const crow::Request&,
                       const std::shared_ptr<bmcweb::AsyncResp>&)>
        openHandler;
    std::function<void(std::shared_ptr<crow::sse_socket::Connection>&)>
        closeHandler;
};

} // namespace crow
