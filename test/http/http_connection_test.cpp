// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#include "async_resp.hpp"
#include "http/http_connection.hpp"
#include "http/http_request.hpp"
#include "http/http_response.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast/_experimental/test/stream.hpp>
#include <boost/beast/http/field.hpp>
#include <boost/beast/http/verb.hpp>

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include "gtest/gtest.h"
namespace crow
{

struct FakeHandler
{
    static void handleUpgrade(
        const std::shared_ptr<Request>& /*req*/,
        const std::shared_ptr<bmcweb::AsyncResp>& /*asyncResp*/,
        boost::beast::test::stream&& /*adaptor*/)
    {
        // Handle Upgrade should never be called
        EXPECT_FALSE(true);
    }

    void handle(const std::shared_ptr<Request>& req,
                const std::shared_ptr<bmcweb::AsyncResp>& /*asyncResp*/)
    {
        EXPECT_EQ(req->method(), boost::beast::http::verb::get);
        EXPECT_EQ(req->target(), "/");
        EXPECT_EQ(req->getHeaderValue(boost::beast::http::field::host),
                  "openbmc_project.xyz");
        EXPECT_FALSE(req->keepAlive());
        EXPECT_EQ(req->version(), 11);
        EXPECT_EQ(req->body(), "");

        called = true;
    }
    bool called = false;
};

struct ClockFake
{
    bool wascalled = false;
    std::string getDateStr()
    {
        wascalled = true;
        return "TestTime";
    }
};

TEST(http_connection, RequestPropogates)
{
    boost::asio::io_context io;
    ClockFake clock;
    boost::beast::test::stream stream(io);
    boost::beast::test::stream out(io);
    stream.connect(out);

    out.write_some(boost::asio::buffer(
        "GET / HTTP/1.1\r\nHost: openbmc_project.xyz\r\nConnection: close\r\n\r\n"));
    FakeHandler handler;
    boost::asio::steady_timer timer(io);
    std::function<std::string()> date(
        std::bind_front(&ClockFake::getDateStr, &clock));
    std::shared_ptr<crow::Connection<boost::beast::test::stream, FakeHandler>>
        conn = std::make_shared<
            crow::Connection<boost::beast::test::stream, FakeHandler>>(
            &handler, std::move(timer), date, std::move(stream));
    conn->start();
    io.run_for(std::chrono::seconds(1000));
    EXPECT_TRUE(handler.called);
    std::string outStr = out.str();

    auto expectHeaderPresent = [&outStr](std::string_view headerLine) {
        EXPECT_NE(outStr.find(headerLine), std::string::npos)
            << "Missing header: " << headerLine;
    };

    EXPECT_NE(outStr.find("HTTP/1.1 200 OK\r\n"), std::string::npos);
    EXPECT_NE(outStr.find("\r\n\r\n"), std::string::npos);
    expectHeaderPresent("Access-Control-Allow-Origin: *\r\n");
    expectHeaderPresent("OData-Version: 4.0\r\n");
    expectHeaderPresent("Connection: close\r\n");
    expectHeaderPresent(
        "Strict-Transport-Security: max-age=31536000; includeSubdomains\r\n");
    expectHeaderPresent("Pragma: no-cache\r\n");
    expectHeaderPresent("Cache-Control: no-store, max-age=0\r\n");
    expectHeaderPresent("X-Content-Type-Options: nosniff\r\n");
    expectHeaderPresent("X-XSS-Protection: 0\r\n");
    expectHeaderPresent("Referrer-Policy: no-referrer\r\n");
    expectHeaderPresent("Date: TestTime\r\n");
    expectHeaderPresent("Content-Length: 0\r\n");
    EXPECT_TRUE(clock.wascalled);
}

} // namespace crow
