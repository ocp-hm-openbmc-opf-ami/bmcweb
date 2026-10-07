// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#include "async_resp.hpp"
#include "http/http2_connection.hpp"
#include "http/http_request.hpp"
#include "http/http_response.hpp"
#include "nghttp2_adapters.hpp"

#include <nghttp2/nghttp2.h>
#include <unistd.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/impl/write.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast/_experimental/test/stream.hpp>
#include <boost/beast/http/field.hpp>

#include <bit>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
namespace crow
{

namespace
{

using ::testing::Pair;
using ::testing::UnorderedElementsAre;

struct FakeHandler
{
    bool called = false;
    void handle(const std::shared_ptr<Request>& req,
                const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
    {
        called = true;
        EXPECT_EQ(req->url().buffer(), "/redfish/v1/");
        EXPECT_EQ(req->methodString(), "GET");
        EXPECT_EQ(req->getHeaderValue(boost::beast::http::field::user_agent),
                  "curl/8.5.0");
        EXPECT_EQ(req->getHeaderValue(boost::beast::http::field::accept),
                  "*/*");
        EXPECT_EQ(req->getHeaderValue(":authority"), "localhost:18080");
        asyncResp->res.write("StringOutput");
    }
};

std::string getDateStr()
{
    return "TestTime";
}

void unpackHeaders(std::string_view dataField,
                   std::vector<std::pair<std::string, std::string>>& headers)
{
    nghttp2_hd_inflater_ex inflater;

    while (!dataField.empty())
    {
        nghttp2_nv nv;
        int inflateFlags = 0;
        const uint8_t* data = std::bit_cast<const uint8_t*>(dataField.data());
        ssize_t parsed =
            inflater.hd2(&nv, &inflateFlags, data, dataField.size(), 1);

        ASSERT_GT(parsed, 0);
        dataField.remove_prefix(static_cast<size_t>(parsed));
        if ((inflateFlags & NGHTTP2_HD_INFLATE_EMIT) > 0)
        {
            const char* namePtr = std::bit_cast<const char*>(nv.name);
            std::string key(namePtr, nv.namelen);
            const char* valPtr = std::bit_cast<const char*>(nv.value);
            std::string value(valPtr, nv.valuelen);
            headers.emplace_back(key, value);
        }
        if ((inflateFlags & NGHTTP2_HD_INFLATE_FINAL) > 0)
        {
            EXPECT_EQ(inflater.endHeaders(), 0);
            break;
        }
    }
}

TEST(http_connection, RequestPropogates)
{
    using namespace std::literals;
    boost::asio::io_context io;
    boost::beast::test::stream stream(io);
    boost::beast::test::stream out(io);
    stream.connect(out);
    // This is a binary pre-encrypted stream captured from curl for a request to
    // curl https://localhost:18080/redfish/v1/
    std::string_view toSend =
        // Hello
        "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        // 18 byte settings frame
        "\x00\x00\x12\x04\x00\x00\x00\x00\x00"
        // Settings
        "\x00\x03\x00\x00\x00\x64\x00\x04\x00\xa0\x00\x00\x00\x02\x00\x00\x00\x00"
        // Window update frame
        "\x00\x00\x04\x08\x00\x00\x00\x00\x00"
        // Window update
        "\x3e\x7f\x00\x01"
        // Header frame END_STREAM, END_HEADERS set
        "\x00\x00\x29\x01\x05\x00\x00\x00"
        // Header payload
        "\x01\x82\x87\x41\x8b\xa0\xe4\x1d\x13\x9d\x09\xb8\x17\x80\xf0\x3f"
        "\x04\x89\x62\xc2\xc9\x29\x91\x3b\x1d\xc2\xc7\x7a\x88\x25\xb6\x50"
        "\xc3\xcb\xb6\xb8\x3f\x53\x03\x2a\x2f\x2a"sv;

    boost::asio::write(out, boost::asio::buffer(toSend));

    FakeHandler handler;
    boost::asio::steady_timer timer(io);
    std::function<std::string()> date(getDateStr);
    auto conn = std::make_shared<
        HTTP2Connection<boost::beast::test::stream, FakeHandler>>(
        std::move(stream), &handler, date);
    conn->start();

    std::string_view expectedPrefix =
        // Settings frame size 13
        "\x00\x00\x0c\x04\x00\x00\x00\x00\x00"
        // 4 max concurrent streams
        "\x00\x03\x00\x00\x00\x04"
        // Enable push = false
        "\x00\x02\x00\x00\x00\x00"
        // Settings ACK from server to client
        "\x00\x00\x00\x04\x01\x00\x00\x00\x00"sv;

    std::string_view expectedPostfix =
        // Data Frame, Length 12, Stream 1, End Stream flag set
        "\x00\x00\x0c\x00\x01\x00\x00\x00\x01"
        // The body expected
        "StringOutput"sv;

    std::string outData;
    auto runUntilSize = [&io, &out, &outData](size_t minSize) {
        for (size_t i = 0; outData.size() < minSize && i < 1000; ++i)
        {
            ASSERT_GT(io.run_one(), 0U);
            outData = out.str();
        }
        ASSERT_GE(outData.size(), minSize);
    };

    // Wait until we have enough bytes for connection preamble plus one frame
    // header, then parse the HPACK block length from the HEADERS frame.
    runUntilSize(expectedPrefix.size() + 9U);

    std::string_view outStr(outData);
    EXPECT_TRUE(handler.called);

    // check the stream output against expected
    EXPECT_EQ(outStr.substr(0, expectedPrefix.size()), expectedPrefix);
    outStr.remove_prefix(expectedPrefix.size());

    ASSERT_GE(outStr.size(), 9U);
    uint32_t headerSize =
        (static_cast<uint32_t>(static_cast<uint8_t>(outStr[0])) << 16U) |
        (static_cast<uint32_t>(static_cast<uint8_t>(outStr[1])) << 8U) |
        static_cast<uint32_t>(static_cast<uint8_t>(outStr[2]));

    EXPECT_EQ(static_cast<uint8_t>(outStr[3]), NGHTTP2_HEADERS);
    EXPECT_EQ(static_cast<uint8_t>(outStr[4]), NGHTTP2_FLAG_END_HEADERS);
    EXPECT_EQ(static_cast<uint8_t>(outStr[5]), 0);
    EXPECT_EQ(static_cast<uint8_t>(outStr[6]), 0);
    EXPECT_EQ(static_cast<uint8_t>(outStr[7]), 0);
    EXPECT_EQ(static_cast<uint8_t>(outStr[8]), 1);

    size_t fullResponseSize =
        expectedPrefix.size() + 9U + static_cast<size_t>(headerSize) +
        expectedPostfix.size();
    runUntilSize(fullResponseSize);
    outStr = outData;
    outStr.remove_prefix(expectedPrefix.size() + 9U);
    ASSERT_GE(outStr.size(), headerSize + expectedPostfix.size());

    std::vector<std::pair<std::string, std::string>> headers;
    unpackHeaders(outStr.substr(0, static_cast<size_t>(headerSize)), headers);
    outStr.remove_prefix(headerSize);

    EXPECT_THAT(
        headers,
        UnorderedElementsAre(
            Pair(":status", "200"), Pair("content-length", "12"),
            Pair("strict-transport-security",
                 "max-age=31536000; includeSubdomains"),
            Pair("cache-control", "no-store, max-age=0"),
            Pair("x-content-type-options", "nosniff"),
            Pair("x-xss-protection", "0"),
            Pair("referrer-policy", "no-referrer"), Pair("pragma", "no-cache"),
            Pair("date", "TestTime"), Pair("access-control-allow-origin", "*"),
            Pair("odata-version", "4.0")));

    EXPECT_EQ(outStr, expectedPostfix);
}

} // namespace
} // namespace crow
