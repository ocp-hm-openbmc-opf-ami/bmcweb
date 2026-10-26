// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "async_resp.hpp"
#include "http_request.hpp"
#include "virtual_media.hpp"

#include <boost/beast/http/status.hpp>

#include <memory>
#include <string>

#include <gtest/gtest.h>

namespace redfish
{
namespace
{

TEST(VirtualMedia, MissingUserNameUsesRedfishParameterName)
{
    auto response = std::make_shared<bmcweb::AsyncResp>();
    crow::Request request;
    InsertMediaActionParams params;
    params.imageUrl = "https://example.com/image.iso";
    params.transferProtocolType = "HTTPS";

    validateParams(response, "", "system", params, request, "CD");

    EXPECT_EQ(response->res.result(), boost::beast::http::status::bad_request);
    EXPECT_EQ(response->res.jsonValue["error"]["@Message.ExtendedInfo"][0]
                  ["MessageArgs"][1],
              "UserName");
}

} // namespace
} // namespace redfish
