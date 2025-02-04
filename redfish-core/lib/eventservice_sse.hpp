// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#pragma once

#include "filter_expr_executor.hpp"
#include "privileges.hpp"
#include "registries/privilege_registry.hpp"

#include <app.hpp>
#include <event_service_manager.hpp>

#include <memory>
#include <string>

namespace redfish
{

inline void
    createSubscription(std::shared_ptr<crow::sse_socket::Connection>& conn,
                       const crow::Request& req,
                       const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    EventServiceManager& manager =
        EventServiceManager::getInstance(&conn->getIoContext());
    if ((manager.getNumberOfSubscriptions() >= maxNoOfSubscriptions) ||
        manager.getNumberOfSSESubscriptions() >= maxNoOfSSESubscriptions)
    {
        messages::eventSubscriptionLimitExceeded(asyncResp->res);
        asyncResp->res.result(boost::beast::http::status::bad_request);
        return;
    }

    std::optional<filter_ast::LogicalAnd> filter;
    boost::urls::params_base::iterator filterIt =
        req.url().params().find("$filter");
    if (filterIt != req.url().params().end())
    {
        std::string_view filterValue = (*filterIt).value;
        filter = parseFilter(filterValue);
        if (!filter)
        {
            // conn.close(std::format("Bad $filter param: {}", filterValue));
            return;
        }
    }
    std::string lastEventId(req.getHeaderValue("Last-Event-Id"));

    BMCWEB_LOG_DEBUG("Request query param size: {}", req.url().params().size());

    // EventService SSE supports only "$filter" query param.
    if (req.url().params().size() > 1)
    {
        messages::invalidQueryFilter(asyncResp->res);
        return;
    }
    std::string evtFormatType;
    std::string queryFilters;
    if (req.url().params().size())
    {
        boost::urls::params_view::iterator it =
            req.url().params().find("$filter");
        if (it == req.url().params().end())
        {
            messages::invalidQueryFilter(asyncResp->res);
            return;
        }
        queryFilters = std::string((*it).value);
    }
    else
    {
        evtFormatType = "Event";
    }

    std::vector<std::string> msgIds;
    std::vector<std::string> regPrefixes;
    std::vector<std::string> mrdsArray;

    if (!queryFilters.empty())
    {
        // Reading from query params.
        bool status = readSSEQueryParams(queryFilters, evtFormatType, msgIds,
                                         regPrefixes, mrdsArray);
        if (!status)
        {
            messages::invalidQueryFilter(asyncResp->res);
            return;
        }

        // RegsitryPrefix and messageIds are mutuly exclusive as per redfish
        // specification.
        if (!regPrefixes.empty() && !msgIds.empty())
        {
            messages::propertyValueConflict(asyncResp->res, "RegistryPrefix",
                                            "MessageId");
            return;
        }

        if (!evtFormatType.empty())
        {
            if (std::find(supportedEvtFormatTypes.begin(),
                          supportedEvtFormatTypes.end(), evtFormatType) ==
                supportedEvtFormatTypes.end())
            {
                messages::propertyValueNotInList(asyncResp->res, evtFormatType,
                                                 "EventFormatType");
                return;
            }
        }
        else
        {
            // If nothing specified, using default "Event"
            evtFormatType = "Event";
        }

        if (!regPrefixes.empty())
        {
            for (const std::string& it : regPrefixes)
            {
                if (std::find(supportedRegPrefixes.begin(),
                              supportedRegPrefixes.end(), it) ==
                    supportedRegPrefixes.end())
                {
                    messages::propertyValueNotInList(asyncResp->res, it,
                                                     "RegistryPrefix");
                    return;
                }
            }
        }

        if (!msgIds.empty())
        {
            std::vector<std::string> registryPrefix;

            // If no registry prefixes are mentioned, consider all supported
            // prefixes to validate message ID
            if (regPrefixes.empty())
            {
                registryPrefix.assign(supportedRegPrefixes.begin(),
                                      supportedRegPrefixes.end());
            }
            else
            {
                registryPrefix = regPrefixes;
            }

            for (const std::string& id : msgIds)
            {
                bool validId = false;

                // Check for Message ID in each of the selected Registry
                for (const std::string& it : registryPrefix)
                {
                    const std::span<const redfish::registries::MessageEntry>
                        registry =
                            redfish::registries::getRegistryFromPrefix(it);

                    if (std::any_of(
                            registry.begin(), registry.end(),
                            [&id](const redfish::registries::MessageEntry&
                                      messageEntry) {
                                return !id.compare(messageEntry.first);
                            }))
                    {
                        validId = true;
                        break;
                    }
                }

                if (!validId)
                {
                    messages::propertyValueNotInList(asyncResp->res, id,
                                                     "MessageIds");
                    return;
                }
            }
        }
    }

    std::shared_ptr<Subscription> subValue =
        std::make_shared<Subscription>(conn);

    if (subValue->userSub == nullptr)
    {
        BMCWEB_LOG_ERROR("Subscription data is null");
        // conn.close("Internal Error");
        return;
    }

    // GET on this URI means, Its SSE subscriptionType.
    subValue->userSub->subscriptionType = redfish::subscriptionTypeSSE;

    subValue->userSub->protocol = "Redfish";
    subValue->userSub->retryPolicy = "TerminateAfterRetries";
    subValue->userSub->eventFormatType = evtFormatType;
    subValue->userSub->owner = req.session->username;
    subValue->userSub->registryMsgIds = msgIds;
    subValue->userSub->registryPrefixes = regPrefixes;
    subValue->userSub->metricReportDefinitions = mrdsArray;

    std::string id;
    manager.addSSESubscription(subValue, lastEventId, id);

    if (id.empty())
    {
        BMCWEB_LOG_WARNING("SSE subscriptions creation failed !");
        messages::internalError(asyncResp->res);
        return;
    }

    subValue->userSub->id = id;

    // All success, So lets send SSE headers
    conn->sendSSEHeader();
    return;
}

inline void
    deleteSubscription(std::shared_ptr<crow::sse_socket::Connection>& conn)
{
    redfish::EventServiceManager::getInstance(&conn->getIoContext())
        .deleteSseSubscription(conn);
}

inline void requestRoutesEventServiceSse(App& app)
{
    // Note, this endpoint is given the same privilege level as creating a
    // subscription, because functionally, that's the operation being done
    BMCWEB_ROUTE(app, "/redfish/v1/EventService/SSE")
        .serverSentEvent()
        .privileges(redfish::privileges::postEventDestinationCollection)
        .onopen(createSubscription)
        .onclose(deleteSubscription);
}
} // namespace redfish
