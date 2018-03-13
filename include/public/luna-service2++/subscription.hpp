// Copyright (c) 2014-2018 LG Electronics, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>
#include <vector>
#include <algorithm>

#include "handle.hpp"
#include "message.hpp"

namespace LS {

/**
 * @ingroup LunaServicePP
 * @brief Represents a publishing point for a sender service.
 */
class SubscriptionPoint
{

    struct SubscriptionItem
    {

    friend class SubscriptionPoint;

    private:
        SubscriptionItem(Message _message, SubscriptionPoint *_parent)
            : message { std::move(_message) }
            , parent { _parent }
            , statusToken { LSMESSAGE_TOKEN_INVALID }
        { }

    public:
        ~SubscriptionItem()
        {
            if (statusToken != LSMESSAGE_TOKEN_INVALID)
                parent->cleanItem(this);
        }

        SubscriptionItem(const SubscriptionItem &) = delete;
        SubscriptionItem &operator=(const SubscriptionItem &) = delete;
        SubscriptionItem(const SubscriptionItem &&) = delete;
        SubscriptionItem &operator=(const SubscriptionItem &&) = delete;

    private:
        LS::Message message;
        LS::SubscriptionPoint *parent;
        LSMessageToken statusToken;
    };

friend struct SubscriptionItem;

public:
    SubscriptionPoint() : SubscriptionPoint { nullptr } { }

    explicit
    SubscriptionPoint(Handle *service_handle)
        : _service_handle { service_handle }
    {
        setCancelNotificationCallback();
    }

    ~SubscriptionPoint()
    {
        unsetCancelNotificationCallback();

        for (auto subscriber : _subs)
            delete subscriber;
    }

    SubscriptionPoint(const SubscriptionPoint &) = delete;
    SubscriptionPoint &operator=(const SubscriptionPoint &) = delete;
    SubscriptionPoint(SubscriptionPoint &&) = delete;
    SubscriptionPoint &operator=(SubscriptionPoint &&) = delete;

    /**
     * Assign a publisher service
     */
    void setServiceHandle(Handle *service_handle)
    {
        _service_handle = service_handle;
        setCancelNotificationCallback();
    }

    /**
     * Process subscription message. Subscribe sender of the given message.
     * @param message subscription message to process.
     * @return Returns true if the method succeeds in adding the sender of the message as a subscriber
     */
    bool subscribe(LS::Message &message) noexcept;

    /**
     * Post payload to all subscribers
     * @param payload posted data
     * @return Returns true if replies were posted successfully
     */
    bool post(const char *payload) noexcept;

    /**
     * Returns number of service subscribers
     * @retval size_t number of subscribers
     */
    std::vector<SubscriptionItem *>::size_type getSubscribersCount() const
    {
        return _subs.size();
    }

private:
    Handle *_service_handle;
    std::vector<SubscriptionItem *> _subs;

    void setCancelNotificationCallback()
    {
        if (_service_handle)
            LSCallCancelNotificationAdd(_service_handle->get(), subscriberCancelCB, this, Error().get());
    }

    void unsetCancelNotificationCallback()
    {
        if (_service_handle)
            LSCallCancelNotificationRemove(_service_handle->get(), subscriberCancelCB, this, Error().get());
    }

    static bool subscriberCancelCB(LSHandle *sh, const char *uniqueToken, void *context);
    static bool subscriberDownCB(LSHandle *sh, LSMessage *message, void *context);
    static bool postSubscriptions(gpointer user_data);
    static bool doSubscribe(gpointer user_data);

    void removeItem(const char *uniqueToken);
    void removeItem(SubscriptionItem *item, LSMessage *message);

    void cleanItem(SubscriptionItem *item);

    std::vector<LS::Message> getActiveMessages() const;
};

} // namespace LS;
