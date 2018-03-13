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

#include "subscription.hpp"
#include "error.hpp"
#include "json_payload.hpp"

extern "C" {

#include "message.h"

}


namespace LS {


std::mutex subscriptions_mutex;


bool SubscriptionPoint::subscribe(LS::Message &message) noexcept
{
    if (!_service_handle)
        return false;

    // TODO: Lock appropriately to resolve race with cancel nofication callback.
    if (!LSMessageIsConnected(message.get()))
        return false;

    bool retVal { false };

    try
    {
        std::unique_ptr<SubscriptionItem> item
        { new SubscriptionItem(message, this) };

        LS::Error error;
        LS::JSONPayload payload;
        payload.set("serviceName", message.getSender());
        retVal = LSCall(_service_handle->get(), "luna://com.webos.service.bus/signal/registerServerStatus",
                        payload.getJSONString().c_str(), subscriberDownCB, item.get(),
                        &item->statusToken, error.get());
        if (retVal)
        {
            std::lock_guard<std::mutex> lock(subscriptions_mutex);
            _subs.push_back(item.release());
        }
    }
    catch (...)
    {
        return false;
    }
    return retVal;
}

struct PostData
{
    PostData(std::vector<LS::Message> &&messages, const char* payload)
        : payload(payload)
        , messages(messages)
    {
    }

    std::string payload;
    std::vector<LS::Message> messages;
};

bool SubscriptionPoint::postSubscriptions(gpointer user_data)
{
    PostData *data = static_cast<PostData*>(user_data);
    try
    {
        for (auto &message: data->messages)
        {
            message.respond(data->payload.c_str());
        }
    }
    catch(LS::Error &e)
    {
        e.log(PmLogGetLibContext(), "LS_SUBS_POST_FAIL");
    }
    catch(...)
    {
    }

    // remove source from loop
    return G_SOURCE_REMOVE;
}

// Subscription responses are sent from within the same thread that Luna
// uses itself to avoid synchronization between other callbacks (like cancel).
// To avoid race between subscription point, a copy of messages to be responded
// is made and passed into the timeout callback. This also ensures a correct
// snapshot of subscriptions is addressed in case of concurrently added
// subscriptions.
bool SubscriptionPoint::post(const char *payload) noexcept
{
    if (!_service_handle)
        return false;

    LS::Error error;
    GMainContext *context = LSGmainGetContext(_service_handle->get(), error.get());
    if (!context)
    {
        error.log(PmLogGetLibContext(), "LS_SUBS_POST_FAIL");
        return false;
    }

    std::unique_ptr<PostData> data(new PostData(getActiveMessages(), payload));
    GSource* source = g_timeout_source_new(0);
    g_source_set_callback(source, (GSourceFunc)postSubscriptions, data.release(),
    [](gpointer data)
    {
        delete static_cast<PostData*>(data);
    });

    g_source_attach(source, context);
    g_source_unref(source);

    return true;
}

bool SubscriptionPoint::subscriberCancelCB(LSHandle *sh, const char *uniqueToken, void *context)
{
    SubscriptionPoint *self = static_cast<SubscriptionPoint *>(context);
    self->removeItem(uniqueToken);
    return true;
}

bool SubscriptionPoint::subscriberDownCB(LSHandle *sh, LSMessage *message, void *context)
{
    SubscriptionItem *item = static_cast<SubscriptionItem *>(context);
    SubscriptionPoint *self = item->parent;
    self->removeItem(item, message);
    return true;
}

void SubscriptionPoint::removeItem(const char *uniqueToken)
{
    std::lock_guard<std::mutex> lock(subscriptions_mutex);

    SubscriptionItem *item {nullptr};
    auto it = std::find_if(_subs.begin(), _subs.end(),
                           [uniqueToken, &item](SubscriptionItem *_item)
    {
        if (!strcmp(uniqueToken, _item->message.getUniqueToken()))
        {
            item = _item;
            return true;
        }
        return false;
    }
                          );
    if (it != _subs.end())
    {
        _subs.erase(it);
        delete item;
    }
}

void SubscriptionPoint::removeItem(LS::SubscriptionPoint::SubscriptionItem *item, LSMessage *message)
{
    LS::JSONPayload reply(LSMessageGetPayload(message));
    if (!reply.isValid())
        return;
    bool isConnected {true};
    if (!reply.get("connected", isConnected) || isConnected)
        return;

    std::lock_guard<std::mutex> lock(subscriptions_mutex);

    auto it = std::find_if(_subs.begin(), _subs.end(),
                           [item](SubscriptionItem *_item)
    {
        return (_item == item);
    }
                          );
    if (it != _subs.end())
    {
        _subs.erase(it);
        delete item;
    }
}

void SubscriptionPoint::cleanItem(LS::SubscriptionPoint::SubscriptionItem *item)
{
    if (item->statusToken != LSMESSAGE_TOKEN_INVALID)
    {
        LS::Error error;
        if (LSCallCancel(_service_handle->get(), item->statusToken, error.get())) {
            item->statusToken = LSMESSAGE_TOKEN_INVALID;
        } else {
            error.logError(MSGID_LS_CANT_CANCEL_METH);
        }
    }
}

std::vector<LS::Message> SubscriptionPoint::getActiveMessages() const
{
    std::lock_guard<std::mutex> lock(subscriptions_mutex);

    std::vector<LS::Message> messages;
    for (auto item : _subs)
    {
        if (item->statusToken != LSMESSAGE_TOKEN_INVALID)
            messages.push_back(item->message);
    }
    return messages;
}

} // namespace LS;
