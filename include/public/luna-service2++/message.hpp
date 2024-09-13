// Copyright (c) 2014-2021 LG Electronics, Inc.
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

#include <luna-service2/lunaservice.h>
#include <cassert>
#include <iostream>

#include "error.hpp"
#include "payload.hpp"

namespace LS {

class Handle;

/**
 * @ingroup LunaServicePP
 * @brief LSMessage wrapper
 */
class Message
{
public:
    Message() : _message(nullptr) { }

    Message(const Message &o)
    {
        _message = o._message;
        if (_message) LSMessageRef(_message);
    }

    Message& operator=(const Message &o)
    {
        if (this == &o)
            return *this;
        if (_message) LSMessageUnref(_message);
        _message = o._message;
        if (_message) LSMessageRef(_message);
        return *this;
    }

    Message(Message &&other) : _message(other._message)
    {
        other._message = nullptr;
    }

    Message(LSMessage *message)
        : _message(message)
    {
        LSMessageRef(_message);
    }

    Message &operator=(Message &&other)
    {
        if (_message)
        {
            LSMessageUnref(_message);
        }
        _message = other._message;
        other._message = nullptr;
        return *this;
    }

    ~Message()
    {
        if (_message)
            LSMessageUnref(_message);
    }

    /**
     * @return underlying LSMessage object
     */
    LSMessage *get() { return _message; }

    /**
     * @return underlying LSMessage object
     */
    const LSMessage *get() const { return _message; }

    /**
     * @return true if there is a message
     */
    explicit operator bool() const { return _message; }

    void print(FILE *out) const
    {
        LSMessagePrint(_message, out);
    }

    bool isHubError() const
    {
        return LSMessageIsHubErrorMessage(_message);
    }

    const char *getUniqueToken() const
    {
        return LSMessageGetUniqueToken(_message);
    }

    const char *getKind() const
    {
        return LSMessageGetKind(_message);
    }

    const char *getApplicationID() const
    {
        return LSMessageGetApplicationID(_message);
    }

    const char *getSender() const
    {
        return LSMessageGetSender(_message);
    }

    const char *getSenderServiceName() const
    {
        return LSMessageGetSenderServiceName(_message);
    }

    const char *getSenderExePath() const {
        return LSMessageGetSenderExePath(_message);
    }

    const char *getSenderTrustLevel() const {
        return LSMessageGetSenderTrustLevel(_message);
    }

    pid_t getSenderPid() const {
        return LSMessageGetSenderPid(get());
    }

    uid_t getSenderUid() const {
        return LSMessageGetSenderUid(get());
    }

    gid_t getSenderGid() const {
        return LSMessageGetSenderGid(get());
    }

    bool getSenderProcessInfo(LSProcessInfo* proc_info) const {
        return LSMessageGetSenderProcessInfo(get(), proc_info);
    }

    const char *getCategory() const
    {
        return LSMessageGetCategory(_message);
    }

    const char *getMethod() const
    {
        return LSMessageGetMethod(_message);
    }

    const char *getPayload() const
    {
        return LSMessageGetPayload(_message);
    }

    /**
     * Access payload in message
     *
     * @return Valid PayloadRef
     */
    LS::PayloadRef accessPayload() const
    {
        return LSMessageAccessPayload(_message);
    }

    LSMessageToken getMessageToken() const
    {
        return LSMessageGetToken(_message);
    }

    LSMessageToken getResponseToken() const
    {
        return LSMessageGetResponseToken(_message);
    }

    bool isSubscription() const
    {
        return LSMessageIsSubscription(_message);
    }

    void respond(const char *reply_payload)
    {
        Error error;

        if (!LSMessageRespond(_message, reply_payload, error.get()))
            throw error;
    }

    /**
     * Respond with payload via LS2.
     *
     * @param payload a payload to respond
     * @note Throw an exception on failure.
     */
    void respond(LS::Payload payload)
    {
        Error error;

        if (!LSMessageRespondWithPayload(_message, payload, error)) throw error;
    }

    void reply(Handle &service_handle, const char *reply_payload);

private:
    LSMessage *_message;

private:

    friend std::ostream &operator<<(std::ostream &os, const Message &message)
    {
        return os << "LS MESSAGE from service '" << message.getSenderServiceName()
            << "'" << ", category: '" << message.getCategory() << "'"
            << ", method: '" << message.getMethod() << "'" << ", payload: "
            << message.getPayload();
    }
};

} //namespace LS;
