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

#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <chrono>
#include <mutex>
#include <queue>
#include <thread>
#include <memory>

#include <luna-service2/lunaservice.h>
#include "message.hpp"
#include "condition_variable.hpp"

namespace LS {


/**
 * @ingroup LunaServicePP
 * @brief This class provides the ability to make a call to service category methods, it controls the lifetime of the call.
 * Call is canceled on object destroy.
 */
class Call
{
    friend class Handle;

public:

    Call()
        : _token { LSMESSAGE_TOKEN_INVALID }
        , _sh { nullptr }
        , _single { false }
        , _callCB { nullptr }
        , _callCtx { nullptr }
        , _context { new CallPtr(this) }
    { }

    /** @brief Destroy the call, and cancel the call if it is active
      */
    ~Call()
    { cancel(); }

    Call(Call &&other)
        : _token { other._token }
        , _sh { other._sh }
        , _single { other._single }
        , _callCB { other._callCB }
        , _callCtx { other._callCtx }
        , _context { std::move(other._context) }
    {
        *_context = this;
        std::lock_guard < std::mutex > lockg { other._mutex };
        other._token = LSMESSAGE_TOKEN_INVALID;
        other._sh = nullptr;
        other._callCB = nullptr;
        other._callCtx = nullptr;
        _queue = std::move(other._queue);
    }

    Call &operator=(Call &&other)
    {
        if (this != &other)
        {
            std::unique_lock < std::mutex > thisLock { _mutex, std::defer_lock };
            std::unique_lock < std::mutex > thatLock { other._mutex, std::defer_lock };
            std::lock(thisLock, thatLock);
            cancel();
            _token = other._token;
            _sh = other._sh;
            _callCB = other._callCB;
            _callCtx = other._callCtx;
            _context = std::move(other._context);
            *_context = this;
            _queue = std::move(other._queue);
            other._token = LSMESSAGE_TOKEN_INVALID;
            other._sh = nullptr;
            other._callCB = nullptr;
            other._callCtx = nullptr;
        }
        return *this;
    }

    Call(const Call &) = delete;
    Call &operator=(const Call &) = delete;

    /**
     * @brief Send a cancel message to service to end call session and
     * unregister any callback associated with call.
     */
    void cancel()
    {
        if (isActive())
        {
            Error error;
            if (LSCallCancel(_sh, _token, error.get()))
                _token = LSMESSAGE_TOKEN_INVALID;
            else
                error.logError("LS_CANC_METH");
        }
    }

    /**
     * @brief Set timeout for a method call.
     * The call will be canceled if no reply is received after msTimeout milliseconds.
     * @param msTimeout time after which method can be canceled
     * @return The setTimeout method returns true if the timeout was successfully set for the call. The setTimeout returns false if the timeout could not be set for the call.
     */
    bool setTimeout(int msTimeout) const
    {
        return isActive()
            ? LSCallSetTimeout(_sh, _token, msTimeout, Error().get())
            : false;
    }

    /**
     * @brief Set callback to continue.
     * This is the callback that is called for each message that arrives. It replaces any previous callback if it exists. 
     * If the internal queue already contains messages then the callback is called sequentially for every message in the queue.
     * @param callback callback function
     * @param context user data
     */
    void continueWith(LSFilterFunc callback, void *context)
    {
        std::lock_guard < std::mutex > lockg { _mutex };
        _callCB = callback;
        _callCtx = context;
        if (!_callCB)
        {
            return;
        }

        while (!_queue.empty())
        {
            (_callCB)(_sh, _queue.front().get(), _callCtx);
            _queue.pop();
        }
    }

    /**
     * Retrieve a message object from the top of its queue.
     * It waits for new messages if there is none. It blocks execution until a new message arrives.\n
     * if msTimeout != 0 the call will be canceled if no reply is received after msTimeout milliseconds.
     * @note If continueWith was called then this call will wait infinitely because callback
     * from continueWith intercepts all messages and keeps the message queue empty.
     * @param msTimeout time after which method can be canceled. If msTimeout == 0 message wasn't canceled.
     * @return message. The message could be empty. Check for an empty message using an if (message) statement before processing the message.
     */
    Message get(unsigned long msTimeout = 0);

    /**
     * @brief Return status of the call
     * If a call is active, it is expected to receive replies and will be canceled in the destructor.\n
     * If a call is not active, it is not expected to receive replies (for calls with one reply), and will not be cancelled in the destructor.
     * @return true if a call is active, false if a call is not active
     */
    bool isActive() const
    {
        return LSMESSAGE_TOKEN_INVALID != _token && _sh;
    }

private:

    LSMessageToken _token;
    LSHandle *_sh;
    bool _single;
    LSFilterFunc _callCB;
    void *_callCtx;
    typedef Call *CallPtr;
    std::unique_ptr<CallPtr> _context;
    std::mutex _mutex;
    std::queue<Message> _queue;
    volatile bool _timeoutExpired;
    LS::condition_variable _cv;

    void call(LSHandle *sh, const char *uri, const char *payload, bool oneReply, const char *appID = NULL)
    {
        Error error;

        _sh = sh;
        _single = oneReply;
        auto callFunc = _single ? LSCallFromApplicationOneReply : LSCallFromApplication;

        if (!callFunc(_sh, uri, payload, appID, &replyCallback, _context.get(), &_token, error.get()))
            throw error;
    }

    void callProxy(LSHandle *sh,
                   const char *origin_exe,
                   const char *origin_id,
                   const char *origin_name,
                   const char *uri,
                   const char *payload,
                   bool oneReply,
                   const char *appID = NULL) {
        Error error;

        _sh = sh;
        _single = oneReply;
        auto callFunc = _single ? LSCallProxyFromApplicationOneReply : LSCallProxyFromApplication;

        if (!callFunc(_sh, origin_exe, origin_id, origin_name, uri, payload, appID,
                      &replyCallback, _context.get(), &_token, error.get()))
            throw error;
    }

    void callSignal(LSHandle *sh, const char *category, const char *methodName)
    {
        Error error;

        _sh = sh;
        _single = false;

        if (!LSSignalCall(_sh, category, methodName, &replyCallback, _context.get(), &_token, error.get()))
            throw error;
    }

    Message wait(unsigned long msTimeout);
    Message waitOnMainLoop(unsigned long msTimeout);

    bool handleReply(LSHandle *sh, LSMessage *reply);

    static bool replyCallback(LSHandle *sh, LSMessage *reply, void *context);

    static gboolean onWaitCB(gpointer context);

};

} //namespace LS;
