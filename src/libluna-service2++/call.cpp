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

#include "call.hpp"
#include "error.hpp"

namespace LS
{

struct _GMainContext_holder
{
    bool h;
    GMainContext* c;

    explicit _GMainContext_holder(GMainContext* c)
        : h(g_main_context_acquire(c) == TRUE)
        , c(c)
    { }

    ~_GMainContext_holder()
    { if (h) g_main_context_release(c); }

    explicit
    operator bool ()
    { return h; }
};

Message Call::get(unsigned long msTimeout)
{
    LS::Error error;
    GMainContext *context = LSGmainGetContext(_sh, error.get());

    assert(context);

    _GMainContext_holder h_ctx(context);
    return h_ctx
        ? waitOnMainLoop(msTimeout)
        : wait(msTimeout);
}

Message Call::wait(unsigned long msTimeout)
{
    bool gotMessage = true;
    auto q_check = [this] { return !_queue.empty(); };
    std::unique_lock < std::mutex > ul { _mutex };
    if (msTimeout)
       gotMessage = _cv.wait_for(ul, msTimeout, q_check);
    else
       _cv.wait(ul, q_check);

    if (gotMessage)
    {
        Message reply = std::move(_queue.front());
        _queue.pop();
        return reply;
    }
    return {};
}

Message Call::waitOnMainLoop(long unsigned int msTimeout)
{
    Message reply;
    auto try_get = [this, &reply] () -> bool {
        std::unique_lock < std::mutex > ul { _mutex };
        if (!_queue.empty())
        {
            reply = std::move(_queue.front());
            _queue.pop();
            return true;
        }
        return false;
    };

    if (try_get())
        return reply;

    LS::Error error;
    GMainContext *mainloopCtx = LSGmainGetContext(_sh, error.get());
    GSource *timeoutSrc = nullptr;

    _timeoutExpired = false;
    if (msTimeout)
    {
        timeoutSrc = g_timeout_source_new(msTimeout);
        g_source_set_callback(timeoutSrc, (GSourceFunc)onWaitCB, this, nullptr);
        g_source_attach(timeoutSrc, mainloopCtx);
    }

    while (!_timeoutExpired)
    {
        if (FALSE == g_main_context_iteration(mainloopCtx, TRUE))
            continue;

        if (try_get())
            break;
    }

    if (timeoutSrc)
    {
        g_source_destroy(timeoutSrc);
        g_source_unref(timeoutSrc);
    }

    return reply;
}

bool Call::handleReply(LSHandle* sh, LSMessage* reply)
{
    std::unique_lock < std::mutex > lockg { _mutex };
    if (LSMESSAGE_TOKEN_INVALID == _token)
        return false;

    if (_single)
        _token = LSMESSAGE_TOKEN_INVALID;

    if (_callCB)
    {
        auto cb = _callCB;
        auto ctx = _callCtx;
        lockg.unlock();

        (cb)(sh, reply, ctx);
    }
    else
    {
        _queue.push(reply);
        lockg.unlock();
        _cv.notify_one();
    }
    return true;
}

bool Call::replyCallback(LSHandle* sh, LSMessage* reply, void* context)
{
    if (context)
    {
        CallPtr * call = static_cast<CallPtr *>(context);
        (*call)->handleReply(sh, reply);
    }
    return true;
}

gboolean Call::onWaitCB(gpointer context)
{
    (static_cast<Call *>(context))->_timeoutExpired = true;
    return G_SOURCE_REMOVE;
}

}
