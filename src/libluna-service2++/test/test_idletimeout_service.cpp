// Copyright (c) 2015-2018 LG Electronics, Inc.
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

#include <glib.h>
#include <luna-service2/lunaservice.hpp>

#include "json_payload.hpp"

#define TIMEOUT (100)

class TestService
{
private:
    int _idle_cnt;
    GMainLoop * _loop;
    LS::Handle _service;
    LS::SubscriptionPoint _sp;

public:
    TestService()
        : _idle_cnt(0)
        , _loop(g_main_loop_new(nullptr, false))
    {
        LSIdleTimeout(TIMEOUT, _timeout, this, g_main_loop_get_context(_loop));

        _service = LS::registerService("com.webos.test_service");

        LSMethod methods[] =
        {
            // control methods
            { "stop", (LSMethodFunction)_stop },
            { "idle", (LSMethodFunction)_idle },
            // test methods
            { "ping", (LSMethodFunction)_ping },
            { "subsc", (LSMethodFunction)_subsc},
            { "subscpp", (LSMethodFunction)_subscpp },
            { "inactive", (LSMethodFunction)_inactive },
            { },
        };
        _service.registerCategory("test", methods, nullptr, nullptr);
        _service.setCategoryData("test", this);
        _service.attachToLoop(_loop);
        _sp.setServiceHandle(&_service);
    }

    ~TestService()
    { g_main_loop_unref(_loop); }

    void run()
    { g_main_loop_run(_loop); }

    bool stop(LS::Message request)
    {
        LS::JSONPayload json;
        json.set("returnValue", true);
        request.respond(json.getJSONString().c_str());

        GSource *s_quit = g_timeout_source_new(10);
        g_source_set_callback(s_quit, (GSourceFunc)g_main_loop_quit, _loop, NULL);
        g_source_attach(s_quit, g_main_loop_get_context(_loop));
        g_source_unref(s_quit);

        return true;
    }

    bool idle(LS::Message request)
    {
        int tmp;
        LS::JSONPayload json(request.getPayload());
        if (json.get("set", tmp))
            _idle_cnt = tmp;
        else
            tmp = _idle_cnt;
        json = {};
        json.set("idle", tmp);
        json.set("returnValue", true);
        request.respond(json.getJSONString().c_str());

        return true;
    }

    bool ping(LS::Message request)
    {
        LS::JSONPayload json;
        json.set("returnValue", true);
        request.respond(json.getJSONString().c_str());

        return true;
    }

    bool subsc(LS::Message request)
    {
        LS::JSONPayload json;
        json.set("returnValue", LSSubscriptionAdd(_service.get(), "subsc", request.get(), LS::Error().get()));
        request.respond(json.getJSONString().c_str());

        return true;
    }

    bool subscpp(LS::Message request)
    {
        LS::JSONPayload json;
        json.set("returnValue", _sp.subscribe(request));
        request.respond(json.getJSONString().c_str());

        return true;
    }

    bool inactive(LS::Message request)
    {
        LS::JSONPayload json;
        json.set("returnValue", _sp.subscribe(request));
        LSMessageMarkInactive(request.get());
        request.respond(json.getJSONString().c_str());

        return true;
    }

    static bool _stop(LSHandle *sh, LSMessage *rq, TestService *ctx)
        { return ctx->stop(rq); }

    static bool _idle(LSHandle *sh, LSMessage *rq, TestService *ctx)
        { return ctx->idle(rq); }

    static bool _ping(LSHandle *sh, LSMessage *rq, TestService *ctx)
        { return ctx->ping(rq); }

    static bool _subsc(LSHandle *sh, LSMessage *rq, TestService *ctx)
        { return ctx->subsc(rq); }

    static bool _subscpp(LSHandle *sh, LSMessage *rq, TestService *ctx)
        { return ctx->subscpp(rq); }

    static bool _inactive(LSHandle *sh, LSMessage *rq, TestService *ctx)
        { return ctx->inactive(rq); }

    static void _timeout(void *l)
        {  static_cast<TestService *>(l)->_idle_cnt++; }
};

int main(int argc, char **argv)
{
    TestService().run();
}
