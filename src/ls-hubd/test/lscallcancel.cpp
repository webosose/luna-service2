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

#include <gtest/gtest.h>

#include <pthread.h>

#include <pbnjson.hpp>
#include <luna-service2/lunaservice.hpp>

#include "test_util.hpp"

#define SVC1_NAME "com.webos.test.service"
#define SVC2_NAME "com.webos.test.client"
#define SVC_URI(n, p) ("luna://" n p)

class TestService : public MainLoopT
{
private:
    LS::Handle _service;

public:
    TestService()
    {
        _service = LS::registerService(SVC1_NAME);

        LSMethod methods[] =
        {
            { "ping", (LSMethodFunction)_ping },
            { },
        };
        _service.registerCategory("/", methods, nullptr, nullptr);
        _service.setCategoryData("/", this);
        _service.attachToLoop(get());
    }

    TestService(const TestService&) = delete;
    TestService(TestService&&) = delete;

    bool ping(LS::Message request)
    {
        pbnjson::JObject json {
            { "returnValue", true }
        };
        request.respond(json.stringify().c_str());

        return true;
    }

    static bool _ping(LSHandle *sh, LSMessage *rq, TestService *ctx)
    { return ctx->ping(rq); }
};

struct Environment : ::testing::Environment
{
    TestService svc;
    pthread_barrier_t b_sync;

    pthread_barrier_t *const sync;
    const long num;

    long idx;

    Environment()
        : sync(&b_sync)
        , num(100)
    {
        pthread_barrier_init(sync, nullptr, 2);
    }

    virtual void SetUp()
    {
        idx = 0;
    }

    virtual void TearDown()
    {
        svc.stop();
        pthread_barrier_destroy(sync);
    }
};

Environment *env = static_cast<Environment *>(::testing::AddGlobalTestEnvironment(new Environment));

TEST(LSCallCancel, PhaseOne)
{
    LS::Handle h = LS::registerService(SVC2_NAME);
    MainLoopT loop;

    h.attachToLoop(loop.get());

    auto _check = [] (LSHandle *sh, LSMessage *reply, void *ctx) -> bool
    {
        pthread_barrier_wait(env->sync);
        EXPECT_EQ(env->idx, (long)ctx);
        LSCallCancel(sh, LSMessageGetResponseToken(reply), nullptr);
        return true;
    };

    for (; env->idx < env->num; ++(env->idx))
    {
        LS::Error error;
        LSMessageToken token;

        if (!LSCall(h.get(), SVC_URI(SVC1_NAME, "/ping"), "{}", _check, (void *)env->idx, &token, error.get()))
            throw error;

        pthread_barrier_wait(env->sync);
        LSCallCancel(h.get(), token, nullptr);
    }
}

TEST(LSCallCancel, PhaseTwo)
{
    LS::Handle h = LS::registerService(SVC2_NAME);
    MainLoopT loop;

    h.attachToLoop(loop.get());

    auto _check = [] (LSHandle *sh, LSMessage *reply, void *ctx) -> bool
    {
        LSCallCancel(sh, LSMessageGetResponseToken(reply), nullptr);
        pthread_barrier_wait(env->sync);
        return true;
    };

    LS::Error error;
    LSMessageToken token;

    if (!LSCall(h.get(), SVC_URI(SVC1_NAME, "/ping"), "{}", _check, nullptr, &token, error.get()))
        throw error;
    pthread_barrier_wait(env->sync);
}

TEST(LSCallCancel, PhaseThree)
{
    LS::Handle h = LS::registerService(SVC2_NAME);
    MainLoopT loop;

    h.attachToLoop(loop.get());

    auto _check = [] (LSHandle *sh, LSMessage *reply, void *ctx) -> bool
    { return true; };

    for (int i = 0; i < env->num; ++i) {
        LS::Error error;
        LSMessageToken token;

        if (!LSCall(h.get(), SVC_URI(SVC1_NAME, "/ping"), "{}", _check, nullptr, &token, error.get()))
            throw error;
        LSCallCancel(h.get(), token, nullptr);
    }
}
