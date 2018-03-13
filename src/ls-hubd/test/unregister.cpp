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
#include "luna-service2/lunaservice.hpp"

#include "util.hpp"
#include "test_util.hpp"


std::string unregister_foo_path;

TEST(TestUnregister, Simple)
{
    ASSERT_NO_THROW(LS::registerService("com.webos.client"));
}

TEST(TestUnregister, DuplicateName)
{
    // Test scenario:
    //
    // 1. Fork -> parent + child
    // 2. Parent registers com.webos.service -> success
    // 3. Child registers com.webos.service -> failure
    // 4. Now we expect that another executable with the same child PID
    //    is able to register its services -> execl + register com.webos.foo
    // 5. Parent waits for the child, reads its status -> 0 is expected

    auto pid = fork();
    ASSERT_NE(-1, pid);

    if (!pid)
    {
        usleep(10000);
        ASSERT_THROW(LS::registerService("com.webos.service"), LS::Error);

        execl(unregister_foo_path.c_str(), "unregister_foo", nullptr);
    }
    else
    {
        auto h = LS::registerService("com.webos.service");
        usleep(20000);

        int status;
        waitpid(pid, &status, 0);
        ASSERT_EQ(0, WEXITSTATUS(status));
    }

    // Let the hub clean up
    usleep(50000);
}

TEST(TestUnregister, Base)
{
    auto method_stub =  [](LSHandle *sh, LSMessage *message, void *data) -> bool
    {
        LS::Error lserror;
        LSMessageReply(sh, message, R"({"returnValue":true})", lserror.get());
        return true;
    };

    MainLoop loop;

    auto service =  LS::registerService("com.webos.service");
    static LSMethod smethods[] =
    {
        { "foo", method_stub, LUNA_METHOD_FLAGS_NONE },
        { nullptr }
    };
    service.registerCategory("/", smethods, nullptr, nullptr);
    service.attachToLoop(loop.get());

    auto client =  LS::registerService("com.webos.client");
    client.attachToLoop(loop.get());

    auto reply = client.callOneReply("luna://com.webos.service/foo", "{}").get();
    EXPECT_EQ(std::string(R"({"returnValue":true})"), std::string(reply.getPayload()));

    QuitTimeout timeout(1000, loop.get());
    g_main_loop_run(loop.get());
}

TEST(TestUnregister, UnregisterUserCallback)
{
    MainLoop loop;

    auto method_stub =  [](LSHandle *sh, LSMessage *message, void *) -> bool
    {
        LS::Error lserror;
        LSMessageReply(sh, message, R"({"returnValue":true})", lserror.get());
        return true;
    };

    static LSMethod methods[] =
    {
        { "foo", method_stub, LUNA_METHOD_FLAGS_NONE },
        { nullptr }
    };

    auto service =  LS::registerService("com.webos.service");
    service.registerCategory("/", methods, nullptr, nullptr);
    service.attachToLoop(loop.get());

    // LSUnregister in method callback
    {
        auto callback =  [](LSHandle *sh, LSMessage *message, void *data) -> bool
        {
            LS::Error lserror;

            LSMessageReply(sh, message, R"({"returnValue":true})", lserror.get());
            LSUnregister(sh, lserror.get());

            if (GMainLoop* loop = (GMainLoop*)data)
                g_main_loop_quit(loop);
            return true;
        };

        LS::Error error;
        LSHandle *handle = nullptr;

        LSRegister("com.webos.client", &handle, error.get());
        EXPECT_FALSE(error.isSet());

        static LSMethod methods[] =
        {
            { "foo", callback, LUNA_METHOD_FLAGS_NONE },
            { nullptr }
        };
        LSRegisterCategory(handle, "/", methods, nullptr, nullptr, error.get());
        LSGmainAttach(handle, loop.get(), error.get());

        auto reply = service.callOneReply("luna://com.webos.client/foo", "{}").get();
        EXPECT_EQ(std::string(R"({"returnValue":true})"), std::string(reply.getPayload()));

        QuitTimeout timeout(1000, loop.get());
        g_main_loop_run(loop.get());
    }

    // LSUnregister in response callback
    {
        auto callback =  [](LSHandle *sh, LSMessage *message, void *data) -> bool
        {
            EXPECT_EQ(std::string(R"({"returnValue":true})"), std::string(LSMessageGetPayload(message)));

            LS::Error lserror;
            LSUnregister(sh, lserror.get());

            if (GMainLoop* loop = (GMainLoop*)data)
                g_main_loop_quit(loop);
            return true;
        };

        LS::Error error;
        LSHandle *handle = nullptr;

        LSRegister("com.webos.client", &handle, error.get());
        EXPECT_FALSE(error.isSet());

        LSGmainAttach(handle, loop.get(), error.get());

        LSMessageToken token;
        LSCallFromApplicationOneReply(handle, "luna://com.webos.service/foo", "{}", nullptr,
                                      callback, loop.get(), &token, error.get());
        g_main_loop_run(loop.get());
    }
}

int main(int argc, char *argv[])
{
    unregister_foo_path = argv[0];
    unregister_foo_path += "_foo";

    try
    {
        ::testing::InitGoogleTest(&argc, argv);
        return RUN_ALL_TESTS();
    }catch (std::exception& e)
    {
        std::cerr << "ERROR: " << e.what() << std::endl;
    }
    return EXIT_FAILURE;
}
