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

#include "luna-service2++/handle.hpp"
#include <gtest/gtest.h>

#include "test_util.hpp"

using namespace std;
using namespace LS;

const string SERVICE_NAME = "com.palm.newserver.new2new";
const string SERVER_URL = "luna://" + SERVICE_NAME;

bool IsCallAllowed(Handle &client, const char *method)
{
    return !client.callOneReply((SERVER_URL + method).c_str(), "{}").get().isHubError();
}

class NewService
{
public:
    NewService(GMainLoop *main_loop)
        : _handle{registerService(SERVICE_NAME.c_str(), false)}
    {
        _handle.attachToLoop(main_loop);

        static LSMethod common_methods1[] =
        {
            { "getInfo", MethodStub, LUNA_METHOD_FLAGS_NONE },
            { nullptr }
        };

        static LSMethod common_methods2[] =
        {
            { "setInfo", MethodStub, LUNA_METHOD_FLAGS_NONE },
            { nullptr }
        };
        _handle.registerCategory("/common", common_methods1, nullptr, nullptr);
        _handle.registerCategoryAppend("/common", common_methods2, nullptr);

        static LSMethod call_methods[] =
        {
            { "testCall", MethodStub, LUNA_METHOD_FLAGS_NONE },
            { nullptr }
        };
        _handle.registerCategory("/common/video", call_methods, nullptr, nullptr);
        _handle.registerCategory("/common/video/nested", call_methods, nullptr, nullptr);
        _handle.registerCategory("/common/audio", call_methods, nullptr, nullptr);
        _handle.registerCategory("/video", call_methods, nullptr, nullptr);
        _handle.registerCategory("/video/nested", call_methods, nullptr, nullptr);
        _handle.registerCategory("/audio", call_methods, nullptr, nullptr);
        _handle.registerCategory("/default", call_methods, nullptr, nullptr);
    }

private:
    Handle _handle;

    static bool MethodStub(LSHandle *sh, LSMessage *message, void *data)
    {
        LSMessageRespond(message, "{}", nullptr);
        return true;
    }
};

TEST(Groups, VideoCommon)
{
    MainLoopT main_loop;

    NewService new_service{main_loop.get()};

    auto client = registerService("com.palm.newclient.new2new.video-common", false);
    client.attachToLoop(main_loop.get());

    EXPECT_TRUE(IsCallAllowed(client, "/common/getInfo"));
    EXPECT_FALSE(IsCallAllowed(client, "/common/setInfo"));
    EXPECT_TRUE(IsCallAllowed(client, "/common/video/testCall"));

    EXPECT_FALSE(IsCallAllowed(client, "/common/video/nested/testCall"));
    EXPECT_FALSE(IsCallAllowed(client, "/common/audio/testCall"));
    EXPECT_TRUE(IsCallAllowed(client, "/video/testCall"));

    EXPECT_FALSE(IsCallAllowed(client, "/video/nested/testCall"));
    EXPECT_FALSE(IsCallAllowed(client, "/audio/testCall"));
    EXPECT_FALSE(IsCallAllowed(client, "/default/testCall"));

    main_loop.stop();
}

TEST(Groups, VideoAll)
{
    MainLoopT main_loop;

    NewService new_service{main_loop.get()};

    auto client = registerService("com.palm.newclient.new2new.video-all", false);
    client.attachToLoop(main_loop.get());

    EXPECT_TRUE(IsCallAllowed(client, "/common/getInfo"));
    EXPECT_FALSE(IsCallAllowed(client, "/common/setInfo"));
    EXPECT_TRUE(IsCallAllowed(client, "/common/video/testCall"));

    EXPECT_TRUE(IsCallAllowed(client, "/common/video/nested/testCall"));
    EXPECT_FALSE(IsCallAllowed(client, "/common/audio/testCall"));
    EXPECT_TRUE(IsCallAllowed(client, "/video/testCall"));

    EXPECT_TRUE(IsCallAllowed(client, "/video/nested/testCall"));
    EXPECT_FALSE(IsCallAllowed(client, "/audio/testCall"));
    EXPECT_FALSE(IsCallAllowed(client, "/default/testCall"));

    main_loop.stop();
}

TEST(Groups, Audio)
{
    MainLoopT main_loop;

    NewService new_service{main_loop.get()};

    auto client = registerService("com.palm.newclient.new2new.audio", false);
    client.attachToLoop(main_loop.get());

    EXPECT_FALSE(IsCallAllowed(client, "/common/getInfo"));
    EXPECT_TRUE(IsCallAllowed(client, "/common/setInfo"));
    EXPECT_FALSE(IsCallAllowed(client, "/common/video/testCall"));

    EXPECT_FALSE(IsCallAllowed(client, "/common/video/nested/testCall"));
    EXPECT_TRUE(IsCallAllowed(client, "/common/audio/testCall"));
    EXPECT_FALSE(IsCallAllowed(client, "/video/testCall"));

    EXPECT_FALSE(IsCallAllowed(client, "/video/nested/testCall"));
    EXPECT_TRUE(IsCallAllowed(client, "/audio/testCall"));
    EXPECT_FALSE(IsCallAllowed(client, "/default/testCall"));

    main_loop.stop();
}

TEST(Groups, Default)
{
    MainLoopT main_loop;

    NewService new_service{main_loop.get()};

    auto client = registerService("com.palm.newclient.new2new.default", false);
    client.attachToLoop(main_loop.get());

    EXPECT_FALSE(IsCallAllowed(client, "/common/getInfo"));
    EXPECT_FALSE(IsCallAllowed(client, "/common/setInfo"));
    EXPECT_FALSE(IsCallAllowed(client, "/common/video/testCall"));

    EXPECT_FALSE(IsCallAllowed(client, "/common/video/nested/testCall"));
    EXPECT_FALSE(IsCallAllowed(client, "/common/audio/testCall"));
    EXPECT_FALSE(IsCallAllowed(client, "/video/testCall"));

    EXPECT_FALSE(IsCallAllowed(client, "/video/nested/testCall"));
    EXPECT_FALSE(IsCallAllowed(client, "/audio/testCall"));
    EXPECT_TRUE(IsCallAllowed(client, "/default/testCall"));

    main_loop.stop();
}
