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

#include "json_payload.hpp"
#include "util.hpp"

#include "test_util.hpp"

class TestService
    : private LS::Handle
{
public:
    TestService(GMainLoop *mainLoop, const char *name)
        : LS::Handle(LS::registerService(name))
    {
        attachToLoop(mainLoop);

        LS_CATEGORY_BEGIN(TestService, "/common")
            LS_CATEGORY_METHOD(echoAppId)
        LS_CATEGORY_END

        LS_CATEGORY_BEGIN(TestService, "/pub")
            LS_CATEGORY_METHOD(test)
        LS_CATEGORY_END

        LS_CATEGORY_BEGIN(TestService, "/prv")
            LS_CATEGORY_METHOD(test)
        LS_CATEGORY_END
    }

private:
    bool test(LSMessage &message)
    {
        LS::Message request(&message);
        request.respond(R"({ "returnValue": true })");
        return true;
    }

    bool echoAppId(LSMessage &message)
    {
        LS::Message request(&message);
        LS::JSONPayload reply;
        reply.set("returnValue", true);
        reply.set("appId", request.getApplicationID());
        request.respond(reply.getJSONString().c_str());
        return true;
    }
};

TEST(ApplicationContainerSecurity, ApplicationContainerSecurityCommon)
{
    MainLoopT main_loop;

    TestService test(main_loop.get(), "com.palm.service");
    //main_loop.ensure();

    LS::Handle pub{"com.palm.app.pub.1", "com.palm.app.pub"};
    pub.attachToLoop(main_loop.get());

    LS::Handle prv{"com.palm.app.prv.1", "com.palm.app.prv"};
    prv.attachToLoop(main_loop.get());

    auto pub2pub = pub.callOneReply("luna://com.palm.service/pub/test", "{}");
    auto pub2prv = pub.callOneReply("luna://com.palm.service/prv/test", "{}");
    auto prv2pub = prv.callOneReply("luna://com.palm.service/pub/test", "{}");
    auto prv2prv = prv.callOneReply("luna://com.palm.service/prv/test", "{}");

    LS::Message pub_from_pub{pub2pub.get()};
    LS::Message pub_from_prv{pub2prv.get()};
    LS::Message prv_from_pub{prv2pub.get()};
    LS::Message prv_from_prv{prv2prv.get()};
    ASSERT_TRUE(bool(pub_from_pub));
    ASSERT_TRUE(bool(pub_from_prv));
    ASSERT_TRUE(bool(prv_from_pub));
    ASSERT_TRUE(bool(prv_from_prv));

    ASSERT_FALSE(pub_from_pub.isHubError());
    ASSERT_TRUE(pub_from_prv.isHubError());
    ASSERT_TRUE(prv_from_pub.isHubError());
    ASSERT_FALSE(prv_from_prv.isHubError());

    main_loop.stop();
}

TEST(ApplicationContainerSecurity, ApplicationServiceApplicationIdCalls)
{
    MainLoopT main_loop;

    TestService test(main_loop.get(), "com.palm.service");
    //main_loop.ensure();

    std::string replyAppId;
    LS::Handle regular{"com.palm.app.regular.1", "com.palm.app.regular"};
    regular.attachToLoop(main_loop.get());

    auto regCall = regular.callOneReply("luna://com.palm.service/common/echoAppId", "{}");
    LS::JSONPayload{regCall.get().getPayload()}.get("appId", replyAppId);
    ASSERT_EQ(std::string{"com.palm.app.regular"}, replyAppId);

    ASSERT_THROW(regular.callOneReply("luna://com.palm.service/common/echoAppId", "{}", "com.palm.app.custom"), LS::Error);

    LS::Handle privileged{"com.palm.app.privileged.1", "com.palm.app.privileged"};
    privileged.attachToLoop(main_loop.get());

    auto privCall = privileged.callOneReply("luna://com.palm.service/common/echoAppId", "{}");
    LS::JSONPayload{privCall.get().getPayload()}.get("appId", replyAppId);
    ASSERT_EQ(std::string{"com.palm.app.privileged"}, replyAppId);

    privCall = privileged.callOneReply("luna://com.palm.service/common/echoAppId", "{}", "com.palm.app.custom");
    LS::JSONPayload{privCall.get().getPayload()}.get("appId", replyAppId);
    ASSERT_EQ(std::string{"com.palm.app.custom"}, replyAppId);

    privCall = privileged.callOneReply("luna://com.palm.service/common/echoAppId", "{}");
    LS::JSONPayload{privCall.get().getPayload()}.get("appId", replyAppId);
    ASSERT_EQ(std::string{"com.palm.app.privileged"}, replyAppId);

    main_loop.stop();
}

int main(int argc, char *argv[])
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
