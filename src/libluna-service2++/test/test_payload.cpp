// Copyright (c) 2014-2019 LG Electronics, Inc.
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

#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <cassert>
#include <iostream>

#include <gtest/gtest.h>
#include <luna-service2/lunaservice.hpp>
#include <pbnjson.hpp>

#include "test_util.hpp"

const char *creply = R"({"returnValue", true})";

namespace
{

class TestService : public MainLoopT
{
private:
    LS::Handle _service;

public:
    TestService(): MainLoopT()
    {
        _service = LS::registerService("com.webos.service.socket_server");

        LSMethod methods[] =
        {
            { "socket", TestService::socket },
            { },
        };
        _service.registerCategory("/", methods, nullptr, nullptr);
        _service.setCategoryData("/", this);
        _service.attachToLoop(get());
    }

    ~TestService()
    {
        stop();
    }

    TestService(const TestService&) = delete;
    TestService(TestService&&) = delete;

    static bool socket(LSHandle *, LSMessage *message, void*)
    {
        LS::Message request(message);

        int socket_vector[2] = { -1, -1 };
        if (-1 == socketpair(AF_UNIX, SOCK_STREAM, 0, socket_vector))
        {
            auto response = pbnjson::JObject {{"returnValue", false}, {"errorText", "Can't create socket"}};
            request.respond(response.stringify().c_str());
        }

        LS::Payload payload(creply);
        payload.attachFd(socket_vector[1]);

        request.respond(std::move(payload));
        close(socket_vector[1]);

        int res = write(socket_vector[0], "Hello socket!", 14);
        if (res != 14) { std::cerr << "Failed to write 14 symbols to the socket" << std::endl; }

        return true;
    }
};

class Caller
    : public ::testing::Test
{
public:
    Caller()
    {
        _service = LS::registerService("service.test");
        _service.attachToLoop(_main_loop.get());
    }

    ~Caller()
    {
        _main_loop.stop();
    }

public:
    LS::Handle _service;
    MainLoopT _main_loop;
};

// Tests LS::Call basic call
TEST_F(Caller, SocketTransfer)
{
    TestService server;
    LS::Call call = _service.callOneReply("luna://com.webos.service.socket_server/socket", "{}");

    LS::Message message = call.get();
    EXPECT_FALSE(!message);
    EXPECT_FALSE(message.isHubError());
    EXPECT_TRUE(strcmp(message.getPayload(), creply) == 0);

    LS::PayloadRef payload = message.accessPayload();

    int fd = payload.getFd();
    EXPECT_NE(fd, -1);

    char buffer[256];
    EXPECT_EQ(read(fd, buffer, 256), 14);

    EXPECT_STREQ(buffer, "Hello socket!");
    server.stop();
}

}  // anonymous namespace

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

