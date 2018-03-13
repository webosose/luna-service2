// Copyright (c) 2016-2018 LG Electronics, Inc.
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

#include <luna-service2/lunaservice.hpp>

#include <fstream>
#include <forward_list>

#include "test_util.hpp"

const unsigned SERVICES_TO_REGISTER = 1024;
const unsigned METHODS_TO_REGISTER = 64;
const unsigned SAMPLE_COUNT = 16;
const unsigned MAX_PAYLOAD = 1 << 20;  // 1 MB

std::string GetStatm()
{
    std::ifstream ifs("/proc/self/statm");

    std::string line;
    getline(ifs, line);
    return line;
}

MainLoopT main_loop;
std::vector<LS::Handle> services;

void TestServiceRegistration(unsigned count)
{
    unsigned sample_step = count / SAMPLE_COUNT;

    for (unsigned i = 0; i != count; ++i)
    {
        std::string service_name{"com.webos.service"};
        service_name += std::to_string(i);

        auto handle = LS::registerService(service_name.c_str());
        handle.attachToLoop(main_loop.get());
        services.emplace_back(std::move(handle));

        if (0 == i % sample_step)
        {
            // Let the hub settles down after the attack
            usleep(10000);
            std::cout << "Lib::Register " << i << " " << GetStatm() << std::endl;
        }
    }

    std::cout << std::endl;
}

bool OnTestMethod(LSHandle *lsh, LSMessage *message, void *ctxt)
{
    LS::Message request{message};
    request.respond(R"({"returnValue": true})");
    return true;
}

void TestMethodRegistration(unsigned method_count)
{
    unsigned sample_step = services.size() / SAMPLE_COUNT;

    for (size_t j{0}; j != services.size(); ++j)
    {
        LS::Handle &service = services[j];

        for (unsigned i = 0; i != method_count; ++i)
        {
            std::string method_name{"method"};
            method_name += std::to_string(i);

            LSMethod methods[] = {
                { method_name.c_str(), OnTestMethod, LUNA_METHOD_FLAGS_NONE },
                { nullptr, nullptr, LUNA_METHOD_FLAGS_NONE }
            };

            service.registerCategoryAppend("/test", methods, nullptr);
        }

        if (0 == j % sample_step)
        {
            usleep(10000);
            std::cout << "Lib::RegisterCategory " << j << " " << GetStatm() << std::endl;
        }
    }

    std::cout << std::endl;
}

void TestMethodCall()
{
    unsigned sample_step = services.size() / SAMPLE_COUNT;

    for (size_t i{0}; i != services.size(); ++i)
    {
        LS::Handle &client = services[i];
        auto call = client.callOneReply("luna://com.webos.service0/test/method0", R"({})");
        call.get();

        if (0 == i % sample_step)
        {
            usleep(10000);
            std::cout << "Lib::CallOneReply " << i << " " << GetStatm() << std::endl;
        }
    }

    std::cout << std::endl;
}


// A 1-MB buffer for testing method calls with different payloads
char payload_buffer[MAX_PAYLOAD] = R"({"key": ""})";

void TestMethodCallPayloadSize()
{
    size_t measurements = services.size() / 16;
    unsigned sample_step = measurements / SAMPLE_COUNT;

    for (size_t i{0}; i != measurements; ++i)
    {
        unsigned long payload_size = i * MAX_PAYLOAD / measurements - 16;

        char format[64];
        sprintf(format, R"({"key": "%%%lds"})", payload_size);
        sprintf(payload_buffer, format, "a");

        LS::Handle &client = services[i];
        auto call = client.callOneReply("luna://com.webos.service0/test/method0", payload_buffer);
        call.get();

        if (0 == i % sample_step)
        {
            usleep(10000);
            std::cout << "Lib::CallPayloadSize " << i << " " << GetStatm() << std::endl;
        }
    }

    std::cout << std::endl;
}

bool OnTestRespondN(LSHandle *lsh, LSMessage *message, void *ctxt)
{
    LS::Message request{message};
    unsigned long payload_size{0};
    sscanf(request.getPayload(), R"({"count": %ld})", &payload_size);

    char format[64];
    sprintf(format, R"({"key": "%%%lds"})", payload_size);
    sprintf(payload_buffer, format, "a");

    request.respond(payload_buffer);
    return true;
}

void TestMethodReplySize()
{
    // We'll send requests to service0 with desired size of payload.
    // It'll respond with payloads of requested size.
    LSMethod methods[] = {
        { "respondN", OnTestRespondN, LUNA_METHOD_FLAGS_NONE },
        { nullptr, nullptr, LUNA_METHOD_FLAGS_NONE }
    };

    services[0].registerCategoryAppend("/test", methods, nullptr);

    size_t measurements = services.size() / 16;
    unsigned sample_step = measurements / SAMPLE_COUNT;

    for (size_t i{0}; i != measurements; ++i)
    {
        unsigned long payload_size = i * MAX_PAYLOAD / measurements - 16;

        sprintf(payload_buffer, R"({"count": %ld})", payload_size);

        LS::Handle &client = services[i];
        auto call = client.callOneReply("luna://com.webos.service0/test/respondN", payload_buffer);
        auto reply = call.get();

        if (0 == i % sample_step)
        {
            usleep(10000);
            std::cout << "Lib::MessageRespond " << i << " " << GetStatm() << std::endl;
        }
    }

    std::cout << std::endl;
}

bool OnTestSubscription(LSHandle *lsh, LSMessage *message, void *ctxt)
{
    LS::Message request{message};
    request.respond(R"({"returnValue": true, "subscribed": true})");

    LSError error;
    LSErrorInit(&error);
    if (!LSSubscriptionAdd(lsh, "test_list", message, &error))
        LSErrorFree(&error);

    return true;
}

void TestSubscription()
{
    // We'll send requests to service0 for it to add messages to subscription
    // list.
    LSMethod methods[] = {
        { "subscription", OnTestSubscription, LUNA_METHOD_FLAGS_NONE },
        { nullptr, nullptr, LUNA_METHOD_FLAGS_NONE }
    };

    services[0].registerCategoryAppend("/test", methods, nullptr);

    unsigned sample_step = services.size() / SAMPLE_COUNT;

    std::forward_list<LS::Call> calls;

    for (size_t i{0}; i != services.size(); ++i)
    {
        LS::Handle &client = services[i];
        calls.emplace_front(client.callMultiReply("luna://com.webos.service0/test/subscription", R"({"subscribe": true})"));
        // Wait for the reply to ensure the subscription has been added.
        auto reply = calls.front().get();

        if (0 == i % sample_step)
        {
            usleep(10000);
            std::cout << "Lib::Subscription " << i << " " << GetStatm() << std::endl;
        }
    }

    std::cout << std::endl;
}

void TestServiceUnregistration()
{
    unsigned sample_step = services.size() / SAMPLE_COUNT;

    for (size_t i{0}, n{services.size()}; i != n; ++i)
    {
        services.pop_back();

        if (0 == i % sample_step)
        {
            usleep(10000);
            std::cout << "Lib::Unregister " << i << " " << GetStatm() << std::endl;
        }
    }

    std::cout << std::endl;
}

int main()
{
    TestServiceRegistration(SERVICES_TO_REGISTER);
    TestMethodRegistration(METHODS_TO_REGISTER);
    TestMethodCall();
    TestSubscription();
    TestMethodCallPayloadSize();
    TestMethodReplySize();

    main_loop.stop();
    TestServiceUnregistration();

    return 0;
}
