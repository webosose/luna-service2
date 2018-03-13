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

#include "test_util.hpp"
#include <iostream>
#include <vector>
#include <fstream>
#include <algorithm>


const unsigned SERVICES_TO_REGISTER = 1024;
const unsigned METHODS_TO_REGISTER = 64;
const unsigned SAMPLE_COUNT = 16;


pid_t GetHubPid()
{
    std::string hub_pid_file = getenv("LS_HUB_CONF_ROOT");
    hub_pid_file += "/run/ls-hubd.pid";
    std::ifstream ifs(hub_pid_file.c_str());
    pid_t hub_pid{-1};
    ifs >> hub_pid;
    return hub_pid;
}

std::string GetHubStatm()
{
    static pid_t hub_pid = GetHubPid();

    std::string statm{"/proc/"};
    statm += std::to_string(hub_pid);
    statm += "/statm";

    std::ifstream ifs(statm.c_str());

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
            std::cout << "Hub::Register " << i << " " << GetHubStatm() << std::endl;
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
            std::cout << "Hub::RegisterCategory " << j << " " << GetHubStatm() << std::endl;
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
            std::cout << "Hub::CallOneReply " << i << " " << GetHubStatm() << std::endl;
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
            std::cout << "Hub::Unregister " << i << " " << GetHubStatm() << std::endl;
        }
    }

    std::cout << std::endl;
}

int main()
{
    TestServiceRegistration(SERVICES_TO_REGISTER);
    TestMethodRegistration(METHODS_TO_REGISTER);
    TestMethodCall();

    main_loop.stop();
    TestServiceUnregistration();
    return 0;
}
