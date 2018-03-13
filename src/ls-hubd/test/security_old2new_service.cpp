// Copyright (c) 2008-2018 LG Electronics, Inc.
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

#include "luna-service2/lunaservice.hpp"
#include <glib.h>
//#include <memory>
#include <functional>

class Old2NewService
    : public LS::Handle
{
    GMainLoop *mainLoop;
public:
    Old2NewService() : LS::Handle(), mainLoop(nullptr)
    {}

    Old2NewService(const char *service_name, GMainLoop *mainLoop)
        : LS::Handle(service_name, false)
        , mainLoop(mainLoop)
    {
        attachToLoop(mainLoop);
        LS_CATEGORY_BEGIN(Old2NewService, "/testCalls")
            LS_CATEGORY_METHOD(restart)
            LS_CATEGORY_METHOD(publicCall)
            LS_CATEGORY_METHOD(privateCall)
        LS_CATEGORY_END
    }

    std::function<void()> restartAction = [](){};

private:

    bool publicCall(LSMessage &message)
    {
        LS::Message request(&message);
        request.respond(R"json({"returnValue":true})json");
        return true;
    }

    bool privateCall(LSMessage &message)
    {
        LS::Message request(&message);
        request.respond(R"json({"returnValue":true})json");
        return true;
    }

    bool restart(LSMessage &message)
    {
        LS::Message request(&message);
        request.respond(R"json({"returnValue":true})json");
        restartAction();
        return true;
    }
};

int main(int argc, char **argv)
{
    GMainContext *mainCtx = g_main_context_new();
    GMainLoop *mainLoop = g_main_loop_new(mainCtx, false);

    try
    {
        bool pendingRestart = false;
        for (;;) {
            std::cerr << "Starting service" << std::endl;
            Old2NewService new_service{"com.palm.newserver.old2new", mainLoop};

            new_service.restartAction = [&pendingRestart, mainLoop]() {
                pendingRestart = true;
                g_main_loop_quit(mainLoop);
            };

            g_main_loop_run(mainLoop);

            if (!pendingRestart)
                break;

            std::cerr << "Restarting" << std::endl;
            pendingRestart = false;
            new_service = Old2NewService {}; // unregister
            continue; // restart
        };
        std::cerr << "Exiting" << std::endl;
    }
    catch(const std::exception &e)
    {
        std::cerr<<"Exception: \n"<<e.what()<<std::endl;
    }
    catch(...)
    {
        std::cerr<<"Unknown exception"<<std::endl;
    }

    g_main_loop_unref(mainLoop);
    g_main_context_unref(mainCtx);

    return 0;
}
