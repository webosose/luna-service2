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

class New2OldServicePublic
    : public LS::Handle
{
public:
    New2OldServicePublic(const char *service_name, GMainLoop *mainLoop)
        : LS::Handle(service_name, true)
    {
        attachToLoop(mainLoop);
        LS_CATEGORY_BEGIN(New2OldServicePublic, "/testCalls")
            LS_CATEGORY_METHOD(getBus)
            LS_CATEGORY_METHOD(testPublic)
        LS_CATEGORY_END
    }

private:

    bool getBus(LSMessage &message)
    {
        LS::Message request(&message);
        request.respond(R"json({"bus":"public"})json");
        return true;
    }

    bool testPublic(LSMessage &message)
    {
        LS::Message request(&message);
        request.respond(R"json({"returnValue":true})json");
        return true;
    }
};

class New2OldServicePrivate
    : public LS::Handle
{
public:
    New2OldServicePrivate(const char *service_name, GMainLoop *mainLoop)
        : LS::Handle(service_name, false)
    {
        attachToLoop(mainLoop);
        LS_CATEGORY_BEGIN(New2OldServicePrivate, "/testCalls")
            LS_CATEGORY_METHOD(getBus)
            LS_CATEGORY_METHOD(testPrivate)
        LS_CATEGORY_END
    }

private:

    bool getBus(LSMessage &message)
    {
        LS::Message request(&message);
        request.respond(R"json({"bus":"private"})json");
        return true;
    }

    bool testPrivate(LSMessage &message)
    {
        LS::Message request(&message);
        request.respond(R"json({"returnValue":true})json");
        return true;
    }
};

int main(int argc, char **argv)
{

    GMainContext *mainCtx = g_main_context_new();
    GMainLoop *mainLoop = g_main_loop_new(mainCtx, false);

    try
    {
        New2OldServicePublic pub{"com.palm.oldserver.new2old", mainLoop};
        New2OldServicePrivate prv{"com.palm.oldserver.new2old", mainLoop};
        g_main_loop_run(mainLoop);
    }
    catch(const std::exception &e)
    {
        std::cerr<<"Exception: "<<e.what()<<std::endl;
    }
    catch(...)
    {
        std::cerr<<"Unknown exception"<<std::endl;
    }

    g_main_loop_unref(mainLoop);
    g_main_context_unref(mainCtx);

    return 0;
}
