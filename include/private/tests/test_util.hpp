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

#ifndef _TEST_UTILS_HPP_
#define _TEST_UTILS_HPP_

#include <memory>
#include <thread>
#include <cassert>
#include <functional>

#include <glib.h>

#include "util.hpp"

//! @cond INTERNAL

/// scope-living glib timeout with possibility to attach to custom context
class Timeout
{

public:
    Timeout(guint interval, std::function<gboolean()> func, GMainContext *context = nullptr)
        : cb(func)
        , source(g_timeout_source_new(interval), g_source_unref)
    {
        create(context);
    }

    Timeout(guint interval, std::function<gboolean()> func, GMainLoop* loop)
        : cb(func)
        , source(g_timeout_source_new(interval), g_source_unref)
    {
        assert(loop);
        create(g_main_loop_get_context(loop));
    }

    ~Timeout()
    {
        g_source_destroy(source.get());
    }

private:
    void create(GMainContext *context)
    {
        auto lamda = [](void* ctx) -> gboolean
        {
            return (*static_cast<std::function<gboolean()>*>(ctx))();
        };
        g_source_set_callback(source.get(), lamda, &cb, nullptr);
        g_source_attach(source.get(), context);
    }

private:
    std::function<gboolean()> cb;
    std::unique_ptr<GSource, void(*)(GSource*)> source;
};

class QuitTimeout : public Timeout
{
    bool waiting = true;
public:
    QuitTimeout(guint interval, GMainLoop *loop)
        : Timeout(interval, [this, loop]()
                  {
                      waiting = false;
                      g_main_loop_quit(loop);
                      return FALSE;
                  }, g_main_loop_get_context(loop))
    {
    }
    bool fired() const { return !waiting; }
};

class LoopContext : public Timeout
{

public:
    LoopContext(guint interval, GMainContext *ctx)
        : Timeout(interval, [this]() { g_main_loop_quit(loop.get()); return FALSE; }, ctx)
        , loop(g_main_loop_new(ctx, false), g_main_loop_unref)
    {
        g_main_loop_run(loop.get());
    }

private:
    std::unique_ptr<GMainLoop, void(*)(GMainLoop*)> loop;
};

class MainLoop
{

public:
    MainLoop()
        : _loop(g_main_loop_new(g_main_context_new(), false), g_main_loop_unref)
    { g_main_context_unref(g_main_loop_get_context(_loop.get())); }

    MainLoop(GMainContext *ctx)
        : _loop(g_main_loop_new(ctx, false), g_main_loop_unref)
    { }

    void operator () ()
    { g_main_loop_run(_loop.get()); }

    void stop()
    { g_main_loop_quit(_loop.get()); }

    GMainLoop* get()
    { return _loop.get(); }

    void ensure()
    { while (!g_main_loop_is_running(_loop.get())) sched_yield(); }

private:
    std::unique_ptr<GMainLoop, void(*)(GMainLoop*)> _loop;
};

class MainLoopT
{
private:
    MainLoop loop;
    std::thread worker;

public:
    MainLoopT()
        : loop()
        , worker(std::ref(loop))
    { }

    ~MainLoopT()
    { stop(); }

    void stop()
    {
        if (!worker.joinable())
            return;

        loop.ensure();
        loop.stop();
        worker.join();
    }

    GMainLoop *get()
    { return loop.get(); }
};

//! @endcond INTERNAL

#endif //_TEST_UTILS_HPP_
