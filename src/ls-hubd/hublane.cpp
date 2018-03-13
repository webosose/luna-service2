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

#include "hublane.hpp"

#include <cstdlib>
#include <transport.h>

#include "util.hpp"

/// @cond INTERNAL
/// @addtogroup LunaServiceHub
/// @{

namespace {
    GMainLoop *GetMainLoop()
    {
        static auto mainloop = mk_ptr(g_main_loop_new(NULL, FALSE), g_main_loop_unref);
        return mainloop.get();
    }
}

void HubLane::AttachLocalListener(const char *name, mode_t mode)
{
    const char *hub_local_dir = _LSGetHubLocalSocketDirectory();
    if (g_mkdir_with_parents(hub_local_dir, 0755) == -1)
    {
        LOG_LS_ERROR(MSGID_LSHUB_MKDIR_ERROR, 3, PMLOGKS("PATH", hub_local_dir),
                     PMLOGKFV("ERROR_CODE", "%d", errno),
                     PMLOGKS("ERROR", g_strerror(errno)),
                     "Unable to create directory");
        exit(EXIT_FAILURE);
    }
    SetLocalListener(name, mode);
    _LSTransportGmainAttach(getTransportHandle(), g_main_context_default());
}

void HubLane::Run()
{
    static auto shutdownHandler = [](int signal){
        g_main_loop_quit(GetMainLoop());
    };

    _LSTransportSetupSignalHandler(SIGPIPE, SIG_IGN);
    _LSTransportSetupSignalHandler(SIGTERM, shutdownHandler);
    _LSTransportSetupSignalHandler(SIGINT, shutdownHandler);

    /* run mainloop */
    g_main_loop_run(GetMainLoop());
}

/// @} END OF GROUP LunaServiceHub
/// @endcond
