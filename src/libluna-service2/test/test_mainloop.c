// Copyright (c) 2008-2019 LG Electronics, Inc.
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


#include <glib.h>
#include <luna-service2/lunaservice.h>
#include <base.h>
#include <transport_priv.h>

/* Mock variables *************************************************************/

static const int g_priority = 8;
static _LSTransport* g_trans;
static GMainContext* g_context;
static LSHandle g_lsh;

static unsigned int g_attach_count = 0;
static unsigned int g_priority_count = 0;
static unsigned int g_detached = 0;

/* Test cases *****************************************************************/

static void
test_LSMainAttachDetachPositive(void)
{
    /* Attach service. */
    LSError error;
    LSErrorInit(&error);

    //LSHandle lsh;
    _LSTransport transport = {};

    g_lsh.context = NULL;

    g_trans = &transport;
    g_lsh.transport = g_trans;

    g_context = g_main_context_default();
    g_lsh.context = g_context;

    //memcpy(&lsh, &g_lsh, sizeof(lsh));

    GMainLoop* mainloop = g_main_loop_new(g_context, false);

    bool ret = LSGmainAttach(&g_lsh, mainloop, &error);
    /* case: return value. */
    g_assert(ret);
    /* case: both services attached. */
    g_assert_cmpint(g_attach_count, ==, 1);
    /* case: both contexts saved. */
    g_assert(NULL != g_lsh.context);

    /* Change priority. */
    ret = LSGmainSetPriority(&g_lsh, g_priority, &error);
    /* case: return value. */
    g_assert(ret);
    /* case: both service priorities changed. */
    g_assert_cmpint(g_priority_count, ==, 1);

    /* Detach services. */
    ret = LSGmainDetach(&g_lsh, &error);
    g_assert(ret);
    /* case: both services detached. */
    g_assert_cmpint(g_detached, ==, 1);

    /* Cleanup. */
    g_main_context_unref(g_lsh.context);
    g_main_loop_unref(mainloop);
}

/* Mocks **********************************************************************/

void
_lshandle_validate(LSHandle *sh)
{
}

bool
_LSUnregisterCommon(LSHandle *sh,
                    bool flush_and_send_shutdown,
                    void *call_ret_addr,
                    LSError *lserror)
{
    if (!flush_and_send_shutdown && call_ret_addr && lserror)
    {
        if (&g_lsh == sh)
        {
            g_detached++;
        }
    }
    return true;
}

bool
_LSTransportGmainSetPriority(_LSTransport *transport,
                             int priority,
                             LSError *lserror)
{
    if (g_priority == priority && lserror)
    {
        if (transport == g_trans)
        {
            g_priority_count++;
        }
    }
    return true;
}

void
_LSTransportGmainAttach(_LSTransport* transport,
                        GMainContext* context)
{
    if (g_context == context)
    {
        if (transport == g_trans)
        {
            g_attach_count++;
        }
    }
}

/* Test suite *****************************************************************/

/* NOTE: mainloop.c contains many deprecated functions. No tests were written
 * for those functions.
 */
int
main(int argc, char *argv[])
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/luna-service2/LSMainAttachDetachPositive",
                     test_LSMainAttachDetachPositive);

    return g_test_run();
}

