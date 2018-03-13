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


#include <stdlib.h>
#include <glib.h>
#include <sys/mman.h>
#include <transport_shm.h>

/* Test cases *****************************************************************/

static void
test_LSTransportShm(void)
{
    _LSTransportShm *shm = NULL;

    LSError error;
    LSErrorInit(&error);
    int i = 0;

    // delete any previous public/private shared memory objects
    shm_unlink("/ls2.monitor.shm");

    g_assert(_LSTransportShmInit(&shm, &error));
    g_assert(NULL != shm);

    for (i=1; i < 10; ++i)
    {
        g_assert_cmpint(_LSTransportShmGetSerial(shm), ==, i);
    }

    _LSTransportShmDeinit(&shm);
    g_assert(NULL == shm);

    // reopen shared memory objects
    g_assert(_LSTransportShmInit(&shm, &error));
    g_assert(NULL != shm);

    for (i=10; i < 20; ++i)
    {
        g_assert_cmpint(_LSTransportShmGetSerial(shm), ==, i);
    }

    _LSTransportShmDeinit(&shm);
    g_assert(NULL == shm);
}

/* Test suite *****************************************************************/

int
main(int argc, char *argv[])
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/luna-service2/LSTransportShm", test_LSTransportShm);

    return g_test_run();
}

