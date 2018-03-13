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


#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <transport.h>

/* Mock variables *************************************************************/

static _LSTransportCred* mvar_transport_cred = NULL;

/* Test cases *****************************************************************/

static void
test_LSTransportSecurityInit(void)
{
    /* Test creation, getters and deletion .*/
    mvar_transport_cred = _LSTransportCredNew();
    g_assert(NULL != mvar_transport_cred);
    g_assert_cmpint(_LSTransportCredGetPid(mvar_transport_cred),
                     ==,
                     (pid_t)LS_PID_INVALID);
    g_assert_cmpint(_LSTransportCredGetUid(mvar_transport_cred),
                     ==,
                     (uid_t)LS_UID_INVALID);
    g_assert_cmpint(_LSTransportCredGetGid(mvar_transport_cred),
                     ==,
                     (gid_t)LS_GID_INVALID);
    g_assert(!_LSTransportCredGetExePath(mvar_transport_cred));
    g_assert(!_LSTransportCredGetCmdLine(mvar_transport_cred));
    _LSTransportCredFree(mvar_transport_cred);
    mvar_transport_cred = NULL;
}

static void
test_LSTransportSecurityPositive(void)
{
    /* Credentials of a socket.  */
    mvar_transport_cred = _LSTransportCredNew();
    struct sockaddr_un socketaddress;
    int socketfd = socket(AF_LOCAL, SOCK_STREAM, 0);
    g_assert_cmpint(socketfd, !=, -1);
    memset(&socketaddress, 0, sizeof(struct sockaddr_un));
    socketaddress.sun_family = AF_LOCAL;
    strncpy(socketaddress.sun_path,
            "/tmp/testsocket-XXXXXX",
            sizeof(socketaddress.sun_path) - 1);
    int fd = mkstemp(socketaddress.sun_path);
    g_assert_cmpint(fd, !=, -1);
    close(fd);
    unlink(socketaddress.sun_path);
    bind(socketfd,
          (struct sockaddr*) &socketaddress,
          sizeof(struct sockaddr_un));
    listen(socketfd, 3);

    pid_t child;
    switch ((child = fork()))
    {
    case -1:
        break;
    case 0:
        {
            int fd = accept(socketfd, NULL, NULL);
            close(socketfd);
            if (fd >= 0)
                close(fd);
            exit(0);
            break;
        }
    default:
        {
            int socketfd2 = socket(AF_LOCAL, SOCK_STREAM, 0);
            g_assert_cmpint(socketfd2, !=, -1);
            while (connect(socketfd2,
                             (struct sockaddr*) &socketaddress,
                             sizeof(struct sockaddr_un)) != 0);

            LSError error;
            LSErrorInit(&error);
            _LSTransportGetCredentials(socketfd, mvar_transport_cred, &error);
            g_assert(NULL != mvar_transport_cred);
            g_assert_cmpint(_LSTransportCredGetPid(mvar_transport_cred),
                             ==,
                             getpid());
            g_assert_cmpint(_LSTransportCredGetUid(mvar_transport_cred),
                             ==,
                             getuid());
            g_assert_cmpint(_LSTransportCredGetGid(mvar_transport_cred),
                             ==,
                             getgid());
            g_assert(_LSTransportCredGetExePath(mvar_transport_cred));
            g_assert(_LSTransportCredGetCmdLine(mvar_transport_cred));

            close(socketfd2);
            waitpid(child, NULL, 0);
        }
    }

    close(socketfd);
    unlink(socketaddress.sun_path);
}

/* Mocks **********************************************************************/

bool
_LSTransportIsHub(void)
{
    return true;
}

/* Test suite *****************************************************************/

int
main(int argc, char *argv[])
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/luna-service2/LSTransportSecurityInit",
                    test_LSTransportSecurityInit);
    g_test_add_func("/luna-service2/LSTransportSecurityPositive",
                     test_LSTransportSecurityPositive);

    return g_test_run();
}

