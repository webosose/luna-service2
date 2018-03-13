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

#include "luna-service2++/handle.hpp"
#include "test_util.hpp"
#include <pbnjson.hpp>
#include <gtest/gtest.h>
#include <sstream>
#include <cstdio>

#include <signal.h>
#include <sys/types.h>
#include <sys/signalfd.h>
#include <sys/wait.h>

using namespace std;

namespace {
    struct ChildFd
    {
        int fd;
        ChildFd()
        {
            sigset_t sigset;
            EXPECT_EQ(0, sigemptyset(&sigset));
            EXPECT_EQ(0, sigaddset(&sigset, SIGCHLD));
            EXPECT_NE(-1, sigprocmask(SIG_BLOCK, &sigset, nullptr));
            //EXPECT_NE(-1, (fd = signalfd(-1, &sigset, 0)));
            EXPECT_NE(-1, (fd = signalfd(-1, &sigset, SFD_NONBLOCK|SFD_CLOEXEC)));
        }
        ~ChildFd()
        { if (fd != -1) close(fd); }
        ChildFd(const ChildFd &) = delete;
        ChildFd &operator=(const ChildFd &) = delete;

        /// Wait for any child to terminate with timeout
        /// @return 0 on timeout
        /// @note status of child is reaped by the end of this call
        pid_t wait(int *wstatus, int timeout_sec)
        {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);

            struct timeval tv = {timeout_sec, 0};
            int retval = select(fd+1, &rfds, nullptr, nullptr, &tv);
            EXPECT_NE(-1, retval);
            if (retval == -1)
                perror("select()");
            if (retval == 0) // timeout
                return 0;

            struct signalfd_siginfo fdsi;
            ssize_t s = read(fd, &fdsi, sizeof(fdsi));
            EXPECT_EQ(sizeof(struct signalfd_siginfo), s);
            if (s <= 0) // no signal detected
                return 0;
            EXPECT_EQ(SIGCHLD, fdsi.ssi_signo);
            if (fdsi.ssi_signo != SIGCHLD)
                return 0; // treat as timeout

            // do blocking wait() to reap status
            return ::wait(wstatus);
        }
    };
} // anonymous namespace

struct TestMonitor
    : ::testing::Test
{
    TestMonitor()
    {
        static auto method = [](LSHandle *sh, LSMessage *message, void *ctxt) -> bool
        {
            LS::Message request(message);
            request.respond(
                R"({"returnValue": true,
                    "string": "hello",
                    "number": 13,
                    "bool": true
                   })"
                );

            return true;
        };

        static LSMethod methods[] =
        {
            { "method", method, LUNA_METHOD_FLAGS_NONE },
            { nullptr }
        };

        _h = LS::registerService("com.webos.A");
        _h.registerCategory("/test", methods, nullptr, nullptr);
        _h.attachToLoop(_main_loop.get());
    }

    virtual void SetUp()
    {
        _t = thread{g_main_loop_run, _main_loop.get()};
    }

    virtual void TearDown()
    {
        g_main_loop_quit(_main_loop.get());
        _t.join();
    }

protected:
    MainLoop _main_loop;
    thread _t;
    LS::Handle _h;
};

TEST_F(TestMonitor, First)
{
    // First try to launch given ls-monitor from the build system.  Resort to
    // the system one otherwise (for testing on the target, for instance).
    const char *ls_monitor = LS_MONITOR;
    if (access(ls_monitor, X_OK))
        ls_monitor = "ls-monitor";
    std::cout << "Using monitor: " << ls_monitor << std::endl;

    std::string command = std::string{"cd /; "} + ls_monitor + " -j";

    unique_ptr<FILE, int (*)(FILE*)> f{
        popen(command.c_str(), "r"),
        pclose
    };
    ASSERT_TRUE(f.get() != NULL);
    // Let the monitor get ready registering itself.
    usleep(100000);

    thread t{
        [this]() {
            // use a separate context to avoid callback processing during
            // unregister
            auto main_ctx = mk_ptr(g_main_context_new(), g_main_context_unref);
            auto s = LS::registerService("com.webos.B");
            s.attachToLoop(main_ctx.get());
            auto c = s.callOneReply("luna://com.webos.A/test/method", "{}");
            c.get();
            s = {}; // unregister our service

            // Let the monitor settles down.
            sleep(2);
            ASSERT_NE(system("killall ls-monitor"), -1);
        }
    };

    ostringstream oss;
    char buff[512];
    while (fgets(buff, sizeof(buff), f.get()))
        oss << buff;

    auto output = oss.str();
    cout << "============= ls-monitor output =============\n" << output;
    cout << "\n=============================================" << endl;

    std::vector<pbnjson::JValue> messages;
    for (size_t start = 0, end; start < output.size(); start = end+1)
    {
        end = output.find('\n', start);
        std::string line = output.substr(start, end-start);
        auto message = pbnjson::JDomParser::fromString(line);
        EXPECT_TRUE(message.isValid())
            << "Should be a valid json: " << line;
        messages.emplace_back(std::move(message));
    }
    ASSERT_EQ(6, messages.size())
        << "Expecting exactly 6 messages to be sent over LS2 bus"
        << " (TX+RX for call, TX+RX for reply, TX+RX for cancel)";

    // Both sides reported about call
    EXPECT_EQ("com.webos.B", messages[0]["sender"].asString());
    EXPECT_EQ("com.webos.A", messages[1]["sender"].asString());

    // Verify that tokens match between TX/RX
    for (size_t i = 0; i < messages.size(); i+=2)
    {
        SCOPED_TRACE("i=" + std::to_string(i));
        EXPECT_EQ("TX", messages[i]["transport"].asString());
        EXPECT_EQ("RX", messages[i+1]["transport"].asString());
        EXPECT_EQ(messages[i]["sender"].asString(), messages[i+1]["destination"].asString());
        EXPECT_EQ(messages[i]["destination"].asString(), messages[i+1]["sender"].asString());
        EXPECT_EQ(messages[i]["type"].asString(), messages[i+1]["type"].asString());
        EXPECT_EQ(messages[i]["token"].asNumber<int64_t>(), messages[i+1]["token"].asNumber<int64_t>());
        if (messages[i]["type"] == "reply")
        {
            EXPECT_EQ(messages[i]["replyToken"].asNumber<int64_t>(), messages[i+1]["replyToken"].asNumber<int64_t>());
        }
    }

    t.join();
}

TEST(TestMonitorAlone, RunTwice)
{
    // First try to launch given ls-monitor from the build system.  Resort to
    // the system one otherwise (for testing on the target, for instance).
    const char *ls_monitor = LS_MONITOR;
    if (access(ls_monitor, X_OK))
        ls_monitor = "ls-monitor";
    std::cout << "Using monitor: " << ls_monitor << std::endl;

    // Setup tracking SIGCHLD through signalfd
    ChildFd child_tracker;

    // spawn first ls-monitor
    pid_t child0_pid = fork();
    ASSERT_NE(-1, child0_pid);
    if (child0_pid == 0) // code for child
    {
        if (!execlp(ls_monitor, ls_monitor, nullptr))
            exit(1);
        exit(0);
    }

    // spawn second ls-monitor
    pid_t child1_pid = fork();
    ASSERT_NE(-1, child1_pid);
    if (child1_pid == 0) // code for child
    {
        if (!execlp(ls_monitor, ls_monitor, nullptr))
            exit(1);
        exit(0);
    }

    pid_t pid;
    EXPECT_LT(0, (pid = child_tracker.wait(nullptr, 3)))
        << "One of the ls-monitors had to fail on start";

    EXPECT_TRUE(pid == 0 || pid == child0_pid || pid == child1_pid)
        << "We expect to be notified only about monitors";

    ASSERT_EQ(0, child_tracker.wait(nullptr, 1))
        << "Second ls-monitor should still be alive";

    // close outstanding ls-mointors
    if (child0_pid != pid)
    {
        EXPECT_EQ(0, kill(child0_pid, SIGKILL));
        EXPECT_EQ(child0_pid, wait(nullptr));
    }
    if (child1_pid != pid)
    {
        EXPECT_EQ(0, kill(child1_pid, SIGKILL));
        EXPECT_EQ(child1_pid, wait(nullptr));
    }
}

TEST_F(TestMonitor, ApiVersion)
{
    // First try to launch given ls-monitor from the build system.  Resort to
    // the system one otherwise (for testing on the target, for instance).
    const char *ls_monitor = LS_MONITOR;
    if (access(ls_monitor, X_OK))
        ls_monitor = "ls-monitor";
    std::cout << "Using monitor: " << ls_monitor << std::endl;

    std::string command = std::string{"cd /; "} + ls_monitor + " -v com.webos.versioned";

    unique_ptr<FILE, int (*)(FILE*)> f{
        popen(command.c_str(), "r"),
        pclose
    };
    ASSERT_TRUE(f.get() != NULL);

    ostringstream oss;
    char buff[512];
    while (fgets(buff, sizeof(buff), f.get()))
        oss << buff;

    auto output = oss.str();
    ASSERT_EQ(output, "com.webos.versioned 3.14\n");
}
