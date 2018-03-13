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

#include <gtest/gtest.h>
#include "luna-service2++/handle.hpp"

#include "test_util.hpp"

TEST(Trusted, A)
{
    std::string name = "com.service.trusted."  + std::to_string(getpid());
    LS::Handle trusted = LS::registerService(name.c_str(), false);

    MainLoopT mainloop;
    trusted.attachToLoop(mainloop.get());

    EXPECT_TRUE(trusted.callOneReply("luna://com.service.any/notexisting", "{}").get().isHubError());
    EXPECT_FALSE(trusted.callOneReply("luna://com.service.any/anycall", "{}").get().isHubError());
}
