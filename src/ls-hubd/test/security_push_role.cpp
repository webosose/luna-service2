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

#include "luna-service2++/handle.hpp"
#include <gtest/gtest.h>

using namespace LS;
using namespace std;

TEST(PushRole, First)
{
    EXPECT_THROW(registerService("private.A", false), Error);
    EXPECT_THROW(registerService("private.A", true), Error);
    EXPECT_THROW(registerService("public.B", false), Error);
    EXPECT_THROW(registerService("public.B", true), Error);

    EXPECT_NO_THROW(registerService("private.X", false));
    EXPECT_THROW(registerService("private.X", true), Error);
    EXPECT_NO_THROW(registerService("public.Y", true));
    EXPECT_THROW(registerService("public.Y", false), Error);
}

TEST(PushRole, PushRole)
{
    Handle new_pub, new_prv;

    {
        auto prv = registerService("private.X", false);
        auto pub = registerService("public.Y", true);

        string conf_root = getenv("LS_CONF_ROOT");
        prv.pushRole((conf_root + "/private.A.json").c_str());
        pub.pushRole((conf_root + "/public.B.json").c_str());

        EXPECT_THROW(prv.pushRole((conf_root + "/private.A.json").c_str()), Error);
        EXPECT_THROW(pub.pushRole((conf_root + "/public.B.json").c_str()), Error);

        EXPECT_NO_THROW(new_prv = registerService("private.A", false));
        EXPECT_THROW(registerService("private.A", true), Error);
        EXPECT_THROW(registerService("public.B", false), Error);
        EXPECT_NO_THROW(new_pub = registerService("public.B", true));
    }

    EXPECT_THROW(registerService("private.X", false), Error);
    EXPECT_THROW(registerService("private.X", true), Error);
    EXPECT_THROW(registerService("public.Y", true), Error);
    EXPECT_THROW(registerService("public.Y", false), Error);
}
