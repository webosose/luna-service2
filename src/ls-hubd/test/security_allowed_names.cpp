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

TEST(TestAllowedNames, Public)
{
    EXPECT_NO_THROW(registerService("public.A", true));
    EXPECT_NO_THROW(registerService("public.B", true));
    EXPECT_NO_THROW(registerService("public.B1", true));

    EXPECT_THROW(registerService("private.C", true), Error);
    EXPECT_THROW(registerService("private.D", true), Error);
    EXPECT_THROW(registerService("private.D4", true), Error);
}

TEST(TestAllowedNames, Private)
{
    EXPECT_NO_THROW(registerService("private.C", false));
    EXPECT_NO_THROW(registerService("private.D", false));
    EXPECT_NO_THROW(registerService("private.D3", false));

    EXPECT_THROW(registerService("public.A", false), Error);
    EXPECT_THROW(registerService("public.B", false), Error);
    EXPECT_THROW(registerService("public.B2", false), Error);
}
