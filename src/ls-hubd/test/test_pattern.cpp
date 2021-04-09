// Copyright (c) 2008-2021 LG Electronics, Inc.
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


#include "../pattern.hpp"

#include <glib.h>
#include <unistd.h>

typedef struct TestData {
} TestData;

static void
test_LSHubPatternSpecCompare(TestData *fixture, gconstpointer user_data)
{
    _LSHubPatternSpec *a = _LSHubPatternSpecNew("a*");
    _LSHubPatternSpec *b = _LSHubPatternSpecNew("b*");
    g_assert_cmpint(_LSHubPatternSpecCompare(a, b, NULL), <, 0);
    g_assert_cmpint(_LSHubPatternSpecCompare(b, a, NULL), >, 0);
    g_assert_cmpint(_LSHubPatternSpecCompare(a, a, NULL), ==, 0);
    g_assert_cmpint(_LSHubPatternSpecCompare(b, b, NULL), ==, 0);

    _LSHubPatternSpec key = { .ref = 0, .pattern_str = "abcd", };
    g_assert_cmpint(_LSHubPatternSpecCompare(a, &key, NULL), ==, 0);
    g_assert_cmpint(_LSHubPatternSpecCompare(&key, a, NULL), ==, 0);
    g_assert_cmpint(_LSHubPatternSpecCompare(b, &key, NULL), >, 0);
    g_assert_cmpint(_LSHubPatternSpecCompare(&key, b, NULL), <, 0);

    key.pattern_str = "bcd";
    g_assert_cmpint(_LSHubPatternSpecCompare(a, &key, NULL), <, 0);
    g_assert_cmpint(_LSHubPatternSpecCompare(&key, a, NULL), >, 0);
    g_assert_cmpint(_LSHubPatternSpecCompare(b, &key, NULL), ==, 0);
    g_assert_cmpint(_LSHubPatternSpecCompare(&key, b, NULL), ==, 0);

    _LSHubPatternSpecFree(a);
    _LSHubPatternSpecFree(b);
}

static void
test_LSHubPatternSpecClash(TestData *fixture, gconstpointer user_data)
{
    _LSHubPatternSpec *a = _LSHubPatternSpecNew("a*");
    _LSHubPatternSpec *b = _LSHubPatternSpecNew("ab*");
    g_assert_cmpint(_LSHubPatternSpecCompare(a, b, NULL), ==, 0);
    g_assert_cmpint(_LSHubPatternSpecCompare(b, a, NULL), ==, 0);

    _LSHubPatternSpecFree(a);
    _LSHubPatternSpecFree(b);
}

int
main(int argc, char *argv[])
{
    g_test_init(&argc, &argv, NULL);

    g_log_set_always_fatal(G_LOG_LEVEL_ERROR);
    g_log_set_fatal_mask("LunaServiceHub", G_LOG_LEVEL_ERROR);

    g_test_add("/pattern/LSHubPatternSpecCompare", TestData, NULL, NULL, test_LSHubPatternSpecCompare, NULL);
    g_test_add("/pattern/LSHubPatternSpecClash", TestData, NULL, NULL, test_LSHubPatternSpecClash, NULL);

    return g_test_run();
}
