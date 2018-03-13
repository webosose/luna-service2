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

#pragma once

#include <memory>
#include <string>
#include <numeric>
#include <unordered_map>
#include <functional>
#include <iostream>
#include <algorithm>
#include <vector>

#include "../libluna-service2/base.h"

// We support only star wildcard, which is also a prefix separator.
static char WILDCARD = '*';

/* Function which separates prefix from string.
 * With default separator, takes 1 character every time
 */
template <char S>
inline ssize_t prefixSeparator(const char* str)
{
    LS_ASSERT(str != nullptr);

    auto suff = strchr(str, S);
    if (suff != nullptr)
    {
        return suff - str + 1;
    }
    else
    {
        return strlen(str);
    }
}

template <>
inline ssize_t prefixSeparator<0>(const char *)
{
    return 1;
}

enum class PatternMatchResult
{
    PATTERN_MISMATCH,
    PATTERN_MATCH,
    PATTERN_SAME
};

/* Ad-hoc pattern matching for our patterns.
 * Doesn't actually work as glob-style pattern, but search
 * wildcard symbol to match string suffix.
 */
inline PatternMatchResult globPatternMatch(const char *pat, const char *str)
{
    // We don't match wildcard, so we exclude it from matching
    auto pat_size = strlen(pat) - 1;
    auto str_len = strlen(str);
    if (str_len < pat_size) return PatternMatchResult::PATTERN_MISMATCH;
    else
    {
        auto match = std::mismatch(pat, pat + pat_size, str);
        if (match.first == (pat + pat_size))
        {
            if (match.second[0] == WILDCARD)
            {
                return PatternMatchResult::PATTERN_SAME;
            }
            else
            {
                return PatternMatchResult::PATTERN_MATCH;
            }
        }
        return PatternMatchResult::PATTERN_MISMATCH;
    }
}
