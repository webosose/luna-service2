// Copyright (c) 2016-2018 LG Electronics, Inc.
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

/**
 *  @file cpu_time.hpp
 */

#pragma once

#include <chrono>

#include <sys/time.h>

namespace {
    /// Represents a CPU user+system usage time
    ///
    /// CPUTime meets the requirements of TrivialClock
    struct CPUTime
    {
        typedef std::chrono::nanoseconds duration;
        typedef duration::rep rep;
        typedef duration::period period;
        typedef std::chrono::time_point<CPUTime> time_point;

        static constexpr bool is_steady = false; // time between clock ticks isn't constant

        static time_point now() noexcept
        {
            using namespace std::chrono;

            struct timespec usage;
            int result = clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &usage);
            (void) result;
            assert(result == 0);

            return time_point{ seconds{usage.tv_sec} + nanoseconds{usage.tv_nsec} };
        }
    };
} // anonymous namespace
