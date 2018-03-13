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
 *  @file benchmark_time.hpp
 */

#pragma once

#include <chrono>
#include "cpu_time.hpp"

namespace {
    /// Our default stop-watch to measure real time intervals
    typedef std::chrono::steady_clock stop_watch;

    /// A collection of time measurements made while benchmarking
    struct MeasuredTime
    {

        stop_watch::duration time;
        CPUTime::duration cpuTime;
        size_t cycles;
        stop_watch::time_point endTime;

        static MeasuredTime zero() noexcept
        {
            MeasuredTime mt;
            mt.time    = stop_watch::duration::zero();
            mt.cpuTime = CPUTime::duration::zero();
            mt.cycles  = 0;
            mt.endTime = stop_watch::time_point::min();
            return mt;
        }

        MeasuredTime &operator+=(const MeasuredTime &ext) noexcept
        {
            time    += ext.time;
            cpuTime += ext.cpuTime;
            cycles  += ext.cycles;
            endTime  = std::max(endTime, ext.endTime);
            return *this;
        }

        MeasuredTime operator+(const MeasuredTime &ext) const noexcept
        {
            MeasuredTime mt(*this);
            mt += ext;
            return mt;
        }
    };

    /// Measure the execution of a benchmark a givent number of times
    ///
    /// @param func - benchmarkable function
    /// @param cycles - amount of cycles to pass into it
    inline MeasuredTime measureTime(std::function<void(size_t n) noexcept> func, size_t cycles) noexcept
    {
        auto timeStart = stop_watch::now();
        auto cpuTimeStart = CPUTime::now();
        func(cycles);
        auto timeStop = stop_watch::now();
        auto cpuTimeStop = CPUTime::now();

        MeasuredTime mt;
        mt.time    = timeStop - timeStart;
        mt.cpuTime = cpuTimeStop - cpuTimeStart;
        mt.cycles  = cycles;
        mt.endTime = timeStop;
        return mt;
    }

    /// Run a single benchmark to measure execution time for a different
    /// amount of cycles.
    ///
    /// Collect meaningful information about distribution of measurements
    /// along requested cycles to use it for fitting linear regression model.
    ///
    /// P.S. Based on http://hackage.haskell.org/package/criterion-1.1.1.0/docs/src/Criterion-Measurement.html
    ///
    /// @param func - benchmarkable function that accepts amount of cycles to run for
    /// @param timeLimit - lower bound on how long the benchmarking process should take
    inline std::vector<MeasuredTime> benchmarkTime(std::function<void(size_t n) noexcept> func, stop_watch::duration timeLimit) noexcept
    {
        // The amount of time a benchmark must run for in order for us to have some trust in the raw measurement.
        constexpr auto threshold = std::chrono::milliseconds{30};
        constexpr auto aboveThreshold = threshold * 10; // ex. 10 times hits double threshold

        constexpr auto zero = stop_watch::duration::zero();

        func(1); // (warmup) let all stuf be initialized, initial connections setup

        std::vector<MeasuredTime> measurements;
        measurements.reserve(4); // 4 runs minimum

        double k = 1;
        size_t cycles = 0;
        size_t runs = 0;
        auto overThresh = zero;

        auto startTime = stop_watch::now();
        for (;;)
        {
            k *= 1.05; // increase amount of cycles by 5% on each step
            size_t ncycles = k; // new/next cycles
            if (ncycles == cycles) continue; // eliminate repeated values
            cycles = ncycles;

            auto m = measureTime(func, cycles);
            measurements.push_back(m);
            overThresh = std::max(zero, m.time - threshold) + overThresh;
            ++runs;
            if (m.endTime - startTime >= timeLimit && // we've hit our limit?
                overThresh > aboveThreshold &&
                runs >= 4 // at least 4 runs should happen (basically iterations 1,2,3,4)
               )
            {
                break;
            }
        }

        return measurements;
    }
} // anonymous namespace
