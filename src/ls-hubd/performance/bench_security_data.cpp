// Copyright (c) 2017-2018 LG Electronics, Inc.
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

#include <cstdio>
#include <cassert>
#include <unordered_set>
#include <sys/time.h>
#include <sys/resource.h>
#include <numeric>

#include <luna-service2/lunaservice.hpp>

#define private public
#include "../file_parser.hpp"
#include "../security.hpp"
#include "../conf.hpp"
#include "../role.hpp"
#include "../patternqueue.hpp"
#include "../pattern.hpp"
#undef private

#include "benchmark_time.hpp"

long maxrss_kb()
{
    struct rusage usage;
    int result = getrusage(RUSAGE_SELF, &usage);
    (void)result;
    assert(result == 0);
    return usage.ru_maxrss;
}

void report(const char *name, const std::vector<MeasuredTime> &ms)
{
    // skip first measurements that have very low quality
    constexpr auto threshold = std::chrono::milliseconds{30};
    auto start = ms.begin();
    while (start != ms.end() && start->time < threshold) ++start;

    auto total = std::accumulate(start, ms.end(), MeasuredTime::zero());
    size_t seconds = std::chrono::duration_cast<std::chrono::seconds>(total.time).count();
    size_t cpuSeconds = std::chrono::duration_cast<std::chrono::seconds>(total.cpuTime).count();
    std::cout
        << name << std::endl
        << "  " << double(total.cycles) / seconds << " iter/s" << std::endl
        << "  " << double(total.cycles) / cpuSeconds << " iter/s (CPU only)" << std::endl;
}

int main(int argc, char *argv[])
{
    ConfigSetDefaults();
    FileCollector filesBag;
    for (int i = 1; i < argc; ++i)
    {
        LS::Error error;
        if (!ProcessDirectory(argv[i], &filesBag, error))
        {
            error.print(stderr);
            return 1;
        }
    }

    auto build = [&](size_t n) noexcept {
        for (size_t i = 0; i < n; ++i)
        {
            SecurityData data;
            for (const auto &f : filesBag.Files())
            {
                (void) data.AddManifest(f, std::string(), nullptr);
            }
        }
    };
    auto maxrss0_kb = maxrss_kb();
    build(1);
    auto maxrss1_kb = maxrss_kb();
    report("build", benchmarkTime(build, std::chrono::seconds{30}));
    auto maxrss2_kb = maxrss_kb();
    std::cout << "max memory usage: " << maxrss0_kb << " - (single pass) -> " << maxrss1_kb << " -(multi pass)-> " << maxrss2_kb << std::endl;

    SecurityData securityData;
    for (const auto &f : filesBag.Files())
    {
        (void) securityData.AddManifest(f, std::string(), nullptr);

    }

    auto collectServiceNames = [&]() noexcept {
        std::unordered_set<std::string> names;

        size_t id = 0;

        // from role-files
        for (const auto &it : securityData.roles._roles)
        {
            auto& role = it.second;
            assert(role->allowed_names);
            auto allowed_names = *role->allowed_names;
            assert(allowed_names.q);
            for (auto p = allowed_names.q; p; p = g_slist_next(p))
            {
                std::string pattern = static_cast<_LSHubPatternSpec*>(p->data)->pattern_str;
                if (pattern.empty()) continue; // ignore anonymous
                if (*pattern.rbegin() == '*')
                {
                    pattern.pop_back();
                    pattern += std::to_string(id++);
                }
                names.insert(pattern);
            }
        }

        return names;
    };

    auto serviceNames = collectServiceNames();
    auto collect = [&](size_t n) noexcept {
        for (size_t i = 0; i < n; ++i)
        {
            for (const auto &serviceName : serviceNames)
            {
                (void) securityData.groups.GetRequired(serviceName.c_str());
                (void) securityData.groups.GetProvided(serviceName.c_str());
            }
        }
    };

    report("collect", benchmarkTime(collect, std::chrono::seconds{30}));
    return 0;
}
