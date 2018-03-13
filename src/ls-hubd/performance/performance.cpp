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

#include <luna-service2/lunaservice.hpp>

#include <iomanip>
#include <fstream>
#include <sstream>
#include <memory>
#include <functional>
#include <chrono>
#include <numeric>
#include <condition_variable>

#include "benchmark_time.hpp"

namespace {
    std::string human_size(size_t bytes) noexcept
    {
        if (bytes < 1024) return std::to_string(bytes) + "B";
        else return std::to_string(bytes / 1024) + "KB";
    }


    void dump_csv(std::ostream &os, const std::vector<MeasuredTime> &data) noexcept
    {
        using ms = std::chrono::duration<float, std::milli>;
        using std::chrono::duration_cast;
        os << "\"time (msec)\","
              "\"cpuTime (msec)\","
              "\"cycles\"" << std::endl;

        for (const auto &entry : data)
        {
            os
                << duration_cast<ms>(entry.time).count() << ", "
                << duration_cast<ms>(entry.cpuTime).count() << ", "
                << entry.cycles << std::endl;
        }
    }
}


class LS2Service : public LS::Handle
{
    typedef std::function<void(LSHandle *sh, LSMessage *msg)> LS2Method;
    std::vector< std::shared_ptr<LS2Method> > methods;
    std::shared_ptr<GMainLoop> loop;
    std::thread loop_thread;

    void loop_thread_func();
    static bool callback(LSHandle *sh, LSMessage *msg, void *category_context);

public:

    explicit LS2Service(const std::string &name);
    ~LS2Service();
    void AddMethod(const std::string& name, const LS2Method& _method);
    void callNoReply(const char *uri, const char *payload, const char * appID = NULL);
};

inline void LS2Service::loop_thread_func()
{
    g_main_loop_run(loop.get());
}

inline bool LS2Service::callback(LSHandle *sh, LSMessage *msg, void *category_context)
{
    reinterpret_cast<LS2Method*>(category_context)->operator()(sh, msg);
    return true;
}

inline LS2Service::LS2Service(const std::string &name)
        : LS::Handle(LS::registerService(name.c_str()))
        , loop(g_main_loop_new(nullptr, false), g_main_loop_unref)
        , loop_thread(std::bind(&LS2Service::loop_thread_func, this))
{
    attachToLoop(loop.get());

    while(!g_main_loop_is_running(loop.get()))
        usleep(1000);
}

inline LS2Service::~LS2Service()
{
    g_main_loop_quit(loop.get());
    loop_thread.join();
}

inline void LS2Service::AddMethod(const std::string& name, const LS2Method& _method)
{
    std::shared_ptr<LS2Method> method(new LS2Method(_method));
    methods.push_back(method);
    LSMethod method_arg[] = {{"call", callback}, { nullptr, nullptr }};
    registerCategory(name.c_str(), method_arg, nullptr, nullptr);
    setCategoryData(name.c_str(), method.get());
}

inline void LS2Service::callNoReply(const char *uri, const char *payload, const char * appID)
{
    LS::Error error;
    if (!LSCallFromApplication( get(), uri, payload, appID, nullptr,nullptr, nullptr,error.get()))
        throw error;
}

namespace stdp=std::placeholders;

struct align_center
{
    std::string text;
    int width;
    align_center(const std::string &_text, int width)
        : text(_text)
        , width(width)
    {}
};

std::ostream& operator<<(std::ostream& stream, const align_center& data)
{
    int padding1 = std::max(0, (data.width-int(data.text.size()))/2);
    int padding2 = std::max(0, data.width-padding1-int(data.text.size()));
    stream << std::string(padding1, ' ') << data.text << std::string(padding2, ' ');
    return stream;
}

class CPUStat
{
    unsigned long total_cpu_times;
    unsigned long process_cpu_times;
public:
    CPUStat();
    int GetCPUUsage();
};

CPUStat::CPUStat()
    : total_cpu_times(0)
    , process_cpu_times(0)
{
    unsigned long  user_time, kernel_time;
    std::string ignore;
    std::ifstream proc_self_stat("/proc/self/stat");
    proc_self_stat >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore
        >> ignore >> ignore >> ignore >> user_time >> kernel_time;
    process_cpu_times = user_time + kernel_time;

    std::ifstream proc_stat("/proc/stat");
    proc_stat >> ignore;
    for (int i = 0 ; i < 10 ; i++)
    {
        unsigned long cpu_time;
        proc_stat >> cpu_time;
        total_cpu_times += cpu_time;
    }
}

int CPUStat::GetCPUUsage()
{
    int numCPU = sysconf( _SC_NPROCESSORS_ONLN );
    CPUStat cur_stat;
    return (numCPU * 100 * (cur_stat.process_cpu_times - process_cpu_times)) / (cur_stat.total_cpu_times - total_cpu_times);
}

class PerformanceTest
{
    LS2Service client, server;
    std::condition_variable call_cv;
    std::mutex call_mut;
    volatile bool call_received;
    std::string payload;

    void simple_call(LSHandle *sh, LSMessage *mes);
    void reply_on_call(LSHandle *sh, LSMessage *mes);
    void reply_on_call_empty(LSHandle *sh, LSMessage *mes);
    void make_server_call(const char* payload, bool with_reply);
    void measure_latency(size_t payload_size, bool with_reply = false, size_t period = 2500);
    size_t memory_usage_kb();

public:
    std::string report_dir;

    PerformanceTest();
    void run();
    static void signal_handler(int);
};

void PerformanceTest::simple_call(LSHandle *sh, LSMessage *mes)
{
    std::unique_lock<std::mutex> lock(call_mut);
    call_received = true;
    call_cv.notify_all();
}

void PerformanceTest::reply_on_call(LSHandle *sh, LSMessage *mes)
{
    LS::Error e;
    LSMessageRespond(mes, payload.c_str(), e.get());
}

void PerformanceTest::reply_on_call_empty(LSHandle *sh, LSMessage *mes)
{
    LS::Error e;
    LSMessageRespond(mes, "{}", e.get());
}

void PerformanceTest::make_server_call(const char* payload, bool with_reply)
{
    if (with_reply)
    {
        client.callOneReply("luna://com.webos.performance/reply_on_call/call", payload).get();
    }
    else
    {
        client.callOneReply("luna://com.webos.performance/reply_on_call_empty/call", payload).get();

        // TODO: measure call without callback. Do not ref outgoing message in
        //       _LSTransportSerialSave if reply is not expected.
        //std::unique_lock<std::mutex> lock(call_mut);
        //call_received = false;
        //client.callNoReply("luna://com.webos.performance/simple_call/call", payload);
        //while (!call_received)
        //    call_cv.wait(lock);
    }
}

size_t PerformanceTest::memory_usage_kb()
{
    unsigned long vsize;
    std::string ignore;
    std::ifstream ifs("/proc/self/stat");
    ifs >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore
        >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore
        >> ignore >> ignore >> vsize;

    return vsize / 1024;
}

void PerformanceTest::measure_latency(size_t payload_size, bool with_reply, size_t period)
{
    payload = std::string(payload_size, '$');

    auto func = [=](size_t n) {
        for (size_t i = 0; i < n; ++i)
        {
            make_server_call(payload.c_str(), with_reply);
        }
    };
    CPUStat cpu_stat;
    auto ms = benchmarkTime(func, std::chrono::milliseconds{period});
    auto total = std::accumulate(ms.begin(), ms.end(), MeasuredTime::zero());

    size_t counter = total.cycles;
    size_t duration = std::chrono::duration_cast<std::chrono::milliseconds>(total.time).count();
    int mes_per_sec = static_cast<int>(counter*1000.0/duration);
    double mb_per_sec = (payload_size*counter*1000.0/duration)/(1024.0*1024.0);
    if (with_reply) mb_per_sec *= 2;
    double latency = static_cast<double>(duration) / counter;
    double memory_usage = memory_usage_kb()/1024.0;
    int cpu_usage = cpu_stat.GetCPUUsage();

    std::cout << '|' << std::setw(15) << payload_size
              << '|' << std::setw(15) << mes_per_sec
              << '|' << std::setw(15) << mb_per_sec
              << '|' << std::setw(15) << latency
              << '|' << std::setw(9) << memory_usage
              << '|' << std::setw(9) << cpu_usage
              << '|' << std::endl;

    if (!report_dir.empty()) {
        std::ostringstream ss;
        ss << report_dir
           << "/report_" << (with_reply ? "bidirect_" : "unidirect_") << human_size(payload_size) << ".csv";
        std::ofstream f(ss.str().c_str());
        dump_csv(f, ms);
    }
}

void PerformanceTest::run()
{
    std::cout << std::string(85, '*') << std::endl;

    std::cout << std::left << std::setfill(' ') << std::setprecision(3);
    std::cout << '|' << std::setw(15) << "Payload size"
              << '|' << std::setw(15) << "Performance"
              << '|' << std::setw(15) << "Speed"
              << '|' << std::setw(15) << "Latency"
              << '|' << std::setw(9) << "Memory"
              << '|' << std::setw(9) << "CPU"
              << '|' << std::endl;
    std::cout << '|' << std::setw(15) << "bytes"
              << '|' << std::setw(15) << "mes/sec"
              << '|' << std::setw(15) << "MB/sec"
              << '|' << std::setw(15) << "ms"
              << '|' << std::setw(9) << "MB"
              << '|' << std::setw(9) << "%"
              << '|' << std::endl;

    std::cout << std::string(85, '*') << std::endl;
    std::cout << '|' << align_center("client--(call)-->server", 83) << '|' << std::endl;
    std::cout << std::string(85, '*') << std::endl;

    measure_latency(64);
    measure_latency(1024);
    measure_latency(64*1024);
    measure_latency(256*1024);
    measure_latency(1024*1024);

    std::cout << std::string(85, '*') << std::endl;
    std::cout << '|' << align_center("client--(call)-->server--(reply)-->client", 83) << '|' << std::endl;
    std::cout << std::string(85, '*') << std::endl;

    measure_latency(64, true);
    measure_latency(1024, true);
    measure_latency(64*1024, true);
    measure_latency(256*1024, true);
    measure_latency(1024*1024, true);

    std::cout << std::string(85, '*') << std::endl;
}

PerformanceTest::PerformanceTest()
    : client("com.webos.performance_client")
    , server("com.webos.performance")
{
    server.AddMethod("/simple_call", std::bind(&PerformanceTest::simple_call, this, stdp::_1, stdp::_2));
    server.AddMethod("/reply_on_call", std::bind(&PerformanceTest::reply_on_call, this, stdp::_1, stdp::_2));
    server.AddMethod("/reply_on_call_empty", std::bind(&PerformanceTest::reply_on_call_empty, this, stdp::_1, stdp::_2));
}


int main(int argc, char** argv)
{
    try
    {
        PerformanceTest test;
        if (const char* env_report_dir = std::getenv("REPORTDIR"))
            test.report_dir = env_report_dir;
        test.run();
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    return 0;
}
