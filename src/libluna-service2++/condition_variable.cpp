// Copyright (c) 2017-2021 LG Electronics, Inc.
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

#include "condition_variable.hpp"

#define NSEC_PER_MSEC 1000000L
namespace LS {

        condition_variable::condition_variable() : ts()
        {
            (void) pthread_mutex_init(&internal_mutex,NULL);
            (void) pthread_condattr_init( &attr);
            (void) pthread_condattr_setclock( &attr, CLOCK_MONOTONIC);
            (void) pthread_cond_init( &cond, &attr);
        }

        condition_variable::~condition_variable()
        {
            (void) pthread_mutex_destroy(&internal_mutex);
            (void) pthread_cond_destroy(&cond);
            (void) pthread_condattr_destroy(&attr);
        }

        void condition_variable::conditional_wait(std::unique_lock<std::mutex>& lock)
        {
            pthread_mutex_lock(&internal_mutex);
            lock.unlock();
            pthread_cond_wait(&cond,&internal_mutex);
            pthread_mutex_unlock(&internal_mutex);
            lock.lock();
        }

        bool condition_variable::conditional_timedwait(std::unique_lock<std::mutex>& lock, unsigned int millisec)
        {
            clock_gettime(CLOCK_MONOTONIC, &ts);
            int sec = millisec / 1000;
            int nsec = (millisec - (sec * 1000)) * NSEC_PER_MSEC;
            ts.tv_sec +=  sec;
            ts.tv_nsec += nsec;
            pthread_mutex_lock(&internal_mutex);
            lock.unlock();
            if (0 != pthread_cond_timedwait(&cond, &internal_mutex, &ts))
            {
                pthread_mutex_unlock(&internal_mutex);
                lock.lock();
                return CW_TIMEOUT;
            }
            pthread_mutex_unlock(&internal_mutex);
            lock.lock();
            return CW_NO_TIMEOUT;
        }

        void condition_variable::notify_one()
        {
            pthread_mutex_lock(&internal_mutex);
            pthread_cond_signal(&cond);
            pthread_mutex_unlock(&internal_mutex);
        }

}
