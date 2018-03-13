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

#include <mutex>

namespace LS {

#define CW_TIMEOUT 0
#define CW_NO_TIMEOUT 1

class condition_variable{

public:

        condition_variable();
        ~condition_variable();

        template<class predicate>
        bool wait(std::unique_lock<std::mutex>& lock, predicate P)
        {
            while (!P())
            {
               conditional_wait(lock);
            }
            return true;
        }

        template<class predicate>
        bool wait_for(std::unique_lock<std::mutex>& lock, unsigned int millisec, predicate P)
        {
            if (!P())
            {
               return conditional_timedwait(lock, millisec);
            }
            return CW_NO_TIMEOUT;
        }

        void notify_one();

private:

        pthread_cond_t cond;
        pthread_condattr_t attr;
        pthread_mutex_t internal_mutex;
        struct timespec ts;

        void conditional_wait(std::unique_lock<std::mutex>& lock);
        bool conditional_timedwait(std::unique_lock<std::mutex>& lock, unsigned int millisec);
};

}
