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

#ifndef _HUBLANE_HPP_
#define _HUBLANE_HPP_

#include <sys/types.h>
#include <transport.hpp>

#include <utility>

/// @cond INTERNAL
/// @addtogroup LunaServiceHub
/// @{

/// \brief Handler of an underlying communication channel.
class HubLane : public LS::Transport
{
    typedef LS::Transport base_t;

public:
    template <typename... Args>
    explicit HubLane(Args&&... args) : base_t(std::forward<Args>(args)...) { }

    void AttachLocalListener(const char *name, mode_t mode);

    static void Run();
};

/// @} END OF GROUP LunaServiceHub
/// @endcond

#endif //_HUBLANE_HPP_
