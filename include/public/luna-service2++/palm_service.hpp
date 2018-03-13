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

#include <luna-service2/lunaservice.h>
#include "handle.hpp"
#include <cstring>
#include <iostream>

namespace LS {

/**
 * @ingroup LunaServicePP
 * @brief This class is a wrapper for a service that has both public and private representations.
 * @deprecated Use LS::Handle instead
 */
class PalmService
{
    friend PalmService registerPalmService(const char *name);

public:
    PalmService();

    PalmService(const PalmService &) = delete;
    PalmService &operator=(const PalmService &) = delete;

    PalmService(PalmService &&) LS_DEPRECATED_PUBPRIV = default;
    PalmService &operator=(PalmService &&) = default;

    /**
     * Register tables of callbacks (private and public) associated with the message category.
     *
     * @param category name
     * @param methods_public LSMethod array that should end with {0}
     * @param methods_private LSMethod array that should end with {0}
     * @param ls_signals LSSignal array that should end with {0}
     */
    void registerCategory(const char *category, LSMethod *methods_public,
                          LSMethod *methods_private, LSSignal *ls_signals)
    {
        _public_handle.registerCategory(category, methods_public, ls_signals, NULL);

        _private_handle.registerCategory(category, methods_private, ls_signals, NULL);
        _private_handle.registerCategoryAppend(category, methods_public, ls_signals);
    }

    /**
     * Function to get public handle
     *
     * @return public service handle
     */
    Handle &getPublicHandle() { return _public_handle; }

    /**
     *Function to get public handle
     *
     * @return public service handle
     */
    const Handle &getPublicHandle() const { return _public_handle; }

    /**
     * Function to get private handle
     *
     * @return private service handle
     */
    Handle &getPrivateHandle() { return _private_handle; }
    /**
     * Function to get private handle
     *
     * @return private service handle
     */
    const Handle &getPrivateHandle() const { return _private_handle; }

    void pushRole(const char *role_path)
    {
        _public_handle.pushRole(role_path);
        _private_handle.pushRole(role_path);
    }

    void attachToLoop(GMainLoop *loop)
    {
        _public_handle.attachToLoop(loop);
        _private_handle.attachToLoop(loop);
    }

    void attachToLoop(GMainContext *context)
    {
        _public_handle.attachToLoop(context);
        _private_handle.attachToLoop(context);
    }

    void setPriority(int priority) const
    {
        _public_handle.setPriority(priority);
        _private_handle.setPriority(priority);
    }

private:
    Handle _private_handle, _public_handle;

private:
    explicit PalmService(const char *name);

    friend std::ostream &operator<<(std::ostream &os, const PalmService &service)
    { return os << "LUNA PALM SERVICE '" << service.getPrivateHandle().getName() << "'"; }
};

/**
 * @deprecated Use LS::registerService instead
 */
extern PalmService registerPalmService(const char *name) LS_DEPRECATED_PUBPRIV;

} //namespace LS;
