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
#include <cstring>
#include <iostream>
#include <exception>

namespace LS {

/**
 * @ingroup LunaServicePP
 * @brief This class wraps LS errors
 */
class Error : public std::exception
{
public:
    Error() { LSErrorInit(&_error); }

    ~Error() noexcept { LSErrorFree(&_error); }

    Error(Error &&other) noexcept
    {
        memcpy(&_error, &other._error, sizeof(_error));
        LSErrorInit(&other._error);
    }

    Error &operator=(Error &&other)
    {
        if (this != &other)
        {
            LSErrorFree(&_error);
            memcpy(&_error, &other._error, sizeof(_error));
            LSErrorInit(&other._error);
        }
        return *this;
    }

    // non-copyable
    Error(const Error &) = delete;
    Error &operator=(const Error &) = delete;

    LSError *get() { return &_error; }
    const LSError *get() const { return &_error; }
    LSError *operator->() { return &_error; }
    const LSError *operator->() const { return &_error; }

    operator LSError* () { return &_error; }

    /**
     * @brief Get text representation of error
     *
     * @return error text message
     */
    const char *what() const noexcept
    { return _error.message; }

    bool isSet() const
    {
        return LSErrorIsSet(const_cast<LSError*>(&_error));
    }

    void print(FILE *out) const
    {
        LSErrorPrint(const_cast<LSError*>(&_error), out);
    }

#ifdef USE_PMLOG_DECLARATION
    void log(PmLogContext context, const char *message_id)
    {
        LSErrorLog(context, message_id, &_error);
    }
#endif

    void logError(const char *message_id)
    {
        LSErrorLogDefault(message_id, &_error);
    }

private:
    LSError _error;

    friend inline std::ostream &operator<<(std::ostream &os, const Error &error)
    {
        return os << "LUNASERVICE ERROR " << error->error_code << ": "
            << error->message << " (" << error->func << " @ " << error->file << ":"
            << error->line << ")";
    }
};

} //namespace LS;
