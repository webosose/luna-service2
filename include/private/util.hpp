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

#ifndef UTIL_HPP
#define UTIL_HPP

#include <memory>
#include <utility>
#include <string>

#include <glib.h>

using GHashTablePointer = std::unique_ptr<GHashTable, void(*)(GHashTable *)>;
using GTreePointer = std::unique_ptr<GTree, void(*)(GTree *)>;

/// @brief Wrap a raw pointer into a unique_ptr with custom deleter.
/// @param[in] t  raw pointer
/// @param[in] d  deleter
/// @return unique_ptr
template <typename T, typename D>
std::unique_ptr<T, D> mk_ptr(T *t, D &&d)
{
    return std::unique_ptr<T, D>(t, std::forward<D>(d));
}

class GErrorPtr
{
public:
    GErrorPtr()
        : ptr(nullptr)
    {
    }

    GErrorPtr(const GErrorPtr&) = delete;
    GErrorPtr& operator=(const GErrorPtr&) = delete;

    GErrorPtr(GErrorPtr&& other)
    {
        ptr = other.ptr;
        other.ptr = nullptr;
    }

    GErrorPtr& operator=(GErrorPtr&& other)
    {
        if (this != &other)
        {
            if (ptr)
                g_error_free(ptr);

            ptr = other.ptr;
            other.ptr = nullptr;
        }

        return *this;
    }

    ~GErrorPtr()
    {
        if (ptr)
            g_error_free(ptr);
    }

    GError* release()
    {
        GError* ret = ptr;
        ptr = nullptr;
        return ret;
    }

    GError* operator->() const
    {
        return ptr;
    }

    operator GError*() const
    {
        return ptr;
    }

    GErrorPtr &clear()
    {
        g_clear_error(&ptr);
        return *this;
    }

    GError **pptr()
    {
        return &ptr;
    }

private:
    GError *ptr;
};

static inline std::string BuildFilename(const std::string &part1, const std::string &part2)
{
    auto fn = mk_ptr(g_build_filename(part1.c_str(), part2.c_str(), nullptr), g_free);
    return fn.get();
}

#endif /* !UTIL_HPP */
