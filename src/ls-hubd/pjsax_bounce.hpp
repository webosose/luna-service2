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
 *  @file pjsax_bounce.hpp
 */

#pragma once

#include <pbnjson.hpp>

/// PJSAXCallbacks adapter to parsers of JSON SAX events
///
/// Underlying type should facilitate next method calls:
///
/// @code{.cpp}
///   (bool) jsonObjectOpen()
///   (bool) jsonObjectKey({str, len})
///   (bool) jsonObjectClose()
///
///   (bool) jsonArrayOpen()
///   (bool) jsonArrayClose()
///
///   (bool) jsonString({str, len})
///   (bool) jsonNumber({str, len})
///   (bool) jsonBoolean(boolVal)
///   (bool) jsonNull()
///
///   const char *str;
///   size_t len;
///   bool boolVal;
/// @endcode
///
///  If method returns something that implicitly casts to false this is treat
///  as request to abort parser.
template <class T>
class PJSAXBounce
{
    static T &ctx(JSAXContextRef saxCtx)
    { return *static_cast<T*>(jsax_getContext(saxCtx)); }

    static int objOpen(JSAXContextRef saxCtx) { return ctx(saxCtx).jsonObjectOpen(); }
    static int objKey(JSAXContextRef saxCtx, const char *key, size_t len)
    { return ctx(saxCtx).jsonObjectKey({key, len}); }
    static int objClose(JSAXContextRef saxCtx) { return ctx(saxCtx).jsonObjectClose(); }

    static int arrOpen(JSAXContextRef saxCtx) { return ctx(saxCtx).jsonArrayOpen(); }
    static int arrClose(JSAXContextRef saxCtx) { return ctx(saxCtx).jsonArrayClose(); }

    static int strVal(JSAXContextRef saxCtx, const char *str, size_t len)
    { return ctx(saxCtx).jsonString({str, len}); }
    static int numVal(JSAXContextRef saxCtx, const char *str, size_t len)
    { return ctx(saxCtx).jsonNumber({str, len}); }
    static int boolVal(JSAXContextRef saxCtx, bool value)
    { return ctx(saxCtx).jsonBoolean(value); }
    static int nullVal(JSAXContextRef saxCtx)
    { return ctx(saxCtx).jsonNull(); }

public:
    /// Get a PJSAXCallbacks for type T
    static PJSAXCallbacks *callbacks()
    {
        static PJSAXCallbacks callbacks = {
            objOpen, objKey, objClose,
            arrOpen, arrClose,
            strVal, numVal, boolVal, nullVal
        };
        return &callbacks;
    };
};
