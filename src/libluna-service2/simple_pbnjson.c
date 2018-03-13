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

/**
 *  @file simple_pbnjson.c
 */

#include "error.h"
#include "simple_pbnjson.h"

/** @cond INTERNAL */

jvalue_ref jvalue_shallow(jvalue_ref value)
{
    if (jis_array(value))
    {
        jvalue_ref array = jarray_create_hint(NULL, jarray_size(value));
        jarray_splice_append(array, value, SPLICE_COPY);
        return array;
    }
    else if (jis_object(value))
    {
        jobject_iter iter;
        if (!jobject_iter_init(&iter, value))
        { return jinvalid(); }

        jvalue_ref object = jobject_create();

        jobject_key_value keyval;
        while (jobject_iter_next(&iter, &keyval))
        {
            jobject_set2(object, keyval.key, keyval.value);
        }
        return object;
    }
    else
    { return jvalue_duplicate(value); }
}

/** @endcond */
