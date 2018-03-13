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
 *  @file category.h
 */

#ifndef __CATEGORY_H
#define __CATEGORY_H

#include <pbnjson.h>

#include "base.h"
#include "error.h"
#include "clock.h"

#include <pmtrace_ls2.h>

/**
 * @cond INTERNAL
 * @addtogroup LunaServiceInternals
 * @{
 */

/**
 *******************************************************************************
 * @brief
 *******************************************************************************
 */
struct LSCategoryTable {

    LSHandle       *sh;

    GHashTable     *methods;
    GHashTable     *signals;
    GHashTable     *properties;

    void           *category_user_data;
    jvalue_ref     description;
};

typedef struct LSCategoryTable LSCategoryTable;

typedef struct {
    LSMethodFunction function;  /**< Method function */
    LSMethodFlags flags;        /**< Method flags */
    jschema_ref schema_call;
    jschema_ref schema_firstReply;
    jschema_ref schema_reply;
    LSTransportBitmaskWord *security_provided_groups; /**< bitmask, see security_mask_size in the struct LSTransport */
    void *method_user_data; /**< Method context. If set, overwrites category context */
} LSMethodEntry;

bool LSCategoryValidateCall(LSMethodEntry *entry, LSMessage *message);

/**
 * @} END OF LunaServiceInternals
 * @endcond
 */

#endif
