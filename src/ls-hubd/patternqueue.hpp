// Copyright (c) 2008-2018 LG Electronics, Inc.
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

#ifndef _PATTERNQUEUE_HPP_
#define _PATTERNQUEUE_HPP_

#include <glib.h>
#include <cstdio>
#include <string>

/// @cond INTERNAL
/// @addtogroup LunaServiceHub
/// @{

struct _LSHubPatternSpec;
struct _LSHubPatternQueue;

typedef struct _LSHubPatternSpec _LSHubPatternSpec;
typedef struct _LSHubPatternQueue _LSHubPatternQueue;

/// @brief List of patterns
struct _LSHubPatternQueue {
    int ref;    //< Reference count
    GSList *q;  //< List of patterns
};

_LSHubPatternQueue*
_LSHubPatternQueueNew(void);
_LSHubPatternQueue*
_LSHubPatternQueueNewRef(void);


void
_LSHubPatternQueueFree(_LSHubPatternQueue *q);
/* returns true if the ref count went to 0 and the queue was freed */
bool
_LSHubPatternQueueUnref(_LSHubPatternQueue *q);

void
_LSHubPatternQueuePushTail(_LSHubPatternQueue *q, _LSHubPatternSpec *pattern);
void
_LSHubPatternQueueInsertSorted(_LSHubPatternQueue *q, _LSHubPatternSpec *pattern);

void
_LSHubPatternQueueMergeInto(_LSHubPatternQueue *to, const _LSHubPatternQueue *from);

void
_LSHubPatternQueueMergeIntoAllowDups(_LSHubPatternQueue *to, const _LSHubPatternQueue *from);

void
_LSHubPatternQueueExtractFrom(_LSHubPatternQueue *from, const _LSHubPatternQueue *what);

void
_LSHubPatternQueueShallowCopy(_LSHubPatternSpec *pattern, _LSHubPatternQueue *q);

/* creates a shallow copy with ref count of 1 */
_LSHubPatternQueue*
_LSHubPatternQueueCopyRef(const _LSHubPatternQueue *q);

bool
_LSHubPatternQueueHasMatch(const _LSHubPatternQueue *q, const char *str);

void
_LSHubPatternQueuePrint(const _LSHubPatternQueue *q, FILE *file);

std::string
_LSHubPatternQueueDump(const _LSHubPatternQueue *q);

std::string
_LSHubPatternQueueDumpPlain(const _LSHubPatternQueue *q);

bool
_LSHubPatternQueueIsEqual(const _LSHubPatternQueue *a, const _LSHubPatternQueue *b);

bool
_LSHubPatternQueueIsEmpty(const _LSHubPatternQueue *q);

/// @} END OF GROUP LunaServiceHub
/// @endcond

#endif //_PATTERNQUEUE_HPP_
