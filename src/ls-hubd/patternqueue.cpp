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

#include "patternqueue.hpp"

#include <glib.h>

#include "util.hpp"
#include "error.h"
#include "pattern.hpp"

/// @cond INTERNAL
/// @addtogroup LunaServiceHub
/// @{

static void
FreePatternSpec(gpointer data)
{
    _LSHubPatternSpecUnref((_LSHubPatternSpec *) data);
}

static int
PatternSpecStringCompare(const _LSHubPatternSpec *a, const _LSHubPatternSpec *b)
{
    return strcmp(a->pattern_str, b->pattern_str);
}

_LSHubPatternQueue*
_LSHubPatternQueueNew(void)
{
    _LSHubPatternQueue *q = g_slice_new0(_LSHubPatternQueue);

    return q;
}

_LSHubPatternQueue*
_LSHubPatternQueueNewRef(void)
{
    _LSHubPatternQueue *q = _LSHubPatternQueueNew();

    q->ref = 1;

    return q;
}

void
_LSHubPatternQueueFree(_LSHubPatternQueue *q)
{
    LS_ASSERT(q != NULL);

    g_slist_free_full(q->q, &FreePatternSpec);
    g_slice_free(_LSHubPatternQueue, q);
}

/* returns true if the ref count went to 0 and the queue was freed */
bool
_LSHubPatternQueueUnref(_LSHubPatternQueue *q)
{
    LS_ASSERT(q != NULL);
    LS_ASSERT(g_atomic_int_get(&q->ref) > 0);

    if (g_atomic_int_dec_and_test(&q->ref))
    {
        _LSHubPatternQueueFree(q);
        return true;
    }

    return false;
}

/// @brief Add new pattern to the list
///
/// Despite of the name, the function doesn't care about the order.
///
/// @param[in,out] q
/// @param[in] pattern
void
_LSHubPatternQueuePushTail(_LSHubPatternQueue *q, _LSHubPatternSpec *pattern)
{
    LS_ASSERT(q != NULL);
    LS_ASSERT(pattern != NULL);

    _LSHubPatternSpecRef(pattern);
    q->q = g_slist_prepend(q->q, pattern);
}

/// @brief Add new pattern to the list maintaining the sorted order
///
/// @param[in,out] q
/// @param[in] pattern
void
_LSHubPatternQueueInsertSorted(_LSHubPatternQueue *q, _LSHubPatternSpec *pattern)
{
    LS_ASSERT(q != NULL);
    LS_ASSERT(pattern != NULL);

    _LSHubPatternSpecRef(pattern);
    q->q = g_slist_insert_sorted(q->q, pattern, (GCompareFunc) &PatternSpecStringCompare);
}

static inline GSList *CopyAll(GSList *from)
{
    if (!from) return nullptr;

    GSList *copy = nullptr;
    for (GSList *it = from; it; it = g_slist_next(it))
    {
        copy = g_slist_append(copy, it->data);
        _LSHubPatternSpecRef((_LSHubPatternSpec *)it->data);
    }

    return copy;
}

static inline GSList *CopyOne(GSList *from)
{
    if (!from) return nullptr;

    GSList *copy = g_slist_alloc();
    copy->data = from->data;
    copy->next = from ->next;

    _LSHubPatternSpecRef((_LSHubPatternSpec *)copy->data);
    return copy;
}

static GSList *MergeUnique(GSList *to, GSList *from)
{
    if(!to) return CopyAll(from);
    if(!from) return to;

    int ret = PatternSpecStringCompare((const _LSHubPatternSpec *)to->data, (const _LSHubPatternSpec *)from->data);
    if (ret < 0)
    {
        to->next = MergeUnique(to->next, from);
        return to;
    }

    if (ret > 0)
    {
        GSList *copy = CopyOne(from);
        copy->next = MergeUnique(to, copy->next);
        return copy;
    }

    to->next = MergeUnique(to->next, from->next);
    return to;
}

/// @brief Concatenate two lists of patterns, eliminating duplciates
///
/// @param[in,out] to
/// @param[in] from
void
_LSHubPatternQueueMergeInto(_LSHubPatternQueue *to, const _LSHubPatternQueue *from)
{
    LS_ASSERT(to != NULL);
    LS_ASSERT(from != NULL);

    to->q = MergeUnique(to->q, from->q);
}

static GSList *Merge(GSList *to, GSList *from)
{
    if(!to) return CopyAll(from);
    if(!from)return to;

    if (PatternSpecStringCompare((const _LSHubPatternSpec *)to->data, (const _LSHubPatternSpec *)from->data) < 0)
    {
        to->next = Merge(to->next, from);
        return to;
    }

    GSList *copy = CopyOne(from);
    copy->next = Merge(to, copy->next);
    return copy;
}

/// @brief Concatenate two lists of patterns, allowing duplciates
///
/// @param[in,out] to
/// @param[in] from
void
_LSHubPatternQueueMergeIntoAllowDups(_LSHubPatternQueue *to, const _LSHubPatternQueue *from)
{
    LS_ASSERT(to != NULL);
    LS_ASSERT(from != NULL);

    to->q = Merge(to->q, from->q);
}

void
_LSHubPatternQueueExtractFrom(_LSHubPatternQueue *from, const _LSHubPatternQueue *what)
{
    for (GSList *fi = from->q, *wi = what->q; fi && wi; )
    {
        int ret = PatternSpecStringCompare((const _LSHubPatternSpec *)fi->data, (const _LSHubPatternSpec *)wi->data);
        if (ret < 0)
        {
            fi = g_slist_next(fi);
        }
        else if (ret == 0)
        {
            GSList *remove = fi;
            fi = g_slist_next(fi);

            from->q = g_slist_remove_link(from->q, remove);
            _LSHubPatternSpecUnref((_LSHubPatternSpec *)remove->data);
            g_slist_free(remove);

            wi = g_slist_next(wi);
        }
        else
        {
            break;
        }
    }
}

void
_LSHubPatternQueueShallowCopy(_LSHubPatternSpec *pattern, _LSHubPatternQueue *q)
{
    LS_ASSERT(pattern != NULL);
    LS_ASSERT(q != NULL);

    _LSHubPatternQueuePushTail(q, pattern);
}

/* creates a shallow copy with ref count of 1 */
_LSHubPatternQueue*
_LSHubPatternQueueCopyRef(const _LSHubPatternQueue *q)
{
    LS_ASSERT(q != NULL);

    _LSHubPatternQueue *new_q = _LSHubPatternQueueNew();

    if (new_q)
    {
        new_q->ref = 1;
        g_slist_foreach(q->q, (GFunc)_LSHubPatternQueueShallowCopy, new_q);
    }

    return new_q;
}

bool
_LSHubPatternQueueHasMatch(const _LSHubPatternQueue *q, const char *str)
{
    LS_ASSERT(q != NULL);
    LS_ASSERT(str != NULL);

    GSList *list = q->q;

    if (!g_utf8_validate(str, -1, NULL))
    {
        LOG_LS_WARNING(MSGID_LSHUB_BAD_PARAMS, 1,
                       PMLOGKS("func", "g_utf8_validate"), "Can not validate string \"%s\"", str);
        return false;
    }

    auto rev_str = mk_ptr(g_utf8_strreverse(str, -1), g_free);
    if (!rev_str)
    {
        LOG_LS_WARNING(MSGID_LSHUB_BAD_PARAMS, 1,
                       PMLOGKS("func", "g_utf8_strreverse"), "Can not reverse string \"%s\"", str);
        return false;
    }

    while (list)
    {
        _LSHubPatternSpec *pattern = (_LSHubPatternSpec*)list->data;
        if (g_pattern_match(pattern->pattern_spec, strlen(str), str, rev_str.get()))
        {
            return true;
        }

        list = g_slist_next(list);
    }

    return false;
}

void
_LSHubPatternQueuePrint(const _LSHubPatternQueue *q, FILE *file)
{
    LS_ASSERT(q != NULL);
    LS_ASSERT(file != NULL);

    GSList *list = q->q;

    while (list)
    {
        _LSHubPatternSpec *pattern = (_LSHubPatternSpec*)list->data;
        fprintf(file, "%s ", pattern->pattern_str);
        list = g_slist_next(list);
    }
}

std::string
_LSHubPatternQueueDump(const _LSHubPatternQueue *q)
{
    LS_ASSERT(q != NULL);

    std::string dump;
    dump = dump + "[";

    for (GSList *list = q->q; list; list = g_slist_next(list))
    {
        const _LSHubPatternSpec *pattern = (const _LSHubPatternSpec *) list->data;
        if (list != q->q)
            dump = dump + ", ";
        dump = dump + "\"" + pattern->pattern_str + "\"";

    }

    dump = dump + "]";
    return dump;
}

std::string
_LSHubPatternQueueDumpPlain(const _LSHubPatternQueue *q)
{
    LS_ASSERT(q != NULL);

    std::string dump;

    for (GSList *list = q->q; list; list = g_slist_next(list))
    {
        const _LSHubPatternSpec *pattern = (const _LSHubPatternSpec *) list->data;
        if (list != q->q)
            dump = dump + " ";
        dump += pattern->pattern_str;

    }

    return dump;
}

bool
_LSHubPatternQueueIsEqual(const  _LSHubPatternQueue *a, const _LSHubPatternQueue *b)
{
    LS_ASSERT(a != NULL);
    LS_ASSERT(b != NULL);

    // Iterate over two sorted lists simultaneously.
    // If a difference is spotted, they aren't equal.

    GSList *i = a->q;
    GSList *j = b->q;

    while (i && j)
    {
        const _LSHubPatternSpec *pa = (const _LSHubPatternSpec *) i->data;
        const _LSHubPatternSpec *pb = (const _LSHubPatternSpec *) j->data;

        if (strcmp(pa->pattern_str, pb->pattern_str))
            return false;

        i = g_slist_next(i);
        j = g_slist_next(j);
    }

    // Finally, both iterators should be NULL.
    return i == j;
}

/// @brief Check if the list of pattern is empty
///
/// @param[in] q
/// @return true if the list has no elements
bool
_LSHubPatternQueueIsEmpty(const  _LSHubPatternQueue *q)
{
    LS_ASSERT(q != NULL);

    return nullptr == q->q;
}

/// @} END OF GROUP LunaServiceHub
/// @endcond
