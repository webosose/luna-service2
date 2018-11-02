// Copyright (c) 2008-2019 LG Electronics, Inc.
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


#ifndef _TRANSPORT_UTILS_H_
#define _TRANSPORT_UTILS_H_

#include <signal.h>
#include <stdbool.h>
#include <pthread.h>
#include <glib.h>

#include "log.h"

#define ARRAY_SIZE(array) (sizeof(array)/sizeof(array[0]))

extern int _ls_debug_tracing;

#define DEBUG_TRACING (_ls_debug_tracing)
#define DEBUG_VERBOSE (_ls_debug_tracing > 1)

#ifdef __cplusplus
extern "C" {
#endif

/** @cond INTERNAL */

int strlen_safe(const char *str);
void DumpHashItem(gpointer key, gpointer value, gpointer user_data);
void DumpHashTable(GHashTable *table);
bool _LSTransportSetupSignalHandler(int signal, void (*handler)(int));
void _LSTransportFdSetBlock(int fd, bool *prev_state_blocking);
void _LSTransportFdSetNonBlock(int fd, bool *prev_state_blocking);
const char *_LSGetHubLocalSocketAddress();
const char *_LSGetHubLocalSocketDirectory();

/* compile-time type check */
#define TYPECHECK(type,val)             \
({	type __type;                        \
	typeof(val) __val;                  \
	(void)(&__type == &__val);          \
	1;                                  \
})

#define LOCK(name, mutex)                                   \
do {                                                        \
    LOG_LS_TRACE("%s: LOCK %s\n", __func__, name);          \
    pthread_mutex_lock(mutex);                              \
} while (0)

#define UNLOCK(name, mutex)                                 \
do {                                                        \
    LOG_LS_TRACE("%s: UNLOCK %s\n", __func__, name);        \
    pthread_mutex_unlock(mutex);                            \
} while (0)


#define TRANSPORT_LOCK(mutex)                               \
do {                                                        \
    LOCK("Transport", mutex);                               \
} while (0)

#define TRANSPORT_UNLOCK(mutex)                             \
do {                                                        \
    UNLOCK("Transport", mutex);                             \
} while (0)

#define SERIAL_INFO_LOCK(mutex)                             \
do {                                                        \
    LOCK("Serial Info", mutex);                             \
} while (0)

#define SERIAL_INFO_UNLOCK(mutex)                           \
do {                                                        \
    UNLOCK("Serial Info", mutex);                           \
} while (0)

#define GLOBAL_TOKEN_LOCK(mutex)                            \
do {                                                        \
    LOCK("Global Token", mutex);                            \
} while (0)

#define GLOBAL_TOKEN_UNLOCK(mutex)                          \
do {                                                        \
    UNLOCK("Global Token", mutex);                          \
} while (0)

#define OUTGOING_LOCK(mutex)                                \
do {                                                        \
    LOCK("Outgoing", mutex);                                \
} while (0)

#define OUTGOING_UNLOCK(mutex)                              \
do {                                                        \
    UNLOCK("Outgoing", mutex);                              \
} while (0)

#define SEND_WATCH_LOCK(mutex)                              \
do {                                                        \
    LOCK("Send Watch", mutex);                              \
} while (0)

#define SEND_WATCH_UNLOCK(mutex)                            \
do {                                                        \
    UNLOCK("Send Watch", mutex);                            \
} while (0)

#define OUTGOING_SERIAL_LOCK(mutex)                         \
do {                                                        \
    LOCK("Outgoing Serial", mutex);                         \
} while (0)

#define OUTGOING_SERIAL_UNLOCK(mutex)                       \
do {                                                        \
    UNLOCK("Outgoing Serial", mutex);                       \
} while (0)

#define INCOMING_LOCK(mutex)                                \
do {                                                        \
    LOCK("Incoming", mutex);                                \
} while (0)

#define INCOMING_UNLOCK(mutex)                              \
do {                                                        \
    UNLOCK("Incoming", mutex);                              \
} while (0)


/**
 * \brief Word of a potentially long bitmask.
 *
 * Speculatively, it should be the same as machine word of the platform.
 */
typedef unsigned long LSTransportBitmaskWord;

/**
 * @brief  Set a bit in a bit mask
 *
 * @param mask IN|OUT   Bit mask to manipulate
 * @param bit  IN     Bit number
 */
static inline
void BitMaskSetBit(LSTransportBitmaskWord *mask, int bit)
{
    const int bits = sizeof(LSTransportBitmaskWord) * 8;
    int nword = bit / bits;
    int nbit = bit % bits;
    //printf("[%s] bit: %d, bits: %d, nword: %d, nbit: %d \n", __func__, bit, bits, nword, nbit);
    //printf("[%s]mask[nword] : %d, mask: %d  \n",__func__, mask[nword],*mask);
    mask[nword] |= ((LSTransportBitmaskWord)1 << nbit);
    //printf("[%s]mask : %d \n",__func__, *mask);
}

/**
* @brief  Bitwise operator Or between 2 bit masks
*
* @param  res  IN|OUT Mask with result
* @param  mask IN     Input mask
* @param  size IN     Size of the mask
*/
static inline void BitMaskBitwiseOr(LSTransportBitmaskWord *res,
                             const LSTransportBitmaskWord *mask,
                             int size)
{
    for (int i = 0; i < size; i++)
        res[i] |= mask[i];
}

/**
* @brief  Check if specific bit is set
*
* @param mask IN    Input mask
* @param bit  IN    Bit number
*
* @retval true/false
*/
static inline
bool BitMaskTestBit(LSTransportBitmaskWord *mask, int bit)
{
    const int bits = sizeof(LSTransportBitmaskWord) * 8;
    int nword = bit / bits;
    int nbit = bit % bits;
    return (mask[nword] & ((LSTransportBitmaskWord)1 << nbit)) != 0;
}

#ifdef __cplusplus
}
#endif

/** @endcond */

#endif  // _TRANSPORT_UTILS_H_
