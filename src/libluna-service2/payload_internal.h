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

#ifndef _PAYLOAD_INTERNAL_H_
#define _PAYLOAD_INTERNAL_H_

#include <stdlib.h>
#include <string.h>

#define PAYLOAD_TYPE_JSON "json"

typedef struct LSPayload
{
    int             fd;
    const char     *type;
    void           *data;
    size_t          size;
} LSPayload;

static inline size_t _LSPayloadGetSerializedSize(const LSPayload* payload)
{
    return strlen(payload->type) + 1 + payload->size;
}

void *_LSPayloadSerialize(void *data, const LSPayload* payload);
void _LSPayloadDeserialize(LSPayload *payload, void *data, size_t size);

#endif //_PAYLOAD_INTERNAL_H_
