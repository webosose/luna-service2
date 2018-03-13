// Copyright (c) 2015-2018 LG Electronics, Inc.
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

#ifndef _PAYLOAD_H_
#define _PAYLOAD_H_

/**
 * @addtogroup LunaServicePayload
 * @{
 */

#include <stdlib.h>
#include <pbnjson/c/jtypes.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct LSPayload LSPayload;

LSPayload *LSPayloadFromJson(const char *json);
LSPayload *LSPayloadFromJValue(jvalue_ref value);
LSPayload *LSPayloadFromData(const char* type, void* ptr, size_t size);

void LSPayloadFree(LSPayload *payload);

void LSPayloadAttachFd(LSPayload *payload, int fd);
int LSPayloadGetFd(const LSPayload *payload);

const char *LSPayloadGetJson(const LSPayload *payload);
jvalue_ref LSPayloadGetJValue(const LSPayload *payload);

const char* LSPayloadGetDataType(const LSPayload *payload);
void* LSPayloadGetData(const LSPayload *payload, size_t* size);

#ifdef __cplusplus
} // extern "C"
#endif

/**
 * @} END OF LunaServicePayload
 */

#endif //_PAYLOAD_H_
