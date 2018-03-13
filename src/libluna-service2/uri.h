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

#ifndef _URI_H_
#define _URI_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @cond INTERNAL */

typedef struct LSError LSError;

typedef struct _LSUri
{
    char *serviceName;
    char *objectPath;
    char *methodName;
} LSUri;

LSUri *
LSUriParse(const char *uri, LSError *lserror);

void
LSUriFree(LSUri *luri);

#ifdef __cplusplus
}
#endif

/** @endcond */

#endif //_URI_H_
